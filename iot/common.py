"""Shared helpers: frame format, AES-256-GCM, SQLite state, event output and fault injection."""
import base64
import json
import os
import sqlite3
import sys

from Crypto.Cipher import AES

TOPIC = "iot/telemetry"
MAX_SEQ = 2**32
NONCE_LEN, TAG_LEN, PAYLOAD_LEN = 12, 16, 128
CRASH_EXIT_CODE = 99  # exit code used by injected faults
STATE_ERROR_EXIT_CODE = 2  # missing/invalid persistent state
EXHAUSTED_EXIT_CODE = 3  # sequence space exhausted


class FrameError(Exception):
    pass


# ---------------------------------------------------------------- cryptography
def encrypt(key, nonce, plaintext, aad):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=TAG_LEN)
    cipher.update(aad)
    return cipher.encrypt_and_digest(plaintext)  # (ciphertext, tag)


def decrypt(key, nonce, ciphertext, aad, tag):
    """Returns the plaintext or raises ValueError when authentication fails."""
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=TAG_LEN)
    cipher.update(aad)
    return cipher.decrypt_and_verify(ciphertext, tag)


# ---------------------------------------------------------------------- frames
def header_bytes(device, key_id, seq):
    """Authenticated header (AAD): fixed key order, no optional spaces, UTF-8."""
    header = {"v": 1, "dev": device, "kid": key_id, "seq": seq}
    return json.dumps(header, separators=(",", ":")).encode("utf-8")


def make_nonce(prefix, seq):
    return prefix + seq.to_bytes(4, "big")  # 64-bit prefix || 32-bit sequence


def build_frame(device, key_id, seq, nonce, ciphertext, tag):
    b64 = lambda b: base64.b64encode(b).decode()
    frame = {"h": {"v": 1, "dev": device, "kid": key_id, "seq": seq},
             "n": b64(nonce), "c": b64(ciphertext), "t": b64(tag)}
    return json.dumps(frame, separators=(",", ":")).encode("utf-8")


def parse_frame(raw):
    """Validates structure and sizes. Returns (device, key_id, seq, nonce, ciphertext, tag)."""
    try:
        frame = json.loads(raw)
        h = frame["h"]
        if set(h) != {"v", "dev", "kid", "seq"} or h["v"] != 1:
            raise FrameError("bad header")
        device, key_id, seq = h["dev"], h["kid"], h["seq"]
        if not (isinstance(device, str) and isinstance(key_id, str)):
            raise FrameError("bad header types")
        if type(seq) is not int or not 0 <= seq < MAX_SEQ:
            raise FrameError("bad sequence")
        nonce = base64.b64decode(frame["n"], validate=True)
        ciphertext = base64.b64decode(frame["c"], validate=True)
        tag = base64.b64decode(frame["t"], validate=True)
    except FrameError:
        raise
    except Exception as exc:  # any malformed input is a structural rejection
        raise FrameError(f"malformed frame: {exc}") from exc
    if len(nonce) != NONCE_LEN or len(tag) != TAG_LEN or len(ciphertext) != PAYLOAD_LEN:
        raise FrameError("bad sizes")
    return device, key_id, seq, nonce, ciphertext, tag


def load_key(run_dir, key_id):
    """Returns (key, nonce_prefix) provisioned for key_id."""
    with open(os.path.join(run_dir, "keys.json")) as f:
        entry = json.load(f)[key_id]
    return bytes.fromhex(entry["key"]), bytes.fromhex(entry["prefix"])


# ----------------------------------------------------------------------- state
def open_db(path):
    db = sqlite3.connect(path, isolation_level=None)  # explicit transactions
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=FULL")
    return db


def persist_confirmed(db, sql, args):
    """Runs one update in an explicit transaction; returns only after COMMIT."""
    db.execute("BEGIN IMMEDIATE")
    try:
        if db.execute(sql, args).rowcount != 1:
            raise sqlite3.Error("state record not found")
        db.execute("COMMIT")
    except BaseException:
        db.execute("ROLLBACK")
        raise


def fail_state(message):
    emit(ev="state_error", message=message)
    sys.exit(STATE_ERROR_EXIT_CODE)


# -------------------------------------------------- events and fault injection
def emit(**event):
    """One JSON line on stdout; the controller reads these as experiment events."""
    print(json.dumps(event), flush=True)


class CrashPoint:
    """Abrupt process death (no cleanup) at the Nth hit of a named point."""

    def __init__(self, point, after):
        self.point, self.after, self.hits = point, after, 0

    def hit(self, name):
        if name != self.point:
            return
        self.hits += 1
        if self.hits == self.after:
            emit(ev="crash", point=name)
            os._exit(CRASH_EXIT_CODE)
