"""Emitter: synthetic telemetry encrypted with AES-256-GCM and published over MQTT.

Nonce policies: C0 volatile counter, C1 persist before each encryption, C2 reserve blocks.
Fault points: F1 before reserve commit, F2 after reserve commit, F3 after encryption.
"""
import argparse
import json
import os
import sqlite3
import threading
import time

import paho.mqtt.client as mqtt

from . import common as c


def connect(port):
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="emitter-1",
                         protocol=mqtt.MQTTv311)
    connected = threading.Event()
    client.on_connect = lambda *a: connected.set()
    client.connect("127.0.0.1", port)
    client.loop_start()
    if not connected.wait(10):
        raise SystemExit("broker connection timeout")
    return client


def load_limit(run_dir, device, key_id):
    """Recovers the persistent limit L; any problem aborts (no automatic reset)."""
    path = os.path.join(run_dir, "emitter.db")
    if not os.path.exists(path):
        c.fail_state("emitter state file missing")
    try:
        row = c.open_db(path).execute(
            "SELECT limit_value FROM emitter_state WHERE device_id=? AND key_id=?",
            (device, key_id)).fetchone()
    except sqlite3.Error as exc:
        c.fail_state(f"emitter state unreadable: {exc}")
    if row is None or type(row[0]) is not int or not 0 <= row[0] <= c.MAX_SEQ:
        c.fail_state("emitter state record missing or invalid")
    return row[0]


def telemetry(sample):
    body = json.dumps({"sample": sample, "ts": time.time(), "temp": 20 + sample % 10,
                       "hum": 40 + sample % 20}, separators=(",", ":")).encode()
    return body.ljust(c.PAYLOAD_LEN, b" ")  # pad with spaces to 128 bytes


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--policy", choices=["C0", "C1", "C2"], required=True)
    ap.add_argument("--block", type=int, default=1, help="reserve size B for C2")
    ap.add_argument("--first-sample", type=int, default=0)
    ap.add_argument("--samples", type=int, required=True)
    ap.add_argument("--rate", type=float, default=10, help="messages/s, 0 = unthrottled")
    ap.add_argument("--device", default="dev-1")
    ap.add_argument("--key-id", default="k1")
    ap.add_argument("--crash-at", choices=["F1", "F2", "F3"])
    ap.add_argument("--crash-after", type=int, default=0)
    a = ap.parse_args()

    key, prefix = c.load_key(a.dir, a.key_id)
    protected = a.policy != "C0"
    B = a.block if a.policy == "C2" else 1
    crash = c.CrashPoint(a.crash_at, a.crash_after)

    if protected:
        s = u = load_limit(a.dir, a.device, a.key_id)  # validates state before use
        db = c.open_db(os.path.join(a.dir, "emitter.db"))
    else:
        s = 0  # volatile counter restarts at zero after every reboot
    c.emit(ev="init", s=s)
    client = connect(a.port)

    start = time.monotonic()
    for i in range(a.samples):
        if a.rate > 0:  # pace messages
            time.sleep(max(0, start + i / a.rate - time.monotonic()))
        t0 = time.perf_counter()
        if s >= c.MAX_SEQ:
            c.emit(ev="exhausted")
            raise SystemExit(c.EXHAUSTED_EXIT_CODE)
        persisted = 0
        if protected and s == u:
            if s + B > c.MAX_SEQ:
                c.emit(ev="exhausted")
                raise SystemExit(c.EXHAUSTED_EXIT_CODE)
            crash.hit("F1")
            c.persist_confirmed(
                db, "UPDATE emitter_state SET limit_value=? WHERE device_id=? AND key_id=?",
                (s + B, a.device, a.key_id))
            persisted = 1
            crash.hit("F2")
            u = s + B
        q, s = s, s + 1
        nonce = c.make_nonce(prefix, q)
        ct, tag = c.encrypt(key, nonce, telemetry(a.first_sample + i),
                            c.header_bytes(a.device, a.key_id, q))
        frame = c.build_frame(a.device, a.key_id, q, nonce, ct, tag)
        prep_us = int((time.perf_counter() - t0) * 1e6)
        c.emit(ev="encrypted", sample=a.first_sample + i, seq=q, kid=a.key_id,
               nonce=nonce.hex(), persisted=persisted, prep_us=prep_us, frame=frame.decode())
        crash.hit("F3")
        client.publish(c.TOPIC, frame, qos=1).wait_for_publish(10)
    c.emit(ev="done")


if __name__ == "__main__":
    main()
