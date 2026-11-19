"""AES-256-GCM known-answer tests (GCM spec test cases 13-16, 96-bit IV, 128-bit tag)
and frame/AAD behaviour."""
import json
import os

import pytest

from iot import common as c

K0 = bytes(32)
K1 = bytes.fromhex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
IV1 = bytes.fromhex("cafebabefacedbaddecaf888")
P = bytes.fromhex(
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
    "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255")
AAD = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
C_FULL = bytes.fromhex(
    "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
    "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad")

VECTORS = [  # key, iv, plaintext, aad, ciphertext, tag
    (K0, bytes(12), b"", b"", b"", "530f8afbc74536b9a963b4f1c4cb738b"),
    (K0, bytes(12), bytes(16), b"", bytes.fromhex("cea7403d4d606b6e074ec5d3baf39d18"),
     "d0d1c8a799996bf0265b98b5d48ab919"),
    (K1, IV1, P, b"", C_FULL, "b094dac5d93471bdec1a502270e3cc6c"),
    (K1, IV1, P[:60], AAD, C_FULL[:60], "76fc6ece0f4e1768cddf8853bb2d551b"),
]


@pytest.mark.parametrize("key,iv,pt,aad,ct,tag", VECTORS)
def test_known_answers(key, iv, pt, aad, ct, tag):
    out_ct, out_tag = c.encrypt(key, iv, pt, aad)
    assert out_ct == ct and out_tag.hex() == tag
    assert c.decrypt(key, iv, ct, aad, bytes.fromhex(tag)) == pt


def make_frame(seq=7, device="dev-1"):
    key, prefix = os.urandom(32), os.urandom(8)
    nonce = c.make_nonce(prefix, seq)
    ct, tag = c.encrypt(key, nonce, b"x".ljust(c.PAYLOAD_LEN), c.header_bytes(device, "k1", seq))
    return key, nonce, c.build_frame(device, "k1", seq, nonce, ct, tag)


def test_frame_roundtrip_and_aad_binding():
    key, nonce, raw = make_frame()
    device, kid, seq, n, ct, tag = c.parse_frame(raw)
    assert (device, kid, seq, n) == ("dev-1", "k1", 7, nonce)
    assert c.decrypt(key, n, ct, c.header_bytes(device, kid, seq), tag).startswith(b"x")
    with pytest.raises(ValueError):  # header change invalidates the tag
        c.decrypt(key, n, ct, c.header_bytes(device, kid, 8), tag)
    with pytest.raises(ValueError):  # ciphertext change invalidates the tag
        c.decrypt(key, n, bytes([ct[0] ^ 1]) + ct[1:], c.header_bytes(device, kid, seq), tag)


def test_malformed_frames_rejected():
    for raw in (b"not json", b"{}", json.dumps({"h": {}, "n": "", "c": "", "t": ""}).encode()):
        with pytest.raises(c.FrameError):
            c.parse_frame(raw)


def test_nonce_layout():
    assert c.make_nonce(b"\x01" * 8, 258) == b"\x01" * 8 + b"\x00\x00\x01\x02"
