"""Receiver: verifies tag, applies strict-monotonic replay control, persists, then delivers.

Fault points: F4 before persisting the highest accepted sequence h, F5 after persisting it.
"""
import argparse
import json
import os
import sqlite3
import time

import paho.mqtt.client as mqtt

from . import common as c


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--volatile-history", action="store_true",
                    help="insecure control: keep h in RAM only")
    ap.add_argument("--device", default="dev-1")
    ap.add_argument("--key-id", default="k1")
    ap.add_argument("--crash-at", choices=["F4", "F5"])
    ap.add_argument("--crash-after", type=int, default=0)
    a = ap.parse_args()

    key, prefix = c.load_key(a.dir, a.key_id)
    context = (a.device, a.key_id)
    crash = c.CrashPoint(a.crash_at, a.crash_after)
    db = None
    h = -1
    if not a.volatile_history:
        path = os.path.join(a.dir, "receiver.db")
        if not os.path.exists(path):
            c.fail_state("receiver state file missing")
        try:
            db = c.open_db(path)
            row = db.execute("SELECT highest FROM receiver_state WHERE device_id=? AND key_id=?",
                             context).fetchone()
        except sqlite3.Error as exc:
            c.fail_state(f"receiver state unreadable: {exc}")
        if row is None or type(row[0]) is not int or row[0] < -1:
            c.fail_state("receiver state record missing or invalid")
        h = row[0]

    def reject(reason, **extra):
        c.emit(ev="rejected", reason=reason, h=h, **extra)

    def receive(raw):  # Algorithm 2; callbacks run one at a time on the MQTT thread
        nonlocal h
        t0 = time.perf_counter()
        try:
            device, key_id, q, nonce, ct, tag = c.parse_frame(raw)
        except c.FrameError:
            return reject("structure")
        if (device, key_id) != context or nonce != c.make_nonce(prefix, q):
            return reject("structure")
        try:
            plaintext = c.decrypt(key, nonce, ct, c.header_bytes(device, key_id, q), tag)
        except ValueError:
            return reject("auth")  # state untouched
        sample = json.loads(plaintext)["sample"]
        if q <= h:
            return reject("replay", seq=q, sample=sample)  # duplicate or out of order
        crash.hit("F4")
        persisted = 0
        if db is not None:
            c.persist_confirmed(
                db, "UPDATE receiver_state SET highest=? WHERE device_id=? AND key_id=?",
                (q, device, key_id))
            persisted = 1
        h = q
        crash.hit("F5")
        c.emit(ev="accepted", seq=q, sample=sample, persisted=persisted,
               prep_us=int((time.perf_counter() - t0) * 1e6))

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="receiver-1",
                         protocol=mqtt.MQTTv311, clean_session=False)
    client.on_connect = lambda cl, *args: cl.subscribe(c.TOPIC, qos=1)
    client.on_subscribe = lambda *args: c.emit(ev="ready", h=h)
    client.on_message = lambda cl, userdata, msg: receive(msg.payload)
    client.connect("127.0.0.1", a.port)
    client.loop_forever()


if __name__ == "__main__":
    main()
