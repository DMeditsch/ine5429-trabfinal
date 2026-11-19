"""Experimental controller infrastructure: provisioning, broker, processes, events, metrics."""
import json
import os
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time

import paho.mqtt.client as mqtt

from . import common as c

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RECOVERY_LIMIT_S = 10.0


def find_mosquitto():
    path = os.environ.get("MOSQUITTO_BIN") or shutil.which("mosquitto") \
        or os.path.join(ROOT, ".mosq", "sbin", "mosquitto")
    if not (path and os.path.exists(path)):
        raise SystemExit("mosquitto not found: install it or set MOSQUITTO_BIN (see README)")
    return path


class Proc:
    """A child process whose stdout JSON lines become timestamped events."""

    def __init__(self, run, module, args):
        self.run, self.name = run, module
        log = open(os.path.join(run.dir, f"{module}.log"), "ab")
        self.p = subprocess.Popen([sys.executable, "-m", f"iot.{module}", *map(str, args)],
                                  cwd=ROOT, stdout=subprocess.PIPE, stderr=log)
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        for line in self.p.stdout:
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            ev.update(src=self.name, t=time.monotonic(), pid=self.p.pid)
            with self.run.lock:
                self.run.events.append(ev)

    def wait(self, timeout):
        try:
            code = self.p.wait(timeout)
        except subprocess.TimeoutExpired:
            return None
        time.sleep(0.2)  # let the reader thread flush the last lines
        return code

    def kill(self):
        if self.p.poll() is None:
            self.p.kill()
            self.p.wait()


class Run:
    """One isolated experiment: provisioned state, own broker, tap client, events."""

    def __init__(self, root, policy, block=1, rate=10):
        os.makedirs(root, exist_ok=True)
        self.dir = tempfile.mkdtemp(prefix="run-", dir=root)
        self.policy, self.block, self.rate = policy, block, rate
        self.events, self.lock, self.restarts, self.procs = [], threading.Lock(), [], []
        self.provision()
        self.start_broker()
        self.tap = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="controller",
                               protocol=mqtt.MQTTv311)
        self.tap.connect("127.0.0.1", self.port)
        self.tap.loop_start()

    # ------------------------------------------------------------ provisioning
    def provision(self, device="dev-1", key_id="k1"):
        keys = {key_id: {"key": os.urandom(32).hex(), "prefix": os.urandom(8).hex()}}
        with open(os.path.join(self.dir, "keys.json"), "w") as f:
            json.dump(keys, f)
        db = c.open_db(os.path.join(self.dir, "emitter.db"))
        db.execute("CREATE TABLE emitter_state(device_id TEXT, key_id TEXT, limit_value INTEGER,"
                   " PRIMARY KEY(device_id, key_id))")
        db.execute("INSERT INTO emitter_state VALUES(?,?,0)", (device, key_id))
        db.close()
        db = c.open_db(os.path.join(self.dir, "receiver.db"))
        db.execute("CREATE TABLE receiver_state(device_id TEXT, key_id TEXT, highest INTEGER,"
                   " PRIMARY KEY(device_id, key_id))")
        db.execute("INSERT INTO receiver_state VALUES(?,?,-1)", (device, key_id))
        db.close()

    def start_broker(self):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            self.port = s.getsockname()[1]
        conf = os.path.join(self.dir, "mosquitto.conf")
        with open(conf, "w") as f:  # max_queued 0 = unlimited queue for offline receiver
            f.write(f"listener {self.port} 127.0.0.1\nallow_anonymous true\n"
                    "persistence false\nmax_queued_messages 0\nlog_dest none\n")
        self.broker = subprocess.Popen([find_mosquitto(), "-c", conf],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", self.port), 0.1).close()
                return
            except OSError:
                time.sleep(0.05)
        raise SystemExit("broker did not start")

    # --------------------------------------------------------------- processes
    def _spawn(self, module, args):
        p = Proc(self, module, ["--dir", self.dir, "--port", self.port, *args])
        self.procs.append(p)
        return p

    def start_emitter(self, first_sample, samples, crash_at=None, crash_after=0):
        args = ["--policy", self.policy, "--block", self.block, "--rate", self.rate,
                "--first-sample", first_sample, "--samples", samples]
        if crash_at:
            args += ["--crash-at", crash_at, "--crash-after", crash_after]
        return self._spawn("emitter", args)

    def start_receiver(self, volatile=False, crash_at=None, crash_after=0, wait_ready=True):
        n = self.count("receiver", "ready")
        args = (["--volatile-history"] if volatile else [])
        if crash_at:
            args += ["--crash-at", crash_at, "--crash-after", crash_after]
        p = self._spawn("receiver", args)
        if wait_ready and not self.wait_for(lambda: self.count("receiver", "ready") > n, 10):
            raise SystemExit("receiver did not become ready")
        return p

    def publish(self, frame):
        raw = frame.encode() if isinstance(frame, str) else frame
        self.tap.publish(c.TOPIC, raw, qos=1).wait_for_publish(10)

    # ------------------------------------------------------------------ events
    def snapshot(self):
        with self.lock:
            return list(self.events)

    def of(self, src, ev):
        return [e for e in self.snapshot() if e["src"] == src and e["ev"] == ev]

    def count(self, src, ev):
        return len(self.of(src, ev))

    def wait_for(self, pred, timeout):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if pred():
                return True
            time.sleep(0.02)
        return False

    def drain(self, idle=1.0, timeout=120):
        """Waits until no receiver event arrives for `idle` seconds."""
        end, last_n, last_t = time.monotonic() + timeout, -1, time.monotonic()
        while time.monotonic() < end:
            n = len([e for e in self.snapshot() if e["src"] == "receiver"])
            if n != last_n:
                last_n, last_t = n, time.monotonic()
            elif time.monotonic() - last_t >= idle:
                return
            time.sleep(0.05)

    def max_sample(self):
        samples = [e["sample"] for e in self.of("emitter", "encrypted")]
        return max(samples) if samples else -1

    def mark_restart(self):
        """Call right when the restart command is issued."""
        self.restarts.append((time.monotonic(), self.max_sample() + 1))

    def close(self):
        for p in self.procs:
            p.kill()
        self.tap.loop_stop()
        self.broker.terminate()
        self.broker.wait()

    # ----------------------------------------------------------------- metrics
    def metrics(self):
        ev = self.snapshot()
        enc = [e for e in ev if e["src"] == "emitter" and e["ev"] == "encrypted"]
        acc = [e for e in ev if e["src"] == "receiver" and e["ev"] == "accepted"]
        rej = [e for e in ev if e["src"] == "receiver" and e["ev"] == "rejected"]
        generated = {e["sample"] for e in enc}
        accepted = {e["sample"] for e in acc}
        lat = sorted(e["prep_us"] for e in enc)
        pct = lambda p: lat[min(len(lat) - 1, int(p * len(lat)))] if lat else None
        reasons = {}
        for e in rej:
            reasons[e["reason"]] = reasons.get(e["reason"], 0) + 1
        lost_reasons = {}
        for s in generated - accepted:  # new, unmodified samples that were never accepted
            r = next((e["reason"] for e in rej if e.get("sample") == s), "not_received")
            lost_reasons[r] = lost_reasons.get(r, 0) + 1
        discarded, last_seq = 0, None
        for e in ev:
            if e["src"] == "emitter" and e["ev"] == "encrypted":
                last_seq = e["seq"]
            elif e["src"] == "emitter" and e["ev"] == "init" and self.policy != "C0" \
                    and last_seq is not None:
                discarded += e["s"] - (last_seq + 1)
        recoveries = []
        for t_cmd, threshold in self.restarts:
            t_new = [e["t"] for e in acc if e["t"] > t_cmd and e["sample"] >= threshold]
            r = min(t_new) - t_cmd if t_new else None
            recoveries.append(r if r is not None and r <= RECOVERY_LIMIT_S else None)
        return {
            "encryptions": len(enc),
            "nonce_reuse": len(enc) - len({(e["kid"], e["nonce"]) for e in enc}),
            "generated": len(generated),
            "accepted_distinct": len(accepted),
            "duplicate_acceptances": len(acc) - len(accepted),
            "rejections": reasons,
            "lost_samples": lost_reasons,
            "emitter_transactions": sum(e["persisted"] for e in enc),
            "receiver_transactions": sum(e["persisted"] for e in acc),
            "discarded_sequences": discarded,
            "prep_median_us": statistics.median(lat) if lat else None,
            "prep_p95_us": pct(0.95),
            "recovery_s": recoveries,  # None = no recovery within the observation limit
        }
