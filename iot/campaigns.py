"""Experiment campaigns and CLI.  Usage: python -m iot.campaigns <campaign> [options]."""
import argparse
import csv
import fcntl
import io
import json
import os
import shutil
import signal
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import time

from . import common as c
from .harness import ROOT, Run

CONFIGS = [("C0", "C0", 1), ("C1", "C1", 1), ("C2-16", "C2", 16),
           ("C2-64", "C2", 64), ("C2-256", "C2", 256)]


class Ctx:
    def __init__(self, a):
        self.runs, self.samples, self.rate = a.runs, a.samples, a.rate
        self.out = a.out
        self.resume = a.resume
        self.active = []
        os.makedirs(self.out, exist_ok=True)
        manifest = os.path.join(self.out, "parameters.json")
        parameters = {"samples": self.samples, "rate": self.rate}
        if os.path.exists(manifest):
            with open(manifest) as f:
                if json.load(f) != parameters:
                    raise ValueError("Output parameters differ; use another --out directory")
        elif any(os.path.exists(os.path.join(self.out, f"{n}.csv")) for n in
                 ("continuous", "emitter_restart", "directed", "receiver_restart")):
            # Old versions did not record parameters. Only adopt the original
            # full-specification results; do not mix them with quick runs.
            if not self.resume or parameters != {"samples": 1000, "rate": 10}:
                raise ValueError("Legacy CSVs require --resume with the original default parameters")
        atomic_write(manifest, json.dumps(parameters, indent=2) + "\n")
        self.work = tempfile.mkdtemp(prefix="work-", dir=ROOT if a.keep else None)
        self.keep = a.keep

    def points(self):  # 250/500/750 for 1000 samples
        return [self.samples // 4, self.samples // 2, 3 * self.samples // 4]

    def run(self, policy, block):
        r = Run(self.work, policy, block, self.rate)
        self.active.append(r)
        return r

    def finish(self, r):
        m = r.metrics()
        r.close()
        self.active.remove(r)
        if not self.keep:
            shutil.rmtree(r.dir, ignore_errors=True)
        return m

    def close(self):
        for r in self.active:
            r.close()
        self.active.clear()


def atomic_write(path, content):
    """Keep the previous checkpoint intact until its replacement is durable."""
    if os.path.exists(path):
        with open(path, newline="") as f:
            if f.read() == content:
                return
    fd, tmp = tempfile.mkstemp(prefix=".checkpoint-", dir=os.path.dirname(path))
    try:
        with os.fdopen(fd, "w", newline="") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        directory = os.open(os.path.dirname(path), os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


class CheckpointRows(list):
    """Save each completed scenario and skip only matching, persisted rows."""

    def __init__(self, ctx, name, *keys):
        super().__init__()
        self.ctx, self.name, self.keys = ctx, name, ("config", "run", *keys)
        self.completed = set()
        path = os.path.join(ctx.out, f"{name}.csv")
        if not os.path.exists(path):
            return
        if not ctx.resume:
            raise ValueError(f"{path} already exists; use --resume or another --out")
        with open(path, newline="") as f:
            for raw in csv.DictReader(f):
                row = {}
                for key, value in raw.items():
                    if key is None or value is None:
                        raise ValueError(f"Malformed checkpoint: {path}")
                    if key in ("config", "point", "failure", "history",
                               "rejections", "lost_samples", "recovery_s"):
                        row[key] = value
                    elif value in ("True", "False"):
                        row[key] = value == "True"
                    else:
                        row[key] = json.loads(value) if value else None
                for field in ("rejections", "lost_samples", "recovery_s"):
                    json.loads(row[field])
                identity = self.identity(row)
                if identity in self.completed:
                    raise ValueError(f"Duplicate checkpoint row in {path}: {identity}")
                self.completed.add(identity)
                super().append(row)
        print(f"[{name}] loaded {len(self)} completed scenarios", flush=True)

    def identity(self, row):
        return tuple(str(row[k]) for k in self.keys)

    def has(self, label, run_idx, **extra):
        return self.identity({"config": label, "run": run_idx, **extra}) in self.completed

    def append(self, row):
        identity = self.identity(row)
        if identity in self.completed:
            raise ValueError(f"Scenario already saved: {identity}")
        super().append(row)
        save(self.ctx, self.name, self, quiet=True)
        self.completed.add(identity)


def flatten(label, run_idx, m, extra=None):
    row = {"config": label, "run": run_idx, **(extra or {})}
    for k, v in m.items():
        row[k] = json.dumps(v) if isinstance(v, (dict, list)) else v
    return row


def save(ctx, name, rows, quiet=False):
    path = os.path.join(ctx.out, f"{name}.csv")
    fields = list(dict.fromkeys(k for r in rows for k in r))
    buf = io.StringIO(newline="")
    w = csv.DictWriter(buf, fieldnames=fields)
    w.writeheader()
    w.writerows(rows)
    atomic_write(path, buf.getvalue())
    if not quiet:
        print(f"[{name}] {len(rows)} rows -> {path}")
    return path


def summarize(rows, keys):
    """Per group: median across runs of the main metrics, plus min..max spread."""
    groups = {}
    for r in rows:
        groups.setdefault(tuple(r.get(k) for k in keys), []).append(r)
    cols = ["encryptions", "nonce_reuse", "duplicate_acceptances", "emitter_transactions",
            "receiver_transactions", "discarded_sequences", "prep_median_us", "prep_p95_us",
            "lost"]
    print("\n" + " | ".join([*keys, *cols, "recovered", "recovery_median_s"]))
    for g, rs in groups.items():
        cells = list(g)
        for col in cols:
            if col == "lost":
                vals = [sum(json.loads(r["lost_samples"]).values()) for r in rs]
            else:
                vals = [r[col] for r in rs if r[col] is not None]
            cells.append(f"{statistics.median(vals):g} [{min(vals):g}..{max(vals):g}]"
                         if vals else "-")
        rec = [x for r in rs for x in json.loads(r["recovery_s"])]
        ok = [x for x in rec if x is not None]
        cells.append(f"{len(ok)}/{len(rec)}" if rec else "-")
        cells.append(f"{statistics.median(ok):.2f}" if ok else "-")
        print(" | ".join(map(str, cells)))


# ------------------------------------------------------------------- campaigns
def continuous(ctx):
    """Campaign 1: continuous operation without faults."""
    rows = CheckpointRows(ctx, "continuous")
    for i in range(ctx.runs):
        order = CONFIGS[i % len(CONFIGS):] + CONFIGS[:i % len(CONFIGS)]  # alternate order
        for label, policy, block in order:
            if rows.has(label, i):
                continue
            r = ctx.run(policy, block)
            r.start_receiver()
            r.start_emitter(0, ctx.samples).wait(ctx.samples / max(ctx.rate, 1) + 120
                                                 if ctx.rate else 300)
            r.drain()
            rows.append(flatten(label, i, ctx.finish(r)))
            print(f"  continuous {label} run {i} done", flush=True)
    save(ctx, "continuous", rows)
    summarize(rows, ["config"])


def emitter_failure(ctx, label, policy, block, point, after, total):
    """One emitter crash at `point` (nth hit) and restart with the same state files."""
    r = ctx.run(policy, block)
    r.start_receiver()
    e = r.start_emitter(0, total, point, after)
    code = e.wait(total / max(ctx.rate, 1) + 120 if ctx.rate else 300)
    if code == c.CRASH_EXIT_CODE:
        last = r.max_sample()
        r.mark_restart()  # restart command
        if point == "F3":  # frame was encrypted but never published: retransmit it
            r.publish(r.of("emitter", "encrypted")[-1]["frame"])
        r.start_emitter(last + 1, total - (last + 1)).wait(
            total / max(ctx.rate, 1) + 120 if ctx.rate else 300)
    r.drain()
    return ctx.finish(r), code == c.CRASH_EXIT_CODE


def emitter_restart(ctx):
    """Campaign 2: emitter restarts after 250/500/750 completed encryptions, F3 crash."""
    rows = CheckpointRows(ctx, "emitter_restart", "restart_after")
    for i in range(ctx.runs):
        for label, policy, block in CONFIGS:
            for k in ctx.points():
                if rows.has(label, i, restart_after=k):
                    continue
                m, crashed = emitter_failure(ctx, label, policy, block, "F3", k, ctx.samples)
                rows.append(flatten(label, i, m, {"restart_after": k, "crashed": crashed}))
                print(f"  emitter-restart {label} k={k} run {i} done", flush=True)
    save(ctx, "emitter_restart", rows)
    summarize(rows, ["config", "restart_after"])


def directed(ctx):
    """Directed tests: F1-F3 and reserve-block transitions, only pertinent points."""
    rows = CheckpointRows(ctx, "directed", "point", "occurrence")
    for i in range(ctx.runs):
        for label, policy, block in CONFIGS:
            if policy == "C0":
                cases = [("F3", 1), ("F3", 2)]
            elif policy == "C1":
                cases = [(p, n) for p in ("F1", "F2", "F3") for n in (1, 2)]
            else:  # first reserve, and the transition between reserve 1 and 2
                cases = [("F1", 1), ("F1", 2), ("F2", 1), ("F2", 2),
                         ("F3", 1), ("F3", block), ("F3", block + 1)]
            for point, n in cases:
                if rows.has(label, i, point=point, occurrence=n):
                    continue
                encryptions_needed = n if point == "F3" else (n - 1) * block + 1
                total = min(ctx.samples, encryptions_needed + 30)
                m, crashed = emitter_failure(ctx, label, policy, block, point, n, total)
                rows.append(flatten(label, i, m, {"point": point, "occurrence": n,
                                                  "crashed": crashed}))
                print(f"  directed {label} {point}#{n} run {i} done", flush=True)
    save(ctx, "directed", rows)
    summarize(rows, ["config", "point", "occurrence"])


def pick_replays(r, count=20):
    """Frames whose acceptance was confirmed before the failure (evenly spaced)."""
    accepted = {e["sample"] for e in r.of("receiver", "accepted")}
    frames = [e["frame"] for e in r.of("emitter", "encrypted") if e["sample"] in accepted]
    step = max(1, len(frames) // count)
    return frames[::step][:count], {e["sample"] for e in r.of("emitter", "encrypted")
                                   if e["frame"] in frames[::step][:count]}


def receiver_failure(ctx, mode, volatile, k, total):
    """mode: receiver | both | F4 | F5. Emitter stays in C1."""
    r = ctx.run("C1", 1)
    wait = total / max(ctx.rate, 1) + 120 if ctx.rate else 300
    rx = r.start_receiver(volatile, mode if mode in ("F4", "F5") else None, k)
    if mode == "both":  # emitter produces k samples, stops; then both ends restart
        r.start_emitter(0, k).wait(wait)
        r.drain()
        em = None
    else:
        em = r.start_emitter(0, total)
    if mode in ("F4", "F5"):
        if rx.wait(wait) != c.CRASH_EXIT_CODE:
            raise RuntimeError(f"Receiver did not reach {mode}#{k}; logs: {r.dir}")
        os.kill(em.p.pid, signal.SIGSTOP)  # keep emitter frozen while we recover
    elif mode == "receiver":
        if not r.wait_for(lambda: r.count("receiver", "accepted") >= k, wait):
            raise RuntimeError(f"Receiver did not accept {k} samples; logs: {r.dir}")
        os.kill(em.p.pid, signal.SIGSTOP)  # no new traffic during the failure window
        r.drain(0.5)
    frames, replay_samples = pick_replays(r)
    n_before = len(r.snapshot())
    rx.kill()  # abrupt (SIGKILL) - no-op if it already crashed itself
    r.mark_restart()
    r.start_receiver(volatile)
    for f in frames:  # attacker re-presents frames accepted before the failure
        r.publish(f)
    r.drain(0.5)
    if mode == "both":
        r.start_emitter(r.max_sample() + 1, total - (r.max_sample() + 1)).wait(wait)
    else:
        os.kill(em.p.pid, signal.SIGCONT)
        em.wait(wait)
    r.drain()
    after = r.snapshot()[n_before:]
    seen = [e for e in after if e["src"] == "receiver" and e.get("sample") in replay_samples
            and (e["ev"] == "accepted" or e.get("reason") == "replay")]
    m = r.metrics()
    m["replays_sent"] = len(frames)
    m["replays_reached"] = len(seen)
    m["replays_accepted"] = sum(e["ev"] == "accepted" for e in seen)
    return ctx.finish(r), m


def receiver_restart(ctx):
    """Campaign 3: receiver / both-ends restarts, volatile vs persistent history."""
    rows = CheckpointRows(ctx, "receiver_restart", "failure", "history", "restart_after")
    scenarios = [("receiver", True), ("receiver", False), ("both", True), ("both", False),
                 ("F4", False), ("F5", False)]
    for i in range(ctx.runs):
        for mode, volatile in scenarios:
            for k in ctx.points():
                hist = "volatile" if volatile else "persistent"
                if rows.has("C1", i, failure=mode, history=hist, restart_after=k):
                    continue
                _, m = receiver_failure(ctx, mode, volatile, k, ctx.samples)
                rows.append(flatten("C1", i, m, {"failure": mode, "history": hist,
                                                 "restart_after": k}))
                print(f"  receiver-restart {mode} {hist} k={k} run {i} done", flush=True)
    save(ctx, "receiver_restart", rows)
    summarize(rows, ["failure", "history", "restart_after"])
    print("\nreplays_sent / reached / accepted (summed per group):")
    groups = {}
    for r in rows:
        g = groups.setdefault((r["failure"], r["history"]), [0, 0, 0])
        g[0] += r["replays_sent"]; g[1] += r["replays_reached"]; g[2] += r["replays_accepted"]
    for g, v in groups.items():
        print(" ", g, v)


def integrity(ctx):
    """Tampering, replay and invalid/missing state checks. Exit code 1 on any failure."""
    results = []
    check = lambda name, ok: (results.append(ok), print(f"  [{'PASS' if ok else 'FAIL'}] {name}"))
    r = Run(ctx.work, "C1", 1, 0)
    if hasattr(ctx, "active"):
        ctx.active.append(r)
    r.start_receiver()
    r.start_emitter(0, 20).wait(60)
    r.drain()
    frames = {e["sample"]: e["frame"] for e in r.of("emitter", "encrypted")}
    check("legitimate frames accepted", r.count("receiver", "accepted") == 20)

    def inject(frame_json, reason):
        n = r.count("receiver", "rejected")
        r.publish(json.dumps(frame_json).encode())
        r.wait_for(lambda: r.count("receiver", "rejected") > n, 5)
        last = r.of("receiver", "rejected")[n:]
        return bool(last) and last[0]["reason"] in reason

    def flip(b64):
        import base64
        raw = bytearray(base64.b64decode(b64))
        raw[0] ^= 1
        return base64.b64encode(bytes(raw)).decode()

    base = json.loads(frames[10])
    check("exact replay rejected", inject(base, {"replay"}))
    check("tampered ciphertext rejected", inject({**base, "c": flip(base["c"])}, {"auth"}))
    check("tampered tag rejected", inject({**base, "t": flip(base["t"])}, {"auth"}))
    check("tampered header (AAD) rejected",
          inject({**base, "h": {**base["h"], "seq": 99}}, {"auth", "structure"}))
    check("tampered nonce rejected", inject({**base, "n": flip(base["n"])},
                                           {"auth", "structure"}))
    check("accepted count unchanged", r.count("receiver", "accepted") == 20)
    with sqlite3.connect(os.path.join(r.dir, "receiver.db")) as db:
        check("receiver history h unchanged by forged frames",
              db.execute("SELECT highest FROM receiver_state").fetchone()[0] == 19)
    r.close()

    def start_code(module, args):
        p = subprocess.run([sys.executable, "-m", f"iot.{module}", "--dir", r.dir, "--port", "1",
                            *args], cwd=ROOT, capture_output=True, timeout=30)
        return p.returncode

    emitter_args = ["--policy", "C1", "--samples", "1"]
    db_path = os.path.join(r.dir, "emitter.db")
    with sqlite3.connect(db_path) as db:
        db.execute("UPDATE emitter_state SET limit_value=-5")
    check("emitter aborts on invalid state", start_code("emitter", emitter_args) == 2)
    with sqlite3.connect(db_path) as db:
        db.execute("DELETE FROM emitter_state")
    check("emitter aborts on missing record", start_code("emitter", emitter_args) == 2)
    for ext in ("", "-wal", "-shm"):
        if os.path.exists(db_path + ext):
            os.remove(db_path + ext)
    check("emitter aborts on missing state file", start_code("emitter", emitter_args) == 2)
    with open(db_path, "wb") as f:
        f.write(b"this is not a sqlite database" * 100)
    check("emitter aborts on corrupt state file", start_code("emitter", emitter_args) == 2)
    with sqlite3.connect(os.path.join(r.dir, "receiver.db")) as db:
        db.execute("DELETE FROM receiver_state")
    check("receiver aborts on missing record", start_code("receiver", []) == 2)
    if not ctx.keep:
        shutil.rmtree(r.dir, ignore_errors=True)
    print(f"\nintegrity: {sum(results)}/{len(results)} checks passed")
    return all(results)


CAMPAIGNS = {"integrity": integrity, "continuous": continuous,
             "emitter-restart": emitter_restart, "directed": directed,
             "receiver-restart": receiver_restart}


def interrupted(signum, frame):
    raise KeyboardInterrupt


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("campaign", choices=[*CAMPAIGNS, "all"])
    ap.add_argument("--runs", type=int, default=10, help="repetitions (spec: 10)")
    ap.add_argument("--samples", type=int, default=1000, help="samples per run (spec: 1000)")
    ap.add_argument("--rate", type=float, default=10, help="msgs/s (spec: 10, 0 = unthrottled)")
    ap.add_argument("--out", default=os.path.join(ROOT, "results"))
    ap.add_argument("--keep", action="store_true", help="keep run directories for inspection")
    ap.add_argument("--resume", action="store_true", help="skip scenarios already saved in CSVs")
    ap.add_argument("--quick", action="store_true", help="2 runs, 300 samples, unthrottled")
    a = ap.parse_args()
    if a.quick:
        a.runs, a.samples, a.rate = 2, 300, 0
    if a.runs < 1 or a.samples < 4 or a.rate < 0:
        ap.error("--runs must be positive, --samples >= 4 and --rate >= 0")
    os.makedirs(a.out, exist_ok=True)
    with open(os.path.join(a.out, ".campaign.lock"), "a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            ap.error("Another campaign is already using this --out directory")
        ctx = Ctx(a)
        ok = True
        completed = False
        old_handler = signal.signal(signal.SIGTERM, interrupted)
        try:
            for name in (CAMPAIGNS if a.campaign == "all" else [a.campaign]):
                print(f"\n=== {name} ===", flush=True)
                ok &= CAMPAIGNS[name](ctx) is not False
            completed = True
        finally:
            signal.signal(signal.SIGTERM, old_handler)
            ctx.close()
            if completed and not a.keep:
                shutil.rmtree(ctx.work, ignore_errors=True)
            elif not completed:
                print(f"Interrupted; completed rows are saved. Diagnostic files: {ctx.work}",
                      flush=True)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
