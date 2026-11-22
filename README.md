# AES-GCM over MQTT: security after restarts

## Results and Analysis

The Portuguese analysis of the complete campaigns is available in
[Results Analysis — AES-GCM in IoT](analise/README.md), featuring a description of the
670 trials, an evaluation of the partial report hypotheses, tables, instrumentation
limitations, and chart suggestions. The chart data and reproducible aggregation
script are located in `analise/`.

Software-only implementation of the experiment described in *"AES-GCM em IoT: segurança após reinícios"*:
an emitter encrypts synthetic telemetry with AES-256-GCM and publishes it over MQTT; a receiver verifies,
rejects replays, and decrypts. Three nonce-management policies are compared under controlled crashes,
tampering and replay.

| Policy | Emitter nonce state |
|--------|---------------------|
| **C0** | volatile counter, restarts at 0 after a reboot (deliberately insecure control) |
| **C1** | durable limit persisted *before every* encryption |
| **C2** | durable limit reserved in blocks of B = 16 / 64 / 256 sequences (RFC 5116 style) |

## Architecture

```
            +--------------------- controller (iot/harness.py, campaigns.py) ----------------------+
            | provisions keys/state, starts Mosquitto + processes, injects faults, replays/tampers  |
            +-----------------------------------------------------------------------------------+
   events (stdout JSON) |                       | tap client (replay / tamper / retransmit)
                        v                       v
  emitter.py --MQTT QoS1--> Mosquitto (no keys) --MQTT QoS1--> receiver.py
      |                                                             |
  emitter.db (SQLite)                                        receiver.db (SQLite)
  reserved limit L                                           highest accepted seq h
```

Everything is plain Python, one process per role, no framework:

| File | Role |
|------|------|
| `iot/common.py` | AES-GCM (PyCryptodome), frame format, SQLite helpers (`WAL` + `synchronous=FULL`, explicit transactions), event output, crash points |
| `iot/emitter.py` | Algorithm 1 (C0/C1/C2). Fault points **F1** before reserve commit, **F2** after it, **F3** after encryption/before publish |
| `iot/receiver.py` | Algorithm 2: tag check -> strict `seq > h` -> persist `h` -> deliver. Fault points **F4** before persisting `h`, **F5** after. `--volatile-history` keeps `h` in RAM (control) |
| `iot/harness.py` | Per-run isolated Mosquitto broker, provisioning, process/event handling, metrics |
| `iot/campaigns.py` | CLI and all campaigns |
| `tests/` | NIST/GCM known-answer tests, frame tests, end-to-end integrity test |

Protocol details (as in the paper): AES-256 key, 96-bit nonce = 64-bit emitter prefix || 32-bit big-endian
sequence, 128-bit tag, 128-byte space-padded JSON telemetry, MQTT 3.1.1 QoS 1 without retained messages.
The frame is JSON with Base64 binary fields; the header `{"v","dev","kid","seq"}` (fixed key order, compact,
UTF-8) is the AAD. The receiver uses a persistent MQTT session so frames sent while it is down are
redelivered. Keys live only in `keys.json` of each run (emitter and receiver read it; the broker never does).

Faults are injected by the process itself: at the Nth hit of a crash point it calls `os._exit(99)` (abrupt,
no cleanup, RAM lost, SQLite files kept). The controller then restarts it with the same state files.
Receiver-only/both-ends failures are triggered by the controller with `SIGKILL`.
State is created only at provisioning; a missing or invalid record makes the process exit with code 2 instead
of resetting the counter.

## Setup

Python 3.10+ and an Eclipse Mosquitto binary.

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
# Mosquitto: either system package (do not need the service running)...
sudo apt install mosquitto
# ...or without root, via conda into ./.mosq (found automatically):
conda create -y -p ./.mosq -c conda-forge mosquitto
# or point to any binary: export MOSQUITTO_BIN=/path/to/mosquitto
```

## Running

```bash
.venv/bin/python -m pytest -q                       # known-answer + end-to-end integrity tests
.venv/bin/python -m iot.campaigns integrity         # tampering, replay, missing/invalid state
.venv/bin/python -m iot.campaigns all --quick       # everything, 2 runs x 300 samples, unthrottled (~8 min)
.venv/bin/python -m iot.campaigns all               # full specification (10 runs x 1000 samples @ 10 msg/s; many hours)
.venv/bin/python -m iot.campaigns all --resume      # continue, skipping scenarios already saved
```

Campaigns (`python -m iot.campaigns <name>`), results in `results/<name>.csv` (one row per run) plus a summary
table printed with median [min..max] across runs:

| Name | Paper section | What it does |
|------|---------------|--------------|
| `integrity` | 5.1 | forged ciphertext/tag/header/nonce and exact replay are rejected without touching `h`; absent/invalid/corrupt state aborts emitter and receiver |
| `continuous` | campaign 1 | C0, C1, C2-16/64/256 without faults, configuration order rotated between repetitions |
| `emitter-restart` | campaign 2 | emitter crash at F3 after 250/500/750 encryptions (scaled to `--samples`); the unpublished frame is retransmitted |
| `directed` | campaign 2 | F1-F3 only where pertinent, including the first reserve and the transition between reserves |
| `receiver-restart` | campaign 3 | emitter in C1; receiver or both ends restarted, volatile vs persistent receiver history, plus F4/F5; 20 previously accepted frames are replayed after the restart |

Options: `--runs`, `--samples`, `--rate` (0 = unthrottled), `--out`, `--keep` (keep run dirs/logs), `--quick`,
`--resume`.

Each completed scenario is saved immediately by atomically replacing its campaign CSV. After an
interruption, repeat the same command with `--resume`: only missing scenarios are executed. Existing
CSVs require `--resume` to prevent accidental overwrites. `parameters.json` records the sample count
and rate and prevents mixing different settings; use a different `--out` directory for different
parameters. A directory lock prevents two controllers from writing the same results concurrently.
Legacy CSVs without parameter metadata can be resumed with the original defaults (1000 samples,
10 msg/s). Legacy campaigns interrupted before their final CSV was written must be rerun.
The short `integrity` check runs again on `all --resume`. Unexpected child exits or timeouts abort
without saving the incomplete scenario; completed CSV rows and diagnostic files remain available.

Metrics (CSV columns): `nonce_reuse` (encryptions repeating a key-nonce pair), `duplicate_acceptances`
(replays producing a new acceptance), `replays_sent/reached/accepted` (campaign 3), `rejections` and
`lost_samples` by reason, `emitter_transactions` / `receiver_transactions` (confirmed SQLite commits),
`discarded_sequences` (reserved values dropped after a restart), `prep_median_us` / `prep_p95_us`
(frame preparation: reserve commit if any + encryption + serialization), `recovery_s` (restart command to
first acceptance of a new sample; `null` = none within 10 s).

The transaction counters rely on subsequent encryption/acceptance events: they omit a commit immediately
followed by F2/F5. In F5, acceptance events represent delivery rather than every durable acceptance.
See the [results analysis](analise/README.md) for these measurement limits and the first-reservation discard gap.

## Expected results and caveats

- C0 reuses nonces after a restart (and loses data while the reset sequence is `<= h`); C1/C2 never do.
- C2 cuts emitter transactions by about B and keeps preparation latency near C0's median, at the cost of
  discarding up to B-1 sequences after F3, or a whole unused block of B sequences after F2.
- A persistent receiver rejects all replays; a volatile one accepts them after a restart.
- F5 loses delivery of one message but never accepts it twice (no exactly-once guarantee).
- With `--rate 0` the emitter may finish before a late restart point, so `recovery_s` can be `null` for the
  last restart point; use the default 10 msg/s for the paper's timing.
- Scope as in the paper: process crashes only (no power loss, no key extraction or storage rollback); counts
  of transactions are not a measure of flash wear. The known-answer tests use the GCM specification vectors
  (test cases 13-16, which are part of the NIST validation material) instead of downloading CAVP files.
