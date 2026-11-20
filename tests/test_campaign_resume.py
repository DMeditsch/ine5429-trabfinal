"""Regression coverage for interrupted campaigns and resource exhaustion."""
import csv
import gc
import os
from types import SimpleNamespace

import pytest

from iot import campaigns, harness


def context(tmp_path, resume=False):
    return campaigns.Ctx(SimpleNamespace(
        runs=1, samples=300, rate=0, out=str(tmp_path), keep=False, resume=resume))


def test_interrupted_campaign_resumes_only_missing_scenarios(tmp_path, monkeypatch):
    calls = []
    metrics = dict(encryptions=31, nonce_reuse=0, duplicate_acceptances=0,
                   emitter_transactions=2, receiver_transactions=31,
                   discarded_sequences=0, prep_median_us=100.0, prep_p95_us=200,
                   rejections={}, lost_samples={}, recovery_s=[0.1])

    def experiment(ctx, label, policy, block, point, after, total):
        if len(calls) == 3:
            raise RuntimeError("simulated interruption")
        calls.append((label, point, after))
        return metrics, True

    monkeypatch.setattr(campaigns, "emitter_failure", experiment)
    ctx = context(tmp_path)
    with pytest.raises(RuntimeError, match="simulated interruption"):
        campaigns.directed(ctx)
    with (tmp_path / "directed.csv").open() as f:
        original = list(csv.DictReader(f))
    assert len(original) == 3
    first_calls = calls[:]
    calls.clear()

    def resumed(ctx, label, policy, block, point, after, total):
        calls.append((label, point, after))
        return metrics, True

    monkeypatch.setattr(campaigns, "emitter_failure", resumed)
    campaigns.directed(context(tmp_path, resume=True))
    with (tmp_path / "directed.csv").open() as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == 29
    assert rows[:3] == original
    assert len(calls) == 26
    assert not set(first_calls).intersection(calls)
    saved = (tmp_path / "directed.csv").read_bytes()
    calls.clear()
    campaigns.directed(context(tmp_path, resume=True))
    assert not calls
    assert (tmp_path / "directed.csv").read_bytes() == saved
    with pytest.raises(ValueError, match="already exists"):
        campaigns.directed(context(tmp_path))


def test_failed_checkpoint_replace_preserves_previous_file(tmp_path, monkeypatch):
    path = tmp_path / "directed.csv"
    path.write_text("previous results\n")

    def fail(*args):
        raise OSError("disk failure")

    monkeypatch.setattr(os, "replace", fail)
    with pytest.raises(OSError, match="disk failure"):
        campaigns.atomic_write(str(path), "new results\n")
    assert path.read_text() == "previous results\n"
    assert not list(tmp_path.glob(".checkpoint-*"))


def test_resume_rejects_different_parameters(tmp_path):
    context(tmp_path)
    with pytest.raises(ValueError, match="parameters differ"):
        campaigns.Ctx(SimpleNamespace(runs=1, samples=1000, rate=10,
                                     out=str(tmp_path), keep=False, resume=True))


@pytest.mark.skipif(not os.path.isdir("/proc/self/fd"), reason="Linux descriptor check")
def test_completed_runs_release_descriptors_even_when_retained(tmp_path):
    try:
        harness.find_mosquitto()
    except SystemExit:
        pytest.skip("mosquitto not installed")
    gc.collect()
    before = len(os.listdir("/proc/self/fd"))
    retained = []
    # Disable cyclic GC: cleanup must not depend on when Python collects a Run.
    gc.disable()
    try:
        for _ in range(12):
            r = harness.Run(str(tmp_path), "C1", rate=0)
            retained.append(r)
            try:
                rx = r.start_receiver()
                em = r.start_emitter(0, 10)
                assert em.wait(30) == 0
                assert r.wait_for(lambda: r.count("receiver", "accepted") == 10, 5)
            finally:
                r.close()
            assert em.p.stdout.closed and rx.p.stdout.closed
            assert not em.reader.is_alive() and not rx.reader.is_alive()
            assert len(os.listdir("/proc/self/fd")) <= before + 2
        for r in retained:
            r.close()  # cleanup is idempotent
    finally:
        gc.enable()


def test_timeout_kills_child_instead_of_returning_partial_metrics(tmp_path):
    try:
        harness.find_mosquitto()
    except SystemExit:
        pytest.skip("mosquitto not installed")
    r = harness.Run(str(tmp_path), "C1", rate=0)
    try:
        rx = r.start_receiver()
        with pytest.raises(RuntimeError, match="timed out"):
            rx.wait(0.01)
        assert rx.p.poll() is not None
        assert rx.p.stdout.closed
    finally:
        r.close()
