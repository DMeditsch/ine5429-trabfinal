"""End-to-end smoke test (needs mosquitto; see README)."""
import pytest

from iot import campaigns, harness


def test_integrity_checks(tmp_path):
    try:
        harness.find_mosquitto()
    except SystemExit:
        pytest.skip("mosquitto not installed")
    ctx = type("Ctx", (), {"work": str(tmp_path), "keep": True})()
    assert campaigns.integrity(ctx) is True
