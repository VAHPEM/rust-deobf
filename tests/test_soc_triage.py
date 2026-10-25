"""SOC triage card (soc_triage.py).

The triage wrapper must, from one binary, produce a structured record with the fields a SOC
analyst needs (format/arch, is_rust, capability fingerprint, indicators grouped by tag, a decoded
sample, a calibrated signal) and must filter benign Rust std/compiler paths out of the indicators
so the card is not flooded. Uses --fast (no emulation) against a built canary so the test is quick;
skips if no canary is built.
"""
from pathlib import Path

import pytest
from conftest import ROOT

import soc_triage


def _canary():
    for name in ("obfstr", "litcrypt", "plaintext"):
        p = ROOT / "bench_src" / name / "target" / "release" / name
        if p.is_file():
            return p
    return None


def test_triage_record_shape():
    b = _canary()
    if b is None:
        pytest.skip("no release canary built")
    c = soc_triage.triage(b, fast=True, time_budget=20)
    # required fields
    for k in ("sha256", "format", "arch", "is_rust", "indicators", "triage_signal",
              "decoded_sample", "mode"):
        assert k in c, f"missing {k}"
    assert len(c["sha256"]) == 64
    assert c["is_rust"] is True, "a Rust canary must be detected as Rust"
    assert c["triage_signal"] in ("LOW", "MEDIUM", "HIGH")
    assert c["mode"] == "static"            # --fast => no emulation
    # benign std/compiler paths must be filtered out of the indicators
    flat = [s for vals in c["indicators"].values() for s in vals]
    assert not any("/rustc/" in s or "/rust/deps/" in s for s in flat), \
        f"benign std paths leaked into indicators: {flat[:3]}"


def test_benign_filter():
    assert soc_triage._benign_indicator(
        "/rustc/2d8144b7880597b6e6d3dfd63a9a9efae3f533d3/library/std/src/io/mod.rs")
    assert soc_triage._benign_indicator("/rust/deps/gimli-0.32.3/src/read/abbrev.rs")
    # a real indicator-shaped path must NOT be filtered
    assert not soc_triage._benign_indicator("C:\\ProgramData\\NorthwindSvc\\state.db")
    assert not soc_triage._benign_indicator("/opt/app/resources/data.bin")
