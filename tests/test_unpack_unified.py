"""Unified unpacking front end (scripts/unpack.py): static-first, dynamic opt-in behind an ack.

The --selftest (via test_selftests.py) covers stage carving and the static-first dispatch. Here we
check the real static path on the committed packed ELF and, crucially, that the dynamic branch never
runs a sample without the explicit isolation acknowledgement.
"""
import sys

import pytest
from conftest import ROOT

sys.path.insert(0, str(ROOT / "scripts"))
pytest.importorskip("unicorn")
import unpack as U  # noqa: E402

PACKED = ROOT / "tests" / "fixtures" / "pack" / "packed_xor.elf64"
BENIGN = ROOT / "tests" / "fixtures" / "vm" / "benign_rust_std.x64"


def test_selftest():
    U._selftest()


@pytest.mark.skipif(not PACKED.is_file(), reason="packed fixture missing")
def test_static_path_detects_and_carves():
    res = U.recover(PACKED)
    assert res["static"]["unpacked_detected"] is True
    assert res["stages"] and res["stages"][0]["source"] == "static-emulation"
    assert res["stages"][0]["executed"] is True
    assert "static unpacking succeeded" in res["recommendation"]
    # static success must NOT fall through to the dynamic (sample-running) branch
    assert res["dynamic"] is None


@pytest.mark.skipif(not BENIGN.is_file(), reason="benign fixture missing")
def test_dynamic_refused_without_ack():
    # a binary that does not unpack statically + --dynamic but no ack: must refuse, never run it
    res = U.recover(BENIGN, dynamic=True, ack=False)
    assert res["static"]["unpacked_detected"] is False
    assert res["dynamic"] and "refused" in res["dynamic"]["error"]


@pytest.mark.skipif(not BENIGN.is_file(), reason="benign fixture missing")
def test_no_dynamic_recommends_next_steps_safely():
    res = U.recover(BENIGN)  # static only, default
    assert res["dynamic"] is None
    assert "--i-understand-this-executes" in res["recommendation"]
