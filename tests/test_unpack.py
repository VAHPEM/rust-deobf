"""Static unpacking emulator (scripts/unpack_emulate.py).

The --selftest (run via test_selftests.py) is the deterministic positive: a hand-assembled in-place
unpacker that stores a `ret` into a writable page and jumps there -- the emulator must carve that
write-then-execute region out. Here we pin the metrics and, crucially, *precision*: a normal binary
emulated from its entry must not be reported as self-unpacking.
"""
import sys

import pytest
from conftest import ROOT

sys.path.insert(0, str(ROOT / "scripts"))
pytest.importorskip("unicorn")
import unpack_emulate as U  # noqa: E402

BENIGN = ROOT / "tests" / "fixtures" / "vm" / "benign_rust_std.x64"


def test_selftest():
    U._selftest()


def test_entropy_and_printable():
    assert U._entropy(b"") == 0.0
    assert U._entropy(b"\x00" * 100) == 0.0
    assert U._entropy(bytes(range(256))) == pytest.approx(8.0, abs=0.01)
    assert U._printable_ratio(b"config.json") == 1.0
    assert U._printable_ratio(b"\x00\xff\x01\xfe") == 0.0


@pytest.mark.skipif(not BENIGN.is_file(), reason="benign fixture missing")
def test_precision_no_false_unpack_on_normal_binary():
    res = U.recover(BENIGN)
    assert res["arch"] == "x86_64"
    # a normal program is not a self-unpacker: nothing written-then-executed should be claimed
    assert res["unpacked_detected"] is False
    # result shape is stable for an agent/MCP consumer
    assert set(res) >= {"arch", "entry", "stopped", "unpacked", "unpacked_detected"}
    for r in res["unpacked"]:
        assert not r["executed"], f"unexpected W^X region in a benign binary: {r}"


@pytest.mark.skipif(not BENIGN.is_file(), reason="benign fixture missing")
def test_json_shape_has_no_private_keys():
    # recover() keeps _regions for --dump; the CLI strips it. Confirm the documented public keys.
    res = U.recover(BENIGN)
    pub = {k: v for k, v in res.items() if not k.startswith("_")}
    assert "unpacked" in pub and isinstance(pub["unpacked"], list)
