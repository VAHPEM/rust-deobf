"""scripts/bench_emu.py: the engine benchmark is a measurement tool, so what it must guarantee is
that every number it prints comes from equal, correct work -- checked here at small sizes.
icicle-emu is optional: its rows are tested only when it is installed."""
import json
import subprocess
import sys

import pytest
from conftest import ROOT

sys.path.insert(0, str(ROOT / "scripts"))
pytest.importorskip("unicorn")
import bench_emu as B  # noqa: E402

BENIGN = ROOT / "tests" / "fixtures" / "vm" / "benign_rust_std.x64"
PACKED = ROOT / "tests" / "fixtures" / "pack" / "packed_xor.elf64"
needs_icicle = pytest.mark.skipif(not B.icicle_available(), reason="icicle-emu not installed")


def test_selftest():
    B._selftest()


def test_loop_rows_are_correct_and_counted():
    rows = B.bench_loop(n=2048, repeat=1)
    assert {r["arch"] for r in rows} == {"x86_64", "i686", "aarch64"}
    for r in rows:
        assert r["ok"], r
        assert r["insns"] == B.LOOP[r["arch"]][1] * 2048 + B.LOOP[r["arch"]][2]


def test_hook_rows_track_the_same_pages():
    rows = B.bench_hooks(n=3 * 4096, repeat=1, step_n=128)
    assert all(r["ok"] for r in rows), [r for r in rows if not r["ok"]]
    by = {(r["engine"], r["hooks"]): r for r in rows}
    # Unicorn's write-protection tracking: one fault per page, every store kept
    assert by[("unicorn", "page-fault write tracking")]["faults"] == 3
    assert by[("unicorn", "block, raw ctypes cb")]["py_calls"] == by[("unicorn", "block")]["py_calls"]


@needs_icicle
def test_icicle_rows():
    rows = B.bench_hooks(n=2 * 4096, repeat=1, step_n=64)
    by = {(r["engine"], r["hooks"]): r for r in rows}
    assert by[("icicle", "none")]["ok"]
    assert by[("icicle", "page-fault write tracking")]["faults"] == 2
    assert by[("icicle", "step(1) per instruction")]["insns"] == 5 * 64 + 1


@pytest.mark.skipif(not BENIGN.is_file(), reason="benign fixture missing")
def test_funcs_equal_work():
    f = B.bench_funcs(BENIGN, k=10, budget=3000, passes=1)
    assert f["functions"] == 10 and f["insns"] > 0
    if B.icicle_available():
        # both engines must end every function in the same register + memory state
        assert f["equal_end_state"] == "10/10", f.get("mismatched")
    s = f["split"]
    # Both timings must be measured. Their ORDER is not asserted: one pass of 10 short functions
    # is timing noise on a loaded or emulated host (x64 Python on Windows-on-ARM measured the
    # engine-only pass slower than the hooked one), and a unit test must not depend on it.
    assert s["engine_ns_per_insn"] > 0 and s["recover_total_ns_per_insn"] > 0


@pytest.mark.skipif(not PACKED.is_file(), reason="packed fixture missing")
def test_unpack_floor_reaches_the_same_oep():
    u = B.bench_unpack(PACKED, repeat=1)
    assert u.get("floor_reached_oep") is True, u


def test_cli_json():
    out = subprocess.run([sys.executable, str(ROOT / "scripts" / "bench_emu.py"), "--workload", "loop",
                          "--quick", "--json"], capture_output=True, text=True, timeout=300)
    assert out.returncode == 0, out.stderr
    d = json.loads(out.stdout)
    assert d["host"]["unicorn"] and all(r["ok"] for r in d["loop"])
