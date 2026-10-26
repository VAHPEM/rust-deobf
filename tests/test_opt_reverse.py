"""Optimization-reversal pass (premium/opt_reverse.py): jump-table un-switching + unrolled loops.

The --selftest (hand-assembled rel32 jump table + unrolled-loop detection) covers the recogniser
with no toolchain. This also compiles a real dense `match` with rustc and checks the switch is
recovered to an exact {index: target} map (skips if rustc is unavailable, like the other premium
build tests).
"""
import shutil
import struct
import subprocess
import sys

import pytest
from conftest import ROOT

sys.path.insert(0, str(ROOT / "premium"))
sys.path.insert(0, str(ROOT / "scripts"))
import opt_reverse as O  # noqa: E402

pytestmark = pytest.mark.filterwarnings("ignore::RuntimeWarning")


def test_selftest_logic():
    O._selftest()


def test_canonical_subregisters():
    assert O._canon("edi") == "rdi" and O._canon("dil") == "rdi" and O._canon("di") == "rdi"
    assert O._canon("r8d") == "r8" and O._canon("r10w") == "r10"
    assert O._canon("rax") == "rax"


@pytest.mark.skipif(not shutil.which("rustc"), reason="rustc not available")
def test_real_match_jump_table(tmp_path):
    src = tmp_path / "m.rs"
    src.write_text(
        "use std::hint::black_box;\n"
        "#[inline(never)] pub fn d(n:u64)->u64{ match n {\n"
        + "".join(f"    {i} => black_box({10 + i}),\n" for i in range(8))
        + "    _ => black_box(999),\n} }\n"
        "fn main(){ println!(\"{}\", d(black_box(3))); }\n")
    binp = tmp_path / "m"
    r = subprocess.run(["rustc", "-O", str(src), "-o", str(binp)], capture_output=True, text=True)
    if r.returncode != 0:
        pytest.skip("rustc failed: " + r.stderr.strip()[-200:])
    res = O.analyze(binp)
    assert res["arch"] == "x86_64"
    # the 8-arm match must appear as a recovered jump table with exactly 8 bounded cases whose
    # targets all land in .text (an exact un-switch, not a guessed length)
    import recover_emulate as E
    img = E.Image(str(binp))
    eights = [jt for jt in res["jump_tables"] if jt["count"] == 8]
    assert eights, [jt["count"] for jt in res["jump_tables"]]
    for jt in eights:
        assert set(jt["cases"]) == set(range(8))
        for t in jt["cases"].values():
            assert img.text_va <= t < img.text_end
