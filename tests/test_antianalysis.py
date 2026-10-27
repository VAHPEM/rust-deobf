"""Anti-analysis inventory + build provenance (recover_antianalysis.py).

The --selftest (instruction counting on hand-assembled bytes) runs via test_selftests.py. This pins
provenance on the committed binary and, with clang, that rdtsc/cpuid evasion instructions are
detected in a program that uses them (and not in one that doesn't).
"""
import shutil
import subprocess
import sys

import pytest
from conftest import ROOT

sys.path.insert(0, str(ROOT / "scripts"))
import recover_antianalysis as A  # noqa: E402

pytestmark = pytest.mark.filterwarnings("ignore::RuntimeWarning")

FIXTURE = ROOT / "tests" / "fixtures" / "vm" / "benign_rust_std.x64"


def test_provenance_on_committed_binary():
    p = A.provenance(FIXTURE)
    assert p["format"] == "ELF" and p["arch"] == "x86_64" and p["bits"] == 64
    assert p["pie"] is True and p["stripped"] is True and p["nx"] is True
    assert "rust" in p["languages"] and p["rust"] and p["rust"]["release"] == "1.97.0"


def test_benign_has_no_evasion():
    e = A.evasion(FIXTURE)
    assert e["instruction_counts"]["rdtsc"] == 0 and e["instruction_counts"]["cpuid"] == 0
    assert not e["likely_direct_syscalls"]


@pytest.mark.skipif(not shutil.which("clang"), reason="clang not available")
def test_rdtsc_cpuid_detected(tmp_path):
    (tmp_path / "e.c").write_text(
        "#include <x86intrin.h>\n#include <stdio.h>\n"
        "int main(){unsigned a,b,c,d;__asm__ volatile(\"cpuid\":\"=a\"(a),\"=b\"(b),\"=c\"(c),"
        "\"=d\"(d):\"a\"(1));unsigned long long t=__rdtsc();printf(\"%u %llu\\n\",a,t);return 0;}\n")
    binp = tmp_path / "e"
    r = subprocess.run(["clang", "-O1", str(tmp_path / "e.c"), "-o", str(binp)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        pytest.skip("clang failed")
    e = A.evasion(binp)
    assert e["instruction_counts"]["rdtsc"] >= 1 and e["instruction_counts"]["cpuid"] >= 1
    assert "cpuid probe" in e["techniques"] and "timing-check (rdtsc)" in e["techniques"]


def test_selftest_runs():
    A._selftest()
