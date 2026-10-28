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


# ---- regressions (review B): junk-byte resync, no-.text error path, benign Go/cgo false positives

def test_sweep_survives_undecodable_byte():
    class Junk:
        arm = False; x32 = False; text_va = 0x1000                         # noqa: E702
        code = b"\x06" + bytes.fromhex("0f31" "0fa2" "0f05") + b"\x06" + bytes.fromhex("0f31c3")
    c = A._count_insns(Junk())
    assert c["rdtsc"] == 2 and c["cpuid"] == 1 and c["syscall"] == 1, c


def test_evasion_error_keeps_provenance_and_json(monkeypatch, capsys):
    import json
    import recover_emulate

    def no_text(_p):
        raise ValueError("no .text")
    monkeypatch.setattr(recover_emulate, "Image", no_text)
    res = A.recover(FIXTURE)
    assert res["evasion"] == {"error": "ValueError: no .text"}
    assert res["provenance"]["format"] == "ELF"
    assert A.main([str(FIXTURE), "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert "error" in out["evasion"] and out["provenance"]["format"] == "ELF"


def test_blob_matching_context():
    assert not A._blob_hits(b"\x00net/http/httptrace\x00", "ptrace", False)       # inside a word
    assert not A._blob_hits(b"*runtime.ptracestate\x00", "ptrace", False)
    assert not A._blob_hits(b"\x9a\x8eqemu\xb4\xb8", "qemu", False)                 # chance bytes
    assert A._blob_hits(b"\x00qemu\x00", "qemu", False)
    assert A._blob_hits(b"\x00ptrace\x00", "ptrace", False)
    assert not A._blob_hits(b"\x00syscall.ptrace\x00", "ptrace", True)            # Go std stub
    assert A._blob_hits(b"\x00syscall.ptrace\x00", "ptrace", False)
    assert A._blob_hits(b"\x00main.ptrace\x00", "ptrace", True)                   # the sample's own
    assert A._name_hits(["isdebuggerpresent"], "isdebuggerpresent")
    assert A._name_hits(["outputdebugstringw"], "outputdebugstring")
    assert A._name_hits(["clock_gettime@glibc_2.17"], "clock_gettime")
    assert not A._name_hits(["runtime.ptracestate", "gptrace"], "ptrace")


def _gobuild(tmp_path, src, cgo):
    import os
    (tmp_path / "g.go").write_text(src)
    out = tmp_path / "g"
    r = subprocess.run(["go", "build", "-o", str(out), str(tmp_path / "g.go")], capture_output=True,
                       text=True, cwd=tmp_path, env=dict(os.environ, CGO_ENABLED="1" if cgo else "0"))
    if r.returncode != 0:
        pytest.skip("go build failed: " + r.stderr.strip()[-200:])
    return out


@pytest.mark.skipif(not shutil.which("go"), reason="go not available")
@pytest.mark.parametrize("cgo", [False, True])
def test_benign_go_not_flagged(tmp_path, cgo):
    """Every Go binary carries runtime syscall stubs (syscall.ptrace, raw syscall/rdtsc/cpuid in the
    runtime, the vdso clock_gettime lookup); a cgo build is also dynamically linked. None of that is
    the sample's evasion."""
    src = ('package main\nimport ("fmt";"net";"os";"time")\n'
           'func main(){ a, err := net.LookupHost("localhost"); fmt.Println(a, err, time.Now(), os.Getpid()) }\n')
    p = _gobuild(tmp_path, src, cgo)
    e = A.evasion(p)
    assert e["go_runtime_filtered"]
    assert e["techniques"] == [], e
    assert not e["likely_direct_syscalls"]
    assert "anti-debug" not in e["evasion_apis"] and "sandbox/vm" not in e["evasion_apis"]
    assert e["instruction_counts"]["go_runtime_excluded"] > 0
    if cgo and e["dynamic"]:
        assert e["syscall_instructions"] < 8


@pytest.mark.skipif(not shutil.which("gcc"), reason="gcc not available")
def test_real_anti_debug_still_flagged(tmp_path):
    (tmp_path / "pt.c").write_text(
        "#include <stdio.h>\n#include <sys/ptrace.h>\n#include <x86intrin.h>\n"
        "int main(void){unsigned long long t0=__rdtsc();long r=ptrace(PTRACE_TRACEME,0,0,0);"
        "printf(\"%ld %llu\\n\",r,__rdtsc()-t0);return 0;}\n")
    out = tmp_path / "pt"
    r = subprocess.run(["gcc", "-O1", "-s", str(tmp_path / "pt.c"), "-o", str(out)], capture_output=True, text=True)
    if r.returncode != 0:
        pytest.skip("gcc failed: " + r.stderr[-200:])
    e = A.evasion(out)
    assert "anti-debug" in e["techniques"] and "timing-check (rdtsc)" in e["techniques"], e
    assert e["evasion_apis"]["anti-debug"] == ["ptrace"]
