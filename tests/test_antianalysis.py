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


def test_aligned_pointer_bytes_are_not_text():
    # CI run #118, test_benign_go_not_flagged[True] (Go 1.23, cgo, x86-64): .rodata held the pointer
    # 0x4d764b at an 8-aligned offset, bytes `KvM\0\0\0\0\0` -- read case-insensitively as `kvm`
    # and reported as sandbox/vm. The bytes around it, as measured (offset 0x106888):
    table = (b"\x10" + b"\x00" * 7 + b"\x00\x81M" + b"\x00" * 5 + b"JN" + b"\x00" * 6
             + b"\x14" + b"\x00" * 7 + b"KvM" + b"\x00" * 5 + b"JN" + b"\x00" * 6).lower()
    assert table.index(b"kvm") % 8 == 0
    assert not A._blob_hits(table, "kvm", True)          # word defaults to 8
    # text stays text: unaligned, or followed by more bytes in the same word, or a long key
    assert A._blob_hits(b"\x00/dev/kvm\x00", "kvm", True)
    assert A._blob_hits(b"\x00" * 8 + b"kvm\x00qemu\x00", "kvm", True)
    assert A._blob_hits(b"\x00" * 8 + b"vmware\x00\x00", "vmware", True)
    # 32-bit: a 4-aligned C string `kvm\0` is indistinguishable from an integer -- left as text
    assert A._blob_hits(b"\x00" * 4 + b"kvm\x00", "kvm", False, 4)
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


def test_go_packed_strings_do_not_make_an_api_name():
    # Go 1.21 / 1.22 (amd64, the benign program of test_benign_go_not_flagged): the runtime's string
    # data packs `... wrong P` and `trace: out of memory` with no separator. Bytes as measured:
    packed = b"treflect.makeFuncStubdodeltimer0: wrong Ptrace: out of memoryinvalid r".lower()
    assert not A._blob_hits(packed, "ptrace", True, 8, api=True)
    # a NAME still counts in a Go binary: a C string (cgo .dynstr) or the sample's own symbol
    assert A._blob_hits(b"\x00ptrace\x00", "ptrace", True, 8, api=True)
    assert A._blob_hits(b"\x00main.ptrace\x00", "ptrace", True, 8, api=True)
    assert not A._blob_hits(b"\x00syscall.ptrace\x00", "ptrace", True, 8, api=True)   # Go std
    # outside Go, and for non-API keys, the neighbour rules are unchanged
    assert A._blob_hits(packed, "ptrace", False, 8, api=True)
    assert A._blob_hits(b"open /proc/self/status: x", "/proc/self/status", True, 8, api=False)



def test_go_binary_with_packed_runtime_strings_not_anti_debug(tmp_path):
    # end to end through evasion(): a synthetic ELF that recover_go takes for Go (pclntab + version
    # string) carrying the Go 1.22 runtime bytes as measured. Before the fix: anti-debug (ptrace).
    import sys
    sys.path.insert(0, str(ROOT / "tests"))
    import recover_go as GO
    from _mkelf import mkelf
    _, tva, _ = mkelf(b"")
    tab = GO._build_pclntab([(i * 0x10, f"runtime.f{i}") for i in range(16)], text_start=tva)
    packed = b"treflect.makeFuncStubdodeltimer0: wrong Ptrace: out of memoryinvalid r"
    elf, _, _ = mkelf(tab + b"\x00" * 16 + packed + b"\x00go1.22.2\x00" + b"\x00" * 32)
    p = tmp_path / "go122.elf"
    p.write_bytes(elf)
    e = A.evasion(p)
    assert e["go_runtime_filtered"]
    assert "anti-debug" not in e["evasion_apis"] and "anti-debug" not in e["techniques"], e


def test_go_packed_tracerpid_check_is_found(tmp_path):
    # Go 1.26 (measured, cgo amd64): the program's `TracerPid:\t0` and "/proc/self/status" literals
    # sit between other strings with no separator (`archive/zip` before, `exec format error` after);
    # the identifier-neighbour rule rejected both, so the check went unreported
    import sys
    sys.path.insert(0, str(ROOT / "tests"))
    import recover_go as GO
    from _mkelf import mkelf
    _, tva, _ = mkelf(b"")
    tab = GO._build_pclntab([(i * 0x10, f"runtime.f{i}") for i in range(16)], text_start=tva)
    packed = (b"crypto/x509archive/zipTracerPid:\t0illegal seekinvalid s"
              b"randhttpcookiemaxnum/proc/self/statusexec format errorpermission")
    elf, _, _ = mkelf(tab + b"\x00" * 16 + packed + b"\x00go1.26.0\x00" + b"\x00" * 32)
    p = tmp_path / "go126.elf"
    p.write_bytes(elf)
    e = A.evasion(p)
    assert e["go_runtime_filtered"]
    assert e["evasion_apis"].get("anti-debug-artifact") == ["/proc/self/status", "tracerpid"], e
    # ... while the same packing still proves nothing for an identifier-shaped API name
    assert "anti-debug" not in e["evasion_apis"], e


@pytest.mark.parametrize("compressed", [True, False])
def test_key_inside_a_compressed_section_is_not_text(tmp_path, compressed):
    # CI windows/ubuntu run: Go 1.24.13 cgo (runner GOROOT) carried `\nkvm?` inside its zlib-
    # compressed .debug_info -- chance bytes, reported as sandbox/vm. A compressed section's content
    # is never a string; the same bytes in an ordinary section still count (control).
    import lief
    sys.path.insert(0, str(ROOT / "tests"))
    from _mkelf import mkelf
    elf, _, _ = mkelf(b"\xc3")
    b = lief.ELF.parse(list(elf))
    sec = lief.ELF.Section(".debug_info" if compressed else ".comment")
    sec.content = list(b"\xd4\xcfn\x99\xa5\xfe\nkvm?;59(\xae\x14u)w2=")   # the measured bytes
    sec.flags = 0x800 if compressed else 0
    b.add(sec, loaded=False)
    p = tmp_path / "z.elf"
    p.write_bytes(b.write_to_bytes())
    e = A.evasion(p)
    assert ("sandbox/vm" in e["evasion_apis"]) is (not compressed), e["evasion_apis"]
