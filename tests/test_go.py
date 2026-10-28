"""Go pclntab metadata recovery (recover_go.py).

The --selftest (synthetic 1.20+ pclntab round-trip) runs via test_selftests.py. This builds a real Go
binary, strips it, and checks the function names + version are still recovered (the point: pclntab
survives strip), and that a non-Go binary is correctly rejected.
"""
import shutil
import subprocess
import sys

import pytest
from conftest import ROOT

sys.path.insert(0, str(ROOT / "scripts"))
import recover_go as GO  # noqa: E402

pytestmark = pytest.mark.filterwarnings("ignore::RuntimeWarning")


def test_synthetic_pclntab_roundtrip():
    GO._selftest()


def test_non_go_binary_rejected():
    res = GO.recover(ROOT / "tests" / "fixtures" / "vm" / "benign_rust_std.x64")
    assert not res["is_go"] or res.get("function_count", 0) == 0


@pytest.mark.skipif(not shutil.which("go"), reason="go not available")
def test_real_stripped_go_binary(tmp_path):
    src = tmp_path / "g.go"
    src.write_text(
        'package main\nimport "fmt"\n'
        '//go:noinline\n'
        'func beacon() string { return fmt.Sprintf("tick-%d", 1) }\n'
        'func main(){ fmt.Println(beacon()) }\n')
    binp = tmp_path / "bin"
    r = subprocess.run(["go", "build", "-o", str(binp), str(src)],
                       capture_output=True, text=True, cwd=tmp_path)
    if r.returncode != 0:
        pytest.skip("go build failed: " + r.stderr.strip()[-200:])
    subprocess.run(["strip", str(binp)], capture_output=True)   # pclntab must survive this
    res = GO.recover(binp)
    assert res["is_go"] and res["function_count"] > 100
    names = set(res["functions"].values())
    assert "main.main" in names and "main.beacon" in names      # our names survive strip
    assert any(n.startswith("runtime.") for n in names)
    assert res["go_version"] and res["go_version"].startswith("go1.")


# ---- regressions (review B): pointer size, whole-section scan, DoS bounds, PE RVAs, version regex

import resource  # noqa: E402
import struct  # noqa: E402
from types import SimpleNamespace  # noqa: E402

_GO_SRC = ('package main\nimport "fmt"\n//go:noinline\n'
           'func beacon() string { return fmt.Sprintf("tick-%d", 1) }\n'
           'func main(){ fmt.Println(beacon()) }\n')


def _gobuild(tmp_path, goos, goarch, name):
    import os
    src = tmp_path / "g.go"
    src.write_text(_GO_SRC)
    out = tmp_path / name
    env = dict(os.environ, GOOS=goos, GOARCH=goarch, CGO_ENABLED="0")
    r = subprocess.run(["go", "build", "-o", str(out), str(src)], capture_output=True, text=True,
                       cwd=tmp_path, env=env)
    if r.returncode != 0:
        pytest.skip(f"go build {goos}/{goarch} failed: " + r.stderr.strip()[-200:])
    return out


@pytest.mark.parametrize("magic", [0xfffffffb, 0xfffffffa, 0xfffffff0, 0xfffffff1])
@pytest.mark.parametrize("ptr", [4, 8])
def test_every_pclntab_version_and_ptr_size(magic, ptr):
    funcs = [(0, "main.main"), (0x10, "runtime.main"), (0x20, "a/b.C")]
    raw = GO._build_pclntab(funcs, text_start=0x8049000, magic=magic, ptr=ptr)
    got = GO.parse_pclntab(raw)["functions"]
    assert got == {0x8049000: "main.main", 0x8049010: "runtime.main", 0x8049020: "a/b.C"}


def test_magic_scan_covers_whole_section():
    """The pclntab of a large Go PE sits megabytes into .rdata; the scan must not stop at 1 MB."""
    names = [(i * 0x10, f"main.f{i}") for i in range(16)]
    tab = GO._build_pclntab(names, text_start=0x401000)
    # a decoy magic with a bad header first, then the real table at 2 MB + 0x2c0
    decoy = struct.pack("<I", 0xfffffff1) + b"\x01\x00\x01\x08" + b"\x00" * 56
    off = (2 << 20) + 0x2c0
    raw = decoy + b"\x00" * (off - len(decoy)) + tab + b"\x00" * 64
    sec = SimpleNamespace(name=".rdata", content=raw, virtual_address=0x1000)
    va, got_raw, named = GO.find_pclntab(SimpleNamespace(sections=[sec]))
    assert va == 0x1000 + off and not named
    assert len(GO.parse_pclntab(got_raw)["functions"]) == 16


def test_crafted_pclntab_bounded():
    """Unterminated names + many entries sharing one name offset must not blow up memory."""
    nfunc, namelen = 400, 1 << 20
    hdr = bytearray(72)
    struct.pack_into("<I", hdr, 0, 0xfffffff1); hdr[6] = 1; hdr[7] = 8
    functab = b"".join(struct.pack("<II", i * 16, nfunc * 8) for i in range(nfunc))
    fstruct = struct.pack("<Ii", 0, 0) + b"\0" * 8
    struct.pack_into("<Q", hdr, 8, nfunc); struct.pack_into("<Q", hdr, 24, 0x401000)
    struct.pack_into("<Q", hdr, 32, 72 + len(functab) + len(fstruct)); struct.pack_into("<Q", hdr, 64, 72)
    raw = bytes(hdr) + functab + fstruct + b"A" * namelen
    before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    res = GO.parse_pclntab(raw)
    grown_mb = (resource.getrusage(resource.RUSAGE_SELF).ru_maxrss - before) >> 10
    assert len(res["functions"]) == nfunc
    assert max(len(n) for n in res["functions"].values()) <= GO._MAX_NAME
    assert grown_mb < 50, grown_mb
    # an nfunc the table cannot hold is rejected outright
    struct.pack_into("<Q", hdr, 8, 10_000_000)
    assert GO.parse_pclntab(bytes(hdr) + functab)["functions"] == {}


def test_go_version_regex_left_anchored():
    assert GO._GO_VER.search(b"xx algo1.5 cargo1.2") is None
    assert GO._GO_VER.search(b"\x00go1.24.7\x00").group() == b"go1.24.7"


@pytest.mark.skipif(not shutil.which("go"), reason="go not available")
@pytest.mark.parametrize("goos,goarch,name", [("linux", "386", "g386"), ("windows", "386", "g386.exe")])
def test_go_386_pointer_size(tmp_path, goos, goarch, name):
    res = GO.recover(_gobuild(tmp_path, goos, goarch, name))
    assert res["is_go"] and res["function_count"] > 100, res.get("function_count")
    assert {"main.main", "main.beacon"} <= set(res["functions"].values())


@pytest.mark.skipif(not shutil.which("go"), reason="go not available")
def test_go_pe_addresses_are_rvas(tmp_path):
    import lief
    p = _gobuild(tmp_path, "windows", "amd64", "g.exe")
    res = GO.recover(p)
    b = lief.parse(str(p))
    text = next(s for s in b.sections if s.name == ".text")
    assert res["address_space"] == "rva" and res["imagebase"] == b.optional_header.imagebase
    mm = [int(k, 16) for k, v in res["functions"].items() if v == "main.main"]
    assert mm and text.virtual_address <= mm[0] < text.virtual_address + text.size
    # COFF symbol value is section-relative: main.main's RVA = .text RVA + value
    sym = next((s for s in b.symbols if s.name == "main.main"), None)
    if sym is not None:
        assert mm[0] == text.virtual_address + sym.value
