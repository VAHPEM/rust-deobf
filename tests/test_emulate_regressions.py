"""Regression tests for the emulation-engine fixes (Oct 2026 review).

Each uses a tiny committed fixture under tests/fixtures/emu/ (benign; see build.sh) that isolates
one loader/runtime path. Fixtures are ANALYSED under Unicorn, never executed natively. Tests skip
when a fixture is absent.
"""
import struct
import sys

import pytest
from conftest import ROOT

sys.path.insert(0, str(ROOT / "scripts"))
import recover_emulate as R

FIX = ROOT / "tests" / "fixtures" / "emu"


def _emu(name):
    f = FIX / name
    if not f.is_file():
        pytest.skip(f"fixture missing: {name}")
    img = R.Image(str(f))
    emu = R.Emulator(img)
    return img, emu


def test_null_call_does_not_end_the_run():
    # work() decodes cecnet-1, calls a helper that calls a null pointer, then decodes cecnet-2.
    # With until=0 the null call looked like a top-level return and cecnet-2 was lost.
    f = FIX / "null64"
    if not f.is_file():
        pytest.skip("fixture missing")
    r = R.recover(str(f), ["cecnet-1", "cecnet-2"], workers=1)
    assert set(r["recovered"]) == {"cecnet-1", "cecnet-2"}, r["recovered"]


def test_pe_data_with_large_virtualsize_is_mapped():
    # .data: SizeOfRawData 0x200, VirtualSize 0x4018 (a .bss merged in). The section must be
    # mapped to its full VirtualSize, or the content write faults and it reads back as zero.
    img, emu = _emu("pe64.exe")
    emu._reset()
    data = next(s for s in img.binary.sections if s.name == ".data")
    raw = bytes(emu.uc.mem_read(R.BASE + data.virtual_address, 16))
    assert b"SECRET-KEY" in raw, raw


def test_i386_relocation_patch_does_not_zero_next_word():
    # a Rust-like vtable {drop, size, align, method}; the size field (12) must survive. A pointer
    # relocation written as 8 bytes zeroed the following word on i386.
    img, emu = _emu("vt32")
    b = img.binary
    sym = next((s for s in b.symbols if "get_size" in s.name), None)
    if sym is None:
        pytest.skip("no get_size symbol")
    import gen_runtime_sigs as G
    va = G.sym_va(b, sym)
    emu.run(va, 0x200)
    import unicorn.x86_const as X
    assert emu.uc.reg_read(X.UC_X86_REG_EAX) == 12


@pytest.mark.parametrize("name", ["ct32", "ct64", "mo2_classic"])
def test_constructors_found_on_every_format(name):
    # the constructor-replay list was empty on i386 PIE (REL, addend 0) and Mach-O (rebase, no
    # addend) because a 0 addend was recorded instead of reading the target in place.
    img, _ = _emu(name)
    assert img.constructor_vas(), f"{name}: no constructors found"


def test_macho_chained_fixup_pointer_is_decoded():
    img, emu = _emu("mo_chained")
    emu._reset()
    b = img.binary
    r = next((x for x in b.relocations if type(x).__name__ == "RelocationFixup"), None)
    if r is None:
        pytest.skip("no chained fixup in fixture")
    val = struct.unpack("<Q", emu.uc.mem_read(R.BASE + r.address, 8))[0]
    assert val == r.target, (hex(val), hex(r.target))


def test_initial_exec_tls_vars_do_not_alias():
    # ta=0x1111; tb=0x2222; return ta -- with TPOFF ignored both land at the thread pointer and
    # f() returns 0x2222 (tb overwrote ta). Distinct TLS offsets make it return 0x1111.
    img, emu = _emu("tls.so")
    b = img.binary
    sym = next((s for s in b.symbols if s.name == "f"), None)
    if sym is None:
        pytest.skip("no f symbol")
    import gen_runtime_sigs as G
    emu.run(G.sym_va(b, sym), 0x200)
    import unicorn.x86_const as X
    assert emu.uc.reg_read(X.UC_X86_REG_EAX) == 0x1111


def test_primed_heap_block_survives_reset():
    # a constructor malloc()s CONFIG and fills it with 'K'; after reset the block must be intact
    # (and the next malloc go above it), not zeroed and handed back to the next allocation.
    img, emu = _emu("heap.so")
    emu.prime_constructors()
    b = img.binary
    g = next((s for s in b.symbols if s.name == "CONFIG"), None)
    if g is None:
        pytest.skip("no CONFIG symbol")
    import gen_runtime_sigs as G
    emu._reset()
    ptr = struct.unpack("<Q", emu.uc.mem_read(R.BASE + G.sym_va(b, g), 8))[0]
    assert bytes(emu.uc.mem_read(ptr, 8)) == b"KKKKKKKK"


def test_dedup_keeps_cross_function_indicators_drops_same_function_views():
    # a substring from a DIFFERENT function than its container is a separate indicator (keep); a
    # half-decoded prefix from the SAME decoder is a view (drop), even though both are 'used'
    recs = [
        {"string": "https://cdn.northwind.example/api/status", "function": 0xf100, "used": True},
        {"string": "cdn.northwind.example", "function": 0xf200, "used": True},
        {"string": "C:\\ProgramData\\NorthwindSvc\\state.db", "function": 0x16a0, "used": True},
        {"string": "C:\\Progra", "function": 0x16a0, "used": True},
    ]
    out = {r["string"] for r in R._drop_overlap_artifacts(recs)}
    assert "cdn.northwind.example" in out                 # separate indicator, different function
    assert "C:\\Progra" not in out                       # half-decoded view, same function
    assert "https://cdn.northwind.example/api/status" in out
    assert "C:\\ProgramData\\NorthwindSvc\\state.db" in out


_BUILT = ["null64", "vt32", "ct64", "ct32", "tls.so", "heap.so"]


def _elf_shape(path):
    """What the regression tests depend on: ELF type, PIE-ness, interpreter, the set of relocation
    types (e.g. TPOFF64 for initial-exec TLS) and the dynamic tags present (e.g. TEXTREL)."""
    import lief
    b = lief.parse(str(path))
    return (str(b.header.file_type), b.is_pie, b.has_interpreter,
            sorted({str(r.type) for r in b.relocations}),
            sorted({str(e.tag) for e in b.dynamic_entries}))


@pytest.mark.skipif(sys.platform == "win32", reason="build.sh is a bash script")
def test_build_script_reproduces_committed_fixture_shapes(tmp_path):
    # build.sh used to build null64/ct64 as -static non-PIE and tls.so without initial-exec TLS,
    # with every error hidden (2>/dev/null || echo) and exit 0, so it could not regenerate the
    # committed fixtures. It must build the same kind of binary into a scratch dir.
    import shutil
    import subprocess
    if not all(shutil.which(t) for t in ("bash", "clang", "ld.lld")):
        pytest.skip("needs bash + clang + ld.lld")
    r = subprocess.run(["bash", str(FIX / "build.sh"), str(tmp_path)], capture_output=True,
                       text=True, timeout=300)
    assert r.returncode == 0, r.stderr[-2000:]
    for name in _BUILT:
        assert (tmp_path / name).is_file(), name
        assert _elf_shape(tmp_path / name) == _elf_shape(FIX / name), name
    tls = _elf_shape(tmp_path / "tls.so")
    assert any("TPOFF64" in t for t in tls[3]), tls
    for exe in ("null64", "ct64", "ct32", "vt32"):
        assert _elf_shape(tmp_path / exe)[:2] == ("FILE_TYPE.DYN", True), exe     # PIE
