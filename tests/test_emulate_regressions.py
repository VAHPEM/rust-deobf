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


_BUILT = ["null64", "vt32", "ct64", "ct32", "tls.so", "heap.so", "tls2_a64.so", "bigbss64"]


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


def _ret_reg(emu):
    if emu.arm:
        import unicorn.arm64_const as A
        return emu.uc.reg_read(A.UC_ARM64_REG_X0)
    import unicorn.x86_const as X
    return emu.uc.reg_read(X.UC_X86_REG_EAX)


@pytest.mark.parametrize("name", ["tls2.so", "tls2_a64.so", "tls2_32.so"])
def test_initial_exec_tls_offsets_respect_variable_size(name):
    # T1 is a 32-byte (16 on i386) struct, T2 an 8-byte long next to it. With a fixed 8-byte offset
    # stride T1 overlaps T2, so setting every T1 field to 0x1111 and then T2 = 0x2222 clobbered a
    # field and the sum of T1 was no longer 0x4444.
    # x86-64 / i386 (variant II, below TP) and AArch64 (variant I, above the 16-byte TCB).
    img, emu = _emu(name)
    b = img.binary
    sym = next((s for s in b.symbols if s.name == "f"), None)
    if sym is None:
        pytest.skip("no f symbol")
    offs = {k[0]: v for k, v in img._tls_off.items() if isinstance(k, tuple)}
    assert set(offs) == {"T1", "T2"}
    span = {"T1": 16 if img.x32 else 32, "T2": 8}
    lo1, lo2 = offs["T1"], offs["T2"]
    assert lo1 + span["T1"] <= lo2 or lo2 + span["T2"] <= lo1, offs        # no overlap
    if img.arm:
        assert min(lo1, lo2) >= 16, offs           # past the TCB, never on top of it
    else:
        assert max(lo1 + span["T1"], lo2 + span["T2"]) <= 0, offs   # wholly below TP
    import gen_runtime_sigs as G
    emu.run(G.sym_va(b, sym), 0x200)
    if img.x32 and _ret_reg(emu) == 0:
        pytest.skip("this Unicorn build cannot set a 32-bit segment base (TLS run faults)")
    assert _ret_reg(emu) & 0xffffffff == 0x4444


def test_primed_baseline_keeps_bss_larger_than_cap():
    # bigbss64: a constructor sets MARK in an image whose .bss (32 MB) exceeds _BSS_CAP. The primed
    # snapshot read the declared s.size (past the 16 MB mapping) -> UcError -> the whole .bss was
    # dropped from the baseline and MARK read 0 after a reset.
    img, emu = _emu("bigbss64")
    mark = next((s for s in img.binary.symbols if s.name == "MARK"), None)
    if mark is None:
        pytest.skip("no MARK symbol")
    assert emu.prime_constructors() == 1
    emu._reset()
    import gen_runtime_sigs as G
    v = struct.unpack("<I", emu.uc.mem_read(R.BASE + G.sym_va(img.binary, mark), 4))[0]
    assert v == 0x1337


def test_strlen_stub_near_end_of_mapping():
    # a string within 4 KB of a mapping's end: the fixed 0x1000 read from an unaligned pointer
    # faulted and strlen returned 0. Also an unterminated run up to the mapping end returns the
    # readable length, not 0.
    img, emu = _emu("ct64")
    emu._reset()
    end = R.HEAP + R.HEAP_SIZE
    for p, s, want in ((R.HEAP + 0x100, b"hello\x00", 5), (end - 16, b"hello\x00", 5),
                       (end - 0x1801, b"\x00", 0), (end - 0x1803, b"ab\x00", 2)):
        emu.uc.mem_write(p, s)
        emu.uc.reg_write(emu.ARGS[0], p)
        assert emu._stub("strlen") == want, hex(p)
    emu.uc.mem_write(end - 0x20, b"A" * 0x20)        # no terminator before the mapping ends
    emu.uc.reg_write(emu.ARGS[0], end - 0x20)
    assert emu._stub("strlen") == 0x20


def test_aead_tag_after_in_place_decrypt_is_cut():
    # obfuse's AES-256-GCM ObfuseStr: ciphertext||tag is copied out of .rodata and decrypted in
    # place in one callee, so the 16 tag bytes after the plaintext carry the same write age. A tag
    # starting with a printable byte glued onto the string (`...build-id-20261018` + `)`), and the
    # (pointer, length) the code passed could not mark the string complete. The tail is a tag when
    # all 16 bytes were written, are not text, and occur verbatim in the file.
    img, emu = _emu("ct64")
    emu._reset()
    plain = b"canary::bravo::build-id-20261018"
    tag = b")" + bytes(range(0x80, 0x8f))                 # 16 bytes, the first one printable
    img.file_bytes = img.file_bytes + b"\x00" + tag        # ... as it sits in .rodata

    def attempt(p, tail, gens=1):
        emu.writes = R._Writes()
        emu.strings, emu.used, emu.exact, emu.straddr = set(), set(), set(), {}
        emu.uc.mem_write(p, plain + tail)
        emu.writes.add(p + len(plain), len(tail))           # the copy ...
        if gens == 2:
            emu.writes.capture(emu.uc, set())               # (a capture between copy and decrypt)
        emu.writes.add(p, len(plain))                       # ... then the decrypt, same age or newer
        emu._try_str(p, len(plain))
        return plain.decode() in emu.used, plain.decode() in emu.exact

    assert attempt(R.HEAP + 0x200, tag) == (True, True)
    assert attempt(R.HEAP + 0x200, tag, gens=2) == (True, True)    # the older-tail rule, as before
    # not in the file: decoded bytes, not a copied tag -> no claim
    assert attempt(R.HEAP + 0x300, b")" + bytes(range(0x90, 0x9f))) == (True, False)
    # a printable tail is text that may continue the string, even if the file holds it
    text = b"-and-more-text-x"
    img.file_bytes += text
    assert attempt(R.HEAP + 0x400, text) == (True, False)


def test_random_key_cipher_state_is_not_reported():
    # obfuse rebuilt with fresh random keys: AES-GCM / MBA-XOR scratch occasionally reads as text.
    # A replicated cipher word (`RvERvE`) is degenerate; a 16-byte block holding the END of a used
    # string plus keystream (`metry-off9]bk1`), and a forced-path junk head glued to a piece from
    # inside a natural string (`wy~v=yu=uild-id-`), are views, not strings.
    assert R._degenerate("RvERvE") and R._degenerate("reAreA") and R._degenerate("zzzzzz")
    assert not R._degenerate("abcabd") and not R._degenerate("a.example")
    delta = "canary::delta::feature-flag-telemetry-off"
    bravo = "canary::bravo::build-id-20261018"
    recs = [{"string": delta, "function": 1, "used": True},
            {"string": bravo, "function": 1, "used": True},
            {"string": "metry-off9]bk1", "function": 1},
            {"string": "wy~v=yu=uild-id-", "function": 2, "forced": True},
            # a separate string that only shares a few characters, kept
            {"string": "feature-x.example", "function": 3}]
    kept = {r["string"] for r in R._drop_overlap_artifacts(recs)}
    assert kept == {delta, bravo, "feature-x.example"}, kept


def test_software_cipher_gets_bounded_extra_budget():
    # the `aes` crate's software AES-256-GCM (AArch64, no AES instructions): ~26k instructions per
    # string, its callees 13-56 instructions per basic block. A callee that dense keeps going (up
    # to 8 half-budgets); a sparse one (a spinning lock: short blocks) is still cut off at 4, and
    # only while it writes text.
    img, emu = _emu("ct64")
    emu._reset()
    emu.count, emu.nblocks, emu.last_text_at = 50000, 1000, -R.BUDGET
    dense = {"c0": 10000, "b0": 0, "start": 10000}            # 40000 instructions in 1000 blocks
    sparse = {"c0": 10000, "b0": 0, "start": 10000}
    assert emu._dense(dense) and emu._dense()                  # 40 per block; the run: 50
    assert [emu._extend(dense) for _ in range(9)] == [True] * 8 + [False]
    emu.nblocks = 10000                                        # 4 per block
    assert not emu._dense(sparse) and not emu._dense()
    assert not emu._extend(sparse)                             # no recent text either
    emu.last_text_at = emu.count - 100
    assert [emu._extend(sparse) for _ in range(5)] == [True] * 4 + [False]


def test_i386_vsyscall_pointer_points_at_int80_ret():
    # i386 libcs make system calls through `call *%gs:0x10`; zero there made every syscall of a
    # static musl build return 0 (no memory for malloc). It now points at the binary's own
    # `int $0x80; ret` (musl's __vsyscall fallback), which _on_intr models.
    img, emu = _emu("ct32")
    tp = R.TLS + R.TLS_SIZE // 2
    emu._reset()
    assert emu._vsyscall == 0                              # dynamic glibc: no such sequence
    assert struct.unpack("<I", emu.uc.mem_read(tp + 0x10, 4))[0] == 0
    img.code = b"\x90\xcd\x80\xc3" + img.code[4:]
    emu2 = R.Emulator(img)
    emu2._reset()
    assert emu2._vsyscall == img.text_va + 1
    assert struct.unpack("<I", emu2.uc.mem_read(tp + 0x10, 4))[0] == img.text_va + 1


def test_i386_decode_views_are_dropped():
    # obfstr on i386 musl: the decoded string followed by an earlier partial copy of its own
    # start (`...data.bin` + `canary::char`) cost the string itself; a seam of two decodes
    # (`bin` + `canary::delt`) and two 4-byte stores out of order (`hema` + `echo`) were reported.
    charlie = "canary::charlie::/opt/app/resources/data.bin"
    delta = "canary::delta::feature-flag-telemetry-off"
    echo = "canary::echo::schema-version-4"
    recs = [{"string": s, "function": 1, "used": True, "addr": [0x100]} for s in (charlie, delta, echo)]
    recs += [{"string": charlie + "canary::char", "function": 1, "addr": [0x100]},
             {"string": "bincanary::delt", "function": 1, "addr": [0x200]},
             {"string": "hemaecho", "function": 1, "addr": [0x300]},
             {"string": "nw-agent.example", "function": 2}]       # unrelated: kept
    kept = {r["string"] for r in R._drop_overlap_artifacts(recs)}
    assert kept == {charlie, delta, echo, "nw-agent.example"}, kept
