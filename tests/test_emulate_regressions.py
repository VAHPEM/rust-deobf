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
    # to DENSE_EXT half-budgets: 16 since x86-64 / i386 software AES-256-GCM callees were measured
    # to need up to 12); a sparse one (a spinning lock: short blocks) is still cut off at 4, and
    # only while it writes text. The bound is pinned: raising it again must change this test.
    img, emu = _emu("ct64")
    emu._reset()
    emu.count, emu.nblocks, emu.last_text_at = 50000, 1000, -R.BUDGET
    dense = {"c0": 10000, "b0": 0, "start": 10000}            # 40000 instructions in 1000 blocks
    sparse = {"c0": 10000, "b0": 0, "start": 10000}
    assert emu._dense(dense) and emu._dense()                  # 40 per block; the run: 50
    assert R.DENSE_EXT == 16
    assert [emu._extend(dense) for _ in range(17)] == [True] * 16 + [False]
    emu.nblocks = 10000                                        # 4 per block
    assert not emu._dense(sparse) and not emu._dense()
    assert not emu._extend(sparse)                             # no recent text either
    emu.last_text_at = emu.count - 100
    assert [emu._extend(sparse) for _ in range(5)] == [True] * 4 + [False]



def test_dense_callee_gets_the_extensions_x86_software_aes_needs():
    # obfuse_aes built by rustc 1.99.1: Unicorn reports no AES-NI, so the `aes` crate runs software
    # AES-256-GCM. Its callees (38 instructions per block) needed up to 12 half-budget extensions on
    # x86-64 (11 on i386); cut at 8 they returned 0, the GCM tag failed, the program panicked
    # (`ObfuseStr decryption failed`) and only 2/5 canaries came out (measured on the Kali VM).
    img, emu = _emu("ct64")
    emu._reset()
    emu.count, emu.nblocks, emu.last_text_at = 50000, 1000, -R.BUDGET
    callee = {"c0": 8000, "b0": 0, "start": 8000}               # 42000 instructions, 42 per block
    assert all(emu._extend(callee) for _ in range(12))

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


class _Obj:
    def __init__(self, **kw):
        self.__dict__.update(kw)


def test_pe32_stdcall_import_pops_its_arguments():
    # A Win32 API is stdcall (`ret n`); the import trampoline's plain `ret` left the arguments on
    # the stack, the caller's `pop ebp; ret` then returned into nowhere and HeapAlloc returned 0
    # to every PE32 decoder. The size: C runtime 0 (cdecl), else the table of the imports Rust std
    # links, else the pushes right before the call.
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    code = bytes.fromhex("56" "6a00" "50" "ff1534120000")      # push esi; push 0; push eax; call [..]
    fake = _Obj(x32=True, img=_Obj(pe=True, tramp=["HeapAlloc", "memcpy", "OddApi", "x"],
                                   tramp_dll=["KERNEL32.dll", "msvcrt.dll", "kernel32.dll", "msvcrt.dll"]),
                _call_blk=(0x1000, len(code)), _md_lite=Cs(CS_ARCH_X86, CS_MODE_32),
                uc=_Obj(mem_read=lambda a, n: code[a - 0x1000:a - 0x1000 + n]))
    sb = R.Emulator._stdcall_bytes
    assert R._stdcall_table().get("HeapAlloc") == 12
    assert sb(fake, 0) == 12                  # the table
    assert sb(fake, 1) == 0                   # msvcrt: cdecl
    assert sb(fake, 2) == 12                  # unknown API: three pushes before the call
    fake.img.pe = False
    assert sb(fake, 0) == 0                   # ELF / 64-bit: never


def test_pe32_eh_frame_gives_function_starts():
    # i386 PE has no .pdata; mingw's .eh_frame (named `/4` once stripped) lists the functions.
    # Without it a stripped PE32 knew only direct call targets and `main` ran as the tail of the
    # function before it. One CIE (zR, pc-relative sdata4) and two FDEs.
    import struct as st
    cie_body = b"\x00\x00\x00\x00" + b"\x01" + b"zR\x00" + b"\x01" + b"\x7c" + b"\x08" + b"\x01" + b"\x1b"
    cie_body += b"\x00" * ((4 - (len(cie_body) + 4) % 4) % 4)
    data = st.pack("<I", len(cie_body)) + cie_body
    va = 0x9000
    for target in (0x1500, 0x1710):
        start = len(data) + 4                                 # where the CIE pointer field sits
        field = start + 4                                     # pc_begin
        body = st.pack("<I", start) + st.pack("<i", target - (va + field)) + st.pack("<I", 0x40)
        data += st.pack("<I", len(body)) + body
    data += b"\x00\x00\x00\x00"
    binary = _Obj(sections=[_Obj(name=".text", content=b"\x90" * 16, virtual_address=0x1000),
                            _Obj(name="/4", content=data, virtual_address=va)])
    assert R._pe_eh_frame_starts(binary, 0x400000) == [0x1500, 0x1710]
    junk = _Obj(sections=[_Obj(name="/4", content=b"\x10\x00\x00\x00" + b"\x01" * 16, virtual_address=va)])
    assert R._pe_eh_frame_starts(junk, 0x400000) == []


def test_import_trampolines_cannot_be_overwritten():
    # A data import (msvcrt's `__initenv`) is bound to a `ret` trampoline; CRT start-up code
    # storing through it (or memset on a fake pointer that was a function pointer) zeroed the
    # stubs, and every later run in that emulator fell through them (PE32: 1/5 instead of 5/5).
    img, emu = _emu("ct64")
    emu._reset()
    good = bytes(emu.uc.mem_read(R.TRAMP, 16))
    emu.uc.reg_write(emu.ARGS[0], R.TRAMP)
    emu.uc.reg_write(emu.ARGS[1], 0)
    emu.uc.reg_write(emu.ARGS[2], 64)
    emu._stub("memset")                                        # the model refuses
    assert bytes(emu.uc.mem_read(R.TRAMP, 16)) == good
    from unicorn import UC_PROT_READ, UC_PROT_EXEC
    perms = [p for b, e, p in emu.uc.mem_regions() if b <= R.TRAMP <= e]
    assert perms == [UC_PROT_READ | UC_PROT_EXEC], perms      # a guest store faults
    emu.uc.mem_write(R.TRAMP, b"\x00" * 16)                   # (host writes still can) ...
    emu._reset()
    assert bytes(emu.uc.mem_read(R.TRAMP, 16)) == good         # ... and a reset restores them


def test_reversed_view_is_dropped():
    delta = "canary::delta::feature-flag-telemetry-off"
    recs = [{"string": delta, "function": 1, "used": True},
            {"string": "ffo-yrtemelet-galf-e", "function": 1},
            {"string": "level.example", "function": 2}]
    kept = {r["string"] for r in R._drop_overlap_artifacts(recs)}
    assert kept == {delta, "level.example"}, kept


def test_eh_frame_cie_with_8_byte_personality():
    # `zPLR` with an 8-byte personality pointer (udata8): the CIE parser must skip all 8 bytes to
    # read the FDE encoding (R) after it (coverage for the P/L/R augmentation path)
    import struct as st
    cie = b"\x00\x00\x00\x00" + b"\x01" + b"zPLR\x00" + b"\x01" + b"\x7c" + b"\x08"
    cie += b"\x0b" + b"\x04" + b"\xaa" * 8 + b"\x00" + b"\x1b"       # aug len 11: P(0x04, 8 bytes) L R
    cie += b"\x00" * ((4 - (len(cie) + 4) % 4) % 4)
    data = st.pack("<I", len(cie)) + cie
    va = 0x9000
    start = len(data) + 4
    body = st.pack("<I", start) + st.pack("<i", 0x1500 - (va + start + 4)) + st.pack("<I", 0x10)
    body += b"\x00"                                                  # (FDE augmentation length)
    data += st.pack("<I", len(body)) + body + b"\x00\x00\x00\x00"
    binary = _Obj(sections=[_Obj(name="/4", content=data, virtual_address=va)])
    assert R._pe_eh_frame_starts(binary, 0x400000) == [0x1500]


def test_vector_chunk_prefix_is_not_a_separate_indicator():
    # a decode cut at a 16-byte chunk, used at that length by another function (`https://telemetr`
    # next to the full URL, PE32 litcrypt size-lto) was kept as a "separate indicator"
    url = "https://telemetry.northwind.example/api/v3/beacon"
    # (each at its own buffer, as in the real run: so not a half-done view of the same buffer)
    recs = [{"string": url, "function": 1, "used": True, "addr": [0x30000100]},
            {"string": url[:16], "function": 2, "used": True, "addr": [0x30000050]},
            {"string": url[:32], "function": 3, "used": True, "addr": [0x30000a20]}]
    kept = {r["string"] for r in R._drop_overlap_artifacts(recs)}
    assert kept == {url}, kept


def test_i386_decoder_features():
    # i386 names data by absolute imm32 (`mov edx, 0x4a3175`: the ciphertext a decoder gets) and
    # obfstr adds 32-bit keys (`add ebx, 0x403eea6e`) where x86-64 uses movabs: both scored 0, so
    # i386 decoders were never path-explored (scatter PE32: `nw-agent::stage=collect` missing)
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    code = bytes.fromhex("81c36eea3e40" "ba75314a00" "81c310000000" "c3")   # add ebx,key; mov edx,ct; add ebx,0x10
    cipher = bytes(range(0x80, 0x90))
    img = _Obj(code=code, text_va=0x1000, md=Cs(CS_ARCH_X86, CS_MODE_32), arm=False, x32=True,
               span=(0x400000, 0x500000), imagebase=0x400000,
               read=lambda va, n: cipher[:n] if va == 0xa3175 else b"\x00" * n)
    imm64, xors, ct, callees = R._features(img, 0x1000, len(code))
    assert (imm64, ct) == (1, 1), (imm64, ct)


# CI run #118, test_tight_strings_by_emulation[pe32-*]: the records recover_emulate produced for
# tight_xor__pe32__release__nostrip.exe (i686-pc-windows-gnu, rustc 1.99.1), as measured on the
# ARM64 Kali VM. The decode writes 8-byte movq stores into a reused stack buffer; three views of
# it -- 7 characters of a canary plus one byte -- were reported as strings.
_PE32_TIGHT = [
    ("canary::bravo::build-id-20261018", 6304, [805306368, 805306480, 805307568, 3222273940, 3222273980], True),
    ("canary::alpha::7f3c-config-endpoint", 5536, [805306368, 805306480, 3222273821, 3222273917, 3222273965], True),
    ("canary::charlie::/opt/app/resources/data.bin", 5536, [805306368, 805306480, 805307664, 3222273928, 3222273968], True),
    ("canary::delta::feature-flag-telemetry-off", 5536, [805306368, 805306480, 805307776, 3222273863, 3222273911], True),
    ("canary::echo::schema-version-4", 5536, [805306368, 805306480, 805307888, 3222273942, 3222273982], True),
    ("chema-v9", 5536, [3222273957], False),
    ("chema-vl", 5536, [3222273889], False),
    ("ild-id-9", 5536, [3222273957], False),
]


def _records(rows):
    out = []
    for s, fn, addr, used in rows:
        r = {"string": s, "function": fn, "method": "emulation", "addr": addr}
        if used:
            r["used"] = True
        out.append(r)
    return out


def test_pe32_store_views_inside_a_used_buffer_are_dropped():
    kept = [r["string"] for r in R._drop_overlap_artifacts(_records(_PE32_TIGHT))]
    assert sorted(kept) == sorted(s for s, _f, _a, used in _PE32_TIGHT if used), kept


def test_same_views_outside_any_used_buffer_are_kept():
    # the address is the evidence: the same text captured in memory no used string occupied is
    # left to the other rules (which keep it), so a separate short string is not lost
    rows = [(s, f, a if used else [0x50000000 + 64 * i], used) for i, (s, f, a, used) in enumerate(_PE32_TIGHT)]
    kept = {r["string"] for r in R._drop_overlap_artifacts(_records(rows))}
    assert {"chema-v9", "chema-vl", "ild-id-9"} <= kept, kept


def test_a_used_string_inside_a_used_buffer_is_never_dropped():
    rows = [(s, f, a, used or s == "chema-v9") for s, f, a, used in _PE32_TIGHT]
    kept = {r["string"] for r in R._drop_overlap_artifacts(_records(rows))}
    assert "chema-v9" in kept


# obfuse_aes (AES-256-GCM, software AES on AArch64), elf-arm64 release strip, Kali builds #12 and #22
# (VALIDATION §77/§78; sha256 6abac2f08d24d2fd / dd2c7175c67ffff4): records as the emulator produced
# them. The last partial block is decrypted in a 16-byte stack scratch at 0x7f00000ffde0 and used
# from there; the capture also read 4 bytes before it (and one after), printable by chance -- which
# ones depends on the build's random key, so the leaked piece changed per build (CI #122, #123).
_AES_BLOCK = [
    ("canary::delta::feature-flag-telemetry-off", 0x225660, [0x300000f0, 0x300006f0, 0x30000770], True),
    ("canary::delta::feature-flag-tele", 0x225660, [0x300006f0], False),
    ("metry-off", 0x225660, [0x7f00000ffde0], True),
    ("emetry-off", 0x225660, [0x3000010f], False),
    (":gUnmetry-offa", 0x225660, [0x7f00000ffddc], False),            # build #12
    ("canary::echo::schema-version-4", 0x225660, [0x300000f0, 0x300007e0, 0x30000850], True),
    ("canary::echo::sc", 0x225660, [0x300007e0], False),
    ("hema-version-4", 0x225660, [0x7f00000ffde0], True),
    ("9(dFhema-version-4", 0x225660, [0x7f00000ffddc], False),        # build #22
]


def test_used_aead_block_read_with_its_neighbours_is_dropped():
    kept = {r["string"] for r in R._drop_overlap_artifacts(_records(_AES_BLOCK))}
    assert ":gUnmetry-offa" not in kept and "9(dFhema-version-4" not in kept, kept
    assert {"canary::delta::feature-flag-telemetry-off", "canary::echo::schema-version-4"} <= kept


def test_same_text_not_over_the_used_block_is_kept():
    # the address is the evidence: the used piece must sit inside x exactly where it was used. The
    # same text captured one byte off (or elsewhere) is not that view and is left to the other rules
    rows = [(s, f, [a[0] + 1] if s in (":gUnmetry-offa", "9(dFhema-version-4") else a, u)
            for s, f, a, u in _AES_BLOCK]
    kept = {r["string"] for r in R._drop_overlap_artifacts(_records(rows))}
    assert {":gUnmetry-offa", "9(dFhema-version-4"} <= kept, kept


def test_used_block_view_rule_needs_the_piece_to_belong_to_a_longer_used_string():
    # a used string that is NOT a piece of another used one (a string of its own, e.g. a short
    # message) keeps a longer capture around it: only an AEAD block of a used whole is junk-padded
    rows = [(s, f, a, u) for s, f, a, u in _AES_BLOCK if not s.startswith("canary::delta")]
    rows = [(s, f, a, u) for s, f, a, u in rows if s != "emetry-off"]
    kept = {r["string"] for r in R._drop_overlap_artifacts(_records(rows))}
    assert ":gUnmetry-offa" in kept, kept


# The adversarial input itself: obfuse_aes 1.0.1 (AES-256-GCM, unseeded), elf-arm64 release strip,
# built on Kali with rustc 1.99.1 (build #12 of VALIDATION §77; sha256 6abac2f08d24d2fd...). Its
# random key makes the scratch around the last partial block printable (`:gUn` ... `a`); every other
# build of the 35 measured but one passed. A committed binary keeps this case forever, whatever keys
# future builds draw.
AEAD_LEAK = ROOT / "tests" / "fixtures" / "aead" / "obfuse_aes_leak.arm64"


def test_aead_scratch_leak_fixture_gives_exactly_the_canaries():
    import json
    import recover
    canaries = json.loads((ROOT / "bench_src" / "manifest.json").read_text())["canaries"]
    res = recover.run(AEAD_LEAK, stackstrings=False, literals=False, time_budget=300)
    got = {x["string"] for x in res["decoded"]}
    assert got == set(canaries), (sorted(set(canaries) - got), sorted(got - set(canaries)))


def test_byte_by_byte_decode_chain_keeps_the_whole_string():
    # scatter_cryptify size-lto (pe / elf-arm64, measured): the decoder pushes one byte at a time, so
    # every prefix is a used string at the SAME address and the whole string holds the last of them
    # at offset 0. That is the string, not a scratch block with junk: a first version of the block
    # rule dropped three whole strings here.
    s = "Software\\Northwind\\Agent\\Settings"
    rows = [(s[:n], 0x158d, [0x30000160], True) for n in range(len("Software\\Northwind\\Agent"), len(s))]
    rows.append((s, 0x158d, [0x30000160], False))
    kept = {r["string"] for r in R._drop_overlap_artifacts(_records(rows))}
    assert s in kept, kept


# --- strings that are not plain UTF-8 (VALIDATION §80) ---------------------------------------
ENCODINGS = ROOT / "tests" / "fixtures" / "strenc" / "encodings.arm64"
_B64 = "canary::charlie::/opt/app/resources/data.bin"
# bench_src `encodings`, elf-arm64 size-lto (measured): main's natural run passes the base64
# decode on at its length; a forced run of the decoder flips the padding branch and passes the same
# buffer with one more byte on. Without the witness the overrun replaced the string.
_B64_ROWS = [(_B64[:16], 0x2205ac, [0x30000050], True), (_B64[:32], 0x2205ac, [0x300000a0], True),
             (_B64, 0x2205ac, [0x30000090, 0x30000100], True)]


def _natural_done(rows, forced_tail):
    recs = _records(rows)
    for r in recs:
        r["natural_done"] = True
    recs.append({"string": _B64 + forced_tail, "function": 0x22044c, "method": "emulation",
                 "forced": True, "addr": [0x30000100], "used": True})
    return recs


def test_forced_overrun_of_a_complete_natural_decode_is_dropped():
    kept = {r["string"] for r in R._drop_overlap_artifacts(_natural_done(_B64_ROWS, ">"))}
    assert _B64 in kept and _B64 + ">" not in kept, kept


def test_forced_overrun_needs_a_completed_natural_run():
    # no witness (the natural run was cut short): the forced run may be the one that finished the
    # decode -- unchanged behaviour, the longer string stays
    recs = _natural_done(_B64_ROWS, ">")
    for r in recs:
        r.pop("natural_done", None)
    kept = {r["string"] for r in R._drop_overlap_artifacts(recs)}
    assert _B64 + ">" in kept, kept


def test_forced_extension_by_a_word_character_is_not_an_overrun():
    # `endpoint` naturally, `endpoints` on another arm: a letter is not junk
    kept = {r["string"] for r in R._drop_overlap_artifacts(_natural_done(_B64_ROWS, "s"))}
    assert _B64 + "s" in kept, kept


def test_utf16_text_is_captured():
    # a UTF-16LE buffer (a Windows `W` string, never converted) has a zero byte between characters:
    # no printable byte run sees it
    from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    uc.mem_map(0x10000, 0x1000)
    w = R._Writes()
    text = "canary::bravo::build-id-20261018"
    data = b"\x01\x02" + text.encode("utf-16-le") + b"\x00\x00"
    uc.mem_write(0x10100, data)
    w.add(0x10100, len(data))
    out = set()
    w.capture(uc, out)
    assert text in out, out
    # short UTF-16 (under 6 characters) and alternating non-text are not strings
    w2, out2 = R._Writes(), set()
    uc.mem_write(0x10800, "abcde".encode("utf-16-le") + bytes([0x41, 0x01] * 8))
    w2.add(0x10800, 26)
    w2.capture(uc, out2)
    assert out2 == set(), out2


def test_encodings_fixture_gives_exactly_the_canaries():
    # UTF-16 never converted (canary 1), base64 with the forced overrun (2), and a 38-byte zlib
    # stream (4) were all missed before §80; 0 (UTF-16, converted) and 3 (hex) were found
    import json
    import recover
    canaries = json.loads((ROOT / "bench_src" / "manifest.json").read_text())["canaries"]
    res = recover.run(ENCODINGS, stackstrings=False, literals=False, time_budget=300)
    got = {x["string"] for x in res["decoded"]}
    assert got == set(canaries), (sorted(set(canaries) - got), sorted(got - set(canaries)))


# --- names resolved at run time (lazy imports, VALIDATION §81) --------------------------------
LAZY = ROOT / "tests" / "fixtures" / "imports" / "lazy_import.exe"


def test_lazy_import_names_are_recorded_and_hidden_ones_marked():
    # obf_src/lazy_import, pe size-lto: two harmless API names XOR-decoded and passed to
    # GetProcAddress(GetModuleHandleA("kernel32.dll"), name). They are not in the file, so
    # in_file=False; std's own compat lookups (SetThreadDescription, "kernel32") are in_file=True
    res = R.recover(LAZY, [])
    hidden = {(r["kind"], r["name"]) for r in res["resolved_imports"] if not r["in_file"]}
    assert hidden == {("module", "kernel32.dll"), ("proc", "GetTickCount"),
                      ("proc", "GetCurrentProcessorNumber")}, res["resolved_imports"]
    assert any(r["in_file"] and r["name"] == "SetThreadDescription" for r in res["resolved_imports"])
    # the decoded name is a string too: pieces of it in the import table (GetCurrentProcess) no
    # longer explain it away as static text
    texts = set(res["recovered_texts"])
    assert "GetCurrentProcessorNumber" in texts and any("GetTickCount" in t for t in texts), texts
