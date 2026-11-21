"""Static unpacker regressions (scripts/unpack_emulate.py, scripts/unpack.py).

Each case pins a bug found in review, on a synthetic input built at test time (tests/_mkelf.py) or
on the committed benign UPX-packed PE fixtures (tests/fixtures/pack/upx_hello_pe{64,32}.exe, built
from upx_hello_pe.c with mingw-w64 GCC 14 -Os -s and packed with `upx --best`, UPX 4.2.4).
"""
import struct
import sys

import pytest
from conftest import ROOT

sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))
pytest.importorskip("unicorn")
import unpack  # noqa: E402
import unpack_emulate as U  # noqa: E402
from _mkelf import mkelf  # noqa: E402

PACK = ROOT / "tests" / "fixtures" / "pack"
UPX64 = PACK / "upx_hello_pe64.exe"
UPX32 = PACK / "upx_hello_pe32.exe"
PACKED_ELF = PACK / "packed_xor.elf64"
# the APIs upx_hello_pe.c calls; the unpacked program must be bound to them
FIXTURE_APIS = {"GetEnvironmentVariableA", "GetTickCount", "GetModuleFileNameA", "CreateFileA",
                "GetFileSize", "CloseHandle"}
ORIGINAL_ENTRY = 0x13f0      # AddressOfEntryPoint of the binaries BEFORE packing (both widths)


def _write(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return p


@pytest.mark.parametrize("fixture", [UPX64, UPX32], ids=["pe64", "pe32"])
def test_upx_pe_unpacks_to_original_entry_with_rebuilt_imports(fixture):
    if not fixture.is_file():
        pytest.skip("UPX fixture missing")
    res = U.recover(fixture)
    assert res.get("error") is None
    assert res["arch"] == ("x86_64" if fixture is UPX64 else "x86")
    # the stub's TLS-callback calls are not mistaken for the hand-off; the JMP to the OEP is
    assert res["stopped"] == "oep" and res["oep"] == ORIGINAL_ENTRY, (res["stopped"], res["oep"])
    assert res["callbacks"], "UPX runs the program's TLS callbacks before the OEP"
    assert res["unpacked_detected"] is True
    # the import table the stub rebuilt (LoadLibraryA + GetProcAddress, stored into the IAT)
    rebuilt = {r["api"].split("!")[-1] for r in res["rebuilt_imports"]}
    assert FIXTURE_APIS <= rebuilt, FIXTURE_APIS - rebuilt
    # ... and the unpacked code's call sites bound to it
    bound = {c["api"].split("!")[-1] for c in res["import_callsites"]}
    assert FIXTURE_APIS <= bound, FIXTURE_APIS - bound
    stage = [r for r in res["unpacked"] if r["executed"]]
    assert stage and stage[0]["va"] <= ORIGINAL_ENTRY < stage[0]["va"] + stage[0]["size"]


def test_upx_pe_one_byte_self_patch_is_not_the_oep():
    # UPX x64 flips one byte of its own stub (a TLS-callback trampoline `ret` -> `cld`) and runs it:
    # self-modification, not an unpacked stage
    if not UPX64.is_file():
        pytest.skip("UPX fixture missing")
    res = U.recover(UPX64)
    assert res["self_patches"] and all(p != res["oep"] for p in res["self_patches"])


def test_entry_given_as_pe_va_is_rebased():
    if not UPX64.is_file():
        pytest.skip("UPX fixture missing")
    import lief
    b = lief.parse(str(UPX64))
    rva = b.optional_header.addressof_entrypoint
    res = U.recover(UPX64, entry=b.optional_header.imagebase + rva)   # a VA from a debugger
    assert res["entry"] == rva and res["oep"] == ORIGINAL_ENTRY


def test_no_section_headers_still_unpacks(tmp_path):
    # UPX-style ELF output has no section table: Image falls back to the executable segment
    data = bytearray(PACKED_ELF.read_bytes())
    struct.pack_into("<Q", data, 0x28, 0)            # e_shoff
    struct.pack_into("<HH", data, 0x3c, 0, 0)        # e_shnum, e_shstrndx
    res = U.recover(_write(tmp_path, "noshdr.elf", bytes(data)))
    assert res.get("error") is None and res["unpacked_detected"] is True and res["stopped"] == "oep"


def test_unloadable_input_reports_error_not_traceback(tmp_path):
    res = U.recover(_write(tmp_path, "junk.bin", b"not a binary" * 32))
    assert res["error"] and res["unpacked_detected"] is False and res["unpacked"] == []
    full = unpack.recover(tmp_path / "junk.bin")
    assert full["static"]["error"] and full["dynamic"] is None


def test_budget_exhaustion_is_not_reported_as_return(tmp_path, monkeypatch):
    monkeypatch.setattr(U, "_MAX_INSNS", 20000)
    res = U.recover(_write(tmp_path, "loop.elf", mkelf(b"\x90\xeb\xfd")[0]))   # nop; jmp $-1
    assert res["stopped"] == "budget", res["stopped"]


def test_hlt_is_reported_as_hlt_not_budget(tmp_path):
    # glibc's _start ends `call __libc_start_main; hlt`: a run ending there stopped after a few
    # instructions and was reported as "budget" (as if the instruction budget had run out)
    res = U.recover(_write(tmp_path, "hlt.elf", mkelf(b"\x90\x90\xf4\xcc")[0]))   # nop; nop; hlt
    assert res["stopped"] == "hlt", res["stopped"]


def test_code_run_then_overwritten_is_not_unpacking(tmp_path):
    # 16 nops run, then `rep stosb` wipes those already-executed bytes, then ret: no byte runs AFTER
    # being written, so nothing was unpacked
    code = (b"\x90" * 16 + b"\x48\x8d\x3d" + struct.pack("<i", -23) + b"\x31\xc0"
            + b"\xb9\x10\x00\x00\x00" + b"\xf3\xaa" + b"\xc3")
    res = U.recover(_write(tmp_path, "wipe.elf", mkelf(code)[0]))
    assert res["unpacked_detected"] is False
    assert not any(r["executed"] for r in res["unpacked"])


def test_x86_32_in_place_unpacker(tmp_path):
    # i386: store four `ret` bytes at TGT, jump there. Emulated in 32-bit mode (it used to run as x86-64)
    _, tva, _ = mkelf(b"\x00" * 96, bits=32)
    tgt = tva + 64
    code = (b"\xbf" + struct.pack("<I", tgt) + b"\xb8\xc3\xc3\xc3\xc3" + b"\xab" * 4
            + b"\xb8" + struct.pack("<I", tgt) + b"\xff\xe0").ljust(96, b"\x00")
    res = U.recover(_write(tmp_path, "x32.elf", mkelf(code, bits=32)[0]))
    assert res["arch"] == "x86"
    assert res["unpacked_detected"] is True and res["oep"] == tgt


def _hatch_stub(prog_bytes, hatch_bytes):
    """x86-64: store the 'unpacked program' at TEXT+0x200 and a hatch at TEXT+0x300, push the
    program's address and a dummy for `pop rdx`, rax = munmap, jump into the hatch -- the shape
    of UPX's static x86-64 ELF stub (measured: hatch `0f 05 5a c3` right after the text segment)."""
    _, tva, _ = mkelf(b"\x00" * 0x400)
    prog, hatch = tva + 0x200, tva + 0x300

    def store(va, chunk):                               # mov dword ptr [va], imm32
        return b"\xc7\x04\x25" + struct.pack("<I", va) + chunk.ljust(4, b"\x90")

    code = b"".join(store(prog + i, prog_bytes[i:i + 4]) for i in range(0, len(prog_bytes), 4))
    code += b"".join(store(hatch + i, hatch_bytes[i:i + 4]) for i in range(0, len(hatch_bytes), 4))
    code += b"\x68" + struct.pack("<I", prog) + b"\x6a\x00"          # push prog; push 0
    code += b"\xb8\x0b\x00\x00\x00\x31\xff\x31\xf6"                  # eax = munmap; edi = esi = 0
    jmp_at = tva + len(code)
    code += b"\xe9" + struct.pack("<i", hatch - (jmp_at + 5))        # jmp hatch
    return mkelf(code.ljust(0x400, b"\x00"))[0], prog, hatch


def test_upx_escape_hatch_is_not_the_oep(tmp_path):
    # CI run #118 / VALIDATION: UPX on a static glibc x86-64 ELF reported the hatch (syscall; pop
    # rdx; ret, written right after the text segment) as the OEP; the real entry is where its ret goes
    elf, prog, hatch = _hatch_stub(b"\x90\x90\x90\xeb\xfe", b"\x0f\x05\x5a\xc3")
    res = U.recover(_write(tmp_path, "hatch.elf", elf))
    assert res["stopped"] == "oep" and res["oep"] == prog, (res["stopped"], res["oep"], res["handoffs"])
    assert res["hatches"] == [hatch]
    assert res["handoffs"] == [{"va": prog, "in_image": True}]


def test_unpacked_entry_starting_with_syscall_is_still_the_oep(tmp_path):
    # the hatch shape needs the return: unpacked code that makes a system call and goes on (no ret
    # after the pops) is the program itself
    elf, prog, hatch = _hatch_stub(b"\x90\x90\x90\xeb\xfe", b"\x0f\x05\x5a\xeb\xfe")
    res = U.recover(_write(tmp_path, "nohatch.elf", elf))
    assert res["stopped"] == "oep" and res["oep"] == hatch and res["hatches"] == []


def test_write_tracking_memory_is_bounded(tmp_path, monkeypatch):
    # a stub that keeps storing across fresh pages is stopped at the page cap, not left to grow
    monkeypatch.setattr(U, "_MAX_WRITE_PAGES", 64)
    # rdi = HEAP; rcx = 1 MB; rep stosq
    code = (b"\x48\xbf" + struct.pack("<Q", U.HEAP) + b"\x48\xc7\xc1\x00\x00\x02\x00"
            + b"\x31\xc0\xf3\x48\xab\xc3")
    res = U.recover(_write(tmp_path, "fill.elf", mkelf(code)[0]))
    assert res["stopped"] == "write_cap", res["stopped"]


def test_abbreviated_execute_gate_rejected(tmp_path, monkeypatch):
    # argparse's default allow_abbrev turned `--dyn --i` into --dynamic --i-understand-this-executes;
    # the sample must never be armed to run from an abbreviation. Use a real file and record what
    # recover() would receive, so the test cannot pass on an unrelated "no such file" error.
    sample = _write(tmp_path, "s.bin", b"\0" * 64)
    seen = {}

    def fake_recover(path, entry=None, dynamic=False, ack=False, **kw):
        seen.update(dynamic=dynamic, ack=ack)
        return {"static": {"error": "x"}, "stages": [], "dynamic": None, "recommendation": "",
                "_regions": []}
    monkeypatch.setattr(unpack, "recover", fake_recover)
    try:
        unpack.main([str(sample), "--dyn", "--i", "--json"])
    except SystemExit as e:
        assert e.code == 2            # rejected by argparse: fine
    assert not seen.get("ack"), seen
    # the full spelling still works
    unpack.main([str(sample), "--dynamic", "--i-understand-this-executes", "--json"])
    assert seen == {"dynamic": True, "ack": True}
    # ... but not when it only appears in the target's pass-through --argv
    unpack.main([str(sample), "--dynamic", "--json", "--argv", "--i-understand-this-executes"])
    assert seen == {"dynamic": True, "ack": False}


RUST_PACKER = ROOT / "tests" / "fixtures" / "pack" / "rust_packer.exe"


def test_rust_written_packer_stage2_is_carved():
    # obf_src/rust_packer, pe size-lto (VALIDATION §83): a whole Rust std program is the stub; it
    # RC4-decrypts a 64-byte stage-2 into VirtualAlloc'd RWX memory and calls it. Before, std's
    # thread-locals failed (TlsSetValue returned 0) and the run aborted (__fastfail) before main's
    # own code: no OEP, nothing carved.
    import json
    want = bytes.fromhex(json.loads((ROOT / "obf_src" / "rust_packer" / "expected.json")
                                    .read_text())["stage2"]["x86_64"])
    res = U.recover(RUST_PACKER)
    carved = [r for r in res["_regions"] if r["executed"]]
    assert carved and carved[0]["_bytes"][:len(want)] == want, \
        ({k: res.get(k) for k in ("stopped", "oep")}, [r["_bytes"][:16].hex() for r in carved])
    assert res["oep"] == carved[0]["va"]
    assert "VirtualAlloc" in res["import_calls"]


GLIBC_ELF = ROOT / "tests" / "fixtures" / "deflatten" / "rustcloak_tree.x64"   # gcc, glibc, dynamic


def test_glibc_libc_start_main_runs_main():
    # every glibc ELF's _start ends in __libc_start_main(main, argc, argv, ...), which never
    # returns. It used to return 0, leaving _start at its `hlt`: the run stopped after one import
    # and no program code (a Rust-written packer's stub on x86-64 glibc, test_obf) ever ran.
    up = U._Unpacker(U.Image(GLIBC_ELF))
    up.run(up.img.binary.entrypoint - up.img.imagebase)
    assert up.stopped == "exit", up.stopped
    assert up.import_calls[0] == "__libc_start_main" and "puts" in up.import_calls, up.import_calls
    assert up.import_calls[-1] == "libc.so.6!exit"           # main returned into exit()
    tp = up.uc.reg_read(U.X.UC_X86_REG_FS_BASE)              # thread pointer for std's TLS reads
    assert tp and struct.unpack("<Q", bytes(up.uc.mem_read(tp, 8)))[0] == tp


def _call_import(up, api, *args):
    regs = [U.X.UC_X86_REG_RDI, U.X.UC_X86_REG_RSI, U.X.UC_X86_REG_RDX]
    for r, v in zip(regs, args):
        up.uc.reg_write(r, v)
    sp = U.STACK + U.STACK_SIZE - 0x1000
    up.uc.mem_write(sp, struct.pack("<Q", 0x1234))
    up.uc.reg_write(up.SP, sp)
    up._import(api, api)
    assert up.uc.reg_read(up.PC) == 0x1234
    return up.uc.reg_read(U.X.UC_X86_REG_RAX)


def test_libc_memory_imports_do_the_work_and_count_as_writes():
    # a glibc Rust program calls memcpy/memset/sysconf through the PLT; returning 0 handed std a
    # NULL destination and uncopied data (std then panicked before main). A model's copy is also a
    # write the unpacker must see: code copied by libc memcpy and then run is unpacked code.
    up = U._Unpacker(U.Image(GLIBC_ELF))
    src, dst = U.HEAP + 0x10, U.HEAP + 0x2ffc               # dst straddles a page boundary
    up.uc.mem_write(src, b"\x90" * 40 + b"\xc3")
    assert _call_import(up, "memcpy", dst, src, 41) == dst
    assert bytes(up.uc.mem_read(dst, 41)) == b"\x90" * 40 + b"\xc3"
    assert all(up._written(dst + i) for i in range(41)) and not up._written(dst + 41)
    assert _call_import(up, "memset", src, 0x41, 3) == src
    assert bytes(up.uc.mem_read(src, 4)) == b"AAA\x90"
    assert _call_import(up, "sysconf", 30) == 0x1000         # _SC_PAGESIZE
    assert _call_import(up, "memcmp", src, dst, 3) != 0
    assert _call_import(up, "strlen", src) == 41            # "AAA", 37 NOPs, ret, then zeroed heap


def test_process_stack_does_not_depend_on_host_path(tmp_path):
    # AT_EXECFN / argv[0] used to be the sample's resolved host path, so every address on the
    # initial stack (and a glibc program's stack-derived values, e.g. an import slot) moved with
    # the checkout's path length: the emu-equivalence golden differed between machines.
    data = GLIBC_ELF.read_bytes()
    short = tmp_path / "a" / "s.x64"
    deep = tmp_path / ("d" * 57) / ("e" * 31) / "s.x64"
    outs = []
    for p in (short, deep):
        p.parent.mkdir(parents=True)
        p.write_bytes(data)
        up = U._Unpacker(U.Image(p))
        sp = up._process_stack(up.img.binary.entrypoint)
        argv0 = struct.unpack("<Q", bytes(up.uc.mem_read(sp + 8, 8)))[0]
        outs.append((sp, argv0, bytes(up.uc.mem_read(argv0, 16))))
    assert outs[0] == outs[1], outs
    assert outs[0][2].startswith(b"/sample/s.x64\0")
