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
