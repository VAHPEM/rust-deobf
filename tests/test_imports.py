"""PE import reconstruction (scripts/recover_imports.py).

The --selftest (via test_selftests.py) covers the call-site decoder on hand-assembled instructions.
Here we check real reconstruction on a committed PE: imports are listed and indirect call sites are
bound to the right API names.
"""
import sys

import pytest
from conftest import ROOT

sys.path.insert(0, str(ROOT / "scripts"))
pytest.importorskip("capstone")
import recover_imports as I  # noqa: E402

PE = ROOT / "tests" / "fixtures" / "vm" / "rustcloak_vm_pe.exe"
ELF = ROOT / "tests" / "fixtures" / "vm" / "benign_rust_std.x64"


def test_selftest():
    I._selftest()


def test_non_pe_is_reported_not_crashed():
    res = I.recover(ELF)
    assert res.get("error") and res["imports"] == []


@pytest.mark.skipif(not PE.is_file(), reason="PE fixture missing")
def test_reconstructs_pe_imports_and_callsites():
    res = I.recover(PE)
    assert res["format"] == "PE" and res["bits"] == 64
    # the import directory is read
    assert res["counts"]["imports"] > 10
    names = {(i["dll"], i["api"]) for i in res["imports"]}
    assert ("KERNEL32.dll", "EnterCriticalSection") in names
    # and .text call sites are bound back to those APIs
    assert res["counts"]["resolved_callsites"] > 0
    resolved_apis = {r["api"] for r in res["resolved_callsites"]}
    assert resolved_apis & {"EnterCriticalSection", "LeaveCriticalSection", "VirtualProtect"}
    # every resolved site points at a real imported api
    for r in res["resolved_callsites"]:
        assert (r["dll"], r["api"]) in names
        assert r["kind"] in ("call", "jmp")


FIX = ROOT / "tests" / "fixtures" / "imports"
_WANT = {("call", "GetTickCount"), ("jmp", "GetTickCount"), ("jmp", "Sleep")}


def _bound(res):
    return {(r["kind"], r["api"]) for r in res["resolved_callsites"]}


@pytest.mark.parametrize("name,arch,bits", [("imp_x64.exe", "x86-64", 64), ("imp_x86.exe", "x86", 32),
                                            ("imp_arm64.exe", "arm64", 64)])
def test_binds_iat_call_sites_on_every_arch(name, arch, bits):
    # x64: an undecodable byte (0xd6) sits in .text ahead of every call site; disasm() stopped
    # there and bound nothing. ARM64 was disassembled as x86-64 and silently bound nothing.
    res = I.recover(FIX / name)
    assert not res.get("error"), res
    assert res["arch"] == arch and res["bits"] == bits
    assert {i["api"] for i in res["imports"]} == {"GetTickCount", "Sleep"}
    assert res["counts"]["resolved_callsites"] == 4, res["resolved_callsites"]
    # the x86 build calls Sleep directly; x64/ARM64 tail-call it through a jmp/br
    want = _WANT if arch != "x86" else {("jmp", "GetTickCount"), ("call", "GetTickCount"),
                                        ("call", "Sleep")}
    assert _bound(res) == want, _bound(res)
    for r in res["resolved_callsites"]:
        assert r["dll"] == "KERNEL32.dll"


def test_unparseable_and_foreign_inputs_return_an_error_not_a_traceback(tmp_path):
    junk = tmp_path / "junk.bin"
    junk.write_bytes(b"not an executable at all\n" * 8)
    res = I.recover(junk)
    assert res.get("error") and res["imports"] == [] and res["resolved_callsites"] == []
    # a PE for a machine we cannot disassemble (ARMNT / Thumb-2) is an explicit error, never a
    # silent x86-64 sweep with an empty answer
    raw = bytearray((FIX / "imp_x64.exe").read_bytes())
    pe = int.from_bytes(raw[0x3c:0x40], "little")
    raw[pe + 4:pe + 6] = (0x1C4).to_bytes(2, "little")      # IMAGE_FILE_MACHINE_ARMNT
    armnt = tmp_path / "armnt.exe"
    armnt.write_bytes(bytes(raw))
    res = I.recover(armnt)
    assert "unsupported PE machine" in res.get("error", ""), res
    assert res["imports"] == []
    # the CLI prints JSON for these too
    import json
    import subprocess
    out = subprocess.run([sys.executable, str(ROOT / "scripts" / "recover_imports.py"), "--json",
                          str(junk)], capture_output=True, text=True, check=True).stdout
    assert json.loads(out)["error"]
