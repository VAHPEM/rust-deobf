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
