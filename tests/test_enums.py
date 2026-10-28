"""Enum discriminant / niche layout recovery (scripts/recover_enums.py).

The --selftest (via test_selftests.py) covers the capstone dispatch-site heuristic always, and the
DWARF path when pyelftools + the fixture are present. Here we pin the DWARF path on a committed
debuginfo fixture (named variants + niche) and check the stripped heuristic + precision.
"""
import sys

import pytest
from conftest import ROOT

sys.path.insert(0, str(ROOT / "scripts"))
import recover_enums as E  # noqa: E402

DBG = ROOT / "tests" / "fixtures" / "enums" / "enum_dbg.elf64"
STRIPPED = ROOT / "tests" / "fixtures" / "vm" / "benign_rust_std.x64"


def test_selftest():
    E._selftest()


def test_dispatch_heuristic():
    # movzx eax,[rdi]; cmp eax,0/1/2 -> a 3-value dispatch on field offset 0
    code = bytes.fromhex("0fb607" "83f800" "7405" "83f801" "7405" "83f802")
    sites = E._dispatch_sites(code, 0x1000)
    assert sites and sites[0]["field_offset"] == 0 and sites[0]["values"] == [0, 1, 2]
    # one compare is not a dispatch
    assert E._dispatch_sites(bytes.fromhex("0fb607" "83f800"), 0x1000) == []


def test_dispatch_heuristic_arm64():
    # ldrb w0,[x0]; cmp w0,#0/1/2 (b.eq each): a 3-value dispatch on field offset 0
    a64 = bytes.fromhex("00004039" "1f000071" "40000054" "1f040071" "40000054" "1f080071" "40000054")
    sites = E._dispatch_sites_arm64(a64, 0x2000)
    assert sites and sites[0]["field_offset"] == 0 and sites[0]["values"] == [0, 1, 2]


@pytest.mark.skipif(not DBG.is_file(), reason="debuginfo fixture missing")
def test_dwarf_named_variants_and_niche():
    pytest.importorskip("elftools")
    res = E.recover(DBG)
    assert res["has_dwarf"] is True
    by = {e["name"]: e for e in res["enums"]}
    # tag enum: Shape with three named variants at a real discriminant field
    shape = by.get("Shape")
    assert shape and shape["discriminant"] and shape["discriminant"]["size"] == 4
    assert {v["name"]: v["value"] for v in shape["variants"]} == {"Circle": 0, "Rect": 1, "Empty": 2}
    # niche enum: Option<&u64> — None is the tag, Some is the niche/default variant
    opt = next((e for e in res["enums"] if e["name"].startswith("Option<")), None)
    assert opt and opt["niche"] is True
    assert any(v["value"] is None for v in opt["variants"])  # the niche/"otherwise" variant


@pytest.mark.skipif(not STRIPPED.is_file(), reason="stripped fixture missing")
def test_stripped_binary_no_dwarf_but_well_formed():
    res = E.recover(STRIPPED)
    assert res["has_dwarf"] is False
    assert set(res) >= {"has_dwarf", "enums", "discriminant_sites", "counts"}
    # no names without debug info; the heuristic may surface dispatch sites, each well-formed
    for s in res["discriminant_sites"]:
        assert len(s["values"]) >= 2 and "field_offset" in s


def test_non_elf_reported(tmp_path):
    # a closed file under tmp_path, not a still-open NamedTemporaryFile: Windows refuses to reopen
    # an open NamedTemporaryFile by name (PermissionError), which made this test fail there
    f = tmp_path / "not_elf.bin"
    f.write_bytes(b"MZ" + b"\x00" * 64)
    res = E.recover(str(f))
    assert res.get("error") and res["enums"] == []
