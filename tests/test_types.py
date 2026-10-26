"""Rust type-layout recovery (recover_types.py) - trait-object vtables.

The script's --selftest (synthetic buffer: real vtables vs decoy shapes, ZST, Ghidra structs) runs
via test_selftests.py. This adds end-to-end coverage on a committed real Rust binary and pins that
the recovered vtables are structurally sound and that the scan is precise (restricted to the data
sections, not the symbol/reloc metadata that otherwise yields absurd false vtables).
"""
import sys

import pytest
from conftest import ROOT

sys.path.insert(0, str(ROOT / "scripts"))
import recover_types as RT  # noqa: E402
import recover_emulate as E  # noqa: E402

pytestmark = pytest.mark.filterwarnings("ignore::RuntimeWarning")

FIXTURE = ROOT / "tests" / "fixtures" / "vm" / "benign_rust_std.x64"


def _exec(img, va):
    return img.text_va <= va < img.text_end or any(lo <= va < hi for lo, hi in img.exec_ranges)


def test_vtables_recovered_and_structurally_sound():
    res = RT.recover(FIXTURE)
    assert res["format"] == "ELF" and res["arch"] == "x86_64"
    vts = res["vtables"]
    # a real std Rust binary has several trait-object vtables, but not hundreds -- the section
    # whitelist keeps the symbol/hash/reloc tables (which produced 150+ false "vtables") out.
    assert 3 <= len(vts) <= 60, len(vts)
    img = E.Image(str(FIXTURE))
    for vt in vts:
        assert _exec(img, vt["drop_in_place"]), hex(vt["drop_in_place"])
        assert vt["align"] in RT._ALIGNS
        assert vt["size"] <= RT._MAX_SIZE and (vt["align"] == 0 or vt["size"] % vt["align"] == 0)
        assert vt["method_count"] >= 1
        for m in vt["methods"]:
            assert _exec(img, m), hex(m)


def test_recovery_is_deterministic():
    a = RT.recover(FIXTURE)["vtables"]
    b = RT.recover(FIXTURE)["vtables"]
    assert [v["va"] for v in a] == [v["va"] for v in b]


def test_ghidra_types_match_vtables():
    res = RT.recover(FIXTURE)
    counts = {}
    for vt in res["vtables"]:
        counts[vt["method_count"]] = counts.get(vt["method_count"], 0) + 1
    gt = {t["name"]: t for t in res["ghidra_types"]}
    for count, n in counts.items():
        name = f"RustVtable_{count}m"
        assert name in gt and gt[name]["instances"] == n
        t = gt[name]
        assert t["size"] == (3 + count) * res["ptr"]
        assert t["fields"][0]["name"] == "drop_in_place" and t["fields"][1]["name"] == "size"
        assert t["fields"][-1]["name"] == f"method_{count - 1}"


def test_metadata_sections_not_scanned():
    """The scan must ignore .dynsym/.rela/.gnu.hash etc. (pointer-shaped metadata) -- only the data
    sections hold vtables. Precision regression guard: those sections yielded 150+ false vtables."""
    assert not RT._is_type_section(".dynsym", "ELF")
    assert not RT._is_type_section(".rela.dyn", "ELF")
    assert not RT._is_type_section(".gnu.hash", "ELF")
    assert RT._is_type_section(".data.rel.ro", "ELF")
    assert RT._is_type_section(".rodata", "ELF")
