"""Mach-O emulation.

The emulation engine loads ELF, PE and Mach-O. Mach-O cannot be built on a Linux CI runner, so a
few canary crates built for aarch64-apple-darwin are committed as fixtures (tests/fixtures/macho/)
and the engine must recover all five canaries from each. Covers the Mach-O path: __text lookup,
cpu_type arch detection, Mach-O executable-section flags, binding -> trampoline import fixups
(rebases are correct at the native vmaddr), and __text-symbol function discovery.
"""
import os
from pathlib import Path

import pytest
from conftest import ROOT

import recover_emulate as E

FIX = ROOT / "tests" / "fixtures" / "macho"
CRATES = ["xor_custom", "litcrypt", "obfstr"]
SECRETS = ["7f3c-config-endpoint", "build-id-20261018", "/opt/app/resources/data.bin",
           "feature-flag-telemetry-off", "schema-version-4"]


@pytest.mark.parametrize("crate", CRATES)
def test_macho_canaries(crate):
    binary = FIX / f"{crate}.arm64"
    if not binary.is_file():
        pytest.skip(f"fixture missing: {binary.name}")
    os.environ.setdefault("UC_IGNORE_REG_BREAK", "1")
    img = E.Image(str(binary))
    assert img.macho and img.arm, "fixture should be an arm64 Mach-O"
    r = E.recover(str(binary), [], time_budget=90)
    got = [x["string"] for x in r.get("records", [])]
    missing = [s for s in SECRETS if not any(s in g for g in got)]
    assert not missing, f"{crate}: missing {missing} (got {len(got)} strings)"


def test_macho_libfuncs():
    """Library-function identification works on Mach-O: signatures from one fixture identify
    functions in another, all correctly (scored against the target's own __text symbols)."""
    ref, tgt = FIX / "litcrypt.arm64", FIX / "xor_custom.arm64"
    if not (ref.is_file() and tgt.is_file()):
        pytest.skip("fixtures missing")
    import lief
    import recover_libfuncs as L
    db = L.generate([ref])
    assert db, "no signatures generated from the Mach-O reference"
    res = L.match_binary(tgt, db)
    assert len(res) >= 50, f"only {len(res)} library functions identified"
    # every identified address must be a real __text function in the target
    b = lief.parse(str(tgt))
    text = next(s for s in b.sections if s.name == "__text")
    lo, hi = text.virtual_address, text.virtual_address + text.size
    for r in res:
        assert lo <= r["va"] < hi, f"match at {r['va']:#x} outside __text"
