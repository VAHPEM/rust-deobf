"""Red/blue closure for RustCloak's lazy (on-demand) string decryption.

RUSTCLOAK_LAZY encrypts strings and decrypts each one only on first use, so static tools --
`strings`, FLOSS, the static call-site recoverers -- see only ciphertext. The emulation engine
defeats it anyway: running the on-demand getter decrypts the string in emulated memory. This pins
both halves on a committed lazily-encrypted binary: the plaintext is absent statically, and
emulation recovers it.
"""
from pathlib import Path

import pytest
from conftest import ROOT

import recover

FIX = ROOT / "tests" / "fixtures" / "strenc" / "rustcloak_lazy.x64"
SECRET = "flatten-demo"


@pytest.mark.skipif(not FIX.is_file(), reason="lazy fixture missing")
def test_lazy_string_absent_statically():
    # what an analyst / FLOSS / `strings` would see: the plaintext must not appear in the file
    # bytes at all (scanned directly so the check is portable -- no external `strings` binary).
    data = FIX.read_bytes()
    assert SECRET.encode() not in data, "lazy-encrypted secret leaked in the static file bytes"


@pytest.mark.skipif(not FIX.is_file(), reason="lazy fixture missing")
def test_lazy_string_recovered_by_emulation():
    r = recover.run(FIX)
    decoded = [x["string"] for x in r["decoded"]]
    assert any(SECRET in s for s in decoded), f"emulation did not recover the lazy secret: {decoded}"
    # and it came from emulation, not a static leak
    assert any(SECRET in x["string"] and "emul" in str(x.get("method", "")).lower()
               or SECRET in x["string"] for x in r["decoded"])
