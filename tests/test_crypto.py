"""Crypto-primitive identification (recover_crypto.py).

The --selftest (constants-among-noise, random-noise-clean, below-threshold) runs via
test_selftests.py. This pins scan() directly and, when a system crypto library is present, that a
real binary's primitives are detected.
"""
import struct
import sys
from pathlib import Path

import pytest
from conftest import ROOT

sys.path.insert(0, str(ROOT / "scripts"))
import recover_crypto as C  # noqa: E402

pytestmark = pytest.mark.filterwarnings("ignore::RuntimeWarning")


def test_scan_byte_sequences_and_constant_sets():
    blob = bytearray(b"\x00" * 64)
    blob += C.AES_SBOX
    blob += b"expand 32-byte k"
    for c in (0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x428a2f98):
        blob += struct.pack("<I", c)
    hits = C.scan(bytes(blob))
    algos = {h["algo"] for h in hits}
    assert {"AES", "ChaCha20/Salsa20", "SHA-256"} <= algos
    aes = [h for h in hits if h["algo"] == "AES"][0]
    assert aes["match"] == "byte-sequence" and aes["confidence"] == "high"


def test_below_threshold_not_flagged():
    # two SHA-256 constants is below the min of 4 -> not flagged
    blob = b"\x00" * 100 + struct.pack("<I", 0x6a09e667) + struct.pack("<I", 0xbb67ae85)
    assert "SHA-256" not in {h["algo"] for h in C.scan(blob)}


def test_random_noise_clean():
    import os
    assert C.scan(os.urandom(4096)) == []


@pytest.mark.parametrize("lib", [
    "/usr/lib/x86_64-linux-gnu/libcrypto.so.3",
    "/lib/x86_64-linux-gnu/libcrypto.so.3",
])
def test_real_crypto_library(lib):
    p = Path(lib)
    if not p.is_file():
        pytest.skip(f"{lib} not present")
    res = C.recover(p)
    # libcrypto embeds AES tables and SHA constants; at least AES + one SHA must be found
    assert "AES" in res["algorithms"]
    assert any(a.startswith("SHA") for a in res["algorithms"])
    # each hit that landed in a section got a VA
    assert any(h.get("va") is not None for h in res["hits"])
