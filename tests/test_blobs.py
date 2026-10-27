"""Blob triage pipeline (scripts/recover_blobs.py): carve -> keyless recovery -> crypto candidates.

The --selftest (via test_selftests.py) covers the keyless decoders. Here we pin them directly and
check precision on a real benign binary (no false "decoded").
"""
import gzip
import os
import sys

from conftest import ROOT

sys.path.insert(0, str(ROOT / "scripts"))
import recover_blobs as B  # noqa: E402

BENIGN = ROOT / "tests" / "fixtures" / "vm" / "benign_rust_std.x64"


def test_selftest():
    B._selftest()


def test_decompression_is_keyless():
    plain = b"benign report payload, perfectly ordinary\n" * 8
    r = B._keyless(gzip.compress(plain))
    assert r and r["method"] == "gzip" and r["out_size"] == len(plain)
    # zlib stream too
    import zlib
    r2 = B._keyless(zlib.compress(plain))
    assert r2 and r2["method"] in ("zlib", "zlib_raw")


def test_xor_recovers_only_via_magic():
    # a one-byte-XOR'd ELF payload is recovered (magic uniquely fixes the key)
    elf = b"\x7fELF\x02\x01\x01" + bytes(200)
    x = B._xor1_break(bytes(b ^ 0x42 for b in elf))
    assert x == {"key": 0x42, "magic": "elf"}
    # plain text and random bytes must NOT yield a key (printability is ambiguous)
    assert B._xor1_break(b"just some readable words here and there " * 4) is None
    assert B._keyless(os.urandom(4096)) is None


def test_precision_on_benign_binary():
    res = B.recover(BENIGN)
    assert set(res) >= {"file_size", "crypto_candidates", "blobs", "counts"}
    # a normal Rust binary: no keyless-recoverable payloads
    assert res["counts"]["keyless_recovered"] == 0, res["counts"]
    for b in res["blobs"]:
        assert b["keyless"] is None
