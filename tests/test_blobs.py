"""Blob triage pipeline (scripts/recover_blobs.py): carve -> keyless recovery -> crypto candidates.

The --selftest (via test_selftests.py) covers the keyless decoders. Here we pin them directly and
check precision on a real benign binary (no false "decoded").
"""
import gzip
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
    assert B._keyless(_rng(4096).randbytes(4096)) is None     # seeded: deterministic


def test_precision_on_benign_binary():
    res = B.recover(BENIGN)
    assert set(res) >= {"file_size", "crypto_candidates", "blobs", "counts"}
    # a normal Rust binary: no keyless-recoverable payloads
    assert res["counts"]["keyless_recovered"] == 0, res["counts"]
    for b in res["blobs"]:
        assert b["keyless"] is None


def _rng(seed):
    import random
    return random.Random(seed)


def test_xor_needs_a_validated_magic_not_two_bytes():
    # a 2-byte "MZ" after XOR was accepted as a key: ~1/700 random blobs falsely "decoded"
    rng = _rng(15)
    crafted = bytes([0x4d ^ 0x77, 0x5a ^ 0x77]) + rng.randbytes(1022)
    assert B._xor1_break(crafted) is None and B._keyless(crafted) is None
    # a 3-byte gzip/bzip2 magic is not proof either
    assert B._xor1_break(bytes(b ^ 0x21 for b in b"BZh") + rng.randbytes(509)) is None
    assert sum(1 for _ in range(3000) if B._xor1_break(rng.randbytes(512))) == 0
    # a real XOR'd PE (e_lfanew -> PE\0\0 beyond the first 512 bytes) is still recovered
    pe = bytearray(0x400)
    pe[0:2] = b"MZ"
    pe[0x3c:0x40] = (0x280).to_bytes(4, "little")
    pe[0x280:0x284] = b"PE\x00\x00"
    assert B._xor1_break(bytes(b ^ 0x5c for b in pe)) == {"key": 0x5c, "magic": "pe"}


def test_key_zero_is_plain_not_xor():
    # key 0 is the identity: a blob whose own bytes carry a magic is "plain", not "xor8 key=0"
    elf = b"\x7fELF\x02\x01\x01" + bytes(200)
    assert B._xor1_break(elf) is None
    assert B._keyless(elf) == {"method": "plain", "magic": "elf"}
    zipped = b"PK\x03\x04" + _rng(16).randbytes(600)
    assert B._keyless(zipped) == {"method": "plain", "magic": "zip"}


def test_decompression_output_is_capped(monkeypatch):
    import bz2
    import lzma
    import zlib
    monkeypatch.setattr(B, "MAX_OUT", 1 << 20)
    zeros = b"\x00" * (4 << 20)
    for method, comp in (("zlib", zlib.compress), ("gzip", gzip.compress),
                         ("bz2", bz2.compress), ("lzma", lzma.compress)):
        r = B._keyless(comp(zeros))
        assert r and r["method"] == method, (method, r)
        assert r["out_size"] == 1 << 20 and r["truncated_at"] == 1 << 20, (method, r)
    # under the cap: complete, not marked truncated
    r = B._keyless(gzip.compress(b"\x00" * 1000))
    assert r["out_size"] == 1000 and "truncated_at" not in r
    # an incomplete stream (cut short, not by our cap) is still rejected, as zlib.decompress would
    cut = gzip.compress(_rng(17).randbytes(4000))[:2000]
    assert B._try_decompress(cut)[0] is None


def test_gzip_overlay_at_eof_is_carved_and_decompressed(tmp_path):
    # the carve used to stop short of EOF, so a gzip overlay came back truncated and undecodable
    payload = _rng(18).randbytes(2900)
    gz = gzip.compress(payload)
    p = tmp_path / "tail_gz.bin"
    p.write_bytes(b"\x00" * 4096 + gz)
    res = B.recover(p)
    assert [(b["offset"], b["size"]) for b in res["blobs"]] == [(4096, len(gz))]
    k = res["blobs"][0]["keyless"]
    assert k and k["method"] == "gzip" and k["out_size"] == len(payload)
    assert res["counts"]["keyless_recovered"] == 1


def test_random_blobs_do_not_decompress():
    # random bytes parse as a tiny complete raw-deflate stream ~1 in 1000 times (10-60 bytes
    # consumed, the rest ignored): that was reported as a "zlib_raw" keyless recovery
    rng = _rng(19)
    hits = [B._try_decompress(rng.randbytes(2048))[0] for _ in range(4000)]
    assert [h for h in hits if h] == []
    # a real stream followed by carve overshoot (trailing bytes) is still accepted
    stream = gzip.compress(_rng(20).randbytes(300))          # >= _MIN_STREAM bytes, incompressible
    r = B._keyless(stream + _rng(21).randbytes(700))
    assert r and r["method"] == "gzip" and r["out_size"] == 300
