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


# ------------------------------------------------- LZ4 / aPLib / BriefLZ / LZNT1 (decompress.py)
def _stub_pe(extra=b""):
    """A benign MZ stub whose e_lfanew points at PE\\0\\0 (recover_embedded's validated "pe")."""
    hdr = bytearray(0x100)
    hdr[:2] = b"MZ"
    hdr[0x3c:0x40] = (0x80).to_bytes(4, "little")
    hdr[0x80:0x84] = b"PE\x00\x00"
    return bytes(hdr) + extra


_CONFIG = b"".join(b"[node%d]\nhost=192.0.2.%d\nport=%d\nname=n%d.example\n" % (i, i % 250, 8000 + i, i)
                   for i in range(60))


def _compressors():
    import _compress as C
    return {"lz4_frame": C.lz4_frame, "lz4_legacy": C.lz4_legacy, "aplib_ap32": C.aplib_ap32,
            "brieflz_blzpack": C.blzpack,
            "lz4_block_sized": lambda d: len(d).to_bytes(4, "little") + C.lz4_block(d),
            "lz4_block": C.lz4_block, "aplib": C.aplib, "brieflz": C.brieflz, "lznt1": C.lznt1}


def test_dropper_overlay_every_format(tmp_path):
    """An ELF 'dropper' with a compressed overlay at EOF (RustDuck-style: core/config appended):
    containers are found by their magic, headerless streams at the exact overlay start."""
    from _mkelf import mkelf
    host, _va, _bss = mkelf(b"\x90" * 200 + b"\xc3")
    for plain, magic in ((_stub_pe(_CONFIG), "pe"), (_CONFIG, None)):
        for fmt, comp in _compressors().items():
            p = tmp_path / f"dropper_{fmt}.bin"
            p.write_bytes(host + comp(plain))
            res = B.recover(p)
            hits = [s for s in res["streams"] if s["offset"] == len(host)]
            assert len(hits) == 1, (fmt, res["streams"])
            s = hits[0]
            k = s["keyless"]
            assert k and k["method"] == fmt and k["out_size"] == len(plain), (fmt, s)
            assert k["out_magic"] == magic, (fmt, k)
            container = fmt in ("lz4_frame", "lz4_legacy", "aplib_ap32", "brieflz_blzpack")
            assert s["anchor"] == ("magic:" if container else "overlay") + (
                {"lz4_frame": "lz4", "lz4_legacy": "lz4_legacy", "aplib_ap32": "aplib",
                 "brieflz_blzpack": "brieflz"}[fmt] if container else ""), (fmt, s["anchor"])
            if not container:
                assert k["evidence"] == ("magic:pe" if magic else "text"), (fmt, k)
            assert res["counts"]["keyless_recovered"] >= 1


def test_headerless_overlay_carved_at_eof(tmp_path):
    """No executable header at all: a high-entropy headerless stream flush with EOF is carved whole
    by recover_embedded's final window and decoded from the carve (evidence: the MZ stub).
    Only for streams the entropy carve sees: literal-heavy BriefLZ/LZNT1 interleave a 0x0000 flag
    word/byte every 16/8 literals, which pulls 512-byte windows under the 7.2 bits/byte threshold
    (measured 7.53 overall, no window >= 7.2) -- those need an exact anchor (host overlay, magic)."""
    rng = _rng(31)
    noise = rng.randbytes(2500)
    plain = _stub_pe(noise + noise)              # incompressible half + one long match
    for fmt in ("lz4_block", "aplib"):
        z = _compressors()[fmt](plain)
        p = tmp_path / f"tail_{fmt}.bin"
        p.write_bytes(b"\x00" * 4096 + z)
        res = B.recover(p)
        assert [(b["offset"], b["size"]) for b in res["blobs"]] == [(4096, len(z))], (fmt, res["blobs"])
        k = res["blobs"][0]["keyless"]
        assert k and k["method"] == fmt and k["out_size"] == len(plain) and k["evidence"] == "magic:pe", (fmt, k)
        assert res["streams"] == []                  # no host header -> no overlay anchor


def test_overlay_offset_parses_elf_and_pe():
    from _mkelf import mkelf
    for bits in (64, 32):
        host, _va, _bss = mkelf(b"\xc3" * 64, bits=bits, bss=0x100)
        assert B._overlay_offset(host) is None                       # nothing appended
        assert B._overlay_offset(host + b"tail") == len(host)
    pe = bytearray(0x400)
    pe[:2] = b"MZ"
    pe[0x3c:0x40] = (0x80).to_bytes(4, "little")
    pe[0x80:0x84] = b"PE\x00\x00"
    pe[0x86:0x88] = (1).to_bytes(2, "little")                       # one section
    pe[0x94:0x96] = (0xf0).to_bytes(2, "little")                    # SizeOfOptionalHeader
    pe[0x98 + 60:0x98 + 64] = (0x200).to_bytes(4, "little")         # SizeOfHeaders
    sec = 0x98 + 0xf0
    pe[sec + 16:sec + 24] = (0x200).to_bytes(4, "little") + (0x200).to_bytes(4, "little")
    assert B._overlay_offset(bytes(pe)) is None
    assert B._overlay_offset(bytes(pe) + b"overlay!") == 0x400
    # hostile headers never raise
    rng = _rng(32)
    for _ in range(500):
        junk = bytearray(rng.randbytes(256))
        junk[:4] = rng.choice([b"\x7fELF", b"MZ\x00\x00"])
        junk[4:6] = bytes([rng.choice([1, 2]), rng.choice([1, 2])])
        B._overlay_offset(bytes(junk))


def test_container_magic_in_code_is_not_a_stream(tmp_path):
    # the LZ4 frame magic as an immediate in code (cmp eax, 0x184d2204) has no valid header after it
    p = tmp_path / "lz4_const.bin"
    p.write_bytes(b"\x90" * 100 + b"\x3d\x04\x22\x4d\x18\x75\x10" + b"\x90" * 100 + b"AP32" + bytes(40))
    res = B.recover(p)
    assert res["streams"] == [] and res["embedded"] == []
