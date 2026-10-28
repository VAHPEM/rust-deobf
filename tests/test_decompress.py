"""Keyless decompressors (scripts/decompress.py): LZ4 block/frame/legacy, aPLib, BriefLZ, LZNT1.

Ground truth, three independent sources:
  * the python `lz4` package (TEST-ONLY, optional: importorskip) for LZ4 frames/blocks in every
    flag combination, both directions (its streams -> our decoder, our encoder -> its decoder);
  * published vectors with provenance: malduck's documented aPLib examples (headerless + 'AP32';
    produced by the real aPLib packer) and the [MS-XCA] LZNT1 worked example (Microsoft's spec);
    BriefLZ's own test-suite error vectors (brieflz test/test_brieflz.c, zlib licence);
  * round trips through tests/_compress.py's pure-Python encoders on several data shapes.
Then the strictness side: random blobs, zero-heavy real-binary windows and mutated streams must not
be accepted, must not raise, and must stay bounded.
"""
import hashlib
import json
import random
import subprocess
import sys
import time

import pytest
from conftest import ROOT

import _compress as C

sys.path.insert(0, str(ROOT / "scripts"))
import decompress as D  # noqa: E402

BENIGN = ROOT / "tests" / "fixtures" / "vm" / "benign_rust_std.x64"
ENCODERS = {
    "lz4_block": C.lz4_block, "lz4_frame": C.lz4_frame, "lz4_legacy": C.lz4_legacy,
    "aplib": C.aplib, "aplib_ap32": C.aplib_ap32, "brieflz": C.brieflz,
    "brieflz_blzpack": C.blzpack, "lznt1": C.lznt1,
}


def _rng(seed):
    return random.Random(seed)


def _shapes():
    rng = _rng(1)
    text = b"".join(b"cfg host=192.0.2.%d port=%d name=node%d.example\n"
                    % (rng.randrange(256), rng.randrange(65536), i) for i in range(400))
    reps = bytes(rng.randrange(6) for _ in range(3000)) + rng.randbytes(500) * 5
    return {
        "text": text,
        "binary_repeats": reps,
        "all_literal": rng.randbytes(2500),                   # incompressible: literals only
        "long_run": b"\x41" * 70000,                          # overlapping offset-1 matches
        "chunk_4096": text[:4096],                            # LZNT1 chunk boundary
        "chunk_4097": text[:4097],
        "tiny": b"abcdefgh",
        "code": BENIGN.read_bytes()[0x2000:0x2000 + 20000],
    }


def test_selftest():
    D._selftest()


# ------------------------------------------------------------------------- published vectors
def test_aplib_published_vectors():
    # malduck documentation (malduck.readthedocs.io, "Compression algorithms" / aplib)
    r = D.decode("aplib", b"T\x00he quick\xecb\x0erown\xcef\xaex\x80jumps\xed\xe4veur`t?lazy"
                          b"\xead\xfeg\xc0\x00")
    assert r["out"] == b"The quick brown fox jumps over the lazy dog"
    ap32 = (b"AP32\x18\x00\x00\x00\r\x00\x00\x00\xbc\x9ab\x9b\x0b\x00\x00\x00\x85\x11J\rh8el"
            b"\x8eo wnr\xecd\x00")
    r = D.decode("aplib_ap32", ap32)
    assert r["out"] == b"hello world" and r["consumed"] == len(ap32)
    # one flipped bit in the packed data breaks its CRC-32 -> rejected
    bad = bytearray(ap32)
    bad[30] ^= 1
    assert D.decode("aplib_ap32", bytes(bad)) is None


def test_lznt1_ms_xca_example():
    ms = bytes.fromhex("38b08846232000204720410010a24701a045204400084501507900c045200524"
                       "138805b4024a44ef0358028c091601484500be009e000401189000")
    r = D.decode("lznt1", ms)
    assert r["out"].endswith(b"F# E D D\x00") and len(r["out"]) == 142 and r["chunks"] == 1


def test_brieflz_reference_error_vectors():
    # brieflz test/test_brieflz.c data_errors: (src_size, depacked_size, data) that blz_depack_safe
    # must reject -- truncated tags/literals/offsets, gamma overflow, a match before the output
    cases = [(1, 2, b"\x42"), (2, 2, b"\x42\x00"), (3, 2, b"\x42\x00\x00"), (3, 5, b"\x42\x00\x80"),
             (4, 5, b"\x42\x55\x45\x42"), (3, 5, b"\x42\xaa\x8a"), (4, 5, b"\x42\x00\x80\x01"),
             (12, 3, b"\x42" + b"\xaa" * 8 + b"\x00\x00\x00"),
             (10, 5, b"\x42\xaa\x8a\xaa\xaa\xaa\xaa\x00\xc0\xff"), (4, 4, b"\x42\x00\x80\x00")]
    for n, size, data in cases:
        r = None
        try:
            lits = bytearray()
            r = D._brieflz_core(data[:n], 0, n, 1 << 20, lits, size)
        except D._Bad:
            pass
        assert r is None, (data, size)


# ------------------------------------------------------------------------------- LZ4 vs lz4 package
def test_lz4_frames_from_reference_library():
    lz4f = pytest.importorskip("lz4.frame")
    rng = _rng(2)
    data = _shapes()["text"] * 40 + rng.randbytes(90000) + _shapes()["code"]
    variants = [{}, {"block_linked": True}, {"block_linked": False},
                {"content_checksum": True, "block_checksum": True},
                {"store_size": True, "block_size": lz4f.BLOCKSIZE_MAX256KB},
                {"block_size": lz4f.BLOCKSIZE_MAX1MB}, {"block_size": lz4f.BLOCKSIZE_MAX4MB},
                {"compression_level": 12}, {"compression_level": 3, "block_checksum": True}]
    for kw in variants:
        z = lz4f.compress(data, **kw)
        r = D.decode("lz4_frame", z)
        assert r and r["out"] == data and r["consumed"] == len(z), kw
        assert D.try_all(z)["format"] == "lz4_frame"
    # two concatenated frames decode as one stream; trailing junk after a frame is tolerated
    z = lz4f.compress(data[:5000]) + lz4f.compress(data[5000:9000])
    r = D.decode("lz4_frame", z + b"\x00junk")
    assert r["out"] == data[:9000] and r["frames"] == 2 and r["consumed"] == len(z)
    # a corrupted content checksum is rejected
    z = bytearray(lz4f.compress(data[:3000], content_checksum=True))
    z[-1] ^= 0xFF
    assert D.decode("lz4_frame", bytes(z)) is None


def test_lz4_blocks_from_reference_library():
    lz4b = pytest.importorskip("lz4.block")
    for name, data in _shapes().items():
        for kw in ({}, {"mode": "high_compression", "compression": 12}, {"mode": "fast", "acceleration": 8}):
            z = lz4b.compress(data, store_size=False, **kw)
            r = D.decode("lz4_block", z)
            assert r and r["out"] == data, (name, kw)
            zs = lz4b.compress(data, **kw)                     # 4-byte LE size prefix (default)
            r = D.decode("lz4_block_sized", zs)
            assert r and r["out"] == data and r["declared_size"] == len(data), (name, kw)
        # legacy frame = magic + [u32 size + independent block]*, here built from reference blocks
        legacy = b"\x02\x21\x4c\x18" + len(z := lz4b.compress(data, store_size=False)).to_bytes(4, "little") + z
        assert D.decode("lz4_legacy", legacy)["out"] == data, name


def test_our_lz4_encoder_against_reference_decoder():
    lz4f = pytest.importorskip("lz4.frame")
    lz4b = pytest.importorskip("lz4.block")
    for data in _shapes().values():
        assert lz4b.decompress(C.lz4_block(data), uncompressed_size=len(data)) == data
        z = C.lz4_frame(data, block_checksum=True, content_checksum=True, content_size=True)
        assert lz4f.decompress(z) == data


# ------------------------------------------------------------------------------------- round trips
@pytest.mark.parametrize("fmt", sorted(ENCODERS))
def test_round_trip_every_shape(fmt):
    for name, data in _shapes().items():
        z = ENCODERS[fmt](data)
        r = D.decode(fmt, z)
        assert r and r["out"] == data and not r["truncated"], (fmt, name)


def test_lz4_frame_flag_matrix_and_multiple_blocks():
    data = _shapes()["text"] * 4 + _shapes()["code"]                # > 64 KiB: several blocks
    for bsum in (False, True):
        for csum in (False, True):
            for csize in (False, True):
                for raw in (False, True):
                    z = C.lz4_frame(data, block_checksum=bsum, content_checksum=csum,
                                    content_size=csize, raw_blocks=raw)
                    r = D.decode("lz4_frame", z)
                    assert r and r["out"] == data, (bsum, csum, csize, raw)
    # a block of a frame that declares 64 KiB blocks may not exceed it
    z = bytearray(C.lz4_frame(b"x" * 10))
    z[5] = 0x40
    hc = (D.xxh32(bytes(z[4:6])) >> 8) & 0xFF
    z[6] = hc
    assert D.decode("lz4_frame", bytes(z))["out"] == b"x" * 10
    z[6] ^= 1                                                       # header checksum
    assert D.decode("lz4_frame", bytes(z)) is None
    # a wrong declared content size is rejected
    z = bytearray(C.lz4_frame(data[:5000], content_size=True))
    z[6] ^= 1
    z[14] = (D.xxh32(bytes(z[4:14])) >> 8) & 0xFF
    assert D.decode("lz4_frame", bytes(z)) is None


def test_lz4_legacy_multiblock(monkeypatch):
    monkeypatch.setattr(D, "_LZ4_LEGACY_BLOCK", 4096)              # small blocks: same layout
    data = _shapes()["text"] * 3
    z = C.lz4_legacy(data, block=4096)
    r = D.decode("lz4_legacy", z)
    assert r and r["out"] == data and r["blocks"] == -(-len(data) // 4096)
    assert D.decode("lz4_legacy", z + b"\x04\x22\x4d\x18rest")["consumed"] == len(z)


def test_lznt1_chunk_boundaries_and_terminator():
    text = _shapes()["text"]
    for n in (1, 4095, 4096, 4097, 8192, 8193, 12000):
        data = (text * 3)[:n]
        if n < 8:
            continue
        for term in (False, True):
            z = C.lznt1(data, terminator=term)
            r = D.decode("lznt1", z)
            assert r["out"] == data and r["chunks"] == -(-n // 4096) and r["terminated"] == term
    # an uncompressible chunk is stored raw (header bit 15 clear): a full 4096-byte chunk
    raw = _rng(3).randbytes(4096) + text[:3000]
    z = C.lznt1(raw)
    assert z[1] & 0x80 == 0 and D.decode("lznt1", z)["out"] == raw
    # a non-final chunk that decodes short is rejected (RtlCompressBuffer never emits one)
    short = C.lznt1(text[:1000]) + C.lznt1(text[:1000])
    assert D.decode("lznt1", short) is None


def test_brieflz_both_end_styles_and_blzpack():
    for data in _shapes().values():
        for fin in (True, False):            # 1.2+ trailing delimiter bit, or the older bare end
            assert D.decode("brieflz", C.brieflz(data, finalize=fin))["out"] == data
            # known output size (blz_depack's API): must stop at the very same end
            assert D.decode("brieflz", C.brieflz(data, finalize=fin), size=len(data))["out"] == data
    # a non-padding bit pattern at the end is rejected
    z = bytearray(C.brieflz(_shapes()["text"]))
    z += b"\x01"
    assert D.decode("brieflz", bytes(z)) is None
    data = _shapes()["text"] * 10
    for chk in (True, False):
        z = C.blzpack(data, block=8192, checksum=chk)
        r = D.decode("brieflz_blzpack", z)
        assert r["out"] == data and r["blocks"] == -(-len(data) // 8192)
    z = bytearray(C.blzpack(data))
    z[-1] ^= 0x40                                                   # packed CRC no longer matches
    assert D.decode("brieflz_blzpack", bytes(z)) is None


def test_aplib_rep_match_short_match_and_nibble_paths_exercised():
    # the encoder must have produced every item kind for the round trips to mean something
    data = _shapes()["binary_repeats"] + b"\x00abc\x00abd\x00abe" * 50
    z = C.aplib(data)
    assert all(C.APLIB_STATS.values()), C.APLIB_STATS
    assert D.decode("aplib", z)["out"] == data
    r = D.decode("aplib_ap32", C.aplib_ap32(data))
    assert r["out"] == data and r["declared_size"] == len(data)
    # 110 + 0x00 is the end marker; 0x01 (offset 0, length bit set) is not an end encoders emit
    out, pos, cut = D._aplib_core(b"A\xc0\x00", 0, 3, 1 << 20, bytearray())
    assert bytes(out) == b"A" and pos == 3 and not cut
    with pytest.raises(D._Bad):
        D._aplib_core(b"A\xc0\x01", 0, 3, 1 << 20, bytearray())
    with pytest.raises(D._Bad):                     # non-zero padding bits after the end marker
        D._aplib_core(b"A\xc1\x00", 0, 3, 1 << 20, bytearray())


# --------------------------------------------------------------------------------- caps and bounds
def test_output_cap_reports_truncation():
    big = (_shapes()["text"] * 40)[:600000]                        # through a 256 KiB cap
    cap = 256 << 10
    for fmt, enc in ENCODERS.items():
        z = enc(big)
        r = D.decode(fmt, z, max_out=cap)
        assert r and r["truncated"] and len(r["out"]) == cap, fmt
        assert r["out"] == big[:cap], fmt
        # through the acceptance policy too (a cut stream is judged on what came out)
        a = D.accept(fmt, z, r)
        assert a is not None, fmt
    # exactly at the cap is complete, not truncated
    data = _shapes()["text"][:5000]
    for fmt, enc in ENCODERS.items():
        r = D.decode(fmt, enc(data), max_out=len(data))
        assert r and r["out"] == data and not r["truncated"], fmt


def test_hostile_inputs_never_raise_and_stay_linear():
    rng = _rng(4)
    valid = {fmt: enc(_shapes()["text"]) for fmt, enc in ENCODERS.items()}
    for fmt, z in valid.items():
        for _ in range(120):
            m = bytearray(z)
            for _k in range(rng.randrange(1, 6)):
                m[rng.randrange(len(m))] = rng.randrange(256)
            cut = bytes(m[:rng.randrange(1, len(m) + 1)])
            for blob in (bytes(m), cut):
                for f in D.FORMATS:                                    # any exception fails here
                    r = D.decode(f, blob, max_out=1 << 20)
                    assert r is None or len(r["out"]) <= 1 << 20
    # pathological shapes: long gamma runs, 0xFF length chains, zeros -- quick and None/bounded
    for blob in (b"\xff" * (1 << 19), bytes(1 << 19), b"\xaa" * (1 << 19), b"\x0f" + b"\xff" * 100000):
        t = time.time()
        for f in D.FORMATS:
            r = D.decode(f, blob)
            assert r is None or len(r["out"]) <= D.MAX_OUT
        assert time.time() - t < 30, "decoder not linear on a pathological input"


# ------------------------------------------------------------------------ false-positive rate
def test_random_blobs_are_never_accepted():
    """2000 random blobs of 512 B and of 4 KiB per format (all formats see every blob)."""
    rng = _rng(0xf9)
    for size in (512, 4096):
        hits = [(f, size) for _ in range(2000) for f in [D.try_all(rng.randbytes(size))] if f]
        assert hits == [], hits


def test_real_binary_windows_are_not_accepted_as_headerless_streams():
    """Uncompressed code/data (zero-heavy) parses as near-identity BriefLZ/aPLib/LZNT1 streams:
    the expansion + evidence rules must reject every such window of a real binary."""
    raw = BENIGN.read_bytes()
    hits = []
    for off in range(0, len(raw), 1024):
        for n in (512, 4096):
            r = D.try_all(raw[off:off + n])
            if r:
                hits.append((off, n, r["format"], r.get("evidence")))
    assert hits == [], hits[:5]


def test_evidence_gate_both_directions():
    rng = _rng(5)
    # accepts: a validated magic, text, structured binary (x86-64 code: literals keep their skew)
    pe = bytearray(0x200)
    pe[:2], pe[0x3c:0x40], pe[0x80:0x84] = b"MZ", (0x80).to_bytes(4, "little"), b"PE\x00\x00"
    assert D.evidence(bytes(pe), bytes(pe[:64])) == "magic:pe"
    txt = _shapes()["text"]
    assert D.evidence(txt, txt[:300], C.aplib(txt)) == "text"
    code = _shapes()["code"]
    z = C.aplib(code)
    r = D.decode("aplib", z)
    assert D.evidence(r["out"], r["literals"], z) == "entropy_drop"
    # rejects: random output; a printable run made by one long match over random literals; a
    # constant input "decoding" to itself; random literals even when the output looks structured
    assert D.evidence(rng.randbytes(4000), rng.randbytes(1000), rng.randbytes(4000)) is None
    assert D.evidence(b"A" * 5000, rng.randbytes(400), rng.randbytes(500)) is None
    assert D.evidence(bytes(5000), bytes(500), bytes(600)) is None
    lits = rng.randbytes(512)
    assert D.evidence(lits[:64] * 60, lits, rng.randbytes(700)) is None
    # and through the full policy: a valid headerless stream of RANDOM plaintext is a decode
    # nobody can tell from noise -- rejected (only containers report it)
    noise = rng.randbytes(3000)
    for fmt in ("lz4_block", "aplib", "brieflz", "lznt1"):
        z = ENCODERS[fmt](noise)
        assert D.decode(fmt, z)["out"] == noise and D.try_all(z) is None, fmt
    for fmt in ("lz4_frame", "aplib_ap32", "brieflz_blzpack"):
        assert D.try_all(ENCODERS[fmt](noise))["format"] == fmt


def test_h_uniform_matches_simulation():
    rng = _rng(6)
    for n in (64, 256, 1024):
        sim = sum(D._entropy(rng.randbytes(n)) for _ in range(200)) / 200
        assert abs(sim - D._h_uniform(n)) < 0.02, (n, sim, D._h_uniform(n))


def test_try_all_prefers_containers_and_reports_evidence():
    code = _shapes()["code"]
    for fmt in ("lz4_frame", "lz4_legacy", "aplib_ap32", "brieflz_blzpack"):
        r = D.try_all(ENCODERS[fmt](code))
        assert r["format"] == fmt and "evidence" not in r
    for fmt in ("lz4_block", "aplib", "brieflz", "lznt1"):
        r = D.try_all(ENCODERS[fmt](code))
        assert r["format"] == fmt and r["evidence"] == "entropy_drop", fmt


def test_cli_json(tmp_path):
    data = b"\x7fELF\x02\x01\x01" + bytes(57) + _shapes()["text"]
    p = tmp_path / "payload.blz"
    p.write_bytes(b"pad!" + C.brieflz(data))
    out = subprocess.run([sys.executable, str(ROOT / "scripts" / "decompress.py"), "--json",
                          "--offset", "4", str(p)], capture_output=True, text=True, timeout=120)
    res = json.loads(out.stdout)
    assert [d["format"] for d in res["decoded"]] == ["brieflz"], res
    d = res["decoded"][0]
    assert d["out_size"] == len(data) and d["out_magic"] == "elf" and d["evidence"] == "magic:elf"
    assert d["out_sha256"] == hashlib.sha256(data).hexdigest() and res["tried"] == list(D.FORMATS)
