#!/usr/bin/env python3
"""decompress.py - strict, bounded, pure-Python decoders for the compressors malware packs payloads
and configs with: LZ4 (block, frame, legacy frame), BriefLZ, aPLib and LZNT1. Keyless: a compressed
payload needs no key, so recover_blobs.py runs these after zlib/gzip/bz2/lzma.

Formats (name -> what is accepted):
  lz4_frame        LZ4 frame (magic 04 22 4D 18): FLG/BD validated, header checksum (HC) checked,
                   optional block / content checksums (xxHash32) and content size verified,
                   linked or independent blocks, concatenated frames + skippable frames
  lz4_legacy       legacy LZ4 frame (magic 02 21 4C 18): independent blocks of <= 8 MiB output
  aplib_ap32       aPLib with its 'AP32' header (aPsafe): sizes and both CRC-32s verified
  brieflz_blzpack  BriefLZ in the blzpack container ('blz' 0x1A, version 1): sizes + CRC-32s
  lz4_block_sized  raw LZ4 block behind a 4-byte LE uncompressed size (lz4_flex
                   compress_prepend_size, python-lz4 block default): decoded size must match
  lz4_block        raw LZ4 block (no header)
  aplib            headerless aPLib stream (aP_depack semantics, ends at its end-of-data marker)
  brieflz          headerless BriefLZ stream (blz_depack semantics; no end marker)
  lznt1            LZNT1 (RtlDecompressBuffer COMPRESSION_FORMAT_LZNT1): 4 KiB chunks, 2-byte
                   headers with the 0b011 signature

Every decoder is STRICT and SAFE on hostile input: output is capped at max_out (default MAX_OUT =
16 MiB; a cut stream is reported truncated), work is linear in input + output (match copies are
slice operations, gamma codes are capped so a run of 1-bits cannot grow a huge integer), and garbage
returns None -- decoders never raise. Structure is validated wherever the format allows it: offsets
must point inside the output already produced, lengths must not overrun, padding bits must be zero,
and the stream must end exactly where the format says it ends.

The headerless formats (lz4_block, aplib, brieflz, lznt1 and, more weakly, lz4_block_sized) have
no magic. Random bytes die in the strict decoders (0 of 40,000 random 512 B / 4 KiB blobs decode
in any format), but zero-heavy UNcompressed data does not: a run of 0x00 is a valid all-literal
BriefLZ/aPLib/LZNT1 stream (1,647 of 14,328 windows of the repo's benign fixture binaries decoded
as one of them). So, beyond strict decoding, a headerless decode is accepted only when
  (1) it consumes the WHOLE input -- or, for the formats with an explicit end (aPLib's end-of-data
      marker, LZNT1's 0x0000 terminator), at least min(128 bytes, the whole input), the same rule
      recover_blobs applies to raw deflate; and
  (2) it EXPANDS: output >= 1.1x the bytes consumed, unless the output carries a validated magic
      (on real binaries, zero-heavy code/data read as BriefLZ/aPLib/LZNT1 parses as near-identity
      all-literal streams that pass (1); real compression of anything worth triage expands); and
  (3) its output is INTERESTING (evidence()), judged on the bytes that came out:
      - "magic:<kind>"  a validated file magic at offset 0 (recover_embedded's _find_magics: PE
                        needs e_lfanew -> PE\\0\\0, ELF a sane e_ident; only signatures of >= 4
                        bytes or the validated PE count, as for recover_blobs' XOR brute);
      - "text"          >= 32 output bytes, >= 85% of the first 64 KiB printable, AND >= 85% of
                        the LITERAL bytes printable (at least 8 literals);
      - "entropy_drop"  (>= 256 output bytes and >= 256 literals) all three of: the output's
                        order-0 entropy is >= 1 bit/byte below what as many uniform random bytes
                        show (_h_uniform: the exact expectation, not 8.0 -- the plug-in estimate
                        is biased low for short samples); the LITERALS' entropy is >= 0.2 below
                        their own uniform expectation (>= 3.7 sigma at 256 literals, >= 50 sigma
                        at 4 KiB); and the output is >= 0.25 bit/byte below the input (a
                        constant/low-entropy input "decoding" to itself is no decompression).
      The literal criteria matter: a decoder run over random input copies random literals, and a
      long match replicates a few of them, so the OUTPUT can look low-entropy or printable (a run
      of 'A's) while the LITERALS -- the bytes taken straight from the input -- stay random. Real
      compressed text or code keeps some of the payload's skew in its literals (measured on x86-64
      code: 0.24-1.2 bits below uniform for aPLib, ~1 bit for LZ4/BriefLZ/LZNT1). A payload
      without magic, not text, and with < 256 literals (tiny, or almost all matches) is missed.
Container formats (magic + checksums or exact sizes) need neither rule; trailing bytes after a
self-delimiting container are allowed (a carve can overshoot) and reported via `consumed`.

Written from the format documentation and reference sources: LZ4 block/frame format docs
(lz4/lz4 doc/, BSD-2), aPLib's depack.c semantics as also implemented by apultra's expand.c
(zlib/CC0), BriefLZ's depack.c/brieflz.c/blzpack.c (Joergen Ibsen, zlib licence) and Microsoft's
[MS-XCA] LZNT1 specification. No code was copied; malduck's GPL decoders were only consulted for
semantics, not adapted.
"""
import hashlib
import math
import struct
import sys
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import recover_embedded  # noqa: E402

MAX_OUT = 16 << 20      # output cap (same as recover_blobs.MAX_OUT): a small bomb must not amplify
_MIN_STREAM = 128       # an end-marked headerless stream shorter than the blob must still be >= this
_SAMPLE = 64 << 10      # bytes of output / literals the evidence gate looks at
_GAMMA_MAX = 1 << 26    # a gamma code above this cannot be a valid length/offset under the cap
_MIN_OUT = 8            # outputs shorter than this are never reported (nothing to triage)
_MIN_RATIO = 1.1        # a headerless decode must expand its input at least this much


class _Bad(Exception):
    """Invalid stream (internal; never escapes a public decoder)."""


def _copy(out, off, n):
    """LZ77 match copy: append n bytes starting `off` back, overlap-safe (a short offset repeats its
    period), as slice operations -- linear in n with no per-byte Python loop."""
    start = len(out) - off
    if off >= n:
        out += out[start:start + n]
    else:
        pat = bytes(out[start:])
        out += (pat * (n // off + 1))[:n]


# ---------------------------------------------------------------------------------------- xxHash32
_P1, _P2, _P3, _P4, _P5 = 2654435761, 2246822519, 3266489917, 668265263, 374761393
_M32 = 0xFFFFFFFF
try:                                   # optional C implementation (not a dependency)
    import xxhash as _xxhash
except ImportError:
    _xxhash = None


def xxh32(data, seed=0) -> int:
    """xxHash32 (the LZ4 frame checksum). Uses the `xxhash` package when importable, else pure
    Python (~2 MB/s: a 16 MiB frame with content + block checksums costs ~16 s to verify;
    `pip install xxhash` makes it C speed)."""
    if _xxhash is not None:
        return _xxhash.xxh32_intdigest(bytes(data), seed)
    n = len(data)
    i = 0
    if n >= 16:
        v1, v2, v3, v4 = (seed + _P1 + _P2) & _M32, (seed + _P2) & _M32, seed & _M32, (seed - _P1) & _M32
        stop = n - n % 16
        for a, b, c, d in struct.iter_unpack("<4I", memoryview(data)[:stop]):
            v1 = (v1 + a * _P2) & _M32
            v1 = (((v1 << 13) | (v1 >> 19)) & _M32) * _P1 & _M32
            v2 = (v2 + b * _P2) & _M32
            v2 = (((v2 << 13) | (v2 >> 19)) & _M32) * _P1 & _M32
            v3 = (v3 + c * _P2) & _M32
            v3 = (((v3 << 13) | (v3 >> 19)) & _M32) * _P1 & _M32
            v4 = (v4 + d * _P2) & _M32
            v4 = (((v4 << 13) | (v4 >> 19)) & _M32) * _P1 & _M32
        i = stop
        h = (((v1 << 1) | (v1 >> 31)) + ((v2 << 7) | (v2 >> 25))
             + ((v3 << 12) | (v3 >> 20)) + ((v4 << 18) | (v4 >> 14))) & _M32
    else:
        h = (seed + _P5) & _M32
    h = (h + n) & _M32
    while i + 4 <= n:
        h = (h + int.from_bytes(data[i:i + 4], "little") * _P3) & _M32
        h = (((h << 17) | (h >> 15)) & _M32) * _P4 & _M32
        i += 4
    while i < n:
        h = (h + data[i] * _P5) & _M32
        h = (((h << 11) | (h >> 21)) & _M32) * _P1 & _M32
        i += 1
    h ^= h >> 15
    h = h * _P2 & _M32
    h ^= h >> 13
    h = h * _P3 & _M32
    return h ^ (h >> 16)


# ---------------------------------------------------------------------------------------------- LZ4
_LZ4_MAGIC = 0x184D2204
_LZ4_LEGACY_MAGIC = 0x184C2102
_LZ4_LEGACY_BLOCK = 8 << 20                                   # legacy blocks decode to <= 8 MiB
_LZ4_LEGACY_BOUND = _LZ4_LEGACY_BLOCK + _LZ4_LEGACY_BLOCK // 255 + 16   # LZ4_compressBound(8 MiB)
_LZ4_BLOCK_MAX = {4: 64 << 10, 5: 256 << 10, 6: 1 << 20, 7: 4 << 20}


def _lz4_block(src, i, end, out, base, max_out, lits):
    """Decode one LZ4 block src[i:end], appending to `out`; a match may reach back to out[base]
    (0 for linked frame blocks, the block's own start for independent ones). The block must end
    exactly at `end` after a literals-only last sequence, and honour the format's end-of-block
    rules (last 5 bytes literals, last match starting >= 12 bytes before the block end) -- every
    conforming encoder (reference lz4, lz4_flex) does, and random input almost never does.
    Returns True when the max_out cap cut the output, else False. Raises _Bad."""
    blk = len(out)
    last_match = -1
    while True:
        if i >= end:
            raise _Bad("block ended after a match")
        tok = src[i]
        i += 1
        lit = tok >> 4
        if lit == 15:
            while True:
                if i >= end:
                    raise _Bad("literal length runs off the block")
                b = src[i]
                i += 1
                lit += b
                if b != 255:
                    break
        if lit:
            if i + lit > end:
                raise _Bad("literals overrun the block")
            room = max_out - len(out)
            take = lit if lit <= room else room
            out += src[i:i + take]
            if len(lits) < _SAMPLE:
                lits += src[i:i + min(take, _SAMPLE - len(lits))]
            if take < lit:
                return True
            i += lit
        if i == end:                                   # literals-only last sequence: block done
            if last_match >= 0 and (lit < 5 or last_match > len(out) - blk - 12):
                raise _Bad("end-of-block rules violated")
            return False
        if i + 2 > end:
            raise _Bad("truncated match offset")
        off = src[i] | (src[i + 1] << 8)
        i += 2
        if off == 0 or off > len(out) - base:
            raise _Bad("match offset outside the window")
        ml = tok & 15
        if ml == 15:
            while True:
                if i >= end:
                    raise _Bad("match length runs off the block")
                b = src[i]
                i += 1
                ml += b
                if b != 255:
                    break
        ml += 4
        last_match = len(out) - blk
        room = max_out - len(out)
        if ml > room:
            _copy(out, off, room)
            return True
        _copy(out, off, ml)


def _res(out, consumed, truncated, lits, **kw):
    r = {"out": bytes(out), "consumed": consumed, "truncated": truncated, "literals": bytes(lits)}
    r.update(kw)
    return r


def _lz4_block_dec(data, max_out, size=None):
    out, lits = bytearray(), bytearray()
    cut = _lz4_block(data, 0, len(data), out, 0, max_out, lits)
    if size is not None and not cut and len(out) != size:
        raise _Bad("decoded size differs from the declared size")
    return _res(out, len(data), cut, lits)


def _lz4_block_sized_dec(data, max_out):
    if len(data) < 5:
        raise _Bad("too short")
    size = int.from_bytes(data[:4], "little")
    # LZ4 expands at most ~255x (a 15+255*k length per byte): a larger claim is not a size field
    if not 0 < size <= (len(data) - 4) * 255 + 16:
        raise _Bad("implausible size prefix")
    out, lits = bytearray(), bytearray()
    cut = _lz4_block(data, 4, len(data), out, 0, max_out, lits)
    if not cut and len(out) != size:
        raise _Bad("decoded size differs from the size prefix")
    return _res(out, len(data), cut, lits, declared_size=size)


def _lz4_frame_one(data, i, out, max_out, lits):
    """One LZ4 frame starting at data[i] (its magic). Returns (next_i, truncated). Raises _Bad."""
    n = len(data)
    if i + 7 > n:
        raise _Bad("short frame header")
    flg, bd = data[i + 4], data[i + 5]
    if flg >> 6 != 1 or flg & 0x02 or bd & 0x8F:
        raise _Bad("bad FLG/BD (version or reserved bits)")
    bsid = (bd >> 4) & 7
    if bsid not in _LZ4_BLOCK_MAX:
        raise _Bad("bad block-max-size id")
    bmax = _LZ4_BLOCK_MAX[bsid]
    indep, bsum, csize, csum, dictid = flg & 0x20, flg & 0x10, flg & 0x08, flg & 0x04, flg & 0x01
    hend = i + 6 + (8 if csize else 0) + (4 if dictid else 0)
    if hend + 1 > n:
        raise _Bad("short frame header")
    if (xxh32(data[i + 4:hend]) >> 8) & 0xFF != data[hend]:
        raise _Bad("header checksum mismatch")
    content = int.from_bytes(data[i + 6:i + 14], "little") if csize else None
    i = hend + 1
    start = len(out)
    while True:
        if i + 4 > n:
            raise _Bad("missing end mark")
        bs = int.from_bytes(data[i:i + 4], "little")
        i += 4
        if bs == 0:                                     # EndMark
            break
        raw, bs = bs >> 31, bs & 0x7FFFFFFF
        if bs > bmax or i + bs + (4 if bsum else 0) > n:
            raise _Bad("block size over the frame maximum or past the input")
        if bsum and xxh32(data[i:i + bs]) != int.from_bytes(data[i + bs:i + bs + 4], "little"):
            raise _Bad("block checksum mismatch")
        if raw:
            room = max_out - len(out)
            take = min(bs, room)
            out += data[i:i + take]
            if len(lits) < _SAMPLE:
                lits += data[i:i + min(take, _SAMPLE - len(lits))]
            if take < bs:
                return i + take, True
        else:
            before = len(out)
            cut = _lz4_block(data, i, i + bs, out, before if indep else start, max_out, lits)
            if cut:
                return i, True
            if len(out) - before > bmax:
                raise _Bad("block decodes past the frame's block maximum")
        i += bs + (4 if bsum else 0)
    if csum:
        if i + 4 > n:
            raise _Bad("missing content checksum")
        if xxh32(bytes(out[start:])) != int.from_bytes(data[i:i + 4], "little"):
            raise _Bad("content checksum mismatch")
        i += 4
    if content is not None and len(out) - start != content:
        raise _Bad("content size mismatch")
    return i, False


def _lz4_frame_dec(data, max_out):
    if int.from_bytes(data[:4], "little") != _LZ4_MAGIC:
        raise _Bad("no LZ4 frame magic")
    out, lits = bytearray(), bytearray()
    i, cut = _lz4_frame_one(data, 0, out, max_out, lits)
    frames = 1
    while not cut and i + 4 <= len(data):              # concatenated frames / skippable frames
        m = int.from_bytes(data[i:i + 4], "little")
        if m == _LZ4_MAGIC:
            try:
                save = len(out), len(lits)
                i, cut = _lz4_frame_one(data, i, out, max_out, lits)
                frames += 1
            except _Bad:                                # junk after a complete frame: stop there
                del out[save[0]:]
                del lits[save[1]:]
                break
        elif m & 0xFFFFFFF0 == 0x184D2A50 and i + 8 <= len(data):
            skip = int.from_bytes(data[i + 4:i + 8], "little")
            if i + 8 + skip > len(data):
                break
            i += 8 + skip
        else:
            break
    return _res(out, i, cut, lits, frames=frames)


def _lz4_legacy_dec(data, max_out):
    if int.from_bytes(data[:4], "little") != _LZ4_LEGACY_MAGIC:
        raise _Bad("no legacy LZ4 magic")
    out, lits = bytearray(), bytearray()
    i, n, blocks = 4, len(data), 0
    while i + 4 <= n:
        bs = int.from_bytes(data[i:i + 4], "little")
        # the stream ends at EOF or where the next frame's magic sits in the size slot
        if bs in (_LZ4_MAGIC, _LZ4_LEGACY_MAGIC) or bs & 0xFFFFFFF0 == 0x184D2A50:
            break
        if not 0 < bs <= _LZ4_LEGACY_BOUND or i + 4 + bs > n:
            if blocks:
                break                                   # trailing bytes after the stream
            raise _Bad("first block size implausible or past the input")
        before = len(out)
        try:
            cut = _lz4_block(data, i + 4, i + 4 + bs, out, before, max_out, lits)
        except _Bad:
            if blocks:                                  # junk after the last real block
                del out[before:]
                break
            raise
        blocks += 1
        if cut:
            return _res(out, i + 4, True, lits, blocks=blocks)
        if len(out) - before > _LZ4_LEGACY_BLOCK:
            raise _Bad("legacy block decodes past 8 MiB")
        i += 4 + bs
        if len(out) - before < _LZ4_LEGACY_BLOCK:      # only the last block is short
            break
    if not blocks:
        raise _Bad("no block")
    return _res(out, i, False, lits, blocks=blocks)


# -------------------------------------------------------------------------------------------- aPLib
def _aplib_core(src, i, end, max_out, lits):
    """Headerless aPLib stream at src[i:end] -> (out, next_i, truncated). Bits come MSB-first from
    tag BYTES interleaved with the data. Items: 0 literal | 10 gamma-coded match (or rep-match) |
    110 7-bit-offset short match (byte 0x00 = end of data) | 111 4-bit-offset single byte. The
    stream must reach its end-of-data marker, and the unused low bits of the final tag byte must be
    zero (aPLib and apultra leave them clear). Raises _Bad."""
    out = bytearray()
    if i >= end:
        raise _Bad("empty")
    out.append(src[i])
    lits.append(src[i])
    pos = i + 1
    tag = 0
    nb = 0

    def bit():
        nonlocal pos, tag, nb
        if not nb:
            if pos >= end:
                raise _Bad("out of input reading a tag")
            tag = src[pos]
            pos += 1
            nb = 8
        nb -= 1
        return (tag >> nb) & 1

    def gamma():
        v = 1
        while True:
            v = (v << 1) | bit()
            if not bit():
                return v
            if v > _GAMMA_MAX:
                raise _Bad("gamma code too long")

    lwm = 0          # 1 right after a match: the next match cannot be a rep-match
    r0 = 0           # last match offset (0 = none yet)
    while True:
        if len(out) > max_out:                          # an item overshoots the cap by <= 3 bytes
            del out[max_out:]
            return out, pos, True
        if not bit():                                   # 0: literal
            if pos >= end:
                raise _Bad("out of input reading a literal")
            out.append(src[pos])
            if len(lits) < _SAMPLE:
                lits.append(src[pos])
            pos += 1
            lwm = 0
            continue
        if not bit():                                   # 10: match
            g = gamma()
            if not lwm and g == 2:                      # rep-match: reuse the last offset
                if not r0:
                    raise _Bad("rep-match before any match")
                off = r0
                ln = gamma()
            else:
                hi = g - (2 if lwm else 3)
                if pos >= end:
                    raise _Bad("out of input reading an offset")
                off = (hi << 8) + src[pos]
                pos += 1
                ln = gamma()
                if off >= 32000:
                    ln += 1
                if off >= 1280:
                    ln += 1
                if off < 128:
                    ln += 2
                r0 = off
            if not 0 < off <= len(out):
                raise _Bad("match offset outside the output")
            _copy(out, off, min(ln, max_out - len(out) + 1))
            lwm = 1
            continue
        if not bit():                                   # 110: short match / end of data
            if pos >= end:
                raise _Bad("out of input reading a short match")
            b = src[pos]
            pos += 1
            off = b >> 1
            if not off:
                if b:
                    raise _Bad("0x01 is not an end marker an encoder emits")
                break
            if off > len(out):
                raise _Bad("short match offset outside the output")
            _copy(out, off, 2 + (b & 1))
            r0 = off
            lwm = 1
            continue
        off = (bit() << 3) | (bit() << 2) | (bit() << 1) | bit()   # 111: 4-bit offset single byte
        if off:
            if off > len(out):
                raise _Bad("nibble offset outside the output")
            out.append(out[-off])
        else:
            out.append(0)
        lwm = 0
    if tag & ((1 << nb) - 1):
        raise _Bad("non-zero padding bits after the end marker")
    if len(out) > max_out:
        del out[max_out:]
        return out, pos, True
    return out, pos, False


def _aplib_dec(data, max_out, size=None):
    lits = bytearray()
    out, pos, cut = _aplib_core(data, 0, len(data), max_out, lits)
    if size is not None and not cut and len(out) != size:
        raise _Bad("decoded size differs from the declared size")
    return _res(out, pos, cut, lits)


def _aplib_ap32_dec(data, max_out):
    if data[:4] != b"AP32" or len(data) < 24:
        raise _Bad("no AP32 header")
    hs, psize, pcrc, osize, ocrc = struct.unpack_from("<5I", data, 4)
    if not 24 <= hs <= 256 or not 0 < psize <= len(data) - hs or osize == 0:
        raise _Bad("implausible AP32 header")
    packed = data[hs:hs + psize]
    if zlib.crc32(packed) != pcrc:
        raise _Bad("packed CRC-32 mismatch")
    lits = bytearray()
    out, pos, cut = _aplib_core(packed, 0, psize, max_out, lits)
    if not cut:
        if pos != psize or len(out) != osize or zlib.crc32(out) != ocrc:
            raise _Bad("AP32 size/CRC mismatch")
    return _res(out, hs + (psize if not cut else pos), cut, lits, declared_size=osize)


# ------------------------------------------------------------------------------------------ BriefLZ
def _brieflz_core(src, i, end, max_out, lits, size=None):
    """BriefLZ stream at src[i:end] -> (out, next_i, truncated). Bits come MSB-first from 16-bit
    little-endian tag words interleaved with the data; the first byte is a bare literal. Items:
    0 literal | 1 match: length = gamma + 2, offset = ((gamma - 2) << 8) + byte + 1.

    BriefLZ has no end marker (blz_depack is told the output size), so the end is where the input
    runs out at an item boundary with the rest of the current tag being padding: all zeros (BriefLZ
    <= 1.1) or a single 1 followed by zeros (1.2+ blz_finalize's delimiting bit, possibly alone in
    one extra tag word 0x8000). With `size` the decode stops at that output size and must then sit
    at that same end. Raises _Bad."""
    out = bytearray()
    if i >= end:
        raise _Bad("empty")
    out.append(src[i])
    lits.append(src[i])
    pos = i + 1
    tag = 0
    nb = 0

    def bit():
        nonlocal pos, tag, nb
        if not nb:
            if pos + 2 > end:
                raise _Bad("out of input reading a tag")
            tag = src[pos] | (src[pos + 1] << 8)
            pos += 2
            nb = 16
        nb -= 1
        return (tag >> nb) & 1

    def gamma():
        v = 1
        while True:
            v = (v << 1) | bit()
            if not bit():
                return v
            if v > _GAMMA_MAX:
                raise _Bad("gamma code too long")

    def at_end():
        """True when the input is exhausted here with only tag padding left (consumes a trailing
        0x8000 tag word); False when more items follow; _Bad for a stream that stops mid-tag."""
        nonlocal pos
        if not nb:
            if pos == end:
                return True
            if pos + 2 == end and src[pos] == 0 and src[pos + 1] == 0x80:
                pos += 2
                return True
            return False
        if pos < end:
            return False
        rest = tag & ((1 << nb) - 1)
        if rest == 0 or rest == 1 << (nb - 1):
            return True
        raise _Bad("input ends with non-padding tag bits")

    while True:
        if size is not None and len(out) >= size:
            if len(out) > size or not at_end():
                raise _Bad("stream does not end at the declared size")
            return out, pos, False
        if len(out) > max_out:                          # copies overshoot the cap by <= 1 byte
            del out[max_out:]
            return out, pos, True
        if size is None and at_end():
            return out, pos, False
        if not bit():
            if pos >= end:
                raise _Bad("out of input reading a literal")
            out.append(src[pos])
            if len(lits) < _SAMPLE:
                lits.append(src[pos])
            pos += 1
            continue
        ln = gamma() + 2
        g = gamma()
        if pos >= end:
            raise _Bad("out of input reading an offset")
        off = ((g - 2) << 8) + src[pos] + 1
        pos += 1
        if off > len(out):
            raise _Bad("match offset outside the output")
        if size is not None and len(out) + ln > size:
            raise _Bad("match overruns the declared size")
        _copy(out, off, min(ln, max_out - len(out) + 1))


def _brieflz_dec(data, max_out, size=None):
    lits = bytearray()
    out, pos, cut = _brieflz_core(data, 0, len(data), max_out, lits, size)
    return _res(out, pos, cut, lits)


_BLZ_MAGIC = b"blz\x1a"


def _brieflz_blzpack_dec(data, max_out):
    """blzpack container: one or more blocks, each a 24-byte big-endian header (magic, version 1,
    packed size, packed CRC-32 or 0, depacked size, depacked CRC-32 or 0) + an independent
    BriefLZ stream."""
    if data[:4] != _BLZ_MAGIC:
        raise _Bad("no blzpack magic")
    out, lits = bytearray(), bytearray()
    i, n, blocks = 0, len(data), 0
    while i + 24 <= n and data[i:i + 4] == _BLZ_MAGIC:
        ver, psize, pcrc, dsize, dcrc = struct.unpack_from(">5I", data, i + 4)
        if ver != 1 or not 0 < psize <= n - i - 24 or dsize == 0:
            if blocks:
                break
            raise _Bad("implausible blzpack header")
        packed = data[i + 24:i + 24 + psize]
        if pcrc and zlib.crc32(packed) != pcrc:
            raise _Bad("packed CRC-32 mismatch")
        room = max_out - len(out)
        if dsize > room:                                # decode what fits and report the cut
            blk, _pos, cut = _brieflz_core(packed, 0, psize, room, lits)
            if not cut:
                raise _Bad("block ends before its declared size")
            out += blk
            return _res(out, i + 24, True, lits, blocks=blocks + 1)
        blk, pos, _cut = _brieflz_core(packed, 0, psize, room, lits, dsize)
        if pos != psize or (dcrc and zlib.crc32(blk) != dcrc):
            raise _Bad("blzpack size/CRC mismatch")
        out += blk
        blocks += 1
        i += 24 + psize
    if not blocks:
        raise _Bad("no block")
    return _res(out, i, False, lits, blocks=blocks)


# -------------------------------------------------------------------------------------------- LZNT1
def _lznt1_dec(data, max_out):
    """LZNT1: chunks of [u16 header][data]; header bits 0-11 = data size - 1, bits 12-14 = 3
    (signature), bit 15 = compressed. A compressed chunk is groups of a flag byte (LSB first: 0
    literal, 1 a u16 token) + up to 8 items and decodes to <= 4096 bytes; the token's offset/length
    split depends on the position inside the chunk (offset bits = max(4, bit_length(pos - 1))).
    Every chunk but the last decodes to exactly 4096 bytes; matches stay inside their chunk; unused
    flag bits after the last item are zero. The stream ends at the input's end or a 0x0000 header."""
    n = len(data)
    out, lits = bytearray(), bytearray()
    i = 0
    chunks = 0
    last_len = 4096
    terminated = False
    while i + 2 <= n:
        h = data[i] | (data[i + 1] << 8)
        if h == 0:
            i += 2
            terminated = True
            break
        if (h >> 12) & 7 != 3:
            raise _Bad("bad chunk signature")
        csz = (h & 0xFFF) + 1
        if i + 2 + csz > n:
            raise _Bad("chunk overruns the input")
        if last_len != 4096:
            raise _Bad("a non-final chunk decoded to less than 4096 bytes")
        c = data[i + 2:i + 2 + csz]
        chunk = bytearray()
        if h & 0x8000:
            j = 0
            while j < csz:
                flags = c[j]
                j += 1
                if j >= csz:
                    raise _Bad("flag byte with no items")
                for k in range(8):
                    if j >= csz:
                        if flags >> k:
                            raise _Bad("flag bits set past the chunk end")
                        break
                    if not (flags >> k) & 1:
                        chunk.append(c[j])
                        j += 1
                        continue
                    if j + 2 > csz:
                        raise _Bad("truncated token")
                    tok = c[j] | (c[j + 1] << 8)
                    j += 2
                    p = len(chunk)
                    if not p:
                        raise _Bad("token before any literal")
                    obits = max(4, (p - 1).bit_length())
                    off = (tok >> (16 - obits)) + 1
                    ln = (tok & ((1 << (16 - obits)) - 1)) + 3
                    if off > p or p + ln > 4096:
                        raise _Bad("token outside the chunk")
                    _copy(chunk, off, ln)
            if len(lits) < _SAMPLE:
                lits += _lznt1_literals(c, _SAMPLE - len(lits))
        else:
            if csz > 4096:
                raise _Bad("uncompressed chunk over 4096 bytes")
            chunk += c
            if len(lits) < _SAMPLE:
                lits += c[:_SAMPLE - len(lits)]
        room = max_out - len(out)
        if len(chunk) > room:
            out += chunk[:room]
            return _res(out, i, True, lits, chunks=chunks + 1)
        out += chunk
        last_len = len(chunk)
        chunks += 1
        i += 2 + csz
    if not chunks:
        raise _Bad("no chunk")
    if not terminated and i != n:
        raise _Bad("odd trailing byte")
    return _res(out, i, False, lits, chunks=chunks, terminated=terminated)


def _lznt1_literals(c, limit):
    """The literal bytes of one compressed chunk (for the evidence gate), up to `limit`."""
    lit = bytearray()
    j = 0
    while j < len(c) and len(lit) < limit:
        flags = c[j]
        j += 1
        for k in range(8):
            if j >= len(c):
                break
            if (flags >> k) & 1:
                j += 2
            else:
                lit.append(c[j])
                j += 1
    return lit[:limit]


# ------------------------------------------------------------------------------------- evidence gate
def _printable_ratio(b) -> float:
    if not b:
        return 0.0
    return sum(1 for x in b if 0x20 <= x < 0x7f or x in (9, 10, 13)) / len(b)


def _entropy(b) -> float:
    if not b:
        return 0.0
    counts = [0] * 256
    for x in b:
        counts[x] += 1
    n = len(b)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


_H_UNIFORM = {}


def _h_uniform(n: int) -> float:
    """Expected order-0 (plug-in) entropy of n independent uniform bytes: 256 * E[-(K/n) log2(K/n)]
    with K ~ Binomial(n, 1/256), summed exactly over the pmf's non-negligible range (the plug-in
    estimate is biased low for small n: ~5.9 bits at n=64, ~7.65 at n=512, ~7.96 at n=4096)."""
    if n in _H_UNIFORM:
        return _H_UNIFORM[n]
    p = 1.0 / 256
    lg = math.lgamma
    mean = n * p
    hi = min(n, int(mean + 12 * math.sqrt(mean + 1) + 20))
    s = 0.0
    for k in range(1, hi + 1):
        logpmf = lg(n + 1) - lg(k + 1) - lg(n - k + 1) + k * math.log(p) + (n - k) * math.log1p(-p)
        q = k / n
        s += math.exp(logpmf) * (-q * math.log2(q))
    _H_UNIFORM[n] = 256 * s
    return _H_UNIFORM[n]


def validated_magic(b):
    """A file magic at offset 0 strong enough to prove a decode: recover_embedded's validated hit
    (PE needs e_lfanew -> PE\\0\\0, ELF a sane e_ident) for any signature of >= 4 bytes, or the
    validated PE. A bare 2-3 byte magic ("MZ", gzip's 1f8b08, "BZh") proves nothing on its own."""
    sigs = {name: sig for name, sig, _need in recover_embedded._MAGICS}
    for h in recover_embedded._find_magics(bytes(b[:1 << 16]), 0):
        if h["offset"] != 0:
            continue
        if h["kind"] == "pe" or len(sigs.get(h["kind"], b"")) >= 4:
            return h["kind"]
    return None


def evidence(out, lits, inp=None):
    """Why a headerless decode is believable (see the module docstring), or None. `inp` is the
    compressed input (for the entropy-drop test; without it that test is skipped)."""
    m = validated_magic(out)
    if m:
        return f"magic:{m}"
    head = out[:_SAMPLE]
    if (len(out) >= 32 and len(lits) >= 8 and _printable_ratio(head) >= 0.85
            and _printable_ratio(lits) >= 0.85):
        return "text"
    if inp is not None and len(head) >= 256 and len(lits) >= 256:
        h_out = _entropy(head)
        if (h_out <= _h_uniform(len(head)) - 1.0
                and _entropy(lits) <= _h_uniform(len(lits)) - 0.2
                and _entropy(inp[:_SAMPLE]) - h_out >= 0.25):
            return "entropy_drop"
    return None


# ------------------------------------------------------------------------------------------- driver
# (name, decoder, headerless, has_end_marker) in the order tried: containers, then headerless.
DECODERS = [
    ("lz4_frame", _lz4_frame_dec, False, True),
    ("lz4_legacy", _lz4_legacy_dec, False, True),
    ("aplib_ap32", _aplib_ap32_dec, False, True),
    ("brieflz_blzpack", _brieflz_blzpack_dec, False, True),
    ("lz4_block_sized", _lz4_block_sized_dec, True, False),
    ("lz4_block", _lz4_block_dec, True, False),
    ("aplib", _aplib_dec, True, True),
    ("brieflz", _brieflz_dec, True, False),
    ("lznt1", _lznt1_dec, True, True),
]
FORMATS = tuple(d[0] for d in DECODERS)
_BY_NAME = {d[0]: d for d in DECODERS}


def decode(fmt, data, max_out=MAX_OUT, size=None):
    """Strictly decode `data` as `fmt` (structure only -- no consumption/evidence policy). Returns
    {out, consumed, truncated, literals, ...} or None; never raises on hostile input. `size` (an
    expected output size, e.g. from a config) is honoured by lz4_block, aplib and brieflz."""
    _name, fn, _hl, _end = _BY_NAME[fmt]
    if not isinstance(data, (bytes, bytearray, memoryview)):
        data = bytes(data)                              # memoryview: a tail of a file, not copied
    try:
        if size is not None and fmt in ("lz4_block", "aplib", "brieflz"):
            r = fn(data, max_out, size)
        else:
            r = fn(data, max_out)
    except (_Bad, IndexError, ValueError, struct.error, OverflowError, MemoryError, RecursionError):
        return None
    if len(r["out"]) < _MIN_OUT and not r["truncated"]:
        return None
    return r


def accept(fmt, data, r):
    """Apply the acceptance policy to a strict decode `r` of `data` as `fmt`: returns the result
    (with "evidence" set for headerless formats) or None. See the module docstring."""
    if r is None:
        return None
    _name, _fn, headerless, has_end = _BY_NAME[fmt]
    if not headerless:
        return r
    n = len(data)
    if not r["truncated"]:
        if has_end:
            if r["consumed"] < min(_MIN_STREAM, n):
                return None
        elif r["consumed"] != n:
            return None
    ev = evidence(r["out"], r["literals"], data[:r["consumed"]])
    if ev is None:
        return None
    # decompression expands: a decode that is not >= 1.1x its input is a near-identity parse of
    # uncompressed bytes (low-entropy code/data read as all-literal items), not a payload. A
    # validated magic is proof enough on its own (a compressed, already-packed PE may not expand).
    if not ev.startswith("magic:") and not r["truncated"] and len(r["out"]) < _MIN_RATIO * r["consumed"]:
        return None
    r["evidence"] = ev
    return r


def try_all(data, max_out=MAX_OUT, formats=None):
    """First format (in DECODERS order) that decodes `data` and passes the acceptance policy:
    {format, out, consumed, truncated, evidence?, ...} or None."""
    for name in formats or FORMATS:
        r = accept(name, data, decode(name, data, max_out))
        if r is not None:
            r["format"] = name
            return r
    return None


def scan(data, max_out=MAX_OUT):
    """Every format that decodes `data` under the acceptance policy (the CLI's view)."""
    hits = []
    for name in FORMATS:
        r = accept(name, data, decode(name, data, max_out))
        if r is not None:
            r["format"] = name
            hits.append(r)
    return hits


def header_ok(kind, data, i) -> bool:
    """Cheap validation of a container magic found at data[i] (recover_embedded's carve): the
    fields right after the magic must be well formed. No decode, no CRC over the payload."""
    try:
        if kind == "lz4":
            flg, bd = data[i + 4], data[i + 5]
            if flg >> 6 != 1 or flg & 0x02 or bd & 0x8F or (bd >> 4) & 7 not in _LZ4_BLOCK_MAX:
                return False
            hend = i + 6 + (8 if flg & 0x08 else 0) + (4 if flg & 0x01 else 0)
            return hend < len(data) and (xxh32(data[i + 4:hend]) >> 8) & 0xFF == data[hend]
        if kind == "lz4_legacy":
            bs = int.from_bytes(data[i + 4:i + 8], "little")
            return 0 < bs <= min(_LZ4_LEGACY_BOUND, len(data) - i - 8)
        if kind == "aplib":
            hs, psize, _pcrc, osize, _ocrc = struct.unpack_from("<5I", data, i + 4)
            return 24 <= hs <= 256 and 0 < psize <= len(data) - i - hs and osize > 0
        if kind == "brieflz":
            ver, psize, _pcrc, dsize, _dcrc = struct.unpack_from(">5I", data, i + 4)
            return ver == 1 and 0 < psize <= len(data) - i - 24 and dsize > 0
    except (IndexError, struct.error):
        return False
    return False


# embedded-magic kind (recover_embedded) -> the container decoder that starts at that magic
CONTAINER_KINDS = {"lz4": "lz4_frame", "lz4_legacy": "lz4_legacy", "aplib": "aplib_ap32",
                   "brieflz": "brieflz_blzpack"}


def describe(r) -> dict:
    """JSON-safe summary of a result (no raw bytes)."""
    out = r["out"]
    d = {"format": r.get("format"), "consumed": r["consumed"], "out_size": len(out),
         "out_sha256": hashlib.sha256(out).hexdigest(), "out_magic": validated_magic(out),
         "truncated": r["truncated"], "preview": out[:48].decode("latin-1")}
    for k in ("evidence", "declared_size", "frames", "blocks", "chunks", "terminated"):
        if k in r:
            d[k] = r[k]
    return d


def recover(path, offset=0, length=None, max_out=MAX_OUT) -> dict:
    """Try every format on the file (or the slice [offset, offset+length)) and report which decode."""
    data = Path(path).read_bytes()
    blob = data[offset:offset + length if length is not None else None]
    hits = scan(blob, max_out)
    return {"file_size": len(data), "offset": offset, "size": len(blob), "tried": list(FORMATS),
            "decoded": [describe(r) for r in hits]}


# ------------------------------------------------------------------------------------------ selftest
def _selftest():
    import random
    rng = random.Random(0xdec0)
    # xxHash32 reference values (xxhash spec test vectors)
    assert xxh32(b"") == 0x02CC5D05 and xxh32(b"a") == 0x550D7456 and xxh32(b"abc") == 0x32D153FF
    # aPLib: the two vectors in malduck's documentation (headerless; AP32 header)
    r = decode("aplib", b"T\x00he quick\xecb\x0erown\xcef\xaex\x80jumps\xed\xe4veur`t?lazy\xead\xfeg\xc0\x00")
    assert r and r["out"] == b"The quick brown fox jumps over the lazy dog", r
    r = decode("aplib_ap32", b"AP32\x18\x00\x00\x00\r\x00\x00\x00\xbc\x9ab\x9b\x0b\x00\x00\x00"
               b"\x85\x11J\rh8el\x8eo wnr\xecd\x00")
    assert r and r["out"] == b"hello world", r
    # LZNT1: the [MS-XCA] specification's worked example (59 bytes -> 142-byte string + NUL)
    ms = bytes.fromhex("38b0884623200020 4720410010a24701 a045204400084501 507900c045200524"
                       "138805b4024a44ef 0358028c09160148 4500be009e000401 189000")
    tune = (b"F# F# G A A G F# E D D E F# F# E E F# F# G A A G F# E D D E F# E D D E E F# D E F# "
            b"G F# D E F# G F# E D E A F# F# G A A G F# E D D E F# E D D\x00")
    r = decode("lznt1", ms)
    assert r and r["out"] == tune and len(tune) == 142, r
    # LZ4 block, hand-assembled: "abcd" literals + match(off 4, len 8) + 5 literal tail
    blk = bytes([0x44]) + b"abcd" + b"\x04\x00" + bytes([0x50]) + b"efghi"
    r = decode("lz4_block", blk)
    assert r and r["out"] == b"abcd" + b"abcdabcd" + b"efghi", r
    # hostile input never raises; random bytes are not accepted by any format
    for n in (0, 1, 7, 64, 512):
        for _ in range(20):
            assert try_all(rng.randbytes(n)) is None
    assert try_all(b"\xff" * 4096) is None and try_all(b"\x00" * 4096) is None
    # the evidence gate: literal-anchored (a printable run built by a long match is not text)
    assert evidence(b"A" * 4000, rng.randbytes(300), rng.randbytes(400)) is None
    assert evidence(bytes(4000), bytes(300), bytes(400)) is None      # constant in, constant out
    assert evidence(b"config: host=192.0.2.10 port=8443\n" * 4, b"config: host=192.0.2.10 port=8443\n")
    print("selftest OK: xxh32 vectors; aPLib (malduck doc vectors, raw + AP32), LZNT1 ([MS-XCA] "
          "example), LZ4 block decoded; random/constant input rejected by every format")


def _print(res):
    print(f"{res['size']}B at offset {res['offset']}: tried {', '.join(res['tried'])}")
    if not res["decoded"]:
        print("  no format decoded (strict decode + acceptance policy)")
    for d in res["decoded"]:
        cut = " (truncated at the output cap)" if d["truncated"] else ""
        ev = f" evidence={d['evidence']}" if d.get("evidence") else ""
        print(f"  {d['format']}: consumed {d['consumed']}B -> {d['out_size']}B{cut} "
              f"magic={d['out_magic']}{ev} sha256={d['out_sha256'][:16]} {d['preview']!r}")


def main(argv=None):
    import argparse
    import json
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("file", nargs="?")
    ap.add_argument("--offset", type=lambda s: int(s, 0), default=0, help="start of the stream")
    ap.add_argument("--length", type=lambda s: int(s, 0), default=None, help="stream length")
    ap.add_argument("--json", action="store_true", help="print the result dict as JSON")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args(argv)
    if a.selftest:
        _selftest()
        return 0
    if not a.file:
        ap.error("give a file, or --selftest")
    path = Path(a.file)
    if not path.is_file():
        ap.error(f"no such file: {path}")
    res = recover(path, a.offset, a.length)
    print(json.dumps(res, indent=2)) if a.json else _print(res)
    return 0


if __name__ == "__main__":
    sys.exit(main())
