"""Pure-Python ENCODERS for the decompress.py tests: produce valid LZ4 (block / frame / legacy),
aPLib (raw / AP32), BriefLZ (raw / blzpack) and LZNT1 streams at test time, so round-trip tests need
no committed binaries and no native compressor.

Simple greedy encoders (hash of the next 3-4 bytes -> last position), written from the same format
documentation as the decoders: lz4 doc/lz4_Block_format.md + lz4_Frame_format.md, BriefLZ's
brieflz.c / blzpack.c (zlib licence; the trailing delimiter bit of blz_finalize is reproduced, and
can be turned off to emit the pre-1.2 stream shape), aPLib's bit layout (as in apultra's expand.c)
and [MS-XCA] LZNT1. They exercise matches, overlapping matches, rep-matches (aPLib), the 4-bit
offset short form (aPLib) and chunk/frame boundaries. They are NOT tuned for ratio. Independent
ground truth comes from elsewhere: the python `lz4` package (optional), and the published vectors
pinned in tests/test_decompress.py (malduck's aPLib doc vectors, the [MS-XCA] LZNT1 example).
"""
import struct
import sys
import zlib

from conftest import ROOT

sys.path.insert(0, str(ROOT / "scripts"))
from decompress import xxh32  # noqa: E402


def _matcher(data, minlen, maxoff, maxlen, key=4):
    """Greedy match finder: yields a function best(i) -> (off, len) or (0, 0)."""
    table = {}

    def best(i, limit):
        if i + key > limit:
            return 0, 0
        k = data[i:i + key]
        j = table.get(k)
        table[k] = i
        if j is None or i - j > maxoff:
            return 0, 0
        n = 0
        cap = min(maxlen, limit - i)
        while n < cap and data[j + n] == data[i + n]:
            n += 1
        return (i - j, n) if n >= minlen else (0, 0)

    def note(i, limit):
        if i + key <= limit:
            table[data[i:i + key]] = i
    return best, note


# ---------------------------------------------------------------------------------------------- LZ4
def _lz4_len(n):
    out = bytearray()
    while n >= 255:
        out.append(255)
        n -= 255
    out.append(n)
    return out


def lz4_block(data: bytes) -> bytes:
    """Greedy LZ4 block honouring the end-of-block rules (last 5 bytes literal, last match starting
    >= 12 bytes before the end; < 13 bytes -> literals only)."""
    n = len(data)
    out = bytearray()
    best, note = _matcher(data, 4, 65535, 1 << 30)
    anchor = i = 0
    mflimit = n - 12          # a match may start at i <= n - 12
    matchlimit = n - 5        # ... and must end by n - 5
    while i <= mflimit:
        off, ln = best(i, matchlimit)
        if not ln:
            i += 1
            continue
        lit = data[anchor:i]
        tok = (min(len(lit), 15) << 4) | min(ln - 4, 15)
        out.append(tok)
        if len(lit) >= 15:
            out += _lz4_len(len(lit) - 15)
        out += lit
        out += struct.pack("<H", off)
        if ln - 4 >= 15:
            out += _lz4_len(ln - 4 - 15)
        for k in range(i + 1, min(i + ln, matchlimit)):
            note(k, matchlimit)
        i += ln
        anchor = i
    lit = data[anchor:]
    out.append(min(len(lit), 15) << 4)
    if len(lit) >= 15:
        out += _lz4_len(len(lit) - 15)
    out += lit
    return bytes(out)


def lz4_frame(data: bytes, block_max_id=4, linked=False, block_checksum=False,
              content_checksum=False, content_size=False, raw_blocks=False) -> bytes:
    """LZ4 frame. Linked mode is produced by compressing each block independently (always valid for
    a linked decoder too); `raw_blocks` stores blocks uncompressed (high bit of the size)."""
    bmax = {4: 64 << 10, 5: 256 << 10, 6: 1 << 20, 7: 4 << 20}[block_max_id]
    flg = 0x40 | (0 if linked else 0x20) | (0x10 if block_checksum else 0) \
        | (0x08 if content_size else 0) | (0x04 if content_checksum else 0)
    desc = bytes([flg, block_max_id << 4]) + (struct.pack("<Q", len(data)) if content_size else b"")
    out = bytearray(struct.pack("<I", 0x184D2204) + desc + bytes([(xxh32(desc) >> 8) & 0xFF]))
    for s in range(0, len(data), bmax):
        chunk = data[s:s + bmax]
        blk = chunk if raw_blocks else lz4_block(chunk)
        out += struct.pack("<I", len(blk) | (0x80000000 if raw_blocks else 0)) + blk
        if block_checksum:
            out += struct.pack("<I", xxh32(blk))
    out += b"\x00\x00\x00\x00"
    if content_checksum:
        out += struct.pack("<I", xxh32(data))
    return bytes(out)


def lz4_legacy(data: bytes, block=8 << 20) -> bytes:
    out = bytearray(struct.pack("<I", 0x184C2102))
    for s in range(0, len(data), block):
        blk = lz4_block(data[s:s + block])
        out += struct.pack("<I", len(blk)) + blk
    return bytes(out)


# -------------------------------------------------------------------------------- bit-tag writers
class _TagWriter:
    """Interleaved tag-bit writer: a tag slot (`width` bytes) is reserved in the output when its
    first bit is written; bits fill it MSB-first. Matches aPLib (8-bit) and BriefLZ (16-bit LE)."""

    def __init__(self, out, width):
        self.out, self.width = out, width
        self.pos = None
        self.tag = 0
        self.left = 0

    def bit(self, b):
        if not self.left:
            self.flush()
            self.pos = len(self.out)
            self.out += bytes(self.width)
            self.tag = 0
            self.left = self.width * 8
        self.left -= 1
        self.tag |= (b & 1) << self.left

    def gamma(self, v):
        """aPLib/BriefLZ gamma2 code of v >= 2: the bits after the leading 1, each followed by a
        continuation bit (1 = more)."""
        assert v >= 2
        bits = bin(v)[3:]
        for k, c in enumerate(bits):
            self.bit(int(c))
            self.bit(1 if k + 1 < len(bits) else 0)

    def flush(self):
        if self.pos is not None:
            self.out[self.pos:self.pos + self.width] = self.tag.to_bytes(self.width, "little")


# -------------------------------------------------------------------------------------------- aPLib
APLIB_STATS = {}     # item kinds the last aplib() call emitted (tests check every kind is covered)


def aplib(data: bytes) -> bytes:
    """Greedy aPLib stream (first byte verbatim; literal / normal match / rep-match / short match /
    4-bit single byte; end-of-data = 110 + 0x00)."""
    assert data
    st = APLIB_STATS
    st.clear()
    st.update(literal=0, match=0, rep=0, short=0, nibble=0)
    out = bytearray([data[0]])
    w = _TagWriter(out, 1)
    best, note = _matcher(data, 2, 0x7FFFF, 1 << 30, key=3)
    lwm, r0 = 0, 0
    i, n = 1, len(data)
    while i < n:
        off, ln = best(i, n)
        # rep-match: the previous offset continues to match, only right after a literal
        if not lwm and r0 and r0 <= i:
            k = 0
            while i + k < n and data[i + k] == data[i + k - r0]:
                k += 1
            if k >= 3 and k >= ln:
                w.bit(1), w.bit(0), w.gamma(2), w.gamma(k)
                st["rep"] += 1
                for t in range(i + 1, i + k):
                    note(t, n)
                i += k
                lwm = 1
                continue
        adj = (2 if off < 128 else 0) + (1 if off >= 1280 else 0) + (1 if off >= 32000 else 0)
        if ln and 2 <= ln <= 3 and off < 128:                      # 110 short match
            w.bit(1), w.bit(1), w.bit(0)
            out.append((off << 1) | (ln - 2))
            st["short"] += 1
            for t in range(i + 1, i + ln):
                note(t, n)
            i += ln
            r0, lwm = off, 1
            continue
        if ln and ln - adj >= 2:                                   # 10 normal match
            w.bit(1), w.bit(0)
            w.gamma((off >> 8) + (2 if lwm else 3))
            out.append(off & 0xFF)
            w.gamma(ln - adj)
            st["match"] += 1
            for t in range(i + 1, i + ln):
                note(t, n)
            i += ln
            r0, lwm = off, 1
            continue
        b = data[i]
        near = next((d for d in range(1, 16) if d <= i and data[i - d] == b), 0)
        if b == 0 or near:                                         # 111 4-bit single byte
            v = 0 if b == 0 else near
            w.bit(1), w.bit(1), w.bit(1)
            for s in (3, 2, 1, 0):
                w.bit((v >> s) & 1)
            st["nibble"] += 1
        else:                                                      # 0 literal
            w.bit(0)
            out.append(b)
            st["literal"] += 1
        i += 1
        lwm = 0
    w.bit(1), w.bit(1), w.bit(0)
    out.append(0)
    w.flush()
    return bytes(out)


def aplib_ap32(data: bytes) -> bytes:
    packed = aplib(data)
    return b"AP32" + struct.pack("<5I", 24, len(packed), zlib.crc32(packed), len(data),
                                 zlib.crc32(data)) + packed


# ------------------------------------------------------------------------------------------ BriefLZ
def brieflz(data: bytes, finalize=True) -> bytes:
    """Greedy BriefLZ stream as blz_pack emits it: first byte verbatim, then 16-bit tags; with
    `finalize` the 1.2+ trailing delimiter bit is written (pre-1.2 streams end without it)."""
    assert data
    out = bytearray([data[0]])
    if len(data) == 1:
        return bytes(out)
    w = _TagWriter(out, 2)
    best, note = _matcher(data, 4, 1 << 24, 1 << 30)
    i, n = 1, len(data)
    while i < n:
        off, ln = best(i, n)
        if ln >= 4:
            o = off - 1
            w.bit(1)
            w.gamma(ln - 2)
            w.gamma((o >> 8) + 2)
            out.append(o & 0xFF)
            for t in range(i + 1, i + ln):
                note(t, n)
            i += ln
        else:
            w.bit(0)
            out.append(data[i])
            i += 1
    if finalize:
        w.bit(1)
    w.flush()
    return bytes(out)


def blzpack(data: bytes, block=1 << 20, checksum=True) -> bytes:
    out = bytearray()
    for s in range(0, len(data), block):
        d = data[s:s + block]
        p = brieflz(d)
        out += b"blz\x1a" + struct.pack(">5I", 1, len(p), zlib.crc32(p) if checksum else 0, len(d),
                                         zlib.crc32(d) if checksum else 0) + p
    return bytes(out)


# -------------------------------------------------------------------------------------------- LZNT1
def _lznt1_chunk(c: bytes) -> bytes:
    out = bytearray()
    i, n = 0, len(c)
    table = {}
    while i < n:
        fpos = len(out)
        out.append(0)
        flags = 0
        for k in range(8):
            if i >= n:
                break
            obits = max(4, (i - 1).bit_length()) if i else 4
            maxoff, maxlen = 1 << obits, (1 << (16 - obits)) + 2
            key = c[i:i + 3]
            j = table.get(key) if len(key) == 3 else None
            ln = 0
            if j is not None and i - j <= maxoff:
                while ln < min(maxlen, n - i) and c[j + ln] == c[i + ln]:
                    ln += 1
            if len(key) == 3:
                table[key] = i
            if ln >= 3:
                flags |= 1 << k
                out += struct.pack("<H", ((i - j - 1) << (16 - obits)) | (ln - 3))
                for t in range(i + 1, i + ln):
                    if t + 3 <= n:
                        table[c[t:t + 3]] = t
                i += ln
            else:
                out.append(c[i])
                i += 1
        out[fpos] = flags
    return bytes(out)


def lznt1(data: bytes, terminator=False) -> bytes:
    """LZNT1 as RtlCompressBuffer lays it out: 4 KiB chunks, each stored compressed, or raw when
    compression does not help (raw chunks are 4096 bytes except possibly the last)."""
    out = bytearray()
    for s in range(0, len(data), 4096):
        c = data[s:s + 4096]
        z = _lznt1_chunk(c)
        if len(z) < len(c):
            out += struct.pack("<H", 0xB000 | (len(z) - 1)) + z
        else:
            out += struct.pack("<H", 0x3000 | (len(c) - 1)) + c
    if terminator:
        out += b"\x00\x00"
    return bytes(out)
