#!/usr/bin/env python3
"""recover_blobs.py - triage embedded payload blobs: carve them, attempt *keyless* recovery, and
annotate with the cryptographic primitives the binary carries.

Pipeline (all defensive, benign inputs): recover_embedded.py carves high-entropy blobs, embedded
executables/archives and base64 payloads; for each blob we try the recoveries that need NO key --
decompression (zlib/gzip/bz2/lzma, then decompress.py's strict LZ4 frame/legacy/block, aPLib,
BriefLZ and LZNT1 decoders) and single-byte-XOR brute (the classic keyless config obfuscation) --
and recover_crypto.py lists the cipher/hash primitives present as *candidates*. Exact stream starts
the 256-byte entropy grid cannot give are tried as `streams`: each validated compressed-container
magic (LZ4 frame/legacy, aPLib 'AP32', BriefLZ blzpack), a PE/ELF overlay (droppers append a
compressed core/config at EOF, often headerless), and a bounded second-pass search for headerless
streams off the grid or under the carve's entropy threshold (_search). Every recovery is followed
down through further compressed layers (`chain`, <= 3 layers, one shared MAX_OUT output budget),
including a stream an XOR key revealed, and containers inside an output are decoded (`nested`).

Honest about limits: a blob encrypted with a real cipher cannot be decrypted without its key, which
a static tool does not have. This surfaces the keyless wins and names the candidate algorithms for
an analyst; it does not claim to break encryption.
"""
import bisect
import math
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import decompress  # noqa: E402
import recover_crypto  # noqa: E402
import recover_embedded  # noqa: E402

MAX_OUT = 16 << 20      # decompression output cap (16 MiB): a small bomb must not amplify to GBs
_MIN_STREAM = 128       # a completed stream shorter than this must span the whole blob (see _inflate)
_XOR_SAMPLE = 4096      # bytes decoded per accepted XOR key (enough for a PE's e_lfanew -> PE\0\0)


def _printable_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    return sum(1 for x in b if 0x20 <= x < 0x7f or x in (9, 10, 13)) / len(b)


def _known_magic(b: bytes):
    for name, sig, _need in recover_embedded._MAGICS:
        if b.startswith(sig):
            return name
    return None


# a file magic at offset 0 strong enough to prove a decode (>= 4-byte signature or validated PE);
# shared with decompress.py's evidence gate
_validated_magic = decompress.validated_magic


def _inflate(make, blob: bytes, max_out=None):
    """Run a streaming decompressor with an output cap (MAX_OUT unless given). Returns
    (out, truncated) only for a stream that either completed (eof) or was cut by the cap; an error
    or an incomplete stream (a random blob that merely parsed for a while) is None, as
    zlib.decompress & co. would raise."""
    cap = MAX_OUT if max_out is None else max_out
    d = make()
    out = d.decompress(blob, cap)
    if getattr(d, "eof", False):
        # a completed stream must account for the blob: random bytes parse as a tiny raw-deflate
        # stream ~1 time in 1000 (consuming 10-60 bytes, the rest left as unused_data). A real
        # payload is the whole carve, or at least _MIN_STREAM bytes of it.
        consumed = len(blob) - len(getattr(d, "unused_data", b""))
        if consumed < min(_MIN_STREAM, len(blob)):
            return None
        return out, False
    if len(out) >= cap:
        return out, True
    return None


def _stdlib_codecs():
    import bz2
    import lzma
    import zlib
    return [
        ("zlib", lambda: zlib.decompressobj(15)),
        ("zlib_raw", lambda: zlib.decompressobj(-15)),
        ("gzip", lambda: zlib.decompressobj(16 + 15)),
        ("bz2", bz2.BZ2Decompressor),
        # memlimit: an xz/lzma header can declare a ~1.5 GiB dictionary; real presets need <= ~65 MiB
        ("lzma", lambda: lzma.LZMADecompressor(memlimit=128 << 20)),
    ]


def _try_decompress(blob: bytes, max_out=None, only=None):
    """Keyless: a compressed payload decompresses with no key. Try the common codecs, each capped at
    `max_out` (default MAX_OUT) bytes of output (a zip bomb is reported truncated, not inflated):
    zlib/gzip/bz2/lzma, then decompress.py's strict LZ4 / aPLib / BriefLZ / LZNT1 decoders
    (containers first; the headerless formats only with full consumption + expansion + an
    "interesting" output, see decompress.py). `only` restricts the formats tried (a header already
    named the format). Returns (name, out, truncated, extra) or (None, None, False, {}); `extra`
    carries `consumed` and, for a headerless format, the `evidence` that made the decode believable."""
    cap = MAX_OUT if max_out is None else max_out
    if cap <= 0:
        return None, None, False, {}
    for name, make in _stdlib_codecs():
        if only is not None and name not in only:
            continue
        try:
            r = _inflate(make, blob, cap)
        except Exception:
            continue
        if r is None:
            continue
        out, truncated = r
        if out and len(out) >= 8:
            return name, out, truncated, {}
    fmts = None if only is None else [f for f in decompress.FORMATS if f in only]
    if fmts == []:
        return None, None, False, {}
    d = decompress.try_all(blob, cap, formats=fmts)
    if d is not None:
        extra = {"consumed": d["consumed"]}
        if d.get("evidence"):
            extra["evidence"] = d["evidence"]
        return d["format"], d["out"], d["truncated"], extra
    return None, None, False, {}


def _stream_formats(b) -> list:
    """Compressed-stream formats whose HEADER sits at b[0] (what a chain step may decode): gzip,
    zlib (CMF/FLG check), bzip2, xz, and decompress.py's validated containers (LZ4 frame / legacy,
    aPLib AP32, BriefLZ blzpack). A header only nominates a format; the strict decode (gzip CRC,
    zlib Adler-32, container checksums) is what proves it."""
    fmts = []
    if b[:3] == b"\x1f\x8b\x08":
        fmts.append("gzip")
    if len(b) >= 2 and b[0] & 0x0F == 8 and b[0] >> 4 <= 7 and not b[1] & 0x20 \
            and ((b[0] << 8) | b[1]) % 31 == 0:
        fmts.append("zlib")
    if b[:3] == b"BZh" and b[3:4].isdigit() and b[4:10] == b"\x31\x41\x59\x26\x53\x59":
        fmts.append("bz2")
    if b[:6] == b"\xfd7zXZ\x00":
        fmts.append("lzma")
    sigs = {name: sig for name, sig, _need in recover_embedded._MAGICS}
    for kind, fmt in decompress.CONTAINER_KINDS.items():
        if b[:4] == sigs[kind] and decompress.header_ok(kind, b, 0):
            fmts.append(fmt)
    return fmts


_CHAIN_DEPTH = 3         # decompression layers per blob (zlib -> LZ4 frame -> aPLib ... stops here)
_MAX_NESTED = 8          # containers found INSIDE a decompressed output that are decoded too


def _step(name, out, truncated, extra, cap):
    r = {"method": name, "out_size": len(out), "out_magic": _known_magic(out),
         "preview": out[:48].decode("latin-1", "replace"), **extra}
    if truncated:
        r["truncated_at"] = cap          # output cap hit: out_size is a floor, not the real size
    return r


def _chain(data, depth, budget):
    """Follow compressed layers: while `data` starts with a compressed-stream header (and fewer than
    _CHAIN_DEPTH layers were decoded), decompress it. Every layer draws on one shared output
    budget (budget[0] bytes, MAX_OUT per blob in total), so a nested bomb cannot multiply the
    cap. Returns (steps, final_bytes)."""
    steps = []
    while depth < _CHAIN_DEPTH and budget[0] > 0:
        fmts = _stream_formats(data)
        if not fmts:
            break
        name, out, truncated, extra = _try_decompress(data, budget[0], only=fmts)
        if out is None:
            break
        steps.append(_step(name, out, truncated, extra, budget[0]))
        budget[0] -= len(out)
        data, depth = out, depth + 1
    return steps, data


def _nested(data, depth, budget):
    """Validated compressed containers INSIDE a decompressed output (not at its start): decoded
    from their magic, each followed through its own chain."""
    found = []
    if depth >= _CHAIN_DEPTH:
        return found
    for h in recover_embedded._find_magics(data, 1):
        fmt = decompress.CONTAINER_KINDS.get(h["kind"])
        if not fmt or len(found) >= _MAX_NESTED or budget[0] <= 0:
            continue
        name, out, truncated, extra = _try_decompress(memoryview(data)[h["offset"]:], budget[0],
                                                      only=[fmt])
        if out is None:
            continue
        st = _step(name, out, truncated, extra, budget[0])
        budget[0] -= len(out)
        more, _final = _chain(out, depth + 1, budget)
        if more:
            st["chain"] = more
        found.append({"offset": h["offset"], **st})
    return found


def _with_chain(r, out, depth, budget):
    """Attach the layers below a recovered output to its record: `chain` (streams starting at
    offset 0, in order) and `nested` (containers inside the final output)."""
    steps, final = _chain(out, depth, budget)
    if steps:
        r["chain"] = r.get("chain", []) + steps
        r["final"] = {"out_size": steps[-1]["out_size"], "out_magic": steps[-1]["out_magic"]}
    inner = _nested(final, depth + len(steps), budget)
    if inner:
        r["nested"] = inner
    return r


def _xor1_break(blob: bytes):
    """Single-byte XOR brute (keys 1..255, keyless). Accept a key ONLY when the decode reveals a
    VALIDATED file magic at offset 0 (_validated_magic): that uniquely identifies the key. A bare
    2-byte "MZ" is not enough (~1/700 random blobs), nor is printability -- many keys turn a
    printable-XOR'd blob back into different printable bytes. Key 0 is the identity, not a
    decode: a blob whose plain bytes carry a magic is reported by _keyless as method "plain"."""
    sample = blob[:_XOR_SAMPLE]
    if not sample:
        return None
    first = sample[0]
    leads = {sig[0] for _name, sig, _need in recover_embedded._MAGICS}
    for k in range(1, 256):
        if (first ^ k) not in leads:       # cheap pre-filter: the decoded first byte must start a magic
            continue
        magic = _validated_magic(sample.translate(_XOR_TABLES[k]))
        if magic:
            return {"key": k, "magic": magic}
    return None


def _xor1_stream(blob: bytes, budget):
    """Single-byte XOR that reveals a compressed STREAM without a >= 4-byte validated magic (gzip's
    3-byte 1f8b08, zlib's 2-byte CMF/FLG, bzip2's "BZh"): a key is accepted only when the revealed
    stream then DEcompresses strictly (gzip CRC-32 / zlib Adler-32 / bzip2 CRC over the whole
    stream). Returns (key, format, out, truncated, extra) or None."""
    if len(blob) < 16:
        return None
    head = blob[:16]
    for k in range(1, 256):
        fmts = [f for f in _stream_formats(head.translate(_XOR_TABLES[k]))
                if f in ("gzip", "zlib", "bz2")]
        if not fmts:
            continue
        name, out, truncated, extra = _try_decompress(blob.translate(_XOR_TABLES[k]), budget[0],
                                                      only=fmts)
        if out is not None:
            return k, name, out, truncated, extra
    return None


_XOR_TABLES = [bytes(b ^ k for b in range(256)) for k in range(256)]


def _keyless(blob: bytes):
    """What can be recovered from `blob` with no key: decompression first, then XOR-1 brute -- and,
    below either, every further compressed layer (`chain`, depth <= _CHAIN_DEPTH, one shared
    MAX_OUT output budget) and containers inside the result (`nested`)."""
    blob = bytes(blob)
    budget = [MAX_OUT]
    name, out, truncated, extra = _try_decompress(blob, budget[0])
    if out is not None:
        r = _step(name, out, truncated, extra, budget[0])
        budget[0] -= len(out)
        return _with_chain(r, out, 1, budget)
    plain = _validated_magic(blob[:_XOR_SAMPLE])
    if plain:
        return {"method": "plain", "magic": plain}  # not encoded at all (the XOR key-0 identity)
    x = _xor1_break(blob)
    if x is not None:
        # the revealed bytes may be a compressed container (LZ4 frame, AP32, blzpack, xz) or
        # carry one: follow it like any decompressed output
        return _with_chain({"method": "xor8", **x}, blob.translate(_XOR_TABLES[x["key"]]), 0, budget)
    s = _xor1_stream(blob, budget)
    if s is not None:
        k, name, out, truncated, extra = s
        r = {"method": "xor8", "key": k, "magic": name,
             "chain": [_step(name, out, truncated, extra, budget[0])]}
        budget[0] -= len(out)
        _with_chain(r, out, 1, budget)                    # appends further layers to r["chain"]
        r["final"] = {"out_size": r["chain"][-1]["out_size"], "out_magic": r["chain"][-1]["out_magic"]}
        return r
    return None


_MAX_STREAMS = 64        # magic-anchored container decodes per file (each is bounded by MAX_OUT)


def _overlay_offset(data: bytes):
    """File offset where a PE's or ELF's own structure ends (sections, segments, header tables), if
    bytes follow it: an appended overlay. Droppers append a compressed core/config there, often in
    a headerless format whose start the entropy carve (256-byte grid) cannot pin down. None when
    there is no overlay or the header does not parse; never raises."""
    import struct
    try:
        n = len(data)
        hi = 0
        if data[:4] == b"\x7fELF" and data[4] in (1, 2) and data[5] in (1, 2):
            e = "<" if data[5] == 1 else ">"
            if data[4] == 2:
                phoff, shoff = struct.unpack_from(e + "QQ", data, 0x20)
                phes, phn, shes, shn = struct.unpack_from(e + "HHHH", data, 0x36)
                hi = 64
            else:
                phoff, shoff = struct.unpack_from(e + "II", data, 0x1c)
                phes, phn, shes, shn = struct.unpack_from(e + "HHHH", data, 0x2a)
                hi = 52
            wide = data[4] == 2
            if (phn and phoff + phn * phes > n) or (shn and shoff + shn * shes > n):
                return None                                    # header tables outside the file
            if phoff and phn:
                hi = max(hi, phoff + phn * phes)
                for k in range(min(phn, 4096)):
                    p = phoff + k * phes
                    off, size = (struct.unpack_from(e + "Q", data, p + 8)[0],
                                 struct.unpack_from(e + "Q", data, p + 32)[0]) if wide else \
                        (struct.unpack_from(e + "I", data, p + 4)[0], struct.unpack_from(e + "I", data, p + 16)[0])
                    if size:
                        hi = max(hi, off + size)
            if shoff and shn:
                hi = max(hi, shoff + shn * shes)
                for k in range(min(shn, 4096)):
                    p = shoff + k * shes
                    typ = struct.unpack_from(e + "I", data, p + 4)[0]
                    off, size = struct.unpack_from(e + ("QQ" if wide else "II"), data, p + (24 if wide else 16))
                    if typ != 8 and size:                      # SHT_NOBITS occupies no file bytes
                        hi = max(hi, off + size)
        elif data[:2] == b"MZ" and n >= 0x40:
            lfa = struct.unpack_from("<I", data, 0x3c)[0]
            if data[lfa:lfa + 4] != b"PE\x00\x00":
                return None
            nsec, = struct.unpack_from("<H", data, lfa + 6)
            optsz, = struct.unpack_from("<H", data, lfa + 20)
            hi = struct.unpack_from("<I", data, lfa + 24 + 60)[0]    # SizeOfHeaders
            sec = lfa + 24 + optsz
            for k in range(min(nsec, 96)):
                rawsize, rawptr = struct.unpack_from("<II", data, sec + 40 * k + 16)
                if rawsize:
                    hi = max(hi, rawptr + rawsize)
        else:
            return None
        return hi if 0 < hi < n else None
    except (struct.error, IndexError, OverflowError):
        return None


def _streams(data: bytes, emb: dict, blobs: list):
    """Keyless recovery at exact stream starts the entropy carve cannot give: (1) every validated
    compressed-container magic recover_embedded found (LZ4 frame / legacy, aPLib AP32, BriefLZ
    blzpack), decoded from the magic; (2) a PE/ELF overlay, tried with the whole keyless chain."""
    out = []
    view = memoryview(data)
    for h in emb["embedded"]:
        fmt = decompress.CONTAINER_KINDS.get(h["kind"])
        if not fmt:
            continue
        if len(out) >= _MAX_STREAMS:
            break
        budget = [MAX_OUT]
        name, o, truncated, extra = _try_decompress(view[h["offset"]:], budget[0], only=[fmt])
        k = None
        if o is not None:
            k = _step(name, o, truncated, extra, budget[0])
            budget[0] -= len(o)
            _with_chain(k, o, 1, budget)
        out.append({"offset": h["offset"], "size": extra.get("consumed") if k else None,
                    "anchor": f"magic:{h['kind']}", "keyless": k})
    ov = _overlay_offset(data)
    if ov is not None:
        covered = {b["offset"] for b in blobs if b["offset"] + b["size"] == len(data)}
        covered |= {s["offset"] for s in out}
        if ov not in covered:
            out.append({"offset": ov, "size": len(data) - ov, "anchor": "overlay",
                        "keyless": _keyless(data[ov:])})
    return out


# ---- second pass: decompression-candidate search (exact starts the 256-byte carve grid misses) ----
_SEARCH_ENT = 6.0          # candidate-region window entropy (the blob carve needs 7.2: literal-heavy
                           # BriefLZ/LZNT1 interleave zero flag bytes and sit at ~6.5-7.1)
_SEARCH_WIN = 256          # candidate-region window (stride _SEARCH_WIN // 2)
_SEARCH_RADIUS = 256       # starts tried, step 1, either side of a candidate region's start
_SEARCH_TAIL = 4096        # starts tried, step 1, in the file's last bytes (payload flush with EOF)
_SEARCH_MAX_STARTS = 8192  # start offsets per file (deterministic budget, priority order below)
_SEARCH_MAX_LEN = 4 << 20  # longest stream a search attempt decodes
_PAD_RE = re.compile(rb"\x00{8,}")
_HEADERLESS = [name for name, _fn, headerless, _end in decompress.DECODERS if headerless]
_NO_END_MARKER = [name for name, _fn, headerless, end in decompress.DECODERS if headerless and not end]
_END_MARKED = [name for name, _fn, headerless, end in decompress.DECODERS if headerless and end]


_CLOGC = [0.0] + [c * math.log2(c) for c in range(1, _SEARCH_WIN + 1)]


def _fast_entropy(b) -> float:
    """Order-0 entropy of a <= _SEARCH_WIN-byte window: H = log2 n - sum(c log2 c) / n."""
    n = len(b)
    if not n:
        return 0.0
    return math.log2(n) - sum(_CLOGC[c] for c in Counter(b).values()) / n


def _region_starts(data: bytes):
    """Starts of regions whose _SEARCH_WIN windows reach _SEARCH_ENT bits/byte (lazily: the
    caller stops pulling once its start budget is spent, so a huge file is not scanned whole)."""
    inside = False
    step = _SEARCH_WIN // 2
    for off in range(0, max(1, len(data) - _SEARCH_WIN + 1), step):
        hot = _fast_entropy(data[off:off + _SEARCH_WIN]) >= _SEARCH_ENT
        if hot and not inside:
            yield off
        inside = hot


def _search_starts(data: bytes, pads):
    """Candidate start offsets in priority order, de-duplicated, at most _SEARCH_MAX_STARTS."""
    n = len(data)

    def gen():
        yield from range(max(0, n - _SEARCH_TAIL), n)
        yield from (e for _a, e in pads if e < n)
        for lo in _region_starts(data):
            yield from range(max(0, lo - _SEARCH_RADIUS), min(n, lo + _SEARCH_RADIUS))
    seen, starts = set(), []
    for c in gen():
        if c not in seen:
            seen.add(c)
            starts.append(c)
            if len(starts) >= _SEARCH_MAX_STARTS:
                break
    return starts


def _end_marked(view, st, e):
    """aPLib / LZNT1 at [st, e): the stream stops at its own end marker; when only zero bytes
    follow it (the padding that delimited the candidate), judge it on exactly the bytes it used."""
    for fmt in _END_MARKED:
        r = decompress.decode(fmt, view[st:e], MAX_OUT)
        if r is None:
            continue
        c = r["consumed"]
        blob = view[st:st + c] if not r["truncated"] and not any(view[st + c:e]) else view[st:e]
        a = decompress.accept(fmt, blob, r)
        if a is not None:
            a["format"] = fmt
            return a
    return None


def _search(data: bytes, taken):
    """Second pass for headerless streams (raw LZ4 block, aPLib, BriefLZ, LZNT1) the entropy carve
    cannot pin down: a stream whose start is off the 256-byte grid, a literal-heavy BriefLZ/LZNT1
    stream under the 7.2 bits/byte carve threshold, a tiny config. Start offsets, in priority order
    and capped at _SEARCH_MAX_STARTS per file: (1) every offset of the last _SEARCH_TAIL bytes (a
    payload appended at EOF), (2) the end of every run of >= 8 zero bytes (alignment padding before
    an embedded payload), (3) +-256 bytes, step 1, around the start of every region of >= 6.0-bit
    windows. A hit moves forward to the latest start within 16 bytes that also decodes (junk just
    before a stream can parse into it; a start inside a stream does not). The stream must END where
    the next zero run starts (+0..3: aPLib's end byte, LZNT1's terminator) or at EOF -- streams
    followed directly by other non-zero data are not found (a no-end-marker format has no exact end
    to find). Precision rests on decompress.py's strict decoders + acceptance policy (full
    consumption, expansion, evidence, encoder-signature veto); `taken` ranges (already recovered)
    are skipped. Returns stream records (anchor "search")."""
    n = len(data)
    pads = [(m.start(), m.end()) for m in _PAD_RE.finditer(data)]
    pad_starts = [a for a, _b in pads]
    starts = _search_starts(data, pads)
    view = memoryview(data)
    found = []
    spans = sorted(taken)
    for st in starts:
        if any(a <= st < b for a, b in spans):
            continue
        r = _try_at(view, st, pad_starts)
        if r is None:
            continue
        # junk right before a real stream can parse as a few literals and fall back into step with
        # it (measured: 6 of 156 embedded streams had such a start within 16 bytes before them);
        # a start INSIDE a real stream essentially never resynchronises (0 of 156). So a later
        # start that also decodes is the better one: move forward while one exists.
        moved = True
        while moved:
            moved = False
            for s2 in range(st + 1, min(n, st + 17)):
                r2 = _try_at(view, s2, pad_starts)
                if r2 is not None:
                    st, r, moved = s2, r2, True
                    break
        budget = [MAX_OUT]
        extra = {"consumed": r["consumed"], "evidence": r["evidence"]}
        rec = _step(r["format"], r["out"], r["truncated"], extra, budget[0])
        budget[0] -= len(r["out"])
        _with_chain(rec, r["out"], 1, budget)
        found.append({"offset": st, "size": r["consumed"], "anchor": "search", "keyless": rec})
        spans.append((st, st + r["consumed"]))
    return found


def _try_at(view, st, pad_starts):
    """A headerless stream starting at `st` and ending where the next zero run begins (+0..3) or
    at EOF: the accepted decode, or None."""
    n = len(view)
    k = bisect.bisect_right(pad_starts, st)
    ends = [e for e in range(pad_starts[k], pad_starts[k] + 4) if e <= n] if k < len(pad_starts) else [n]
    # formats without an end marker need the exact end: nearest candidate first (a farther one
    # would append padding zeros as literals); end-marked formats find their own end, so they
    # are tried once, at the farthest candidate
    for e in sorted(ends):
        if 16 <= e - st <= _SEARCH_MAX_LEN:
            r = decompress.try_all(view[st:e], MAX_OUT, formats=_NO_END_MARKER)
            if r is not None:
                return r
    e = max(ends)
    if 16 <= e - st <= _SEARCH_MAX_LEN:
        return _end_marked(view, st, e)
    return None


def recover(path) -> dict:
    """Carve blobs from `path`, attempt keyless recovery of each, and list crypto candidates.

    Returns {file_size, crypto_candidates, blobs:[{offset,size,entropy,keyless|None}],
    streams:[{offset,size,anchor,keyless|None}], embedded, base64, counts}. `streams` are exact
    stream starts (a compressed-container magic, or a PE/ELF overlay) tried on top of the
    entropy-carved blobs. Offsets are file offsets (feed a carver directly)."""
    data = Path(path).read_bytes()
    emb = recover_embedded.recover(path)
    crypto = recover_crypto.recover(path).get("algorithms", [])
    blobs = []
    for h in emb["high_entropy"]:
        b = data[h["offset"]:h["offset"] + h["size"]]
        blobs.append({"offset": h["offset"], "size": h["size"], "entropy": h["entropy"],
                      "sha256": h["sha256"], "keyless": _keyless(b)})
    streams = _streams(data, emb, blobs)
    taken = [(x["offset"], x["offset"] + (x["size"] or 0)) for x in blobs + streams
             if x["keyless"] and x["keyless"]["method"] != "plain"]
    streams += _search(data, taken)
    # "plain" is a blob that needed no recovery (its bytes already carry a magic), not a recovery
    recovered = sum(1 for x in blobs + streams if x["keyless"] and x["keyless"]["method"] != "plain")
    return {
        "file_size": len(data),
        "crypto_candidates": crypto,
        "blobs": blobs,
        "streams": streams,
        "embedded": emb["embedded"],
        "base64": emb["base64"],
        "counts": {"blobs": len(blobs), "streams": len(streams), "keyless_recovered": recovered,
                   "embedded": len(emb["embedded"]), "base64": len(emb["base64"]),
                   "crypto_candidates": len(crypto)},
    }


def _describe(k) -> str:
    if not k:
        return "opaque (encrypted?); no keyless recovery"
    if k["method"] == "plain":
        return f"plain {k['magic']} (not encoded)"
    if k["method"] == "xor8":
        head = f"single-byte XOR key=0x{k['key']:02x} reveals {k['magic']}"
    else:
        cut = f" (truncated at the {k['truncated_at']}B cap)" if k.get("truncated_at") else ""
        ev = f" evidence={k['evidence']}" if k.get("evidence") else ""
        head = (f"decompressed via {k['method']} -> {k['out_size']}B{cut} magic={k['out_magic']}{ev} "
                f"{k['preview']!r}")
    for st in k.get("chain", []):
        head += f" | then {st['method']} -> {st['out_size']}B magic={st['out_magic']}"
    if k.get("nested"):
        head += " | inside: " + ", ".join(f"{x['method']}@0x{x['offset']:x}->{x['out_size']}B"
                                          for x in k["nested"])
    return head


def _print(res):
    c = res["counts"]
    print(f"file_size={res['file_size']}  blobs={c['blobs']} streams={c['streams']} "
          f"(keyless_recovered={c['keyless_recovered']})  embedded={c['embedded']}  base64={c['base64']}  "
          f"crypto_candidates={c['crypto_candidates']}")
    if res["crypto_candidates"]:
        print(f"  candidate algorithms present (need a key to decrypt): {', '.join(res['crypto_candidates'])}")
    for b in res["blobs"]:
        print(f"  [blob 0x{b['offset']:x} {b['size']}B H={b['entropy']}] {_describe(b['keyless'])}")
    for s in res["streams"]:
        size = f" {s['size']}B" if s["size"] is not None else ""
        print(f"  [stream 0x{s['offset']:x}{size} {s['anchor']}] {_describe(s['keyless'])}")


def _selftest():
    import gzip
    # 1. a gzip-compressed payload is recovered with no key
    plain = b"report: status=ok region=eu count=42 note=benign-fixture\n" * 4
    r = _keyless(gzip.compress(plain))
    assert r and r["method"] == "gzip" and r["out_size"] == len(plain), r

    # 2. a single-byte-XOR'd PE header: the brute finds the key and the revealed magic
    # (a real DOS header: e_lfanew at 0x3c points at the PE\0\0 signature, which validation checks)
    hdr = b"MZ" + b"\x90" * 6 + b"\x00" * 52 + (0x40).to_bytes(4, "little") + b"PE\x00\x00" + bytes(64)
    enc = bytes(b ^ 0x3c for b in hdr)
    x = _xor1_break(enc)
    assert x and x["key"] == 0x3c and x["magic"] == "pe", x

    # 3. a single-byte-XOR'd ELF payload is likewise recovered via its magic
    elf = b"\x7fELF\x02\x01\x01" + bytes(120)
    z = _xor1_break(bytes(b ^ 0xa5 for b in elf))
    assert z and z["key"] == 0xa5 and z["magic"] == "elf", z

    # 4. precision: random bytes and plain text yield NO magic-anchored XOR key (no false decode);
    #    seeded so the assertion is deterministic, and including a blob whose first two bytes XOR to
    #    "MZ" (which a bare 2-byte magic check accepted as key 0x77)
    import random
    rng = random.Random(0xb10b)
    assert _keyless(rng.randbytes(2048)) is None
    assert _keyless(bytes([0x4d ^ 0x77, 0x5a ^ 0x77]) + rng.randbytes(1022)) is None
    assert _xor1_break(b"ordinary readable configuration text, nothing hidden here " * 4) is None

    # 5. key 0 is not a decode: a plain ELF is "plain", never "xor8 key=0"
    assert _keyless(elf) == {"method": "plain", "magic": "elf"}, _keyless(elf)
    print("selftest OK: gzip payload decompressed; XOR-1 PE & ELF payloads recovered by magic; "
          "random and plain text stay opaque (no false decode)")


def main(argv=None):
    import argparse
    import json
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("binary", nargs="?")
    ap.add_argument("--json", action="store_true", help="print the result dict as JSON")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args(argv)
    if a.selftest:
        _selftest()
        return 0
    if not a.binary:
        ap.error("give a binary, or --selftest")
    path = Path(a.binary)
    if not path.is_file():
        ap.error(f"no such file: {path}")
    res = recover(path)
    print(json.dumps(res, indent=2)) if a.json else _print(res)
    return 0


if __name__ == "__main__":
    sys.exit(main())
