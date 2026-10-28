#!/usr/bin/env python3
"""recover_blobs.py - triage embedded payload blobs: carve them, attempt *keyless* recovery, and
annotate with the cryptographic primitives the binary carries.

Pipeline (all defensive, benign inputs): recover_embedded.py carves high-entropy blobs, embedded
executables/archives and base64 payloads; for each blob we try the recoveries that need NO key --
decompression (zlib/gzip/bz2/lzma, then decompress.py's strict LZ4 frame/legacy/block, aPLib,
BriefLZ and LZNT1 decoders) and single-byte-XOR brute (the classic keyless config obfuscation) --
and recover_crypto.py lists the cipher/hash primitives present as *candidates*. Exact stream starts
the 256-byte entropy grid cannot give are tried as `streams`: each validated compressed-container
magic (LZ4 frame/legacy, aPLib 'AP32', BriefLZ blzpack) and a PE/ELF overlay (droppers append a
compressed core/config at EOF, often headerless).

Honest about limits: a blob encrypted with a real cipher cannot be decrypted without its key, which
a static tool does not have. This surfaces the keyless wins and names the candidate algorithms for
an analyst; it does not claim to break encryption.
"""
import sys
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


def _inflate(make, blob: bytes):
    """Run a streaming decompressor with the MAX_OUT output cap. Returns (out, truncated) only for a
    stream that either completed (eof) or was cut by the cap; an error or an incomplete stream (a
    random blob that merely parsed for a while) is None, as zlib.decompress & co. would raise."""
    d = make()
    out = d.decompress(blob, MAX_OUT)
    if getattr(d, "eof", False):
        # a completed stream must account for the blob: random bytes parse as a tiny raw-deflate
        # stream ~1 time in 1000 (consuming 10-60 bytes, the rest left as unused_data). A real
        # payload is the whole carve, or at least _MIN_STREAM bytes of it.
        consumed = len(blob) - len(getattr(d, "unused_data", b""))
        if consumed < min(_MIN_STREAM, len(blob)):
            return None
        return out, False
    if len(out) >= MAX_OUT:
        return out, True
    return None


def _try_decompress(blob: bytes):
    """Keyless: a compressed payload decompresses with no key. Try the common codecs, each capped at
    MAX_OUT bytes of output (a zip bomb is reported truncated, not inflated): zlib/gzip/bz2/lzma,
    then decompress.py's strict LZ4 / aPLib / BriefLZ / LZNT1 decoders (containers first; the
    headerless formats only with full consumption + expansion + an "interesting" output, see
    decompress.py). Returns (name, out, truncated, extra) or (None, None, False, {}); `extra` carries
    `consumed` and, for a headerless format, the `evidence` that made the decode believable."""
    import bz2
    import lzma
    import zlib
    attempts = [
        ("zlib", lambda: zlib.decompressobj(15)),
        ("zlib_raw", lambda: zlib.decompressobj(-15)),
        ("gzip", lambda: zlib.decompressobj(16 + 15)),
        ("bz2", bz2.BZ2Decompressor),
        # memlimit: an xz/lzma header can declare a ~1.5 GiB dictionary; real presets need <= ~65 MiB
        ("lzma", lambda: lzma.LZMADecompressor(memlimit=128 << 20)),
    ]
    for name, make in attempts:
        try:
            r = _inflate(make, blob)
        except Exception:
            continue
        if r is None:
            continue
        out, truncated = r
        if out and len(out) >= 8:
            return name, out, truncated, {}
    d = decompress.try_all(blob, MAX_OUT)
    if d is not None:
        extra = {"consumed": d["consumed"]}
        if d.get("evidence"):
            extra["evidence"] = d["evidence"]
        return d["format"], d["out"], d["truncated"], extra
    return None, None, False, {}


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


_XOR_TABLES = [bytes(b ^ k for b in range(256)) for k in range(256)]


def _keyless(blob: bytes):
    """What can be recovered from `blob` with no key: decompression first, then XOR-1 brute."""
    name, out, truncated, extra = _try_decompress(blob)
    if out is not None:
        r = {"method": name, "out_size": len(out), "out_magic": _known_magic(out),
             "preview": out[:48].decode("latin-1", "replace"), **extra}
        if truncated:
            r["truncated_at"] = MAX_OUT      # output cap hit: out_size is a floor, not the real size
        return r
    plain = _validated_magic(blob[:_XOR_SAMPLE])
    if plain:
        return {"method": "plain", "magic": plain}  # not encoded at all (the XOR key-0 identity)
    x = _xor1_break(blob)
    if x is not None:
        return {"method": "xor8", **x}
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
        r = decompress.try_all(view[h["offset"]:], MAX_OUT, formats=[fmt])
        k = None
        if r is not None:
            o = r["out"]
            k = {"method": fmt, "consumed": r["consumed"], "out_size": len(o),
                 "out_magic": _known_magic(o), "preview": o[:48].decode("latin-1", "replace")}
            if r["truncated"]:
                k["truncated_at"] = MAX_OUT
        out.append({"offset": h["offset"], "size": r["consumed"] if r else None,
                    "anchor": f"magic:{h['kind']}", "keyless": k})
    ov = _overlay_offset(data)
    if ov is not None:
        covered = {b["offset"] for b in blobs if b["offset"] + b["size"] == len(data)}
        covered |= {s["offset"] for s in out}
        if ov not in covered:
            out.append({"offset": ov, "size": len(data) - ov, "anchor": "overlay",
                        "keyless": _keyless(data[ov:])})
    return out


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
        return f"single-byte XOR key=0x{k['key']:02x} reveals {k['magic']}"
    cut = f" (truncated at the {k['truncated_at']}B cap)" if k.get("truncated_at") else ""
    ev = f" evidence={k['evidence']}" if k.get("evidence") else ""
    return (f"decompressed via {k['method']} -> {k['out_size']}B{cut} magic={k['out_magic']}{ev} "
            f"{k['preview']!r}")


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
