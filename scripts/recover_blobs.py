#!/usr/bin/env python3
"""recover_blobs.py - triage embedded payload blobs: carve them, attempt *keyless* recovery, and
annotate with the cryptographic primitives the binary carries.

Pipeline (all defensive, benign inputs): recover_embedded.py carves high-entropy blobs, embedded
executables/archives and base64 payloads; for each blob we try the recoveries that need NO key --
decompression (zlib/gzip/bz2/lzma) and single-byte-XOR brute (the classic keyless config
obfuscation) -- and recover_crypto.py lists the cipher/hash primitives present as *candidates*.

Honest about limits: a blob encrypted with a real cipher cannot be decrypted without its key, which
a static tool does not have. This surfaces the keyless wins and names the candidate algorithms for
an analyst; it does not claim to break encryption.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

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


def _validated_magic(b: bytes):
    """A file magic at offset 0 that is strong enough to prove a decode: recover_embedded's
    validated hit (PE needs e_lfanew -> PE\\0\\0, ELF a sane e_ident) for any signature of at least
    4 bytes, or the validated PE. A bare 2-3 byte magic ("MZ", gzip's 1f8b08, "BZh") is hit by ~1 in
    700 random blobs across 255 XOR keys, so it proves nothing on its own."""
    sigs = {name: sig for name, sig, _need in recover_embedded._MAGICS}
    for h in recover_embedded._find_magics(b, 0):
        if h["offset"] != 0:
            continue
        if h["kind"] == "pe" or len(sigs.get(h["kind"], b"")) >= 4:
            return h["kind"]
    return None


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
    MAX_OUT bytes of output (a zip bomb is reported truncated, not inflated). Returns
    (name, out, truncated) or (None, None, False)."""
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
            return name, out, truncated
    return None, None, False


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
    name, out, truncated = _try_decompress(blob)
    if out is not None:
        r = {"method": name, "out_size": len(out), "out_magic": _known_magic(out),
             "preview": out[:48].decode("latin-1", "replace")}
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


def recover(path) -> dict:
    """Carve blobs from `path`, attempt keyless recovery of each, and list crypto candidates.

    Returns {file_size, crypto_candidates, blobs:[{offset,size,entropy,keyless|None}],
    embedded, base64, counts}. Offsets are file offsets (feed a carver directly).
    """
    data = Path(path).read_bytes()
    emb = recover_embedded.recover(path)
    crypto = recover_crypto.recover(path).get("algorithms", [])
    blobs = []
    for h in emb["high_entropy"]:
        b = data[h["offset"]:h["offset"] + h["size"]]
        blobs.append({"offset": h["offset"], "size": h["size"], "entropy": h["entropy"],
                      "sha256": h["sha256"], "keyless": _keyless(b)})
    # "plain" is a blob that needed no recovery (its bytes already carry a magic), not a recovery
    recovered = sum(1 for x in blobs if x["keyless"] and x["keyless"]["method"] != "plain")
    return {
        "file_size": len(data),
        "crypto_candidates": crypto,
        "blobs": blobs,
        "embedded": emb["embedded"],
        "base64": emb["base64"],
        "counts": {"blobs": len(blobs), "keyless_recovered": recovered,
                   "embedded": len(emb["embedded"]), "base64": len(emb["base64"]),
                   "crypto_candidates": len(crypto)},
    }


def _print(res):
    c = res["counts"]
    print(f"file_size={res['file_size']}  blobs={c['blobs']} (keyless_recovered={c['keyless_recovered']})  "
          f"embedded={c['embedded']}  base64={c['base64']}  crypto_candidates={c['crypto_candidates']}")
    if res["crypto_candidates"]:
        print(f"  candidate algorithms present (need a key to decrypt): {', '.join(res['crypto_candidates'])}")
    for b in res["blobs"]:
        k = b["keyless"]
        if k and k["method"] == "plain":
            print(f"  [blob 0x{b['offset']:x} {b['size']}B H={b['entropy']}] plain {k['magic']} (not encoded)")
        elif k and k["method"] != "xor8":
            cut = f" (truncated at the {k['truncated_at']}B cap)" if k.get("truncated_at") else ""
            print(f"  [blob 0x{b['offset']:x} {b['size']}B H={b['entropy']}] decompressed via {k['method']} "
                  f"-> {k['out_size']}B{cut} magic={k['out_magic']} {k['preview']!r}")
        elif k:
            print(f"  [blob 0x{b['offset']:x} {b['size']}B H={b['entropy']}] single-byte XOR key=0x{k['key']:02x} "
                  f"reveals {k['magic']}")
        else:
            print(f"  [blob 0x{b['offset']:x} {b['size']}B H={b['entropy']}] opaque (encrypted?); no keyless recovery")


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
