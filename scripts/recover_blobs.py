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


def _printable_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    return sum(1 for x in b if 0x20 <= x < 0x7f or x in (9, 10, 13)) / len(b)


def _known_magic(b: bytes):
    for name, sig, _need in recover_embedded._MAGICS:
        if b.startswith(sig):
            return name
    return None


def _try_decompress(blob: bytes):
    """Keyless: a compressed payload decompresses with no key. Try the common codecs."""
    import bz2
    import gzip
    import lzma
    import zlib
    attempts = [
        ("zlib", lambda d: zlib.decompress(d)),
        ("zlib_raw", lambda d: zlib.decompress(d, -15)),
        ("gzip", lambda d: gzip.decompress(d)),
        ("bz2", lambda d: bz2.decompress(d)),
        ("lzma", lambda d: lzma.decompress(d)),
    ]
    for name, fn in attempts:
        try:
            out = fn(blob)
        except Exception:
            continue
        if out and len(out) >= 8:
            return name, out
    return None, None


def _xor1_break(blob: bytes):
    """Single-byte XOR brute (256 tries, keyless). Accept a key ONLY when the decode reveals a known
    file magic: that uniquely identifies the key. Printability alone is ambiguous -- many keys turn a
    printable-XOR'd blob back into different printable bytes -- so we don't guess from it (that would
    be a false 'decoded'). A nested exe/archive hidden by a one-byte XOR is the reliable win here."""
    sample = blob[:512]
    if not sample:
        return None
    for k in range(256):
        if _known_magic(bytes(b ^ k for b in sample)):
            return {"key": k, "magic": _known_magic(bytes(b ^ k for b in sample))}
    return None


def _keyless(blob: bytes):
    """What can be recovered from `blob` with no key: decompression first, then XOR-1 brute."""
    name, out = _try_decompress(blob)
    if out is not None:
        return {"method": name, "out_size": len(out), "out_magic": _known_magic(out),
                "preview": out[:48].decode("latin-1", "replace")}
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
    recovered = sum(1 for x in blobs if x["keyless"])
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
        if k and k["method"] != "xor8":
            print(f"  [blob 0x{b['offset']:x} {b['size']}B H={b['entropy']}] decompressed via {k['method']} "
                  f"-> {k['out_size']}B magic={k['out_magic']} {k['preview']!r}")
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
    hdr = b"MZ" + b"\x90" * 6 + b"\x00" * 56 + b"PE\x00\x00" + bytes(64)
    enc = bytes(b ^ 0x3c for b in hdr)
    x = _xor1_break(enc)
    assert x and x["key"] == 0x3c and x["magic"] == "pe", x

    # 3. a single-byte-XOR'd ELF payload is likewise recovered via its magic
    elf = b"\x7fELF\x02\x01\x01" + bytes(120)
    z = _xor1_break(bytes(b ^ 0xa5 for b in elf))
    assert z and z["key"] == 0xa5 and z["magic"] == "elf", z

    # 4. precision: random bytes and plain text yield NO magic-anchored XOR key (no false decode)
    import os
    assert _keyless(os.urandom(2048)) is None
    assert _xor1_break(b"ordinary readable configuration text, nothing hidden here " * 4) is None
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
