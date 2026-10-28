#!/usr/bin/env python3
"""recover_crypto.py - identify cryptographic primitives in a binary by their constants.

Malware that encrypts its config / C2 / payload embeds the cipher's constants, and those constants
are universal -- the same bytes in every implementation, regardless of source language or compiler.
Recognising them names the algorithm (AES, ChaCha20/Salsa20, RC4, SHA-1/256/512, MD5, CRC32,
BLAKE2) even in a stripped binary with no symbols, which tells an analyst what the sample uses to
protect its secrets and where to look for the key material. This complements the string tier:
`recover_cryptify`/`muddy` already name and key the two Rust crates rust-deobf models; this finds
the primitive itself in arbitrary code (hand-rolled, a C crypto lib linked via FFI, a Go binary).

Two kinds of signature:
  * byte sequences -- the Rijndael S-boxes, the ChaCha/Salsa `expand 32-byte k` sigma, the Base64
    alphabet: matched as exact substrings;
  * constant sets -- SHA/MD5 round + init constants, the CRC32 polynomial, BLAKE2 IV: each algorithm
    has a set of 32/64-bit magic words; we scan the file for them as little-endian values and flag
    the algorithm when enough distinct ones are present (order- and padding-independent). Shared IV
    words (MD5/SHA-1, SHA-256 = halves of SHA-512) never make a "high" hit alone: that needs one of
    the algorithm's own round constants. On AArch64, constants built by movz/movk are decoded too.

    python3 scripts/recover_crypto.py path/to/binary            # human-readable
    python3 scripts/recover_crypto.py path/to/binary --json
    python3 scripts/recover_crypto.py --selftest

Language-agnostic (works on any ELF/PE/Mach-O). A hit means the primitive's constants are present,
not that the sample necessarily uses it at run time -- an analyst confirms.
"""
from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

# --- byte-sequence signatures (exact substrings) --------------------------------------------
# Rijndael (AES) forward S-box, first 32 bytes -- distinctive enough that a coincidental match is
# astronomically unlikely, so we need not carry all 256.
AES_SBOX = bytes([
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0])
AES_INV_SBOX = bytes([
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb])

_BYTE_SIGS = [
    ("AES", "Rijndael forward S-box", AES_SBOX, "high"),
    ("AES", "Rijndael inverse S-box", AES_INV_SBOX, "high"),
    ("ChaCha20/Salsa20", "sigma constant", b"expand 32-byte k", "high"),
    ("ChaCha20/Salsa20", "tau constant", b"expand 16-byte k", "high"),
    ("Base64", "standard alphabet", b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", "medium"),
    ("Base64", "url-safe alphabet", b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", "medium"),
]

# --- constant-set signatures (32/64-bit magic words, scanned as little-endian) --------------
# Each set is split into INIT words (IVs -- several algorithms share them: MD5 and SHA-1 start from
# the same four words; the SHA-256 IV is the high halves of the SHA-512/BLAKE2b IV) and ROUND
# constants (unique to one algorithm). "high" confidence needs at least one round constant; an
# init-only match is "medium" and is dropped entirely when another algorithm's match with round
# constants already explains every word it found.
_CONST_SIGS = {
    "SHA-256": {"width": 4, "min": 4,
                "init": [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                         0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19],
                "round": [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
                          0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5]},
    "SHA-1": {"width": 4, "min": 3,
              "init": [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0],
              "round": [0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6]},
    "MD5": {"width": 4, "min": 4,
            "init": [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476],
            "round": [0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
                      0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501]},
    "SHA-512/BLAKE2b": {"width": 8, "min": 3,
                        "init": [0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b,
                                 0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f,
                                 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179],
                        "round": [0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f,
                                  0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019]},
    "CRC32": {"width": 4, "min": 1, "init": [],
              "round": [0xedb88320, 0x04c11db7, 0x82f63b78]},  # poly (refl/norm/Castagnoli)
}
# every 64-bit word whose 32-bit halves would otherwise read as SHA-256 init/round constants
_WIDE = frozenset(_CONST_SIGS["SHA-512/BLAKE2b"]["init"] + _CONST_SIGS["SHA-512/BLAKE2b"]["round"])


def _half_of_wide(data: bytes, off: int) -> bool:
    """Is the 32-bit word at `off` one half of a known 64-bit constant (LE) in `data`?"""
    for base in (off - 4, off):
        if 0 <= base and base + 8 <= len(data) and struct.unpack_from("<Q", data, base)[0] in _WIDE:
            return True
    return False


def arm64_immediates(code: bytes, file_off: int = 0):
    """Constants an AArch64 code blob builds with `movz`/`mov` + `movk` (a 32/64-bit value split into
    16-bit chunks, so it never appears as contiguous little-endian bytes). Yields
    (value, width, file_offset_of_the_movz). Only movk's to the same register within a short window
    after the movz are folded in; a 64-bit (x-register) value is reported at width 8, and also at
    width 4 when it fits in 32 bits."""
    n = len(code) // 4
    words = struct.unpack_from(f"<{n}I", code) if n else ()
    for i, w in enumerate(words):
        if (w & 0x7f800000) != 0x52800000:              # MOVZ (32/64-bit)
            continue
        sf, rd = w >> 31, w & 0x1f
        hw = (w >> 21) & 3
        if not sf and hw > 1:
            continue
        val = ((w >> 5) & 0xffff) << (16 * hw)
        chunks = 1
        for j in range(i + 1, min(n, i + 9)):
            x = words[j]
            if (x & 0x1f) != rd:
                continue
            if (x & 0x7f800000) == 0x72800000 and (x >> 31) == sf:     # MOVK same width, same Rd
                h = (x >> 21) & 3
                if not sf and h > 1:
                    break
                val = (val & ~(0xffff << (16 * h))) | (((x >> 5) & 0xffff) << (16 * h))
                chunks += 1
                continue
            break                                       # any other write to Rd ends the sequence
        if chunks < 2:
            continue                                    # a single movz is a plain 16-bit immediate
        off = file_off + 4 * i
        if sf:
            yield val, 8, off
            if val < (1 << 32):
                yield val, 4, off
        else:
            yield val, 4, off


def scan(data: bytes, extra=None) -> list[dict]:
    """All crypto-constant hits in `data` (file offsets). `extra` is an optional iterable of
    (value, width, file_offset) constants decoded from instructions (arm64_immediates)."""
    hits = []
    for algo, what, sig, conf in _BYTE_SIGS:
        start = data.find(sig)
        while start != -1:
            hits.append({"algo": algo, "kind": what, "offset": start, "confidence": conf,
                         "match": "byte-sequence"})
            start = data.find(sig, start + 1)
    decoded = {}
    for v, w, off in (extra or ()):
        decoded.setdefault((w, v), off)
    sets = []
    for algo, spec in _CONST_SIGS.items():
        w = spec["width"]
        fmt = "<I" if w == 4 else "<Q"
        rounds = set(spec["round"])
        found = {}
        for c in set(spec["init"]) | rounds:
            pat = struct.pack(fmt, c)
            off = data.find(pat)
            # a 32-bit hit that is just half of a SHA-512/BLAKE2b word is that word, not SHA-256
            while off != -1 and w == 4 and _half_of_wide(data, off):
                off = data.find(pat, off + 1)
            if off == -1 and (w, c) in decoded:
                off = decoded[(w, c)]
            if off != -1:
                found[c] = off
        if len(found) >= spec["min"]:
            nround = len(rounds & set(found))
            sets.append((algo, found, nround, spec["min"]))
    for algo, found, nround, mn in sets:
        if nround == 0 and any(o_n and set(found) <= set(o_f) for o_a, o_f, o_n, _ in sets
                               if o_a != algo):
            continue        # shared IV words, already explained by an algorithm with round constants
        conf = "high" if nround and len(found) >= mn + 1 else "medium"
        hits.append({"algo": algo, "kind": f"{len(found)} constant(s): {len(found) - nround} init, "
                                           f"{nround} round",
                     "offset": min(found.values()), "confidence": conf,
                     "match": "constant-set", "constants": sorted(hex(c) for c in found)})
    hits.sort(key=lambda h: h["offset"])
    return hits


def _is_arm64(b) -> bool:
    try:
        if b.format.name == "ELF":
            return "AARCH64" in str(b.header.machine_type)
        if b.format.name == "MACHO":
            return "ARM64" in str(b.header.cpu_type)
        return "ARM64" in str(b.header.machine)
    except Exception:
        return False


def _exec_section(b, s) -> bool:
    f = b.format.name
    if f == "PE":
        return bool(int(s.characteristics) & 0x20000000)
    if f == "MACHO":
        return bool(int(s.flags) & 0x80000400)
    return bool(int(s.flags) & 0x4)


def recover(path) -> dict:
    """Scan a binary's bytes for crypto primitives; map each hit's file offset to a VA when it falls
    inside a section."""
    import lief
    data = Path(path).read_bytes()
    b = lief.parse(str(path))
    secs = []
    if b is not None:
        for s in b.sections:
            try:
                off = s.offset
                size = len(bytes(s.content))
                if off and size:
                    secs.append((off, off + size, s.virtual_address, s.name))
            except Exception:
                continue
    extra = []
    if b is not None and _is_arm64(b):
        for s in b.sections:
            try:
                if not _exec_section(b, s) or not s.size:
                    continue
                extra.extend(arm64_immediates(bytes(s.content), s.offset))
            except Exception:
                continue
    hits = scan(data, extra)
    for h in hits:
        h["va"], h["section"] = None, None
        for lo, hi, va, name in secs:
            if lo <= h["offset"] < hi:
                h["va"] = va + (h["offset"] - lo)
                h["section"] = name
                break
    algos = sorted({h["algo"] for h in hits})
    return {"file": str(path), "algorithms": algos, "hits": hits}


def _print(res: dict) -> None:
    print(f"file={Path(res['file']).name}  crypto primitives: "
          + (", ".join(res["algorithms"]) if res["algorithms"] else "none found"))
    for h in res["hits"]:
        loc = f"0x{h['va']:x} ({h['section']})" if h.get("va") is not None else f"file+0x{h['offset']:x}"
        extra = ("  " + " ".join(h["constants"][:6])) if h.get("constants") else ""
        print(f"  [{h['confidence']:<6}] {h['algo']:<16} {h['kind']}  @ {loc}{extra}")


def _selftest():
    # a buffer salting several primitives' constants among noise -> all must be identified
    import os
    blob = bytearray(os.urandom(4096))
    def put(b): blob.extend(b)
    put(AES_SBOX)
    put(b"expand 32-byte k")
    for c in (0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x428a2f98):   # SHA-256 (5 consts)
        put(struct.pack("<I", c))
    for c in (0x67452301, 0xefcdab89, 0xd76aa478, 0xe8c7b756):               # MD5 (4 consts)
        put(struct.pack("<I", c))
    put(struct.pack("<I", 0xedb88320))                                       # CRC32 poly
    put(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")  # base64
    hits = scan(bytes(blob))
    algos = {h["algo"] for h in hits}
    assert "AES" in algos, algos
    assert "ChaCha20/Salsa20" in algos, algos
    assert "SHA-256" in algos, algos
    assert "MD5" in algos, algos
    assert "CRC32" in algos, algos
    assert "Base64" in algos, algos
    # the AES hit is a high-confidence byte-sequence match
    aes = [h for h in hits if h["algo"] == "AES"][0]
    assert aes["confidence"] == "high" and aes["match"] == "byte-sequence"
    # precision: pure random noise yields no primitive -- the signatures (32-byte S-box, a 16-byte
    # sigma, a set of specific 32-bit constants) are far too specific to appear by chance
    clean = scan(os.urandom(4096))
    assert clean == [], f"random noise produced {clean}"
    # SHA-256 below threshold (only 2 constants) is NOT flagged
    low = bytearray(os.urandom(2048))
    low.extend(struct.pack("<I", 0x6a09e667)); low.extend(struct.pack("<I", 0xbb67ae85))
    assert "SHA-256" not in {h["algo"] for h in scan(bytes(low))}
    print("selftest OK: identified AES/ChaCha/SHA-256/MD5/CRC32/Base64 from constants among noise, "
          "random noise clean, below-threshold constant set not flagged")


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("binary", nargs="?")
    ap.add_argument("--json", action="store_true")
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
