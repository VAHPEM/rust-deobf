#!/usr/bin/env python3
"""recover_embedded.py - find embedded artifacts carried inside a binary: nested executables and
archives, high-entropy (packed/encrypted) blobs, and long base64 runs.

This is the statically-recoverable half of "embedded data recovery": a config, a second-stage
payload, or an archive dropped by the sample is often stored verbatim (or lightly encoded) in a data
section. We do NOT try to name enum variants or reconstruct niche layout -- that needs debug info a
stripped binary does not carry, so its value is marginal (see the repo backlog). What *is* reliable
without debug info: magic-byte signatures, Shannon entropy over a sliding window, and base64 runs.

Defensive triage only; benign inputs.
"""
import base64
import hashlib
import math
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

# (name, signature, min-trailing-bytes-to-believe-it). Kept compact and neutral on purpose.
_MAGICS = [
    ("pe", b"MZ", 0x40),
    ("elf", b"\x7fELF", 16),
    ("macho64", b"\xcf\xfa\xed\xfe", 16),
    ("macho32", b"\xce\xfa\xed\xfe", 16),
    ("macho_fat", b"\xca\xfe\xba\xbe", 16),
    ("zip", b"PK\x03\x04", 16),
    ("gzip", b"\x1f\x8b\x08", 8),
    ("xz", b"\xfd7zXZ\x00", 8),
    ("zstd", b"\x28\xb5\x2f\xfd", 8),
    ("bzip2", b"BZh", 8),
    ("pdf", b"%PDF-", 8),
    ("png", b"\x89PNG\r\n\x1a\n", 16),
    ("sqlite", b"SQLite format 3\x00", 16),
    ("rar", b"Rar!\x1a\x07", 8),
    ("cab", b"MSCF", 8),
    ("7z", b"7z\xbc\xaf\x27\x1c", 8),
    # compressed containers (decompress.py decodes them; header fields validated in _find_magics)
    ("lz4", b"\x04\x22\x4d\x18", 3),          # LZ4 frame: FLG, BD, header checksum
    ("lz4_legacy", b"\x02\x21\x4c\x18", 4),   # legacy LZ4 frame: first block size
    ("aplib", b"AP32", 20),                      # aPLib aPsafe header
    ("brieflz", b"blz\x1a", 20),                # BriefLZ blzpack block header
]
_CONTAINERS = {"lz4", "lz4_legacy", "aplib", "brieflz"}

_B64_RUN = re.compile(rb"[A-Za-z0-9+/]{40,}={0,2}")
_WIN = 512          # entropy window (small windows undershoot Shannon on random data)
_STEP = 256         # entropy window stride
_ENT_HI = 7.2       # bits/byte: packed/encrypted (a 512B random window sits ~7.6)
_MIN_BLOB = 1024    # smallest high-entropy region worth reporting
_MAX_HITS = 256     # per-kind cap on magic hits (a crafted run of PK\x03\x04 gave 200k entries)

# Mach-O host headers (thin, both byte orders) and universal ("fat") headers. The fat magic is
# shared with Java class files; a fat header's nfat_arch is small, a class file's version is >= 45.
_MACHO_THIN = (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce")
_MACHO_FAT = (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf")     # fat_header / fat_header_64 (BE)


def _entropy(b: bytes) -> float:
    if not b:
        return 0.0
    counts = [0] * 256
    for x in b:
        counts[x] += 1
    n = len(b)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def _find_magics(data: bytes, self_skip=0, exclude=()):
    """Magic-byte hits, excluding offset 0 if it is the host's own header (self_skip bytes) and any
    offset in `exclude` (the host's own structure, e.g. a fat Mach-O's slices). At most _MAX_HITS
    per kind; _find_magics_capped also says which kinds hit the cap."""
    return _find_magics_capped(data, self_skip, exclude)[0]


def _find_magics_capped(data: bytes, self_skip=0, exclude=()):
    """(hits, capped_kinds): _find_magics plus the kinds whose hit count reached _MAX_HITS (so a
    flood of one signature is reported as truncated rather than as an exact count)."""
    out = []
    capped = []
    exclude = set(exclude)
    for name, sig, need in _MAGICS:
        start = 0
        n = 0
        while True:
            i = data.find(sig, start)
            if i < 0:
                break
            start = i + 1
            if i < self_skip or i in exclude:    # the file's own header/structure, not embedded
                continue
            if i + len(sig) + need > len(data):
                continue
            if name == "pe":      # "MZ" is only 2 bytes: confirm the DOS stub points at a PE header
                e_lfanew = int.from_bytes(data[i + 0x3c:i + 0x40], "little") if i + 0x40 <= len(data) else 0
                if not (0 < e_lfanew < len(data) - i - 4 and data[i + e_lfanew:i + e_lfanew + 4] == b"PE\x00\x00"):
                    continue
            if name == "elf":     # validate e_ident class/data/version to drop coincidental \x7fELF
                cls, dat, ver = data[i + 4], data[i + 5], data[i + 6]
                if cls not in (1, 2) or dat not in (1, 2) or ver != 1:
                    continue
            if name in _CONTAINERS:   # a bare 4-byte magic (e.g. an LZ4 constant in code) is not a
                import decompress     # container: its header fields must be well formed
                if not decompress.header_ok(name, data, i):
                    continue
            if n >= _MAX_HITS:
                capped.append(name)
                break
            out.append({"kind": name, "offset": i})
            n += 1
    return out, capped


def _host_layout(data: bytes):
    """(self_skip, exclude): how much of offset 0 is the host's own header, and the offsets of the
    host's own nested headers (a fat Mach-O's per-architecture slices), so neither is reported as an
    embedded artifact. PE (DOS header), ELF, thin Mach-O (either byte order) and fat Mach-O."""
    head = data[:4]
    if head[:2] == b"MZ":
        return 0x40, ()
    if head == b"\x7fELF" or head in _MACHO_THIN:
        return 4, ()
    if head in _MACHO_FAT and len(data) >= 8:
        nfat = int.from_bytes(data[4:8], "big")
        if 0 < nfat < 45:                # else a Java class file (major version >= 45), not fat
            wide = head == _MACHO_FAT[1]
            esz, ooff, osz = (32, 8, 8) if wide else (20, 8, 4)
            slices = []
            for k in range(min(nfat, 64)):
                e = 8 + k * esz
                if e + esz > len(data):
                    break
                slices.append(int.from_bytes(data[e + ooff:e + ooff + osz], "big"))
            return 4, tuple(slices)
    return 0, ()


def _high_entropy_regions(data: bytes):
    """Coalesce sliding windows whose entropy exceeds the threshold into contiguous blobs."""
    hot = []
    if len(data) < _WIN:
        return []                        # smaller than one window (and than _MIN_BLOB)
    offs = list(range(0, len(data) - _WIN + 1, _STEP))
    if offs[-1] != len(data) - _WIN:
        offs.append(len(data) - _WIN)    # a final window flush with EOF: an overlay blob at the
    for off in offs:                     # end must be carved whole, not cut at the last stride
        if _entropy(data[off:off + _WIN]) >= _ENT_HI:
            hot.append((off, off + _WIN))
    if not hot:
        return []
    merged = [list(hot[0])]
    for lo, hi in hot[1:]:
        if lo <= merged[-1][1]:
            merged[-1][1] = hi
        else:
            merged.append([lo, hi])
    out = []
    for lo, hi in merged:
        hi = min(hi, len(data))
        if hi - lo < _MIN_BLOB:
            continue
        blob = data[lo:hi]
        out.append({"offset": lo, "size": hi - lo, "entropy": round(_entropy(blob), 2),
                    "sha256": hashlib.sha256(blob).hexdigest()})
    return out


def _base64_runs(data: bytes, limit=32):
    """Long base64 runs that decode cleanly to non-trivial bytes (skip ASCII-looking decodes:
    those are usually ordinary text that merely matches the charset)."""
    out = []
    for m in _B64_RUN.finditer(data):
        tok = m.group()
        r = len(tok) % 4
        # a run glued to identifier characters (`key` + payload, or payload + `End`) is not a
        # multiple of 4 long: try the 4-aligned suffix (glued head) and, for an unpadded run, the
        # 4-aligned prefix (glued tail). Which side was glued is a guess, so it is reported.
        if not r:
            cands = [(0, tok, None)]
        else:
            cands = [(r, tok[r:], "head")]
            if not tok.endswith(b"="):
                cands.append((0, tok[:-r], "tail"))
        for skip, t, trimmed in cands:
            dec = _b64_payload(t)
            if dec is None:
                continue
            ent = _entropy(dec)
            rec = {"offset": m.start() + skip, "b64_len": len(t), "decoded_len": len(dec),
                   "decoded_entropy": round(ent, 2),
                   "decoded_sha256": hashlib.sha256(dec).hexdigest()}
            if trimmed:
                rec["trimmed"] = trimmed
            out.append(rec)
            break
        if len(out) >= limit:
            break
    return out


def _wordlike(tok: bytes) -> bool:
    """True when a base64-charset run reads as identifiers (CamelCase words, mangled C++/Rust
    names, concatenated enum-variant names) rather than encoded bytes. Base64 of binary data draws
    each character ~independently from 26 lower / 26 upper / 10 digit / 2 symbol, so the character
    CLASS changes between neighbours with probability q = 1 - sum(p^2) ~= 0.645. Words keep the
    class for runs of letters/digits, giving far fewer changes. Reject at z < -3 under a binomial
    model: on a corpus of real ELF binaries this drops 99.7% of the charset-matching identifier runs
    that also decode to "binary-looking" bytes, at a ~0.3% loss on random 64-char payloads (less
    for longer ones). Without it, trimming glued runs to 4-aligned length quadrupled those FPs."""
    t = tok.rstrip(b"=")
    n = len(t) - 1
    if n < 1:
        return False

    def cls(c):
        return 0 if 97 <= c <= 122 else 1 if 65 <= c <= 90 else 2 if 48 <= c <= 57 else 3
    changes = sum(1 for a, b in zip(t, t[1:]) if cls(a) != cls(b))
    q = 0.645
    return (changes - n * q) / math.sqrt(n * q * (1 - q)) < -3.0


def _b64_payload(tok: bytes):
    """Decoded bytes of a base64 token if it decodes cleanly to a non-trivial binary payload."""
    if len(tok) < 4 or len(tok) % 4:
        return None
    try:
        dec = base64.b64decode(tok, validate=True)
    except Exception:
        return None
    if len(dec) < 48:
        return None
    if _wordlike(tok):
        return None
    # require a genuinely binary decode: symbol/identifier runs on a real binary match the
    # charset but decode to low-entropy ASCII, so gate on entropy AND control bytes.
    if not (_entropy(dec) >= 5.5 and any(b < 9 or (13 < b < 32) for b in dec)):
        return None
    return dec


def recover(path) -> dict:
    """Scan `path` for embedded executables/archives, high-entropy blobs, and base64 payloads.

    File offsets throughout (not VAs): this is a byte-level carve over the raw file, so the results
    feed a carver/`dd` directly. Returns {embedded, high_entropy, base64, counts}.
    """
    data = Path(path).read_bytes()
    # the host's own header (and a fat Mach-O's own slices) are not embedded artifacts
    self_skip, exclude = _host_layout(data)
    embedded, capped = _find_magics_capped(data, self_skip, exclude)
    hi = _high_entropy_regions(data)
    b64 = _base64_runs(data)
    res = {
        "file_size": len(data),
        "embedded": embedded,
        "high_entropy": hi,
        "base64": b64,
        "counts": {"embedded": len(embedded), "high_entropy": len(hi), "base64": len(b64)},
    }
    if capped:
        res["embedded_capped"] = {"kinds": capped, "max_per_kind": _MAX_HITS}
    return res


def _print(res):
    print(f"file_size={res['file_size']}  embedded={res['counts']['embedded']}  "
          f"high_entropy_blobs={res['counts']['high_entropy']}  base64_payloads={res['counts']['base64']}")
    if res.get("embedded_capped"):
        cap = res["embedded_capped"]
        print(f"  (embedded hits capped at {cap['max_per_kind']} per kind for: {', '.join(cap['kinds'])})")
    for e in res["embedded"]:
        print(f"  [embedded] {e['kind']:8} @ file offset 0x{e['offset']:x}")
    for h in res["high_entropy"]:
        print(f"  [entropy ] 0x{h['offset']:x} size={h['size']} H={h['entropy']} "
              f"sha256={h['sha256'][:16]}")
    for b in res["base64"]:
        print(f"  [base64  ] @0x{b['offset']:x} {b['b64_len']}ch -> {b['decoded_len']}B "
              f"H={b['decoded_entropy']} sha256={b['decoded_sha256'][:16]}")


def _selftest():
    # a synthetic data section: an embedded ELF header, a high-entropy blob, and a base64 payload.
    import random
    rng = random.Random(0x5eed)                        # deterministic: the selftest must not flake
    blob = rng.randbytes(4096)                         # high entropy (~7.9 over 4 KB)
    payload = rng.randbytes(128)                       # 128 random bytes decode at entropy ~6.7
    b64 = base64.b64encode(payload)
    buf = (b"HOST BINARY HEADER\x00" + b"\x00" * 64
           + b"\x7fELF" + b"\x02\x01\x01" + b"\x00" * 64            # embedded ELF
           + b"text config region, perfectly ordinary\n" * 4
           + blob
           + b"\n token: " + b64 + b" \n")
    res_embedded = _find_magics(buf, self_skip=0)
    assert any(e["kind"] == "elf" for e in res_embedded), "embedded ELF not found"
    hi = _high_entropy_regions(buf)
    assert hi and max(h["entropy"] for h in hi) > 7.5, "high-entropy blob not isolated"
    b = _base64_runs(buf)
    assert b and b[0]["decoded_len"] == 128, f"base64 payload not recovered: {b}"
    # precision: low-entropy ASCII text must NOT be flagged as a packed blob
    assert not _high_entropy_regions(b"the quick brown fox " * 200), "false high-entropy on plain text"
    assert abs(_entropy(bytes(range(256))) - 8.0) < 0.01, "entropy of a uniform byte range must be 8"
    # an overlay blob flush with EOF is carved to the end of the file, not cut at the last stride
    tail = b"\x00" * 4096 + rng.randbytes(1100)
    hot = _high_entropy_regions(tail)
    assert hot and hot[-1]["offset"] + hot[-1]["size"] == len(tail), hot
    print("selftest OK: embedded ELF, high-entropy blob and base64 payload recovered; "
          "plain text not misflagged")


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
