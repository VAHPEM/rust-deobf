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
]

_B64_RUN = re.compile(rb"[A-Za-z0-9+/]{40,}={0,2}")
_WIN = 512          # entropy window (small windows undershoot Shannon on random data)
_STEP = 256         # entropy window stride
_ENT_HI = 7.2       # bits/byte: packed/encrypted (a 512B random window sits ~7.6)
_MIN_BLOB = 1024    # smallest high-entropy region worth reporting


def _entropy(b: bytes) -> float:
    if not b:
        return 0.0
    counts = [0] * 256
    for x in b:
        counts[x] += 1
    n = len(b)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def _find_magics(data: bytes, self_skip=0):
    """Magic-byte hits, excluding offset 0 if it is the host's own header (self_skip bytes)."""
    out = []
    for name, sig, need in _MAGICS:
        start = 0
        while True:
            i = data.find(sig, start)
            if i < 0:
                break
            start = i + 1
            if i < self_skip:            # the file's own header, not an embedded artifact
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
            out.append({"kind": name, "offset": i})
    return out


def _high_entropy_regions(data: bytes):
    """Coalesce sliding windows whose entropy exceeds the threshold into contiguous blobs."""
    hot = []
    for off in range(0, max(0, len(data) - _WIN), _STEP):
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
        if len(tok) % 4:
            continue
        try:
            dec = base64.b64decode(tok, validate=True)
        except Exception:
            continue
        if len(dec) < 48:
            continue
        ent = _entropy(dec)
        # require a genuinely binary decode: symbol/identifier runs on a real binary match the
        # charset but decode to low-entropy ASCII, so gate on entropy AND control bytes.
        if not (ent >= 5.5 and any(b < 9 or (13 < b < 32) for b in dec)):
            continue
        out.append({"offset": m.start(), "b64_len": len(tok), "decoded_len": len(dec),
                    "decoded_entropy": round(ent, 2),
                    "decoded_sha256": hashlib.sha256(dec).hexdigest()})
        if len(out) >= limit:
            break
    return out


def recover(path) -> dict:
    """Scan `path` for embedded executables/archives, high-entropy blobs, and base64 payloads.

    File offsets throughout (not VAs): this is a byte-level carve over the raw file, so the results
    feed a carver/`dd` directly. Returns {embedded, high_entropy, base64, counts}.
    """
    data = Path(path).read_bytes()
    # the host's own header occupies the first page; don't report it as an embedded artifact
    self_skip = 0x40 if data[:2] == b"MZ" else (4 if data[:4] == b"\x7fELF" else 0)
    embedded = _find_magics(data, self_skip)
    hi = _high_entropy_regions(data)
    b64 = _base64_runs(data)
    return {
        "file_size": len(data),
        "embedded": embedded,
        "high_entropy": hi,
        "base64": b64,
        "counts": {"embedded": len(embedded), "high_entropy": len(hi), "base64": len(b64)},
    }


def _print(res):
    print(f"file_size={res['file_size']}  embedded={res['counts']['embedded']}  "
          f"high_entropy_blobs={res['counts']['high_entropy']}  base64_payloads={res['counts']['base64']}")
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
    import os
    blob = os.urandom(4096)                           # high entropy (~7.9 over 4 KB)
    payload = os.urandom(128)                          # 128 random bytes decode at entropy ~6.7
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
