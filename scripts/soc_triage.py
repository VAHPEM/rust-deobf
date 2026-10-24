#!/usr/bin/env python3
"""soc_triage.py - a one-screen triage card for a SOC analyst, from one binary.

Wraps the recovery pipeline into the answer an analyst actually needs in the first minute:
is this Rust, what can it do, and what are the indicators to pivot on -- without reading a wall
of strings. It runs recover_rust_meta (static: toolchain, panic sites, crate/capability
fingerprint) and recover.run (decoded strings + indicator tags), then prints a compact card and,
with --json, a machine record for a SIEM/case system. STATIC + EMULATION ONLY; never executes the
sample.

Speed knobs: --fast skips emulation (sub-second, metadata + literals only); otherwise emulation
runs under --time-budget (default 60s, lower than the deep default so triage stays quick).

    python3 scripts/soc_triage.py <binary> [--fast] [--time-budget N] [--json]

The verdict line is a calibrated triage SIGNAL with its evidence, not a definitive malware verdict
-- an analyst makes the call.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from pathlib import Path

# Benign strings every Rust binary carries (compiler/std panic-location paths, debug paths). They
# match the "path" indicator shape but are noise in a triage card, so they are filtered out.
_BENIGN_RE = re.compile(
    r"/rustc/|/rust/deps/|\.cargo[/\\]registry|[/\\]library[/\\](std|core|alloc|backtrace|"
    r"portable-simd|panic_unwind|panic_abort|proc_macro)|/proc/self/|/usr/lib/debug|"
    r"^/sys/|rustlib|/\.rustup/", re.I)


def _benign_indicator(s: str) -> bool:
    return bool(_BENIGN_RE.search(s))

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

# Crate/capability buckets that matter most for a first-pass malware read.
_CAP_INTEREST = {
    "network": ("c2 / networking", ("reqwest", "hyper", "tokio", "ureq", "socket2", "trust-dns",
                                    "tungstenite", "tonic", "quinn", "curl", "isahc", "ureq")),
    "crypto": ("encryption", ("aes", "aes-gcm", "chacha20", "chacha20poly1305", "rsa", "cbc",
                              "cfb-mode", "cipher", "ring", "rustls", "sha2", "md5", "base64",
                              "des", "blowfish", "block-modes")),
    "sysinfo": ("host recon", ("sysinfo", "whoami", "machine-uid", "mac_address", "if-addrs",
                               "hostname", "os_info")),
    "persist": ("persistence / exec", ("windows", "windows-sys", "winreg", "ntapi", "registry",
                                       "launchd", "plist", "self-replace")),
    "exfil": ("staging / archive", ("zip", "flate2", "tar", "walkdir", "glob", "rusqlite",
                                    "keyring")),
}

_TAG_LABEL = {"url": "URLs", "domain": "domains", "ip": "IPs", "path": "paths",
              "registry": "registry keys", "mutex": "mutex/objects", "email": "emails",
              "guid": "GUIDs", "token": "credential tokens"}


def _sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def triage(path: Path, fast: bool, time_budget: float) -> dict:
    import recover
    import recover_rust_meta

    t0 = time.monotonic()
    fmt, arch, imagebase = recover.detect(path)
    meta = {}
    try:
        meta = recover_rust_meta.recover(path)
    except Exception as e:
        meta = {"error": str(e)}

    res = recover.run(path, emulate=("never" if fast else "always"), stackstrings=not fast,
                      min_len=5, literals=True, time_budget=time_budget, libfuncs=False)

    # indicators, grouped by kind, de-duplicated, from everything with a tag
    from recover_callsite import ioc_tags
    iocs: dict[str, list[str]] = {}
    seen = set()
    for x in res["decoded"] + res["stack"] + res.get("literals", []):
        s = x["string"] if isinstance(x, dict) else x
        if s in seen or _benign_indicator(s):
            continue
        seen.add(s)
        for t in (x.get("tags") if isinstance(x, dict) else None) or ioc_tags(s):
            iocs.setdefault(t, [])
            if s not in iocs[t]:
                iocs[t].append(s)

    caps = meta.get("capabilities", {}) if isinstance(meta, dict) else {}
    crates = set((meta.get("crates") or {}).keys()) if isinstance(meta, dict) else set()
    hits = {}
    for key, (label, names) in _CAP_INTEREST.items():
        found = sorted(c for c in crates if any(n in c.lower() for n in names))
        if found:
            hits[label] = found

    decoded = [x["string"] for x in res["decoded"]]
    n_ioc = sum(len(v) for v in iocs.values())
    is_rust = bool(meta.get("is_rust")) if isinstance(meta, dict) else False

    # calibrated triage signal (NOT a verdict): obfuscated strings + indicators + offensive crates
    score = 0
    reasons = []
    if decoded:
        score += 2; reasons.append(f"{len(decoded)} obfuscated/decoded strings")
    if iocs.get("url") or iocs.get("domain") or iocs.get("ip"):
        score += 2; reasons.append("network indicators (C2-shaped)")
    if hits.get("c2 / networking"):
        score += 1; reasons.append("networking crates")
    if hits.get("encryption"):
        score += 1; reasons.append("crypto crates")
    if iocs.get("registry") or iocs.get("mutex") or hits.get("persistence / exec"):
        score += 1; reasons.append("persistence/registry")
    if iocs.get("token"):
        score += 1; reasons.append("credential tokens")
    signal = "HIGH" if score >= 5 else "MEDIUM" if score >= 3 else "LOW"

    return {
        "file": str(path), "sha256": _sha256(path), "size": path.stat().st_size,
        "format": fmt, "arch": arch, "is_rust": is_rust,
        "rustc_commit": meta.get("rustc_commit") if isinstance(meta, dict) else None,
        "rust_release": (meta.get("rust_release") or {}).get("version") if isinstance(meta, dict) else None,
        "panic_sites": (meta.get("counts") or {}).get("panic_sites") if isinstance(meta, dict) else None,
        "capabilities": hits,
        "indicators": iocs,
        "decoded_sample": decoded[:10],
        "decoded_total": len(decoded),
        "triage_signal": signal, "signal_reasons": reasons,
        "mode": "static" if fast else "static+emulation (not executed)",
        "seconds": round(time.monotonic() - t0, 1),
    }


def print_card(c: dict) -> None:
    W = 78
    line = "=" * W
    print(line)
    print(f" SOC TRIAGE  |  signal: {c['triage_signal']}  |  {c['mode']}  |  {c['seconds']}s")
    print(line)
    print(f" file     : {Path(c['file']).name}  ({c['size']:,} bytes)")
    print(f" sha256   : {c['sha256']}")
    print(f" format   : {c['format']} / {c['arch']}")
    rust = f"yes (rustc {c['rustc_commit'][:12]}{', ' + c['rust_release'] if c['rust_release'] else ''})" if c["is_rust"] else "no"
    print(f" rust     : {rust}" + (f"   panic-sites: {c['panic_sites']}" if c['panic_sites'] else ""))
    if c["capabilities"]:
        print(" capability fingerprint:")
        for label, names in c["capabilities"].items():
            print(f"   - {label}: {', '.join(names[:8])}")
    if any(c["indicators"].values()):
        print(" indicators:")
        for tag, label in _TAG_LABEL.items():
            vals = c["indicators"].get(tag)
            if vals:
                print(f"   [{tag}] {label}:")
                for v in vals[:8]:
                    print(f"       {v[:72]}")
    else:
        print(" indicators: none surfaced")
    if c["decoded_sample"]:
        print(f" decoded strings ({c['decoded_total']} total, first {min(10, c['decoded_total'])}):")
        for s in c["decoded_sample"]:
            print(f"   . {s[:72]}")
    print(f" signal   : {c['triage_signal']}" + (f"  ({'; '.join(c['signal_reasons'])})" if c['signal_reasons'] else ""))
    print(f"          : triage aid, not a verdict -- analyst confirms")
    print(line)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("binary")
    ap.add_argument("--fast", action="store_true", help="skip emulation (metadata + literals only; sub-second)")
    ap.add_argument("--time-budget", type=float, default=60.0, help="emulation budget in seconds (default 60)")
    ap.add_argument("--json", action="store_true", help="emit the triage record as JSON (for a SIEM/case system)")
    a = ap.parse_args(argv)
    path = Path(a.binary)
    if not path.is_file():
        ap.error(f"no such file: {path}")
    card = triage(path, a.fast, a.time_budget)
    if a.json:
        print(json.dumps(card, indent=2))
    else:
        print_card(card)


if __name__ == "__main__":
    main()
