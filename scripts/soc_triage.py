#!/usr/bin/env python3
"""soc_triage.py - a one-screen triage card for a SOC analyst, from one binary.

Wraps the recovery pipeline into the answer an analyst actually needs in the first minute:
is this Rust, what can it do, and what are the indicators to pivot on -- without reading a wall
of strings. It runs recover_rust_meta (static: toolchain, panic sites, crate/capability
fingerprint) and recover.run (decoded strings + indicator tags), then prints a compact card and,
with --json, a machine record for a SIEM/case system. STATIC + EMULATION ONLY; never executes the
sample.

Speed knobs: --fast skips everything that decodes (static call-site recovery, stack strings,
emulation and the code-virtualization scan) and keeps only metadata + literal indicators. It still
splits the Rust literals, which scales with binary size (measured: 0.6 s on a 0.4 MB canary, 6 s on
rg 5 MB, 19 s on rustup 20 MB, 100 s on uv 66 MB). Because it cannot see obfuscation, a --fast
card's signal is always LOW-with-a-caveat. Otherwise emulation runs under --time-budget (default 60s, lower than
the deep default so triage stays quick).

    python3 scripts/soc_triage.py <binary> [--fast] [--time-budget N] [--json] [--fail-on LEVEL]

Exit codes: 0 card produced (and below --fail-on), 1 signal at or above --fail-on, 2 usage error,
3 unsupported / unparseable input (not an ELF/PE/Mach-O LIEF can read), 4 analysis error (the card
is still printed when only one recovery engine failed; it says which).

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
    r"^/sys/|rustlib|/\.rustup/|^/dev/u?random$", re.I)


def _benign_indicator(s: str) -> bool:
    return bool(_BENIGN_RE.search(s))

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

# Crate/capability buckets that matter most for a first-pass malware read. Every bucket is shown in
# the capability fingerprint, but most of these crates are in ordinary Rust software too (tokio/hyper
# and rustls/ring are the standard HTTP+TLS stack, base64/sha2 are everywhere, windows-sys is how any
# Rust program talks to Windows). So only the narrower "scored" subset of each bucket adds to the
# triage signal, and only once the binary shows obfuscation evidence (see triage()).
_CAP_INTEREST = {
    "network": ("c2 / networking", ("reqwest", "hyper", "tokio", "ureq", "socket2", "trust-dns",
                                    "tungstenite", "tonic", "quinn", "curl", "isahc")),
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
# crates that add to the score (exact crate names, not substrings): the bulk-encryption / raw-socket /
# registry / self-replacing ones, not the ubiquitous HTTP, TLS, hashing or OS-binding stacks
_SCORED = {
    "c2 / networking": {"tungstenite", "tokio-tungstenite", "quinn", "trust-dns-resolver",
                        "hickory-resolver", "socket2"},
    "encryption": {"aes", "aes-gcm", "chacha20", "chacha20poly1305", "rsa", "cbc", "cfb-mode",
                   "des", "blowfish", "block-modes", "salsa20", "rc4"},
    "persistence / exec": {"winreg", "ntapi", "self-replace", "windows-service"},
}


# Crates that legitimately embed a bytecode interpreter / threaded-dispatch engine. detect_vm flags
# their dispatch loops as virtualization-shaped -- correctly, they ARE interpreters (rg's regex
# engines: 16 hits) -- so when one is linked, VM-shaped functions are reported but not counted as
# obfuscation evidence (a VM-protected sample still shows its decoded strings).
_INTERPRETER_CRATES = {"regex-automata", "regex", "fancy-regex", "pcre2", "onig", "wasmi", "wasmtime",
                       "wasmer", "cranelift-codegen", "rhai", "mlua", "rlua", "pyo3", "boa-engine",
                       "deno-core", "v8", "rustpython-vm", "gluon", "dyon", "rune", "koto"}
# Obfuscation evidence, calibrated on benign Rust tools (rustup, uv, rg) run through the full
# pipeline:
#  * decoded strings: the emulation engine reports a few false positives on big benign binaries
#    (rustup: a tempfile name '/tmp/rustup-update' + random suffix, one junk string; rg: a help-text
#    line). A decoded string that is mostly a plain literal of the same binary (a literal covering at
#    least half of it) was formatted from visible text, not hidden. Of the rest, one carrying a strong
#    indicator tag counts, or _MIN_HIDDEN of any kind.
#  * stack strings: benign code builds strings on the stack all the time (std's /proc/self/exe,
#    SipHash's "somepseudorandomlygeneratedbytes" constant, short UI words), so only stack-built
#    strings with a strong indicator tag count.
_STRONG_TAGS = {"url", "domain", "ip", "registry", "mutex", "token", "email"}
_MIN_HIDDEN = 3
_LITERAL_MIN = 6


def _explained_by_literals(s: str, literals: list[str]) -> bool:
    need = max(_LITERAL_MIN, (len(s) + 1) // 2)
    return any(len(lit) >= need and lit in s for lit in literals)


def _strong(strings, tagged: dict) -> list[str]:
    ss = set(strings)
    return sorted({x for t in _STRONG_TAGS for x in tagged.get(t, ()) if x in ss})


# Crate source paths embedded in panic locations: ~/.cargo/registry/src/<index>/<crate>-<ver>/ and
# distro builds' /usr/share/cargo/registry/<crate>-<ver>/ (Debian/Ubuntu), plus vendored trees.
# recover_rust_meta reports the former; this also catches the distro layout it misses (Debian's rg).
_CRATE_PATH = re.compile(r"[/\\](?:registry|vendor)[/\\](?:src[/\\][^/\\]+[/\\])?"
                         r"([A-Za-z][A-Za-z0-9_\-]*?)-(\d+\.\d+\.\d+)[^/\\]*[/\\]")


def _crates_from_paths(strings) -> set[str]:
    return {m.group(1) for s in strings for m in _CRATE_PATH.finditer(s)}


def _crate_match(crate: str, names) -> bool:
    """A crate belongs to a bucket when its name is one of the bucket names or a dashed/underscored
    extension of one (aes -> aes-gcm, windows -> windows-sys), not on any substring (so 'tar' does not
    match 'tracing-subscriber' and 'des' does not match 'serde_derive')."""
    c = crate.lower().replace("_", "-")
    return any(c == n or c.startswith(n + "-") for n in names)

_TAG_LABEL = {"url": "URLs", "domain": "domains", "ip": "IPs", "path": "paths",
              "registry": "registry keys", "mutex": "mutex/objects", "email": "emails",
              "guid": "GUIDs", "token": "credential tokens"}


def _sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class UnsupportedInput(Exception):
    """The file is not a binary LIEF can parse (ELF/PE/Mach-O)."""


def triage(path: Path, fast: bool, time_budget: float) -> dict:
    import recover
    import recover_rust_meta

    t0 = time.monotonic()
    fmt, arch, imagebase = recover.detect(path)
    if fmt is None:
        raise UnsupportedInput(f"{path}: not an ELF/PE/Mach-O binary LIEF can parse")
    meta = {}
    try:
        meta = recover_rust_meta.recover(path)
    except Exception as e:
        meta = {"error": str(e)}
    if not isinstance(meta, dict):
        meta = {}

    # --fast: no decoding at all (no static call-site recovery, stack strings, emulation)
    res = recover.run(path, emulate=("never" if fast else "always"), stackstrings=not fast,
                      min_len=5, literals=True, time_budget=time_budget, libfuncs=False,
                      static=not fast)

    # Indicators, grouped by kind, de-duplicated. Only strings the binary had to BUILD at run time
    # (decoded by a decoder, assembled on the stack) are evidence of hiding; the same shapes in plain
    # literals are what every networked program carries (rustup's update URL, uv's index URL), so
    # those are reported separately as literal_indicators and never scored.
    from recover_callsite import ioc_tags

    def _group(records, skip=()):
        out: dict[str, list[str]] = {}
        seen = set()
        for x in records:
            s = x["string"] if isinstance(x, dict) else x
            if s in seen or s in skip or _benign_indicator(s):
                continue
            seen.add(s)
            tags = x.get("tags") if isinstance(x, dict) and "tags" in x else ioc_tags(s)
            for t in tags or ():
                out.setdefault(t, [])
                if s not in out[t]:
                    out[t].append(s)
        return out

    built = res["decoded"] + res["stack"]
    iocs = _group(built)
    lit_iocs = _group(res.get("literals", []), skip={x["string"] for x in built})

    crates = set((meta.get("crates") or {}).keys())
    crates |= _crates_from_paths(x["string"] for x in res.get("literals", []))
    hits = {}
    for key, (label, names) in _CAP_INTEREST.items():
        found = sorted(c for c in crates if _crate_match(c, names))
        if found:
            hits[label] = found
    scored_hits = {label: sorted(c for c in crates if c.lower().replace("_", "-") in names)
                   for label, names in _SCORED.items()}

    decoded = [x["string"] for x in res["decoded"]]
    # std's own stack-built paths (backtrace's /proc/self/exe, /usr/lib/debug) are in every Rust
    # binary; they are not obfuscation
    stack = [x["string"] for x in res["stack"] if not _benign_indicator(x["string"])]
    is_rust = bool(meta.get("is_rust"))

    # code virtualization (bytecode-VM obfuscation): a strong "this is protected" signal. Not in
    # --fast: the scan disassembles the whole .text (seconds to tens of seconds on a big binary).
    vm = {"count": 0, "functions": []}
    if not fast:
        try:
            import detect_vm
            vm = detect_vm.detect(path)
        except Exception:
            pass
    n_vm = vm.get("count", 0)

    # Calibrated triage signal (NOT a verdict). Obfuscation evidence -- strings the binary decodes or
    # assembles at run time, or virtualized functions -- is REQUIRED for anything above LOW: crates and
    # literal URLs alone describe half of all Rust CLI tools. Given obfuscation, what the hidden
    # strings are (C2-shaped, registry/mutex, credential tokens) and the narrow offensive crate set
    # raise it to HIGH.
    score = 0
    reasons = []
    interp = sorted(c for c in crates if c.lower().replace("_", "-") in _INTERPRETER_CRATES)
    vm_counts = bool(n_vm) and not interp
    lit_strings = [x["string"] for x in res.get("literals", []) if len(x["string"]) >= _LITERAL_MIN]
    hidden = [d for d in decoded if not _explained_by_literals(d, lit_strings)]
    dec_strong, stack_strong = _strong(hidden, iocs), _strong(stack, iocs)
    dec_counts = bool(dec_strong) or len(hidden) >= _MIN_HIDDEN
    obfuscated = dec_counts or bool(stack_strong) or vm_counts
    if decoded:
        why = "" if dec_counts else (
            f" (not scored: {len(decoded) - len(hidden)} formatted from plain literals, "
            f"{len(hidden)} without an indicator shape, below the false-positive floor)")
        reasons.append(f"{len(decoded)} obfuscated/decoded strings{why}")
    if stack:
        reasons.append(f"{len(stack)} stack-built strings" + (
            f" ({len(stack_strong)} indicator-shaped)" if stack_strong else
            " (not scored: none indicator-shaped; benign code builds strings on the stack too)"))
    if n_vm:
        reasons.append(f"{n_vm} virtualized function(s) (code virtualization)" if vm_counts else
                       f"{n_vm} virtualization-shaped function(s), not scored: the binary embeds an "
                       f"interpreter crate ({', '.join(interp[:3])})")
    # only strings that survived the evidence filters above say what is hidden
    scored = set(hidden) | set(stack)

    def hidden_tag(*tags):
        return any(x in scored for t in tags for x in iocs.get(t, ()))
    if obfuscated:
        score += 3
    if hidden_tag("url", "domain", "ip"):
        score += 2; reasons.append("network indicators hidden in decoded/stack strings (C2-shaped)")
    if hidden_tag("registry", "mutex"):
        score += 1; reasons.append("hidden registry/mutex indicators")
    if hidden_tag("token"):
        score += 1; reasons.append("hidden credential tokens")
    for label, found in scored_hits.items():
        if found:
            reasons.append(f"{label} crates ({', '.join(found[:4])})"
                           + ("" if obfuscated else " (not scored without obfuscation evidence)"))
            if obfuscated:
                score += 1
    if not obfuscated:
        signal = "LOW"
        reasons.append("no obfuscation evidence" + (" (--fast: decoding skipped, signal capped at LOW)"
                                                    if fast else ""))
    else:
        signal = "HIGH" if score >= 5 else "MEDIUM"

    rustc = meta.get("rustc_commit")
    return {
        "file": str(path), "sha256": _sha256(path), "size": path.stat().st_size,
        "format": fmt, "arch": arch, "is_rust": is_rust,
        "rustc_commit": rustc if isinstance(rustc, str) else None,
        "rust_release": (meta.get("rust_release") or {}).get("version"),
        "panic_sites": (meta.get("counts") or {}).get("panic_sites"),
        "capabilities": hits,
        "indicators": iocs,
        "literal_indicators": lit_iocs,
        "decoded_sample": decoded[:10],
        "decoded_total": len(decoded),
        "stack_total": len(stack),
        "virtualized_functions": n_vm,
        "virtualization_scored": vm_counts,
        "triage_signal": signal, "signal_reasons": reasons,
        "mode": "static (fast: metadata + literals, no decoding)" if fast
                else "static+emulation (not executed)",
        "notes": list(res.get("notes", [])),
        "engine_errors": list(res.get("errors", [])),
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
    if c["is_rust"]:
        bits = [f"rustc {c['rustc_commit'][:12]}" if c.get("rustc_commit") else "rustc commit unknown"]
        if c.get("rust_release"):
            bits.append(str(c["rust_release"]))
        rust = f"yes ({', '.join(bits)})"
    else:
        rust = "no"
    print(f" rust     : {rust}" + (f"   panic-sites: {c['panic_sites']}" if c.get('panic_sites') else ""))
    if c["capabilities"]:
        print(" capability fingerprint:")
        for label, names in c["capabilities"].items():
            print(f"   - {label}: {', '.join(names[:8])}")
    for key, title in (("indicators", "hidden indicators (decoded / stack-built)"),
                       ("literal_indicators", "literal indicators (plain strings, not scored)")):
        group = c.get(key) or {}
        if any(group.values()):
            print(f" {title}:")
            for tag, label in _TAG_LABEL.items():
                vals = group.get(tag)
                if vals:
                    print(f"   [{tag}] {label}:")
                    for v in vals[:8]:
                        print(f"       {v[:72]}")
        else:
            print(f" {title}: none surfaced")
    if c.get("virtualized_functions"):
        if c.get("virtualization_scored", True):
            print(f" virtualization: {c['virtualized_functions']} function(s) look VM-protected "
                  "(code virtualization) -- detection only, run detect_vm.py for details")
        else:
            print(f" virtualization: {c['virtualized_functions']} virtualization-shaped function(s), "
                  "likely the linked interpreter crate's own dispatch loops (not scored)")
    if c["decoded_sample"]:
        print(f" decoded strings ({c['decoded_total']} total, first {min(10, c['decoded_total'])}):")
        for s in c["decoded_sample"]:
            print(f"   . {s[:72]}")
    for e in c.get("engine_errors") or []:
        print(f" WARNING  : {e['engine']} failed ({e['error'][:60]}); the signal may be incomplete")
    print(f" signal   : {c['triage_signal']}" + (f"  ({'; '.join(c['signal_reasons'])})" if c['signal_reasons'] else ""))
    print(f"          : triage aid, not a verdict -- analyst confirms")
    print(line)


_LEVELS = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
EXIT_OK, EXIT_FAIL_ON, EXIT_USAGE, EXIT_UNSUPPORTED, EXIT_ERROR = 0, 1, 2, 3, 4


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("binary")
    ap.add_argument("--fast", action="store_true",
                    help="no decoding: metadata + literal indicators only (time grows with binary size); "
                         "signal capped at LOW")
    ap.add_argument("--time-budget", type=float, default=60.0, help="emulation budget in seconds (default 60)")
    ap.add_argument("--json", action="store_true", help="emit the triage record as JSON (for a SIEM/case system)")
    ap.add_argument("--fail-on", choices=("MEDIUM", "HIGH"),
                    help="exit 1 when the signal is at or above this level (for scripted gating)")
    a = ap.parse_args(argv)             # argparse exits 2 on a usage error
    path = Path(a.binary)
    if not path.is_file():
        ap.error(f"no such file: {path}")
    try:
        card = triage(path, a.fast, a.time_budget)
    except UnsupportedInput as e:
        print(f"soc_triage: unsupported input: {e}", file=sys.stderr)
        return EXIT_UNSUPPORTED
    except Exception as e:
        print(f"soc_triage: analysis error: {type(e).__name__}: {e}", file=sys.stderr)
        return EXIT_ERROR
    if a.json:
        print(json.dumps(card, indent=2))
    else:
        print_card(card)
    if a.fail_on and _LEVELS[card["triage_signal"]] >= _LEVELS[a.fail_on]:
        return EXIT_FAIL_ON
    if card.get("engine_errors"):        # the card was printed, but an engine raised
        return EXIT_ERROR
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
