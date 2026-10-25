#!/usr/bin/env python3
"""Independent held-out evaluation of the string-deobfuscation engine.

The canary benchmark (bench_src/) uses five fixed strings that the engine's heuristics were
tuned against. This script measures generalisation the honest way: a *disjoint* set of secrets
the engine was never tuned on, run through the same real obfuscator crates (obfstr, litcrypt,
litcrypt2, cryptify) and the same custom XOR/ADD ciphers but with *fresh keys*, built into a
throwaway directory (the committed benchmark is left untouched), and scored by the current,
frozen engine. Nothing in the engine is changed after seeing these results -- misses are reported
as misses. That is the point of a held-out set.

The secrets are deliberately varied in shape (URLs, Windows/Unix paths, a registry key, IPs, a
GUID, base64-ish tokens, a very long and a very short string, mixed punctuation) so the result is
not an artefact of the benchmark's `canary::name::value` shape.

Usage:  python3 scripts/heldout_eval.py [--keep] [--time-budget N]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

# Held-out secrets -- disjoint from bench_src canaries/scatter, varied in structure and length.
SECRETS = [
    "https://api.meridian-sync.net/v2/ingest?tok=9ac41",   # URL with query
    "/var/lib/meridian/agent.sock",                        # unix socket path
    "C:\\Users\\Public\\Meridian\\cache\\sess.dat",        # windows path
    "SOFTWARE\\Meridian\\Telemetry\\v3",                   # registry key
    "198.51.100.23:9440",                                  # ip:port
    "b3f1a9d0-7c42-4e18-9a55-0cc1e2f67d84",                # GUID
    "sk_live_51MeridianQZx7Kp0294aBc",                     # api-key-shaped token
    "no",                                                  # very short
    "rotate-credentials-every-24h-and-purge-stale-sessions-on-restart",  # long, hyphen-rich
    "x-meridian-signature: v1=",                           # header fragment with punctuation
]

# A second, disjoint held-out set used to validate the structured-IOC recognition added after the
# first set exposed the recall gap (VALIDATION.md §17). New GUID / AWS / GitHub / Slack tokens and
# a long hyphenated id -- none seen by the engine when the recognisers were written -- so the 60/60
# recall it reports is generalisation, not a fit to the first set. Select with --set fresh.
FRESH_SECRETS = [
    "https://cdn.auroralink.io/beacon/ingest",
    "/etc/aurora/keyring.d/agent.key",
    "D:\\Aurora\\Spool\\queue\\outbound.tmp",
    "SYSTEM\\CurrentControlSet\\Services\\AuroraSvc",
    "203.0.113.77:8080",
    "7d2e5f01-aa93-4c6b-b1e0-9f3c82d14e6a",
    "AKIA2E4KQ7ZB9XYLMNOP",
    "ghp_Q7xK2pL9mN4rT8wZ1aB3cD5eF6gH0jK2lM4xY",
    "xoxb-209348-ZkQp0294aBcLmNoPqR",
    "aurora-session-rotate-interval-1800-seconds",
]

# litcrypt(v1) strips one char from each end of the literal's *source* when the literal is a raw
# string (a crate quirk the benchmark documents). None of our secrets need a raw string except
# the two with backslashes, so those two are written as raw strings and their litcrypt runtime
# value loses the outer quotes' neighbours. We score litcrypt against that true runtime value.
def _lit(c: str) -> str:
    esc = c.replace("\\", "\\\\").replace('"', '\\"')
    return f'r"{c}"' if "\\" in c else f'"{esc}"'


def _runtime_value(obf: str, c: str) -> str:
    if obf == "litcrypt" and "\\" in c:
        return '"' + c            # same quirk the benchmark's runtime_value() records
    return c


# Custom ciphers with FRESH keys (not the benchmark's), so the custom-decoder path is held out too.
_XOR_KEY = hashlib.sha256(b"heldout-xor-key-2026").digest()[:16]
_ADD_KEY = hashlib.sha256(b"heldout-add-key-2026").digest()[:16]


def _blob(data: bytes) -> str:
    return "[" + ",".join(str(b) for b in data) + "]"


def _xor_crate() -> tuple[str, str, list[str]]:
    decls = "\n".join(
        f"static ENC_{i}: [u8; {len(c.encode())}] = {_blob(bytes(b ^ _XOR_KEY[k % 16] for k, b in enumerate(c.encode())))};"
        for i, c in enumerate(SECRETS))
    header = (f"static XK: [u8; 16] = {_blob(_XOR_KEY)};\n{decls}\n"
              "#[inline(never)]\nfn dex(e: &[u8]) -> String {\n"
              "    let mut o = Vec::with_capacity(e.len());\n"
              "    for (i, b) in e.iter().enumerate() { o.push(b ^ XK[i % 16]); }\n"
              "    String::from_utf8_lossy(&o).into_owned()\n}")
    body = "fn main() {\n" + "\n".join(f'    println!("{{}}", dex(&ENC_{i}));' for i in range(len(SECRETS))) + "\n}"
    return header, body, []


def _add_crate() -> tuple[str, str, list[str]]:
    # cipher = plain + key ; decode = cipher - key
    decls = "\n".join(
        f"static ENC_{i}: [u8; {len(c.encode())}] = {_blob(bytes((b + _ADD_KEY[k % 16]) & 0xff for k, b in enumerate(c.encode())))};"
        for i, c in enumerate(SECRETS))
    header = (f"static DK: [u8; 16] = {_blob(_ADD_KEY)};\n{decls}\n"
              "#[inline(never)]\nfn dec(e: &[u8]) -> String {\n"
              "    let mut o = Vec::with_capacity(e.len());\n"
              "    for (i, b) in e.iter().enumerate() { o.push(b.wrapping_sub(DK[i % 16])); }\n"
              "    String::from_utf8_lossy(&o).into_owned()\n}")
    body = "fn main() {\n" + "\n".join(f'    println!("{{}}", dec(&ENC_{i}));' for i in range(len(SECRETS))) + "\n}"
    return header, body, []


def _macro_crate(wrap, header: str, deps: list[str]) -> tuple[str, str, list[str]]:
    body = "fn main() {\n" + "\n".join(f'    println!("{{}}", {wrap(c)});' for c in SECRETS) + "\n}"
    return header, body, deps


# obf name -> (header, body, cargo deps, build env)
def _variants() -> dict:
    v = {}
    v["xor_custom"] = (*_xor_crate(), None)
    v["add_custom"] = (*_add_crate(), None)
    v["obfstr"] = (*_macro_crate(lambda c: f"obfstr::obfstr!({_lit(c)})", "use obfstr::obfstr;",
                                 ['obfstr = "0.4"']), None)
    v["litcrypt"] = (*_macro_crate(lambda c: f"lc!({_lit(c)})",
                                   "#[macro_use]\nextern crate litcrypt;\nuse_litcrypt!();",
                                   ['litcrypt = "0.4"']),
                     ("LITCRYPT_ENCRYPT_KEY", "heldout-fixed-key"))
    v["litcrypt2"] = (*_macro_crate(lambda c: f"lc!({_lit(c)})",
                                    "extern crate alloc;\n#[macro_use]\nextern crate litcrypt2;\nuse_litcrypt!();",
                                    ['litcrypt2 = "0.1"']),
                      ("LITCRYPT_ENCRYPT_KEY", "heldout-fixed-key-2"))
    v["cryptify"] = (*_macro_crate(lambda c: f"cryptify::encrypt_string!({_lit(c)})", "",
                                   ['cryptify = "3"']), None)
    return v


def _write(name: str, header: str, body: str, deps: list[str], root: Path) -> Path:
    d = root / name
    (d / "src").mkdir(parents=True, exist_ok=True)
    cargo = ['[package]', f'name = "{name}"', 'version = "0.1.0"', 'edition = "2021"', "",
             "[dependencies]", *deps, "", "[profile.release]", "strip = false", "opt-level = 3"]
    (d / "Cargo.toml").write_text("\n".join(cargo) + "\n")
    src = (header + "\n\n" + body + "\n") if header else (body + "\n")
    (d / "src" / "main.rs").write_text(src)
    return d


def _build(d: Path, env_kv) -> Path | None:
    env = dict(os.environ)
    if env_kv:
        env[env_kv[0]] = env_kv[1]
    r = subprocess.run(["cargo", "build", "--release"], cwd=d, capture_output=True, text=True, env=env)
    out = d / "target" / "release" / d.name
    if out.is_file():
        return out
    sys.stderr.write(f"[build failed] {d.name}:\n{r.stderr[-800:]}\n")
    return None


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", action="store_true", help="keep the temp build dir")
    ap.add_argument("--time-budget", type=int, default=90)
    ap.add_argument("--set", choices=("heldout", "fresh"), default="heldout",
                    help="which held-out set: 'heldout' (§16) or 'fresh' (§17 validation set)")
    args = ap.parse_args(argv)

    global SECRETS
    if args.set == "fresh":
        SECRETS = FRESH_SECRETS

    import recover

    root = Path(tempfile.mkdtemp(prefix="heldout-"))
    print(f"held-out eval: {len(SECRETS)} secrets x {len(_variants())} obfuscators")
    print(f"build dir: {root}\n")
    rows, total_hits, total_possible, all_fps = [], 0, 0, 0
    for name, (header, body, deps, env_kv) in _variants().items():
        d = _write(name, header, body, deps, root)
        t0 = time.monotonic()
        binp = _build(d, env_kv)
        if binp is None:
            rows.append((name, "BUILD FAILED", "", ""))
            continue
        res = recover.run(binp, emulate="always", stackstrings=True, min_len=2,
                          literals=False, time_budget=args.time_budget)
        decoded = [x["string"] for x in res["decoded"]]
        expected = [_runtime_value(name, c) for c in SECRETS]
        hits = [s for s in expected if any(s in dstr for dstr in decoded)]
        # a decoded string is "explained" if it is contained in some expected secret (full or a
        # partial decode of one); anything else is a false positive the engine invented.
        fps = [dstr for dstr in decoded if not any(dstr in e or e in dstr for e in expected)]
        total_hits += len(hits)
        total_possible += len(expected)
        all_fps += len(fps)
        rows.append((name, f"{len(hits)}/{len(expected)}", f"{len(fps)} FP",
                     f"{time.monotonic() - t0:.0f}s"))
        miss = [e for e in expected if e not in hits]
        if miss:
            rows.append(("", "  missed:", ", ".join(repr(m) for m in miss)[:140], ""))
        if fps:
            rows.append(("", "  false+:", ", ".join(repr(f) for f in fps[:6])[:140], ""))

    print(f"{'obfuscator':16} {'recall':10} {'precision':24} time")
    print("-" * 62)
    for name, a, b, c in rows:
        print(f"{name:16} {a:10} {b:24} {c}")
    print("-" * 62)
    prec = f"{100 * (total_hits) / max(total_hits + all_fps, 1):.0f}%" if (total_hits + all_fps) else "n/a"
    print(f"TOTAL recall {total_hits}/{total_possible}  |  false positives {all_fps}  |  "
          f"precision {prec} (recovered / (recovered + FP))")

    if args.keep:
        print(f"\nkept: {root}")
    else:
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    main()
