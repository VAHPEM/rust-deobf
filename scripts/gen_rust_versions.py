#!/usr/bin/env python3
"""gen_rust_versions.py - build the rustc commit -> Rust release table used by recover_rust_meta.

Every stable Rust release publishes a channel manifest at
`https://static.rust-lang.org/dist/channel-rust-<version>.toml` whose `[pkg.rustc]` entry records
the git commit the compiler was built from. Rust binaries embed that commit in panic paths
(`/rustc/<hash>/library/...`), so the table turns a recovered hash into "Rust 1.97.0 (2026-07-09)".

Manifests exist from Rust 1.8.0 on. Writes scripts/data/rust_versions.json:
    {"<full commit hash>": {"version": "1.97.0", "date": "2026-07-09"}, ...}

    python scripts/gen_rust_versions.py            # fetch every stable release (network)
    python scripts/gen_rust_versions.py --max-minor 120
"""
from __future__ import annotations
import argparse
import json
import re
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

OUT = Path(__file__).resolve().parent / "data" / "rust_versions.json"
URL = "https://static.rust-lang.org/dist/channel-rust-{}.toml"
RE_RUSTC = re.compile(r'\[pkg\.rustc\]\s*\nversion = "[^"]*"\s*\ngit_commit_hash = "([0-9a-f]{40})"', re.M)
RE_HASH = re.compile(r'^git_commit_hash = "([0-9a-f]{40})"', re.M)
RE_DATE = re.compile(r'^date = "([0-9-]+)"', re.M)


def fetch(version: str):
    try:
        with urllib.request.urlopen(URL.format(version), timeout=30) as r:
            text = r.read().decode("utf-8", "replace")
    except Exception:
        return version, None
    m = RE_RUSTC.search(text) or RE_HASH.search(text)
    d = RE_DATE.search(text)
    if not m:
        return version, None
    return version, {"hash": m.group(1), "date": d.group(1) if d else ""}


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--max-minor", type=int, default=130)
    ap.add_argument("--max-patch", type=int, default=5)
    args = ap.parse_args()

    versions = [f"1.{mi}.{pa}" for mi in range(8, args.max_minor + 1) for pa in range(args.max_patch + 1)]
    with ThreadPoolExecutor(max_workers=16) as pool:
        found = {v: info for v, info in pool.map(fetch, versions) if info}

    table = {}
    for v in sorted(found, key=lambda s: tuple(int(x) for x in s.split("."))):
        info = found[v]
        table.setdefault(info["hash"], {"version": v, "date": info["date"]})
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(table, indent=1, sort_keys=True) + "\n")
    newest = max(found, key=lambda s: tuple(int(x) for x in s.split("."))) if found else None
    print(f"{len(table)} releases (1.8.0 .. {newest}) -> {OUT}")


if __name__ == "__main__":
    main()
