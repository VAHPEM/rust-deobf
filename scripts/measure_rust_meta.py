#!/usr/bin/env python3
"""measure_rust_meta.py - labelled accuracy for Tier-3 Rust metadata recovery.

recover_rust_meta.py recovers, statically, the crates+versions and panic file:line:col a
Rust binary leaks. This scores it against ground truth: each bench project's `Cargo.lock`
is the exact set of crate names+versions compiled in, so we can measure

  precision      = recovered crates that are real deps / recovered crates
  version-exact  = recovered (crate,version) pairs that match the lock exactly / recovered
  coverage       = recovered crates / crates in the lock
                   (the fraction of the dependency tree that leaks identifiable panic
                    metadata -- inherently < 1: proc-macro/build-only/panic-free crates
                    leave no `.cargo/registry/<crate>-<ver>/` path, so this is a property
                    of what Rust emits, not a recoverer miss)

and reports panic-site counts (now recovered on PIE ELF via relocations) per binary.

    python scripts/measure_rust_meta.py            # all built bench binaries
    python scripts/measure_rust_meta.py --json     # writes build/rust_meta_results.json
"""
from __future__ import annotations
import argparse, json, re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

RE_PKG = re.compile(r'name = "([^"]+)"\nversion = "([^"]+)"')


def ground_truth(lock: Path) -> dict:
    """{crate_name: set(versions)} from a Cargo.lock."""
    g = {}
    for n, v in RE_PKG.findall(lock.read_text(errors="ignore")):
        g.setdefault(n, set()).add(v)
    return g


def discover():
    out = []
    for proj in sorted((ROOT / "bench_src").glob("*")):
        lock = proj / "Cargo.lock"
        binp = proj / "target" / "release" / proj.name
        if lock.exists() and binp.exists():
            out.append((proj.name, binp, lock))
    return out


def measure(name, binp, lock):
    import recover_rust_meta as M
    g = ground_truth(lock)
    r = M.recover(binp)
    det = r["crates"]                      # {crate: [versions]}
    det_names = set(det)
    in_lock = det_names & set(g)
    ver_pairs = [(c, v) for c in det for v in det[c]]
    ver_ok = [(c, v) for c, v in ver_pairs if c in g and v in g[c]]
    # exclude the project's own crate name from the lock denominator for coverage
    dep_names = set(g) - {name}
    return {
        "binary": name, "lock_crates": len(dep_names),
        "recovered_crates": len(det_names), "recovered_in_lock": len(in_lock),
        "version_pairs": len(ver_pairs), "version_exact": len(ver_ok),
        "panic_sites": r["counts"]["panic_sites"],
        "own_source_files": len(r["own_source_files"]),
        "false_crates": sorted(det_names - set(g)),
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    projs = discover()
    if not projs:
        sys.exit("no built bench binaries with a Cargo.lock found (run scripts/build_all.sh)")
    rows = [measure(n, b, l) for n, b, l in projs]

    det = sum(r["recovered_crates"] for r in rows)
    inlock = sum(r["recovered_in_lock"] for r in rows)
    vpairs = sum(r["version_pairs"] for r in rows)
    vok = sum(r["version_exact"] for r in rows)
    sites = sum(r["panic_sites"] for r in rows)
    summary = {
        "binaries": len(rows),
        "crates_recovered": det, "crates_in_lock": inlock,
        "precision": round(inlock / det, 3) if det else None,
        "version_pairs": vpairs, "version_exact": vok,
        "version_accuracy": round(vok / vpairs, 3) if vpairs else None,
        "panic_sites_total": sites,
    }

    if a.json:
        (ROOT / "build").mkdir(exist_ok=True)
        (ROOT / "build" / "rust_meta_results.json").write_text(
            json.dumps({"summary": summary, "rows": rows}, indent=2))
        print(json.dumps({"summary": summary, "rows": rows}, indent=2))
        return

    print(f"{'binary':<12}{'lockdeps':>9}{'rec':>5}{'ok':>4}{'verOK':>7}{'panic':>7}  false")
    print("-" * 60)
    for r in rows:
        print(f"{r['binary']:<12}{r['lock_crates']:>9}{r['recovered_crates']:>5}"
              f"{r['recovered_in_lock']:>4}{r['version_exact']:>7}{r['panic_sites']:>7}"
              f"  {','.join(r['false_crates']) or '-'}")
    print("-" * 60)
    print(f"precision (recovered crates that are real deps): {inlock}/{det}"
          f" = {summary['precision']}")
    print(f"version-exact (recovered crate@version matches lock): {vok}/{vpairs}"
          f" = {summary['version_accuracy']}")
    print(f"panic sites recovered across {len(rows)} binaries: {sites}")
    print("note: coverage (recovered/lockdeps) is intentionally < 1 — proc-macro / build-only")
    print("      / panic-free crates leave no registry path, so they cannot leak a version.")


if __name__ == "__main__":
    main()
