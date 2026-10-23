#!/usr/bin/env python3
"""measure_fp.py - reproducible false-positive measurement for static recovery.

The micro-benchmark (RESULTS.md) measures recall on tiny programs that *do* hide
canaries. The complementary question VALIDATION.md raises is precision: run the
static recoverer on real, benign binaries that hide **nothing**, and every string it
"recovers" is a false positive. The xor/add/sub-byte-in-a-loop idiom the detector keys
on is extremely common in ordinary code (UTF-8, hashing, checksums), so an unfiltered
detector fires everywhere; this script quantifies how much survives the shipped filters.

It runs `recover_callsite.recover(path, canaries=[])` over a corpus of real binaries and
reports, per binary and in aggregate: decoder candidates considered (pre-filter signal),
false-positive strings emitted (post-filter), and FP normalised per MB of `.text`. No
binary here contains the benchmark canaries, so the ideal result is 0 FP.

    python scripts/measure_fp.py                     # auto-discover real system binaries
    python scripts/measure_fp.py --bins /usr/bin/git /tmp/rg/bin/rg
    python scripts/measure_fp.py --json              # machine-readable + writes build/fp_results.json
    python scripts/measure_fp.py --pipeline          # the whole recover.py pipeline (static +
                                                     # emulation), as a user runs it; writes
                                                     # build/fp_pipeline_results.json with --json

Only x86-64 ELF/PE that LIEF can parse are scanned (the static engine is x86-64). This is
a defensive, read-only measurement: it disassembles binaries and prints statistics.
"""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

# Candidate real binaries to measure precision on. Benign, widely available, and none
# contains the benchmark canaries -- so any "recovered" string is a false positive. The
# list is filtered to those that actually exist and parse as x86-64 at run time.
DEFAULT_CANDIDATES = [
    "/usr/bin/git", "/usr/bin/openssl", "/usr/bin/python3.11", "/usr/bin/python3.12",
    "/usr/bin/python3.13", "/usr/bin/bash", "/usr/bin/gpg", "/usr/bin/curl",
    "/usr/bin/ssh", "/usr/bin/perl", "/usr/bin/vim.basic", "/usr/bin/dpkg",
    "/bin/tar", "/usr/bin/gzip", "/usr/bin/xz", "/usr/lib/x86_64-linux-gnu/libcrypto.so.3",
]


def is_x86_64(path: Path) -> bool:
    try:
        import lief
        b = lief.parse(str(path))
        if b is None:
            return False
        m = (b.header.machine_type.name if hasattr(b.header, "machine_type")
             else str(b.header.machine)).upper()
        return "X86_64" in m or "AMD64" in m or "86_64" in m
    except Exception:
        return False


def text_size(path: Path) -> int:
    try:
        import lief
        b = lief.parse(str(path))
        t = next((s for s in b.sections if s.name == ".text"), None)
        return int(t.size) if t else 0
    except Exception:
        return 0


def discover(globs) -> list[Path]:
    import glob as _glob
    out = []
    for g in globs:
        for p in sorted(_glob.glob(g)):
            out.append(Path(p))
    return out


def measure_pipeline(path: Path, time_budget: float):
    """Every decoded string the full recover.py pipeline reports is a FP on a benign binary."""
    import time
    import recover
    t0 = time.monotonic()
    res = recover.run(path, emulate="always", stackstrings=False, literals=False,
                      time_budget=time_budget)
    by_engine = {}
    for x in res["decoded"]:
        by_engine.setdefault(x.get("method", "?"), []).append(x["string"])
    emu = next((e for e in res["engines"] if e["engine"].startswith("emulation")), {})
    fp = sorted({x["string"] for x in res["decoded"]})
    return {"binary": str(path), "text_bytes": text_size(path),
            "emulated_functions": emu.get("functions", "-"), "timed_out": emu.get("timed_out", False),
            "seconds": round(time.monotonic() - t0, 1),
            "false_positives": len(fp), "fp_strings": fp[:20],
            "fp_by_method": {k: len(v) for k, v in by_engine.items()},
            "decoder_candidates": next((e.get("decoders", 0) for e in res["engines"]
                                        if e["engine"].startswith("static")), 0),
            "error": None}


def measure(path: Path):
    import recover_callsite as R
    r = R.recover(path, [])            # no canaries -> every recovered text is a FP
    fp = sorted(set(s for s in r.get("recovered_texts", []) if len(s) >= 6))
    return {"binary": str(path), "text_bytes": text_size(path),
            "decoder_candidates": r.get("decoders", 0),
            "false_positives": len(fp), "fp_strings": fp[:20],
            "error": r.get("error")}


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bins", nargs="*", help="explicit binary paths to measure")
    ap.add_argument("--glob", nargs="*", default=[], help="glob(s) of binaries to add")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--pipeline", action="store_true",
                    help="measure the whole recover.py pipeline instead of static recovery alone")
    ap.add_argument("--time-budget", type=float, default=120.0,
                    help="emulation time budget per binary with --pipeline (default 120 s)")
    a = ap.parse_args()

    cands = [Path(b) for b in a.bins] if a.bins else [Path(p) for p in DEFAULT_CANDIDATES]
    cands += discover(a.glob)
    # resolve symlinks, de-dup, keep only existing x86-64 binaries
    seen, bins = set(), []
    for p in cands:
        try:
            rp = p.resolve()
        except Exception:
            continue
        if rp in seen or not rp.exists() or not (is_x86_64(rp) or a.pipeline):
            continue
        seen.add(rp); bins.append(rp)
    if not bins:
        sys.exit("no x86-64 binaries found to measure (pass --bins or --glob)")

    if a.pipeline:
        rows = []
        for p in bins:
            r = measure_pipeline(p, a.time_budget)
            rows.append(r)
            if not a.json:
                print(f"{p.name:<40} {r['text_bytes'] // 1024:>7} KB  emulated {r['emulated_functions']:>11}"
                      f"{' (budget)' if r['timed_out'] else ''}  {r['seconds']:>5}s  FP {r['false_positives']}"
                      f"  {r['fp_by_method'] or ''}", flush=True)
                for st in r["fp_strings"]:
                    print(f"      FP: {st!r}")
        tot = sum(r["false_positives"] for r in rows)
        summary = {"binaries": len(rows), "clean_binaries": sum(1 for r in rows if not r["false_positives"]),
                   "false_positives_total": tot, "time_budget_s": a.time_budget}
        if a.json:
            (ROOT / "build").mkdir(exist_ok=True)
            out = json.dumps({"summary": summary, "rows": rows}, indent=2)
            (ROOT / "build" / "fp_pipeline_results.json").write_text(out)
            print(out)
        else:
            print(f"{summary['clean_binaries']}/{len(rows)} binaries with zero FP, {tot} FP total")
        return

    rows = [measure(p) for p in bins]
    n = len(rows)
    tot_fp = sum(r["false_positives"] for r in rows)
    tot_cand = sum(r["decoder_candidates"] for r in rows)
    tot_mb = sum(r["text_bytes"] for r in rows) / 1e6
    clean = sum(1 for r in rows if r["false_positives"] == 0)
    summary = {"binaries": n, "clean_binaries": clean,
               "decoder_candidates_total": tot_cand, "false_positives_total": tot_fp,
               "fp_per_binary": round(tot_fp / n, 2) if n else 0,
               "fp_per_text_mb": round(tot_fp / tot_mb, 2) if tot_mb else 0,
               "text_mb_total": round(tot_mb, 1)}

    if a.json:
        (ROOT / "build").mkdir(exist_ok=True)
        (ROOT / "build" / "fp_results.json").write_text(
            json.dumps({"summary": summary, "rows": rows}, indent=2))
        print(json.dumps({"summary": summary, "rows": rows}, indent=2))
        return

    print(f"{'binary':<44}{'.text KB':>9}{'cand':>6}{'FP':>5}")
    print("-" * 64)
    for r in rows:
        name = Path(r["binary"]).name
        print(f"{name:<44}{r['text_bytes']//1024:>9}{r['decoder_candidates']:>6}"
              f"{r['false_positives']:>5}" + ("  "+r['error'] if r.get('error') else ""))
        for s in r["fp_strings"]:
            print(f"      FP: {s}")
    print("-" * 64)
    print(f"{n} binaries, {summary['text_mb_total']} MB .text scanned | "
          f"{clean}/{n} with zero FP | {tot_cand} decoder candidates considered | "
          f"{tot_fp} false positives total "
          f"({summary['fp_per_binary']}/binary, {summary['fp_per_text_mb']}/MB)")


if __name__ == "__main__":
    main()
