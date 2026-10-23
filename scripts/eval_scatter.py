#!/usr/bin/env python3
"""Score recover.py on the "scatter" suite: strings used the way real programs use them.

The canary benchmark prints five strings from main() under one build profile. The scatter
programs (bench_src/scatter_*) keep eight indicator-shaped strings in struct fields, match arms,
comparisons that are never printed and a branch that never runs, and are built with the
release profile and the two fat-LTO profiles (size-lto: opt-level="z", speed-lto: opt-level=3,
both codegen-units=1, panic=abort). See bench_src/gen_projects.py.

For every binary it runs the same pipeline a user runs (`recover.run`, default settings) and
reports, per expected string:
  exact      a decoded string equal to it
  truncated  only a decoded string that is a strict prefix/substring of it (>= 6 chars)
  missed     nothing
plus `extra`: decoded strings that are none of the eight (false positives / noise).

    python scripts/eval_scatter.py                       # every scatter_* binary in build/
    python scripts/eval_scatter.py build/scatter_obfstr__pe__size-lto__strip.exe
    python scripts/eval_scatter.py --json build/scatter_results.json
"""
from __future__ import annotations
import argparse
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
ROOT = Path(__file__).resolve().parent.parent
BUILD = Path(os.environ.get("RUST_DEOBF_BUILD", ROOT / "build"))
_MAN = json.loads((ROOT / "bench_src" / "manifest.json").read_text())
SCATTER = _MAN["scatter"]
# what each program really holds at run time (litcrypt v1 mangles raw literals; see the manifest)
EXPECTED = _MAN.get("scatter_expected", {})


def score(decoded, expected=SCATTER):
    texts = {d["string"] for d in decoded}
    expected = list(expected)
    exact = [s for s in expected if s in texts]
    trunc = [s for s in expected if s not in texts
             and any(len(t) >= 6 and t in s for t in texts)]
    missed = [s for s in expected if s not in exact and s not in trunc]
    extra = sorted(t for t in texts
                   if t not in expected and not any(t in s for s in expected)
                   and not any(s in t for s in expected))
    # a decoded string that contains an expected one plus junk counts as found but noisy
    padded = sorted(t for t in texts if t not in expected and any(s in t for s in expected))
    return {"exact": exact, "truncated": trunc, "missed": missed, "extra": extra, "padded": padded}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("binaries", nargs="*")
    ap.add_argument("--json", metavar="OUT")
    ap.add_argument("--time-budget", type=float, default=120.0)
    ap.add_argument("--max-funcs", type=int, default=0)
    args = ap.parse_args(argv)
    import recover
    paths = [Path(p) for p in args.binaries] or sorted(
        p for p in BUILD.glob("scatter_*") if p.is_file() and "__debug__" not in p.name)
    rows = []
    print(f"{'binary':<52} exact trunc miss extra  secs")
    for p in paths:
        t0 = time.monotonic()
        res = recover.run(p, emulate="always", stackstrings=False, literals=False,
                          time_budget=args.time_budget, max_funcs=args.max_funcs)
        sc = score(res["decoded"], EXPECTED.get(p.name.split("__")[0], SCATTER))
        sc.update(binary=p.name, seconds=round(time.monotonic() - t0, 1),
                  engines=[e["engine"] for e in res["engines"]])
        rows.append(sc)
        print(f"{p.name:<52} {len(sc['exact']):>3}/8 {len(sc['truncated']):>5} {len(sc['missed']):>4} "
              f"{len(sc['extra']):>5}  {sc['seconds']:>4}")
        for s in sc["truncated"]:
            print(f"      ~ truncated: {s}")
        for s in sc["missed"]:
            print(f"      - missed:    {s}")
        for s in sc["extra"] + sc["padded"]:
            print(f"      + extra:     {s!r}")
    if args.json:
        Path(args.json).write_text(json.dumps(rows, indent=1) + "\n")
    tot = sum(len(r["exact"]) for r in rows)
    print(f"\n{tot}/{8 * len(rows)} exact over {len(rows)} binaries; "
          f"{sum(len(r['extra']) for r in rows)} extra strings")


if __name__ == "__main__":
    main()
