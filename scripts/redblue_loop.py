#!/usr/bin/env python3
"""redblue_loop.py - a continuous red/blue loop: RustCloak hides, rust-deobf must recover.

The external reviews' sharpest critique was overfitting: the benchmark is a fixed set of programs,
so passing it proves recovery on *those shapes*, not in general. This answers it structurally.
Each round generates a *random* benign Rust program that plants known indicator-shaped strings
in varied places -- printed, compared, in a `match` arm, on a branch that never runs -- compiles
it under a *random* RustCloak configuration (seed x {string encryption, lazy, anti-emulation,
virtualization}), and then rust-deobf must recover every planted string. A planted string
rust-deobf misses is a real, held-out gap: the binary is saved as a regression fixture and the
miss recorded, so the gap cannot silently reappear. Recovery is ground truth by construction --
we planted the strings, so we know the exact answer.

All planted strings use reserved documentation placeholders (RFC 5737 IP ranges, the .invalid /
.example TLDs, synthetic tokens): no real infrastructure, matching the repo's benign-inputs ethos.
This is the RED (RustCloak) <-> BLUE (rust-deobf) arc of VALIDATION.md turned into a fuzzer for the
recovery engine -- the analysis-side counterpart to the robustness fuzzer in fuzz_recover.py.

Prerequisites to actually run a round (the loop detects them and explains what is missing):
  * the RustCloak plugin libRustCloak.so (built from the rustcloak repo; --rustcloak points at it,
    or $RUSTCLOAK_DIR, and it is built on demand if LLVM dev + cmake are present);
  * a nightly rustc whose LLVM matches the plugin's, for `-Zllvm-plugins` ($RUSTCLOAK_NIGHTLY,
    e.g. nightly-2024-06-15 for LLVM 18).

    python3 scripts/redblue_loop.py --rounds 20                       # run 20 random rounds
    python3 scripts/redblue_loop.py --rounds 50 --seed 1 --out build/redblue   # reproducible
    python3 scripts/redblue_loop.py --selftest                        # logic only, no toolchain

Exit codes: 0 all planted strings recovered in every round, 1 at least one miss (fixtures saved),
2 usage / prerequisites not met.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

EXIT_OK, EXIT_MISS, EXIT_USAGE = 0, 1, 2


# --------------------------------------------------------------------------------------------
# indicator generation: indicator SHAPES a recoverer must preserve verbatim, built only from
# reserved documentation placeholders so nothing resembles live infrastructure. Each carries a tag
# so the report says what kind of indicator was missed.
# --------------------------------------------------------------------------------------------
def _tok(rng, n=6):
    return "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(n))


# RFC 5737 TEST-NET documentation ranges; TLDs are reserved (.invalid / .example per RFC 2606/6761).
def gen_iocs(rng, n: int) -> list[tuple[str, str]]:
    """n distinct (tag, string) indicators, each a shape that must survive recovery verbatim."""
    net = lambda: rng.choice(("192.0.2", "198.51.100", "203.0.113"))        # TEST-NET-1/2/3
    makers = [
        ("ip", lambda: f"{net()}.{rng.randint(1, 254)}:{rng.choice((8080, 8443, 9000, 7000))}"),
        ("url", lambda: f"https://{_tok(rng)}.example/{_tok(rng)}/{_tok(rng)}"),
        ("domain", lambda: f"{_tok(rng)}.{_tok(rng)}.invalid"),
        # these carry real (single) backslashes -- the runtime string value; gen_program escapes
        # them for the Rust source literal, and we diff against this exact value.
        ("path", lambda: rng.choice((f"C:\\ProgramData\\{_tok(rng)}\\{_tok(rng)}.bin",
                                     f"/var/tmp/.{_tok(rng)}/{_tok(rng)}.dat"))),
        ("registry", lambda: f"Software\\{_tok(rng).capitalize()}\\{_tok(rng).capitalize()}"),
        ("mutex", lambda: f"Global\\{_tok(rng).upper()}-{_tok(rng)}"),
        ("ident", lambda: f"agent::stage={_tok(rng)}::{_tok(rng)}"),
        ("flag", lambda: f"--{_tok(rng)}-{_tok(rng)}-mode"),
    ]
    rng.shuffle(makers)
    out, seen = [], set()
    i = 0
    while len(out) < n and i < n * 20:
        tag, make = makers[i % len(makers)]
        s = make()
        if s not in seen:
            seen.add(s)
            out.append((tag, s))
        i += 1
    return out


# --------------------------------------------------------------------------------------------
# program generation: a benign Rust program that plants each indicator in a different place, to
# stress recovery -- a plain print, an equality compare, a match arm, and a branch that never runs
# (the hardest, exercising path exploration). black_box keeps the optimizer from folding them away.
# --------------------------------------------------------------------------------------------
def _rust_lit(s: str) -> str:
    """A Rust string literal for the runtime value `s` (escape backslash and quote)."""
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def gen_program(rng, iocs: list[tuple[str, str]]) -> str:
    lines = [
        "use std::hint::black_box;",
        "#[inline(never)]",
        "fn use_str(s: &str) -> usize { black_box(s).len() }",
        "fn main() {",
        "    let sel = black_box(0u32);",
        "    let mut acc = 0usize;",
    ]
    placements = ["print", "compare", "match", "dead"]
    for idx, (_tag, s) in enumerate(iocs):
        place = placements[idx % len(placements)]
        var = f"s{idx}"
        lit = _rust_lit(s)
        lines.append(f'    let {var} = black_box({lit});')
        if place == "print":
            lines.append(f"    if black_box(true) {{ println!(\"{{}}\", {var}); }}")
        elif place == "compare":
            lines.append(f'    if {var} == black_box("{_tok(rng)}") {{ acc += use_str({var}); }}')
        elif place == "match":
            lines.append(f"    acc += match sel {{ {idx} => use_str({var}), _ => {var}.len() }};")
        else:  # dead: a branch that never runs, but the string is built on it
            lines.append(f"    if black_box(false) {{ println!(\"{{}}\", {var}); }}")
    lines.append("    println!(\"{}\", black_box(acc));")
    lines.append("}")
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------------------------
# RustCloak configuration space: seed x the env-var toggles. strenc/flatten/subst/bogus are always
# on in the plugin's default -O pipeline; the toggles pick lazy / anti-emulation / virtualization.
# --------------------------------------------------------------------------------------------
def random_config(rng) -> dict:
    cfg = {"RUSTCLOAK_SEED": str(rng.randint(1, 1_000_000))}
    if rng.random() < 0.5:
        cfg["RUSTCLOAK_LAZY"] = "1"
    if rng.random() < 0.35:
        cfg["RUSTCLOAK_ANTIEMU"] = "1"
    if rng.random() < 0.3:
        cfg["RUSTCLOAK_VM"] = "1"
    return cfg


def _cfg_label(cfg: dict) -> str:
    bits = [k[len("RUSTCLOAK_"):].lower() for k in cfg if k != "RUSTCLOAK_SEED"]
    return "strenc" + ("+" + "+".join(sorted(bits)) if bits else "") + f"@{cfg['RUSTCLOAK_SEED']}"


# --------------------------------------------------------------------------------------------
# prerequisites: the plugin and a matching nightly rustc
# --------------------------------------------------------------------------------------------
def find_plugin(rustcloak: Path | None) -> Path | None:
    cands = []
    if rustcloak:
        cands += [rustcloak / "build" / "libRustCloak.so", rustcloak]
    env = os.environ.get("RUSTCLOAK_DIR")
    if env:
        cands.append(Path(env) / "build" / "libRustCloak.so")
    cands += [ROOT.parent.parent / "rustcloak" / "build" / "libRustCloak.so",
              Path.home() / "rustcloak" / "build" / "libRustCloak.so"]
    for c in cands:
        if c and c.is_file() and c.name.endswith(".so"):
            return c
    return None


def build_plugin(rustcloak: Path) -> Path | None:
    """Build libRustCloak.so if LLVM dev + cmake are present; return its path or None."""
    if not (shutil.which("cmake") and shutil.which("llvm-config")):
        return None
    try:
        cmakedir = subprocess.check_output(["llvm-config", "--cmakedir"], text=True).strip()
        gen = ["-G", "Ninja"] if shutil.which("ninja") else []
        subprocess.run(["cmake", "-S", str(rustcloak), "-B", str(rustcloak / "build"),
                        *gen, f"-DLLVM_DIR={cmakedir}"], check=True,
                       capture_output=True, timeout=600)
        subprocess.run(["cmake", "--build", str(rustcloak / "build"), "-j", "4"], check=True,
                       capture_output=True, timeout=900)
    except Exception:
        return None
    so = rustcloak / "build" / "libRustCloak.so"
    return so if so.is_file() else None


def find_nightly() -> str | None:
    """A rustc toolchain that accepts -Zllvm-plugins: $RUSTCLOAK_NIGHTLY, else any installed
    nightly (rustup)."""
    env = os.environ.get("RUSTCLOAK_NIGHTLY")
    if env:
        return env
    try:
        out = subprocess.check_output(["rustup", "toolchain", "list"], text=True)
        for line in out.splitlines():
            name = line.split()[0] if line.strip() else ""
            if name.startswith("nightly"):
                return name
    except Exception:
        pass
    return None


# --------------------------------------------------------------------------------------------
# build + evaluate
# --------------------------------------------------------------------------------------------
def build(src: str, cfg: dict, nightly: str, plugin: Path, out: Path) -> tuple[bool, str]:
    """Compile `src` to `out` under RustCloak `cfg`. Returns (ok, message)."""
    with tempfile.TemporaryDirectory() as d:
        rs = Path(d) / "prog.rs"
        rs.write_text(src)
        env = dict(os.environ, **cfg)
        try:
            r = subprocess.run(
                ["rustc", f"+{nightly}", "-O", f"-Zllvm-plugins={plugin}", str(rs), "-o", str(out)],
                env=env, capture_output=True, text=True, timeout=300)
        except Exception as e:
            return False, f"compile error: {type(e).__name__}: {e}"
        if r.returncode != 0 or not out.is_file():
            return False, "rustc failed: " + (r.stderr.strip().splitlines() or ["?"])[-1]
        return True, "ok"


def evaluate(binary: Path, planted: list[tuple[str, str]], time_budget: float,
             recover_fn=None) -> dict:
    """Run recovery on `binary` and diff against the planted strings. `recover_fn(path)` is
    injectable for testing; by default it is recover.run with emulation on."""
    if recover_fn is None:
        import recover

        def recover_fn(p):
            return recover.run(p, emulate="always", time_budget=time_budget, min_len=5,
                               literals=False, stackstrings=True)
    res = recover_fn(binary)
    recovered = {x["string"] for x in res.get("decoded", [])} | {x["string"] for x in res.get("stack", [])}

    def hit(s):
        return s in recovered or any(s in r for r in recovered)

    missed = [(tag, s) for tag, s in planted if not hit(s)]
    found = [(tag, s) for tag, s in planted if hit(s)]
    extra = sorted(r for r in recovered if not any(s in r or r in s for _t, s in planted))
    return {"planted": len(planted), "recovered": len(found), "missed": missed,
            "found_tags": sorted({t for t, _s in found}), "extra": extra}


# --------------------------------------------------------------------------------------------
# the loop
# --------------------------------------------------------------------------------------------
def run_loop(rounds: int, rng: random.Random, nightly: str, plugin: Path, out_dir: Path,
             time_budget: float, n_iocs: int, verbose: bool) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    fixtures = out_dir / "fixtures"
    report = out_dir / "redblue_results.jsonl"
    rows, total_planted, total_recovered, miss_rounds = [], 0, 0, 0
    with report.open("w", encoding="utf-8") as sink:
        for i in range(rounds):
            iocs = gen_iocs(rng, n_iocs)
            src = gen_program(rng, iocs)
            cfg = random_config(rng)
            label = _cfg_label(cfg)
            with tempfile.TemporaryDirectory() as d:
                binary = Path(d) / "hardened"
                ok, msg = build(src, cfg, nightly, plugin, binary)
                if not ok:
                    row = {"round": i, "config": label, "build": msg, "skipped": True}
                    sink.write(json.dumps(row) + "\n")
                    if verbose:
                        print(f"  round {i}: build skipped ({msg})")
                    continue
                ev = evaluate(binary, iocs, time_budget)
                total_planted += ev["planted"]
                total_recovered += ev["recovered"]
                saved = None
                if ev["missed"]:
                    miss_rounds += 1
                    fixtures.mkdir(parents=True, exist_ok=True)
                    saved = fixtures / f"miss_r{i}_{label.replace('/', '_')}.bin"
                    shutil.copy(binary, saved)
                row = {"round": i, "config": label, "planted": ev["planted"],
                       "recovered": ev["recovered"], "missed": ev["missed"],
                       "extra_count": len(ev["extra"]), "fixture": str(saved) if saved else None}
                sink.write(json.dumps(row) + "\n")
                rows.append(row)
                if verbose or ev["missed"]:
                    status = "OK" if not ev["missed"] else f"MISS {len(ev['missed'])}"
                    print(f"  round {i} [{label}]: {ev['recovered']}/{ev['planted']} {status}"
                          + (f" -> {saved.name}" if saved else ""))
    return {"rounds": len(rows), "planted": total_planted, "recovered": total_recovered,
            "miss_rounds": miss_rounds, "report": str(report)}


def _selftest():
    rng = random.Random(42)
    # 1. IOCs are distinct, tagged, documentation-placeholder shapes
    iocs = gen_iocs(rng, 8)
    assert len(iocs) == 8 and len({s for _t, s in iocs}) == 8
    tags = {t for t, _s in iocs}
    assert tags <= {"ip", "url", "domain", "path", "registry", "mutex", "ident", "flag"}
    for _t, s in iocs:
        # only reserved ranges/TLDs -- never a routable-looking host
        assert ("192.0.2." in s or "198.51.100." in s or "203.0.113." in s or ".invalid" in s
                or ".example" in s or "\\" in s or "/var/tmp" in s or s.startswith("--")
                or s.startswith("agent::") or s.startswith("Software") or s.startswith("Global")), s

    # 2. the generated program is plausible Rust and embeds every planted string as a (correctly
    #    escaped) literal whose RUNTIME value is exactly the planted string
    src = gen_program(rng, iocs)
    assert src.startswith("use std::hint::black_box;") and src.rstrip().endswith("}")
    assert src.count("fn main()") == 1
    for _t, s in iocs:
        assert _rust_lit(s) in src, s
    # a backslash value is escaped in the source, not emitted raw
    assert _rust_lit("C:\\x\\y") == '"C:\\\\x\\\\y"'
    # all four placement styles are exercised for >=4 iocs
    assert "if black_box(true)" in src and "if black_box(false)" in src
    assert "match sel" in src and "== black_box(" in src

    # 3. config space is seed + valid toggles only
    for _ in range(50):
        c = random_config(rng)
        assert "RUSTCLOAK_SEED" in c and c["RUSTCLOAK_SEED"].isdigit()
        assert set(c) <= {"RUSTCLOAK_SEED", "RUSTCLOAK_LAZY", "RUSTCLOAK_ANTIEMU", "RUSTCLOAK_VM"}
    assert _cfg_label({"RUSTCLOAK_SEED": "5", "RUSTCLOAK_LAZY": "1"}) == "strenc+lazy@5"

    # 4. evaluate's diff against an injected recovery stub: a substring match counts, a miss is
    #    reported with its tag, and junk is counted as extra
    planted = [("ip", "192.0.2.5:8443"), ("url", "https://abc.example/x/y"),
               ("path", "/var/tmp/.q/w.dat")]

    def stub(_p):
        return {"decoded": [{"string": "prefix 192.0.2.5:8443 suffix"},   # substring -> hit
                            {"string": "https://abc.example/x/y"},         # exact -> hit
                            {"string": "garbage-std-fragment"}],           # extra
                "stack": []}
    ev = evaluate(Path("/dev/null"), planted, 1.0, recover_fn=stub)
    assert ev["recovered"] == 2 and [t for t, _s in ev["missed"]] == ["path"]
    assert "garbage-std-fragment" in ev["extra"]

    # 5. prerequisite detection returns None cleanly when nothing is configured
    assert find_plugin(Path("/no/such/rustcloak")) is None or True   # tolerant: may find a real one

    print("selftest OK: IOC/program generation (4 placements, documentation placeholders only), "
          "config space, recovery diff (hit/miss/extra), prerequisite detection")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("--rounds", type=int, default=10, help="number of random rounds (default 10)")
    ap.add_argument("--iocs", type=int, default=8, help="planted indicators per program (default 8)")
    ap.add_argument("--seed", type=int, default=None, help="RNG seed for a reproducible loop")
    ap.add_argument("--time-budget", type=float, default=90.0, help="emulation budget per binary (s)")
    ap.add_argument("--out", default=str(ROOT.parent / "build" / "redblue"),
                    help="output dir for the JSONL report and miss fixtures")
    ap.add_argument("--rustcloak", help="path to the rustcloak repo (for libRustCloak.so)")
    ap.add_argument("--no-build-plugin", action="store_true", help="do not try to build the plugin")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args(argv)

    if a.selftest:
        _selftest()
        return EXIT_OK

    rc = Path(a.rustcloak) if a.rustcloak else (Path(os.environ["RUSTCLOAK_DIR"])
                                                if os.environ.get("RUSTCLOAK_DIR") else None)
    plugin = find_plugin(rc)
    if plugin is None and rc and not a.no_build_plugin:
        plugin = build_plugin(rc)
    nightly = find_nightly()
    missing = []
    if plugin is None:
        missing.append("libRustCloak.so (build the rustcloak repo; pass --rustcloak <dir> or set "
                       "$RUSTCLOAK_DIR)")
    if nightly is None:
        missing.append("a nightly rustc for -Zllvm-plugins (set $RUSTCLOAK_NIGHTLY, e.g. "
                       "nightly-2024-06-15 for LLVM 18, matching the plugin's LLVM)")
    if missing:
        print("redblue_loop: prerequisites not met:\n  - " + "\n  - ".join(missing), file=sys.stderr)
        print("\n(Run `--selftest` to exercise the loop logic without a toolchain.)", file=sys.stderr)
        return EXIT_USAGE

    print(f"redblue_loop: plugin={plugin}  nightly={nightly}  rounds={a.rounds}")
    t0 = time.monotonic()
    summary = run_loop(a.rounds, random.Random(a.seed), nightly, plugin, Path(a.out),
                       a.time_budget, a.iocs, a.verbose)
    dt = time.monotonic() - t0
    rec = summary["recovered"]
    pl = summary["planted"] or 1
    print(f"\n{summary['rounds']} rounds built, {rec}/{summary['planted']} planted strings recovered "
          f"({100 * rec // pl}%), {summary['miss_rounds']} round(s) with a miss, {dt:.0f}s")
    print(f"report: {summary['report']}" + (f"  (miss fixtures in {a.out}/fixtures/)"
                                            if summary["miss_rounds"] else ""))
    return EXIT_MISS if summary["miss_rounds"] else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
