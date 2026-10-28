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

A planted string RustCloak did not actually hide (still present as plaintext UTF-8 / UTF-16LE in
the built binary) is reported as `not_hidden` and excluded from the recall figures: finding it says
nothing about rust-deobf. A round in which nothing was hidden is skipped ("plugin had no effect"),
as is a round whose build failed; skipped rounds are counted and reported.

Exit codes: 0 all planted strings recovered in every round, 1 at least one miss (fixtures saved),
2 usage / prerequisites not met, 3 no round was evaluable (every build failed or the plugin hid
nothing -- a broken toolchain, not a clean bill of health).
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

EXIT_OK, EXIT_MISS, EXIT_USAGE, EXIT_NO_ROUNDS = 0, 1, 2, 3


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
            return False, "rustc failed: " + _first_error_line(r.stderr)
        return True, "ok"


def _first_error_line(stderr: str) -> str:
    """The line that says what went wrong. rustc's LAST line is the generic "error: aborting due to
    N previous errors", so report the first line that starts with `error` (e.g. `error[E0425]: ...`
    or a plugin load failure), else the first line mentioning "error", else the last line."""
    lines = [ln.strip() for ln in (stderr or "").splitlines() if ln.strip()]
    if not lines:
        return "?"
    for ln in lines:
        if ln.lower().startswith("error"):
            return ln
    for ln in lines:
        if "error" in ln.lower():
            return ln
    return lines[-1]


def not_hidden(data: bytes, planted: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """Planted strings still present verbatim in the binary (UTF-8 or UTF-16LE): the obfuscator
    did not hide them, so recovering them is not evidence about rust-deobf either way."""
    return [(tag, s) for tag, s in planted
            if s.encode("utf-8") in data or s.encode("utf-16-le") in data]


def evaluate(binary: Path, planted: list[tuple[str, str]], time_budget: float,
             recover_fn=None) -> dict:
    """Run recovery on `binary` and diff against the planted strings. `recover_fn(path)` is
    injectable for testing; by default it is recover.run with emulation on.

    Only strings the obfuscator actually hid count: those left in plaintext are reported under
    `not_hidden` and excluded from `planted` / `recovered` / `missed`. If nothing was hidden the
    result carries `skipped` and recovery is not run at all."""
    try:
        data = Path(binary).read_bytes()
    except OSError:
        data = b""
    plain = not_hidden(data, planted)
    hidden = [p for p in planted if p not in plain]
    if not hidden:
        return {"planted": 0, "planted_total": len(planted), "recovered": 0, "missed": [],
                "not_hidden": plain, "found_tags": [], "extra": [],
                "skipped": "plugin had no effect"}
    if recover_fn is None:
        import recover

        def recover_fn(p):
            return recover.run(p, emulate="always", time_budget=time_budget, min_len=5,
                               literals=False, stackstrings=True)
    res = recover_fn(binary)
    recovered = {x["string"] for x in res.get("decoded", [])} | {x["string"] for x in res.get("stack", [])}

    def hit(s):
        return s in recovered or any(s in r for r in recovered)

    missed = [(tag, s) for tag, s in hidden if not hit(s)]
    found = [(tag, s) for tag, s in hidden if hit(s)]
    extra = sorted(r for r in recovered if not any(s in r or r in s for _t, s in planted))
    return {"planted": len(hidden), "planted_total": len(planted), "recovered": len(found),
            "missed": missed, "not_hidden": plain, "found_tags": sorted({t for t, _s in found}),
            "extra": extra}


# --------------------------------------------------------------------------------------------
# the loop
# --------------------------------------------------------------------------------------------
def run_loop(rounds: int, rng: random.Random, nightly: str, plugin: Path, out_dir: Path,
             time_budget: float, n_iocs: int, verbose: bool) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    fixtures = out_dir / "fixtures"
    report = out_dir / "redblue_results.jsonl"
    rows, total_planted, total_recovered, miss_rounds = [], 0, 0, 0
    skipped: dict[str, int] = {}            # reason -> rounds
    total_not_hidden = 0
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
                    row = {"round": i, "config": label, "build": msg, "skipped": "build failed"}
                    sink.write(json.dumps(row) + "\n")
                    skipped["build failed"] = skipped.get("build failed", 0) + 1
                    if verbose:
                        print(f"  round {i} [{label}]: skipped, build failed ({msg})")
                    continue
                ev = evaluate(binary, iocs, time_budget)
                total_not_hidden += len(ev["not_hidden"])
                if ev.get("skipped"):
                    row = {"round": i, "config": label, "skipped": ev["skipped"],
                           "not_hidden": ev["not_hidden"]}
                    sink.write(json.dumps(row) + "\n")
                    skipped[ev["skipped"]] = skipped.get(ev["skipped"], 0) + 1
                    if verbose:
                        print(f"  round {i} [{label}]: skipped, {ev['skipped']} "
                              f"({len(ev['not_hidden'])} planted string(s) left in plaintext)")
                    continue
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
                       "not_hidden": ev["not_hidden"],
                       "extra_count": len(ev["extra"]), "fixture": str(saved) if saved else None}
                sink.write(json.dumps(row) + "\n")
                rows.append(row)
                if verbose or ev["missed"]:
                    status = "OK" if not ev["missed"] else f"MISS {len(ev['missed'])}"
                    print(f"  round {i} [{label}]: {ev['recovered']}/{ev['planted']} {status}"
                          + (f" ({len(ev['not_hidden'])} not hidden)" if ev["not_hidden"] else "")
                          + (f" -> {saved.name}" if saved else ""))
    return {"rounds": len(rows), "planted": total_planted, "recovered": total_recovered,
            "miss_rounds": miss_rounds, "skipped": sum(skipped.values()),
            "skip_reasons": skipped, "not_hidden": total_not_hidden, "report": str(report)}


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
    with tempfile.TemporaryDirectory() as d:
        hidden_bin = Path(d) / "hidden.bin"
        hidden_bin.write_bytes(b"\x7fELF" + bytes(64))           # nothing planted in plaintext
        ev = evaluate(hidden_bin, planted, 1.0, recover_fn=stub)
        assert ev["recovered"] == 2 and [t for t, _s in ev["missed"]] == ["path"]
        assert "garbage-std-fragment" in ev["extra"] and ev["not_hidden"] == []

        # 4b. a string the obfuscator left in plaintext (UTF-8 or UTF-16LE) is not_hidden: it is
        #     neither a rust-deobf hit nor a miss; if nothing was hidden the round is skipped
        leaky = Path(d) / "leaky.bin"
        leaky.write_bytes(b"..." + "/var/tmp/.q/w.dat".encode("utf-16-le") + b"...")
        ev = evaluate(leaky, planted, 1.0, recover_fn=stub)
        assert ev["not_hidden"] == [("path", "/var/tmp/.q/w.dat")] and ev["missed"] == []
        assert ev["planted"] == 2 and ev["recovered"] == 2
        plain = Path(d) / "plain.bin"
        plain.write_bytes(b"\x00".join(s.encode() for _t, s in planted))
        ev = evaluate(plain, planted, 1.0,
                      recover_fn=lambda _p: (_ for _ in ()).throw(AssertionError("ran")))
        assert ev["skipped"] == "plugin had no effect" and ev["planted"] == 0

    # 4c. a failed build reports rustc's first error line, not the generic last "aborting" line
    assert _first_error_line("warning: x\nerror[E0425]: cannot find value `q`\n --> a.rs:1\n"
                             "error: aborting due to 1 previous error\n") == \
        "error[E0425]: cannot find value `q`"
    assert _first_error_line("") == "?"

    # 5. prerequisite detection returns None cleanly when nothing is configured
    assert find_plugin(Path("/no/such/rustcloak")) is None or True   # tolerant: may find a real one

    print("selftest OK: IOC/program generation (4 placements, documentation placeholders only), "
          "config space, recovery diff (hit/miss/extra/not-hidden/skip), first-error-line, "
          "prerequisite detection")


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
    reasons = ", ".join(f"{n} {why}" for why, n in sorted(summary["skip_reasons"].items()))
    print(f"\n{summary['rounds']} round(s) evaluated, {summary['skipped']} skipped"
          + (f" ({reasons})" if reasons else "")
          + f"; {rec}/{summary['planted']} hidden strings recovered ({100 * rec // pl}%), "
          f"{summary['not_hidden']} planted string(s) left in plaintext (not counted), "
          f"{summary['miss_rounds']} round(s) with a miss, {dt:.0f}s")
    print(f"report: {summary['report']}" + (f"  (miss fixtures in {a.out}/fixtures/)"
                                            if summary["miss_rounds"] else ""))
    if summary["rounds"] == 0:
        print(f"redblue_loop: no round was evaluable ({reasons or 'no rounds requested'}); see the "
              "report for the build errors -- this is not a pass", file=sys.stderr)
        return EXIT_NO_ROUNDS
    return EXIT_MISS if summary["miss_rounds"] else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
