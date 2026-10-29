#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Ve (VAHPEM) <ve0912084386@gmail.com>
"""cli.py - the `rust-deobf` command: one entry point that dispatches to the toolkit's scripts.

    rust-deobf <subcommand> [args...]   runs that script's main(), exactly like
                                        `python3 scripts/<module>.py [args...]` from a clone
    rust-deobf list [--json]            every subcommand with a one-line description
    rust-deobf doctor [--json]          check Python, dependencies, platform and optional tools
    rust-deobf ghidra <bin> [json] [project_dir] [--dry-run]
                                        recover + import + annotate in Ghidra, headless (PyGhidra)
    rust-deobf --version

Also `python -m rust_deobf ...` (installed) and `python3 scripts/cli.py ...` (a clone, no install).
Arguments after the subcommand are passed through untouched, so `rust-deobf recover --help` is
recover.py's own help. Premium subcommands (AGPL-3.0-or-later OR commercial) need the separate
`rust-deobf-premium` distribution (pip install "rust-deobf[premium]") and run as their own Python
process: this Apache-2.0 core never imports premium code (premium/README.md).

To add a tool: add one row to COMMANDS below. A row whose module is not present at run time (a
script not merged yet, premium not installed) is skipped or reported, never an error.
"""
from __future__ import annotations

import importlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_PACKAGED = bool(__package__)              # rust_deobf.cli (installed / -m) vs scripts/cli.py

if _PACKAGED:
    from ._version import __version__
else:                                      # python3 scripts/cli.py from a clone
    _ns: dict = {}
    exec(compile((_HERE / "_version.py").read_text(encoding="utf-8"), str(_HERE / "_version.py"),
                 "exec"), _ns)
    __version__ = _ns["__version__"]

PROG = "rust-deobf"
REPO_URL = "https://github.com/VAHPEM/rust-deobf"
PREMIUM_HINT = 'pip install "rust-deobf[premium]"   (AGPL-3.0-or-later OR commercial; see LICENSING.md)'

CORE, PREMIUM = "core", "premium"

# subcommand -> script module. Order is the order of `rust-deobf list`. One row per tool; the
# description comes from the script's own docstring. Engine internals whose own CLI is a benchmark
# harness (recover_emulate, recover_callsite, recover_arm64) are reached through `recover`.
COMMANDS = (
    # front ends
    ("recover",       "recover",               CORE),
    ("triage",        "soc_triage",            CORE),
    ("llm-triage",    "llm_triage",            CORE),
    ("mcp",           "mcp_server",            CORE),
    ("rules",         "export_rules",          CORE),
    # unpacking
    ("unpack",        "unpack",                CORE),
    ("unpack-emulate", "unpack_emulate",       CORE),
    ("dump",          "dump_unpacked",         CORE),
    ("decompress",    "decompress",            CORE),
    # structure / metadata
    ("metadata",      "recover_rust_meta",     CORE),
    ("strings",       "recover_rust_strings",  CORE),
    ("stackstrings",  "recover_stackstrings",  CORE),
    ("libfuncs",      "recover_libfuncs",      CORE),
    ("gen-sigdb",     "gen_sigdb",             CORE),
    ("types",         "recover_types",         CORE),
    ("enums",         "recover_enums",         CORE),
    ("idioms",        "recover_idioms",        CORE),
    ("async",         "recover_async",         CORE),
    ("go",            "recover_go",            CORE),
    ("imports",       "recover_imports",       CORE),
    ("cfg",           "recover_cfg",           CORE),
    ("behavior",      "recover_behavior",      CORE),
    ("lang",          "recover_lang",          CORE),
    ("crypto",        "recover_crypto",        CORE),
    ("apihash",       "recover_apihash",       CORE),
    ("cryptify",      "recover_cryptify",      CORE),
    ("antianalysis",  "recover_antianalysis",  CORE),
    ("detect-vm",     "detect_vm",             CORE),
    ("blobs",         "recover_blobs",         CORE),
    ("embedded",      "recover_embedded",      CORE),
    ("decompiler",    "decompiler_bridge",     CORE),
    # dynamic (Frida; RUNS the sample - isolated VM only, each tool has its own guard)
    ("dynamic",       "recover_dynamic",       CORE),
    ("artifacts",     "recover_artifacts",     CORE),
    # measurement
    ("bench-emu",     "bench_emu",             CORE),
    # premium (rust-deobf-premium)
    ("cff",           "deobf_cff",             PREMIUM),
    ("deflatten",     "deobf_deflatten",       PREMIUM),
    ("expr",          "deobf_expr",            PREMIUM),
    ("opaque",        "deobf_opaque",          PREMIUM),
    ("opt-reverse",   "opt_reverse",           PREMIUM),
    ("devirt",        "devirt_emulate",        PREMIUM),
    ("lift-vm",       "lift_vm",               PREMIUM),
)

BUILTINS = {
    "list": "list every subcommand with a one-line description (--json)",
    "doctor": "check Python, dependencies, platform notes and optional tools (--json)",
    "ghidra": "recover strings/vtables and annotate them in Ghidra, headless (PyGhidra)",
}

# import name -> what to install when it is missing
_INSTALL_HINT = {
    "lief": "lief>=0.16", "capstone": "capstone>=5,<6", "unicorn": "unicorn>=2.1,<3",
    "z3": "z3-solver", "elftools": "pyelftools", "yaml": "pyyaml",
    "frida": '"rust-deobf[dynamic]"  (frida, frida-tools)', "yara": '"rust-deobf[rules]"',
    "capa": '"rust-deobf[rules]"',
}

# a path in a FileNotFoundError that only exists in a source checkout
_SOURCE_ONLY_PARTS = ("bench_src", "tests" + os.sep + "fixtures", "tests/fixtures", "obf_src")


def _err(msg: str) -> None:
    print(f"{PROG}: {msg}", file=sys.stderr)


def _win_arm64_native() -> bool:
    return sys.platform == "win32" and platform.machine().upper() == "ARM64"


WIN_ARM64_NOTE = ("Windows ARM64 *native* Python cannot run rust-deobf: unicorn and capstone<6 "
                  "publish no win_arm64 wheels. Install the x64 build of Python (it runs under "
                  "Windows-on-ARM emulation) and `pip install rust-deobf` into it.")


# ---------------------------------------------------------------------------------------------
# locating modules
# ---------------------------------------------------------------------------------------------
def premium_location():
    """(directory, version, how) of the premium modules, or None.

    A clone uses its own premium/ directory (same version by construction); an installed core uses
    the `rust_deobf_premium` distribution. Found WITHOUT importing it: the Apache-2.0 core never
    imports premium (AGPL) code -- premium tools run in their own process (see run_premium)."""
    if not _PACKAGED:
        clone = _HERE.parent / "premium"
        if clone.is_dir() and any(clone.glob("*.py")):
            return clone, __version__, "source checkout"
    try:
        import importlib.util
        spec = importlib.util.find_spec("rust_deobf_premium")
    except (ImportError, ValueError):
        spec = None
    if spec is None or not spec.submodule_search_locations:
        return None
    directory = Path(list(spec.submodule_search_locations)[0]).resolve()
    return directory, _dist_version("rust-deobf-premium"), "installed"


def module_file(module: str, tier: str, premium=None):
    if tier == PREMIUM:
        if premium is None:
            return None
        p = premium[0] / f"{module}.py"
    else:
        p = _HERE / f"{module}.py"
    return p if p.is_file() else None


_DOC_RE = re.compile(r'\A(?:[ \t]*(?:#[^\n]*)?\n)*[ \t]*[rRuU]?("""|\'\'\')(.*?)\1', re.S)


def describe(path: Path) -> str:
    """One line from a script's module docstring (without reading the whole AST)."""
    try:
        head = path.read_text(encoding="utf-8", errors="replace")[:8192]
    except OSError:
        return ""
    m = _DOC_RE.match(head)
    if not m:
        return ""
    para = m.group(2).strip().split("\n\n")[0]
    text = " ".join(line.strip() for line in para.splitlines())
    text = re.sub(r"^[\w.]+\.py\s*(?:-|—|:)\s*", "", text)        # "recover.py - ..." prefix
    for cut in re.finditer(r"[.;](?:\s|$)", text):       # first sentence (not "Tier 2:")
        if cut.start() > 20:
            text = text[:cut.start()]
            break
    text = text.rstrip(" .")
    if len(text) > 96:
        text = text[:93].rstrip() + "..."
    return text


def commands(premium="auto"):
    """[(subcommand, module, tier, path-or-None, description)] for every table row whose module
    exists (premium rows are kept with path None when premium is missing)."""
    if premium == "auto":
        premium = premium_location()
    rows = []
    for name, module, tier in COMMANDS:
        path = module_file(module, tier, premium)
        if path is None and tier == CORE:
            continue                      # not merged / not shipped in this build: skip quietly
        rows.append((name, module, tier, path, describe(path) if path else ""))
    return rows


def _lookup(word: str):
    for name, module, tier in COMMANDS:
        if word in (name, module):
            return name, module, tier
    return None


# ---------------------------------------------------------------------------------------------
# dispatch
# ---------------------------------------------------------------------------------------------
def _prepare_path(directories) -> None:
    """Put the script directories first on sys.path -- what `python3 scripts/x.py` does -- and
    switch the installed package out of library mode for this process."""
    if _PACKAGED:
        try:
            pkg = importlib.import_module(__package__)
            pkg.set_library_mode(False)
        except (ImportError, AttributeError):
            pass
    for d in reversed([str(d) for d in directories]):
        if not sys.path or sys.path[0] != d:
            sys.path.insert(0, d)


def _defines_main(path: Path) -> bool:
    try:
        return re.search(r"^def main\(", path.read_text(encoding="utf-8", errors="replace"),
                         re.M) is not None
    except OSError:
        return False


def _source_only(exc: FileNotFoundError) -> bool:
    if (_HERE.parent / "tests").is_dir():
        return False                      # a clone: the file really is missing, report as is
    s = str(exc.filename or exc)
    return any(part in s for part in _SOURCE_ONLY_PARTS)


def run_script(name: str, path: Path, argv, directories) -> object:
    """Run one script as `rust-deobf <name>`: its main() with sys.argv set, or (no main()) the file
    itself as __main__. Returns what main() returned (the sys.exit value)."""
    module = path.stem
    _prepare_path(directories)
    saved_argv = sys.argv
    sys.argv = [f"{PROG} {name}", *argv]
    try:
        if not _defines_main(path):
            import runpy
            runpy.run_path(str(path), run_name="__main__")
            return 0
        try:
            mod = importlib.import_module(module)
        except ImportError as e:
            missing = (getattr(e, "name", None) or "").split(".")[0]
            _err(f"{name}: cannot load {module}: {e}")
            if missing in ("capstone", "unicorn") and _win_arm64_native():
                _err(WIN_ARM64_NOTE)
            elif missing in _INSTALL_HINT:
                _err(f"install it with: pip install {_INSTALL_HINT[missing]}"
                     "   (or run `rust-deobf doctor`)")
            return 3
        origin = getattr(mod, "__file__", None)
        if not origin or os.path.normcase(str(Path(origin).resolve())) != \
                os.path.normcase(str(path)):
            _err(f"{name}: the module name {module!r} resolves to {origin or mod!r}, not {path} "
                 "(another module of that name shadows it on sys.path)")
            return 3
        return mod.main()
    except FileNotFoundError as e:
        if _source_only(e):
            _err(f"{name}: this needs files from a source checkout ({e.filename}), which the "
                 f"installed package does not ship. Use a git clone: {REPO_URL}")
            return 2
        raise
    except KeyboardInterrupt:
        return 130
    finally:
        sys.argv = saved_argv


def _dispatch(word: str, argv) -> object:
    hit = _lookup(word)
    if hit is None:
        _err(f"unknown subcommand {word!r}. `{PROG} list` shows them all.")
        return 2
    name, module, tier = hit
    premium = premium_location() if tier == PREMIUM else None
    if tier == PREMIUM:
        if premium is None:
            _err(f"{name} is a premium module ({module}); it is not installed.\n  {PREMIUM_HINT}")
            return 2
        if premium[1] != __version__:
            _err(f"version mismatch: rust-deobf {__version__} but rust-deobf-premium "
                 f"{premium[1]} (they must match). Upgrade both together:\n"
                 f'  pip install -U "rust-deobf[premium]=={__version__}"   or   '
                 f'pip install -U "rust-deobf[premium]"')
            return 2
    path = module_file(module, tier, premium)
    if path is None:
        _err(f"{name}: module {module} is not part of this rust-deobf build ({__version__}).")
        return 2
    if tier == PREMIUM:
        return run_premium(name, path, argv)
    return run_script(name, path, argv, [_HERE])


def run_premium(name: str, path: Path, argv) -> int:
    """Run a premium (AGPL-3.0-or-later OR commercial) tool as a separate program: its own Python
    process, `python <premium>/<module>.py args`, with the core directory on PYTHONPATH for the
    core modules it imports. The Apache-2.0 core never imports premium code in-process (the license
    boundary in premium/README.md); the exit code is passed through."""
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(_HERE)] + [p for p in
                                         env.get("PYTHONPATH", "").split(os.pathsep) if p])
    try:
        return subprocess.call([sys.executable, str(path), *argv], env=env)
    except KeyboardInterrupt:
        return 130


# ---------------------------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------------------------
def cmd_list(argv) -> int:
    as_json = "--json" in argv
    premium = premium_location()
    rows = commands(premium)
    if as_json:
        out = [{"command": n, "module": m, "tier": t, "available": p is not None,
                "description": d} for n, m, t, p, d in rows]
        out += [{"command": n, "module": None, "tier": "builtin", "available": True,
                 "description": d} for n, d in BUILTINS.items()]
        print(json.dumps(out, indent=2))
        return 0
    width = max(len(n) for n, *_ in rows + [(b,) for b in BUILTINS]) + 2
    print(f"{PROG} {__version__}  ({'installed' if _PACKAGED else 'source checkout'})\n")
    print("built-in:")
    for n, d in BUILTINS.items():
        print(f"  {n:<{width}}{d}")
    print("\ncore (Apache-2.0):")
    for n, m, t, p, d in rows:
        if t == CORE:
            print(f"  {n:<{width}}{d}")
    state = (f"{premium[2]}, {premium[1]}" if premium else "not installed: " + PREMIUM_HINT)
    print(f"\npremium (AGPL-3.0-or-later OR commercial; {state}):")
    for n, m, t, p, d in rows:
        if t == PREMIUM:
            print(f"  {n:<{width}}{d or '(not installed)'}")
    print(f"\n`{PROG} <command> --help` for a command's options.")
    return 0


# ---------------------------------------------------------------------------------------------
# doctor
# ---------------------------------------------------------------------------------------------
OK, WARN, FAIL, INFO = "ok", "warn", "FAIL", "info"

# (import name, distribution, required, min version, exclusive max version, what it is for)
_DEPS = (
    ("lief", "lief", True, (0, 16), None, "binary parsing (ELF/PE/Mach-O)"),
    ("capstone", "capstone", True, (5, 0), (6, 0), "disassembly; <6: the code uses CS_ARCH_ARM64"),
    ("unicorn", "unicorn", True, (2, 1), (3, 0), "emulation engine"),
    ("z3", "z3-solver", True, None, None, "expression / opaque-predicate solving"),
    ("yaml", "pyyaml", True, None, None, "capa rule round-trip (export_rules)"),
    ("elftools", "pyelftools", False, None, None, "DWARF enum names (recover_enums; optional)"),
)
_OPTIONAL = (
    ("frida", "frida", "dynamic recovery (recover_dynamic, dump_unpacked) - rust-deobf[dynamic]"),
    ("yara", "yara-python", "compile-check exported YARA rules - rust-deobf[rules]"),
    ("capa", "flare-capa", "load exported capa rules - rust-deobf[rules]"),
    ("pyghidra", "pyghidra", "Ghidra annotation (`rust-deobf ghidra` installs it from Ghidra)"),
)


def _vtuple(v: str):
    out = []
    for part in re.split(r"[.+-]", v or ""):
        if not part.isdigit():
            break
        out.append(int(part))
    return tuple(out)


def _dist_version(dist: str, mod=None) -> str:
    try:
        from importlib.metadata import version
        return version(dist)
    except Exception:  # noqa: BLE001 - not installed as a distribution (vendored, source build)
        return str(getattr(mod, "__version__", "") or "?")


def cache_dir() -> Path:
    """Where rust-deobf tools keep per-user caches (e.g. a signature DB). Documented in README."""
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    elif sys.platform == "darwin":
        base = str(Path.home() / "Library" / "Caches")
    else:
        base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "rust-deobf"


def _ghidra_dir():
    d = os.environ.get("GHIDRA_INSTALL_DIR")
    if d:
        return Path(d)
    ah = shutil.which("analyzeHeadless")
    if ah:
        cand = Path(os.path.realpath(ah)).parent.parent
        if (cand / "Ghidra").is_dir():
            return cand
    return None


def doctor_checks(heavy: bool = True):
    """[(status, check, detail)]. heavy=False skips importing the optional packages."""
    checks = []
    add = lambda s, c, d: checks.append((s, c, d))  # noqa: E731

    v = sys.version_info
    add(OK if v >= (3, 10) else FAIL, "python",
        f"{platform.python_version()} ({platform.python_implementation()}, "
        f"{8 * __import__('struct').calcsize('P')}-bit) at {sys.executable}"
        + ("" if v >= (3, 10) else " - rust-deobf needs Python >= 3.10"))
    add(INFO, "platform", f"{sys.platform} / {platform.machine() or '?'} / {platform.platform()}")
    if _win_arm64_native():
        add(FAIL, "platform", WIN_ARM64_NOTE)
    elif sys.platform == "win32":
        add(INFO, "platform", "Windows: no fork/forkserver (emulation workers use spawn); on "
            "Windows-on-ARM use x64 Python")
    add(INFO, "install", f"{PROG} {__version__}, "
        + (f"installed package at {_HERE}" if _PACKAGED else f"source checkout at {_HERE.parent}"))

    for imp, dist, required, lo, hi, note in _DEPS:
        try:
            mod = importlib.import_module(imp)
        except Exception as e:  # noqa: BLE001 - any import failure is the finding
            why = WIN_ARM64_NOTE if (_win_arm64_native() and imp in ("capstone", "unicorn")) \
                else f"pip install {_INSTALL_HINT.get(imp, dist)}"
            add(FAIL if required else WARN, imp, f"not importable ({type(e).__name__}: {e}); {why}")
            continue
        ver = _dist_version(dist, mod)
        vt = _vtuple(ver)
        bad = (lo and vt and vt < lo) or (hi and vt and vt >= hi)
        rng = (f" (need >={'.'.join(map(str, lo))}" if lo else "") + \
              (f",<{'.'.join(map(str, hi))})" if hi else (")" if lo else ""))
        if bad:
            add(FAIL, imp, f"{dist} {ver}{rng}: pip install \"{_INSTALL_HINT.get(imp, dist)}\"")
        else:
            add(OK, imp, f"{dist} {ver} - {note}")

    # unicorn is importable but can it actually emulate? (a broken native lib fails here)
    try:
        from unicorn import Uc, UC_ARCH_X86, UC_MODE_64
        uc = Uc(UC_ARCH_X86, UC_MODE_64)
        uc.mem_map(0x1000, 0x1000)
        uc.mem_write(0x1000, b"\x48\x31\xc0")                     # xor rax, rax
        uc.emu_start(0x1000, 0x1003)
        add(OK, "unicorn-run", "emulated an x86-64 instruction")
        del uc
    except ImportError:
        pass
    except Exception as e:  # noqa: BLE001
        add(FAIL, "unicorn-run", f"unicorn imports but cannot emulate: {type(e).__name__}: {e}")

    for name in ("libfunc_sigs.json", "runtime_sigs.json", "rust_versions.json"):
        p = _HERE / "data" / name
        add(OK if p.is_file() else WARN, f"data/{name}",
            "present" if p.is_file() else f"missing at {p} (reinstall rust-deobf)")

    prem = premium_location()
    if prem is None:
        add(INFO, "premium", f"not installed (optional): {PREMIUM_HINT}")
    elif prem[1] != __version__:
        add(FAIL, "premium", f"rust-deobf-premium {prem[1]} != rust-deobf {__version__}: "
            'pip install -U "rust-deobf[premium]"')
    else:
        add(OK, "premium", f"{prem[1]} ({prem[2]}) at {prem[0]}")

    if heavy:
        for imp, dist, note in _OPTIONAL:
            try:
                mod = importlib.import_module(imp)
                add(OK, imp, f"{dist} {_dist_version(dist, mod)} - {note}")
            except Exception:  # noqa: BLE001
                add(INFO, imp, f"not installed (optional) - {note}")
    for tool, note in (("rustup", "toolchains for building signature DBs (gen_sigdb)"),
                       ("cargo", "building signature DBs (gen_sigdb)")):
        w = shutil.which(tool)
        add(OK if w else INFO, tool, f"{w} - {note}" if w else f"not on PATH (optional) - {note}")
    g = _ghidra_dir()
    if g and (g / "Ghidra").is_dir():
        add(OK, "ghidra", f"{g}")
    elif g:
        add(WARN, "ghidra", f"GHIDRA_INSTALL_DIR={g} has no ./Ghidra")
    else:
        add(INFO, "ghidra", "not found (optional): set GHIDRA_INSTALL_DIR for `rust-deobf ghidra`")
    c = cache_dir()
    add(INFO, "cache", f"{c} ({'exists' if c.is_dir() else 'not created yet'}); safe to delete")
    return checks


def cmd_doctor(argv) -> int:
    checks = doctor_checks(heavy="--quick" not in argv)
    failed = [c for c in checks if c[0] == FAIL]
    if "--json" in argv:
        print(json.dumps({"version": __version__, "ok": not failed,
                          "checks": [{"status": s, "check": c, "detail": d} for s, c, d in checks]},
                         indent=2))
    else:
        w = max(len(c) for _, c, _ in checks) + 2
        for s, c, d in checks:
            print(f"[{s:>4}] {c:<{w}}{d}")
        print(f"\n{PROG} doctor: " + (f"{len(failed)} problem(s) - see FAIL lines" if failed
                                     else "everything required is in place"))
    return 1 if failed else 0


# ---------------------------------------------------------------------------------------------
# ghidra (a portable port of scripts/ghidra_run.sh: no bash needed, works installed)
# ---------------------------------------------------------------------------------------------
def cmd_ghidra(argv) -> int:
    import argparse
    ap = argparse.ArgumentParser(
        prog=f"{PROG} ghidra",
        description="Recover strings (+ trait-object vtables) from BINARY and annotate them in a "
                    "headless Ghidra project via PyGhidra. Never executes the binary. Same steps "
                    "as scripts/ghidra_run.sh. Needs GHIDRA_INSTALL_DIR (or analyzeHeadless on "
                    "PATH).")
    ap.add_argument("binary")
    ap.add_argument("recovered_json", nargs="?", help="an existing `recover --json` output")
    ap.add_argument("project_dir", nargs="?", help="Ghidra project dir (default: a new temp dir)")
    ap.add_argument("--dry-run", action="store_true", help="print the commands, run nothing")
    a = ap.parse_args(argv)

    binary = os.path.abspath(a.binary)
    if not a.dry_run and not os.path.isfile(binary):
        _err(f"ghidra: no such file: {a.binary}")
        return 2
    gdir = _ghidra_dir()
    if not a.dry_run and (gdir is None or not (gdir / "Ghidra").is_dir()):
        _err("ghidra: set GHIDRA_INSTALL_DIR to your Ghidra install (the dir with ./Ghidra and "
             "./support), or put analyzeHeadless on PATH")
        return 2
    env = dict(os.environ)
    if gdir:
        env["GHIDRA_INSTALL_DIR"] = str(gdir)
    py = sys.executable

    def run(cmd, **kw):
        if a.dry_run:
            print("+ " + " ".join(str(c) for c in cmd))
            return subprocess.CompletedProcess(cmd, 0, "{}", "")
        return subprocess.run([str(c) for c in cmd], env=env, **kw)

    if not a.dry_run:
        try:
            import pyghidra  # noqa: F401
        except ImportError:
            whl = sorted((gdir / "Ghidra" / "Features" / "PyGhidra" / "pypkg" / "dist")
                         .glob("pyghidra-*.whl"))
            target = str(whl[-1]) if whl else "pyghidra"
            print(f"ghidra: installing {target} into {py}", file=sys.stderr)
            if run([py, "-m", "pip", "install", "-q", target]).returncode != 0:
                _err("ghidra: could not install pyghidra")
                return 2

    tmp = []
    try:
        js = a.recovered_json
        if not js:
            fd, js = tempfile.mkstemp(prefix="rd-recover.", suffix=".json")
            os.close(fd)
            tmp.append(js)
            print(f"ghidra: recovering strings -> {js}", file=sys.stderr)
            with open(js, "w", encoding="utf-8") as fh:
                rc = run([py, _HERE / "recover.py", "--json", "--", binary], stdout=fh).returncode
            if rc == 4:
                print("ghidra: warning: an engine failed (see the notes in the JSON); annotating "
                      "what was recovered", file=sys.stderr)
            elif rc != 0:
                _err(f"ghidra: recover failed (exit {rc}); nothing to annotate")
                return rc
            # best effort, never fatal: merge trait-object vtables for ghidra_annotate
            types = run([py, _HERE / "recover_types.py", "--json", "--", binary],
                        capture_output=True, text=True)
            if types.returncode == 0 and not a.dry_run:
                try:
                    t = json.loads(types.stdout)
                    with open(js, encoding="utf-8") as fh:
                        data = json.load(fh)
                    data["vtables"] = t.get("vtables", [])
                    data["ghidra_types"] = t.get("ghidra_types", [])
                    with open(js, "w", encoding="utf-8") as fh:
                        json.dump(data, fh)
                except (ValueError, OSError, AttributeError):
                    pass
        proj = a.project_dir or (tempfile.mkdtemp(prefix="rd-ghidra.") if not a.dry_run
                                 else "<temp project dir>")
        if not a.dry_run:
            os.makedirs(proj, exist_ok=True)
        print(f"ghidra: importing {os.path.basename(binary)} into {proj}", file=sys.stderr)
        rc = run([py, "-m", "pyghidra.ghidra_launch", "ghidra.app.util.headless.AnalyzeHeadless",
                  proj, "rd_proj", "-import", binary, "-overwrite",
                  "-postScript", _HERE / "ghidra_annotate.py", js]).returncode
        if rc == 0:
            print(f"ghidra: done. Open project '{os.path.join(proj, 'rd_proj')}' in Ghidra.",
                  file=sys.stderr)
        return rc
    finally:
        for p in tmp:
            try:
                os.unlink(p)
            except OSError:
                pass


# ---------------------------------------------------------------------------------------------
def usage() -> str:
    return (f"usage: {PROG} <command> [args...]   |   {PROG} list   |   {PROG} doctor   |   "
            f"{PROG} --version\n\n"
            "Deobfuscation and triage for (Rust) binaries: ELF / PE / Mach-O, x86-64 / ARM64 / x86.\n"
            "Static + emulation by default; nothing executes the sample unless a tool says so.\n\n"
            f"common: recover, triage, unpack, metadata, imports, cfg, crypto, rules, mcp\n"
            f"`{PROG} list` shows every command; `{PROG} <command> --help` its options.")


def version_string() -> str:
    prem = premium_location()
    extra = f" (premium {prem[1]}, {prem[2]})" if prem else ""
    return f"{PROG} {__version__}{extra}"


def main(argv=None) -> object:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help", "help"):
        if len(argv) >= 2 and argv[0] == "help":
            return main([argv[1], "--help"])
        print(usage())
        return 0 if argv else 2
    word, rest = argv[0], argv[1:]
    if word in ("-V", "--version", "version"):
        print(version_string())
        return 0
    if word == "--selftest":
        _selftest()
        return 0
    if word == "list":
        return cmd_list(rest)
    if word == "doctor":
        return cmd_doctor(rest)
    if word == "ghidra":
        return cmd_ghidra(rest)
    try:
        return _dispatch(word, rest)
    except BrokenPipeError:               # `rust-deobf recover x --json | head`: not an error
        try:
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, sys.stdout.fileno())      # no second traceback at interpreter exit
        except (OSError, ValueError):
            pass
        return 141 if os.name != "nt" else 1


# ---------------------------------------------------------------------------------------------
def _selftest() -> None:
    import contextlib
    import io

    # the table: unique names/modules, no clash with the built-ins, every present core module has
    # a description, and the tools every user relies on are present
    names = [n for n, _, _ in COMMANDS]
    mods = [m for _, m, _ in COMMANDS]
    assert len(set(names)) == len(names) and len(set(mods)) == len(mods)
    assert not set(names) & set(BUILTINS)
    present = {m for _, m, t, p, _ in commands(premium=None) if p}
    for must in ("recover", "soc_triage", "unpack", "recover_rust_meta", "export_rules",
                 "mcp_server", "recover_imports", "recover_cfg"):
        assert must in present, must
    for n, m, t, p, d in commands(premium=None):
        assert p is None or d, f"{m}: no docstring description"
    assert describe(_HERE / "recover.py").startswith("unified string-recovery front end")
    assert re.fullmatch(r"\d+\.\d+\.\d+(?:(?:a|b|rc)\d+)?(?:\.post\d+)?(?:\.dev\d+)?", __version__)
    assert _lookup("triage")[1] == "soc_triage" and _lookup("soc_triage")[0] == "triage"
    assert _vtuple("5.0.6") == (5, 0, 6) and _vtuple("2.1.4.post1") == (2, 1, 4)

    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        # a main() that sees `rust-deobf <name> args` in sys.argv and returns an exit code
        (d / "rdcli_probe_main.py").write_text(
            "import sys\nSEEN = None\n"
            "def main():\n    global SEEN\n    SEEN = list(sys.argv)\n    return 7\n")
        # no main(): the file runs as __main__, like `python3 x.py`
        (d / "rdcli_probe_nomain.py").write_text(
            "import sys\nif __name__ == '__main__':\n    sys.modules['rdcli_probe_main'].SEEN = "
            "['nomain'] + sys.argv[1:]\n")
        # a source-checkout-only path in an installed package -> clear message, exit 2
        (d / "rdcli_probe_src.py").write_text(
            "def main():\n    raise FileNotFoundError(2, 'No such file', "
            "'/x/bench_src/manifest.json')\n")
        saved_path, saved_argv = list(sys.path), list(sys.argv)
        try:
            rc = run_script("probe", d / "rdcli_probe_main.py", ["--json", "a b"], [d])
            assert rc == 7, rc
            probe = sys.modules["rdcli_probe_main"]
            assert probe.SEEN == [f"{PROG} probe", "--json", "a b"], probe.SEEN
            assert sys.argv == saved_argv                      # restored
            rc = run_script("probe2", d / "rdcli_probe_nomain.py", ["x"], [d])
            assert rc == 0 and probe.SEEN == ["nomain", "x"], (rc, probe.SEEN)
            err = io.StringIO()
            here = _HERE
            try:
                globals()["_HERE"] = d                         # pretend: installed (no tests/)
                with contextlib.redirect_stderr(err):
                    rc = run_script("probe3", d / "rdcli_probe_src.py", [], [d])
            finally:
                globals()["_HERE"] = here
            assert rc == 2 and "source checkout" in err.getvalue(), (rc, err.getvalue())
        finally:
            sys.path[:] = saved_path
            sys.argv[:] = saved_argv
            for m in ("rdcli_probe_main", "rdcli_probe_src"):
                sys.modules.pop(m, None)

        # a premium tool runs as its own process, the core dir on its PYTHONPATH, exit code kept
        (d / "rdcli_probe_prem.py").write_text(
            "import os, sys\n"
            f"ok = {str(_HERE)!r} in os.environ.get('PYTHONPATH', '').split(os.pathsep)\n"
            "sys.exit(5 if ok and sys.argv[1:] == ['--json', 'x'] else 1)\n")
        assert run_premium("probe4", d / "rdcli_probe_prem.py", ["--json", "x"]) == 5
        assert "rdcli_probe_prem" not in sys.modules

    # unknown command / premium-missing are usage errors (2), not crashes
    with contextlib.redirect_stderr(io.StringIO()) as err:
        assert _dispatch("no-such-command", []) == 2
    assert "unknown subcommand" in err.getvalue()
    g = globals()
    real = g["premium_location"]
    try:
        g["premium_location"] = lambda: None
        with contextlib.redirect_stderr(io.StringIO()) as err:
            assert _dispatch("opaque", ["x"]) == 2
        assert "rust-deobf[premium]" in err.getvalue()
        g["premium_location"] = lambda: (_HERE, "0.0.0-other", "installed")
        with contextlib.redirect_stderr(io.StringIO()) as err:
            assert _dispatch("opaque", ["x"]) == 2
        assert "version mismatch" in err.getvalue()
    finally:
        g["premium_location"] = real

    # list / --version / ghidra --dry-run print without touching a binary
    with contextlib.redirect_stdout(io.StringIO()) as out:
        assert cmd_list(["--json"]) == 0
    rows = json.loads(out.getvalue())
    assert any(r["command"] == "recover" and r["available"] for r in rows)
    with contextlib.redirect_stdout(io.StringIO()) as out:
        assert main(["--version"]) == 0
    assert out.getvalue().startswith(f"{PROG} {__version__}")
    with contextlib.redirect_stdout(io.StringIO()) as out, \
            contextlib.redirect_stderr(io.StringIO()):
        assert cmd_ghidra(["sample.bin", "--dry-run"]) == 0
    assert "ghidra_annotate.py" in out.getvalue() and "recover.py" in out.getvalue()

    # doctor (no optional imports) reports the interpreter and every required dependency
    checks = doctor_checks(heavy=False)
    seen = {c for _, c, _ in checks}
    assert {"python", "lief", "capstone", "unicorn", "z3", "premium", "cache"} <= seen, seen
    print(f"selftest OK: {len(COMMANDS)} table rows ({len(present)} core present), dispatch "
          "(main/argv/exit code, no-main __main__, source-only message), premium subprocess + gating, "
          "list, "
          "--version, ghidra --dry-run, doctor")


if __name__ == "__main__":
    sys.exit(main())
