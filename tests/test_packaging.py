"""Packaging: `pip install rust-deobf` / `rust-deobf-premium` and the `rust-deobf` command.

Two layers:

* fast, static checks (always run, part of the fast CI subset): single-source version, pyproject vs
  requirements.txt, license metadata, the CLI subcommand table, the license boundary (core never
  imports premium), the wheel module list, bare module names that could shadow stdlib/deps;
* the installed-mode tests (slow: build + a fresh venv + dependency install). They run when
  RUST_DEOBF_PACKAGING=1 (the CI `packaging` job and the release workflow) or when
  RUST_DEOBF_WHEEL_DIR points at already-built dists (the release workflow's per-OS check of the
  exact artifacts it will publish). Everything runs from a temp directory OUTSIDE the source tree,
  so a passing test means the wheel works on its own, not the checkout.
  RUST_DEOBF_PACKAGING_OFFLINE=1 reuses this interpreter's site-packages (`--system-site-packages`,
  `pip --no-deps`) instead of downloading the dependencies.
"""
from __future__ import annotations

import ast
import json
import os
import re
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest
from conftest import ROOT

SCRIPTS = ROOT / "scripts"
PREMIUM = ROOT / "premium"
FIXTURE = ROOT / "tests" / "fixtures" / "antiemu" / "rustcloak_antiemu.x64"
FIXTURE_STRING = "rustcloak::flatten-demo::oK"

# cli.py rows for scripts being added in parallel: present-or-not are both fine (skipped at run time)
PENDING = {"decompress", "gen_sigdb", "decompiler_bridge", "recover_idioms", "recover_async",
           "bench_emu"}


def _version() -> str:
    ns: dict = {}
    exec((SCRIPTS / "_version.py").read_text(encoding="utf-8"), ns)
    return ns["__version__"]


def _setup_literal(path: Path, name: str):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(getattr(t, "id", None) == name for t in node.targets):
            return ast.literal_eval(node.value)
    raise AssertionError(f"{name} not found in {path}")


SOURCE_ONLY = _setup_literal(ROOT / "setup.py", "SOURCE_ONLY")


def _cli():
    """scripts/cli.py loaded by path (as `python3 scripts/cli.py` would)."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("rdcli_under_test", SCRIPTS / "cli.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _toml(path: Path) -> dict:
    tomllib = pytest.importorskip("tomllib")          # Python 3.11+
    return tomllib.loads(path.read_text(encoding="utf-8"))


def _shipped_stems():
    return sorted(p.stem for p in SCRIPTS.glob("*.py") if p.stem not in SOURCE_ONLY)


# ----------------------------------------------------------------------------------- fast checks
def test_version_is_single_source():
    v = _version()
    assert re.fullmatch(r"\d+\.\d+\.\d+(?:(?:a|b|rc)\d+)?(?:\.post\d+)?(?:\.dev\d+)?", v), v
    # nobody hard-codes the version elsewhere in the packaging files
    for f in (ROOT / "pyproject.toml", PREMIUM / "pyproject.toml"):
        assert "dynamic" in f.read_text() and f'version = "{v}"' not in f.read_text(), f
    assert f"## [{v}]" in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8"), \
        "CHANGELOG.md has no section for the current version"


def test_pyproject_matches_requirements_txt():
    deps = _toml(ROOT / "pyproject.toml")["project"]["dependencies"]

    def norm(spec: str):
        spec = spec.split(";")[0].split("#")[0].strip().lower().replace(" ", "")
        m = re.match(r"([a-z0-9_.\-]+)(.*)", spec)
        return m.group(1), ",".join(sorted(m.group(2).split(","))) if m.group(2) else ""

    req = [norm(line) for line in (ROOT / "requirements.txt").read_text().splitlines()
           if line.split("#")[0].strip()]
    assert sorted(norm(d) for d in deps) == sorted(req)


def test_license_metadata():
    core = _toml(ROOT / "pyproject.toml")["project"]
    prem = _toml(PREMIUM / "pyproject.toml")["project"]
    assert core["license"] == "Apache-2.0"
    assert prem["license"] == "AGPL-3.0-or-later OR LicenseRef-Commercial"
    assert prem["name"] == "rust-deobf-premium" and core["name"] == "rust-deobf"
    for f in core["license-files"]:
        assert (ROOT / f).is_file(), f
    for f in prem["license-files"]:
        assert (PREMIUM / f).is_file(), f
    assert "AFFERO" in (PREMIUM / "LICENSE").read_text()[:200]
    assert core["requires-python"] == prem["requires-python"] == ">=3.10"
    assert core["scripts"]["rust-deobf"] == "rust_deobf.cli:main"
    setup = (ROOT / "setup.py").read_text()
    assert 'f"rust-deobf-premium=={VERSION}"' in setup                 # premium extra, same version
    assert 'f"rust-deobf=={VERSION}"' in (PREMIUM / "setup.py").read_text()


def test_premium_files_carry_their_license_header():
    for p in sorted(PREMIUM.glob("*.py")):
        head = p.read_text(encoding="utf-8").splitlines()[:6]
        if p.stem in ("__init__", "setup"):
            assert any("SPDX-License-Identifier: AGPL-3.0-or-later" in h for h in head), p


def test_cli_table_points_at_existing_modules():
    cli = _cli()
    for name, module, tier in cli.COMMANDS:
        if tier == cli.PREMIUM:
            assert (PREMIUM / f"{module}.py").is_file(), (name, module)
        elif module not in PENDING:
            assert (SCRIPTS / f"{module}.py").is_file(), (name, module)
        assert module not in SOURCE_ONLY, f"{name} -> {module} is not shipped in the wheel"
    for p in SCRIPTS.glob("*.py"):
        if p.stem in PENDING:
            # a pending script has landed: it must be documented and give a description
            assert cli.describe(p), p


def _imports(path: Path):
    tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                yield a.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            yield node.module.split(".")[0]


def test_shipped_modules_do_not_import_source_only_tools():
    bad = [(s, i) for s in _shipped_stems() for i in _imports(SCRIPTS / f"{s}.py")
           if i in SOURCE_ONLY]
    assert not bad, f"a wheel module imports a tool left out of the wheel (setup.py SOURCE_ONLY): {bad}"
    for s in SOURCE_ONLY:
        assert (SCRIPTS / f"{s}.py").is_file() or s in PENDING, f"SOURCE_ONLY names a missing {s}"


def test_core_never_imports_premium():
    """The license boundary (premium/README.md): Apache-2.0 code must not import AGPL modules.
    The CLI runs premium tools as a separate process instead."""
    premium = {p.stem for p in PREMIUM.glob("*.py")} - {"__init__", "setup"}
    premium |= {"rust_deobf_premium", "premium"}
    bad = [(p.name, i) for p in SCRIPTS.glob("*.py") for i in _imports(p) if i in premium]
    assert not bad, bad


def test_bare_module_names_cannot_shadow_stdlib_or_dependencies():
    """The scripts put their own directory first on sys.path (bare sibling imports); in the CLI
    process that stays so. A module named like a stdlib or dependency module would break them."""
    stdlib = set(getattr(sys, "stdlib_module_names", ()))
    deps = {"lief", "capstone", "unicorn", "z3", "elftools", "yaml", "frida", "yara", "capa",
            "pyghidra", "setuptools", "pip", "pkg_resources", "build", "pytest", "conftest"}
    names = set(_shipped_stems()) | {p.stem for p in PREMIUM.glob("*.py")} | {"data"}
    assert not names & (stdlib | deps), names & (stdlib | deps)


def test_cli_selftest_passes():
    out = subprocess.run([sys.executable, str(SCRIPTS / "cli.py"), "--selftest"],
                         capture_output=True, text=True, timeout=300)
    assert out.returncode == 0 and "selftest OK" in out.stdout, out.stdout + out.stderr


# ------------------------------------------------------------------------- installed-mode tests
SLOW = bool(os.environ.get("RUST_DEOBF_PACKAGING") or os.environ.get("RUST_DEOBF_WHEEL_DIR"))
slow = pytest.mark.skipif(not SLOW, reason="installed-mode packaging test: set "
                          "RUST_DEOBF_PACKAGING=1 (CI packaging job) or RUST_DEOBF_WHEEL_DIR")


def _run(cmd, cwd, timeout=900, check=True, env=None):
    e = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "PYTHONHOME")}
    e.update(env or {})
    r = subprocess.run([str(c) for c in cmd], cwd=str(cwd), capture_output=True, text=True,
                       timeout=timeout, env=e)
    if check and r.returncode != 0:
        raise AssertionError(f"{cmd} -> {r.returncode}\n{r.stdout[-4000:]}\n{r.stderr[-4000:]}")
    return r


@pytest.fixture(scope="module")
def dist(tmp_path_factory):
    given = os.environ.get("RUST_DEOBF_WHEEL_DIR")
    if given:
        d = Path(given).resolve()
    else:
        d = tmp_path_factory.mktemp("dist")
        work = tmp_path_factory.mktemp("buildcwd")
        # (checked in a subprocess from a neutral cwd: the repo's own build/ benchmark dir would
        # satisfy a plain `import build` here as a namespace package)
        if _run([sys.executable, "-m", "build", "--version"], cwd=work, check=False).returncode:
            pytest.skip("python -m build is not installed (pip install build)")
        for src in (ROOT, PREMIUM):
            r = _run([sys.executable, "-m", "build", "--outdir", d, src], cwd=work, check=False)
            if r.returncode != 0 and ("Could not find a version" in r.stderr
                                      or "No matching distribution" in r.stderr):
                pytest.skip("building needs setuptools from an index (offline?)")
            assert r.returncode == 0, r.stdout[-3000:] + r.stderr[-3000:]
    v = _version()
    files = {p.name: p for p in d.iterdir()}
    for f in (f"rust_deobf-{v}-py3-none-any.whl", f"rust_deobf-{v}.tar.gz",
              f"rust_deobf_premium-{v}-py3-none-any.whl", f"rust_deobf_premium-{v}.tar.gz"):
        assert f in files, f"{f} not in {sorted(files)}"
    return d


@pytest.fixture(scope="module")
def venv(dist, tmp_path_factory):
    """A fresh venv with rust-deobf[premium] installed from the built wheels only."""
    root = tmp_path_factory.mktemp("venv")
    offline = bool(os.environ.get("RUST_DEOBF_PACKAGING_OFFLINE"))
    args = [sys.executable, "-m", "venv"] + (["--system-site-packages"] if offline else []) + [root]
    _run(args, cwd=root)
    bindir = root / ("Scripts" if os.name == "nt" else "bin")
    py = bindir / ("python.exe" if os.name == "nt" else "python")
    pip = [py, "-m", "pip", "install", "--disable-pip-version-check", "-q"]
    if offline:
        _run(pip + ["--no-deps", "--no-index", "--find-links", dist,
                    "rust-deobf", "rust-deobf-premium"], cwd=root)
    else:
        _run(pip + ["--find-links", dist, f"rust-deobf[premium]=={_version()}"], cwd=root)
    exe = bindir / ("rust-deobf.exe" if os.name == "nt" else "rust-deobf")
    assert exe.is_file(), f"console script missing: {exe}"
    outside = tmp_path_factory.mktemp("outside")          # cwd for every command: not the repo
    return {"py": py, "exe": exe, "cwd": outside}


@slow
def test_core_wheel_contents(dist):
    v = _version()
    names = zipfile.ZipFile(dist / f"rust_deobf-{v}-py3-none-any.whl").namelist()
    stems = {Path(n).stem for n in names if n.startswith("rust_deobf/") and n.endswith(".py")}
    premium = {p.stem for p in PREMIUM.glob("*.py")} - {"__init__"}
    assert not stems & premium, f"premium code in the Apache-2.0 wheel: {stems & premium}"
    assert not stems & SOURCE_ONLY, stems & SOURCE_ONLY
    assert not [n for n in names if "tests/" in n or "fixtures" in n or n.startswith("premium")]
    assert {"cli", "_version", "__init__", "__main__", "recover", "soc_triage"} <= stems
    for data in ("libfunc_sigs.json", "runtime_sigs.json", "rust_versions.json"):
        assert f"rust_deobf/data/{data}" in names
    meta = zipfile.ZipFile(dist / f"rust_deobf-{v}-py3-none-any.whl").read(
        f"rust_deobf-{v}.dist-info/METADATA").decode()
    assert "License-Expression: Apache-2.0" in meta
    assert f'Requires-Dist: rust-deobf-premium=={v}; extra == "premium"' in meta
    assert re.search(r'Requires-Dist: unicorn.*platform_machine != "ARM64"', meta)
    sdist = tarfile.open(dist / f"rust_deobf-{v}.tar.gz").getnames()
    assert not [n for n in sdist if "/premium/" in n or "/tests/" in n], "core sdist leaks"


@slow
def test_premium_wheel_contents(dist):
    v = _version()
    whl = zipfile.ZipFile(dist / f"rust_deobf_premium-{v}-py3-none-any.whl")
    names = whl.namelist()
    code = [n for n in names if n.endswith(".py")]
    assert code and all(n.startswith("rust_deobf_premium/") for n in code), code
    assert "rust_deobf_premium/setup.py" not in names
    assert not [n for n in code if Path(n).stem in ("recover", "recover_emulate", "cli")]
    meta = whl.read(f"rust_deobf_premium-{v}.dist-info/METADATA").decode()
    assert "License-Expression: AGPL-3.0-or-later OR LicenseRef-Commercial" in meta
    assert f"Requires-Dist: rust-deobf=={v}" in meta
    assert any(n.endswith("licenses/LICENSE-COMMERCIAL.md") for n in names)


@slow
def test_installed_version_list_doctor(venv):
    v = _version()
    r = _run([venv["exe"], "--version"], venv["cwd"])
    assert r.stdout.startswith(f"rust-deobf {v}") and f"premium {v}" in r.stdout, r.stdout
    r = _run([venv["py"], "-m", "rust_deobf", "--version"], venv["cwd"])
    assert r.stdout.startswith(f"rust-deobf {v}")
    rows = json.loads(_run([venv["exe"], "list", "--json"], venv["cwd"]).stdout)
    by = {x["command"]: x for x in rows}
    for c in ("recover", "triage", "unpack", "metadata", "imports", "cfg", "rules", "mcp",
              "doctor", "ghidra", "opaque"):
        assert by[c]["available"], c
    assert all(x["description"] for x in rows if x["available"]), rows
    doc = json.loads(_run([venv["exe"], "doctor", "--json"], venv["cwd"]).stdout)
    assert doc["ok"] and doc["version"] == v, doc
    assert "installed package" in json.dumps(doc)


@slow
def test_installed_recover_smoke(venv):
    r = _run([venv["exe"], "recover", FIXTURE, "--json"], venv["cwd"])
    out = json.loads(r.stdout)
    assert FIXTURE_STRING in [d["string"] for d in out["decoded"]], out["decoded"]
    # the same through python -m, from a cwd whose own recover.py would shadow a sloppy CLI
    (venv["cwd"] / "recover.py").write_text("raise SystemExit('host module imported')\n")
    try:
        r = _run([venv["py"], "-m", "rust_deobf", "recover", FIXTURE, "--json"], venv["cwd"])
        assert FIXTURE_STRING in r.stdout
    finally:
        (venv["cwd"] / "recover.py").unlink()


@slow
def test_installed_premium_runs_and_gates(venv):
    r = _run([venv["exe"], "opaque", "--selftest"], venv["cwd"])
    assert "selftest OK" in r.stdout
    r = _run([venv["exe"], "no-such-tool"], venv["cwd"], check=False)
    assert r.returncode == 2 and "unknown subcommand" in r.stderr


@slow
def test_installed_library_mode(venv):
    """import rust_deobf.X == the bare X the scripts use; the package dir never shadows the host's
    own modules (a host `recover.py` in cwd keeps winning); every shipped module imports."""
    code = r"""
import importlib, pkgutil, sys
import rust_deobf, rust_deobf.recover_emulate as a, recover_emulate as b
assert a is b and a.__name__ == "recover_emulate", (a, b)
d = rust_deobf.__path__[0]
bad = []
for m in pkgutil.iter_modules([d]):
    if m.name.startswith(("_", "ghidra_")):
        continue
    try:
        importlib.import_module("rust_deobf." + m.name)
    except Exception as e:
        bad.append((m.name, repr(e)))
assert not bad, bad
hits = [i for i, e in enumerate(sys.path) if e == d]
assert hits == [len(sys.path) - 1], (hits, sys.path)
open("recover.py", "w").write("WHO = 'host'\n")      # the host program's own recover.py
importlib.invalidate_caches()
sys.modules.pop("recover", None)
import recover
assert getattr(recover, "WHO", None) == "host", recover
import rust_deobf_premium.deobf_opaque as p, deobf_opaque as q
assert p is q
print("library-mode OK")
"""
    try:
        r = _run([venv["py"], "-c", code], venv["cwd"])
    finally:
        if (venv["cwd"] / "recover.py").exists():
            (venv["cwd"] / "recover.py").unlink()
    assert "library-mode OK" in r.stdout
