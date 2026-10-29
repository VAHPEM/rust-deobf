# SPDX-License-Identifier: Apache-2.0
"""Build-time logic for the rust-deobf (core) distribution; static metadata is in pyproject.toml.

Three things a static pyproject.toml cannot express:
  * the version, read from scripts/_version.py (the single source of truth);
  * the `premium` extra, pinned to exactly the same version of rust-deobf-premium (the premium
    modules import core internals, so mismatched versions are unsupported);
  * the wheel's module list: SOURCE_ONLY tools are left out of the wheel/sdist because they need a
    source checkout (bench_src/, build/, tests/fixtures/, the RustCloak tree) or write into their
    own directory. They keep working from a clone exactly as before.
Nothing here runs when the scripts are used from a clone.
"""
import re
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py as _build_py

HERE = Path(__file__).resolve().parent

# keep in step with CLAUDE.md "Eval/measurement only"; tests/test_packaging.py checks that no shipped
# module imports one of these and that the cli table does not point at one
SOURCE_ONLY = {
    "eval_scatter",       # reads bench_src/manifest.json at import
    "run_floss",          # reads bench_src/manifest.json at import
    "evaluate_all",       # benchmark report over build/ -> METRICS.md
    "heldout_eval",       # held-out benchmark evaluation
    "measure_fp",         # FP corpus measurement, writes build/
    "measure_rust_meta",  # labelled metadata accuracy over bench_src/
    "parse_gallery",      # rust-malware-gallery README -> manifest (repo data)
    "gen_rust_versions",  # regenerates data/rust_versions.json in place (maintainer tool)
    "redblue_loop",       # RustCloak regression loop (needs the RustCloak build)
    "fuzz_recover",       # fuzzes our own parsers, seeds from tests/fixtures, writes build/
}


def _version() -> str:
    text = (HERE / "scripts" / "_version.py").read_text(encoding="utf-8")
    m = re.search(r'^__version__\s*=\s*["\']([^"\']+)["\']', text, re.M)
    if not m:
        raise RuntimeError("scripts/_version.py: no __version__ = '...' line")
    return m.group(1)


class build_py(_build_py):
    def find_package_modules(self, package, package_dir):
        mods = super().find_package_modules(package, package_dir)
        if package != "rust_deobf":
            return mods
        return [m for m in mods if m[1] not in SOURCE_ONLY]


VERSION = _version()

setup(
    version=VERSION,
    extras_require={
        # the AGPL/commercial Tier-4 modules: a separate distribution, same version
        "premium": [f"rust-deobf-premium=={VERSION}"],
        # dynamic recovery (RUNS the sample: isolated analysis VM only)
        "dynamic": ["frida>=16", "frida-tools"],
        # validate/consume the exported YARA and capa rules
        "rules": ["yara-python>=4.3", "flare-capa>=7"],
        "dev": ["pytest>=7", "build>=1"],
    },
    cmdclass={"build_py": build_py},
)
