# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: Ve (VAHPEM) <ve0912084386@gmail.com>
"""Build-time logic for rust-deobf-premium; static metadata is in pyproject.toml.

The version is rust-deobf's (../scripts/_version.py, the single source of truth) and the dependency
on the core is pinned to exactly that version. Building from this distribution's own sdist (where
../scripts does not exist) reads the version back from PKG-INFO. setup.py itself is excluded from
the wheel (the package directory is this directory).
"""
import re
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py as _build_py

HERE = Path(__file__).resolve().parent


def _version() -> str:
    core = HERE.parent / "scripts" / "_version.py"
    if core.is_file():
        m = re.search(r'^__version__\s*=\s*["\']([^"\']+)["\']', core.read_text(encoding="utf-8"),
                      re.M)
        if m:
            return m.group(1)
    pkg_info = HERE / "PKG-INFO"                       # building from the premium sdist
    if pkg_info.is_file():
        m = re.search(r"^Version:\s*(\S+)", pkg_info.read_text(encoding="utf-8"), re.M)
        if m:
            return m.group(1)
    raise RuntimeError("rust-deobf-premium: no version (../scripts/_version.py or PKG-INFO)")


class build_py(_build_py):
    def find_package_modules(self, package, package_dir):
        return [m for m in super().find_package_modules(package, package_dir)
                if m[1] != "setup"]


VERSION = _version()

setup(
    version=VERSION,
    install_requires=[f"rust-deobf=={VERSION}"],
    cmdclass={"build_py": build_py},
)
