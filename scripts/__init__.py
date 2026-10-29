# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Ve (VAHPEM) <ve0912084386@gmail.com>
"""rust_deobf - the installed form of rust-deobf's scripts/ directory.

pyproject.toml maps the `rust_deobf` package onto scripts/ unchanged, so every script keeps working
both ways: `python3 scripts/recover.py` from a clone, and `rust-deobf recover` / `import rust_deobf`
after `pip install rust-deobf`. This file only runs in the second case (nothing imports `scripts`
as a package in a clone), and keeps the scripts' existing wiring safe there:

* The scripts import each other by bare name (`import recover_emulate`) after putting their own
  directory on sys.path. `import rust_deobf.recover_emulate` / `from rust_deobf import recover`
  therefore return *that same* bare module object (one copy, one `Image` class), not a second copy
  under a dotted name.
* Library mode (a host program imports rust_deobf): the package directory is moved to the END of
  sys.path before every top-level import, so its bare module names (recover, unpack, disasm, ...)
  can never shadow the host program's own modules or another installed package. The rust-deobf
  CLI process turns this off (cli.py), because there the toolkit's own modules must win.
"""
from __future__ import annotations

import importlib
import importlib.abc
import importlib.machinery
import os
import sys
from pathlib import Path

from ._version import __version__

__all__ = ["__version__"]

_HERE = str(Path(__file__).resolve().parent)

# module stems that are NOT bare-imported siblings: package plumbing (cli imports _version
# relatively; it is the console-script target, so it lives only under its dotted name)
_PLUMBING = {"cli"}


def _siblings(directory: str) -> frozenset:
    try:
        names = os.listdir(directory)
    except OSError:
        return frozenset()
    return frozenset(n[:-3] for n in names
                     if n.endswith(".py") and not n.startswith("_") and n[:-3] not in _PLUMBING)


def _norm(p) -> str | None:
    if not isinstance(p, str):
        return None
    try:
        return os.path.normcase(os.path.abspath(p))
    except (OSError, ValueError):
        return None


class _PackageDirs(importlib.abc.MetaPathFinder):
    """One finder for rust_deobf and (when installed) rust_deobf_premium.

    - `<package>.<sibling>` resolves to the bare `<sibling>` module (see the module docstring).
    - in library mode, every top-level import first moves the registered package directories to the
      end of sys.path (the scripts re-insert them at index 0 whenever one of them is imported)."""

    def __init__(self) -> None:
        self.library_mode = True
        self.packages: dict = {}          # package name -> (dir, frozenset of sibling stems)
        self._spellings: set = set()      # sys.path strings that name a registered dir
        self._norms: set = set()

    def register(self, package: str, directory: str) -> None:
        self.packages[package] = (directory, _siblings(directory))
        self._spellings.add(directory)
        n = _norm(directory)
        if n:
            self._norms.add(n)

    def _ours(self, entry) -> bool:
        if entry in self._spellings:
            return True
        n = _norm(entry)
        if n in self._norms:
            if isinstance(entry, str) and os.path.isabs(entry):   # "" (cwd) may change
                self._spellings.add(entry)
            return True
        return False

    def demote(self) -> None:
        """Move every registered package dir to the end of sys.path (each kept once)."""
        path = sys.path
        if not self._spellings or not path:
            return
        hits = [i for i, e in enumerate(path) if self._ours(e)]
        if not hits:
            return
        n = len(hits)
        if hits == list(range(len(path) - n, len(path))) and len({_norm(path[i]) for i in hits}) == n:
            return                        # already at the end, no duplicates
        keep, seen = [], set()
        for i in hits:
            k = _norm(path[i])
            if k not in seen:
                seen.add(k)
                keep.append(path[i])
        drop = set(hits)
        path[:] = [e for i, e in enumerate(path) if i not in drop] + keep

    def ensure_on_path(self, directory: str, front: bool) -> None:
        present = any(_norm(e) == _norm(directory) for e in sys.path)
        if front:
            if not (sys.path and _norm(sys.path[0]) == _norm(directory)):
                sys.path.insert(0, directory)
        elif not present:
            sys.path.append(directory)

    def find_spec(self, fullname, path, target=None):
        if path is None:                  # a top-level import
            if self.library_mode:
                self.demote()
            return None
        pkg, _, short = fullname.rpartition(".")
        entry = self.packages.get(pkg)
        if entry is None or short not in entry[1]:
            return None
        directory = entry[0]
        return importlib.machinery.ModuleSpec(
            fullname, _AliasLoader(self, short, directory),
            origin=os.path.join(directory, short + ".py"))


class _AliasLoader(importlib.abc.Loader):
    """Loads `<package>.<short>` as the bare module `<short>` (the one the scripts import)."""

    def __init__(self, finder: _PackageDirs, short: str, directory: str) -> None:
        self.finder, self.short, self.directory = finder, short, directory
        self._spec = None

    def create_module(self, spec):
        self.finder.ensure_on_path(self.directory, front=not self.finder.library_mode)
        mod = importlib.import_module(self.short)
        origin = getattr(mod, "__file__", None) or ""
        if _norm(os.path.dirname(origin)) != _norm(self.directory):
            raise ImportError(
                f"{spec.name}: the bare module name {self.short!r} resolves to {origin or mod!r}, "
                f"not to {self.directory}: another top-level module of that name shadows it",
                name=spec.name)
        self._spec = getattr(mod, "__spec__", None)
        return mod

    def exec_module(self, module) -> None:
        # module_from_spec() overwrote __spec__ with the alias spec: keep the bare module's own
        if self._spec is not None:
            module.__spec__ = self._spec
        if self.finder.library_mode:      # the module's own sys.path.insert(0, ...) undone now
            self.finder.demote()


def _finder() -> _PackageDirs:
    for f in sys.meta_path:
        if type(f).__name__ == "_PackageDirs" and getattr(f, "_rust_deobf", False):
            return f
    f = _PackageDirs()
    f._rust_deobf = True
    sys.meta_path.insert(0, f)
    return f


def register_package_dir(package: str, directory: str) -> None:
    """Used by rust_deobf_premium: alias its modules and keep its dir in the same sys.path policy."""
    _finder().register(package, str(directory))


def ensure_package_dirs_on_path() -> None:
    """Every registered package dir on sys.path: appended (library mode) or first (CLI)."""
    f = _finder()
    for directory, _ in list(f.packages.values()):
        f.ensure_on_path(directory, front=not f.library_mode)


def set_library_mode(on: bool) -> None:
    """True (default on import): keep the package dirs last on sys.path. The CLI sets False and puts
    the package dir first, like `python3 scripts/<tool>.py` does."""
    f = _finder()
    f.library_mode = bool(on)
    if on:
        f.demote()
    else:
        ensure_package_dirs_on_path()


register_package_dir(__name__, _HERE)
