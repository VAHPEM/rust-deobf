"""recover_rust_meta: the crates vendored into std are not the author's code.

rustc <= 1.99 remapped std's own dependencies (gimli, addr2line, rustc-demangle, miniz_oxide,
memchr, ...) to `/rust/deps/<crate>-<ver>/`; rustc 1.100.0 (0ef1bc386, measured on every
benchmark target) remaps them to `/cargo/registry/<16 hex>/<crate>-<ver>/`. The new prefix was
read as user code: own_source_files of the CI benchmark became
['src/function/line.rs'-style gimli paths, ..., '/cargo/registry/25cdd57fae9f0462/rustc-demangle-
0.1.28/src/lib.rs'] instead of ['src/main.rs']. Synthetic sections, no binary.
"""
import struct
import sys

import pytest
from conftest import ROOT

sys.path.insert(0, str(ROOT / "scripts"))
pytest.importorskip("lief")
import recover_rust_meta as M  # noqa: E402

BASE = 0x10000
HASH = "0ef1bc386059596dada8fb65b50425aab2ea637a"


def _sections(paths):
    """One rodata section: each path, then a Location {ptr, len, line, col} pointing at it."""
    blob = bytearray()
    for i, p in enumerate(paths):
        fn = p.encode()
        va = BASE + len(blob)
        blob += fn + b"\x00"
        blob += b"\x00" * ((8 - len(blob) % 8) % 8)
        blob += struct.pack("<QQII", va, len(fn), 10 + i, 5)
    return [(BASE, bytes(blob))]


def _recover(monkeypatch, paths):
    secs = _sections(paths)
    monkeypatch.setattr(M, "read_sections", lambda p: (0, 8, secs, [], {}))
    return M.recover(ROOT / "tests" / "fixtures" / "emu" / "ct64")


V100 = ["/cargo/registry/25cdd57fae9f0462/rustc-demangle-0.1.28/src/lib.rs",
        "/cargo/registry/25cdd57fae9f0462/gimli-0.34.0/src/read/line.rs",
        "/cargo/registry/25cdd57fae9f0462/addr2line-0.26.0/src/function.rs"]


def test_rustc_1_100_std_dep_paths_are_not_own_code(monkeypatch):
    r = _recover(monkeypatch, ["src/main.rs", "/rustc/%s/library/std/src/io/mod.rs" % HASH] + V100)
    assert r["own_source_files"] == ["src/main.rs"], r["own_source_files"]
    assert r["std_vendored_crates"] == {"addr2line": ["0.26.0"], "gimli": ["0.34.0"],
                                        "rustc-demangle": ["0.1.28"]}
    assert not set(r["crates"]) & {"gimli", "addr2line", "rustc-demangle"}, r["crates"]


def test_rustc_1_99_std_dep_paths_still_classified(monkeypatch):
    r = _recover(monkeypatch, ["src/main.rs", "/rust/deps/gimli-0.32.3/src/read/abbrev.rs"])
    assert r["own_source_files"] == ["src/main.rs"]
    assert r["std_vendored_crates"] == {"gimli": ["0.32.3"]}


@pytest.mark.parametrize("path", [
    # a user's own registry checkout keeps cargo's layout: registry/src/<index>-<hash>/ -- a real
    # dependency (crates), never a std-vendored one
    "/home/u/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/memchr-2.7.4/src/lib.rs",
    # hex but not 16 digits / no leading separator: not the rustc remap
    "/cargo/registry/25cdd57fae9f/memchr-2.7.4/src/lib.rs",
    "x.cargo/registry/25cdd57fae9f0462/memchr-2.7.4/src/lib.rs",
])
def test_user_registry_paths_are_not_std_deps(path):
    assert M.RE_STD_DEP.search(path) is None
