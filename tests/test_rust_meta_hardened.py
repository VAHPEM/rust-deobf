"""recover_rust_meta on builds that hide their metadata (VALIDATION §79).

Measured on meta_probe (regex, serde_json, url, base64; rustc 1.99.1, AArch64), 14 registry crates
in the plain build:
- `--remap-path-prefix=$HOME/.cargo/registry/src=/reg` left `/reg/index.crates.io-<hash>/regex-
  automata-0.4.18/src/...` in every Location, and the crate tier reported 0 crates: it keyed on
  the `.cargo/registry/src` prefix the remap had replaced. The index directory still names it.
- cargo `trim-paths` maps a dependency's root to `<crate>-<version>/` (no prefix at all): read
  only from a path a Location record bounds exactly, since a regex hit can have rodata glued on.
- `panic=immediate-abort` (+ build-std) leaves no panic path and no Location: the binary was
  reported `is_rust: False`. rustc's ELF `.comment` ("rustc version X (hash date)", which GNU strip
  keeps) is still there and is Rust evidence and the toolchain version.
- an empty crate list says why (notes), instead of a silent nothing.
"""
import sys

import pytest
from conftest import ROOT

sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))
pytest.importorskip("lief")
import recover_rust_meta as M  # noqa: E402
from _mkelf import mkelf  # noqa: E402

IDX = "index.crates.io-1949cf8c6b5b557f"


def test_remapped_registry_prefix_still_names_the_crate():
    paths = [f"/reg/{IDX}/regex-automata-0.4.18/src/util/pool.rs",
             f"C:\\b\\{IDX}\\base64-0.22.1\\src\\engine\\mod.rs",
             "/x/github.com-1ecc6299db9ec823/serde-1.0.200/src/de.rs",
             "/build/.rustup/toolchains/stable/lib/rustlib/src/rust/library/alloc/src/vec.rs"]
    crates, _ = M.fingerprint_crates(paths, "", True)
    assert crates == {"regex-automata": {"0.4.18"}, "base64": {"0.22.1"}, "serde": {"1.0.200"}}, crates


def test_remapped_needs_a_real_index_directory():
    # the index dir is `<host>-<16 hex>`: anything else is not a registry checkout
    for p in ("/reg/index.crates.io-1949cf8c/regex-1.11.1/src/lib.rs",       # short hash
              "/reg/crates-1949cf8c6b5b557f/regex-1.11.1/src/lib.rs",       # not an index host
              "/home/u/proj/regex-1.11.1/src/lib.rs"):
        assert M._registry_crate(p) is None, p


def test_trimmed_path_only_when_a_location_bounds_it():
    p = "regex-1.11.1/src/lib.rs"
    assert M._registry_crate(p, {p}) == ("regex", "1.11.1")
    assert M._registry_crate(p) is None                       # a bare regex hit: maybe glued
    glued = "valueregex-1.11.1/src/lib.rs"
    assert M._registry_crate(glued, {p}) is None
    assert M._registry_crate("src/main.rs", {"src/main.rs"}) is None


def test_comment_is_rust_evidence_and_toolchain(tmp_path):
    code = b"\x90" * 32 + b"rustc version 1.99.1 (58cf8f9c3 2026-10-13)\x00"
    f = tmp_path / "pia.elf"
    f.write_bytes(mkelf(code)[0])
    r = M.recover(f)
    assert r["is_rust"] is True
    assert r["rustc_comment"] == {"version": "1.99.1", "commit": "58cf8f9c3", "date": "2026-10-13"}
    assert r["rust_release"]["version"] == "1.99.1" and r["rustc_source"] == ".comment"
    assert any("no panic Location" in n for n in r["notes"]), r["notes"]
    assert any(".comment" in n for n in r["notes"]), r["notes"]


def test_no_comment_no_rust(tmp_path):
    f = tmp_path / "c.elf"
    f.write_bytes(mkelf(b"\x90" * 32 + b"GCC: (Debian 14.2.0) 14.2.0\x00")[0])
    r = M.recover(f)
    assert r["is_rust"] is False and r["notes"] == [] and r["rustc_comment"] is None
