"""recover_libfuncs: which DB group a binary is matched against, and AArch64 data accessors.

Pure tests on committed fixtures (no Rust build): the binary's toolchain facts come from a stubbed
recover_rust_meta.recover and its function starts from a stubbed function_starts, so each case
pins one decision of match_binary.

Rust 1.100 (CI benchmark, 2026-11) broke test_libfuncs.py on pe / elf-arm64 / the per-binary DB:
the commit -> release table ended at 1.99.1, so a stripped 1.100 binary was keyed
`commit-0ef1bc386059` (from `/rustc/<hash>/` paths) while its unstripped reference -- whose
`.comment` names the release -- and gen_sigdb's DB were keyed `rustc-1.100.0`. Group selection
compared key strings, so no signature was ever consulted (0 functions identified).
"""
import sys

import pytest

from conftest import ROOT

sys.path.insert(0, str(ROOT / "scripts"))
import recover_libfuncs as LF  # noqa: E402
import recover_rust_meta as M  # noqa: E402

X64 = ROOT / "tests" / "fixtures" / "emu" / "ct64"            # .text 0x13a0: 18 bytes
A64 = ROOT / "tests" / "fixtures" / "static" / "a64_stack"    # .text 0x210120
COMMIT = "0ef1bc386059" + "0" * 28                            # a rustc newer than the table
X64_PAT = "c705f620000037130000c30f1f440000"                  # ct64's .text, whole


def _stub(monkeypatch, meta, starts):
    monkeypatch.setattr(M, "recover", lambda *a, **k: dict(meta))
    monkeypatch.setattr(LF, "function_starts", lambda b: set(starts))


def _sig(pat, name="std::io::stdio::print_to"):
    return {"name": name, "sym": name, "pattern": pat}


def test_stripped_binary_known_by_commit_finds_group_keyed_by_release(monkeypatch):
    # generate() on the unstripped reference: release from `.comment`, commit recorded beside it
    _stub(monkeypatch, {"rustc_commit": COMMIT[:12], "rust_release": None}, [0x13a0])
    db = {"rustc-9.100.0": {"x86_64": [_sig(X64_PAT)]},
          "__toolchains__": {"rustc-9.100.0": {"version": "9.100.0", "commit": COMMIT}}}
    res = LF.match_binary(X64, db)
    assert [(r["va"], r["name"]) for r in res] == [(0x13a0, "std::io::stdio::print_to")]


def test_binary_with_comment_finds_per_binary_db_keyed_by_commit(monkeypatch):
    # gen_sigdb keyed the group by commit (toolchain newer than the table); the stripped binary
    # kept `.comment` (GNU strip does): release + 9-hex commit
    _stub(monkeypatch, {"rustc_commit": COMMIT[:9],
                        "rust_release": {"version": "9.100.0", "date": None}}, [0x13a0])
    db = {"commit-" + COMMIT[:12]: {"x86_64": [_sig(X64_PAT)]},
          "__meta__": {"built": {"tool_key": "commit-" + COMMIT[:12], "rustc_commit": COMMIT,
                                 "rust_version": "9.100.0"}}}
    assert [r["va"] for r in LF.match_binary(X64, db)] == [0x13a0]
    # recover()'s path passes the key it derived plus the metadata
    assert [r["va"] for r in LF.match_binary(X64, db, tool="rustc-9.100.0",
                                             meta=M.recover(X64))] == [0x13a0]


def test_other_toolchain_still_not_used(monkeypatch):
    # a KNOWN different rustc's signatures are never borrowed (by key or by recorded commit)
    _stub(monkeypatch, {"rustc_commit": COMMIT[:12], "rust_release": None}, [0x13a0])
    db = {"rustc-9.99.0": {"x86_64": [_sig(X64_PAT)]},
          "__toolchains__": {"rustc-9.99.0": {"version": "9.99.0", "commit": "1" * 40}}}
    monkeypatch.setattr(M, "rust_release", lambda c: {"version": "9.100.0"} if c and COMMIT.startswith(c) else None)
    assert LF.match_binary(X64, db) == []


def test_generate_records_each_groups_toolchain(monkeypatch):
    _stub(monkeypatch, {"rustc_commit": COMMIT, "rust_release": {"version": "9.100.0"},
                        "crates": {}}, [0x13a0])
    db = LF.generate([X64])                        # C fixture: no library symbols, no groups
    assert "__toolchains__" not in db or set(db["__toolchains__"]) <= set(LF._groups(db))
    tcs = LF._db_toolchains({"rustc-9.100.0": {}, "__toolchains__": {
        "rustc-9.100.0": {"version": "9.100.0", "commit": COMMIT}}})
    assert tcs == {"rustc-9.100.0": ("9.100.0", COMMIT)}


@pytest.mark.parametrize("masked,expect", [(True, []), (False, [0x210120])])
def test_a64_short_data_accessor_not_named_alone(monkeypatch, masked, expect):
    # rustc 1.100 `<T as Any>::type_id` = adrp/add/ldr q0/str q0/ret: identical for every T once
    # the page address is masked -- the name lives in the datum loaded, not in the code
    import lief
    b = lief.parse(str(A64))
    text = b.get_section(".text")
    code = bytes(text.content)[:20]
    pat = ("........" if masked else code[:4].hex()) + code[4:20].hex()
    _stub(monkeypatch, {"rustc_commit": COMMIT, "rust_release": {"version": "9.100.0"}},
          [0x210120, 0x210120 + 0x40])
    db = {"rustc-9.100.0": {"aarch64": [_sig(pat, "core::any::Any::type_id")]}}
    assert [r["va"] for r in LF.match_binary(A64, db)] == expect
