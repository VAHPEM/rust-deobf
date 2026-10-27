"""Opaque-predicate detection in ordinary functions (premium/deobf_opaque.py).

The --selftest runs via test_selftests.py. This pins the classification on hand-assembled blocks
(always-taken / never-taken / input-dependent / abandoned) and the precision on a committed binary.
"""
import sys

import pytest
from conftest import ROOT

sys.path.insert(0, str(ROOT / "premium"))
sys.path.insert(0, str(ROOT / "scripts"))
import deobf_opaque as O  # noqa: E402

z3 = pytest.importorskip("z3")
pytestmark = pytest.mark.filterwarnings("ignore::RuntimeWarning")


def _b(h):
    return bytes.fromhex(h.replace(" ", ""))


def test_opaque_always_taken():
    # mov rax,rdi ; or rax,1 ; cmp rax,0 ; jne  -> (x|1)!=0 is always true
    r = O.classify_block(_b("4889f8 4883c801 4883f800 7500"), 0x1000)
    assert r and r["result"] == "always-taken" and r["dead_direction"] == "fall-through"


def test_opaque_never_taken():
    # mov rax,rdi ; and rax,0 ; cmp rax,1 ; je  -> 0==1 never
    r = O.classify_block(_b("4889f8 4883e000 4883f801 7400"), 0x2000)
    assert r and r["result"] == "never-taken"


def test_real_branch_not_flagged():
    # mov rax,rdi ; cmp rax,5 ; jb  -> input-dependent, must NOT be flagged
    assert O.classify_block(_b("4889f8 4883f805 7200"), 0x3000) is None


def test_memory_block_abandoned():
    # mov rax,[rdi] ; cmp rax,0 ; je  -> touches memory: abandoned (no unsound claim)
    assert O.classify_block(_b("488b07 4883f800 7400"), 0x4000) is None


def test_precision_on_committed_binary():
    # normal code has genuine branches; the sound detector must not invent opaque ones
    res = O.recover(ROOT / "tests" / "fixtures" / "vm" / "benign_rust_std.x64")
    assert res["arch"] == "x86_64"
    assert res["opaque_branches"] == []
