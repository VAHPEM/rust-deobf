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


# --- AArch64 parity (hand-assembled with llvm-mc; deterministic, no toolchain at test time) ---
def test_opaque_arm64_always_taken():
    # orr x0,x1,#1; cmp x0,#0; b.ne  ->  (x1|1)!=0 is always true
    r = O.classify_block(_b("e00301aa 000040b2 1f0000f1 41000054"), 0x1000, "aarch64")
    assert r and r["result"] == "always-taken" and r["jcc"] == "b.ne"
    assert r["dead_direction"] == "fall-through"


def test_opaque_arm64_cbz_never_taken():
    # orr x0,x1,#1; cbz x0  ->  x0 never zero, so the branch is never taken
    r = O.classify_block(_b("200040b2 400000b4"), 0x2000, "aarch64")
    assert r and r["result"] == "never-taken" and r["jcc"] == "cbz"


def test_arm64_real_branch_not_flagged():
    # cmp w0,#5; b.lt  ->  input-dependent signed 32-bit branch, must NOT be flagged
    assert O.classify_block(_b("1f140071 4b000054"), 0x3000, "aarch64") is None


def test_arm64_memory_block_abandoned():
    # ldr x0,[x1]; cmp x0,#0; b.eq  ->  touches memory: abandoned (no unsound claim)
    assert O.classify_block(_b("200040f9 1f0000f1 40000054"), 0x4000, "aarch64") is None


# --- soundness regressions: each block was once mis-lifted into a FALSE opaque claim (a live branch
# reported dead). Truth is from Unicorn emulation; the detector must give the true verdict or no
# claim (None) -- never the opposite verdict. Bytes assembled with llvm-mc (Intel syntax / A64).
_SOUND = [
    # (label, arch, hex, truth)  truth None == input-dependent (no claim allowed)
    ("stale cmp survives sub: cmp rax,rax; sub rdi,1; je", "x86_64",
     "4839c0 4883ef01 7402 9090", None),
    ("32-bit wrap: mov eax,-1; add eax,1; test eax,eax; je", "x86_64",
     "b8ffffffff 83c001 85c0 7402 9090", "always-taken"),
    ("32-bit signed: mov eax,0x80000000; cmp eax,0; jge", "x86_64",
     "b800000080 83f800 7d02 9090", "never-taken"),
    ("test eax after or rax,1<<32", "x86_64",
     "4889f8 48b90000000001000000 4809c8 85c0 7502 9090", None),
    ("8-bit merge: mov eax,0x100; mov al,0; test rax,rax; je", "x86_64",
     "b800010000 b000 4885c0 7402 9090", "never-taken"),
    ("high byte: xor eax,eax; mov ah,1; test eax,eax; je", "x86_64",
     "31c0 b401 85c0 7402 9090", "never-taken"),
    ("3-op imul keeps imm: xor eax,eax; imul rax,rdi,1; test rax,rax; je", "x86_64",
     "31c0 486bc701 4885c0 7402 9090", None),
    ("movzx truncates: mov eax,0x100; movzx eax,al; test eax,eax; je", "x86_64",
     "b800010000 0fb6c0 85c0 7402 9090", "always-taken"),
    ("shift count masked: mov ecx,64; mov eax,1; shl rax,cl; test rax,rax; je", "x86_64",
     "b940000000 b801000000 48d3e0 4885c0 7402 9090", "never-taken"),
    ("a64 asr on w: orr w1,w1,#0x80000000; asr w0,w1,#31; cmp w0,#1; b.eq", "aarch64",
     "21000132 207c1f13 1f040071 40000054", "never-taken"),
    ("a64 shifted operand asr on w: add w0,wzr,w1,asr #31; cmp w0,#1; b.eq", "aarch64",
     "21000132 e07f810b 1f040071 40000054", "never-taken"),
    ("a64 reg shift mod 32: mov w1,#1; mov w2,#32; lsl w0,w1,w2; cbz w0", "aarch64",
     "21008052 02048052 2020c21a 40000034", "never-taken"),
    ("a64 cmn #0 carry: cmn x0,#0; b.hs", "aarch64", "1f0000b1 42000054", "never-taken"),
]


@pytest.mark.parametrize("label,arch,hx,truth", _SOUND, ids=[c[0] for c in _SOUND])
def test_no_false_opaque_claim(label, arch, hx, truth):
    r = O.classify_block(_b(hx), 0x1000, arch)
    got = r["result"] if r else None
    # sound: never the wrong verdict; and these are all modelled exactly, so the true verdict (not
    # merely "no claim") is expected wherever the branch really is constant
    assert got == truth, (label, got, truth)


def test_one_operand_imul_abandons_not_crashes():
    # imul rdi (rdx:rax = rax*rdi) used to raise IndexError, killing recover() on a whole binary
    assert O.classify_block(_b("48f7ef 4885c0 7402 9090"), 0x1000, "x86_64") is None


def test_flag_writers_clear_the_compare():
    # cmp rax,rax (ZF=1) then a flag write by each op the lifter models -> the je reads THAT op's
    # flags; no claim may survive from the stale cmp. and rdi,rdi / inc rdi / shl rdi,1 / neg rdi.
    for mid in ("4821ff", "48ffc7", "48d1e7", "48f7df", "4883c701", "486bff03"):
        assert O.classify_block(_b("4839c0" + mid + "7402 9090"), 0x1000, "x86_64") is None, mid


def test_cmn_non_eq_conditions_exact():
    # cmn x0,#1; b.vs : V set iff x0 == INT64_MAX -> input-dependent, no claim (V of the ADDITION)
    assert O.classify_block(_b("1f0400b1 46000054"), 0x1000, "aarch64") is None
    # eq/ne after cmn still classified: orr w0,w1,#1; cmn w0,#0; b.ne -> always taken
    r = O.classify_block(_b("20000032 1f000031 41000054"), 0x1000, "aarch64")
    assert r and r["result"] == "always-taken", r


def test_recover_contains_per_block_failures(monkeypatch):
    # any exception inside one block's lift/solve is contained: that block makes no claim
    def boom(*a, **k):
        raise RuntimeError("synthetic lifter bug")
    monkeypatch.setattr(O, "_lift_block", boom)
    assert O.classify_block(_b("4889f8 4883c801 4883f800 7500"), 0x1000) is None
