# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: Ve (VAHPEM) <ve0912084386@gmail.com>
#
# Exercises the premium module premium/devirt_emulate.py (dual-licensed AGPL-3.0-or-later OR
# commercial). This test file is part of that premium capability's verification.
"""Emulation-based VM devirtualization: recover a virtualized function's logic by running its
interpreter under Unicorn and observing opcode semantics (codegen-agnostic), with a correctness
gate that re-executes the recovered program and refuses anything it cannot reproduce.

Pins two things: it devirtualizes a branchless function the *static* lifter cannot (fold64, whose
unguarded dense switch defeats the static patterns), and it never emits unverified output -- the
loop/memory functions, which this branchless core does not model, come back as None, not wrong C.
"""
import platform
import sys
from pathlib import Path

import pytest
from conftest import ROOT

pytestmark = pytest.mark.skipif(platform.machine() not in ("x86_64", "AMD64"),
                                reason="x86-64 fixtures")

unicorn = pytest.importorskip("unicorn")
sys.path.insert(0, str(ROOT / "premium"))

CALLFIX = ROOT / "tests" / "fixtures" / "vm" / "rustcloak_vm_call.x64"
OBFFIX = ROOT / "tests" / "fixtures" / "vm" / "rustcloak_vm_obf.x64"
NESTFIX = ROOT / "tests" / "fixtures" / "vm" / "rustcloak_vm_nested.x64"


def _syms(fix):
    import subprocess
    out = subprocess.check_output(["nm", str(fix)]).decode().splitlines()
    return {p[2]: int(p[0], 16) for p in (l.split() for l in out) if len(p) == 3 and p[1] == "T"}


@pytest.mark.skipif(not CALLFIX.is_file(), reason="fixture missing")
def test_emulation_recovers_a_function_static_cannot():
    import devirt_emulate
    import lift_vm
    syms = _syms(CALLFIX)
    fold64 = syms.get("fold64")
    assert fold64, "fixture has no fold64 symbol"

    # the static lifter does not recover fold64 (unguarded dense switch, handlers past the function
    # boundary); emulation does, and the result is self-verified against the observed return value.
    static = {r["bytecode_va"] for r in lift_vm.lift(CALLFIX)["lifted"]}
    r = devirt_emulate.recover(CALLFIX, fold64)
    assert r is not None, "emulation failed to recover fold64"
    assert r["bytecode_va"] not in static, "expected a function static could not lift"
    pc = "\n".join(r["pseudocode"])
    assert pc.startswith("return ") and ("^" in pc and "*" in pc)   # fold64's xor + multiply chain


@pytest.mark.skipif(not CALLFIX.is_file(), reason="fixture missing")
def test_emulation_recovers_a_loop_with_memory():
    import devirt_emulate
    syms = _syms(CALLFIX)
    sm = syms.get("sum_mix")
    assert sm, "fixture has no sum_mix symbol"
    # sum_mix is a loop over a memory buffer (load + loop + FNV mixing): the dynamic CFG recovery
    # must reconstruct its control flow and the Python-VM verifier confirm it against both the return
    # value and the observed loads. The FNV prime 0x1000193 must appear among its constants.
    r = devirt_emulate.recover(CALLFIX, sm)
    assert r is not None, "emulation failed to recover the loop+memory function sum_mix"
    assert r["has_control_flow"], "sum_mix should lift with control flow"
    body = "\n".join(r["pseudocode"]) + " ".join(t for _, _, t in r["listing"])
    assert "0x1000193" in body or "0x811c9dc5" in body       # the FNV constants it mixes with


@pytest.mark.skipif(not CALLFIX.is_file(), reason="fixture missing")
def test_emulation_recovers_an_unrolled_select_loop():
    import devirt_emulate
    syms = _syms(CALLFIX)
    cr = syms.get("crc_ish")
    assert cr, "fixture has no crc_ish symbol"
    # crc_ish was the holdout: an -O2-unrolled loop with a branchless select (a CMOVNZ the emulator
    # used to drop) and a 32-bit parameter narrowed into the reg file. Modelling the select, detecting
    # it in reconstruction, and seeding arguments at their observed width lets it recover and verify.
    r = devirt_emulate.recover(CALLFIX, cr)
    assert r is not None, "emulation failed to recover crc_ish"
    assert r["has_control_flow"], "crc_ish should lift with control flow (it is a loop)"
    assert any("cmovnz" in t for _, _, t in r["listing"]), "crc_ish's select should recover as CMOVNZ"
    body = "\n".join(r["pseudocode"]) + " ".join(t for _, _, t in r["listing"])
    assert "0x1000193" in body or "0x811c9dc5" in body       # the FNV constants it folds with


@pytest.mark.skipif(not CALLFIX.is_file(), reason="fixture missing")
def test_emulation_refuses_rather_than_emits_wrong_c():
    import devirt_emulate
    syms = _syms(CALLFIX)
    # decode is *not* virtualized in the build (the compiler auto-vectorized it; there is no VM
    # dispatch), so there is nothing to devirtualize: recovery must come back None rather than emit a
    # plausible-but-wrong expression. This pins the "never emit unverified output" guarantee.
    va = syms.get("decode")
    if va:
        assert devirt_emulate.recover(CALLFIX, va) is None, "a non-virtualized function must be declined"


def test_select_detector_is_codegen_agnostic_both_polarities():
    """The select detector and interpreter handle both CMOVNZ and CMOVZ. RustCloak only ever emits
    CMOVNZ (an LLVM `select` lowers to `mov dst,false; cmovnz dst,cond,true`), so the CMOVZ polarity
    cannot be produced from a RustCloak binary -- but the emulation recovery is codegen-agnostic and
    must recognize a select however another obfuscator or compiler expresses it. We exercise both from
    synthetic observations (detection) and a synthetic program (interpretation + rendering)."""
    import devirt_emulate as de
    import lift_vm

    nreg = 8

    def regs(s):
        return [(i, v) for i, v in s if 0 <= i < nreg]

    # r3 = cond(r1) ? r2 : r3(prev) -- the trace shows only the operand each run actually took.
    cmovnz = [{"srcs": [(1, 1), (2, 0xaa), (3, 0x11)], "result": 0xaa, "regvals": {}},
              {"srcs": [(1, 5), (2, 0xbb), (3, 0x22)], "result": 0xbb, "regvals": {}},
              {"srcs": [(1, 0), (2, 0xcc), (3, 0x33)], "result": 0x33, "regvals": {}},
              {"srcs": [(1, 0), (2, 0xdd), (3, 0x44)], "result": 0x44, "regvals": {}}]
    assert de._cmov(cmovnz, regs, 3) == (1, 2, True)

    # r3 = cond(r1) ? r3(prev) : r2 -- the inverted polarity.
    cmovz = [{"srcs": [(1, 0), (2, 0xaa), (3, 0x11)], "result": 0xaa, "regvals": {}},
             {"srcs": [(1, 0), (2, 0xbb), (3, 0x22)], "result": 0xbb, "regvals": {}},
             {"srcs": [(1, 1), (2, 0xcc), (3, 0x33)], "result": 0x33, "regvals": {}},
             {"srcs": [(1, 5), (2, 0xdd), (3, 0x44)], "result": 0x44, "regvals": {}}]
    assert de._cmov(cmovz, regs, 3) == (1, 2, False)

    # a genuine binary op (r3 = r1 ^ r2) must NOT be mistaken for a select.
    xor = [{"srcs": [(1, a), (2, b), (3, 0)], "result": a ^ b, "regvals": {}}
           for a, b in [(0x10, 0x01), (0x0, 0xff), (0xaa, 0x55), (0xf0, 0x0f)]]
    assert de._cmov(xor, regs, 3) is None

    # interpret + render both opcodes (27 CMOVNZ, 31 CMOVZ): const r2,r1,r3 then select then ret r3.
    C, Z, NZ, RET = (3 << 6) | 1, (3 << 6) | 31, (3 << 6) | 27, (3 << 6) | 0
    bm = {C: 1, Z: 31, NZ: 27, RET: 0}
    pool = [0x99, 0, 0x11, 5]                                # val, cond=0, prev, cond!=0

    def run(sel, cond_idx):
        prog = [(0, C, 2, 0, 0), (4, C, 1, cond_idx, 0), (8, C, 3, 2, 0),
                (0xc, sel, 3, 1, 2), (0x10, RET, 0, 3, 0)]
        idx = {p[0]: i for i, p in enumerate(prog)}
        return de._vm_exec(prog, bm, None, pool, idx, [])[0]

    assert run(Z, 1) == 0x99 and run(Z, 3) == 0x11            # CMOVZ: cond==0 takes val, else prev
    assert run(NZ, 3) == 0x99 and run(NZ, 1) == 0x11          # CMOVNZ: cond!=0 takes val, else prev
    rendered = lift_vm.lift_region(0x1000, [(0xc, Z, 3, 1, 2)], bm, None, None)
    assert any("cmovz" in t for _, _, t in rendered["listing"])


@pytest.mark.skipif(not NESTFIX.is_file(), reason="fixture missing")
def test_emulation_recovers_nested_loops_and_structures_the_inner_while():
    """Loop nests stress two things. Emulation: a nest's trip count is the product of its bounds, so
    the ordinary input vectors blow past the execution budget and leave too few cleanly-returning
    runs -- the tiny-count vectors (every lane small) fix that, and all three nested functions recover
    and self-verify (recover() returns only verified output). The relooper: a top-tested `for`/`while`
    is a single unconditional back-edge with a forward exit, which the while(1)+break peephole raises
    to a structured loop, so the recovered body shows at least one `while (1)`."""
    import devirt_emulate

    def syms():
        import subprocess
        out = subprocess.check_output(["nm", str(NESTFIX)]).decode().splitlines()
        return {p[2]: int(p[0], 16) for p in (l.split() for l in out) if len(p) == 3 and p[1] == "T"}

    import re
    s = syms()
    for fn in ("nested_sum", "tri_mix", "find_mix"):      # find_mix has an inner break
        assert fn in s, f"fixture has no {fn} symbol"
        r = devirt_emulate.recover(NESTFIX, s[fn])
        assert r is not None, f"emulation failed to recover nested-loop {fn}"
        assert r["has_control_flow"], f"{fn} should lift with control flow"
        pc = r["pseudocode"]
        # no `goto` may dangle: every branch target resolves to an emitted label (the CFG layout bumps
        # a target that fell on a skipped no-op to the next real instruction).
        labels = {m.group(1) for line in pc for m in [re.match(r"^(L\w+):", line.strip())] if m}
        gotos = {m.group(1) for line in pc for m in re.finditer(r"goto (L\w+)", line)}
        assert not (gotos - labels), f"{fn} has dangling goto(s): {gotos - labels}"

    # a clean nest (no inner break) fully structures: both loops become nested while(1), no goto left
    # -- the CFG layout makes the non-contiguously compiled outer loop contiguous so it folds too.
    pc = "\n".join(devirt_emulate.recover(NESTFIX, s["nested_sum"])["pseudocode"])
    assert pc.count("while (1)") == 2 and "break" in pc, "both loops of nested_sum should structure"
    assert "goto L" not in pc, "a clean reducible nest should leave no goto"


@pytest.mark.skipif(not CALLFIX.is_file(), reason="fixture missing")
def test_combined_recover_all_adds_emulation_to_static():
    import devirt_emulate
    r = devirt_emulate.recover_all(CALLFIX)
    assert len(r["static"]) >= 3                         # mix, check, wrap via the static lifter
    assert len(r["emulated"]) >= 4                        # emulation adds fold64 + sum_mix + roll + crc_ish
    assert r["count"] >= 7                                # every virtualized function in the demo


@pytest.mark.skipif(not OBFFIX.is_file(), reason="fixture missing")
def test_emulation_sees_through_an_obfuscated_interpreter():
    """Round 13: the VM's *interpreter* is itself obfuscated (the full RustCloak pipeline -- operand
    decrypt turned to MBA, dispatch flattened, bogus flow). The static lifter pattern-matches the
    dispatch's native code, so obfuscating that code defeats it entirely. Emulation instead *runs*
    the interpreter and observes what it computes, so the same obfuscation is transparent to it.

    Pins both halves: the static lifter recovers nothing on this build, and emulation still recovers
    the virtualized functions -- each one self-verified by re-execution, so this is recovery, not a
    plausible guess. The incoming arguments land in build-specific VM registers here (arg0 is not r0),
    which is exactly what the observed argument-register map handles."""
    import devirt_emulate
    import lift_vm
    assert len(lift_vm.lift(OBFFIX)["lifted"]) == 0, "static lifter should be defeated by obfuscation"
    r = devirt_emulate.recover_all(OBFFIX)
    assert len(r["static"]) == 0                          # confirm nothing came from the static path
    assert len(r["emulated"]) >= 5                        # mix, fold64, sum_mix, roll, crc_ish via emulation
    # mix is a pure 32-bit mixing function; its recovered body must reproduce the xor/multiply chain.
    syms = _syms(OBFFIX)
    mix = devirt_emulate.recover(OBFFIX, syms["mix"])
    assert mix is not None, "emulation failed to recover mix through the obfuscated interpreter"
    pc = "\n".join(mix["pseudocode"])
    assert "^" in pc and "*" in pc                        # the mix's xor + multiply chain survived
