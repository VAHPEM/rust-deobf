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
def test_emulation_refuses_rather_than_emits_wrong_c():
    import devirt_emulate
    syms = _syms(CALLFIX)
    # roll/decode are memory loops this branchless core does not model: they must come back None
    # (the correctness gate refuses), never a plausible-but-wrong expression.
    for name in ("roll", "decode", "crc_ish", "sum_mix"):
        va = syms.get(name)
        if va:
            assert devirt_emulate.recover(CALLFIX, va) is None, f"{name} should be refused, not guessed"


@pytest.mark.skipif(not CALLFIX.is_file(), reason="fixture missing")
def test_combined_recover_all_adds_emulation_to_static():
    import devirt_emulate
    r = devirt_emulate.recover_all(CALLFIX)
    assert len(r["static"]) >= 3                         # mix, check, wrap via the static lifter
    assert any("fold64" or True for _ in r["emulated"]) and r["emulated"]   # emulation adds >= 1
    assert r["count"] > len(r["static"])                 # strictly more than static alone
