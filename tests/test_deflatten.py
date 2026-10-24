"""Control-flow deflattening on the goldberg debug build (deobf_deflatten.py).

goldberg's `goldberg_stmts!` flattens `band()` into a state machine; at opt-level=0 it survives
(in release rustc inlines band away). The recoverer must find the dispatcher, the state/update
slots and the full state-transition graph, and the graph must be a connected chain from the
start state to a terminal (return) state with XOR-consistent transitions. Skips if the debug
binary cannot be built (no cargo).
"""
import shutil
import subprocess
from pathlib import Path

import pytest
from conftest import ROOT

import lief
import deobf_deflatten as D

GOLD = ROOT / "obf_src" / "goldberg_cff"


def _debug_binary():
    bin_ = GOLD / "target" / "debug" / "goldberg_cff"
    if bin_.is_file():
        return bin_
    if shutil.which("cargo") is None:
        return None
    subprocess.run(["cargo", "build"], cwd=GOLD, capture_output=True)
    return bin_ if bin_.is_file() else None


def test_deflatten_band():
    bin_ = _debug_binary()
    if bin_ is None:
        pytest.skip("goldberg debug build unavailable (no cargo)")
    b = lief.parse(str(bin_))
    text = next(s for s in b.sections if s.name == ".text")
    code, tbase = bytes(text.content), text.virtual_address
    band = [s for s in b.symbols if "band" in s.name and getattr(s, "is_function", False) and s.size]
    assert band, "band() is not a standalone symbol in the debug build"
    s = band[0]

    r = D.deflatten(code, tbase, s.value, s.size)
    assert r["flattened"], r
    assert r["num_states"] >= 5, r
    assert r["state_slot_disp"] and r["update_slot_disp"], r
    assert r["start_state"] is not None, r

    states = {st["state"]: st for st in r["states"]}
    start = r["start_state"]
    assert start in states, (start, list(states))

    # walk the single-successor backbone from the start; it must reach a terminal (return)
    seen, cur, terminal = set(), start, False
    for _ in range(len(states) + 1):
        if cur not in states or cur in seen:
            break
        seen.add(cur)
        st = states[cur]
        if st["terminal"]:
            terminal = True
            break
        nxts = st["next_states"]
        if not nxts:
            break
        cur = nxts[0]
    assert terminal, f"start {start} did not reach a terminal state; visited {sorted(seen)}"
    # every transition target that exists must be one of the recovered states (closed graph)
    for st in r["states"]:
        for n in st["next_states"]:
            assert n in states, f"transition to unknown state {n} from {st['state']}"


OLLVM = ROOT / "obf_src" / "ollvm_fla"


def _ollvm_binary():
    """Build the OLLVM `-fla`-shaped C target with clang if available. This is a hand-written
    post-flattening form (switch var, dispatcher, DIRECT-assignment transitions `sv = next_const`)
    compiled by a real compiler -- the direct-assignment form OLLVM uses, which goldberg's
    XOR-delta transitions never exercise."""
    binp = OLLVM / "fla"
    if binp.is_file():
        return binp
    if shutil.which("clang") is None:
        return None
    subprocess.run(["clang", "-O0", "-fno-inline", "-o", str(binp), str(OLLVM / "fla.c")],
                   capture_output=True)
    return binp if binp.is_file() else None


def test_deflatten_ollvm_direct_assignment():
    """OLLVM-style flattening: the recoverer must handle DIRECT-assignment state transitions
    (sv = next_const), not just goldberg's XOR-delta. The target's original logic has two real
    branches (a loop test and a length-parity check) that must survive as two-way transitions, and
    the graph must be fully reachable from the start to the single terminal."""
    binp = _ollvm_binary()
    if binp is None:
        pytest.skip("clang unavailable to build the OLLVM-fla target")
    b = lief.parse(str(binp))
    text = next(s for s in b.sections if s.name == ".text")
    code, tbase = bytes(text.content), text.virtual_address
    dec = [s for s in b.symbols if s.name == "decode" and s.size]
    assert dec, "decode() symbol not found"
    s = dec[0]

    r = D.deflatten(code, tbase, s.value, s.size)
    assert r["flattened"], r
    assert r["num_states"] == 6, r
    # direct-assignment form: there is NO xor update slot (that is what distinguishes it from
    # goldberg); the recoverer must still get the transitions, from the `mov [state], imm` stores.
    assert r["update_slot_disp"] is None, r
    assert r["start_state"] is not None, r

    states = {st["state"]: st for st in r["states"]}
    start = r["start_state"]
    assert start in states

    # full reachability (there are branches, so BFS not a single backbone) ending at a terminal
    seen, stack, saw_terminal = set(), [start], False
    while stack:
        cur = stack.pop()
        if cur in seen or cur not in states:
            continue
        seen.add(cur)
        st = states[cur]
        saw_terminal |= st["terminal"]
        stack.extend(st["next_states"])
    assert len(seen) == len(states), f"unreachable states: {set(states) - seen}"
    assert saw_terminal, "no terminal state reached"
    # the two real branches survive as two-way transitions
    two_way = [st for st in r["states"] if len(st["next_states"]) == 2]
    assert len(two_way) == 2, f"expected the loop test + parity branch as 2-way, got {two_way}"
    # closed graph
    for st in r["states"]:
        for n in st["next_states"]:
            assert n in states, f"transition to unknown state {n}"
