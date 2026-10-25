"""Devirtualization: lift RustCloak-virtualized bytecode back to a readable VM-assembly listing.

detect_vm says a function is virtualized; lift_vm goes further and decodes the embedded bytecode --
including the control-flow opcodes (JMP/JZ/JNZ), so branches and loops come back as labelled jumps.
This pins that the committed virtualized fixture lifts to the expected shapes: a branchless mixer
decodes to its arithmetic sequence, the loop function decodes WITH control flow, and an ordinary
build lifts to nothing (the detector gates the decode).
"""
import platform

import pytest
from conftest import ROOT

import lift_vm

VMFIX = ROOT / "tests" / "fixtures" / "vm" / "rustcloak_vm.x64"
PLAIN = ROOT / "tests" / "fixtures" / "vm" / "plain.x64"
_X64 = platform.machine() in ("x86_64", "AMD64")

pytestmark = pytest.mark.skipif(not _X64, reason="x86-64 fixtures")


def _mnemonics(fn):
    # strip the width suffix (add.i32 -> add) so tests compare base mnemonics
    return [text.split()[0].split(".")[0] for _, _, text in fn["listing"]]


@pytest.mark.skipif(not VMFIX.is_file(), reason="vm fixture missing")
def test_lifts_all_virtualized_functions():
    r = lift_vm.lift(VMFIX)
    assert r["count"] >= 4, f"expected at least 4 virtualized functions, lifted {r['count']}"
    # every listing ends in a ret and only uses known VM mnemonics
    known = {m for m, _ in lift_vm.OPS.values()}
    for fn in r["lifted"]:
        assert _mnemonics(fn)[-1] == "ret"
        assert set(_mnemonics(fn)) <= known


@pytest.mark.skipif(not VMFIX.is_file(), reason="vm fixture missing")
def test_memory_function_lifts_with_load_store():
    r = lift_vm.lift(VMFIX)
    mem = [f for f in r["lifted"] if f.get("has_memory")]
    assert mem, "a buffer function should lift with memory load/store ops"
    ms = set(_mnemonics(mem[0]))
    assert "load" in ms or "store" in ms
    # width-tagged ops render with their width (e.g. load.i8 / add.i32)
    assert any("." in text.split()[0] for _, _, text in mem[0]["listing"])


@pytest.mark.skipif(not VMFIX.is_file(), reason="vm fixture missing")
def test_branchless_mixer_decodes_to_its_arithmetic():
    r = lift_vm.lift(VMFIX)
    # the mix() function: 7 constants, no control flow, a chain of xor/shl/add/mul/lshr/...
    mixer = next((f for f in r["lifted"] if f["constants"] == 7 and not f["has_control_flow"]), None)
    assert mixer is not None, "did not find the branchless 7-constant mixer"
    ms = _mnemonics(mixer)
    for op in ("const", "xor", "shl", "add", "mul", "lshr", "or", "sub", "and"):
        assert op in ms, f"expected {op} in the lifted mixer, got {ms}"


@pytest.mark.skipif(not VMFIX.is_file(), reason="vm fixture missing")
def test_loop_function_lifts_with_control_flow():
    r = lift_vm.lift(VMFIX)
    cf = [f for f in r["lifted"] if f["has_control_flow"]]
    assert cf, "the loop function should lift WITH control flow (jmp/jz/jnz)"
    fn = cf[0]
    ms = _mnemonics(fn)
    assert "jmp" in ms and ("jnz" in ms or "jz" in ms), f"no branch opcodes in listing: {set(ms)}"
    assert fn["labels"], "control-flow listing should have jump labels"


@pytest.mark.skipif(not PLAIN.is_file(), reason="plain fixture missing")
def test_plain_build_lifts_nothing():
    assert lift_vm.lift(PLAIN)["count"] == 0
