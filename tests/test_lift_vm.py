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
CALLFIX = ROOT / "tests" / "fixtures" / "vm" / "rustcloak_vm_call.x64"
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


# --- round 9: per-build randomized opcode encoding + map recovery ---------------------------------
RND = ROOT / "tests" / "fixtures" / "vm" / "rustcloak_vm_rnd.x64"


@pytest.mark.skipif(not RND.is_file(), reason="randomized fixture missing")
def test_randomized_build_opcodes_differ_from_fixed():
    # RustCloak randomizes the opcode->byte map per build: the two fixtures encode the same program
    # but share no opcode bytes for, e.g., CONST. (Sanity that the randomized fixture is different.)
    assert RND.read_bytes() != VMFIX.read_bytes()


@pytest.mark.skipif(not RND.is_file(), reason="randomized fixture missing")
def test_opcode_map_recovered_and_logic_reconstructed():
    # the lifter cannot assume opcode numbers OR operand bytes (both are randomized/encrypted per
    # build); it must recover the opcode map AND the operand key from the interpreter. Success =
    # it reconstructs a function's exact logic. check() is distinctive: a signed modulo and a
    # select guarded by two comparisons.
    r = lift_vm.lift(RND)
    assert r["count"] >= 1, "recovered no function from the randomized build"
    sigs = [set(_mnemonics(fn)) for fn in r["lifted"]]
    want = {"mul", "ashr", "xor", "srem", "eq", "sgt", "and", "cmovnz"}
    assert any(want <= s for s in sigs), \
        f"did not reconstruct check()'s logic from randomized opcodes; got {sigs}"


# --- round 12: virtualized CALL / PUSHARG --------------------------------------------------------
@pytest.mark.skipif(not CALLFIX.is_file(), reason="call fixture missing")
def test_virtualized_call_is_devirtualized():
    # RustCloak can virtualize a function's CALLs: arguments are staged via PUSHARG and the call is
    # dispatched through a per-function callee table (CALL). The lifter must decode both opcodes --
    # even though PUSHARG's handler jumps *directly* back to the dispatch loop (so a naive handler
    # reader would run it into the following CALL handler) and ADD/MUL are peeled out of the switch
    # into a compare-chain with a fall-through default. wrap() = helper(x,y) + helper(y,x)*3 must come
    # back as a C expression with two calls through the recovered callee index.
    r = lift_vm.lift(CALLFIX)
    assert r["count"] >= 1
    callfn = next((f for f in r["lifted"]
                   if any("call" == t.split()[0].split(".")[0] for _, _, t in f["listing"])), None)
    assert callfn is not None, "no function lifted with a CALL opcode"
    ms = _mnemonics(callfn)
    assert "call" in ms and "pusharg" in ms, f"CALL/PUSHARG not both present: {set(ms)}"
    pc = "\n".join(callfn["pseudocode"])
    assert pc.count("fn0(") == 2, f"expected two calls to the one callee in pseudocode: {pc!r}"
    assert "* 3" in pc and pc.startswith("return ")           # the *3 and a single return expression


def test_structurer_raises_goto_to_while_and_if():
    # the structurer turns a reducible if/goto body into structured while/if (correctness-preserving;
    # irreducible -O2-unrolled control flow is left as if/goto)
    stmts = [
        "L0010:", "    r3 = r1 + r2;", "    r4 = r3 & 1;", "    if (r4 != 0) goto L0010;",
        "    r5 = r3 > 100;", "    if (r5 == 0) goto L0030;", "    r6 = r3 + 7;",
        "L0030:", "    return r6;",
    ]
    out = "\n".join(lift_vm._structure(list(stmts)))
    assert "do {" in out and "} while (r4 != 0);" in out          # back-edge -> do/while
    assert "if (r5 != 0) {" in out                                 # forward skip -> inverted if
    assert "goto" not in out                                       # fully structured here


def test_cfg_layout_structures_a_noncontiguous_loop():
    # a reducible loop the compiler laid out non-contiguously: the test/header is at 0x20, the body at
    # the *lower* offset 0x08, the exit at 0x14. In offset order the peephole structurer cannot fold
    # it; the CFG layout reorders the basic blocks so the loop is contiguous and it raises cleanly to
    # while(1)+break. It also resolves branch targets to real instructions, so no goto dangles.
    W = 3 << 6
    C, ADD, ULE, JMP, JNZ, RET = W | 1, W | 2, W | 19, W | 28, W | 30, W | 0
    bm = {C: 1, ADD: 2, ULE: 19, JMP: 28, JNZ: 30, RET: 0}
    prog = [
        (0x00, C, 1, 0, 0),       # i = 0
        (0x04, JMP, 0, 0x20, 0),  # jump forward into the loop test
        (0x08, ADD, 2, 2, 1),     # body: acc += i
        (0x0c, ADD, 1, 1, 3),     # i += step
        (0x10, JMP, 0, 0x20, 0),  # back-edge to the test
        (0x14, RET, 0, 2, 0),     # exit: return acc
        (0x20, ULE, 4, 5, 1),     # header/test: r4 = (limit <= i)
        (0x24, JNZ, 4, 0x14, 0),  # if done -> exit
        (0x28, JMP, 0, 0x08, 0),  # else -> body
    ]
    pc = lift_vm.lift_region(0x1000, prog, bm, [0], None)["pseudocode"]
    body = "\n".join(pc)
    assert body.count("while (1)") == 1 and "break" in body       # the non-contiguous loop folds
    assert "goto" not in body                                      # fully structured, nothing dangles


@pytest.mark.skipif(not RND.is_file(), reason="randomized fixture missing")
def test_pseudocode_reconstructs_c_expression():
    # the lifter raises the recovered VM-assembly to C: resolve the constant pool, fold the
    # temporaries into one expression. check()'s body must come back as readable C with its real
    # constants (31, 97, the >1000 guard), from a VM with randomized opcodes AND encrypted operands.
    r = lift_vm.lift(RND)
    pc = next(("\n".join(fn["pseudocode"]) for fn in r["lifted"]
               if fn["pseudocode"] and not fn["has_control_flow"] and "% 97" in "\n".join(fn["pseudocode"])), None)
    assert pc is not None, "did not produce check()'s pseudocode"
    assert "* 31" in pc and "% 97" in pc and "> 1000" in pc   # pool constants resolved
    assert ">> 3" in pc and "?" in pc                          # the shift and the select
    assert pc.startswith("return ")
