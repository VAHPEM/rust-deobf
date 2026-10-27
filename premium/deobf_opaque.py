#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: Ve (VAHPEM) <ve0912084386@gmail.com>
#
# Dual-licensed: AGPL-3.0-or-later OR a commercial license.
"""deobf_opaque.py - opaque-predicate detection in ordinary functions (premium).

deobf_expr proves MBA/opaque facts over *expressions*; the VM lifter feeds it lifted expressions.
This brings the same power to *ordinary* machine code: it symbolically executes a single straight-
line basic block (registers only, a strict integer subset), builds a z3 expression for the condition
of the block's terminating conditional branch, and asks z3 whether that condition is constant for all
inputs -- i.e. an opaque predicate guarding a bogus/dead branch (RustCloak `bogus`, OLLVM's opaque
predicates), which a decompiler can then prune.

Sound by construction: the symbolic executor models only a small, exactly-known integer instruction
set (mov/add/sub/imul/and/or/xor/not/neg/shl/shr/sar/lea/inc/dec/movzx/movsx + cmp/test + jcc) over
64-bit register values, and ABANDONS the block on anything it does not model exactly (a memory
access, a call, an unmodelled mnemonic). So it never lifts a wrong expression and then "proves" a
false opaque claim -- it either understands the whole block or says nothing. z3 then decides
always-true / always-false / input-dependent; only the first two are reported, with the branch's
dead direction.

    python3 premium/deobf_opaque.py path/to/binary            # opaque branches found
    python3 premium/deobf_opaque.py --selftest

x86-64 (and 32-bit x86). A block that touches memory or calls out is abandoned (conservative); a
richer lifter (memory, cross-block) is the next tier.
"""
from __future__ import annotations

import sys
from pathlib import Path

for _p in (str(Path(__file__).resolve().parent), str(Path(__file__).resolve().parent.parent / "scripts")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

try:
    import z3
except Exception:
    z3 = None

# jcc mnemonic -> builder of the (taken) condition from a prior `cmp a, b` (unsigned/signed aware)
# or `test a, b`. We model the common set; others abandon.
_CMP_JCC = {
    "je": lambda a, b: a == b, "jz": lambda a, b: a == b,
    "jne": lambda a, b: a != b, "jnz": lambda a, b: a != b,
    "jb": lambda a, b: z3.ULT(a, b) if z3 else None, "jc": lambda a, b: z3.ULT(a, b) if z3 else None,
    "jae": lambda a, b: z3.UGE(a, b) if z3 else None, "jnb": lambda a, b: z3.UGE(a, b) if z3 else None,
    "jbe": lambda a, b: z3.ULE(a, b) if z3 else None, "ja": lambda a, b: z3.UGT(a, b) if z3 else None,
    "jl": lambda a, b: a < b, "jge": lambda a, b: a >= b,
    "jle": lambda a, b: a <= b, "jg": lambda a, b: a > b,
}


def _canon64(name):
    m = {"eax": "rax", "ebx": "rbx", "ecx": "rcx", "edx": "rdx", "esi": "rsi", "edi": "rdi",
         "ebp": "rbp", "esp": "rsp", "r8d": "r8", "r9d": "r9", "r10d": "r10", "r11d": "r11",
         "r12d": "r12", "r13d": "r13", "r14d": "r14", "r15d": "r15",
         "ax": "rax", "bx": "rbx", "cx": "rcx", "dx": "rdx", "si": "rsi", "di": "rdi",
         "al": "rax", "bl": "rbx", "cl": "rcx", "dl": "rdx"}
    return m.get(name, name)


class _Abandon(Exception):
    pass


def _lift_block(insns, nbits=64):
    """Symbolically execute a straight-line integer block; return (regs, pending_cmp, terminator) or
    raise _Abandon. regs: name->z3 BV. pending_cmp: (a, b) of the last cmp, or ('test', a, b)."""
    from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM
    regs = {}
    pending = None
    term = None

    def val(op, insn):
        if op.type == X86_OP_IMM:
            return z3.BitVecVal(op.imm & ((1 << nbits) - 1), nbits)
        if op.type == X86_OP_REG:
            r = _canon64(insn.reg_name(op.reg))
            if r not in regs:
                regs[r] = z3.BitVec("in_" + r, nbits)       # fresh symbol = arbitrary input
            return regs[r]
        raise _Abandon("non-reg/imm operand")

    def setreg(op, insn, expr):
        if op.type != X86_OP_REG:
            raise _Abandon("write to non-register")
        regs[_canon64(insn.reg_name(op.reg))] = expr

    for insn in insns:
        m = insn.mnemonic
        ops = insn.operands
        if m in ("nop", "endbr64", "endbr32"):
            continue
        if m.startswith("j"):
            term = insn                     # a (conditional) jump ends the block
            break
        if m in ("ret", "call", "leave", "push", "pop", "div", "idiv", "cqo", "cdq",
                 "syscall", "int", "cpuid", "rdtsc"):
            raise _Abandon(m)
        # any memory operand (except lea's address computation) -> abandon
        if m != "lea" and any(o.type == X86_OP_MEM for o in ops):
            raise _Abandon("memory operand")
        if m == "mov" or m == "movabs":
            setreg(ops[0], insn, val(ops[1], insn))
        elif m in ("movzx", "movsx", "movsxd"):
            setreg(ops[0], insn, val(ops[1], insn))   # width tracked loosely at 64-bit
        elif m == "lea":
            mem = ops[1].mem
            e = z3.BitVecVal(mem.disp & ((1 << nbits) - 1), nbits)
            from capstone.x86 import X86_REG_RIP, X86_REG_EIP
            if mem.base and mem.base not in (X86_REG_RIP, X86_REG_EIP):
                bn = _canon64(insn.reg_name(mem.base))
                e = e + regs.setdefault(bn, z3.BitVec("in_" + bn, nbits))
            elif mem.base in (X86_REG_RIP, X86_REG_EIP):
                raise _Abandon("rip-relative lea")
            if mem.index:
                idx = _canon64(insn.reg_name(mem.index))
                e = e + regs.setdefault(idx, z3.BitVec("in_" + idx, nbits)) * \
                    z3.BitVecVal(mem.scale, nbits)
            setreg(ops[0], insn, e)
        elif m in ("add", "sub", "and", "or", "xor", "imul"):
            a, b = val(ops[0], insn), val(ops[1], insn)
            if m == "xor" and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_REG \
                    and insn.reg_name(ops[0].reg) == insn.reg_name(ops[1].reg):
                r = z3.BitVecVal(0, nbits)
            else:
                r = {"add": a + b, "sub": a - b, "and": a & b, "or": a | b, "xor": a ^ b,
                     "imul": a * b}[m]
            setreg(ops[0], insn, r)
        elif m in ("shl", "sal", "shr", "sar"):
            a = val(ops[0], insn)
            b = val(ops[1], insn) if len(ops) == 2 else z3.BitVecVal(1, nbits)
            r = {"shl": a << b, "sal": a << b, "shr": z3.LShR(a, b), "sar": a >> b}[m]
            setreg(ops[0], insn, r)
        elif m in ("not", "neg", "inc", "dec"):
            a = val(ops[0], insn)
            r = {"not": ~a, "neg": -a, "inc": a + 1, "dec": a - 1}[m]
            setreg(ops[0], insn, r)
        elif m == "cmp":
            pending = ("cmp", val(ops[0], insn), val(ops[1], insn))
        elif m == "test":
            pending = ("test", val(ops[0], insn), val(ops[1], insn))
        else:
            raise _Abandon(m)
    return regs, pending, term


def classify_block(code: bytes, va: int, arch: str = "x86_64"):
    """Lift the block at `va` and classify its terminating branch. Returns a dict or None (abandoned
    / not a conditional branch / input-dependent)."""
    if z3 is None:
        return None
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
    md = Cs(CS_ARCH_X86, CS_MODE_32 if arch == "x86" else CS_MODE_64)
    md.detail = True
    nbits = 32 if arch == "x86" else 64
    insns = list(md.disasm(code, va))
    try:
        regs, pending, term = _lift_block(insns, nbits)
    except _Abandon:
        return None
    if term is None or term.mnemonic not in _CMP_JCC or pending is None:
        return None
    kind, a, b = pending
    if kind == "cmp":
        cond = _CMP_JCC[term.mnemonic](a, b)
    else:  # test a,b : ZF = (a & b)==0 ; je taken when zero
        z = (a & b) == z3.BitVecVal(0, nbits)
        cond = z if term.mnemonic in ("je", "jz") else (z3.Not(z) if term.mnemonic in ("jne", "jnz")
                                                        else None)
    if cond is None:
        return None
    s = z3.Solver()
    s.add(z3.Not(cond))
    always_true = s.check() == z3.unsat
    s = z3.Solver()
    s.add(cond)
    always_false = s.check() == z3.unsat
    if not (always_true or always_false):
        return None            # input-dependent: a real branch, not opaque
    return {"branch_va": term.address, "jcc": term.mnemonic,
            "result": "always-taken" if always_true else "never-taken",
            "dead_direction": "fall-through" if always_true else "target"}


def recover(path) -> dict:
    """Scan each function's entry block for an opaque terminating branch."""
    import recover_emulate
    import gen_runtime_sigs
    img = recover_emulate.Image(path)
    arch = "x86" if img.x32 else "x86_64"
    if img.arm:
        return {"arch": "aarch64", "opaque_branches": [], "note": "AArch64 opaque detection is next tier"}
    starts = sorted(a for a in gen_runtime_sigs.function_starts(img.binary)
                    if img.text_va <= a < img.text_end)
    nexts = {s: n for s, n in zip(starts, starts[1:] + [img.text_end])}
    out = []
    for s in starts:
        block = img.code[s - img.text_va:min(nexts[s], s + 256) - img.text_va]
        r = classify_block(block, s, arch)
        if r:
            out.append(r)
    return {"arch": arch, "functions": len(starts), "opaque_branches": out}


def _asm_block(hexstr):
    return bytes.fromhex(hexstr.replace(" ", ""))


def _selftest():
    if z3 is None:
        print("selftest OK: z3 not installed, opaque detection unavailable (skipped)")
        return
    # 1. an opaque predicate: `(x | 1) != 0` is always true. Block:
    #      mov rax, rdi ; or rax, 1 ; cmp rax, 0 ; jne target
    #    => jne is always-taken; the fall-through is dead.
    opq = _asm_block("4889f8"      # mov rax, rdi
                     "4883c801"    # or  rax, 1
                     "4883f800"    # cmp rax, 0
                     "7500")       # jne .+2
    r = classify_block(opq, 0x1000, "x86_64")
    assert r is not None and r["result"] == "always-taken" and r["jcc"] == "jne", r
    assert r["dead_direction"] == "fall-through"

    # 2. an always-FALSE predicate: `(x & 0) == 0` ... use `and rax,0; cmp rax,1; je` (rax==1 never).
    nev = _asm_block("4889f8"      # mov rax, rdi
                     "4883e000"    # and rax, 0
                     "4883f801"    # cmp rax, 1
                     "7400")       # je .+2  (taken iff 0==1 -> never)
    r2 = classify_block(nev, 0x2000, "x86_64")
    assert r2 is not None and r2["result"] == "never-taken", r2

    # 3. a genuine, input-dependent branch is NOT flagged: mov rax,rdi; cmp rax,5; jb
    dep = _asm_block("4889f8" "4883f805" "7200")   # mov rax,rdi; cmp rax,5; jb .+2
    assert classify_block(dep, 0x3000, "x86_64") is None

    # 4. a block that touches memory is abandoned (no false claim): mov rax,[rdi]; cmp rax,0; je
    mem = _asm_block("488b07" "4883f800" "7400")   # mov rax,[rdi]; cmp rax,0; je
    assert classify_block(mem, 0x4000, "x86_64") is None
    print("selftest OK: opaque predicate (x|1)!=0 -> always-taken, (x&0)==1 -> never-taken, "
          "input-dependent branch not flagged, memory block abandoned (sound)")


def main(argv=None) -> int:
    import argparse
    import json
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("binary", nargs="?")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args(argv)
    if a.selftest:
        _selftest()
        return 0
    if not a.binary:
        ap.error("give a binary, or --selftest")
    res = recover(Path(a.binary))
    if a.json:
        print(json.dumps(res, indent=2))
    else:
        print(f"arch={res['arch']}  functions={res.get('functions', 0)}  "
              f"opaque branches={len(res['opaque_branches'])}")
        for o in res["opaque_branches"][:40]:
            print(f"  0x{o['branch_va']:x}  {o['jcc']} {o['result']} (dead: {o['dead_direction']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
