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

x86-64, 32-bit x86, and AArch64 (cmp/cmn/tst + b.<cond>, and the reg-direct cbz/cbnz/tbz/tbnz). A
block that touches memory or calls out is abandoned (conservative); a richer lifter (memory,
cross-block) is the next tier.
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


# AArch64 condition code -> (taken) condition from a prior `cmp`/`cmn` (flag-setting). b.mi/pl/vs/vc
# depend on N/V in ways a simple compare does not model, so they are omitted (abandon).
_ARM_COND = {
    "eq": lambda a, b: a == b, "ne": lambda a, b: a != b,
    "cs": lambda a, b: z3.UGE(a, b), "hs": lambda a, b: z3.UGE(a, b),
    "cc": lambda a, b: z3.ULT(a, b), "lo": lambda a, b: z3.ULT(a, b),
    "hi": lambda a, b: z3.UGT(a, b), "ls": lambda a, b: z3.ULE(a, b),
    "ge": lambda a, b: a >= b, "lt": lambda a, b: a < b,
    "gt": lambda a, b: a > b, "le": lambda a, b: a <= b,
}


def _acanon(nm):
    if nm in ("wzr", "xzr"):
        return "xzr"
    return ("x" + nm[1:]) if nm and nm[0] == "w" else nm


def _lift_block_arm64(insns):
    """AArch64 analog of _lift_block: symbolically execute a straight-line integer block over 64-bit
    register BVs (w-registers masked to 32), tracking the last cmp/cmn/tst and the terminating branch
    (b.<cond> / cbz / cbnz / tbz / tbnz). ABANDON on memory, calls, or any unmodelled instruction, so
    it never lifts a wrong expression. Returns (regs, pending, term); pending is (kind, a, b, width)."""
    from capstone.arm64 import (ARM64_OP_IMM, ARM64_OP_MEM, ARM64_OP_REG,
                                ARM64_SFT_ASR, ARM64_SFT_LSL, ARM64_SFT_LSR)
    regs = {}
    pending = None
    term = None

    def wof(nm):
        return 32 if nm and nm[0] == "w" else 64

    def opval(op, insn):
        if op.type == ARM64_OP_IMM:
            v = z3.BitVecVal(op.imm & ((1 << 64) - 1), 64)
        elif op.type == ARM64_OP_REG:
            nm = insn.reg_name(op.reg)
            c = _acanon(nm)
            v = z3.BitVecVal(0, 64) if c == "xzr" else regs.setdefault(c, z3.BitVec("in_" + c, 64))
            if wof(nm) == 32:
                v = z3.ZeroExt(32, z3.Extract(31, 0, v))
        else:
            raise _Abandon("operand")
        sh = getattr(op, "shift", None)
        if sh is not None and getattr(sh, "type", 0):
            if sh.type == ARM64_SFT_LSL:
                v = v << sh.value
            elif sh.type == ARM64_SFT_LSR:
                v = z3.LShR(v, sh.value)
            elif sh.type == ARM64_SFT_ASR:
                v = v >> sh.value
            else:
                raise _Abandon("operand shift")
        if getattr(op, "ext", 0):
            raise _Abandon("operand extend")
        return v

    def setreg(op, insn, expr):
        if op.type != ARM64_OP_REG:
            raise _Abandon("write non-reg")
        nm = insn.reg_name(op.reg)
        c = _acanon(nm)
        if c == "xzr":
            return
        regs[c] = z3.ZeroExt(32, z3.Extract(31, 0, expr)) if wof(nm) == 32 else expr

    def pwidth(op, insn):
        return wof(insn.reg_name(op.reg)) if op.type == ARM64_OP_REG else 64

    for insn in insns:
        m = insn.mnemonic
        ops = insn.operands
        if m == "nop":
            continue
        if m in ("ret", "bl", "blr", "br", "svc", "hlt", "brk", "smc", "hvc", "movk"):
            raise _Abandon(m)
        if any(o.type == ARM64_OP_MEM for o in ops):
            raise _Abandon("memory")
        if m == "b" or m.startswith("b.") or m in ("cbz", "cbnz", "tbz", "tbnz"):
            term = insn
            break
        if m in ("mov", "movz"):
            setreg(ops[0], insn, opval(ops[1], insn))
        elif m in ("movn", "mvn"):
            setreg(ops[0], insn, ~opval(ops[1], insn))
        elif m == "neg":
            setreg(ops[0], insn, -opval(ops[1], insn))
        elif m in ("add", "sub", "and", "orr", "eor", "orn", "eon", "bic", "mul"):
            a, b = opval(ops[1], insn), opval(ops[2], insn)
            r = {"add": a + b, "sub": a - b, "and": a & b, "orr": a | b, "eor": a ^ b,
                 "orn": a | ~b, "eon": a ^ ~b, "bic": a & ~b, "mul": a * b}[m]
            setreg(ops[0], insn, r)
        elif m in ("lsl", "lsr", "asr"):
            a, b = opval(ops[1], insn), opval(ops[2], insn)
            setreg(ops[0], insn, {"lsl": a << b, "lsr": z3.LShR(a, b), "asr": a >> b}[m])
        elif m in ("sxtb", "sxth", "sxtw", "uxtb", "uxth", "uxtw"):
            bits = {"b": 8, "h": 16, "w": 32}[m[-1]]
            low = z3.Extract(bits - 1, 0, opval(ops[1], insn))
            setreg(ops[0], insn,
                   z3.SignExt(64 - bits, low) if m[0] == "s" else z3.ZeroExt(64 - bits, low))
        elif m == "cmp":
            pending = ("cmp", opval(ops[0], insn), opval(ops[1], insn), pwidth(ops[0], insn))
        elif m == "cmn":
            pending = ("cmp", opval(ops[0], insn), -opval(ops[1], insn), pwidth(ops[0], insn))
        elif m == "tst":
            pending = ("tst", opval(ops[0], insn), opval(ops[1], insn), pwidth(ops[0], insn))
        else:
            raise _Abandon(m)
    return regs, pending, term


def _classify_arm64(code, va):
    from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    try:
        regs, pending, term = _lift_block_arm64(list(md.disasm(code, va)))
    except _Abandon:
        return None
    if term is None:
        return None
    tm = term.mnemonic

    def regview(op):
        nm = term.reg_name(op.reg)
        c = _acanon(nm)
        full = z3.BitVecVal(0, 64) if c == "xzr" else regs.get(c, z3.BitVec("in_" + c, 64))
        return z3.Extract(31, 0, full) if (nm and nm[0] == "w") else full

    if tm in ("cbz", "cbnz"):
        v = regview(term.operands[0])
        zero = v == z3.BitVecVal(0, v.size())
        cond = zero if tm == "cbz" else z3.Not(zero)
    elif tm in ("tbz", "tbnz"):
        v = regview(term.operands[0])
        one = z3.BitVecVal(1, v.size())
        setb = (z3.LShR(v, term.operands[1].imm) & one) == one
        cond = z3.Not(setb) if tm == "tbz" else setb
    elif tm.startswith("b.") and pending is not None:
        cc = tm[2:]
        if cc not in _ARM_COND:
            return None
        kind, a, b, w = pending
        if w == 32:
            a, b = z3.Extract(31, 0, a), z3.Extract(31, 0, b)
        if kind == "cmp":
            cond = _ARM_COND[cc](a, b)
        else:   # tst a,b: ZF=(a&b)==0; b.eq taken iff zero
            z = (a & b) == z3.BitVecVal(0, a.size())
            cond = z if cc == "eq" else (z3.Not(z) if cc == "ne" else None)
        if cond is None:
            return None
    else:
        return None
    s = z3.Solver(); s.add(z3.Not(cond)); always_true = s.check() == z3.unsat
    s = z3.Solver(); s.add(cond); always_false = s.check() == z3.unsat
    if not (always_true or always_false):
        return None
    return {"branch_va": term.address, "jcc": tm,
            "result": "always-taken" if always_true else "never-taken",
            "dead_direction": "fall-through" if always_true else "target"}


def classify_block(code: bytes, va: int, arch: str = "x86_64"):
    """Lift the block at `va` and classify its terminating branch. Returns a dict or None (abandoned
    / not a conditional branch / input-dependent)."""
    if z3 is None:
        return None
    if arch == "aarch64":
        return _classify_arm64(code, va)
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
    arch = "aarch64" if img.arm else ("x86" if img.x32 else "x86_64")
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

    # --- AArch64 parity (hand-assembled with llvm-mc; no toolchain needed at test time) ---
    # (x1|1)!=0 is always true: orr x0,x1,#1; cmp x0,#0; b.ne -> always-taken
    a = classify_block(_asm_block("e00301aa" "000040b2" "1f0000f1" "41000054"), 0x1000, "aarch64")
    assert a and a["result"] == "always-taken" and a["jcc"] == "b.ne", a
    # (x1&0)==1 never: and x0,x1,xzr; cmp x0,#1; b.eq -> never-taken
    b = classify_block(_asm_block("20001f8a" "1f0400f1" "40000054"), 0x2000, "aarch64")
    assert b and b["result"] == "never-taken", b
    # tst: (x1|1)&1 != 0 always: orr x0,x1,#1; tst x0,#1; b.ne -> always-taken
    t = classify_block(_asm_block("200040b2" "1f0040f2" "41000054"), 0x2100, "aarch64")
    assert t and t["result"] == "always-taken", t
    # cbz on (x1|1), which is never 0 -> never-taken
    c = classify_block(_asm_block("200040b2" "400000b4"), 0x2200, "aarch64")
    assert c and c["result"] == "never-taken" and c["jcc"] == "cbz", c
    # tbz bit0 of (x1|1) (bit0 always set) -> never-taken
    tb = classify_block(_asm_block("200040b2" "40000036"), 0x2300, "aarch64")
    assert tb and tb["result"] == "never-taken" and tb["jcc"] == "tbz", tb
    # input-dependent signed 32-bit branch must NOT be flagged: cmp w0,#5; b.lt
    assert classify_block(_asm_block("1f140071" "4b000054"), 0x3000, "aarch64") is None
    # a memory load aarch64 block is abandoned: ldr x0,[x1]; cmp x0,#0; b.eq
    assert classify_block(_asm_block("200040f9" "1f0000f1" "40000054"), 0x4000, "aarch64") is None
    print("selftest OK: x86-64 + AArch64 opaque predicates classified (always/never-taken via "
          "cmp/tst/cbz/tbz); input-dependent and memory blocks not flagged (sound on both arches)")


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
