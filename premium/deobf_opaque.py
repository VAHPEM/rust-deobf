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

Soundness guarantee (the requirement: a false claim makes a decompiler prune LIVE code):
  * Every register value starts as an unconstrained symbol, so the model covers every real entry
    state; a claim is made only when z3 proves the branch condition constant over ALL of them.
  * Registers are modelled at their architectural widths. x86: each GPR is one 64-bit (32-bit in
    i386 mode) value; 32-bit writes zero-extend, 8/16-bit writes merge into the untouched bits
    (ah/bh/ch/dh = bits 15:8), movzx/movsx/movsxd truncate+extend, and arithmetic, compares and
    flags are computed at the operand width. AArch64: w-register ops are computed at 32 bits (asr
    sign-extends from bit 31, register shift counts are taken mod the width) and zero-extend on write.
  * Condition flags are modelled per flag (x86 ZF/SF/CF/OF, AArch64 N/Z/C/V) by every modelled
    instruction that writes them -- so a later add/sub/and/shift/inc/neg/imul... replaces an earlier
    cmp's flags, never "remembers" it. Flags an instruction leaves architecturally undefined (imul
    ZF/SF, multi-bit shift OF, over-wide shift CF) or may leave unchanged (x86 shift by `cl`, which
    is a no-op on the flags when the masked count is 0) become UNKNOWN; a branch reading an unknown
    flag (or PF, never modelled) gets no claim. cmn/adds model carry/overflow of the addition
    exactly (not as `cmp a,-b`, which is wrong for b=0 / INT_MIN).
  * Anything not modelled exactly ABANDONS the block (no claim): memory operands, calls/returns,
    rip-relative addresses, non-GPR registers (segment/vector), adc/sbb/rotates through carry,
    1-operand mul/imul, extended-register operands, any unlisted mnemonic. Any unexpected error in
    one block is contained to that block (no claim) and never escapes recover().
So the detector says "always/never taken" only for a branch it fully understands; it is
deliberately incomplete (it misses opaque predicates that need memory or cross-block reasoning),
never unsound within that model. tests/test_opaque_differential.py checks the guarantee against
Unicorn emulation on randomly generated blocks.

    python3 premium/deobf_opaque.py path/to/binary            # opaque branches found
    python3 premium/deobf_opaque.py --selftest

x86-64, 32-bit x86, and AArch64 (cmp/cmn/tst/adds/subs/ands + b.<cond>, and the reg-direct
cbz/cbnz/tbz/tbnz). A richer lifter (memory, cross-block) is the next tier.
"""
from __future__ import annotations

import sys
from pathlib import Path

# ../scripts only in a source checkout (premium/ next to scripts/); installed, it would name
# site-packages/scripts -- not ours, and first on sys.path (VALIDATION §76). The installed core is
# put on the path by rust_deobf_premium/__init__.py (library) or PYTHONPATH (the CLI).
_h = Path(__file__).resolve().parent
for _p in [str(_h)] + ([str(_h.parent / "scripts")] if _h.name == "premium" and (_h.parent / "scripts" / "recover_emulate.py").is_file() else []):
    if _p not in sys.path:
        sys.path.insert(0, _p)

try:
    import z3
except Exception:
    z3 = None

_SOLVER_TIMEOUT_MS = 2000      # an `unknown` from z3 is never a claim
_LOADS = __import__("itertools").count(1)   # memory-read symbols: unique across lifts (a path lifts
                                            # two blocks; equal names would be one z3 variable)


class _Abandon(Exception):
    pass


def _mask(w):
    return (1 << w) - 1


# --------------------------------------------------------------------------------------- x86 ----
def _x86_regtable(full):
    """capstone register name -> (canonical full register, low bit, width) for the GPRs only."""
    t = {}
    if full == 64:
        for x in "abcd":
            c = "r%sx" % x
            t.update({c: (c, 0, 64), "e%sx" % x: (c, 0, 32), "%sx" % x: (c, 0, 16),
                      "%sl" % x: (c, 0, 8), "%sh" % x: (c, 8, 8)})
        for x in ("si", "di", "bp", "sp"):
            c = "r" + x
            t.update({c: (c, 0, 64), "e" + x: (c, 0, 32), x: (c, 0, 16), x + "l": (c, 0, 8)})
        for n in range(8, 16):
            c = "r%d" % n
            t.update({c: (c, 0, 64), c + "d": (c, 0, 32), c + "w": (c, 0, 16), c + "b": (c, 0, 8)})
    else:
        for x in "abcd":
            c = "e%sx" % x
            t.update({c: (c, 0, 32), "%sx" % x: (c, 0, 16), "%sl" % x: (c, 0, 8),
                      "%sh" % x: (c, 8, 8)})
        for x in ("si", "di", "bp", "sp"):
            t.update({"e" + x: ("e" + x, 0, 32), x: ("e" + x, 0, 16)})
    return t


_X86_REGS = {}

# jcc suffix -> (flags it reads, builder of the taken condition from those flags)
_X86_JCC = {
    "o": (("OF",), lambda f: f["OF"]), "no": (("OF",), lambda f: z3.Not(f["OF"])),
    "b": (("CF",), lambda f: f["CF"]), "c": (("CF",), lambda f: f["CF"]),
    "nae": (("CF",), lambda f: f["CF"]),
    "ae": (("CF",), lambda f: z3.Not(f["CF"])), "nb": (("CF",), lambda f: z3.Not(f["CF"])),
    "nc": (("CF",), lambda f: z3.Not(f["CF"])),
    "e": (("ZF",), lambda f: f["ZF"]), "z": (("ZF",), lambda f: f["ZF"]),
    "ne": (("ZF",), lambda f: z3.Not(f["ZF"])), "nz": (("ZF",), lambda f: z3.Not(f["ZF"])),
    "be": (("CF", "ZF"), lambda f: z3.Or(f["CF"], f["ZF"])),
    "na": (("CF", "ZF"), lambda f: z3.Or(f["CF"], f["ZF"])),
    "a": (("CF", "ZF"), lambda f: z3.And(z3.Not(f["CF"]), z3.Not(f["ZF"]))),
    "nbe": (("CF", "ZF"), lambda f: z3.And(z3.Not(f["CF"]), z3.Not(f["ZF"]))),
    "s": (("SF",), lambda f: f["SF"]), "ns": (("SF",), lambda f: z3.Not(f["SF"])),
    "l": (("SF", "OF"), lambda f: f["SF"] != f["OF"]),
    "nge": (("SF", "OF"), lambda f: f["SF"] != f["OF"]),
    "ge": (("SF", "OF"), lambda f: f["SF"] == f["OF"]),
    "nl": (("SF", "OF"), lambda f: f["SF"] == f["OF"]),
    "le": (("ZF", "SF", "OF"), lambda f: z3.Or(f["ZF"], f["SF"] != f["OF"])),
    "ng": (("ZF", "SF", "OF"), lambda f: z3.Or(f["ZF"], f["SF"] != f["OF"])),
    "g": (("ZF", "SF", "OF"), lambda f: z3.And(z3.Not(f["ZF"]), f["SF"] == f["OF"])),
    "nle": (("ZF", "SF", "OF"), lambda f: z3.And(z3.Not(f["ZF"]), f["SF"] == f["OF"])),
}


def _neg(x):
    return x < 0                     # z3 BV `<` is signed: the sign bit at x's own width


def _flags_add(a, b, r):
    return {"ZF": r == 0, "SF": _neg(r), "CF": z3.ULT(r, a),
            "OF": z3.And(_neg(a) == _neg(b), _neg(r) != _neg(a))}


def _flags_sub(a, b, r):
    return {"ZF": r == 0, "SF": _neg(r), "CF": z3.ULT(a, b),
            "OF": z3.And(_neg(a) != _neg(b), _neg(r) != _neg(a))}


def _flags_logic(r):
    return {"ZF": r == 0, "SF": _neg(r), "CF": z3.BoolVal(False), "OF": z3.BoolVal(False)}


def _bit(x, i):
    return z3.Extract(i, i, x) == 1


def _lift_block(insns, nbits=64, init=None):
    """Symbolically execute a straight-line integer x86 block. Returns (regs, flags, terminator) or
    raises _Abandon. regs: canonical full register -> z3 BV of `nbits`; flags: ZF/SF/CF/OF -> z3
    Bool, or None when unknown/undefined at that point."""
    from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_EIP, X86_REG_RIP
    table = _X86_REGS.setdefault(nbits, _x86_regtable(nbits))
    regs = dict(init[0]) if init else {}
    # unknown at block entry, or the predecessor's flags on a path (init)
    flags = dict(init[1]) if init else {"ZF": None, "SF": None, "CF": None, "OF": None}
    term = None

    def fresh_load(w):
        # a memory read is an UNCONSTRAINED value: every claim must hold whatever memory holds --
        # sound for always/never-taken (an OLLVM -bcf predicate over globals the program never
        # writes is opaque for all of their values). Each read is its own symbol, even of the same
        # address (an over-approximation: a store before it is ignored, never trusted).
        return z3.BitVec("mem%d" % next(_LOADS), w)

    def desc(insn, reg):
        d = table.get(insn.reg_name(reg))
        if d is None:
            raise _Abandon("non-GPR register")
        return d

    def full(c):
        if c not in regs:
            regs[c] = z3.BitVec("in_" + c, nbits)       # fresh symbol = arbitrary input
        return regs[c]

    def rd(insn, reg):
        c, lo, w = desc(insn, reg)
        v = full(c)
        return v if w == nbits else z3.Extract(lo + w - 1, lo, v)

    def wr(insn, op, v):
        if op.type == X86_OP_MEM:
            return                                       # a store: registers and flags unchanged
        if op.type != X86_OP_REG:
            raise _Abandon("write to non-register")
        c, lo, w = desc(insn, op.reg)
        if v.size() != w:
            raise _Abandon("width mismatch")
        if w == nbits:
            regs[c] = v
        elif w == 32 and nbits == 64:
            regs[c] = z3.ZeroExt(32, v)                  # 32-bit writes zero the upper half
        else:                                            # 8/16-bit writes merge
            old = full(c)
            parts = []
            if lo + w < nbits:
                parts.append(z3.Extract(nbits - 1, lo + w, old))
            parts.append(v)
            if lo > 0:
                parts.append(z3.Extract(lo - 1, 0, old))
            regs[c] = z3.Concat(*parts)

    def width(insn, op):
        if op.type == X86_OP_MEM and op.size in (1, 2, 4, 8):
            return 8 * op.size
        if op.type != X86_OP_REG:
            raise _Abandon("expected register")
        return desc(insn, op.reg)[2]

    def val(insn, op, w):
        if op.type == X86_OP_IMM:
            return z3.BitVecVal(op.imm & _mask(w), w)
        if op.type == X86_OP_MEM:
            if 8 * op.size != w:
                raise _Abandon("memory operand width")
            return fresh_load(w)
        if op.type == X86_OP_REG:
            v = rd(insn, op.reg)
            if v.size() != w:
                raise _Abandon("operand width mismatch")
            return v
        raise _Abandon("non-reg/imm operand")

    for insn in insns:
        m = insn.mnemonic
        ops = insn.operands
        if m in ("nop", "endbr64", "endbr32"):
            continue
        if m.startswith("j"):
            term = insn                     # a (conditional) jump ends the block
            break
        n = len(ops)
        if m in ("push", "pop") and n == 1 and ops[0].type == X86_OP_REG:
            sp = "rsp" if nbits == 64 else "esp"
            pw = nbits // 8
            if desc(insn, ops[0].reg)[2] != nbits or desc(insn, ops[0].reg)[0] == table[sp][0]:
                raise _Abandon("push/pop form")
            spc = table[sp][0]
            spv = full(spc)
            if m == "pop":
                wr(insn, ops[0], fresh_load(nbits))      # popped: an unconstrained value
            regs[spc] = spv - pw if m == "push" else spv + pw   # (a pushed value is never read back)
            continue
        if m in ("mov", "movabs") and n == 2:
            w = width(insn, ops[0])
            wr(insn, ops[0], val(insn, ops[1], w))
        elif m in ("movzx", "movsx", "movsxd") and n == 2:
            dw = width(insn, ops[0])
            if ops[1].type == X86_OP_MEM and ops[1].size in (1, 2, 4):
                src = fresh_load(8 * ops[1].size)
            elif ops[1].type != X86_OP_REG:
                raise _Abandon("movzx source")
            else:
                src = rd(insn, ops[1].reg)
            sw = src.size()
            if sw > dw:
                raise _Abandon("narrowing extend")
            ext = z3.ZeroExt if m == "movzx" else z3.SignExt
            wr(insn, ops[0], src if sw == dw else ext(dw - sw, src))
        elif m == "lea" and n == 2 and ops[1].type == X86_OP_MEM:
            dw = width(insn, ops[0])
            mem = ops[1].mem
            if mem.base in (X86_REG_RIP, X86_REG_EIP) or mem.index in (X86_REG_RIP, X86_REG_EIP):
                # the value depends on the load base (PIE): an unconstrained address, never a
                # constant -- sound, like a memory read
                wr(insn, ops[0], z3.BitVec("addr%d" % next(_LOADS), dw))
                continue
            e = z3.BitVecVal(mem.disp & _mask(nbits), nbits)
            for r, sc in ((mem.base, 1), (mem.index, mem.scale)):
                if r:
                    v = rd(insn, r)
                    if v.size() != nbits:
                        raise _Abandon("address-size override")
                    e = e + v * z3.BitVecVal(sc, nbits)
            wr(insn, ops[0], e if dw == nbits else z3.Extract(dw - 1, 0, e))
        elif m in ("add", "sub", "and", "or", "xor", "cmp", "test") and n == 2:
            w = width(insn, ops[0])
            a, b = val(insn, ops[0], w), val(insn, ops[1], w)
            if m in ("add",):
                r = a + b
                flags = _flags_add(a, b, r)
            elif m in ("sub", "cmp"):
                r = a - b
                flags = _flags_sub(a, b, r)
            else:
                r = {"and": a & b, "test": a & b, "or": a | b, "xor": a ^ b}[m]
                flags = _flags_logic(r)
            if m not in ("cmp", "test"):
                wr(insn, ops[0], r)
        elif m in ("inc", "dec", "neg", "not") and n == 1:
            w = width(insn, ops[0])
            a = val(insn, ops[0], w)
            if m == "not":
                wr(insn, ops[0], ~a)                     # not writes no flags
                continue
            if m == "inc":
                r = a + 1
                of = a == z3.BitVecVal(_mask(w - 1), w)          # INT_MAX + 1 overflows
                flags = {"ZF": r == 0, "SF": _neg(r), "CF": flags["CF"], "OF": of}   # CF kept
            elif m == "dec":
                r = a - 1
                of = a == z3.BitVecVal(1 << (w - 1), w)          # INT_MIN - 1 overflows
                flags = {"ZF": r == 0, "SF": _neg(r), "CF": flags["CF"], "OF": of}
            else:
                r = -a
                flags = {"ZF": r == 0, "SF": _neg(r), "CF": a != 0,
                         "OF": a == z3.BitVecVal(1 << (w - 1), w)}
            wr(insn, ops[0], r)
        elif m == "imul" and n in (2, 3):
            w = width(insn, ops[0])
            if n == 2:
                a, b = val(insn, ops[0], w), val(insn, ops[1], w)
            else:
                if ops[2].type != X86_OP_IMM:
                    raise _Abandon("imul form")
                a, b = val(insn, ops[1], w), val(insn, ops[2], w)
            r = a * b
            ovf = z3.SignExt(w, a) * z3.SignExt(w, b) != z3.SignExt(w, r)
            flags = {"ZF": None, "SF": None, "CF": ovf, "OF": ovf}   # ZF/SF undefined after imul
            wr(insn, ops[0], r)
        elif m in ("shl", "sal", "shr", "sar") and n in (1, 2):
            w = width(insn, ops[0])
            a = val(insn, ops[0], w)
            cmask = 63 if w == 64 else 31                # x86 masks the count to 5/6 bits
            if n == 1 or ops[1].type == X86_OP_IMM:
                c = (1 if n == 1 else ops[1].imm) & cmask
                if c == 0:
                    wr(insn, ops[0], a)                  # count 0: value kept, flags untouched
                    continue
                cv = z3.BitVecVal(c, w)
                r = {"shl": a << cv, "sal": a << cv, "shr": z3.LShR(a, cv), "sar": a >> cv}[m]
                if c < w:
                    cf = _bit(a, w - c) if m in ("shl", "sal") else _bit(a, c - 1)
                else:
                    cf = None                            # undefined for count >= width
                if c == 1:
                    of = {"shl": None, "sal": None, "shr": _bit(a, w - 1),
                          "sar": z3.BoolVal(False)}[m]
                    if of is None:                       # shl by 1: OF = MSB(result) xor CF
                        of = z3.Xor(_bit(r, w - 1), cf)
                else:
                    of = None                            # undefined for multi-bit shifts
                flags = {"ZF": r == 0, "SF": _neg(r), "CF": cf, "OF": of}
            elif ops[1].type == X86_OP_REG and insn.reg_name(ops[1].reg) == "cl":
                cl = rd(insn, ops[1].reg)
                cnt = (z3.ZeroExt(w - 8, cl) if w > 8 else cl) & z3.BitVecVal(cmask, w)
                r = {"shl": a << cnt, "sal": a << cnt, "shr": z3.LShR(a, cnt), "sar": a >> cnt}[m]
                # flags are untouched when the masked count is 0, else set: unknown either way
                flags = {"ZF": None, "SF": None, "CF": None, "OF": None}
            else:
                raise _Abandon("shift form")
            wr(insn, ops[0], r)
        else:
            raise _Abandon(m)    # incl. adc/sbb/rol/ror/bt*/xchg/cmov/set*/1-op mul/div/push/call...
    return regs, flags, term


def _cond_x86(_regs, flags, term):
    """The taken-condition of the block's terminating jcc, or None (no claim possible)."""
    if term is None or not term.mnemonic.startswith("j"):
        return None
    jcc = _X86_JCC.get(term.mnemonic[1:])
    if jcc is None:                     # jmp / jrcxz / jp (PF is never modelled) ...
        return None
    need, build = jcc
    if any(flags[f] is None for f in need):
        return None                     # reads a flag we do not know exactly: no claim
    return build(flags)


def _md(arch):
    from capstone import (CS_ARCH_ARM64, CS_ARCH_X86, CS_MODE_32, CS_MODE_64,
                          CS_MODE_LITTLE_ENDIAN, Cs)
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN) if arch == "aarch64" else \
        Cs(CS_ARCH_X86, CS_MODE_32 if arch == "x86" else CS_MODE_64)
    md.detail = True
    return md


def _lift(arch, code, va, init=None):
    insns = list(_md(arch).disasm(code, va))
    if arch == "aarch64":
        return _lift_block_arm64(insns, init)
    return _lift_block(insns, 32 if arch == "x86" else 64, init)


def _cond(arch, state):
    return _cond_arm64(*state) if arch == "aarch64" else _cond_x86(*state)


def _classify_x86(code, va, nbits):
    state = _lift("x86" if nbits == 32 else "x86_64", code, va)
    cond = _cond_x86(*state)
    return None if cond is None else _decide(cond, state[2])


# ------------------------------------------------------------------------------------- AArch64 --
# condition code -> taken condition over the NZCV flags (b.al / b.nv are not predicates)
_ARM_COND = {
    "eq": lambda f: f["Z"], "ne": lambda f: z3.Not(f["Z"]),
    "cs": lambda f: f["C"], "hs": lambda f: f["C"],
    "cc": lambda f: z3.Not(f["C"]), "lo": lambda f: z3.Not(f["C"]),
    "mi": lambda f: f["N"], "pl": lambda f: z3.Not(f["N"]),
    "vs": lambda f: f["V"], "vc": lambda f: z3.Not(f["V"]),
    "hi": lambda f: z3.And(f["C"], z3.Not(f["Z"])), "ls": lambda f: z3.Or(z3.Not(f["C"]), f["Z"]),
    "ge": lambda f: f["N"] == f["V"], "lt": lambda f: f["N"] != f["V"],
    "gt": lambda f: z3.And(z3.Not(f["Z"]), f["N"] == f["V"]),
    "le": lambda f: z3.Or(f["Z"], f["N"] != f["V"]),
}


def _acanon(nm):
    """GPR name -> (canonical 64-bit name, width); raises _Abandon for non-GPRs (v0, d0, ...)."""
    if nm in ("xzr", "wzr"):
        return "xzr", 64 if nm[0] == "x" else 32
    if nm in ("sp", "wsp"):
        return "sp", 64 if nm == "sp" else 32
    if nm in ("fp", "lr"):                       # capstone's names for x29 / x30
        return ("x29" if nm == "fp" else "x30"), 64
    if nm and nm[0] in "xw" and nm[1:].isdigit() and 0 <= int(nm[1:]) <= 30:
        return "x" + nm[1:], 64 if nm[0] == "x" else 32
    raise _Abandon("non-GPR register " + str(nm))


def _aflags_add(a, b, r):
    return {"N": _neg(r), "Z": r == 0, "C": z3.ULT(r, a),
            "V": z3.And(_neg(a) == _neg(b), _neg(r) != _neg(a))}


def _aflags_sub(a, b, r):
    return {"N": _neg(r), "Z": r == 0, "C": z3.UGE(a, b),        # C = NOT borrow
            "V": z3.And(_neg(a) != _neg(b), _neg(r) != _neg(a))}


def _aflags_logic(r):
    return {"N": _neg(r), "Z": r == 0, "C": z3.BoolVal(False), "V": z3.BoolVal(False)}


def _lift_block_arm64(insns, init=None):
    """AArch64 analog of _lift_block: symbolically execute a straight-line integer block, each op at
    its register width (w = 32, x = 64; w writes zero-extend), tracking NZCV exactly through
    cmp/cmn/tst/adds/subs/ands/bics/negs and the terminating branch (b.<cond> / cbz / cbnz / tbz /
    tbnz). ABANDON on memory, calls, extended-register operands, non-GPRs, or any unmodelled
    instruction. Returns (regs, flags, term); flags N/Z/C/V -> z3 Bool or None (unknown)."""
    from capstone.arm64 import (ARM64_OP_IMM, ARM64_OP_MEM, ARM64_OP_REG, ARM64_SFT_ASR,
                                ARM64_SFT_LSL, ARM64_SFT_LSR, ARM64_SFT_ROR)
    regs = dict(init[0]) if init else {}
    flags = dict(init[1]) if init else {"N": None, "Z": None, "C": None, "V": None}
    term = None

    def rdname(nm):
        c, w = _acanon(nm)
        if c == "xzr":
            return z3.BitVecVal(0, w)
        v = regs.setdefault(c, z3.BitVec("in_" + c, 64))
        return v if w == 64 else z3.Extract(31, 0, v)

    def width(op, insn):
        if op.type != ARM64_OP_REG:
            raise _Abandon("expected register")
        return _acanon(insn.reg_name(op.reg))[1]

    def opval(op, insn, w):
        if getattr(op, "ext", 0) or getattr(op, "vector_index", -1) != -1:
            raise _Abandon("operand extend / vector lane")
        if op.type == ARM64_OP_IMM:
            v = z3.BitVecVal(op.imm & _mask(w), w)
        elif op.type == ARM64_OP_REG:
            v = rdname(insn.reg_name(op.reg))
            if v.size() != w:
                raise _Abandon("operand width mismatch")
        else:
            raise _Abandon("operand")
        sh = getattr(op, "shift", None)
        if sh is not None and getattr(sh, "type", 0):
            s = sh.value
            if not 0 <= s < w:
                raise _Abandon("shift amount")
            sv = z3.BitVecVal(s, w)
            if sh.type == ARM64_SFT_LSL:
                v = v << sv
            elif sh.type == ARM64_SFT_LSR:
                v = z3.LShR(v, sv)
            elif sh.type == ARM64_SFT_ASR:
                v = v >> sv                      # arithmetic at the operand width
            elif sh.type == ARM64_SFT_ROR and op.type == ARM64_OP_REG:
                v = z3.RotateRight(v, sv)
            else:
                raise _Abandon("operand shift")
        return v

    def setreg(op, insn, expr):
        if op.type != ARM64_OP_REG:
            raise _Abandon("write non-reg")
        c, w = _acanon(insn.reg_name(op.reg))
        if expr.size() != w:
            raise _Abandon("width mismatch")
        if c == "xzr":
            return
        regs[c] = z3.ZeroExt(32, expr) if w == 32 else expr

    for insn in insns:
        m = insn.mnemonic
        ops = insn.operands
        n = len(ops)
        if m == "nop":
            continue
        if any(o.type == ARM64_OP_MEM for o in ops):
            # loads give unconstrained values and stores are ignored (see the x86 lifter); a
            # pre/post-index writeback changes the base register: not modelled -> abandon
            post_index = n >= 2 and ops[-1].type == ARM64_OP_IMM and ops[-2].type == ARM64_OP_MEM
            wb = None                          # (base register, new value) of a pre/post-index
            if getattr(insn, "writeback", False) or post_index:
                mop = next(o for o in ops if o.type == ARM64_OP_MEM)
                if mop.mem.index:
                    raise _Abandon("memory writeback with index")
                bname = insn.reg_name(mop.mem.base)
                step = ops[-1].imm if post_index else mop.mem.disp
                wb = (mop, rdname(bname) + z3.BitVecVal(step & _mask(64), 64))
                if _acanon(bname)[1] != 64:
                    raise _Abandon("writeback base width")
                if post_index:
                    ops = ops[:-1]
                    n -= 1
            ld = {"ldr": None, "ldur": None, "ldrb": 8, "ldurb": 8, "ldrh": 16, "ldurh": 16,
                  "ldrsb": -8, "ldursb": -8, "ldrsh": -16, "ldursh": -16, "ldrsw": -32,
                  "ldursw": -32}
            def writeback():
                if wb is not None:
                    c = _acanon(insn.reg_name(wb[0].mem.base))[0]
                    if c != "xzr":
                        regs[c] = wb[1]
            if m in ld and n == 2:
                w = width(ops[0], insn)
                k = ld[m]
                if wb is not None and _acanon(insn.reg_name(ops[0].reg))[0] == \
                        _acanon(insn.reg_name(wb[0].mem.base))[0]:
                    raise _Abandon("load into its own writeback base")
                if k is None:
                    setreg(ops[0], insn, z3.BitVec("mem%d" % next(_LOADS), w))
                else:
                    v = z3.BitVec("mem%d" % next(_LOADS), abs(k))
                    if abs(k) > w:
                        raise _Abandon("load width")
                    ext = z3.SignExt if k < 0 else z3.ZeroExt
                    setreg(ops[0], insn, v if abs(k) == w else ext(w - abs(k), v))
                writeback()
                continue
            if m == "ldp" and n == 3:
                base_c = _acanon(insn.reg_name(ops[2].mem.base))[0]
                if wb is not None and base_c in {_acanon(insn.reg_name(o.reg))[0] for o in ops[:2]}:
                    raise _Abandon("load pair into its own writeback base")
                for o in ops[:2]:
                    setreg(o, insn, z3.BitVec("mem%d" % next(_LOADS), width(o, insn)))
                writeback()
                continue
            if m in ("str", "stur", "strb", "sturb", "strh", "sturh", "stp"):
                writeback()                    # a store: only a writeback changes a register
                continue
            raise _Abandon("memory")
        if m == "b" or m.startswith("b.") or m in ("cbz", "cbnz", "tbz", "tbnz"):
            term = insn
            break
        if m in ("adrp", "adr") and n == 2:
            # a PC-relative address: depends on the load base -- unconstrained (see x86 rip lea)
            setreg(ops[0], insn, z3.BitVec("addr%d" % next(_LOADS), width(ops[0], insn)))
            continue
        if m in ("mov", "movz") and n == 2:
            w = width(ops[0], insn)
            setreg(ops[0], insn, opval(ops[1], insn, w))
        elif m in ("movn", "mvn") and n == 2:
            w = width(ops[0], insn)
            setreg(ops[0], insn, ~opval(ops[1], insn, w))
        elif m == "movk" and n == 2 and ops[1].type == ARM64_OP_IMM:
            w = width(ops[0], insn)
            sh = getattr(ops[1], "shift", None)
            s = sh.value if (sh is not None and getattr(sh, "type", 0)) else 0
            if (sh is not None and getattr(sh, "type", 0) not in (0, ARM64_SFT_LSL)) \
                    or s % 16 or s >= w or not 0 <= ops[1].imm <= 0xffff:
                raise _Abandon("movk form")
            old = rdname(insn.reg_name(ops[0].reg))
            keep = z3.BitVecVal(_mask(w) & ~(0xffff << s), w)
            setreg(ops[0], insn, (old & keep) | z3.BitVecVal(ops[1].imm << s, w))
        elif m in ("neg", "negs") and n == 2:
            w = width(ops[0], insn)
            b = opval(ops[1], insn, w)
            zero = z3.BitVecVal(0, w)
            r = zero - b
            if m == "negs":
                flags = _aflags_sub(zero, b, r)
            setreg(ops[0], insn, r)
        elif m in ("add", "sub", "adds", "subs", "and", "ands", "orr", "eor", "orn", "eon", "bic",
                   "bics", "mul") and n == 3:
            w = width(ops[0], insn)
            a, b = opval(ops[1], insn, w), opval(ops[2], insn, w)
            base = m[:-1] if m in ("adds", "subs", "ands", "bics") else m
            r = {"add": a + b, "sub": a - b, "and": a & b, "orr": a | b, "eor": a ^ b,
                 "orn": a | ~b, "eon": a ^ ~b, "bic": a & ~b, "mul": a * b}[base]
            if m == "adds":
                flags = _aflags_add(a, b, r)
            elif m == "subs":
                flags = _aflags_sub(a, b, r)
            elif m in ("ands", "bics"):
                flags = _aflags_logic(r)
            setreg(ops[0], insn, r)
        elif m in ("lsl", "lsr", "asr", "ror") and n == 3:
            w = width(ops[0], insn)
            a = opval(ops[1], insn, w)
            if ops[2].type == ARM64_OP_IMM:
                if not 0 <= ops[2].imm < w:
                    raise _Abandon("shift amount")
                cnt = z3.BitVecVal(ops[2].imm, w)
            else:
                cnt = opval(ops[2], insn, w) & z3.BitVecVal(w - 1, w)   # count mod width
            r = {"lsl": a << cnt, "lsr": z3.LShR(a, cnt), "asr": a >> cnt,
                 "ror": z3.RotateRight(a, cnt)}[m]
            setreg(ops[0], insn, r)
        elif m in ("sxtb", "sxth", "sxtw", "uxtb", "uxth") and n == 2:
            bits = {"b": 8, "h": 16, "w": 32}[m[-1]]
            dw = width(ops[0], insn)
            src = opval(ops[1], insn, 32)                # the source is always a w-register
            if bits > dw:
                raise _Abandon("extend width")
            low = z3.Extract(bits - 1, 0, src)
            ext = z3.SignExt if m[0] == "s" else z3.ZeroExt
            setreg(ops[0], insn, low if bits == dw else ext(dw - bits, low))
        elif m in ("cmp", "cmn", "tst") and n == 2:
            w = width(ops[0], insn)
            a, b = opval(ops[0], insn, w), opval(ops[1], insn, w)
            if m == "cmp":
                flags = _aflags_sub(a, b, a - b)
            elif m == "cmn":
                flags = _aflags_add(a, b, a + b)         # carry/overflow of the ADDITION
            else:
                flags = _aflags_logic(a & b)
        else:
            raise _Abandon(m)    # incl. ccmp/csel/adc/madd/bfm/ubfx/... and every other mnemonic
    return regs, flags, term


def _classify_arm64(code, va):
    state = _lift("aarch64", code, va)
    cond = _cond_arm64(*state)
    return None if cond is None else _decide(cond, state[2])


def _cond_arm64(regs, flags, term):
    """The taken-condition of the block's terminating branch, or None (no claim possible)."""
    if term is None:
        return None
    tm = term.mnemonic

    def regview(op):
        c, w = _acanon(term.reg_name(op.reg))
        if c == "xzr":
            return z3.BitVecVal(0, w)
        full = regs.get(c, z3.BitVec("in_" + c, 64))
        return z3.Extract(31, 0, full) if w == 32 else full

    if tm in ("cbz", "cbnz"):
        v = regview(term.operands[0])
        zero = v == z3.BitVecVal(0, v.size())
        cond = zero if tm == "cbz" else z3.Not(zero)
    elif tm in ("tbz", "tbnz"):
        v = regview(term.operands[0])
        bit = term.operands[1].imm
        if not 0 <= bit < v.size():
            return None
        setb = _bit(v, bit)
        cond = z3.Not(setb) if tm == "tbz" else setb
    elif tm.startswith("b."):
        build = _ARM_COND.get(tm[2:])
        if build is None:
            return None
        need = {"eq": "Z", "ne": "Z", "cs": "C", "hs": "C", "cc": "C", "lo": "C", "mi": "N",
                "pl": "N", "vs": "V", "vc": "V", "hi": "CZ", "ls": "CZ", "ge": "NV", "lt": "NV",
                "gt": "ZNV", "le": "ZNV"}[tm[2:]]
        if any(flags[f] is None for f in need):
            return None
        cond = build(flags)
    else:
        return None
    return cond


# ---------------------------------------------------------------------------------- decision --
def _unsat(c):
    s = z3.Solver()
    s.set("timeout", _SOLVER_TIMEOUT_MS)
    s.add(c)
    return s.check() == z3.unsat        # sat or unknown (timeout) -> not proven


def _decide(cond, term, assume=None):
    """Always / never taken -- for every input, or (assume: a path condition) for every input on
    that path: unsat(assume and not cond) / unsat(assume and cond). (Not via Implies(assume, cond):
    an implication is true wherever the path is not taken, so "never" could never be shown.)"""
    a = assume if assume is not None else z3.BoolVal(True)
    always_true = _unsat(z3.And(a, z3.Not(cond)))
    always_false = (not always_true) and _unsat(z3.And(a, cond))
    if not (always_true or always_false):
        return None                     # input-dependent: a real branch, not opaque
    return {"branch_va": term.address, "jcc": term.mnemonic,
            "result": "always-taken" if always_true else "never-taken",
            "dead_direction": "fall-through" if always_true else "target",
            # opaque: the condition reads inputs (registers, memory) and is constant anyway --
            # an inserted predicate. constant: it simplifies to true/false with no input left --
            # a branch the compiler did not fold (`mov al,1; test al,al; je`), not obfuscation
            "kind": "opaque" if _has_inputs(z3.simplify(cond)) else "constant"}


def _has_inputs(e):
    seen, stack = set(), [e]
    while stack:
        x = stack.pop()
        if x.get_id() in seen:
            continue
        seen.add(x.get_id())
        if z3.is_const(x) and x.decl().kind() == z3.Z3_OP_UNINTERPRETED:
            return True
        stack.extend(x.children())
    return False


def classify_block(code: bytes, va: int, arch: str = "x86_64"):
    """Lift the block at `va` and classify its terminating branch. Returns a dict or None (abandoned
    / not a conditional branch / input-dependent). Never raises: an unexpected error in the lifter
    or solver means "no claim" for this block (sound), not a crash of the whole scan."""
    if z3 is None:
        return None
    try:
        if arch == "aarch64":
            return _classify_arm64(code, va)
        return _classify_x86(code, va, 32 if arch == "x86" else 64)
    except _Abandon:
        return None
    except Exception:       # noqa: BLE001 -- containment: one odd block must not kill recover()
        return None


def classify_path(pred: bytes, pred_va: int, taken: bool | None, code: bytes, va: int,
                  arch: str = "x86_64"):
    """Classify the block at `va` as reached from the block at `pred_va` -- its ONLY predecessor --
    over the edge `taken` (True: pred's branch taken, False: its fall-through, None: an
    unconditional jump or straight fall-through). pred's registers and flags flow into the block
    and the edge's condition is assumed. Sound only when the caller knows every predecessor of the
    block (recover() requires a function without indirect jumps). Never raises."""
    if z3 is None:
        return None
    try:
        p_state = _lift(arch, pred, pred_va)
        assume = z3.BoolVal(True)
        if taken is not None:
            pc = _cond(arch, p_state)
            if pc is None:
                return None
            assume = pc if taken else z3.Not(pc)
        b_state = _lift(arch, code, va, init=(p_state[0], p_state[1]))
        cond = _cond(arch, b_state)
        if cond is None or _unsat(assume):
            return None
        # constant by itself once the predecessor's computation flows in (an OLLVM -bcf predicate
        # computed in one block and tested in the next): opaque / constant as for one block
        r = _decide(cond, b_state[2])
        if r is None:
            # constant only GIVEN the edge's condition: a check implied by an earlier one (a
            # redundant bounds check the compiler kept: `a+b < n` then `n-(a+b)-1 < n`) -- true,
            # but not an inserted predicate
            r = _decide(cond, b_state[2], assume)
            if r is None:
                return None
            r["kind"] = "implied"
        r["via"] = pred_va                # proven on the path through this predecessor
        return r
    except _Abandon:
        return None
    except Exception:       # noqa: BLE001 -- containment, as classify_block
        return None


_BRANCHES_A64 = ("b", "br", "ret", "cbz", "cbnz", "tbz", "tbnz")
MAX_BLOCKS = 512                     # per function


def _function_blocks(img, arch, lo, hi):
    """Recursive descent over [lo, hi): {block start: (end, [(succ, taken)])} and whether the
    function has an indirect jump (then predecessor sets are not known to be complete)."""
    md = _md(arch)
    code, base = img.code, img.text_va
    leaders, work, indirect = {lo}, [lo], False
    ends = {}
    while work and len(ends) < MAX_BLOCKS:
        a = work.pop()
        if a in ends or not lo <= a < hi:
            continue
        succ, end = [], a
        for ins in md.disasm(code[a - base:hi - base], a):
            end = ins.address + ins.size
            m = ins.mnemonic
            if arch == "aarch64":
                cond = m.startswith("b.") or m in ("cbz", "cbnz", "tbz", "tbnz")
                jump = m == "b"
                stop = cond or m in _BRANCHES_A64
                if m == "br":
                    indirect = True
            else:
                cond = m.startswith("j") and m != "jmp"
                jump = m == "jmp"
                stop = m.startswith("j") or m.startswith("ret")
                if jump and ins.operands and ins.operands[0].type != 2:     # jmp reg / [mem]
                    indirect = True
            if cond or jump:
                t = ins.operands[-1].imm if ins.operands and ins.operands[-1].type == 2 else None
                if t is not None and lo <= t < hi:
                    succ.append((t, True if cond else None))
                    leaders.add(t)
                    work.append(t)
                elif cond or t is None:
                    indirect = indirect or t is None
            if cond:
                succ.append((end, False))
                leaders.add(end)
                work.append(end)
            if stop:
                break
        ends[a] = (end, succ)
    # split blocks at leaders found later (a straight fall-through into a leader is an edge)
    blocks = {}
    for a in sorted(ends):
        end, succ = ends[a]
        cut = next((x for x in sorted(leaders) if a < x < end), None)
        blocks[a] = (cut, [(cut, None)]) if cut is not None else (end, succ)
    return blocks, indirect


def recover(path) -> dict:
    """Scan every block of every function (recursive descent) for an opaque terminating branch:
    alone first, then -- in functions without indirect jumps, where the predecessor set is known
    -- through its single predecessor (a predicate computed in one block and tested in the next,
    the -O2 shape of an OLLVM -bcf guard)."""
    import recover_emulate
    import gen_runtime_sigs
    img = recover_emulate.Image(path)
    arch = "aarch64" if img.arm else ("x86" if img.x32 else "x86_64")
    starts = sorted(a for a in gen_runtime_sigs.function_starts(img.binary)
                    if img.text_va <= a < img.text_end)
    nexts = {s: n for s, n in zip(starts, starts[1:] + [img.text_end])}
    out = []
    blocks_seen = 0

    def raw(a, e):
        return img.code[a - img.text_va:min(e, a + 256) - img.text_va]
    for s in starts:
        try:
            blocks, indirect = _function_blocks(img, arch, s, nexts[s])
        except Exception:   # noqa: BLE001 -- one odd function must not end the scan
            continue
        blocks_seen += len(blocks)
        preds = {}
        for a, (_e, succ) in blocks.items():
            for t, taken in succ:
                if t is not None:
                    preds.setdefault(t, []).append((a, taken))
        for a, (e, _succ) in sorted(blocks.items()):
            r = classify_block(raw(a, e), a, arch)
            if r is None and not indirect and a != s and len(preds.get(a, ())) == 1:
                p, taken = preds[a][0]
                if blocks[p][0] - p <= 256:          # the WHOLE predecessor, never a truncation
                    r = classify_path(raw(p, blocks[p][0]), p, taken, raw(a, e), a, arch)
            if r:
                out.append(r)
    return {"arch": arch, "functions": len(starts), "blocks": blocks_seen,
            "opaque_branches": [r for r in out if r["kind"] == "opaque"],
            "constant_branches": [r for r in out if r["kind"] == "constant"],
            "implied_branches": [r for r in out if r["kind"] == "implied"]}


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
    # widths/flags are architectural: mov eax,-1; add eax,1 wraps to 0 in 32 bits -> je always taken
    w = classify_block(_asm_block("b8ffffffff" "83c001" "85c0" "7402"), 0x5000, "x86_64")
    assert w and w["result"] == "always-taken", w
    # a later flag write replaces the cmp: cmp rax,rax; sub rdi,1; je -> input-dependent
    assert classify_block(_asm_block("4839c0" "4883ef01" "7402"), 0x5100, "x86_64") is None
    # cmn x0,#0 never carries: b.hs never taken (the old `cmp a,-b` model said always)
    h = classify_block(_asm_block("1f0000b1" "42000054"), 0x5200, "aarch64")
    assert h and h["result"] == "never-taken", h
    print("selftest OK: x86-64 + AArch64 opaque predicates classified (always/never-taken via "
          "cmp/tst/cmn/cbz/tbz) at architectural widths with exact flags; input-dependent, stale-"
          "compare and memory blocks not flagged (sound on both arches)")


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
