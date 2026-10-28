#!/usr/bin/env python3
"""opt_reverse.py - reverse compiler optimizations before structuring (premium).

Oxidizer (IEEE S&P 2026) names "revert optimizations before structuring" as decompilation's #1 open
problem. Two optimizations dominate what makes recovered control flow unreadable, and both are
mechanical to undo:

  * un-switch jump tables  -  a `match` / `switch` lowers to an indirect jump through a table of
    offsets; the structure (case -> target) is implicit in the table. recover_jump_tables() reads
    the table back to an explicit {case index: target} map, so the devirtualizer / deflattener (and
    any downstream decompiler) see a switch, not a `jmp rax`.
  * detect unrolled loops  -  `-O2` unrolls a small loop into N identical copies of its body; the
    loop is gone. detect_unrolled_loops() finds the repeated-body run and its stride/count, the
    fact a re-roller (or a reader) needs to collapse it back to one loop.

This is a reusable analysis, not tied to one engine: the deflattener's relooper and the VM
devirtualizer both dispatch through jump tables, and so does ordinary optimized code a decompiler
reads. x86-64 (the `lea table; movsxd [table+idx*4]; add; jmp` rel32 idiom), 32-bit x86 PIC (the
GOT-relative `[ebx+idx*4-off]` table, GOT from a pc thunk + `add ebx, imm`) and AArch64
(`adr|adrp+add table; adr anchor; ldrsw [table+idx*4]; add; br`, plus LLVM's compressed 1/2-byte
tables `ldrb|ldrh ...; add ..., lsl #2`). A table's length always comes from the dominating bound
(`cmp idx, K` + `ja`/`jae` on x86, `cmp idx, #K` on AArch64), followed through register copies of the
bounded index (a u32 index zero-extended by `mov eax, edi` / `mov w8, w0`); with no bound, no table.

    python3 premium/opt_reverse.py path/to/binary            # list recovered jump tables
    python3 premium/opt_reverse.py path/to/binary --loops    # + unrolled-loop runs
    python3 premium/opt_reverse.py --selftest

Premium module: dual-licensed AGPL-3.0-or-later OR Commercial (see LICENSING.md).
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "premium"))

_MAX_CASES = 4096          # a sane upper bound on switch arms


_CANON = {"eax": "rax", "edi": "rdi", "esi": "rsi", "edx": "rdx", "ecx": "rcx", "ebx": "rbx",
          "ebp": "rbp", "esp": "rsp", "ax": "rax", "di": "rdi", "si": "rsi", "dx": "rdx",
          "cx": "rcx", "bx": "rbx", "bp": "rbp", "sp": "rsp", "al": "rax", "dil": "rdi",
          "sil": "rsi", "dl": "rdx", "cl": "rcx", "bl": "rbx", "bpl": "rbp", "spl": "rsp",
          "ah": "rax", "bh": "rbx", "ch": "rcx", "dh": "rdx"}
# registers a call preserves (SysV): a value in one of these survives an intervening call
_CALLEE_SAVED = {"x86": {"rbx", "rbp", "rsi", "rdi"},
                 "x86_64": {"rbx", "rbp", "r12", "r13", "r14", "r15"}}


def _canon(name: str) -> str:
    """The 64-bit register a sub-register belongs to (edi/di/dil -> rdi, r8d/r8w/r8b -> r8)."""
    if name in _CANON:
        return _CANON[name]
    if name.startswith("r") and name[-1] in "dwb" and name[1:-1].isdigit():
        return name[:-1]
    return name


def _md(arch: str):
    """A detail-mode capstone disassembler for `arch` (x86_64 / x86 / aarch64)."""
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
    if arch == "aarch64":
        from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
        md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    else:
        md = Cs(CS_ARCH_X86, CS_MODE_32 if arch == "x86" else CS_MODE_64)
    md.detail = True
    return md


def _writes(insn, c):
    """True if `insn` writes canonical register `c` (explicitly or implicitly). Conservative: an
    instruction capstone cannot describe counts as writing it."""
    try:
        _r, w = insn.regs_access()
    except Exception:
        return True
    return any(_canon(insn.reg_name(r)) == c for r in w)


def _is_reg(op):
    from capstone.x86 import X86_OP_REG
    return op.type == X86_OP_REG


def _block_edge(insn):
    """An instruction that ends straight-line flow backwards-scanning cannot see past."""
    return insn.mnemonic in ("jmp", "ret", "retf", "ud2", "hlt") or insn.mnemonic.startswith("ret")


def _x86_index_bound(insns, k, idx, arch):
    """Count of a table indexed by canonical register `idx` at insns[k], from a dominating bound
    `cmp r, K` + `ja` (count K+1) / `jae` (count K) on a register holding the SAME value as idx.
    Values are numbered forward over the preceding straight-line window: a reg-to-reg mov / movzx /
    movsxd copies its source's value (`cmp edi, K; ja ..; mov eax, edi; ... [base + rax*4]`, or the
    copy made before the cmp); any other write, a call (caller-saved regs), or a block edge gives a
    fresh value. No bounded value at the load -> None: the count must come from a bound, never be
    guessed."""
    from capstone.x86 import X86_OP_IMM
    vals, bound, fresh = {}, {}, [0]

    def new():
        fresh[0] += 1
        return fresh[0]

    def val(c):
        if c not in vals:
            vals[c] = new()
        return vals[c]
    lo = max(0, k - 24)
    for p in range(lo, k):
        w = insns[p]
        ops = w.operands
        if _block_edge(w):
            vals.clear()
            bound.clear()
            continue
        if w.mnemonic == "cmp" and len(ops) == 2 and _is_reg(ops[0]) and ops[1].type == X86_OP_IMM:
            nxt = insns[p + 1].mnemonic if p + 1 < k else ""   # the jump to the default arm
            cnt = {"ja": 1, "jnbe": 1, "jae": 0, "jnb": 0, "jnc": 0}.get(nxt)
            if cnt is not None:
                bound[val(_canon(w.reg_name(ops[0].reg)))] = ops[1].imm + cnt
            continue
        if w.mnemonic.startswith("call"):
            for c in list(vals):
                if c not in _CALLEE_SAVED[arch]:
                    del vals[c]
        if w.mnemonic in ("mov", "movzx", "movsxd") and len(ops) == 2 and _is_reg(ops[0]) \
                and _is_reg(ops[1]):
            vals[_canon(w.reg_name(ops[0].reg))] = val(_canon(w.reg_name(ops[1].reg)))
            continue
        try:
            _r, wr = w.regs_access()
        except Exception:
            vals.clear()
            continue
        for r in wr:
            vals[_canon(w.reg_name(r))] = new()
    return bound.get(val(idx))


def _x86_pc_thunk(insns, p, B, code, base):
    """i386 PIC: the PC that insns[p-1] (just before `add B, GOT-PC`) loads into B, or None.
    Recognises `call L; L: pop B` and `call __x86.get_pc_thunk.<B>` (`mov B, [esp]; ret`)."""
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    from capstone.x86 import X86_OP_IMM, X86_OP_MEM
    if p < 1:
        return None
    w = insns[p - 1]
    if w.mnemonic == "pop" and len(w.operands) == 1 and _is_reg(w.operands[0]) \
            and _canon(w.reg_name(w.operands[0].reg)) == B and p >= 2:
        c = insns[p - 2]
        if c.mnemonic == "call" and c.operands and c.operands[0].type == X86_OP_IMM \
                and c.operands[0].imm == w.address:
            return w.address
        return None
    if w.mnemonic == "call" and w.operands and w.operands[0].type == X86_OP_IMM:
        t = w.operands[0].imm - base
        if not 0 <= t < len(code):
            return None
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        md.detail = True
        th = list(md.disasm(code[t:t + 8], base + t, 2))
        if len(th) == 2 and th[0].mnemonic == "mov" and len(th[0].operands) == 2 \
                and _is_reg(th[0].operands[0]) and _canon(th[0].reg_name(th[0].operands[0].reg)) == B \
                and th[0].operands[1].type == X86_OP_MEM and th[0].operands[1].mem.index == 0 \
                and th[0].operands[1].mem.disp == 0 \
                and _canon(th[0].reg_name(th[0].operands[1].mem.base)) == "rsp" \
                and th[1].mnemonic == "ret":
            return w.address + w.size
    return None


def _x86_base_value(insns, k, B, arch, code, base):
    """The value of table-base register B (canonical) at insns[k]: x86-64 `lea B, [rip + d]`, or
    i386 PIC's GOT pointer (`<pc thunk>; add B, imm`). Scans back to B's defining instruction; any
    other definition, a call clobbering it, or a block edge -> None."""
    from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_EIP, X86_REG_RIP
    for p in range(k - 1, max(-1, k - 64), -1):
        w = insns[p]
        ops = w.operands
        dst = _canon(w.reg_name(ops[0].reg)) if ops and _is_reg(ops[0]) else None
        if w.mnemonic == "lea" and dst == B and len(ops) == 2 and ops[1].type == X86_OP_MEM:
            mem = ops[1].mem
            if mem.base in (X86_REG_RIP, X86_REG_EIP) and mem.index == 0:
                return w.address + w.size + mem.disp   # rip-relative: from the NEXT insn
            return None
        if arch == "x86" and w.mnemonic == "add" and dst == B and len(ops) == 2 \
                and ops[1].type == X86_OP_IMM:
            pc = _x86_pc_thunk(insns, p, B, code, base)
            return None if pc is None else (pc + ops[1].imm) & 0xffffffff
        if _block_edge(w):
            return None
        if w.mnemonic.startswith("call") and B not in _CALLEE_SAVED[arch]:
            return None
        if _writes(w, B):
            return None
    return None


def recover_jump_tables(code: bytes, base: int, arch: str, read_i32, text_lo: int, text_hi: int):
    """Scan x86 `code` (loaded at VA `base`) for the relative jump-table idiom and recover each switch:
        cmp idx, K ; ja default            (the bound; jae -> K cases; a mov/movzx copy may follow)
        lea B, [rip + table]               (x86-64)  |  i386 PIC: B = GOT (pc thunk; add B, imm)
        movsxd|mov T, [B + idx*4 + disp]   (table = B + disp; entries are offsets from B)
        add T, B ; jmp T
    read_i32(va) -> signed 32-bit table entry at `va` (from the data section holding the table), or
    None if unmapped. Returns [{jmp_va, table_va, index_reg, count, default, cases:{i:target}}]."""
    from capstone.x86 import X86_OP_MEM
    md = _md(arch)
    insns = list(md.disasm(code, base))
    amask = (1 << (64 if arch != "x86" else 32)) - 1
    out = []
    for i, jmp in enumerate(insns):
        if jmp.mnemonic != "jmp" or len(jmp.operands) != 1 or not _is_reg(jmp.operands[0]):
            continue
        tgt = _canon(jmp.reg_name(jmp.operands[0].reg))
        # back from the jmp: `add T, B` then the table load `T <- [B + idx*4 + disp]`; nothing else
        # in between may write T, and nothing between the load and the add may write B
        add_k = load_k = None
        for p in range(i - 1, max(-1, i - 6), -1):
            w = insns[p]
            ops = w.operands
            if add_k is None:
                if w.mnemonic == "add" and len(ops) == 2 and _is_reg(ops[0]) and _is_reg(ops[1]) \
                        and _canon(w.reg_name(ops[0].reg)) == tgt \
                        and _canon(w.reg_name(ops[1].reg)) != tgt:     # `add T, T` is no base
                    add_k = p
                elif _writes(w, tgt) or _block_edge(w):
                    break
                continue
            B = _canon(insns[add_k].reg_name(insns[add_k].operands[1].reg))
            if w.mnemonic in ("movsxd", "mov") and len(ops) == 2 and _is_reg(ops[0]) \
                    and _canon(w.reg_name(ops[0].reg)) == tgt and ops[1].type == X86_OP_MEM:
                mem = ops[1].mem
                if mem.base and mem.index and mem.scale == 4 \
                        and _canon(w.reg_name(mem.base)) == B:
                    load_k = p
                break
            if _writes(w, tgt) or _writes(w, B) or _block_edge(w):
                break
        if add_k is None or load_k is None:
            continue
        load = insns[load_k]
        B = _canon(insns[add_k].reg_name(insns[add_k].operands[1].reg))
        mem = load.operands[1].mem
        index_reg = mem.index
        base_val = _x86_base_value(insns, load_k, B, arch, code, base)
        if base_val is None:
            continue
        table_va = (base_val + mem.disp) & amask
        # bound: REQUIRED -- without it the table length is unknown and reading "until an entry
        # leaves .text" over-reads into adjacent data that coincidentally points into code
        # (observed: 700-case phantom tables), so a bounded, exact recovery beats a guessed one
        count = _x86_index_bound(insns, load_k, _canon(load.reg_name(index_reg)), arch)
        if count is None or not (0 < count <= _MAX_CASES):
            continue
        # x86-64 `mov r32, [..]` zero-extends its entry; movsxd (and i386's 32-bit add) sign-extend
        unsigned = arch != "x86" and load.mnemonic == "mov" and load.operands[0].size == 4
        cases = {}
        for k in range(count):
            entry = read_i32(table_va + 4 * k)
            if entry is None:
                break
            if unsigned:
                entry &= 0xffffffff
            target = (base_val + entry) & amask
            if not (text_lo <= target < text_hi):
                break
            cases[k] = target
        if len(cases) == count:            # every bounded entry resolved into code: a real table
            out.append({"jmp_va": jmp.address, "table_va": table_va,
                        "index_reg": md.reg_name(index_reg), "count": count,
                        "default": None, "cases": cases})
    return out


import re as _re
_A64_LDRSW = _re.compile(r"^(\w+), \[(\w+), (\w+), lsl #2\]$")
_A64_ADD = _re.compile(r"^(\w+), (\w+), (\w+)$")
_A64_IMM = _re.compile(r"^(\w+), #(0x[0-9a-f]+|\d+)$")
# general forms: an entry load `ldr{sw,b,h} Rt, [Xtbl, Ridx{, lsl|uxtw|sxtw #s}]` and the target add
# `add Xdst, Xa, Xb{, lsl|sxtw #k}` (LLVM's *compressed* AArch64 tables scale a 1/2-byte entry by 4)
_A64_LDX = _re.compile(r"^(\w+), \[(\w+), (\w+)(?:, (?:lsl|uxtw|sxtw) #(\d+))?\]$")
_A64_ADDX = _re.compile(r"^(\w+), (\w+), (\w+)(?:, (?:lsl|sxtw|uxtw) #(\d+))?$")
_A64_ADDI = _re.compile(r"^(\w+), (\w+), #(0x[0-9a-f]+|\d+)$")
# entry width/signedness per load mnemonic, and the index scale it must use
_A64_ENTRY = {"ldrsw": (4, True, 2), "ldr": (4, True, 2), "ldrh": (2, False, 1), "ldrb": (1, False, 0)}


def _xr(r):
    """Canonical 64-bit name, so `ldrb w10` feeds `add x9, x9, x10` and `cmp w0` bounds `x0`."""
    return "x" + r[1:] if r and r[0] == "w" and r[1:].isdigit() else r


def _a64_index_bound(before, idx):
    """`cmp r, #K` bounding the table index (count K+1) over `before` (the straight-line instructions
    preceding the table load), where r holds the SAME value as the index register. Values are
    numbered forward: a reg-to-reg `mov` copies its source's value (clang: `mov w8, w0; cmp w0, #K;
    b.hi ..; mov w8, w8; ... ldrb w11, [x9, x8]`); any other write, a call (caller-saved regs) or a
    block edge gives a fresh value. No bounded value at the load -> None (no bound, no table)."""
    vals, bound, fresh = {}, {}, [0]
    saved = {"x%d" % n for n in range(19, 29)} | {"x29", "sp"}

    def new():
        fresh[0] += 1
        return fresh[0]

    def val(c):
        if c not in vals:
            vals[c] = new()
        return vals[c]
    for w in before:
        m = w.mnemonic
        if m == "cmp":                           # writes only NZCV (capstone lists Rn as written)
            mm = _A64_IMM.match(w.op_str)
            if mm:
                bound[val(_xr(mm.group(1)))] = int(mm.group(2), 0) + 1
            continue
        if m in ("b", "br", "ret", "braa", "brab", "retaa", "retab"):
            vals.clear()
            bound.clear()
            continue
        if m in ("bl", "blr"):
            for c in list(vals):
                if c not in saved:
                    del vals[c]
            continue
        ops = w.op_str.split(", ")
        if m == "mov" and len(ops) == 2 and _re.fullmatch(r"[wx]\d+", ops[0]) \
                and _re.fullmatch(r"[wx]\d+", ops[1]):
            vals[_xr(ops[0])] = val(_xr(ops[1]))
            continue
        try:
            _r, wr = w.regs_access()
        except Exception:
            vals.clear()
            continue
        for r in wr:
            vals[_xr(w.reg_name(r))] = new()
    return bound.get(val(idx))


def recover_jump_tables_arm64(code, base, read_i32, text_lo, text_hi, read_bytes=None):
    """AArch64 jump tables. LLVM lowers a dense `match`/`switch` to one of:
        cmp  idx, #K ; b.hi default
        adr|adrp(+add) Xtbl, <table>   ; table base (adr in range, adrp+add when the table is far)
        adr  Xanchor, <anchor>         ; the base the entries are added to
        ldrsw Xt, [Xtbl, idx, lsl #2]  ; rel32 table            -> target = anchor + entry
        ldrh  Wt, [Xtbl, idx, lsl #1]  ; compressed 16-bit table -> target = anchor + entry * 4
        ldrb  Wt, [Xtbl, idx]          ; compressed 8-bit table  -> target = anchor + entry * 4
        add  Xdst, Xanchor, Xt{, lsl #2}
        br   Xdst
    recovered to {index: target}. capstone resolves each adr/adrp immediate to an absolute address.
    `read_bytes(va, n)` (optional) reads 1/2-byte entries; without it they are derived from
    `read_i32` (which needs 4 readable bytes)."""
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True                     # regs_access: who writes the index between bound and load
    insns = list(md.disasm(code, base))

    def read_entry(va, size, signed):
        if read_bytes is not None:
            raw = read_bytes(va, size)
            if raw is None or len(raw) < size:
                return None
            return int.from_bytes(raw[:size], "little", signed=signed)
        v = read_i32(va)
        if v is None:
            return None
        if size == 4:
            return v if signed else v & 0xffffffff
        v &= (1 << (8 * size)) - 1
        if signed and v & (1 << (8 * size - 1)):
            v -= 1 << (8 * size)
        return v

    out = []
    for i, br in enumerate(insns):
        if br.mnemonic != "br":
            continue
        dst = _xr(br.op_str.strip())
        win = insns[max(0, i - 12):i]
        regs = {}                   # reg -> absolute address materialized by adr / adrp(+add #imm)
        for w in win:
            if w.mnemonic in ("adr", "adrp"):
                m = _A64_IMM.match(w.op_str)
                if m:
                    regs[_xr(m.group(1))] = int(m.group(2), 0)
            elif w.mnemonic == "add":
                m = _A64_ADDI.match(w.op_str)
                if m and _xr(m.group(2)) in regs:
                    regs[_xr(m.group(1))] = regs[_xr(m.group(2))] + int(m.group(3), 0)
        add_a = add_t = tbl_reg = idx_reg = kind = load_w = None
        shift = 0
        for w in reversed(win):
            if add_a is None and w.mnemonic == "add":
                m = _A64_ADDX.match(w.op_str)
                if m and _xr(m.group(1)) == dst:
                    a, t = _xr(m.group(2)), _xr(m.group(3))
                    if t in regs and a not in regs:     # `add Xd, Xoff, Xanchor` operand order
                        a, t = t, a
                    add_a, add_t, shift = a, t, int(m.group(4) or 0)
            elif add_t is not None and tbl_reg is None and w.mnemonic in _A64_ENTRY:
                m = _A64_LDX.match(w.op_str)
                if m and _xr(m.group(1)) == add_t:
                    size, _signed, scale = _A64_ENTRY[w.mnemonic]
                    if int(m.group(4) or 0) == scale:
                        tbl_reg, idx_reg, kind = _xr(m.group(2)), _xr(m.group(3)), w.mnemonic
                        load_w = w
        if tbl_reg is None or add_a is None:
            continue
        table_va, anchor = regs.get(tbl_reg), regs.get(add_a)
        if table_va is None or anchor is None:
            continue
        size, signed, _scale = _A64_ENTRY[kind]
        count = _a64_index_bound(win[:win.index(load_w)], idx_reg)
        if count is None or not (0 < count <= _MAX_CASES):
            continue
        cases = {}
        for k in range(count):
            entry = read_entry(table_va + size * k, size, signed)
            if entry is None:
                break
            target = (anchor + (entry << shift)) & ((1 << 64) - 1)
            if not (text_lo <= target < text_hi):
                break
            cases[k] = target
        if len(cases) == count:
            out.append({"br_va": br.address, "table_va": table_va, "anchor": anchor,
                        "index_reg": idx_reg, "count": count, "default": None, "cases": cases,
                        "entry_size": size})
    return out


def detect_unrolled_loops(code: bytes, base: int, arch: str, min_repeat: int = 3):
    """Find runs of >= min_repeat consecutive instruction blocks with an identical instruction-
    mnemonic shape and a constant byte stride: the fingerprint of an `-O2`-unrolled loop body. Returns
    [{start_va, stride, count, span}] -- the fact a re-roller needs to collapse the copies to a loop.

    Shape-only (mnemonic sequence + stride), so it is not fooled by the immediates/offsets the copies
    differ in; it does not itself re-roll (lifting the copies back to one loop body is the next tier).
    AArch64 is decoded with the ARM64 disassembler (fixed 4-byte instructions), x86 with x86."""
    md = _md(arch)
    md.detail = False                    # mnemonics + addresses only: much faster over a whole .text
    insns = list(md.disasm(code, base))
    # a per-instruction shape key that ignores operands' concrete values
    shape = [ins.mnemonic for ins in insns]
    addrs = [ins.address for ins in insns]
    out = []
    n = len(insns)
    i = 0
    while i < n:
        best = None
        # try block lengths from large-ish down to small; a block is blocklen consecutive insns
        for blen in range(2, 13):
            if i + 2 * blen > n:
                continue
            if shape[i:i + blen] != shape[i + blen:i + 2 * blen]:
                continue
            stride = addrs[i + blen] - addrs[i]
            if stride <= 0:
                continue
            reps = 2
            j = i + 2 * blen
            while j + blen <= n and shape[j:j + blen] == shape[i:i + blen] \
                    and (addrs[j] - addrs[j - blen]) == stride:
                reps += 1
                j += blen
            # keep the run covering the most instructions (reps*blen insns; not the byte stride)
            if reps >= min_repeat and (best is None or reps * blen > best[2] * best[0]):
                best = (blen, stride, reps, j)
        if best:
            blen, stride, reps, j = best
            out.append({"start_va": addrs[i], "stride": stride, "count": reps,
                        "span": addrs[j - 1] + insns[j - 1].size - addrs[i] if j <= n else 0,
                        "block_insns": blen})
            i = j
        else:
            i += 1
    return out


def analyze(path) -> dict:
    """Recover jump tables (and detect unrolled loops) in a binary, resolving the table data via the
    emulator's Image (so a PIE's table is read correctly)."""
    import recover_emulate
    img = recover_emulate.Image(path)
    arch = "aarch64" if img.arm else ("x86" if img.x32 else "x86_64")
    data = {s.virtual_address: bytes(s.content) for s in img.binary.sections
            if s.virtual_address and not img._exec_sec(s)}
    data_sorted = sorted(data.items())

    def read_i32(va):
        for sv, raw in data_sorted:
            o = va - sv
            if 0 <= o <= len(raw) - 4:
                return struct.unpack_from("<i", raw, o)[0]
        return None

    def read_bytes(va, n):
        for sv, raw in data_sorted:
            o = va - sv
            if 0 <= o <= len(raw) - n:
                return raw[o:o + n]
        return None

    if img.arm:
        jts = recover_jump_tables_arm64(img.code, img.text_va, read_i32, img.text_va, img.text_end,
                                        read_bytes=read_bytes)
    else:
        jts = recover_jump_tables(img.code, img.text_va, arch, read_i32, img.text_va, img.text_end)
    loops = detect_unrolled_loops(img.code, img.text_va, arch)
    return {"arch": arch, "jump_tables": jts, "unrolled_loops": loops}


def _selftest():
    # Hand-assemble the LLVM rel32 jump-table idiom for a 3-case switch and recover it.
    #   cmp edi, 2
    #   ja  default
    #   lea rax, [rip + d]        ; table base
    #   movsxd rcx, [rax + rdi*4]
    #   add rcx, rax
    #   jmp rcx
    # table (3 x i32 offsets to the three case bodies), then the case bodies.
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    base = 0x1000
    # assemble by hand at known offsets
    buf = bytearray()

    def emit(b):
        buf.extend(b)
    emit(b"\x83\xff\x02")                       # cmp edi, 2                      @1000 (3)
    emit(b"\x0f\x87\x00\x00\x00\x00")           # ja rel32 (default, patched)     @1003 (6)
    lea_at = len(buf)
    emit(b"\x48\x8d\x05\x00\x00\x00\x00")       # lea rax,[rip+d] (patched)       @1009 (7)
    emit(b"\x48\x63\x0c\xb8")                   # movsxd rcx,[rax+rdi*4]           @1010 (4)
    emit(b"\x48\x01\xc1")                       # add rcx, rax                    @1014 (3)
    emit(b"\xff\xe1")                           # jmp rcx                         @1017 (2)
    jmp_end = len(buf)
    # three case bodies + default, each `mov eax, imm32; ret` (6 bytes)
    bodies = {}
    for name in ("c0", "c1", "c2", "default"):
        bodies[name] = base + len(buf)
        emit(b"\xb8" + struct.pack("<I", 0x11) + b"\xc3")
    # the jump table: 3 i32 offsets from table_base to each case body
    table_va = base + len(buf)
    for name in ("c0", "c1", "c2"):
        emit(struct.pack("<i", bodies[name] - table_va))
    code = bytes(buf)

    # patch the lea disp so [rip+d] (from the next insn) == table_va
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    lea = next(ins for ins in md.disasm(code[lea_at:lea_at + 7], base + lea_at))
    disp = table_va - (lea.address + lea.size)
    code = code[:lea_at + 3] + struct.pack("<i", disp) + code[lea_at + 7:]
    # patch the ja to the default body
    ja_at = 3
    ja_disp = bodies["default"] - (base + ja_at + 6)
    code = code[:ja_at + 2] + struct.pack("<i", ja_disp) + code[ja_at + 6:]

    def read_i32(va):
        o = va - base
        return struct.unpack_from("<i", code, o)[0] if 0 <= o <= len(code) - 4 else None

    jts = recover_jump_tables(code, base, "x86_64", read_i32, base, table_va)
    assert len(jts) == 1, jts
    jt = jts[0]
    assert jt["count"] == 3, jt
    assert jt["index_reg"] in ("rdi", "edi"), jt["index_reg"]
    assert jt["table_va"] == table_va, (hex(jt["table_va"]), hex(table_va))
    assert jt["cases"] == {0: bodies["c0"], 1: bodies["c1"], 2: bodies["c2"]}, jt["cases"]

    # a plain instruction stream with no indirect jmp recovers nothing
    assert recover_jump_tables(b"\x90\x90\xc3", base, "x86_64", read_i32, base, base + 3) == []

    # unrolled-loop detection: four identical `add eax,1; add ecx,4` blocks in a row
    blk = b"\x83\xc0\x01\x83\xc1\x04"            # add eax,1 ; add ecx,4  (6 bytes, 2 insns)
    unrolled = blk * 4 + b"\xc3"
    loops = detect_unrolled_loops(unrolled, base, "x86_64", min_repeat=3)
    assert len(loops) == 1 and loops[0]["count"] == 4 and loops[0]["block_insns"] == 2, loops
    assert loops[0]["stride"] == 6 and loops[0]["start_va"] == base
    # a non-repeating stream has no unrolled loop
    assert detect_unrolled_loops(b"\x90\x48\xff\xc0\x5d\xc3", base, "x86_64") == []

    # AArch64 idiom operand parsers
    assert _A64_LDRSW.match("x10, [x8, x0, lsl #2]").groups() == ("x10", "x8", "x0")
    assert _A64_ADD.match("x9, x9, x10").groups() == ("x9", "x9", "x10")
    assert _A64_IMM.match("x8, #0x200240").groups() == ("x8", "0x200240")
    assert _A64_IMM.match("x0, #0x13").group(2) == "0x13"

    # AArch64 compressed tables, table base via adrp+add (a far table), hand-assembled:
    #   10000 cmp x0,#2 ; 10004 nop ; 10008 adrp x8,0x11000 ; 1000c add x8,x8,#0x10
    #   10010 adr x9,#0 (anchor) ; 10014 ldrb w10,[x8,x0] | ldrh w10,[x8,x0,lsl #1]
    #   10018 add x9,x9,x10,lsl #2 ; 1001c br x9 ; case bodies at 10020/10028/10030
    a_base, a_tbl = 0x10000, 0x11010
    bodies_a = [0x10020, 0x10028, 0x10030]
    for load, esize in ((0x3860690a, 1), (0x7860790a, 2)):
        words = [0xf100081f, 0xd503201f, 0xb0000008, 0x91004108, 0x10000009, load,
                 0x8b0a0929, 0xd61f0120] + [0xd65f03c0, 0xd503201f] * 3
        a_code = struct.pack("<%dI" % len(words), *words)
        tbl = b"".join(((b - 0x10010) // 4).to_bytes(esize, "little") for b in bodies_a)

        def rb(va, n, _t=tbl):
            o = va - a_tbl
            return _t[o:o + n] if 0 <= o <= len(_t) - n else None
        got = recover_jump_tables_arm64(a_code, a_base, lambda va: None, a_base,
                                        a_base + len(a_code), read_bytes=rb)
        assert len(got) == 1, (esize, got)
        assert got[0]["table_va"] == a_tbl and got[0]["anchor"] == 0x10010, got[0]
        assert got[0]["count"] == 3 and got[0]["entry_size"] == esize, got[0]
        assert got[0]["cases"] == dict(enumerate(bodies_a)), got[0]["cases"]
    # a wrong index scale (ldrh with no lsl #1) is not a table load -> nothing recovered
    words = [0xf100081f, 0xd503201f, 0xb0000008, 0x91004108, 0x10000009, 0x7860690a,
             0x8b0a0929, 0xd61f0120] + [0xd65f03c0, 0xd503201f] * 3
    a_code = struct.pack("<%dI" % len(words), *words)
    assert recover_jump_tables_arm64(a_code, a_base, lambda va: None, a_base, a_base + len(a_code),
                                     read_bytes=lambda va, n: b"\x04\x00" * n) == []

    print("selftest OK: rel32 jump-table recovery (3-case switch -> {index: target}), rejects a "
          "plain stream, unrolled-loop detection (4x body), AArch64 idiom operand parsing, and AArch64 compressed (ldrb/ldrh) tables via adrp+add")


def main(argv=None) -> int:
    import argparse
    import json
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("binary", nargs="?")
    ap.add_argument("--loops", action="store_true", help="also report unrolled-loop runs")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args(argv)
    if a.selftest:
        _selftest()
        return 0
    if not a.binary:
        ap.error("give a binary, or --selftest")
    res = analyze(Path(a.binary))
    if a.json:
        print(json.dumps(res, indent=2, default=lambda o: {hex(k): hex(v) for k, v in o.items()}
                         if isinstance(o, dict) else o))
        return 0
    print(f"arch={res['arch']}  jump tables={len(res['jump_tables'])}"
          + (f"  unrolled-loop runs={len(res['unrolled_loops'])}" if a.loops else ""))
    for jt in res["jump_tables"]:
        tgts = " ".join(f"{i}->0x{t:x}" for i, t in sorted(jt["cases"].items())[:8])
        more = f" (+{jt['count'] - 8} more)" if jt["count"] > 8 else ""
        # x86 results carry `jmp_va`, AArch64 results `br_va` (the indirect branch's address)
        kind, at = ("jmp", jt["jmp_va"]) if "jmp_va" in jt else ("br", jt["br_va"])
        print(f"  {kind} 0x{at:x}  table 0x{jt['table_va']:x}  {jt['count']} cases: {tgts}{more}")
    if a.loops:
        for lp in res["unrolled_loops"]:
            print(f"  unrolled loop 0x{lp['start_va']:x}  {lp['count']}x body of {lp['block_insns']} "
                  f"insn(s), stride {lp['stride']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
