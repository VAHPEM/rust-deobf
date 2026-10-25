#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: Ve (VAHPEM) <ve0912084386@gmail.com>
#
# Dual-licensed: AGPL-3.0-or-later OR a commercial license.
# Commercial licensing: Ve (VAHPEM) <ve0912084386@gmail.com>
"""deobf_deflatten.py - Tier 4: recover the control flow of a flattened function.

deobf_cff.py *locates* a flattening dispatcher; this *recovers the state machine* behind it.
goldberg (and OLLVM-style passes) rewrite a function into `loop { state = f(state); switch state }`,
so the original order of the blocks is hidden in a state variable. The giveaway, seen in the
goldberg debug build of `band()`:

    mov eax, [rsp+0x40]        ; load state
    mov [rsp+0x2c], eax        ; scratch copy
    sub eax, 0x9ecf39a7        ; }
    je  case_A                 ; } cmp-less ladder: state == const -> case
    ...                        ;
  case_X:                      ; a case does its work, then:
    mov [rsp+0x44], 0xc5aee326 ; set a delta
    ... xor [rsp+0x40], [rsp+0x44] ; state ^= delta   (transition is XOR-based)
    jmp dispatcher

So each case runs at a known state value and transitions to `state ^ delta`. Recovering the
(state -> case, case -> next state) maps rebuilds the real control-flow graph; real branches in
the original code (`if code < 10`) survive as a case with two deltas on two paths.

Two transition forms are handled and tested: goldberg's XOR-delta (`state ^= delta`) and the
classic OLLVM `-fla` **direct assignment** (`switchVar = next_const`, no update slot). The direct
form is covered by `tests/test_deflatten.py::test_deflatten_ollvm_direct_assignment` against a
clang-built target in `obf_src/ollvm_fla/` whose two original branches (a loop test and a parity
check) must reappear as two-way transitions.

This is observational static analysis: it reads the binary and runs nothing. It reconstructs the
graph; it does not re-emit a binary.

    python deobf_deflatten.py <binary> [--func 0x16a50] [--json]
    python deobf_deflatten.py --selftest

Scope note: source-level macro flattening (goldberg's `goldberg_stmts!`) survives only in
unoptimised builds - at `opt-level>=1` rustc's own passes dissolve it (in the release goldberg
build `band` is inlined away). It is the LLVM-pass / OLLVM style of flattening, which survives
-O, that this matters for on real malware; goldberg's debug output is the worked example.
"""
from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path
# premium module: find both premium/ (sibling premium modules) and the Apache core in scripts/
for _p in (str(_Path(__file__).resolve().parent), str(_Path(__file__).resolve().parent.parent / 'scripts')):
    if _p not in _sys.path:
        _sys.path.insert(0, _p)

import argparse
import json
import sys
from pathlib import Path


def _detect_arch(b):
    """'aarch64' or 'x86_64' from the LIEF object header (default x86_64)."""
    cand = ""
    hdr = getattr(b, "header", None)
    for attr in ("machine_type", "cpu_type", "machine"):
        v = getattr(hdr, attr, None) if hdr is not None else None
        if v is not None:
            cand = str(v).upper()
            break
    if "AARCH64" in cand or "ARM64" in cand:
        return "aarch64"
    return "x86_64"


def _load_text_and_funcs(path):
    import lief
    b = lief.parse(str(path))
    if b is None:
        raise ValueError("LIEF could not parse the file")
    base = b.optional_header.imagebase if "PE" in b.format.name else 0
    text = next((s for s in b.sections if s.name == ".text"), None)
    if text is None:
        raise ValueError("no .text section")
    code = bytes(text.content)
    tbase = base + text.virtual_address
    funcs = {}
    for s in b.symbols:
        # Relocatable objects give in-section functions value 0 (e.g. the first symbol),
        # so key on is_function + a real size, not a truthy value.
        if getattr(s, "is_function", False) and getattr(s, "size", 0):
            funcs[s.value] = (s.name, s.size)
    return code, tbase, funcs, _detect_arch(b)


def _mem_key(ins):
    """A stable key for a `[reg +/- disp]` memory operand, or None."""
    from capstone import x86
    for op in ins.operands:
        if op.type == x86.X86_OP_MEM:
            m = op.mem
            return (m.base, m.index, m.scale, m.disp)
    return None


def _imm(ins):
    from capstone import x86
    for op in ins.operands:
        if op.type == x86.X86_OP_IMM:
            return op.imm
    return None


def _x86_cmp_tree_ladder(ins, by_addr, ladder, U32, x86):
    """The OTHER x86 switch lowering: a balanced compare-tree, not the `sub imm; je` ladder.
    LLVM picks it depending on the state-constant distribution, so a flattened function can use
    either (RustCloak hits both). Head: `mov r32,[state] ; cmp r32,imm ; jCC`; the state constants
    are the cmp IMMEDIATES (not materialised into registers as on AArch64). Nodes: `je` leaf
    (state==imm -> target), `jne` default chain (fall-through is the case; follow a non-dispatcher
    target), and the signed range splits jg/jge/jl/jle (follow both). Fills `ladder` {state->case_va}
    and returns (state_slot, disp_addr), or (None, None). Picks the head yielding the largest tree."""
    SPLIT = {"jg", "jge", "jl", "jle", "ja", "jae", "jb", "jbe"}
    best = (None, None, {})
    for idx in range(len(ins) - 2):
        a = ins[idx]
        if a.mnemonic != "mov" or not a.operands or a.operands[0].type != x86.X86_OP_REG:
            continue
        slot = _mem_key(a)
        if not slot:
            continue
        sreg = a.operands[0].reg
        c, j = ins[idx + 1], ins[idx + 2]
        if (c.mnemonic != "cmp" or not c.operands or c.operands[0].type != x86.X86_OP_REG
                or c.operands[0].reg != sreg or _imm(c) is None
                or not j.mnemonic.startswith("j") or j.mnemonic == "jmp"):
            continue
        disp_addr = a.address
        local, nodes, seen = {}, [idx + 1], set()
        for _ in range(8192):
            if not nodes:
                break
            p = nodes.pop()
            if p in seen or p < 0 or p >= len(ins):
                continue
            seen.add(p)
            while p < len(ins) and ins[p].mnemonic == "mov":
                p += 1
            if p + 1 >= len(ins) or ins[p].mnemonic != "cmp":
                continue
            cm = ins[p]
            if (not cm.operands or cm.operands[0].type != x86.X86_OP_REG
                    or cm.operands[0].reg != sreg or _imm(cm) is None):
                continue
            imm = _imm(cm) & U32
            br, m, tgt = ins[p + 1], ins[p + 1].mnemonic, _imm(ins[p + 1])
            if m == "je":
                local[imm] = tgt
                nodes.append(p + 2)
            elif m == "jne":
                if p + 2 < len(ins):
                    local[imm] = ins[p + 2].address      # fall-through is this case
                if tgt != disp_addr and tgt in by_addr:  # default-chain hop, not back to dispatch
                    nodes.append(by_addr[tgt])
            elif m in SPLIT:                             # range split: follow both edges
                if tgt in by_addr:
                    nodes.append(by_addr[tgt])
                nodes.append(p + 2)
        if len(local) > len(best[2]):
            best = (slot, disp_addr, local)
    slot, disp_addr, local = best
    if slot is None or len(local) < 3:
        return None, None
    ladder.update(local)
    return slot, disp_addr


def deflatten(code, tbase, func_va, func_size, arch="x86_64"):
    """Recover a flattened function's state machine. Dispatches on architecture: x86-64 (the
    goldberg/OLLVM sub-je ladder) and AArch64 (the RustCloak/LLVM balanced compare-tree)."""
    if arch == "aarch64":
        return _deflatten_arm64(code, tbase, func_va, func_size)
    return _deflatten_x86(code, tbase, func_va, func_size)


def _deflatten_x86(code, tbase, func_va, func_size):
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, x86
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    off = func_va - tbase
    ins = list(md.disasm(code[off:off + func_size], func_va))
    by_addr = {i.address: k for k, i in enumerate(ins)}
    U32 = 0xFFFFFFFF

    # --- find the dispatcher: a stack slot loaded, optionally copied to a scratch slot, then
    #     compared by a `sub r32,imm ; je` ladder. goldberg emits `mov r,[state]; mov [scratch],r;
    #     sub r,imm; je`; an LLVM `switch` lowering (OLLVM, RustCloak) reloads the slot before each
    #     rung, so the head reads `mov r,[state]; mov [scratch],r; mov r,[scratch]; sub r,imm; je`
    #     -- i.e. extra `mov` reloads sit between the copy and the first `sub`. Skip them.
    state_slot = scratch_slot = disp_addr = None
    for idx in range(len(ins) - 3):
        a = ins[idx]
        if a.mnemonic != "mov" or a.operands[0].type != x86.X86_OP_REG:
            continue
        ssrc = _mem_key(a)                 # mov r, [state]
        if not ssrc:
            continue
        j = idx + 1
        scpy = None
        if j < len(ins) and ins[j].mnemonic == "mov" and ins[j].operands[0].type == x86.X86_OP_MEM:
            scpy = _mem_key(ins[j])        # mov [scratch], r
            j += 1
        while j < len(ins) and ins[j].mnemonic == "mov":   # reloads between copy and the ladder
            j += 1
        if j + 1 < len(ins) and ins[j].mnemonic == "sub" and ins[j + 1].mnemonic == "je":
            state_slot, scratch_slot, disp_addr = ssrc, (scpy or ssrc), a.address
            break
    ladder = {}                        # state value -> case VA
    if disp_addr is not None:
        # --- walk the sub/je ladder from the dispatcher: collect state_const -> case block.
        #     Each rung is `[mov r,[scratch]]* ; sub r,imm ; je case ; jmp next_rung`.
        p = by_addr[disp_addr]
        seen = set()
        for _ in range(4096):
            if p is None or p < 0 or p >= len(ins) or p in seen:
                break
            seen.add(p)
            # advance over mov reloads/copies to the comparison
            while p < len(ins) and ins[p].mnemonic == "mov":
                p += 1
            if p + 1 >= len(ins) or ins[p].mnemonic != "sub" or ins[p + 1].mnemonic != "je":
                break
            imm = _imm(ins[p]) & U32
            ladder[imm] = _imm(ins[p + 1])
            nxt = ins[p + 2] if p + 2 < len(ins) else None
            if nxt is not None and nxt.mnemonic == "jmp" and _imm(nxt) in by_addr:
                p = by_addr[_imm(nxt)]      # jump to the next rung
            else:
                p = p + 2                   # fall straight through to it
    else:
        # --- no sub/je ladder: try the balanced compare-tree lowering (the AArch64-shaped form,
        #     which LLVM also emits on x86 for some state-constant distributions).
        state_slot, disp_addr = _x86_cmp_tree_ladder(ins, by_addr, ladder, U32, x86)
        if state_slot is None:
            return {"flattened": False, "reason": "no dispatcher (sub/je ladder or compare-tree)"}
        scratch_slot = state_slot

    # --- find the state-update: `mov r,[upd] ; xor r,[state] ; mov [state],r`
    #     (goldberg loads the delta, xors it into the state slot). update_slot = [upd].
    update_slot = None
    for idx in range(1, len(ins) - 1):
        cur, nx = ins[idx], ins[idx + 1]
        if (cur.mnemonic == "xor" and _mem_key(cur) == state_slot
                and nx.mnemonic == "mov" and _mem_key(nx) == state_slot):
            # the delta was loaded into the register a few insns earlier
            for back in range(idx - 1, max(idx - 4, -1), -1):
                if ins[back].mnemonic == "mov" and _mem_key(ins[back]) not in (None, state_slot):
                    update_slot = _mem_key(ins[back])
                    break
            if update_slot:
                break

    # --- per case: forward DFS to the next dispatch, carrying register->immediate values along
    #     the path, so a transition that passes through a SHARED store epilogue still resolves.
    #     OLLVM/RustCloak lower a transition as `mov r,next_const ; [cmov ...] ; jmp store` where
    #     `store: mov [state],r ; jmp dispatcher`, and the `mov r,const` usually sits in a different
    #     block from the store -- a local backward scan cannot see it, so the value is carried
    #     forward across the jmp instead.
    def case_transitions(state_val, case_va):
        """Forward DFS from a case to its state store(s): [(next_state, None)] (and (None,'return')
        at a ret). Handles goldberg's `xor [state]` delta, a direct `mov [state],imm`, and the
        `mov r,imm` / `cmov`-select then `mov [state],r` form, including through a shared epilogue."""
        outs = []
        start = by_addr.get(case_va)
        if start is None:
            return outs
        SKIP = ("cmp", "test", "push", "pop", "j", "call", "ret", "nop")
        stack = [(start, None, (), 0)]     # (index, delta, regvals-as-sorted-tuple, steps)
        visited = set()
        while stack:
            k, delta, rv, steps = stack.pop()
            if k is None or k >= len(ins) or steps > 600:
                continue
            key = (k, delta, rv)
            if key in visited:
                continue
            visited.add(key)
            cur = ins[k]
            if cur.address == disp_addr:          # reached the dispatcher: end of this path
                continue
            regvals = dict(rv)
            m = cur.mnemonic
            if m == "mov" and _mem_key(cur) == update_slot and _imm(cur) is not None:
                delta = _imm(cur) & U32           # goldberg delta load
            if m == "mov" and _mem_key(cur) == state_slot:        # store to the state slot
                if _imm(cur) is not None:
                    outs.append((_imm(cur) & U32, None))
                    continue
                if cur.operands[1].type == x86.X86_OP_REG:
                    v = regvals.get(cur.operands[1].reg)
                    if v is not None:
                        outs.append((v, None))
                    continue
            if m == "xor" and _mem_key(cur) == state_slot:        # goldberg xor-apply
                outs.append(((state_val ^ (delta or 0)) & U32, None))
                continue
            rt = lambda d: tuple(sorted(d.items()))
            if m == "mov" and cur.operands[0].type == x86.X86_OP_REG \
                    and _mem_key(cur) is None and _imm(cur) is not None:
                regvals[cur.operands[0].reg] = _imm(cur) & U32    # track `mov reg, imm`
                stack.append((k + 1, delta, rt(regvals), steps + 1))
                continue
            if m.startswith("cmov") and cur.operands[0].type == x86.X86_OP_REG:
                dst = cur.operands[0].reg         # branch: dst unchanged, or dst <- src
                stack.append((k + 1, delta, rt(regvals), steps + 1))
                rb = dict(regvals)
                if cur.operands[1].type == x86.X86_OP_REG and cur.operands[1].reg in regvals:
                    rb[dst] = regvals[cur.operands[1].reg]
                elif cur.operands[1].type == x86.X86_OP_IMM and _imm(cur) is not None:
                    rb[dst] = _imm(cur) & U32
                else:
                    rb.pop(dst, None)
                stack.append((k + 1, delta, rt(rb), steps + 1))
                continue
            if m == "jmp":
                t = _imm(cur)
                if t in by_addr:
                    stack.append((by_addr[t], delta, rt(regvals), steps + 1))
                continue
            if m == "ret" or m.startswith("ret"):
                outs.append((None, "return"))
                continue
            if m == "call":
                stack.append((k + 1, delta, rt(regvals), steps + 1))
                continue
            if m.startswith("j"):                 # conditional branch = original logic: both edges
                t = _imm(cur)
                if t in by_addr:
                    stack.append((by_addr[t], delta, rt(regvals), steps + 1))
                stack.append((k + 1, delta, rt(regvals), steps + 1))
                continue
            if cur.operands and cur.operands[0].type == x86.X86_OP_REG \
                    and cur.operands[0].reg in regvals and not m.startswith(SKIP):
                regvals.pop(cur.operands[0].reg, None)   # a write invalidates a tracked reg
            stack.append((k + 1, delta, rt(regvals), steps + 1))
        return outs

    states = []
    start_state = None
    # the initial state is the FIRST imm stored to state_slot (the entry's init), before the case
    # blocks' own direct-assignment stores that also precede the dispatcher in address order.
    for idx in range(by_addr.get(disp_addr, 0)):
        if ins[idx].mnemonic == "mov" and _mem_key(ins[idx]) == state_slot and _imm(ins[idx]) is not None:
            start_state = _imm(ins[idx]) & U32
            break
    for sval, cva in sorted(ladder.items()):
        trans = case_transitions(sval, cva)
        nexts = sorted({t for t, _c in trans if t is not None})
        terminal = any(c == "return" for _t, c in trans)
        states.append({
            "state": "%#010x" % sval,
            "case_va": "%#x" % cva,
            "next_states": ["%#010x" % n for n in nexts],
            "terminal": terminal,
        })

    return {
        "flattened": True,
        "func_va": "%#x" % func_va,
        "dispatcher_va": "%#x" % disp_addr,
        "state_slot_disp": "%#x" % (state_slot[3] & U32) if state_slot else None,
        "update_slot_disp": "%#x" % (update_slot[3] & U32) if update_slot else None,
        "start_state": ("%#010x" % start_state) if start_state is not None else None,
        "num_states": len(ladder),
        "states": states,
    }


# ---------------------------------------------------------------------------
# AArch64 (ARM64)
#
# RustCloak / the LLVM `switch` lowering do NOT emit x86's linear `sub imm; je` ladder on
# AArch64. The 32-bit state constants are sparse, so LLVM materialises each into its own
# register (`mov w,#lo ; movk w,#hi,lsl#16`) at the top of the function and lowers the switch
# into a **balanced compare-tree**:
#
#     ldr  w10, [sp, #0x14]        ; load state
#     cmp  w10, w4                 ; w4 = a pivot constant (in a register)
#     b.gt upper_subtree           ; range split routes the search
#     ...
#     cmp  w10, w8                 ; equality leaf
#     b.eq case_for_w8             ; state == const(w8) -> case
#     ...
#     cmp  w10, w7 ; b.ne disp     ; last leaf: != -> dispatcher, fall through = its case
#
# A case transitions by writing the state slot: `str wCONST,[sp,#off]` (unconditional) or
# `csel wT,wA,wB,cc ; str wT,[sp,#off]` (an original branch -> two next states). So recovery =
# (1) build reg->const from the mov/movk defs, (2) walk the compare-tree for state->case,
# (3) read each case's str/csel for case->next. Resolves the same graph the x86 path does.
# ---------------------------------------------------------------------------
_A64_READERS = {"str", "stp", "strb", "strh", "cmp", "cmn", "tst", "ccmp", "ccmn"}


def _a64_rk(name):
    """Register key with the w/x width dropped (w4 and x4 alias): 'w4'/'x4' -> '4'."""
    if not name:
        return None
    if name in ("wzr", "xzr"):
        return "zr"
    if name[0] in "wx" and name[1:].isdigit():
        return name[1:]
    return name


def _a64_reg0(i, A):
    return _a64_rk(i.reg_name(i.operands[0].reg)) \
        if i.operands and i.operands[0].type == A.ARM64_OP_REG else None


def _a64_imm(i, A):
    for o in i.operands:
        if o.type == A.ARM64_OP_IMM:
            return o.imm
    return None


def _a64_const_before(ins, k, regkey, A, back=400):
    """The 32-bit constant a register holds just before index k, from its `mov`(movz) base and
    optional `movk ...,lsl#16` high half. None if it was defined by anything else (clobbered)."""
    U32 = 0xFFFFFFFF
    lo = hi = None
    for b in range(k - 1, max(k - back, -1), -1):
        ib = ins[b]
        m = ib.mnemonic
        if m in _A64_READERS or m.startswith(("b", "cb", "tb")):
            continue                       # reads/branches don't define op0
        if _a64_reg0(ib, A) != regkey:
            continue
        if m == "movk" and len(ib.operands) >= 2 and ib.operands[1].type == A.ARM64_OP_IMM:
            if hi is None:
                hi = ib.operands[1].imm & 0xFFFF
        elif m in ("mov", "movz") and len(ib.operands) >= 2 and ib.operands[1].type == A.ARM64_OP_IMM:
            lo = ib.operands[1].imm & U32
            break
        else:
            return None                    # defined by something we can't fold
    if lo is None:
        return None
    return ((hi << 16) | (lo & 0xFFFF)) & U32 if hi is not None else (lo & U32)


def _deflatten_arm64(code, tbase, func_va, func_size):
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
    from capstone import arm64 as A
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    off = func_va - tbase
    ins = list(md.disasm(code[off:off + func_size], func_va))
    by_addr = {i.address: k for k, i in enumerate(ins)}
    U32 = 0xFFFFFFFF

    def mem_sp_disp(i):
        mo = next((o for o in i.operands if o.type == A.ARM64_OP_MEM), None)
        if mo and i.reg_name(mo.mem.base) == "sp":
            return mo.mem.disp
        return None

    # --- dispatcher: `ldr wS,[sp,#off] ; cmp wS,wR ; b.cc` (the state reload + first compare)
    state_off = disp_k = wS = None
    for k in range(len(ins) - 2):
        i0, i1, i2 = ins[k], ins[k + 1], ins[k + 2]
        if i0.mnemonic != "ldr":
            continue
        d = mem_sp_disp(i0)
        sreg = _a64_reg0(i0, A)
        if d is not None and sreg and i1.mnemonic == "cmp" \
                and _a64_reg0(i1, A) == sreg and i2.mnemonic.startswith("b."):
            state_off, disp_k, wS = d, k, sreg
            break
    if disp_k is None:
        return {"flattened": False, "reason": "no ldr/cmp/b.cc dispatcher tree found"}
    disp_va = ins[disp_k].address

    # --- walk the compare-tree from the dispatcher: state_const -> case VA
    ladder = {}
    nodes = [disp_k + 1]
    seen = set()
    for _ in range(8192):
        if not nodes:
            break
        p = nodes.pop()
        if p in seen or p < 0 or p >= len(ins):
            continue
        seen.add(p)
        while p < len(ins) and ins[p].mnemonic in ("mov", "movz", "movk"):
            p += 1                         # skip materialisation of the compare constant
        if p + 1 >= len(ins) or ins[p].mnemonic != "cmp" or _a64_reg0(ins[p], A) != wS:
            continue
        if len(ins[p].operands) < 2 or ins[p].operands[1].type != A.ARM64_OP_REG:
            continue
        wR = _a64_rk(ins[p].reg_name(ins[p].operands[1].reg))
        c = _a64_const_before(ins, p, wR, A)
        br = ins[p + 1]
        cond, tgt = br.mnemonic, _a64_imm(br, A)
        if cond.endswith("eq"):            # state == const -> target case
            if c is not None:
                ladder[c] = tgt
            nodes.append(p + 2)            # tree continues at the fall-through
        elif cond.endswith("ne"):          # != -> next check (or dispatcher); fall-through = case
            if c is not None and p + 2 < len(ins):
                ladder[c] = ins[p + 2].address
            if tgt != disp_va and tgt in by_addr:   # a default-chain hop, not back to dispatch
                nodes.append(by_addr[tgt])
        else:                              # range split (gt/le/lt/ge/hi/ls...) -> follow both
            if tgt in by_addr:
                nodes.append(by_addr[tgt])
            nodes.append(p + 2)

    # --- initial state: first `str wR,[sp,#off]` to the state slot before the dispatcher
    start_state = None
    for k in range(disp_k):
        i = ins[k]
        if i.mnemonic == "str" and _a64_reg0(i, A) is not None and mem_sp_disp(i) == state_off:
            c = _a64_const_before(ins, k, _a64_reg0(i, A), A)
            if c is not None:
                start_state = c
                break

    def _store_nexts(p, out):
        """Resolve the next state(s) written by `str wR,[state]` at index p: a materialised
        constant -> one next; the destination of a nearby `csel wR,wA,wB` -> two next states."""
        dst = _a64_reg0(ins[p], A)
        csel_q = None
        for q in range(p - 1, max(p - 10, -1), -1):   # the csel that defined wR, if any
            if ins[q].mnemonic == "csel" and _a64_reg0(ins[q], A) == dst:
                csel_q = q
                break
            if _a64_reg0(ins[q], A) == dst and ins[q].mnemonic not in _A64_READERS:
                break
        if csel_q is not None and len(ins[csel_q].operands) >= 3:
            # resolve each source operand AT the csel: a csel reusing its own dest (csel wd,wd,ws)
            # holds wd's pre-csel value, which is clobbered by the time of the later str.
            for oi in (1, 2):
                c = _a64_const_before(ins, csel_q, _a64_rk(
                    ins[csel_q].reg_name(ins[csel_q].operands[oi].reg)), A)
                if c is not None:
                    out.add(c)
        else:
            c = _a64_const_before(ins, p, dst, A)
            if c is not None:
                out.add(c)

    def case_transitions(case_va):
        """Bounded DFS over a case's own blocks to its `b dispatcher`/`ret`, collecting every
        state-slot store on every path: `str wCONST,[state]` -> one next, `csel ...; str` -> two.
        A linear scan misses stores that sit on a conditional branch inside the case."""
        start = by_addr.get(case_va)
        if start is None:
            return [], False
        nexts, terminal = set(), False
        stack, visited = [start], set()
        while stack:
            p = stack.pop()
            steps = 0
            while 0 <= p < len(ins) and p not in visited and steps < 400:
                if ins[p].address == disp_va:
                    break                  # a case may fall straight through into the dispatcher
                visited.add(p)
                steps += 1
                i = ins[p]
                m = i.mnemonic
                if m == "str" and mem_sp_disp(i) == state_off:
                    _store_nexts(p, nexts)
                    p += 1
                    continue
                if m == "ret":
                    terminal = True
                    break
                if m == "b":
                    t = _a64_imm(i, A)
                    if t == disp_va:
                        break              # transition already recorded; end of path
                    j = by_addr.get(t)
                    if j is not None and any(ins[q].mnemonic == "ret"
                                             for q in range(j, min(j + 8, len(ins)))):
                        terminal = True
                        break
                    p = j if j is not None else p + 1
                    continue
                if m.startswith(("b.", "cb", "tb")):   # conditional branch: follow both edges
                    t = _a64_imm(i, A)
                    if t is not None and t != disp_va and t in by_addr:
                        stack.append(by_addr[t])
                    p += 1
                    continue
                p += 1
        return sorted(nexts), terminal

    states = []
    for sval, cva in sorted(ladder.items()):
        nexts, terminal = case_transitions(cva)
        states.append({
            "state": "%#010x" % sval,
            "case_va": "%#x" % cva,
            "next_states": ["%#010x" % n for n in nexts],
            "terminal": terminal,
        })
    return {
        "flattened": True,
        "arch": "aarch64",
        "func_va": "%#x" % func_va,
        "dispatcher_va": "%#x" % disp_va,
        "state_slot_disp": "%#x" % (state_off & U32),
        "update_slot_disp": None,
        "start_state": ("%#010x" % start_state) if start_state is not None else None,
        "num_states": len(ladder),
        "states": states,
    }


def _selftest():
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    # the XOR transition invariant the recovery relies on (state ^= delta), from real band() data
    assert (0xc8100b67 ^ 0xc5aee326) & 0xFFFFFFFF == 0x0dbee841
    # operand helpers decode a real dispatcher head: mov eax,[rsp+0x40]; sub eax,imm; je ...
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    head = list(md.disasm(bytes.fromhex("8b442440" "2da739cf9e" "7405"), 0x1000))
    assert head[0].mnemonic == "mov" and _mem_key(head[0]) is not None
    assert head[1].mnemonic == "sub" and (_imm(head[1]) & 0xFFFFFFFF) == 0x9ecf39a7
    # no false dispatcher on non-flattened bytes
    nop = deflatten(b"\x90" * 256 + b"\xc3", 0x0, 0x0, 257)
    assert nop.get("flattened") is False, nop
    print("selftest OK: XOR transition model, operand decode, and no false dispatcher on "
          "flat code (full recovery in tests/test_deflatten.py on the goldberg debug build)")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("binary", nargs="?")
    ap.add_argument("--func", help="function VA (hex); default: the symbol named *band* or the "
                                   "largest function")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        _selftest()
        return
    if not a.binary:
        ap.error("binary required or --selftest")
    code, tbase, funcs, arch = _load_text_and_funcs(Path(a.binary))
    if a.func:
        fva = int(a.func, 16)
        fsz = funcs.get(fva, (None, 0x4000))[1] or 0x4000
    else:
        cand = [(v, n, s) for v, (n, s) in funcs.items() if "band" in n]
        if not cand:
            cand = [(v, n, s) for v, (n, s) in funcs.items()]
            cand.sort(key=lambda x: x[2], reverse=True)
        fva, _n, fsz = cand[0]
    r = deflatten(code, tbase, fva, fsz, arch)
    if a.json:
        print(json.dumps(r, indent=2))
        return
    if not r.get("flattened"):
        print(f"{Path(a.binary).name} @ {fva:#x}: {r.get('reason')}")
        return
    sp = "sp" if arch == "aarch64" else "rsp"
    upd = f"  update_slot [{sp}+{r['update_slot_disp']}]" if r.get("update_slot_disp") else ""
    print(f"{Path(a.binary).name} @ {r['func_va']} ({arch}): flattened state machine recovered")
    print(f"  dispatcher {r['dispatcher_va']}  state_slot [{sp}+{r['state_slot_disp']}]{upd}  "
          f"states {r['num_states']}  start {r['start_state']}")
    for s in r["states"]:
        arrow = " -> " + ", ".join(s["next_states"]) if s["next_states"] else ""
        term = "  [return]" if s["terminal"] else ""
        print(f"    {s['state']} @ {s['case_va']}{arrow}{term}")


if __name__ == "__main__":
    main()
