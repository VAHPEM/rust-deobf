# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: Ve (VAHPEM) <ve0912084386@gmail.com>
#
# Dual-licensed: AGPL-3.0-or-later OR a commercial license.
# Commercial licensing: Ve (VAHPEM) <ve0912084386@gmail.com>
"""devirt_emulate.py - recover a RustCloak VM's instruction set by *emulating* its interpreter.

The static lifter (core `scripts/lift_vm.py`) recovers the opcode map by pattern-matching the
dispatch's native code. That is fast but codegen-specific: every LLVM switch lowering (jump table,
threaded, hoisted/accumulator, guarded/unguarded) needs its own patterns, and an *obfuscated*
interpreter (operand-decrypt turned into MBA, dispatch flattened) defeats the patterns entirely.

This module recovers the same facts dynamically and codegen-agnostically. It runs the virtualized
function under Unicorn with a few concrete input vectors and watches it interpret its own bytecode:

  * the interpreter fetches 4 instruction bytes from the bytecode blob (in .rodata) -> the blob VA
    and the per-instruction raw bytes [opcode, dst, a, b] fall straight out of the read addresses;
  * each handler reads some VM register-file slots and writes one -> the (dst, a, b) register
    *indices* are observed directly as stack-slot offsets, no operand-key parsing needed;
  * the operation is inferred from the observed value relation (result == a+b, a^b, a*b, ...),
    which reproduces the opcode's semantics even when the handler's native code is obfuscated.

From those observations it reconstructs the opcode-byte -> logical-op map, the operand-encryption
key (raw operand byte XOR observed register index), the i64 constant pool, and the fall-through
default -- exactly the tuple the core lifter's `lift_region` consumes -- then hands off to it for
expression folding, control-flow structuring and C pseudocode. So the hard, obfuscation-resistant
recovery is dynamic; the rendering stays in the (Apache-2.0) core.

    from premium import devirt_emulate
    devirt_emulate.recover(Path("sample"), func_va)

x86-64 only for now. STATIC analysis is never enough for a hardened VM; this executes the
interpreter in a sandbox (Unicorn), it never runs the sample natively.
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent                     # premium/ (sibling premium modules)
_CORE = _HERE.parent / "scripts"                            # the Apache-2.0 core
for _p in (str(_HERE), str(_CORE)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import lift_vm                              # premium: static decode + lift_region (devirtualizer)
from recover_emulate import Image, map_image, _fast_access, STACK, STACK_SIZE  # core emulation infra

from unicorn import (Uc, UcError, UC_ARCH_X86, UC_MODE_64,
                     UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE)
from unicorn import x86_const as X

_ARG_REGS = [X.UC_X86_REG_RDI, X.UC_X86_REG_RSI, X.UC_X86_REG_RDX,
             X.UC_X86_REG_RCX, X.UC_X86_REG_R8, X.UC_X86_REG_R9]
_RETADDR = 0x0cad0000                       # sentinel return address: run stops when we return here
_M64 = (1 << 64) - 1

# input vectors. The "value" vectors are distinct, high-entropy scalars so a value relation
# (add vs xor vs mul ...) that holds by coincidence on one vector is ruled out by another. The
# "pointer" vectors put each argument into its own scratch buffer with small loop-counts, so a
# function that dereferences or loops over its arguments runs (and returns) instead of faulting.
_VALUE_VECTORS = [
    [0x1122334455667788, 0x00000000000000aa, 0x0f0f0f0f0f0f0f0f, 3, 5, 7],
    [0xdeadbeefcafef00d, 0x0123456789abcdef, 0xfedcba9876543210, 9, 11, 13],
    [0x8000000000000001, 0x7fffffffffffffff, 0x5555555555555555, 2, 4, 6],
    # small-magnitude vectors: whichever argument is a loop count stays small so the function
    # terminates, giving every instruction -- including run-once preamble ops -- several samples to
    # disambiguate its operation. Overlapping low bits keep OR/ADD/XOR distinguishable.
    [0x3b, 0x17, 0x2d, 0x1f, 0x29, 0x35],
    [0x51, 0x3a, 0x6c, 0x27, 0x4e, 0x19],
    [0x7, 0xd, 0xb, 0x13, 0x25, 0x11],
    # tiny-count vectors: *every* lane is small, so a loop *nest* (whose trip count is the product of
    # its bounds) still terminates within the execution budget, and a data-dependent exit (an inner
    # `break`) is more likely to be exercised -- both give the reconstruction fuller coverage. They
    # are cheap now that the trace budget is modest (a non-terminating run caps quickly), so they are
    # traced for every function rather than held back; dropping them cost find_mix's break-path
    # fidelity. Distinct small values keep the ops separable.
    [2, 3, 4, 5, 2, 3],
    [4, 2, 5, 3, 4, 2],
    [3, 5, 2, 4, 3, 5],
]
_SCRATCH = 0x20000000
_SCRATCH_SIZE = 0x400000
# pointer vectors: the lane value is a scratch pointer, or a small loop-count. Several assignments of
# which lanes are counts cover functions with the count in different argument positions.
_PTR_VECTORS = [
    {"ptr": _SCRATCH + 0x1000, "counts": {1: 9, 2: 7, 3: 5}},
    {"ptr": _SCRATCH + 0x2000, "counts": {1: 6, 3: 4, 4: 8}},
    {"ptr": _SCRATCH + 0x3000, "counts": {2: 11, 3: 10}},
    # single small lane so the other arguments stay valid pointers -- covers functions whose only
    # scalar is the length (e.g. decode(out, ct, len, key): only arg 2 is the count, the rest point
    # into buffers that get dereferenced).
    {"ptr": _SCRATCH + 0x4000, "counts": {2: 7}},
    {"ptr": _SCRATCH + 0x5000, "counts": {1: 6}},
    {"ptr": _SCRATCH + 0x6000, "counts": {3: 9}},
]


_ENTROPY_CACHE = {}


def _entropy(n, seed=0x2545F4914F6CDD1D):
    if n in _ENTROPY_CACHE:
        return _ENTROPY_CACHE[n]
    out = bytearray()
    x = seed
    while len(out) < n:
        x = (x * 6364136223846793005 + 1442695040888963407) & _M64
        out += struct.pack("<Q", x)
    buf = bytes(out[:n])
    _ENTROPY_CACHE[n] = buf
    return buf


_TRACE_CAP = 120_000                                         # native-instruction budget per trace


def _trace(img, fva, size, args, cap=_TRACE_CAP):
    """Run one input vector under Unicorn and return the executed VM-instruction trace. Each entry:
    {off, next, dst, srcs, result, pool, loads, stores, regvals}. Register indices are relative to
    the reg-file base; loads/stores are (addr, size, value) outside the reg file; `next` is the
    bytecode offset of the following fetch (for control-flow recovery).

    `cap` bounds a single run's native instructions. A run that hits it did not return and is
    discarded by `_attempt` (only cleanly-returning runs are used), so the budget only has to be large
    enough for the *terminating* runs -- and since loops are driven by small-count input vectors they
    terminate quickly (the longest across the fixtures is ~17k VM-instructions, and recovery holds
    well below 50k native). A big-argument vector that turns an argument into a huge loop count simply
    caps and is thrown away, so keeping the budget modest cuts that wasted work several-fold with a
    wide safety margin rather than spending 400k instructions to produce nothing."""
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    _fast_access(uc)
    map_image(uc, img.binary)
    uc.mem_map(STACK, STACK_SIZE)
    try:
        uc.mem_map(_SCRATCH, _SCRATCH_SIZE)
        uc.mem_write(_SCRATCH, _entropy(_SCRATCH_SIZE))      # so loads see high-entropy data
    except UcError:
        pass
    sp = STACK + STACK_SIZE // 2
    sp -= 8
    uc.mem_write(sp, struct.pack("<Q", _RETADDR))
    uc.reg_write(X.UC_X86_REG_RSP, sp)
    for r, v in zip(_ARG_REGS, args):
        uc.reg_write(r, v & _M64)

    stk_lo, stk_hi = STACK, STACK + STACK_SIZE
    events = []
    returned = [False]

    def on_code(uc, address, sz, _):
        if address == _RETADDR:
            returned[0] = True
            uc.emu_stop()
            return
        events.append(("c", address, sz, 0))

    def on_read(uc, _t, addr, sz, _v, _u):
        try:
            v = int.from_bytes(uc.mem_read(addr, sz), "little")
        except UcError:
            v = 0
        events.append(("r", addr, sz, v))

    def on_write(uc, _t, addr, sz, v, _u):
        events.append(("w", addr, sz, v & ((1 << (8 * sz)) - 1)))

    uc.hook_add(UC_HOOK_CODE, on_code)
    uc.hook_add(UC_HOOK_MEM_READ, on_read)
    uc.hook_add(UC_HOOK_MEM_WRITE, on_write)
    retval = None
    try:
        uc.emu_start(fva, _RETADDR, count=cap)
        # a clean return reaches the sentinel address (emu_start's `until`); a budget-capped run
        # stops elsewhere mid-execution. Only trust RAX when we actually returned.
        if uc.reg_read(X.UC_X86_REG_RIP) == _RETADDR:
            returned[0] = True
            retval = uc.reg_read(X.UC_X86_REG_RAX) & _M64
    except UcError:
        pass

    byte_reads = [a for k, a, s, v in events if k == "r" and s == 1 and _rodata(img, a)]
    if not byte_reads:
        return None, None, None, None
    blob_lo = min(byte_reads)
    rf = [a for k, a, s, v in events if k == "w" and s == 8 and stk_lo <= a < stk_hi]
    if not rf:
        return None, None, None, None
    reg_base = min(rf)

    def slot(addr):
        return (addr - reg_base) // 8 if stk_lo <= addr < stk_hi and (addr - reg_base) % 8 == 0 else None

    def is_opcode_fetch(addr, sz):
        return sz == 1 and blob_lo <= addr < blob_lo + 0x4000 and (addr - blob_lo) % 4 == 0

    def is_pool(addr, sz):
        return sz >= 4 and _rodata(img, addr) and addr >= blob_lo + 0x40

    instrs, cur = [], None
    regvals = {}
    for k, addr, sz, v in events:
        if k == "r" and is_opcode_fetch(addr, sz):
            if cur is not None:
                cur["next"] = addr - blob_lo                 # this fetch is the previous instr's successor
            cur = {"off": addr - blob_lo, "next": None, "dst": None, "srcs": [], "result": None,
                   "pool": None, "loads": [], "stores": [], "regvals": dict(regvals)}
            instrs.append(cur)
        elif cur is None:
            continue
        elif k == "r" and is_pool(addr, sz):
            cur["pool"] = v
        elif k == "r" and (si := slot(addr)) is not None:
            cur["srcs"].append((si, v))
            regvals[si] = v
        elif k == "w" and sz == 8 and (si := slot(addr)) is not None:
            cur["dst"], cur["result"] = si, v
            regvals[si] = v
        elif k == "r" and not _rodata(img, addr) and not (stk_lo <= addr < stk_hi):
            cur["loads"].append((addr, sz, v))               # a dereference: LOAD
        elif k == "w" and not (stk_lo <= addr < stk_hi):
            cur["stores"].append((addr, sz, v))              # a dereference: STORE
    return blob_lo, reg_base, instrs, (retval if returned[0] else None)


def _rodata(img, va):
    # RustCloak keeps the bytecode and pool as *mutable* globals (volatile reads defeat
    # constant-folding), so they sit in .data as often as .rodata.
    for s in img.binary.sections:
        if s.name in (".rodata", ".data.rel.ro", ".data") and \
                s.virtual_address <= va < s.virtual_address + s.size:
            return True
    return False


# value-relation tests: logical op (OPS key) -> f(a, b) at a given width mask, matched against the
# observed result. Ordered so a more specific relation is preferred over one it subsumes.
def _rel(op, a, b, m):
    half = (m == 0xffffffff)
    sa = a - (m + 1) if a > (m >> 1) else a
    sb = b - (m + 1) if b > (m >> 1) else b
    try:
        return {
            2: (a + b) & m, 3: (a - b) & m, 4: (a * b) & m,
            5: a & b, 6: a | b, 7: a ^ b,
            8: (a << (b & 63)) & m, 9: (a & m) >> (b & 63),
            10: ((sa >> (b & 63)) & m),
            11: (a // b) & m if b else None, 13: (a % b) & m if b else None,
            12: (sa // sb) & m if sb else None, 14: (sa % sb) & m if sb else None,
            16: int(a == b), 17: int(a != b),
            18: int(a < b), 19: int(a <= b), 20: int(a > b), 21: int(a >= b),
            22: int(sa < sb), 23: int(sa <= sb), 24: int(sa > sb), 25: int(sa >= sb),
            26: a,
        }.get(op)
    except (ZeroDivisionError, ValueError):
        return None


_CMPOPS = {16, 17, 18, 19, 20, 21, 22, 23, 24, 25}
# inference order: common logic/arithmetic/shifts and comparisons first, then multiply; the
# division and remainder relations are rare and coincide easily on correlated loop samples, so they
# are tried last and only when enough distinct samples make a coincidence unlikely.
_BINOPS = [2, 3, 7, 5, 6, 8, 9, 10, 18, 19, 20, 21, 22, 23, 24, 25, 16, 17, 4, 26]
_DIVOPS = [11, 12, 13, 14]


def _infer_op(samples):
    """samples: list of (a_val, b_val, result). Return the logical op whose value relation reproduces
    the result on every sample (32- then 64-bit width), or None."""
    ops = _BINOPS + (_DIVOPS if len({s for s in samples}) >= 3 else [])
    for m in (0xffffffff, _M64):
        for op in ops:
            ok = True
            for a, b, res in samples:
                want = _rel(op, a & m, b & m, m)
                if want is None or want != (res if op in _CMPOPS else res & m):
                    ok = False
                    break
            if ok:
                return op
    return None


def _ptr_args(pv):
    """A pointer input vector: every lane is a distinct scratch pointer except the lanes named in
    `counts`, which carry small loop iteration counts so a loop over an argument terminates."""
    return [pv["counts"].get(i, pv["ptr"] + i * 0x10000) for i in range(6)]


def recover(path: Path, fva: int, size: int | None = None) -> dict | None:
    """Emulate the virtualized function at `fva`, reconstruct its opcode map / key / pool / control
    flow / memory ops by observation, lift with the core static lifter, and verify the result by
    re-executing the recovered program. Returns a lift_region result dict, or None."""
    img = Image(str(path))
    if img.arm or img.x32:
        return None
    if size is None:
        size = next((s for f, s in img.functions() if f == fva), 0x400)

    def trace_group(vecs):                                   # -> ([(args, instrs, ret, rb)], blob_lo)
        out, blob = [], None
        for args in vecs:
            bl, rb, instrs, ret = _trace(img, fva, size, args)
            if instrs:
                blob = bl
                out.append((args, instrs, ret, rb))
        return out, blob

    # Reconstruct per argument-type group (a scalar function run with pointer args, or vice versa,
    # takes a different/garbage path -- never mix the two). Trace and attempt the scalar group first
    # and return as soon as it verifies, so a scalar function never pays for the pointer-vector traces
    # (the common case). Both groups keep all their vectors -- the laziness is per *group*, not per
    # vector, so coverage (e.g. find_mix's data-dependent break) is unaffected.
    vraw, vblob = trace_group(_VALUE_VECTORS)
    if vblob is not None:
        result = _attempt(vraw, vblob, img)
        if result is not None:
            return result
    praw, pblob = trace_group([_ptr_args(pv) for pv in _PTR_VECTORS])
    if pblob is not None:
        result = _attempt(praw, pblob, img)
        if result is not None:
            return result
    return None


def _arg_map(clean):
    """Recover which VM register holds each incoming argument: {vm_reg -> (arg_index, mask)}.

    The interpreter copies the function's arguments into its register file by its own (build-specific)
    convention -- arg0 need not land in r0. We find it by observation: a register that is read before
    it is ever written is an input, and its first observed value equals one argument across every run.

    `mask` is the width at which the argument entered the register. A C `uint32` parameter is narrowed
    on the way in (the VM register only ever holds `arg & 0xffffffff`), so an op that reads it may have
    been recovered as 64-bit (its low half matched the narrowed operand), and seeding the register with
    the *full* 64-bit argument would then leak the high bits into that op. We therefore seed each
    argument register at the narrowest integer width that matches every run -- the parameter's true
    width. Requiring the SAME argument index across all runs rules out a constant that coincidentally
    equals one run's argument."""
    first = {}                                               # vm_reg -> [(value, args) per run]
    for args, instrs, _ in clean:
        seen = {}
        for ins in instrs:
            for i, v in ins["srcs"]:
                seen.setdefault(i, v)                        # value at its first use (pre-overwrite)
        for r, v in seen.items():
            first.setdefault(r, []).append((v, args))
    amap = {}
    for r, rows in first.items():
        if len(rows) < len(clean):                           # not read in every run -> not a clean input
            continue
        hit = None
        for k in range(6):
            if any(k >= len(a) for _, a in rows):
                continue
            # the *widest* width at which the observed value still equals the argument in every run is
            # the parameter's width: if the VM dropped the argument's high bits (a uint32 parameter),
            # the full-width compare fails and we fall to 0xffffffff; a genuine 64-bit argument matches
            # at _M64. (When the observed value equals the full argument, every mask matches, so taking
            # the narrowest would wrongly shrink a 64-bit parameter -- hence widest-first.)
            mask = next((m for m in (_M64, 0xffffffff, 0xffff, 0xff)
                         if all((v & m) == (a[k] & m) for v, a in rows)), None)
            if mask is not None:
                hit = (k, mask) if hit is None else "amb"
        if isinstance(hit, tuple):
            amap[r] = hit
    return amap


def _attempt(group_raw, blob_lo, img):
    """Reconstruct from one argument-type group and verify. group_raw is [(args, instrs, ret, rb)].
    Normalizes register indices within the group (the reg file is at fixed addresses, but each run's
    lowest written slot varies), keeps only cleanly-returning runs, reconstructs op/width/operands
    from the observations (no global operand key), and re-executes to confirm every run's return
    value and memory writes. Returns a lift_region dict or None -- nothing unverified is emitted."""
    if not group_raw:
        return None
    gbase = min(rb for *_, rb in group_raw)                  # one base for this group's runs
    clean = []
    for args, instrs, ret, rb in group_raw:
        if ret is None:                                      # did not cleanly return -> untrustworthy
            continue
        sh = (rb - gbase) // 8
        if sh:
            for ins in instrs:
                if ins["dst"] is not None:
                    ins["dst"] += sh
                ins["srcs"] = [(i + sh, v) for i, v in ins["srcs"]]
                ins["regvals"] = {i + sh: v for i, v in ins["regvals"].items()}
        clean.append((args, instrs, ret))
    if not clean:
        return None
    nreg = max((ins["dst"] for _, r, _ in clean for ins in r if ins["dst"] is not None), default=0) + 1
    by_off = {}
    for _, instrs, _ in clean:
        for ins in instrs:
            by_off.setdefault(ins["off"], []).append(ins)
    recon = _reconstruct(clean, by_off, nreg)
    if recon is None:
        return None
    prog, bytemap, pool = recon
    idx_of = {p[0]: i for i, p in enumerate(prog)}
    argmap = _arg_map(clean)
    checked = 0
    for args, instrs, ret in clean:
        res = _vm_exec(prog, bytemap, None, pool, idx_of, args, argmap=argmap)
        if res is None:
            return None
        rv, mem = res
        stores = [s for ins in instrs for s in ins["stores"]]
        # A function with memory writes is side-effecting: its output is those writes, and the value
        # left in the return register may be void/garbage -- verify by memory then. A pure function
        # (no writes) is verified by its return value.
        if not _mem_agrees(mem, stores):
            return None
        if not stores and ret is not None and rv is not None \
                and (rv & _M64) != (ret & _M64) and (rv & 0xffffffff) != (ret & 0xffffffff):
            return None
        checked += 1
    if not checked:
        return None
    return lift_vm.lift_region(blob_lo, prog, bytemap, pool, None)


_WC = {8: 0, 16: 1, 32: 2, 64: 3}


def _reconstruct(runs, by_off, nreg):
    """Build (prog, bytemap, pool) from the observed execution alone. Each bytecode offset becomes
    one instruction whose operands are the observed reg-file indices; operand bytes are synthesized
    (op byte = width<<6 | logical) so lift_region renders without any key."""
    def regs(srcs):
        return [(i, v) for i, v in srcs if 0 <= i < nreg]

    entries, pool, poolidx = {}, [], {}
    for off, occ in sorted(by_off.items()):
        s0 = occ[0]
        seq = off + 4
        terminal = any(o["next"] is None for o in occ)       # execution returned right after this
        nn = sorted({o["next"] for o in occ if o["next"] is not None})
        others = [n for n in nn if n != seq]                 # non-sequential successors (branch tgts)

        # Control flow is decided by the observed successor offsets, before anything reg-based: in the
        # hoisted dispatch even a branch gets a (garbage) result store, so "has a dst" cannot tell a
        # branch from an arithmetic op -- only the successor can. RET is only a terminal instruction;
        # a dst-less op that merely fell through (a branch never taken on these inputs) is a no-op.
        if terminal:
            entries[off] = (0, 64, 0, _ret_reg(occ, runs, off, regs), 0)   # RET r[a]
        elif others and seq in nn:                           # conditional branch (taken both ways seen)
            jb = _branch_kind(occ, regs, seq)
            if jb is None:
                return None
            base, cond = jb
            tgt = others[0]
            entries[off] = (base, 64, cond, tgt & 0xff, (tgt >> 8) & 0xff)
        elif others and seq not in nn:                       # unconditional jump
            tgt = others[0]
            entries[off] = (28, 64, 0, tgt & 0xff, (tgt >> 8) & 0xff)
        # A genuine VM memory op dereferences a pointer *register* (its address equals a reg value).
        # An obfuscated interpreter also touches memory incidentally (bogus flow, MBA constants); those
        # addresses match no reg, so _mem_op returns None and we fall through to dataflow classification
        # rather than mis-reading the instruction as a load/store.
        elif any(o["stores"] for o in occ) and _mem_op(occ, regs, store=True) is not None:
            a, b, w = _mem_op(occ, regs, store=True)
            entries[off] = (33, w, 0, a, b)
        elif (s0["dst"] is not None and any(o["loads"] for o in occ)
              and _mem_op(occ, regs, store=False) is not None):
            a, w, dst = _mem_op(occ, regs, store=False)
            entries[off] = (32, w, dst, a, 0)
        elif s0["dst"] is None:
            continue                                         # sequential, no result: a no-op here
        else:
            rd = regs(s0["srcs"])
            if not rd:                                       # wrote a reg, read none -> CONST
                val = s0["result"]
                if val is None:
                    return None
                if val not in poolidx:
                    poolidx[val] = len(pool)
                    pool.append(val & _M64)
                idx = poolidx[val]
                entries[off] = (1, 64, s0["dst"], idx & 0xff, (idx >> 8) & 0xff)
            else:
                cm = _cmov(occ, regs, s0["dst"])
                r = _arith(occ, regs)
                if cm is not None:                           # branchless select: cond ? val : prev
                    cond, val, nz = cm
                    entries[off] = (27 if nz else 31, 64, s0["dst"], cond, val)
                elif r is not None:
                    op, w, a, b = r
                    entries[off] = (op, w, s0["dst"], a, b)
                elif len({i for i, _ in rd}) == 1:           # single source -> MOV
                    entries[off] = (26, 64, s0["dst"], rd[0][0], 0)
                else:
                    return None

    prog, bytemap = [], {}
    for off in sorted(entries):
        logical, w, dst, a, b = entries[off]
        ob = (_WC.get(w, 3) << 6) | logical
        bytemap[ob] = logical
        prog.append((off, ob, dst, a, b))
    return prog, bytemap, (pool or None)


def _cmov(occ, regs, dst):
    """Detect a branchless select and return (cond_idx, val_idx, take_nonzero), else None.

    A select reads a condition register and, on one polarity of the condition, writes a value register;
    on the other it leaves the destination unchanged. Two shapes occur in practice (and this is
    codegen-agnostic, so we recognize both whatever the obfuscator):
        CMOVNZ:  r[dst] = r[cond] ? r[val] : r[dst]      (take_nonzero=True)
        CMOVZ:   r[dst] = r[cond] ? r[dst] : r[val]      (take_nonzero=False)
    Compiled as a conditional move or a tiny branch, the trace shows, per occurrence, the condition
    plus whichever operand *that run* actually took, so the source set varies between occurrences --
    which is why the fixed-operand arithmetic inference misses it (and can even mistake the selecting
    majority for `AND(val, val)`). The value may be read from a slot in one run and be live in a CPU
    register in another, so we consult the reg-file snapshot as well as the freshly-read sources.

    We require two-sided evidence so this never fires on a real binary op: at least one occurrence that
    preserves the destination (result equals its own prior value) and at least one that selects a
    distinct value register, each holding across every occurrence on its side of the condition."""
    def eq(x, y):
        return (x & _M64) == (y & _M64) or (x & 0xffffffff) == (y & 0xffffffff)

    merged = []
    for o in occ:
        if o["result"] is None:
            continue
        rd = dict(regs(o["srcs"]))
        for i, v in regs(list(o.get("regvals", {}).items())):
            rd.setdefault(i, v)                              # operand live in a register, not re-read
        if rd:
            merged.append((rd, o["result"]))
    if len(merged) < 2:
        return None

    def value_reg(rows, c):                                  # a distinct reg whose value == result in all
        vs = set.intersection(*[{i for i, v in rd.items() if i != c and eq(v, res)} for rd, res in rows])
        vs.discard(dst)
        return min(vs) if vs else None

    cond_candidates = set.intersection(*[set(rd) for rd, _ in merged])
    for c in cond_candidates:
        cz = [(rd, res) for rd, res in merged if rd[c] == 0]
        cnz = [(rd, res) for rd, res in merged if rd[c] != 0]
        if not cz or not cnz:
            continue
        # CMOVNZ: cond!=0 selects a value; cond==0 preserves the destination.
        if all(dst in rd and eq(rd[dst], res) for rd, res in cz):
            v = value_reg(cnz, c)
            if v is not None:
                return c, v, True
        # CMOVZ: cond==0 selects a value; cond!=0 preserves the destination.
        if all(dst in rd and eq(rd[dst], res) for rd, res in cnz):
            v = value_reg(cz, c)
            if v is not None:
                return c, v, False
    return None


def _arith(occ, regs):
    """Infer (op, width, a_idx, b_idx) for an arithmetic instruction from the observed source values
    and result across occurrences: the ordered operand pair and width whose value relation holds."""
    data = [(dict(regs(o["srcs"])), o["result"]) for o in occ if o["result"] is not None]
    data = [(rd, res) for rd, res in data if rd]
    if not data:
        return None
    slots = sorted({i for rd, _ in data for i in rd})
    # widest first: a genuine 32-bit op rejects width 64 (its zero-extended result loses the carry a
    # 64-bit relation would keep), while a 64-bit op would spuriously match at 32 on its low half.
    for w in (64, 32, 16, 8):
        m = (1 << w) - 1
        for a in slots:
            for b in slots:
                sub = [(rd, res) for rd, res in data if a in rd and b in rd]
                if len(sub) < max(2, len(data) // 2):        # enough evidence, not a stray pair
                    continue
                for op in _BINOPS + (_DIVOPS if len(sub) >= 3 else []):
                    if all((_rel(op, rd[a] & m, rd[b] & m, m)) ==
                           (res if op in _CMPOPS else res & m) for rd, res in sub):
                        return op, w, a, b
    return None


def _mem_op(occ, regs, store):
    """A LOAD/STORE: match the dereferenced address (and stored value) to the register holding it."""
    for o in occ:
        rd = dict(regs(o["srcs"]))
        acc = o["stores"] if store else o["loads"]
        if not acc:
            continue
        addr, sz, val = acc[0]
        a = next((i for i, v in rd.items() if v == addr), None)
        if a is None:
            continue
        if store:
            m = (1 << (8 * sz)) - 1
            b = next((i for i, v in rd.items() if (v & m) == (val & m)), None)
            return a, (b if b is not None else 0), sz * 8
        if o["dst"] is not None:
            return a, sz * 8, o["dst"]
    return None


def _branch_kind(occ, regs, seq):
    """Decide JZ vs JNZ and the condition register from whether the branch was taken when the
    observed condition register was zero."""
    votes = {29: 0, 30: 0}
    cond_idx = None
    for o in occ:
        if o["next"] is None:
            continue
        rd = dict(regs(o["srcs"]))
        if not rd:
            continue
        ci = next(iter(rd))
        cond_idx = ci
        took = o["next"] != seq
        votes[29 if (took == (rd[ci] == 0)) else 30] += 1
    if cond_idx is None:
        return None
    return (29 if votes[29] >= votes[30] else 30), cond_idx


def _ret_reg(occ, runs, off, regs):
    """The register a RET returns: the source whose value equals the function's observed return."""
    for args, instrs, ret in runs:
        if ret is None or instrs[-1]["off"] != off:
            continue
        rd = dict(regs(instrs[-1]["srcs"]))
        a = next((i for i, v in rd.items() if (v & 0xffffffff) == (ret & 0xffffffff) or v == ret), None)
        if a is not None:
            return a
    rd = dict(regs(occ[0]["srcs"]))
    return next(iter(rd), 0) if rd else 0


def _classify_offset(occ, blob, off, key, nreg):
    """Classify one bytecode offset to a logical op (OPS key) from its observations across runs.
    Returns (base, pool_value_or_None). Handles arithmetic (value relation), CONST, MOV, RET, the
    control-flow ops (via the next-fetch offset) and the memory ops (via dereferences)."""
    kd, ka, kb = key

    def regs(s):
        return {si: v for si, v in s if 0 <= si < nreg}

    s0 = occ[0]
    a_idx, b_idx = blob[off + 2] ^ ka, blob[off + 3] ^ kb
    seq = off + 4
    nexts = [o["next"] for o in occ if o["next"] is not None]
    jumped = [n for n in nexts if n != seq]

    if any(o["stores"] for o in occ):
        return 33, None                                      # STORE *(iW*)r[a] = r[b]
    if any(o["loads"] for o in occ) and s0["dst"] is not None:
        return 32, None                                      # LOAD r[dst] = *(iW*)r[a]
    if s0["dst"] is None:
        if jumped:
            cond_idx = blob[off + 1] ^ kd                    # JZ/JNZ read r[dst] as the condition
            votes = {29: 0, 30: 0}
            for o in occ:
                if o["next"] is None:
                    continue
                cond = regs(o["srcs"]).get(cond_idx)
                if cond is None:
                    continue
                took = o["next"] != seq
                votes[29 if (took == (cond == 0)) else 30] += 1
            if seq in nexts and (votes[29] or votes[30]):    # conditional branch
                return (29 if votes[29] >= votes[30] else 30), None
            if seq not in nexts:                             # always jumps -> unconditional
                return 28, None
        return 0, None                                       # no dst, no jump -> RET
    rmap0 = regs(s0["srcs"])
    if not rmap0:                                            # wrote a reg, read none -> CONST
        return 1, (s0["pool"] if s0["pool"] is not None else s0["result"])
    # operand values: prefer the freshly-read slots; fall back to the reg-file snapshot for an
    # operand that was live in a CPU register (a read-modify-write, or a reg reused without a
    # slot re-read), so loop-body ops are not lost. Require both operands present (no 0 defaults).
    samples = []
    for o in occ:
        if o["result"] is None:
            continue
        rm = regs(o["srcs"])
        av = rm.get(a_idx, o["regvals"].get(a_idx))
        bv = rm.get(b_idx, o["regvals"].get(b_idx))
        if av is not None and bv is not None:
            samples.append((av, bv, o["result"]))
    op = _infer_op(samples) if samples else None
    if op is not None:
        return op, None
    # single-operand copy (MOV), or a reg-to-reg move whose source is live in a register
    if len(rmap0) <= 1:
        return 26, None
    return None, None


class _ScratchMem:
    """Byte-addressable memory that mirrors the emulator's scratch: unwritten scratch bytes read back
    as the same high-entropy fill Unicorn used, so a verifier run reproduces what the sample read."""
    def __init__(self):
        self.ov = {}

    def _base(self, a):
        if _SCRATCH <= a < _SCRATCH + _SCRATCH_SIZE:
            return _entropy(_SCRATCH_SIZE)[a - _SCRATCH]
        return 0

    def read(self, addr, width):
        return int.from_bytes(bytes(self.ov.get(addr + i, self._base(addr + i))
                                    for i in range(width // 8)), "little")

    def write(self, addr, width, val):
        for i in range(width // 8):
            self.ov[addr + i] = (val >> (8 * i)) & 0xff


def _vm_exec(prog, bytemap, key, pool, idx_of, args, maxsteps=500_000, argmap=None):
    """Interpret the recovered program (register machine + control flow + memory) over args. Returns
    (return_value_or_None, memory) or None if it hits an op it does not model (call/select/sext...).

    `argmap` is {vm_reg -> (argument_index, mask)}: which VM register holds each incoming argument and
    the width it entered at, recovered by observation. The interpreter lays its arguments into VM
    registers by its own convention (an obfuscated build may put arg0 in r10, not r0) and narrows each
    to its C parameter width, so seeding reg[i]=args[i] blindly feeds the program zeros for its real
    inputs -- or the full 64 bits of a value the program only uses 32 of. When no map is supplied we
    fall back to the positional assumption."""
    import bisect
    if argmap:
        reg = {i: 0 for i in range(64)}
        for vr, (k, mask) in argmap.items():
            if k < len(args):
                reg[vr] = args[k] & mask                      # seed at the parameter's observed width
    else:
        reg = {i: (args[i] & _M64 if i < len(args) else 0) for i in range(64)}
    mem = _ScratchMem()
    offs = [p[0] for p in prog]

    def target(t):
        # a branch target may be a skipped no-op (a never-taken branch); it falls through, so resolve
        # to the first real instruction at or after it.
        if t in idx_of:
            return idx_of[t]
        j = bisect.bisect_left(offs, t)
        return j if j < len(prog) else None

    i = steps = 0
    while 0 <= i < len(prog) and steps < maxsteps:
        steps += 1
        off, op, dst, a, b = prog[i]
        base = bytemap.get(op)
        w = lift_vm._width(op)
        m = (1 << w) - 1
        if base == 0:
            return reg.get(a, 0), mem
        if base == 35:
            return None, mem
        if base == 1:
            reg[dst] = (pool[a | (b << 8)] if pool and (a | (b << 8)) < len(pool) else 0) & _M64
        elif base == 26:
            reg[dst] = reg.get(a, 0)
        elif base == 27:                                     # CMOVNZ: r[dst] = r[a] ? r[b] : r[dst]
            if reg.get(a, 0) != 0:
                reg[dst] = reg.get(b, 0)
        elif base == 31:                                     # CMOVZ:  r[dst] = r[a] ? r[dst] : r[b]
            if reg.get(a, 0) == 0:
                reg[dst] = reg.get(b, 0)
        elif base == 32:
            reg[dst] = mem.read(reg.get(a, 0), w) & _M64
        elif base == 33:
            mem.write(reg.get(a, 0), w, reg.get(b, 0) & m)
        elif base == 28:
            i = target(a | (b << 8))
            if i is None:
                return None
            continue
        elif base in (29, 30):
            take = (reg.get(dst, 0) == 0) if base == 29 else (reg.get(dst, 0) != 0)
            if take:
                i = target(a | (b << 8))
                if i is None:
                    return None
                continue
        elif base is None or base in (34, 36, 37):           # sext/pusharg/call: not modelled
            return None
        else:
            v = _rel(base, reg.get(a, 0) & m, reg.get(b, 0) & m, m)
            if v is None:
                return None
            reg[dst] = v if base in _CMPOPS else (v & m)
        i += 1
    return None


def _mem_agrees(mem, observed_stores):
    """Every byte the sample stored must read back the same from the verifier's memory."""
    final = {}
    for addr, sz, val in observed_stores:
        for i in range(sz):
            final[addr + i] = (val >> (8 * i)) & 0xff
    for addr, byte in final.items():
        if mem.read(addr, 8) & 0xff != byte:
            return False
    return True


def recover_all(path: Path) -> dict:
    """Devirtualize every VM function in a binary, preferring the fast static lifter and falling back
    to emulation for functions it cannot recover (e.g. a dispatch shape or an obfuscated interpreter
    the static patterns miss). Emulation results are self-verified. Returns
    {"static": [...], "emulated": [...], "count": n}."""
    img = Image(str(path))
    static = lift_vm.lift(path)
    done = {r["bytecode_va"] for r in static["lifted"]}
    emulated = []
    if not (img.arm or img.x32):
        text_lo, text_hi = img.text_va, img.text_end
        for fva, size in img.functions():
            if lift_vm._recover_map(img, fva, size, text_lo, text_hi) is None:
                continue                                     # not a VM function
            r = recover(path, fva, size)
            if r and r["bytecode_va"] not in done:
                emulated.append(r)
                done.add(r["bytecode_va"])
    return {"file": str(path), "static": static["lifted"], "emulated": emulated,
            "count": len(done)}


def _solve_kd(blob, by_off, nreg):
    """kd from the dst byte: raw_byte[1] XOR observed_dst_index, required consistent."""
    kd = None
    for off, occ in by_off.items():
        d = occ[0]["dst"]
        if d is None or not (0 <= d < nreg):
            continue
        k = blob[off + 1] ^ d
        if kd is None:
            kd = k
        elif k != kd:
            return None
    return kd


def _solve_kab(blob, by_off, regs):
    """ka, kb from the two operand bytes: find keys so that {byte2^ka, byte3^kb} equals each binary
    instruction's observed source-register set. Read order is not fixed, so match as a set. A few
    instructions may read an extra reg-file slot (dispatch artifacts), so pick the (ka,kb) that
    satisfies the most binary candidates rather than requiring all."""
    bins = [(off, set(regs(occ[0]["srcs"])))
            for off, occ in by_off.items() if len(regs(occ[0]["srcs"])) == 2]
    if not bins:
        return None, None
    best, best_hits = (None, None), 0
    for off0, set0 in bins:                                  # each candidate proposes a (ka, kb)
        s = sorted(set0)
        for a_from, b_from in ((0, 1), (1, 0)):
            ka = blob[off0 + 2] ^ s[a_from]
            kb = blob[off0 + 3] ^ s[b_from]
            hits = sum({blob[off + 2] ^ ka, blob[off + 3] ^ kb} == st for off, st in bins)
            if hits > best_hits:
                best, best_hits = (ka, kb), hits
    if best_hits >= max(2, (len(bins) + 1) // 2):            # a real majority, not a coincidence
        return best
    return None, None


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("binary")
    ap.add_argument("func_va", help="virtualized function VA, e.g. 0x1650")
    a = ap.parse_args(argv)
    r = recover(Path(a.binary), int(a.func_va, 0))
    if not r:
        print("could not recover")
        return 1
    print(f"emulated devirtualization @ 0x{r['bytecode_va']:x} ({r['instructions']} vm-instructions)")
    for ln in r.get("pseudocode") or []:
        print("  " + ln)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
