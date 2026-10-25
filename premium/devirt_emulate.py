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

_CORE = Path(__file__).resolve().parent.parent / "scripts"
if str(_CORE) not in sys.path:
    sys.path.insert(0, str(_CORE))

import lift_vm                              # core (Apache-2.0): static decode + lift_region
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
]
_SCRATCH = 0x20000000
_SCRATCH_SIZE = 0x400000
# pointer vectors: the lane value is a scratch pointer, or a small loop-count. Several assignments of
# which lanes are counts cover functions with the count in different argument positions.
_PTR_VECTORS = [
    {"ptr": _SCRATCH + 0x1000, "counts": {1: 9, 2: 7, 3: 5}},
    {"ptr": _SCRATCH + 0x2000, "counts": {1: 6, 3: 4, 4: 8}},
    {"ptr": _SCRATCH + 0x3000, "counts": {2: 11, 3: 10}},
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


def _trace(img, fva, size, args, cap=400_000):
    """Run one input vector under Unicorn and return the executed VM-instruction trace. Each entry:
    {off, next, dst, srcs, result, pool, loads, stores, regvals}. Register indices are relative to
    the reg-file base; loads/stores are (addr, size, value) outside the reg file; `next` is the
    bytecode offset of the following fetch (for control-flow recovery)."""
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

    def on_code(uc, address, sz, _):
        if address == _RETADDR:
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
    return blob_lo, reg_base, instrs, retval


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

    runs = []                                                # (args, instrs, retval)
    blob_lo = None
    for args in _VALUE_VECTORS + [_ptr_args(pv) for pv in _PTR_VECTORS]:
        bl, rb, instrs, ret = _trace(img, fva, size, args)
        if instrs:
            blob_lo = bl
            runs.append((args, instrs, ret))
    if not runs:
        return None

    nreg = max((ins["dst"] for _, r, _ in runs for ins in r if ins["dst"] is not None), default=0) + 1

    def regs(srcs):
        return {si: v for si, v in srcs if 0 <= si < nreg}

    by_off = {}
    for _, instrs, _ in runs:
        for ins in instrs:
            by_off.setdefault(ins["off"], []).append(ins)
    blob = lift_vm._read_va(img, blob_lo, max(by_off) + 8)

    kd = _solve_kd(blob, by_off, nreg)
    ka, kb = _solve_kab(blob, by_off, regs)
    if kd is None or ka is None:
        return None
    key = (kd, ka, kb)

    bytemap, idxpool = {}, {}
    for off, occ in sorted(by_off.items()):
        base, poolval = _classify_offset(occ, blob, off, key, nreg)
        if base is None:
            continue
        bytemap[blob[off]] = base
        if base == 1 and poolval is not None:
            idxpool[(blob[off + 2] ^ ka) | ((blob[off + 3] ^ kb) << 8)] = poolval & _M64
    pool = [idxpool.get(i, 0) for i in range(max(idxpool) + 1)] if idxpool else None

    prog = lift_vm._decode_map(blob, bytemap, key, None)
    if not prog:
        return None
    # correctness gate: re-execute the recovered program in the Python VM for every input vector that
    # cleanly returned under emulation, and require it to reproduce the observed return value AND the
    # observed memory writes. Refuse (None) on any mismatch or unmodelled op, so we never emit wrong C.
    idx_of = {p[0]: i for i, p in enumerate(prog)}
    checked = 0
    for args, instrs, ret in runs:
        if instrs[-1]["next"] is not None:                   # run hit the instruction budget, not a RET
            continue
        observed_stores = [s for ins in instrs for s in ins["stores"]]
        res = _vm_exec(prog, bytemap, key, pool, idx_of, args)
        if res is None:
            return None
        rv, mem = res
        if ret is not None and rv is not None and (rv & _M64) != (ret & _M64) \
                and (rv & 0xffffffff) != (ret & 0xffffffff):
            return None
        if not _mem_agrees(mem, observed_stores):
            return None
        checked += 1
    if not checked:
        return None
    return lift_vm.lift_region(blob_lo, prog, bytemap, pool, None)


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


def _vm_exec(prog, bytemap, key, pool, idx_of, args, maxsteps=500_000):
    """Interpret the recovered program (register machine + control flow + memory) over args. Returns
    (return_value_or_None, memory) or None if it hits an op it does not model (call/select/sext...)."""
    reg = {i: (args[i] & _M64 if i < len(args) else 0) for i in range(64)}
    mem = _ScratchMem()
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
        elif base == 32:
            reg[dst] = mem.read(reg.get(a, 0), w) & _M64
        elif base == 33:
            mem.write(reg.get(a, 0), w, reg.get(b, 0) & m)
        elif base == 28:
            i = idx_of.get(a | (b << 8))
            if i is None:
                return None
            continue
        elif base in (29, 30):
            take = (reg.get(dst, 0) == 0) if base == 29 else (reg.get(dst, 0) != 0)
            if take:
                i = idx_of.get(a | (b << 8))
                if i is None:
                    return None
                continue
        elif base is None or base in (27, 34, 36, 37):       # select/sext/pusharg/call: not modelled
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
