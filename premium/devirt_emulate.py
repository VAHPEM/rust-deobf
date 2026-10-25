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

# input vectors: distinct, odd, high-entropy values so a value relation (add vs xor vs mul ...) that
# holds by coincidence on one vector is ruled out by another. Six lanes cover a 6-arg callee.
_VECTORS = [
    [0x1122334455667788, 0x00000000000000aa, 0x0f0f0f0f0f0f0f0f, 3, 5, 7],
    [0xdeadbeefcafef00d, 0x0123456789abcdef, 0xfedcba9876543210, 9, 11, 13],
    [0x8000000000000001, 0x7fffffffffffffff, 0x5555555555555555, 2, 4, 6],
]


def _trace(img, fva, size, args):
    """Run one input vector; return the ordered list of VM instructions actually executed, each as
    {off, dst, srcs, result, opvals, pool} with register indices relative to the reg-file base."""
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    _fast_access(uc)
    map_image(uc, img.binary)
    uc.mem_map(STACK, STACK_SIZE)
    sp = STACK + STACK_SIZE // 2
    sp -= 8
    uc.mem_write(sp, struct.pack("<Q", _RETADDR))
    uc.reg_write(X.UC_X86_REG_RSP, sp)
    for r, v in zip(_ARG_REGS, args):
        uc.reg_write(r, v & _M64)

    stk_lo, stk_hi = STACK, STACK + STACK_SIZE
    events = []                              # ('r'|'w', addr, size, value)

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
        uc.emu_start(fva, _RETADDR, count=2_000_000)
        retval = uc.reg_read(X.UC_X86_REG_RAX) & _M64
    except UcError:
        pass

    # blob = the run of 1-byte reads from .rodata; pool = 8-byte reads just past it
    byte_reads = [a for k, a, s, v in events if k == "r" and s == 1 and _rodata(img, a)]
    if not byte_reads:
        return None, None, None, None
    blob_lo = min(byte_reads)
    # reg-file base = the lowest stack slot the interpreter writes as an 8-byte word
    rf = [a for k, a, s, v in events if k == "w" and s == 8 and stk_lo <= a < stk_hi]
    if not rf:
        return None, None, None, None
    reg_base = min(rf)

    def slot(addr):
        return (addr - reg_base) // 8 if stk_lo <= addr < stk_hi and (addr - reg_base) % 8 == 0 else None

    instrs, cur = [], None
    nonreg_mem = [False]                     # any load/store outside reg-file/blob/pool/stack-frame?
    for k, addr, sz, v in events:
        if k == "r" and sz == 1 and blob_lo <= addr < blob_lo + 0x4000 and (addr - blob_lo) % 4 == 0:
            cur = {"off": addr - blob_lo, "dst": None, "srcs": [], "result": None, "pool": None}
            instrs.append(cur)
        elif cur is not None and k == "r" and sz == 8 and _rodata(img, addr) and addr >= blob_lo + 0x40:
            cur["pool"] = v                  # CONST: the i64 pool entry it loaded
        elif cur is not None and k == "r" and (si := slot(addr)) is not None:
            cur["srcs"].append((si, v))
        elif cur is not None and k == "w" and sz == 8 and (si := slot(addr)) is not None:
            cur["dst"], cur["result"] = si, v
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


_BINOPS = [4, 11, 12, 13, 14, 2, 3, 7, 5, 6, 8, 9, 10, 24, 20, 22, 18, 25, 21, 23, 19, 16, 17, 26]
_CMPOPS = {16, 17, 18, 19, 20, 21, 22, 23, 24, 25}


def _infer_op(samples):
    """samples: list of (a_val, b_val, result). Return the logical op whose value relation reproduces
    the result on every sample (32- then 64-bit width), or None."""
    for m in (0xffffffff, _M64):
        for op in _BINOPS:
            ok = True
            for a, b, res in samples:
                want = _rel(op, a & m, b & m, m)
                if want is None or want != (res if op in _CMPOPS else res & m):
                    ok = False
                    break
            if ok:
                return op
    return None


def recover(path: Path, fva: int, size: int | None = None) -> dict | None:
    """Emulate the virtualized function at `fva` and reconstruct (blob_va, bytemap, key, pool,
    default_base) by observation, then lift with the core static lifter. Returns a lift_region
    result dict (with pseudocode), or None if the function could not be recovered."""
    img = Image(str(path))
    if img.arm or img.x32:
        return None
    if size is None:
        size = next((s for f, s in img.functions() if f == fva), 0x400)

    runs, rets = [], []
    blob_lo = None
    for vec in _VECTORS:
        bl, rb, instrs, ret = _trace(img, fva, size, vec)
        if instrs:
            blob_lo = bl
            runs.append(instrs)
            rets.append((vec, ret))
    if not runs:
        return None

    # this module models branchless functions (the robust core; control flow and memory are the next
    # extension). A repeated bytecode offset within one run means a loop/branch -- bail cleanly so we
    # never emit unverifiable C for a function we do not fully model.
    for r in runs:
        offs = [ins["off"] for ins in r]
        if len(offs) != len(set(offs)):
            return None

    nreg = max((ins["dst"] for r in runs for ins in r if ins["dst"] is not None), default=0) + 1

    def regs(srcs):                                          # keep only plausible reg-file indices
        return {si: v for si, v in srcs if 0 <= si < nreg}

    # group every executed instruction by its bytecode offset; one offset is one static instruction,
    # seen once (branchless) or many times (a loop body) -- the observations agree either way.
    by_off = {}
    for instrs in runs:
        for ins in instrs:
            by_off.setdefault(ins["off"], []).append(ins)

    blob = lift_vm._read_va(img, blob_lo, max(by_off) + 8)

    # Byte layout is [opcode, dst^kd, a^ka, b^kb] (opcode first in observed builds). Recover the three
    # keys from the observed register indices: kd from the dst byte (always reliable), then ka/kb by
    # set-matching the two operand bytes against each binary instruction's source-index set (the
    # handler's read order is not fixed, so match as a set, not positionally).
    kd = _solve_kd(blob, by_off, nreg)
    ka, kb = _solve_kab(blob, by_off, regs)
    if kd is None or ka is None:
        return None
    key = (kd, ka, kb)

    # classify each offset with the decoded a/b (byte2^ka, byte3^kb), re-inferring the op from the
    # values recorded for those exact registers.
    bytemap, idxpool, default_base = {}, {}, None
    for off, occ in sorted(by_off.items()):
        s0 = occ[0]
        rmap0 = regs(s0["srcs"])
        ob = blob[off]
        if s0["dst"] is None:                                # no reg write -> return (control flow TODO)
            bytemap[ob] = 0
            continue
        a_idx = blob[off + 2] ^ ka
        b_idx = blob[off + 3] ^ kb
        if not rmap0:                                        # wrote a reg, read none -> CONST
            bytemap[ob] = 1
            idxpool[(blob[off + 2] ^ ka) | ((blob[off + 3] ^ kb) << 8)] = \
                (s0["pool"] if s0["pool"] is not None else s0["result"]) & _M64
            continue
        samples = []
        for o in occ:
            rm = regs(o["srcs"])
            if o["result"] is not None and a_idx in rm:
                samples.append((rm[a_idx], rm.get(b_idx, 0), o["result"]))
        op = _infer_op(samples) if samples else None
        bytemap[ob] = op if op is not None else (26 if len(rmap0) <= 1 else None)
        if bytemap[ob] is None:
            del bytemap[ob]

    pool = [idxpool.get(i, 0) for i in range(max(idxpool) + 1)] if idxpool else None
    prog = lift_vm._decode_map(blob, bytemap, key, default_base)
    if not prog:
        return None
    # correctness gate: re-execute the recovered program in a tiny verifier and require it to
    # reproduce the return value observed for every input vector. This refuses -- rather than emits
    # wrong C -- anything the branchless recovery does not fully model (loops, memory, calls, select).
    checked = [(vec, ret) for vec, ret in rets if ret is not None]
    if not checked or not all(_verify(prog, bytemap, key, pool, vec, ret) for vec, ret in checked):
        return None                                          # no clean return, or a mismatch -> refuse
    return lift_vm.lift_region(blob_lo, prog, bytemap, pool, default_base)


def _verify(prog, bytemap, key, pool, args, observed):
    """Execute the decoded branchless program over a register file seeded with `args` and check its
    return equals `observed` (at 64- or 32-bit width). Returns False on any op it does not model."""
    kd, ka, kb = key
    reg = {i: (args[i] & _M64 if i < len(args) else 0) for i in range(64)}
    for off, op, dst, a, b in prog:
        base = bytemap.get(op)
        if base in (36, 37, 27, 28, 29, 30, 32, 33, 34):     # call/pusharg/select/branch/mem: not modelled
            return False
        if base == 0:                                        # RET a
            r = reg.get(a, 0)
            return (r & _M64) == (observed & _M64) or (r & 0xffffffff) == (observed & 0xffffffff)
        if base == 35:
            return True
        if base == 1:
            reg[dst] = (pool[a | (b << 8)] if pool and (a | (b << 8)) < len(pool) else 0) & _M64
        elif base == 26:
            reg[dst] = reg.get(a, 0)
        else:
            w = lift_vm._width(op)                           # the op's width rides in the opcode byte
            m = (1 << w) - 1
            v = _rel(base, reg.get(a, 0) & m, reg.get(b, 0) & m, m)
            if v is None:
                return False
            reg[dst] = (v & m) if base not in _CMPOPS else v  # 32-bit ops zero-extend into the slot
    return False


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
    instruction's observed source-register set. Read order is not fixed, so match as a set."""
    bins = [(off, set(regs(occ[0]["srcs"])))
            for off, occ in by_off.items() if len(regs(occ[0]["srcs"])) == 2]
    if not bins:
        return None, None
    off0, set0 = bins[0]
    for a_from, b_from in ((0, 1), (1, 0)):                  # which source maps to byte2 vs byte3
        s = sorted(set0)
        ka = blob[off0 + 2] ^ s[a_from]
        kb = blob[off0 + 3] ^ s[b_from]
        if all({blob[off + 2] ^ ka, blob[off + 3] ^ kb} == st for off, st in bins):
            return ka, kb
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
