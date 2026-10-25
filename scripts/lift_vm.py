#!/usr/bin/env python3
"""lift_vm.py - lift a RustCloak-virtualized function's bytecode back to a readable listing.

detect_vm.py says a function is virtualized; this goes one step further and *devirtualizes* it to
the VM's own assembly: it finds the embedded bytecode blob, decodes the register-machine
instructions (including the control-flow opcodes -- JMP/JZ/JNZ, so loops and branches show as
labels), and resolves the constant pool. The result is the function's logic as a compact listing an
analyst can read, instead of a dispatch loop they cannot.

This is a round-1 lifter: it targets RustCloak's own bytecode format on x86-64 (where the dispatch
is a threaded computed-goto and the blob is easy to anchor). It recovers the VM-assembly, not yet
C/pseudocode source (that -- re-SSA, expression folding -- is the next round), and it does not need
to run anything. STATIC ONLY.

    python3 scripts/lift_vm.py <binary> [--json]
"""
from __future__ import annotations

import argparse
import json
import re
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

# base opcode -> (mnemonic, kind). The opcode byte is `base | (wcode<<6)` where wcode in
# {0:i8,1:i16,2:i32,3:i64} gives the width of a width-sensitive op. kind: "bin" dst,a,b ;
# "mov" dst,a ; "cmov" dst,a,b ; "const" dst,idx ; "ret" a ; "retv" ; "jmp" tgt ; "jcc" dst,tgt ;
# "load" dst,a ; "store" a,b ; "sext" dst,a
OPS = {
    0: ("ret", "ret"), 1: ("const", "const"),
    2: ("add", "bin"), 3: ("sub", "bin"), 4: ("mul", "bin"), 5: ("and", "bin"),
    6: ("or", "bin"), 7: ("xor", "bin"), 8: ("shl", "bin"), 9: ("lshr", "bin"),
    10: ("ashr", "bin"), 11: ("udiv", "bin"), 12: ("sdiv", "bin"), 13: ("urem", "bin"),
    14: ("srem", "bin"),
    16: ("eq", "bin"), 17: ("ne", "bin"), 18: ("ult", "bin"), 19: ("ule", "bin"),
    20: ("ugt", "bin"), 21: ("uge", "bin"), 22: ("slt", "bin"), 23: ("sle", "bin"),
    24: ("sgt", "bin"), 25: ("sge", "bin"),
    26: ("mov", "mov"), 27: ("cmovnz", "cmov"),
    28: ("jmp", "jmp"), 29: ("jz", "jcc"), 30: ("jnz", "jcc"),
    32: ("load", "load"), 33: ("store", "store"), 34: ("sext", "sext"), 35: ("retv", "retv"),
}
WIDTH = {0: 8, 1: 16, 2: 32, 3: 64}


def _base(op):
    return op & 0x3f


def _width(op):
    return WIDTH[(op >> 6) & 3]


# RustCloak randomizes the opcode->byte map per build, so the lifter cannot assume fixed numbers:
# it must recover the map from the interpreter's dispatch handlers. A handler's characteristic
# native instruction reveals its logical operation.
_CHAR = {
    "xor": 7, "sub": 3, "imul": 4, "and": 5, "or": 6, "add": 2,
    "shl": 8, "sal": 8, "shr": 9, "sar": 10,
    "sete": 16, "setne": 17, "setb": 18, "setbe": 19, "seta": 20, "setae": 21,
    "setl": 22, "setle": 23, "setg": 24, "setge": 25,
}
_REGS = re.compile(r"\[rsp \+ \w+\*8 - 0x[0-9a-f]+\]")       # the VM register file on the stack


def _handler_insns(img, hva, text_lo, text_hi):
    if not (text_lo <= hva < text_hi):
        return []
    code = bytes(img.code[hva - img.text_va: hva - img.text_va + 64])
    out = []
    for ins in img.md.disasm(code, hva):
        out.append((ins.mnemonic, ins.op_str))
        # a handler ends by re-fetching the next opcode (`add rsi, 4` / bumping the bc pointer) or
        # returning; stop there so we only read this handler's body
        if ins.mnemonic == "ret" or (ins.mnemonic == "add" and re.match(r"r\w+, [0-9]", ins.op_str)
                                     and "rsp" not in ins.op_str):
            break
        if ins.mnemonic in ("jmp",) and not ins.op_str.startswith("0x"):
            break
    return out


_STKPTR = re.compile(r"^(rsp|rbp|rsi|rdi|esp|ebp|esi|edi),")   # stack / bytecode-pointer dests


def _classify_handler(img, hva, text_lo, text_hi):
    """Map a dispatch handler's native body to a logical VM opcode (an OPS key), or None.

    Keyed on the handler's characteristic native instruction, in a priority that avoids the index
    arithmetic in a CONST or the pointer math in a load being mistaken for the real operation."""
    insns = _handler_insns(img, hva, text_lo, text_hi)
    if not insns:
        return None
    mnems = [m for m, _ in insns]
    regs_store = any(m == "mov" and re.search(r"\[rsp \+ \w+\*8 - 0x[0-9a-f]+\],", o)
                     for m, o in insns)                    # writes the VM register file
    regs_load = any(_REGS.search(o) for _, o in insns)

    if "ret" in mnems:
        return 0 if regs_load else 35                       # RET vs RETV
    # CMOVNZ writes the reg file via a conditional move (select); check before load/arith
    if any(m.startswith("cmov") for m, _ in insns) and regs_store:
        return 27
    # CONST is the only handler that references a global (the pool) via a rip-relative lea
    if any(m == "lea" and "[rip " in o for m, o in insns) and regs_store:
        return 1
    # division: quotient (eax/rax) vs remainder (edx/rdx -> stored back to the reg file)
    for m, o in insns:
        if m in ("div", "idiv"):
            rem = any(re.search(r"\[rsp \+ \w+\*8 - 0x[0-9a-f]+\], [re]dx$", oo) for _, oo in insns)
            return (14 if rem else 12) if m == "idiv" else (13 if rem else 11)
    # store through a register pointer: mov [rX], rY  (rX is a VM pointer, not the rsp reg-file)
    if any(m == "mov" and re.match(r"\[r[a-z0-9]+\], ", o) and "rsp" not in o for m, o in insns):
        return 33
    # load through a register pointer: mov/movzx rD, [rX]  (rX not rsp reg-file, not rip)
    if any(m in ("mov", "movzx") and re.search(r", (?:[a-z]+ ptr )?\[r[a-z0-9]+\]$", o)
           and "rsp" not in o and "rip" not in o for m, o in insns) and regs_store:
        return 32
    if any(m == "movsx" for m, _ in insns) and regs_store:
        return 34                                            # SEXT (sign-extend into the reg file)
    # arithmetic / comparison on the reg file or on temporaries (skip stack/bc-pointer bumps)
    for m, o in insns:
        if m in _CHAR and not _STKPTR.match(o):
            if m == "xor":
                parts = o.split(",")
                if len(parts) == 2 and parts[0].strip() == parts[1].strip():
                    continue                                # xor eax,eax zeroing
            return _CHAR[m]
    # control flow: handlers that do not write the reg file
    if not regs_store:
        for m, _ in insns:
            if m in ("cmove", "sete"):
                return 29                                    # JZ
            if m in ("cmovne", "setne"):
                return 30                                    # JNZ
        return 28                                            # JMP
    return 26                                                # MOV (reg file -> reg file)


def _alias32(r):
    m = {"rax": "eax", "rbx": "ebx", "rcx": "ecx", "rdx": "edx",
         "rsi": "esi", "rdi": "edi", "rbp": "ebp", "rsp": "esp"}
    if r in m:
        return m[r]
    return r + "d" if re.match(r"r\d+$", r) else r


def _alias64(r):
    m = {"eax": "rax", "ebx": "rbx", "ecx": "rcx", "edx": "rdx",
         "esi": "rsi", "edi": "rdi", "ebp": "rbp", "esp": "rsp"}
    if r in m:
        return m[r]
    return r[:-1] if re.match(r"r\d+d$", r) else r


def _recover_operand_key(lines):
    """RustCloak XOR-encrypts the three operand bytes (dst,a,b) with a per-build key; the interpreter
    decrypts each with `xor reg, IMM` right after fetching it. Recover (kd, ka, kb). The opcode byte
    (at [ptr-3]) is not encrypted; dst=[ptr-2], a=[ptr-1], b=[ptr-0]."""
    key = {2: 0, 1: 0, 0: 0}                                  # offset-from-ptr -> key byte
    for i, ins in enumerate(lines):
        m = re.match(r"movzx (\w+), byte ptr \[\w+( - ([0-3]))?\]$", ins.mnemonic + " " + ins.op_str)
        if not m:
            continue
        k = int(m.group(3)) if m.group(3) else 0
        if k not in (0, 1, 2):
            continue
        reg = m.group(1)
        for j in range(i + 1, min(i + 4, len(lines))):
            x = re.match(r"xor (\w+), (0x[0-9a-fA-F]+)$", lines[j].mnemonic + " " + lines[j].op_str)
            if x and x.group(1) in (reg, _alias64(reg)):
                key[k] = int(x.group(2), 16) & 0xff
                break
    return (key[2], key[1], key[0])                           # (kd, ka, kb)


def _recover_map(img, fva, size, text_lo, text_hi):
    """Recover this function's opcode-byte -> logical-op map by parsing its dispatch jump table
    (`lea base,[rip+T]; add idx,-min; cmp idx,N; movsxd r,[base+idx*4]; add r,base; jmp r`) and
    classifying each handler. Returns {byte: base} or None if the dispatch can't be parsed."""
    off = fva - img.text_va
    lines = list(img.md.disasm(bytes(img.code[off:off + size]), fva))
    disp_i = base_reg = idx_reg = None
    for i, ins in enumerate(lines):
        m = re.match(r"(movsxd|movslq) \w+, dword ptr \[(\w+) \+ (\w+)\*4\]",
                     ins.mnemonic + " " + ins.op_str)
        if m:
            disp_i, base_reg, idx_reg = i, m.group(2), m.group(3)
            break
    if disp_i is None:
        return None
    table_base = None
    for j in range(disp_i - 1, -1, -1):                      # scan the whole prologue for the lea
        lm = re.match(r"lea " + base_reg + r", \[rip \+ (0x[0-9a-f]+)\]",
                      lines[j].mnemonic + " " + lines[j].op_str)
        if lm:
            table_base = lines[j].address + lines[j].size + int(lm.group(1), 16)
            break
    if table_base is None:
        return None
    idx32 = _alias32(idx_reg)
    idxpat = "(?:" + idx_reg + "|" + idx32 + ")"
    minv, extent = 0, None
    key_imm = []
    # the normalization, range check and operand-decrypt all sit in the prologue just before the
    # table load; restrict to that window so handler code on the same registers isn't mistaken.
    win = lines[max(0, disp_i - 18):disp_i]
    for ins in win:
        t = ins.mnemonic + " " + ins.op_str
        # normalization: either `add idx, -min` or `lea idx, [src - min]`
        m = re.match(r"add " + idxpat + r", (0x[0-9a-fA-F]+)$", t)
        if m:
            imm = int(m.group(1), 16)
            imm -= (1 << 32) if imm >= 0x80000000 else 0
            minv = (-imm) & 0xff
        m = re.match(r"lea " + idxpat + r", \[\w+ - (0x[0-9a-fA-F]+)\]$", t)
        if m:
            minv = int(m.group(1), 16) & 0xff
        c = re.match(r"cmp " + idxpat + r", (0x[0-9a-fA-F]+)$", t)
        if c:
            extent = int(c.group(1), 16) + 1                 # the switch range check bounds the table
        # the three operand-decrypt keys (dst,a,b order): xor REG, IMM8 on any-width register
        x = re.match(r"xor \w+, (0x[0-9a-fA-F]+)$", t)
        if x and int(x.group(1), 16) <= 0xff:
            key_imm.append(int(x.group(1), 16))

    def resolve(byte):
        idx = byte - minv
        if idx < 0:
            return None
        ent = _read_va(img, table_base + idx * 4, 4)
        if len(ent) < 4:
            return None
        h = (table_base + struct.unpack("<i", ent)[0]) & 0xffffffffffffffff
        return h if text_lo <= h < text_hi else None

    if extent is None:                                       # no explicit range check: the table runs
        extent = 0                                           # until an entry points outside .text
        while extent < 160 and resolve(minv + extent) is not None:
            extent += 1
    key = tuple(key_imm[:3]) if len(key_imm) >= 3 else (0, 0, 0)

    import collections
    cnt = collections.Counter(resolve(b) for b in range(minv, minv + extent) if resolve(b))
    if not cnt:
        return None
    default = cnt.most_common(1)[0][0]
    bytemap, pool_va = {}, None
    for byte in range(minv, minv + extent):
        h = resolve(byte)
        if h is None or h == default:
            continue
        base = _classify_handler(img, h, text_lo, text_hi)
        if base is None:
            continue
        bytemap[byte] = base
        if base == 1 and pool_va is None:                   # CONST handler: its rip-lea is the pool
            ho = h - img.text_va
            for ins in img.md.disasm(bytes(img.code[ho:ho + 64]), h):
                lm = re.match(r"lea \w+, \[rip \+ (0x[0-9a-f]+)\]", ins.mnemonic + " " + ins.op_str)
                if lm:
                    pool_va = ins.address + ins.size + int(lm.group(1), 16)
                    break
    return bytemap, key, pool_va


def _decode_map(blob, bytemap, key=(0, 0, 0)):
    """Decode a blob using a recovered byte->base map, decrypting the operand bytes with the
    recovered key (same structural checks as _decode)."""
    kd, ka, kb = key
    if len(blob) < 4 or blob[0] not in bytemap or bytemap[blob[0]] in (0, 35):
        return None
    prog = []
    off = 0
    while off + 4 <= len(blob) and blob[off] in bytemap:
        prog.append((off, blob[off], blob[off + 1] ^ kd, blob[off + 2] ^ ka, blob[off + 3] ^ kb))
        off += 4
    if len(prog) < 6 or bytemap[prog[-1][1]] not in (0, 35):
        return None
    for _, op, dst, a, b in prog:
        base = bytemap[op]
        if base in (28, 29, 30) and ((a | (b << 8)) % 4 or (a | (b << 8)) >= len(prog) * 4):
            return None
    return prog


def _read_va(img, va, n):
    """n bytes of the binary's image at virtual address va (from section contents)."""
    for s in img.binary.sections:
        lo = s.virtual_address
        if lo and lo <= va < lo + s.size:
            data = bytes(s.content)
            off = va - lo
            return data[off:off + n]
    return b""


def _rip_targets(img):
    """Every rip-relative address referenced from code (bytecode / pool / jump-table bases).
    The bytecode blobs are packed contiguously in .rodata, so a blind scan cannot delimit one
    function from the next; the lea targets give each blob's exact start."""
    out = set()
    for fva, size in img.functions():
        off = fva - img.text_va
        for ins in img.md.disasm(bytes(img.code[off:off + size]), fva):
            m = re.search(r"\[rip ([+\-]) (0x[0-9a-fA-F]+)\]", ins.op_str)
            if m:
                disp = int(m.group(2), 16) * (1 if m.group(1) == "+" else -1)
                out.add(ins.address + ins.size + disp)
    return out


def _decode_bounded(blob, limit):
    """Decode a blob but only up to `limit` bytes (the start of the next blob), then run the same
    structural checks. Delimiting each function's bytecode is what lets control-flow targets (which
    are offsets from this blob's start) validate."""
    return _decode(blob[:limit])


def _scan_sections(img):
    """Find each virtualized function's bytecode blob, delimited by the cross-reference anchors."""
    DATA = (".rodata", ".data", ".data.rel.ro", "__const", "__data", "__cstring", ".rdata")
    def in_data(va):
        for s in img.binary.sections:
            if s.virtual_address and s.virtual_address <= va < s.virtual_address + s.size:
                return any(s.name == d or s.name.startswith(d) for d in DATA) and not img._exec_sec(s)
        return False

    anchors = sorted(t for t in _rip_targets(img) if in_data(t))
    regions = []
    for i, va in enumerate(anchors):
        # a small alignment search absorbs an off-by-a-few anchor; the true start decodes, and for
        # a function with constants it begins with CONST
        best = None
        for d in (0, 1, 2, 3, -1, -2, -3):
            start = va + d
            nxt = next((a for a in anchors if a > start), start + 8192)
            prog = _decode_bounded(_read_va(img, start, 8192), nxt - start)
            if not prog:
                continue
            score = (prog[0][1] == 1, len(prog))   # prefer starting on CONST, then longer
            if best is None or score > best[0]:
                best = (score, start, prog)
        if best:
            regions.append((best[1], best[2]))
    # dedupe overlaps, keep the longest
    regions.sort(key=lambda r: (r[0], -len(r[1])))
    kept, end = [], -1
    for va, prog in regions:
        if va >= end:
            kept.append((va, prog))
            end = va + len(prog) * 4
    return kept


def _decode(blob):
    """Decode a byte blob as VM bytecode, greedily, until the first invalid opcode (valid opcodes
    are 0-14, 16-30, so any other byte -- a pointer, pool value, padding -- bounds the blob).
    Returns [(off,op,dst,a,b)] or None if the region doesn't look like real bytecode. Several
    structural checks reject random data that happens to start with low bytes."""
    if len(blob) < 4 or _base(blob[0]) not in OPS or _base(blob[0]) in (0, 35):
        return None                                           # never starts with ret/retv
    prog = []
    off = 0
    while off + 4 <= len(blob) and _base(blob[off]) in OPS:
        prog.append((off, blob[off], blob[off + 1], blob[off + 2], blob[off + 3]))
        off += 4
    if len(prog) < 10 or _base(prog[-1][1]) not in (0, 35):   # too short / doesn't end in ret(v)
        return None
    if sum(1 for (_, op, _, _, _) in prog if _base(op) not in (0, 35)) < 5:
        return None
    # registers are densely numbered 0..nreg; a real stream's indices stay within ~the slot count,
    # whereas random data has sparse huge byte values (r128, r192, ...)
    cap = min(200, 4 * len(prog) + 8)
    for _, op, dst, a, b in prog:
        base = _base(op)
        if base in (1, 28):                                   # const idx / jmp target use a,b as u16
            if base == 1 and (a | (b << 8)) >= 4096:
                return None
            if dst >= cap:
                return None
        elif base in (29, 30):                                # jcc: dst is a reg, a,b a target
            if dst >= cap:
                return None
        else:
            if dst >= cap or a >= cap or b >= cap:
                return None
        if base in (28, 29, 30) and ((a | (b << 8)) % 4 or (a | (b << 8)) >= len(prog) * 4):
            return None
    return prog


# logical base -> C operator (for pseudocode); unsigned ops are tagged
_COPS = {2: "+", 3: "-", 4: "*", 5: "&", 6: "|", 7: "^", 8: "<<", 9: ">>u", 10: ">>",
         11: "/u", 12: "/", 13: "%u", 14: "%",
         16: "==", 17: "!=", 18: "<u", 19: "<=u", 20: ">u", 21: ">=u",
         22: "<", 23: "<=", 24: ">", 25: ">="}


def _fmt_const(v, width):
    v &= (1 << width) - 1
    s = v - (1 << width) if v >> (width - 1) else v          # show small values signed
    return str(s) if -4096 < s < 65536 else hex(v)


def _invert(cond):
    return cond.replace(" != 0", " == 0") if " != 0" in cond else cond.replace(" == 0", " != 0")


def _structure(stmts):
    """Raise an if/goto statement list to structured while/if where the control flow is reducible,
    by two correctness-preserving peepholes (a single back-edge -> do/while; a forward branch over a
    straight block -> if). Anything irreducible (an -O2-unrolled loop nest) is left as if/goto."""
    def targets(ss):
        t = {}
        for s in ss:
            m = re.search(r"goto (L\w+);", s)
            if m:
                t[m.group(1)] = t.get(m.group(1), 0) + 1
        return t

    changed = True
    while changed:
        changed = False
        labels = {s.strip()[:-1]: i for i, s in enumerate(stmts) if re.match(r"^L\w+:$", s.strip())}
        tc = targets(stmts)
        # do/while: a label L at i, a later `if (cond) goto L;` at j referenced only once, with no
        # label inside (i,j) targeted from outside -> do { body } while (cond);
        for lab, i in labels.items():
            js = [k for k, s in enumerate(stmts) if k > i and re.match(rf"\s*if \(.*\) goto {lab};$", s)]
            if len(js) != 1 or tc.get(lab, 0) != 1:
                continue
            j = js[0]
            inner = stmts[i + 1:j]
            if any(re.match(r"^L\w+:$", s.strip()) and tc.get(s.strip()[:-1], 0) for s in inner):
                continue                                     # a nested label targeted elsewhere: skip
            if any("goto" in s for s in inner):
                continue                                     # keep it simple: straight-line body only
            cond = re.search(r"if \((.*)\) goto", stmts[j]).group(1)
            body = ["    " + s.strip() for s in inner]
            stmts = stmts[:i] + ["do {"] + body + [f"}} while ({cond});"] + stmts[j + 1:]
            changed = True
            break
        if changed:
            continue
        # if-then: `if (cond) goto T;` then a straight block then `T:` (T referenced once) ->
        # if (!cond) { block }
        for i, s in enumerate(stmts):
            m = re.match(r"\s*if \((.*)\) goto (L\w+);$", s)
            if not m:
                continue
            cond, tlab = m.group(1), m.group(2)
            ti = labels.get(tlab)
            if ti is None or ti <= i or tc.get(tlab, 0) != 1:
                continue
            block = stmts[i + 1:ti]
            if not block or any("goto" in b or re.match(r"^L\w+:$", b.strip()) or b.startswith("do")
                               or b.startswith("}") for b in block):
                continue
            body = ["    " + b.strip() for b in block]
            stmts = stmts[:i] + [f"if ({_invert(cond)}) {{"] + body + ["}"] + stmts[ti + 1:]
            changed = True
            break
    # drop labels no longer referenced
    tc = targets(stmts)
    return [s for s in stmts if not (re.match(r"^L\w+:$", s.strip()) and not tc.get(s.strip()[:-1]))]


def _pseudocode(prog, bof, pool):
    """Raise the VM-assembly to C-like pseudocode: resolve the constant pool, and -- for a
    straight-line (branchless) function, whose VM registers are each assigned once -- fold every
    temporary into one nested expression, naming the inputs a0, a1, ... A function with control
    flow is emitted as flat statements with labels and if/goto (still correct, less pretty)."""
    has_cf = any(bof(op) in (28, 29, 30) for _, op, _, _, _ in prog)
    expr = {}

    def val(r):
        return expr.get(r, f"a{r}")                          # undefined reg = an input argument

    def cexpr(off, op, dst, a, b):
        base, w = bof(op), _width(op)
        if base == 1:
            return _fmt_const(pool[a | (b << 8)], 64) if pool and (a | (b << 8)) < len(pool) \
                else f"pool[{a | (b << 8)}]"
        if base in _COPS:
            return f"({val(a)} {_COPS[base]} {val(b)})"
        if base == 26:
            return val(a)
        if base == 27:
            return f"({val(a)} ? {val(b)} : {val(dst)})"     # select: cond ? true : prev(false)
        if base == 34:
            return f"sext{w}({val(a)})"
        if base == 32:
            return f"*(i{w}*){val(a)}"
        return None

    if not has_cf:                                           # fold into a single return expression
        ret = None
        for off, op, dst, a, b in prog:
            base = bof(op)
            if base in (0,):
                ret = val(a)
            elif base == 33:                                 # a store in a "branchless" body: keep it
                pass
            else:
                e = cexpr(off, op, dst, a, b)
                if e is not None:
                    expr[dst] = e
        return [f"return {ret};"] if ret is not None else []

    # control flow: flat statements with labels and gotos
    labels = {a | (b << 8) for _, op, _, a, b in prog if bof(op) in (28, 29, 30)}
    out = []
    for off, op, dst, a, b in prog:
        base, w = bof(op), _width(op)
        if off in labels:
            out.append(f"L{off:04x}:")
        pre = "    "
        if base == 0:
            out.append(pre + f"return r{a};")
        elif base == 35:
            out.append(pre + "return;")
        elif base == 1:
            cv = _fmt_const(pool[a | (b << 8)], 64) if pool and (a | (b << 8)) < len(pool) else f"pool[{a|(b<<8)}]"
            out.append(pre + f"r{dst} = {cv};")
        elif base in _COPS:
            out.append(pre + f"r{dst} = r{a} {_COPS[base]} r{b};")
        elif base == 26:
            out.append(pre + f"r{dst} = r{a};")
        elif base == 27:
            out.append(pre + f"r{dst} = r{a} ? r{b} : r{dst};")
        elif base == 34:
            out.append(pre + f"r{dst} = sext{w}(r{a});")
        elif base == 32:
            out.append(pre + f"r{dst} = *(i{w}*)r{a};")
        elif base == 33:
            out.append(pre + f"*(i{w}*)r{a} = r{b};")
        elif base == 28:
            out.append(pre + f"goto L{(a|(b<<8)):04x};")
        elif base in (29, 30):
            cond = f"r{dst} == 0" if base == 29 else f"r{dst} != 0"
            out.append(pre + f"if ({cond}) goto L{(a|(b<<8)):04x};")
    return _structure(out)


def lift_region(bc_va, prog, bytemap=None, pool=None):
    # base opcode: from the recovered per-build map when randomized, else the fixed low 6 bits
    bof = (lambda op: bytemap[op]) if bytemap else _base
    nconst = max((a | (b << 8)) + 1 for (_, op, dst, a, b) in prog if bof(op) == 1) if \
        any(bof(op) == 1 for (_, op, _, _, _) in prog) else 0
    labels = {off for (_, op, _, a, b) in prog if bof(op) in (28, 29, 30)
              for off in [a | (b << 8)]}
    has_mem = any(bof(op) in (32, 33) for (_, op, _, _, _) in prog)
    lines = []
    for off, op, dst, a, b in prog:
        mn, kind = OPS[bof(op)]
        w = _width(op)
        ws = "" if bof(op) in (0, 1, 26, 27, 28, 29, 30, 35) else f".i{w}"
        lbl = f"L{off:04x}" if off in labels else "     "
        tag = f"{mn}{ws}"
        if kind == "ret":
            lines.append((off, lbl, f"ret      r{a}"))
        elif kind == "retv":
            lines.append((off, lbl, "ret      (void)"))
        elif kind == "const":
            lines.append((off, lbl, f"const    r{dst}, pool[{a | (b << 8)}]"))
        elif kind == "bin":
            lines.append((off, lbl, f"{tag:<9} r{dst}, r{a}, r{b}"))
        elif kind == "mov":
            lines.append((off, lbl, f"mov      r{dst}, r{a}"))
        elif kind == "cmov":
            lines.append((off, lbl, f"cmovnz   r{dst}, r{a}, r{b}"))
        elif kind == "sext":
            lines.append((off, lbl, f"{tag:<9} r{dst}, r{a}"))
        elif kind == "load":
            lines.append((off, lbl, f"{tag:<9} r{dst}, [r{a}]"))
        elif kind == "store":
            lines.append((off, lbl, f"{tag:<9} [r{a}], r{b}"))
        elif kind == "jmp":
            lines.append((off, lbl, f"jmp      L{(a | (b << 8)):04x}"))
        elif kind == "jcc":
            lines.append((off, lbl, f"{tag:<9} r{dst}, L{(a | (b << 8)):04x}"))
    return {"bytecode_va": bc_va, "instructions": len(prog), "constants": nconst,
            "has_control_flow": bool(labels), "has_memory": has_mem,
            "listing": lines, "labels": sorted(labels),
            "pseudocode": _pseudocode(prog, bof, pool)}


def _rip_targets_fn(img, fva, size):
    """rip-relative addresses referenced by one function (its bytecode / pool / jump-table bases)."""
    off = fva - img.text_va
    out = []
    for ins in img.md.disasm(bytes(img.code[off:off + size]), fva):
        m = re.search(r"\[rip ([+\-]) (0x[0-9a-fA-F]+)\]", ins.op_str)
        if m:
            disp = int(m.group(2), 16) * (1 if m.group(1) == "+" else -1)
            out.append(ins.address + ins.size + disp)
    return list(dict.fromkeys(out))


def lift(path: Path) -> dict:
    import detect_vm
    from recover_emulate import Image
    img = Image(str(path))
    arch = "arm64" if img.arm else ("x86" if img.x32 else "x86-64")
    det = detect_vm.detect(path)
    if det["count"] == 0 or img.arm or img.x32:
        return {"file": str(path), "arch": arch, "lifted": [], "count": 0}
    text_lo, text_hi = img.text_va, img.text_end
    out, seen = [], set()
    # the detector flags a binary as virtualized; to lift *every* VM function (the randomized
    # dispatch can drop some below the detector's threshold) we try map-recovery on each function --
    # _recover_map returns None for anything without the VM's jump-table dispatch, so ordinary
    # functions are skipped for free.
    for fva, size in img.functions():
        rec = _recover_map(img, fva, size, text_lo, text_hi)
        if not rec:
            continue
        bytemap, key, pool_va = rec
        for t in _rip_targets_fn(img, fva, size):
            # the bytecode cursor is initialised a few bytes into the blob (the fetch reads
            # [cursor-3]), so the true start can be just before the lea target: search both ways
            best = None
            for d in range(-4, 5):
                if (t + d) in seen:
                    continue
                prog = _decode_map(_read_va(img, t + d, 8192), bytemap, key)
                if not prog or len(prog) < 8:
                    continue
                bases = [bytemap[op] for _, op, _, _, _ in prog]
                starts_const = bases[0] == 1
                distinct = len(set(bases))
                # a correct decode begins with the CONST preamble and is not dominated by one op;
                # a misparse (wrong min/table) degenerates into a near-uniform stream
                workers = [b for b in bases if b not in (0, 35)]
                dominated = workers and max(workers.count(x) for x in set(workers)) > 0.7 * len(workers)
                ok = starts_const and distinct >= 4 and not dominated
                score = (ok, distinct, len(prog))
                if ok and (best is None or score > best[0]):
                    best = (score, t + d, prog)
            if best:
                nconst = max((a | (b << 8)) + 1 for _, op, dst, a, b in best[2]
                             if bytemap[op] == 1) if any(bytemap[op] == 1 for _, op, *_ in best[2]) else 0
                pool = None
                if pool_va and nconst:
                    raw = _read_va(img, pool_va, nconst * 8)
                    if len(raw) >= nconst * 8:
                        pool = list(struct.unpack("<%dQ" % nconst, raw[:nconst * 8]))
                out.append(lift_region(best[1], best[2], bytemap, pool))
                seen.add(best[1])
                break
    # also run the fixed-encoding scan (identity-opcode builds); recovery wins on a shared blob
    for va, prog in _scan_sections(img):
        if all(abs(va - r["bytecode_va"]) > 3 for r in out):
            out.append(lift_region(va, prog))
    out.sort(key=lambda r: r["bytecode_va"])
    return {"file": str(path), "arch": arch, "lifted": out, "count": len(out)}


def print_human(r: dict) -> None:
    print(f"VM lift: {Path(r['file']).name}  ({r['arch']})")
    if not r["lifted"]:
        print("  no virtualized function could be lifted")
        return
    for fn in r["lifted"]:
        tags = []
        if fn["has_control_flow"]:
            tags.append("control flow")
        if fn.get("has_memory"):
            tags.append("memory load/store")
        cf = f"  ({', '.join(tags)})" if tags else ""
        print(f"\n  bytecode @ 0x{fn['bytecode_va']:x}  ({fn['instructions']} vm-instructions, "
              f"{fn['constants']} constants){cf}")
        print("  " + "-" * 50)
        for off, lbl, text in fn["listing"]:
            print(f"  {lbl} {off:04x}:  {text}")
        if fn.get("pseudocode"):
            print("  pseudocode:")
            for ln in fn["pseudocode"]:
                print("    " + ln)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("binary")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    path = Path(a.binary)
    if not path.is_file():
        ap.error(f"no such file: {path}")
    r = lift(path)
    if a.json:
        print(json.dumps({k: v for k, v in r.items()}, indent=2, default=list))
    else:
        print_human(r)


if __name__ == "__main__":
    main()
