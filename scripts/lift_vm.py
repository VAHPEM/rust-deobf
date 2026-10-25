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


def lift_region(bc_va, prog):
    nconst = max((a | (b << 8)) + 1 for (_, op, dst, a, b) in prog if _base(op) == 1) if \
        any(_base(op) == 1 for (_, op, _, _, _) in prog) else 0
    labels = {off for (_, op, _, a, b) in prog if _base(op) in (28, 29, 30)
              for off in [a | (b << 8)]}
    has_mem = any(_base(op) in (32, 33) for (_, op, _, _, _) in prog)
    lines = []
    for off, op, dst, a, b in prog:
        mn, kind = OPS[_base(op)]
        w = _width(op)
        ws = "" if _base(op) in (0, 1, 26, 27, 28, 29, 30, 35) else f".i{w}"
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
            "listing": lines, "labels": sorted(labels)}


def lift(path: Path) -> dict:
    import detect_vm
    from recover_emulate import Image
    img = Image(str(path))
    arch = "arm64" if img.arm else ("x86" if img.x32 else "x86-64")
    # only lift where a VM is actually present: the detector gates the decode, so pointing this at
    # an ordinary binary (whose data can contain byte runs that happen to decode) finds nothing
    if detect_vm.detect(path)["count"] == 0:
        return {"file": str(path), "arch": arch, "lifted": [], "count": 0}
    out = [lift_region(va, prog) for va, prog in _scan_sections(img)]
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
