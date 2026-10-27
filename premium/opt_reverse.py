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
reads. x86-64 and 32-bit x86 (the LLVM `lea table; movsxd [table+idx*4]; add; jmp` rel32 idiom) and
AArch64 (`adr table; adr anchor; ldrsw [table+idx*4]; add; br`).

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
          "sil": "rsi", "dl": "rdx", "cl": "rcx", "bl": "rbx", "bpl": "rbp", "spl": "rsp"}


def _canon(name: str) -> str:
    """The 64-bit register a sub-register belongs to (edi/di/dil -> rdi, r8d/r8w/r8b -> r8)."""
    if name in _CANON:
        return _CANON[name]
    if name.startswith("r") and name[-1] in "dwb" and name[1:-1].isdigit():
        return name[:-1]
    return name


def _md(arch: str):
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
    md = Cs(CS_ARCH_X86, CS_MODE_32 if arch == "x86" else CS_MODE_64)
    md.detail = True
    return md


def recover_jump_tables(code: bytes, base: int, arch: str, read_i32, text_lo: int, text_hi: int):
    """Scan x86 `code` (loaded at VA `base`) for the rel32 jump-table idiom and recover each switch.

    read_i32(va) -> signed 32-bit table entry at `va` (from the data section holding the table), or
    None if unmapped. Returns [{jmp_va, table_va, index_reg, count, default, cases:{i:target}}]."""
    from capstone.x86 import X86_OP_REG, X86_OP_MEM, X86_OP_IMM
    md = _md(arch)

    def same_reg(a, b):              # cmp edi bounds an index rdi: compare 64-bit canonical names
        return _canon(md.reg_name(a)) == _canon(md.reg_name(b))
    insns = list(md.disasm(code, base))
    out = []
    for i, jmp in enumerate(insns):
        if jmp.mnemonic != "jmp" or not jmp.operands or jmp.operands[0].type != X86_OP_REG:
            continue
        tgt_reg = jmp.operands[0].reg
        # look back a few instructions for: add tgt, B ; movsxd/mov tgt, [B + idx*4] ; lea B,[rip+d]
        window = insns[max(0, i - 5):i]
        add_i = movsxd_i = lea_i = None
        base_reg = index_reg = None
        for w in reversed(window):
            if add_i is None and w.mnemonic == "add" and len(w.operands) == 2 \
                    and w.operands[0].type == X86_OP_REG and w.operands[0].reg == tgt_reg \
                    and w.operands[1].type == X86_OP_REG:
                add_i, base_reg = w, w.operands[1].reg
            elif add_i is not None and movsxd_i is None and w.mnemonic in ("movsxd", "mov") \
                    and len(w.operands) == 2 and w.operands[0].type == X86_OP_REG \
                    and w.operands[0].reg == tgt_reg and w.operands[1].type == X86_OP_MEM:
                mem = w.operands[1].mem
                if mem.base == base_reg and mem.scale == 4 and mem.index != 0:
                    movsxd_i, index_reg = w, mem.index
            elif movsxd_i is not None and lea_i is None and w.mnemonic == "lea" \
                    and len(w.operands) == 2 and w.operands[0].type == X86_OP_REG \
                    and w.operands[0].reg == base_reg and w.operands[1].type == X86_OP_MEM:
                mem = w.operands[1].mem
                from capstone.x86 import X86_REG_RIP, X86_REG_EIP
                if mem.base in (X86_REG_RIP, X86_REG_EIP) and mem.index == 0:
                    lea_i = w
                    table_va = w.address + w.size + mem.disp   # rip-relative: from the NEXT insn
                    break
        if lea_i is None or movsxd_i is None or add_i is None:
            continue
        # bound: a preceding `cmp index_reg, K` gives count K+1. We REQUIRE this bound -- without it
        # the table length is unknown and reading "until an entry leaves .text" over-reads into
        # adjacent data that coincidentally points into code (observed: 700-case phantom tables), so
        # a bounded, exact recovery is preferred over a guessed one (precision over recall).
        count = None
        for w in reversed(insns[max(0, i - 12):i]):
            if w.mnemonic in ("cmp", "sub") and len(w.operands) == 2 \
                    and w.operands[0].type == X86_OP_REG and same_reg(w.operands[0].reg, index_reg) \
                    and w.operands[1].type == X86_OP_IMM:
                count = w.operands[1].imm + 1
                break
        if count is None or not (0 < count <= _MAX_CASES):
            continue
        cases = {}
        for k in range(count):
            entry = read_i32(table_va + 4 * k)
            if entry is None:
                break
            target = (table_va + entry) & ((1 << (64 if arch != "x86" else 32)) - 1)
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


def recover_jump_tables_arm64(code, base, read_i32, text_lo, text_hi):
    """AArch64 rel32 jump tables. LLVM lowers a dense `match`/`switch` to:
        cmp  idx, #K ; b.hi default
        adr  Xtbl, <table>            ; table base (an array of rel32 offsets)
        adr  Xanchor, <anchor>        ; the base the offsets are added to
        ldrsw Xt, [Xtbl, idx, lsl #2]
        add  Xdst, Xanchor, Xt        ; target = anchor + table[idx]
        br   Xdst
    recovered to {index: target}. capstone resolves each `adr` immediate to an absolute address."""
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    insns = list(md.disasm(code, base))
    out = []
    for i, br in enumerate(insns):
        if br.mnemonic != "br":
            continue
        dst = br.op_str.strip()
        win = insns[max(0, i - 10):i]
        regs = {}                       # reg -> adr-resolved absolute address seen in the window
        for w in win:
            if w.mnemonic == "adr":
                m = _A64_IMM.match(w.op_str)
                if m:
                    regs[m.group(1)] = int(m.group(2), 0)
        add_a = add_t = tbl_reg = idx_reg = None
        for w in reversed(win):
            if add_a is None and w.mnemonic == "add":
                m = _A64_ADD.match(w.op_str)
                if m and m.group(1) == dst:
                    add_a, add_t = m.group(2), m.group(3)
            elif add_t is not None and tbl_reg is None and w.mnemonic in ("ldrsw", "ldr"):
                m = _A64_LDRSW.match(w.op_str)
                if m and m.group(1) == add_t:
                    tbl_reg, idx_reg = m.group(2), m.group(3)
        if tbl_reg is None or add_a is None:
            continue
        table_va, anchor = regs.get(tbl_reg), regs.get(add_a)
        if table_va is None or anchor is None:
            continue
        count = None
        for w in reversed(win):
            if w.mnemonic in ("cmp", "subs") and idx_reg:
                m = _A64_IMM.match(w.op_str)
                if m and m.group(1) == idx_reg:
                    count = int(m.group(2), 0) + 1
                    break
        if count is None or not (0 < count <= _MAX_CASES):
            continue
        cases = {}
        for k in range(count):
            entry = read_i32(table_va + 4 * k)
            if entry is None:
                break
            target = (anchor + entry) & ((1 << 64) - 1)
            if not (text_lo <= target < text_hi):
                break
            cases[k] = target
        if len(cases) == count:
            out.append({"br_va": br.address, "table_va": table_va, "anchor": anchor,
                        "index_reg": idx_reg, "count": count, "default": None, "cases": cases})
    return out


def detect_unrolled_loops(code: bytes, base: int, arch: str, min_repeat: int = 3):
    """Find runs of >= min_repeat consecutive instruction blocks with an identical instruction-
    mnemonic shape and a constant byte stride: the fingerprint of an `-O2`-unrolled loop body. Returns
    [{start_va, stride, count, span}] -- the fact a re-roller needs to collapse the copies to a loop.

    Shape-only (mnemonic sequence + stride), so it is not fooled by the immediates/offsets the copies
    differ in; it does not itself re-roll (lifting the copies back to one loop body is the next tier)."""
    md = _md(arch)
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
            if reps >= min_repeat and (best is None or reps * blen > best[2] * best[1]):
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

    if img.arm:
        jts = recover_jump_tables_arm64(img.code, img.text_va, read_i32, img.text_va, img.text_end)
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

    print("selftest OK: rel32 jump-table recovery (3-case switch -> {index: target}), rejects a "
          "plain stream, unrolled-loop detection (4x body), and AArch64 idiom operand parsing")


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
        print(f"  jmp 0x{jt['jmp_va']:x}  table 0x{jt['table_va']:x}  {jt['count']} cases: {tgts}{more}")
    if a.loops:
        for lp in res["unrolled_loops"]:
            print(f"  unrolled loop 0x{lp['start_va']:x}  {lp['count']}x body of {lp['block_insns']} "
                  f"insn(s), stride {lp['stride']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
