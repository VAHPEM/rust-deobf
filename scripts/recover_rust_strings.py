#!/usr/bin/env python3
"""recover_rust_strings.py - split Rust's concatenated string literals back into &str values.

Rust string literals are not NUL-terminated. The linker packs them back to back in .rodata
(ELF) / .rdata (PE), so a plain `strings` pass sees one long run such as

    permission deniedconnection refusednetwork unreachableconnection aborted...

Every use of a literal carries its exact length, though: a `&str` is a (pointer, length) pair.
This module finds those pairs and cuts the runs at the true boundaries:

  data   - &str fields in constant tables (.data.rel.ro, .rdata, .rodata, panic Location
           structs, ...): an 8-byte pointer into the string section followed by an 8-byte
           length. ELF PIE tables hold zeros until load; the pointer comes from the
           R_*_RELATIVE relocation for that slot.
  code   - x86-64: `lea R,[rip+S]` with the length moved into the next argument register
           (SysV rdi>rsi>rdx>rcx>r8>r9, Win64 rcx>rdx>r8>r9), or both stored to adjacent
           stack slots (`mov [B+k],R` ... `mov qword [B+k+8],N`).
           AArch64: `adrp/add` or `adr` into xN with the length in x(N+1) (`mov`/`orr` wN+1).
           One unconditional jump is followed into shared panic tails. In rustc 1.97 a
           `fmt::Arguments` for a lone literal carries the length as (len << 1) | 1; both
           readings are tried and the one that ends where another literal starts wins.
  table  - `match` arms returning &str compiled to lookup tables: i32 offsets from the table
           (LLVM relative lookup tables) or relocated pointers, next to a u64 length table.
  fmt    - pieces of rustc 1.97's compact format_args! templates (see fmt_pieces).

Only pairs that decode as UTF-8 text are kept. FLOSS's Rust support (floss/language/rust)
splits PE .rdata at cross-reference *starts*; using the length as well also yields the end of
each literal, and the same code handles ELF and AArch64.

Output records: {"string", "address", "offset", "length", "source": data|code|table|fmt} plus
`missed` -- printable text in the string section that no literal explains (FLOSS's
language_strings_missed).

    python recover_rust_strings.py <binary> [-n MIN_LENGTH] [--json]
"""
from __future__ import annotations
import argparse
import json
import re
import struct
import sys
from bisect import bisect_right
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from disasm import Insns, linear  # noqa: E402

MAX_LEN = 4096
TABLE = "table"   # callee marker for lookup-table pairs
SYSV_NEXT = {"rdi": "rsi", "rsi": "rdx", "rdx": "rcx", "rcx": "r8", "r8": "r9"}
WIN64_NEXT = {"rcx": "rdx", "rdx": "r8", "r8": "r9"}
_PRINTABLE = re.compile(rb"[\x20-\x7e]{4,}")


class _Ranges:
    """Sorted, non-overlapping (start, bytes) string sections with containment lookups."""

    def __init__(self, sections):
        self.secs = sorted(sections)
        self.starts = [s for s, _ in self.secs]

    def find(self, va):
        i = bisect_right(self.starts, va) - 1
        if i >= 0:
            start, data = self.secs[i]
            if start <= va < start + len(data):
                return start, data
        return None

    def read(self, va, n):
        hit = self.find(va)
        if hit is None:
            return None
        start, data = hit
        o = va - start
        if o + n > len(data):
            return None
        return data[o:o + n]


def _string_sections(binary):
    fmt = binary.format.name
    pe, macho = fmt == "PE", fmt == "MACHO"
    base = binary.optional_header.imagebase if pe else 0
    out = []
    for s in binary.sections:
        name = s.name
        if pe:
            ok = name == ".rdata"
        elif macho:
            ok = name in ("__cstring", "__const")          # packed &str data + C strings
        else:
            ok = name == ".rodata" or name.startswith(".rodata.")
        if ok:
            out.append((base + s.virtual_address, bytes(s.content)))
    return out, base


def _ptr_width(binary):
    """Pointer size in bytes: 4 for 32-bit (i386 ELF, PE32, 32-bit Mach-O), else 8."""
    try:
        import recover_emulate as E
        return 4 if E._is_32bit(binary) else 8
    except Exception:
        return 8


def _relative_relocs(binary):
    """{slot VA: target VA} for pointers the loader fills in, so an &str field that is stored as 0
    (and relocated) or as an encoded fixup is read as the real target:
      - ELF RELA (x86-64/arm64): R_*_RELATIVE carries the target in the addend; the slot is 0.
      - ELF REL (i386): the target is stored IN PLACE and the addend is 0 -- left out of the map on
        purpose so data_pairs reads it from the section bytes (a 0 addend here used to be recorded
        and then rejected as 'no pointer', dropping every i386 PIE &str).
      - Mach-O chained fixups: the on-disk pointer is an encoded fixup, not the address; LIEF
        resolves each to its target. Classic dyld rebases are correct in place (slide 0) -> no entry.
    """
    out = {}
    try:
        if binary.format.name == "MACHO":
            if getattr(binary, "has_dyld_chained_fixups", False):
                for r in binary.relocations:
                    if type(r).__name__ == "RelocationFixup":
                        out[r.address] = r.target
        else:
            for r in binary.relocations:
                t = str(r.type)
                if "RELATIVE" in t and "IRELATIVE" not in t and r.addend:
                    out[r.address] = r.addend
    except Exception:
        pass
    return out


def _clean(raw: bytes):
    """The literal as text if it is UTF-8 without control characters other than \\t\\n\\r."""
    try:
        s = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if any((ord(c) < 0x20 and c not in "\t\n\r") or ord(c) == 0x7f for c in s):
        return None
    return s


def data_pairs(binary, strs: _Ranges, base: int):
    """(pointer, length) &str fields in the image's constant data."""
    fmt = binary.format.name
    pe, macho = fmt == "PE", fmt == "MACHO"
    # PE has no RELATIVE/chained map here (absolute pointers in place); ELF and Mach-O do
    relocs = {} if pe else _relative_relocs(binary)
    pw = _ptr_width(binary)                 # 4 on i386/PE32, so a (ptr,len) &str field is 8 bytes
    fmtP = "<Q" if pw == 8 else "<I"
    for s in binary.sections:
        name = s.name
        if pe:
            if name not in (".rdata", ".data"):
                continue
        elif macho:
            if name not in ("__const", "__data"):
                continue
        elif not (name.startswith(".data.rel.ro") or name in (".data", ".rodata") or name.startswith(".rodata.")):
            continue
        data = bytes(s.content)
        va0 = base + s.virtual_address
        for o in range(0, len(data) - (2 * pw - 1), pw):
            va = va0 + o
            ptr = relocs.get(va)
            if ptr is None:
                ptr = struct.unpack_from(fmtP, data, o)[0]
            if not ptr or strs.find(ptr) is None:
                continue
            n = struct.unpack_from(fmtP, data, o + pw)[0]
            if 0 < n <= MAX_LEN:
                yield ptr, n, None


def _forward(insns, i, addr_index, budget=10, jump="jmp"):
    """Indices after i in execution order, following one unconditional `jmp` (shared panic
    tails: `lea rdi,[msg]; lea rdx,[loc]; jmp tail` with `tail: mov esi,N; call panic`; on
    AArch64 `adr x0,msg; adr x2,loc; b tail` with `tail: mov w1,#N; bl panic`)."""
    from capstone import CS_OP_IMM
    j, hops = i + 1, 0
    while budget > 0 and j < len(insns):
        ins = insns[j]
        if ins.mnemonic == jump and hops == 0 and ins.operands and ins.operands[0].type == CS_OP_IMM \
                and ins.operands[0].imm in addr_index:
            j, hops = addr_index[ins.operands[0].imm], 1
            continue
        yield j
        j += 1
        budget -= 1


def _x86_callee(insns, i, rip_target):
    """Identity of the first call after index i: its direct target, or the slot it loads."""
    from capstone import CS_OP_IMM, CS_OP_REG
    for j in range(i + 1, min(len(insns), i + 14)):
        pj = insns[j]
        if pj.mnemonic in ("ret", "jmp"):
            return None
        if pj.mnemonic != "call" or not pj.operands:
            continue
        op = pj.operands[0]
        if op.type == CS_OP_IMM:
            return op.imm
        if op.type == CS_OP_REG:            # call rbx: find `mov rbx,[rip+X]` above
            r = op.reg
            for k in range(j - 1, max(-1, j - 40), -1):
                pk = insns[k]
                if pk.mnemonic == "mov" and pk.operands and pk.operands[0].type == CS_OP_REG \
                        and pk.operands[0].reg == r:
                    return rip_target(pk)
            return None
        return rip_target(pj)
    return None


def _x86_pairs(binary, insns, strs: _Ranges, base: int):
    from capstone import CS_OP_IMM, CS_OP_MEM, CS_OP_REG
    from recover_callsite import _canon_reg, rip_target
    nxt = WIN64_NEXT if binary.format.name == "PE" else SYSV_NEXT
    n_ins = len(insns)
    addr_index = insns.index_map()

    def writes(pj, reg):
        try:
            return any(_canon_reg(pj.reg_name(r)) == reg for r in pj.regs_access()[1])
        except Exception:
            return False

    for i, ins in enumerate(insns):
        if ins.mnemonic != "lea" or len(ins.operands) != 2 or ins.operands[0].type != CS_OP_REG:
            continue
        target = rip_target(ins)
        if target is None or strs.find(target) is None:
            continue
        reg = _canon_reg(ins.reg_name(ins.operands[0].reg))
        want = nxt.get(reg)
        length = None
        if want:
            for direction in (_forward(insns, i, addr_index), range(i - 1, max(-1, i - 5), -1)):
                for j in direction:
                    pj = insns[j]
                    if pj.mnemonic in ("call", "ret", "jmp") or pj.mnemonic.startswith("j"):
                        break
                    if not writes(pj, want):
                        continue
                    if pj.mnemonic == "mov" and len(pj.operands) == 2 and pj.operands[1].type == CS_OP_IMM \
                            and 0 < pj.operands[1].imm <= MAX_LEN:
                        length = pj.operands[1].imm
                    elif pj.mnemonic == "pop" and j > 0 and insns[j - 1].mnemonic == "push" \
                            and insns[j - 1].operands and insns[j - 1].operands[0].type == CS_OP_IMM \
                            and 0 < insns[j - 1].operands[0].imm <= MAX_LEN:
                        length = insns[j - 1].operands[0].imm       # push N; pop reg (size-optimised)
                    break
                if length:
                    break
        if length is None:
            # both halves stored to adjacent stack slots: mov [B+k],R ... mov qword [B+k+8],N
            slot = None
            for j in range(i + 1, min(n_ins, i + 6)):
                pj = insns[j]
                if pj.mnemonic == "mov" and len(pj.operands) == 2 and pj.operands[0].type == CS_OP_MEM \
                        and pj.operands[1].type == CS_OP_REG and _canon_reg(pj.reg_name(pj.operands[1].reg)) == reg:
                    slot = (pj.operands[0].mem.base, pj.operands[0].mem.disp)
                    break
            if slot is not None:
                for j in range(max(0, i - 4), min(n_ins, i + 10)):
                    pj = insns[j]
                    if pj.mnemonic == "mov" and len(pj.operands) == 2 and pj.operands[0].type == CS_OP_MEM \
                            and pj.operands[1].type == CS_OP_IMM and 0 < pj.operands[1].imm <= MAX_LEN \
                            and (pj.operands[0].mem.base, pj.operands[0].mem.disp) == (slot[0], slot[1] + 8):
                        length = pj.operands[1].imm
                        break
        if length:
            yield target, length, _x86_callee(insns, i, rip_target)


class _Image:
    """Little-endian reads anywhere in the image, with ELF RELATIVE relocations applied (a PIE's
    pointer tables hold zeros, or the addend, until the loader fills them in)."""

    def __init__(self, binary, base: int):
        self.secs = _Ranges([(base + s.virtual_address, bytes(s.content)) for s in binary.sections
                             if s.virtual_address and s.size])
        self.relocs = {} if binary.format.name == "PE" else _relative_relocs(binary)

    def u64(self, va):
        if va in self.relocs:
            return self.relocs[va]
        raw = self.secs.read(va, 8)
        return None if raw is None else struct.unpack("<Q", raw)[0]

    def uint(self, va, size):
        if size == 8:
            return self.u64(va)
        raw = self.secs.read(va, size)
        return None if raw is None else int.from_bytes(raw, "little")

    def i32(self, va):
        raw = self.secs.read(va, 4)
        return None if raw is None else struct.unpack("<i", raw)[0]


def _table_entries(img: _Image, strs: _Ranges, ptrs: int, lens: int, relative: bool, lw: int):
    """(pointer, length) entries of a `match`-to-&str lookup: a pointer table -- i32 offsets
    from the table itself (LLVM relative lookup tables) or absolute pointers -- next to a
    length table of `lw`-byte integers (LLVM narrows it: u64 in rustc 1.88/1.97, u8 in 1.99).
    The tables have no stored size: stop at the first entry that is not a clean literal or
    that points back into the tables."""
    width = 4 if relative else 8
    for k in range(512):
        v = img.i32(ptrs + 4 * k) if relative else img.u64(ptrs + 8 * k)
        n = img.uint(lens + lw * k, lw)
        if v is None or n is None or not 0 < n <= MAX_LEN:
            return
        ptr = ptrs + v if relative else v
        if (ptr < ptrs + width * (k + 1) and ptr + n > ptrs) or (ptr < lens + lw * (k + 1) and ptr + n > lens):
            return
        text = strs.read(ptr, n)
        if text is None or _clean(text) is None:
            return
        yield ptr, n, TABLE


def _pair_tables(loads, img: _Image, strs: _Ranges):
    """Pair indexed loads that share an index register: a 4-byte sign-extending load (relative
    table) or an 8-byte load whose entries point into the string section (pointer table), with
    a zero-extending load of small integers (lengths) from another table.

        lea L,[rip+lens]; mov len,[L+i*8] / movzx len,byte [i+L]   ldr xN,[xL,xI,lsl #3] / ldrb wN,[xL,xI]
        lea T,[rip+offs]; movsxd p,[T+i*4]                         ldrsw xP,[xT,xI,lsl #2]
        lea T,[rip+ptrs]; mov p,[T+i*8]                            ldr xP,[xT,xI,lsl #3]
    """
    seen = set()
    for a, (pos, table, idx, width, signed) in enumerate(loads):
        if width == 4 and signed:
            relative = True
        elif width == 8 and not signed and (img.u64(table) or 0) and strs.find(img.u64(table)) is not None:
            relative = False
        else:
            continue
        for pos2, lens, idx2, lw, signed2 in loads[max(0, a - 6):a + 7]:
            if idx2 != idx or signed2 or lens == table or abs(pos2 - pos) > 10:
                continue
            first = img.uint(lens, lw)
            if first is None or not 0 < first <= MAX_LEN or (table, lens) in seen:
                continue
            seen.add((table, lens))
            yield from _table_entries(img, strs, table, lens, relative, lw)
            break


def _x86_indexed_loads(insns):
    """(position, table VA, index reg, element size, sign-extending) for `lea R,[rip+T]` followed
    by a load of T[i]: [R + I*size], or [I + R] for byte tables."""
    from capstone import CS_OP_MEM, CS_OP_REG
    from recover_callsite import rip_target
    out = []
    for i, ins in enumerate(insns):
        if ins.mnemonic != "lea" or len(ins.operands) != 2 or ins.operands[0].type != CS_OP_REG:
            continue
        table = rip_target(ins)
        if table is None:
            continue
        reg = ins.operands[0].reg
        for j in range(i + 1, min(len(insns), i + 4)):
            pj = insns[j]
            if pj.mnemonic not in ("mov", "movsxd", "movzx") or len(pj.operands) != 2 \
                    or pj.operands[1].type != CS_OP_MEM:
                continue
            m, size = pj.operands[1].mem, pj.operands[1].size
            if m.disp or size not in (1, 2, 4, 8):
                continue
            if m.base == reg and m.index and m.scale == size:
                idx = m.index
            elif m.index == reg and m.scale == 1 and m.base and size == 1:
                idx = m.base
            else:
                continue
            out.append((i, table, idx, size, pj.mnemonic == "movsxd"))
            break
    return out


def _arm64_indexed_loads(insns):
    from capstone import CS_OP_MEM
    from recover_arm64 import _resolve_pageadd, _rn
    sizes = {"ldrb": 1, "ldrh": 2, "ldrsw": 4}
    out = []
    for i, ins in enumerate(insns):
        m = ins.mnemonic
        if m not in ("ldr", "ldrb", "ldrh", "ldrsw") or len(ins.operands) < 2 or ins.operands[1].type != CS_OP_MEM:
            continue
        op = ins.operands[1]
        if not op.mem.index or op.mem.disp:
            continue
        size = sizes.get(m) or (8 if _rn(ins, ins.operands[0].reg).startswith("x") else 4)
        if (getattr(op.shift, "value", 0) or 0) != size.bit_length() - 1:
            continue
        table = _resolve_pageadd(insns, i - 1, _rn(ins, op.mem.base), back=6)
        if table is not None:
            out.append((i, table, op.mem.index, size, m == "ldrsw"))
    return out


def _arm64_pairs(insns, strs: _Ranges):
    from capstone import CS_OP_IMM, CS_OP_REG
    from recover_arm64 import _resolve_pageadd, _rn
    n_ins = len(insns)
    addr_index = insns.index_map()
    for i, ins in enumerate(insns):
        if ins.mnemonic not in ("add", "adr") or not ins.operands or ins.operands[0].type != CS_OP_REG:
            continue
        reg = _rn(ins, ins.operands[0].reg)
        if not reg.startswith("x") or not reg[1:].isdigit() or int(reg[1:]) > 7:
            continue
        target = _resolve_pageadd(insns, i, reg, back=8)
        if target is None or strs.find(target) is None:
            continue
        want = {"x" + str(int(reg[1:]) + 1), "w" + str(int(reg[1:]) + 1)}
        length = None
        for direction in (_forward(insns, i, addr_index, budget=6, jump="b"), range(i - 1, max(-1, i - 5), -1)):
            for j in direction:
                pj = insns[j]
                if pj.mnemonic in ("bl", "blr", "ret", "b", "br") or pj.mnemonic.startswith("b.") \
                        or pj.mnemonic in ("cbz", "cbnz", "tbz", "tbnz"):
                    break
                if not pj.operands or pj.operands[0].type != CS_OP_REG or _rn(pj, pj.operands[0].reg) not in want:
                    continue
                if pj.mnemonic in ("mov", "movz", "orr"):
                    imm = next((o.imm for o in pj.operands[1:] if o.type == CS_OP_IMM), None)
                    if imm is not None and 0 < imm <= MAX_LEN:
                        length = imm
                break
            if length:
                break
        if length:
            callee = None
            for j in range(i + 1, min(n_ins, i + 12)):
                if insns[j].mnemonic == "bl":
                    callee = next((o.imm for o in insns[j].operands if o.type == CS_OP_IMM), None)
                    break
                if insns[j].mnemonic in ("ret", "b", "br", "blr"):
                    break
            yield target, length, callee


def code_pairs(binary, strs: _Ranges, base: int):
    from capstone import (Cs, CS_ARCH_ARM64, CS_ARCH_X86, CS_MODE_64, CS_MODE_32,
                          CS_MODE_LITTLE_ENDIAN)
    mach = ""
    for attr in ("machine_type", "cpu_type", "machine"):   # ELF/PE: machine_type; Mach-O: cpu_type
        if hasattr(binary.header, attr):
            v = getattr(binary.header, attr)
            mach = (v.name if hasattr(v, "name") else str(v)).upper()
            break
    arm = "AARCH64" in mach or "ARM64" in mach
    x32 = (not arm) and ("I386" in mach or "80386" in mach or ("X86" in mach and "64" not in mach))
    if arm:
        md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    else:
        md = Cs(CS_ARCH_X86, CS_MODE_32 if x32 else CS_MODE_64)
    md.detail = True
    img = _Image(binary, base)
    text_name = "__text" if binary.format.name == "MACHO" else ".text"
    for s in binary.sections:
        if s.name != text_name:
            continue
        insns = Insns(md, bytes(s.content), base + s.virtual_address)
        if arm:
            yield from _arm64_pairs(insns, strs)
            yield from _pair_tables(_arm64_indexed_loads(insns), img, strs)
        else:
            yield from _x86_pairs(binary, insns, strs, base)
            yield from _pair_tables(_x86_indexed_loads(insns), img, strs)


def _offset_mapper(binary, base):
    """VA -> file offset (the offsets FLOSS documents use for static and language strings)."""
    secs = [(base + s.virtual_address, s.size, s.offset) for s in binary.sections if s.size]

    def to_off(va):
        for start, size, off in secs:
            if start <= va < start + size:
                return off + (va - start)
        return 0
    return to_off


def fmt_pieces(secs, taken):
    """Literal pieces of format_args! templates in the compact encoding of recent rustc.

    The template is a byte string: a byte below 0x80 is the length of the literal piece that
    follows, 0xC0 is a plain `{}` argument, 0x00 ends the template; other bytes >= 0x80 are
    arguments with format specs (their operands are not decoded -- parsing stops there).
        b"\x15memory allocation of \xc0\x0e bytes failed\n\x00"
    A plain strings pass shows these pieces with the length byte glued on when it happens to
    be printable ("& is not a char boundary", 0x26 = 38). Templates are accepted only with at
    least one argument (a template without one is emitted as a plain &str instead) and only
    when every piece is clean text and no piece overlaps a literal found through a reference.
    """
    out = []
    for start, d in secs:
        i, n = 0, len(d)
        while i < n:
            pos, pieces, saw_arg, ok = i, [], False, False
            while pos < n:
                c = d[pos]
                if c == 0x00:
                    ok = saw_arg and bool(pieces) and pos > i
                    break
                if c == 0xC0:
                    saw_arg = True
                    pos += 1
                    continue
                if c >= 0x80:
                    ok = saw_arg and bool(pieces)
                    break
                text = _clean(d[pos + 1:pos + 1 + c]) if pos + 1 + c <= n else None
                if text is None or not (pos + 1 + c < n and (d[pos + 1 + c] in (0x00,) or d[pos + 1 + c] >= 0x80)):
                    break
                pieces.append((start + pos + 1, c, text))
                pos += 1 + c
            if ok and not any(taken(a, a + c) for a, c, _ in pieces):
                out.extend(pieces)
                i = pos + 1
            else:
                i += 1
    return out


def recover(path, min_len: int = 4) -> dict:
    import lief
    binary = lief.parse(str(path))
    result = {"strings": [], "missed": [], "pairs": 0}
    if binary is None:
        return result
    secs, base = _string_sections(binary)
    if not secs:
        return result
    strs = _Ranges(secs)

    # every (pointer, length) use, by pointer
    uses = {}                                   # address -> {length: [votes, source]}
    ambiguous = []                              # (ptr, raw odd length, callee)
    callee_raw, callee_tagged = {}, {}
    for origin, pairs in (("data", data_pairs(binary, strs, base)), ("code", code_pairs(binary, strs, base))):
        for ptr, n, callee in pairs:
            source = origin
            if callee == TABLE:
                source, callee = TABLE, None
            cands = [n]
            if source == "code" and n & 1 and n > 1:
                # fmt::Arguments for a lone literal (println!("text"), panic!("text")) carries
                # its length tagged as (len << 1) | 1 in recent rustc (seen in 1.97); a plain
                # odd length looks the same, so both are candidates
                cands.append(n >> 1)
            ok = [m for m in cands if strs.read(ptr, m) is not None and _clean(strs.read(ptr, m)) is not None]
            if not ok:
                continue
            result["pairs"] += 1
            for m in ok:
                v = uses.setdefault(ptr, {}).setdefault(m, [0, source])
                v[0] += 1
                if source == "data":
                    v[1] = "data"
            if source == "code":
                if len(ok) == 2:
                    ambiguous.append((ptr, n, callee))
                elif callee is not None and not n & 1:
                    callee_raw[callee] = callee_raw.get(callee, 0) + 1

    starts = sorted(uses)

    def fit(ptr, m):
        """+1 when the literal ends where another one starts or at a non-text byte,
        -1 for every other literal's start that it would swallow."""
        end = ptr + m
        inner = bisect_right(starts, end - 1) - bisect_right(starts, ptr)
        nxt = strs.read(end, 1)
        edge = end in uses or nxt is None or not (0x20 <= nxt[0] < 0x7f)
        return int(edge) - inner

    # ambiguous odd lengths: decide the clear cases by fit, learn which callees take tagged
    # lengths from them, then settle the ties by the callee's habit
    decided = {}
    for ptr, n, callee in ambiguous:
        raw, tag = fit(ptr, n), fit(ptr, n >> 1)
        if raw != tag:
            decided[(ptr, n)] = n if raw > tag else n >> 1
            if callee is not None:
                d = callee_tagged if tag > raw else callee_raw
                d[callee] = d.get(callee, 0) + 1
    for ptr, n, callee in ambiguous:
        if (ptr, n) not in decided:
            tagged = callee is not None and callee_tagged.get(callee, 0) > callee_raw.get(callee, 0)
            decided[(ptr, n)] = n >> 1 if tagged else n
        drop = n if decided[(ptr, n)] != n else n >> 1
        v = uses[ptr].get(drop)
        if v:
            v[0] -= 1
            if v[0] <= 0 and v[1] == "code":
                del uses[ptr][drop]

    found = {}
    for ptr, lens in uses.items():
        if not lens:
            continue
        m = max(lens, key=lambda k: (fit(ptr, k), lens[k][1] == "data", lens[k][0]))
        found[ptr] = (m, lens[m][1])

    records = []
    for ptr in sorted(found):
        n, source = found[ptr]
        text = _clean(strs.read(ptr, n))
        if len(text.strip()) >= min_len:
            records.append({"string": text, "address": ptr, "length": n, "source": source})
    lits = sorted((r["address"], r["address"] + r["length"]) for r in records)
    lstarts = [a for a, _ in lits]

    def taken(a, b):
        k = bisect_right(lstarts, b - 1) - 1
        return k >= 0 and lits[k][1] > a

    for a, c, text in fmt_pieces(secs, taken):
        if len(text.strip()) >= min_len:
            records.append({"string": text, "address": a, "length": c, "source": "fmt"})
    records.sort(key=lambda r: r["address"])
    result["strings"] = records
    to_off = _offset_mapper(binary, base)
    for r in records:
        r["offset"] = to_off(r["address"])

    # what a plain strings pass shows that no literal explains: printable runs minus every
    # recovered literal (FLOSS's language_strings_missed)
    covered = sorted((r["address"], r["address"] + r["length"]) for r in records)
    for start, data in secs:
        for m in _PRINTABLE.finditer(data):
            a, b = start + m.start(), start + m.end()
            k = max(0, bisect_right(covered, (a, a)) - 1)
            cur = a
            while cur < b:
                while k < len(covered) and covered[k][1] <= cur:
                    k += 1
                nxt = covered[k][0] if k < len(covered) else b
                if nxt > cur:
                    seg_end = min(nxt, b)
                    seg = data[cur - start:seg_end - start].decode("ascii")
                    if len(seg.strip()) >= min_len:
                        result["missed"].append({"string": seg, "address": cur, "offset": to_off(cur)})
                    cur = seg_end
                else:
                    cur = max(cur, covered[k][1])
    return result


def _selftest():
    # format_args! template pieces, with a length byte that is printable ('&' = 38)
    piece = b" is not a char boundary; it is inside "
    blob = (b"junk" + b"\x11start byte index \xc0" + bytes([len(piece)]) + piece + b"\xc0\x00"
            + b"\x05plain\x00")                   # no argument: not a template
    got = [(t, c) for _, c, t in fmt_pieces([(0x1000, blob)], lambda a, b: False)]
    assert got == [("start byte index ", 17), (piece.decode(), len(piece))], got

    # relative lookup table: i32 offsets from the table, u64 lengths
    words = [b"permission denied", b"connection refused"]
    text = b"".join(words)
    table_at, lens_at = 0x40, 0x60
    img = bytearray(0x80)
    img[0:len(text)] = text
    struct.pack_into("<ii", img, table_at, 0 - table_at, len(words[0]) - table_at)
    struct.pack_into("<QQ", img, lens_at, len(words[0]), len(words[1]))
    struct.pack_into("<i", img, table_at + 8, 0x7fffffff)          # end of table
    strs = _Ranges([(0x2000, bytes(img))])

    class _Img(_Image):
        def __init__(self):
            self.secs, self.relocs = strs, {}
    got = [strs.read(p, n) for p, n, _ in _table_entries(_Img(), strs, 0x2000 + table_at, 0x2000 + lens_at, True, 8)]
    assert got == words, got

    assert _clean(b"ok\ttext\n") == "ok\ttext\n" and _clean(b"bad\x01") is None and _clean(b"\xff") is None
    print("selftest OK: fmt template pieces, relative lookup tables, literal text check")


def main(argv=None):
    if argv is None and "--selftest" in sys.argv:
        _selftest()
        return
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("binary")
    ap.add_argument("-n", "--min-length", type=int, default=4)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--missed", action="store_true", help="also print runs no &str explains")
    args = ap.parse_args(argv)
    r = recover(args.binary, args.min_length)
    if args.json:
        print(json.dumps(r, indent=2))
        return
    for x in r["strings"]:
        print(f"0x{x['address']:x}  {x['source']:<4}  {x['string']!r}")
    if args.missed:
        for x in r["missed"]:
            print(f"0x{x['address']:x}  miss  {x['string']!r}")
    print(f"\n{len(r['strings'])} literals from {r['pairs']} &str references; "
          f"{len(r['missed'])} printable runs unexplained", file=sys.stderr)


if __name__ == "__main__":
    main()
