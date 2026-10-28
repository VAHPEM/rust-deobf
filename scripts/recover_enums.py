#!/usr/bin/env python3
"""recover_enums.py - recover Rust enum discriminant/niche layout, with variant names when the
binary carries debug info.

Two paths, by what the binary actually offers:

* With DWARF (debuginfo builds): parse each Rust enum's `DW_TAG_variant_part` -> the enum name, the
  discriminant field (offset + size) or a niche encoding, and every variant {name, tag value,
  payload offset}. This is the precise, named recovery -- exactly what a decompiler wants for enum
  data, and it needs debug info, which a stripped binary does not have (hence limited value on real
  stripped malware; honest about that).
* Stripped (no DWARF): a capstone heuristic flags discriminant-dispatch sites in .text -- a small
  integer loaded from a fixed field offset of an object pointer (not a RIP-relative global or a
  stack slot) and matched against >=2 constants before anything else writes that register -- i.e.
  the *layout* (which offset is the tag, which values it takes) without names. The sweep resyncs
  past undecodable bytes. A DWARF parse failure is reported (`dwarf_error`) and falls back to it.

pyelftools is an optional dependency (the DWARF path); the heuristic path needs only capstone. ELF
only for now. Defensive; benign inputs.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))


# ----------------------------------------------------------------------------- DWARF (named) path
def _name(die):
    a = die.attributes.get("DW_AT_name")
    return a.value.decode("utf-8", "replace") if a else None


def _const(die, attr, default=None):
    a = die.attributes.get(attr)
    return a.value if a is not None else default


def _iter_dies(die):
    """Pre-order walk of a DIE tree, iteratively: a deeply nested (or crafted) .debug_info must not
    hit Python's recursion limit."""
    stack = [die]
    while stack:
        d = stack.pop()
        yield d
        kids = list(d.iter_children())
        kids.reverse()
        stack.extend(kids)


def _parse_dwarf_enums(elffile):
    if not elffile.has_dwarf_info():
        return []
    dw = elffile.get_dwarf_info()
    enums = []
    for cu in dw.iter_CUs():
        offmap = {d.offset: d for d in _iter_dies(cu.get_top_DIE())}

        def type_size(member):
            ref = member.attributes.get("DW_AT_type")
            if ref is None:
                return None
            t = offmap.get(cu.cu_offset + ref.value)
            return _const(t, "DW_AT_byte_size") if t else None

        for die in offmap.values():
            if die.tag != "DW_TAG_structure_type":
                continue
            vp = next((c for c in die.iter_children() if c.tag == "DW_TAG_variant_part"), None)
            if vp is None:
                continue
            # the discriminant field is the unnamed member of the variant_part (absent => pure niche)
            disc = next((c for c in vp.iter_children()
                         if c.tag == "DW_TAG_member" and _name(c) is None), None)
            discriminant = None
            if disc is not None:
                discriminant = {"offset": _const(disc, "DW_AT_data_member_location", 0),
                                "size": type_size(disc)}
            variants = []
            for v in vp.iter_children():
                if v.tag != "DW_TAG_variant":
                    continue
                mem = next((c for c in v.iter_children() if c.tag == "DW_TAG_member"), None)
                variants.append({
                    "name": _name(mem) if mem is not None else None,
                    "value": _const(v, "DW_AT_discr_value"),   # None => the niche/"otherwise" variant
                    "payload_offset": _const(mem, "DW_AT_data_member_location", 0) if mem else None,
                })
            # niche encoding: no explicit tag field, or exactly one variant is the default (value None)
            niche = discriminant is None or any(x["value"] is None for x in variants)
            enums.append({"name": _name(die), "byte_size": _const(die, "DW_AT_byte_size"),
                          "discriminant": discriminant, "niche": niche, "variants": variants})
    return enums


# ----------------------------------------------------------------- stripped heuristic (no names)
# A tag load is `reg <- [base + small disp]` with base an object pointer. RIP-relative globals and
# stack-frame reloads (rsp/rbp; sp/x29) are not enum fields, so those bases are skipped. A tracked
# register is dropped as soon as anything else writes it (or control leaves: call/ret/jmp), and a
# finished site is kept if it reached >= 2 distinct compare values. Disassembly runs with capstone
# SKIPDATA so one undecodable byte (anti-disassembly junk, data in .text) does not end the sweep.
_X86_FAMILY = {}
for _fam, _names in {
        "rax": "al ah ax eax rax", "rbx": "bl bh bx ebx rbx", "rcx": "cl ch cx ecx rcx",
        "rdx": "dl dh dx edx rdx", "rsi": "sil si esi rsi", "rdi": "dil di edi rdi",
        "rbp": "bpl bp ebp rbp", "rsp": "spl sp esp rsp"}.items():
    for _n in _names.split():
        _X86_FAMILY[_n] = _fam
for _i in range(8, 16):
    for _suf in ("b", "w", "d", ""):
        _X86_FAMILY[f"r{_i}{_suf}"] = f"r{_i}"


_X86_LOADS = frozenset(("mov", "movzx", "movsx", "movsxd"))
_A64_LOADS = frozenset(("ldrb", "ldrh", "ldr", "ldrsb", "ldrsh", "ldrsw"))


def _fam_x86(md, reg):
    n = md.reg_name(reg)
    return _X86_FAMILY.get(n, n)


def _fam_arm64(md, reg):
    n = md.reg_name(reg)
    if len(n) > 1 and n[0] in "wx" and n[1:].isdigit():
        return "x" + n[1:]
    return n


def _sweep(md, code, base, on_insn):
    """Linear sweep that survives undecodable bytes (SKIPDATA emits a pseudo-insn -- 1 byte on x86,
    4 on AArch64 -- and continues); `on_insn(insn)` gets every real instruction, `on_insn(None)` a
    skipped chunk."""
    md.skipdata = True
    md.skipdata_setup = (".byte", None, None)
    for insn in md.disasm(code, base):
        on_insn(None if insn.id == 0 else insn)


class _Tracker:
    """Per-register tag-load sites; finished ones with >= 2 compare values go to `out`."""

    def __init__(self, limit):
        self.live, self.out, self.limit = {}, [], limit

    def finish(self, fam):
        st = self.live.pop(fam, None)
        if st and len(st["values"]) >= 2 and len(self.out) < self.limit:
            self.out.append({"site": st["site"], "field_offset": st["disp"],
                             "values": sorted(st["values"])})

    def clear(self):
        for fam in list(self.live):
            self.finish(fam)


def _dispatch_sites(code: bytes, base: int, limit=256):
    """Discriminant-dispatch sites: a small int loaded from [reg+disp] (reg an object pointer, not
    rip/rsp/rbp) then matched against >=2 distinct constants with no write to the register in
    between. Returns [{site, field_offset, values}]. Heuristic, x86-64."""
    from capstone import CS_ARCH_X86, CS_MODE_64, Cs
    from capstone import x86 as X
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    bad_base = {X.X86_REG_RIP, X.X86_REG_RSP, X.X86_REG_RBP, X.X86_REG_ESP, X.X86_REG_EBP}
    tr = _Tracker(limit)

    def on(insn):
        if insn is None:
            tr.clear()
            return
        m = insn.mnemonic
        ops = insn.operands if (m in _X86_LOADS or (m == "cmp" and tr.live)) else ()
        if m in _X86_LOADS and len(ops) == 2 and \
                ops[0].type == X.X86_OP_REG and ops[1].type == X.X86_OP_MEM and \
                ops[1].mem.base != 0 and ops[1].mem.base not in bad_base and \
                ops[1].mem.index == 0 and ops[1].mem.segment == 0 and 0 <= ops[1].mem.disp < 0x1000:
            fam = _fam_x86(md, ops[0].reg)
            tr.finish(fam)
            tr.live[fam] = {"site": insn.address, "disp": ops[1].mem.disp, "values": set()}
            return
        if not tr.live:
            return
        if m == "cmp" and len(ops) == 2 and ops[0].type == X.X86_OP_REG and ops[1].type == X.X86_OP_IMM:
            fam = _fam_x86(md, ops[0].reg)
            if fam in tr.live and 0 <= ops[1].imm < 0x10000:
                tr.live[fam]["values"].add(ops[1].imm)
            return
        if m in ("call", "ret", "jmp", "retf", "iret", "iretq", "syscall", "int3", "ud2", "hlt"):
            tr.clear()
            return
        try:
            _r, written = insn.regs_access()
        except Exception:
            tr.clear()
            return
        for reg in written:
            fam = _fam_x86(md, reg)
            if fam in tr.live:
                tr.finish(fam)

    _sweep(md, code, base, on)
    tr.clear()
    return tr.out


def _dispatch_sites_arm64(code: bytes, base: int, limit=256):
    """AArch64 analog: a small int loaded with ldrb/ldrh/ldr from [reg+disp] (reg not sp/x29) then
    matched against >=2 cmp immediates with no write to the register in between. Heuristic."""
    from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs
    from capstone import arm64 as A
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    bad_base = {A.ARM64_REG_SP, A.ARM64_REG_WSP, A.ARM64_REG_X29}
    tr = _Tracker(limit)

    def on(insn):
        if insn is None:
            tr.clear()
            return
        m = insn.mnemonic
        ops = insn.operands if (m in _A64_LOADS or (m == "cmp" and tr.live)) else ()
        if m in _A64_LOADS and len(ops) == 2 and \
                ops[0].type == A.ARM64_OP_REG and ops[1].type == A.ARM64_OP_MEM and \
                ops[1].mem.base not in bad_base and ops[1].mem.index == 0 and \
                0 <= ops[1].mem.disp < 0x1000 and not insn.writeback:
            fam = _fam_arm64(md, ops[0].reg)
            tr.finish(fam)
            tr.live[fam] = {"site": insn.address, "disp": ops[1].mem.disp, "values": set()}
            return
        if not tr.live:
            return
        if m == "cmp" and len(ops) == 2 and ops[0].type == A.ARM64_OP_REG and ops[1].type == A.ARM64_OP_IMM:
            fam = _fam_arm64(md, ops[0].reg)
            if fam in tr.live and 0 <= ops[1].imm < 0x10000:
                tr.live[fam]["values"].add(ops[1].imm)
            return
        if m in ("bl", "blr", "br", "b", "ret", "braa", "brab", "blraa", "blrab", "retaa", "retab",
                 "svc", "brk", "hlt"):
            tr.clear()
            return
        try:
            _r, written = insn.regs_access()
        except Exception:
            tr.clear()
            return
        for reg in written:
            fam = _fam_arm64(md, reg)
            if fam in tr.live:
                tr.finish(fam)

    _sweep(md, code, base, on)
    tr.clear()
    return tr.out


def _text_lief(path):
    """(.text bytes, address) via lief -- the fallback when pyelftools is absent or fails."""
    try:
        import lief
        b = lief.parse(str(path))
        sec = next((x for x in b.sections if x.name == ".text"), None) if b is not None else None
        if sec is not None:
            return bytes(sec.content), sec.virtual_address
    except Exception:
        pass
    return None


def recover(path) -> dict:
    """Recover enum layout for the ELF at `path`. DWARF when present (named), else a heuristic.

    Returns {has_dwarf, enums:[{name,byte_size,discriminant,niche,variants}],
    discriminant_sites:[{site,field_offset,values}], counts}.
    """
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError:
        ELFFile = None
    data = Path(path).read_bytes()
    dwarf_error = None
    if data[:4] != b"\x7fELF":
        return {"error": "not an ELF; recover_enums is ELF-only", "has_dwarf": False,
                "enums": [], "discriminant_sites": [], "counts": {}}
    enums, has_dwarf = [], False
    text = None
    # .text first, on its own: a DWARF parse failure (malformed .debug_info, a deep DIE tree) must
    # not also disable the stripped heuristic
    if ELFFile is not None:
        try:
            with open(path, "rb") as fh:
                ef = ELFFile(fh)
                sec = ef.get_section_by_name(".text")
                if sec is not None:
                    text = (sec.data(), sec["sh_addr"])
                try:
                    has_dwarf = ef.has_dwarf_info() and ef.get_section_by_name(".debug_info") is not None
                    if has_dwarf:
                        enums = _parse_dwarf_enums(ef)
                except Exception as e:          # incl. RecursionError, pyelftools parse errors
                    dwarf_error = f"{type(e).__name__}: {e}"[:200]
        except Exception:
            pass
    if text is None:
        text = _text_lief(path)
    machine = int.from_bytes(data[18:20], "little")   # e_machine: 0x3e x86-64, 0xb7 AArch64
    sites = []
    if not enums and text is not None:        # only bother with the heuristic when DWARF gave nothing
        try:
            if machine == 0xb7:
                sites = _dispatch_sites_arm64(text[0], text[1])
            elif machine == 0x3e:
                sites = _dispatch_sites(text[0], text[1])
        except Exception:
            sites = []
    named = sum(1 for e in enums for v in e["variants"] if v["name"])
    res = {
        "has_dwarf": has_dwarf,
        "enums": enums,
        "discriminant_sites": sites,
        "counts": {"enums": len(enums), "named_variants": named, "dispatch_sites": len(sites)},
    }
    if dwarf_error:
        res["dwarf_error"] = dwarf_error
    return res


def _print(res):
    if res.get("error"):
        print(res["error"])
        return
    c = res["counts"]
    print(f"has_dwarf={res['has_dwarf']}  enums={c['enums']} (named_variants={c['named_variants']})  "
          f"dispatch_sites={c['dispatch_sites']}")
    for e in res["enums"][:40]:
        d = e["discriminant"]
        tag = f"tag@0x{d['offset']:x}/{d['size']}B" if d else "niche"
        print(f"  enum {e['name']} ({e['byte_size']}B, {tag}{', niche' if e['niche'] and d else ''})")
        for v in e["variants"]:
            val = "niche/default" if v["value"] is None else v["value"]
            print(f"      {v['name']} = {val}  payload@0x{(v['payload_offset'] or 0):x}")
    for s in res["discriminant_sites"][:40]:
        print(f"  dispatch @0x{s['site']:x}: field@0x{s['field_offset']:x} values={s['values']}")


def _selftest():
    # heuristic path (always available): a hand-assembled match on a byte loaded from [rdi+0]
    #   movzx eax, byte ptr [rdi]      0f b6 07
    #   cmp eax, 0 ; je                83 f8 00 74 ..
    #   cmp eax, 1 ; je                83 f8 01 74 ..
    #   cmp eax, 2                     83 f8 02
    code = bytes.fromhex("0fb607" "83f800" "7405" "83f801" "7405" "83f802")
    sites = _dispatch_sites(code, 0x1000)
    assert sites and sites[0]["field_offset"] == 0 and sites[0]["values"] == [0, 1, 2], sites

    # a single compare is NOT a dispatch (need >= 2 distinct tag values)
    assert _dispatch_sites(bytes.fromhex("0fb607" "83f800"), 0x1000) == []

    # AArch64: ldrb w0,[x0]; cmp w0,#0/1/2 (b.eq each) -> a 3-value dispatch on field offset 0
    a64 = bytes.fromhex("00004039" "1f000071" "40000054" "1f040071" "40000054" "1f080071" "40000054")
    asites = _dispatch_sites_arm64(a64, 0x2000)
    assert asites and asites[0]["field_offset"] == 0 and asites[0]["values"] == [0, 1, 2], asites

    # DWARF parse, only if pyelftools + the committed fixture are present (else skip quietly)
    try:
        from elftools.elf.elffile import ELFFile  # noqa: F401
    except ImportError:
        print("selftest OK: dispatch-site heuristic works (pyelftools absent; DWARF path untested here)")
        return
    fix = ROOT.parent / "tests" / "fixtures" / "enums" / "enum_dbg.elf64"
    if not fix.is_file():
        print("selftest OK: dispatch-site heuristic works (DWARF fixture absent)")
        return
    res = recover(fix)
    shape = next((e for e in res["enums"] if e["name"] == "Shape"), None)
    assert shape and {v["name"] for v in shape["variants"]} >= {"Circle", "Rect", "Empty"}, shape
    print("selftest OK: dispatch-site heuristic + DWARF enum 'Shape' variants (Circle/Rect/Empty) recovered")


def main(argv=None):
    import argparse
    import json
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("binary", nargs="?")
    ap.add_argument("--json", action="store_true", help="print the result dict as JSON")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args(argv)
    if a.selftest:
        _selftest()
        return 0
    if not a.binary:
        ap.error("give a binary, or --selftest")
    path = Path(a.binary)
    if not path.is_file():
        ap.error(f"no such file: {path}")
    res = recover(path)
    print(json.dumps(res, indent=2)) if a.json else _print(res)
    return 0


if __name__ == "__main__":
    sys.exit(main())
