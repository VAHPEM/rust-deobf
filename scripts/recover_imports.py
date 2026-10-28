#!/usr/bin/env python3
"""recover_imports.py - reconstruct a PE's imports and bind indirect call sites to API names.

After a packer is peeled off (see unpack_emulate.py / dump_unpacked.py) the analyst has an image
whose `call [IAT_slot]` sites mean nothing until each slot is tied back to its API. This does that:
it reads the PE import directory, builds the IAT-slot -> (dll, api) map, then disassembles .text and
resolves every memory-indirect call/jmp whose target is an IAT slot -- x86-64 `call/jmp [rip+disp]`,
x86 `call/jmp [abs32]`, and ARM64 (Windows on ARM) `adrp xN, page; ldr xM, [xN, #off]; blr|br xM`
(the import-thunk form included). It also flags runtime import resolution (GetProcAddress /
LoadLibrary / GetModuleHandle + API-name strings) -- the signature of a stub that rebuilds imports
itself, i.e. a packed/obfuscated sample.

Complements recover_apihash.py (hash-obfuscated imports) and recover_cfg.py (the call graph). PE
only; benign inputs.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from recover_emulate import Image, _machine  # noqa: E402  (shared PE parse + .text bounds)

from capstone import (CS_ARCH_ARM64, CS_ARCH_X86, CS_MODE_32, CS_MODE_64,  # noqa: E402
                      CS_MODE_LITTLE_ENDIAN, Cs)
from capstone import arm64 as _a64  # noqa: E402
from capstone import x86 as _x86  # noqa: E402

# PE machines whose code this tool can bind (x86, x86-64, ARM64 incl. ARM64EC/ARM64X images)
_SUPPORTED = {"I386": 32, "AMD64": 64, "ARM64": 64, "ARM64EC": 64, "ARM64X": 64}

# APIs whose presence means the sample resolves imports at runtime (packer/loader stub signature).
_RESOLVERS = ("GetProcAddress", "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
              "GetModuleHandleA", "GetModuleHandleW", "LdrGetProcedureAddress", "LdrLoadDll")


def _iat_map(binary):
    """{iat_rva: (dll, api_or_ordinal)} for every import entry lief exposes."""
    out = {}
    for lib in getattr(binary, "imports", []) or []:
        dll = lib.name or "?"
        for e in lib.entries:
            rva = getattr(e, "iat_address", None)
            if not rva:
                continue
            name = f"#{e.ordinal}" if e.is_ordinal else (e.name or "?")
            out[int(rva)] = (dll, name)
    return out


def _indirect_mem_targets(code, base, bits):
    """Yield (site_va, target_va, mnemonic) for call/jmp through a memory operand.

    x86-64: `call qword [rip+disp]` -> target = next_ip + disp. x86: `call dword [disp32]` ->
    target = disp (absolute). These are the two IAT-call encodings.
    """
    md = Cs(CS_ARCH_X86, CS_MODE_64 if bits == 64 else CS_MODE_32)
    md.detail = True
    # skipdata: emit an undecodable byte as data (id 0) and keep going. Plain disasm() stops at the
    # first one, so a single junk byte early in .text hid every IAT call site after it.
    md.skipdata = True
    for insn in md.disasm(code, base):
        if insn.id == 0 or insn.mnemonic not in ("call", "jmp"):
            continue
        ops = insn.operands
        if len(ops) != 1 or ops[0].type != _x86.X86_OP_MEM:
            continue
        mem = ops[0].mem
        if mem.index != 0:
            continue
        if bits == 64 and mem.base == _x86.X86_REG_RIP:
            yield insn.address, insn.address + insn.size + mem.disp, insn.mnemonic
        elif bits == 32 and mem.base == 0:
            yield insn.address, mem.disp & 0xffffffff, insn.mnemonic


def _a64_xreg_map():
    """capstone ARM64 register id -> canonical 64-bit X register id (W<n> -> X<n>, FP/LR -> X29/X30).
    A write to w8 zero-extends into x8, so state tracked for x8 must be forgotten on it."""
    m = {}
    for i in range(31):
        x = _a64.ARM64_REG_FP if i == 29 else _a64.ARM64_REG_LR if i == 30 \
            else getattr(_a64, f"ARM64_REG_X{i}")
        m[x] = x
        m[getattr(_a64, f"ARM64_REG_W{i}")] = x
    return m


_A64_X = _a64_xreg_map()


def _arm64_import_sites(code, base):
    """Yield (site_va, slot_va, kind) for ARM64 calls/jumps through a pointer loaded from memory.

    Windows-on-ARM import calls are `adrp xN, page; ldr xM, [xN, #lo12]; blr xM` (or `br xM` in an
    import thunk / tail call; `add xN, xN, #lo12; ldr xM, [xN]` and a literal `ldr xM, =slot` also
    occur). A linear sweep tracks, per register, a known address (from adrp/add) and the memory slot
    a register was last loaded from; a blr/br through such a register yields that slot. Any other
    write to a register forgets it, and every branch resets the state (a call clobbers registers; a
    branch target may be reached from elsewhere). The caller keeps the slots that are IAT entries.
    """
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    md.skipdata = True                 # an undecodable word is skipped, not the end of the sweep
    addr = {}                          # reg -> known address value (adrp page, + add imm)
    loaded = {}                        # reg -> slot address the register was loaded from
    for insn in md.disasm(code, base):
        if insn.id == 0:               # skipped data: unknown effect on registers
            addr.clear()
            loaded.clear()
            continue
        mn = insn.mnemonic
        ops = insn.operands
        new_addr = new_loaded = None
        if mn in ("blr", "br") and len(ops) == 1 and ops[0].type == _a64.ARM64_OP_REG:
            slot = loaded.get(_A64_X.get(ops[0].reg))
            if slot is not None:
                yield insn.address, slot, "call" if mn == "blr" else "jmp"
            addr.clear()
            loaded.clear()
            continue
        if mn in ("b", "bl", "ret", "braa", "brab", "blraa", "blrab", "retaa", "retab") \
                or mn.startswith("b."):
            addr.clear()
            loaded.clear()
            continue
        # only 64-bit X destinations carry an address/pointer (`ldr w8, ...` is a 32-bit load);
        # a W register or SP/XZR is not in _A64_X-as-X form, so it is never tracked
        dst = ops[0].reg if ops and ops[0].type == _a64.ARM64_OP_REG else None
        dst = dst if dst is not None and _A64_X.get(dst) == dst else None
        if dst is None:
            pass
        elif mn == "adrp" and len(ops) == 2 and ops[1].type == _a64.ARM64_OP_IMM:
            new_addr = (dst, ops[1].imm)
        elif (mn == "add" and len(ops) == 3 and ops[1].type == _a64.ARM64_OP_REG
              and ops[2].type == _a64.ARM64_OP_IMM and ops[1].reg in addr
              and ops[2].shift.type == 0):
            new_addr = (dst, addr[ops[1].reg] + ops[2].imm)
        elif mn == "ldr" and len(ops) == 2:
            if ops[1].type == _a64.ARM64_OP_MEM:
                m = ops[1].mem
                # [xN, #off] only: no index register, no pre/post-index writeback
                if m.index == 0 and m.base in addr and not insn.writeback:
                    new_loaded = (dst, addr[m.base] + m.disp)
            elif ops[1].type == _a64.ARM64_OP_IMM:        # literal: ldr xM, <label>
                new_loaded = (dst, ops[1].imm)
        try:
            written = insn.regs_access()[1]
        except Exception:              # no access info: assume it may clobber anything we track
            written = list(addr) + list(loaded)
        for r in written:
            r = _A64_X.get(r, r)
            addr.pop(r, None)
            loaded.pop(r, None)
        if new_addr is not None:
            addr[new_addr[0]] = new_addr[1]
        if new_loaded is not None:
            loaded[new_loaded[0]] = new_loaded[1]


def _error(fmt, msg):
    return {"format": fmt, "error": msg, "imports": [], "resolved_callsites": [], "counts": {}}


def recover(path) -> dict:
    """Reconstruct imports and resolve indirect call sites for the PE at `path`.

    Returns {format, bits, imports:[{dll,api,iat_rva}], resolved_callsites:[{site,dll,api,kind}],
    dynamic_resolution:{present,resolvers,api_name_strings}, counts}.
    """
    try:
        img = Image(path)
    except Exception as e:             # unparseable, or no code section to bind call sites in
        return _error(None, f"cannot analyse: {e or type(e).__name__}")
    if not img.pe:
        return _error(img.fmt, "not a PE; this tool reconstructs PE imports")
    binary = img.binary
    machine = _machine(binary).replace("MACHINE_TYPES.", "")
    if machine not in _SUPPORTED:
        # never disassemble foreign code as x86-64: that silently yields a wrong, empty answer
        return _error(img.fmt, f"unsupported PE machine {machine or '?'}: call-site binding "
                               f"supports {', '.join(sorted(_SUPPORTED))}")
    iat = _iat_map(binary)
    imports = [{"dll": d, "api": n, "iat_rva": rva} for rva, (d, n) in sorted(iat.items())]

    bits = _SUPPORTED[machine]
    arch = "arm64" if img.arm else ("x86-64" if bits == 64 else "x86")
    if img.arm:
        sites = _arm64_import_sites(img.code, img.text_va)
    else:
        sites = _indirect_mem_targets(img.code, img.text_va, bits)
    # .text is at an RVA for PE; lief's iat_address is an RVA too, so resolve in RVA space.
    resolved = []
    seen = set()
    for site, target, kind in sites:
        hit = iat.get(target) or iat.get(target - img.imagebase)
        if hit and site not in seen:
            seen.add(site)
            resolved.append({"site": site, "dll": hit[0], "api": hit[1], "kind": kind})

    api_names = {n for _, n in iat.values()}
    resolvers_present = sorted(api_names & set(_RESOLVERS))
    # API-name-looking strings in the raw file hint at runtime resolution even when the IAT is thin
    try:
        import re
        blob = img.file_bytes or b""
        name_like = len(set(re.findall(rb"[A-Z][a-zA-Z0-9]{5,}(?:A|W|Ex)?\x00", blob)))
    except Exception:
        name_like = 0

    return {
        "format": img.fmt,
        "bits": bits,
        "arch": arch,
        "imports": imports,
        "resolved_callsites": resolved,
        "dynamic_resolution": {
            "present": bool(resolvers_present),
            "resolvers": resolvers_present,
            "api_name_strings": name_like,
        },
        "counts": {"imports": len(imports), "resolved_callsites": len(resolved),
                   "libraries": len({d for d, _ in iat.values()})},
    }


def _print(res):
    if res.get("error"):
        print(res["error"])
        return
    c = res["counts"]
    print(f"{res['format']} {res['arch']}  imports={c['imports']} across {c['libraries']} lib(s)  "
          f"resolved_callsites={c['resolved_callsites']}")
    dr = res["dynamic_resolution"]
    if dr["present"]:
        print(f"  runtime import resolution present: {', '.join(dr['resolvers'])} "
              f"(api_name_strings={dr['api_name_strings']})")
    for r in res["resolved_callsites"][:40]:
        print(f"  0x{r['site']:x}: {r['kind']} -> {r['dll']}!{r['api']}")


def _selftest():
    # Resolve a hand-assembled `call qword [rip+disp]` against a synthetic IAT (no binary).
    base = 0x1000
    # ff 15 <disp32> = call [rip+disp]; site 0x1000, len 6, disp 0x100 -> target 0x1106
    code = b"\xff\x15" + (0x100).to_bytes(4, "little") + b"\xc3"
    iat = {0x1106: ("USER.dll", "DoThing")}
    hits = list(_indirect_mem_targets(code, base, 64))
    assert hits and hits[0][1] == 0x1106, hits
    resolved = [iat[t] for _s, t, _k in hits if t in iat]
    assert resolved == [("USER.dll", "DoThing")], resolved

    # x86 absolute `call dword [disp32]`: ff 15 <abs32>
    code32 = b"\xff\x15" + (0x4030).to_bytes(4, "little")
    h32 = list(_indirect_mem_targets(code32, 0x2000, 32))
    assert h32 and h32[0][1] == 0x4030, h32

    # a direct `call rel32` (e8 ..) is NOT a memory-indirect import call
    assert list(_indirect_mem_targets(b"\xe8\x00\x00\x00\x00", 0x1000, 64)) == []

    # an undecodable byte (0xd6 is invalid in 64-bit mode) must not end the sweep
    junk = b"\xd6\x06" + code
    hj = list(_indirect_mem_targets(junk, base - 2, 64))
    assert hj and hj[0][1] == 0x1106, hj

    # ARM64: adrp x8, page(+0x1000); ldr x8, [x8, #0x40]; blr x8  and  the thunk form via x16 / br
    a64 = (bytes.fromhex("08000090") + bytes.fromhex("082140f9") + bytes.fromhex("00013fd6")
           + bytes.fromhex("10000090") + bytes.fromhex("102640f9") + bytes.fromhex("00021fd6"))
    ha = list(_arm64_import_sites(a64, 0x1000))
    assert [(s, t, k) for s, t, k in ha] == [(0x1008, 0x1040, "call"), (0x1014, 0x1048, "jmp")], ha
    # a clobbered register is forgotten: adrp x8; ldr x8,[x8,#0x40]; mov x8, #1; blr x8 -> nothing
    clob = (bytes.fromhex("08000090") + bytes.fromhex("082140f9") + bytes.fromhex("280080d2")
            + bytes.fromhex("00013fd6"))
    assert list(_arm64_import_sites(clob, 0x1000)) == []
    # ... including through its 32-bit view: `mov w8, #1` zero-extends into x8
    clob_w = clob[:8] + bytes.fromhex("28008052") + clob[12:]
    assert list(_arm64_import_sites(clob_w, 0x1000)) == []
    # a 32-bit load (`ldr w8, [x8, #0x40]`) is not a pointer load
    assert list(_arm64_import_sites(clob[:4] + bytes.fromhex("084140b9") + clob[12:], 0x1000)) == []
    # add-lo12 and literal forms: adrp x8; add x8,x8,#0x40; ldr x9,[x8]; blr x9 / ldr x16,=+0x40; br
    alt = (bytes.fromhex("08000090") + bytes.fromhex("08010191") + bytes.fromhex("090140f9")
           + bytes.fromhex("20013fd6") + bytes.fromhex("10020058") + bytes.fromhex("00021fd6"))
    assert list(_arm64_import_sites(alt, 0x1000)) == [(0x100c, 0x1040, "call"), (0x1014, 0x1050, "jmp")]
    print("selftest OK: rip-relative, absolute and ARM64 adrp/ldr/blr IAT call sites resolved; "
          "junk bytes skipped; direct call and clobbered register ignored")


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
