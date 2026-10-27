#!/usr/bin/env python3
"""recover_imports.py - reconstruct a PE's imports and bind indirect call sites to API names.

After a packer is peeled off (see unpack_emulate.py / dump_unpacked.py) the analyst has an image
whose `call [IAT_slot]` sites mean nothing until each slot is tied back to its API. This does that:
it reads the PE import directory, builds the IAT-slot -> (dll, api) map, then disassembles .text and
resolves every memory-indirect call/jmp whose target is an IAT slot. It also flags runtime import
resolution (GetProcAddress / LoadLibrary / GetModuleHandle + API-name strings) -- the signature of a
stub that rebuilds imports itself, i.e. a packed/obfuscated sample.

Complements recover_apihash.py (hash-obfuscated imports) and recover_cfg.py (the call graph). PE
only; benign inputs.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from recover_emulate import Image  # noqa: E402  (shared PE parse + .text bounds)

from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs  # noqa: E402
from capstone import x86 as _x86  # noqa: E402

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


def recover(path) -> dict:
    """Reconstruct imports and resolve indirect call sites for the PE at `path`.

    Returns {format, bits, imports:[{dll,api,iat_rva}], resolved_callsites:[{site,dll,api,kind}],
    dynamic_resolution:{present,resolvers,api_name_strings}, counts}.
    """
    img = Image(path)
    if not img.pe:
        return {"format": img.fmt, "error": "not a PE; this tool reconstructs PE imports",
                "imports": [], "resolved_callsites": [], "counts": {}}
    binary = img.binary
    iat = _iat_map(binary)
    imports = [{"dll": d, "api": n, "iat_rva": rva} for rva, (d, n) in sorted(iat.items())]

    bits = 32 if img.x32 else 64
    # .text is at an RVA for PE; lief's iat_address is an RVA too, so resolve in RVA space.
    resolved = []
    seen = set()
    for site, target, kind in _indirect_mem_targets(img.code, img.text_va, bits):
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
    print(f"{res['format']} {res['bits']}-bit  imports={c['imports']} across {c['libraries']} lib(s)  "
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
    print("selftest OK: rip-relative and absolute IAT call sites resolved; direct call ignored")


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
