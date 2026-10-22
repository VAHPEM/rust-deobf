#!/usr/bin/env python3
"""recover_stackstrings.py - recover stack strings (x86-64 + AArch64), statically.

A stack string is assembled at runtime from immediates written to consecutive stack
slots -- `mov byte ptr [rbp-0x20], 'h'; mov byte ptr [rbp-0x1f], 'i'`, or packed as
`mov dword ptr [rsp+0x10], 0x6c6c6568` ("hell"). The characters never appear as a
contiguous run in the file, so `strings(1)` and the keyed-decoder recoverers miss them.
This is one of FLOSS's three core techniques (Mandiant); FLOSS recovers them by emulating
every function with vivisect. This is a lighter, static approximation: disassemble `.text`,
collect immediate stores to frame-relative slots, lay the bytes out by offset, and read off
the printable runs. No execution, no vivisect dependency.

Scope and honesty: this catches the common immediate-store idiom (per-byte and packed
word/dword/qword moves to `[rbp±k]`/`[rsp+k]`). It does NOT model data flow, so a stack
string whose bytes are computed (xored, shuffled) rather than stored as immediates is out
of reach -- that is the decoded-string case (use recover_dynamic / recover_emulate). Output
is gated by length + a text-likeness score to keep struct/array initialisers from flooding
it; `measure_fp.py`-style review on real binaries still applies.

    python recover_stackstrings.py <binary> [--min-len 5] [--json]
    python recover_stackstrings.py --selftest
"""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from disasm import linear  # noqa: E402


def _text_gate():
    """Reuse recover_callsite's word-likeness gate when available; else a simple fallback."""
    try:
        from recover_callsite import looks_like_text, english_score
        return looks_like_text, english_score
    except Exception:
        def looks_like_text(b):
            return len(b) >= 4 and sum(c in range(0x20, 0x7f) for c in b) / len(b) > 0.9
        def english_score(t):
            return 1.0
        return looks_like_text, english_score


_X86_FAMILIES = {}
for _full, _parts in {
    "rax": "eax ax al ah", "rbx": "ebx bx bl bh", "rcx": "ecx cx cl ch", "rdx": "edx dx dl dh",
    "rsi": "esi si sil", "rdi": "edi di dil", "rbp": "ebp bp bpl", "rsp": "esp sp spl",
}.items():
    for _p in [_full] + _parts.split():
        _X86_FAMILIES[_p] = _full
for _n in range(8, 16):
    for _p in (f"r{_n}", f"r{_n}d", f"r{_n}w", f"r{_n}b"):
        _X86_FAMILIES[_p] = f"r{_n}"


def _x86_canon(name: str) -> str:
    """Map a sub-register (eax, al, r8d, ...) to its 64-bit register."""
    return _X86_FAMILIES.get(name, name)


def collect(code: bytes, text_va: int, min_len: int):
    """Disassemble .text and assemble stack strings from immediate frame stores."""
    from capstone import (Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_MEM, CS_OP_IMM, CS_OP_REG)
    looks_like_text, english_score = _text_gate()
    md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail = True

    # frame-relative byte map for the current region, keyed by (base_reg, disp) -> byte.
    # Flush and scan for runs on a control-flow boundary (call/ret/jmp) so unrelated
    # buffers in different regions don't merge.
    frame: dict = {}
    found = []
    sites: dict = {}   # string -> {"pc": last store, "base": frame register, "offset": slot}

    def flush():
        if not frame:
            return
        by_base = {}
        for (base, disp), b in frame.items():
            by_base.setdefault(base, {})[disp] = b
        for base, slots in by_base.items():
            offs = sorted(slots)
            run = bytearray(); start = None; prev = None; pcs = []
            def emit():
                if len(run) >= min_len:
                    raw = bytes(run)
                    if looks_like_text(raw):
                        txt = raw.decode("latin-1", "ignore")
                        found.append((english_score(txt), txt))
                        sites.setdefault(txt, {"pc": max(pcs), "base": base, "offset": start})
            for o in offs:
                c, pc = slots[o]
                if prev is not None and o != prev + 1:
                    emit(); run = bytearray(); pcs = []
                if 0x20 <= c < 0x7f or c in (9,):
                    if not run:
                        start = o
                    run.append(c); pcs.append(pc)
                else:
                    emit(); run = bytearray(); pcs = []
                prev = o
            emit()
        frame.clear()

    # Immediates held in registers. x86-64 has no 64-bit immediate store, so compilers build an
    # 8-byte chunk as `movabs rax, imm64; mov [rbp-k], rax` -- the immediate reaches the frame
    # through a register (the AArch64 path below has always had to do the same).
    regval: dict = {}

    for ins in linear(md, code, text_va):
        m = ins.mnemonic
        if m in ("call", "ret", "jmp", "leave") or m.startswith("j"):
            flush(); regval.clear(); continue
        ops = ins.operands
        if m in ("mov", "movabs") and len(ops) == 2 and ops[0].type == CS_OP_REG:
            dreg = _x86_canon(ins.reg_name(ops[0].reg))
            if ops[1].type == CS_OP_IMM:
                regval[dreg] = ops[1].imm & 0xFFFFFFFFFFFFFFFF
            else:
                regval.pop(dreg, None)
            continue
        if m != "mov" or len(ops) != 2:
            # anything else that writes a register makes its tracked immediate stale
            if ops and ops[0].type == CS_OP_REG:
                regval.pop(_x86_canon(ins.reg_name(ops[0].reg)), None)
            continue
        dst, src = ops
        if dst.type != CS_OP_MEM:
            continue
        if src.type == CS_OP_IMM:
            imm = src.imm
        elif src.type == CS_OP_REG and _x86_canon(ins.reg_name(src.reg)) in regval:
            imm = regval[_x86_canon(ins.reg_name(src.reg))]
        else:
            continue
        base = dst.mem.base
        if not base or dst.mem.index:
            continue
        bname = ins.reg_name(base)
        if bname not in ("rbp", "rsp", "ebp", "esp"):
            continue
        size = dst.size or 1
        if size not in (1, 2, 4, 8):
            continue
        val = imm & ((1 << (size * 8)) - 1)
        data = val.to_bytes(size, "little")
        for k, b in enumerate(data):
            frame[(bname, dst.mem.disp + k)] = (b, ins.address)
    flush()
    collect.last_sites = sites

    # de-dup, rank by word-likeness
    best = {}
    for sc, s in found:
        if s not in best or sc > best[s]:
            best[s] = sc
    return sorted(((sc, s) for s, sc in best.items()), reverse=True)


def _arm_canon(n):
    """w0/x0 are the same register; wzr/xzr read as zero."""
    if n in ("wzr", "xzr"):
        return "zr"
    if n and n[0] in "wx" and n[1:].isdigit():
        return "r" + n[1:]
    return n


def collect_arm64(code: bytes, text_va: int, min_len: int):
    """AArch64 stack strings: `mov wN,#imm` then `strb/strh/str wN,[sp|x29,#off]` (the value
    register is reused across stores, `strb wzr` writes a NUL). Track each register's last
    immediate, place the stored bytes by offset, and read off runs -- same shape as collect()."""
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
    from capstone.arm64 import ARM64_OP_REG, ARM64_OP_IMM, ARM64_OP_MEM
    looks_like_text, english_score = _text_gate()
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail = True

    regval = {"zr": 0}
    frame: dict = {}
    found = []
    sites: dict = {}   # string -> {"pc": last store, "base": frame register, "offset": slot}

    def flush():
        if not frame:
            return
        by_base = {}
        for (base, disp), b in frame.items():
            by_base.setdefault(base, {})[disp] = b
        for base, slots in by_base.items():
            offs = sorted(slots)
            run = bytearray(); prev = None; start = None; pcs = []
            def emit():
                if len(run) >= min_len:
                    s = bytes(run).decode("latin-1", "ignore")
                    if looks_like_text(bytes(run)):
                        found.append((english_score(s), s))
                        sites.setdefault(s, {"pc": max(pcs), "base": base, "offset": start})
            for o in offs:
                c, pc = slots[o]
                if prev is not None and o != prev + 1:
                    emit(); run = bytearray(); pcs = []
                if 0x20 <= c < 0x7f or c == 9:
                    if not run:
                        start = o
                    run.append(c); pcs.append(pc)
                else:
                    emit(); run = bytearray(); pcs = []
                prev = o
            emit()
        frame.clear()

    for ins in linear(md, code, text_va):
        m = ins.mnemonic
        if m in ("bl", "blr", "b", "br", "ret", "cbz", "cbnz", "tbz", "tbnz") or m.startswith("b."):
            flush(); continue
        ops = ins.operands
        if m in ("mov", "movz") and len(ops) == 2 \
           and ops[0].type == ARM64_OP_REG and ops[1].type == ARM64_OP_IMM:
            regval[_arm_canon(ins.reg_name(ops[0].reg))] = ops[1].imm & 0xFFFFFFFFFFFFFFFF
        elif m in ("strb", "strh", "str") and len(ops) == 2 \
             and ops[0].type == ARM64_OP_REG and ops[1].type == ARM64_OP_MEM:
            src_name = ins.reg_name(ops[0].reg)
            size = {"strb": 1, "strh": 2}.get(m) or (4 if src_name.startswith("w") else 8)
            base = ins.reg_name(ops[1].mem.base) if ops[1].mem.base else None
            if base not in ("sp", "x29"):
                continue
            src = _arm_canon(src_name)
            if src not in regval:
                continue
            val = regval[src] & ((1 << (size * 8)) - 1)
            for k, b in enumerate(val.to_bytes(size, "little")):
                frame[(base, ops[1].mem.disp + k)] = (b, ins.address)
    flush()
    collect_arm64.last_sites = sites
    best = {}
    for sc, s in found:
        if s not in best or sc > best[s]:
            best[s] = sc
    return sorted(((sc, s) for s, sc in best.items()), reverse=True)


def recover(path: Path, min_len: int = 5):
    import lief
    b = lief.parse(str(path))
    if b is None:
        return {"error": "parse failed", "stackstrings": []}
    text = next((s for s in b.sections if s.name == ".text"), None)
    if text is None:
        return {"error": "no .text", "stackstrings": []}
    base = (b.optional_header.imagebase if "PE" in b.format.name else 0) + text.virtual_address
    try:
        mach = (b.header.machine_type.name if hasattr(b.header, "machine_type")
                else str(b.header.machine)).upper()
    except Exception:
        mach = ""
    arm = "AARCH64" in mach or "ARM64" in mach
    collector = collect_arm64 if arm else collect
    ss = collector(bytes(text.content), base, min_len)
    sites = getattr(collector, "last_sites", {})
    # records: {"string", "pc", "base", "offset"} -- pc is the last immediate store that wrote the
    # string, base/offset the frame register and slot it was written to
    records = [dict(string=s, **sites[s]) for _, s in ss if s in sites]
    return {"stackstrings": [s for _, s in ss], "ranked": ss, "records": records,
            "arch": "aarch64" if arm else "x86-64"}


def _selftest():
    # synthesise .text that builds "secret_on_stack!" via packed dword/byte stores to [rbp-k],
    # bracketed by a ret so the region flushes, and check we read it back.
    import capstone  # noqa: F401  (ensure capstone is present)
    import struct as _s
    s = b"secret_on_stack!"
    code = bytearray()
    # mov dword ptr [rbp - 0x20 + o], imm32  for each 4-byte chunk
    off = -0x20
    for i in range(0, 16, 4):
        chunk = s[i:i+4]
        # C7 45 disp8 imm32  => mov dword ptr [rbp+disp8], imm32
        disp = (off + i) & 0xff
        code += b"\xc7\x45" + bytes([disp]) + _s.pack("<I", int.from_bytes(chunk, "little"))
    code += b"\xc3"  # ret -> flush
    r = collect(bytes(code), 0x1000, 5)
    got = [t for _, t in r]
    assert any("secret_on_stack!" in t for t in got), got

    # AArch64: mov w0,#c; strb w0,[sp,#off] for "Key", then ret -> flush
    def mov_w0(imm):   # MOVZ w0,#imm16
        return _s.pack("<I", 0x52800000 | ((imm & 0xFFFF) << 5))
    def strb_sp(off):  # STRB w0,[sp,#off]
        return _s.pack("<I", 0x39000000 | ((off & 0xFFF) << 10) | (31 << 5))
    acode = bytearray()
    for k, ch in enumerate(s):               # same 16-char secret, clears the text gate
        acode += mov_w0(ch) + strb_sp(k)
    acode += _s.pack("<I", 0xD65F03C0)  # ret
    ar = collect_arm64(bytes(acode), 0x1000, 5)
    agot = [t for _, t in ar]
    assert any("secret_on_stack!" in t for t in agot), agot
    print("selftest OK: x86 stack string", [t for t in got if "secret" in t],
          "| arm64 stack string", [t for t in agot if "secret" in t])


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("binary", nargs="?")
    ap.add_argument("--min-len", type=int, default=5)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        _selftest(); return
    if not a.binary:
        ap.error("binary required or --selftest")
    r = recover(Path(a.binary), a.min_len)
    if a.json:
        print(json.dumps(r, indent=2)); return
    if r.get("error"):
        sys.exit(r["error"])
    print(f"{Path(a.binary).name}: {len(r['stackstrings'])} stack string(s)")
    for sc, s in r["ranked"]:
        print(f"  [{sc:.2f}] {s}")


if __name__ == "__main__":
    main()
