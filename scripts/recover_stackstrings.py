#!/usr/bin/env python3
"""recover_stackstrings.py - recover stack strings (x86-64), statically.

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
import argparse, json, struct, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))


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


def collect(code: bytes, text_va: int, min_len: int):
    """Disassemble .text and assemble stack strings from immediate frame stores."""
    from capstone import (Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_MEM, CS_OP_IMM)
    looks_like_text, english_score = _text_gate()
    md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail = True

    # frame-relative byte map for the current region, keyed by (base_reg, disp) -> byte.
    # Flush and scan for runs on a control-flow boundary (call/ret/jmp) so unrelated
    # buffers in different regions don't merge.
    frame: dict = {}
    found = []

    def flush():
        if not frame:
            return
        by_base = {}
        for (base, disp), b in frame.items():
            by_base.setdefault(base, {})[disp] = b
        for base, slots in by_base.items():
            offs = sorted(slots)
            run = bytearray(); start = None; prev = None
            def emit():
                if len(run) >= min_len:
                    raw = bytes(run)
                    if looks_like_text(raw):
                        found.append((english_score(raw.decode("latin-1", "ignore")),
                                      raw.decode("latin-1", "ignore")))
            for o in offs:
                c = slots[o]
                if prev is not None and o != prev + 1:
                    emit(); run = bytearray()
                if 0x20 <= c < 0x7f or c in (9,):
                    run.append(c)
                else:
                    emit(); run = bytearray()
                prev = o
            emit()
        frame.clear()

    for ins in md.disasm(code, text_va):
        m = ins.mnemonic
        if m in ("call", "ret", "jmp", "leave") or m.startswith("j"):
            flush(); continue
        if m != "mov" or len(ins.operands) != 2:
            continue
        dst, src = ins.operands
        if dst.type != CS_OP_MEM or src.type != CS_OP_IMM:
            continue
        base = dst.mem.base
        if not base:
            continue
        bname = ins.reg_name(base)
        if bname not in ("rbp", "rsp", "ebp", "esp"):
            continue
        size = dst.size or 1
        if size not in (1, 2, 4, 8):
            continue
        val = src.imm & ((1 << (size * 8)) - 1)
        data = val.to_bytes(size, "little")
        for k, b in enumerate(data):
            frame[(bname, dst.mem.disp + k)] = b
    flush()

    # de-dup, rank by word-likeness
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
    ss = collect(bytes(text.content), base, min_len)
    return {"stackstrings": [s for _, s in ss], "ranked": ss}


def _selftest():
    # synthesise .text that builds "secret_on_stack!" via packed dword/byte stores to [rbp-k],
    # bracketed by a ret so the region flushes, and check we read it back.
    from capstone import Cs  # ensure capstone present
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
    print("selftest OK: recovered stack string", [t for t in got if "secret" in t])


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
