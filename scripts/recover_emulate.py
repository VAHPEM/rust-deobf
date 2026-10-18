#!/usr/bin/env python3
"""Emulation-based string recoverer (Unicorn) for inlined/vectorised decoders.

The static call-site recoverer handles decoders that keep their key in a data section
and decode in a recognisable loop (hand-rolled XOR, litcrypt). It cannot handle obfstr,
which inlines the decode into the caller, embeds the key as immediate `mov` constants in
the code stream, and lets the compiler unroll/vectorise it — there is no key array and no
callable decoder function.

This tool takes the FLOSS approach for that case: emulate the code and capture the plaintext
the decoder materialises in memory. Because obfstr inlines into `main`, we emulate whole
functions with external calls stubbed out (a call is skipped and treated as returning 0),
bound by an instruction budget, and record every byte written to memory. Printable runs in
those writes are the recovered strings.

Honest scope: recovers decoders whose plaintext transits writable memory during a bounded,
call-free emulation (obfstr, and as a bonus the XOR/litcrypt families). It does not execute
real library calls, so a decoder that only yields plaintext *inside* a std/libc call is out
of reach. AEAD (muddy) remains cryptographically out of scope.
"""
from __future__ import annotations
import json, sys, string
from pathlib import Path
import lief
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from unicorn import *
from unicorn.x86_const import *

ROOT = Path(__file__).resolve().parent.parent
PRINT = set(bytes(string.printable, "ascii")) - set(b"\x0b\x0c")

BASE = 0x0                # map image at native VAs (PIE-safe: xref pointer math matches)
STACK = 0x7f0000000000
STACK_SIZE = 0x200000
SCRATCH = 0x10000000     # dummy target for stubbed calls / unmapped reads
BUDGET = 8000            # max instructions per function

def map_image(uc, binary):
    """Map every section at its virtual address (rebased under BASE window)."""
    pages = {}
    for s in binary.sections:
        if s.size == 0 or s.virtual_address == 0: continue
        va = BASE + s.virtual_address
        start = va & ~0xfff
        end = (va + len(bytes(s.content)) + 0xfff) & ~0xfff
        for p in range(start, end, 0x1000):
            pages[p] = True
    for p in sorted(pages):
        try: uc.mem_map(p, 0x1000)
        except UcError: pass
    for s in binary.sections:
        c = bytes(s.content)
        if c and s.virtual_address:
            try: uc.mem_write(BASE + s.virtual_address, c)
            except UcError: pass

def function_ranges(binary, code, text_va):
    """Yield (start_va, size) for functions: prefer symbols, else split on `ret`+prologue."""
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    funcs = []
    syms = [(s.value, s.name) for s in binary.symbols if s.value and getattr(s, "is_function", False)]
    syms = [(v, n) for v, n in syms if text_va <= v < text_va + len(code)]
    if syms:
        syms.sort()
        for (v, _), nxt in zip(syms, [s[0] for s in syms[1:]] + [text_va + len(code)]):
            funcs.append((v, min(nxt - v, 0x4000)))
    else:
        # stripped: window the whole .text in overlapping chunks from each `push rbp`
        addrs = [ins.address for ins in md.disasm(code, text_va)
                 if ins.mnemonic == "push" and ins.op_str in ("rbp", "r15")]
        for a in addrs:
            funcs.append((a, 0x2000))
    return funcs

def emulate_capture(binary, code, text_va, func_va, canaries, block_heads=None):
    text_lo = text_va; text_hi = text_va + len(code)
    depth = [0]
    heads = sorted(block_heads or [])
    writes = bytearray(0x4000)
    seen = set()
    hits = set()
    strings_out = emulate_capture.last_strings = set()
    try:
        uc = Uc(UC_ARCH_X86, UC_MODE_64)
        map_image(uc, binary)
        uc.mem_map(STACK, STACK_SIZE)
        uc.mem_map(SCRATCH, 0x1000000)
        uc.reg_write(UC_X86_REG_RSP, STACK + STACK_SIZE // 2)
        uc.reg_write(UC_X86_REG_RBP, STACK + STACK_SIZE // 2)
        # out-pointer args point into scratch so decoders writing via args don't fault
        for r in (UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_RCX,
                  UC_X86_REG_R8, UC_X86_REG_R9):
            uc.reg_write(r, SCRATCH + 0x8000)

        def hook_code(uc, address, size, _):
            # fast path: dispatch on opcode bytes, no per-insn disassembly
            try:
                op = uc.mem_read(address, 2)
            except UcError:
                return
            b0 = op[0]
            lo = BASE + text_lo; hi = BASE + text_hi
            if b0 in (0xc3, 0xc2):          # ret / ret imm16
                if depth[0] == 0:
                    uc.emu_stop()           # returned from the top-level function
                else:
                    depth[0] -= 1           # returning from an intra-text callee: let it continue
                return
            if b0 == 0xe8:                  # call rel32
                import struct
                rel = struct.unpack("<i", uc.mem_read(address + 1, 4))[0]
                tgt = (address + 5 + rel) & 0xffffffffffffffff
                if lo <= tgt < hi:
                    depth[0] += 1            # intra-.text call (e.g. obfstr xref): let it run
                    return
                nh = next((h for h in heads if h > address), None)
                uc.reg_write(UC_X86_REG_RIP, BASE + nh if nh is not None else address + size)
                uc.reg_write(UC_X86_REG_RAX, 0); return
            if b0 == 0xff and (op[1] >> 3) & 7 in (2, 3):  # indirect call (GOT/PLT) -> external
                nh = next((h for h in heads if h > address), None)
                uc.reg_write(UC_X86_REG_RIP, BASE + nh if nh is not None else address + size)
                uc.reg_write(UC_X86_REG_RAX, 0); return

        def hook_write(uc, access, address, size, value, _):
            off = address
            try:
                b = value.to_bytes(size, "little")
            except (OverflowError, AttributeError):
                return
            # record into a flat buffer keyed by low bits so we can scan runs
            for k, byte in enumerate(b):
                writes.append(byte)

        def hook_mem_invalid(uc, access, address, size, value, _):
            # map missing pages on the fly so emulation keeps going
            try: uc.mem_map(address & ~0xfff, 0x1000)
            except UcError: pass
            return True

        uc.hook_add(UC_HOOK_CODE, hook_code)
        uc.hook_add(UC_HOOK_MEM_WRITE, hook_write)
        uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED, hook_mem_invalid)

        start = BASE + func_va
        try:
            uc.emu_start(start, BASE + text_va + len(code), timeout=3_000_000, count=BUDGET)
        except UcError:
            pass

        # scan the recorded writes for canaries; also scan scratch + stack memory
        blobs = [bytes(writes)]
        for region in (SCRATCH, STACK + STACK_SIZE // 2 - 0x4000):
            try: blobs.append(bytes(uc.mem_read(region, 0x8000)))
            except UcError: pass
        text = b"\x00".join(blobs)
        for c in canaries:
            if c.encode() in text:
                hits.add(c)
        # also surface general printable runs (for analysts without known canaries)
        import string as _s
        PR = set(bytes(_s.printable, "ascii")) - set(b"\x0b\x0c\r\n\t")
        cur = bytearray()
        for by in text:
            if by in PR: cur.append(by)
            else:
                if len(cur) >= 6: strings_out.add(bytes(cur).decode("ascii", "ignore"))
                cur = bytearray()
        if len(cur) >= 6: strings_out.add(bytes(cur).decode("ascii", "ignore"))
    except Exception:
        pass
    return hits

def recover(path, canaries, max_funcs=400):
    binary = lief.parse(str(path))
    text = next((s for s in binary.sections if s.name == ".text"), None)
    if text is None: return {"error": "no .text", "recall": 0, "n": len(canaries)}
    code = bytes(text.content); text_va = text.virtual_address
    funcs = function_ranges(binary, code, text_va)
    found = set()
    for (fva, _) in funcs[:max_funcs]:
        found |= emulate_capture(binary, code, text_va, fva, canaries)
        if len(found) == len(canaries): break
    return {"functions_tried": min(len(funcs), max_funcs), "recovered": sorted(found),
            "recall": len(found), "n": len(canaries)}

def main():
    man = json.loads((ROOT/"bench_src"/"manifest.json").read_text()); can = man["canaries"]
    targets = sys.argv[1:] or ["build/obfstr__elf__release__nostrip"]
    for t in targets:
        r = recover(ROOT/t, can)
        print(f"{Path(t).name:<42} recall {r['recall']}/{r['n']}  funcs={r.get('functions_tried')}"
              + ("  ERR "+r['error'] if r.get('error') else ""))
        for s in r.get("recovered", []): print("     +", s)

if __name__ == "__main__":
    main()
