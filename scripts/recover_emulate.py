#!/usr/bin/env python3
"""Emulation-based string recoverer (Unicorn) for inlined/vectorised decoders.

The static call-site recoverer handles decoders that keep their key in a data section
and decode in a recognisable loop (hand-rolled XOR, litcrypt). It cannot handle obfstr,
which inlines the decode into the caller, embeds the key as immediate `mov` constants in
the code stream, and lets the compiler unroll/vectorise it — there is no key array and no
callable decoder function.

This tool takes the FLOSS approach for that case: emulate the code and capture the plaintext
the decoder materialises in memory. Because obfstr inlines into `main`, we emulate whole
functions bounded by an instruction budget and record every byte written to memory; printable
runs in those writes are the recovered strings. Two call classes are treated differently:
an *intra-.text* `call` (obfstr's `xref::inner`, which reconstructs the real ciphertext
pointer from a deliberately-corrupted argument) is executed, because its return value is
load-bearing; an *external* or register-indirect call (the `println!`/formatter, reached as
`call r15` through an unrelocated GOT) is stubbed (skipped, returns 0) so emulation does not
follow a zero pointer into garbage. Getting the register-indirect case right — it is REX-
prefixed (`41 ff d7`), so the opcode test must skip the REX byte — is what lifts obfstr from
1/5 (first literal only) to 5/5.

Honest scope: this targets the *inlined* case (obfstr), where the plaintext is materialised
in `main`'s own frame during a bounded emulation. It is NOT the tool for the keyed-decoder
families (hand-rolled XOR/ADD/SUB, litcrypt): those decode in a separate function whose
ciphertext/length arrive as arguments, so emulating the function in isolation sees no input
and recovers nothing — the static call-site recoverer handles them (5/5) and should be used
there. A decoder that only yields plaintext *inside* a real std/libc call is out of reach
(the call is stubbed), and AEAD (muddy) is cryptographically out of scope.
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
            # fast path: dispatch on opcode bytes, no per-insn disassembly. Skip any REX
            # prefix first: a register-indirect call such as `call r15` is `41 ff d7`, so
            # testing the raw first byte would miss it, let Unicorn execute the external
            # call into an unrelocated (zero) GOT slot, and diverge into garbage. This REX
            # skip is what lets obfstr (whose print call is `call r15`) decode all literals
            # instead of only the first.
            try:
                raw = uc.mem_read(address, min(size, 15))
            except UcError:
                return
            j = 0
            while j < len(raw) and 0x40 <= raw[j] <= 0x4f:   # REX prefix(es)
                j += 1
            if j >= len(raw):
                return
            b0 = raw[j]
            lo = BASE + text_lo; hi = BASE + text_hi
            if b0 in (0xc3, 0xc2):          # ret / ret imm16
                if depth[0] == 0:
                    uc.emu_stop()           # returned from the top-level function
                else:
                    depth[0] -= 1           # returning from an intra-text callee: let it continue
                return
            if b0 == 0xe8:                  # call rel32
                import struct
                rel = struct.unpack("<i", raw[j + 1:j + 5])[0]
                tgt = (address + size + rel) & 0xffffffffffffffff
                if lo <= tgt < hi:
                    depth[0] += 1            # intra-.text call (e.g. obfstr xref::inner): let it run
                    return
                nh = next((h for h in heads if h > address), None)
                uc.reg_write(UC_X86_REG_RIP, BASE + nh if nh is not None else address + size)
                uc.reg_write(UC_X86_REG_RAX, 0); return
            if b0 == 0xff and j + 1 < len(raw) and (raw[j + 1] >> 3) & 7 in (2, 3):  # indirect call (GOT/PLT) -> external
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

def function_ranges_arm64(binary, code, text_va):
    """ARM64 function starts: prefer symbols, else `stp x29, x30, [sp...]` prologues."""
    from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    syms = [(s.value, s.name) for s in binary.symbols
            if s.value and getattr(s, "is_function", False)]
    syms = [(v, n) for v, n in syms if text_va <= v < text_va + len(code)]
    funcs = []
    if syms:
        syms.sort()
        for (v, _), nxt in zip(syms, [s[0] for s in syms[1:]] + [text_va + len(code)]):
            funcs.append((v, min(nxt - v, 0x8000)))
    else:
        for ins in md.disasm(code, text_va):
            if ins.mnemonic == "stp" and "x29, x30" in ins.op_str and "[sp" in ins.op_str:
                funcs.append((ins.address, 0x4000))
    return funcs


def emulate_capture_arm64(binary, code, text_va, func_va, canaries):
    """AArch64 analogue of emulate_capture.

    obfstr inlines its decode as immediate `movz`/`movk` key arithmetic and materialises the
    plaintext on the stack, then calls the formatter. On a *static* ELF the Rust fmt runtime
    lives in `.text`, so that print is an *intra-text* `bl` (not x86's GOT `call r15`): we must
    still execute intra-text calls (some are load-bearing before the decode completes), but we
    snapshot the live stack window *before every call* -- that is exactly when the decoded
    buffer is complete and not yet clobbered by the formatter. External/register-indirect calls
    (`blr`) are stubbed. Printable runs from those snapshots are the recovered strings.
    """
    import string as _s
    from unicorn import (Uc, UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN, UcError, UC_HOOK_CODE,
                         UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE_UNMAPPED,
                         UC_HOOK_MEM_FETCH_UNMAPPED)
    from unicorn.arm64_const import (UC_ARM64_REG_SP, UC_ARM64_REG_PC, UC_ARM64_REG_X0,
        UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X5,
        UC_ARM64_REG_X6, UC_ARM64_REG_X7)
    import struct as _struct

    text_lo = text_va; text_hi = text_va + len(code)
    depth = [0]; hits = set()
    strings_out = emulate_capture_arm64.last_strings = set()
    PR = set(bytes(_s.printable, "ascii")) - set(b"\x0b\x0c\r\n\t")

    try:
        uc = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
        map_image(uc, binary)
        uc.mem_map(STACK, STACK_SIZE); uc.mem_map(SCRATCH, 0x1000000)
        uc.reg_write(UC_ARM64_REG_SP, STACK + STACK_SIZE // 2)
        for r in (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
                  UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7):
            uc.reg_write(r, SCRATCH + 0x8000)

        def snap():
            try: sp = uc.reg_read(UC_ARM64_REG_SP)
            except UcError: return
            try: mem = bytes(uc.mem_read((sp - 0x200) & ~0xf, 0xA00))
            except UcError: return
            cur = bytearray()
            for by in mem:
                if by in PR: cur.append(by)
                else:
                    if len(cur) >= 6: strings_out.add(bytes(cur).decode("ascii", "ignore"))
                    cur = bytearray()
            if len(cur) >= 6: strings_out.add(bytes(cur).decode("ascii", "ignore"))

        def hook_code(uc, address, size, _):
            try: insn = _struct.unpack("<I", uc.mem_read(address, 4))[0]
            except UcError: return
            if (insn & 0xFFFFFC1F) == 0xD65F0000:          # ret {Xn}
                snap()
                if depth[0] == 0: uc.emu_stop()
                else: depth[0] -= 1
                return
            if (insn & 0xFC000000) == 0x94000000:          # bl imm26
                snap()
                imm = insn & 0x03FFFFFF
                if imm & 0x02000000: imm -= 0x04000000
                tgt = (address + imm * 4) & 0xffffffffffffffff
                if text_lo <= tgt < text_hi:
                    depth[0] += 1; return                  # intra-text: execute
                uc.reg_write(UC_ARM64_REG_X0, 0)
                uc.reg_write(UC_ARM64_REG_PC, address + 4); return
            if (insn & 0xFFFFFC1F) == 0xD63F0000:          # blr Xn -> external
                snap()
                uc.reg_write(UC_ARM64_REG_X0, 0)
                uc.reg_write(UC_ARM64_REG_PC, address + 4); return

        def hook_inv(uc, access, address, size, value, _):
            try: uc.mem_map(address & ~0xfff, 0x1000)
            except UcError: pass
            return True

        uc.hook_add(UC_HOOK_CODE, hook_code)
        uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED, hook_inv)
        try:
            uc.emu_start(func_va, text_hi, timeout=3_000_000, count=BUDGET)
        except UcError:
            pass
        snap()
        text = b"\x00".join(s.encode() for s in strings_out)
        for c in canaries:
            if c.encode() in text:
                hits.add(c)
    except Exception:
        pass
    return hits


def _machine(binary):
    try:
        return (binary.header.machine_type.name if hasattr(binary.header, "machine_type")
                else str(binary.header.machine)).upper()
    except Exception:
        return ""


def recover(path, canaries, max_funcs=400):
    binary = lief.parse(str(path))
    text = next((s for s in binary.sections if s.name == ".text"), None)
    if text is None: return {"error": "no .text", "recall": 0, "n": len(canaries)}
    code = bytes(text.content); text_va = text.virtual_address
    arm = "AARCH64" in _machine(binary) or "ARM64" in _machine(binary)
    ranges = function_ranges_arm64 if arm else function_ranges
    capture = emulate_capture_arm64 if arm else emulate_capture
    funcs = ranges(binary, code, text_va)
    found = set()
    for (fva, _) in funcs[:max_funcs]:
        found |= capture(binary, code, text_va, fva, canaries)
        if len(found) == len(canaries): break
    return {"functions_tried": min(len(funcs), max_funcs), "recovered": sorted(found),
            "recall": len(found), "n": len(canaries), "arch": "aarch64" if arm else "x86-64"}

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
