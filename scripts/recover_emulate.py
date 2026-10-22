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
import json, re, sys, string
from pathlib import Path
import lief
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from unicorn import *
from unicorn.x86_const import *
sys.path.insert(0, str(Path(__file__).resolve().parent))
from disasm import linear  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
# printable ASCII runs (space..~) of 6+ bytes: the candidate strings in emulated memory
_PRINTABLE_RUN = re.compile(rb"[\x20-\x7e]{6,}")
PRINT = set(bytes(string.printable, "ascii")) - set(b"\x0b\x0c")

BASE = 0x0                # map image at native VAs (PIE-safe: xref pointer math matches)
STACK = 0x7f0000000000
STACK_SIZE = 0x200000
SCRATCH = 0x10000000     # dummy target for stubbed calls / unmapped reads
BUDGET = 8000            # max instructions per function
# Intra-.text calls are executed only this many levels deep; deeper ones are stubbed like
# external calls. obfstr's load-bearing helper (`xref::inner`) is a direct callee, while a
# statically linked print path (fmt -> stdout lock -> write) is many levels deep and, under
# emulation, can spin in its lock-retry loop until the time limit.
MAX_CALL_DEPTH = 1

class _WrittenMemory:
    """Addresses written during emulation, read back on demand.

    The x86 write hook sees each store's value, but SIMD stores (a vectorised XOR loop writes
    16 bytes at a time) report at most 8 of them, and interleaved stores scramble the stream.
    Reading the written bytes back from emulator memory just before a call -- when a decoded
    buffer is complete and about to be printed or copied -- gives the buffer as it really is.
    """

    def __init__(self, limit=1 << 20):
        self.addrs = set()
        self.limit = limit
        self.dirty = False

    def add(self, address, size):
        if len(self.addrs) < self.limit:
            self.addrs.update(range(address, address + size))
            self.dirty = True

    def snapshot(self, uc, out):
        if not self.dirty:
            return
        self.dirty = False
        run_start = prev = None
        for a in sorted(self.addrs) + [None]:
            if a is not None and prev is not None and a == prev + 1:
                prev = a
                continue
            if run_start is not None:
                try:
                    mem = bytes(uc.mem_read(run_start, prev - run_start + 1))
                except Exception:
                    mem = b""
                for m in _PRINTABLE_RUN.finditer(mem):
                    out.add(m.group().decode("ascii"))
            run_start = prev = a


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

def pdata_ranges(binary, code, text_va):
    """PE x64: every non-leaf function has a RUNTIME_FUNCTION entry in .pdata (begin, end,
    unwind info as RVAs), stripped or not -- the same table Windows uses to unwind the stack.
    COFF symbol values, by contrast, are offsets into their section, not addresses."""
    import struct
    pdata = next((s for s in binary.sections if s.name == ".pdata"), None)
    if pdata is None:
        return []
    raw = bytes(pdata.content)
    lo, hi = text_va, text_va + len(code)
    seen, funcs = set(), []
    for k in range(0, len(raw) - 11, 12):
        begin, end, _unwind = struct.unpack_from("<III", raw, k)
        if lo <= begin < hi and begin < end and begin not in seen:
            seen.add(begin)
            funcs.append((begin, min(end - begin, 0x4000)))
    funcs.sort()
    return funcs


def function_ranges(binary, code, text_va):
    """Yield (start_va, size) for functions: .pdata on PE, else symbols, else split on prologues."""
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    try:
        if binary.format.name == "PE":
            funcs = pdata_ranges(binary, code, text_va)
            if funcs:
                return funcs
    except Exception:
        pass
    funcs = []
    syms = [(s.value, s.name) for s in binary.symbols if s.value and getattr(s, "is_function", False)]
    syms = [(v, n) for v, n in syms if text_va <= v < text_va + len(code)]
    if syms:
        syms.sort()
        for (v, _), nxt in zip(syms, [s[0] for s in syms[1:]] + [text_va + len(code)]):
            funcs.append((v, min(nxt - v, 0x4000)))
    else:
        # stripped: window the whole .text in overlapping chunks from each `push rbp`
        addrs = [ins.address for ins in linear(md, code, text_va)
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
    written = _WrittenMemory()
    last_end = [None]
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
                written.snapshot(uc, strings_out)
                if depth[0] == 0:
                    uc.emu_stop()           # returned from the top-level function
                else:
                    depth[0] -= 1           # returning from an intra-text callee: let it continue
                return
            if b0 == 0xe8 or (b0 == 0xff and j + 1 < len(raw) and (raw[j + 1] >> 3) & 7 in (2, 3)):
                written.snapshot(uc, strings_out)   # a buffer handed to a callee is complete now
            if b0 == 0xe8:                  # call rel32
                import struct
                rel = struct.unpack("<i", raw[j + 1:j + 5])[0]
                tgt = (address + size + rel) & 0xffffffffffffffff
                if lo <= tgt < hi and depth[0] < MAX_CALL_DEPTH:
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
            written.add(address, size)
            # only sequential stores extend the current run: a decoder writing front to back
            # yields the string, while scheduled/vectorised code storing pieces out of order
            # would splice unrelated bytes together (the read-back covers those buffers)
            if address != last_end[0]:
                writes.append(0)
            last_end[0] = address + size
            if size > 8:
                # a SIMD store: Unicorn reports at most 8 bytes of its value, so it would put
                # scrambled bytes into the stream. End the current run instead; the read-back
                # of written memory recovers the buffer whole.
                writes.append(0)
                return
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

        def hook_syscall(uc, _):
            # `syscall` in a statically linked runtime (e.g. write() behind println!): report
            # success (rax = count) instead of letting Unicorn stop on an unhandled instruction
            try: uc.reg_write(UC_X86_REG_RAX, uc.reg_read(UC_X86_REG_RDX))
            except UcError: pass

        uc.hook_add(UC_HOOK_CODE, hook_code)
        uc.hook_add(UC_HOOK_INSN, hook_syscall, None, 1, 0, UC_X86_INS_SYSCALL)
        uc.hook_add(UC_HOOK_MEM_WRITE, hook_write)
        uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED, hook_mem_invalid)

        start = BASE + func_va
        try:
            uc.emu_start(start, BASE + text_va + len(code), timeout=0, count=BUDGET)
        except UcError:
            pass
        written.snapshot(uc, strings_out)

        # scan the recorded write stream (byte-wise decoders write front to back, which gives
        # exact strings) plus scratch + stack memory; SIMD stores are left to the read-back
        blobs = [bytes(writes)]
        for region in (SCRATCH, STACK + STACK_SIZE // 2 - 0x4000):
            try: blobs.append(bytes(uc.mem_read(region, 0x8000)))
            except UcError: pass
        text = b"\x00".join(blobs)
        for c in canaries:
            if c.encode() in text:
                hits.add(c)
        # also surface general printable runs (for analysts without known canaries)
        for m in _PRINTABLE_RUN.finditer(text):
            strings_out.add(m.group().decode("ascii"))
        for st in strings_out:
            for c in canaries:
                if c in st:
                    hits.add(c)
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
        for ins in linear(md, code, text_va):
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
    from unicorn import (Uc, UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN, UcError, UC_HOOK_CODE, UC_HOOK_INTR,
                         UC_HOOK_MEM_WRITE,
                         UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE_UNMAPPED,
                         UC_HOOK_MEM_FETCH_UNMAPPED)
    from unicorn.arm64_const import (UC_ARM64_REG_SP, UC_ARM64_REG_PC, UC_ARM64_REG_X0,
        UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X5,
        UC_ARM64_REG_X6, UC_ARM64_REG_X7)
    import struct as _struct

    text_lo = text_va; text_hi = text_va + len(code)
    depth = [0]; hits = set()
    strings_out = emulate_capture_arm64.last_strings = set()

    try:
        top = STACK + STACK_SIZE // 2
        uc = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
        map_image(uc, binary)
        uc.mem_map(STACK, STACK_SIZE); uc.mem_map(SCRATCH, 0x1000000)
        uc.reg_write(UC_ARM64_REG_SP, top)
        for r in (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
                  UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7):
            uc.reg_write(r, SCRATCH + 0x8000)

        written = _WrittenMemory()

        def hook_write(uc, access, address, size, value, _):
            written.add(address, size)

        def snap():
            written.snapshot(uc, strings_out)
            # the whole live frame: from just below SP up to the stack pointer we started with,
            # so a function that reserves a large frame (`sub sp, sp, #N` before its `stp`) still
            # has its decoded buffers inside the window
            try: sp = uc.reg_read(UC_ARM64_REG_SP)
            except UcError: return
            lo = (sp - 0x200) & ~0xf
            hi = min(max(top + 0x100, lo + 0xA00), lo + 0x40000)
            try: mem = bytes(uc.mem_read(lo, hi - lo))
            except UcError: return
            for m in _PRINTABLE_RUN.finditer(mem):
                strings_out.add(m.group().decode("ascii"))

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
                if text_lo <= tgt < text_hi and depth[0] < MAX_CALL_DEPTH:
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

        def hook_svc(uc, intno, _):
            # `svc #0` in a statically linked runtime (musl's write() behind println!): without
            # this hook Unicorn raises UC_ERR_EXCEPTION and emulation ends after the first
            # string. Pretend the syscall succeeded (x0 = count, as write() returns) and go on.
            snap()
            try: uc.reg_write(UC_ARM64_REG_X0, uc.reg_read(UC_ARM64_REG_X2))
            except UcError: pass

        uc.hook_add(UC_HOOK_CODE, hook_code)
        uc.hook_add(UC_HOOK_INTR, hook_svc)
        uc.hook_add(UC_HOOK_MEM_WRITE, hook_write)
        uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED, hook_inv)
        try:
            uc.emu_start(func_va, text_hi, timeout=0, count=BUDGET)
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


def _score_function(md, code, text_va, fva, size, arm):
    """Cheap static prior for 'does this function decode something?', used to order emulation.

    Like FLOSS's function scoring (floss/identify.py), it looks for decoder features rather than
    trying every function in address order: 64-bit immediates (obfstr embeds its per-literal keys
    as `movabs` / `movz`+`movk` constants) and non-zeroing XOR/EOR. Functions without either are
    still emulated, just after the ones that have them, so a cap on the number of functions no
    longer cuts off a decoder that happens to sit late in .text.
    """
    off = fva - text_va
    chunk = code[off:off + min(size, 0x2000)]
    imm64 = xors = 0
    for ins in md.disasm_lite(chunk, fva):
        _, _, mn, ops = ins
        if arm:
            if mn == "movk":
                imm64 += 1
            elif mn == "eor":
                parts = [p.strip() for p in ops.split(",")]
                if len(parts) == 3 and parts[1] != parts[2]:
                    xors += 1
        else:
            if mn == "movabs" and "0x" in ops:
                imm64 += 1
            elif mn in ("xor", "pxor", "xorps", "xorpd", "vpxor", "vxorps", "vpxord", "vpxorq"):
                parts = [p.strip() for p in ops.split(",")]
                if len(set(parts)) > 1:
                    xors += 1
    return 2 * imm64 + xors


def _static_cover(file_bytes, min_piece=4, min_edge=1, max_pieces=3):
    """Return a predicate: is a candidate just static data that emulation copied around?

    A string that occurs in the file is a static string, not a decoded one (FLOSS's rule). Copies
    also splice static pieces together -- `_ITM_deregisterTMCloneTable` and `__libc_start_main`
    written next to each other leave `TM_deregisterTMCibc_start_main` -- so a candidate that
    greedy longest-match covers with at most `max_pieces` file substrings is treated as static
    too. Interior pieces must be `min_piece`+ bytes; the first and last may be as short as
    `min_edge` (a copy that starts or ends mid-word). Real decoded text is not in the file at
    all, or only in many short pieces.
    """
    def explained(st):
        b = st.encode("ascii", "ignore")
        if b in file_bytes:
            return True
        # a fake argument the emulator passed (out-pointers point into SCRATCH) that the code
        # formatted into text, e.g. "/proc/self/fd/268468224"
        if any(a in st for a in _EMULATOR_VALUES):
            return True
        # static text plus a number the emulator made up (a fake pointer or fd formatted into a
        # path, e.g. "/proc/self/fd/" + the scratch address) is static too
        stem = b.rstrip(b"0123456789abcdefABCDEFx")
        if len(stem) >= 6 and len(stem) < len(b) and stem in file_bytes:
            return True
        i, pieces = 0, []
        while i < len(b):
            n = 1
            if b[i:i + 1] not in file_bytes:
                return False
            while i + n < len(b) and b[i:i + n + 1] in file_bytes:
                n += 1
            pieces.append(n)
            i += n
            if len(pieces) > max_pieces:
                return False
        inner = pieces[1:-1]
        if any(n < min_piece for n in inner):
            return False
        if len(pieces) > 1 and (pieces[0] < min_edge or pieces[-1] < min_edge):
            return False
        # every piece but the edges carries real weight: an edge-only explanation is not enough
        return sum(pieces) - (pieces[0] if pieces[0] < min_piece else 0) \
            - (pieces[-1] if len(pieces) > 1 and pieces[-1] < min_piece else 0) >= min_piece * max(1, len(pieces) - 1)

    return explained


_EMULATOR_VALUES = tuple(
    fmt % v for v in (SCRATCH, SCRATCH + 0x8000, STACK, STACK + STACK_SIZE // 2)
    for fmt in ("%d", "%x", "%#x"))


def _drop_overlap_artifacts(records):
    """Resolve views of a buffer that was partially overwritten or seen mid-write.

    Rust strings are not NUL-terminated, so when P is a prefix of S, either
      - S = P + a stale tail: a shorter string was written over a longer one, or into memory
        that held another string (stubbed allocators hand out the same block), and the tail is
        a piece of another recovered string (`...version-4` + `lemetry-offbin`,
        `...telemetry-off` + `lpha::7`) -> drop S and the shorter views of S's buffer; or
      - P is S seen before its decode finished (`canary::alpha::7f3c-`)          -> drop P.
    A view that diverges from a longer string only in its last few characters is the same
    buffer read mid-decode with ciphertext after the decoded part (`canary::echo::sc%{` next
    to `canary::echo::schema-version-4`) -> drop it. Then pieces of a surviving string (a
    suffix or the middle, from out-of-order stores) go.
    """
    texts = {r["string"] for r in records}
    stale, partial = set(), set()
    for p in texts:
        if len(p) < 6:
            continue
        for s in texts:
            if s == p or not s.startswith(p):
                continue
            tail = s[len(p):]
            if any(tail in o and o not in (s, tail) and not o.startswith(p) for o in texts):
                stale.add(s)
            else:
                partial.add(p)
    garbled = set()
    for x in texts:
        for y in texts:
            if x == y or len(y) <= len(x) or y.startswith(x) or x.startswith(y):
                continue
            k = 0
            while k < len(x) and x[k] == y[k]:
                k += 1
            if k >= 12 and len(x) - k <= 3 and len(y) - k > len(x) - k:
                garbled.add(x)
    drop = stale | partial | garbled
    drop |= {t for t in texts for s in stale if t != s and s.endswith(t)}
    keep = [r for r in records if r["string"] not in drop]
    alive = {r["string"] for r in keep}
    return [r for r in keep if not any(o != r["string"] and r["string"] in o for o in alive)]


def _static_bytes(path):
    try:
        return Path(path).read_bytes()
    except OSError:
        return b""


def recover(path, canaries, max_funcs=400, time_budget=None):
    """Emulate functions and collect the strings they materialise in memory.

    Returns, besides the canary bookkeeping used by the benchmark, ``recovered_texts`` and
    ``records`` ({"string", "function", "method"}): every text-like string written during
    emulation that does not already occur in the file. That last filter is FLOSS's rule for
    decoded strings (static strings are reported by `strings`, not here), and it is what keeps
    stack copies of ordinary .rodata literals out of the output when no canaries are known.
    """
    from recover_callsite import looks_like_text
    binary = lief.parse(str(path))
    text = next((s for s in binary.sections if s.name == ".text"), None)
    if text is None:
        return {"error": "no .text", "recall": 0, "n": len(canaries), "recovered_texts": [], "records": []}
    code = bytes(text.content); text_va = text.virtual_address
    arm = "AARCH64" in _machine(binary) or "ARM64" in _machine(binary)
    ranges = function_ranges_arm64 if arm else function_ranges
    capture = emulate_capture_arm64 if arm else emulate_capture
    funcs = ranges(binary, code, text_va)

    if arm:
        from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
        md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    else:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
    scores = {fva: _score_function(md, code, text_va, fva, size, arm) for fva, size in funcs}
    order = sorted(funcs, key=lambda f: (-scores[f[0]], f[0]))

    file_bytes = _static_bytes(path)
    explained = _static_cover(file_bytes)
    found = set()
    records, seen_strings = [], set()
    tried = 0
    import time as _time
    deadline = _time.monotonic() + time_budget if time_budget else None
    timed_out = False
    import gc
    for (fva, _) in order[:max_funcs]:
        if deadline is not None and _time.monotonic() > deadline:
            timed_out = True
            break
        if tried % 16 == 0:
            # each emulation's Uc sits in a reference cycle (hook closures); collect them
            # before their native memory runs out (UC_ERR_NOMEM on mem_map, which made
            # later functions -- and later binaries in the same process -- yield nothing)
            gc.collect()
        tried += 1
        found |= capture(binary, code, text_va, fva, canaries)
        for st in sorted(getattr(capture, "last_strings", ()) or ()):
            if st in seen_strings or not looks_like_text(st.encode("ascii", "ignore")):
                continue
            if explained(st):
                continue
            seen_strings.add(st)
            records.append({"string": st, "function": fva, "method": "emulation"})
        if canaries and len(found) == len(canaries):
            break
    records = _drop_overlap_artifacts(records)
    return {"functions_tried": tried, "functions_total": len(funcs), "timed_out": timed_out,
            "recovered": sorted(found),
            "recall": len(found), "n": len(canaries), "arch": "aarch64" if arm else "x86-64",
            "recovered_texts": [r["string"] for r in records], "records": records}

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
