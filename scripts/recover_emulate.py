#!/usr/bin/env python3
"""Emulation-based string recoverer (Unicorn) for Rust binaries, x86-64 and AArch64.

The static call-site recoverers read a decoder's key and each call's ciphertext straight out of
the instructions. That only works while the compiler emits the shapes they look for, and the
shapes move with the build profile: under `opt-level="z"` lengths arrive as `push 0xf; pop rdx`,
litcrypt's key lives in an iterator struct and the XOR sits in that iterator's `next()`, LTO
inlines some decoders and outlines others. This module does not depend on any of that. It runs
the code and collects the plaintext the program itself builds in memory, the approach FLOSS takes
for C/C++ -- with the pieces Rust code needs:

* **Every function is a start point.** Function starts come from `.pdata` (PE), `.eh_frame_hdr`
  (ELF, present even when stripped), symbols, and direct call targets. Functions are ordered by
  decoder features (64-bit immediates, non-zeroing XOR, pointers to ciphertext-looking data,
  calls into functions that XOR) and emulated until the time budget runs out; there is no fixed
  cap on the number of functions.
* **Real calls.** Calls inside `.text` are executed up to `MAX_DEPTH` levels deep, so a call site
  runs its out-of-line decoder (`lc!` -> `decrypt_bytes` -> `Iterator::next`). Callees have
  instruction budgets; a callee that overruns its budget (a formatter spinning on a lock, a loop
  over a fake length) or faults is abandoned and the caller resumes with its registers
  restored, as if the callee had returned 0.
* **A loader and a C runtime.** Relocations are applied (ELF RELATIVE/GLOB_DAT/JUMP_SLOT, PE
  base relocations), every import slot points at a named trampoline, `.bss` is zero and the
  thread pointer is set. Allocators (`malloc`, `HeapAlloc`, `__rust_alloc`, ...) return fresh,
  zeroed, separated blocks, `memcpy` / `memmove` / `memset` / `memcmp` / `bcmp` / `strlen` do
  what they say, `brk`/`mmap` work, environment variables are unset; in stripped static (musl)
  builds these functions are found by byte signature (gen_runtime_sigs.py). Every other import
  returns 0.
* **Path exploration.** Strings that are only built in one `match` arm, or on a branch that never
  runs, are reached by re-running a function with forward conditional branches forced the other
  way (breadth-first over flip sets, bounded per function).
* **Capture.** Every store is tracked with its age (capture generation). Before calls made by the
  emulated function, at stubbed calls, when a callee returns to it and when it returns, the bytes
  written since the last capture are read back from emulator memory, extended through adjacent
  written bytes and cut where an older write follows a newer one, so a buffer decoded byte by
  byte, by SIMD stores, or across several calls comes back whole and a stale tail does not. The
  (pointer, length) pairs the code passes on give a Rust string's exact end.

A string is reported when it is text-like (including indicator shapes: IPs, paths, mutex names)
and not already in the file -- FLOSS's rule for decoded strings. Nothing runs natively; the
sample is never executed. AEAD-encrypted strings (muddy's ChaCha20-Poly1305) decrypt in emulation
as well: the whole decrypt path is reachable from the function that uses them.
"""
from __future__ import annotations
from array import array
import gc
import json
import re
import string
import struct
import sys
import time
from collections import deque
from pathlib import Path

import lief
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from unicorn import (Uc, UcError, UC_ARCH_X86, UC_ARCH_ARM64, UC_MODE_64, UC_MODE_ARM,
                     UC_HOOK_BLOCK, UC_HOOK_MEM_WRITE, UC_HOOK_INSN, UC_HOOK_INTR,
                     UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE_UNMAPPED,
                     UC_HOOK_MEM_FETCH_UNMAPPED)
from unicorn import x86_const as X
from unicorn import arm64_const as A

sys.path.insert(0, str(Path(__file__).resolve().parent))

ROOT = Path(__file__).resolve().parent.parent
_SIGS = Path(__file__).resolve().parent / "data" / "runtime_sigs.json"
_PRINTABLE_RUN = re.compile(rb"[\x20-\x7e]{6,}")
PRINT = set(bytes(string.printable, "ascii")) - set(b"\x0b\x0c")

BASE = 0x0                # map image at native VAs (PIE-safe: obfstr's xref pointer math matches)
STACK = 0x7f0000000000
STACK_SIZE = 0x200000
SCRATCH = 0x10000000      # fake pointer arguments point here
SCRATCH_SIZE = 0x1000000
HEAP = 0x30000000         # bump allocator for malloc/HeapAlloc/__rust_alloc/mmap
HEAP_SIZE = 0x4000000
TLS = 0x50000000          # thread pointer block (fs/gs base on x86-64, TPIDR_EL0 on AArch64)
TLS_SIZE = 0x20000
TRAMP = 0x7e000000        # one 16-byte `ret` trampoline per import
TRAMP_SIZE = 0x100000
BRK = 0x60000000          # program break for brk()
BUDGET = 40000            # instructions per run of one function
FRAME_BUDGET = 20000      # instructions a direct callee (with everything below it) may use
INNER_BUDGET = 6000       # ... and any deeper callee: a lock spinning in std is cut off there
MAX_DEPTH = 8             # call levels executed below the emulated function
MAX_RUNS = 8              # runs per function (1 natural + forced-branch runs)
WRITE_BUDGET = 1 << 21    # bytes one run may store
FUNC_SECONDS = 30.0       # wall-clock safety cap per function (runs are bounded by MAX_RUNS)
# kept for compatibility with callers that imported the old constant
MAX_CALL_DEPTH = MAX_DEPTH

_ALLOC = {"malloc": (0,), "rust_alloc": (0,), "rdl_alloc": (0,), "rg_alloc": (0,),
          "rust_alloc_zeroed": (0,), "rdl_alloc_zeroed": (0,), "aligned_alloc": (1,),
          "heapalloc": (2,), "localalloc": (1,), "globalalloc": (1,), "virtualalloc": (1,),
          "cotaskmemalloc": (0,)}
_FREE = {"free", "rust_dealloc", "rdl_dealloc", "heapfree", "localfree", "globalfree",
         "virtualfree", "cotaskmemfree"}


def _norm(name):
    return name.split("@")[0].lstrip("_").lower() if name else ""


# --------------------------------------------------------------------------------------------
# the binary
# --------------------------------------------------------------------------------------------

class Image:
    """A parsed binary: code, data sections, imports and function starts."""

    def __init__(self, path):
        self.path = Path(path)
        self.binary = b = lief.parse(str(path))
        if b is None:
            raise ValueError("unparseable")
        self.text = next((s for s in b.sections if s.name == ".text"), None)
        if self.text is None:
            raise ValueError("no .text")
        self.code = bytes(self.text.content)
        self.text_va = self.text.virtual_address
        self.text_end = self.text_va + len(self.code)
        self.fmt = b.format.name
        self.pe = self.fmt == "PE"
        self.arm = any(t in _machine(b) for t in ("AARCH64", "ARM64"))
        self.md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN) if self.arm else Cs(CS_ARCH_X86, CS_MODE_64)
        self.file_bytes = _static_bytes(path)
        self.data = []      # (va, bytes) of non-executable sections, for the ciphertext feature
        for s in b.sections:
            if not s.virtual_address or not s.size or s.name in (".text", ".bss", ".tbss"):
                continue
            if self.pe:
                exe = bool(int(s.characteristics) & 0x20000000)
            else:
                exe = bool(int(s.flags) & 0x4)
            if not exe:
                self.data.append((s.virtual_address, _content(s)))
        self.data.sort()
        vas = [s.virtual_address for s in b.sections if s.virtual_address]
        self.imagebase = b.optional_header.imagebase if self.pe else 0
        self.span = (self.imagebase + min(vas, default=0),
                     self.imagebase + max((s.virtual_address + s.size for s in b.sections), default=0))
        self.exec_ranges = []
        for sec in b.sections:
            if not sec.virtual_address or not sec.size:
                continue
            ex = (int(sec.characteristics) & 0x20000000) if self.pe else (int(sec.flags) & 0x4)
            if ex:
                self.exec_ranges.append((sec.virtual_address, sec.virtual_address + sec.size))
        self.named = {}     # va -> name of a C-runtime function linked into .text (static builds)
        try:
            known = set(_ALLOC) | _FREE | {"calloc", "realloc", "memcpy", "memmove", "memset", "memcmp",
                                           "bcmp", "strlen", "posix_memalign"}
            for va, nm in self.function_symbols():
                if self.text_va <= va < self.text_end and _norm(nm) in known:
                    self.named[va] = nm
        except Exception:
            pass
        self.patches = {}   # va -> 8-byte value written after mapping (relocations, import slots)
        self.tramp = []     # import names; import i lives at TRAMP + 16*i
        self._relocate()
        self.lse_flags = self._lse_flags() if self.arm else []

    def _lse_flags(self):
        """Addresses of the `__aarch64_have_lse_atomics` byte the outlined-atomic helpers test.

        Each `__aarch64_cas4_acq`-style helper starts `adrp x16, flag; ldrb w16, [x16, #lo];
        cbz w16, <LL/SC loop>`. The flag is set by a constructor reading AT_HWCAP, which never
        runs here; left at 0, every atomic takes the `ldaxr`/`stxr` path, whose exclusive access
        to a fake pointer raises a data abort and ends the run inside std's locks. Setting it
        selects the LSE instruction (`casa`, `swpal`, ...), which the ARM64_MAX CPU executes."""
        out = set()
        words = struct.unpack_from(f"<{len(self.code) // 4}I", self.code)
        for i in range(len(words) - 2):
            w0 = words[i]
            if (w0 & 0x9f00001f) != 0x90000010:            # adrp x16
                continue
            w1, w2 = words[i + 1], words[i + 2]
            if (w1 & 0xffc003ff) != 0x39400210 or (w2 & 0xff00001f) != 0x34000010:
                continue                                    # ldrb w16, [x16, #imm]; cbz w16
            imm = (((w0 >> 5) & 0x7ffff) << 2) | ((w0 >> 29) & 3)
            if imm & (1 << 20):
                imm -= 1 << 21
            pc = self.text_va + 4 * i
            out.add((pc & ~0xfff) + (imm << 12) + ((w1 >> 10) & 0xfff))
        return sorted(out)[:4]

    def _import(self, name):
        self.tramp.append(name or "?")
        return TRAMP + 16 * (len(self.tramp) - 1)

    def _relocate(self):
        """Apply the relocations the loader would, and point every import at a named trampoline.

        Rust calls `__rust_alloc` and friends through the GOT, vtables and fmt tables hold
        absolute pointers, and the formatter is reached as `call r15` from a GOT slot: without
        relocations all of those are 0. Imports (IAT entries, GOT slots of undefined symbols) get
        a distinct trampoline address each, so direct, PLT, GOT and register-indirect calls to an
        import all land on one place where the emulator knows the import's name.
        """
        b = self.binary
        try:
            if self.pe:
                ib = b.optional_header.imagebase
                for imp in b.imports:
                    for e in imp.entries:
                        nm = e.name if e.name else f"{imp.name}#{e.ordinal}"
                        self.patches[e.iat_address] = self._import(nm)
                for blk in b.relocations:
                    for e in blk.entries:
                        if str(e.type).endswith("DIR64"):
                            raw = self.read_any(e.address, 8)
                            if len(raw) == 8:
                                v = struct.unpack("<Q", raw)[0]
                                if v >= ib:
                                    self.patches[e.address] = v - ib
                return
            for r in b.relocations:
                t = str(r.type)
                if t.endswith("_RELATIVE"):
                    self.patches[r.address] = r.addend
                elif t.endswith(("_GLOB_DAT", "_JUMP_SLOT", "_X86_64_64", "_ABS64")) and r.has_symbol:
                    sym = r.symbol
                    if sym.value:
                        self.patches[r.address] = sym.value + r.addend
                    elif sym.name:
                        self.patches[r.address] = self._import(sym.name)
        except Exception:
            pass

    def read_any(self, va, n):
        for s in self.binary.sections:
            if s.virtual_address <= va < s.virtual_address + len(s.content):
                o = va - s.virtual_address
                return bytes(s.content[o:o + n])
        return b""

    def executable(self, va):
        if self.text_va <= va < self.text_end:
            return True
        return any(lo <= va < hi for lo, hi in self.exec_ranges)

    def function_symbols(self):
        """[(va, name)] of function symbols. COFF symbol values are offsets into their section."""
        out = []
        try:
            secs = list(self.binary.sections)
            for sym in self.binary.symbols:
                if not sym.value:
                    continue
                if self.pe:
                    idx = getattr(sym, "section_idx", 0)
                    if not 0 < idx <= len(secs) or not getattr(sym, "is_function", False):
                        continue
                    out.append((secs[idx - 1].virtual_address + sym.value, sym.name))
                elif getattr(sym, "is_function", False):
                    out.append((sym.value, sym.name))
        except Exception:
            pass
        return out

    def code_constants(self):
        """AArch64 builds constants in registers with `movz`/`movk` (16 bits at a time), so a
        string the code stores from immediates -- musl's "/proc/self/fd/", a plain stack string --
        is not in the file as bytes. Rebuild those constants so such text counts as static, the
        way it already does on x86-64, where `movabs` keeps the 8 bytes together."""
        if not self.arm:
            return b""
        out, regs, stores = [], {}, {}
        _W = {"str": None, "stur": None, "strh": 2, "sturh": 2, "strb": 1, "sturb": 1, "stp": None}

        def flush():
            for base, offs in stores.items():
                run, end = b"", None
                for off in sorted(offs):
                    if end is not None and off != end:
                        out.append(run)
                        run = b""
                    run += offs[off]
                    end = off + len(offs[off])
                out.append(run)
            stores.clear()

        for addr, size, mn, ops in _linear_lite(self.md, self.code, self.text_va):
            parts = [p.strip() for p in ops.split(",")]
            if mn in ("movz", "movk", "mov") and len(parts) >= 2 and parts[1].startswith("#"):
                try:
                    imm = int(parts[1][1:], 0) & ((1 << 64) - 1)
                except ValueError:
                    continue
                sh = int(parts[2].split("#")[1], 0) if len(parts) > 2 and "lsl" in parts[2] else 0
                r = "x" + parts[0][1:]
                regs[r] = (regs.get(r, 0) & ~(0xffff << sh) | (imm << sh)) if mn == "movk" else imm << sh
                continue
            if mn in _W and "[" in ops:
                srcs = parts[:2] if mn == "stp" else parts[:1]
                mem = ops[ops.index("[") + 1:ops.index("]")].split(",")
                base = mem[0].strip()
                try:
                    off = int(mem[1].strip().lstrip("#"), 0) if len(mem) > 1 else 0
                except ValueError:
                    continue                      # register offset: not a constant layout
                for r in srcs:
                    if r in ("xzr", "wzr"):
                        val, w = 0, 8 if r[0] == "x" else 4
                    elif ("x" + r[1:]) in regs:
                        val, w = regs["x" + r[1:]], 8 if r[0] == "x" else 4
                    else:
                        off += 8 if r[0] == "x" else 4
                        continue
                    w = _W[mn] or w
                    stores.setdefault(base, {})[off] = (val & ((1 << (8 * w)) - 1)).to_bytes(w, "little")
                    off += w
                continue
            if mn in ("bl", "blr", "b", "br", "ret", "cbz", "cbnz", "tbz", "tbnz") or mn.startswith("b."):
                flush()
                regs.clear()
        flush()
        return b"\0" + b"\0".join(out)

    def call_targets(self):
        """Targets of direct calls in .text (exact: decoded, not byte-scanned)."""
        if getattr(self, "_calls", None) is not None:
            return self._calls
        lo, hi = self.text_va, self.text_end
        out = set()
        if self.arm:
            code = self.code
            for k, (w,) in enumerate(struct.iter_unpack("<I", code[:len(code) & ~3])):
                if (w & 0xFC000000) == 0x94000000:
                    imm = w & 0x03FFFFFF
                    t = lo + 4 * k + 4 * (imm - 0x04000000 if imm & 0x02000000 else imm)
                    if lo <= t < hi:
                        out.add(t)
        else:
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            for addr, size, mn, ops in _linear_lite(md, self.code, lo):
                if mn == "call" and ops.startswith("0x"):
                    t = int(ops, 16)
                    if lo <= t < hi:
                        out.add(t)
        self._calls = out
        return out

    def _match_runtime(self, starts):
        """Name the C-runtime functions of a stripped static build by byte signature
        (scripts/data/runtime_sigs.json, made by gen_runtime_sigs.py)."""
        if getattr(self, "_sigs_done", False):
            return
        self._sigs_done = True
        try:
            sigs = json.loads(_SIGS.read_text()).get("aarch64" if self.arm else "x86_64", [])
        except (OSError, ValueError):
            return
        if not sigs:
            return
        from gen_runtime_sigs import matches
        cands = set(starts)
        if not self.tramp:
            # static build: musl's own functions carry no unwind info, so take every direct call
            # target as a candidate start too (only for signature matching)
            code, base = self.code, self.text_va
            if self.arm:
                for k, (w,) in enumerate(struct.iter_unpack("<I", code[:len(code) & ~3])):
                    if (w & 0x7C000000) == 0x14000000:          # bl and b (tail calls)
                        imm = w & 0x03FFFFFF
                        cands.add(base + 4 * k + 4 * (imm - 0x04000000 if imm & 0x02000000 else imm))
            else:
                for op in (b"\xe8", b"\xe9"):                  # call and jmp (tail calls)
                    i = code.find(op)
                    while i != -1 and i + 5 <= len(code):
                        t = base + i + 5 + struct.unpack_from("<i", code, i + 1)[0]
                        if base <= t < base + len(code):
                            cands.add(t)
                        i = code.find(op, i + 1)
        for a in sorted(cands):
            off = a - self.text_va
            if not 0 <= off < len(self.code) or a in self.named:
                continue
            chunk = self.code[off:off + 64]
            for sig in sigs:
                if matches(sig["pattern"], chunk):
                    self.named[a] = sig["name"]
                    break

    def read(self, va, n):
        i = _bisect_le(self.data, va)
        if i is None:
            return b""
        base, blob = self.data[i]
        if va - base < len(blob):
            return blob[va - base:va - base + n]
        return b""

    def functions(self):
        """[(start_va, size)] for every function we can find, in address order."""
        lo, hi = self.text_va, self.text_end
        starts = set()
        if self.pe:
            starts.update(f for f, _ in pdata_ranges(self.binary, self.code, self.text_va))
        else:
            starts.update(a for a in _eh_frame_starts(self.binary) if lo <= a < hi)
        starts.update(a for a, _ in self.function_symbols() if lo <= a < hi)
        # leaf functions need no unwind entry (`lea rsi,[ct]; push 0x24; pop rdx; jmp decrypt`
        # under opt-level="z" has none in .pdata): every direct call target is a function too
        starts.update(self.call_targets())
        if not starts:
            # no unwind table, no symbols: direct call targets plus classic prologues
            for addr, size, mn, ops in self.md.disasm_lite(self.code, self.text_va):
                if mn in ("call", "bl") and (ops.startswith("0x") or ops.startswith("#0x")):
                    try:
                        t = int(ops.lstrip("#"), 16)
                    except ValueError:
                        continue
                    if lo <= t < hi:
                        starts.add(t)
                elif (mn == "push" and ops in ("rbp", "r15")) or (mn == "stp" and "x29, x30" in ops):
                    starts.add(addr)
        starts = sorted(starts)
        self._match_runtime(starts)
        cap = 0x8000 if self.arm else 0x4000
        return [(a, min(n - a, cap)) for a, n in zip(starts, starts[1:] + [hi])]


def _linear_lite(md, code, base):
    """disasm_lite over a whole section, resuming one byte past anything undecodable."""
    off, n = 0, len(code)
    while off < n:
        end = off
        for ins in md.disasm_lite(code[off:], base + off):
            yield ins
            end = ins[0] - base + ins[1]
        off = end + 1 if end < n else n


def _bisect_le(pairs, va):
    lo, hi = 0, len(pairs)
    while lo < hi:
        mid = (lo + hi) // 2
        if pairs[mid][0] <= va:
            lo = mid + 1
        else:
            hi = mid
    return lo - 1 if lo else None


def _eh_frame_starts(binary):
    """Function starts from .eh_frame_hdr's binary-search table (kept in stripped ELF)."""
    sec = next((s for s in binary.sections if s.name == ".eh_frame_hdr"), None)
    if sec is None:
        return []
    data, va = bytes(sec.content), sec.virtual_address
    if len(data) < 12 or data[0] != 1:
        return []

    def rd(enc, off):
        fmt, app = enc & 0x0f, enc & 0x70
        if fmt == 0x0b:
            v, n = struct.unpack_from("<i", data, off)[0], 4
        elif fmt == 0x03:
            v, n = struct.unpack_from("<I", data, off)[0], 4
        elif fmt == 0x0c:
            v, n = struct.unpack_from("<q", data, off)[0], 8
        elif fmt in (0x04, 0x00):
            v, n = struct.unpack_from("<Q", data, off)[0], 8
        else:
            raise ValueError(enc)
        base = va + off if app == 0x10 else va if app == 0x30 else 0
        return v + base, off + n

    try:
        _, ptr_enc, cnt_enc, tbl_enc = data[:4]
        _, off = rd(ptr_enc, 4)
        if cnt_enc == 0xff or tbl_enc == 0xff:
            return []
        count, off = rd(cnt_enc, off)
        out = []
        for _ in range(min(count, 1 << 20)):
            loc, off = rd(tbl_enc, off)
            _, off = rd(tbl_enc, off)
            out.append(loc)
        return out
    except (ValueError, struct.error):
        return []


def _machine(binary):
    try:
        return (binary.header.machine_type.name if hasattr(binary.header, "machine_type")
                else str(binary.header.machine)).upper()
    except Exception:
        return ""


def _static_bytes(path):
    try:
        return Path(path).read_bytes()
    except OSError:
        return b""


def _content(s):
    """Section bytes as loaded: zeros for NOBITS (.bss/.tbss), whose `content` LIEF fills with
    whatever follows in the file (a .comment string in a mutex's place)."""
    try:
        if str(getattr(s, "type", "")).endswith("NOBITS"):
            return b"\x00" * s.size
    except Exception:
        pass
    c = bytes(s.content)
    n = max(s.size, getattr(s, "virtual_size", 0) or 0)      # PE: zero-filled up to virtual size
    return c + b"\x00" * max(0, n - len(c))


def map_image(uc, binary):
    """Map every section at its virtual address (rebased under BASE window)."""
    pages = {}
    for s in binary.sections:
        if s.size == 0 or s.virtual_address == 0:
            continue
        va = BASE + s.virtual_address
        start = va & ~0xfff
        end = (va + max(len(bytes(s.content)), s.size) + 0xfff) & ~0xfff
        for p in range(start, end, 0x1000):
            pages[p] = True
    run = None
    for p in sorted(pages) + [None]:          # map contiguous page runs in one call
        if run and p == run[1]:
            run[1] = p + 0x1000
            continue
        if run:
            try:
                uc.mem_map(run[0], run[1] - run[0])
            except UcError:
                for q in range(run[0], run[1], 0x1000):
                    try:
                        uc.mem_map(q, 0x1000)
                    except UcError:
                        pass
        run = [p, p + 0x1000] if p is not None else None
    for s in binary.sections:
        c = _content(s)
        if c and s.virtual_address:
            try:
                uc.mem_write(BASE + s.virtual_address, c)
            except UcError:
                pass


# --------------------------------------------------------------------------------------------
# what was written
# --------------------------------------------------------------------------------------------

class _Writes:
    """Every byte the emulated code stored, and which of them are new since the last capture.

    A capture reads the new bytes back from emulator memory (the write hook sees at most 8 bytes
    of a SIMD store's value, and out-of-order stores scramble a value stream) and extends each
    piece through neighbouring bytes that were also written, so a string decoded in several steps
    is read whole, and static bytes that merely sit next to it are not glued on.
    """

    def __init__(self):
        self.pages = {}       # page -> array of (capture generation + 1) of each byte's last write
        self.dirty = []
        self.gen = 1

    def add(self, address, size):
        if size <= 0 or size > 4096:
            return
        self.dirty.append((address, size))
        end = address + size
        a = address
        g = self.gen
        while a < end:
            pg = self.pages.get(a >> 12)
            if pg is None:
                if len(self.pages) > 1 << 12:      # 16 MB of written pages: stop tracking
                    return
                pg = self.pages[a >> 12] = array("I", bytes(4 * 4096))
            o = a & 0xfff
            n = min(end - a, 4096 - o)
            pg[o:o + n] = array("I", [g]) * n
            a += n

    def written(self, a):
        pg = self.pages.get(a >> 12)
        return bool(pg and pg[a & 0xfff])

    def generation(self, a):
        pg = self.pages.get(a >> 12)
        return pg[a & 0xfff] if pg else 0

    def capture(self, uc, out):
        if not self.dirty:
            return
        spans = sorted(self.dirty)
        self.dirty = []
        self.gen += 1
        merged = []
        for a, n in spans:
            if merged and a <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], a + n)
            else:
                merged.append([a, a + n])
        cache = {}

        def page(p):
            if p not in cache:
                try:
                    cache[p] = bytes(uc.mem_read(p << 12, 4096))
                except UcError:
                    cache[p] = None
            return cache[p]

        def byte(x):
            pg = page(x >> 12)
            return None if pg is None else pg[x & 0xfff]

        for a, b in merged:
            s, e = a, b
            while a - s < 4096 and self.written(s - 1):
                c = byte(s - 1)
                if c is None or not 0x20 <= c <= 0x7e:
                    break
                s -= 1
            while e - b < 4096 and self.written(e):
                c = byte(e)
                if c is None or not 0x20 <= c <= 0x7e:
                    break
                e += 1
            buf = bytearray()
            x = s
            while x < e:
                pg = page(x >> 12)
                n = min(e - x, 4096 - (x & 0xfff))
                buf += pg[x & 0xfff:(x & 0xfff) + n] if pg is not None else b"\x00" * n
                x += n
            for m in _PRINTABLE_RUN.finditer(bytes(buf)):
                for piece in self._split(s + m.start(), m.group()):
                    out.add(piece)

    def _split(self, start, run):
        """Cut a printable run where it mixes writes of different ages.

        A string written over part of an older, longer one leaves `new + old tail`; one written
        into the middle of another leaves `old head + new + old tail`. Bytes of one decode are
        written together (one capture generation), or one or two at a time when a string is built
        by pushes -- so a run is cut where the generation goes down, and where it goes up between
        two pieces that were each written in one go (4+ bytes)."""
        gens = [self.generation(start + i) for i in range(len(run))]
        segs = []                               # [start index, end index, generation]
        for i, g in enumerate(gens):
            if segs and segs[-1][2] == g:
                segs[-1][1] = i + 1
            else:
                segs.append([i, i + 1, g])
        pieces, cur = [], segs[0][0]
        for a, b in zip(segs, segs[1:]):
            if b[2] < a[2]:
                pieces.append(run[cur:b[0]])
                cur = b[0]
        pieces.append(run[cur:])
        out = [p.decode("ascii") for p in pieces if len(p) >= 6]
        return out if len(pieces) > 1 else [run.decode("ascii")]


# --------------------------------------------------------------------------------------------
# the emulator
# --------------------------------------------------------------------------------------------

def _s32(b):
    return struct.unpack("<i", b)[0]


def _x86_classify(raw):
    """Control-flow class of one x86-64 instruction from its bytes: (kind, rel_or_slot_disp).

    kind: ret | call | icall | icall_rip | jmp | ijmp | ijmp_rip | jcc | syscall. Prefixes are
    skipped first: `call r15` is `41 ff d7`, and missing the REX byte lets an external call run
    into an unrelocated GOT slot.
    """
    j, n = 0, len(raw)
    while j < n and (0x40 <= raw[j] <= 0x4f or raw[j] in (0x66, 0xf2, 0xf3, 0x2e, 0x3e)):
        j += 1
    if j >= n:
        return None
    b0 = raw[j]
    if b0 in (0xc3, 0xc2):
        return ("ret", 0)
    if b0 == 0xe8 and j + 5 <= n:
        return ("call", _s32(raw[j + 1:j + 5]))
    if b0 == 0xe9 and j + 5 <= n:
        return ("jmp", _s32(raw[j + 1:j + 5]))
    if b0 == 0xeb and j + 2 <= n:
        return ("jmp", struct.unpack("b", raw[j + 1:j + 2])[0])
    if 0x70 <= b0 <= 0x7f and j + 2 <= n:
        return ("jcc", struct.unpack("b", raw[j + 1:j + 2])[0])
    if b0 == 0x0f and j + 1 < n:
        b1 = raw[j + 1]
        if 0x80 <= b1 <= 0x8f and j + 6 <= n:
            return ("jcc", _s32(raw[j + 2:j + 6]))
        if b1 == 0x05:
            return ("syscall", 0)
    if b0 == 0xff and j + 1 < n:
        modrm = raw[j + 1]
        reg = (modrm >> 3) & 7
        if reg in (2, 3, 4, 5):
            call = reg in (2, 3)
            if modrm & 0xc7 == 0x05 and j + 6 <= n:          # [rip + disp32]
                return ("icall_rip" if call else "ijmp_rip", _s32(raw[j + 2:j + 6]))
            return ("icall" if call else "ijmp", 0)
    return None


def _arm_classify(insn, address):
    """(kind, target) for one AArch64 instruction word."""
    if (insn & 0xFFFFFC1F) == 0xD65F0000:
        return ("ret", 0)
    top6 = insn & 0xFC000000
    if top6 == 0x94000000 or top6 == 0x14000000:
        imm = insn & 0x03FFFFFF
        if imm & 0x02000000:
            imm -= 0x04000000
        return ("call" if top6 == 0x94000000 else "jmp", address + imm * 4)
    if (insn & 0xFFFFFC1F) == 0xD63F0000:
        return ("icall", 0)
    if (insn & 0xFF000010) == 0x54000000 or (insn & 0x7E000000) == 0x34000000:   # b.cond / cbz/cbnz
        imm = (insn >> 5) & 0x7FFFF
        if imm & 0x40000:
            imm -= 0x80000
        return ("jcc", address + imm * 4)
    if (insn & 0x7E000000) == 0x36000000:                                         # tbz/tbnz
        imm = (insn >> 5) & 0x3FFF
        if imm & 0x2000:
            imm -= 0x4000
        return ("jcc", address + imm * 4)
    if (insn & 0xFFE0001F) == 0xD4000001:                                         # svc
        return ("syscall", 0)
    return None


class _Abort(Exception):
    pass


class Emulator:
    """Runs functions of one Image under Unicorn and collects the strings they build."""

    def __init__(self, img: Image):
        self.img = img
        self.arm = img.arm
        self.uc = None
        self._blk = {}
        self._md_lite = Cs(CS_ARCH_X86, CS_MODE_64)
        if self.arm:
            self.SP, self.PC, self.RET = A.UC_ARM64_REG_SP, A.UC_ARM64_REG_PC, A.UC_ARM64_REG_X0
            self.ARGS = [getattr(A, f"UC_ARM64_REG_X{i}") for i in range(8)]
            self.SAVED = [getattr(A, f"UC_ARM64_REG_X{i}") for i in range(19, 29)] + \
                [A.UC_ARM64_REG_X29, A.UC_ARM64_REG_X30]
        else:
            self.SP, self.PC, self.RET = X.UC_X86_REG_RSP, X.UC_X86_REG_RIP, X.UC_X86_REG_RAX
            self.ARGS = ([X.UC_X86_REG_RCX, X.UC_X86_REG_RDX, X.UC_X86_REG_R8, X.UC_X86_REG_R9]
                         if img.pe else
                         [X.UC_X86_REG_RDI, X.UC_X86_REG_RSI, X.UC_X86_REG_RDX, X.UC_X86_REG_RCX,
                          X.UC_X86_REG_R8, X.UC_X86_REG_R9])
            self.SAVED = [X.UC_X86_REG_RBX, X.UC_X86_REG_RBP, X.UC_X86_REG_R12, X.UC_X86_REG_R13,
                          X.UC_X86_REG_R14, X.UC_X86_REG_R15]
            if img.pe:
                self.SAVED += [X.UC_X86_REG_RSI, X.UC_X86_REG_RDI]
        self._fresh()

    # ---- machine setup ---------------------------------------------------------------------

    def _fresh(self):
        if self.uc is not None:
            self.uc = None
            gc.collect()
        uc = self.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM) if self.arm else Uc(UC_ARCH_X86, UC_MODE_64)
        if self.arm:
            try:   # LSE atomics (casa, ldadd, swp: Rust's outlined atomics use them) need ARMv8.1+
                uc.ctl_set_cpu_model(A.UC_CPU_ARM64_MAX)
            except Exception:
                pass
        map_image(uc, self.img.binary)
        uc.mem_map(TRAMP, TRAMP_SIZE)
        ret = b"\xc0\x03\x5f\xd6" if self.arm else b"\xc3"
        uc.mem_write(TRAMP, (ret + b"\x00" * (16 - len(ret))) * min(len(self.img.tramp) + 1, TRAMP_SIZE // 16))
        for va, v in self.img.patches.items():
            try:
                uc.mem_write(BASE + va, struct.pack("<Q", v & 0xffffffffffffffff))
            except UcError:
                pass
        # the loaded image, page by page, to undo whatever a run writes into it
        self._orig = {}
        for sec in self.img.binary.sections:
            if not sec.virtual_address or not sec.size:
                continue
            lo = (BASE + sec.virtual_address) >> 12
            hi = (BASE + sec.virtual_address + max(sec.size, getattr(sec, "virtual_size", 0) or 0) + 0xfff) >> 12
            for pg in range(lo, hi):
                if pg not in self._orig:
                    try:
                        self._orig[pg] = bytes(uc.mem_read(pg << 12, 4096))
                    except UcError:
                        pass
        self.touched = set()
        uc.mem_map(STACK, STACK_SIZE)
        uc.mem_map(SCRATCH, SCRATCH_SIZE)
        uc.mem_map(HEAP, HEAP_SIZE)
        uc.mem_map(TLS, TLS_SIZE)
        self._image_snapshot = None
        uc.hook_add(UC_HOOK_BLOCK, self._on_block)
        uc.hook_add(UC_HOOK_MEM_WRITE, self._on_write)
        uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED,
                    self._on_unmapped)
        if self.arm:
            uc.hook_add(UC_HOOK_INTR, self._on_intr)
        else:
            uc.hook_add(UC_HOOK_INSN, self._on_syscall, None, 1, 0, X.UC_X86_INS_SYSCALL)
        self.runs_on_this_uc = 0
        self.auto_pages = []

    def _reset(self):
        """Fresh registers, stack, heap and data for the next run (code is never written)."""
        if self.runs_on_this_uc >= 64:     # Unicorn grows its TB cache; start over now and then
            self._fresh()
        uc = self.uc                       # (after _fresh: the new instance, not the old one)
        self.runs_on_this_uc += 1
        for page in self.auto_pages:
            try:
                uc.mem_unmap(page, 0x1000)
            except UcError:
                pass
        self.auto_pages = []
        # memory the previous run wrote outside the image (auto-mapped pages, scratch beyond
        # the cleared window): zero it, or a later run reads the earlier run's bytes
        # (pages of the image get their loaded contents back: a wild store into .rodata must not
        # wipe the ciphertext the next function decodes)
        prev = getattr(self, "writes", None)
        dirty = set(prev.pages) if prev is not None else set()
        dirty |= self.touched
        self.touched = set()
        z = b"\x00" * 4096
        for pg in dirty:
            try:
                uc.mem_write(pg << 12, self._orig.get(pg, z))
            except UcError:
                pass
        for va, blob in self._writable_sections():
            try:
                uc.mem_write(va, blob)
            except UcError:
                pass
        for region, size in ((STACK, STACK_SIZE), (SCRATCH, 0x20000)):
            uc.mem_write(region, b"\x00" * size)
        if getattr(self, "heap_top", HEAP) > HEAP:
            uc.mem_write(HEAP, b"\x00" * (min(self.heap_top, HEAP + HEAP_SIZE) - HEAP))
        self.heap_top = HEAP
        self.sizes = {}
        self.last_error = 0
        self.brk = BRK
        # thread-local storage: Rust reads thread-locals (the current thread, panic count, output
        # capture) through the thread pointer; with it at 0 the first access faults
        tp = TLS + TLS_SIZE // 2
        uc.mem_write(TLS, b"\x00" * TLS_SIZE)
        if self.arm:
            uc.reg_write(A.UC_ARM64_REG_TPIDR_EL0, tp)
        elif self.img.pe:
            # TEB: [0x30] self pointer, [0x58] thread-local storage array -> zeroed blocks
            uc.reg_write(X.UC_X86_REG_GS_BASE, tp)
            uc.mem_write(tp + 0x30, struct.pack("<Q", tp))
            uc.mem_write(tp + 0x58, struct.pack("<Q", TLS + 0x1000))
            uc.mem_write(TLS + 0x1000, b"".join(struct.pack("<Q", TLS + 0x2000 + 0x800 * k) for k in range(8)))
        else:
            # x86-64 SysV: fs:0 holds the thread pointer itself; variables sit below it
            uc.reg_write(X.UC_X86_REG_FS_BASE, tp)
            uc.mem_write(tp, struct.pack("<Q", tp))
        top = STACK + STACK_SIZE // 2
        if self.arm:
            for i in range(31):
                uc.reg_write(getattr(A, f"UC_ARM64_REG_X{i}"), 0)
        else:
            for r in (X.UC_X86_REG_RAX, X.UC_X86_REG_RBX, X.UC_X86_REG_R10, X.UC_X86_REG_R11,
                      X.UC_X86_REG_R12, X.UC_X86_REG_R13, X.UC_X86_REG_R14, X.UC_X86_REG_R15,
                      X.UC_X86_REG_RSI, X.UC_X86_REG_RDI, X.UC_X86_REG_RCX, X.UC_X86_REG_RDX,
                      X.UC_X86_REG_R8, X.UC_X86_REG_R9):
                uc.reg_write(r, 0)
            uc.reg_write(X.UC_X86_REG_RBP, top)
        uc.reg_write(self.SP, top)
        # out-pointer and slice arguments point at zeroed scratch memory
        for r in self.ARGS:
            uc.reg_write(r, SCRATCH + 0x8000)
        if not self.arm:
            # a return address the run stops at, so `ret` from the top frame is well defined
            uc.mem_write(top, struct.pack("<Q", 0))

    def _writable_sections(self):
        if self._image_snapshot is None:
            out = []
            for s in self.img.binary.sections:
                if not s.virtual_address or not s.size:
                    continue
                if self.img.pe:
                    w = bool(int(s.characteristics) & 0x80000000)
                else:
                    w = bool(int(s.flags) & 0x1)
                if w:
                    raw = _content(s)
                    c = bytearray(raw + b"\x00" * max(0, s.size - len(raw)))
                    lo = s.virtual_address
                    for va, v in self.img.patches.items():
                        if lo <= va and va + 8 <= lo + len(c):
                            c[va - lo:va - lo + 8] = struct.pack("<Q", v & 0xffffffffffffffff)
                    for va in self.img.lse_flags:
                        if lo <= va < lo + len(c):
                            c[va - lo] = 1
                    out.append((BASE + lo, bytes(c)))
            self._image_snapshot = out
        return self._image_snapshot

    # ---- heap and C runtime ----------------------------------------------------------------

    def _alloc(self, size):
        size = int(size)
        if size < 0 or size > 0x1000000:
            return 0
        p = (self.heap_top + 0xf) & ~0xf
        if p + size + 0x40 > HEAP + HEAP_SIZE:
            return 0
        self.heap_top = p + max(size, 1) + 0x40      # a zero gap keeps neighbouring blocks apart
        self.sizes[p] = size
        return p

    def _touch(self, addr, n):
        self.touched.update(range(addr >> 12, ((addr + n + 0xfff) >> 12)))

    def _arg(self, i):
        if i < len(self.ARGS):
            return self.uc.reg_read(self.ARGS[i])
        # Win64: 5th+ argument on the stack above the 32-byte shadow space
        sp = self.uc.reg_read(self.SP)
        return struct.unpack("<Q", self.uc.mem_read(sp + 8 + 8 * i, 8))[0]

    def _stub(self, name):
        """Model an external call by name; returns the value to place in the return register."""
        n = _norm(name)
        uc, arg = self.uc, self._arg
        try:
            if n in _ALLOC:
                return self._alloc(arg(_ALLOC[n][0]))
            if n == "calloc":
                return self._alloc(arg(0) * arg(1))
            if n in ("realloc", "rust_realloc", "rdl_realloc", "heaprealloc"):
                ptr, size = ((arg(0), arg(1)) if n == "realloc" else
                             (arg(0), arg(3)) if n != "heaprealloc" else (arg(2), arg(3)))
                old = arg(1) if n in ("rust_realloc", "rdl_realloc") else self.sizes.get(ptr, 0)
                p = self._alloc(size)
                k = min(size, old, 0x100000)
                if p and ptr and k:
                    try:
                        uc.mem_write(p, bytes(uc.mem_read(ptr, k)))
                        self._touch(p, k)
                        for o in range(0, k, 4096):
                            self.writes.add(p + o, min(k - o, 4096))
                    except UcError:
                        pass
                return p
            if n == "posix_memalign":
                p = self._alloc(arg(2))
                uc.mem_write(arg(0), struct.pack("<Q", p))
                return 0
            if n in ("memcpy", "memmove", "memcpy_chk", "memmove_chk"):
                d, s, k = arg(0), arg(1), arg(2)
                if 0 < k <= 0x100000:
                    data = bytes(uc.mem_read(s, k))
                    uc.mem_write(d, data)
                    self._touch(d, k)
                    for o in range(0, k, 4096):
                        self.writes.add(d + o, min(k - o, 4096))
                return d
            if n in ("memset", "memset_chk"):
                d, c, k = arg(0), arg(1) & 0xff, arg(2)
                if 0 < k <= 0x100000:
                    uc.mem_write(d, bytes([c]) * k)
                    self._touch(d, k)
                return d
            if n in ("memcmp", "bcmp"):
                a, b, k = arg(0), arg(1), arg(2)
                if 0 < k <= 0x100000:
                    x, y = bytes(uc.mem_read(a, k)), bytes(uc.mem_read(b, k))
                    return 0 if x == y else (1 if x > y else 0xffffffffffffffff)
                return 0
            if n == "strlen":
                s = bytes(uc.mem_read(arg(0), 0x1000))
                return s.index(0) if 0 in s else 0x1000
            # output succeeds: a `write` that returns 0 is io::ErrorKind::WriteZero, and std's
            # print! panics ("failed printing to stdout") after the first line, ending the run
            if n == "write":
                return arg(2)
            if n == "writev":
                iov, cnt = arg(1), min(arg(2), 64)
                return sum(struct.unpack_from("<Q", uc.mem_read(iov + 16 * i + 8, 8))[0]
                           for i in range(cnt)) & 0x7fffffffffffffff
            if n == "getprocessheap":
                return 0x1000
            if n in ("errno_location", "errno", "error"):
                return SCRATCH + 0x100
            # environment: every variable is unset (Rust's Windows `var_os` tells "unset" from
            # "empty" by GetLastError() == ERROR_ENVVAR_NOT_FOUND)
            if n in ("getenvironmentvariablew", "getenvironmentvariablea"):
                self.last_error = 203
                return 0
            if n == "getlasterror":
                return self.last_error
            if n == "setlasterror":
                self.last_error = arg(0) & 0xffffffff
                return 0
            if n in _FREE:
                return 1
        except (UcError, struct.error, ValueError, OverflowError):
            return 0
        return 0

    def _on_syscall(self, uc, _):
        nr = uc.reg_read(X.UC_X86_REG_RAX)
        uc.reg_write(X.UC_X86_REG_RAX, self._syscall(nr, uc.reg_read(X.UC_X86_REG_RDI),
                                                     uc.reg_read(X.UC_X86_REG_RSI),
                                                     uc.reg_read(X.UC_X86_REG_RDX), x86=True))

    def _on_intr(self, uc, intno, _):
        self._capture()
        if intno != 2:
            # not `svc`: an undefined instruction, `brk`, an exclusive-monitor exception. Inside a
            # callee, give up on that callee; in the emulated function itself, stop
            # (stopped here and handled by run(), like a memory fault: changing PC from inside an
            # exception hook does not reliably leave the faulting function)
            self.fault = True
            uc.emu_stop()
            return
        nr = uc.reg_read(A.UC_ARM64_REG_X8)
        uc.reg_write(A.UC_ARM64_REG_X0, self._syscall(nr, uc.reg_read(A.UC_ARM64_REG_X0),
                                                      uc.reg_read(A.UC_ARM64_REG_X1),
                                                      uc.reg_read(A.UC_ARM64_REG_X2), x86=False))

    def _syscall(self, nr, a0, a1, a2, x86):
        WRITE, BRK_, MMAP, MUNMAP = (1, 12, 9, 11) if x86 else (64, 214, 222, 215)
        if nr == WRITE:
            return a2
        if nr == BRK_:
            if a0 > self.brk:
                self.brk = a0
            return self.brk
        if nr == MMAP:
            size = (a1 + 0xfff) & ~0xfff
            p = (self.heap_top + 0xfff) & ~0xfff          # mmap returns whole pages
            if not size or p + size > HEAP + HEAP_SIZE:
                return 0xfffffffffffffff4                  # -ENOMEM
            self.heap_top = p + size
            return p
        return 0

    # ---- hooks -----------------------------------------------------------------------------

    def _on_write(self, uc, access, address, size, value, _):
        self.writes.add(address, size)
        self.wrote += size
        if self.wrote > WRITE_BUDGET:
            # `rep stos`/`rep movs` over a fake length counts as one instruction but writes
            # megabytes, one hook call per element: stop the run instead
            uc.emu_stop()

    def _on_unmapped(self, uc, access, address, size, value, _):
        # map a missing page on the fly so a wild pointer does not end the run; the page is
        # unmapped again before the next run, so mappings do not pile up across thousands of
        # runs (Unicorn slows down, and eventually crashes, with very many regions)
        page = address & ~0xfff
        if page >= 1 << 47 or len(self.auto_pages) >= 256:
            # a `rep` string instruction or loop walking a fake length across memory: stop
            uc.emu_stop()
            return False
        try:
            uc.mem_map(page, 0x1000)
        except UcError:
            return False
        self.auto_pages.append(page)
        return True

    def _capture(self):
        self.writes.capture(self.uc, self.strings)

    def _plausible(self, p):
        return (STACK <= p < STACK + STACK_SIZE or HEAP <= p < HEAP + HEAP_SIZE
                or SCRATCH <= p < SCRATCH + SCRATCH_SIZE or TLS <= p < TLS + TLS_SIZE
                or BRK <= p < BRK + 0x1000000)

    def _try_str(self, ptr, n):
        if not 6 <= n <= 4096 or not self._plausible(ptr):
            return
        try:
            b = bytes(self.uc.mem_read(ptr, n))
        except UcError:
            return
        if all(0x20 <= c <= 0x7e for c in b):
            t = b.decode("ascii")
            self.strings.add(t)
            self.used.add(t)
            # the code says the string ends here. If the next byte holds printable text written
            # *before* the string's own last byte, that text is a stale tail of an older,
            # longer string in the same buffer (not this string still being built)
            w = self.writes
            end = ptr + n
            if w.written(end) and w.generation(end) < w.generation(end - 1):
                try:
                    nxt = bytes(self.uc.mem_read(end, 1))[0]
                except UcError:
                    nxt = 0
                if 0x20 <= nxt <= 0x7e:
                    self.exact.add(t)              # complete: what follows is stale

    def _capture_args(self):
        """Strings the code is about to use, at their exact length.

        Rust passes a &str as (pointer, length): in two argument registers, or inside a struct
        (fmt::Arguments -> Argument -> &str) the arguments point to. Memory alone cannot say
        where a Rust string ends -- a shorter string decoded over a longer one keeps the longer
        one's tail -- but the length the code passes along can."""
        uc = self.uc
        if self.writes.gen == self._args_gen:
            return                       # nothing written since the last look: nothing new
        self._args_gen = self.writes.gen
        regs = list(uc.reg_read_batch(self.ARGS[:6]))
        for a, b in zip(regs, regs[1:]):
            self._try_str(a, b)
        seen, budget = set(), [48]

        def walk(p, depth):
            if depth == 0 or budget[0] <= 0 or p in seen or not self._plausible(p):
                return
            seen.add(p)
            budget[0] -= 1
            try:
                q = struct.unpack("<8Q", uc.mem_read(p, 64))
            except UcError:
                return
            for a, b in zip(q, q[1:]):
                self._try_str(a, b)
            for v in q:
                walk(v, depth - 1)

        for r in regs:
            walk(r, 3)

    def _on_return(self):
        if self.frames:
            self.frames.pop()
            if not self.frames:
                self._capture()          # a callee of the emulated function just finished
        else:
            self._capture()
            self.uc.emu_stop()

    def _abandon(self):
        """The outermost callee overran FRAME_BUDGET: unwind to its caller, return 0."""
        uc = self.uc
        frame = self.frames[0]
        self.frames = []
        self._capture()
        for r, v in zip(self.SAVED, frame["regs"]):
            uc.reg_write(r, v)
        uc.reg_write(self.SP, frame["sp"])
        uc.reg_write(self.RET, 0)
        uc.reg_write(self.PC, frame["ret"])

    def _enter_or_skip(self, address):
        """First instruction after a call: decide whether the callee runs."""
        call = self.call
        self.call = None
        img = self.img
        if TRAMP <= address < TRAMP + TRAMP_SIZE:
            self.frames.append(call)            # popped by the trampoline's `ret`
            return False
        if img.executable(address) and len(self.frames) < MAX_DEPTH:
            self.frames.append(call)
            return False
        # too deep, or a call through a pointer the image never set (0, garbage): return 0
        self._capture()
        self._unwind(call)
        return True

    def _unwind(self, frame):
        uc = self.uc
        for r, v in zip(self.SAVED, frame["regs"]):
            uc.reg_write(r, v)
        uc.reg_write(self.SP, frame["sp"])
        uc.reg_write(self.RET, 0)
        uc.reg_write(self.PC, frame["ret"])

    def _block_info(self, address, size):
        """(instruction count, terminator kind, value, terminator address, terminator size)."""
        key = (address, size)
        info = self._blk.get(key)
        if info is None:
            try:
                raw = bytes(self.uc.mem_read(address, size))
            except UcError:
                raw = b""
            if self.arm:
                n = max(1, size // 4)
                last_a, last_n = address + size - 4, 4
                k = _arm_classify(struct.unpack("<I", raw[-4:])[0], last_a) if len(raw) >= 4 else None
            else:
                ins = list(self._md_lite.disasm_lite(raw, address)) if raw else []
                n = max(1, len(ins))
                if ins:
                    last_a, last_n = ins[-1][0], ins[-1][1]
                    k = _x86_classify(raw[last_a - address:last_a - address + last_n])
                else:
                    last_a, last_n, k = address, size, None
            kind, val = k if k else (None, 0)
            info = self._blk[key] = (n, kind, val, last_a, last_n)
        return info

    def _on_block(self, uc, address, size, _):
        """Everything the emulator decides happens at basic-block boundaries: callee entry,
        return, which way a branch went (and forcing it), stubs, budgets. One callback per block
        instead of per instruction."""
        prev, self.prev = self.prev, None
        if prev is not None:
            kind, val, pa, pn, depth0 = prev
            if kind == "call":
                if depth0:
                    self._capture()            # buffers handed to a callee are complete now
                    self._capture_args()
                sp = uc.reg_read(self.SP)
                self.call = {"ret": pa + pn, "start": self.count, "sp": sp if self.arm else sp + 8,
                             "regs": list(uc.reg_read_batch(self.SAVED))}
                if self._enter_or_skip(address):
                    return
            elif kind == "ret":
                if self.frames:
                    self.frames.pop()
                    if not self.frames:
                        self._capture()        # a callee of the emulated function just finished
                else:
                    self._capture()
                    uc.emu_stop()
                    return
            elif kind == "jcc" and depth0:
                tgt = val if self.arm else pa + pn + val
                fall = pa + pn
                if self.lo <= tgt < self.hi and tgt > pa:      # forward branch in this function
                    self.branches.add(pa)
                    force = self.plan.get(pa)
                    if force is not None and pa not in self.forced:
                        self.forced.add(pa)
                        self.covered.add((pa, force))
                        want = tgt if force else fall
                        if address != want:
                            uc.reg_write(self.PC, want)
                            return
                    else:
                        self.covered.add((pa, address == tgt))
        if self.frames:
            if self.count - self.frames[0]["start"] > FRAME_BUDGET:
                self._abandon()
                return
            if len(self.frames) > 1 and self.count - self.frames[-1]["start"] > INNER_BUDGET:
                # the innermost callee overran (a spinning lock, a loop over a fake length):
                # return 0 from it and let its caller -- the decoder -- carry on
                self._unwind(self.frames.pop())
                return
        if TRAMP <= address < TRAMP + TRAMP_SIZE:
            i = (address - TRAMP) // 16
            self._capture()
            self._capture_args()
            uc.reg_write(self.RET, self._stub(self.img.tramp[i] if i < len(self.img.tramp) else "")
                         & 0xffffffffffffffff)
            self.count += 1
            self.prev = ("ret", 0, address, 1, not self.frames)   # the trampoline's `ret` runs next
            return
        name = self.img.named.get(address)
        if name is not None:
            # malloc/memcpy/... linked into .text (static builds): model it, return to the caller
            self._capture()
            self._capture_args()
            uc.reg_write(self.RET, self._stub(name) & 0xffffffffffffffff)
            if self.arm:
                uc.reg_write(self.PC, uc.reg_read(A.UC_ARM64_REG_X30))
            else:
                sp = uc.reg_read(self.SP)
                uc.reg_write(self.PC, struct.unpack("<Q", uc.mem_read(sp, 8))[0])
                uc.reg_write(self.SP, sp + 8)
            self._on_return()
            return
        if not (self.img.text_va <= address < self.img.text_end) and not self.img.executable(address):
            # running data or an unmapped page (a jump through an unset pointer): inside a callee,
            # give up on that callee and return 0 to its caller; in the function itself, stop
            self._capture()
            if self.frames:
                self._unwind(self.frames.pop())
            else:
                uc.emu_stop()
            return
        n, kind, val, la, ln = self._block_info(address, size)
        self.count += n
        if kind in ("call", "icall", "icall_rip"):
            self.prev = ("call", val, la, ln, not self.frames)
        elif kind in ("ret", "jcc"):
            self.prev = (kind, val, la, ln, not self.frames)

    # ---- running a function ----------------------------------------------------------------

    def run(self, func_va, size, plan=None):
        """Emulate one function once, forcing the branches in `plan` ({addr: taken}).

        Returns (strings, branches seen, (branch, direction) pairs covered)."""
        self._reset()
        self.writes = _Writes()
        self._args_gen = -1
        self.wrote = 0
        self.strings = set()
        if not getattr(self, "keep_exact", False):
            self.exact = set()
            self.used = set()
        self.frames = []
        self.count = 0
        self.plan = plan or {}
        self.forced = set()
        self.branches = set()
        self.covered = set()
        self.call = None
        self.prev = None
        self.lo, self.hi = func_va, func_va + size
        pc = BASE + func_va
        faults = {}
        for _ in range(64):
            try:
                self.fault = False
                self.uc.emu_start(pc, 0, timeout=0, count=max(1, BUDGET - self.count))
                if not self.fault:
                    break
                raise UcError(0)
            except UcError:
                # a fault (unmappable address, invalid instruction) inside a callee: give up on
                # that callee and return 0 to its caller. A call from the emulated function that
                # keeps faulting (a panic unwinding through std) is abandoned as a whole. A fault
                # in the function itself ends the run.
                if not self.frames or self.count >= BUDGET:
                    break
                self._capture()
                self.prev = None
                top = id(self.frames[0])
                faults[top] = faults.get(top, 0) + 1
                if faults[top] >= 3 or len(self.frames) == 1:
                    self._abandon()
                else:
                    self._unwind(self.frames.pop())
                pc = self.uc.reg_read(self.PC)
            except Exception:
                break
        self._capture()
        return self.strings, self.branches, self.covered

    def explore(self, func_va, size, max_runs=MAX_RUNS, seconds=FUNC_SECONDS, deadline=None):
        """Run a function, then re-run it with unexplored forward branches flipped."""
        t_end = time.monotonic() + seconds
        if deadline is not None:
            t_end = min(t_end, deadline)
        self.exact = set()
        self.used = set()
        self.keep_exact = True
        try:
            return self._explore(func_va, size, max_runs, t_end)
        finally:
            self.keep_exact = False

    def _explore(self, func_va, size, max_runs, t_end):
        strings, branches, covered = self.run(func_va, size)
        out = set(strings)
        self.natural = set(strings)        # what the unforced run produced
        all_cov = set(covered)
        queue = deque()
        tried = set()

        def enqueue(base, brs):
            for b in sorted(brs):
                for d in (True, False):
                    if (b, d) not in all_cov and b not in base:
                        key = tuple(sorted({**base, b: d}.items()))
                        if key not in tried:
                            tried.add(key)
                            queue.append({**base, b: d})

        enqueue({}, branches)
        runs = 1
        spent = self.count
        while queue and runs < max_runs and time.monotonic() < t_end and spent < 3 * BUDGET:
            plan = queue.popleft()
            if all((b, d) in all_cov for b, d in plan.items()):
                continue
            strings, branches, covered = self.run(func_va, size, plan)
            runs += 1
            spent += self.count
            out |= strings
            new = covered - all_cov
            all_cov |= covered
            if new:
                enqueue(plan, branches)
        return out, runs


# --------------------------------------------------------------------------------------------
# which functions first
# --------------------------------------------------------------------------------------------

def _cipherish(b, image_lo=0, image_hi=0):
    """Bytes that look like ciphertext rather than text, a pointer table or zero padding.

    XOR with a printable key leaves many bytes printable, so the test is the presence of
    control/high bytes, not their majority; pointers into the image and runs of zeros are not
    ciphertext."""
    if len(b) < 12 or b.count(0) > 2:
        return False
    odd = sum(1 for x in b if x < 0x20 or x > 0x7e)
    if len(set(b)) < 8:
        return False
    if odd < 3:
        # printable: ciphertext of text under a printable key often is. Plain text has common
        # English/identifier trigrams and a sane case pattern; XOR output does not.
        from recover_callsite import english_score
        t = b.decode("latin-1")
        letters = [c for c in t if c.isalpha()]
        flips = sum(1 for x, y in zip(letters, letters[1:]) if x.isupper() != y.isupper())
        if english_score(t) >= 0.12 and flips <= max(2, len(letters) // 3):
            return False
    if image_hi:
        for k in range(0, len(b) - 7, 8):
            v = struct.unpack_from("<Q", b, k)[0]
            if image_lo <= v < image_hi:
                return False
    return True


_HEX = re.compile(r"0x[0-9a-f]+")


def _features(img, fva, size):
    """(imm64, xors, ciphertext refs, direct callees) of one function."""
    off = fva - img.text_va
    chunk = img.code[off:off + min(size, 0x2000)]
    imm64 = xors = cipher = 0
    callees = []
    pages = {}
    for addr, sz, mn, ops in img.md.disasm_lite(chunk, fva):
        if img.arm:
            if mn == "movk":
                imm64 += 1
            elif mn == "eor":
                parts = [p.strip() for p in ops.split(",")]
                if len(parts) == 3 and parts[1] != parts[2]:
                    xors += 1
            elif mn == "adrp":
                m = _HEX.search(ops)
                if m:
                    pages[ops.split(",")[0]] = int(m.group(), 16)
            elif mn in ("add", "adr"):
                parts = [p.strip() for p in ops.split(",")]
                t = None
                if mn == "adr" and len(parts) == 2:
                    t = int(parts[1].lstrip("#"), 16) if parts[1].startswith("#0x") else None
                elif len(parts) == 3 and parts[1] in pages and parts[2].startswith("#0x"):
                    t = pages[parts[1]] + int(parts[2][1:], 16)
                if t is not None and _cipherish(img.read(t, 16), *img.span):
                    cipher += 1
            elif mn in ("bl", "b") and ops.startswith("#0x"):
                callees.append(int(ops[1:], 16))
        else:
            if mn == "movabs" and "0x" in ops:
                imm64 += 1
            elif mn in ("xor", "pxor", "xorps", "xorpd", "vpxor", "vxorps", "vpxord", "vpxorq"):
                parts = [p.strip() for p in ops.split(",")]
                if len(set(parts)) > 1:
                    xors += 1
            elif mn == "lea" and "rip" in ops:
                m = re.search(r"\[rip ([+-]) (0x[0-9a-f]+)\]", ops)
                if m:
                    disp = int(m.group(2), 16) * (1 if m.group(1) == "+" else -1)
                    if _cipherish(img.read(addr + sz + disp, 16), *img.span):
                        cipher += 1
            elif mn in ("call", "jmp") and ops.startswith("0x"):
                callees.append(int(ops, 16))       # a jmp out of the function is a tail call
    return imm64, xors, cipher, callees


def _scores(img, funcs):
    """Decoder prior per function, like FLOSS's function scoring (floss/identify.py).

    Own features: 64-bit immediates (obfstr's per-literal keys), non-zeroing XOR, references to
    ciphertext-looking data. Reach: a call (one or two levels down) into a function that XORs,
    which is how an out-of-line decoder's call sites look. Functions scoring 0 are still
    emulated, after the others.
    """
    feats = {f: _features(img, f, n) for f, n in funcs}
    xorer = {f for f, v in feats.items() if v[1]}
    reach1 = {f for f, v in feats.items() if any(c in xorer for c in v[3])}
    out = {}
    for f, (imm64, xors, cipher, callees) in feats.items():
        reach = 2 if any(c in xorer for c in callees) else 1 if any(c in reach1 for c in callees) else 0
        out[f] = 2 * imm64 + xors + 3 * min(cipher, 5) + (reach if cipher else 0)
    return out


# --------------------------------------------------------------------------------------------
# results
# --------------------------------------------------------------------------------------------
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


def _norm_text(b):
    return re.sub(rb"[^a-z0-9]", b"", b.lower())


_FMT_DIRECTIVE = re.compile(rb"%[-+ #0]*\d*(?:\.\d+)?(?:hh|h|ll|l|L|q|j|z|t)?[diouxXeEfgGcspn]")


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
    templates = []
    mid = []
    _normalized = []

    def normalized():
        if not _normalized:
            _normalized.append(b"\0".join(_norm_text(m.group())
                                           for m in re.finditer(rb"[\x20-\x7e]{4,}", file_bytes)))
        return _normalized[0]

    def printf_output(st):
        """Text a printf-style format string in the file produced, e.g. `Assertion failed: %s
        (%s: %s: %d)` formatted with the emulator's empty arguments, possibly cut short. The
        literal parts of the template must make up most of the candidate, so a decoded URL is
        not "explained" by a `http://%s/%s` template."""
        if not templates:
            for m in re.finditer(rb"[\x20-\x7e]{6,200}", file_bytes):
                t = m.group()
                if b"%" in t and _FMT_DIRECTIVE.search(t):
                    lit = [x for x in _FMT_DIRECTIVE.split(t)]
                    if len(lit[0]) >= 3:
                        rxs = []
                        for k in range(len(lit), 1, -1):
                            body = b"(.{0,64}?)".join(re.escape(x) for x in lit[:k])
                            rxs.append(re.compile(body + b"(.{0,64})", re.S))
                        templates.append((lit[0][:3], rxs))
                        if len(lit[0]) >= 8:
                            mid.append((lit[0], lit[1:4]))
            templates.append((None, []))
        b = st.encode("ascii", "ignore")
        if len(b) >= 8:
            # a view that starts inside a template's first literal (`_hdr version: 0 at ` from
            # `unsupported .eh_frame_hdr version: %d at %p`)
            for lit0, lits in mid:
                j = lit0.find(b[:6])
                if j > 0:
                    for k in range(len(lits) + 1, 0, -1):
                        rxk = re.compile(b"(.{0,64}?)".join(re.escape(x) for x in ([lit0[j:]] + lits)[:k])
                                         + b"(.{0,64})", re.S)
                        m = rxk.fullmatch(b)
                        if m and len(b) - sum(len(g) for g in m.groups()) >= 0.6 * len(b):
                            return True
        for head, rxs in templates:
            if head is None or not b.startswith(head):
                continue
            for rx in rxs:
                m = rx.fullmatch(b)
                if m and len(b) - sum(len(g) for g in m.groups()) >= 0.6 * len(b):
                    return True
        return False

    cache = {}

    def explained(st):
        if st not in cache:
            cache[st] = _explained(st)
        return cache[st]

    def _explained(st):
        b = st.encode("ascii", "ignore")
        if b in file_bytes:
            return True
        if printf_output(st):
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
        # static words joined at run time (a flag list: `--file -f --after-context -A`)
        toks = b.split()
        if len(toks) >= 3 and all((len(t) >= 2 and t in file_bytes) or
                                  (len(t) == 1 and not t.isalnum()) for t in toks):
            return True
        if len(b) > 160:
            # long text (help screens, formatted messages): judge it by its windows instead of an
            # exact cover, which is quadratic in the length and searches the whole file each step
            wins = [b[i:i + 16] for i in range(0, len(b) - 15, 8)]
            return sum(1 for w in wins if w in file_bytes) >= 0.8 * len(wins)
        # longest file match starting at every position, then the fewest pieces that cover the
        # candidate (any prefix of a file substring is one too). Greedy longest-match alone
        # splits `_` + `ation` (from `__errno_location`) into `_at` + `ion` and misses it.
        n = len(b)
        longest = [0] * n
        for i in range(n):
            k = longest[i - 1] - 1 if i and longest[i - 1] > 1 else 0
            while i + k < n and b[i:i + k + 1] in file_bytes:
                k += 1
            longest[i] = k
            if k == 0:
                return False
        best = [None] * (n + 1)
        best[n] = []
        for i in range(n - 1, -1, -1):
            for k in range(longest[i], 0, -1):
                rest = best[i + k]
                if rest is None:
                    continue
                cand = [k] + rest
                # fewest pieces; among those, the longest ones (`_`+`ation`, not `_at`+`ion`)
                if best[i] is None or (len(cand), -sum(x * x for x in cand)) < \
                        (len(best[i]), -sum(x * x for x in best[i])):
                    best[i] = cand
        pieces = best[0]
        if not pieces:
            return False
        if len(pieces) <= max_pieces:
            inner = pieces[1:-1]
            if all(p >= min_piece for p in inner) and \
                    (len(pieces) == 1 or (pieces[0] >= min_edge and pieces[-1] >= min_edge)):
                # every piece but the edges carries real weight
                weight = sum(pieces) - (pieces[0] if pieces[0] < min_piece else 0) \
                    - (pieces[-1] if len(pieces) > 1 and pieces[-1] < min_piece else 0)
                if weight >= min_piece * max(1, len(pieces) - 1):
                    return True
        # formatted output: a few long static pieces glued with short ones (`libunwind: ` +
        # `getRegister` + ` - ` + `unsupported arm64 register`), as printf/format! produce
        long = [p for p in pieces if p >= 6]
        if long and sum(long) >= 0.75 * n and len(pieces) - len(long) <= 2 * len(long) + 1:
            return True
        # a static identifier re-cased or re-punctuated at run time (git's BAD_DATE_OVERFLOW
        # reported as badDateOverflow)
        k = _norm_text(b)
        return len(k) >= 8 and k in normalized()

    return explained


_EMULATOR_VALUES = tuple(
    fmt % v for v in (SCRATCH, SCRATCH + 0x8000, STACK, STACK + STACK_SIZE // 2, HEAP)
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
    exact = {r["string"] for r in records if r.get("exact")}
    used = {r["string"] for r in records if r.get("used")}
    stale, partial = set(), set()
    # a string the code used at a known length, followed by more text in memory: that text is a
    # stale tail from an earlier, longer string in the same buffer
    for p in exact:
        for s in texts:
            if s != p and s.startswith(p) and s not in exact:
                stale.add(s)
    for p in texts:
        if len(p) < 6:
            continue
        for s in texts:
            if s == p or not s.startswith(p) or s in stale:
                continue
            if s in used and p not in exact:
                partial.add(p)                 # the code used s at its full length
                continue
            tail = s[len(p):]
            # a tail of a few characters is a buffer still being decoded byte by byte, not a stale
            # piece of another string (stale tails are cut by write age in _Writes._split)
            if len(tail) >= 4 and \
                    any(tail in o and o not in (s, tail) and not o.startswith(p) for o in texts):
                stale.add(s)
            elif p not in exact:
                partial.add(p)
    garbled = set()
    for x in texts:
        for y in texts:
            if x == y or y.startswith(x) or x.startswith(y):
                continue
            if len(y) < len(x) or (len(y) == len(x) and y not in used):
                continue
            k = 0
            while k < len(x) and x[k] == y[k]:
                k += 1
            if x not in exact and x not in used and len(y) - k > len(x) - k and \
                    ((k >= 12 and len(x) - k <= 3) or (k >= 8 and len(x) - k <= 1)
                     or (len(x) <= 12 and k >= 5 and len(x) - k <= 3)):
                garbled.add(x)
            # y is what the code passed on, at its length; x differs only in its last few
            # characters (`...telemetry-ofF` against `...telemetry-off`): a half-decoded view
            elif y in used and x not in used and k >= 12 and len(x) - k <= 4:
                garbled.add(x)
    # a forced path that cut a decode short or ran it on half-initialised state: a near copy of a
    # string the natural run produced (`...telemetry-ofF`), or a piece from inside one plus junk
    # (`ture-fla` + `eett`). Strings only a forced path reaches (another match arm) are kept.
    natural = {r["string"] for r in records if not r.get("forced")}
    for f in {r["string"] for r in records if r.get("forced")} - natural - used:
        if len(f) < 8:
            garbled.add(f)    # short text only a forced path built (`lib`+`map`): too little evidence
            continue
        for n in natural | used:
            k = 0
            while k < min(len(f), len(n)) and f[k] == n[k]:
                k += 1
            # (a shorter string is a prefix seen on the way, not the truth)
            if len(n) >= len(f) and k >= 12 and len(f) - k <= 4:
                garbled.add(f)
                break
            head = f[:8]
            if len(head) == 8 and head in n[1:] and not n.startswith(head):
                garbled.add(f)
                break
    # padded: a string the code used, glued to pieces of other recovered strings
    # (`https://telemetr` + `--skip-update-check`): the run, not a string
    padded = set()
    for c in texts - used:
        for u in used:
            if len(u) >= 6 and u in c and u != c and not c.startswith(u):
                rest = [x for x in c.split(u) if x]
                if all(len(x) <= 3 or any(x in o for o in texts if o not in (c,)) for x in rest):
                    padded.add(c)
                    break
    # a view starting inside a used string plus a few bytes of junk (`bravo::build-id-20261018xK`
    # from `canary::bravo::build-id-20261018`)
    for x in texts - used - exact:
        for y in used:
            if len(y) < 12 or x == y:
                continue
            m = len(x) - 1
            while m >= 12 and y.find(x[:m], 1) < 0:
                m -= 1
            # (inside, not at the start: a used prefix of x is the decode seen half-way through)
            if m >= 12 and 0 < len(x) - m <= 3:
                garbled.add(x)
                break
    drop = stale | partial | garbled | padded
    drop |= {t for t in texts - used - exact for s in stale if t != s and s.endswith(t)}
    keep = [r for r in records if r["string"] not in drop]
    alive = {r["string"] for r in keep}
    return [r for r in keep if not any(o != r["string"] and r["string"] in o for o in alive)]




def _degenerate(st):
    """Fake inputs formatted into text: a build-id of zeros, a run of one character."""
    if len(st) < 16:
        return False
    top = max(st.count(c) for c in set(st))
    return top / len(st) > 0.5 or re.search(r"(.)\1{15}", st) is not None


def recover(path, canaries, max_funcs=0, time_budget=None, explore=True):
    """Emulate functions and collect the strings they materialise in memory.

    Returns, besides the canary bookkeeping used by the benchmark, ``recovered_texts`` and
    ``records`` ({"string", "function", "method"}): every text-like string written during
    emulation that does not already occur in the file. That last filter is FLOSS's rule for
    decoded strings (static strings are reported by `strings`, not here), and it is what keeps
    stack copies of ordinary .rodata literals out of the output when no canaries are known.

    max_funcs: 0 = no cap (the time budget decides); explore: re-run decoder-like functions with
    forward branches flipped, to reach strings on paths the fake arguments do not take.
    """
    from recover_callsite import looks_like_text
    try:
        img = Image(path)
    except Exception as e:
        return {"error": str(e), "recall": 0, "n": len(canaries), "recovered_texts": [], "records": [],
                "functions_tried": 0, "functions_total": 0, "timed_out": False}
    funcs = img.functions()
    scores = _scores(img, funcs)
    order = sorted(funcs, key=lambda f: (-scores[f[0]], f[0]))
    if max_funcs:
        order = order[:max_funcs]
    explained = _static_cover(img.file_bytes + img.code_constants())
    emu = Emulator(img)
    deadline = time.monotonic() + time_budget if time_budget else None
    found, records, seen = set(), [], set()
    tried = runs = 0
    timed_out = False
    for fva, size in order:
        if deadline is not None and time.monotonic() > deadline:
            timed_out = True
            break
        tried += 1
        if explore and scores[fva] > 0:
            strs, n = emu.explore(fva, size, deadline=deadline)
            natural = emu.natural
        else:
            strs, _, _ = emu.run(fva, size)
            n = 1
            natural = strs
        exact, used = set(emu.exact), set(emu.used)
        runs += n
        for st in sorted(strs):
            for c in canaries:
                if c in st:
                    found.add(c)
            if st in seen or _degenerate(st) or not looks_like_text(st.encode("ascii", "ignore")) \
                    or explained(st):
                continue
            seen.add(st)
            rec = {"string": st, "function": fva, "method": "emulation"}
            if st not in natural:
                rec["forced"] = True       # only on a path reached by forcing branches
            if st in used:
                rec["used"] = True         # the code passed it on at exactly this length
            if st in exact:
                rec["exact"] = True        # ... and what followed it in memory was stale
            records.append(rec)
        if canaries and len(found) == len(canaries):
            break
    records = _drop_overlap_artifacts(records)
    return {"functions_tried": tried, "functions_total": len(funcs), "runs": runs,
            "timed_out": timed_out, "recovered": sorted(found),
            "recall": len(found), "n": len(canaries), "arch": "aarch64" if img.arm else "x86-64",
            "recovered_texts": [r["string"] for r in records], "records": records}


def _selftest():
    # x86 control-flow classification, prefixes included
    assert _x86_classify(bytes.fromhex("41ffd7")) == ("icall", 0)               # call r15
    assert _x86_classify(bytes.fromhex("ff1510000000")) == ("icall_rip", 0x10)  # call [rip+0x10]
    assert _x86_classify(bytes.fromhex("e8fbffffff")) == ("call", -5)
    assert _x86_classify(bytes.fromhex("0f8410000000")) == ("jcc", 0x10)
    assert _x86_classify(bytes.fromhex("7405")) == ("jcc", 5)
    assert _x86_classify(bytes.fromhex("f3c3")) == ("ret", 0)
    assert _x86_classify(bytes.fromhex("f30f1efa")) is None                     # endbr64
    assert _x86_classify(bytes.fromhex("0f05")) == ("syscall", 0)
    # AArch64
    assert _arm_classify(0xD65F03C0, 0x1000) == ("ret", 0)
    assert _arm_classify(0x94000004, 0x1000) == ("call", 0x1010)
    assert _arm_classify(0x97FFFFFF, 0x1000) == ("call", 0xFFC)
    assert _arm_classify(0x54000040, 0x1000) == ("jcc", 0x1008)                 # b.eq +8
    assert _arm_classify(0xB4000060, 0x1000) == ("jcc", 0x100C)                 # cbz x0, +12
    assert _arm_classify(0xD63F0200, 0x1000) == ("icall", 0)                    # blr x16
    # captured strings are read back from memory and extended through written neighbours only,
    # and cut where they mix writes of different ages
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(0x1000, 0x2000)
    uc.mem_write(0x1000, b"STATIC-TEXT" + b"\x00" * 5)
    w, out = _Writes(), set()
    for i, ch in enumerate(b"built-one-byte-at-a-time"):     # a string built by pushes
        uc.mem_write(0x1010 + i, bytes([ch]))
        w.add(0x1010 + i, 1)
        w.capture(uc, out)
    assert "built-one-byte-at-a-time" in out and not any("STATIC" in s for s in out), out
    w, out = _Writes(), set()
    uc.mem_write(0x1800, b"canary::config-endpoint")        # an older, longer string...
    w.add(0x1800, 23)
    w.capture(uc, out)
    uc.mem_write(0x1800, b"short-string")                   # ...partly overwritten
    w.add(0x1800, 12)
    w.capture(uc, out)
    assert "short-string" in out and not any(s.startswith("short-stringg") for s in out), out
    # the heap model hands out separated, zeroed blocks
    class _Img:
        pe = False; arm = False
    e = Emulator.__new__(Emulator)
    e.heap_top, e.sizes = HEAP, {}
    a, b = e._alloc(10), e._alloc(10)
    assert b - a >= 0x40 and a % 16 == 0 and b % 16 == 0
    print("selftest OK: classification, written-memory capture and write-age splitting, heap model")


def main():
    if "--selftest" in sys.argv:
        _selftest()
        return
    man = json.loads((ROOT / "bench_src" / "manifest.json").read_text())
    can = man["canaries"]
    targets = sys.argv[1:] or ["build/obfstr__elf__release__nostrip"]
    for t in targets:
        p = Path(t) if Path(t).exists() else ROOT / t
        t0 = time.monotonic()
        r = recover(p, can, time_budget=120)
        print(f"{p.name:<46} recall {r['recall']}/{r['n']}  funcs={r.get('functions_tried')}/"
              f"{r.get('functions_total')} runs={r.get('runs')}  {time.monotonic() - t0:.1f}s"
              + ("  ERR " + r['error'] if r.get('error') else ""))
        for s in r.get("recovered_texts", []):
            print("     +", s)


if __name__ == "__main__":
    main()
