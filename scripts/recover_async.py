#!/usr/bin/env python3
"""recover_async.py - recover Rust async state machines from (stripped) binaries.

rustc lowers every `async fn` / async block to a coroutine type whose `poll` is a state machine: a
discriminant field inside the coroutine (`self`, the first argument) selects where to resume.
  state 0 = Unresumed (start), 1 = Returned, 2 = Panicked, 3.. = one Suspend state per `.await`.
States 1 and 2 panic with "`async fn` resumed after completion" / "...after panicking" (through
`core::panicking::panic_const::panic_const_async_fn_resumed[_panic]` on current rustc, a direct
`panic("...")` on older ones). Those strings survive `strip`, so they anchor the search:

  1. anchors   - find the two strings in data, the code that references them (the panic_const
                 helpers, or inline panic sites), and every call/tail call into those helpers
                 (direct, through a GOT/IAT slot) -> candidate functions;
  2. dispatch  - in each candidate, every narrow load from [reg+disp] (and `cmp byte [m], imm`) is
                 tried as a state load: a tiny concrete interpreter runs the code after it with the
                 loaded value = v (compare chains, `cbz/tbz`, bit tests, and jump tables -- read
                 from the binary, no premium code needed) and records where control lands for each
                 v. A load is a state dispatch only if v=1 lands on the "completion" panic and v=2
                 on the "panicking" panic. States 3.. are enumerated until a target repeats, lands
                 on a panic arm, leaves the function, or a jump-table read runs into other data.
                 (premium/opt_reverse's table recovery is not reused: it requires the dominating
                 `cmp idx, K` bound, and rustc emits none for a u8 state with range metadata --
                 the table is indexed by the raw byte, so its length comes from these checks);
  3. dataflow  - a forward analysis (register = arg/stack pointer + offset, a pointer loaded from
                 such a slot, a stack spill, a constant, or a bounded set of these where paths
                 merge -- a pointer phi) gives each state field's location relative to `self` (or
                 the stack, for a coroutine inlined into its executor) and every store of a state
                 value to it: the Pending paths' write-backs, which validate the recovered states
                 (a store through a pointer phi counts for each field it may hit);
  4. suspend   - for each Suspend state, the first poll reached from its resume target: a direct
                 call (another recovered poll function -> nesting edge), a `dyn Future` vtable
                 slot (slot 3 = poll), or a nested inlined state machine. A dyn call is resolved
                 per call site: the vtable that reaches the call's vtable register on the path
                 that set the await up (dispatch edges cut), through spills and constructor return
                 values; ambiguous ones are reported as candidates;
  5. extras    - the coroutine's source location (the &Location passed to the resume panic, so a
                 stripped binary still says `src/main.rs:13:30`), its size (the `dyn Future`
                 vtable's size field when it is boxed; else a lower bound from the accesses through
                 `self`), and which async runtime is linked (registry paths in the data).

Two dispatch sites on one state field are one machine when they share a target (one coroutine
polled from two code paths) and two when they share none (two inlined copies of a coroutine whose
storage overlaps).

Machines whose field is relative to the function's own argument are that function's state
machine ("poll"); with -O an awaited future's poll is often inlined into its parent's, so a function
can also hold nested machines (field inside self) or a coroutine inlined into a non-poll function
(`block_on`, tokio's Core::poll) with its state on the stack.

    python3 scripts/recover_async.py path/to/binary           # summary
    python3 scripts/recover_async.py path/to/binary --json
    python3 scripts/recover_async.py --selftest

x86-64 (ELF SysV: self in rdi/rsi; PE Win64: rcx/rdx), AArch64 (x0/x1) and i386 (cdecl: self on
the stack, tracked through push/pop/`and esp`; LLVM fastcc: ecx/edx; PIC tables `[pic + idx*4 - d]`
with the PC base from `call $+5; pop`, and mingw's absolute tables in .text); ELF, PE (RVAs; a
stripped PE32 gets its function starts by recursive descent + code pointers) and Mach-O
(LC_FUNCTION_STARTS). Measured on rustc 1.70 (inline `panic("...")`, message pointer sometimes
hoisted above the dispatch), 1.85 and 1.97 (panic_const helpers). Static only.
"""
from __future__ import annotations

import argparse
import bisect
import json
import re
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

ANCHOR_STRINGS = {"returned": b"`async fn` resumed after completion",
                  "panicked": b"`async fn` resumed after panicking"}
STATE_NAMES = {0: "Unresumed", 1: "Returned", 2: "Panicked"}
# async runtimes, by crate name as recover_rust_meta's registry-path fingerprint reports it
RUNTIMES = ("tokio", "async-std", "smol", "async-executor", "futures-executor", "async-global-executor",
            "embassy-executor", "glommio", "actix-rt", "monoio")
_MAX_STATES = 256          # a u8 discriminant; wider tags are rare and capped here
_RUN_STEPS = 96            # instructions one dispatch run may execute
_WALK_STEPS = 48           # instructions a classification / suspend walk may visit
_ANCHOR_FN_MAX = 0x80      # a panic_const helper is a handful of instructions
_MAX_CANDIDATES = 4000     # functions analyzed per binary
_MAX_FN_BYTES = 0x40000    # skip absurd "functions" (missing starts merge whole regions)

# ----------------------------------------------------------------------------------------------
# register naming
# ----------------------------------------------------------------------------------------------
_X86_CANON = {}
for _b in "abcd":
    for _n in (f"r{_b}x", f"e{_b}x", f"{_b}x", f"{_b}l", f"{_b}h"):
        _X86_CANON[_n] = f"r{_b}x"
for _b in ("si", "di", "bp", "sp"):
    for _n in (f"r{_b}", f"e{_b}", _b, f"{_b}l"):
        _X86_CANON[_n] = f"r{_b}"
for _i in range(8, 16):
    for _n in (f"r{_i}", f"r{_i}d", f"r{_i}w", f"r{_i}b"):
        _X86_CANON[_n] = f"r{_i}"
_X86_CALLER_SAVED = {"sysv": ("rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"),
                     "win64": ("rax", "rcx", "rdx", "r8", "r9", "r10", "r11"),
                     "cdecl": ("rax", "rcx", "rdx")}
_A64_CALLER_SAVED = tuple(f"x{i}" for i in range(19)) + ("x30",)


def _xc(name: str) -> str:
    return _X86_CANON.get(name, name)


def _ac(name: str) -> str:
    """AArch64 canonical name: wN -> xN, wzr -> xzr, wsp -> sp."""
    if not name:
        return name
    if name == "wzr":
        return "xzr"
    if name == "wsp":
        return "sp"
    if name[0] == "w" and name[1:].isdigit():
        return "x" + name[1:]
    return name


def _mask(bits):
    return (1 << bits) - 1


def _sx(v, bits):
    v &= _mask(bits)
    return v - (1 << bits) if v >> (bits - 1) else v


# ----------------------------------------------------------------------------------------------
# flags
# ----------------------------------------------------------------------------------------------
def _f_sub(a, b, bits):
    m = _mask(bits)
    a, b = a & m, b & m
    r = (a - b) & m
    sa, sb, sr = a >> (bits - 1), b >> (bits - 1), r >> (bits - 1)
    # x86 CF = borrow; AArch64 C = NOT borrow -- both derived from `borrow` by the caller
    return {"Z": r == 0, "N": bool(sr), "borrow": a < b, "O": sa != sb and sr != sa}


def _f_add(a, b, bits):
    m = _mask(bits)
    a, b = a & m, b & m
    r = (a + b) & m
    sa, sb, sr = a >> (bits - 1), b >> (bits - 1), r >> (bits - 1)
    return {"Z": r == 0, "N": bool(sr), "carry": a + b > m, "O": sa == sb and sr != sa}


def _f_logic(r, bits):
    r &= _mask(bits)
    # C = V = 0 on both ISAs (x86 TEST/AND, AArch64 TST/ANDS); no "borrow" key, so the AArch64
    # NOT-borrow carry convention in _a64_cond does not turn this into C = 1
    return {"Z": r == 0, "N": bool(r >> (bits - 1)), "carry": False, "O": False}


def _x86_cond(cc, f):
    Z, S, O = f["Z"], f["N"], f["O"]
    C = f.get("borrow", f.get("carry", False))
    table = {"je": Z, "jne": not Z, "ja": not C and not Z, "jae": not C, "jb": C, "jbe": C or Z,
             "jg": not Z and S == O, "jge": S == O, "jl": S != O, "jle": Z or S != O,
             "js": S, "jns": not S, "jo": O, "jno": not O}
    return table.get(cc)


def _a64_cond(cc, f):
    Z, N, V = f["Z"], f["N"], f["O"]
    C = (not f["borrow"]) if "borrow" in f else f.get("carry", False)
    table = {"eq": Z, "ne": not Z, "hs": C, "cs": C, "lo": not C, "cc": not C, "mi": N, "pl": not N,
             "vs": V, "vc": not V, "hi": C and not Z, "ls": (not C) or Z, "ge": N == V,
             "lt": N != V, "gt": (not Z) and N == V, "le": Z or N != V, "al": True}
    return table.get(cc)


_A64_IMM = re.compile(r"^#?(-?(?:0x[0-9a-f]+|\d+))$")
_A64_MEM_IMM = re.compile(r"^(\w+), \[(\w+)(?:, #(-?(?:0x[0-9a-f]+|\d+)))?\](!?)$")
_A64_MEM_POST = re.compile(r"^(\w+), \[(\w+)\], #(-?(?:0x[0-9a-f]+|\d+))$")
_A64_MEM_IDX = re.compile(r"^(\w+), \[(\w+), (\w+)(?:, (lsl|uxtw|sxtw|sxtx|uxtx)(?: #(\d+))?)?\]$")
_A64_SHIFTED = re.compile(r"^(\w+)(?:, (lsl|lsr|asr|uxtw|sxtw|uxtb|uxth|sxtb|sxth|sxtx|uxtx)(?: #(\d+))?)?$")


def _num(s):
    return int(s, 0)


def _a64_bits(reg):
    return 32 if reg.startswith("w") else 64


# ----------------------------------------------------------------------------------------------
# the binary
# ----------------------------------------------------------------------------------------------
class _Bin:
    """The parsed binary plus the bits this tier needs: code, data reads with relocations applied,
    function starts, the ABI's argument registers and a decoded-instruction cache."""

    def __init__(self, path):
        import recover_emulate
        import gen_runtime_sigs
        self.path = Path(path)
        img = recover_emulate.Image(path)
        self.img = img
        self.arm, self.pe, self.x32, self.macho = img.arm, img.pe, img.x32, img.macho
        self.fmt = img.fmt
        self.arch = "aarch64" if img.arm else ("x86" if img.x32 else "x86_64")
        self.code, self.lo, self.hi = img.code, img.text_va, img.text_end
        self.ptr = img.ptr
        self.secs = []
        for s in img.binary.sections:
            try:
                if s.virtual_address and len(s.content):
                    self.secs.append((s.virtual_address, bytes(s.content), bool(img._exec_sec(s)),
                                      s.name if isinstance(s.name, str) else ""))
            except Exception:
                continue
        self.secs.sort(key=lambda t: t[0])
        self._sec_vas = [t[0] for t in self.secs]
        try:
            st = gen_runtime_sigs.function_starts(img.binary)
        except Exception:
            st = set()
        if img.macho:
            # a stripped Mach-O keeps LC_FUNCTION_STARTS (offsets from __TEXT): every function
            try:
                seg = img.binary.get_segment("__TEXT")
                st = set(st) | {seg.virtual_address + o for o in img.binary.function_starts.functions}
            except Exception:
                pass
        self.starts = sorted(a for a in st if self.lo <= a < self.hi)
        from capstone import Cs, CS_ARCH_X86, CS_ARCH_ARM64, CS_MODE_64, CS_MODE_32, CS_MODE_LITTLE_ENDIAN
        if len(self.starts) < 8 or (self.pe and self.x32):
            # no metadata function starts (a stripped PE32 has neither .pdata nor symbols):
            # recursive descent from the entry point, as recover_cfg does
            try:
                import recover_cfg
                ep = img.binary.entrypoint - (img.imagebase if img.pe else 0)
                more = set(recover_cfg._seed_starts(img, self.starts, ep))
            except Exception:
                more = set(self.starts)
            # ... plus every direct call target and every code address held in data or relocated
            # immediates (vtable slots, fn pointers): poll functions are reached through those
            for v in img.patches.values():
                v &= _mask(8 * self.ptr)
                if not (self.lo < v < self.hi):
                    continue
                if self.arm:
                    more.add(v)
                    continue
                # an absolute jump table's relocated case labels are code addresses too: keep a
                # pointer only where a function can start (16-aligned after padding / a return)
                if v % 16 == 0 and self.code[v - self.lo - 1] in (0xCC, 0x90, 0xC3, 0x0B, 0x00):
                    more.add(v)
            if not self.arm:
                from capstone import Cs as _Cs
                lite = _Cs(CS_ARCH_X86, CS_MODE_32 if self.x32 else CS_MODE_64)
                for addr, size, mn, ops in lite.disasm_lite(self.code, self.lo):
                    if mn == "call" and ops.startswith("0x") and int(ops, 16) != addr + size:
                        more.add(int(ops, 16))          # (not `call $+5`, the i386 PC fetch)
            self.starts = sorted(a for a in more if self.lo <= a < self.hi)
        self.got = None
        if self.x32 and not self.pe:     # i386 PIC addresses data as [ebx + d], ebx = the GOT
            for nm in (".got.plt", ".got"):
                sec = next((t for t in self.secs if t[3] == nm), None)
                if sec:
                    self.got = sec[0]
                    break
        if self.arm:
            self.args, self.abi = ("x0", "x1", "x2", "x3"), "aapcs64"
        elif self.x32:
            self.args, self.abi = (), "cdecl"     # arguments on the stack: [esp+4], [esp+8], ...
        elif self.pe:
            self.args, self.abi = ("rcx", "rdx", "r8", "r9"), "win64"
        else:
            self.args, self.abi = ("rdi", "rsi", "rdx", "rcx"), "sysv"
        from capstone import Cs, CS_ARCH_X86, CS_ARCH_ARM64, CS_MODE_64, CS_MODE_32, CS_MODE_LITTLE_ENDIAN
        self.md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN) if self.arm else \
            Cs(CS_ARCH_X86, CS_MODE_32 if self.x32 else CS_MODE_64)
        self.md.detail = True
        self._insn = {}
        try:
            from recover_emulate import TRAMP
        except Exception:
            TRAMP = None
        self.tramp_base = TRAMP

    # --- data ---
    def read(self, va, n):
        i = bisect.bisect_right(self._sec_vas, va) - 1
        if i < 0:
            return None
        base, raw, _x, _nm = self.secs[i]
        o = va - base
        if 0 <= o and o + n <= len(raw):
            return raw[o:o + n]
        return None

    def is_data(self, va):
        i = bisect.bisect_right(self._sec_vas, va) - 1
        if i < 0:
            return False
        base, raw, ex, _nm = self.secs[i]
        return 0 <= va - base < len(raw) and not ex

    def read_ptr(self, va):
        p = self.img.patches.get(va)
        if p is not None:
            return p & _mask(8 * self.ptr)
        raw = self.read(va, self.ptr)
        if raw is None:
            return None
        v = int.from_bytes(raw, "little")
        if self.pe and v >= self.img.imagebase:
            v -= self.img.imagebase           # an unrelocated absolute VA -> RVA
        return v

    def import_name(self, va):
        if self.tramp_base is None or va is None:
            return None
        i = (va - self.tramp_base) // 16
        if 0 <= i < len(self.img.tramp) and va >= self.tramp_base:
            return self.img.tramp[i]
        return None

    # --- code ---
    def fn_bounds(self, va):
        i = bisect.bisect_right(self.starts, va) - 1
        lo = self.starts[i] if i >= 0 else self.lo
        hi = self.starts[i + 1] if i + 1 < len(self.starts) else self.hi
        return lo, hi

    def insn(self, va):
        """The instruction decoded at `va` (cached), or None."""
        if va in self._insn:
            return self._insn[va]
        ins = None
        if self.lo <= va < self.hi:
            o = va - self.lo
            for i in self.md.disasm(self.code[o:o + 16], va):
                ins = i
                break
        self._insn[va] = ins
        return ins

    def sweep(self, lo, hi):
        """Linear sweep of [lo, hi): the decoded instructions (cached)."""
        out = []
        o = lo - self.lo
        for i in self.md.disasm(self.code[o:hi - self.lo], lo):
            self._insn[i.address] = i
            out.append(i)
        return out


# ----------------------------------------------------------------------------------------------
# 1. anchors
# ----------------------------------------------------------------------------------------------
_LEA_RIP = re.compile(rb"[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]", re.S)


def _code_refs(b: _Bin, targets: set):
    """[(code VA, target)] where code materializes one of `targets`: x86-64 `lea r, [rip+d]`,
    AArch64 `adr` / `adrp`+`add`, i386 absolute or GOT-relative immediates. Byte/word scans."""
    out = []
    code, lo = b.code, b.lo
    if not targets:
        return out
    if b.arm:
        n = len(code) // 4
        words = struct.unpack_from(f"<{n}I", code)
        for i, w in enumerate(words):
            pc = lo + 4 * i
            if (w & 0x9f000000) == 0x10000000:                       # adr
                imm = (((w >> 5) & 0x7ffff) << 2) | ((w >> 29) & 3)
                if (pc + _sx(imm, 21)) in targets:
                    out.append((pc, pc + _sx(imm, 21)))
            elif (w & 0x9f000000) == 0x90000000:                     # adrp ; add rd, rd, #lo12
                imm = (((w >> 5) & 0x7ffff) << 2) | ((w >> 29) & 3)
                page = (pc & ~0xfff) + (_sx(imm, 21) << 12)
                rd = w & 31
                for j in range(i + 1, min(n, i + 4)):
                    w2 = words[j]
                    if (w2 & 0xffc00000) == 0x91000000 and ((w2 >> 5) & 31) == rd:
                        if page + ((w2 >> 10) & 0xfff) in targets:
                            out.append((lo + 4 * j, page + ((w2 >> 10) & 0xfff)))
                        break
    elif not b.x32:
        for m in _LEA_RIP.finditer(code):
            o = m.start()
            if o + 7 > len(code):
                continue
            d = struct.unpack_from("<i", code, o + 3)[0]
            if lo + o + 7 + d in targets:
                out.append((lo + o, lo + o + 7 + d))
    else:
        # i386: an absolute address (non-PIC / PE, relocated) or a GOT-relative displacement
        # (PIC `lea r, [ebx + d]`) appears as a 4-byte immediate somewhere in the instruction
        for t in targets:
            pats = []
            if b.pe:
                pats.append(t + b.img.imagebase)
            else:
                pats.append(t)
                if b.got is not None:
                    pats.append(t - b.got)
            for pv in pats:
                pat = (pv & _mask(32)).to_bytes(4, "little")
                o = code.find(pat)
                while o != -1:
                    out.append((lo + o, t))
                    o = code.find(pat, o + 1)
    return out


def _call_sites(b: _Bin, fns: set):
    """Call / tail-jump sites whose target is in `fns`: direct rel32 / bl / b, and x86-64
    `call|jmp [rip+slot]` whose slot (relocated) holds one of them."""
    out = []
    code, lo = b.code, b.lo
    if not fns:
        return out
    if b.arm:
        n = len(code) // 4
        words = struct.unpack_from(f"<{n}I", code)
        for i, w in enumerate(words):
            if (w & 0x7c000000) == 0x14000000:                       # b / bl
                if lo + 4 * i + (_sx(w & 0x3ffffff, 26) << 2) in fns:
                    out.append(lo + 4 * i)
        return out
    slots = {}
    for o in range(len(code) - 5):
        op = code[o]
        if op in (0xe8, 0xe9):
            t = lo + o + 5 + struct.unpack_from("<i", code, o + 1)[0]
            if t in fns:
                out.append(lo + o)
        elif op == 0xff and code[o + 1] in (0x15, 0x25) and o + 6 <= len(code):
            if b.x32:        # `call [abs32]`: an absolute slot address (PE: an IAT entry)
                slot = struct.unpack_from("<I", code, o + 2)[0] - (b.img.imagebase if b.pe else 0)
            else:
                slot = lo + o + 6 + struct.unpack_from("<i", code, o + 2)[0]
            if slot not in slots:
                slots[slot] = b.read_ptr(slot)
            if slots[slot] in fns:
                out.append(lo + o)
    return out


def find_anchors(b: _Bin) -> dict:
    """The panic anchors: string VAs, pointer slots holding them (older `&[&str]` pieces), the small
    helper functions that reference them (panic_const_*) and inline reference sites in bigger
    functions (older rustc's direct `panic("...")`)."""
    res = {"strings": {}, "funcs": {"returned": set(), "panicked": set()},
           "inline": {"returned": set(), "panicked": set()}, "refs": {}}
    by_va = {}
    for base, raw, ex, _nm in b.secs:
        if ex:
            continue
        for kind, s in ANCHOR_STRINGS.items():
            o = raw.find(s)
            while o != -1:
                by_va[base + o] = kind
                res["strings"].setdefault(kind, []).append(base + o)
                o = raw.find(s, o + 1)
    if not by_va:
        return res
    # pointer slots holding a string address (fmt pieces / &str statics), relocated or raw
    slot_kind = {}
    for va, v in b.img.patches.items():
        if v in by_va:
            slot_kind[va] = by_va[v]
    if not b.pe:
        for base, raw, ex, _nm in b.secs:
            if ex:
                continue
            for o in range(0, len(raw) - b.ptr + 1, b.ptr):
                v = int.from_bytes(raw[o:o + b.ptr], "little")
                if v in by_va:
                    slot_kind[base + o] = by_va[v]
    kind_of = dict(by_va)
    kind_of.update(slot_kind)
    res["refs"] = kind_of
    for site, tgt in _code_refs(b, set(kind_of)):
        kind = kind_of.get(tgt)
        if kind is None:
            continue
        lo, hi = b.fn_bounds(site)
        if hi - lo <= _ANCHOR_FN_MAX:
            res["funcs"][kind].add(lo)
        else:
            res["inline"][kind].add(site)
    return res


def _const_of(b: _Bin, ins):
    """The absolute address an `lea r,[rip+d]` / `adr` / `add xd, xd, #lo12` (after its adrp)
    materializes, or None."""
    if b.arm:
        if ins.mnemonic in ("adr", "adrp"):
            m = re.match(r"^\w+, #(0x[0-9a-f]+|\d+)$", ins.op_str)
            return int(m.group(1), 0) if m else None
        if ins.mnemonic == "add":
            m = re.match(r"^(\w+), (\w+), #(0x[0-9a-f]+|\d+)$", ins.op_str)
            if m:
                for back in (4, 8, 12):
                    p = b.insn(ins.address - back)
                    if p is not None and p.mnemonic == "adrp" and _ac(p.op_str.split(",")[0]) == _ac(m.group(2)):
                        page = _const_of(b, p)
                        return None if page is None else page + int(m.group(3), 0)
        return None
    from capstone.x86 import X86_OP_MEM, X86_OP_IMM, X86_REG_RIP
    if b.x32:
        # PIC `lea r, [ebx + d]` (ebx = GOT), or an absolute data address (non-PIC / PE) in a
        # `lea r, [abs]`, `mov r, imm32` or `push imm32`
        c = None
        ops = ins.operands
        if ins.mnemonic == "lea" and len(ops) == 2 and ops[1].type == X86_OP_MEM and not ops[1].mem.index:
            mem = ops[1].mem
            if mem.base and _xc(ins.reg_name(mem.base)) in ("rbx", "rsi", "rdi") and b.got is not None \
                    and abs(mem.disp) >= 0x100:
                # the PIC base is conventionally ebx, but LLVM keeps it in any callee-saved
                # register; a small displacement is a field access, not a GOT-relative address
                c = (b.got + mem.disp) & _mask(32)
            elif not mem.base:
                c = mem.disp & _mask(32)
                if b.pe:
                    c -= b.img.imagebase
        elif ins.mnemonic in ("mov", "push") and ops and ops[-1].type == X86_OP_IMM \
                and (ins.mnemonic == "push" or ops[0].size == 4):
            c = ops[-1].imm & _mask(32)
            if b.pe:
                c -= b.img.imagebase
        return c if c is not None and b.is_data(c) else None
    if ins.mnemonic == "lea":
        op = ins.operands[1]
        if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP and not op.mem.index:
            return ins.address + ins.size + op.mem.disp
    return None


# ----------------------------------------------------------------------------------------------
# 2. the dispatch interpreter
# ----------------------------------------------------------------------------------------------
class _Run:
    __slots__ = ("target", "jt", "table", "reads", "branches", "path", "regs")

    def __init__(self):
        self.target = None      # where control lands for this state value
        self.jt = False         # passed through an indirect (table) jump
        self.table = None       # first table read VA
        self.reads = []         # table entry VAs read
        self.branches = 0
        self.path = []          # instructions the dispatch executed (its CFG edges are "dispatch")
        self.regs = {}          # register values when it stopped


def _x86_op_val(b, ins, op, regs, smem, v, run):
    """Value of an x86 operand, or None if unknown. Raises _Stop for a memory read that is neither
    the state field nor a resolvable table entry."""
    from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM, X86_REG_RIP
    bits = op.size * 8 or 64
    if op.type == X86_OP_IMM:
        return op.imm & _mask(bits)
    if op.type == X86_OP_REG:
        nm = ins.reg_name(op.reg)
        c = _xc(nm)
        if c not in regs:
            return None
        val = regs[c]
        if nm.endswith("h") and len(nm) == 2:
            val >>= 8
        return val & _mask(bits)
    if op.type == X86_OP_MEM:
        mem = op.mem
        key = (_xc(ins.reg_name(mem.base)) if mem.base else None,
               _xc(ins.reg_name(mem.index)) if mem.index else None, mem.scale, mem.disp)
        if smem is not None and key == smem[0] and not mem.segment:
            return v & _mask(min(bits, smem[1]))
        disp = mem.disp
        if mem.base == X86_REG_RIP:
            base = ins.address + ins.size
        elif mem.base:
            base = regs.get(_xc(ins.reg_name(mem.base)))
            if base is None and b.x32 and b.got is not None and mem.index and mem.scale == 4:
                # i386 PIC jump table `[reg + idx*4 - d]`: the base register holds the GOT (set
                # by a `call; pop; add` far from here); a wrong guess fails the panic-arm check
                base = regs[_xc(ins.reg_name(mem.base))] = b.got
        else:
            base = 0
            if b.x32 and b.pe:               # `[table + idx*4]`: an absolute (relocated) VA
                disp = (disp & _mask(32)) - b.img.imagebase
        idx = 0
        if mem.index:
            idx = regs.get(_xc(ins.reg_name(mem.index)))
        if base is None or idx is None or mem.segment:
            raise _Stop()
        addr = (base + idx * mem.scale + disp) & _mask(32 if b.x32 else 64)
        # (mingw's i686 and Apple's x86-64 tables sit in the code section itself)
        if not (b.is_data(addr) or ((b.x32 or b.macho) and b.lo <= addr < b.hi)):
            raise _Stop()
        if b.x32 and op.size == 4 and addr in b.img.patches:
            val = b.img.patches[addr] & _mask(32)   # an absolute table entry, relocated (RVA)
        else:
            raw = b.read(addr, op.size)
            if raw is None:
                raise _Stop()
            val = int.from_bytes(raw, "little")
            if b.x32 and b.pe and op.size == 4 and mem.scale == 4 and val >= b.img.imagebase \
                    and b.lo <= val - b.img.imagebase < b.hi:
                val -= b.img.imagebase           # unrelocated absolute code address
        if run.table is None:
            run.table = addr
        run.reads.append(addr)
        return val
    return None


class _Stop(Exception):
    pass


def _run_x86(b: _Bin, load_va: int, v: int, lo: int, hi: int, seed=None) -> _Run:
    from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM
    run = _Run()
    ins = b.insn(load_va)
    regs = dict(seed or {})
    flags = None
    mop = next((o for o in ins.operands if o.type == X86_OP_MEM), None)
    if mop is None:                       # `movzx r32, r8`: the state lives in a register
        smem = (None, 8 * ins.operands[1].size)
    else:
        mem = mop.mem
        smem = ((_xc(ins.reg_name(mem.base)) if mem.base else None,
                 _xc(ins.reg_name(mem.index)) if mem.index else None, mem.scale, mem.disp), mop.size * 8)
    seg = ins.address + ins.size
    pc = load_va
    steps = 0
    first = True
    pushed = None
    tainted = False         # an unrelated load ran: a plain jump now is body control flow
    while steps < _RUN_STEPS:
        steps += 1
        ins = b.insn(pc)
        if ins is None or not (lo <= pc < hi):
            run.target = seg
            return run
        run.path.append(pc)
        m = ins.mnemonic
        ops = ins.operands
        nxt = pc + ins.size
        try:
            if first:
                first = False
                if m in ("cmp", "test"):
                    a = v & _mask(smem[1])
                    c = _x86_op_val(b, ins, ops[1], regs, smem, v, run)
                    if c is None:
                        raise _Stop()
                    flags = _f_sub(a, c, smem[1]) if m == "cmp" else _f_logic(a & c, smem[1])
                else:
                    regs[_xc(ins.reg_name(ops[0].reg))] = v & _mask(smem[1])
                    # a load into the base register clobbers it: the field is gone afterwards
                    if smem[0] is None or smem[0][0] == _xc(ins.reg_name(ops[0].reg)):
                        smem = None
                pc = nxt
                continue
            if m in ("nop", "endbr64", "endbr32") or m.startswith("nop"):
                pc = nxt
                continue
            if b.x32 and m == "call" and ops and ops[0].type == X86_OP_IMM and ops[0].imm == nxt:
                pushed = nxt                    # `call $+5 ; pop reg`: the i386 PC fetch, which
                pc = nxt                        # LLVM schedules into the dispatch sequence
                continue
            if b.x32 and m == "pop" and pushed is not None and ops and ops[0].type == X86_OP_REG:
                regs[_xc(ins.reg_name(ops[0].reg))] = pushed
                pushed = None
                pc = nxt
                continue
            if m in ("mov", "movzx", "movsx", "movsxd", "movabs"):
                if ops[0].type != X86_OP_REG:
                    # a spill to the stack may be scheduled into the dispatch; any other store
                    # means the body has started
                    if ops[0].type == X86_OP_MEM and ops[0].mem.base and \
                            _xc(ins.reg_name(ops[0].mem.base)) in ("rsp", "rbp") \
                            and not (smem is not None and smem[0] is not None
                                     and smem[0][0] in ("rsp", "rbp")):
                        tainted = True
                        pc = nxt
                        continue
                    raise _Stop()
                try:
                    val = _x86_op_val(b, ins, ops[1], regs, smem, v, run)
                except _Stop:
                    val = None                       # an unrelated load interleaved by the scheduler
                    tainted = True
                dst = _xc(ins.reg_name(ops[0].reg))
                if ops[1].type == X86_OP_IMM:
                    tainted = True      # argument set-up (`mov esi, len`): body, not dispatch
                if val is not None and m in ("movsx", "movsxd"):
                    val = _sx(val, ops[1].size * 8) & _mask(64)
                if val is None:
                    regs.pop(dst, None)
                else:
                    regs[dst] = val & _mask(ops[0].size * 8 if ops[0].size >= 4 else 64)
                if smem is not None and smem[0][0] == dst:
                    smem = None
                pc = nxt
                continue
            if m == "lea":
                dst = _xc(ins.reg_name(ops[0].reg))
                mm = ops[1].mem
                tainted = True          # a table base (then an indirect jump) or body set-up
                from capstone.x86 import X86_REG_RIP
                if mm.base == X86_REG_RIP:
                    regs[dst] = ins.address + ins.size + mm.disp
                else:
                    bv = regs.get(_xc(ins.reg_name(mm.base))) if mm.base else 0
                    iv = regs.get(_xc(ins.reg_name(mm.index))) if mm.index else 0
                    if bv is None or iv is None:
                        regs.pop(dst, None)
                    else:
                        regs[dst] = (bv + iv * mm.scale + mm.disp) & _mask(64)
                if smem is not None and smem[0][0] == dst:
                    smem = None
                pc = nxt
                continue
            if m in ("cmp", "test"):
                a = _x86_op_val(b, ins, ops[0], regs, smem, v, run)
                c = _x86_op_val(b, ins, ops[1], regs, smem, v, run)
                bits = ops[0].size * 8
                if a is None or c is None:
                    flags = None
                else:
                    flags = _f_sub(a, c, bits) if m == "cmp" else _f_logic(a & c, bits)
                pc = nxt
                continue
            if m in ("add", "sub", "and", "or", "xor", "inc", "dec", "neg", "shl", "shr", "sar", "not"):
                if ops[0].type != X86_OP_REG:
                    raise _Stop()
                dst = _xc(ins.reg_name(ops[0].reg))
                bits = ops[0].size * 8
                a = _x86_op_val(b, ins, ops[0], regs, smem, v, run)
                c = _x86_op_val(b, ins, ops[1], regs, smem, v, run) if len(ops) > 1 else None
                if m == "add" and c is None and a is not None and run.reads and "__pic" in regs \
                        and len(ops) == 2 and ops[1].type == X86_OP_REG:
                    # i386 `add entry, pic`: a relative table entry plus the function's PC base
                    # (`call $+5; pop reg` earlier, out of this run's sight)
                    c = regs[_xc(ins.reg_name(ops[1].reg))] = regs["__pic"]
                if m == "xor" and len(ops) == 2 and ops[1].type == X86_OP_REG and ops[1].reg == ops[0].reg:
                    a = c = 0
                r = None
                if a is not None and (c is not None or m in ("inc", "dec", "neg", "not")):
                    if m == "add":
                        r, flags = a + c, _f_add(a, c, bits)
                    elif m == "sub":
                        r, flags = a - c, _f_sub(a, c, bits)
                    elif m == "inc":
                        r, flags = a + 1, _f_add(a, 1, bits)
                    elif m == "dec":
                        r, flags = a - 1, _f_sub(a, 1, bits)
                    elif m == "neg":
                        r, flags = -a, _f_sub(0, a, bits)
                    elif m == "not":
                        r = ~a
                    elif m in ("shl", "shr", "sar"):
                        k = c & (bits - 1)
                        r = a << k if m == "shl" else (a >> k if m == "shr" else _sx(a, bits) >> k)
                        flags = _f_logic(r, bits)
                    else:
                        r = a & c if m == "and" else (a | c if m == "or" else a ^ c)
                        flags = _f_logic(r, bits)
                else:
                    flags = None
                if r is None:
                    regs.pop(dst, None)
                else:
                    regs[dst] = r & _mask(bits if bits >= 32 else 64)
                if smem is not None and smem[0][0] == dst:
                    smem = None
                pc = nxt
                continue
            if m.startswith("j") and m != "jmp":
                if flags is None:
                    raise _Stop()
                cond = _x86_cond(m, flags)
                if cond is None:
                    raise _Stop()
                run.branches += 1
                tainted = False
                if cond:
                    pc = seg = ops[0].imm
                else:
                    pc = seg = nxt
                continue
            if m == "jmp":
                op = ops[0]
                if op.type == X86_OP_IMM:
                    if tainted:
                        raise _Stop()
                    pc = seg = op.imm
                    continue
                if op.type == X86_OP_REG:
                    t = _x86_op_val(b, ins, op, regs, smem, v, run)
                elif op.type == X86_OP_MEM and b.x32:
                    t = _x86_op_val(b, ins, op, regs, smem, v, run)   # i386 `jmp [table + idx*4]`
                else:
                    t = None
                if t is None:
                    raise _Stop()
                run.jt = True
                pc = seg = t
                continue
            raise _Stop()
        except _Stop:
            run.target = seg
            run.regs = regs
            return run
    return run      # step budget exhausted: unresolved (target None)


def _a64_reg_val(regs, name):
    c = _ac(name)
    if c == "xzr":
        return 0
    v = regs.get(c)
    if v is None:
        return None
    return v & _mask(_a64_bits(name))


def _a64_operand(regs, text):
    """`x9`, `w8, uxtw #2`, `x10, lsl #2`, `#0x12` -> value or None."""
    text = text.strip()
    im = _A64_IMM.match(text)
    if im:
        return _num(im.group(1))
    m = _A64_SHIFTED.match(text)
    if not m:
        return None
    val = _a64_reg_val(regs, m.group(1))
    if val is None:
        return None
    kind, amt = m.group(2), int(m.group(3) or 0)
    if kind in (None, "lsl"):
        return val << amt
    if kind == "lsr":
        return val >> amt
    if kind == "asr":
        return _sx(val, _a64_bits(m.group(1))) >> amt
    if kind in ("sxtw", "sxtx"):
        return _sx(val, 32 if kind == "sxtw" else 64) << amt
    if kind in ("uxtw", "uxtx"):
        return (val & _mask(32 if kind == "uxtw" else 64)) << amt
    if kind in ("uxtb", "sxtb"):
        return ((val & 0xff) if kind == "uxtb" else _sx(val, 8)) << amt
    if kind in ("uxth", "sxth"):
        return ((val & 0xffff) if kind == "uxth" else _sx(val, 16)) << amt
    return None


_A64_LOAD = {"ldrb": (1, False), "ldurb": (1, False), "ldrh": (2, False), "ldurh": (2, False),
             "ldrsb": (1, True), "ldursb": (1, True), "ldrsh": (2, True), "ldursh": (2, True),
             "ldrsw": (4, True), "ldursw": (4, True), "ldr": (None, False), "ldur": (None, False)}


def _run_a64(b: _Bin, load_va: int, v: int, lo: int, hi: int, seed=None) -> _Run:
    run = _Run()
    ins = b.insn(load_va)
    regs = dict(seed or {})
    flags = None
    m0 = _A64_MEM_IMM.match(ins.op_str)
    if m0 is None:                      # `and wD, wS, #0xff` / `uxtb`: the state is in a register
        width = 2 if ins.op_str.endswith("0xffff") or ins.mnemonic == "uxth" else 1
        regs[_ac(ins.op_str.split(",")[0])] = v & _mask(8 * width)
        smem = None
    else:
        width, _s = _A64_LOAD[ins.mnemonic]
        if width is None:
            width = 4 if m0.group(1).startswith("w") else 8
        sbase, sdisp = _ac(m0.group(2)), _num(m0.group(3) or "0")
        regs[_ac(m0.group(1))] = v & _mask(8 * width)
        if m0.group(4) == "!":              # pre-index: base += disp, the field is now at [base]
            sdisp = 0
        smem = (sbase, sdisp)
        if _ac(m0.group(1)) == sbase:
            smem = None
    seg = load_va + 4
    pc = load_va + 4
    steps = 0
    tainted = False
    while steps < _RUN_STEPS:
        steps += 1
        ins = b.insn(pc)
        if ins is None or not (lo <= pc < hi):
            run.target = seg
            return run
        run.path.append(pc)
        m, s = ins.mnemonic, ins.op_str
        nxt = pc + 4
        parts = [p.strip() for p in s.split(",")] if s else []
        try:
            if m in ("nop", "hint", "bti"):
                pc = nxt
                continue
            if m in ("str", "stur", "stp", "strb", "strh") and re.search(r"\[(sp|x29)(, #[^\]]*)?\]$", s) \
                    and (smem is None or smem[0] not in ("sp", "x29")):
                tainted = True                  # a spill scheduled into the dispatch
                pc = nxt
                continue
            if m in _A64_LOAD:
                width, signed = _A64_LOAD[m]
                dst = parts[0]
                if width is None:
                    width = 4 if dst.startswith("w") else 8
                mi = _A64_MEM_IMM.match(s)
                mx = _A64_MEM_IDX.match(s)
                val = None
                if mi:
                    base, disp = _ac(mi.group(2)), _num(mi.group(3) or "0")
                    if smem is not None and (base, disp) == smem:
                        val = v & _mask(8 * width)
                    else:
                        bv = 0 if base == "xzr" else regs.get(base)
                        if bv is not None and b.is_data(bv + disp):
                            raw = b.read(bv + disp, width)
                            if raw is None:
                                raise _Stop()
                            val = int.from_bytes(raw, "little", signed=signed)
                            run.reads.append(bv + disp)
                            run.table = run.table or bv + disp
                        else:
                            tainted = True              # an unrelated load interleaved by the scheduler
                    if mi.group(4) == "!":              # pre-index writeback: base += disp
                        if base in regs:
                            regs[base] = (regs[base] + disp) & _mask(64)
                        if smem is not None and smem[0] == base:
                            smem = (base, smem[1] - disp)
                elif mx:
                    bv = regs.get(_ac(mx.group(2)))
                    iv = _a64_reg_val(regs, mx.group(3))
                    if bv is None or iv is None:
                        raise _Stop()
                    kind, amt = mx.group(4), int(mx.group(5) or 0)
                    if kind == "sxtw":
                        iv = _sx(iv, 32)
                    elif kind == "uxtw":
                        iv &= _mask(32)
                    addr = (bv + (iv << amt)) & _mask(64)
                    if not b.is_data(addr):
                        raise _Stop()
                    raw = b.read(addr, width)
                    if raw is None:
                        raise _Stop()
                    val = int.from_bytes(raw, "little", signed=signed)
                    run.reads.append(addr)
                    run.table = run.table or addr
                else:
                    raise _Stop()
                if val is None:
                    regs.pop(_ac(dst), None)
                else:
                    regs[_ac(dst)] = val & _mask(_a64_bits(dst) if signed else 8 * max(width, 4))
                if smem is not None and _ac(dst) == smem[0]:
                    smem = None
                pc = nxt
                continue
            if m in ("adr", "adrp"):
                regs[_ac(parts[0])] = _num(parts[1].lstrip("#"))
                tainted = True
                pc = nxt
                continue
            if m == "mov" and len(parts) == 2:
                dst = _ac(parts[0])
                val = _a64_operand(regs, parts[1])
                if _A64_IMM.match(parts[1]):
                    tainted = True
                if val is None:
                    regs.pop(dst, None)
                else:
                    regs[dst] = val & _mask(_a64_bits(parts[0]))
                if smem is not None and dst == smem[0]:
                    smem = None
                pc = nxt
                continue
            if m in ("add", "sub", "adds", "subs", "and", "ands", "orr", "eor", "lsl", "lsr", "asr") and len(parts) >= 3:
                dst = _ac(parts[0])
                bits = _a64_bits(parts[0])
                a = _a64_reg_val(regs, parts[1])
                c = _a64_operand(regs, ", ".join(parts[2:]))
                r = None
                if a is not None and c is not None:
                    if m in ("add", "adds"):
                        r = a + c
                        if m == "adds":
                            flags = _f_add(a, c, bits)
                    elif m in ("sub", "subs"):
                        r = a - c
                        if m == "subs":
                            flags = _f_sub(a, c, bits)
                    elif m in ("and", "ands"):
                        r = a & c
                        if m == "ands":
                            flags = _f_logic(r, bits)
                    elif m == "orr":
                        r = a | c
                    elif m == "eor":
                        r = a ^ c
                    elif m == "lsl":
                        r = a << (c & (bits - 1))
                    elif m == "lsr":
                        r = a >> (c & (bits - 1))
                    else:
                        r = _sx(a, bits) >> (c & (bits - 1))
                elif m in ("adds", "subs", "ands"):
                    flags = None
                if dst not in ("xzr", "sp"):
                    if r is None:
                        regs.pop(dst, None)
                    else:
                        regs[dst] = r & _mask(bits)
                if smem is not None and dst == smem[0]:
                    smem = None
                pc = nxt
                continue
            if m in ("cmp", "cmn", "tst") and len(parts) >= 2:
                bits = _a64_bits(parts[0])
                a = _a64_reg_val(regs, parts[0])
                c = _a64_operand(regs, ", ".join(parts[1:]))
                if a is None or c is None:
                    flags = None
                elif m == "cmp":
                    flags = _f_sub(a, c, bits)
                elif m == "cmn":
                    flags = _f_add(a, c, bits)
                else:
                    flags = _f_logic(a & c, bits)
                pc = nxt
                continue
            if m.startswith("b.") and len(parts) == 1:
                if flags is None:
                    raise _Stop()
                cond = _a64_cond(m[2:], flags)
                if cond is None:
                    raise _Stop()
                run.branches += 1
                tainted = False
                pc = seg = (_num(parts[0].lstrip("#")) if cond else nxt)
                continue
            if m in ("cbz", "cbnz") and len(parts) == 2:
                a = _a64_reg_val(regs, parts[0])
                if a is None:
                    raise _Stop()
                run.branches += 1
                take = (a == 0) == (m == "cbz")
                tainted = False
                pc = seg = (_num(parts[1].lstrip("#")) if take else nxt)
                continue
            if m in ("tbz", "tbnz") and len(parts) == 3:
                a = _a64_reg_val(regs, parts[0])
                if a is None:
                    raise _Stop()
                run.branches += 1
                bit = (a >> _num(parts[1].lstrip("#"))) & 1
                take = (bit == 0) == (m == "tbz")
                tainted = False
                pc = seg = (_num(parts[2].lstrip("#")) if take else nxt)
                continue
            if m == "b" and len(parts) == 1:
                if tainted:
                    raise _Stop()
                pc = seg = _num(parts[0].lstrip("#"))
                continue
            if m == "br" and len(parts) == 1:
                t = regs.get(_ac(parts[0]))
                if t is None:
                    raise _Stop()
                run.jt = True
                pc = seg = t
                continue
            raise _Stop()
        except _Stop:
            run.target = seg
            run.regs = regs
            return run
    return run


def _dispatch_run(b, load_va, v, lo, hi, seed=None):
    """Run the dispatch after the state load at `load_va` with state value `v`. `seed`: constant
    registers known at the load (a jump-table base hoisted out of a loop)."""
    return _run_a64(b, load_va, v, lo, hi, seed) if b.arm else _run_x86(b, load_va, v, lo, hi, seed)


def _is_state_load(b: _Bin, ins):
    """Is `ins` a candidate state load: a 1/2/4-byte read of [reg + disp] (no index) into a
    register, or an x86 `cmp|test <mem>, imm`? Returns the access width in bytes or None."""
    if b.arm:
        if ins.mnemonic in ("and", "uxtb", "uxth"):
            s = ins.op_str
            if re.match(r"^w\d+, w\d+(, #0xff)?$", s) and (ins.mnemonic == "uxtb" or s.endswith("#0xff")):
                return 1
            if re.match(r"^w\d+, w\d+(, #0xffff)?$", s) and (ins.mnemonic == "uxth" or s.endswith("#0xffff")):
                return 2
            return None
        if ins.mnemonic not in ("ldrb", "ldurb", "ldrh", "ldurh", "ldr", "ldur"):
            return None
        mi = _A64_MEM_IMM.match(ins.op_str)
        if not mi or mi.group(2) in ("pc",):
            return None
        w, _s = _A64_LOAD[ins.mnemonic]
        if w is None:
            if not mi.group(1).startswith("w"):
                return None
            w = 4
        return w
    from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM, X86_REG_RIP
    m = ins.mnemonic
    ops = ins.operands
    if m == "movzx" and len(ops) == 2 and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_REG \
            and ops[1].size in (1, 2):
        return ops[1].size                   # a register-promoted state (coroutine inlined into a loop)
    if m in ("movzx", "mov") and len(ops) == 2 and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_MEM:
        mem = ops[1].mem
        if mem.base in (0, X86_REG_RIP) or mem.index or mem.segment or ops[1].size not in (1, 2, 4):
            return None
        if m == "mov" and ops[0].size != ops[1].size:
            return None
        return ops[1].size
    if m in ("cmp", "test") and len(ops) == 2 and ops[0].type == X86_OP_MEM and ops[1].type == X86_OP_IMM:
        mem = ops[0].mem
        if mem.base in (0, X86_REG_RIP) or mem.index or mem.segment or ops[0].size not in (1, 2, 4):
            return None
        return ops[0].size
    return None


# ----------------------------------------------------------------------------------------------
# classification / suspend walks
# ----------------------------------------------------------------------------------------------
def _call_info(b: _Bin, ins, recent):
    """Describe a call instruction: {"kind": direct|import|dyn|indirect, ...}."""
    if b.arm:
        if ins.mnemonic == "bl":
            return {"kind": "direct", "target": _num(ins.op_str.lstrip("#"))}
        reg = _ac(ins.op_str.strip())
        for p in reversed(recent):
            if p.mnemonic in ("ldr", "ldur"):
                mi = _A64_MEM_IMM.match(p.op_str)
                if mi and _ac(mi.group(1)) == reg:
                    disp = _num(mi.group(3) or "0")
                    base_c = None
                    # adrp xN, page ; ldr xM, [xN, #lo] -> a GOT/IAT slot (the adrp must be the
                    # latest write of xN before the load)
                    later = recent[recent.index(p):] if p in recent else []
                    for q in reversed(recent[:len(recent) - len(later)]):
                        if _ac(q.op_str.split(",")[0].strip()) == _ac(mi.group(2)):
                            if q.mnemonic == "adrp":
                                base_c = _const_of(b, q)
                            break
                    if base_c is not None:
                        t = b.read_ptr(base_c + disp)
                        nm = b.import_name(t)
                        return {"kind": "import", "name": nm} if nm else {"kind": "direct", "target": t}
                    return {"kind": "dyn", "slot_offset": disp, "via": (p.address, _ac(mi.group(2)))}
            if p.mnemonic not in ("mov",) and p.op_str.split(",")[0].strip() in (reg, "w" + reg[1:]):
                break
        return {"kind": "indirect"}
    from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP
    op = ins.operands[0]
    if op.type == X86_OP_IMM:
        return {"kind": "direct", "target": op.imm}
    if op.type == X86_OP_MEM:
        if op.mem.base == X86_REG_RIP:
            t = b.read_ptr(ins.address + ins.size + op.mem.disp)
            nm = b.import_name(t)
            return {"kind": "import", "name": nm} if nm else {"kind": "direct", "target": t}
        if op.mem.base and not op.mem.index and _xc(ins.reg_name(op.mem.base)) not in ("rsp", "rbp"):
            return {"kind": "dyn", "slot_offset": op.mem.disp,
                    "via": (ins.address, _xc(ins.reg_name(op.mem.base)))}
        return {"kind": "indirect"}
    if op.type == X86_OP_REG:
        reg = _xc(ins.reg_name(op.reg))
        for p in reversed(recent):
            if p.mnemonic == "mov" and len(p.operands) == 2 and p.operands[0].type == X86_OP_REG \
                    and _xc(p.reg_name(p.operands[0].reg)) == reg:
                src = p.operands[1]
                if src.type == X86_OP_MEM and src.mem.base and src.mem.base != X86_REG_RIP \
                        and not src.mem.index and _xc(p.reg_name(src.mem.base)) not in ("rsp", "rbp"):
                    return {"kind": "dyn", "slot_offset": src.mem.disp,
                            "via": (p.address, _xc(p.reg_name(src.mem.base)))}
                break
    return {"kind": "indirect"}


def _walk(b: _Bin, start, lo, hi, stop_sites=frozenset()):
    """Walk forward from `start` along straight-line code (direct unconditional jumps followed)
    and return (events, consts): events = [("call", va, info) | ("site", va) | ("ref", va, const)
    | ("branch", va)] up to the first call, known dispatch site, conditional branch (control
    splits: what follows is no longer certain) or function exit."""
    events, consts, recent = [], [], []
    pc, seen = start, set()
    for _ in range(_WALK_STEPS):
        if pc in seen or not (lo <= pc < hi):
            break
        seen.add(pc)
        if pc in stop_sites:
            events.append(("site", pc))
            break
        ins = b.insn(pc)
        if ins is None:
            break
        m = ins.mnemonic
        c = _const_of(b, ins)
        if c is not None:
            consts.append(c)
            events.append(("ref", pc, c))
        if m in ("call", "bl", "blr"):
            events.append(("call", pc, _call_info(b, ins, recent[-8:])))
            break
        recent.append(ins)
        if (m.startswith("j") and m != "jmp") or m.startswith("b.") or m in ("cbz", "cbnz", "tbz", "tbnz"):
            events.append(("branch", pc))
            break
        if m in ("ret", "ud2", "int3", "hlt", "brk", "br") or (m == "jmp" and not ins.op_str.startswith("0x")):
            # a tail call `jmp <fn>` / `b <fn>` outside the function is a call too
            break
        if m in ("jmp", "b"):
            t = _num(ins.op_str.lstrip("#"))
            if not (lo <= t < hi):
                events.append(("call", pc, {"kind": "direct", "target": t, "tail": True}))
                break
            pc = t
            continue
        pc += ins.size
    return events, consts


def _classify(b: _Bin, anchors, target, lo, hi):
    """Which panic arm (returned / panicked) the code at `target` reaches first, or None; plus the
    Location constant passed to it."""
    if target is None:
        return None, None
    events, consts = _walk(b, target, lo, hi)
    kind = None
    has_call = any(e[0] == "call" for e in events)
    for e in events:
        if e[0] == "ref" and e[2] in anchors["refs"]:
            # older rustc's `panic("...")`: the message must actually reach a call -- a message
            # pointer hoisted into an inner dispatch ahead of its jump table is not a panic arm
            if has_call:
                kind = anchors["refs"][e[2]]
                break
            continue
        if e[0] == "call":
            t = e[2].get("target")
            for k in ("returned", "panicked"):
                if t in anchors["funcs"][k]:
                    kind = k
            break
    loc = None
    if kind:
        for c in reversed(consts):
            if c not in anchors["refs"] and _location(b, c):
                loc = c
                break
        if loc is None:
            # merged panic arms load the &Location once, before a `cmp state, #1` picks the helper
            step = 4 if b.arm else 1
            for back in range(step, 33, step):
                ins = b.insn(target - back)
                if ins is None or ins.address + ins.size > target:
                    continue
                c = _const_of(b, ins)
                if c is not None and c not in anchors["refs"] and _location(b, c):
                    loc = c
                    break
    return kind, loc


def _location(b: _Bin, va):
    """Parse a core::panic::Location {&str file, u32 line, u32 col} at `va`, or None."""
    if va is None or not b.is_data(va):
        return None
    p = b.read_ptr(va)
    raw = b.read(va + b.ptr, b.ptr + 8)
    if p is None or raw is None:
        return None
    n = int.from_bytes(raw[:b.ptr], "little")
    line, col = struct.unpack_from("<II", raw, b.ptr)
    if not (0 < n < 4096 and 0 < line < 10_000_000 and col < 100_000):
        return None
    s = b.read(p, n)
    if s is None:
        return None
    try:
        f = s.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not f.endswith(".rs") or any(ch in f for ch in "\x00\n"):
        return None
    return {"file": f, "line": line, "col": col}


# ----------------------------------------------------------------------------------------------
# 3. dataflow: pointer aliases (root + offset) and constants
# ----------------------------------------------------------------------------------------------
# A fact is one of
#   ("p", root, k)            the register holds root + k (root: argN, sp, *<root>+off, ...)
#   ("ps", frozenset{(root, k)})  one of several such pointers -- a pointer phi at a merge point
#   ("c", value) / ("cs", frozenset{value})   a constant / one of several constants
#   ("cp", value, bits)       only the low `bits` bits are known (`mov cl, 3`)
# Joins keep a register when every incoming edge knows it, merging differing pointers (or
# constants) into a bounded set; a set that grows past the cap is dropped. Facts only shrink or
# grow towards the cap, so the fixpoint terminates.
_MAX_ALT_PTR = 4
_MAX_ALT_CONST = 8
_ARG_SLOTS_32 = 6          # i386: [esp_entry + 4 .. + 24] are the first six stack arguments


def _ptrs(fact):
    if not fact:
        return None
    if fact[0] == "p":
        return {(fact[1], fact[2])}
    if fact[0] == "ps":
        return set(fact[1])
    return None


def _consts(fact):
    if not fact:
        return None
    if fact[0] == "c":
        return {fact[1]}
    if fact[0] == "cs":
        return set(fact[1])
    return None


def _mkptr(pairs):
    if not pairs or len(pairs) > _MAX_ALT_PTR:
        return None
    if len(pairs) == 1:
        r, k = next(iter(pairs))
        return ("p", r, k)
    return ("ps", frozenset(pairs))


def _mkconst(vals):
    if not vals or len(vals) > _MAX_ALT_CONST:
        return None
    if len(vals) == 1:
        return ("c", next(iter(vals)))
    return ("cs", frozenset(vals))


def _shift(fact, k, bits=64):
    """fact + k (a pointer moves, a constant adds)."""
    p = _ptrs(fact)
    if p is not None:
        return _mkptr({(r, o + k) for r, o in p})
    c = _consts(fact)
    if c is not None:
        return _mkconst({(v + k) & _mask(bits) for v in c})
    return None


def _deref(bf, disp, x32=False):
    """A pointer loaded from [root+k+disp] gets its own symbolic root `*root+off`, so two accesses
    through the same loaded pointer (a `&mut Future` held in the executor's frame) agree. One level
    of indirection beyond an argument / the stack is enough here and keeps roots finite. On i386
    the entry-relative stack slots [esp+4..] ARE the arguments: they load as `argN` itself."""
    if not bf or bf[0] != "p" or bf[1].count("*") >= 2:
        return None
    off = bf[2] + disp
    if x32 and bf[1] == "sp" and 4 <= off <= 4 * _ARG_SLOTS_32 and off % 4 == 0:
        return ("p", f"arg{off // 4 - 1}", 0)
    return ("p", f"*{bf[1]}{off:+#x}", 0)


_DEREF_RE = re.compile(r"^\*(.+?)([+-]0x[0-9a-f]+)$")


def _deref_slot(root):
    """`*sp+0x48` -> ("sp", 0x48): the memory slot a deref'd root was loaded from, or None."""
    m = _DEREF_RE.match(root or "")
    return (m.group(1), int(m.group(2), 16)) if m else None


def _cvals(fact, bits=64):
    """The possible values of a constant(-set) fact in its low `bits` bits, or None. A partial
    fact ("cp"/"cps": only the low w bits known) answers only for bits <= w."""
    if not fact:
        return None
    m = _mask(bits)
    if fact[0] == "c":
        return {fact[1] & m}
    if fact[0] == "cs":
        return {v & m for v in fact[1]}
    if fact[0] in ("cp", "cps") and bits <= fact[2]:
        return {v & m for v in ((fact[1],) if fact[0] == "cp" else fact[1])}
    return None


def _cwidth(fact):
    return fact[2] if fact and fact[0] in ("cp", "cps") else 64


def _mkvals(vals, bits):
    """A constant-set fact for `vals` known in the low `bits` bits (64 = the whole register)."""
    if vals is None or not vals or len(vals) > _MAX_ALT_CONST:
        return None
    if bits >= 64:
        return _mkconst(vals)
    vals = {v & _mask(bits) for v in vals}
    if len(vals) == 1:
        return ("cp", next(iter(vals)), bits)
    return ("cps", frozenset(vals), bits)


def _fvals(bn, fact, bits):
    """Value set of a fact in its low `bits` bits: a constant set, or what the callee returns
    for a call-result fact (its return summary), else None."""
    v = _cvals(fact, bits)
    if v is None and fact and fact[0] == "r":
        rv = _ret_summary(bn, fact[1], fact[2])
        v = {x & _mask(bits) for x in rv} if rv else None
    return v


def _binop(op, a, b, bits):
    m = _mask(bits)
    if op == "add":
        return (a + b) & m
    if op == "sub":
        return (a - b) & m
    if op == "and":
        return a & b
    if op in ("or", "orr"):
        return a | b
    if op in ("xor", "eor"):
        return a ^ b
    if op in ("shl", "lsl"):
        return (a << (b & (bits - 1))) & m
    if op in ("shr", "lsr"):
        return (a & m) >> (b & (bits - 1))
    return None


def _setop(op, av, bv, bits, same=False):
    """Element-wise `op` over two value sets (correlated when both operands are one register)."""
    if av is None or bv is None:
        return None
    if same:
        out = {_binop(op, a, a, bits) for a in av}
    elif len(av) * len(bv) > 4 * _MAX_ALT_CONST:
        return None
    else:
        out = {_binop(op, a, b, bits) for a in av for b in bv}
    return None if None in out else out


def _merge(a, b):
    if a == b:
        return a
    pa, pb = _ptrs(a), _ptrs(b)
    if pa is not None and pb is not None:
        return _mkptr(pa | pb)
    w = min(_cwidth(a), _cwidth(b))
    ca, cb = _cvals(a, w), _cvals(b, w)
    if ca is not None and cb is not None:
        # values reaching from different paths (`mov cl, 3` here, `mov cl, 4` there, the
        # zero of `xor eax, eax` on entry): their set, in the bits both sides know
        return _mkvals(ca | cb, w)
    return None


def _join(a, b):
    if a is None:
        return dict(b)
    out = {}
    for k, va in a.items():
        vb = b.get(k)
        if vb is None:
            continue
        m = _merge(va, vb)
        if m is not None:
            out[k] = m
    return out


def _sp_fact(bn, f):
    """The stack pointer's fact: a constant root on x86-64/AArch64 (rsp/sp do not move after the
    prologue there), tracked through push/pop/sub/add on i386 (cdecl args live above it)."""
    if bn.x32:
        return f.get("rsp")
    return ("p", "sp", 0)


def _callee_pop(bn, target):
    """Bytes an i386 callee pops on return (`ret imm16`: sret / stdcall), from its first `ret`."""
    cache = bn.__dict__.setdefault("_pop_cache", {})
    if target in cache:
        return cache[target]
    pop = 0
    if target is not None and bn.lo <= target < bn.hi:
        o = target - bn.lo
        for ins in bn.md.disasm(bn.code[o:o + 0x1000], target):
            if ins.mnemonic in ("ret", "retn"):
                pop = ins.operands[0].imm if ins.operands else 0
                break
            if ins.mnemonic in ("int3", "ud2", "hlt"):
                break
    cache[target] = pop
    return pop


def _pc_thunk_reg(bn, target):
    """If `target` is an i386 PIC thunk `mov reg, [esp]; ret`, the register it loads, else None."""
    raw = bn.read(target, 4) if target is not None and bn.lo <= target < bn.hi else None
    if raw and raw[0] == 0x8B and raw[2] == 0x24 and raw[3] == 0xC3 and (raw[1] & 0xC7) == 0x04:
        return ("rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi")[(raw[1] >> 3) & 7]
    return None


def _slot_clear(f, slot, size, ptr=8):
    """A write to the stack slot (root, off) of `size` bytes: forget every spill it overlaps
    (a remembered spill is at most pointer-sized)."""
    root, off = slot
    for k in [k for k in f if isinstance(k, tuple) and k[0] == "m" and k[1] == root
              and off - ptr < k[2] < off + size]:
        del f[k]


def _mk(slot, k=0):
    return ("m", slot[0], slot[1] + k)


def _stack_slot(bf, disp):
    """(stack root, offset) of [base+disp] when the base is a plain stack pointer: "sp" is the
    entry stack pointer, "spa" the realigned one after an i386 `and esp, -N`."""
    if bf and bf[0] == "p" and bf[1] in ("sp", "spa"):
        return (bf[1], bf[2] + disp)
    return None


def _ret_regs(bn):
    return ("x0", "x1") if bn.arm else ("rax", "rdx")


def _ret_facts(bn, f, target):
    """After a direct call: the return registers hold "what `target` returns" -- a symbolic fact
    resolved on demand by _ret_summary (a `Pin<Box<dyn Future>>` constructor returns its vtable)."""
    if target is not None and bn.lo <= target < bn.hi:
        for k, r in enumerate(_ret_regs(bn)):
            f[r] = ("r", target, k)


def _ret_summary(bn, target, idx):
    """Constants function `target` returns in return register `idx` on every `ret`, or None."""
    cache = bn.__dict__.setdefault("_ret_cache", {})
    key = (target, idx)
    if key in cache:
        return cache[key]
    cache[key] = None                     # recursion guard
    lo, hi = bn.fn_bounds(target)
    if lo != target or hi - lo > 0x1000:
        return None
    insns = bn.sweep(lo, hi)
    entry = {r: ("p", f"arg{k}", 0) for k, r in enumerate(bn.args)}
    if bn.x32:
        entry = {"rsp": ("p", "sp", 0)}
    at = _dataflow(bn, insns, lo, hi, {}, entry, None)
    vals = set()
    reg = _ret_regs(bn)[idx]
    pos = {i.address: k for k, i in enumerate(insns)}
    for i in insns:
        if i.mnemonic in ("ret", "retn"):
            c = _consts(at.get(i.address, {}).get(reg))
            if c is None:
                # a return block the CFG reaches only through a jump table: evaluate the
                # straight-line code just before the `ret` on its own
                k = pos[i.address]
                j = k
                while j > 0 and k - j < 16:
                    pm = insns[j - 1].mnemonic
                    if pm.startswith("j") or pm in ("ret", "retn", "call", "b", "br", "bl", "blr") \
                            or pm.startswith("b.") or pm in ("cbz", "cbnz", "tbz", "tbnz"):
                        break
                    j -= 1
                loc = {}
                for q in insns[j:k]:
                    _transfer(bn, q, loc)
                c = _consts(loc.get(reg))
            if c is None:
                return None
            vals |= c
    cache[key] = vals or None
    return cache[key]


def _transfer(bn: _Bin, ins, f, on_access=None):
    """Update facts `f` across `ins`. `on_access(ins, kind, ptrs, width, vals, may)` is called for
    each memory access through a known pointer: `ptrs` = [(root, off)] (several for a pointer
    phi), `vals` = possible stored constants (None = unknown), `may` = the access targets one of
    several locations."""
    m = ins.mnemonic
    if bn.arm:
        _transfer_a64(bn, ins, f, on_access, m)
    else:
        _transfer_x86(bn, ins, f, on_access, m)


def _report(on_access, ins, kind, base_fact, disp, width, vals):
    p = _ptrs(base_fact)
    if on_access and p:
        on_access(ins, kind, sorted((r, k + disp) for r, k in p), width, vals, len(p) > 1)


def _transfer_a64(bn, ins, f, on_access, m):
    s = ins.op_str
    parts = [p.strip() for p in s.split(",")] if s else []
    if m in ("bl", "blr"):
        for r in _A64_CALLER_SAVED:
            f.pop(r, None)
        if m == "bl":
            _ret_facts(bn, f, _num(s.lstrip("#")))
        return
    pair = m in ("ldp", "stp", "ldpsw")
    is_ld = m in _A64_LOAD or m in ("ldp", "ldpsw")
    is_st = m in ("strb", "strh", "str", "sturb", "sturh", "stur", "stp")
    if is_ld or is_st:
        if pair:
            mi = re.match(r"^(\w+), (\w+), \[(\w+)(?:, #(-?(?:0x[0-9a-f]+|\d+)))?\](!?)$", s)
            mp = None if mi else re.match(r"^(\w+), (\w+), \[(\w+)\], #(-?(?:0x[0-9a-f]+|\d+))$", s)
            regs_ = (mi or mp).groups()[:2] if (mi or mp) else (parts[0],)
            bidx = 3
        else:
            mi = _A64_MEM_IMM.match(s)
            mp = None if mi else _A64_MEM_POST.match(s)
            regs_ = (parts[0],)
            bidx = 2
        base = disp = None
        wb = 0
        if mi:
            base, disp = _ac(mi.group(bidx)), _num(mi.group(bidx + 1) or "0")
            if mi.group(bidx + 2):
                wb = disp
        elif mp:
            base, disp, wb = _ac(mp.group(bidx)), 0, _num(mp.group(bidx + 1))
        bf = None
        if base is not None:
            bf = ("p", "sp", 0) if base == "sp" else f.get(base)   # before any writeback
            if on_access and _ptrs(bf):
                w = {"strb": 1, "sturb": 1, "strh": 2, "sturh": 2}.get(m)
                if w is None:
                    w = _A64_LOAD.get(m, (None, 0))[0] if is_ld and not pair else None
                if w is None:
                    w = 4 if regs_[0].startswith("w") else 8
                for k, r in enumerate(regs_):
                    vals = None
                    if is_st:
                        src = _ac(r)
                        vals = {0} if src == "xzr" else _cvals(f.get(src), 8 * w)
                    _report(on_access, ins, "store" if is_st else "load", bf, disp + k * w, w, vals)
            if wb and base != "sp":
                nf = _shift(bf, wb)
                if nf is None:
                    f.pop(base, None)
                else:
                    f[base] = nf
        slot = _stack_slot(bf, disp) if base is not None else None
        wid = 4 if regs_[0].startswith("w") else 8
        if is_st and slot is not None:
            # a spill: remember what an 8-byte register store put in the frame
            for k, r in enumerate(regs_):
                _slot_clear(f, (slot[0], slot[1] + k * wid), wid, bn.ptr)
                sf = ("c", 0) if _ac(r) == "xzr" else f.get(_ac(r))
                if wid == 8 and sf is not None and m in ("str", "stur", "stp"):
                    f[_mk(slot, k * wid)] = sf
        if is_ld:
            for r in regs_:
                f.pop(_ac(r), None)
            if base is not None and m in ("ldr", "ldur", "ldp") and regs_[0].startswith("x"):
                for k, r in enumerate(regs_):
                    if _ac(r) == base and wb:
                        continue       # the writeback and the load both target it: unknown
                    sv = f.get(_mk(slot, 8 * k)) if slot is not None else None
                    d = sv if sv is not None else _deref(bf, disp + 8 * k)
                    if d is not None:
                        f[_ac(r)] = d
        return
    if not parts:
        return
    dst = _ac(parts[0])
    if dst == "sp" or m in ("cmp", "cmn", "tst", "b", "br", "cbz", "cbnz", "tbz", "tbnz", "ret", "nop") \
            or m.startswith("b."):
        return
    if m == "mov" and len(parts) == 2:
        src = parts[1]
        im = _A64_IMM.match(src)
        if im:
            f[dst] = ("c", _num(im.group(1)) & _mask(_a64_bits(parts[0])))
        elif _ac(src) == "sp":
            f[dst] = ("p", "sp", 0)
        elif _ac(src) == "xzr":
            f[dst] = ("c", 0)
        elif _ac(src) in f and (parts[0].startswith("x") or _consts(f[_ac(src)]) is not None):
            sf = f[_ac(src)]
            f[dst] = sf if parts[0].startswith("x") else _mkconst({v & _mask(32) for v in _consts(sf)})
        else:
            f.pop(dst, None)
        return
    if m in ("adr", "adrp"):
        c = _const_of(bn, ins)
        if c is None:
            f.pop(dst, None)
        else:
            f[dst] = ("c", c)
        return
    if m in ("add", "sub") and len(parts) == 3 and _A64_IMM.match(parts[2]):
        k = _num(_A64_IMM.match(parts[2]).group(1))
        k = k if m == "add" else -k
        src = ("p", "sp", 0) if _ac(parts[1]) == "sp" else f.get(_ac(parts[1]))
        nf = _shift(src, k)
        if nf is None and _fvals(bn, src, _a64_bits(parts[0])):
            nf = _mkvals({(x + k) & _mask(_a64_bits(parts[0]))
                          for x in _fvals(bn, src, _a64_bits(parts[0]))}, 64)
        if nf is None:
            f.pop(dst, None)
        else:
            f[dst] = nf
        return
    # conditional selects: both outcomes as a value set (`mov w8, #3; csinc w8, w8, wzr, ne`
    # = {3, 1}: Pending -> Suspend, Ready -> Returned)
    bits = _a64_bits(parts[0])
    msk = _mask(bits)

    def rv(r):
        r = r.strip()
        if _ac(r) == "xzr":
            return {0}
        return _fvals(bn, f.get(_ac(r)), bits)
    res = None
    if m in ("csel", "csinc", "csinv", "csneg") and len(parts) == 4:
        a, b2 = rv(parts[1]), rv(parts[2])
        if a is not None and b2 is not None:
            alt = {(x + 1) & msk for x in b2} if m == "csinc" else \
                {(~x) & msk for x in b2} if m == "csinv" else \
                {(-x) & msk for x in b2} if m == "csneg" else b2
            res = a | alt
    elif m in ("cset", "csetm") and len(parts) == 2:
        res = {0, 1} if m == "cset" else {0, msk}
    elif m in ("cinc", "cinv", "cneg") and len(parts) == 3:
        a = rv(parts[1])
        if a is not None:
            res = a | {((x + 1) if m == "cinc" else (~x) if m == "cinv" else (-x)) & msk for x in a}
    elif m in ("add", "sub", "and", "orr", "eor", "lsl", "lsr") and len(parts) == 3:
        a = rv(parts[1])
        im = _A64_IMM.match(parts[2])
        if im:
            res = _setop(m, a, {_num(im.group(1)) & msk}, bits)
        else:
            res = _setop(m, a, rv(parts[2]), bits, same=_ac(parts[1]) == _ac(parts[2]))
    if res is not None:
        nf = _mkvals(res, 64)
        if nf is not None:
            f[dst] = nf
            return
    f.pop(dst, None)


def _transfer_x86(bn, ins, f, on_access, m):
    from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM, X86_REG_RIP
    ops = ins.operands
    x32 = bn.x32
    ptrw = bn.ptr
    if m == "call":
        tgt = _x86_call_target(bn, ins)
        nxt = ins.address + ins.size
        if x32 and ops and ops[0].type != X86_OP_IMM:
            tgt_pop = None                       # indirect: no callee to read `ret imm` from
        else:
            tgt_pop = tgt
        if x32:
            thunk = _pc_thunk_reg(bn, tgt)
            spf = f.get("rsp")
            if tgt == nxt:                       # `call $+5 ; pop reg`: the PIC base, not a call
                f["__pushed"] = ("c", nxt)
                if spf:
                    f["rsp"] = _shift(spf, -4, 32) or spf
                return
            for r in _X86_CALLER_SAVED["cdecl"]:
                f.pop(r, None)
            if thunk:
                f[thunk] = ("c", nxt)
            pop = _callee_pop(bn, tgt_pop) if tgt_pop is not None else None
            _ret_facts(bn, f, tgt)
            if pop is None:
                # an indirect call: LLVM re-reserves what an sret/stdcall callee popped with the
                # `sub esp, N` right after it -- take N as the pop, so the frame stays in sync
                n = bn.insn(nxt)
                pop = 0
                if n is not None and n.mnemonic == "sub" and len(n.operands) == 2 \
                        and n.operands[0].type == X86_OP_REG and _xc(n.reg_name(n.operands[0].reg)) == "rsp" \
                        and n.operands[1].type == X86_OP_IMM and 0 < n.operands[1].imm <= 16:
                    pop = n.operands[1].imm
            if spf and pop:
                f["rsp"] = _shift(spf, pop, 32)
            return
        for r in _X86_CALLER_SAVED[bn.abi]:
            f.pop(r, None)
        _ret_facts(bn, f, tgt)
        return
    spf = _sp_fact(bn, f)
    if on_access:
        for i, op in enumerate(ops):
            if op.type == X86_OP_MEM and op.mem.base and op.mem.base != X86_REG_RIP and not op.mem.index \
                    and m not in ("lea", "nop") and not m.startswith("nop"):
                bc = _xc(ins.reg_name(op.mem.base))
                bf = spf if bc == "rsp" else f.get(bc)
                if _ptrs(bf):
                    store = i == 0 and m == "mov" and len(ops) == 2
                    vals = None
                    if store:
                        src = ops[1]
                        if src.type == X86_OP_IMM:
                            vals = {src.imm & _mask(op.size * 8)}
                        elif src.type == X86_OP_REG:
                            vals = _cvals(f.get(_xc(ins.reg_name(src.reg))), op.size * 8)
                    kind = "store" if store else ("rmw" if i == 0 and m not in ("cmp", "test", "push") else "load")
                    _report(on_access, ins, kind, bf, op.mem.disp, op.size, vals)
    # stack spills: a pointer-sized register/immediate stored to [sp+k] and reloaded later
    for i, op in enumerate(ops):
        if op.type == X86_OP_MEM and i == 0 and m not in ("cmp", "test", "lea", "push") \
                and not m.startswith("nop") and op.mem.base and not op.mem.index and op.mem.base != X86_REG_RIP:
            bc = _xc(ins.reg_name(op.mem.base))
            slot = _stack_slot(spf if bc == "rsp" else f.get(bc), op.mem.disp)
            if slot is not None:
                _slot_clear(f, slot, max(op.size, 1), ptrw)
                if m == "mov" and op.size == ptrw and len(ops) == 2:
                    src = ops[1]
                    sv = None
                    if src.type == X86_OP_REG:
                        sc = _xc(ins.reg_name(src.reg))
                        sv = spf if sc == "rsp" else f.get(sc)
                    elif src.type == X86_OP_IMM:
                        sv = ("c", src.imm & _mask(8 * ptrw))
                    if sv is not None:
                        f[_mk(slot)] = sv
                elif m == "mov" and len(ops) == 2 and ops[1].type == X86_OP_IMM:
                    # a narrow constant parked in the frame (`mov byte [ebp-0x10], 3`): reloaded
                    # by movzx and stored as the next state
                    f[_mk(slot)] = ("cp", ops[1].imm & _mask(8 * op.size), 8 * op.size)
                elif m == "mov" and len(ops) == 2 and ops[1].type == X86_OP_REG:
                    sv = _mkvals(_cvals(f.get(_xc(ins.reg_name(ops[1].reg))), 8 * op.size), 8 * op.size)
                    if sv is not None:
                        f[_mk(slot)] = sv
    if x32:
        if m == "and" and ops and ops[0].type == X86_OP_REG and _xc(ins.reg_name(ops[0].reg)) == "rsp":
            f["rsp"] = ("p", "spa", 0)   # realigned: a fresh stack root (args stay at [ebp+..])
            return
        if m == "push":
            if spf:
                f["rsp"] = _shift(spf, -4, 32)
            return
        if m == "pop":
            if spf:
                f["rsp"] = _shift(spf, 4, 32)
            if ops and ops[0].type == X86_OP_REG:
                d = _xc(ins.reg_name(ops[0].reg))
                if d != "rsp":
                    pushed = f.pop("__pushed", None)
                    if pushed:
                        f[d] = pushed
                    else:
                        f.pop(d, None)
            return
        f.pop("__pushed", None)
    if not ops or ops[0].type != X86_OP_REG:
        return
    dst = _xc(ins.reg_name(ops[0].reg))
    if dst == "rsp" and not x32:
        return
    if m in ("cmp", "test") or m.startswith("j") or m == "push":
        return
    if m == "pop":
        f.pop(dst, None)
        return
    if m == "mov" and len(ops) == 2:
        src = ops[1]
        if src.type == X86_OP_IMM:
            old = f.pop(dst, None)
            w = ops[0].size * 8
            if w >= 32:
                imm = src.imm & _mask(w)
                if x32 and bn.pe and imm >= bn.img.imagebase and bn.is_data(imm - bn.img.imagebase):
                    imm -= bn.img.imagebase          # an absolute data VA -> RVA (relocated)
                f[dst] = ("c", imm)
            elif old and old[0] == "c":           # a partial write merges into a known constant
                f[dst] = ("c", (old[1] & ~_mask(w)) | (src.imm & _mask(w)))
            else:                                 # only the low `w` bits are known (`mov cl, 3`)
                f[dst] = ("cp", src.imm & _mask(w), w)
        elif src.type == X86_OP_REG:
            sc = _xc(ins.reg_name(src.reg))
            sf = spf if sc == "rsp" else f.get(sc)
            if sf and ops[0].size == ptrw:
                f[dst] = sf
            else:
                # a narrower copy keeps the value set it carries (`mov ecx, eax`, `mov cl, al`)
                vs = _fvals(bn, sf, 8 * ops[0].size)
                nf = _mkvals(vs, 64 if ops[0].size >= 4 else 8 * ops[0].size)
                if nf is None:
                    f.pop(dst, None)
                else:
                    f[dst] = nf
        elif src.type == X86_OP_MEM and ops[0].size == ptrw and src.mem.base and not src.mem.index \
                and src.mem.base != X86_REG_RIP and not src.mem.segment:
            bc = _xc(ins.reg_name(src.mem.base))
            bf = spf if bc == "rsp" else f.get(bc)
            slot = _stack_slot(bf, src.mem.disp)
            d = f.get(_mk(slot)) if slot is not None else None
            if d is None:
                d = _deref(bf, src.mem.disp, x32)
            if d is None:
                f.pop(dst, None)
            else:
                f[dst] = d
        else:
            f.pop(dst, None)
        return
    if m == "movzx" and len(ops) == 2 and ops[1].type == X86_OP_MEM and ops[1].size < ptrw \
            and ops[1].mem.base and not ops[1].mem.index:
        bc = _xc(ins.reg_name(ops[1].mem.base))
        slot = _stack_slot(spf if bc == "rsp" else f.get(bc), ops[1].mem.disp)
        sv = f.get(_mk(slot)) if slot is not None else None
        f.pop(dst, None)
        vals = _cvals(sv, 8 * ops[1].size) if sv and _cwidth(sv) == 8 * ops[1].size else None
        if vals:
            f[dst] = _mkconst(vals)          # zero-extended
        return
    if m == "lea" and len(ops) == 2:
        mm = ops[1].mem
        if mm.base == X86_REG_RIP:
            f[dst] = ("c", ins.address + ins.size + mm.disp)
        elif mm.base and not mm.index and ops[0].size == ptrw:
            bc = _xc(ins.reg_name(mm.base))
            nf = _shift(spf if bc == "rsp" else f.get(bc), mm.disp, 8 * ptrw)
            if nf is not None:
                f[dst] = nf
                return
        # (otherwise fall through: `lea` arithmetic over value sets below, or the generic kill)
        if mm.base == X86_REG_RIP:
            return
    if m in ("add", "sub") and len(ops) == 2 and ops[1].type == X86_OP_IMM and ops[0].size == ptrw:
        df = spf if dst == "rsp" else f.get(dst)
        k = ops[1].imm if m == "add" else -ops[1].imm
        nf = _shift(df, k, 8 * ptrw)
        if nf is None:
            f.pop(dst, None)
        else:
            f[dst] = nf
        return
    if m == "xor" and len(ops) == 2 and ops[1].type == X86_OP_REG and ops[1].reg == ops[0].reg:
        f[dst] = ("c", 0)
        return
    # value sets through flag selects and small arithmetic: `sete cl; add cl, cl; inc cl`,
    # `lea ecx, [rax+rax]; inc cl`, `cmovne eax, ecx` -- what a Pending path computes as the next
    # state without a constant store (each side of the select evaluated to its constant set)
    bits = ops[0].size * 8
    wbits = 64 if bits >= 32 else bits           # a 32-bit write zero-extends: the whole register
    res = None
    if m.startswith("set") and len(ops) == 1:
        res = {0, 1}
    elif m.startswith("cmov") and len(ops) == 2 and ops[1].type == X86_OP_REG:
        a = _fvals(bn, f.get(dst), bits)
        b2 = _fvals(bn, f.get(_xc(ins.reg_name(ops[1].reg))), bits)
        res = (a | b2) if a is not None and b2 is not None else None
    elif m in ("add", "sub", "and", "or", "xor", "shl", "shr") and len(ops) == 2:
        a = _fvals(bn, f.get(dst), bits)
        if ops[1].type == X86_OP_IMM:
            res = _setop(m, a, {ops[1].imm & _mask(bits)}, bits)
        elif ops[1].type == X86_OP_REG:
            sc = _xc(ins.reg_name(ops[1].reg))
            res = _setop(m, a, _fvals(bn, f.get(sc), bits), bits, same=(sc == dst))
    elif m in ("inc", "dec", "neg", "not") and len(ops) == 1:
        a = _fvals(bn, f.get(dst), bits)
        if a is not None:
            res = {((x + 1) if m == "inc" else (x - 1) if m == "dec" else (-x) if m == "neg" else ~x)
                   & _mask(bits) for x in a}
    elif m == "lea" and len(ops) == 2 and ops[1].mem.base and ops[1].mem.base != X86_REG_RIP:
        mm = ops[1].mem
        bc = _xc(ins.reg_name(mm.base))
        a = _fvals(bn, f.get(bc), 64)
        if mm.index:
            ic = _xc(ins.reg_name(mm.index))
            iv = _fvals(bn, f.get(ic), 64)
            if a is not None and iv is not None:
                res = {(x + x * mm.scale + mm.disp) & _mask(bits) for x in a} if ic == bc else \
                    {(x + y * mm.scale + mm.disp) & _mask(bits) for x in a for y in iv}
        elif a is not None:
            res = {(x + mm.disp) & _mask(bits) for x in a}
    elif m in ("movzx", "mov") and len(ops) == 2 and ops[1].type == X86_OP_REG:
        res = _fvals(bn, f.get(_xc(ins.reg_name(ops[1].reg))), 8 * ops[1].size)
        if m == "movzx":
            wbits = 64
    if res is not None:
        old = _cvals(f.get(dst), 64) if wbits < 64 else None
        if old is not None and len(old) == 1:
            # a byte write into a register whose upper bits are known (`xor ecx, ecx; setne cl`)
            o = next(iter(old))
            res, wbits = {(o & ~_mask(bits)) | (v & _mask(bits)) for v in res}, 64
        nf = _mkvals(res, wbits)
        if nf is not None:
            f[dst] = nf
            return
    try:
        _r, w = ins.regs_access()
        for r in w:
            c = _xc(ins.reg_name(r))
            if c != "rsp" or x32:
                f.pop(c, None)
    except Exception:
        f.pop(dst, None)


def _x86_call_target(bn, ins):
    """Direct target of an x86 call: rel32, or the function a [rip+slot] / [abs32] slot holds."""
    from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP
    op = ins.operands[0] if ins.operands else None
    if op is None:
        return None
    if op.type == X86_OP_IMM:
        return op.imm
    if op.type == X86_OP_MEM and not op.mem.index:
        if op.mem.base == X86_REG_RIP:
            return bn.read_ptr(ins.address + ins.size + op.mem.disp)
        if not op.mem.base and bn.x32:
            slot = op.mem.disp & _mask(32)
            if bn.pe:
                slot -= bn.img.imagebase
            return bn.read_ptr(slot)
    return None


def _noreturn(bn, target):
    """Does the function at `target` never return (no `ret`, no tail jump out -- a panic helper)?"""
    cache = bn.__dict__.setdefault("_noret_cache", {})
    if target in cache:
        return cache[target]
    res = False
    i = bisect.bisect_left(bn.starts, target) if target is not None else 0
    if target is not None and bn.lo <= target < bn.hi and i < len(bn.starts) and bn.starts[i] == target:
        lo, hi = bn.fn_bounds(target)
        res = True
        n = 0
        for ins in bn.md.disasm(bn.code[lo - bn.lo:min(hi, lo + 0x4000) - bn.lo], lo):
            n += 1
            m = ins.mnemonic
            if m in ("ret", "retn", "retf", "br") or (m == "jmp" and not ins.op_str.startswith("0x")):
                res = False
                break
            if m in ("jmp", "b") or m.startswith("b.") or m in ("cbz", "cbnz", "tbz", "tbnz"):
                try:
                    t = _num(ins.op_str.split(",")[-1].strip().lstrip("#"))
                except ValueError:
                    res = False
                    break
                if not (lo <= t < hi):
                    res = False          # a tail call: returns whenever the callee does
                    break
        if hi - lo > 0x4000 or n == 0:
            res = False
    cache[target] = res
    return res


def _blocks(bn: _Bin, insns, lo, hi, extra_edges):
    """Basic blocks of a linear sweep: {start: [insns]} and successor map. `extra_edges` maps an
    indirect jump VA -> targets (the dispatch runs resolved them)."""
    if not insns:
        return {}, {}
    addrs = [i.address for i in insns]
    aset = set(addrs)
    leaders = {lo, addrs[0]}
    ends = {}
    for i in insns:
        m = i.mnemonic
        tgts = []
        term = False
        if bn.arm:
            if m.startswith("b.") or m in ("cbz", "cbnz", "tbz", "tbnz"):
                tgts = [_num(i.op_str.split(",")[-1].strip().lstrip("#"))]
            elif m == "b":
                tgts, term = [_num(i.op_str.lstrip("#"))], True
            elif m in ("br", "ret", "brk"):
                term = True
            elif m == "bl":
                term = _noreturn(bn, _num(i.op_str.lstrip("#")))
        else:
            if m.startswith("j"):
                from capstone.x86 import X86_OP_IMM
                if i.operands and i.operands[0].type == X86_OP_IMM:
                    tgts = [i.operands[0].imm]
                term = m == "jmp"
            elif m in ("ret", "ud2", "int3", "hlt"):
                term = True
            elif m == "call":
                term = _noreturn(bn, _x86_call_target(bn, i))
        tgts = [t for t in tgts if t in aset]
        tgts += [t for t in extra_edges.get(i.address, ()) if t in aset]
        if tgts or term or m.startswith("b.") or (not bn.arm and m.startswith("j")):
            # (a call into a function that never returns -- a panic -- ends its block too, so the
            # registers it clobbers do not flow into the code laid out after it)
            ends[i.address] = (tgts, term)
            leaders.update(tgts)
            leaders.add(i.address + i.size)
    blocks, succ = {}, {}
    cur = None
    for i in insns:
        if i.address in leaders or cur is None:
            cur = i.address
            blocks[cur] = []
        blocks[cur].append(i)
    for st, lst in blocks.items():
        last = lst[-1]
        tg, term = ends.get(last.address, ([], False))
        s = list(tg)
        nxt = last.address + last.size
        if not term and nxt in blocks:
            s.append(nxt)
        succ[st] = s
    return blocks, succ


def _dataflow(bn: _Bin, insns, lo, hi, extra_edges, entry_facts, on_access, cut=None):
    """Forward dataflow to a fixpoint; returns {insn VA: facts before it}. `cut`: CFG edges
    (last insn VA of the source block, successor start) to ignore."""
    blocks, succ = _blocks(bn, insns, lo, hi, extra_edges)
    if not blocks:
        return {}
    fin = {st: None for st in blocks}
    first = min(blocks)
    fin[first] = dict(entry_facts)
    work = [first]
    if cut:
        # drop a cut edge only where its target has another way in: a block entered solely
        # through the dispatch keeps that edge (it would otherwise never be reached)
        kept = {t for st, ss in succ.items() for t in ss if (blocks[st][-1].address, t) not in cut}
        succ = {st: [t for t in ss if (blocks[st][-1].address, t) not in cut or t not in kept]
                for st, ss in succ.items()}
    visits = 0
    budget = 40 * len(blocks) + 100
    while work and visits < budget:
        st = work.pop()
        visits += 1
        f = dict(fin[st])
        for ins in blocks[st]:
            _transfer(bn, ins, f)
        for s in succ.get(st, ()):
            new = _join(fin[s], f)
            if fin[s] is None or new != fin[s]:
                fin[s] = new
                work.append(s)
    # final pass: report accesses with the converged facts; blocks never reached start empty
    at = {}
    for st, lst in blocks.items():
        f = dict(fin[st]) if fin[st] is not None else {}
        for ins in lst:
            at[ins.address] = dict(f)
            _transfer(bn, ins, f, on_access)
    return at


# ----------------------------------------------------------------------------------------------
# per-function analysis
# ----------------------------------------------------------------------------------------------
def _is_trap(b, va):
    ins = b.insn(va) if va is not None else None
    return ins is not None and ins.mnemonic in ("ud2", "int3", "hlt", "brk", "udf")


_SELF_ROOTS = ("arg0", "arg1", "ecx", "edx")    # where `self` can arrive (edx/ecx: i386 fastcc)


def _try_dispatch(b, anchors, load_va, lo, hi, cls_cache, seed=None):
    def cls(t):
        if t not in cls_cache:
            cls_cache[t] = _classify(b, anchors, t, lo, hi)
        return cls_cache[t]
    def kind(r):
        k, loc = cls(r.target)
        if k is None and anchors["refs"] and r.target is not None:
            # older rustc: `core::panicking::panic(msg, ..)` with the message pointer loaded
            # before the dispatch (LLVM hoists it out of a tail-merged arm): the run holds it
            held = {anchors["refs"][v] for v in r.regs.values() if v in anchors["refs"]}
            ev, _c = _walk(b, r.target, lo, hi)
            if len(held) == 1 and any(e[0] == "call" for e in ev) and not any(
                    e[0] == "ref" and e[2] in anchors["refs"] for e in ev):
                k = held.pop()
                cls_cache[r.target] = (k, loc)
        return k
    r1 = _dispatch_run(b, load_va, 1, lo, hi, seed)
    if kind(r1) != "returned":
        return None
    r2 = _dispatch_run(b, load_va, 2, lo, hi, seed)
    if kind(r2) != "panicked":
        return None
    r0 = _dispatch_run(b, load_va, 0, lo, hi, seed)
    if r0.target is None or cls(r0.target)[0] is not None:
        return None
    return r0, r1, r2


def _enumerate_states(b, anchors, load_va, width, runs, lo, hi, boundaries, cls_cache, insn_set,
                      seed=None):
    r0, r1, r2 = runs
    targets = {0: r0.target, 1: r1.target, 2: r2.target}
    via_table = r0.jt or r1.jt or r2.jt
    table = next((r.table for r in runs if r.table is not None), None)
    edges = {}
    seen = {r0.target}
    limit = min(_MAX_STATES, 1 << (8 * width))
    for v in range(3, limit):
        r = _dispatch_run(b, load_va, v, lo, hi, seed)
        t = r.target
        if t is None or t in seen or t not in insn_set:
            break
        if r.reads and table is not None and any(
                table < bd <= max(r.reads) for bd in boundaries if bd != table):
            break                     # ran past this table into the next datum
        if t not in cls_cache:
            cls_cache[t] = _classify(b, anchors, t, lo, hi)
        if cls_cache[t][0] is not None or _is_trap(b, t):
            break
        targets[v] = t
        seen.add(t)
        via_table = via_table or r.jt
        table = table or r.table
    return targets, ("jump_table" if via_table else "compare_chain"), table


def analyze_function(b: _Bin, anchors, lo, hi):
    """All validated state machines in the function [lo, hi)."""
    insns = b.sweep(lo, hi)
    insn_set = {i.address for i in insns}
    cls_cache = {}
    # data constants the function materializes: bounds on any table it reads
    boundaries = set()
    for i in insns:
        c = _const_of(b, i)
        if c is not None and (b.is_data(c) or (b.macho and not b.arm and lo <= c < hi)):
            boundaries.add(c)            # (an Apple x86-64 table lives inside its function)
        elif b.x32:
            # i386 tables are read as [pic + idx*4 + d] (ELF PIC: pic = GOT) or [idx*4 + abs]
            # (PE: an absolute, relocated address -- mingw puts them in .text): each names a table
            for op in i.operands:
                if op.type != 3 or not op.mem.index or op.mem.scale != 4:
                    continue
                t = None
                if not op.mem.base:
                    t = (op.mem.disp & _mask(32)) - (b.img.imagebase if b.pe else 0)
                elif b.got is not None and _xc(i.reg_name(op.mem.base)) not in ("rsp", "rbp"):
                    t = (b.got + op.mem.disp) & _mask(32)
                if t is not None and (b.is_data(t) or b.lo <= t < b.hi):
                    boundaries.add(t)
    sites = []
    entry = {r: ("p", f"arg{k}", 0) for k, r in enumerate(b.args)}
    if b.x32:
        # cdecl puts the arguments on the stack; LLVM's fastcc (internal functions) passes the
        # first two in ecx / edx -- both are tracked, as distinct roots
        entry = {"rsp": ("p", "sp", 0), "rcx": ("p", "ecx", 0), "rdx": ("p", "edx", 0)}
    loads = [(i, w) for i in insns for w in [_is_state_load(b, i)] if w]
    if not loads:
        return []
    edges = {}           # indirect jump VA -> targets the dispatch runs resolved (CFG edges)
    done = set()
    pic = set()
    if b.x32:            # the function's PC base(s): the address after each `call $+5`
        for i in insns:
            if i.mnemonic == "call" and i.operands and i.operands[0].type == 2 \
                    and i.operands[0].imm == i.address + i.size:
                pic.add(i.address + i.size)
    # rounds: a dispatch reached only through another machine's jump table gets its constants
    # (a table base hoisted out of the executor loop) once that table's edges are in the CFG
    for _round in range(3):
        pre = _dataflow(b, insns, lo, hi, edges, entry, None)
        # a register that holds one and the same constant wherever it is known (the PIC base,
        # a table base set once before the executor loop) seeds loads in blocks the CFG does not
        # reach yet (behind an unresolved jump table)
        seen_c = {}
        for fa in pre.values():
            for r, fv in fa.items():
                if isinstance(r, str):
                    seen_c.setdefault(r, set()).add(fv[1] if fv[0] == "c" else None)
        glob = {r: next(iter(v)) for r, v in seen_c.items() if len(v) == 1 and None not in v}
        new = 0
        for i, w in loads:
            if i.address in done:
                continue
            f0 = pre.get(i.address) or {}
            seed = dict(glob)
            seed.update({r: fv[1] for r, fv in f0.items() if isinstance(r, str) and fv[0] == "c"})
            if len(pic) == 1:
                seed["__pic"] = next(iter(pic))
            runs = _try_dispatch(b, anchors, i.address, lo, hi, cls_cache, seed)
            if runs is None:
                continue
            done.add(i.address)
            new += 1
            targets, kind, table = _enumerate_states(b, anchors, i.address, w, runs, lo, hi,
                                                     boundaries, cls_cache, insn_set, seed)
            loc = cls_cache.get(runs[1].target, (None, None))[1] or \
                cls_cache.get(runs[2].target, (None, None))[1]
            sites.append({"va": i.address, "width": w, "kind": kind, "table": table,
                          "targets": targets, "location": loc, "seed": seed})
            if kind == "jump_table":
                jv = _indirect_jump_after(b, i.address, lo, hi)
                if jv is not None:
                    edges.setdefault(jv, set()).update(targets.values())
        if not new or not edges:
            break
    if sites:
        # a coroutine whose state LLVM promoted to a register (inlined into the executor's loop)
        # can lose its Returned/Panicked arms altogether: the register provably never holds 1 or
        # 2, so both land on one `ud2`. Accepted only next to validated machines, for register
        # dispatches whose other states are real code
        pre = _dataflow(b, insns, lo, hi, edges, entry, None)
        for i, w in loads:
            if i.address in done or _load_base(b, i)[0] is not None:
                continue
            f0 = pre.get(i.address) or {}
            seed = {r: fv[1] for r, fv in f0.items() if isinstance(r, str) and fv[0] == "c"}
            r1 = _dispatch_run(b, i.address, 1, lo, hi, seed)
            r2 = _dispatch_run(b, i.address, 2, lo, hi, seed)
            r0 = _dispatch_run(b, i.address, 0, lo, hi, seed)
            if r1.target is None or r1.target != r2.target or not _is_trap(b, r1.target) \
                    or r0.target is None or _is_trap(b, r0.target) or not (r0.jt or r0.branches):
                continue
            targets, kind, table = _enumerate_states(b, anchors, i.address, w, (r0, r1, r2), lo, hi,
                                                     boundaries, cls_cache, insn_set, seed)
            if len(targets) <= 3:
                continue
            done.add(i.address)
            sites.append({"va": i.address, "width": w, "kind": kind, "table": table,
                          "targets": targets, "location": None, "seed": seed, "unreachable_arms": True})
            if kind == "jump_table":
                jv = _indirect_jump_after(b, i.address, lo, hi)
                if jv is not None:
                    edges.setdefault(jv, set()).update(targets.values())
    if not sites:
        return []
    # dataflow: where is each state field, and who writes it
    accesses = []

    def on_access(ins, kind, ptrs, width, vals, may):
        accesses.append((ins.address, kind, tuple(ptrs), width,
                         None if vals is None else frozenset(vals), may))
    at = _dataflow(b, insns, lo, hi, edges, entry, on_access)
    for s in sites:
        f = at.get(s["va"], {})
        ins = b.insn(s["va"])
        base, disp = _load_base(b, ins)
        bf = _sp_fact(b, f) if base in ("rsp", "sp") else f.get(base)
        if base is None:
            s["field"] = ("reg", disp)     # a register: sites sharing targets merge below
        elif bf and bf[0] == "p":
            s["field"] = (bf[1], bf[2] + disp)
        else:
            s["field"] = ("?", disp, s["va"])          # unknown (or phi) base: its own group
    # stack slot -> every value spilled there anywhere in the function (flow-insensitive)
    spills = {}
    for fa in at.values():
        for k, v in fa.items():
            if isinstance(k, tuple) and k[0] == "m":
                spills.setdefault((k[1], k[2]), set()).add(v)
    # memory slot -> constants stored there (pointer-sized), for per-call-site dyn resolution
    slot_consts = {}
    for _a, kind, ptrs, w, vals, may in accesses:
        if kind == "store" and w == b.ptr and vals and not may:
            slot_consts.setdefault(ptrs[0], set()).update(vals)
    # group sites by field, then split a group whose sites share no target at all: two inlined
    # copies of one coroutine whose (overlapping) storage puts both states at the same offset
    groups = {}
    for s in sites:
        groups.setdefault(s["field"], []).append(s)
    comps = []
    for field, ss in groups.items():
        ss.sort(key=lambda s: s["va"])
        parent = list(range(len(ss)))

        def find(i):
            while parent[i] != i:
                parent[i] = parent[parent[i]]
                i = parent[i]
            return i
        # any shared target (a resume block or a panic arm) = one coroutine dispatched from two
        # code paths (e.g. tokio::select! polling a branch in rotating order) -> keep together
        live = [set(s["targets"].values()) for s in ss]
        for i in range(len(ss)):
            for j in range(i + 1, len(ss)):
                if live[i] & live[j]:
                    parent[find(i)] = find(j)
        by = {}
        for i in range(len(ss)):
            by.setdefault(find(i), []).append(ss[i])
        for part in by.values():
            comps.append((field, part, len(by) > 1))
    # a register-state dispatch with the same targets as a memory-state one is the same
    # coroutine: the first poll still holds the fresh state in a register, a resumed poll reloads
    # it from the field (older rustc) -- fold it into the memory machine
    merged = []
    for c in comps:
        if c[0][0] == "reg":
            def live(sites_):           # Unresumed + resume targets (not the shareable arms)
                return {t for s_ in sites_ for v, t in s_["targets"].items() if v == 0 or v >= 3}
            tg = live(c[1])
            host = next((d for d in comps if d[0][0] != "reg" and d is not c and tg & live(d[1])),
                        None)
            if host is not None:
                host[1].extend(c[1])
                continue
        merged.append(c)
    comps = merged
    entry_order = _entry_order(b, lo, hi, {s["va"] for s in sites})
    machines = []
    all_sites = {s["va"] for s in sites}
    for field, ss, split in comps:
        width = ss[0]["width"]
        writes = []
        for a, kind, ptrs, w, vals, may in accesses:
            if kind in ("store", "rmw") and w == width and field[:2] in ptrs:
                may = may or len(ptrs) > 1
                writes.append({"va": a, "values": None if vals is None else sorted(vals), "may": may})
        writes.sort(key=lambda x: x["va"])
        main = max(ss, key=lambda s: len(s["targets"]))
        targets = dict(main["targets"])
        definite = sorted({x["values"][0] for x in writes
                           if x["values"] and len(x["values"]) == 1 and not x["may"]})
        computed = any(x["values"] is None and not x["may"] for x in writes)
        notes = []
        if split:
            notes.append("state field shared with another inlined copy (disjoint resume targets)")
        if any(x.get("unreachable_arms") for x in ss):
            notes.append("Returned/Panicked arms optimized away (both states reach a trap)")
        if field[0] == "reg":
            # a promoted state: its write-backs are register moves into the dispatch -- the value
            # set reaching the dispatch (entry 0 + every back edge's next state) is the check
            notes.append(f"state kept in register {field[1]} (coroutine inlined into a loop)")
            reach = set()
            for s_ in ss:
                src = _load_base(b, b.insn(s_["va"]))[1]
                v_ = _cvals(at.get(s_["va"], {}).get(src), 8 * width)
                if v_ is None:
                    reach = None
                    break
                reach |= v_
            # a reaching set that covers every suspend state confirms it; otherwise the
            # back-edge writes went through arithmetic we could not follow -> computed, not a gap
            n_now = max(max(s_["targets"]) for s_ in ss) + 1
            if reach and all(v in reach for v in range(3, n_now)):
                writes.append({"va": ss[0]["va"], "values": sorted(reach), "may": False,
                               "reach": True})
                definite = []       # (a reaching set, not a single definite store)
            else:
                computed = True
        n_states = max(targets) + 1
        # writes are the ground truth of which suspend states exist: extend a chain that stopped
        # early on a merged target, and cap a table read that ran past its end
        mx_all = max((v for x in writes if not x["may"] for v in (x["values"] or ())), default=0)
        if definite and not split:
            mx = max(definite)
            if mx >= n_states and mx < _MAX_STATES:
                for v in range(n_states, mx + 1):
                    r = _dispatch_run(b, main["va"], v, lo, hi, main["seed"])
                    if r.target is None or r.target not in insn_set:
                        break
                    targets[v] = r.target
                notes.append("states extended to the highest written value")
            # (the cap counts every value a store may write -- `csinc`/`setcc` sets included)
            elif not computed and max(mx, mx_all) >= 3 and max(mx, mx_all) + 1 < n_states \
                    and main["kind"] == "jump_table":
                # only an unbounded table read can overshoot; a compare chain cannot, and a
                # pending write the dataflow missed must not cost a real state
                for v in range(max(mx, mx_all) + 1, n_states):
                    targets.pop(v, None)
                notes.append("table entries past the highest written state dropped")
        n_states = max(targets) + 1
        seen_vals = {v for x in writes for v in (x["values"] or ())}
        contradicted = any(v >= n_states for v in definite) or any(
            v >= n_states for x in writes if x.get("reach") for v in x["values"])
        unseen = [v for v in range(3, n_states) if v not in seen_vals]
        if contradicted:
            check = "contradicted"
            notes.append("a state value written back is outside the recovered dispatch")
        elif unseen and not computed:
            check = "partial"
        elif unseen:
            check = "computed"
        else:
            check = "confirmed"
        root = field[0]
        loc = next((s["location"] for s in ss if s["location"]), None)
        machines.append({
            "function": lo, "function_end": hi, "field": field,
            "root": root, "offset": field[1] if root not in ("?", "reg") else None, "width": width,
            "register": field[1] if root == "reg" else None,
            "sites": ss, "targets": targets, "writes": writes, "computed_writes": computed,
            "consistent": not contradicted, "check": check, "unseen": unseen, "notes": notes,
            "location_va": loc,
            "first_seen": entry_order.get(min(s["va"] for s in ss), 1 << 30),
        })
    # primary = the machine reached first from the entry whose field hangs off an argument
    machines.sort(key=lambda mm: (mm["first_seen"], mm["sites"][0]["va"]))
    prim = next((mm for mm in machines if mm["root"] in _SELF_ROOTS
                 and mm["first_seen"] < (1 << 30)), None)
    if prim is None:
        # the entry walk (fall-through first) can miss a dispatch behind a taken branch: fall back
        # to the argument-relative machine dispatched earliest in the code
        argm = [mm for mm in machines if mm["root"] in _SELF_ROOTS]
        if argm:
            prim = min(argm, key=lambda mm: mm["sites"][0]["va"])
    max_off = {}
    for _a, _k, ptrs, w, _v, may in accesses:
        if may:
            continue
        root, off = ptrs[0]
        if root in _SELF_ROOTS and off >= 0:
            max_off[root] = max(max_off.get(root, 0), off + w)
    fresh_at = []

    def fresh():
        """Facts with the dispatch edges cut: what reaches a resume target on the path that set
        the await up (a value carried around the executor loop joins away otherwise)."""
        if not fresh_at:
            cut = set()
            for s_ in sites:
                tg = set(s_["targets"].values())
                for v_ in s_["targets"]:
                    for pc in _dispatch_run(b, s_["va"], v_, lo, hi, s_["seed"]).path:
                        cut |= {(pc, t_) for t_ in tg}
            fresh_at.append(_dataflow(b, insns, lo, hi, edges, entry, None, cut))
        return fresh_at[0]
    for mm in machines:
        mm["role"] = "poll" if mm is prim else "inlined"
        mm["min_size"] = max_off.get(mm["root"]) if mm is prim else None
        # suspend points: the first poll reached from each resume target
        sus = {}
        own = {s["va"] for s in mm["sites"]}
        for v, t in sorted(mm["targets"].items()):
            if v < 3:
                continue
            ev, _c = _walk(b, t, lo, hi, frozenset(all_sites - own))
            inner = {"kind": "inline_code"}      # the awaited future's poll was inlined here
            for e in ev:
                if e[0] == "site":
                    inner = {"kind": "inlined", "site": e[1]}
                    break
                if e[0] == "call":
                    inner = dict(e[2])
                    break
            via = inner.pop("via", None)
            if inner["kind"] == "dyn" and via is not None and inner.get("slot_offset") == 3 * b.ptr:
                cands, src = _dyn_candidates(b, via, at, fresh(), spills, slot_consts)
                if cands:
                    inner["vt_candidates"] = cands
                    inner["vt_from"] = src
            sus[v] = {"resume": t, "inner": inner,
                      "pending_writes": [x["va"] for x in mm["writes"] if v in (x["values"] or ())]}
        mm["suspend"] = sus
    return machines


def _dyn_candidates(b, via, at, at_fresh, spills, slot_consts):
    """Valid `dyn Future` vtables that can reach the indirect poll call whose vtable pointer is
    register via[1] at instruction via[0]. Tried in order of precision: the facts on the path that
    set the await up (dispatch edges cut), the full fixpoint, then every value that register takes
    anywhere in the function. Returns (sorted vtable VAs, how they were found)."""
    def from_fact(fact):
        out = set()
        facts = [fact]
        for r, k in (_ptrs(fact) or ()):
            slot = _deref_slot(r)
            if k == 0 and slot and slot[0] in ("sp", "spa"):
                facts += list(spills.get(slot, ()))
                out |= slot_consts.get(slot, set())
        for fc in facts:
            if _consts(fc):
                out |= _consts(fc)
            elif fc and fc[0] == "r":
                out |= _ret_summary(b, fc[1], fc[2]) or set()
        return {c for c in out if _vtable_at(b, c)}
    fresh = from_fact(at_fresh.get(via[0], {}).get(via[1]))
    if len(fresh) == 1:
        return sorted(fresh), "setup path"
    full = from_fact(at.get(via[0], {}).get(via[1]))
    if full:
        return sorted(full), "fixpoint"
    if fresh:
        return sorted(fresh), "setup path"
    anyw = set()
    for fa in at.values():
        anyw |= from_fact(fa.get(via[1]))
    return sorted(anyw), "register (flow-insensitive)"


def _load_base(b, ins):
    """(base register, displacement) of a state load; (None, register) for a register state."""
    if b.arm:
        mi = _A64_MEM_IMM.match(ins.op_str)
        if mi is None:
            return None, _ac(ins.op_str.split(",")[1].strip())
        return _ac(mi.group(2)), _num(mi.group(3) or "0")
    from capstone.x86 import X86_OP_MEM
    op = next((o for o in ins.operands if o.type == X86_OP_MEM), None)
    if op is None:
        return None, _xc(ins.reg_name(ins.operands[1].reg))
    return _xc(ins.reg_name(op.mem.base)), op.mem.disp


def _indirect_jump_after(b, va, lo, hi):
    """The first `jmp reg` / `br xN` after `va` (the table jump a dispatch run went through)."""
    pc = va
    for _ in range(24):
        ins = b.insn(pc)
        if ins is None or not (lo <= pc < hi):
            return None
        if (b.arm and ins.mnemonic == "br") or (not b.arm and ins.mnemonic == "jmp" and not ins.op_str.startswith("0x")):
            return pc
        pc += ins.size
    return None


def _entry_order(b, lo, hi, sites):
    """Order in which dispatch sites are met walking from the entry (fall-through first, direct
    jumps followed, calls stepped over): {site: rank}."""
    order, pc, seen = {}, lo, set()
    for step in range(400):
        if pc in seen or not (lo <= pc < hi):
            break
        seen.add(pc)
        if pc in sites and pc not in order:
            order[pc] = len(order)
        ins = b.insn(pc)
        if ins is None:
            break
        m = ins.mnemonic
        if m in ("ret", "ud2", "int3", "brk", "hlt"):
            break
        if (b.arm and m == "br") or (not b.arm and m == "jmp" and not ins.op_str.startswith("0x")):
            break
        if m in ("jmp", "b"):
            pc = _num(ins.op_str.lstrip("#"))
            continue
        pc += ins.size
    return order


# ----------------------------------------------------------------------------------------------
# whole binary
# ----------------------------------------------------------------------------------------------
# `<registry or vendor dir>/<crate>-<semver>/` in the panic-location paths every Rust binary keeps;
# one bytes regex over the data sections replaces a full recover_rust_meta pass (its RE_CARGO shape)
_RT_RE = re.compile(rb"(?:cargo[\\/]registry[\\/]src[\\/][^\\/\x00]{1,80}|[\\/]vendor)[\\/]("
                    + b"|".join(re.escape(c.encode()) for c in RUNTIMES)
                    + rb")-(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)[\\/]")


def _runtime(path, b):
    found = {}
    for _va, raw, ex, _nm in b.secs:
        if ex:
            continue
        for m in _RT_RE.finditer(raw):
            found.setdefault(m.group(1).decode(), set()).add(m.group(2).decode())
    det = [c for c in RUNTIMES if c in found]
    return {"detected": det, "versions": {c: sorted(found[c]) for c in det},
            "note": None if det else "no known runtime crate (hand-written executor or stripped paths)"}


_ALIGNS = {1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096}


def _vtable_at(b: _Bin, va):
    """A `dyn Future` vtable header at `va`: [drop_in_place|0, size, align, poll, ...] with drop and
    poll in code and a sane size/align -> {"va", "size", "align", "poll"}, else None."""
    if va is None or not b.is_data(va):
        return None
    drop, size, align, poll = (b.read_ptr(va + i * b.ptr) for i in range(4))
    if None in (size, align, poll) or not (b.lo <= poll < b.hi):
        return None
    if drop and not (b.lo <= drop < b.hi):
        return None
    if align not in _ALIGNS or size > (1 << 20) or size % align:
        return None
    return {"va": va, "size": size, "align": align, "poll": poll}


def _vtables_for_polls(b: _Bin, polls: set) -> dict:
    """poll fn -> the dyn Future vtable whose slot 3 is it (a boxed coroutine's vtable): found by
    looking up pointer slots holding a poll address (relocations, then raw words), not by
    recovering every vtable in the binary."""
    out = {}
    slots = [va for va, v in b.img.patches.items() if (v & _mask(8 * b.ptr)) in polls]
    if not slots:
        for base, raw, ex, _nm in b.secs:
            if ex:
                continue
            for p in polls:
                vv = p + (b.img.imagebase if b.pe else 0)
                pat = vv.to_bytes(b.ptr, "little")
                o = raw.find(pat)
                while o != -1:
                    if o % b.ptr == 0:
                        slots.append(base + o)
                    o = raw.find(pat, o + 1)
    for slot in slots:
        vt = _vtable_at(b, slot - 3 * b.ptr)
        if vt and vt["poll"] in polls:
            out.setdefault(vt["poll"], vt)
    return out


def recover(path) -> dict:
    b = _Bin(path)
    res = {"path": str(path), "format": b.fmt, "arch": b.arch, "supported": True,
           "anchors": {}, "runtime": None, "machines": [], "poll_functions": [], "nesting": [],
           "counts": {}}
    anchors = find_anchors(b)
    res["anchors"] = {"strings": {k: v for k, v in anchors["strings"].items()},
                      "functions": {k: sorted(v) for k, v in anchors["funcs"].items()},
                      "inline_sites": {k: len(v) for k, v in anchors["inline"].items()}}
    fns = set().union(*anchors["funcs"].values())
    cands = set()
    for site in _call_sites(b, fns):
        lo, _hi = b.fn_bounds(site)
        if lo not in fns:
            cands.add(lo)
    for k in ("returned", "panicked"):
        for site in anchors["inline"][k]:
            cands.add(b.fn_bounds(site)[0])
    machines = []
    skipped = 0
    for lo in sorted(cands)[:_MAX_CANDIDATES]:
        lo, hi = b.fn_bounds(lo)
        if hi - lo > _MAX_FN_BYTES:
            skipped += 1
            continue
        try:
            machines.extend(analyze_function(b, anchors, lo, hi))
        except Exception as e:      # one odd function must not sink the rest
            res.setdefault("errors", []).append({"function": lo, "error": f"{type(e).__name__}: {e}"})
    # vtables: a boxed coroutine's dyn Future vtable gives its size; resolves dyn awaits. Read
    # directly (header [drop, size, align, poll]) only where needed -- no whole-binary vtable scan
    poll_by_fn = {mm["function"]: mm for mm in machines if mm["role"] == "poll"}
    vt_by_poll = _vtables_for_polls(b, set(poll_by_fn)) if poll_by_fn else {}
    fn_refs = {}

    def refs_of(fn_lo, fn_hi):
        """Valid dyn Future vtables a function materializes (the function-level fallback)."""
        if fn_lo not in fn_refs:
            vs = {c for i in b.sweep(fn_lo, fn_hi) for c in [_const_of(b, i)] if c is not None}
            fn_refs[fn_lo] = sorted(c for c in vs if _vtable_at(b, c))
        return fn_refs[fn_lo]

    out, ids = [], {}
    for n, mm in enumerate(machines):
        ids[id(mm)] = f"m{n}"
    site_owner = {s["va"]: mm for mm in machines for s in mm["sites"]}
    # a suspend state with no write-back is expected when the future awaited there can never be
    # Pending (an inlined coroutine with no await of its own, e.g. tokio's async_trace_leaf):
    # LLVM deletes the dead store
    for mm in machines:
        if mm["check"] != "partial":
            continue
        never = []
        for v in mm["unseen"]:
            inner = mm["suspend"].get(v, {}).get("inner", {})
            other = site_owner.get(inner.get("site")) if inner.get("kind") == "inlined" else \
                (poll_by_fn.get(inner.get("target")) if inner.get("kind") == "direct" else None)
            if other is not None and not other["suspend"]:
                never.append(v)
        if never and len(never) == len(mm["unseen"]):
            mm["check"] = "confirmed"
            mm["notes"].append(f"state(s) {never} never written: the future awaited there has no "
                               "suspend point, so it is never Pending")
    nesting = []
    for mm in machines:
        mid = ids[id(mm)]
        states = {}
        for v, t in sorted(mm["targets"].items()):
            nm = STATE_NAMES.get(v, f"Suspend{v - 3}")
            st = {"name": nm, "target": t}
            if v in mm["suspend"]:
                sp = mm["suspend"][v]
                inner = dict(sp["inner"])
                to = None
                if inner["kind"] == "inlined":
                    other = site_owner.get(inner["site"])
                    if other is not None:
                        inner["machine"] = to = ids[id(other)]
                elif inner["kind"] == "direct":
                    pm = poll_by_fn.get(inner.get("target"))
                    if pm is not None:
                        inner["machine"] = to = ids[id(pm)]
                elif inner["kind"] == "dyn":
                    inner["dyn_future_poll"] = inner.get("slot_offset") == 3 * b.ptr
                    raw = inner.pop("vt_candidates", None)
                    if inner["dyn_future_poll"]:
                        if raw is None:      # nothing reached the call site: any vtable the fn uses
                            raw = refs_of(mm["function"], mm["function_end"])
                            inner["vt_from"] = "function"
                        cands = []
                        for va in raw:
                            vt = _vtable_at(b, va)
                            if vt:
                                pm = poll_by_fn.get(vt["poll"])
                                cands.append({"vtable": va, "poll": vt["poll"], "size": vt["size"],
                                              "machine": ids[id(pm)] if pm is not None else None})
                        if len(cands) == 1:
                            inner["vtable"] = cands[0]["vtable"]
                            inner["target"] = cands[0]["poll"]
                            if cands[0]["machine"]:
                                inner["machine"] = to = cands[0]["machine"]
                        elif cands:
                            inner["candidates"] = cands      # ambiguous: every vtable that may reach it
                st["inner"] = inner
                st["pending_writes"] = sp["pending_writes"]
                nesting.append({"from": mid, "state": v, "via": inner["kind"],
                                "to": to or (f"fn:{inner['target']:#x}" if inner.get("target") is not None
                                             else inner.get("name"))})
            states[str(v)] = st
        root = mm["root"]
        base = {"arg0": "self" if mm["role"] == "poll" else "arg0", "sp": "stack", "spa": "stack",
                "reg": "register"}.get(root, f"[{root}]" if root.startswith("*") else
                                       (root if root.startswith("arg") or root in ("ecx", "edx")
                                        else "unknown"))
        if mm["role"] == "poll" and root in _SELF_ROOTS:
            base = "self"
        vt = vt_by_poll.get(mm["function"]) if mm["role"] == "poll" else None
        if vt:
            vt = {"size": vt["size"], "align": vt["align"]}
        loc = _location(b, mm["location_va"]) if mm["location_va"] else None
        out.append({
            "id": mid, "function": mm["function"], "role": mm["role"],
            "self_register": (None if mm["role"] != "poll" else root if root in ("ecx", "edx") else
                              f"[esp+{4 * (int(root[3:]) + 1):#x}]" if b.x32 else b.args[int(root[3:])]),
            "state_field": {"base": base, "root": root, "offset": mm["offset"], "width": mm["width"],
                            "register": mm["register"]},
            "dispatch": [{"va": s["va"], "kind": s["kind"], "table": s["table"],
                          "targets": {str(k): t for k, t in sorted(s["targets"].items())}}
                         for s in mm["sites"]],
            "states": states, "suspend_points": len(mm["suspend"]),
            "state_writes": [{"va": x["va"], "value": x["values"][0] if x["values"] and len(x["values"]) == 1
                              and not x["may"] else None, "values": x["values"], "may": x["may"]}
                             for x in mm["writes"]],
            "validated": mm["consistent"], "writes_check": mm["check"], "notes": mm["notes"],
            "source": loc,
            "size": {"vtable": vt["size"] if vt else None, "align": vt["align"] if vt else None,
                     "min_from_accesses": mm["min_size"]},
        })
    res["machines"] = out
    res["poll_functions"] = sorted({m["function"] for m in out if m["role"] == "poll"})
    res["host_functions"] = sorted({m["function"] for m in out})
    res["nesting"] = nesting
    res["runtime"] = _runtime(path, b)
    res["counts"] = {"candidates": len(cands), "skipped_oversized": skipped + max(0, len(cands) - _MAX_CANDIDATES),
                     "machines": len(out),
                     "poll_functions": len(res["poll_functions"]),
                     "host_functions": len(res["host_functions"]),
                     "suspend_points": sum(m["suspend_points"] for m in out)}
    return res


# ----------------------------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------------------------
def _print(res: dict) -> None:
    print(f"{res['path']}: format={res['format']} arch={res['arch']}")
    if not res.get("supported", True):
        print("  " + res.get("note", "unsupported"))
        return
    c = res["counts"]
    rt = res["runtime"] or {}
    print(f"  {c['machines']} async state machine(s) in {c['host_functions']} function(s); "
          f"{c['poll_functions']} poll function(s); {c['suspend_points']} suspend point(s)")
    print(f"  runtime: {', '.join(rt.get('detected') or []) or (rt.get('note') or 'none')}")
    for m in res["machines"]:
        f = m["state_field"]
        if f.get("register"):
            where = f"register {f['register']}"
        else:
            where = f"{f['base']}+{f['offset']:#x}" if f["offset"] is not None else f"{f['base']}+?"
        src = f"  [{m['source']['file']}:{m['source']['line']}:{m['source']['col']}]" if m["source"] else ""
        print(f"  {m['id']} fn {m['function']:#x} {m['role']}: state u{8 * f['width']} at {where}, "
              f"{m['suspend_points']} suspend point(s), dispatch {m['dispatch'][0]['kind']}"
              f", writes {m['writes_check']}{src}")
        for k, st in m["states"].items():
            line = f"      {k:>3} {st['name']:<10} -> {st['target']:#x}"
            if "inner" in st:
                i = st["inner"]
                desc = {"direct": lambda: (f"polls fn {i['target']:#x}" if i.get("target") is not None
                                           else "polls an unresolved slot"),
                        "inlined": lambda: f"inlined machine {i.get('machine', '?')}",
                        "dyn": lambda: f"dyn vtable slot {i.get('slot_offset', 0):#x}"
                                       + (f" -> {i['machine']}" if i.get("machine") else ""),
                        "import": lambda: f"import {i.get('name')}"}.get(i["kind"], lambda: i["kind"])()
                line += f"   {desc}; pending writes {[hex(a) for a in st['pending_writes']]}"
            print(line)
        sz = m["size"]
        if sz["vtable"] or sz["min_from_accesses"]:
            print(f"      size: vtable={sz['vtable']} min-from-accesses={sz['min_from_accesses']}")


def _selftest():
    # flag semantics: x86 vs AArch64 carry conventions on the same compare
    f = _f_sub(3, 1, 8)
    assert _x86_cond("ja", f) and not _x86_cond("jb", f) and _a64_cond("hi", f) and _a64_cond("hs", f)
    f = _f_sub(1, 3, 8)
    assert _x86_cond("jb", f) and _a64_cond("lo", f) and _a64_cond("lt", f) and not _a64_cond("gt", f)
    assert _x86_cond("je", _f_sub(4, 4, 8)) and _a64_cond("le", _f_sub(4, 4, 32))
    assert _xc("cl") == "rcx" and _xc("r15b") == "r15" and _ac("w8") == "x8" and _ac("wzr") == "xzr"
    assert _a64_operand({"x10": 3}, "x10, lsl #2") == 12 and _a64_operand({}, "#0x10") == 16
    assert _a64_operand({"x8": 0xffffffff}, "w8, sxtw #2") == -4

    class FakeBin(_Bin):
        """A synthetic image: code at `lo`, one rodata section; no LIEF."""
        def __init__(self, arm, code, lo, data, data_va, funcs=None):
            from capstone import Cs, CS_ARCH_X86, CS_ARCH_ARM64, CS_MODE_64, CS_MODE_LITTLE_ENDIAN
            self.arm, self.pe, self.x32, self.ptr, self.macho = arm, False, False, 8, False
            self.code, self.lo, self.hi = code, lo, lo + len(code)
            self.secs = sorted([(lo, code, True, ".text"), (data_va, data, False, ".rodata")])
            self._sec_vas = [t[0] for t in self.secs]
            self.starts = sorted(funcs or [lo])
            self.args, self.abi = (("x0", "x1", "x2", "x3"), "aapcs64") if arm else \
                (("rdi", "rsi", "rdx", "rcx"), "sysv")
            self.md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN) if arm else Cs(CS_ARCH_X86, CS_MODE_64)
            self.md.detail = True
            self._insn = {}
            self.tramp_base = None

            class _Img:
                patches = {}
                tramp = []
            self.img = _Img()

    # --- x86-64: a jump-table dispatch on the state byte at self+0x10, as rustc -O emits it ---
    LO, DATA = 0x1000, 0x8000
    PANIC_DONE, PANIC_POIS = 0x1f00, 0x1f40
    asm = bytearray()
    lab = {}

    def emit(bs):
        asm.extend(bs)

    def here():
        return LO + len(asm)
    emit(b"\x53")                                   # push rbx
    emit(b"\x48\x89\xfb")                           # mov rbx, rdi
    lab["load"] = here()
    emit(b"\x0f\xb6\x47\x10")                       # movzx eax, byte [rdi+0x10]
    lea_at = here()
    emit(b"\x48\x8d\x0d\x00\x00\x00\x00")           # lea rcx, [rip+table]   (patched below)
    emit(b"\x48\x63\x04\x81")                       # movsxd rax, dword [rcx+rax*4]
    emit(b"\x48\x01\xc8")                           # add rax, rcx
    emit(b"\xff\xe0")                               # jmp rax
    lab[0] = here(); emit(b"\x48\x8b\x03")          # state 0: mov rax, [rbx]   (body)
    lab[3] = here(); emit(b"\xe8\x00\x00\x00\x00")  # state 3: call inner poll  (patched)
    call3 = lab[3]
    emit(b"\xc6\x43\x10\x03")                       # mov byte [rbx+0x10], 3   (pending write)
    emit(b"\x5b\xc3")                               # pop rbx ; ret
    lab[4] = here(); emit(b"\xe8\x00\x00\x00\x00")  # state 4: call inner poll 2
    call4 = lab[4]
    emit(b"\xc6\x43\x10\x04")                       # mov byte [rbx+0x10], 4
    emit(b"\xc6\x43\x10\x01")                       # mov byte [rbx+0x10], 1   (returned)
    emit(b"\x5b\xc3")
    lab[1] = here(); emit(b"\xe8\x00\x00\x00\x00")  # call panic_const_async_fn_resumed
    c1 = lab[1]
    lab[2] = here(); emit(b"\xe8\x00\x00\x00\x00")  # call ..._resumed_panic
    c2 = lab[2]
    emit(b"\x0f\x0b")
    while here() < 0x1e00:
        emit(b"\xcc")
    inner1 = here(); emit(b"\x31\xc0\xc3")          # inner poll fn: xor eax,eax; ret
    inner2 = here(); emit(b"\x31\xc0\xc3")
    while here() < PANIC_DONE:
        emit(b"\xcc")
    emit(b"\x0f\x0b" + b"\xcc" * 0x3e)
    emit(b"\x0f\x0b" + b"\xcc" * 0x3e)

    def rel32(at, to, ln=5, off=1):
        struct.pack_into("<i", asm, at - LO + off, to - (at + ln))
    rel32(lea_at, DATA, 7, 3)
    rel32(c1, PANIC_DONE)
    rel32(c2, PANIC_POIS)
    rel32(call3, inner1)
    rel32(call4, inner2)
    table = b"".join(struct.pack("<i", lab[k] - DATA) for k in range(5)) + b"\xff\xff\xff\x7f" * 4
    fb = FakeBin(False, bytes(asm), LO, table, DATA, funcs=[LO, inner1, inner2, PANIC_DONE, PANIC_POIS])
    anchors = {"refs": {}, "funcs": {"returned": {PANIC_DONE}, "panicked": {PANIC_POIS}},
               "inline": {"returned": set(), "panicked": set()}}
    ms = analyze_function(fb, anchors, LO, inner1)
    assert len(ms) == 1, ms
    m = ms[0]
    assert m["role"] == "poll" and m["field"] == ("arg0", 0x10) and m["width"] == 1, m
    assert m["targets"] == {0: lab[0], 1: lab[1], 2: lab[2], 3: lab[3], 4: lab[4]}, m["targets"]
    assert m["sites"][0]["kind"] == "jump_table"
    assert m["suspend"][3]["inner"] == {"kind": "direct", "target": inner1}
    assert m["suspend"][4]["inner"]["target"] == inner2
    assert m["consistent"] and [x["values"] for x in m["writes"]] == [[3], [4], [1]]

    # --- AArch64: the compare-chain form (cmp/b.gt/cbnz) ---
    A = []
    A_LO = 0x4000
    words = {}

    def a(word):
        A.append(word)
        return A_LO + 4 * (len(A) - 1)

    def b_imm(op, at, to):       # b/bl encoding
        return op | (((to - at) >> 2) & 0x3ffffff)

    def bcond(at, to, cond):
        return 0x54000000 | ((((to - at) >> 2) & 0x7ffff) << 5) | cond

    def cbz(at, to, rt, nz=False):
        return (0x35000000 if nz else 0x34000000) | ((((to - at) >> 2) & 0x7ffff) << 5) | rt
    a(0xa9be7bfd)                                  # stp x29, x30, [sp, #-0x20]!
    load = a(0x3940e008)                           # ldrb w8, [x0, #0x38]
    a(0xaa0003f3)                                  # mov x19, x0
    a(0x7100051f)                                  # cmp w8, #1
    p_gt = a(0)                                    # b.gt L_ge2
    p_nz = a(0)                                    # cbnz w8, L_ret
    s0 = a(0xf9400268)                             # state 0: ldr x8, [x19]
    p_b = a(0)                                     # b L_s3
    l_ge2 = a(0x71000d1f)                          # cmp w8, #3
    p_ne = a(0)                                    # b.ne L_pois
    l_s3 = a(0)                                    # bl inner
    a(0x52800068)                                  # mov w8, #3
    a(0x3900e268)                                  # strb w8, [x19, #0x38]
    a(0xd65f03c0)                                  # ret
    l_ret = a(0)                                   # bl panic_done
    l_pois = a(0)                                  # bl panic_pois
    a(0xd4200020)                                  # brk #1
    inner = a(0xd65f03c0)                          # inner: ret
    pd = a(0xd4200020)
    for _ in range(31):
        a(0xd503201f)
    pp = a(0xd4200020)
    for _ in range(31):
        a(0xd503201f)

    def setw(at, w):
        A[(at - A_LO) // 4] = w
    setw(p_gt, bcond(p_gt, l_ge2, 0xc))            # gt
    setw(p_nz, cbz(p_nz, l_ret, 8, nz=True))
    setw(p_b, b_imm(0x14000000, p_b, l_s3))
    setw(p_ne, bcond(p_ne, l_pois, 0x1))           # ne
    setw(l_s3, b_imm(0x94000000, l_s3, inner))
    setw(l_ret, b_imm(0x94000000, l_ret, pd))
    setw(l_pois, b_imm(0x94000000, l_pois, pp))
    code = struct.pack(f"<{len(A)}I", *A)
    fa = FakeBin(True, code, A_LO, b"\x00" * 16, 0x9000, funcs=[A_LO, inner, pd, pp])
    anchors = {"refs": {}, "funcs": {"returned": {pd}, "panicked": {pp}},
               "inline": {"returned": set(), "panicked": set()}}
    ms = analyze_function(fa, anchors, A_LO, inner)
    assert len(ms) == 1, ms
    m = ms[0]
    assert m["field"] == ("arg0", 0x38) and m["sites"][0]["kind"] == "compare_chain", m
    assert m["targets"] == {0: s0, 1: l_ret, 2: l_pois, 3: l_s3}, m["targets"]
    assert m["suspend"][3]["inner"] == {"kind": "direct", "target": inner}
    assert m["consistent"] and [x["values"] for x in m["writes"]] == [[3]]
    assert load == m["sites"][0]["va"]

    # --- a pending write through a pointer phi: x21 = self+0x51 on one path, self+0xe9 on the
    # other, one shared `strb w8, [x21]` -- the store must be attributed to both fields (may)
    P = []

    def pa(w):
        P.append(w)
        return 0x6000 + 4 * (len(P) - 1)
    c0 = pa(0)                                     # cbz x2, L1
    pa(0x91014415)                                 # add x21, x0, #0x51
    b0 = pa(0)                                     # b L2
    l1 = pa(0x9103a415)                            # L1: add x21, x0, #0xe9
    l2 = pa(0x52800068)                            # L2: mov w8, #3
    st_ = pa(0x390002a8)                           # strb w8, [x21]
    pa(0xd65f03c0)                                 # ret
    P[(c0 - 0x6000) // 4] = 0xb4000000 | (((l1 - c0) >> 2) << 5) | 2
    P[(b0 - 0x6000) // 4] = 0x14000000 | ((l2 - b0) >> 2)
    fp = FakeBin(True, struct.pack(f"<{len(P)}I", *P), 0x6000, b"\x00" * 8, 0x9000)
    acc = []
    _dataflow(fp, fp.sweep(0x6000, fp.hi), 0x6000, fp.hi, {}, {"x0": ("p", "arg0", 0)},
              lambda ins, kind, ptrs, w, vals, may: acc.append((ins.address, kind, ptrs, w, vals, may)))
    assert acc == [(st_, "store", [("arg0", 0x51), ("arg0", 0xe9)], 1, {3}, True)], acc
    assert _join({"x1": ("c", 3)}, {"x1": ("c", 4)}) == {"x1": ("cs", frozenset({3, 4}))}
    assert _join({"x1": ("c", 3)}, {}) == {}
    print("selftest OK")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("binaries", nargs="*")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args(argv)
    if a.selftest:
        _selftest()
        return 0
    if not a.binaries:
        ap.error("give a binary (or --selftest)")
    results = []
    for p in a.binaries:
        try:
            r = recover(p)
        except Exception as e:
            r = {"path": p, "error": f"{type(e).__name__}: {e}"}
        results.append(r)
        if not a.json:
            if "error" in r:
                print(f"{p}: error: {r['error']}")
            else:
                _print(r)
    if a.json:
        print(json.dumps(results[0] if len(results) == 1 else results, indent=1, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
