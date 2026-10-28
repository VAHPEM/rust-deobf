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
  3. dataflow  - a small forward analysis (register = arg/stack pointer + offset, or a constant)
                 gives each state field's location relative to `self` (or the stack, for a
                 coroutine inlined into its executor), and every store of a state value to it:
                 the Pending paths' write-backs, which validate the recovered state count;
  4. suspend   - for each Suspend state, the first poll reached from its resume target: a direct
                 call (another recovered poll function -> nesting edge), a `dyn Future` vtable
                 slot (slot 3 = poll; resolved through recover_types' vtables when the function
                 references one whose poll is recovered), or a nested inlined state machine;
  5. extras    - the coroutine's source location (the &Location passed to the resume panic, so a
                 stripped binary still says `src/main.rs:13:30`), its size (the `dyn Future`
                 vtable's size field when it is boxed; else a lower bound from the accesses through
                 `self`), and which async runtime is linked (recover_rust_meta's crate list).

Machines whose field is relative to the function's own argument are that function's state
machine ("poll"); with -O an awaited future's poll is often inlined into its parent's, so a function
can also hold nested machines (field inside self) or a coroutine inlined into a non-poll function
(`block_on`, tokio's Core::poll) with its state on the stack.

    python3 scripts/recover_async.py path/to/binary           # summary
    python3 scripts/recover_async.py path/to/binary --json
    python3 scripts/recover_async.py --selftest

x86-64 (ELF SysV: self in rdi/rsi; PE Win64: rcx/rdx) and AArch64 (x0/x1), ELF + PE (RVAs).
32-bit x86 is reported as unsupported. Static only: nothing is executed.
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
                     "win64": ("rax", "rcx", "rdx", "r8", "r9", "r10", "r11")}
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
        self.arm, self.pe, self.x32 = img.arm, img.pe, img.x32
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
        self.starts = sorted(a for a in st if self.lo <= a < self.hi)
        if self.arm:
            self.args, self.abi = ("x0", "x1", "x2", "x3"), "aapcs64"
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
    """Code addresses that materialize one of `targets`: x86-64 `lea r, [rip+d]` / AArch64 `adr`
    and `adrp`+`add`. Byte/word scans (fast); every hit is re-decoded before use by the callers."""
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
                    out.append(pc)
            elif (w & 0x9f000000) == 0x90000000:                     # adrp ; add rd, rd, #lo12
                imm = (((w >> 5) & 0x7ffff) << 2) | ((w >> 29) & 3)
                page = (pc & ~0xfff) + (_sx(imm, 21) << 12)
                rd = w & 31
                for j in range(i + 1, min(n, i + 4)):
                    w2 = words[j]
                    if (w2 & 0xffc00000) == 0x91000000 and ((w2 >> 5) & 31) == rd:
                        if page + ((w2 >> 10) & 0xfff) in targets:
                            out.append(lo + 4 * j)
                        break
    elif not b.x32:
        for m in _LEA_RIP.finditer(code):
            o = m.start()
            if o + 7 > len(code):
                continue
            d = struct.unpack_from("<i", code, o + 3)[0]
            if lo + o + 7 + d in targets:
                out.append(lo + o)
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
    for site in _code_refs(b, set(kind_of)):
        ins = b.insn(site)
        if ins is None:
            continue
        tgt = _const_of(b, ins)
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
    if ins.mnemonic == "lea":
        from capstone.x86 import X86_OP_MEM, X86_REG_RIP
        op = ins.operands[1]
        if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP and not op.mem.index:
            return ins.address + ins.size + op.mem.disp
    return None


# ----------------------------------------------------------------------------------------------
# 2. the dispatch interpreter
# ----------------------------------------------------------------------------------------------
class _Run:
    __slots__ = ("target", "jt", "table", "reads", "branches")

    def __init__(self):
        self.target = None      # where control lands for this state value
        self.jt = False         # passed through an indirect (table) jump
        self.table = None       # first table read VA
        self.reads = []         # table entry VAs read
        self.branches = 0


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
        if mem.base == X86_REG_RIP:
            base = ins.address + ins.size
        elif mem.base:
            base = regs.get(_xc(ins.reg_name(mem.base)))
        else:
            base = 0
        idx = 0
        if mem.index:
            idx = regs.get(_xc(ins.reg_name(mem.index)))
        if base is None or idx is None or mem.segment:
            raise _Stop()
        addr = (base + idx * mem.scale + mem.disp) & _mask(64)
        if not b.is_data(addr):
            raise _Stop()
        raw = b.read(addr, op.size)
        if raw is None:
            raise _Stop()
        if run.table is None:
            run.table = addr
        run.reads.append(addr)
        return int.from_bytes(raw, "little")
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
    tainted = False         # an unrelated load ran: a plain jump now is body control flow
    while steps < _RUN_STEPS:
        steps += 1
        ins = b.insn(pc)
        if ins is None or not (lo <= pc < hi):
            run.target = seg
            return run
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
            if m in ("mov", "movzx", "movsx", "movsxd", "movabs"):
                if ops[0].type != X86_OP_REG:
                    # a spill to the stack may be scheduled into the dispatch; any other store
                    # means the body has started
                    if ops[0].type == X86_OP_MEM and ops[0].mem.base and \
                            _xc(ins.reg_name(ops[0].mem.base)) in ("rsp", "rbp") and smem is not None \
                            and smem[0] is not None and smem[0][0] not in ("rsp", "rbp"):
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
                t = _x86_op_val(b, ins, op, regs, smem, v, run) if op.type == X86_OP_REG else None
                if t is None:
                    raise _Stop()
                run.jt = True
                pc = seg = t
                continue
            raise _Stop()
        except _Stop:
            run.target = seg
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
                pc = nxt
                continue
            if m == "mov" and len(parts) == 2:
                dst = _ac(parts[0])
                val = _a64_operand(regs, parts[1])
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
                    return {"kind": "dyn", "slot_offset": disp}
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
            return {"kind": "dyn", "slot_offset": op.mem.disp}
        return {"kind": "indirect"}
    if op.type == X86_OP_REG:
        reg = _xc(ins.reg_name(op.reg))
        for p in reversed(recent):
            if p.mnemonic == "mov" and len(p.operands) == 2 and p.operands[0].type == X86_OP_REG \
                    and _xc(p.reg_name(p.operands[0].reg)) == reg:
                src = p.operands[1]
                if src.type == X86_OP_MEM and src.mem.base and src.mem.base != X86_REG_RIP \
                        and not src.mem.index and _xc(p.reg_name(src.mem.base)) not in ("rsp", "rbp"):
                    return {"kind": "dyn", "slot_offset": src.mem.disp}
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
    for e in events:
        if e[0] == "ref" and e[2] in anchors["refs"]:
            kind = anchors["refs"][e[2]]
            break
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
def _deref(bf, disp):
    """A pointer loaded from [root+k+disp] gets its own symbolic root `*root+off`, so two accesses
    through the same loaded pointer (a `&mut Future` held in the executor's frame) agree. One level
    of indirection beyond an argument / the stack is enough here and keeps roots finite."""
    if not bf or bf[0] != "p" or bf[1].count("*") >= 2:
        return None
    return ("p", f"*{bf[1]}{bf[2] + disp:+#x}", 0)


def _join(a, b):
    if a is None:
        return dict(b)
    return {k: v for k, v in a.items() if b.get(k) == v}


def _transfer(bn: _Bin, ins, f, on_access=None):
    """Update facts `f` (reg -> ("p", root, k) | ("c", value)) across `ins`. `on_access(ins, kind,
    root, off, width, value)` is called for memory accesses through a known pointer."""
    m = ins.mnemonic
    if bn.arm:
        s = ins.op_str
        parts = [p.strip() for p in s.split(",")] if s else []
        if m in ("bl", "blr"):
            for r in _A64_CALLER_SAVED:
                f.pop(r, None)
            return
        is_ld = m in _A64_LOAD or m in ("ldp", "ldpsw")
        is_st = m in ("strb", "strh", "str", "sturb", "sturh", "stur", "stp")
        if is_ld or is_st:
            mi = _A64_MEM_IMM.match(s) if m not in ("ldp", "stp", "ldpsw") else \
                re.match(r"^(\w+), \w+, \[(\w+)(?:, #(-?(?:0x[0-9a-f]+|\d+)))?\](!?)$", s)
            mp = _A64_MEM_POST.match(s) if mi is None else None
            if mp is None and mi is None and m in ("ldp", "stp", "ldpsw"):
                mp = re.match(r"^(\w+), \w+, \[(\w+)\], #(-?(?:0x[0-9a-f]+|\d+))$", s)
            base = disp = None
            wb = 0
            if mi:
                base, disp = _ac(mi.group(2)), _num(mi.group(3) or "0")
                if mi.group(4):
                    wb = disp
            elif mp:
                base, disp, wb = _ac(mp.group(2)), 0, _num(mp.group(3))
            bf = None
            if base is not None:
                bf = ("p", "sp", 0) if base == "sp" else f.get(base)   # before any writeback
                if on_access and bf and bf[0] == "p" and m not in ("ldp", "stp", "ldpsw"):
                    w = {"strb": 1, "sturb": 1, "strh": 2, "sturh": 2}.get(m)
                    if w is None:
                        w = _A64_LOAD.get(m, (None, 0))[0] if is_ld else None
                    if w is None:
                        w = 4 if parts[0].startswith("w") else 8
                    val = None
                    if is_st:
                        src = _ac(parts[0])
                        val = 0 if src == "xzr" else (f[src][1] if f.get(src, ("",))[0] == "c" else None)
                    on_access(ins, "store" if is_st else "load", bf[1], bf[2] + disp, w, val)
                if wb and base != "sp":
                    if bf and bf[0] == "p":
                        f[base] = ("p", bf[1], bf[2] + wb)
                    elif bf and bf[0] == "c":
                        f[base] = ("c", bf[1] + wb)
                    else:
                        f.pop(base, None)
            if is_ld:
                f.pop(_ac(parts[0]), None)
                if m in ("ldp", "ldpsw") and len(parts) > 1:
                    f.pop(_ac(parts[1]), None)
                    if m == "ldp" and parts[0].startswith("x") and base is not None and not wb:
                        for k, r in enumerate((parts[0], parts[1])):
                            d = _deref(bf, disp + 8 * k)
                            if d is not None and _ac(r) != base:
                                f[_ac(r)] = d
                elif m in ("ldr", "ldur") and parts[0].startswith("x") and base is not None:
                    d = _deref(bf, disp)
                    if d is not None and _ac(parts[0]) != base:
                        f[_ac(parts[0])] = d
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
            elif _ac(src) in f and (parts[0].startswith("x") or f[_ac(src)][0] == "c"):
                f[dst] = f[_ac(src)]
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
            if src and src[0] == "p":
                f[dst] = ("p", src[1], src[2] + k)
            elif src and src[0] == "c":
                f[dst] = ("c", (src[1] + k) & _mask(64))
            else:
                f.pop(dst, None)
            return
        f.pop(dst, None)
        return
    # x86-64
    from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM, X86_REG_RIP
    ops = ins.operands
    if m == "call":
        for r in _X86_CALLER_SAVED[bn.abi]:
            f.pop(r, None)
        return
    if on_access:
        for i, op in enumerate(ops):
            if op.type == X86_OP_MEM and op.mem.base and op.mem.base != X86_REG_RIP and not op.mem.index \
                    and m not in ("lea", "nop") and not m.startswith("nop"):
                bc = _xc(ins.reg_name(op.mem.base))
                bf = ("p", "sp", 0) if bc == "rsp" else f.get(bc)
                if bf and bf[0] == "p":
                    store = i == 0 and m in ("mov", "movb", "movw", "movl", "movq") and len(ops) == 2
                    val = None
                    if store:
                        src = ops[1]
                        if src.type == X86_OP_IMM:
                            val = src.imm & _mask(op.size * 8)
                        elif src.type == X86_OP_REG:
                            sf = f.get(_xc(ins.reg_name(src.reg)))
                            if sf and (sf[0] == "c" or (sf[0] == "cp" and op.size * 8 <= sf[2])):
                                val = sf[1] & _mask(op.size * 8)
                    kind = "store" if store else ("rmw" if i == 0 and m not in ("cmp", "test") else "load")
                    on_access(ins, kind, bf[1], bf[2] + op.mem.disp, op.size, val)
    if not ops or ops[0].type != X86_OP_REG:
        return
    dst = _xc(ins.reg_name(ops[0].reg))
    if dst == "rsp":
        return
    if m in ("cmp", "test") or m.startswith("j") or m in ("push",):
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
                f[dst] = ("c", src.imm & _mask(w))
            elif old and old[0] == "c":           # a partial write merges into a known constant
                f[dst] = ("c", (old[1] & ~_mask(w)) | (src.imm & _mask(w)))
            else:                                 # only the low `w` bits are known (`mov cl, 3`)
                f[dst] = ("cp", src.imm & _mask(w), w)
        elif src.type == X86_OP_REG:
            sc = _xc(ins.reg_name(src.reg))
            sf = ("p", "sp", 0) if sc == "rsp" else f.get(sc)
            if sf and (ops[0].size == 8 or (sf[0] == "c" and ops[0].size == 4)):
                f[dst] = sf if ops[0].size == 8 else ("c", sf[1] & _mask(32))
            else:
                f.pop(dst, None)
        elif src.type == X86_OP_MEM and ops[0].size == 8 and src.mem.base and not src.mem.index \
                and src.mem.base != X86_REG_RIP and not src.mem.segment:
            bc = _xc(ins.reg_name(src.mem.base))
            d = _deref(("p", "sp", 0) if bc == "rsp" else f.get(bc), src.mem.disp)
            if d is None:
                f.pop(dst, None)
            else:
                f[dst] = d
        else:
            f.pop(dst, None)
        return
    if m == "lea" and len(ops) == 2:
        mm = ops[1].mem
        if mm.base == X86_REG_RIP:
            f[dst] = ("c", ins.address + ins.size + mm.disp)
        elif mm.base and not mm.index and ops[0].size == 8:
            bc = _xc(ins.reg_name(mm.base))
            bf = ("p", "sp", 0) if bc == "rsp" else f.get(bc)
            if bf and bf[0] == "p":
                f[dst] = ("p", bf[1], bf[2] + mm.disp)
            else:
                f.pop(dst, None)
        else:
            f.pop(dst, None)
        return
    if m in ("add", "sub") and len(ops) == 2 and ops[1].type == X86_OP_IMM and ops[0].size == 8:
        df = f.get(dst)
        k = ops[1].imm if m == "add" else -ops[1].imm
        if df and df[0] == "p":
            f[dst] = ("p", df[1], df[2] + k)
        else:
            f.pop(dst, None)
        return
    if m == "xor" and len(ops) == 2 and ops[1].type == X86_OP_REG and ops[1].reg == ops[0].reg:
        f[dst] = ("c", 0)
        return
    try:
        _r, w = ins.regs_access()
        for r in w:
            c = _xc(ins.reg_name(r))
            if c != "rsp":
                f.pop(c, None)
    except Exception:
        f.pop(dst, None)


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
        else:
            if m.startswith("j"):
                from capstone.x86 import X86_OP_IMM
                if i.operands and i.operands[0].type == X86_OP_IMM:
                    tgts = [i.operands[0].imm]
                term = m == "jmp"
            elif m in ("ret", "ud2", "int3", "hlt"):
                term = True
        tgts = [t for t in tgts if t in aset]
        tgts += [t for t in extra_edges.get(i.address, ()) if t in aset]
        if tgts or term or m.startswith("b.") or (not bn.arm and m.startswith("j")):
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


def _dataflow(bn: _Bin, insns, lo, hi, extra_edges, entry_facts, on_access):
    blocks, succ = _blocks(bn, insns, lo, hi, extra_edges)
    if not blocks:
        return {}
    fin = {st: None for st in blocks}
    first = min(blocks)
    fin[first] = dict(entry_facts)
    work = [first]
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
def _try_dispatch(b, anchors, load_va, lo, hi, cls_cache, seed=None):
    def cls(t):
        if t not in cls_cache:
            cls_cache[t] = _classify(b, anchors, t, lo, hi)
        return cls_cache[t]
    r1 = _dispatch_run(b, load_va, 1, lo, hi, seed)
    if cls(r1.target)[0] != "returned":
        return None
    r2 = _dispatch_run(b, load_va, 2, lo, hi, seed)
    if cls(r2.target)[0] != "panicked":
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
        if cls_cache[t][0] is not None:
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
        if c is not None and b.is_data(c):
            boundaries.add(c)
    sites = []
    entry = {r: ("p", f"arg{k}", 0) for k, r in enumerate(b.args)}
    loads = [(i, w) for i in insns for w in [_is_state_load(b, i)] if w]
    if not loads:
        return []
    edges = {}           # indirect jump VA -> targets the dispatch runs resolved (CFG edges)
    done = set()
    # rounds: a dispatch reached only through another machine's jump table gets its constants
    # (a table base hoisted out of the executor loop) once that table's edges are in the CFG
    for _round in range(3):
        pre = _dataflow(b, insns, lo, hi, edges, entry, None)
        new = 0
        for i, w in loads:
            if i.address in done:
                continue
            f0 = pre.get(i.address) or {}
            seed = {r: fv[1] for r, fv in f0.items() if fv[0] == "c"}
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
    if not sites:
        return []
    # dataflow: where is each state field, and who writes it
    accesses = []

    def on_access(ins, kind, root, off, width, val):
        accesses.append((ins.address, kind, root, off, width, val))
    at = _dataflow(b, insns, lo, hi, edges, entry, on_access)
    for s in sites:
        f = at.get(s["va"], {})
        ins = b.insn(s["va"])
        base, disp = _load_base(b, ins)
        bf = ("p", "sp", 0) if base in ("rsp", "sp") else f.get(base)
        if base is None:
            s["field"] = ("reg", disp, s["va"])         # a register: one machine per dispatch site
        elif bf and bf[0] == "p":
            s["field"] = (bf[1], bf[2] + disp)
        else:
            s["field"] = ("?", disp, s["va"])          # unknown base: its own group
    # group sites by field
    groups = {}
    for s in sites:
        groups.setdefault(s["field"], []).append(s)
    entry_order = _entry_order(b, lo, hi, {s["va"] for s in sites})
    machines = []
    all_sites = {s["va"] for s in sites}
    for field, ss in groups.items():
        ss.sort(key=lambda s: s["va"])
        width = ss[0]["width"]
        writes = sorted({(a, val) for a, kind, root, off, w, val in accesses
                         if kind in ("store", "rmw") and (root, off) == field[:2] and w == width})
        main = max(ss, key=lambda s: len(s["targets"]))
        targets = dict(main["targets"])
        consts = sorted({val for _a, val in writes if val is not None})
        computed = any(val is None for _a, val in writes)
        notes = []
        if field[0] == "reg":
            computed = True             # a promoted state: its write-backs are register moves
            notes.append(f"state kept in register {field[1]} (coroutine inlined into a loop)")
        n_states = max(targets) + 1
        # writes are the ground truth of which suspend states exist: extend a chain that stopped
        # early on a merged target, and cap a table read that ran past its end
        if consts:
            mx = max(consts)
            if mx >= n_states and mx < _MAX_STATES:
                for v in range(n_states, mx + 1):
                    r = _dispatch_run(b, main["va"], v, lo, hi, main["seed"])
                    if r.target is None or r.target not in insn_set:
                        break
                    targets[v] = r.target
                notes.append("states extended to the highest written value")
            elif not computed and mx >= 3 and mx + 1 < n_states and main["kind"] == "jump_table":
                # only an unbounded table read can overshoot; a compare chain cannot, and a
                # pending write the dataflow missed must not cost a real state
                for v in range(mx + 1, n_states):
                    targets.pop(v, None)
                notes.append("table entries past the highest written state dropped")
        n_states = max(targets) + 1
        contradicted = any(v >= n_states for v in consts)
        unseen = [v for v in range(3, n_states) if not any(val == v for _a, val in writes)]
        consistent = not contradicted
        if contradicted:
            check = "contradicted"
            notes.append("a state value written back is outside the recovered dispatch")
        elif unseen and not computed:
            check = "partial"        # e.g. a pending write through a pointer phi (merged arms)
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
            "consistent": consistent, "check": check, "notes": notes, "location_va": loc,
            "first_seen": entry_order.get(min(s["va"] for s in ss), 1 << 30),
        })
    # primary = the machine reached first from the entry whose field hangs off an argument
    machines.sort(key=lambda mm: (mm["first_seen"], mm["sites"][0]["va"]))
    prim = next((mm for mm in machines if mm["root"] in ("arg0", "arg1")
                 and mm["first_seen"] < (1 << 30)), None)
    if prim is None:
        # the entry walk (fall-through first) can miss a dispatch behind a taken branch: fall back
        # to the argument-relative machine dispatched earliest in the code
        argm = [mm for mm in machines if mm["root"] in ("arg0", "arg1")]
        if argm:
            prim = min(argm, key=lambda mm: mm["sites"][0]["va"])
    max_off = {}
    for _a, _k, root, off, w, _v in accesses:
        if root in ("arg0", "arg1") and off >= 0:
            max_off[root] = max(max_off.get(root, 0), off + w)
    for mm in machines:
        mm["role"] = "poll" if mm is prim else "inlined"
        mm["min_size"] = max_off.get(mm["root"]) if mm is prim else None
        # suspend points: the first poll reached from each resume target
        sus = {}
        for v, t in sorted(mm["targets"].items()):
            if v < 3:
                continue
            others = all_sites - {s["va"] for s in mm["sites"]}
            ev, _c = _walk(b, t, lo, hi, frozenset(others))
            inner = {"kind": "inline_code"}      # the awaited future's poll was inlined here
            for e in ev:
                if e[0] == "site":
                    inner = {"kind": "inlined", "site": e[1]}
                    break
                if e[0] == "call":
                    inner = dict(e[2])
                    break
            sus[v] = {"resume": t, "inner": inner,
                      "pending_writes": [a for a, val in mm["writes"] if val == v]}
        mm["suspend"] = sus
    return machines


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
def _runtime(path, b):
    found, versions = [], {}
    try:
        import recover_rust_meta
        crates = recover_rust_meta.recover(Path(path)).get("crates", {})
    except Exception:
        crates = {}
    for c in RUNTIMES:
        if c in crates or c.replace("-", "_") in crates:
            found.append(c)
            versions[c] = crates.get(c) or crates.get(c.replace("-", "_")) or []
    return {"detected": found, "versions": versions,
            "note": None if found else "no known runtime crate (hand-written executor or stripped paths)"}


def recover(path) -> dict:
    b = _Bin(path)
    res = {"path": str(path), "format": b.fmt, "arch": b.arch, "supported": not b.x32,
           "anchors": {}, "runtime": None, "machines": [], "poll_functions": [], "nesting": [],
           "counts": {}}
    if b.x32:
        res["note"] = "32-bit x86 is not supported by this tier"
        res["counts"] = {"candidates": 0, "skipped_oversized": 0, "machines": 0, "poll_functions": 0,
                         "host_functions": 0, "suspend_points": 0}
        return res
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
    # vtables: a boxed coroutine's dyn Future vtable gives its size; resolves dyn awaits
    poll_by_fn = {mm["function"]: mm for mm in machines if mm["role"] == "poll"}
    vt_by_poll, vt_by_va = {}, {}
    if poll_by_fn:
        try:
            import recover_types
            for vt in recover_types.recover(path)["vtables"]:
                if vt["methods"] and vt["methods"][0] in poll_by_fn:
                    vt_by_poll.setdefault(vt["methods"][0], vt)
                    vt_by_va[vt["va"]] = vt
        except Exception:
            pass
    fn_refs = {}

    def refs_of(fn_lo, fn_hi):
        if fn_lo not in fn_refs:
            fn_refs[fn_lo] = {c for i in b.sweep(fn_lo, fn_hi) for c in [_const_of(b, i)] if c in vt_by_va}
        return fn_refs[fn_lo]

    out, ids = [], {}
    for n, mm in enumerate(machines):
        ids[id(mm)] = f"m{n}"
    site_owner = {s["va"]: mm for mm in machines for s in mm["sites"]}
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
                    if inner["dyn_future_poll"]:
                        cand = [vt_by_va[r] for r in refs_of(mm["function"], mm["function_end"])]
                        if len(cand) == 1:
                            pm = poll_by_fn.get(cand[0]["methods"][0])
                            inner["vtable"] = cand[0]["va"]
                            if pm is not None:
                                inner["machine"] = to = ids[id(pm)]
                st["inner"] = inner
                st["pending_writes"] = sp["pending_writes"]
                nesting.append({"from": mid, "state": v, "via": inner["kind"],
                                "to": to or (f"fn:{inner['target']:#x}" if inner.get("target") is not None
                                             else inner.get("name"))})
            states[str(v)] = st
        root = mm["root"]
        base = {"arg0": "self" if mm["role"] == "poll" else "arg0", "sp": "stack",
                "reg": "register"}.get(root, f"[{root}]" if root.startswith("*") else
                                       (root if root.startswith("arg") else "unknown"))
        if mm["role"] == "poll" and root == "arg1":
            base = "self"
        vt = vt_by_poll.get(mm["function"]) if mm["role"] == "poll" else None
        loc = _location(b, mm["location_va"]) if mm["location_va"] else None
        out.append({
            "id": mid, "function": mm["function"], "role": mm["role"],
            "self_register": b.args[int(root[3:])] if mm["role"] == "poll" else None,
            "state_field": {"base": base, "root": root, "offset": mm["offset"], "width": mm["width"],
                            "register": mm["register"]},
            "dispatch": [{"va": s["va"], "kind": s["kind"], "table": s["table"],
                          "targets": {str(k): t for k, t in sorted(s["targets"].items())}}
                         for s in mm["sites"]],
            "states": states, "suspend_points": len(mm["suspend"]),
            "state_writes": [{"va": a, "value": val} for a, val in mm["writes"]],
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
                desc = {"direct": lambda: f"polls fn {i.get('target', 0):#x}",
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
            self.arm, self.pe, self.x32, self.ptr = arm, False, False, 8
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
    assert m["consistent"] and [v for _a, v in m["writes"]] == [3, 4, 1]

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
    assert m["consistent"] and [v for _a, v in m["writes"]] == [3]
    assert load == m["sites"][0]["va"]
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
