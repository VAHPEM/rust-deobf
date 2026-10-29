#!/usr/bin/env python3
"""recover_idioms.py - recover Rust source idioms from (stripped) binaries: format macros, safety
checks, drop glue, and enum-like (Option/Result) returns.

A decompiled Rust function is long mostly because of code the programmer never wrote: bounds and
overflow checks that branch to a panic, `drop_in_place` glue and `__rust_dealloc` calls, and the
`core::fmt::Arguments` plumbing behind every `println!`/`format!`/`panic!`. Oxidizer (IEEE S&P 2026,
"Toward Concise and High-fidelity Rust Decompilation") shows that marking or folding these idioms
makes the output read like source again. This tier recovers the cheap, high-value part of that for
STRIPPED binaries, statically (nothing is executed), and reports it as observations:

  1. fmt macro sites -- a `core::fmt::Arguments` handed to `_print` / `_eprint` / `format` /
     `panic_fmt` / `write_fmt`. The literal text comes back even with no symbols:
       * newer rustc (1.97 measured; 1.91 still uses pieces): the compact *template* encoding
         (`template: *const u8` -> b"\\x06hello \\xc0\\x00", `args: &[Argument]` or
         `len << 1 | 1` for a plain `&'static str`); decoded
         byte-for-byte, including `{:>8.3}`-style options (the formatting *trait* -- `?`, `x` -- is
         chosen by the argument's formatter fn, not the template, so it is shown as `{}`);
       * older rustc: the `pieces: &[&str]` array (+ args / fmt slices) the struct points at.
     Reported as `println!("hello {} you are {}")`, `format!(...)`, `panic!(...)`, or
     `format_args!(...)` when the consuming function is not identified.
  2. panic / safety-check paths -- calls to bounds-check, slice/str index, unwrap/expect, arithmetic
     overflow, capacity-overflow and alloc-error helpers and to `panic_fmt`, with the panic kind, the
     `core::panic::Location` (file:line:col) passed at the call (recover_rust_meta's record layout,
     read relocation-aware), and the conditional branch that guards the cold block.
  3. drop / deallocation -- calls to `__rust_dealloc` and `drop_in_place` glue.
  4. enum-like returns -- callers that test a returned tag (rax/x0) and then use the payload
     (rdx/x1), and sret functions that store different small constants (or a capacity niche) to
     the same field of the return slot on different paths: "returns Option/Result?" + confidence.
     Heuristic and labelled as such: it never asserts a source type. Not reported on i386, where
     edx:eax also carries every 64-bit integer.

How the helpers are identified in a stripped binary (each record says which, `via`):
  * `symbol`   -- the binary's own symbols (unstripped / partially stripped builds);
  * `libfuncs` -- recover_libfuncs byte signatures (+ its thunk / drop-glue propagation);
  * `anchor`   -- structure that survives stripping: a helper is the small function whose own
                  fmt/str site carries core's fixed panic message ("index out of bounds: the len is
                  ", "called `Option::unwrap()` on a `None` value", "attempt to add with overflow",
                  ...); `_print`/`_eprint` reference "stdout"/"stderr"; `__rust_dealloc` is the thin
                  wrapper around `free`/`HeapFree`; `panic_fmt` is what those helpers call;
  * `shape`    -- a call that passes a valid `Location` to a function that never returns.

    python3 scripts/recover_idioms.py <binary>              # human summary
    python3 scripts/recover_idioms.py <binary> --json       # full result dict
    python3 scripts/recover_idioms.py --eval <unstripped> [<stripped>]   # precision/recall vs symbols
    python3 scripts/recover_idioms.py --selftest

x86-64 (SysV + Win64), AArch64 and 32-bit x86; ELF, PE (all addresses are RVAs) and Mach-O. A
light per-function forward dataflow (registers + stack slots, joined at branch targets) tracks
constants, rodata addresses (PIE relocations through recover_emulate.Image's patches) and stack
addresses into each call's argument registers / stack arguments. `ghidra_annotate.py` turns the
`--json` output into comments, bookmarks and default-name renames (observational only).
"""
from __future__ import annotations

import json
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

# ------------------------------------------------------------------------------------------------
# kind tables (compact, neutral). Names are matched against demangled symbol / libfuncs labels.
# ------------------------------------------------------------------------------------------------
PANIC_NAME_KINDS = [
    (re.compile(r"panic_bounds_check"), "bounds_check"),
    (re.compile(r"slice_(?:start_|end_)?index_(?:len_|order_|overflow_)?fail|slice_index_fail|"
                r"slice_end_index_overflow_fail|slice_start_index_overflow_fail"), "slice_index"),
    (re.compile(r"str::slice_error_fail|slice_error_fail|str_index_overflow_fail"), "str_index"),
    (re.compile(r"option::unwrap_failed"), "unwrap_none"),
    (re.compile(r"option::expect_failed"), "expect"),
    (re.compile(r"result::unwrap_failed"), "unwrap_err"),
    (re.compile(r"panic_const_(?:div_by_zero|rem_by_zero)"), "div_by_zero"),
    (re.compile(r"panic_const_\w*overflow|panic_const"), "overflow"),
    (re.compile(r"capacity_overflow"), "capacity_overflow"),
    (re.compile(r"handle_alloc_error|raw_vec::handle_error|alloc_error_handler"), "alloc_error"),
    (re.compile(r"assert_failed"), "assert"),
    (re.compile(r"panic_nounwind|panic_in_cleanup|panic_cannot_unwind"), "panic_nounwind"),
    (re.compile(r"panicking::panic_fmt|panicking::panic_display|panicking::panic_str|"
                r"panicking::panic(?:_explicit)?$|panicking::panic::|begin_panic|"
                r"unreachable_display|panicking::panic_fmt"), "panic"),
]
SINK_NAME_KINDS = [
    (re.compile(r"(?:^|::)_eprint$|stdio::_eprint|\b_eprint\b"), "eprint"),
    (re.compile(r"(?:^|::)_print$|stdio::_print|\b_print\b"), "print"),
    (re.compile(r"fmt::format::format_inner|alloc::fmt::format\b|fmt::format$"), "format"),
    (re.compile(r"panicking::panic_fmt|panic_nounwind_fmt"), "panic"),
    (re.compile(r"write_fmt|core::fmt::write$"), "write"),
]
DROP_NAME = re.compile(r"drop_in_place|drop_glue|ptr::drop\b")
DEALLOC_NAME = re.compile(r"__rust_dealloc|__rdl_dealloc|__rg_dealloc|alloc::alloc::dealloc\b")

# core's fixed panic messages -> kind. Matched as a PREFIX of a site's rendered text (a template's
# first literal, or a `&'static str` argument). Compact by design.
CORE_MESSAGES = [
    ("index out of bounds: the len is ", "bounds_check"),
    ("range start index ", "slice_index"),
    ("range end index ", "slice_index"),
    ("slice index starts at ", "slice_index"),
    ("byte index ", "str_index"),
    ("start byte index ", "str_index"),
    ("end byte index ", "str_index"),
    ("byte range starts at ", "str_index"),
    ("begin <= end (", "str_index"),
    ("called `Option::unwrap()` on a `None` value", "unwrap_none"),
    ("called `Result::unwrap()` on an `Err` value", "unwrap_err"),
    ("called `Result::unwrap_err()` on an `Ok` value", "unwrap_err"),
    ("attempt to divide by zero", "div_by_zero"),
    ("attempt to calculate the remainder with a divisor of zero", "div_by_zero"),
    ("attempt to ", "overflow"),               # "... add/subtract/multiply/negate/shift ... overflow"
    ("capacity overflow", "capacity_overflow"),
    ("memory allocation of ", "alloc_error"),
    ("assertion `left ", "assert"),
    ("assertion failed: ", "assert"),
    ("internal error: entered unreachable code", "unreachable"),
    ("panic in a destructor during cleanup", "panic_nounwind"),
    ("panic in a function that cannot unwind", "panic_nounwind"),
    ("not implemented", "unimplemented"),
    ("not yet implemented", "todo"),
]
_KIND_LABEL = {
    "bounds_check": "index out of bounds", "slice_index": "slice index out of range",
    "str_index": "str index/char boundary", "unwrap_none": "Option::unwrap on None",
    "expect": "expect(msg) / panic with a message", "unwrap_err": "Result::unwrap/expect on Err",
    "div_by_zero": "division by zero", "overflow": "arithmetic overflow",
    "capacity_overflow": "capacity overflow", "alloc_error": "allocation failure",
    "assert": "assertion", "panic_nounwind": "panic (nounwind)", "panic": "panic!",
    "unreachable": "unreachable!", "unimplemented": "unimplemented!", "todo": "todo!",
    "panic_unidentified": "panic (helper not identified)",
}
# kinds that mark a compiler-inserted safety check (vs. an explicit panic!/assert! by the author)
SAFETY_KINDS = {"bounds_check", "slice_index", "str_index", "div_by_zero", "overflow",
                "capacity_overflow", "alloc_error", "unwrap_none", "expect", "unwrap_err"}
_MACRO = {"print": "print!", "eprint": "eprint!", "format": "format!", "panic": "panic!",
          "write": "write!", None: "format_args!"}

_UNWIND_RESUME = re.compile(r"_Unwind_Resume|__cxa_end_cleanup|_Unwind_RaiseException")
TEMPLATE_MAX = 4096          # bytes of a template / piece we are willing to read
MAX_ARGS = 64                # placeholders / pieces beyond this are not a real format string
HELPER_MAX = 0x180           # a panic helper / dealloc wrapper is a small function
DROP_GLUE_MAX = 0x600        # inferred drop glue is at most this large


# ------------------------------------------------------------------------------------------------
# fmt::Arguments decoding (pure: `read(va, n) -> bytes`, `ptr_at(va) -> int|None`)
# ------------------------------------------------------------------------------------------------
_OK_CTRL = {9, 10, 13, 27}


def _plausible_text(s: str) -> bool:
    return all(ord(c) >= 32 or ord(c) in _OK_CTRL for c in s)


def _esc(s: str) -> str:
    """A literal as it would appear inside a Rust format string."""
    s = s.replace("\\", "\\\\").replace('"', '\\"').replace("{", "{{").replace("}", "}}")
    return s.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t").replace("\x1b", "\\x1b")


def _render_spec(flags, width, prec, w_ind, p_ind, arg_idx):
    """`{...}` for a template placeholder. The trait (Display/Debug/hex) is not in the template."""
    spec = ""
    if flags is not None:
        fill = chr(flags & 0x1FFFFF) if (flags & 0x1FFFFF) < 0x110000 else " "
        align = (flags >> 29) & 3
        if align != 3:
            spec += ("" if fill == " " else fill) + "<>^"[align]
        if flags & (1 << 21):
            spec += "+"
        if flags & (1 << 22):
            spec += "-"
        if flags & (1 << 23):
            spec += "#"
        if flags & (1 << 24):
            spec += "0"
    if width is not None:
        spec += ("%d$" % width) if w_ind else str(width)
    if prec is not None:
        spec += "." + (("%d$" % prec) if p_ind else str(prec))
    if flags is not None and flags & (3 << 25):
        spec += "x?" if flags & (1 << 25) else "X?"
    head = "" if arg_idx is None else str(arg_idx)
    return "{" + head + (":" + spec if spec else "") + "}"


def decode_template(read, va):
    """Decode a compact fmt template (newer rustc, e.g. 1.97) at `va`.

    Grammar: len<0x80 + bytes (literal) | 0x80 + u16 len + bytes (long literal) | 0b11xxxxxx
    placeholder [+ u32 flags][+ u16 width][+ u16 precision][+ u16 arg_index] | 0x00 end.
    Returns {"text", "literals", "placeholders", "nargs", "size"} or None when the bytes are not a
    complete, well-formed template of plausible UTF-8 text."""
    buf = read(va, TEMPLATE_MAX)
    if not buf:
        return None
    i, out, lits, nph, nxt, max_arg = 0, [], [], 0, 0, -1
    while True:
        if i >= len(buf):
            return None                          # unterminated within the window
        n = buf[i]
        i += 1
        if n == 0:
            break
        if n < 0x80 or n == 0x80:
            if n == 0x80:
                if i + 2 > len(buf):
                    return None
                n = buf[i] | (buf[i + 1] << 8)
                i += 2
                if n < 0x80:                     # the long form is only used for long pieces
                    return None
            raw = buf[i:i + n]
            if len(raw) != n:
                return None
            i += n
            try:
                s = raw.decode("utf-8")
            except UnicodeDecodeError:
                return None
            if not _plausible_text(s):
                return None
            lits.append(s)
            out.append(_esc(s))
        elif n >= 0xC0:
            b = n & 0x3F
            need = (4 if b & 1 else 0) + (2 if b & 2 else 0) + (2 if b & 4 else 0) + (2 if b & 8 else 0)
            if i + need > len(buf):
                return None
            flags = width = prec = idx = None
            if b & 1:
                flags = struct.unpack_from("<I", buf, i)[0]
                i += 4
                if flags >> 31:                  # bit 31 is always zero
                    return None
            if b & 2:
                width = struct.unpack_from("<H", buf, i)[0]
                i += 2
            if b & 4:
                prec = struct.unpack_from("<H", buf, i)[0]
                i += 2
            if b & 8:
                idx = struct.unpack_from("<H", buf, i)[0]
                i += 2
            if (b & 0x10 and width is None) or (b & 0x20 and prec is None):
                return None                      # "indirect" without the field it qualifies
            use = idx if idx is not None else nxt
            if idx is None:
                nxt += 1
            max_arg = max(max_arg, use, width if b & 0x10 else -1, prec if b & 0x20 else -1)
            nph += 1
            if nph > MAX_ARGS or max_arg >= MAX_ARGS:
                return None
            out.append(_render_spec(flags, width, prec, b & 0x10, b & 0x20, idx))
        else:
            return None                          # 0x81..0xBF: not a valid tag
    if not out:
        return None
    return {"text": "".join(out), "literals": lits, "placeholders": nph, "nargs": max_arg + 1,
            "size": i}


def decode_str(read, va, n):
    """A `&'static str` of length n at va, or None (n bounded, UTF-8, plausible text)."""
    if not 0 < n <= TEMPLATE_MAX:
        return None
    raw = read(va, n)
    if len(raw) != n:
        return None
    try:
        s = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return s if _plausible_text(s) else None


def decode_pieces(read, ptr_at, pieces_va, npieces, nargs, psize):
    """Older rustc: `pieces: &[&'static str]` (+ `args` count). Rebuild "p0{}p1{}..."."""
    if not 0 < npieces <= MAX_ARGS or not 0 <= nargs <= MAX_ARGS:
        return None
    if not (npieces == nargs or npieces == nargs + 1 or (nargs == 0 and npieces == 1)):
        return None
    lits = []
    for k in range(npieces):
        p = ptr_at(pieces_va + 2 * psize * k)
        raw_len = read(pieces_va + 2 * psize * k + psize, psize)
        if p is None or len(raw_len) != psize:
            return None
        ln = int.from_bytes(raw_len, "little")
        if ln == 0:
            s = ""
        else:
            s = decode_str(read, p, ln)
            if s is None:
                return None
        lits.append(s)
    out = []
    for k, s in enumerate(lits):
        out.append(_esc(s))
        if k < nargs:
            out.append("{}")
    return {"text": "".join(out), "literals": lits, "placeholders": nargs, "nargs": nargs,
            "size": npieces}


def read_location(read, ptr_at, va, psize):
    """A `core::panic::Location` {file: &str, line: u32, col: u32} at va -> (file, line, col)."""
    p = ptr_at(va)
    raw = read(va + psize, psize + 8)
    if p is None or len(raw) != psize + 8:
        return None
    ln = int.from_bytes(raw[:psize], "little")
    line, col = struct.unpack_from("<II", raw, psize)
    if not (0 < ln < 4096 and 0 < line < 2_000_000 and 0 < col < 100_000):
        return None
    f = decode_str(read, p, ln)
    if f is None or not f.endswith(".rs"):
        return None
    return f, line, col


def message_kind(text):
    """Kind of a core panic message (prefix match on the rendered text), else None."""
    if not text:
        return None
    for pre, kind in CORE_MESSAGES:
        if text.startswith(pre):
            if kind == "overflow" and "overflow" not in text:
                continue
            return kind
    return None


def name_kind(name, table):
    if not name:
        return None
    for rx, kind in table:
        if rx.search(name):
            return kind
    return None


# ------------------------------------------------------------------------------------------------
# program model
# ------------------------------------------------------------------------------------------------
class Prog:
    """What the dataflow needs from a binary. Built from recover_emulate.Image (`from_path`) or by
    hand in the selftest. All addresses are in the toolkit's terms (PE: RVAs)."""

    def __init__(self, arch, code, text_va, funcs, read, ptr_at, *, abi="sysv", psize=8,
                 imports=None, names=None, executable=None, fmt="ELF", stub=None, norm=None):
        self.arch, self.code, self.text_va, self.funcs = arch, code, text_va, funcs
        self.text_end = text_va + len(code)
        self.read, self.ptr_at, self.abi, self.psize = read, ptr_at, abi, psize
        self.imports = imports or {}             # address (trampoline / slot value) -> import name
        self.names = names or {}                 # function start -> (name, via)
        self.executable = executable or (lambda va: self.text_va <= va < self.text_end)
        self.fmt = fmt
        self.stub = stub or (lambda va: None)    # PLT/IAT stub at va -> import name
        self.norm = norm or (lambda v: v)        # absolute VA -> toolkit address (PE: RVA)

    @classmethod
    def from_path(cls, path):
        import recover_emulate as E
        img = E.Image(path)
        pe = img.pe
        ib = img.imagebase if pe else 0
        arch = "aarch64" if img.arm else ("x86" if img.x32 else "x86_64")
        psize = img.ptr
        span_lo, span_hi = img.span

        def norm(v):
            if v is None:
                return None
            if pe and v >= ib and span_lo <= v < span_hi:
                return v - ib
            return v

        def read(va, n):
            if va is None or n <= 0:
                return b""
            return img.read_any(va, n)

        def ptr_at(va):
            if va is None:
                return None
            v = img.patches.get(va)
            if v is not None:
                return v & ((1 << (8 * psize)) - 1)
            raw = img.read_any(va, psize)
            if len(raw) != psize:
                return None
            return norm(int.from_bytes(raw, "little"))

        imports = {E.TRAMP + 16 * i: nm for i, nm in enumerate(img.tramp)}
        funcs = [a for a, _ in img.functions()]   # (also names static C-runtime fns: img.named)
        if img.x32:
            # i386 PIC `call next; pop ebx`: the call "target" is the next instruction, not a function
            code, base = img.code, img.text_va
            funcs = [a for a in funcs if not (a - base >= 5 and code[a - base - 5:a - base] == b"\xe8\0\0\0\0")]
        func_end = {}
        if pe:
            # .pdata bounds every function that has unwind info; the bytes after its end up to the
            # next start are a function without one (leaf / tail-call-only): analyze them as such
            # instead of letting the previous range swallow them
            try:
                for begin, size in E.pdata_ranges(img.binary, img.code, img.text_va):
                    func_end[begin] = begin + size
                fs = set(funcs)
                funcs = sorted(fs | {e for e in func_end.values() if img.text_va <= e < img.text_end})
            except Exception:
                func_end = {}
        names = {}
        for va, nm in img.function_symbols():
            if isinstance(nm, bytes):
                nm = nm.decode("latin-1")
            if not nm or nm.startswith("$"):
                continue
            names.setdefault(va, (_readable(nm), "symbol"))
        for va, nm in img.named.items():           # C-runtime functions named by signature
            names.setdefault(va, (nm, "libfuncs"))
        cache = {}

        def stub(va):
            try:
                import recover_cfg
                slot = recover_cfg._stub_import(img, va, cache)
            except Exception:
                return None
            if slot is None:
                return None
            v = ptr_at(slot)
            return imports.get(v)

        abi = "aarch64" if img.arm else ("i386" if img.x32 else ("win64" if pe else "sysv"))
        p = cls(arch, img.code, img.text_va, funcs, read, ptr_at, abi=abi, psize=psize,
                imports=imports, names=names, executable=img.executable, fmt=img.fmt, stub=stub,
                norm=norm)
        p.image = img
        p.func_end = func_end
        return p


def _v0_label(sym):
    """'a::b::c' for a Rust v0 symbol: every identifier in order, minus a trailing instantiating
    crate root (the `C`-introduced identifier v0 appends). Generic arguments are flattened in,
    which is fine for keyword matching. None when not v0."""
    if not sym.startswith("_R"):
        return None
    s = sym[2:]
    i, n, toks, root, guard = 0, len(s), [], False, 0
    while i < n and guard < 4000:
        guard += 1
        c = s[i]
        if c == "C":                                   # crate root: next identifier is a crate
            root = True
            i += 1
            continue
        if c == "B":                                   # backref B<base62>_
            j = s.find("_", i + 1)
            i = n if j < 0 else j + 1
            continue
        if c == "s":                                   # disambiguator s<base62>_
            j = s.find("_", i + 1)
            if j > 0 and all(ch.isalnum() for ch in s[i + 1:j]):
                i = j + 1
                continue
        if c == "u" and i + 1 < n and s[i + 1].isdigit():
            i += 1
            c = s[i]
        if c.isdigit():
            j = i
            while j < n and s[j].isdigit():
                j += 1
            ln = int(s[i:j])
            i = j
            if i < n and s[i] == "_":
                i += 1
            name = s[i:i + ln]
            i += ln
            if name:
                toks.append((name, root))
            root = False
            continue
        root = False
        i += 1
    if len(toks) >= 2 and toks[-1][1]:
        toks = toks[:-1]
    return "::".join(t for t, _r in toks) if toks else None


def _readable(sym):
    if sym.startswith("__R") or sym.startswith("__Z"):
        sym = sym[1:]                            # Mach-O leading underscore
    lab = _v0_label(sym)
    if lab:
        return lab
    try:
        import recover_rust_meta as M
        return M.demangle(sym)
    except Exception:
        return sym


# ------------------------------------------------------------------------------------------------
# ABI tables
# ------------------------------------------------------------------------------------------------
_X86_FAM = {}
for _full, _subs in {"rax": ("eax", "ax", "al", "ah"), "rbx": ("ebx", "bx", "bl", "bh"),
                     "rcx": ("ecx", "cx", "cl", "ch"), "rdx": ("edx", "dx", "dl", "dh"),
                     "rsi": ("esi", "si", "sil"), "rdi": ("edi", "di", "dil"),
                     "rbp": ("ebp", "bp", "bpl"), "rsp": ("esp", "sp", "spl")}.items():
    _X86_FAM[_full] = (_full, 8)
    for _s in _subs:
        _X86_FAM[_s] = (_full, 4 if _s[0] == "e" else (2 if len(_s) == 2 and _s[1] in "xip" else 1))
for _k in range(8, 16):
    _X86_FAM["r%d" % _k] = ("r%d" % _k, 8)
    _X86_FAM["r%dd" % _k] = ("r%d" % _k, 4)
    _X86_FAM["r%dw" % _k] = ("r%d" % _k, 2)
    _X86_FAM["r%db" % _k] = ("r%d" % _k, 1)

ABI = {
    "sysv": {"args": ["rdi", "rsi", "rdx", "rcx", "r8", "r9"], "sret": "rdi", "ret": ("rax", "rdx"),
             "clobber": ["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"],
             "stack_args": 0},
    "win64": {"args": ["rcx", "rdx", "r8", "r9"], "sret": "rcx", "ret": ("rax", "rdx"),
              "clobber": ["rax", "rcx", "rdx", "r8", "r9", "r10", "r11"], "stack_args": 4,
              "stack_base": 0x20},
    "i386": {"args": [], "sret": None, "ret": ("rax", "rdx"), "clobber": ["rax", "rcx", "rdx"],
             "stack_args": 6, "stack_base": 0, "fast": ["rcx", "rdx"]},
    "aarch64": {"args": ["x%d" % i for i in range(8)], "sret": "x8", "ret": ("x0", "x1"),
                "clobber": ["x%d" % i for i in range(19)] + ["x30"], "stack_args": 0},
}


def _a64(name):
    if name in ("fp",):
        return "x29"
    if name in ("lr",):
        return "x30"
    if name in ("wsp",):
        return "sp"
    if name and name[0] == "w" and name[1:].isdigit():
        return "x" + name[1:]
    return name


# ------------------------------------------------------------------------------------------------
# the per-function forward dataflow
# ------------------------------------------------------------------------------------------------
# abstract values: int (a constant / address), ("s", off) (entry stack pointer + off),
# ("in", reg) (a register's value at function entry), None (unknown)
def _add(v, k):
    if isinstance(v, int):
        return (v + k) & 0xFFFFFFFFFFFFFFFF
    if isinstance(v, tuple) and v[0] == "s":
        return ("s", v[1] + k)
    if isinstance(v, tuple) and v[0] == "in" and len(v) == 2:
        return ("in", v[1], k)
    if isinstance(v, tuple) and v[0] == "in":
        return ("in", v[1], v[2] + k)
    return None


def _base_off(v):
    """('in', reg[, off]) -> (reg, off)"""
    if isinstance(v, tuple) and v[0] == "in":
        return v[1], (v[2] if len(v) == 3 else 0)
    return None


class _State:
    __slots__ = ("regs", "slots", "sp")

    def __init__(self, regs=None, slots=None, sp=None):
        self.regs = regs if regs is not None else {}
        self.slots = slots if slots is not None else {}
        self.sp = sp

    def copy(self):
        return _State(dict(self.regs), dict(self.slots), self.sp)

    @staticmethod
    def meet(states):
        states = [s for s in states if s is not None]
        if not states:
            return None
        if len(states) == 1:
            return states[0].copy()
        a = states[0]
        regs = {k: v for k, v in a.regs.items() if all(s.regs.get(k) == v for s in states[1:])}
        slots = {k: v for k, v in a.slots.items() if all(s.slots.get(k) == v for s in states[1:])}
        sp = a.sp if all(s.sp == a.sp for s in states[1:]) else None
        return _State(regs, slots, sp)


class FuncFacts:
    """Everything one pass over a function records."""

    def __init__(self, start, end):
        self.start, self.end = start, end
        self.calls = []          # dicts: site, size, target, imp, args, slots, tail, post
        self.rets = []           # (site, ret0, ret1)
        self.sret_stores = []    # (site, off, value, width)
        self.jcc = []            # (site, target, mnemonic, fallthrough)
        self.blocks = set()      # block start addresses
        self.lea_consts = []     # constants materialised (lea/adr/adrp+add), for body anchors
        self.has_ret = False
        self.has_trap = False    # ud2 / brk / udf reached
        self.first_mn = None
        self.cmp_in = set()      # entry registers compared / tested before being overwritten
        self.has_indirect_jmp = False
        self.tail_targets = set()
        self.back_jumps = []     # (target, state) of jumps to an already-processed address
        self.merged_calls = []   # per-predecessor replays of a call in a tail-merged block
        self.first_tests = []    # registers tested with `test r, 1` near the entry (as_str check)
        self.ninsn = 0           # reachable (non-padding) instructions
        self.eff_end = start     # end of the last such instruction


def _x86_cs(arch):
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
    md = Cs(CS_ARCH_X86, CS_MODE_32 if arch == "x86" else CS_MODE_64)
    md.detail = True
    md.skipdata = True
    return md


def _a64_cs():
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    md.skipdata = True
    return md


_JCC_X86 = re.compile(r"^j(?!mp)")
_VMOV16 = {"movups", "movaps", "movdqu", "movdqa", "vmovups", "vmovaps", "vmovdqu", "vmovdqa"}
_PADDING = {"int3", "nop", "udf", ".byte", "brk", "hlt"}
_PCTHUNK = {b"\x8b\x04\x24\xc3": "rax", b"\x8b\x1c\x24\xc3": "rbx", b"\x8b\x0c\x24\xc3": "rcx",
            b"\x8b\x14\x24\xc3": "rdx", b"\x8b\x34\x24\xc3": "rsi", b"\x8b\x3c\x24\xc3": "rdi",
            b"\x8b\x2c\x24\xc3": "rbp"}


class _Post:
    """Watches the instructions right after a call for `test tag; jcc` + a read of the payload."""
    __slots__ = ("rec", "tag", "pay", "n", "tested", "tested_full", "pay_used", "flags_from_tag",
                 "done")

    def __init__(self, rec, tag, pay):
        self.rec, self.tag, self.pay = rec, {tag}, {pay}
        self.n, self.tested, self.tested_full, self.pay_used = 0, False, False, False
        self.flags_from_tag, self.done = False, False

    def finish(self):
        if not self.done:
            self.done = True
            self.rec["post"] = {"tested": self.tested, "tested_full": self.tested_full,
                                "pay_used": self.pay_used}


def analyze_function(prog, start, end, md):
    """Forward dataflow over [start, end). Returns FuncFacts."""
    F = FuncFacts(start, end)
    abi = ABI[prog.abi]
    arm = prog.arch == "aarch64"
    mask = (1 << (8 * prog.psize)) - 1
    code = prog.code[start - prog.text_va:end - prog.text_va]
    insns = list(md.disasm(code, start))
    if not insns:
        return F
    # block starts = branch targets inside the function
    targets = set()
    for ins in insns:
        t = _branch_target(ins, arm)
        if t is not None and start <= t < end and t != ins.address + ins.size:
            targets.add(t)
    F.blocks = targets | {start}
    pending = {}
    st = _State(sp=("s", 0))
    for r in abi["args"] + ([abi["sret"]] if abi["sret"] else []) + abi.get("fast", []):
        st.regs[r] = ("in", r)
    if prog.abi == "i386":                       # stack args: [esp+4], [esp+8], ...
        for k in range(abi["stack_args"]):
            st.slots[4 * (k + 1)] = ("in", "stk%d" % k)
    if arm:
        st.regs["sp"] = ("s", 0)
    else:
        st.regs["rsp"] = ("s", 0)
    live = True
    last_sp = st.sp
    post = None
    dead = None
    idx_of = {ins.address: i for i, ins in enumerate(insns)}
    replays = []              # (block start, predecessor state): see _replay below
    padded = False
    for idx, ins in enumerate(insns):
        a = ins.address
        if live:
            padded = False
        if a in targets:
            incoming = pending.pop(a, [])
            if live:
                incoming.append(st)
            if len(incoming) >= 2:
                replays.extend((a, s_.copy()) for s_ in incoming)
            # a block reached only by back edges (a rotated loop's head) inherits the state at the
            # jump that skipped over it: loop-invariant values hoisted before the loop survive
            st = _State.meet(incoming) or (dead.copy() if dead is not None else _State(sp=last_sp))
            dead = None
            if arm:
                st.regs.setdefault("sp", st.sp)
            else:
                st.regs.setdefault("rsp", st.sp)
            live = True
            if post is not None:
                post.finish()
                post = None
        elif not live:
            if ins.mnemonic in _PADDING or (not arm and ins.bytes[:2] == b"\x00\x00"):
                padded = True
                continue                          # inter-function / alignment padding
            if padded and a % 16 == 0 and not arm:
                # unreached code after alignment padding is the next function (one without an
                # unwind entry: leaf / tail-call-only functions in a stripped PE), not ours
                break
            st = dead.copy() if dead is not None else _State(sp=last_sp)
            dead = None
            if arm:
                st.regs.setdefault("sp", last_sp)
            else:
                st.regs.setdefault("rsp", last_sp)
            live = True
        if ins.mnemonic == ".byte":             # skipdata
            continue
        F.ninsn += 1
        F.eff_end = a + ins.size
        if F.first_mn is None:
            F.first_mn = ins.mnemonic
        try:
            if arm:
                live, post = _step_a64(prog, F, st, ins, abi, mask, pending, post, idx, insns)
            else:
                live, post = _step_x86(prog, F, st, ins, abi, mask, pending, post, idx, insns)
            if not live:
                m = ins.mnemonic
                dead = st if m in ("jmp", "b") else None
        except Exception:
            # an operand shape we do not model: forget what it writes, keep going
            for r in _written(ins, arm):
                st.regs.pop(r, None)
        sp = st.regs.get("sp" if arm else "rsp")
        st.sp = sp
        if sp is not None:
            last_sp = sp
    if post is not None:
        post.finish()
    # backward jumps into an already-processed block (LLVM tail-merges `lea rsi,[tmpl]; jmp
    # shared_call`) and joins whose predecessors disagree: the meet forgets the per-path argument,
    # so replay each predecessor's own state through the short merged block up to its first call
    replays.extend(F.back_jumps)
    seen = {}
    for c in F.calls:
        seen.setdefault(c["site"], []).append(c["args"])
    for blk, s0 in replays[:_MAX_REPLAYS]:
        rec = _replay(prog, F, insns, idx_of, blk, s0, abi, mask, arm)
        if rec is not None and rec["args"] not in seen.get(rec["site"], []):
            rec["merged"] = True
            seen.setdefault(rec["site"], []).append(rec["args"])
            F.merged_calls.append(rec)      # extra argument views of an existing call site
    return F


_MAX_REPLAYS = 256
_REPLAY_LEN = 16


def _replay(prog, F, insns, idx_of, blk, st, abi, mask, arm):
    """Run one predecessor state through the straight-line code at `blk` to its first call."""
    i = idx_of.get(blk)
    if i is None:
        return None
    G = FuncFacts(F.start, F.end)
    step = _step_a64 if arm else _step_x86
    for ins in insns[i:i + _REPLAY_LEN]:
        if ins.mnemonic == ".byte":
            return None
        try:
            live, _p = step(prog, G, st, ins, abi, mask, {}, None, 99, insns)
        except Exception:
            return None
        if G.calls:
            return G.calls[0]
        if not live or G.jcc:
            return None
    return None


def _branch_target(ins, arm):
    m = ins.mnemonic
    if arm:
        if m in ("b", "bl") or m.startswith("b.") or m in ("cbz", "cbnz", "tbz", "tbnz"):
            op = ins.operands[-1]
            if op.type == 2:                     # IMM
                return op.imm
        return None
    if m.startswith("j") and len(ins.operands) == 1 and ins.operands[0].type == 2:
        return ins.operands[0].imm
    return None


def _written(ins, arm):
    try:
        _r, w = ins.regs_access()
    except Exception:
        return []
    out = []
    for r in w:
        n = ins.reg_name(r)
        if arm:
            out.append(_a64(n))
        else:
            fam = _X86_FAM.get(n)
            out.append(fam[0] if fam else n)
    return out


def _read_regs(ins, arm):
    try:
        r, _w = ins.regs_access()
    except Exception:
        return []
    out = []
    for x in r:
        n = ins.reg_name(x)
        if arm:
            out.append(_a64(n))
        else:
            fam = _X86_FAM.get(n)
            out.append(fam[0] if fam else n)
    return out


def _resolve_target(prog, v):
    """A call target value -> (address or None, import name or None)."""
    if not isinstance(v, int):
        return None, None
    if v in prog.imports:
        return None, prog.imports[v]
    nm = prog.stub(v)               # a PLT / `.plt.sec` / IAT jump stub (cached; inside .text on PE)
    return v, (nm or None)


def _record_call(prog, F, st, ins, abi, target_val, tail=False):
    tgt, imp = _resolve_target(prog, target_val)
    args = [st.regs.get(r) for r in abi["args"]]
    if prog.abi == "win64":
        sp = st.regs.get("rsp")
        for k in range(abi["stack_args"]):
            args.append(st.slots.get(sp[1] + abi["stack_base"] + 8 * k)
                        if isinstance(sp, tuple) else None)
    elif prog.abi == "i386":
        sp = st.regs.get("rsp")
        # a tail jump sees its own return address at [esp]: its stack args start one word up
        sb = 4 if tail else 0
        for k in range(abi["stack_args"]):
            args.append(st.slots.get(sp[1] + sb + 4 * k) if isinstance(sp, tuple) else None)
        args += [st.regs.get(r) for r in abi["fast"]]
    rec = {"site": ins.address, "size": ins.size, "target": tgt, "imp": imp, "args": args,
           "slots": dict(st.slots), "tail": tail, "sret": st.regs.get(abi["sret"]) if abi["sret"] else None,
           "post": None}
    F.calls.append(rec)
    if tail and isinstance(tgt, int):
        F.tail_targets.add(tgt)
    return rec


def _clobber(st, abi, rec=None):
    for r in abi["clobber"]:
        st.regs.pop(r, None)
    # a stack buffer passed by pointer belongs to the callee now (an sret slot it fills, an
    # Arguments struct it consumes): forget its contents so a later call that reuses the same
    # frame offset is not decoded with stale words
    if rec is not None:
        for v in rec["args"]:
            if isinstance(v, tuple) and v[0] == "s":
                for k in [k for k in st.slots if v[1] <= k < v[1] + 0x40]:
                    del st.slots[k]


def _x86_mem_addr(prog, st, ins, op):
    from capstone.x86 import X86_REG_RIP, X86_REG_EIP
    m = op.mem
    if m.segment != 0:
        return None
    if m.base in (X86_REG_RIP, X86_REG_EIP):
        if m.index:
            return None
        return (ins.address + ins.size + m.disp) & 0xFFFFFFFFFFFFFFFF
    if m.index:
        return None
    if m.base == 0:
        return prog.norm(m.disp & 0xFFFFFFFF) if prog.arch == "x86" else m.disp & 0xFFFFFFFFFFFFFFFF
    base = _X86_FAM.get(ins.reg_name(m.base), (None,))[0]
    bv = st.regs.get(base)
    if bv is None:
        return None
    if isinstance(bv, int) and prog.arch == "x86":
        return prog.norm((bv + m.disp) & 0xFFFFFFFF)
    return _add(bv, m.disp)


def _load(prog, st, addr, width):
    """Value loaded from an abstract address."""
    if isinstance(addr, tuple) and addr[0] == "s":
        v = st.slots.get(addr[1])
        if isinstance(v, tuple) and v[0] == "n":
            return v[2] if v[1] == width else None
        if v is not None and width == prog.psize:
            return v
        if isinstance(v, int) and width < prog.psize:
            return v & ((1 << (8 * width)) - 1)
        return None
    if isinstance(addr, int) and width == prog.psize:
        return prog.ptr_at(addr)
    return None


def _store(prog, F, st, addr, val, width, site):
    if isinstance(addr, tuple) and addr[0] == "s":
        off = addr[1]
        # invalidate overlapping slots
        for k in [k for k in st.slots if k < off + width and off < k + prog.psize]:
            del st.slots[k]
        if width == prog.psize:
            st.slots[off] = (val & ((1 << (8 * width)) - 1)) if isinstance(val, int) else val
        elif isinstance(val, int):
            # a sub-word constant: only a load of the same width may read it back as a value
            st.slots[off] = ("n", width, val & ((1 << (8 * width)) - 1))
        return
    bo = _base_off(addr)
    if bo is not None:
        # constant stores (tags / niches) and, as None, non-constant ones (payloads)
        F.sret_stores.append((site, bo[0], bo[1], val if isinstance(val, int) else None, width))


def _forget_mem_writes(prog, st, ins, addr_of, mem_type):
    """An instruction we do not model may write memory: drop the stack slots it could cover (a
    stale slot would otherwise be decoded as a later call's argument)."""
    from capstone import CS_AC_WRITE
    for op in ins.operands:
        if op.type != mem_type:
            continue
        try:
            if not (op.access & CS_AC_WRITE):
                continue
        except Exception:
            pass
        a = addr_of(op)
        size = max(getattr(op, "size", 0) or 0, 16)
        if isinstance(a, tuple) and a[0] == "s":
            for k in [k for k in st.slots if a[1] - prog.psize < k < a[1] + size]:
                del st.slots[k]


def _step_x86(prog, F, st, ins, abi, mask, pending, post, idx, insns):
    from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM
    m = ins.mnemonic
    ops = ins.operands
    live = True
    regs = st.regs
    psz = prog.psize

    # ---- post-call watch (enum-like returns) ----
    if post is not None and not post.done:
        post.n += 1
        rd = set(_read_regs(ins, False))
        wr = set(_written(ins, False))
        if m in ("test", "cmp", "bt", "and", "or") and rd & post.tag:
            post.flags_from_tag = True
            if m == "test" and len(ops) == 2 and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_REG \
                    and ops[0].reg == ops[1].reg and ops[0].size == psz:
                post.tested_full = True
        elif (_JCC_X86.match(m) or m.startswith("set") or m.startswith("cmov")) and post.flags_from_tag:
            post.tested = True
        elif m in ("mov", "movzx", "movsx", "movsxd") and len(ops) == 2 and ops[0].type == X86_OP_REG:
            src = _read_regs(ins, False)
            dst = _X86_FAM.get(ins.reg_name(ops[0].reg), (None,))[0]
            if ops[1].type == X86_OP_REG:
                s = _X86_FAM.get(ins.reg_name(ops[1].reg), (None,))[0]
                if s in post.pay:
                    post.pay_used = True
                    post.pay.add(dst)
                elif s in post.tag:
                    post.tag.add(dst)
                    post.pay.discard(dst)
                else:
                    post.tag.discard(dst)
                    post.pay.discard(dst)
            else:
                if set(src) & post.pay:
                    post.pay_used = True
                post.tag.discard(dst)
                post.pay.discard(dst)
        else:
            if rd & post.pay and not (m == "xor" and len(ops) == 2 and ops[0].type == X86_OP_REG
                                      and ops[1].type == X86_OP_REG and ops[0].reg == ops[1].reg):
                post.pay_used = True
            post.tag -= wr
            post.pay -= wr
        if post.n >= 12 or m in ("call", "ret", "jmp") or (not post.tag and not post.pay):
            post.finish()
            post = None

    def reg_of(op):
        n = ins.reg_name(op.reg)
        return _X86_FAM.get(n, (n, 8))

    if m in ("nop", "endbr64", "endbr32", "int3", "hlt") or m.startswith("prefetch"):
        if m in ("int3", "hlt"):
            live = False
        return live, post
    if m == "ud2":
        F.has_trap = True
        return False, post

    if m in ("call", "jmp"):
        tv = None
        op = ops[0] if ops else None
        if op is not None and op.type == X86_OP_IMM:
            tv = op.imm & mask
            if m == "call" and tv == ins.address + ins.size:      # i386 `call next; pop reg`
                sp = regs.get("rsp")
                if isinstance(sp, tuple):
                    sp = ("s", sp[1] - psz)
                    regs["rsp"] = sp
                    st.slots[sp[1]] = tv
                return True, post
            if m == "call" and prog.arch == "x86":
                hit = _PCTHUNK.get(prog.read(tv, 4))
                if hit:                                         # __x86.get_pc_thunk.<reg>
                    regs[hit] = (ins.address + ins.size) & mask
                    return True, post
        elif op is not None and op.type == X86_OP_MEM:
            a = _x86_mem_addr(prog, st, ins, op)
            if isinstance(a, int):
                tv = prog.ptr_at(a)
                if tv is not None and tv not in prog.imports and prog.arch == "x86":
                    tv = prog.norm(tv)
        elif op is not None and op.type == X86_OP_REG:
            tv = regs.get(reg_of(op)[0])
        if m == "jmp":
            if op is not None and op.type == X86_OP_IMM and F.start <= tv < F.end:
                if tv <= ins.address:
                    F.back_jumps.append((tv, st.copy()))
                pending.setdefault(tv, []).append(st.copy())
                return False, post
            if op is not None and op.type != X86_OP_IMM and tv is None:
                F.has_indirect_jmp = True
                return False, post
            _record_call(prog, F, st, ins, abi, tv, tail=True)
            return False, post
        rec = _record_call(prog, F, st, ins, abi, tv)
        if post is not None:
            post.finish()
        post = _Post(rec, abi["ret"][0], abi["ret"][1])
        _clobber(st, abi, rec)
        return True, post

    if m in ("ret", "retf"):
        F.has_ret = True
        F.rets.append((ins.address, regs.get(abi["ret"][0]), regs.get(abi["ret"][1])))
        return False, post

    if _JCC_X86.match(m):
        t = _branch_target(ins, False)
        if t is not None:
            F.jcc.append((ins.address, t, m, ins.address + ins.size))
            if F.start <= t < F.end:
                pending.setdefault(t, []).append(st.copy())
            elif prog.executable(t):
                # a conditional tail call (`jne other_fn`): drop glue does this a lot
                _record_call(prog, F, st, ins, abi, t, tail=True)
        return True, post

    # ---- data movement ----
    if m in ("mov", "movabs") and len(ops) == 2:
        d, s = ops
        if d.type == X86_OP_REG:
            dr, dw = reg_of(d)
            if s.type == X86_OP_IMM:
                regs[dr] = (s.imm & ((1 << (8 * dw)) - 1)) if dw >= 4 else None
                if prog.arch == "x86" and regs[dr] is not None:
                    regs[dr] = prog.norm(regs[dr])          # i386 PE: absolute VA -> RVA
            elif s.type == X86_OP_REG:
                sr, sw = reg_of(s)
                v = regs.get(sr)
                if dw == psz and sw == psz:
                    regs[dr] = v
                elif dw == 4 and isinstance(v, int):
                    regs[dr] = v & 0xFFFFFFFF
                else:
                    regs[dr] = None
            elif s.type == X86_OP_MEM:
                a = _x86_mem_addr(prog, st, ins, s)
                regs[dr] = _load(prog, st, a, dw) if dw >= 4 else None
            if dw < 4:
                regs[dr] = None
            return True, post
        if d.type == X86_OP_MEM:
            a = _x86_mem_addr(prog, st, ins, d)
            if s.type == X86_OP_IMM:
                v = s.imm & ((1 << (8 * d.size)) - 1)
                if prog.arch == "x86" and d.size == 4:
                    v = prog.norm(v)
            elif s.type == X86_OP_REG:
                sr, sw = reg_of(s)
                v = regs.get(sr)
                if sw < psz and isinstance(v, int):
                    v &= (1 << (8 * sw)) - 1
                elif sw < psz:
                    v = None
            else:
                v = None
            if a is not None:
                _store(prog, F, st, a, v, d.size, ins.address)
            return True, post
    if m == "lea" and len(ops) == 2 and ops[0].type == X86_OP_REG:
        dr, dw = reg_of(ops[0])
        a = _x86_mem_addr(prog, st, ins, ops[1])
        regs[dr] = a if dw == psz or (dw == 4 and isinstance(a, int)) else None
        if isinstance(a, int):
            F.lea_consts.append((ins.address, a))
        return True, post
    if m == "xor" and len(ops) == 2 and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_REG \
            and ops[0].reg == ops[1].reg:
        regs[reg_of(ops[0])[0]] = 0
        return True, post
    if m == "push" and ops:
        sp = regs.get("rsp")
        v = None
        if ops[0].type == X86_OP_REG:
            v = regs.get(reg_of(ops[0])[0])
        elif ops[0].type == X86_OP_IMM:
            v = ops[0].imm & mask
            if prog.arch == "x86":
                v = prog.norm(v)
        elif ops[0].type == X86_OP_MEM:
            v = _load(prog, st, _x86_mem_addr(prog, st, ins, ops[0]), psz)
        if isinstance(sp, tuple):
            sp = ("s", sp[1] - psz)
            regs["rsp"] = sp
            st.slots[sp[1]] = v
        return True, post
    if m == "pop" and ops:
        sp = regs.get("rsp")
        v = st.slots.get(sp[1]) if isinstance(sp, tuple) else None
        if ops[0].type == X86_OP_REG:
            regs[reg_of(ops[0])[0]] = v
        if isinstance(sp, tuple):
            regs["rsp"] = ("s", sp[1] + psz)
        return True, post
    if m in ("add", "sub") and len(ops) == 2 and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_IMM:
        dr, dw = reg_of(ops[0])
        v = regs.get(dr)
        k = ops[1].imm if m == "add" else -ops[1].imm
        if dw == psz and v is not None:
            nv = _add(v, k)
            if isinstance(nv, int):
                nv &= mask
            regs[dr] = nv
        else:
            regs[dr] = None
        return True, post
    if m in ("cmp", "test") and ops:
        for o in ops:
            if o.type == X86_OP_REG:
                v = regs.get(reg_of(o)[0])
                if isinstance(v, tuple) and v[0] == "in" and len(v) == 2:
                    F.cmp_in.add(v[1])
    if m == "test" and len(ops) == 2 and ops[1].type == X86_OP_IMM and ops[1].imm == 1 \
            and ops[0].type == X86_OP_REG and len(F.first_tests) < 4 and idx < 24:
        v = regs.get(reg_of(ops[0])[0])
        if isinstance(v, tuple) and v[0] == "in":
            F.first_tests.append(v[1])
        return True, post
    if m in _VMOV16 and len(ops) == 2 and psz == 8:
        d, s_ = ops
        if d.type == X86_OP_REG and s_.type == X86_OP_MEM and s_.size == 16:
            a = _x86_mem_addr(prog, st, ins, s_)
            regs[ins.reg_name(d.reg)] = ("q", _load(prog, st, a, 8), _load(prog, st, _add(a, 8), 8)) \
                if a is not None else None
            return True, post
        if d.type == X86_OP_MEM and s_.type == X86_OP_REG and d.size == 16:
            a = _x86_mem_addr(prog, st, ins, d)
            q = regs.get(ins.reg_name(s_.reg))
            w0, w1 = (q[1], q[2]) if isinstance(q, tuple) and q[0] == "q" else (None, None)
            if a is not None:
                _store(prog, F, st, a, w0, 8, ins.address)
                _store(prog, F, st, _add(a, 8), w1, 8, ins.address)
            return True, post
    if m in ("xorps", "pxor", "vxorps", "vpxor") and len(ops) >= 2 and all(o.type == X86_OP_REG for o in ops) \
            and len({o.reg for o in ops}) == 1:
        regs[ins.reg_name(ops[0].reg)] = ("q", 0, 0)
        return True, post
    # anything else: forget the registers it writes, and the stack bytes it may write
    _forget_mem_writes(prog, st, ins, lambda op: _x86_mem_addr(prog, st, ins, op), X86_OP_MEM)
    for r in _written(ins, False):
        if r == "rsp" and m == "and":
            continue                              # stack realignment: keep the frame model
        regs.pop(r, None)
        if r.startswith(("xmm", "ymm")):
            regs.pop(r, None)
    return True, post


def _a64_mem_addr(st, ins, op):
    m = op.mem
    base = _a64(ins.reg_name(m.base)) if m.base else None
    if m.index:
        return None
    bv = st.regs.get(base)
    if bv is None:
        return None
    return _add(bv, m.disp)


def _step_a64(prog, F, st, ins, abi, mask, pending, post, idx, insns):
    from capstone.arm64 import ARM64_OP_REG, ARM64_OP_IMM, ARM64_OP_MEM
    m = ins.mnemonic
    ops = ins.operands
    regs = st.regs

    if post is not None and not post.done:
        post.n += 1
        rd = set(_read_regs(ins, True))
        wr = set(_written(ins, True))
        if m in ("cbz", "cbnz", "tbz", "tbnz") and rd & post.tag:
            post.tested = True
            if m in ("cbz", "cbnz") and ops and not ins.reg_name(ops[0].reg).startswith("w"):
                post.tested_full = True
        elif m in ("cmp", "tst", "cmn", "ands") and rd & post.tag:
            post.flags_from_tag = True
        elif (m.startswith("b.") or m in ("cset", "csel", "csinc", "cinc", "csetm")) and post.flags_from_tag:
            post.tested = True
        elif m == "mov" and len(ops) == 2 and ops[0].type == ARM64_OP_REG and ops[1].type == ARM64_OP_REG:
            s = _a64(ins.reg_name(ops[1].reg))
            d = _a64(ins.reg_name(ops[0].reg))
            if s in post.pay:
                post.pay_used = True
                post.pay.add(d)
            elif s in post.tag:
                post.tag.add(d)
                post.pay.discard(d)
            else:
                post.tag.discard(d)
                post.pay.discard(d)
        else:
            if rd & post.pay:
                post.pay_used = True
            post.tag -= wr
            post.pay -= wr
        if post.n >= 12 or m in ("bl", "blr", "ret", "b", "br") or (not post.tag and not post.pay):
            post.finish()
            post = None

    def R(op):
        return _a64(ins.reg_name(op.reg))

    if m in ("nop", "hint", "bti", "paciasp", "autiasp", "pacibsp", "autibsp", "prfm"):
        return True, post
    if m in ("brk", "udf", "hlt"):
        F.has_trap = True
        return False, post
    if m in ("bl", "blr", "b", "br"):
        tv = None
        if ops and ops[0].type == ARM64_OP_IMM:
            tv = ops[0].imm
        elif ops and ops[0].type == ARM64_OP_REG:
            tv = regs.get(R(ops[0]))
        if m in ("b", "br"):
            if m == "b" and isinstance(tv, int) and F.start <= tv < F.end:
                if tv <= ins.address:
                    F.back_jumps.append((tv, st.copy()))
                pending.setdefault(tv, []).append(st.copy())
                return False, post
            if m == "br" and tv is None:
                F.has_indirect_jmp = True
                return False, post
            _record_call(prog, F, st, ins, abi, tv, tail=True)
            return False, post
        rec = _record_call(prog, F, st, ins, abi, tv)
        if post is not None:
            post.finish()
        post = _Post(rec, abi["ret"][0], abi["ret"][1])
        _clobber(st, abi, rec)
        return True, post
    if m in ("ret", "retaa", "retab"):
        F.has_ret = True
        F.rets.append((ins.address, regs.get("x0"), regs.get("x1")))
        return False, post
    if m in ("cmp", "tst", "ccmp", "cmn") and ops:
        for o in ops:
            if o.type == ARM64_OP_REG:
                v = regs.get(R(o))
                if isinstance(v, tuple) and v[0] == "in" and len(v) == 2:
                    F.cmp_in.add(v[1])
        return True, post
    if m in ("tbz", "tbnz") and len(ops) == 3 and ops[1].type == ARM64_OP_IMM and ops[1].imm == 0 \
            and idx < 24 and len(F.first_tests) < 4:
        v = regs.get(R(ops[0]))
        if isinstance(v, tuple) and v[0] == "in":
            F.first_tests.append(v[1])          # `args & 1`: the &'static str form check
    if m.startswith("b.") or m in ("cbz", "cbnz", "tbz", "tbnz"):
        t = _branch_target(ins, True)
        if t is not None:
            F.jcc.append((ins.address, t, m, ins.address + ins.size))
            if F.start <= t < F.end:
                pending.setdefault(t, []).append(st.copy())
            elif prog.executable(t):
                _record_call(prog, F, st, ins, abi, t, tail=True)   # conditional tail call
        return True, post

    if m in ("adrp", "adr") and len(ops) == 2:
        regs[R(ops[0])] = ops[1].imm & mask
        if m == "adr":
            F.lea_consts.append((ins.address, ops[1].imm & mask))
        return True, post
    if m in ("add", "sub") and len(ops) == 3 and ops[0].type == ARM64_OP_REG and \
            ops[1].type == ARM64_OP_REG and ops[2].type == ARM64_OP_IMM:
        d = R(ops[0])
        v = regs.get(R(ops[1]))
        k = ops[2].imm
        if ops[2].shift.type and ops[2].shift.value:
            k <<= ops[2].shift.value
        nv = _add(v, k if m == "add" else -k) if v is not None else None
        if isinstance(nv, int):
            nv &= mask
            if m == "add" and not ins.reg_name(ops[0].reg).startswith("w"):
                F.lea_consts.append((ins.address, nv))
        # (capstone names x29/x30 "fp"/"lr": test for the 32-bit W form, not for an "x" prefix)
        regs[d] = nv if not ins.reg_name(ops[0].reg).startswith("w") or not isinstance(nv, tuple) else None
        if ins.reg_name(ops[0].reg).startswith("w") and isinstance(nv, int):
            regs[d] = nv & 0xFFFFFFFF
        return True, post
    if m in ("mov", "movz", "orr") and len(ops) >= 2 and ops[0].type == ARM64_OP_REG:
        d = R(ops[0])
        if m == "orr":
            if len(ops) == 3 and ops[1].type == ARM64_OP_REG and R(ops[1]) in ("xzr",) and \
                    ops[2].type == ARM64_OP_IMM:
                regs[d] = ops[2].imm & mask
            else:
                regs.pop(d, None)
            return True, post
        if ops[1].type == ARM64_OP_IMM:
            k = ops[1].imm
            if ops[1].shift.type and ops[1].shift.value:
                k <<= ops[1].shift.value
            w = ins.reg_name(ops[0].reg).startswith("w")
            regs[d] = k & (0xFFFFFFFF if w else mask)
        elif ops[1].type == ARM64_OP_REG:
            s = R(ops[1])
            if s in ("xzr", "wzr"):
                regs[d] = 0
            elif ins.reg_name(ops[0].reg).startswith("w"):
                v = regs.get(s)
                regs[d] = v & 0xFFFFFFFF if isinstance(v, int) else None
            else:
                regs[d] = regs.get(s)
        else:
            regs.pop(d, None)
        return True, post
    if m == "movk" and len(ops) == 2:
        d = R(ops[0])
        v = regs.get(d)
        sh = ops[1].shift.value if ops[1].shift.type else 0
        if isinstance(v, int):
            regs[d] = (v & ~(0xFFFF << sh) | ((ops[1].imm & 0xFFFF) << sh)) & mask
        else:
            regs.pop(d, None)
        return True, post
    if m in ("ldr", "ldur", "str", "stur", "stp", "ldp", "strb", "sturb", "strh", "sturh",
             "ldrb", "ldrh", "ldrsw") and ops:
        memop = next((o for o in ops if o.type == ARM64_OP_MEM), None)
        if memop is None:
            for r in _written(ins, True):
                regs.pop(r, None)
            return True, post
        base = _a64(ins.reg_name(memop.mem.base))
        bv = regs.get(base)
        post_idx = ins.writeback and ops[-1].type == ARM64_OP_IMM
        if memop.mem.index:
            addr = None
        elif post_idx:
            addr = bv
        else:
            addr = _add(bv, memop.mem.disp) if bv is not None else None
        regops = [o for o in ops if o.type == ARM64_OP_REG]
        widths = []
        for o in regops:
            n = ins.reg_name(o.reg)
            widths.append(8 if n.startswith("x") or n in ("xzr", "sp", "fp", "lr") else
                          (4 if n.startswith(("w", "s")) else (16 if n.startswith("q") else 8)))
        if m.endswith("b") and m.startswith(("str", "stur", "ldr")):
            widths = [1] * len(regops)
        elif m.endswith("h") and m.startswith(("str", "stur", "ldr")):
            widths = [2] * len(regops)
        if m.startswith("st"):
            off = 0
            for o, w in zip(regops, widths):
                n = _a64(ins.reg_name(o.reg))
                v = 0 if n in ("xzr", "wzr") else regs.get(n)
                if addr is not None and w == 16:          # a q register: two 8-byte words
                    q = v if isinstance(v, tuple) and v[0] == "q" else ("q", None, None)
                    _store(prog, F, st, _add(addr, off), q[1], 8, ins.address)
                    _store(prog, F, st, _add(addr, off + 8), q[2], 8, ins.address)
                    off += w
                    continue
                if isinstance(v, int) and w < 8:
                    v &= (1 << (8 * w)) - 1
                elif w < 8 and v is not None:
                    v = None
                if addr is not None:
                    _store(prog, F, st, _add(addr, off), v, min(w, 8), ins.address)
                off += w
        else:
            off = 0
            for o, w in zip(regops, widths):
                d = _a64(ins.reg_name(o.reg))
                if w == 16:
                    v = ("q", _load(prog, st, _add(addr, off), 8), _load(prog, st, _add(addr, off + 8), 8)) \
                        if addr is not None else None
                else:
                    v = _load(prog, st, _add(addr, off), w) if addr is not None and w in (4, 8) else None
                if m == "ldrsw":
                    v = None
                regs[d] = v
                off += w
        if ins.writeback and bv is not None:
            regs[base] = _add(bv, ops[-1].imm if post_idx else memop.mem.disp)
        return True, post
    if m in ("movi", "dup") and ops and ops[0].type == ARM64_OP_REG and len(ops) == 2 and \
            ops[1].type == ARM64_OP_IMM and ops[1].imm == 0 and ins.reg_name(ops[0].reg).startswith("v"):
        regs["q" + ins.reg_name(ops[0].reg)[1:].split(".")[0]] = ("q", 0, 0)
        return True, post
    # anything else: forget the registers it writes, and the stack bytes it may write
    _forget_mem_writes(prog, st, ins, lambda op: _a64_mem_addr(st, ins, op), ARM64_OP_MEM)
    for r in _written(ins, True):
        regs.pop(r, None)
        if r.startswith(("v", "d", "s", "b", "h")) and r[1:].isdigit():
            regs.pop("q" + r[1:], None)
    return True, post


# ------------------------------------------------------------------------------------------------
# fmt::Arguments at a call site
# ------------------------------------------------------------------------------------------------
def _args_array_ok(prog, slots, args_val, nargs):
    """The `[rt::Argument; n]` a template indexes must exist: n pairs on the stack (or in rodata),
    each holding a formatter fn pointer (a code address) in one of its two words."""
    if nargs == 0:
        return True
    psz = prog.psize
    if isinstance(args_val, tuple) and args_val[0] == "s":
        good = 0
        for k in range(nargs):
            w0 = slots.get(args_val[1] + 2 * psz * k)
            w1 = slots.get(args_val[1] + 2 * psz * k + psz)
            if any(isinstance(w, int) and prog.executable(w) for w in (w0, w1)):
                good += 1
        return good >= max(1, (nargs + 1) // 2)
    if isinstance(args_val, int):
        good = 0
        for k in range(nargs):
            w0 = prog.ptr_at(args_val + 2 * psz * k)
            w1 = prog.ptr_at(args_val + 2 * psz * k + psz)
            if any(isinstance(w, int) and prog.executable(w) for w in (w0, w1)):
                good += 1
        return good == nargs
    return False


def formatter_fns(prog, slots, args_val, nargs):
    """The formatter fn pointers (`fn(&T, &mut Formatter) -> fmt::Result`) in a validated
    `[rt::Argument; n]` array: the code-address word of each (value, formatter) pair."""
    psz, out = prog.psize, set()
    for k in range(min(nargs, MAX_ARGS)):
        if isinstance(args_val, tuple) and args_val[0] == "s":
            ws = (slots.get(args_val[1] + 2 * psz * k), slots.get(args_val[1] + 2 * psz * k + psz))
        elif isinstance(args_val, int):
            ws = (prog.ptr_at(args_val + 2 * psz * k), prog.ptr_at(args_val + 2 * psz * k + psz))
        else:
            return out
        out.update(w for w in ws if isinstance(w, int) and prog.executable(w))
    return out


def decode_arguments(prog, args, slots):
    """Find a fmt::Arguments among a call's argument values.

    Returns (position, form, decoded, strength) or None. `position` is the index in `args` of the
    first word (by-value pair) or of the pointer (by reference). strength: "strong" when the
    args array was validated (or old-form pieces decoded), "weak" for a plain `&'static str`."""
    psz = prog.psize
    best = None
    for k, v in enumerate(args):
        # by value: (template, args) in two consecutive argument slots
        if isinstance(v, int) and k + 1 < len(args):
            nxt = args[k + 1]
            got = _decode_pair(prog, v, nxt, slots)
            if got:
                form, dec, strength = got
                if strength == "strong":
                    return k, form, dec, strength
                best = best or (k, form, dec, strength)
        # by reference: a pointer to a stack copy (Win64 / i386 / older rustc)
        if isinstance(v, tuple) and v[0] == "s":
            w0, w1 = slots.get(v[1]), slots.get(v[1] + psz)
            if isinstance(w0, int):
                got = _decode_pair(prog, w0, w1, slots)
                if got and got[2] == "strong":
                    return k, got[0] + "-ref", got[1], "strong"
            got = _decode_old(prog, v[1], slots)
            if got:
                return k, "pieces", got, "strong"
    return best


def _decode_pair(prog, tmpl, second, slots):
    if not isinstance(tmpl, int) or tmpl == 0:
        return None
    if isinstance(second, int) and second & 1:
        s = decode_str(prog.read, tmpl, second >> 1)
        if s is not None and s:
            return "str", {"text": _esc(s), "literals": [s], "placeholders": 0, "nargs": 0}, "weak"
        return None
    if second is None or second == 0:
        return None
    dec = decode_template(prog.read, tmpl)
    if dec is None:
        return None
    if dec["placeholders"] == 0:
        return None
    if not _args_array_ok(prog, slots, second, dec["nargs"]):
        return None
    dec = dict(dec, formatters=sorted(formatter_fns(prog, slots, second, dec["nargs"])))
    return "template", dec, "strong"


def _decode_old(prog, off, slots):
    """Pre-template fmt::Arguments on the stack: {pieces (ptr,len), args (ptr,len), fmt (ptr,len)}
    in some field order. Find a (ptr, n) pair whose ptr is n valid &str and an args (ptr, m) pair."""
    psz = prog.psize
    words = [slots.get(off + psz * i) for i in range(6)]
    if words[0] is None and words[1] is None:
        return None
    for pi in (0, 2, 4):
        p, n = words[pi], words[pi + 1]
        if not (isinstance(p, int) and isinstance(n, int) and 0 < n <= MAX_ARGS):
            continue
        if prog.executable(p):
            continue
        for ai in (0, 2, 4):
            if ai == pi:
                continue
            ap, an = words[ai], words[ai + 1]
            if not isinstance(an, int) or not 0 <= an <= MAX_ARGS:
                continue
            if an and not (isinstance(ap, tuple) or isinstance(ap, int)):
                continue
            if an and not _args_array_ok(prog, slots, ap, an):
                continue
            dec = decode_pieces(prog.read, prog.ptr_at, p, n, an, psz)
            if dec:
                dec["formatters"] = sorted(formatter_fns(prog, slots, ap, an)) if an else []
                return dec
    return None


def find_location(prog, args):
    """The first argument value that points at a valid core::panic::Location."""
    for k, v in enumerate(args):
        if isinstance(v, int) and v:
            loc = read_location(prog.read, prog.ptr_at, v, prog.psize)
            if loc:
                return k, v, loc
    return None


def _str_arg(prog, args):
    """The first (ptr, len) argument pair that is a plausible `&'static str` (an expect message)."""
    for k in range(len(args) - 1):
        p, n = args[k], args[k + 1]
        if isinstance(p, int) and isinstance(n, int) and 2 <= n <= 512 and not prog.executable(p):
            s = decode_str(prog.read, p, n)
            if s and s.isprintable():
                return _esc(s)
    return None


def find_str_message(prog, args):
    """A (ptr, len) `&str` argument pair that is one of core's panic messages."""
    for k in range(len(args) - 1):
        p, n = args[k], args[k + 1]
        if isinstance(p, int) and isinstance(n, int) and 0 < n <= 512:
            s = decode_str(prog.read, p, n)
            if s and message_kind(s):
                return s
    return None


# ------------------------------------------------------------------------------------------------
# whole-program analysis
# ------------------------------------------------------------------------------------------------
def _ranges(prog):
    starts = sorted(set(a for a in prog.funcs if prog.text_va <= a < prog.text_end))
    cap = 0x8000 if prog.arch == "aarch64" else 0x4000
    ends = getattr(prog, "func_end", None) or {}
    out = []
    for a, b in zip(starts, starts[1:] + [prog.text_end]):
        e = min(b, a + cap)
        if a < ends.get(a, e) < e:
            e = ends[a]                           # PE: the function's .pdata end
        out.append((a, e))
    return out


def run(prog, libfunc_names=None):
    """Analyze a Prog. `libfunc_names`: {va: name} from recover_libfuncs (optional)."""
    md = _a64_cs() if prog.arch == "aarch64" else _x86_cs(prog.arch)
    facts = {}
    for s, e in _ranges(prog):
        facts[s] = analyze_function(prog, s, e, md)
    names = dict(prog.names)
    for va, nm in (libfunc_names or {}).items():
        names.setdefault(va, (nm, "libfuncs"))
    return _classify(prog, facts, names)


def _callee_key(c):
    if c["target"] is not None and c["imp"] is None:
        return c["target"]
    if c["imp"]:
        return "imp:" + c["imp"]
    return None


def _guard(F, site):
    """The conditional branch that leads to the block holding `site`: (branch, mnemonic) or None."""
    starts = sorted(b for b in F.blocks if b <= site)
    blk = starts[-1] if starts else F.start
    cands = [(a, mnem) for a, t, mnem, ft in F.jcc if t == blk]
    if cands:
        return cands[0]
    # block entered by falling through a jcc: the nearest jcc before the site whose fall-through
    # starts this straight-line run
    prev = [(a, mnem, ft) for a, t, mnem, ft in F.jcc if a < site and ft <= site and ft >= blk]
    if prev:
        a, mnem, _ = max(prev)
        return a, mnem
    return None


def _noreturn_set(facts):
    """Functions that never return: no `ret`, no indirect jump, and every tail call goes to a
    function that itself never returns (fixed point)."""
    nr = {s for s, F in facts.items()
          if not F.has_ret and not F.has_indirect_jmp and (F.calls or F.has_trap) and F.ninsn > 0}
    changed = True
    while changed:
        changed = False
        for s in list(nr):
            F = facts[s]
            tails = [c for c in F.calls if c["tail"]]
            if any(_callee_key(c) not in nr for c in tails):
                nr.discard(s)
                changed = True
                continue
            # a function whose last instruction is a call that returns would fall off its end;
            # that only happens when the last call is to a noreturn function
            if not F.calls:
                continue                         # ends in a trap: nothing to check
            last = max(F.calls, key=lambda c: c["site"])
            if not last["tail"] and _callee_key(last) not in nr and not last["imp"]:
                # unknown yet: keep it (the panic chain resolves bottom-up: rust_begin_unwind ->
                # panic_fmt -> helpers); a returning last call is caught by the size check below
                if last["target"] in facts and facts[last["target"]].has_ret:
                    nr.discard(s)
                    changed = True
    return nr


def _align_pos(prog):
    """Index of __rust_dealloc's `align` argument in a call record's argument vector (i386: the
    third stack word)."""
    return 2


def _align_arg(prog):
    """Register carrying __rust_dealloc's third argument (align), or None (stack on i386)."""
    args = ABI[prog.abi]["args"]
    return args[2] if len(args) > 2 else None


def _classify(prog, facts, names):
    fsize = {s: F.eff_end - s for s, F in facts.items()}

    def nm(key):
        if isinstance(key, int):
            n = names.get(key)
            return n[0] if n else None
        if isinstance(key, str) and key.startswith("imp:"):
            return _readable(key[4:])
        return None

    def via_of(key):
        if isinstance(key, int) and key in names:
            return names[key][1]
        if isinstance(key, str):
            return "import"
        return None

    # ---- 1. decode fmt / str / Location at every call site ----
    sites = []
    for s, F in facts.items():
        for c in F.calls + F.merged_calls:
            c["func"] = s
            c["fmt"] = decode_arguments(prog, c["args"], c["slots"])
            c["loc"] = find_location(prog, c["args"])
            c["msg"] = find_str_message(prog, c["args"])
            sites.append(c)

    # one binary uses one fmt::Arguments encoding: the compact template (newer rustc, where an
    # odd second word is the `&'static str` form) or the older pieces struct. Keep the dominant
    # one; the other can only be a coincidental decode.
    n_tmpl = sum(1 for c in sites if c["fmt"] and c["fmt"][1].startswith("template"))
    n_pcs = sum(1 for c in sites if c["fmt"] and c["fmt"][1] == "pieces")
    era = "template" if n_tmpl >= n_pcs else "pieces"
    for c in sites:
        if c["fmt"] and ((era == "template" and c["fmt"][1] == "pieces") or
                         (era == "pieces" and c["fmt"][1] != "pieces")):
            c["fmt"] = None

    # ---- 2. identify helpers ----
    panic_kind = {}       # callee key -> (kind, via)
    sink_kind = {}        # callee key -> (kind, via)
    dealloc, drop = {}, {}
    keys = {k for k in (_callee_key(c) for c in sites) if k is not None} | set(facts)
    for k in keys:
        n = nm(k)
        if not n:
            continue
        pk = name_kind(n, PANIC_NAME_KINDS)
        sk = name_kind(n, SINK_NAME_KINDS)
        if pk:
            panic_kind[k] = (pk, via_of(k))
        if sk:
            sink_kind[k] = (sk, via_of(k))
        if DEALLOC_NAME.search(n):
            dealloc[k] = via_of(k)
        elif DROP_NAME.search(n):
            drop[k] = via_of(k)
    noret = _noreturn_set(facts)

    # body anchors: a noreturn function whose own sites carry core panic messages of one kind is
    # that helper (small, or up to 0x400 bytes when every message agrees: str::slice_error_fail_rt
    # formats three variants of its message), and the noreturn function it hands the message to
    # is panic_fmt (Arguments) / panic (&str)
    # (replayed per-predecessor views of merged blocks are kept out of every identification rule:
    # they only add format strings at their call site)
    base_sites = [c for c in sites if not c.get("merged")]
    fkinds = {}
    for c in base_sites:
        text = None
        if c["fmt"]:
            lits = c["fmt"][2].get("literals") or []
            text = lits[0] if lits else None
        kind = message_kind(text) or message_kind(c["msg"])
        if not kind:
            continue
        fkinds.setdefault(c["func"], []).append(kind)
        callee = _callee_key(c)
        # the message must be handed to a function that never returns: rtprintpanic!/abort paths
        # print the same core messages through write_fmt, which returns
        if callee is not None and callee not in panic_kind and callee in noret:
            panic_kind[callee] = ("panic", "anchor")
            if c["fmt"] and c["fmt"][3] == "strong":
                sink_kind.setdefault(callee, ("panic", "anchor"))
    for f, ks in fkinds.items():
        if f in panic_kind or f not in noret:
            continue
        if (fsize[f] <= HELPER_MAX and facts[f].ninsn <= 64) or (fsize[f] <= 0x400 and len(set(ks)) == 1):
            panic_kind[f] = (ks[0], "anchor")
    # "{}: {}" helpers (result::unwrap_failed) and the generic "{}" (expect / panic_display)
    for c in base_sites:
        if not c["fmt"] or c["fmt"][1] not in ("template", "template-ref", "pieces"):
            continue
        callee = _callee_key(c)
        if panic_kind.get(callee, (None,))[0] != "panic":
            continue
        f = c["func"]
        if (f in panic_kind and panic_kind[f][0] != "panic") or fsize[f] > HELPER_MAX or \
                f not in noret or c["loc"]:
            continue
        lits = [x for x in c["fmt"][2]["literals"] if x]     # pieces carry "" around placeholders
        if c["fmt"][2]["placeholders"] == 2 and lits == [": "]:
            panic_kind[f] = ("unwrap_err", "anchor")
        elif c["fmt"][2]["placeholders"] == 1 and not lits:
            panic_kind[f] = ("expect", "anchor")
    # thunks / tiny wrappers of a panic helper inherit its kind (panic(&str) -> panic_fmt, ...)
    # (raw_vec::handle_error = "capacity_overflow() or handle_alloc_error()": both noreturn)
    changed = True
    while changed:
        changed = False
        for f, F in facts.items():
            if f in panic_kind or f not in noret or fsize[f] > 0x40 or not 1 <= len(F.calls) <= 3:
                continue
            ks = [_callee_key(c) for c in F.calls]
            known = [panic_kind[k][0] for k in ks if k in panic_kind]
            if not known or any(k not in panic_kind and k not in noret for k in ks):
                continue
            kind = "alloc_error" if "capacity_overflow" in known and len(set(ks)) > 1 else known[0]
            panic_kind[f] = (kind, "anchor")
            changed = True
    # stdout / stderr anchors for _print / _eprint: a fmt sink whose body references the stream name
    sink_cands = {}
    arg_pos = {}          # callee -> argument positions where it receives validated Arguments
    for c in base_sites:
        if c["fmt"] and c["fmt"][3] == "strong":
            sink_cands.setdefault(_callee_key(c), []).append(c)
            arg_pos.setdefault(_callee_key(c), set()).add(c["fmt"][0])
    for k in sink_cands:
        if k in sink_kind or not isinstance(k, int) or k not in facts:
            continue
        refs = {prog.read(a, 6) for _s, a in facts[k].lea_consts}
        if b"stdout" in refs and b"stderr" not in refs:
            sink_kind[k] = ("print", "anchor")
        elif b"stderr" in refs and b"stdout" not in refs:
            sink_kind[k] = ("eprint", "anchor")
        elif any(c["loc"] for c in sink_cands[k]) and k in noret:
            sink_kind[k] = ("panic", "anchor")
            panic_kind.setdefault(k, ("panic", "anchor"))
        elif facts[k].first_tests:
            # format_inner(&mut String /*sret*/, Arguments) and core::fmt::write(&mut dyn Write,
            # Arguments) both test `args & 1` (the &'static str form) on entry; they differ in
            # where the Arguments sit: right after the sret slot vs. after a (data, vtable) pair
            pos = arg_pos.get(k, set())
            sret_first = (pos == {0} and prog.arch == "aarch64" and
                          all(isinstance(c["sret"], tuple) for c in sink_cands[k])) or \
                (pos == {1} and prog.arch != "aarch64" and
                 all(isinstance(c["args"][0], tuple) and c["args"][0][0] == "s" for c in sink_cands[k]))
            if sret_first:
                sink_kind[k] = ("format", "anchor")
            elif pos and min(pos) >= 2:
                sink_kind[k] = ("write", "anchor")
    # dealloc: a small wrapper around free / HeapFree (and jmp-thunks to it)
    # the C allocator's free: the import, a signature-named static copy, and one-instruction
    # aliases of it (musl: `free: b __libc_free`)
    free_set = {k for k in keys if (isinstance(k, str) and re.fullmatch(
        r"imp:_?(free|HeapFree|_aligned_free)(@.*)?", k)) or re.fullmatch(r"_?free", nm(k) or "")}
    changed = True
    while changed:
        changed = False
        for f, F in facts.items():
            if f not in free_set and fsize[f] <= 0x8 and len(F.calls) == 1 and F.calls[0]["tail"] \
                    and _callee_key(F.calls[0]) in free_set:
                free_set.add(f)
                changed = True
    for f, F in facts.items():
        if f in dealloc or fsize[f] > HELPER_MAX or (nm(f) and re.fullmatch(r"_?free", nm(f))):
            continue
        frees = [1 for c in F.calls if _callee_key(c) in free_set]
        others = [c for c in F.calls if not (c["imp"] and re.fullmatch(r"_?(GetProcessHeap)(@.*)?", c["imp"]))]
        # __rust_dealloc(ptr, size, align) / __rdl_dealloc: a one-instruction thunk to free, or a
        # small function that compares its `align` argument and only ever calls free (plain /
        # over-aligned paths). Compiler-outlined C fragments that end in `b free` are neither.
        align_reg = _align_arg(prog)
        thunk = len(F.calls) == 1 and F.calls[0]["tail"] and (
            F.ninsn == 1 or (F.ninsn == 2 and F.first_mn in ("endbr64", "endbr32", "bti")))
        if frees and len(frees) == len(others) and len(frees) <= 2 and (
                thunk or (align_reg is not None and align_reg in F.cmp_in) or
                (align_reg is None and fsize[f] <= 0x40)):   # i386: args on the stack
            dealloc[f] = "anchor"
    # call-shape anchor, no names needed (a static musl/i386 `free` has no signature):
    # __rust_dealloc(ptr, size, align) is called from many places with a constant power-of-two
    # `align` and its (nonexistent) result is never tested -- __rust_realloc / __rust_alloc share
    # the align argument but their callers null-test the returned pointer
    if not dealloc:
        apos = _align_pos(prog)
        by = {}
        for c in base_sites:
            k = _callee_key(c)
            if isinstance(k, int) and k in facts and not c["tail"]:
                by.setdefault(k, []).append(c)
        best = None
        for k, cs in by.items():
            Fk = facts[k]
            # __rust_dealloc itself is a forwarding thunk to __rdl_dealloc (or the user's
            # #[global_allocator]): tiny, one tail call
            if len(cs) < 10 or k in panic_kind or k in noret or k in sink_kind or fsize[k] > 0x20 \
                    or len(Fk.calls) != 1 or not Fk.calls[0]["tail"]:
                continue
            av = [c["args"][apos] if apos < len(c["args"]) else None for c in cs]
            aligned = sum(1 for v in av if v in (1, 2, 4, 8, 16))
            other = sum(1 for v in av if isinstance(v, int) and v not in (1, 2, 4, 8, 16))
            tested = sum(1 for c in cs if c.get("post") and (c["post"]["tested"] or c["post"]["tested_full"]))
            if aligned >= 0.5 * len(cs) and other <= 0.05 * len(cs) and tested <= 0.1 * len(cs) \
                    and (best is None or len(cs) > len(by[best])):
                best = k
        if best is not None:
            dealloc[best] = "shape"
            # and the function it forwards to (__rdl_dealloc), when it is a thunk
            Fb = facts[best]
            if len(Fb.calls) == 1 and Fb.calls[0]["tail"] and isinstance(_callee_key(Fb.calls[0]), int):
                dealloc[_callee_key(Fb.calls[0])] = "shape"
    changed = True
    while changed:
        changed = False
        for f, F in facts.items():
            if f in dealloc or fsize[f] > 0x20 or len(F.calls) != 1 or not F.calls[0]["tail"]:
                continue
            if _callee_key(F.calls[0]) in dealloc:
                dealloc[f] = "anchor"
                changed = True
    # the unwinder's resume (`_Unwind_Resume`, unnamed when statically linked): the function that
    # many functions call as their very last instruction (the end of a cleanup landing pad)
    last_calls = {}
    for f, F in facts.items():
        for c in F.calls:
            if not c["tail"] and c["site"] + c["size"] == F.eff_end:
                k = _callee_key(c)
                if k is not None and k not in panic_kind:
                    last_calls[k] = last_calls.get(k, 0) + 1
    resume = {k for k, n in last_calls.items() if n >= 10}
    resume |= {k for k in keys if isinstance(k, str) and _UNWIND_RESUME.search(k)}
    # tiny call-free leaves (AArch64 outlined atomics `__aarch64_ldadd8_rel` that Arc's refcount
    # drop uses, small accessors) are neutral for the drop-glue rule below
    leaves = {f for f, F in facts.items() if not F.calls and F.has_ret and fsize[f] <= 0x40}
    # drop glue: functions whose every call goes to dealloc / known drop glue (fixed point)
    changed = True
    while changed:
        changed = False
        for f, F in facts.items():
            if f in drop or f in dealloc or f in panic_kind or fsize[f] > DROP_GLUE_MAX or not F.calls:
                continue
            ks = [_callee_key(c) for c in F.calls]
            # a dyn field is dropped through its vtable (`call [vtable]`): allow a couple of those
            if sum(1 for k in ks if k is None) > 2:
                continue
            real = [k for k in ks if k is not None and k not in panic_kind and k not in noret
                    and k not in resume and k not in leaves]
            if real and all(k in dealloc or k in drop for k in real) and any(not c["fmt"] for c in F.calls):
                drop[f] = "inferred"
                changed = True

    # ---- 3. emit ----
    fmt_sites, panic_sites, drop_sites = [], [], []
    seen_fmt, seen_site = set(), set()
    for c in sites:
        callee = _callee_key(c)
        fn = nm(callee)
        if c["fmt"] and ((c["site"], c["fmt"][2]["text"]) in seen_fmt or
                         (c.get("merged") and c["fmt"][3] != "strong")):
            c = dict(c, fmt=None)                 # a replay: same text, or only a weak decode
        if c["fmt"]:
            seen_fmt.add((c["site"], c["fmt"][2]["text"]))
            pos, form, dec, strength = c["fmt"]
            sk = sink_kind.get(callee)
            kind = sk[0] if sk else None
            if strength == "weak" and callee not in sink_kind and pos not in arg_pos.get(callee, ()):
                # `len << 1 | 1` is only an Arguments::from_str when the callee consumes
                # fmt::Arguments; to anything else an odd second word is just an odd &str length
                pass
            else:
                text = dec["text"]
                macro = _MACRO.get(kind, "format_args!")
                if kind in ("print", "eprint", "write") and text.endswith("\\n"):
                    text = text[:-2]
                    macro = macro[:-1] + "ln!"
                if kind is None and callee in panic_kind:
                    kind, macro = "panic", "panic!"
                rec = {"site": c["site"], "function": c["func"], "callee": callee if isinstance(callee, int) else None,
                       "callee_name": fn, "sink": kind, "sink_via": (sink_kind.get(callee) or
                                                                     panic_kind.get(callee) or (None, None))[1],
                       "macro": macro, "format": text, "args": dec.get("nargs", 0),
                       "literals": dec.get("literals", []), "encoding": form, "confidence":
                       "high" if strength == "strong" and kind else ("medium" if strength == "strong" else "low")}
                if c["loc"]:
                    rec["location"] = "%s:%d:%d" % c["loc"][2]
                fmt_sites.append(rec)
        if c["site"] in seen_site:
            continue                              # one panic / drop record per call site
        is_panic = callee in panic_kind or (c["loc"] and callee in noret)
        if is_panic or callee in dealloc or callee in drop:
            seen_site.add(c["site"])
        if is_panic and not (callee in sink_kind and sink_kind[callee][0] != "panic"):
            if callee in panic_kind:
                kind, via = panic_kind[callee]
            else:
                kind, via = "panic_unidentified", "shape"
            # refine a generic panic by the message it carries
            if kind == "panic":
                text = None
                if c["fmt"] and (c["fmt"][3] == "strong" or callee in sink_kind):
                    lits = c["fmt"][2].get("literals") or []
                    text = lits[0] if lits else None
                mk = message_kind(text) or message_kind(c["msg"])
                if mk:
                    kind = mk
            elif c["msg"] and message_kind(c["msg"]):
                kind = message_kind(c["msg"])
            g = _guard(facts[c["func"]], c["site"])
            rec = {"site": c["site"], "function": c["func"], "callee": callee if isinstance(callee, int) else None,
                   "callee_name": fn, "kind": kind, "label": _KIND_LABEL.get(kind, kind),
                   "safety_check": kind in SAFETY_KINDS, "via": via}
            if c["loc"]:
                rec["location"] = "%s:%d:%d" % c["loc"][2]
            m = c["fmt"][2]["text"] if c["fmt"] and (c["fmt"][3] == "strong" or callee in sink_kind) \
                else _str_arg(prog, c["args"])
            if m:
                rec["message"] = m
            if g:
                rec["guard"], rec["guard_branch"] = g
            panic_sites.append(rec)
        elif callee in dealloc or callee in drop:
            drop_sites.append({"site": c["site"], "function": c["func"],
                               "callee": callee if isinstance(callee, int) else None, "callee_name": fn,
                               "kind": "dealloc" if callee in dealloc else "drop_glue",
                               "via": dealloc.get(callee) or drop.get(callee)})

    # every formatter fn handed to a validated fmt::Arguments returns core::fmt::Result
    fmt_fns = {}
    for c in base_sites:
        if c["fmt"] and c["fmt"][3] == "strong":
            for w in c["fmt"][2].get("formatters") or []:
                if w in facts:
                    fmt_fns[w] = fmt_fns.get(w, 0) + 1
    enum_returns = _enum_returns(prog, facts, sites, panic_kind, noret, sink_kind, fmt_fns)

    helpers = []
    for k, (kind, via) in sorted(panic_kind.items(), key=lambda kv: str(kv[0])):
        if isinstance(k, int):
            helpers.append({"va": k, "role": "panic", "kind": kind, "via": via, "name": nm(k)})
    for k, (kind, via) in sorted(sink_kind.items(), key=lambda kv: str(kv[0])):
        if isinstance(k, int) and k not in panic_kind:
            helpers.append({"va": k, "role": "fmt_sink", "kind": kind, "via": via, "name": nm(k)})
    for k, via in sorted(dealloc.items(), key=lambda kv: str(kv[0])):
        if isinstance(k, int):
            helpers.append({"va": k, "role": "dealloc", "kind": "dealloc", "via": via, "name": nm(k)})
    for k, via in sorted(drop.items(), key=lambda kv: str(kv[0])):
        if isinstance(k, int):
            helpers.append({"va": k, "role": "drop_glue", "kind": "drop_glue", "via": via, "name": nm(k)})

    fmt_sites.sort(key=lambda r: r["site"])
    panic_sites.sort(key=lambda r: r["site"])
    drop_sites.sort(key=lambda r: r["site"])
    return {
        "arch": prog.arch, "abi": prog.abi, "format": prog.fmt, "fmt_encoding": era,
        "functions": len(facts),
        "helpers": helpers,
        "fmt_sites": fmt_sites,
        "panic_sites": panic_sites,
        "drop_sites": drop_sites,
        "enum_returns": enum_returns,
        "counts": {"fmt_sites": len(fmt_sites), "panic_sites": len(panic_sites),
                   "safety_checks": sum(1 for p in panic_sites if p["safety_check"]),
                   "panic_with_location": sum(1 for p in panic_sites if "location" in p),
                   "drop_sites": len(drop_sites), "enum_returns": len(enum_returns),
                   "helpers": len(helpers)},
    }


def _enum_returns(prog, facts, sites, panic_kind, noret, sink_kind, fmt_fns=None):
    abi = ABI[prog.abi]
    # (d) formatter functions: their address sits in the formatter slot of an rt::Argument, so
    # their signature is fn(&T, &mut Formatter) -> fmt::Result = Result<(), fmt::Error> -- a type
    # fact from how they are used, independent of the (bool-like, one-register) return shape
    fmt_out = [{"va": f, "shape": "fmt-result", "confidence": "high", "score": 1.0, "callers": 0,
                "evidence": ["used as the formatter of %d fmt::Arguments argument(s)" % n],
                "note": "returns core::fmt::Result (Result<(), fmt::Error>)"}
               for f, n in sorted((fmt_fns or {}).items())]
    done = set(fmt_fns or ())
    if prog.abi == "i386":
        # 32-bit x86 returns every 64-bit integer in edx:eax, so "test eax, then read edx" is
        # ordinary u64 arithmetic, not a tag + payload; measured precision there was 3/120 against
        # DWARF before the shape heuristics were switched off. Only (d) is reported on i386.
        return fmt_out
    by_callee = {}
    for c in sites:
        if c.get("merged"):
            continue
        k = c["target"]
        if c["imp"] or not isinstance(k, int) or k not in facts or c["tail"]:
            continue
        by_callee.setdefault(k, []).append(c)
    out = []
    excluded = set(panic_kind) | set(noret) | set(sink_kind) | done
    out.extend(fmt_out)
    for f, F in facts.items():
        if f in excluded:
            continue
        ev, reasons = 0.0, []
        # (a) callers test a returned tag and use the payload register (tag + payload pair)
        cs = [c for c in by_callee.get(f, []) if c.get("post")]
        tagpay = sum(1 for c in cs if c["post"]["tested"] and c["post"]["pay_used"])
        nullable = sum(1 for c in cs if c["post"]["tested_full"] and not c["post"]["pay_used"])
        # (b) the function itself returns different small tags in the first return register
        tags = {r0 for _a, r0, _r1 in F.rets if isinstance(r0, int) and r0 <= 0xFF}
        shape = None
        if cs and tagpay and tagpay * 2 >= len(cs):
            shape = "tag+payload"
            ev = tagpay / len(cs)
            reasons.append("%d/%d caller(s) test the returned tag (%s) then use the payload (%s)"
                           % (tagpay, len(cs), abi["ret"][0], abi["ret"][1]))
            if len(tags) >= 2:
                reasons.append("returns tags %s" % sorted(tags))
                ev = min(1.0, ev + 0.25)
        # (c) sret: the caller's result slot gets different small constants (a tag) on different
        # paths, or a capacity niche (a Vec/String `cap` with the top bit set can only be a
        # discriminant: None / Err) on one path while another path fills it with a real value or
        # hands the slot on to a callee. Under the Rust ABI the slot pointer is just argument 0
        # (x8 on AArch64), so `*self = State::X` mutations look the same: require that callers
        # pass a stack buffer there (a fresh result slot), when any caller is known.
        sret = abi["sret"]
        if shape is None and sret:
            want = "stk0" if prog.abi == "i386" else sret
            all_cs = by_callee.get(f, [])
            if prog.abi == "i386":
                slot_args = [c["args"][0] if c["args"] else None for c in all_cs]
            else:
                slot_args = [c["sret"] for c in all_cs]
            stack_slot = (not all_cs) or sum(1 for v in slot_args if isinstance(v, tuple) and v[0] == "s") * 2 >= len(all_cs)
            forwards = any(c["args"] and (c["sret"] if prog.abi != "i386" else c["args"][0]) == ("in", want)
                           for c in F.calls)
            byoff = {}
            for _site, base, off, val, width in F.sret_stores:
                if base == want:
                    byoff.setdefault(off, []).append((val, width))
            niche_lo = 1 << (8 * prog.psize - 1)
            for off, vals in sorted(byoff.items()):
                consts = {v for v, _w in vals if v is not None}
                small = {v for v in consts if v <= 0xFF}
                niche = {v for v, w in vals if v is not None and w == prog.psize and v >= niche_lo}
                other = any(v is None for v, _w in vals) or forwards
                hit = None
                # an empty Vec / String is {cap: 0, ptr: align (dangling), len: 0}: cap 0 vs.
                # a constant initial capacity on another path is not a discriminant
                nxt = {v for v, _w in byoff.get(off + prog.psize, []) if v is not None}
                nxt2 = {v for v, _w in byoff.get(off + 2 * prog.psize, []) if v is not None}
                empty_vec = 0 in consts and nxt & {1, 2, 4, 8, 16} and 0 in nxt2
                if len(consts) >= 2 and len(small) >= 2 and not empty_vec:
                    hit = "stores tags %s to result-slot field +%#x on different paths" % (
                        sorted(hex(v) for v in small)[:6], off)
                elif niche and (other or len(consts) >= 2):
                    hit = "stores capacity niche %s to result-slot field +%#x, a real value on another path" % (
                        sorted(hex(v) for v in niche)[:2], off)
                if hit and stack_slot:
                    shape = "sret-tag"
                    ev = 0.75 if (off == 0 or niche) else 0.5
                    reasons.append(hit)
                    break
        if shape is None and cs and nullable and nullable * 2 >= len(cs):
            shape = "nullable-pointer"
            ev = 0.3 if nullable >= 2 else 0.2
            reasons.append("%d/%d caller(s) null-test the returned pointer (Option<&T>/Option<Box<T>> "
                           "or a raw pointer: indistinguishable)" % (nullable, len(cs)))
        if shape is None:
            continue
        conf = "high" if ev >= 0.75 and (len(cs) >= 2 or shape == "sret-tag") else (
            "medium" if ev >= 0.5 else "low")
        out.append({"va": f, "shape": shape, "confidence": conf, "score": round(ev, 2),
                    "callers": len(cs), "evidence": reasons,
                    "note": "returns enum-like value (Option/Result?)" if shape != "nullable-pointer"
                    else "returns nullable pointer (Option<&T>?)"})
    return out


# ------------------------------------------------------------------------------------------------
# entry points
# ------------------------------------------------------------------------------------------------
def recover(path, use_libfuncs=True):
    path = Path(path)
    prog = Prog.from_path(path)
    lib = {}
    notes = []
    if use_libfuncs:
        try:
            import recover_libfuncs as L
            m = L.match_binary(path)
            # relabel from the signature's own symbol: libfuncs' short label drops the final
            # path segment of non-generic v0 names ("core::panicking" for panic_bounds_check)
            lib = {r["va"]: (_readable(r["sym"]) if r.get("sym") else r["name"]) for r in m}
            try:
                for r in L.propagate(path, m):
                    lib.setdefault(r["va"], r["name"])
            except Exception as e:  # pragma: no cover - propagation is best-effort
                notes.append("libfuncs propagation failed: %s" % e)
        except Exception as e:
            notes.append("libfuncs unavailable: %s" % e)
    res = run(prog, lib)
    res["file"] = str(path)
    res["libfuncs_named"] = len(lib)
    res["symbols_named"] = sum(1 for v in prog.names.values() if v[1] == "symbol")
    if notes:
        res["notes"] = notes
    return res


def _hx(v):
    return "0x%x" % v if isinstance(v, int) else "-"


def _print(res):
    c = res["counts"]
    print("%s  [%s %s, %d functions; names: %d symbols, %d libfuncs]" % (
        res.get("file", "?"), res["arch"], res["format"], res["functions"],
        res.get("symbols_named", 0), res.get("libfuncs_named", 0)))
    print("  fmt macro sites: %d   panic sites: %d (%d safety checks, %d with Location)   "
          "drop/dealloc calls: %d   enum-like returns: %d" % (
              c["fmt_sites"], c["panic_sites"], c["safety_checks"], c["panic_with_location"],
              c["drop_sites"], c["enum_returns"]))
    if res["helpers"]:
        print("  identified helpers:")
        for h in res["helpers"][:40]:
            print("    %s  %-10s %-18s via %-8s %s" % (_hx(h["va"]), h["role"], h["kind"], h["via"],
                                                     h.get("name") or ""))
    if res["fmt_sites"]:
        print("  format strings:")
        for r in res["fmt_sites"][:60]:
            print("    %s  %s(\"%s\")%s" % (_hx(r["site"]), r["macro"], r["format"][:100],
                                         ("  @ " + r["location"]) if r.get("location") else ""))
    kinds = {}
    for p in res["panic_sites"]:
        kinds[p["label"]] = kinds.get(p["label"], 0) + 1
    if kinds:
        print("  panic sites by kind: " + ", ".join("%s=%d" % kv for kv in sorted(kinds.items())))
    for e in res["enum_returns"][:30]:
        print("    %s  %s [%s, %s] %s" % (_hx(e["va"]), e["note"], e["shape"], e["confidence"],
                                          "; ".join(e["evidence"])[:120]))


# ------------------------------------------------------------------------------------------------
# evaluation against an unstripped build (symbols = ground truth)
# ------------------------------------------------------------------------------------------------
def _truth_names(path):
    import recover_emulate as E
    img = E.Image(path)
    out = {}
    for va, n in img.function_symbols():
        if isinstance(n, bytes):
            n = n.decode("latin-1")
        if n and not n.startswith("$"):
            out.setdefault(va, _readable(n))
    return out


# drop machinery that is not named drop_in_place/drop_glue: Drop::drop impls, Arc::drop_slow,
# RawVec deallocation
_GT_DROP_EXTRA = re.compile(r"Drop::drop$|::drop_slow$|::deallocate$|Drop::drop::")
_GT_PANIC_EXTRA = re.compile(r"(?:^|::)panic_\w+$|_fail(?:ed)?$|::exhausted$|::panic$")


def _dwarf_return_kinds(path):
    """{low_pc: (kind, type name)} from DWARF subprograms of an unstripped ELF build: kind is
    "enum" (enumeration type, or a struct with a variant part = a Rust data-carrying enum incl.
    Option/Result), "unit" (no return type) or "other". {} without pyelftools / DWARF."""
    try:
        from elftools.elf.elffile import ELFFile
        from recover_enums import _iter_dies
    except Exception:
        return {}
    out = {}
    with open(path, "rb") as fh:
        try:
            ef = ELFFile(fh)
        except Exception:
            return {}
        if not ef.has_dwarf_info():
            return {}
        dw = ef.get_dwarf_info()
        for cu in dw.iter_CUs():
            dies = {d.offset: d for d in _iter_dies(cu.get_top_DIE())}
            if not any(d.tag == "DW_TAG_base_type" for d in dies.values()):
                continue                          # line-tables-only CU (prebuilt std): no types

            def ref(d, attr):
                a = d.attributes.get(attr)
                if a is None:
                    return None
                off = a.value + (cu.cu_offset if a.form in ("DW_FORM_ref4", "DW_FORM_ref8", "DW_FORM_ref2",
                                                             "DW_FORM_ref1", "DW_FORM_ref_udata") else 0)
                return dies.get(off)

            def ret_type(d, depth=0):
                if depth > 4 or d is None:
                    return None, False
                if "DW_AT_type" in d.attributes:
                    return ref(d, "DW_AT_type"), True
                for attr in ("DW_AT_specification", "DW_AT_abstract_origin"):
                    o = ref(d, attr)
                    if o is not None:
                        return ret_type(o, depth + 1)
                return None, False

            for d in dies.values():
                if d.tag != "DW_TAG_subprogram" or "DW_AT_low_pc" not in d.attributes:
                    continue
                t, has = ret_type(d)
                kind, name = "unit", None
                if has and t is not None:
                    for _ in range(6):
                        if t is not None and t.tag in ("DW_TAG_typedef", "DW_TAG_const_type",
                                                       "DW_TAG_volatile_type"):
                            t = ref(t, "DW_AT_type")
                    if t is None:
                        kind = "other"
                    else:
                        a = t.attributes.get("DW_AT_name")
                        name = a.value.decode("utf-8", "replace") if a else t.tag
                        variant = any(k.tag == "DW_TAG_variant_part" for k in t.iter_children()) \
                            if t.tag == "DW_TAG_structure_type" else False
                        kind = "enum" if t.tag == "DW_TAG_enumeration_type" or variant else "other"
                        if name == "bool":
                            kind = "other"
                out[d.attributes["DW_AT_low_pc"].value] = (kind, name)
    return out


def evaluate(unstripped, stripped=None, use_libfuncs=True):
    """Precision / recall of the stripped-binary analysis against the unstripped build's symbols.

    Ground truth per call site = the callee's symbol name (same code: `strip` does not move it):
    panic helper kinds (PANIC_NAME_KINDS), fmt sinks (SINK_NAME_KINDS), drop glue / dealloc. A fmt
    site counts as correct when its callee's true name is an Arguments consumer; the decoded text
    is reported for manual comparison with the source."""
    unstripped = Path(unstripped)
    truth_prog = Prog.from_path(unstripped)
    tnames = _truth_names(unstripped)
    res = recover(stripped or unstripped, use_libfuncs=use_libfuncs)

    def tname(va):
        return tnames.get(va) if isinstance(va, int) else None

    def gt_panic_kind(n):
        # PANIC_NAME_KINDS plus core/std's other dedicated panic helpers (panic_already_borrowed,
        # panic_on_ord_violation, len_mismatch_fail, ThreadId::new::exhausted, ...)
        return name_kind(n, PANIC_NAME_KINDS) or (
            "panic" if _GT_PANIC_EXTRA.search(n) else None)

    # call-site truth from the unstripped run (callees resolved; names from symbols)
    gt_panic, gt_fmt, gt_drop = {}, {}, {}
    unresolved = set()
    md = _a64_cs() if truth_prog.arch == "aarch64" else _x86_cs(truth_prog.arch)
    tfacts = {s: analyze_function(truth_prog, s, e, md) for s, e in _ranges(truth_prog)}
    # LLVM's machine outliner (AArch64) leaves `OUTLINED_FUNCTION_n: mov w2,#8; b __rust_dealloc`
    # fragments: a call to one is a call to what it tail-calls
    for s, F in tfacts.items():
        if (tnames.get(s) or "").startswith("OUTLINED_FUNCTION") and len(F.calls) == 1 \
                and F.calls[0]["tail"] and isinstance(F.calls[0]["target"], int):
            tn = tnames.get(F.calls[0]["target"])
            if tn:
                tnames[s] = tn
    for s, F in tfacts.items():
        for c in F.calls:
            n = tname(c["target"]) or (_readable(c["imp"]) if c["imp"] else None)
            if not n:
                if c["target"] is None and not c["imp"]:
                    unresolved.add(c["site"])
                continue
            pk = gt_panic_kind(n)
            sk = name_kind(n, SINK_NAME_KINDS)
            if pk:
                gt_panic[c["site"]] = pk
            if sk:
                gt_fmt[c["site"]] = sk
            if DEALLOC_NAME.search(n) or DROP_NAME.search(n) or _GT_DROP_EXTRA.search(n):
                gt_drop[c["site"]] = "dealloc" if DEALLOC_NAME.search(n) else "drop_glue"

    def pr(found, gt, kind_ok=None):
        # a site whose callee the unstripped build cannot name either (an indirect / dyn call) is
        # not verifiable against symbols: reported, but kept out of precision
        judged = [s for s in found if s not in unresolved]
        tp = sum(1 for s in judged if s in gt and (kind_ok is None or kind_ok(s)))
        p = tp / len(judged) if judged else None
        r = sum(1 for s in gt if s in found) / len(gt) if gt else None
        return {"found": len(found), "unverifiable": len(found) - len(judged), "truth": len(gt),
                "correct": tp, "precision": round(p, 3) if p is not None else None,
                "recall": round(r, 3) if r is not None else None}

    fp = {p["site"]: p for p in res["panic_sites"]}
    ff = {f["site"]: f for f in res["fmt_sites"]}
    fd = {d["site"]: d for d in res["drop_sites"]}

    def panic_kind_ok(s):
        want, got = gt_panic[s], fp[s]["kind"]
        if want == got:
            return True
        # explicit panic sites carrying a core message are classified by the message
        return want == "panic" and got in _KIND_LABEL
    out = {
        "panic_sites": pr(fp, gt_panic),
        "panic_kind": pr(fp, gt_panic, panic_kind_ok),
        "fmt_sites": pr(ff, gt_fmt),
        "fmt_sink_kind": pr(ff, gt_fmt, lambda s: ff[s]["sink"] == gt_fmt[s]),
        "drop_sites": pr(fd, gt_drop),
        "with_location": sum(1 for p in res["panic_sites"] if "location" in p),
        "helpers_by_via": {},
    }
    for h in res["helpers"]:
        out["helpers_by_via"][h["via"]] = out["helpers_by_via"].get(h["via"], 0) + 1
    # helper identification: of the true panic/fmt/drop helper functions that have call sites,
    # how many were identified in the stripped analysis, and how many identifications are right
    hid = {h["va"]: h for h in res["helpers"]}
    correct = 0
    for va, h in hid.items():
        n = tname(va) or ""
        ok = (h["role"] == "panic" and (gt_panic_kind(n) or name_kind(n, SINK_NAME_KINDS) == "panic")) \
            or (h["role"] == "fmt_sink" and name_kind(n, SINK_NAME_KINDS)) \
            or (h["role"] in ("dealloc", "drop_glue") and (DEALLOC_NAME.search(n) or DROP_NAME.search(n)
                                                         or re.search(r"::drop\b|drop_slow|Drop", n)))
        correct += bool(ok)
    out["helpers"] = {"identified": len(hid), "correct": correct,
                      "precision": round(correct / len(hid), 3) if hid else None}
    # enum-like returns vs. DWARF return types (functions with a DWARF subprogram only: the
    # program's own code and the generics monomorphised into it; prebuilt std has none)
    rk = _dwarf_return_kinds(unstripped)
    if rk:
        rep = {e["va"]: e for e in res["enum_returns"]}
        judged = [va for va in rep if va in rk]
        tp = [va for va in judged if rk[va][0] == "enum"]
        pos = [va for va, (k, _n) in rk.items() if k == "enum"]
        by_shape = {}
        for va in judged:
            sh = rep[va]["shape"]
            t = by_shape.setdefault(sh, [0, 0])
            t[0] += 1
            t[1] += rk[va][0] == "enum"
        out["enum_returns"] = {
            "reported": len(rep), "with_dwarf": len(judged), "correct": len(tp),
            "precision": round(len(tp) / len(judged), 3) if judged else None,
            "dwarf_enum_functions": len(pos),
            "recall": round(sum(1 for va in pos if va in rep) / len(pos), 3) if pos else None,
            "by_shape": {k: {"reported": v[0], "correct": v[1]} for k, v in by_shape.items()},
            "wrong": sorted("%s %s" % (tnames.get(va, hex(va))[:70], rk[va][1]) for va in judged
                            if rk[va][0] != "enum")[:20],
        }
    out["fmt_texts"] = sorted({f["macro"] + '("' + f["format"] + '")' for f in res["fmt_sites"]})
    return out


# ------------------------------------------------------------------------------------------------
# selftest (no binaries)
# ------------------------------------------------------------------------------------------------
def _selftest():
    # --- template decoding (newer rustc encoding) ---
    mem = {}

    def put(va, b):
        mem[va] = b

    def read(va, n):
        for base, b in mem.items():
            if base <= va < base + len(b):
                return b[va - base:va - base + n]
        return b""

    put(0x1000, b"\x06hello \xc0\x09 you are \xc0\x07 years\n\x00junk")
    d = decode_template(read, 0x1000)
    assert d and d["text"] == "hello {} you are {} years\\n" and d["nargs"] == 2, d
    # placeholder with flags+width (`{:08}` -> zero pad flag + width 8), explicit index, `{{`
    flags = (3 << 29) | (1 << 24) | (1 << 27) | 0x20
    put(0x2000, b"\x02a{" + bytes([0xC3]) + struct.pack("<IH", flags, 8) + b"\xc8\x00\x00\x00")
    d = decode_template(read, 0x2000)
    assert d and d["text"] == "a{{{:08}{0}", d
    put(0x3000, b"\x05ab\x00")                 # truncated literal -> reject
    assert decode_template(read, 0x3000) is None
    put(0x3100, b"\x90abc\x00")                # 0x81..0xBF is not a tag
    assert decode_template(read, 0x3100) is None
    # long literal piece (0x80 + u16)
    put(0x3200, b"\x80" + struct.pack("<H", 200) + b"x" * 200 + b"\xc0\x00")
    assert decode_template(read, 0x3200)["text"] == "x" * 200 + "{}"
    # Location record (ptr, len, line, col) and core message kinds
    put(0x4000, b"src/main.rs")
    put(0x5000, struct.pack("<QQII", 0x4000, 11, 42, 7))
    ptr_at = lambda va: int.from_bytes(read(va, 8), "little") if len(read(va, 8)) == 8 else None  # noqa: E731
    assert read_location(read, ptr_at, 0x5000, 8) == ("src/main.rs", 42, 7)
    assert message_kind("index out of bounds: the len is ") == "bounds_check"
    assert message_kind("attempt to add with overflow") == "overflow"
    assert message_kind("attempt to divide by zero") == "div_by_zero"
    assert message_kind("hello") is None
    # old-form pieces array: [("x=",2), (" y=",3)] + 2 args
    put(0x6000, b"x= y=")
    put(0x6100, struct.pack("<QQQQ", 0x6000, 2, 0x6002, 3))
    d = decode_pieces(read, ptr_at, 0x6100, 2, 2, 8)
    assert d and d["text"] == "x={} y={}", d

    # --- x86-64 SysV dataflow on hand-assembled code ---
    # f @0x10000: lea rdi,[rip+tmpl]; lea rsi,[rsp+0x10]; (args array on stack: [rsp+0x10]=&x,
    #             [rsp+0x18]=fmtfn); call _print ; ret
    # g @0x10100: cmp rsi,2; ja L; mov eax,[rdi+rsi*4]; ret; L: lea rdx,[rip+loc]; mov rdi,rsi;
    #             mov esi,3; call bounds  (no ret)
    # bounds @0x10200: lea rdi,[rip+bt]; lea rsi,[rsp]; mov [rsp],rax ; mov [rsp+8], fn ; call pfmt
    # pfmt @0x10300: ud2 (no ret)
    text_va = 0x10000
    code = bytearray(b"\xcc" * 0x400)

    def asm(at, b):
        code[at - text_va:at - text_va + len(b)] = b

    def rel(frm, size, to):
        return struct.pack("<i", to - (frm + size))
    tmpl = 0x1000
    a = 0x10000
    seq = b""
    seq += b"\x48\x83\xec\x28"                                                  # sub rsp,0x28
    seq += b"\x48\x8d\x44\x24\x08"                                              # lea rax,[rsp+8]
    seq += b"\x48\x89\x44\x24\x10"                                              # mov [rsp+0x10],rax
    p = a + len(seq)
    seq += b"\x48\x8d\x05" + rel(p, 7, 0x10380)                                 # lea rax,[rip+fmtfn]
    seq += b"\x48\x89\x44\x24\x18"                                              # mov [rsp+0x18],rax
    seq += b"\x48\x8d\x44\x24\x08"                                              # (2nd arg pair)
    seq += b"\x48\x89\x44\x24\x20"                                              # mov [rsp+0x20],rax
    p = a + len(seq)
    seq += b"\x48\x8d\x05" + rel(p, 7, 0x10380)
    seq += b"\x48\x89\x44\x24\x28"                                              # mov [rsp+0x28],rax
    p = a + len(seq)
    seq += b"\x48\x8d\x3d" + rel(p, 7, tmpl)                                    # lea rdi,[rip+tmpl]
    seq += b"\x48\x8d\x74\x24\x10"                                              # lea rsi,[rsp+0x10]
    p = a + len(seq)
    seq += b"\xe8" + rel(p, 5, 0x10340)                                         # call _print
    seq += b"\x48\x83\xc4\x28\xc3"                                              # add rsp,0x28; ret
    asm(a, seq)
    g = 0x10100
    seq = b"\x48\x83\xfe\x02"                                                   # cmp rsi,2
    seq += b"\x77\x04"                                                          # ja +4
    seq += b"\x8b\x04\xb7\xc3"                                                  # mov eax,[rdi+rsi*4]; ret
    p = g + len(seq)
    seq += b"\x48\x8d\x15" + rel(p, 7, 0x5000)                                  # lea rdx,[rip+loc]
    seq += b"\x48\x89\xf7"                                                      # mov rdi,rsi
    seq += b"\xbe\x03\x00\x00\x00"                                              # mov esi,3
    p = g + len(seq)
    seq += b"\xe8" + rel(p, 5, 0x10200)                                         # call bounds
    asm(g, seq)
    put(0x7000, b" index out of bounds: the len is \xc0\x12 but the index is \xc0\x00")
    bnd = 0x10200
    seq = b"\x48\x83\xec\x18"
    p = bnd + len(seq)
    seq += b"\x48\x8d\x05" + rel(p, 7, 0x10380)                                 # lea rax,[fmtfn]
    seq += b"\x48\x89\x44\x24\x08"                                              # [rsp+8]=fn
    p = bnd + len(seq)
    seq += b"\x48\x8d\x3d" + rel(p, 7, 0x7000)                                  # lea rdi,[tmpl]
    seq += b"\x48\x8d\x34\x24"                                                  # lea rsi,[rsp]
    p = bnd + len(seq)
    seq += b"\xe8" + rel(p, 5, 0x10300)                                         # call pfmt
    asm(bnd, seq)
    asm(0x10300, b"\x0f\x0b")                                                   # pfmt: ud2
    asm(0x10340, b"\x48\x8d\x05" + rel(0x10340, 7, 0x8000) + b"\xc3")           # _print: lea "stdout"
    asm(0x10380, b"\xc3")                                                       # a formatter fn
    put(0x8000, b"stdoutstderr")

    def read2(va, n):
        if text_va <= va < text_va + len(code):
            return bytes(code[va - text_va:va - text_va + n])
        return read(va, n)
    prog = Prog("x86_64", bytes(code), text_va, [0x10000, 0x10100, 0x10200, 0x10300, 0x10340, 0x10380],
                read2, lambda va: int.from_bytes(read2(va, 8), "little") if len(read2(va, 8)) == 8 else None)
    res = run(prog)
    hello = [r for r in res["fmt_sites"] if r["function"] == 0x10000]
    assert hello and hello[0]["format"] == "hello {} you are {} years" and hello[0]["macro"] == "println!", \
        res["fmt_sites"]
    pk = {p["function"]: p for p in res["panic_sites"]}
    assert pk[0x10100]["kind"] == "bounds_check" and pk[0x10100]["location"] == "src/main.rs:42:7", pk
    assert pk[0x10100]["guard"] == 0x10104 and pk[0x10100]["safety_check"], pk[0x10100]
    roles = {h["va"]: (h["role"], h["kind"], h["via"]) for h in res["helpers"]}
    assert roles[0x10200] == ("panic", "bounds_check", "anchor"), roles
    assert roles[0x10300][0] == "panic", roles
    assert roles[0x10340] == ("fmt_sink", "print", "anchor"), roles

    # --- AArch64: adr formatter fn + adrp/add template + stack args array, bl _print; then a
    # call whose x0 tag is tested (cbz) and whose x1 payload is used: tag+payload return ---
    def adr(rd, frm, to):
        imm = to - frm
        return 0x10000000 | ((imm & 3) << 29) | (((imm >> 2) & 0x7FFFF) << 5) | rd

    def adrp(rd, frm, to):
        imm = ((to & ~0xFFF) - (frm & ~0xFFF)) >> 12
        return 0x90000000 | ((imm & 3) << 29) | (((imm >> 2) & 0x7FFFF) << 5) | rd

    def addi(rd, rn, imm):
        return 0x91000000 | (imm << 10) | (rn << 5) | rd

    def bl(frm, to):
        return 0x94000000 | (((to - frm) >> 2) & 0x3FFFFFF)

    base2 = 0x20000
    w = [0xA9BD7BFD,                                  # stp x29,x30,[sp,#-0x30]!
         adr(9, base2 + 4, 0x20100),                  # adr x9, fmtfn
         0xF9000FE9,                                  # str x9,[sp,#0x18]
         0xF90017E9,                                  # str x9,[sp,#0x28]
         adrp(0, base2 + 16, 0x1000),                 # adrp x0, tmpl page
         addi(0, 0, 0x000),                           # add x0,x0,#0
         addi(1, 31, 0x10),                           # add x1,sp,#0x10
         bl(base2 + 28, 0x20200),                     # bl _print
         bl(base2 + 32, 0x20300),                     # bl find -> (x0 tag, x1 payload)
         0xB4000040,                                  # cbz x0, +8
         0xAA0103E0,                                  # mov x0, x1  (payload use)
         0xA8C37BFD,                                  # ldp x29,x30,[sp],#0x30
         0xD65F03C0]                                  # ret
    words = w
    code2 = bytearray(b"\x00" * 0x400)
    code2[0:len(words) * 4] = b"".join(struct.pack("<I", x) for x in words)
    code2[0x100:0x104] = struct.pack("<I", 0xD65F03C0)               # fmtfn: ret
    code2[0x200:0x20c] = b"".join(struct.pack("<I", x) for x in (
        adrp(9, 0x20200, 0x8000), addi(9, 9, 0), 0xD65F03C0))      # _print: refs "stdout"
    code2[0x300:0x30c] = b"".join(struct.pack("<I", x) for x in (
        0xD2800020, 0xD2800001, 0xD65F03C0))                      # find: mov x0,#1; mov x1,#0; ret

    def read3(va, n):
        if 0x20000 <= va < 0x20000 + len(code2):
            return bytes(code2[va - 0x20000:va - 0x20000 + n])
        return read(va, n)
    prog2 = Prog("aarch64", bytes(code2), 0x20000, [0x20000, 0x20100, 0x20200, 0x20300], read3,
                 lambda va: int.from_bytes(read3(va, 8), "little") if len(read3(va, 8)) == 8 else None,
                 abi="aarch64")
    res2 = run(prog2)
    f2 = [r for r in res2["fmt_sites"] if r["function"] == 0x20000]
    assert f2 and f2[0]["format"] == "hello {} you are {} years" and f2[0]["macro"] == "println!", res2
    er = {e["va"]: e for e in res2["enum_returns"]}
    assert 0x20300 in er and er[0x20300]["shape"] == "tag+payload", res2["enum_returns"]
    print("selftest OK: template/pieces/Location decoding, x86-64 + AArch64 dataflow "
          "(println! text, bounds-check helper by message anchor, Location, guard, tag+payload return)")


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if "--selftest" in args:
        _selftest()
        return 0
    as_json = "--json" in args
    nolib = "--no-libfuncs" in args
    if "--eval" in args:
        paths = [a for a in args if not a.startswith("--")]
        if not paths:
            print("usage: recover_idioms.py --eval <unstripped> [<stripped>] [--json]", file=sys.stderr)
            return 2
        r = evaluate(paths[0], paths[1] if len(paths) > 1 else None, use_libfuncs=not nolib)
        print(json.dumps(r, indent=1))
        return 0
    paths = [a for a in args if not a.startswith("--")]
    if not paths:
        print("usage: recover_idioms.py <binary> [--json] [--no-libfuncs] | --eval <unstripped> "
              "[<stripped>] | --selftest", file=sys.stderr)
        return 2
    results = []
    for p in paths:
        try:
            results.append(recover(p, use_libfuncs=not nolib))
        except Exception as e:
            results.append({"file": p, "error": "%s: %s" % (type(e).__name__, e)})
    if as_json:
        print(json.dumps(results[0] if len(results) == 1 else results, indent=1))
    else:
        for r in results:
            if "error" in r:
                print("%s: error: %s" % (r["file"], r["error"]))
            else:
                _print(r)
    return 1 if all("error" in r for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
