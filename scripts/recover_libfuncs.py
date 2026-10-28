#!/usr/bin/env python3
"""recover_libfuncs.py - identify Rust standard-library and crate functions in a (possibly
stripped) binary by masked byte-signature matching.

A stripped Rust binary is mostly `FUN_1400xxxx` in a disassembler, yet a large fraction of its
code is prebuilt std/core/alloc and third-party crates, linked and monomorphised identically
across every program built with the same toolchain. If we take an *unstripped* reference build,
sign the first bytes of each library function with the same position-independent masking the
runtime signatures use (gen_runtime_sigs.py: blank out relocation/branch bytes), those signatures
match the same functions in a *stripped* target. The analyst then reads `alloc::raw_vec::
RawVecInner::finish_grow` instead of `FUN_`, and the string decoders stand out from the library
noise around them.

This is the library-function-identification tier of the "beyond strings" work: it reuses
recover_rust_meta.py's crate+version fingerprint to pick the right signature set, and feeds
`ghidra_annotate.py` function renames.

    # generate signatures from unstripped reference builds (keyed by toolchain + arch):
    python3 scripts/recover_libfuncs.py --gen build/*nostrip obf_src/*/target/release/prog
    # identify library functions in a target:
    python3 scripts/recover_libfuncs.py path/to/binary            # human-readable
    python3 scripts/recover_libfuncs.py path/to/binary --json     # {va, name, sym} records
    python3 scripts/recover_libfuncs.py path/to/binary --propagate  # + call-graph propagation
    python3 scripts/recover_libfuncs.py --selftest

Signature matching only labels functions it has an exact masked match for -- a fraction of the
library code in a stripped static build. `--propagate` carries those labels further through the
call graph, conservatively (a wrong label is worse than none): a function that is just a `jmp F` /
`call F; ret` forwarder to a labelled F is named `thunk.<F>`, and Rust `drop_in_place` glue whose
calls are all to known drop glue / the deallocator is itself marked drop glue, to a fixed point.
Propagated labels carry a `via` field so they are never confused with signature hits.

Signatures describe one toolchain's prebuilt std; a different rustc produces different code, so
the DB is keyed by rust release (from recover_rust_meta) and matching prefers the target's own
version, falling back to any version only when that is empty.
"""
from __future__ import annotations
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
OUT = ROOT / "scripts" / "data" / "libfunc_sigs.json"
SIG_LEN = 48          # bytes signed per function start
MIN_SIZE = 20         # ignore tiny thunks/aliases
MAX_WILDCARD = 0.4    # drop a signature that is mostly masked (no discriminating bytes)

# ---------------------------------------------------------------------------------------------
# v0 (and legacy) demangling, dependency-free. Only needed for the human-readable label; the
# identification itself is the signature match, so an imperfect demangle never causes a
# misidentification, only a less pretty name.
# ---------------------------------------------------------------------------------------------
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


def _v0_path(sym: str):
    """Best-effort dotted path for a Rust v0 (`_R`) symbol, by scanning its length-prefixed
    identifiers left to right: skip production letters, `s<base62>_` disambiguators and
    `B<base62>_` backrefs, read each `[u]<len><name>` identifier, and drop the trailing
    instantiating-crate token v0 always appends. Yields e.g.
    'alloc::raw_vec::RawVecInner::finish_grow'. Not a full demangle (generic args are flattened
    away), but it never needs to be exact: the identification is the byte-signature match, and
    this only produces the label. Returns None for non-v0 or empty results."""
    if not sym.startswith("_R"):
        return None
    s = sym[2:]
    i, n, toks, guard = 0, len(s), [], 0
    while i < n and guard < 8000:
        guard += 1
        c = s[i]
        if c == "B":                                   # backref B<base62>_ : skip
            i += 1
            while i < n and s[i] != "_":
                i += 1
            i += 1
            continue
        if c == "s":                                   # disambiguator s<base62>_ : skip
            j = i + 1
            while j < n and s[j] != "_":
                j += 1
            if j < n and s[j] == "_":
                i = j + 1
                continue
        if c == "u" and i + 1 < n and s[i + 1].isdigit():
            i += 1                                     # unicode-ident prefix
            c = s[i]
        if c.isdigit():
            j = i
            while j < n and s[j].isdigit():
                j += 1
            ln = int(s[i:j])
            i = j
            if i < n and s[i] == "_":                  # separator before a name starting with a digit
                i += 1
            name = s[i:i + ln]
            i += ln
            if name and _IDENT.match(name):
                toks.append(name)
            continue
        i += 1
    if len(toks) >= 2:
        toks = toks[:-1]                               # drop the instantiating crate v0 appends
    return "::".join(toks) if toks else None


def readable(sym: str) -> str:
    """A human label for a mangled symbol: v0 path, legacy demangle, or the raw symbol."""
    p = _v0_path(sym)
    if p:
        return p
    try:
        import recover_rust_meta as M
        d = M.demangle(sym)
        if d and d != sym:
            return d
    except Exception:
        pass
    return sym


# ---------------------------------------------------------------------------------------------
# which symbols are "library" (worth a signature): std/core/alloc and detected crates, not the
# program's own crate. v0 encodes the crate as `C<ident>`; the program crate is the last C-root.
# ---------------------------------------------------------------------------------------------
_STD_ROOTS = {"core", "std", "alloc", "proc_macro", "panic_unwind", "panic_abort",
              "compiler_builtins"}


def _is_library_symbol(sym: str, own_crate: str | None, crates: set[str]) -> bool:
    p = _v0_path(sym) or ""
    root = p.split("::", 1)[0] if p else ""
    if root in _STD_ROOTS:
        return True
    if root and root in crates and root != own_crate:
        return True
    # legacy mangling: leading segment
    if sym.startswith("_ZN"):
        for r in _STD_ROOTS:
            if ("%d%s" % (len(r), r)) in sym[:24]:
                return True
    return False


# ---------------------------------------------------------------------------------------------
# generation and matching, reusing the signature engine
# ---------------------------------------------------------------------------------------------
def _engine():
    import gen_runtime_sigs as G
    return G


def _toolchain(path: Path) -> str:
    try:
        import recover_rust_meta as M
        d = M.recover(path)
        rel = d.get("rust_release")
        if isinstance(rel, dict) and rel.get("version"):
            return "rustc-" + str(rel["version"])
        commit = d.get("rustc_commit")
        if commit:
            return "commit-" + str(commit)[:12]
    except Exception:
        pass
    return "unknown"



def _macho_sym(name: str) -> str:
    """Mach-O prefixes symbols with '_': '__RNv...' / '__ZN...' -> strip one so the demanglers
    (which expect '_R' / '_ZN') see the real name."""
    if name.startswith("__R") or name.startswith("__Z"):
        return name[1:]
    return name


def _own_crate(binary) -> str | None:
    """The program's own crate = the C-root that appears as the final instantiating crate of
    most symbols (heuristic: the most common last path root among functions)."""
    from collections import Counter
    macho = binary.format.name == "MACHO"
    c = Counter()
    for s in binary.symbols:
        nm = _macho_sym(s.name) if macho else s.name
        if (macho or getattr(s, "is_function", False)) and nm.startswith("_R"):
            p = _v0_path(nm)
            if p:
                c[p.split("::", 1)[0]] += 1
    for root, _n in c.most_common():
        if root not in _STD_ROOTS:
            return root
    return None


def generate(paths):
    import lief
    G = _engine()
    seen: dict[tuple, dict] = {}        # (tool, arch, name, pat) -> {"files": set, "sym": sym}
    per_group = {}
    for p in paths:
        b = lief.parse(str(p))
        arch = G._arch(b)
        macho = b.format.name == "MACHO"
        tool = _toolchain(Path(p))
        text = next((s for s in b.sections if s.name == ("__text" if macho else ".text")), None)
        if text is None:
            continue
        code, base = bytes(text.content), text.virtual_address
        starts = G.function_starts(b)
        crates = set()
        try:
            import recover_rust_meta as M
            crates = set(M.recover(Path(p)).get("crates", {}).keys())
        except Exception:
            pass
        own = _own_crate(b)
        per_group.setdefault((tool, arch), 0)
        per_group[(tool, arch)] += 1
        for sym in b.symbols:
            va = G.sym_va(b, sym)             # PE COFF values are section-relative; sym_va -> RVA
            if not va or not (base <= va < base + len(code)):
                continue
            if not macho and not getattr(sym, "is_function", False):
                continue
            nm = _macho_sym(sym.name) if macho else sym.name
            if not _is_library_symbol(nm, own, crates):
                continue
            size = sym.size or SIG_LEN
            if size < MIN_SIZE:
                continue
            n = min(SIG_LEN, size)
            off = va - base
            pat = G.mask(code[off:off + n], va, arch)
            if pat.count("..") > len(pat) * MAX_WILDCARD:
                continue
            # unique function start in this build
            hits = [a for a in starts if base <= a < base + len(code)
                    and G.matches(pat, code[a - base:a - base + n])]
            if hits != [va]:
                continue
            name = readable(nm)
            key = (tool, arch, name, pat)
            rec = seen.setdefault(key, {"files": set(), "sym": sym.name})
            rec["files"].add(str(p))
    # keep a signature only if it was consistent across every build of its (tool, arch) group
    db = {}
    for (tool, arch, name, pat), rec in seen.items():
        if len(rec["files"]) == per_group.get((tool, arch), 0):
            db.setdefault(tool, {}).setdefault(arch, []).append(
                {"name": name, "sym": rec["sym"], "pattern": pat})
    # drop patterns that map to more than one name within a group (ambiguous)
    for tool, byarch in db.items():
        for arch, lst in byarch.items():
            bypat = {}
            for e in lst:
                bypat.setdefault(e["pattern"], set()).add(e["name"])
            byarch[arch] = [e for e in lst if len(bypat[e["pattern"]]) == 1]
    return db


def load_db():
    return json.loads(OUT.read_text()) if OUT.exists() else {}


def match_binary(path: Path, db=None):
    import lief
    G = _engine()
    if db is None:
        db = load_db()
    b = lief.parse(str(path))
    arch = G._arch(b)
    text = next((s for s in b.sections if s.name == ("__text" if b.format.name == "MACHO" else ".text")), None)
    if text is None:
        return []
    code, base = bytes(text.content), text.virtual_address
    starts = sorted(a for a in G.function_starts(b) if base <= a < base + len(code))
    tool = _toolchain(path)
    # prefer the target's own toolchain; else pool every toolchain's sigs for this arch
    groups = []
    if tool in db and arch in db[tool]:
        groups.append(db[tool][arch])
    else:
        for t, byarch in db.items():
            if arch in byarch:
                groups.append(byarch[arch])
    sigs = [e for g in groups for e in g]
    # bucket by first concrete byte for speed
    bucket: dict[str, list] = {}
    for e in sigs:
        bucket.setdefault(e["pattern"][:2], []).append(e)
    # 1) which function start(s) each signature matches
    hits_by_sig = {}                              # pattern -> list[(start, name, sym)]
    matched_at = {}                               # start -> list[(pattern, name, sym)]
    for a in starts:
        chunk = code[a - base:a - base + SIG_LEN]
        if not chunk:
            continue
        for e in bucket.get("%02x" % chunk[0], []) + bucket.get("..", []):
            if G.matches(e["pattern"], chunk):
                hits_by_sig.setdefault(e["pattern"], []).append((a, e["name"], e["sym"]))
                matched_at.setdefault(a, []).append((e["pattern"], e["name"], e["sym"]))
    # 2) a signature that matches more than one start is too loose to tell those functions
    #    apart (e.g. LowerHex vs UpperHex sharing a masked prologue) -> discard that pattern.
    loose = {pat for pat, hs in hits_by_sig.items() if len({a for a, _n, _s in hs}) > 1}
    # 3) assign a start from its tight signatures when they agree on one name
    out = []
    for a in sorted(matched_at):
        tight = [(n, s) for pat, n, s in matched_at[a] if pat not in loose]
        names = {n: s for n, s in tight}
        if len(names) == 1:
            (name, sym), = names.items()
            out.append({"va": a, "name": name, "sym": sym})
    return out


# ---------------------------------------------------------------------------------------------
# signature propagation: a byte-signature DB only labels functions it has an exact masked match
# for, which on a stripped static build is a fraction of the library code. The call graph lets us
# carry those labels further, conservatively (a wrong label is worse than none):
#   * forwarder thunks  - a function that is just `jmp F` or `call F; ret` to a labelled F is a
#                         monomorphisation/ICF thunk of F -> label it thunk.<F> (exact: it forwards).
#   * drop glue         - Rust `drop_in_place<T>` glue whose calls are all to known drop glue /
#                         drop_in_place / the deallocator is itself drop glue; propagated to a fixed
#                         point (a dropper of a type whose fields are themselves droppers).
# Both are reported with a `via` field so an analyst sees they are inferred, not signature-matched.
# ---------------------------------------------------------------------------------------------
_CALL_X86 = 0xE8
_JMP32_X86, _JMP8_X86 = 0xE9, 0xEB
_RET_X86 = {0xC3, 0xC2}
_DEALLOC_HINT = re.compile(r"__rust_dealloc|dealloc|\bfree\b|GlobalAlloc.*dealloc", re.I)
_DROP_HINT = re.compile(r"drop_in_place|core::ptr::drop|::drop\b", re.I)


def _cs_md(arch: str):
    from capstone import Cs, CS_ARCH_X86, CS_ARCH_ARM64, CS_MODE_32, CS_MODE_64, CS_MODE_LITTLE_ENDIAN
    if arch == "aarch64":
        return Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    return Cs(CS_ARCH_X86, CS_MODE_32 if arch == "x86" else CS_MODE_64)


def _call_graph(code: bytes, base: int, starts: list[int], arch: str):
    """{start: {"calls": set(target_starts), "tail": target_or_None, "size": bytes, "insns": n}}.

    Direct calls/branches only (E8/E9/EB on x86, bl/b on arm64) go into `calls`; indirect calls,
    conditional branches and direct calls to a target that is not a known start (a PLT/import stub)
    count as `other_flow` -- they are real control flow even though they name no labelled function.
    A function spans from its start to the next start. `tail` is the single direct unconditional
    jump a forwarder thunk is, when that is the function's only control flow."""
    md = _cs_md(arch)
    startset = set(starts)
    nexts = {s: n for s, n in zip(starts, starts[1:] + [base + len(code)])}
    graph = {}
    for s in starts:
        end = nexts[s]
        chunk = code[s - base:end - base]
        calls, tail, insns, other_flow = set(), None, 0, 0
        ends_ret = False
        try:
            # disassemble only up to the first terminator (ret / unconditional jump): thunks and
            # drop glue are straight-line, and anything with earlier branching sets other_flow and
            # is excluded from propagation anyway. Stopping here avoids disassembling inter-function
            # padding (zeros -> junk `add` instructions) as part of the function.
            for insn in md.disasm(chunk, s):
                insns += 1
                stop = False
                if arch == "aarch64":
                    m = insn.mnemonic
                    if m == "bl" and insn.op_str.startswith("#"):
                        t = _imm(insn.op_str)
                        if t in startset:
                            calls.add(t)
                        else:
                            other_flow += 1   # a call to a PLT/import stub or mid-function: not
                            #                   a known start, but still control flow
                    elif m == "b" and insn.op_str.startswith("#"):
                        t = _imm(insn.op_str)
                        if t in startset and not calls and not other_flow and insns <= 4:
                            tail = t     # forwarder: short, straight-line, tail-branch to a known fn
                        other_flow += 1
                        stop = True                       # unconditional branch ends the block
                    elif m == "ret":
                        ends_ret = True
                        stop = True
                    elif m in ("br", "blr", "cbz", "cbnz", "tbz", "tbnz") or m.startswith("b."):
                        other_flow += 1
                else:
                    b0 = insn.bytes[0]
                    if b0 == _CALL_X86:
                        t = _rel_target(insn)
                        if t in startset:
                            calls.add(t)
                        else:
                            other_flow += 1   # PLT/import stub or non-start target: other flow
                    elif b0 in (_JMP32_X86, _JMP8_X86):
                        t = _rel_target(insn)
                        if t in startset and not calls and not other_flow and insns <= 4:
                            tail = t     # forwarder: short, straight-line, tail-jump to a known fn
                        other_flow += 1
                        stop = True                       # unconditional jump ends the block
                    elif b0 in _RET_X86:
                        ends_ret = True
                        stop = True
                    elif insn.mnemonic.startswith("j") or insn.mnemonic == "call":
                        other_flow += 1   # indirect / conditional
                if stop:
                    break
        except Exception:
            pass
        graph[s] = {"calls": calls, "tail": tail, "size": end - s, "insns": insns,
                    "ends_ret": ends_ret, "other_flow": other_flow}
    return graph


def _imm(op_str: str) -> int:
    try:
        return int(op_str.split("#", 1)[1].split(",")[0].strip(), 0)
    except Exception:
        return -1


def _rel_target(insn) -> int:
    try:
        # capstone x86: the branch target is the sole immediate operand
        return int(insn.op_str, 0)
    except Exception:
        return -1


def propagate(path: Path, matches: list, db=None) -> list:
    """Extra labels derived from `matches` (the signature hits) via the call graph. Returns
    [{va, name, via}] for functions not already in `matches`; `via` is 'thunk'/'drop-glue'."""
    import lief
    G = _engine()
    b = lief.parse(str(path))
    arch = G._arch(b)
    text = next((s for s in b.sections if s.name == ("__text" if b.format.name == "MACHO" else ".text")), None)
    if text is None:
        return []
    code, base = bytes(text.content), text.virtual_address
    starts = sorted(a for a in G.function_starts(b) if base <= a < base + len(code))
    graph = _call_graph(code, base, starts, arch)
    return _propagate_from_graph(starts, graph, matches)


def _propagate_from_graph(starts: list, graph: dict, matches: list) -> list:
    """The pure call-graph propagation (no lief): seed from `matches`, grow thunks + drop glue."""
    labelled = {m["va"]: m["name"] for m in matches}
    dealloc = {va for va, nm in labelled.items() if _DEALLOC_HINT.search(nm)}
    dropglue = {va for va, nm in labelled.items() if _DROP_HINT.search(nm)}
    out = {}

    # 1) forwarder thunks: a single tail `jmp F`, or a body that is just `call F` (+ prologue/ret)
    for s in starts:
        if s in labelled or s in out:
            continue
        g = graph.get(s) or {}
        tgt = None
        if g.get("tail") is not None and g["tail"] in labelled:
            tgt = g["tail"]                                    # jmp F
        elif (len(g.get("calls", ())) == 1 and g.get("ends_ret") and g.get("other_flow", 0) == 0
              and g.get("size", 999) <= 48):
            only = next(iter(g["calls"]))
            if only in labelled:
                tgt = only                                     # call F; ret (small forwarder)
        if tgt is not None:
            out[s] = {"va": s, "name": "thunk." + labelled[tgt], "via": "thunk"}

    # 2) drop glue to a fixed point: a function whose every direct call goes to known drop glue /
    #    drop_in_place / the deallocator, with at least one such call, is itself drop glue.
    known_drop = set(dropglue)
    changed = True
    while changed:
        changed = False
        for s in starts:
            if s in labelled or s in out or s in known_drop:
                continue
            g = graph.get(s) or {}
            calls = g.get("calls", set())
            if not calls or g.get("other_flow", 0) > 0:
                continue
            if all(c in known_drop or c in dropglue or c in dealloc for c in calls):
                known_drop.add(s)
                out[s] = {"va": s, "name": "core::ptr::drop_in_place (glue)", "via": "drop-glue"}
                changed = True
    return sorted(out.values(), key=lambda x: x["va"])


def _selftest():
    # v0 demangle of real std symbols seen in a release build
    cases = {
        "_RNvMs4_NtCs40k4W9msRzi_5alloc7raw_vecNtB5_11RawVecInner11finish_growCs8FMd1QCh2cR_12goldberg_cff":
            "alloc::raw_vec",
        "_RNCINvNtCsgczF5crJ4sT_3std2rt10lang_startuE0Cs8FMd1QCh2cR_12goldberg_cff":
            "std::rt",
    }
    for sym, must in cases.items():
        got = _v0_path(sym) or ""
        assert got.startswith(must), "demangle %r -> %r (want prefix %r)" % (sym, got, must)
    # full-path checks (trailing instantiating crate dropped)
    assert _v0_path(
        "_RNvMs4_NtCs40k4W9msRzi_5alloc7raw_vecNtB5_11RawVecInner11finish_growCs8FMd1QCh2cR_12goldberg_cff"
    ) == "alloc::raw_vec::RawVecInner::finish_grow", _v0_path(
        "_RNvMs4_NtCs40k4W9msRzi_5alloc7raw_vecNtB5_11RawVecInner11finish_growCs8FMd1QCh2cR_12goldberg_cff")
    # library classification
    assert _is_library_symbol(
        "_RNvNtCs40k4W9msRzi_5alloc5alloc8box_free", "goldberg_cff", set())
    assert not _is_library_symbol(
        "_RNvCs8FMd1QCh2cR_12goldberg_cff4band", "goldberg_cff", set())

    # --- call-graph propagation: thunks + drop glue on a hand-assembled x86-64 .text ---
    base = 0x1000
    # F   @0x1000: std::foo (labelled)              : nop; ret
    # B   @0x1010: jmp F                             -> thunk.std::foo
    # C   @0x1020: call F; ret                       -> thunk.std::foo (single-call forwarder)
    # DP  @0x1030: core::ptr::drop_in_place (labelled): ret
    # DA  @0x1040: __rust_dealloc (labelled)         : ret
    # D1  @0x1050: call DP; call DA; ret             -> drop glue (two calls: drops then deallocs)
    # D2  @0x1060: call D1; ret                      -> drop glue (fixed point: calls known glue)
    def rel32(frm, to):  # E8/E9 rel is to-(frm+5)
        return (to - (frm + 5)) & 0xffffffff
    code = bytearray(0x100)
    code[0x00:0x02] = b"\x90\xc3"                                             # F: nop; ret
    code[0x10:0x15] = b"\xe9" + rel32(0x1010, 0x1000).to_bytes(4, "little")   # B: jmp F
    code[0x20:0x26] = b"\xe8" + rel32(0x1020, 0x1000).to_bytes(4, "little") + b"\xc3"   # C: call F; ret
    code[0x30:0x31] = b"\xc3"                                                 # DP: ret
    code[0x40:0x41] = b"\xc3"                                                 # DA: ret
    code[0x50:0x5b] = (b"\xe8" + rel32(0x1050, 0x1030).to_bytes(4, "little")  # D1: call DP; call DA; ret
                       + b"\xe8" + rel32(0x1055, 0x1040).to_bytes(4, "little") + b"\xc3")
    code[0x60:0x66] = b"\xe8" + rel32(0x1060, 0x1050).to_bytes(4, "little") + b"\xc3"   # D2: call D1; ret
    # N1  @0x1070: call F; call 0x5000(PLT); ret    -> NOT a thunk (a second, unlabelled call)
    # N2  @0x1080: test rdi,rdi; je +0; jmp F       -> NOT a thunk (conditional flow first)
    # N3  @0x1090: call DP; call 0x5000(PLT); ret   -> NOT drop glue (calls something unknown)
    code[0x70:0x7b] = (b"\xe8" + rel32(0x1070, 0x1000).to_bytes(4, "little")
                       + b"\xe8" + rel32(0x1075, 0x5000).to_bytes(4, "little") + b"\xc3")
    code[0x80:0x8a] = (b"\x48\x85\xff" + b"\x74\x00"
                       + b"\xe9" + rel32(0x1085, 0x1000).to_bytes(4, "little"))
    code[0x90:0x9b] = (b"\xe8" + rel32(0x1090, 0x1030).to_bytes(4, "little")
                       + b"\xe8" + rel32(0x1095, 0x5000).to_bytes(4, "little") + b"\xc3")
    starts = [0x1000, 0x1010, 0x1020, 0x1030, 0x1040, 0x1050, 0x1060, 0x1070, 0x1080, 0x1090]
    graph = _call_graph(bytes(code), base, starts, "x86_64")
    assert graph[0x1010]["tail"] == 0x1000, graph[0x1010]
    assert graph[0x1020]["calls"] == {0x1000} and graph[0x1020]["ends_ret"], graph[0x1020]
    assert graph[0x1050]["calls"] == {0x1030, 0x1040}, graph[0x1050]
    assert graph[0x1060]["calls"] == {0x1050}, graph[0x1060]
    matches = [{"va": 0x1000, "name": "std::foo", "sym": "F"},
               {"va": 0x1030, "name": "core::ptr::drop_in_place", "sym": "DP"},
               {"va": 0x1040, "name": "alloc::alloc::__rust_dealloc", "sym": "DA"}]
    prop = {p["va"]: p for p in _propagate_from_graph(starts, graph, matches)}
    assert prop[0x1010]["name"] == "thunk.std::foo" and prop[0x1010]["via"] == "thunk", prop.get(0x1010)
    assert prop[0x1020]["name"] == "thunk.std::foo", prop.get(0x1020)
    assert prop[0x1050]["via"] == "drop-glue" and prop[0x1060]["via"] == "drop-glue", prop
    assert 0x1000 not in prop and 0x1030 not in prop          # already labelled, not re-emitted
    assert graph[0x1070]["other_flow"] == 1 and graph[0x1080]["tail"] is None
    assert not ({0x1070, 0x1080, 0x1090} & set(prop)), {hex(k): v for k, v in prop.items()}
    print("selftest OK: v0 paths, base62, library classification, call-graph propagation "
          "(2 thunks + 2 drop-glue to a fixed point; PLT calls / guarded jumps not propagated)")


def main():
    args = sys.argv[1:]
    if "--selftest" in args:
        _selftest()
        return
    if "--gen" in args:
        args.remove("--gen")
        paths = [Path(a) for a in args]
        if not paths:
            sys.exit("usage: recover_libfuncs.py --gen <unstripped builds...>")
        db = generate(paths)
        old = load_db()
        for tool, byarch in db.items():
            for arch, lst in byarch.items():
                old.setdefault(tool, {})[arch] = lst
        OUT.parent.mkdir(parents=True, exist_ok=True)
        OUT.write_text(json.dumps(old, indent=1) + "\n")
        for tool, byarch in db.items():
            for arch, lst in byarch.items():
                print("%s / %s: %d signatures (%d distinct names)"
                      % (tool, arch, len(lst), len({e["name"] for e in lst})))
        return
    as_json = "--json" in args
    do_prop = "--propagate" in args
    paths = [Path(a) for a in args if not a.startswith("--")]
    if not paths:
        sys.exit("usage: recover_libfuncs.py <binary> [--json] [--propagate]  |  "
                 "--gen <builds...>  |  --selftest")
    res = match_binary(paths[0])
    prop = propagate(paths[0], res) if do_prop else []
    if as_json:
        print(json.dumps({"file": str(paths[0]), "libfuncs": res, "propagated": prop}, indent=1))
    else:
        print("identified %d library function(s) in %s" % (len(res), paths[0]))
        for r in sorted(res, key=lambda x: x["va"]):
            print("  0x%x  %s" % (r["va"], r["name"]))
        if do_prop:
            print("propagated %d more via the call graph (thunks + drop glue):" % len(prop))
            for r in prop:
                print("  0x%x  %s  [%s]" % (r["va"], r["name"], r["via"]))


if __name__ == "__main__":
    main()
