#!/usr/bin/env python3
"""gen_sigdb.py - build a library-signature DB matched to ONE binary's own toolchain and crates.

recover_libfuncs.py names std/crate functions in a stripped Rust binary by masked byte signature,
but its bundled DB describes one toolchain (rustc 1.97, x86-64). A binary built by another rustc,
for another architecture or with other crates shares little code with it. This script builds the
DB the binary actually needs (the idea behind rustbinsign / Oxidizer's per-version FLIRT):

  1. read the binary's facts (never runs it): rustc commit/release and the crates WITH versions
     (recover_rust_meta), and the target triple guessed from the file (ELF/PE/Mach-O, x86-64 /
     AArch64 / i686, gnu/musl/msvc/darwin: `detect_target`);
  2. find that exact toolchain + target std among the installed ones; with --allow-download,
     install it with rustup (profile minimal) -- otherwise say what is missing and stop;
  3. in a temp dir, create a throwaway cargo project pinning those crates at `=<version>` (default
     features; features are not recoverable from a stripped binary) and build its dependencies
     for that target, in release (cargo defaults) -- or with --profile size-lto / speed-lto;
  4. sign, in recover_libfuncs' DB format and with its masking engine (gen_runtime_sigs.mask):
       * every function of the compiled crate rlibs and of the toolchain's PREBUILT std rlibs
         (std is shipped compiled per toolchain+target, so its object code is exactly what a
         non-LTO binary links; relocated bytes are masked from the object's relocations), and
       * when the target can be linked here, a tiny linked "std exerciser" program run through
         recover_libfuncs.generate() -- the same --gen path the bundled DB came from -- which adds
         the common std monomorphisations (Vec/String/fmt/HashMap instances) a program compiles;
  5. cache it under <cache>/rust-deobf/sigdb/<rustc>-<triple>-<cratehash>.json (XDG_CACHE_HOME,
     %LOCALAPPDATA% on Windows, or $RUST_DEOBF_CACHE), keyed by the BINARY's toolchain + target +
     crate set, so `recover_libfuncs.py --db auto` finds it for that binary and its siblings.

    python3 scripts/gen_sigdb.py path/to/binary                    # installed toolchains only
    python3 scripts/gen_sigdb.py path/to/binary --allow-download   # rustup install + crates.io
    python3 scripts/gen_sigdb.py path/to/binary --dry-run          # print the plan, build nothing
    python3 scripts/gen_sigdb.py path/to/binary --json             # the report as JSON
    python3 scripts/gen_sigdb.py --selftest

SECURITY: the crate list comes from the (untrusted) binary, and building a crate runs its build
script and proc-macros on this host. Network is used only with --allow-download (cargo runs
--offline otherwise, so only crates already in the local cargo cache are built); review the plan
with --dry-run, override it with --crates name@ver,... or --std-only, and build inside the
analysis VM when the binary is hostile. The target binary itself is only read, never executed.
Exit status: 0 DB written (or already cached), 1 error, 2 usage, 3 toolchain/target missing.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

SIGDB_FORMAT = 1                    # bump when the DB layout or the signing rules change
DEFAULT_TIMEOUT = 1800              # seconds for the whole run (installs + builds + signing)
DEFAULT_MAX_CRATES = 40
PROFILES = {
    # cargo's release defaults (opt-level 3, 16 codegen units, thin-local LTO, unwind)
    "release": "",
    # what shipped Rust malware typically uses (same as bench_src/gen_projects.py)
    "size-lto": 'inherits = "release"\nopt-level = "z"\nlto = "fat"\ncodegen-units = 1\npanic = "abort"\n',
    "speed-lto": 'inherits = "release"\nopt-level = 3\nlto = "fat"\ncodegen-units = 1\npanic = "abort"\n',
}
# sysroot rlibs never linked into an ordinary program (or empty shims)
_STD_SKIP = re.compile(r"^lib(proc_macro|test|getopts|profiler_builtins|rustc_std_workspace_\w+|"
                       r"sysroot)-")
_CRATE_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_-]{0,63}$")
_VERSION = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
_TRIPLE = re.compile(r"^[a-z0-9_]+(?:-[a-z0-9_.]+){1,3}$")


# ---------------------------------------------------------------------------------------------
# binary facts: target triple, toolchain, crates (read-only; the binary is never executed)
# ---------------------------------------------------------------------------------------------
def triple_from(fmt: str, arch: str, abi: str | None, os_name: str | None = None) -> str | None:
    """Rust target triple for (format, arch, abi). arch is gen_runtime_sigs._arch's name
    (x86_64 / aarch64 / x86); abi: gnu|musl|msvc|android for ELF/PE, darwin|ios for Mach-O."""
    a = {"x86_64": "x86_64", "aarch64": "aarch64", "x86": "i686"}.get(arch)
    if a is None:
        return None
    if fmt == "MACHO":
        if os_name == "ios" or abi == "ios":
            return f"{a}-apple-ios"
        return f"{a}-apple-darwin"
    if fmt == "PE":
        return f"{a}-pc-windows-{'gnu' if abi == 'gnu' else 'msvc'}"
    if fmt == "ELF":
        if abi == "android":
            return {"aarch64": "aarch64-linux-android", "x86_64": "x86_64-linux-android",
                    "i686": "i686-linux-android"}[a]
        if os_name == "freebsd":
            return f"{a}-unknown-freebsd"
        return f"{a}-unknown-linux-{'musl' if abi == 'musl' else 'gnu'}"
    return None


def _pe_abi(b) -> tuple[str, str]:
    """('gnu'|'msvc', why) for a PE. MSVC's link.exe writes a Rich header and Rust's msvc targets
    import the VC runtime; mingw (windows-gnu) imports msvcrt.dll and keeps a .CRT section."""
    try:
        libs = [str(lib.name).lower() for lib in b.imports]
    except Exception:
        libs = []
    secs = {str(s.name) for s in b.sections}
    if getattr(b, "has_rich_header", False):
        return "msvc", "Rich header (MSVC link.exe)"
    if any(x.startswith(("vcruntime", "api-ms-win-crt-", "ucrtbase")) for x in libs):
        return "msvc", "imports the VC/UCRT runtime"
    if "msvcrt.dll" in libs or ".CRT" in secs or any(x.startswith("libgcc") for x in libs):
        return "gnu", "msvcrt.dll import / .CRT section (mingw)"
    return "msvc", "no mingw markers (default)"


def _elf_abi(b, raw: bytes) -> tuple[str, str | None, str]:
    """(abi, os, why) for an ELF: the interpreter names the libc; a static binary is musl unless
    glibc's own strings are inside."""
    interp = ""
    try:
        interp = str(b.interpreter) if b.has_interpreter else ""
    except Exception:
        pass
    if "linker" in interp and "/system/" in interp:
        return "android", None, f"interpreter {interp}"
    if "ld-elf.so" in interp:
        return "gnu", "freebsd", f"interpreter {interp}"
    if "ld-musl" in interp:
        return "musl", None, f"interpreter {interp}"
    if interp:
        return "gnu", None, f"interpreter {interp}"
    if b"GLIBC_" in raw or b"glibc.malloc" in raw:
        return "gnu", None, "static, glibc strings"
    return "musl", None, "static, no interpreter (Rust's musl targets link statically)"


def detect_target(path: Path) -> dict:
    """{format, arch, abi, os, triple, why} for the file at `path`, from its headers only."""
    import lief
    import gen_runtime_sigs as G
    b = lief.parse(str(path))
    if b is None:
        raise ValueError("LIEF could not parse %s" % path)
    if not hasattr(b, "format") and hasattr(b, "at"):     # a fat Mach-O: its first slice
        b = b.at(0)
    fmt = b.format.name
    arch = G._arch(b)
    os_name, why = None, ""
    if fmt == "PE":
        abi, why = _pe_abi(b)
    elif fmt == "MACHO":
        abi = "darwin"
        try:
            plat = str(b.build_version.platform).upper() if b.has_build_version else ""
        except Exception:
            plat = ""
        if "IOS" in plat and "SIMULATOR" not in plat:
            abi, os_name = "ios", "ios"
        why = "Mach-O" + (" (%s)" % plat if plat else "")
    else:
        try:
            raw = Path(path).read_bytes()
        except OSError:
            raw = b""
        abi, os_name, why = _elf_abi(b, raw)
    return {"format": fmt, "arch": arch, "abi": abi, "os": os_name,
            "triple": triple_from(fmt, arch, abi, os_name), "why": why}


def _crate_weights(meta: dict) -> dict:
    """crate -> number of panic sites in its sources (a proxy for how much of it is linked)."""
    import recover_rust_meta as M
    w: dict[str, int] = {}
    for s in meta.get("panic_sites", []):
        m = M.RE_CARGO.search(s.get("file", ""))
        if m:
            w[m.group("crate")] = w.get(m.group("crate"), 0) + 1
    return w


def crate_list(meta: dict) -> list[tuple[str, str | None]]:
    """[(name, version|None)] from recover_rust_meta's crates, validated (names and versions come
    from untrusted rodata and end up in a Cargo.toml), most-referenced first, stable order."""
    weights = _crate_weights(meta)
    out = []
    for name, vers in (meta.get("crates") or {}).items():
        if not _CRATE_NAME.match(name or ""):
            continue
        good = [v for v in vers if _VERSION.match(v or "")]
        if not good:
            out.append((name, None))
        for v in sorted(set(good)):
            out.append((name, v))
    out.sort(key=lambda nv: (-weights.get(nv[0], 0), nv[0], nv[1] or ""))
    return out


def rustc_id(version: str | None, commit: str | None) -> str:
    if version:
        return version
    if commit:
        return "commit-" + commit[:12]
    return "unknown"


def crate_hash(crates) -> str:
    """Order-independent hash of a crate set (name@version, unversioned as name@?)."""
    canon = "\n".join(sorted("%s@%s" % (n, v or "?") for n, v in crates))
    return hashlib.sha256(("sigdb-v%d\n" % SIGDB_FORMAT + canon).encode()).hexdigest()[:16]


def cache_key(facts: dict) -> str:
    triple = facts.get("triple") or "unknown-target"
    if not _TRIPLE.match(triple):
        triple = "unknown-target"
    rid = re.sub(r"[^A-Za-z0-9._-]", "_", rustc_id(facts.get("rust_version"),
                                                     facts.get("rustc_commit")))
    return "%s-%s-%s" % (rid, triple, crate_hash(facts.get("crates", [])))


def cache_dir(windows: bool | None = None) -> Path:
    """<cache>/rust-deobf/sigdb: $RUST_DEOBF_CACHE, else %LOCALAPPDATA% (Windows), else
    $XDG_CACHE_HOME, else ~/.cache. `windows` overrides the host check (tests)."""
    env = os.environ.get("RUST_DEOBF_CACHE")
    if env:
        return Path(env) / "sigdb"
    if windows is None:
        windows = os.name == "nt"
    if windows and os.environ.get("LOCALAPPDATA"):
        base = Path(os.environ["LOCALAPPDATA"])
    elif os.environ.get("XDG_CACHE_HOME"):
        base = Path(os.environ["XDG_CACHE_HOME"])
    else:
        base = Path.home() / ".cache"
    return base / "rust-deobf" / "sigdb"


def cache_path(key: str) -> Path:
    return cache_dir() / (key + ".json")


def binary_facts(path: Path, meta: dict | None = None) -> dict:
    """Everything the cache key and the build plan need, from the binary alone."""
    import recover_rust_meta as M
    if meta is None:
        meta = M.recover(Path(path))
    rel = meta.get("rust_release") or {}
    tgt = detect_target(Path(path))
    facts = {"rustc_commit": meta.get("rustc_commit"),
             "rust_version": rel.get("version") if isinstance(rel, dict) else None,
             "rust_date": rel.get("date") if isinstance(rel, dict) else None,
             "is_rust": meta.get("is_rust"), "target": tgt, "triple": tgt.get("triple"),
             "crates": crate_list(meta)}
    facts["key"] = cache_key(facts)
    return facts


def _version_of_commit(commit: str | None) -> str | None:
    if not commit:
        return None
    import recover_rust_meta as M
    rel = M.rust_release(commit)
    return rel.get("version") if isinstance(rel, dict) else None


def commit_of_version(version: str | None) -> str | None:
    """Reverse of recover_rust_meta.rust_release (version -> full commit), from the same table."""
    if not version:
        return None
    try:
        table = json.loads((ROOT / "scripts" / "data" / "rust_versions.json").read_text())
    except (OSError, ValueError):
        return None
    for h, rel in table.items():
        if isinstance(rel, dict) and rel.get("version") == version:
            return h
    return None


def match_quality(bin_commit, bin_version, db_commit, db_version) -> str:
    """'exact' (same rustc commit/release), 'same-minor' (same 1.N), 'mismatch', or 'unknown'
    when the binary's toolchain (or the DB's) is not known."""
    if bin_commit and db_commit:
        n = min(len(bin_commit), len(db_commit))
        if n >= 7 and bin_commit[:n] == db_commit[:n]:
            return "exact"
    bv = bin_version or _version_of_commit(bin_commit)
    dv = db_version or _version_of_commit(db_commit)
    if not bv or not dv:
        return "unknown"
    if bv == dv:
        return "exact"
    if bv.split(".")[:2] == dv.split(".")[:2]:
        return "same-minor"
    return "mismatch"


# ---------------------------------------------------------------------------------------------
# signing object files (the rlib members) with recover_libfuncs' masking
# ---------------------------------------------------------------------------------------------
def ar_members(data: bytes):
    """Yield (name, bytes) of an `ar` archive (rlib/.a): GNU (`/` symtab, `//` long names,
    `/N` refs, `name/`) and BSD (`#1/len`) layouts. Malformed headers end the walk."""
    if not data.startswith(b"!<arch>\n"):
        return
    off, longnames = 8, b""
    while off + 60 <= len(data):
        hdr = data[off:off + 60]
        if hdr[58:60] != b"`\n":
            return
        name = hdr[:16].rstrip(b" ")
        try:
            size = int(hdr[48:58].strip() or b"0")
        except ValueError:
            return
        body_off = off + 60
        if size < 0 or body_off + size > len(data):
            return
        body = data[body_off:body_off + size]
        off = body_off + size + (size & 1)
        if name.startswith(b"#1/"):                       # BSD: name follows the header
            try:
                ln = int(name[3:])
            except ValueError:
                return
            if ln > len(body):
                return
            name, body = body[:ln].rstrip(b"\x00"), body[ln:]
        elif name == b"//":
            longnames = body
            continue
        elif name in (b"/", b"/SYM64/", b"__.SYMDEF", b"__.SYMDEF SORTED"):
            continue
        elif name.startswith(b"/") and name[1:].isdigit():
            i = int(name[1:])                             # GNU ends a long name "/\n",
            ends = [e for e in (longnames.find(b"\n", i), longnames.find(b"\0", i)) if e >= 0]
            name = longnames[i:min(ends) if ends else len(longnames)].rstrip(b"/")  # MS/COFF: NUL
        else:
            name = name.rstrip(b"/")
        yield name.decode("latin-1"), body


def _rust_sym(name: str) -> str:
    """'__RNv..'/'__ZN..' (Mach-O, i386 COFF add a '_') -> '_RNv..'/'_ZN..'."""
    if name.startswith("__R") or name.startswith("__Z"):
        return name[1:]
    return name


def _reloc_width(tname: str, bits: int, arch: str) -> tuple[int, int]:
    """(bytes before the relocated field, bytes from it) to mask for one relocation. Covers the
    field itself plus the opcode bytes a linker rewrites when it relaxes the access (x86 GOT ->
    direct, TLS GD/LD/IE -> LE), which differ between the object and the linked binary."""
    t = tname.upper()
    if arch == "aarch64":
        return 0, max(4, bits // 8)                       # whole instruction word (or a 64-bit datum)
    n = bits // 8 if bits and bits % 8 == 0 else 4
    if "TLSGD" in t or "TLS_GD" in t:
        return 4, 12
    if "TLSLD" in t or "TLS_LDM" in t:
        return 3, 9
    if "REX_GOTPCRELX" in t or "GOTTPOFF" in t or "TLSDESC" in t or "GOT_LOAD" in t:
        return 3, n
    if "GOTPCRELX" in t or "GOT32X" in t or "TLS_IE" in t or "TLS_GOTIE" in t:
        return 2, n
    return 0, n


_X86_NOPS = sorted([bytes.fromhex(h) for h in (
    "90", "cc", "6690", "0f1f00", "0f1f4000", "0f1f440000", "660f1f440000", "0f1f8000000000",
    "0f1f840000000000", "660f1f840000000000", "662e0f1f840000000000")], key=len, reverse=True)


def _trim_padding(code: bytes, arch: str) -> bytes:
    """Drop the alignment padding a symbol-to-next-symbol size includes (COFF and Mach-O carry no
    function size): trailing nop/int3 on x86 (multi-byte nops included), nop/zero words on
    AArch64. ELF symbols have st_size, which already excludes it."""
    if arch == "aarch64":
        while len(code) >= 4 and code[-4:] in (b"\x1f\x20\x03\xd5", b"\x00\x00\x00\x00"):
            code = code[:-4]
        return code
    while code:
        for nop in _X86_NOPS:
            if code.endswith(nop):
                code = code[:-len(nop)]
                break
        else:
            break
    return code


def _object_functions(raw: bytes, arch: str):
    """[(symbol, code bytes, masked offsets)] for every defined function of one object file
    (ELF relocatable, COFF, Mach-O MH_OBJECT); masked offsets are relative to the function."""
    import lief
    b = lief.parse(raw)
    if b is None:
        return []
    out = []
    cls = type(b).__module__ + "." + type(b).__name__
    if ".ELF" in cls:
        secs = list(b.sections)
        flags: dict[int, bytearray] = {}                 # section file offset -> masked-byte map
        for r in b.object_relocations:
            s = r.section if r.has_section else None
            if s is None or s.size == 0:
                continue
            m = flags.setdefault(s.offset, bytearray(s.size))
            before, n = _reloc_width(str(r.type), int(r.size or 0), arch)
            a = int(r.address)
            if arch == "aarch64":
                a &= ~3
            for k in range(max(0, a - before), min(len(m), a + n)):
                m[k] = 1
        for sym in b.symbols:
            if sym.type != lief.ELF.Symbol.TYPE.FUNC or not (0 < sym.shndx < 0xff00):
                continue
            if sym.shndx >= len(secs) or not sym.name or sym.name[0] in ".$":
                continue
            sec = secs[sym.shndx]
            content = bytes(sec.content)
            off, size = int(sym.value), int(sym.size) or (len(content) - int(sym.value))
            if not (0 <= off < len(content)) or size <= 0:
                continue
            m = flags.get(sec.offset)
            code = content[off:off + size]
            masked = {k - off for k in range(off, off + len(code)) if m is not None and m[k]}
            out.append((sym.name, code, masked))
        return out
    if ".COFF" in cls:
        bysec: dict[int, list] = {}
        sections = list(b.sections)
        for sym in b.symbols:
            if not getattr(sym, "is_function", False) or not sym.name:
                continue
            idx = int(getattr(sym, "section_idx", 0) or 0)
            if not (1 <= idx <= len(sections)):
                continue
            bysec.setdefault(idx, []).append((int(sym.value), sym.name))
        for idx, syms in bysec.items():
            sec = sections[idx - 1]
            content = bytes(sec.content)
            m = bytearray(len(content))
            for r in sec.relocations:
                tn = str(r.type).upper()
                bits = 64 if "ADDR64" in tn else (16 if tn.endswith("SECTION") else 32)
                before, n = _reloc_width(tn, bits, arch)
                a = int(r.address) & (~3 if arch == "aarch64" else ~0)
                for k in range(max(0, a - before), min(len(m), a + n)):
                    m[k] = 1
            syms.sort()
            for i, (off, name) in enumerate(syms):
                end = syms[i + 1][0] if i + 1 < len(syms) else len(content)
                if not (0 <= off < end <= len(content)):
                    continue
                code = _trim_padding(content[off:end], arch)
                out.append((name, code, {k - off for k in range(off, off + len(code)) if m[k]}))
        return out
    if ".MachO" in cls:
        if hasattr(b, "at"):
            b = b.at(0)
        sections = list(b.sections)
        for sidx, sec in enumerate(sections, start=1):
            if str(sec.name) != "__text":
                continue
            content, base = bytes(sec.content), int(sec.virtual_address)
            m = bytearray(len(content))
            for r in sec.relocations:
                tn = str(getattr(r, "type", "")).upper()
                before, n = _reloc_width(tn, int(getattr(r, "size", 32) or 32), arch)
                a = int(r.address)
                if a >= len(content) and base <= a < base + len(content):
                    a -= base                             # absolute vs section-relative address
                if arch == "aarch64":
                    a &= ~3
                for k in range(max(0, a - before), min(len(m), a + n)):
                    m[k] = 1
            syms = sorted((int(s.value) - base, str(s.name)) for s in b.symbols
                          if getattr(s, "numberof_sections", 0) == sidx and s.name
                          and not str(s.name).startswith(("ltmp", "l_", "L")))
            for i, (off, name) in enumerate(syms):
                end = syms[i + 1][0] if i + 1 < len(syms) else len(content)
                if not (0 <= off < end <= len(content)):
                    continue
                code = _trim_padding(content[off:end], arch)
                out.append((name, code, {k - off for k in range(off, off + len(code)) if m[k]}))
    return out


def sign_function(code: bytes, masked: set, arch: str) -> str | None:
    """recover_libfuncs' signature for one function (first SIG_LEN bytes, position-dependent
    bytes masked by gen_runtime_sigs.mask, PLUS every relocated byte), or None when it is too
    short or too wildcarded -- the same filters recover_libfuncs.generate applies."""
    import gen_runtime_sigs as G
    import recover_libfuncs as L
    if len(code) < L.MIN_SIZE:
        return None
    n = min(L.SIG_LEN, len(code))
    pat = G.mask(code[:n], 0, arch)
    if masked:
        toks = [pat[i:i + 2] for i in range(0, len(pat), 2)]
        for k in masked:
            if 0 <= k < len(toks):
                toks[k] = ".."
        pat = "".join(toks)
    if pat.count("..") > len(pat) * L.MAX_WILDCARD:
        return None
    return pat


def sign_rlibs(paths, arch: str, deadline: float | None = None) -> tuple[list, dict]:
    """Sign every function in the object members of the given .rlib/.a archives."""
    import recover_libfuncs as L
    entries, stats = [], {"archives": 0, "objects": 0, "functions": 0, "signed": 0}
    for p in paths:
        if deadline is not None and time.monotonic() > deadline:
            stats["timed_out"] = True
            break
        try:
            data = Path(p).read_bytes()
        except OSError:
            continue
        stats["archives"] += 1
        for name, body in ar_members(data):
            if not name.endswith(".o") and not name.endswith(".obj"):
                continue
            if deadline is not None and time.monotonic() > deadline:
                stats["timed_out"] = True
                break
            stats["objects"] += 1
            try:
                funcs = _object_functions(body, arch)
            except Exception:
                continue
            for sym, code, masked in funcs:
                stats["functions"] += 1
                pat = sign_function(code, masked, arch)
                if pat is None:
                    continue
                stats["signed"] += 1
                entries.append({"name": L.readable(_rust_sym(sym)), "sym": sym, "pattern": pat})
    return entries, stats


def prune(entries: list) -> list:
    """De-duplicate (name, pattern) and drop patterns that map to more than one name -- the same
    ambiguity rule recover_libfuncs.generate applies."""
    seen, uniq = set(), []
    for e in entries:
        k = (e["name"], e["pattern"])
        if k not in seen:
            seen.add(k)
            uniq.append(e)
    names: dict[str, set] = {}
    for e in uniq:
        names.setdefault(e["pattern"], set()).add(e["name"])
    return [e for e in uniq if len(names[e["pattern"]]) == 1]


# ---------------------------------------------------------------------------------------------
# subprocesses with a hard deadline (process-tree kill), toolchains, the throwaway build
# ---------------------------------------------------------------------------------------------
def _kill_tree(p):
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(p.pid)], capture_output=True,
                           timeout=30)
        else:
            import signal
            os.killpg(p.pid, signal.SIGKILL)
    except Exception:
        pass
    try:
        p.kill()
    except Exception:
        pass


def run(cmd, timeout: float, env=None, cwd=None) -> tuple[int | None, str, str]:
    """(returncode | None on timeout, stdout, stderr). The child runs in its own process group /
    session so a timeout kills cargo AND the rustc/linker/build-script processes it spawned."""
    kw = {}
    if os.name == "nt":
        kw["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    else:
        kw["start_new_session"] = True
    if timeout <= 0:
        return None, "", "time budget exhausted before: %s" % " ".join(map(str, cmd))
    try:
        p = subprocess.Popen([str(c) for c in cmd], stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
                             cwd=None if cwd is None else str(cwd), text=True, errors="replace",
                             **kw)
    except OSError as e:
        return 127, "", str(e)
    try:
        out, err = p.communicate(timeout=timeout)
        return p.returncode, out, err
    except subprocess.TimeoutExpired:
        _kill_tree(p)
        try:
            out, err = p.communicate(timeout=15)
        except Exception:
            out, err = "", ""
        return None, out or "", (err or "") + "\n[timed out after %ds]" % int(timeout)


class Budget:
    def __init__(self, seconds: float):
        self.deadline = time.monotonic() + seconds

    def left(self) -> float:
        return self.deadline - time.monotonic()


def _rustc_vv(text: str) -> dict:
    d = {}
    for line in text.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            d[k.strip()] = v.strip()
    first = text.splitlines()[0] if text.strip() else ""
    m = re.match(r"rustc (\S+)", first)
    return {"version_full": d.get("release") or (m.group(1) if m else None),
            "commit": d.get("commit-hash") if d.get("commit-hash", "unknown") != "unknown" else None,
            "host": d.get("host"), "llvm": d.get("LLVM version")}


def _base_env(allow_download: bool) -> dict:
    env = dict(os.environ)
    env["RUSTUP_AUTO_INSTALL"] = "0"          # never let a proxy call install a toolchain
    env["CARGO_INCREMENTAL"] = "0"
    if not allow_download:
        env["CARGO_NET_OFFLINE"] = "true"
    for k in ("RUSTFLAGS", "CARGO_BUILD_RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_TARGET",
              "CARGO_TARGET_DIR", "RUSTC_WRAPPER", "CARGO_BUILD_RUSTC_WRAPPER", "RUSTC"):
        env.pop(k, None)                      # user flags would change the codegen we sign
    return env


def toolchain_info(name: str | None, env: dict, budget: Budget) -> dict | None:
    """{name, rustc, cargo, sysroot, version, commit, host} of a rustup toolchain (or, with
    name=None, of the rustc/cargo on PATH)."""
    rustup = shutil.which("rustup")
    if name is not None and rustup:
        rc, out, _ = run([rustup, "run", name, "rustc", "-vV"], min(60, budget.left()), env)
        if rc != 0:
            return None
        rc2, sysroot, _ = run([rustup, "run", name, "rustc", "--print", "sysroot"],
                              min(60, budget.left()), env)
        exe = ".exe" if os.name == "nt" else ""
        sysroot = sysroot.strip()
        rustc = Path(sysroot) / "bin" / ("rustc" + exe)
        cargo = Path(sysroot) / "bin" / ("cargo" + exe)
        if not cargo.is_file():                 # an older layout: ask rustup
            rc3, w, _ = run([rustup, "which", "cargo", "--toolchain", name], min(60, budget.left()), env)
            if rc3 == 0 and w.strip():
                cargo = Path(w.strip())
    else:
        r = shutil.which("rustc")
        c = shutil.which("cargo")
        if not r or not c:
            return None
        rc, out, _ = run([r, "-vV"], min(60, budget.left()), env)
        if rc != 0:
            return None
        rc2, sysroot, _ = run([r, "--print", "sysroot"], min(60, budget.left()), env)
        rustc, cargo, sysroot = Path(r), Path(c), sysroot.strip()
    if rc2 != 0 or not sysroot or not cargo.is_file():
        return None
    v = _rustc_vv(out)
    ver = (v["version_full"] or "").split("-")[0] or None
    return {"name": name, "rustc": str(rustc), "cargo": str(cargo), "sysroot": sysroot,
            "version": ver, "version_full": v["version_full"], "commit": v["commit"],
            "host": v["host"], "llvm": v["llvm"]}


def installed_toolchains(env: dict, budget: Budget) -> list[str]:
    rustup = shutil.which("rustup")
    if not rustup:
        return []
    rc, out, _ = run([rustup, "toolchain", "list"], min(60, budget.left()), env)
    if rc != 0:
        return []
    names = []
    for line in out.splitlines():
        tok = line.strip().split(" ")[0] if line.strip() else ""
        if tok and not tok.startswith(("no ", "info")):
            names.append(tok)
    return names


def target_installed(tc: dict, triple: str) -> bool:
    return (Path(tc["sysroot"]) / "lib" / "rustlib" / triple / "lib").is_dir()


def resolve_toolchain(facts: dict, override: str | None, allow_download: bool, env: dict,
                      budget: Budget, log) -> tuple[dict | None, list]:
    """Find (or, with allow_download, install) the binary's toolchain and target std.
    Returns (toolchain info | None, [missing items])."""
    want_ver, want_commit = facts.get("rust_version"), facts.get("rustc_commit")
    triple = facts.get("triple")
    missing = []
    rustup = shutil.which("rustup")
    tc = None
    if override:
        tc = toolchain_info(override, env, budget)
        if tc is None and allow_download and rustup:
            log("installing toolchain %s (rustup, profile minimal)" % override)
            run([rustup, "toolchain", "install", override, "--profile", "minimal",
                 "--no-self-update"], budget.left(), env)
            tc = toolchain_info(override, env, budget)
        if tc is None:
            missing.append({"what": "toolchain", "need": override,
                            "fix": "rustup toolchain install %s --profile minimal" % override})
    else:
        cands = installed_toolchains(env, budget)
        # a toolchain named after the release first, then any whose rustc commit is the binary's
        if want_ver:
            cands.sort(key=lambda n: not (n == want_ver or n.startswith(want_ver + "-")))
        for name in cands[:24]:
            if want_ver and not want_commit and not (name == want_ver or name.startswith(want_ver + "-")):
                continue
            info = toolchain_info(name, env, budget)
            if info and match_quality(want_commit, want_ver, info["commit"], info["version"]) == "exact":
                tc = info
                break
        if tc is None and not rustup:
            info = toolchain_info(None, env, budget)
            if info and match_quality(want_commit, want_ver, info["commit"], info["version"]) == "exact":
                tc = info
        if tc is None and want_ver and allow_download and rustup:
            log("installing rustc %s (rustup, profile minimal)" % want_ver)
            rc, _o, err = run([rustup, "toolchain", "install", want_ver, "--profile", "minimal",
                               "--no-self-update"], budget.left(), env)
            if rc == 0:
                tc = toolchain_info(want_ver, env, budget)
            else:
                log("rustup install failed: %s" % err.strip()[-300:])
        if tc is None:
            if want_ver:
                missing.append({"what": "toolchain", "need": want_ver, "commit": want_commit,
                                "fix": "rustup toolchain install %s --profile minimal "
                                       "(or rerun with --allow-download)" % want_ver})
            else:
                missing.append({"what": "toolchain", "need": "unknown",
                                "commit": want_commit,
                                "fix": "the binary's rustc release is unknown (commit %s not in "
                                       "rust_versions.json, or no /rustc/ path survived): pass "
                                       "--toolchain <name> to build with a chosen toolchain"
                                       % (want_commit or "?")})
    if tc is not None and triple and not target_installed(tc, triple):
        if allow_download and rustup and tc.get("name"):
            log("adding target %s to %s" % (triple, tc["name"]))
            run([rustup, "target", "add", "--toolchain", tc["name"], triple], budget.left(), env)
        if not target_installed(tc, triple):
            missing.append({"what": "target", "need": triple, "toolchain": tc.get("name"),
                            "fix": "rustup target add --toolchain %s %s (or --allow-download)"
                                   % (tc.get("name") or "<toolchain>", triple)})
    return tc, missing


def _toml_str(s: str) -> str:
    return json.dumps(s)                      # a JSON string is a valid TOML basic string (ASCII)


def _edition(version: str | None) -> str:
    try:
        minor = int((version or "1.97").split(".")[1])
    except (IndexError, ValueError):
        minor = 97
    return "2021" if minor >= 56 else ("2018" if minor >= 31 else "2015")


def render_manifest(crates, profile: str, version: str | None) -> str:
    """Cargo.toml of the throwaway project: one dependency per (crate, version), renamed so two
    versions of one crate can coexist, pinned with `=`. Names/versions are validated again here
    (they come from the untrusted binary and are written into TOML)."""
    lines = ["[package]", 'name = "rd_sigdb_probe"', 'version = "0.0.0"',
             "edition = %s" % _toml_str(_edition(version)), "publish = false"]
    if version and re.match(r"^\d+\.\d+(\.\d+)?$", version):
        try:
            if int(version.split(".")[1]) >= 56:
                lines.append("rust-version = %s" % _toml_str(version))
        except (IndexError, ValueError):
            pass
    lines += ["", "[lib]", 'path = "src/lib.rs"', "", "[[bin]]", 'name = "rd_sigdb_exerciser"',
              'path = "src/main.rs"', "", "[dependencies]"]
    for i, (name, ver) in enumerate(crates):
        if not _CRATE_NAME.match(name) or not ver or not _VERSION.match(ver):
            raise ValueError("refusing crate %r @ %r" % (name, ver))
        alias = "d%d_%s" % (i, name.replace("-", "_"))
        lines.append("%s = { package = %s, version = %s }"
                     % (alias, _toml_str(name), _toml_str("=" + ver)))
    lines += ["", "[profile.release]", "debug = false", "incremental = false"]
    if profile != "release":
        lines += ["", "[profile.%s]" % profile] + PROFILES[profile].strip().splitlines()
    lines += ["", "[workspace]", ""]
    return "\n".join(lines)


# A benign program exercising common std paths, so the linked build carries the std code (and the
# std monomorphisations) an ordinary program links. It is compiled, never run.
EXERCISER = r'''
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fmt::Write as _;
use std::hint::black_box;
use std::io::{Read, Write};
use std::sync::{mpsc, Arc, Mutex, RwLock};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut s = String::new();
    for (i, a) in args.iter().enumerate() {
        write!(s, "{}:{:>4}:{:x}:{:?};", i, a, i * 31, a.len()).unwrap();
    }
    let mut v: Vec<u64> = black_box((0..64u64).map(|x| x.wrapping_mul(2654435761)).collect());
    v.sort_unstable();
    v.sort();
    v.dedup();
    let mut hm: HashMap<String, usize> = HashMap::new();
    for w in s.split(';').chain(args.iter().map(|x| x.as_str())) {
        *hm.entry(w.to_owned()).or_insert(0) += 1;
    }
    let hs: HashSet<u64> = v.iter().copied().collect();
    let mut bt = BTreeMap::new();
    for (k, c) in &hm {
        bt.insert(k.clone(), *c);
    }
    let mut dq: VecDeque<u8> = s.bytes().collect();
    dq.rotate_left(dq.len() / 2);
    let n: i64 = args.get(1).and_then(|x| x.parse().ok()).unwrap_or(7);
    let f: f64 = args.get(2).and_then(|x| x.parse().ok()).unwrap_or(1.5);
    let shared = Arc::new(Mutex::new(Vec::<String>::new()));
    let rw = Arc::new(RwLock::new(0usize));
    let (tx, rx) = mpsc::channel();
    let hs_len = hs.len();
    let handles: Vec<_> = (0..2)
        .map(|i| {
            let shared = Arc::clone(&shared);
            let rw = Arc::clone(&rw);
            let tx = tx.clone();
            std::thread::spawn(move || {
                shared.lock().unwrap().push(format!("t{i} {}", hs_len));
                *rw.write().unwrap() += i;
                tx.send(i * 2).unwrap();
            })
        })
        .collect();
    drop(tx);
    for h in handles {
        h.join().unwrap();
    }
    let got: usize = rx.iter().sum();
    let mut buf = String::new();
    if let Ok(mut fh) = std::fs::File::open(args.get(3).map(|x| x.as_str()).unwrap_or("/nonexistent.invalid")) {
        let _ = fh.read_to_string(&mut buf);
    }
    let p = std::path::Path::new(&s).join("x").with_extension("rs");
    let t0 = std::time::Instant::now();
    let upper: String = buf.chars().rev().flat_map(char::to_uppercase).collect();
    let env = std::env::var("RD_SIGDB_X").unwrap_or_default();
    let out = std::io::stdout();
    let mut lock = out.lock();
    let _ = writeln!(lock, "{} {} {} {:.3} {:?} {} {} {:?} {} {} {}", s.len(), v.len(), bt.len(), f,
                     p.display().to_string(), n, got, t0.elapsed(), upper.len(), dq.len(), env);
    eprintln!("{:#?}", bt.iter().next());
    let r = std::panic::catch_unwind(|| black_box(v.get(n as usize).copied()).unwrap());
    let _ = writeln!(lock, "{}", r.is_ok());
}
'''


def _linker_setup(triple: str, host: str | None) -> tuple[list | None, str]:
    """Extra `cargo rustc -- <flags>` to link the exerciser for `triple` here, or (None, why) when
    this host cannot link it (the rlib signatures still work: they need no linker)."""
    if not host or triple == host:
        return [], "native"
    tarch, harch = triple.split("-")[0], host.split("-")[0]
    if triple.endswith("-linux-musl"):
        if tarch == harch:
            return [], "musl (self-contained)"
        return ["-C", "linker=rust-lld", "-C", "link-self-contained=yes"], "rust-lld (cross musl)"
    if triple.endswith("-linux-gnu") and "linux" in host:
        if tarch == "i686" and harch == "x86_64":
            return [], "host cc -m32 (needs multilib)"
        cc = shutil.which("%s-linux-gnu-gcc" % tarch)
        return (["-C", "linker=" + cc], "cross gcc") if cc else (None, "no %s-linux-gnu-gcc" % tarch)
    if triple.endswith("-windows-gnu"):
        cc = shutil.which(("x86_64" if tarch == "x86_64" else "i686") + "-w64-mingw32-gcc")
        if os.name == "nt":
            return [], "native mingw"
        return (["-C", "linker=" + cc], "mingw gcc") if cc else (None, "no mingw-w64 gcc")
    if triple.endswith("-windows-msvc"):
        return ([], "msvc") if os.name == "nt" else (None, "msvc link needs a Windows host")
    if "-apple-" in triple:
        return ([], "apple") if sys.platform == "darwin" else (None, "Apple link needs a macOS host")
    return None, "no known linker for %s on %s" % (triple, host)


_ERR_CRATE = [
    re.compile(r"no matching package named `([A-Za-z0-9_-]+)`"),
    re.compile(r"failed to select a version for the requirement `([A-Za-z0-9_-]+) = "),
    re.compile(r"failed to select a version for `([A-Za-z0-9_-]+)`"),
    re.compile(r"could not compile `([A-Za-z0-9_-]+)`"),
    re.compile(r"failed to run custom build command for `([A-Za-z0-9_-]+) v"),
    re.compile(r"failed to download `?([A-Za-z0-9_-]+) v"),
    re.compile(r"package `([A-Za-z0-9_-]+) v[^`]*` cannot be built because it requires rustc"),
    re.compile(r"rustc [0-9.]+ is not supported by the following packages?:\s*\n?\s*([A-Za-z0-9_-]+)@"),
]


def failing_crates(stderr: str) -> list[str]:
    """Crate names a failed cargo run blames, in order of appearance."""
    hits = []
    for rx in _ERR_CRATE:
        for m in rx.finditer(stderr):
            hits.append((m.start(), m.group(1)))
    out = []
    for _pos, name in sorted(hits):
        if name not in out:
            out.append(name)
    return out


def _deps_rlibs(target_dir: Path, triple: str, profile: str) -> list[Path]:
    d = target_dir / triple / profile / "deps"
    return sorted(p for p in d.glob("*.rlib") if not p.name.startswith("librd_sigdb_probe-"))


def build_and_sign(facts: dict, tc: dict, crates: list, profiles: list, env: dict, budget: Budget,
                   exerciser: bool, log) -> dict:
    """Build the throwaway project for each profile in a temp dir and sign it. Returns
    {entries, crates_built, crates_skipped, sources, notes}."""
    import recover_libfuncs as L
    triple, arch = facts["triple"], facts["target"]["arch"]
    entries, notes, sources = [], [], {}
    skipped: dict[str, str] = {}
    built_crates: list = []
    # 1) the toolchain's prebuilt std for the target: no build needed
    libdir = Path(tc["sysroot"]) / "lib" / "rustlib" / triple / "lib"
    std_rlibs = sorted(p for p in libdir.glob("*.rlib") if not _STD_SKIP.match(p.name))
    e, st = sign_rlibs(std_rlibs, arch, budget.deadline)
    entries += e
    std_entries = list(e)
    sources["std_rlibs"] = st
    log("std rlibs: %d archives, %d functions, %d signed" % (st["archives"], st["functions"], st["signed"]))
    # ignore_cleanup_errors: on Windows a just-killed rustc can still hold a file for a moment
    with tempfile.TemporaryDirectory(prefix="rd-sigdb-", ignore_cleanup_errors=True) as tmp:
        proj = Path(tmp) / "probe"
        (proj / "src").mkdir(parents=True)
        (proj / ".cargo").mkdir()
        (proj / ".cargo" / "config.toml").write_text(
            '[resolver]\nincompatible-rust-versions = "fallback"\n')
        (proj / "src" / "lib.rs").write_text("#![allow(unused)]\n")
        (proj / "src" / "main.rs").write_text(EXERCISER)
        tdir = Path(tmp) / "target"
        benv = dict(env)
        benv["CARGO_TARGET_DIR"] = str(tdir)
        if tc.get("name"):
            benv["RUSTUP_TOOLCHAIN"] = tc["name"]
        benv["RUSTC"] = tc["rustc"]
        offline = [] if env.get("CARGO_NET_OFFLINE") != "true" else ["--offline"]
        for profile in profiles:
            pdir = "release" if profile == "release" else profile
            todo = list(crates)
            built_ok = not todo
            # 2) the crates, as rlibs (no linking -> works for any installed target)
            for attempt in range(8):
                (proj / "Cargo.toml").write_text(render_manifest(todo, profile, tc.get("version")))
                lock = proj / "Cargo.lock"
                if lock.exists():
                    lock.unlink()
                if not todo:
                    break
                cmd = [tc["cargo"], "build", "--lib", "--target", triple, "--profile", profile] + offline
                if profile == "release":
                    cmd[cmd.index("--profile"):cmd.index("--profile") + 2] = ["--release"]
                log("[%s] cargo build of %d crate(s), attempt %d" % (profile, len(todo), attempt + 1))
                rc, _out, err = run(cmd, budget.left(), benv, cwd=proj)
                if rc == 0:
                    built_ok = True
                    break
                if rc is None:
                    notes.append("[%s] crate build timed out; signing what was built" % profile)
                    break
                blamed = [n for n in failing_crates(err) if any(n == c for c, _v in todo)]
                if not blamed:
                    tail = " | ".join(err.strip().splitlines()[-3:])[-400:]
                    notes.append("[%s] crate build failed (unattributed): %s" % (profile, tail))
                    for c, v in todo:
                        skipped.setdefault("%s@%s" % (c, v), "build failed (unattributed)")
                    todo = []
                    break
                for n in blamed:
                    why = ("not in the local cargo cache (--allow-download fetches it)"
                           if offline and "no matching package" in err else "build failed")
                    for c, v in todo:
                        if c == n:
                            skipped.setdefault("%s@%s" % (c, v), why)
                todo = [(c, v) for c, v in todo if c not in blamed]
            # sign whatever compiled, but only claim the crates of a build that succeeded
            rlibs = _deps_rlibs(tdir, triple, pdir) if crates else []
            if not built_ok:
                for c, v in todo:
                    skipped.setdefault("%s@%s" % (c, v), "[%s] build did not finish" % profile)
                todo = []
            for c, v in todo:
                if (c, v) not in built_crates:
                    built_crates.append((c, v))
            e, st = sign_rlibs(rlibs, arch, budget.deadline)
            entries += e
            sources["crate_rlibs_" + profile] = st
            if rlibs and not st["signed"] and "lto" in PROFILES[profile]:
                notes.append("[%s] the crate rlibs of an LTO profile are LLVM bitcode (no machine "
                             "code to sign): only the linked exerciser contributes for it" % profile)
            log("[%s] crate rlibs: %d archives, %d signed" % (profile, st["archives"], st["signed"]))
            # 3) the linked std exerciser through recover_libfuncs.generate (the --gen path)
            if not exerciser:
                continue
            flags, how = _linker_setup(triple, tc.get("host"))
            if flags is None:
                notes.append("[%s] std exerciser not linked: %s (rlib signatures only)" % (profile, how))
                continue
            (proj / "Cargo.toml").write_text(render_manifest([], profile, tc.get("version")))
            if (proj / "Cargo.lock").exists():
                (proj / "Cargo.lock").unlink()
            cmd = [tc["cargo"], "rustc", "--bin", "rd_sigdb_exerciser", "--target", triple] + offline
            cmd += ["--release"] if profile == "release" else ["--profile", profile]
            cmd += ["--"] + flags
            rc, _out, err = run(cmd, budget.left(), benv, cwd=proj)
            exe = tdir / triple / pdir / ("rd_sigdb_exerciser" + (".exe" if "windows" in triple else ""))
            if rc != 0 or not exe.is_file():
                tail = " | ".join(err.strip().splitlines()[-2:])[-300:]
                notes.append("[%s] std exerciser link failed (%s): %s" % (profile, how, tail))
                continue
            db = L.generate([exe])
            n = 0
            for _tool, byarch in db.items():
                for a, lst in byarch.items():
                    if a == arch:
                        entries += lst
                        n += len(lst)
            sources["exerciser_" + profile] = {"signed": n, "linker": how}
            log("[%s] linked std exerciser: %d signatures" % (profile, n))
    return {"entries": entries, "std_entries": std_entries, "crates_built": built_crates,
            "crates_skipped": skipped, "sources": sources, "notes": notes}


LTO_HINT_RATE = 0.08    # measured (VALIDATION): exact-toolchain std rlib signatures name 15% of the
#                         function starts of a release build, 5% of the same program built fat-LTO


def std_hit_rate(path: Path, std_entries: list, arch: str) -> float | None:
    """Fraction of the binary's function starts the toolchain's own std rlib signatures name.
    Low with an exact toolchain = std was re-optimised (fat LTO / another opt-level)."""
    import lief
    import gen_runtime_sigs as G
    import recover_libfuncs as L
    try:
        b = lief.parse(str(path))
        text = next((s for s in b.sections if s.name in (".text", "__text")), None)
        if text is None:
            return None
        lo, hi = text.virtual_address, text.virtual_address + len(bytes(text.content))
        n = sum(1 for a in G.function_starts(b) if lo <= a < hi)
        if not n:
            return None
        hits = L.match_binary(Path(path), {"t": {arch: prune(std_entries)}}, tool="t")
        return round(len(hits) / n, 4)
    except Exception:
        return None


def _tool_key(tc: dict) -> str:
    """The DB group key recover_libfuncs._toolchain() derives for a binary of this toolchain."""
    import recover_rust_meta as M
    rel = M.rust_release(tc.get("commit")) if tc.get("commit") else None
    if isinstance(rel, dict) and rel.get("version"):
        return "rustc-" + rel["version"]
    if tc.get("commit"):
        return "commit-" + tc["commit"][:12]
    return "rustc-" + (tc.get("version") or "unknown")


def load_cached(path: Path) -> dict | None:
    try:
        d = json.loads(Path(path).read_text())
        return d if isinstance(d, dict) else None
    except (OSError, ValueError):
        return None


def write_db(path: Path, db: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp%d" % os.getpid())
    tmp.write_text(json.dumps(db, indent=0, sort_keys=False) + "\n")
    os.replace(tmp, path)                     # atomic: a reader never sees a half-written DB


def generate_for_binary(path: Path, *, allow_download=False, toolchain=None, profiles=("release",),
                        max_crates=DEFAULT_MAX_CRATES, timeout=DEFAULT_TIMEOUT, crates_override=None,
                        std_only=False, exerciser=True, dry_run=False, force=False, out=None,
                        log=lambda m: None) -> dict:
    """The whole pipeline for one binary. Returns a report dict (status: ok / cached / dry-run /
    missing / error)."""
    budget = Budget(timeout)
    facts = binary_facts(Path(path))
    key, dest = facts["key"], Path(out) if out else cache_path(facts["key"])
    report = {"file": str(path), "key": key, "db": str(dest), "facts": {
        k: facts[k] for k in ("rustc_commit", "rust_version", "triple", "is_rust")},
        "target": facts["target"], "crates_detected": ["%s@%s" % (n, v or "?") for n, v in facts["crates"]]}
    if not facts["triple"]:
        report.update(status="error", error="unsupported target (format/arch) for a Rust triple")
        return report
    crates = [(n, v) for n, v in (crates_override if crates_override is not None else facts["crates"])]
    skipped = {"%s@?" % n: "version unknown (no registry path in the binary)" for n, v in crates if not v}
    crates = [(n, v) for n, v in crates if v]
    if std_only:
        skipped.update({"%s@%s" % (n, v): "--std-only" for n, v in crates})
        crates = []
    if len(crates) > max_crates:
        skipped.update({"%s@%s" % (n, v): "over --max-crates %d" % max_crates for n, v in crates[max_crates:]})
        crates = crates[:max_crates]
    report["plan"] = {"crates": ["%s@%s" % c for c in crates], "skipped": skipped,
                      "profiles": list(profiles), "allow_download": allow_download}
    existing = load_cached(dest)
    if existing and not force:
        have = set((existing.get("__meta__") or {}).get("built", {}).get("profiles", []))
        if set(profiles) <= have:
            report.update(status="cached", meta=existing.get("__meta__"))
            return report
    if dry_run:
        report["plan"]["manifest"] = render_manifest(crates, list(profiles)[0], facts.get("rust_version"))
        report["status"] = "dry-run"
        return report
    env = _base_env(allow_download)
    tc, missing = resolve_toolchain(facts, toolchain, allow_download, env, budget, log)
    if missing or tc is None:
        report.update(status="missing", missing=missing)
        return report
    quality = match_quality(facts.get("rustc_commit"), facts.get("rust_version"), tc["commit"], tc["version"])
    log("toolchain %s (rustc %s, %s) -> match: %s" % (tc.get("name") or "PATH", tc["version"],
                                                       (tc["commit"] or "?")[:12], quality))
    res = build_and_sign(facts, tc, crates, list(profiles), env, budget, exerciser, log)
    arch = facts["target"]["arch"]
    tool = _tool_key(tc)
    meta = {"format": SIGDB_FORMAT, "key": key,
            "binary": {"rustc_commit": facts.get("rustc_commit"),
                       "rust_version": facts.get("rust_version"), "triple": facts["triple"],
                       "crates": report["crates_detected"]},
            "built": {"toolchain": tc.get("name"), "rustc_commit": tc["commit"],
                      "rust_version": tc["version"], "llvm": tc.get("llvm"), "triple": facts["triple"],
                      "arch": arch, "tool_key": tool, "profiles": list(profiles),
                      "crates": ["%s@%s" % c for c in res["crates_built"]],
                      "crates_skipped": dict(skipped, **res["crates_skipped"]),
                      "sources": res["sources"]},
            "toolchain_match": quality, "notes": res["notes"],
            "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    rate = std_hit_rate(Path(path), res["std_entries"], arch) if quality == "exact" else None
    meta["std_hit_rate"] = rate
    if rate is not None and rate < LTO_HINT_RATE and not any("lto" in PROFILES[p] for p in profiles):
        meta["notes"].append("only %.1f%% of the binary's functions match its own toolchain's std: it "
                             "looks LTO-built or built at another opt-level -- rerun with --profile "
                             "size-lto / speed-lto (merged into the same cached DB)" % (100 * rate))
    entries = res["entries"]
    if existing and not force and (existing.get("__meta__") or {}).get("built", {}).get("tool_key") == tool:
        old = (existing.get(tool) or {}).get(arch, [])
        entries = old + entries
        oldb = existing["__meta__"]["built"]
        meta["built"]["profiles"] = sorted(set(oldb.get("profiles", [])) | set(profiles))
        meta["built"]["crates"] = sorted(set(oldb.get("crates", [])) | set(meta["built"]["crates"]))
        meta["built"]["sources"] = dict(oldb.get("sources", {}), **res["sources"])
    entries = prune(entries)
    meta["signatures"] = len(entries)
    db = {"__meta__": meta, tool: {arch: entries}}
    if budget.left() <= 0:
        meta["notes"].append("time budget exhausted: the DB may be partial")
    write_db(dest, db)
    report.update(status="ok", meta=meta, signatures=len(entries))
    return report


# ---------------------------------------------------------------------------------------------
def _selftest():
    # target triples from (format, arch, abi)
    assert triple_from("ELF", "x86_64", "gnu") == "x86_64-unknown-linux-gnu"
    assert triple_from("ELF", "aarch64", "musl") == "aarch64-unknown-linux-musl"
    assert triple_from("ELF", "x86", "gnu") == "i686-unknown-linux-gnu"
    assert triple_from("PE", "x86_64", "gnu") == "x86_64-pc-windows-gnu"
    assert triple_from("PE", "x86", "msvc") == "i686-pc-windows-msvc"
    assert triple_from("MACHO", "aarch64", "darwin") == "aarch64-apple-darwin"
    assert triple_from("ELF", "aarch64", "android") == "aarch64-linux-android"
    assert triple_from("ELF", "mips", "gnu") is None
    # cache key: deterministic, order-independent, sensitive to toolchain / target / crates
    f = {"rust_version": "1.85.0", "rustc_commit": "4d91de4e48198da2e33413efdcd9cd2cc0c46688",
         "triple": "x86_64-unknown-linux-gnu", "crates": [("serde_json", "1.0.140"), ("regex", "1.11.1")]}
    k = cache_key(f)
    assert k.startswith("1.85.0-x86_64-unknown-linux-gnu-") and len(k.rsplit("-", 1)[1]) == 16, k
    assert cache_key(dict(f, crates=list(reversed(f["crates"])))) == k
    assert cache_key(dict(f, crates=[("serde_json", "1.0.141"), ("regex", "1.11.1")])) != k
    assert cache_key(dict(f, triple="aarch64-unknown-linux-musl")) != k
    assert cache_key(dict(f, rust_version=None)) .startswith("commit-4d91de4e4819-")
    assert cache_key(dict(f, rust_version=None, rustc_commit=None)).startswith("unknown-")
    assert cache_key(dict(f, triple="x/../../evil")).startswith("1.85.0-unknown-target-")
    # crate list: validated (TOML injection from rodata refused), weighted by panic sites
    meta = {"crates": {"serde_json": ["1.0.140"], "evil\"]\n[x": ["1.0.0"], "regex": ["1.11.1"],
                       "tokio": [], "bad": ["1.0.0\"; x"]},
            "panic_sites": [{"file": "/h/.cargo/registry/src/idx/regex-1.11.1/src/re.rs"}] * 3}
    cl = crate_list(meta)
    assert cl[0] == ("regex", "1.11.1"), cl
    assert ("tokio", None) in cl and ("bad", None) in cl and not any("evil" in n for n, _ in cl), cl
    man = render_manifest([("serde_json", "1.0.140"), ("serde_json", "1.0.100")], "size-lto", "1.85.0")
    assert 'd0_serde_json = { package = "serde_json", version = "=1.0.140" }' in man, man
    assert "d1_serde_json" in man and "[profile.size-lto]" in man and 'rust-version = "1.85.0"' in man
    for bad in [("a\"b", "1.0.0"), ("ok", "1.0.0\"\n[x]"), ("ok", None)]:
        try:
            render_manifest([bad], "release", None)
            raise AssertionError("accepted %r" % (bad,))
        except ValueError:
            pass
    # toolchain match quality
    c = "4d91de4e48198da2e33413efdcd9cd2cc0c46688"
    assert match_quality(c, "1.85.0", c, "1.85.0") == "exact"
    assert match_quality(c[:9], None, c, None) == "exact"
    assert match_quality(None, "1.85.0", None, "1.85.1") == "same-minor"
    assert match_quality(None, "1.85.0", None, "1.97.0") == "mismatch"
    assert match_quality(None, None, c, "1.85.0") == "unknown"
    # ar parsing: GNU (symtab, long-name table, /N refs) and BSD (#1/len) members
    def hdr(name: bytes, size: int) -> bytes:
        return name.ljust(16) + b"0".ljust(12) + b"0".ljust(6) + b"0".ljust(6) + b"644".ljust(8) \
            + str(size).encode().ljust(10) + b"`\n"
    longn = b"a_very_long_object_name.rcgu.o/\n"
    gnu = (b"!<arch>\n" + hdr(b"/", 4) + b"\0\0\0\0" + hdr(b"//", len(longn)) + longn
           + hdr(b"/0", 3) + b"abc" + b"\n" + hdr(b"lib.rmeta/", 2) + b"xy")
    assert list(ar_members(gnu)) == [("a_very_long_object_name.rcgu.o", b"abc"), ("lib.rmeta", b"xy")]
    msn = b"first.o\0second.dll\0"                       # (19 bytes: padded) MS/COFF archives NUL-terminate long names
    ms = b"!<arch>\n" + hdr(b"//", len(msn)) + msn + b"\n" + hdr(b"/0", 1) + b"A" + b"\n" + hdr(b"/8", 1) + b"B\n"
    assert list(ar_members(ms)) == [("first.o", b"A"), ("second.dll", b"B")], list(ar_members(ms))
    bsd = b"!<arch>\n" + hdr(b"#1/12", 12 + 4) + b"obj.o\0\0\0\0\0\0\0" + b"DATA"
    assert list(ar_members(bsd)) == [("obj.o", b"DATA")]
    assert list(ar_members(b"!<arch>\n" + hdr(b"x", 999) + b"short")) == []     # truncated: stop
    assert list(ar_members(b"not an archive")) == []
    # relocation masking: the relocated field + relaxable opcode bytes are wildcards
    assert _reloc_width("TYPE.X86_64_PLT32", 32, "x86_64") == (0, 4)
    assert _reloc_width("TYPE.X86_64_REX_GOTPCRELX", 32, "x86_64") == (3, 4)
    assert _reloc_width("TYPE.X86_64_GOTPCRELX", 32, "x86_64") == (2, 4)
    assert _reloc_width("TYPE.X86_64_64", 64, "x86_64") == (0, 8)
    assert _reloc_width("TYPE.AARCH64_ADD_ABS_LO12_NC", 12, "aarch64") == (0, 4)
    # x86-64: `mov rax,[rip+GOT]` (relaxable) + `call rel32` + ret, padded to 24 bytes
    code = bytes.fromhex("488b0500000000" "e800000000" "c3") + b"\x90" * 11
    pat = sign_function(code, {0, 1, 2, 3, 4, 5, 6}, "x86_64")
    assert pat.startswith(".." * 7 + "e8........c3"), pat
    assert sign_function(code[:10], set(), "x86_64") is None            # under MIN_SIZE
    assert _trim_padding(b"\xc3" + b"\xcc" * 3 + bytes.fromhex("0f1f440000"), "x86_64") == b"\xc3"
    assert _trim_padding(bytes.fromhex("c0035fd6" "1f2003d5" "00000000"), "aarch64") == bytes.fromhex("c0035fd6")
    # prune: duplicate (name, pattern) collapsed, a pattern with two names dropped
    es = [{"name": "a", "sym": "A", "pattern": "11"}, {"name": "a", "sym": "A2", "pattern": "11"},
          {"name": "b", "sym": "B", "pattern": "22"}, {"name": "c", "sym": "C", "pattern": "22"}]
    assert prune(es) == [es[0]], prune(es)
    # build-error attribution
    err = ("error: no matching package named `foo-bar` found\n"
           "error: failed to run custom build command for `ring v0.17.8`\n"
           "error: could not compile `serde_json` (lib) due to 2 previous errors\n")
    assert failing_crates(err) == ["foo-bar", "ring", "serde_json"], failing_crates(err)
    # cache dir honours the overrides
    old = {k: os.environ.get(k) for k in ("RUST_DEOBF_CACHE", "XDG_CACHE_HOME")}
    try:
        os.environ["RUST_DEOBF_CACHE"] = os.path.join("somewhere", "c")
        assert cache_dir() == Path("somewhere") / "c" / "sigdb"
        del os.environ["RUST_DEOBF_CACHE"]
        os.environ["XDG_CACHE_HOME"] = os.path.join("xdg")
        if os.name != "nt":
            assert cache_dir() == Path("xdg") / "rust-deobf" / "sigdb"
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    # a timed-out command is reported, not raised (budget already spent -> not even started)
    rc, _o, e = run([sys.executable, "-c", "pass"], 0)
    assert rc is None and "budget" in e
    print("selftest OK: triples, cache keys, crate validation, manifest, match quality, ar parsing, "
          "relocation masking, prune, error attribution, cache dir")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("binary", nargs="?")
    ap.add_argument("--allow-download", action="store_true",
                    help="allow rustup to install the toolchain/target and cargo to use the network")
    ap.add_argument("--toolchain", help="build with this rustup toolchain instead of the binary's own")
    ap.add_argument("--profile", default="release", choices=sorted(PROFILES) + ["all"])
    ap.add_argument("--max-crates", type=int, default=DEFAULT_MAX_CRATES)
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="total seconds")
    ap.add_argument("--crates", help="override the crate list: name@ver,name@ver")
    ap.add_argument("--std-only", action="store_true", help="sign std only; build no crates")
    ap.add_argument("--no-exerciser", action="store_true", help="skip the linked std exerciser")
    ap.add_argument("--dry-run", action="store_true", help="print the plan and the Cargo.toml only")
    ap.add_argument("--force", action="store_true", help="rebuild even if a cached DB exists")
    ap.add_argument("--out", help="write the DB here instead of the cache")
    ap.add_argument("--print-key", action="store_true", help="print the cache key/path and exit")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args(argv)
    if a.selftest:
        _selftest()
        return 0
    if not a.binary:
        ap.error("binary required (or --selftest)")
    path = Path(a.binary)
    if not path.is_file():
        print("no such file: %s" % path, file=sys.stderr)
        return 2
    if a.print_key:
        facts = binary_facts(path)
        r = {"key": facts["key"], "path": str(cache_path(facts["key"])),
             "exists": cache_path(facts["key"]).is_file()}
        print(json.dumps(r, indent=1) if a.json else "%s\n%s%s" % (r["key"], r["path"],
                                                                   "" if r["exists"] else "  (not built)"))
        return 0
    crates_override = None
    if a.crates is not None:
        crates_override = []
        for tok in filter(None, (t.strip() for t in a.crates.split(","))):
            name, _, ver = tok.partition("@")
            if not _CRATE_NAME.match(name) or (ver and not _VERSION.match(ver)):
                print("bad --crates entry: %r" % tok, file=sys.stderr)
                return 2
            crates_override.append((name, ver or None))
    profiles = sorted(PROFILES) if a.profile == "all" else [a.profile]
    log = (lambda m: print("  " + m, file=sys.stderr)) if not a.json else (lambda m: None)
    try:
        rep = generate_for_binary(path, allow_download=a.allow_download, toolchain=a.toolchain,
                                  profiles=profiles, max_crates=a.max_crates, timeout=a.timeout,
                                  crates_override=crates_override, std_only=a.std_only,
                                  exerciser=not a.no_exerciser, dry_run=a.dry_run, force=a.force,
                                  out=a.out, log=log)
    except Exception as e:                       # report, don't traceback, on a hostile file
        rep = {"file": str(path), "status": "error", "error": "%s: %s" % (type(e).__name__, e)}
    if a.json:
        print(json.dumps(rep, indent=1))
    else:
        st = rep.get("status")
        print("%s: %s" % (path, st))
        if rep.get("facts"):
            fa = rep["facts"]
            print("  binary: rustc %s (%s), %s; crates: %s" % (
                fa.get("rust_version") or "?", (fa.get("rustc_commit") or "?")[:12], fa.get("triple"),
                ", ".join(rep.get("crates_detected", [])) or "none detected"))
        if st == "missing":
            for m in rep["missing"]:
                print("  MISSING %s %s -> %s" % (m["what"], m["need"], m["fix"]))
        elif st == "dry-run":
            print("  would build: %s" % (", ".join(rep["plan"]["crates"]) or "std only"))
            for c, why in rep["plan"]["skipped"].items():
                print("  skip %s: %s" % (c, why))
            print(rep["plan"]["manifest"])
        elif st in ("ok", "cached"):
            m = rep.get("meta") or {}
            b = m.get("built", {})
            print("  DB %s\n  built with rustc %s (%s) for %s, profiles %s, toolchain match: %s"
                  % (rep["db"], b.get("rust_version"), (b.get("rustc_commit") or "?")[:12],
                     b.get("triple"), ",".join(b.get("profiles", [])), m.get("toolchain_match")))
            print("  %d signatures; crates built: %s" % (m.get("signatures", 0),
                                                         ", ".join(b.get("crates", [])) or "none"))
            for c, why in (b.get("crates_skipped") or {}).items():
                print("  skipped %s: %s" % (c, why))
            for n in m.get("notes", []):
                print("  note: %s" % n)
        elif st == "error":
            print("  error: %s" % rep.get("error"))
    return {"ok": 0, "cached": 0, "dry-run": 0, "missing": 3}.get(rep.get("status"), 1)


if __name__ == "__main__":
    sys.exit(main())
