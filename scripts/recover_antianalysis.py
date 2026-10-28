#!/usr/bin/env python3
"""recover_antianalysis.py - inventory a sample's anti-analysis techniques and build provenance.

An analyst's first questions about a hostile binary include "will it behave differently under a
debugger / in a sandbox / while emulated, and how was it built". This reports, defensively, the
evidence of such techniques so they can be anticipated (and so rust-deobf's own emulation knows what
may defeat it), plus the binary's provenance.

Evasion evidence (detection only -- the presence of the technique, not how to use it):
  * timing instructions: `rdtsc` / `rdtscp` (a timing gate can detect single-stepping / emulation);
  * `cpuid` (feature/hypervisor-presence checks);
  * the inline system-call instruction (`syscall` / `int 0x80` / `svc`): normal in a static musl
    build, but in a *dynamically* linked binary a high count means the sample reaches the kernel
    directly instead of through libc -- an import-table-evasion signal;
  * anti-debug / timing / sandbox APIs and artifacts by name (ptrace, IsDebuggerPresent,
    QueryPerformanceCounter, the TracerPid line of /proc/self/status, common VM vendor strings),
    matched as whole names / standalone strings, not substrings of longer identifiers. Timing APIs
    are a low-weight signal (`low_signal`), not a technique on their own.

Go binaries: the runtime and standard library carry raw syscalls, rdtsc/cpuid, `syscall.ptrace` and
a vdso `clock_gettime` lookup in every build, so code and names in Go std/runtime functions (located
via the pclntab, recover_go) are excluded and counted under `go_runtime_excluded`. If evasion
analysis fails (e.g. no code section), `evasion` is {"error": ...} and provenance is still reported.

Provenance: format, arch/bits, PIE, stripped, NX, RELRO, static/dynamic, source languages
(recover_lang), and the Rust toolchain when present (recover_rust_meta).

    python3 scripts/recover_antianalysis.py path/to/binary            # inventory + provenance
    python3 scripts/recover_antianalysis.py path/to/binary --json
    python3 scripts/recover_antianalysis.py --selftest
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

# anti-debug / timing / sandbox API names (import or referenced), lower-case
_EVASION_APIS = {
    "anti-debug": ("isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess",
                   "ptrace", "ntsetinformationthread", "outputdebugstring"),
    "timing": ("queryperformancecounter", "gettickcount", "clock_gettime", "timegettime",
               "ntdelayexecution"),
    "sandbox/vm": ("vmware", "virtualbox", "vbox", "qemu", "xen ", "kvm", "hypervisor",
                   "sbiedll", "sandboxie", "cuckoo", "/sys/class/dmi", "/proc/scsi/scsi"),
    "anti-debug-artifact": ("tracerpid", "/proc/self/status", "ptrace_traceme"),
}
# How much a category says on its own. Timing APIs are in nearly every program (any clock read), so
# they are reported as a low signal and do not make a "technique" by themselves.
_WEIGHT = {"anti-debug": "high", "anti-debug-artifact": "high", "sandbox/vm": "medium", "timing": "low"}
_API_SUFFIX = re.compile(r"(?:a|w|exa|exw|ex)?$")
_IDENT = b"abcdefghijklmnopqrstuvwxyz0123456789_"
_TOKEN = frozenset(b"abcdefghijklmnopqrstuvwxyz0123456789_./*-")
# Go runtime / standard-library packages: their syscall stubs (syscall.ptrace, runtime vdso
# clock_gettime lookups, internal/cpu cpuid, runtime.cputicks rdtsc, raw syscalls) are in EVERY Go
# binary and say nothing about the sample's intent.
_GO_STD_ROOTS = frozenset(("runtime", "internal", "syscall", "os", "time", "sync", "crypto", "net",
                           "reflect", "math", "hash", "vendor", "type:", "go:"))


def _go_std(name: str) -> bool:
    """Is a Go function / symbol name in the runtime or standard library (not the sample's code)?"""
    n = name.lower().lstrip("_")
    if n.startswith(("golang.org/x/", "vendor/", "type:", "go:")):
        return True
    first = n.split("/", 1)[0].split(".", 1)[0]
    return first in _GO_STD_ROOTS


def _count_insns(img, skip=None):
    """Counts of the evasion-relevant instructions in .text (capstone linear sweep with SKIPDATA,
    so an undecodable byte -- anti-disassembly junk -- does not end the sweep). `skip(address)`
    True excludes that instruction (Go runtime/std code); excluded hits are counted separately."""
    from capstone import Cs, CS_ARCH_X86, CS_ARCH_ARM64, CS_MODE_32, CS_MODE_64, CS_MODE_LITTLE_ENDIAN
    counts = {"rdtsc": 0, "rdtscp": 0, "cpuid": 0, "syscall": 0, "int80": 0, "svc": 0}
    excluded = 0
    if img.arm:
        md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    else:
        md = Cs(CS_ARCH_X86, CS_MODE_32 if img.x32 else CS_MODE_64)
    md.skipdata = True
    try:
        for insn in md.disasm(img.code, img.text_va):
            m = insn.mnemonic
            if m == "int":
                key = "int80" if insn.op_str.strip() in ("0x80", "0x2e") else None
            else:
                key = m if m in counts and m != "int80" else None
            if key is None:
                continue
            if skip is not None and skip(insn.address):
                excluded += 1
                continue
            counts[key] += 1
    except Exception:
        pass
    if skip is not None:
        counts["go_runtime_excluded"] = excluded
    return counts


def _blob_hits(blob: bytes, key: str, go: bool) -> bool:
    """Does `key` occur in the (lower-cased) file bytes as a string of its own -- not inside a longer
    identifier (`httptrace`, `runtime.ptraceState`), not as 4 chance bytes in compressed / random data
    (neighbours must be NUL, printable or the buffer edge), and, in a Go binary, not as a Go
    standard-library symbol (`syscall.ptrace`)?"""
    k = key.encode()
    i = blob.find(k)
    seen = 0
    while i != -1 and seen < 4096:
        seen += 1
        lo, hi = i - 1, i + len(k)
        left = blob[lo] if lo >= 0 else 0
        right = blob[hi] if hi < len(blob) else 0
        ok = True
        if k[0] in _IDENT and left in _IDENT:
            ok = False
        if k[-1] in _IDENT and right in _IDENT:
            ok = False
        for c in (left, right):
            if c != 0 and not (0x20 <= c < 0x7f) and c not in (0x09, 0x0a, 0x0d):
                ok = False
        if ok and go and left == 0x2e:                    # `pkg.key` -- whose package?
            j = lo
            while j > 0 and blob[j - 1] in _TOKEN:
                j -= 1
            if _go_std(blob[j:hi].decode("latin-1")):
                ok = False
        if ok:
            return True
        i = blob.find(k, i + 1)
    return False


def _name_hits(names, key: str) -> bool:
    """Does an imported / defined symbol name BE the API (modulo leading `_`, `@VERSION`, and the
    Windows A/W/Ex suffixes)? Substrings of longer identifiers do not count."""
    for nm in names:
        base = nm.split("@", 1)[0].lstrip("_")
        if base.startswith(key) and _API_SUFFIX.fullmatch(base[len(key):]):
            return True
    return False


def _is_dynamic(b) -> bool:
    try:
        if any(True for _ in b.libraries):
            return True
    except Exception:
        pass
    try:
        return b.has_interpreter   # ELF PT_INTERP => dynamically linked
    except Exception:
        return False


def _go_info(path):
    """(is_go, sorted [(start, name)], text_end) from the pclntab (recover_go); (False, [], None)
    otherwise. Addresses are in the toolkit's space (RVA for PE), like recover_emulate.Image."""
    try:
        import recover_go
        g = recover_go.recover(path)
    except Exception:
        return False, [], None
    if not g.get("is_go"):
        return False, [], None
    funcs = sorted((int(k, 16), v) for k, v in g.get("functions", {}).items())
    end = int(g["text_end"], 16) if g.get("text_end") else None
    return True, funcs, end


def _go_runtime_skip(gofuncs, text_end):
    """addr -> True when it lies in Go runtime / standard-library code: inside the Go text range
    (C code linked around it by cgo is outside and still counted) in a function whose package is
    std, or a package-less name (runtime assembly: `exit1`, `_rt0_arm64_darwin`, cgo glue)."""
    import bisect
    starts = [a for a, _n in gofuncs]
    lo = starts[0]
    hi = text_end if text_end is not None else None

    def skip(addr):
        if addr < lo or (hi is not None and addr >= hi):
            return False
        name = gofuncs[bisect.bisect_right(starts, addr) - 1][1]
        return _go_std(name) or "." not in name
    return skip


def evasion(path) -> dict:
    import recover_emulate
    img = recover_emulate.Image(path)
    b = img.binary
    is_go, gofuncs, go_end = _go_info(path)
    skip = _go_runtime_skip(gofuncs, go_end) if is_go and gofuncs else None
    counts = _count_insns(img, skip)
    # named APIs / artifacts
    names = []
    try:
        names += [s.name.lower() for s in b.symbols if s.name]
    except Exception:
        pass
    try:
        for imp in getattr(b, "imported_functions", []) or []:
            names.append(str(getattr(imp, "name", imp)).lower())
    except Exception:
        pass
    if is_go:
        names = [n for n in names if not _go_std(n)]
    blob = Path(path).read_bytes().lower()
    found_apis = {}
    for cat, keys in _EVASION_APIS.items():
        api = cat in ("anti-debug", "timing")
        hits = sorted({k.strip() for k in keys
                       if (api and _name_hits(names, k)) or _blob_hits(blob, k, is_go)})
        if hits:
            found_apis[cat] = hits

    dynamic = _is_dynamic(b)
    syscalls = counts["syscall"] + counts["int80"] + counts["svc"]
    techniques = []
    if counts["rdtsc"] or counts["rdtscp"]:
        techniques.append("timing-check (rdtsc)")
    if counts["cpuid"]:
        techniques.append("cpuid probe")
    # direct syscalls: only a signal in a dynamically-linked binary (static musl inlines them; a Go
    # binary's runtime makes raw syscalls by design, which `skip` already left out)
    likely_direct_syscalls = dynamic and syscalls >= 8
    if likely_direct_syscalls:
        techniques.append(f"direct syscalls ({syscalls}) in a dynamically-linked binary")
    low = []
    for cat, hits in found_apis.items():
        if _WEIGHT.get(cat) == "low":
            low.append(f"{cat}: {', '.join(hits)}")
        else:
            techniques.append(cat)
    out = {"instruction_counts": counts, "syscall_instructions": syscalls, "dynamic": dynamic,
           "likely_direct_syscalls": likely_direct_syscalls, "evasion_apis": found_apis,
           "api_weights": {c: _WEIGHT.get(c, "medium") for c in found_apis},
           "low_signal": low, "techniques": sorted(set(techniques)), "go_runtime_filtered": is_go}
    if img.text_fallback:
        out["code_section"] = img.text_fallback     # no .text: swept the entry's executable region
    return out


def provenance(path) -> dict:
    import lief
    b = lief.parse(str(path))
    fmt = b.format.name
    arch = "?"
    bits = 64
    try:
        import recover
        _f, arch, _ib = recover.detect(path)
    except Exception:
        pass
    bits = 32 if arch in ("x86", "arm") else 64
    pie = stripped = nx = relro = dynamic = None
    try:
        if fmt == "ELF":
            pie = str(b.header.file_type).endswith("DYN")
            stripped = not any(s.name == ".symtab" for s in b.sections)
            nx = any("GNU_STACK" in str(seg.type) and not (int(seg.flags) & 0x1) for seg in b.segments)
            relro = any("GNU_RELRO" in str(seg.type) for seg in b.segments)
            dynamic = b.has_interpreter
        elif fmt == "PE":
            dll = b.optional_header.dll_characteristics
            pie = bool(dll & 0x40)         # DYNAMIC_BASE (ASLR)
            nx = bool(dll & 0x100)         # NX_COMPAT
            stripped = True
            dynamic = True
    except Exception:
        pass
    langs, rust = [], None
    try:
        import recover_lang
        langs = recover_lang.recover(path).get("languages_present", [])
    except Exception:
        pass
    try:
        if "rust" in langs:
            import recover_rust_meta
            m = recover_rust_meta.recover(path)
            rel = m.get("rust_release") or {}
            rust = {"rustc_commit": m.get("rustc_commit"), "release": rel.get("version")}
    except Exception:
        pass
    return {"format": fmt, "arch": arch, "bits": bits, "pie": pie, "stripped": stripped,
            "nx": nx, "relro": relro, "dynamic": dynamic, "languages": langs, "rust": rust}


def recover(path) -> dict:
    """Provenance + evasion inventory. Either part failing (an unparseable header, a binary with no
    code section to sweep) is reported as {"error": ...} in its slot instead of raising, so the other
    part -- and the --json output -- survive."""
    out = {"file": str(path)}
    for key, fn in (("provenance", provenance), ("evasion", evasion)):
        try:
            out[key] = fn(path)
        except Exception as e:
            out[key] = {"error": f"{type(e).__name__}: {e}"[:200]}
    return out


def _print(res: dict) -> None:
    p, e = res["provenance"], res["evasion"]
    if "error" in p:
        print(f"provenance: error ({p['error']})")
        p = None
    if p is not None:
        _print_prov(p)
    if "error" in e:
        print(f"evasion: error ({e['error']})")
        return
    c = e["instruction_counts"]
    print(f"evasion instructions: rdtsc={c['rdtsc']} rdtscp={c['rdtscp']} cpuid={c['cpuid']} "
          f"syscall={e['syscall_instructions']} (direct-syscalls likely: {e['likely_direct_syscalls']})"
          + (f"  [Go runtime/std sites excluded: {c['go_runtime_excluded']}]"
             if "go_runtime_excluded" in c else ""))
    if e["evasion_apis"]:
        for cat, hits in e["evasion_apis"].items():
            print(f"  [{cat}, {e['api_weights'].get(cat, '?')}] " + ", ".join(hits))
    print("techniques: " + (", ".join(e["techniques"]) or "none detected"))


def _print_prov(p: dict) -> None:
    print(f"provenance: {p['format']}/{p['arch']} {p['bits']}-bit  pie={p['pie']} stripped={p['stripped']} "
          f"nx={p['nx']} relro={p['relro']} dynamic={p['dynamic']}  langs={','.join(p['languages'])}")
    if p.get("rust"):
        print(f"  rust: {p['rust'].get('release') or p['rust'].get('rustc_commit')}")


def _selftest():
    # hand-assembled x86-64 .text with rdtsc (0f 31), cpuid (0f a2), syscall (0f 05), int 0x80 (cd 80)
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64

    class FakeImg:
        arm = False
        x32 = False
        text_va = 0x1000
        code = bytes.fromhex("0f31" "0fa2" "0f05" "0f05" "cd80" "90" "c3")
    counts = _count_insns(FakeImg())
    assert counts["rdtsc"] == 1 and counts["cpuid"] == 1, counts
    assert counts["syscall"] == 2 and counts["int80"] == 1, counts
    # a clean stream (nops + ret) has none
    class Clean:
        arm = False; x32 = False; text_va = 0x1000; code = b"\x90" * 32 + b"\xc3"
    assert sum(_count_insns(Clean()).values()) == 0
    # the evasion-API table maps the expected categories
    assert "anti-debug" in _EVASION_APIS and "timing" in _EVASION_APIS and "sandbox/vm" in _EVASION_APIS
    print("selftest OK: evasion-instruction counting (rdtsc/cpuid/syscall/int0x80), clean stream "
          "zero, evasion-API categories present")


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("binary", nargs="?")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args(argv)
    if a.selftest:
        _selftest()
        return 0
    if not a.binary:
        ap.error("give a binary, or --selftest")
    path = Path(a.binary)
    if not path.is_file():
        ap.error(f"no such file: {path}")
    res = recover(path)
    print(json.dumps(res, indent=2)) if a.json else _print(res)
    return 0


if __name__ == "__main__":
    sys.exit(main())
