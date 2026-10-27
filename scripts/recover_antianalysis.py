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
    QueryPerformanceCounter, the TracerPid line of /proc/self/status, common VM vendor strings).

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

# anti-debug / timing / sandbox API names (import or referenced), lower-case substrings
_EVASION_APIS = {
    "anti-debug": ("isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess",
                   "ptrace", "ntsetinformationthread", "outputdebugstring"),
    "timing": ("queryperformancecounter", "gettickcount", "clock_gettime", "timegettime",
               "ntdelayexecution"),
    "sandbox/vm": ("vmware", "virtualbox", "vbox", "qemu", "xen ", "kvm", "hypervisor",
                   "sbiedll", "sandboxie", "cuckoo", "/sys/class/dmi", "/proc/scsi/scsi"),
    "anti-debug-artifact": ("tracerpid", "/proc/self/status", "ptrace_traceme"),
}


def _count_insns(img):
    """Counts of the evasion-relevant instructions in .text (capstone linear sweep)."""
    from capstone import Cs, CS_ARCH_X86, CS_ARCH_ARM64, CS_MODE_32, CS_MODE_64, CS_MODE_LITTLE_ENDIAN
    counts = {"rdtsc": 0, "rdtscp": 0, "cpuid": 0, "syscall": 0, "int80": 0, "svc": 0}
    if img.arm:
        md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    else:
        md = Cs(CS_ARCH_X86, CS_MODE_32 if img.x32 else CS_MODE_64)
    try:
        for insn in md.disasm(img.code, img.text_va):
            m = insn.mnemonic
            if m == "rdtsc":
                counts["rdtsc"] += 1
            elif m == "rdtscp":
                counts["rdtscp"] += 1
            elif m == "cpuid":
                counts["cpuid"] += 1
            elif m == "syscall":
                counts["syscall"] += 1
            elif m == "svc":
                counts["svc"] += 1
            elif m == "int" and insn.op_str.strip() in ("0x80", "0x2e"):
                counts["int80"] += 1
    except Exception:
        pass
    return counts


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


def evasion(path) -> dict:
    import recover_emulate
    import lief
    img = recover_emulate.Image(path)
    b = img.binary
    counts = _count_insns(img)
    # named APIs / artifacts
    names = []
    try:
        names += [s.name.lower() for s in b.symbols if s.name]
    except Exception:
        pass
    try:
        for imp in getattr(b, "imported_functions", []) or []:
            names.append(str(imp).lower())
    except Exception:
        pass
    blob = Path(path).read_bytes().lower()
    found_apis = {}
    for cat, keys in _EVASION_APIS.items():
        hits = sorted({k.strip() for k in keys
                       if any(k in nm for nm in names) or k.encode() in blob})
        if hits:
            found_apis[cat] = hits

    dynamic = _is_dynamic(b)
    syscalls = counts["syscall"] + counts["int80"] + counts["svc"]
    techniques = []
    if counts["rdtsc"] or counts["rdtscp"]:
        techniques.append("timing-check (rdtsc)")
    if counts["cpuid"]:
        techniques.append("cpuid probe")
    # direct syscalls: only a signal in a dynamically-linked binary (static musl inlines them)
    likely_direct_syscalls = dynamic and syscalls >= 8
    if likely_direct_syscalls:
        techniques.append(f"direct syscalls ({syscalls}) in a dynamically-linked binary")
    for cat in found_apis:
        techniques.append(cat)
    return {"instruction_counts": counts, "syscall_instructions": syscalls, "dynamic": dynamic,
            "likely_direct_syscalls": likely_direct_syscalls, "evasion_apis": found_apis,
            "techniques": sorted(set(techniques))}


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
    return {"file": str(path), "provenance": provenance(path), "evasion": evasion(path)}


def _print(res: dict) -> None:
    p, e = res["provenance"], res["evasion"]
    print(f"provenance: {p['format']}/{p['arch']} {p['bits']}-bit  pie={p['pie']} stripped={p['stripped']} "
          f"nx={p['nx']} relro={p['relro']} dynamic={p['dynamic']}  langs={','.join(p['languages'])}")
    if p.get("rust"):
        print(f"  rust: {p['rust'].get('release') or p['rust'].get('rustc_commit')}")
    c = e["instruction_counts"]
    print(f"evasion instructions: rdtsc={c['rdtsc']} rdtscp={c['rdtscp']} cpuid={c['cpuid']} "
          f"syscall={e['syscall_instructions']} (direct-syscalls likely: {e['likely_direct_syscalls']})")
    if e["evasion_apis"]:
        for cat, hits in e["evasion_apis"].items():
            print(f"  [{cat}] " + ", ".join(hits))
    print("techniques: " + (", ".join(e["techniques"]) or "none detected"))


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
