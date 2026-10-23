#!/usr/bin/env python3
"""gen_runtime_sigs.py - FLIRT-style byte signatures for the C runtime of static Rust builds.

Statically linked Rust binaries (the `*-linux-musl` targets) carry musl's own `malloc`, `free`,
`realloc`, `memcpy`, ... inside `.text`. Once stripped, nothing names them, and emulating musl's
`mallocng` in isolation fails: it needs the process state `__init_libc` sets up (auxv, page size,
random secret), so every allocation returns NULL and the decoded string is never built.
recover_emulate.py models these functions instead of running them; this script gives it a way to
find them in a stripped binary.

For each runtime function it takes the first bytes of the function in an *unstripped* build and
masks everything that depends on where things were linked: on AArch64 the whole word of
`adrp`/`adr`/`b`/`bl`/`cbz`/`tbz`/`b.cond`/literal `ldr`; on x86-64 the displacement and
immediate bytes of RIP-relative and relative-branch instructions. A signature is kept only if it
matches exactly one function start in every build it was generated from.

    python scripts/gen_runtime_sigs.py build/*elf-arm64*nostrip   # writes scripts/data/runtime_sigs.json
    python scripts/gen_runtime_sigs.py --selftest

The signatures describe the musl that rustc bundles (self-contained CRT); a toolchain that bundles
a different musl version may need them regenerated.
"""
from __future__ import annotations
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "scripts" / "data" / "runtime_sigs.json"
SIG_LEN = 64
# symbol name in the unstripped build -> the name recover_emulate models it as
TARGETS = {
    "__libc_malloc_impl": "malloc", "malloc": "malloc", "__libc_malloc": "malloc",
    "__libc_free": "free", "free": "free", "__libc_calloc": "calloc", "calloc": "calloc",
    "__libc_realloc": "realloc", "realloc": "realloc", "aligned_alloc": "aligned_alloc",
    "posix_memalign": "posix_memalign", "memcpy": "memcpy", "memmove": "memmove",
    "memset": "memset", "memcmp": "memcmp", "bcmp": "bcmp", "strlen": "strlen",
}
_ARM_PCREL = {"adrp", "adr", "b", "bl", "cbz", "cbnz", "tbz", "tbnz"}


def _arch(binary):
    m = (binary.header.machine_type.name if hasattr(binary.header, "machine_type")
         else str(binary.header.machine)).upper()
    return "aarch64" if "AARCH64" in m or "ARM64" in m else "x86_64"


def mask(code: bytes, va: int, arch: str) -> str:
    """Hex pattern of `code` with position-dependent bytes replaced by '..'."""
    from capstone import Cs, CS_ARCH_ARM64, CS_ARCH_X86, CS_MODE_64, CS_MODE_LITTLE_ENDIAN
    out = [f"{b:02x}" for b in code]
    if arch == "aarch64":
        md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        for off in range(0, len(code) - 3, 4):
            ins = next(md.disasm_lite(code[off:off + 4], va + off), None)
            if ins is None:
                continue
            mn = ins[2]
            if mn in _ARM_PCREL or mn.startswith("b.") or (mn.startswith("ldr") and "#0x" in ins[3]
                                                          and "[" not in ins[3]):
                out[off:off + 4] = [".."] * 4
        return "".join(out)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    for ins in md.disasm(code, va):
        o = ins.address - va
        rel = ins.group(7) or ins.group(2) or ins.group(1)        # relative branch / call / jump
        rip = "rip" in ins.op_str
        if rel or rip:
            start = ins.disp_offset if rip and ins.disp_offset else ins.imm_offset or 1
            for k in range(o + start, min(o + ins.size, len(out))):
                out[k] = ".."
    return "".join(out)


def matches(pattern: str, data: bytes) -> bool:
    n = len(pattern) // 2
    if len(data) < n:
        return False
    for i in range(n):
        p = pattern[2 * i:2 * i + 2]
        if p != ".." and int(p, 16) != data[i]:
            return False
    return True


def function_starts(binary):
    import recover_emulate as E
    starts = set(E._eh_frame_starts(binary))
    starts.update(s.value for s in binary.symbols if s.value and getattr(s, "is_function", False))
    return starts


def generate(paths):
    import lief
    sigs = {}
    seen = {}
    for p in paths:
        b = lief.parse(str(p))
        arch = _arch(b)
        text = next(s for s in b.sections if s.name == ".text")
        code, base = bytes(text.content), text.virtual_address
        starts = function_starts(b)
        for sym in b.symbols:
            if sym.name not in TARGETS or not sym.value or not base <= sym.value < base + len(code):
                continue
            size = sym.size or SIG_LEN
            if size < 16:
                continue                      # a 4-byte `b impl` alias: sign the implementation
            n = min(SIG_LEN, size)
            off = sym.value - base
            pat = mask(code[off:off + n], sym.value, arch)
            if pat.count("..") > len(pat) // 4:
                continue
            hits = [a for a in starts if base <= a < base + len(code)
                    and matches(pat, code[a - base:a - base + n])]
            if hits != [sym.value]:
                continue                      # not unique in this build
            key = (arch, TARGETS[sym.name], pat)
            seen.setdefault(key, set()).add(str(p))
    for (arch, name, pat), files in seen.items():
        if len(files) == len([p for p in paths if _arch(__import__("lief").parse(str(p))) == arch]):
            sigs.setdefault(arch, []).append({"name": name, "pattern": pat})
    return sigs


def _selftest():
    # AArch64: `adrp x0, #page` (0x90000000) masked, `ret` kept
    pat = mask(bytes.fromhex("00000090c0035fd6"), 0x1000, "aarch64")
    assert pat == "........c0035fd6", pat
    # x86-64: `lea rax, [rip+0x10]` disp masked, `call rel32` imm masked, `ret` kept
    pat = mask(bytes.fromhex("488d0510000000e800000000c3"), 0x1000, "x86_64")
    assert pat == "488d05........e8........c3", pat
    assert matches("48..c3", bytes.fromhex("4899c3ff")) and not matches("48..c3", bytes.fromhex("4899c2"))
    print("selftest OK: position-dependent bytes masked, patterns match with wildcards")


def main():
    if "--selftest" in sys.argv:
        _selftest()
        return
    sys.path.insert(0, str(ROOT / "scripts"))
    paths = [Path(a) for a in sys.argv[1:]]
    if not paths:
        sys.exit("usage: gen_runtime_sigs.py <unstripped static builds...>")
    sigs = generate(paths)
    old = json.loads(OUT.read_text()) if OUT.exists() else {}
    old.update(sigs)
    OUT.write_text(json.dumps(old, indent=1) + "\n")
    for arch, lst in sigs.items():
        print(arch, sorted({s["name"] for s in lst}), len(lst), "signatures")


if __name__ == "__main__":
    main()
