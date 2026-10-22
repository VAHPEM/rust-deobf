"""disasm.py - linear disassembly of a whole code section.

capstone's `Cs.disasm()` stops at the first bytes it cannot decode. On AArch64 that happens
inside .text at literal pools, jump tables and `udf` padding: in the benchmark's stripped
AArch64 builds a plain `md.disasm(code, base)` covered only ~67% of .text, so every recoverer
silently ignored the last third of the program. `linear()` resumes past such bytes (one
instruction slot on AArch64, one byte on x86) and yields every decodable instruction.
"""
from __future__ import annotations

from capstone import CS_ARCH_ARM64


def linear(md, code: bytes, base: int, step: int | None = None):
    """Every instruction capstone can decode in `code` (mapped at `base`), in address order."""
    if step is None:
        step = 4 if md.arch == CS_ARCH_ARM64 else 1
    n = len(code)
    off = 0
    view = memoryview(code)
    while off < n:
        end = off
        for ins in md.disasm(bytes(view[off:]) if off else code, base + off):
            yield ins
            end = ins.address - base + ins.size
        off = end if end >= n else end + step


def coverage(md, code: bytes, base: int) -> float:
    """Fraction of `code` a single `md.disasm()` pass decodes (diagnostics)."""
    end = 0
    for addr, size, _, _ in md.disasm_lite(code, base):
        end = addr - base + size
    return end / len(code) if code else 1.0


def _selftest():
    from capstone import Cs, CS_MODE_LITTLE_ENDIAN
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    nop, ret, bad = bytes.fromhex("1f2003d5"), bytes.fromhex("c0035fd6"), b"\xff\xff\xff\xff"
    code = nop + ret + bad + nop + ret           # a literal-pool word in the middle
    assert [i.mnemonic for i in md.disasm(code, 0x1000)] == ["nop", "ret"]
    assert [(i.address, i.mnemonic) for i in linear(md, code, 0x1000)] == \
        [(0x1000, "nop"), (0x1004, "ret"), (0x100c, "nop"), (0x1010, "ret")]
    assert coverage(md, code, 0x1000) == 0.4
    print("selftest OK: linear disassembly resumes past undecodable words")


if __name__ == "__main__":
    import sys
    if "--selftest" in sys.argv:
        _selftest()
