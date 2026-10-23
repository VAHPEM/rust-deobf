"""disasm.py - linear disassembly of a whole code section.

capstone's `Cs.disasm()` stops at the first bytes it cannot decode. On AArch64 that happens
inside .text at literal pools, jump tables and `udf` padding: in the benchmark's stripped
AArch64 builds a plain `md.disasm(code, base)` covered only ~67% of .text, so every recoverer
silently ignored the last third of the program. `linear()` resumes past such bytes (one
instruction slot on AArch64, one byte on x86) and yields every decodable instruction.
"""
from __future__ import annotations

from capstone import CS_ARCH_ARM64


CHUNK = 0x10000      # bytes per capstone call: cs_disasm materialises a whole buffer at once


def _walk(fn, code: bytes, base: int, step: int):
    """Drive `fn(buffer, address)` (md.disasm or md.disasm_lite) over `code` in CHUNK-sized
    pieces, resuming past undecodable bytes. capstone decodes the whole buffer it is given
    before yielding anything (with `detail`, ~1.5 KB per instruction), which on an 8 MB .text
    is gigabytes; chunks bound that. An instruction cut by a chunk boundary simply fails to
    decode at the end of its chunk and is decoded again at the start of the next one."""
    n = len(code)
    off = 0
    view = memoryview(code)
    while off < n:
        stop = min(n, off + CHUNK)
        end = off
        for ins in fn(bytes(view[off:stop]), base + off):
            yield ins
            a, sz = (ins[0], ins[1]) if isinstance(ins, tuple) else (ins.address, ins.size)
            end = a - base + sz
        if end >= n:
            break
        if stop < n and stop - end < 16 and end > off:
            off = end              # stopped at the chunk boundary, not at undecodable bytes
        else:
            off = end + step


def linear(md, code: bytes, base: int, step: int | None = None):
    """Every instruction capstone can decode in `code` (mapped at `base`), in address order."""
    if step is None:
        step = 4 if md.arch == CS_ARCH_ARM64 else 1
    yield from _walk(md.disasm, code, base, step)


class _Ins:
    """One instruction of an `Insns` list: address, size, mnemonic and op_str are stored; any
    other attribute (operands, reg_name, regs_access, ...) decodes it fully on first use."""
    __slots__ = ("_seq", "_i", "address", "size", "mnemonic", "op_str", "_f")

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        try:
            f = object.__getattribute__(self, "_f")
        except AttributeError:
            f = self._f = self._seq._full(self._i)
        return getattr(f, name)

    def __repr__(self):
        return f"<{self.address:#x}: {self.mnemonic} {self.op_str}>"


class Insns:
    """`list(linear(md, code, base))` without the memory: a compact table of every decodable
    instruction (address, size, mnemonic, operand text) with full capstone details decoded on
    demand, a few thousand kept. Indexing, len() and iteration behave like the list."""

    def __init__(self, md, code: bytes, base: int, step: int | None = None):
        from array import array
        from capstone import Cs
        self.md, self.code, self.base = md, code, base
        if step is None:
            step = 4 if md.arch == CS_ARCH_ARM64 else 1
        lite = Cs(md.arch, md.mode)            # no detail: cheap first pass
        self.addr, self.size, self.mn, self.ops = array("Q"), bytearray(), array("H"), []
        names, self.names = {}, []
        for a, sz, mn, ops in _walk(lite.disasm_lite, code, base, step):
            k = names.get(mn)
            if k is None:
                k = names[mn] = len(self.names)
                self.names.append(mn)
            self.addr.append(a)
            self.size.append(sz)
            self.mn.append(k)
            self.ops.append(ops)
        self._cache = {}

    def __len__(self):
        return len(self.addr)

    def index_map(self):
        """{address: index} of every instruction."""
        return dict(zip(self.addr, range(len(self.addr))))

    def _direct_calls(self):
        """{target: [indices]} of direct calls (`call 0x...` / `bl #0x...`), from the operand
        text alone: recognisers ask "who calls the decoder?" once per decoder, and decoding
        every call of a 40 MB binary in full each time took minutes."""
        calls = getattr(self, "_calls", None)
        if calls is None:
            calls = self._calls = {}
            want = {k for k, n in enumerate(self.names) if n in ("call", "bl")}
            for i, (k, ops) in enumerate(zip(self.mn, self.ops)):
                if k in want and ops.startswith(("0x", "#0x")):
                    try:
                        t = int(ops.lstrip("#"), 16)
                    except ValueError:
                        continue
                    calls.setdefault(t, []).append(i)
        return calls

    def calls_to(self, target):
        """Indices of the direct calls to `target`, in address order."""
        return self._direct_calls().get(target, [])

    def call_targets(self):
        """Every direct call target (with repeats, like scanning the calls)."""
        return [t for t, idx in self._direct_calls().items() for _ in idx]

    def _full(self, i):
        f = self._cache.get(i)
        if f is None:
            a = self.addr[i]
            off = a - self.base
            f = next(self.md.disasm(self.code[off:off + self.size[i]], a, 1))
            if len(self._cache) > 4096:
                self._cache.clear()
            self._cache[i] = f
        return f

    def __getitem__(self, i):
        if isinstance(i, slice):
            return [self[k] for k in range(*i.indices(len(self)))]
        if i < 0:
            i += len(self)
        if not 0 <= i < len(self.addr):
            raise IndexError(i)
        x = _Ins.__new__(_Ins)
        x._seq, x._i = self, i
        x.address, x.size = self.addr[i], self.size[i]
        x.mnemonic, x.op_str = self.names[self.mn[i]], self.ops[i]
        return x

    def __iter__(self):
        for i in range(len(self.addr)):
            yield self[i]


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
    md.detail = True
    seq = Insns(md, code, 0x1000)
    assert [(i.address, i.mnemonic) for i in seq] == [(0x1000, "nop"), (0x1004, "ret"),
                                                      (0x100c, "nop"), (0x1010, "ret")]
    assert seq[-1].address == 0x1010 and seq[1].id == list(md.disasm(ret, 0))[0].id
    # chunk boundaries: the same instructions whatever the chunk size
    from capstone import CS_ARCH_X86, CS_MODE_64
    import os
    global CHUNK
    x = Cs(CS_ARCH_X86, CS_MODE_64)
    blob = os.urandom(5000)
    want = [(i.address, i.size) for i in linear(x, blob, 0)]
    old, CHUNK = CHUNK, 37
    try:
        got = [(i.address, i.size) for i in linear(x, blob, 0)]
        assert got[:len(want)] == want or set(want) <= set(got), "chunked walk lost instructions"
    finally:
        CHUNK = old
    print("selftest OK: linear disassembly resumes past undecodable words; chunked; lazy Insns")


if __name__ == "__main__":
    import sys
    if "--selftest" in sys.argv:
        _selftest()
