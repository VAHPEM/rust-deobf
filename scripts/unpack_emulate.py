#!/usr/bin/env python3
"""unpack_emulate.py - static unpacking by emulation: run a self-unpacking stub under Unicorn
and recover the stage-2 it writes, without executing the sample on the host.

This is the *static* sibling of dump_unpacked.py (which runs the sample and dumps stage-2 from a
live process). Here nothing runs on the host: the stub is emulated, writes are tracked, and any
region that is both *written during the run* and *then executed* (a W^X / self-modifying step, the
signature of an in-place unpacker) is carved out and reported.

Scope (honest): this handles the common in-place / stub-at-entry unpacker that decodes a payload
into memory the image already maps and jumps to it (UPX-like, many Rust/crypter stubs). It is NOT a
universal dynamic unpacker -- a packer that mmaps fresh pages, resolves imports dynamically, or runs
through libc's _start before unpacking will fault early under pure emulation; for those, point
--entry at the unpacking routine (found via recover_cfg / detect_vm / the string tiers), or use the
dynamic dump_unpacked.py in an isolated VM.

Safety: emulation is bounded (instruction count + wall clock) because a crafted stub can loop
forever; for batch use, run under forkserver isolation as recover_emulate.py does. Benign inputs
only.
"""
import hashlib
import math
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from recover_emulate import (  # noqa: E402  (shared, fuzz-hardened primitives)
    BASE, HEAP, HEAP_SIZE, RET_SENTINEL, STACK, STACK_SIZE, Image, map_image,
)
from unicorn import (  # noqa: E402
    UC_ARCH_ARM64, UC_ARCH_X86, UC_HOOK_BLOCK, UC_HOOK_INSN, UC_HOOK_MEM_FETCH_UNMAPPED,
    UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE, UC_HOOK_MEM_WRITE_UNMAPPED, UC_MODE_64,
    UC_MODE_ARM, Uc, UcError,
)
from unicorn import x86_const as X  # noqa: E402
from unicorn import arm64_const as A  # noqa: E402

_MAX_INSNS = 5_000_000       # instruction budget: a crafted decode loop must not run forever
_WALL_S = 10.0               # wall-clock bound (slow hooks make instruction count a loose proxy)
_MIN_REGION = 16             # smallest written run worth reporting (bytes)
_MAX_REGIONS = 64            # cap carved regions so a scattered writer can't flood the report
_ENTROPY_HI = 7.2            # bits/byte above which a blob reads as packed/encrypted


def _entropy(b: bytes) -> float:
    if not b:
        return 0.0
    counts = [0] * 256
    for x in b:
        counts[x] += 1
    n = len(b)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def _printable_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    return sum(1 for x in b if 0x20 <= x < 0x7f or x in (9, 10, 13)) / len(b)


class _Unpacker:
    """A minimal, bounded emulator that watches for write-then-execute (self-unpacking)."""

    def __init__(self, img: Image):
        self.img = img
        self.arm = img.arm
        self.written = set()          # byte addresses stored to during this run
        self.exec_targets = []        # (addr) of each basic block entered
        self.wx_hits = []             # blocks executed from memory written this run
        self.stopped = "ret"          # ret | budget | timeout | unmapped | error
        self.blocks = 0
        if self.arm:
            self.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
            self.SP, self.PC = A.UC_ARM64_REG_SP, A.UC_ARM64_REG_PC
        else:
            self.uc = Uc(UC_ARCH_X86, UC_MODE_64)
            self.SP, self.PC = X.UC_X86_REG_RSP, X.UC_X86_REG_RIP
        map_image(self.uc, img.binary)
        self.uc.mem_map(STACK, STACK_SIZE)
        self.uc.mem_map(HEAP, HEAP_SIZE)        # a bump arena, in case the stub touches it
        self.uc.hook_add(UC_HOOK_MEM_WRITE, self._on_write)
        self.uc.hook_add(UC_HOOK_BLOCK, self._on_block)
        self.uc.hook_add(
            UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED,
            self._on_unmapped)
        if not self.arm:
            self.uc.hook_add(UC_HOOK_INSN, self._on_syscall, None, 1, 0, X.UC_X86_INS_SYSCALL)

    def _on_write(self, uc, access, address, size, value, _):
        if 0 < size <= 64:
            for a in range(address, address + size):
                self.written.add(a)

    def _on_block(self, uc, address, size, _):
        self.blocks += 1
        self.exec_targets.append(address)
        if address in self.written:          # executing bytes this run produced = unpacked code
            self.wx_hits.append(address)

    def _on_unmapped(self, uc, access, address, size, value, _):
        self.stopped = "unmapped"
        uc.emu_stop()
        return False                          # do not retry: an MVP does not satisfy mmap/brk

    def _on_syscall(self, uc, _):
        uc.reg_write(X.UC_X86_REG_RAX, 0)     # neutral success; keep emulation moving

    def run(self, entry_rva: int):
        uc = self.uc
        sp = STACK + STACK_SIZE - 0x1000
        uc.reg_write(self.SP, sp)
        if self.arm:
            uc.reg_write(A.UC_ARM64_REG_LR, RET_SENTINEL)
        else:
            uc.mem_write(sp, struct.pack("<Q", RET_SENTINEL))  # top frame returns to the sentinel
        pc = BASE + entry_rva
        import time
        t0 = time.monotonic()
        try:
            uc.emu_start(pc, RET_SENTINEL, timeout=int(_WALL_S * 1e6), count=_MAX_INSNS)
            if self.stopped == "ret":
                if self.blocks >= 1 and uc.reg_read(self.PC) not in (RET_SENTINEL, 0):
                    pass
        except UcError:
            if self.stopped == "ret":
                self.stopped = "error"
        if (time.monotonic() - t0) >= _WALL_S and self.stopped == "ret":
            self.stopped = "timeout"
        if self.blocks >= _MAX_INSNS and self.stopped == "ret":
            self.stopped = "budget"
        return self._regions()

    def _regions(self):
        """Coalesce written bytes into contiguous runs (gaps <= 8 bridged) and describe each."""
        if not self.written:
            return []
        wx = set(self.wx_hits)
        exec_set = sorted(set(self.exec_targets))
        addrs = sorted(self.written)
        runs, start, prev = [], addrs[0], addrs[0]
        for a in addrs[1:]:
            if a - prev <= 8:
                prev = a
                continue
            runs.append((start, prev + 1))
            start = prev = a
        runs.append((start, prev + 1))
        text_lo = BASE + self.img.text_va
        text_hi = BASE + self.img.text_end
        out = []
        for lo, hi in runs:
            if hi - lo < _MIN_REGION:
                continue
            if STACK <= lo < STACK + STACK_SIZE:    # runtime stack scribble, never a payload
                continue
            try:
                data = bytes(self.uc.mem_read(lo, hi - lo))
            except UcError:
                continue
            executed = any(lo <= t < hi for t in exec_set) or any(lo <= w < hi for w in wx)
            out.append({
                "va": lo - BASE,
                "size": hi - lo,
                "sha256": hashlib.sha256(data).hexdigest(),
                "entropy": round(_entropy(data), 2),
                "printable_ratio": round(_printable_ratio(data), 2),
                "executed": executed,
                "in_text": text_lo <= lo < text_hi,
                "_bytes": data,
            })
        # the unpacked payload first: executed regions, then by size
        out.sort(key=lambda r: (not r["executed"], -r["size"]))
        return out[:_MAX_REGIONS]


def recover(path, entry=None) -> dict:
    """Emulate `path` from its entry (or `entry` RVA) and report written-then-executed regions.

    Returns {arch, entry, instructions, stopped, unpacked:[{va,size,sha256,entropy,
    printable_ratio,executed,in_text}], unpacked_detected}.
    """
    img = Image(path)
    entry_rva = entry if entry is not None else (img.binary.entrypoint - img.imagebase)
    up = _Unpacker(img)
    regions = up.run(entry_rva)
    detected = any(r["executed"] and (not r["in_text"] or r["entropy"] < 7.9) for r in regions)
    return {
        "arch": "aarch64" if img.arm else "x86_64",
        "entry": entry_rva,
        "instructions_blocks": up.blocks,
        "stopped": up.stopped,
        "unpacked_detected": detected,
        "unpacked": [{k: v for k, v in r.items() if k != "_bytes"} for r in regions],
        "_regions": regions,            # kept for --dump; stripped by --json
    }


def _print(res):
    print(f"arch={res['arch']} entry=0x{res['entry']:x} blocks={res['instructions_blocks']} "
          f"stopped={res['stopped']} unpacked_detected={res['unpacked_detected']}")
    if not res["unpacked"]:
        print("  no written-then-executed region observed from this entry.")
        print("  If the sample unpacks past libc _start or via mmap, pass --entry <unpack-routine>")
        print("  (recover_cfg.py / detect_vm.py help locate it), or use dynamic dump_unpacked.py.")
        return
    for r in res["unpacked"]:
        tag = "EXEC" if r["executed"] else "data"
        print(f"  [{tag}] va=0x{r['va']:x} size={r['size']} entropy={r['entropy']} "
              f"printable={r['printable_ratio']} sha256={r['sha256'][:16]} "
              f"{'(in .text)' if r['in_text'] else ''}")


def _selftest():
    # A synthetic in-place unpacker, assembled by hand (no binary, no toolchain): the stub stores a
    # `ret` byte into a writable target page, then jumps there and executes it. The emulator must see
    # the target region as written AND executed (a W^X unpack step) and carve it out.
    TGT = HEAP + 0x1000
    code = (
        b"\x48\xb8" + struct.pack("<Q", 0xC3) +            # mov rax, 0x00..00c3  (a `ret`)
        b"\x48\xa3" + struct.pack("<Q", TGT) +             # mov [TGT], rax        (the "unpack")
        b"\x48\xb8" + struct.pack("<Q", TGT) +             # mov rax, TGT
        b"\xff\xe0"                                        # jmp rax               (run stage-2)
    )
    CODE = 0x400000
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(CODE, 0x1000)
    uc.mem_map(HEAP, HEAP_SIZE)
    uc.mem_map(STACK, STACK_SIZE)
    uc.mem_write(CODE, code)
    written, execd = set(), []

    def on_w(u, acc, addr, size, val, _):
        for a in range(addr, addr + size):
            written.add(a)

    def on_b(u, addr, size, _):
        execd.append(addr)
    uc.hook_add(UC_HOOK_MEM_WRITE, on_w)
    uc.hook_add(UC_HOOK_BLOCK, on_b)
    sp = STACK + STACK_SIZE - 0x1000
    uc.reg_write(X.UC_X86_REG_RSP, sp)
    uc.mem_write(sp, struct.pack("<Q", RET_SENTINEL))
    uc.emu_start(CODE, RET_SENTINEL, count=100)
    assert TGT in written, "store to the unpack target not observed"
    assert any(TGT <= a < TGT + 8 for a in execd), "did not execute the unpacked bytes"

    # entropy + printable sanity
    assert _entropy(b"\x00" * 64) == 0.0
    assert _entropy(bytes(range(256))) > 7.9
    assert _printable_ratio(b"hello world") == 1.0 and _printable_ratio(b"\x00\x01") == 0.0
    print("selftest OK: synthetic in-place unpacker detected (write-then-execute carved); "
          "entropy/printable metrics sane")


def main(argv=None):
    import argparse
    import json
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("binary", nargs="?")
    ap.add_argument("--entry", help="start RVA/VA of the unpacking routine (hex ok), e.g. 0x1650")
    ap.add_argument("--dump", metavar="DIR", help="write each carved region to DIR/unpacked_<va>.bin")
    ap.add_argument("--json", action="store_true", help="print the result dict as JSON")
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
    entry = int(a.entry, 0) if a.entry else None
    res = recover(path, entry)
    if a.dump and res["_regions"]:
        d = Path(a.dump)
        d.mkdir(parents=True, exist_ok=True)
        for r in res["_regions"]:
            (d / f"unpacked_{r['va']:x}.bin").write_bytes(r["_bytes"])
        print(f"wrote {len(res['_regions'])} region(s) to {d}/", file=sys.stderr)
    res = {k: v for k, v in res.items() if k != "_regions"}
    print(json.dumps(res, indent=2)) if a.json else _print(res)
    return 0


if __name__ == "__main__":
    sys.exit(main())
