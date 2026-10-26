#!/usr/bin/env python3
"""recover_types.py - recover Rust type layout facts from a binary, for a decompiler's data types.

The "beyond strings" tier aimed at a decompiler (Ghidra): academic Rust decompilers put obfuscation
out of scope, so rust-deobf is the obfuscation-resilient front end whose recovered facts feed them.
The first, most concrete fact is the **trait-object vtable**. Every `dyn Trait` pointer in Rust is a
fat pointer (data, vtable), and the vtable is a fixed, recognisable record in read-only data:

    [ drop_in_place: fn(*mut T),  size: usize,  align: usize,  method_0: fn, method_1: fn, ... ]

Recovering those lets a decompiler resolve dynamic dispatch (which function a `dyn Trait` call
reaches), label each vtable, and recover the concrete type's size/align and its method set -- turning
a wall of `FUN_`/`DAT_` into named methods behind a trait. The layout is position-independent across
x86-64 / AArch64 and ELF / PE / Mach-O (only the pointer width and relocation form differ), so one
recogniser covers them, reusing the emulator's relocation resolver so the vtable slots hold real
addresses (a PIE stores them as relocation addends / chained fixups, 0 in the raw file).

    python3 scripts/recover_types.py path/to/binary              # human-readable
    python3 scripts/recover_types.py path/to/binary --json       # {vtables, ghidra_types} records
    python3 scripts/recover_types.py --selftest

This is a first tier: it recovers vtables (and the type size/align they carry). Enum-discriminant
and Option/Result niche-layout recovery from `match` jump tables is the next tier. ghidra_annotate.py
applies the recovered vtables as Ghidra structs and names the method functions.
"""
from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

# a plausible Rust type's size/align: align is a power of two up to a page, size is a multiple of
# align and not absurd. These bounds are what tell a real vtable from a coincidental run of pointers.
_ALIGNS = {1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096}
_MAX_SIZE = 1 << 20          # a Rust type's size; a vtable records the concrete type's size
_MAX_METHODS = 256

# vtables live in read-only / relocated data, not in the symbol/hash/reloc metadata sections (whose
# pointer-shaped bytes otherwise produce false "vtables" with absurd sizes). Restrict the scan to the
# data sections where a `dyn Trait` vtable is actually emitted, per format.
_TYPE_SECTIONS = {
    "ELF": (".data.rel.ro", ".data.rel.ro.local", ".rodata", ".data", ".ldata"),
    "PE": (".rdata", ".data"),
    "MACHO": ("__const", "__data", "__const_coal", "__data_coal", "__objc_const"),
}


def _is_type_section(name: str, fmt: str) -> bool:
    for base in _TYPE_SECTIONS.get(fmt, (".rodata", ".data")):
        if name == base:
            return True
    return False


def _resolver(img):
    """A function va -> resolved pointer value, over the non-executable data sections, applying the
    emulator's relocation patches (so PIE slots / chained fixups read as real addresses)."""
    ptr = img.ptr
    unpack = "<I" if ptr == 4 else "<Q"
    fmt = getattr(img, "fmt", "ELF")
    secs = []
    for s in img.binary.sections:
        va = s.virtual_address
        if not va or img._exec_sec(s) or not _is_type_section(s.name, fmt):
            continue
        secs.append((va, bytes(s.content)))
    secs.sort()
    patches = img.patches

    def read(va):
        if va in patches:
            return patches[va] & ((1 << (8 * ptr)) - 1)
        for base, raw in secs:
            o = va - base
            if 0 <= o <= len(raw) - ptr:
                return struct.unpack_from(unpack, raw, o)[0]
        return None

    return read, secs


def _exec(img, va):
    if va is None:
        return False
    return img.text_va <= va < img.text_end or any(lo <= va < hi for lo, hi in img.exec_ranges)


def recover(path) -> dict:
    """Recover vtables and the type facts they carry. Returns {arch, format, vtables, ghidra_types}."""
    import recover_emulate
    img = recover_emulate.Image(path)
    ptr = img.ptr
    read, secs = _resolver(img)
    vtables = []
    claimed = []     # (lo, hi) spans already taken by an accepted vtable, so its interior method
    #                  pointers are not re-read as the start of another vtable

    def in_claimed(va):
        return any(lo <= va < hi for lo, hi in claimed)

    for base, raw in secs:
        n = len(raw) // ptr
        for i in range(n):
            va = base + i * ptr
            if in_claimed(va):
                continue
            drop = read(va)
            size = read(va + ptr)
            align = read(va + 2 * ptr)
            if not (_exec(img, drop) and size is not None and align in _ALIGNS):
                continue
            if size > _MAX_SIZE or (align and size % align != 0):
                continue
            m0 = read(va + 3 * ptr)
            if not _exec(img, m0):                     # a vtable has at least one method slot
                continue
            methods = []
            k = 3
            while k < 3 + _MAX_METHODS:
                p = read(va + k * ptr)
                if not _exec(img, p):
                    break
                methods.append(p)
                k += 1
            vt = {"va": va, "drop_in_place": drop, "size": size, "align": align,
                  "methods": methods, "method_count": len(methods)}
            vtables.append(vt)
            claimed.append((va, va + (3 + len(methods)) * ptr))

    return {"format": img.fmt, "arch": ("aarch64" if img.arm else ("x86" if img.x32 else "x86_64")),
            "ptr": ptr, "vtables": vtables, "ghidra_types": _ghidra_types(vtables, ptr)}


def _ghidra_types(vtables, ptr: int) -> list:
    """One Ghidra struct datatype per distinct method-count: the vtable record for a `dyn Trait` with
    that many methods. Fields are at explicit byte offsets so ghidra_annotate can lay them on the
    vtable address and resolve the dynamic-dispatch call sites to the method functions."""
    by_count = {}
    for vt in vtables:
        by_count.setdefault(vt["method_count"], 0)
        by_count[vt["method_count"]] += 1
    utype = "uint" if ptr == 4 else "ulong"
    out = []
    for count in sorted(by_count):
        fields = [{"offset": 0, "name": "drop_in_place", "type": "pointer"},
                  {"offset": ptr, "name": "size", "type": utype},
                  {"offset": 2 * ptr, "name": "align", "type": utype}]
        for m in range(count):
            fields.append({"offset": (3 + m) * ptr, "name": f"method_{m}", "type": "pointer"})
        out.append({"name": f"RustVtable_{count}m", "size": (3 + count) * ptr,
                    "fields": fields, "instances": by_count[count]})
    return out


def _print(res: dict) -> None:
    print(f"format={res['format']}  arch={res['arch']}  vtables={len(res['vtables'])}")
    for vt in sorted(res["vtables"], key=lambda v: v["va"]):
        ms = " ".join(f"0x{m:x}" for m in vt["methods"][:6])
        more = f" (+{vt['method_count'] - 6} more)" if vt["method_count"] > 6 else ""
        print(f"  vtable 0x{vt['va']:x}  drop=0x{vt['drop_in_place']:x}  size={vt['size']} "
              f"align={vt['align']}  {vt['method_count']} method(s): {ms}{more}")
    if res["ghidra_types"]:
        print("ghidra datatypes:")
        for t in res["ghidra_types"]:
            print(f"  {t['name']} ({t['size']} bytes, {len(t['fields'])} fields) x{t['instances']}")


def _selftest():
    # Synthetic resolver test: a hand-built .data.rel.ro-like buffer with one real vtable and
    # several decoys (a run of data pointers; a bad align; size not a multiple of align). Only the
    # real vtable must be recovered. We drive recover()'s inner logic via a tiny fake Image.
    ptr = 8
    TEXTLO, TEXTHI = 0x1000, 0x2000      # "executable" range
    base = 0x10000
    S = 0x90000                           # a non-executable sentinel (terminates method lists)
    words = []

    def add(*vs):
        words.extend(vs)
    # [0] real vtable: drop(code), size 16, align 8, 2 method code ptrs
    vt_va = base + 0 * ptr
    add(0x1100, 16, 8, 0x1200, 0x1300)
    add(S)                                # terminates the method list at 2
    # [6] decoy: align 3 (not a power of two) -> rejected
    add(0x1100, 16, 3, 0x1200)
    add(S)
    # [11] decoy: align 8 but size 20 (not a multiple of 8) -> rejected
    add(0x1100, 20, 8, 0x1200)
    add(S)
    # [16] second real vtable: drop, size 0 (a ZST is legal), align 1, 1 method
    vt2_va = base + 16 * ptr
    add(0x1180, 0, 1, 0x1280)
    add(S)
    raw = b"".join(struct.pack("<Q", w & 0xffffffffffffffff) for w in words)

    class FakeSec:
        def __init__(self, va, content):
            self.virtual_address = va
            self.content = content
            self.name = ".data.rel.ro"

    class FakeBin:
        sections = [FakeSec(base, raw)]

    class FakeImg:
        binary = FakeBin()
        ptr = 8
        fmt = "ELF"
        arm = False
        x32 = False
        text_va = TEXTLO
        text_end = TEXTHI
        exec_ranges = []
        patches = {}

        def _exec_sec(self, s):
            return False

    import recover_types as RT
    # monkeypatch Image for the duration
    import recover_emulate
    orig = recover_emulate.Image
    recover_emulate.Image = lambda _p: FakeImg()
    try:
        res = RT.recover("ignored")
    finally:
        recover_emulate.Image = orig
    got = {vt["va"]: vt for vt in res["vtables"]}
    assert vt_va in got and vt2_va in got, sorted(hex(v) for v in got)
    assert len(got) == 2, [hex(v) for v in got]             # exactly the two real vtables
    assert got[vt_va]["size"] == 16 and got[vt_va]["align"] == 8 and got[vt_va]["method_count"] == 2
    assert got[vt2_va]["size"] == 0 and got[vt2_va]["align"] == 1 and got[vt2_va]["method_count"] == 1
    # the decoy regions produced no vtable
    assert all(v not in got for v in (base + 5 * ptr, base + 10 * ptr, base + 15 * ptr))
    # ghidra datatypes: a struct per method-count, fields at the right offsets
    gt = {t["name"]: t for t in res["ghidra_types"]}
    assert "RustVtable_2m" in gt and "RustVtable_1m" in gt
    t2 = gt["RustVtable_2m"]
    assert t2["size"] == 5 * ptr and t2["fields"][0] == {"offset": 0, "name": "drop_in_place", "type": "pointer"}
    assert t2["fields"][1]["name"] == "size" and t2["fields"][1]["offset"] == ptr
    assert t2["fields"][-1] == {"offset": 4 * ptr, "name": "method_1", "type": "pointer"}
    print("selftest OK: vtable recovery ([drop,size,align,methods]) rejects 3 decoy shapes, "
          "handles a ZST vtable, and emits a Ghidra struct per method-count")


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
    if a.json:
        print(json.dumps(res, indent=2))
    else:
        _print(res)
    return 0


if __name__ == "__main__":
    sys.exit(main())
