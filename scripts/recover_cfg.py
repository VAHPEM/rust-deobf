#!/usr/bin/env python3
"""recover_cfg.py - a resolved call graph and a code-coverage metric, beyond strings.

rust-deobf's headline numbers are about strings. This measures and raises *code* coverage: it builds
the call graph, resolves the indirect control flow that normally leaves it full of holes, and reports
how much of the binary that actually reaches.

What it resolves:
  * direct calls  -> internal edges (caller -> callee) and import edges (call into a named import);
  * address-taken functions -- a function whose address is loaded (`lea reg,[rip+fn]`, a relocation
    pointing at it, a vtable slot) is a root: `main` is reached this way (the start glue passes its
    address to `__libc_start_main`), and so are callbacks and closures, which a naive "reachable from
    the entry point by direct calls" sweep misses entirely;
  * dynamic dispatch -- a `dyn Trait` call is a `call [vtable+off]`; using recover_types' recovered
    vtables, a function that takes a vtable's address can reach that vtable's methods, so those edges
    (and the methods behind the trait) are added instead of being dropped as `call rax`.

The coverage metric then reports functions reachable from the realistic root set over direct +
dispatch edges, and how many indirect call sites resolved to an import vs. stayed opaque -- turning
"code coverage" into a number, and showing the lift that resolving indirect flow buys over a
direct-edges-from-entry-only sweep.

    python3 scripts/recover_cfg.py path/to/binary            # summary + coverage
    python3 scripts/recover_cfg.py path/to/binary --json
    python3 scripts/recover_cfg.py --selftest

x86-64 and 32-bit x86 (direct calls, rip-relative address-taken, dispatch) and AArch64 (direct `bl`,
adrp+add / adrp+ldr address-taken, dispatch). Calls through a PLT / `.plt.sec` jump stub are resolved
to the import they jump to on both architectures, and a tail call (`b` / `jmp` to another function's
start) counts as an edge.
"""
from __future__ import annotations

import json
import struct
import sys
from collections import deque
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))


def _stub_import(img, va, cache):
    """If `va` is an import jump stub (ELF PLT / .plt.sec entry, or a PE `jmp [slot]` thunk), return
    the GOT/IAT slot it jumps through; else None. Static: decodes the stub bytes, no emulation.
      AArch64:  [bti c] adrp x16, page ; ldr x17, [x16, #off] ; ... br x17
      x86-64:   [endbr64] [bnd] jmp [rip+disp32]
      x86-32:   jmp [abs32]
    """
    if va in cache:
        return cache[va]
    slot = None
    try:
        b = img.read_any(va, 16)
        if img.arm and len(b) >= 12:
            w = list(struct.unpack("<%dI" % (len(b) // 4), b[:len(b) // 4 * 4]))
            if w and w[0] == 0xd503245f:            # bti c
                w = w[1:]
            if len(w) >= 2 and (w[0] & 0x9f00001f) == 0x90000010 \
                    and (w[1] & 0xffc003ff) == (0xf9400000 | (16 << 5) | 17):
                immlo, immhi = (w[0] >> 29) & 3, (w[0] >> 5) & 0x7ffff
                imm = (immhi << 2) | immlo
                if imm & (1 << 20):
                    imm -= 1 << 21
                page = (va & ~0xfff) + (imm << 12)
                slot = page + ((w[1] >> 10) & 0xfff) * 8
        elif not img.arm and len(b) >= 6:
            o = 4 if b[:4] == b"\xf3\x0f\x1e\xfa" else 0     # endbr64 / endbr32
            if b[o:o + 1] == b"\xf2":                       # bnd prefix
                o += 1
            if b[o:o + 2] == b"\xff\x25" and len(b) >= o + 6:
                d = struct.unpack("<i", b[o + 2:o + 6])[0]
                slot = (d & 0xffffffff) if img.x32 else va + o + 6 + d
    except Exception:
        slot = None
    cache[va] = slot
    return slot


def _arm_xreg(name):
    """Normalize an AArch64 register name so a W write invalidates the X register it aliases."""
    if name and name[0] == "w" and name[1:].isdigit():
        return "x" + name[1:]
    return name


def _disasm_calls(img, starts):
    """Per function, classify control flow. Returns:
      edges[fn] = set(internal callee starts)
      import_sites[fn] = [import name...]            (direct or GOT-slot calls into a known import)
      indirect[fn] = count of unresolved indirect calls (call reg / call [reg+..])
      taken = set(function starts whose address is loaded somewhere -> roots)
      vtref[fn] = set(data VAs the fn takes the address of)   (to tie dispatch to vtables)
    """
    from capstone import Cs, CS_ARCH_X86, CS_ARCH_ARM64, CS_MODE_32, CS_MODE_64, CS_MODE_LITTLE_ENDIAN
    arm = img.arm
    if arm:
        md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    else:
        md = Cs(CS_ARCH_X86, CS_MODE_32 if img.x32 else CS_MODE_64)
    md.detail = True
    startset = set(starts)
    code, base, end = img.code, img.text_va, img.text_end
    TRAMP = __import__("recover_emulate").TRAMP
    nexts = {s: n for s, n in zip(starts, starts[1:] + [end])}
    edges, import_sites, indirect, vtref = {}, {}, {}, {}
    taken = set()

    def import_name(tramp_va):
        idx = (tramp_va - TRAMP) // 16
        return img.tramp[idx] if 0 <= idx < len(img.tramp) else "?"

    def is_tramp(v):
        return v is not None and TRAMP <= v < TRAMP + 16 * len(img.tramp)

    stub_cache = {}

    def direct_target(t, s, ed, imps, tail):
        """Classify a direct branch target. `tail`: a b/jmp (only a jump to ANOTHER function's start
        is an edge; jumps inside the function are ordinary control flow)."""
        if t in startset:
            if not tail or not (s <= t < nexts[s]):
                ed.add(t)
            return True
        if is_tramp(t):
            imps.append(import_name(t))
            return True
        if tail and s <= t < nexts[s]:
            return False
        slot = _stub_import(img, t, stub_cache)
        if slot is not None:
            v = img.patches.get(slot)
            if is_tramp(v):
                imps.append(import_name(v))
                return True
        return False

    if arm:
        from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_MEM, ARM64_OP_REG, ARM64_SFT_LSL
    else:
        from capstone.x86 import X86_OP_IMM as _X86_IMM, X86_OP_MEM as _X86_MEM
        from capstone.x86 import X86_REG_RIP as _X86_RIP, X86_REG_EIP as _X86_EIP

    for s in starts:
        chunk = code[s - base:nexts[s] - base]
        ed, imps, ind, refs = set(), [], 0, set()
        pages = {}          # AArch64: x-register -> address materialized by adrp/adr/add
        try:
            for insn in md.disasm(chunk, s):
                if arm:
                    m = insn.mnemonic
                    ops = insn.operands
                    keep = None
                    if m in ("bl", "b") and insn.op_str.startswith("#"):
                        direct_target(_imm(insn.op_str), s, ed, imps, tail=(m == "b"))
                    elif m == "blr":
                        ind += 1
                    elif m in ("adrp", "adr") and len(ops) == 2 and ops[1].type == ARM64_OP_IMM:
                        r = _arm_xreg(insn.reg_name(ops[0].reg))
                        pages[r] = ops[1].imm
                        keep = r
                        if m == "adr":
                            t = ops[1].imm
                            (taken.add(t) if t in startset else refs.add(t))
                    elif m == "add" and len(ops) == 3 and ops[1].type == ARM64_OP_REG \
                            and ops[2].type == ARM64_OP_IMM:
                        src = _arm_xreg(insn.reg_name(ops[1].reg))
                        if src in pages:
                            imm = ops[2].imm
                            if ops[2].shift.type == ARM64_SFT_LSL:
                                imm <<= ops[2].shift.value
                            t = pages[src] + imm
                            (taken.add(t) if t in startset else refs.add(t))
                            r = _arm_xreg(insn.reg_name(ops[0].reg))
                            pages[r] = t
                            keep = r
                    elif m == "ldr" and len(ops) == 2 and ops[1].type == ARM64_OP_MEM \
                            and ops[1].mem.index == 0:
                        src = _arm_xreg(insn.reg_name(ops[1].mem.base))
                        if src in pages:
                            v = img.patches.get(pages[src] + ops[1].mem.disp)   # a GOT slot
                            if v is not None and v in startset:
                                taken.add(v)
                    # any other register write invalidates what we knew about that register
                    try:
                        _, written = insn.regs_access()
                        for w in written:
                            r = _arm_xreg(insn.reg_name(w))
                            if r != keep:
                                pages.pop(r, None)
                    except Exception:
                        kept = pages.get(keep) if keep else None
                        pages.clear()
                        if kept is not None:
                            pages[keep] = kept
                    continue
                m = insn.mnemonic
                if m == "jmp" and insn.operands:
                    op = insn.operands[0]
                    if op.type == _X86_IMM:
                        direct_target(op.imm & 0xffffffffffffffff, s, ed, imps, tail=True)
                    elif op.type == _X86_MEM and op.mem.index == 0:
                        # tail call through a GOT/IAT slot: jmp [rip+slot] (x86-64) / jmp [abs] (x86)
                        if op.mem.base in (_X86_RIP, _X86_EIP):
                            slot = insn.address + insn.size + op.mem.disp
                        elif op.mem.base == 0 and img.x32:
                            slot = op.mem.disp & 0xffffffff
                        else:
                            slot = None
                        if slot is not None and is_tramp(img.patches.get(slot)):
                            imps.append(import_name(img.patches[slot]))
                    continue
                if m == "call":
                    op = insn.operands[0]
                    from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP, X86_REG_EIP
                    if op.type == X86_OP_IMM:
                        direct_target(op.imm & 0xffffffffffffffff, s, ed, imps, tail=False)
                    elif op.type == X86_OP_MEM and op.mem.base in (X86_REG_RIP, X86_REG_EIP) \
                            and op.mem.index == 0:
                        slot = insn.address + insn.size + op.mem.disp
                        v = img.patches.get(slot)
                        if v is not None and TRAMP <= v < TRAMP + 16 * len(img.tramp):
                            imps.append(import_name(v))
                        else:
                            ind += 1
                    else:
                        ind += 1
                elif m == "lea":
                    from capstone.x86 import X86_OP_MEM, X86_REG_RIP, X86_REG_EIP
                    op = insn.operands[1] if len(insn.operands) == 2 else None
                    if op is not None and op.type == X86_OP_MEM \
                            and op.mem.base in (X86_REG_RIP, X86_REG_EIP) and op.mem.index == 0:
                        t = insn.address + insn.size + op.mem.disp
                        if t in startset:
                            taken.add(t)
                        else:
                            refs.add(t)       # a data address (maybe a vtable)
        except Exception:
            pass
        edges[s] = ed
        import_sites[s] = imps
        indirect[s] = ind
        vtref[s] = refs
    return edges, import_sites, indirect, taken, vtref


def _imm(op_str):
    try:
        return int(op_str.split("#", 1)[1].split(",")[0].strip(), 0)
    except Exception:
        return -1


def build(path) -> dict:
    import recover_emulate
    import gen_runtime_sigs
    img = recover_emulate.Image(path)
    b = img.binary
    starts = sorted(a for a in gen_runtime_sigs.function_starts(b)
                    if img.text_va <= a < img.text_end)
    edges, import_sites, indirect, taken, vtref = _disasm_calls(img, starts)
    startset = set(starts)

    # address-taken via relocations pointing into .text (vtables, fn-pointer tables)
    for va, v in img.patches.items():
        if v in startset:
            taken.add(v)

    # dynamic-dispatch edges from recovered vtables: a function that takes a vtable's address can
    # reach that vtable's methods (dyn Trait dispatch), so add those edges + mark methods reachable.
    dispatch_edges = 0
    vtable_methods = set()
    try:
        import recover_types
        vts = recover_types.recover(path)["vtables"]
        by_va = {vt["va"]: vt for vt in vts}
        for vt in vts:
            for m in vt["methods"]:
                if m in startset:
                    vtable_methods.add(m)
        for fn, refs in vtref.items():
            for r in refs:
                vt = by_va.get(r)
                if vt:
                    for m in vt["methods"]:
                        if m in startset:
                            edges.setdefault(fn, set()).add(m)
                            dispatch_edges += 1
    except Exception:
        by_va = {}

    # roots: entry, exported functions, and every address-taken function (incl. main, callbacks,
    # vtable methods). These are where execution can actually start / be entered.
    roots = set()
    try:
        if img.text_va <= b.entrypoint < img.text_end:
            roots.add(b.entrypoint)
    except Exception:
        pass
    try:
        for s in b.symbols:
            va = gen_runtime_sigs.sym_va(b, s)
            if va in startset and (getattr(s, "exported", False) or getattr(s, "is_function", False)):
                # only exported as roots; internal symbols are reached by edges
                if getattr(s, "exported", False):
                    roots.add(va)
    except Exception:
        pass
    roots |= (taken & startset) | vtable_methods

    reachable = _bfs(roots, edges)
    # the naive baseline: direct edges from the entry point only
    entry_roots = {b.entrypoint} if (hasattr(b, "entrypoint") and b.entrypoint in startset) else set()
    base_reach = _bfs(entry_roots, {k: {e for e in v} for k, v in edges.items()}) if entry_roots else set()

    total = len(starts)
    n_import_sites = sum(len(v) for v in import_sites.values())
    n_indirect = sum(indirect.values())
    imports_used = sorted({nm for v in import_sites.values() for nm in v})
    return {
        "format": img.fmt, "arch": ("aarch64" if img.arm else ("x86" if img.x32 else "x86_64")),
        "functions_total": total,
        "direct_edges": sum(len(v) for v in edges.values()),
        "dispatch_edges": dispatch_edges,
        "vtables": len(by_va),
        "import_call_sites": n_import_sites,
        "indirect_call_sites_unresolved": n_indirect,
        "imports_used": imports_used[:200],
        "roots": len(roots),
        "reachable": len(reachable),
        "reachable_pct": round(100 * len(reachable) / total, 1) if total else 0.0,
        "reachable_from_entry_only": len(base_reach),
        "coverage_lift": len(reachable) - len(base_reach),
        "_edges": edges, "_roots": roots, "_reachable": reachable, "_starts": starts,
        "_import_sites": import_sites, "_indirect": indirect,
    }


def _bfs(roots, edges):
    seen = set(roots)
    q = deque(roots)
    while q:
        u = q.popleft()
        for v in edges.get(u, ()):  # noqa
            if v not in seen:
                seen.add(v)
                q.append(v)
    return seen


def _print(res: dict) -> None:
    print(f"format={res['format']}  arch={res['arch']}  functions={res['functions_total']}")
    print(f"  call graph: {res['direct_edges']} direct edges, {res['dispatch_edges']} dynamic-"
          f"dispatch edges from {res['vtables']} vtable(s)")
    print(f"  calls: {res['import_call_sites']} to imports, "
          f"{res['indirect_call_sites_unresolved']} indirect (unresolved)")
    print(f"  reachable: {res['reachable']}/{res['functions_total']} ({res['reachable_pct']}%) "
          f"from {res['roots']} roots")
    print(f"  coverage lift vs entry-only: +{res['coverage_lift']} functions "
          f"({res['reachable_from_entry_only']} -> {res['reachable']})")
    if res["imports_used"]:
        print("  imports used: " + ", ".join(res["imports_used"][:16])
              + (" ..." if len(res["imports_used"]) > 16 else ""))


def _selftest():
    # exercise the pure graph pieces: BFS reachability and the coverage-lift accounting.
    edges = {1: {2, 3}, 2: {4}, 3: set(), 4: set(), 5: {6}, 6: set(), 7: set()}
    # from entry (1) only: 1,2,3,4 ; function 5,6 are an address-taken callback island, 7 dead
    assert _bfs({1}, edges) == {1, 2, 3, 4}
    # adding the address-taken root 5 reaches 6 too -> the coverage lift
    assert _bfs({1, 5}, edges) == {1, 2, 3, 4, 5, 6}
    assert _bfs({1, 5}, edges) - _bfs({1}, edges) == {5, 6}
    # a dispatch edge (fn 4 builds a trait object whose method is fn 7) pulls 7 in
    e2 = {k: set(v) for k, v in edges.items()}
    e2[4].add(7)
    assert 7 in _bfs({1}, e2)
    # _imm parses aarch64 branch operands
    assert _imm("#0x1234") == 0x1234 and _imm("#4660") == 4660

    # import jump stubs decode to the GOT/IAT slot they jump through (both architectures)
    class _Img:
        def __init__(self, arm, x32, mem):
            self.arm, self.x32, self.mem = arm, x32, mem

        def read_any(self, va, n):
            for base, blob in self.mem.items():
                if base <= va < base + len(blob):
                    return blob[va - base:va - base + n]
            return b""
    # the real AArch64 PLT entry rustc/ld emits: adrp x16,#0x5f000; ldr x17,[x16,#0xcc0]; add; br x17
    plt = struct.pack("<4I", 0x900002f0, 0xf9466211, 0x91330210, 0xd61f0220)
    assert _stub_import(_Img(True, False, {0x3d70: plt}), 0x3d70, {}) == 0x5fcc0
    # with a leading `bti c` (BTI-enabled PLT)
    bti = struct.pack("<I", 0xd503245f) + struct.pack("<3I", 0x900002f0, 0xf9466211, 0xd61f0220)
    assert _stub_import(_Img(True, False, {0x3d6c: bti}), 0x3d6c, {}) == 0x5fcc0
    # adrp to a page BELOW the stub (negative immhi) -- the sign extension matters
    neg = struct.pack("<2I", 0xf0fffff0, 0xf9400211) + b"\0" * 8
    assert _stub_import(_Img(True, False, {0x10000: neg}), 0x10000, {}) == 0x10000 - 0x1000
    # not a stub (adrp to x0, not x16) -> None
    assert _stub_import(_Img(True, False, {0x3d70: struct.pack("<4I", 0x90000000, 0, 0, 0)}),
                        0x3d70, {}) is None
    # x86-64 .plt.sec: endbr64; bnd jmp [rip+0x100]  -> slot = va + 11 + 0x100
    sec = b"\xf3\x0f\x1e\xfa\xf2\xff\x25" + struct.pack("<i", 0x100) + b"\x90" * 5
    assert _stub_import(_Img(False, False, {0x1000: sec}), 0x1000, {}) == 0x1000 + 11 + 0x100
    # PE thunk: jmp [rip-0x20] -> slot = va + 6 - 0x20
    th = b"\xff\x25" + struct.pack("<i", -0x20) + b"\xcc" * 10
    assert _stub_import(_Img(False, False, {0x2000: th}), 0x2000, {}) == 0x2000 + 6 - 0x20
    # x86-32: jmp [abs32]
    th32 = b"\xff\x25" + struct.pack("<I", 0x40a000) + b"\xcc" * 10
    assert _stub_import(_Img(False, True, {0x401000: th32}), 0x401000, {}) == 0x40a000
    # a W write invalidates the X register it aliases
    assert _arm_xreg("w5") == "x5" and _arm_xreg("x5") == "x5" and _arm_xreg("wzr") == "wzr"
    print("selftest OK: reachability BFS, address-taken root coverage-lift, dispatch-edge reach, "
          "branch-immediate parse, PLT/.plt.sec/IAT stub decode (AArch64 + x86)")


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
    res = build(path)
    pub = {k: v for k, v in res.items() if not k.startswith("_")}
    print(json.dumps(pub, indent=2)) if a.json else _print(pub)
    return 0


if __name__ == "__main__":
    sys.exit(main())
