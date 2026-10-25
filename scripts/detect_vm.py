#!/usr/bin/env python3
"""detect_vm.py - flag functions hidden behind a bytecode VM (code virtualization).

Code virtualization (VMProtect / Themida / Tigress, and RustCloak's `virt`) replaces a function's
native code with an interpreter for a custom bytecode: a dispatch loop that fetches opcode/operand
bytes from an embedded blob and runs a handler per opcode. That leaves a machine-code fingerprint
very unlike ordinary code:

  * a THREADED DISPATCH -- many indirect branches through the *same* register (each opcode handler
    re-dispatches to the next), or a jump table indexed by a fetched byte; and
  * dense BYTECODE FETCHES -- many byte-sized loads (`movzx ...byte`, `ldrb`) of a data blob.

This is a DETECTOR, not a devirtualizer (that is a later round): it reports which functions look
virtualized and how strong the signal is, so an analyst knows a function is VM-protected and can
prioritise it. STATIC ONLY; never executes the sample.

    python3 scripts/detect_vm.py <binary> [--json]

Honest limits:
  * x86-64 is precise here (LLVM lowers the dispatch to a threaded computed-goto -- repeated
    `jmp *%reg` -- which this keys on). On AArch64 the same interpreter lowers to a compare-tree
    dispatcher that is structurally like control-flow flattening; detecting it well overlaps the
    deflattener's CFG analysis, so ARM VM detection is the NEXT blue round, not this one.
  * If the interpreter is also control-flow-flattened (RustCloak applies virt then flatten), the
    threaded dispatch is itself hidden -- run the deflattener first, then this detector on the
    recovered form (pipeline integration is a later round).
  * A genuine embedded interpreter in benign code (CPython's computed-goto eval loop, some regex
    engines) has the same shape and will match -- correctly, it IS an interpreter. The report says
    "virtualization-shaped"; in triage, the surrounding context (is this a small Rust sample that
    should not embed a VM?) disambiguates, and the analyst confirms.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))


def _scan_function(img, fva, size):
    """Return (max_same_reg_indirect, jumptable_count, byteload_count) for one function."""
    off = fva - img.text_va
    code = bytes(img.code[off:off + size])
    if not code:
        return 0, 0, 0
    indreg = Counter()
    jmptab = 0
    byteload = 0
    for ins in img.md.disasm(code, fva):
        m, o = ins.mnemonic, ins.op_str
        if img.arm:
            if m == "br" and o and not o.startswith("#"):      # br xN -- indirect/threaded dispatch
                indreg[o.strip()] += 1
            elif m in ("ldrb", "ldrsb"):                        # byte fetch of the bytecode
                byteload += 1
        else:
            if m == "jmp" and o:
                if "[" in o:                                    # jmp qword ptr [tab + idx*8] -- table
                    jmptab += 1
                elif not o.startswith("0x"):                    # jmp rax/r8 -- threaded dispatch
                    indreg[o.strip()] += 1
            elif m in ("movzx", "movzbl") and "byte" in o:
                byteload += 1
    top = max(indreg.values()) if indreg else 0
    return top, jmptab, byteload


def _classify(top, jmptab, byteload):
    """(is_vm, confidence, reason) from one function's counts.

    The discriminator is THREADED DISPATCH -- many indirect branches through the *same* register,
    each opcode handler re-dispatching. A single jump table (one `jmp [tab+idx*8]`) is an ordinary
    `switch` and is NOT enough; dense byte-fetches alone (byte-processing loops in benign code) are
    NOT enough. Both together, with repeated same-register dispatch, is the interpreter signature.

    The `top` thresholds are set from measurement: a RustCloak-virtualized function re-dispatches from
    every opcode handler (observed top >= 8 across the fixtures), whereas a benign interpreter-shaped
    std function -- the one that caused false positives -- is gimli's DWARF range-list reader, whose
    switch dispatches through one register only ~5 times. Requiring top >= 6 keeps every real VM and
    drops that DWARF reader, with the symbol filter in `detect()` as the primary guard when names
    survive (this threshold is the fallback for stripped binaries)."""
    if top >= 8 and byteload >= 8:
        return True, "high", f"threaded dispatch ({top} indirect branches to one register) + {byteload} bytecode fetches"
    if top >= 6 and byteload >= 8:
        return True, "medium", f"threaded dispatch ({top} indirect branches to one register) + {byteload} bytecode fetches"
    if jmptab >= 2 and top >= 4 and byteload >= 12:
        return True, "medium", f"jump-table dispatch ({jmptab}) + {byteload} bytecode fetches"
    return False, "", ""


# Benign, interpreter-shaped functions pulled in by the Rust/C++ runtime: gimli (the DWARF parser
# behind std backtraces), the language unwinder, backtrace/addr2line symbolization, and the `object`
# file reader. Each walks a bytecode-like format (DWARF CFI, EH tables) with a dispatch + byte-fetch
# shape that matches the VM signature -- correctly, they ARE interpreters, just not code
# virtualization. We skip them when a symbol names them (they are the same std code in every binary,
# which is exactly how they showed up as identical false positives across unrelated samples).
_BENIGN_INTERP = ("gimli", "_Unwind", "unwind", "backtrace", "addr2line", "rustc_demangle",
                  "5gimli", "6object", "panic_unwind", "eh_frame", "dwarf")


def _is_benign_interp(name):
    return bool(name) and any(tok in name for tok in _BENIGN_INTERP)


def _symbol_names(img):
    """va -> symbol name, for skipping benign interpreter-shaped std functions by name."""
    names = {}
    try:
        base = img.binary.imagebase if img.pe else 0
        for s in img.binary.symbols:
            try:
                v = int(s.value)
                if v:
                    names.setdefault(base + v, s.name)
            except Exception:
                pass
    except Exception:
        pass
    return names


def detect(path: Path) -> dict:
    from recover_emulate import Image
    img = Image(str(path))
    arch = "arm64" if img.arm else ("x86" if img.x32 else "x86-64")
    names = _symbol_names(img)
    hits = []
    for fva, size in img.functions():
        if _is_benign_interp(names.get(fva)):               # gimli/unwinder/etc. -- an interpreter,
            continue                                         # but not code virtualization
        top, jmptab, byteload = _scan_function(img, fva, size)
        is_vm, conf, reason = _classify(top, jmptab, byteload)
        if is_vm:
            hits.append({"va": fva, "size": size, "confidence": conf, "reason": reason,
                         "indirect_same_reg": top, "jumptable": jmptab, "byte_fetches": byteload})
    hits.sort(key=lambda h: (-{"high": 2, "medium": 1, "low": 0}[h["confidence"]], -h["byte_fetches"]))
    return {"file": str(path), "format": img.fmt, "arch": arch,
            "virtualized_functions": hits, "count": len(hits)}


def print_human(r: dict) -> None:
    print(f"VM detection: {Path(r['file']).name}  ({r['format']} / {r['arch']})")
    if not r["virtualized_functions"]:
        print("  no virtualized functions detected")
        return
    print(f"  {r['count']} function(s) look virtualized (bytecode VM / code virtualization):")
    for h in r["virtualized_functions"]:
        print(f"   - 0x{h['va']:x} ({h['size']} bytes)  [{h['confidence']}]  {h['reason']}")
    print("  note: detection, not devirtualization; an analyst confirms. Flattened interpreters "
          "need the deflattener first.")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("binary")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    path = Path(a.binary)
    if not path.is_file():
        ap.error(f"no such file: {path}")
    r = detect(path)
    print(json.dumps(r, indent=2) if a.json else "", end="")
    if not a.json:
        print_human(r)


if __name__ == "__main__":
    main()
