#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: Ve (VAHPEM) <ve0912084386@gmail.com>
#
# Dual-licensed: AGPL-3.0-or-later OR a commercial license.
# Commercial licensing: Ve (VAHPEM) <ve0912084386@gmail.com>
"""deobf_cff.py - Tier 4: static detection of control-flow flattening (CFF).

CFF rewrites a function's straight-line/branching body into a `while(1){ switch(state) }`:
every original block becomes a switch case, blocks no longer fall through to each other
but instead set a state variable and jump back to a central dispatcher. The giveaway,
visible without a full CFG, is a dispatcher: one address that a large number of sites
jump to, reached through a ladder of `cmp <reg>, <imm32>` / conditional-jump on a single
state register, or an indexed jump table.

This is a TRIAGE detector -- it flags and locates likely-flattened regions and the
dispatcher so an analyst (or an SMT/emulation deflattener) can focus there. It does not
rebuild the original control flow. Observational: reads the binary, runs nothing.

    python deobf_cff.py <binary> [--min-cases 12] [--json]
    python deobf_cff.py --selftest
"""
from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path
# premium module: find both premium/ (sibling premium modules) and the Apache core in scripts/
for _p in (str(_Path(__file__).resolve().parent), str(_Path(__file__).resolve().parent.parent / 'scripts')):
    if _p not in _sys.path:
        _sys.path.insert(0, _p)

import argparse, collections, json, sys
from pathlib import Path


def _load_text(path):
    import lief
    b = lief.parse(str(path))
    if b is None:
        raise ValueError("LIEF could not parse the file")
    base = b.optional_header.imagebase if "PE" in b.format.name else 0
    for s in b.sections:
        if s.name == ".text" or (getattr(s, "characteristics", 0) and ".text" in s.name):
            va = base + s.virtual_address
            return bytes(s.content), va
    # fall back to the first executable section
    for s in b.sections:
        if getattr(s, "virtual_address", 0):
            return bytes(s.content), base + s.virtual_address
    raise ValueError("no .text section")


def analyze(code, base, min_cases=12):
    """Find dispatcher candidates: a target jumped-to from many sites, plus a nearby
    cmp-imm ladder on one register. Returns a list of candidate dict regions."""
    from capstone import (Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_IMM, CS_OP_REG,
                          CS_GRP_JUMP)
    md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail = True
    insns = list(md.disasm(code, base))

    jump_targets = collections.Counter()           # direct jmp/jcc target -> count
    jump_sites = collections.defaultdict(list)      # target -> [site addrs]
    cmps = []                                        # (addr, reg, imm)
    for ins in insns:
        m = ins.mnemonic
        if m.startswith("j"):                       # jmp/je/jne/...
            imm = next((op.imm for op in ins.operands if op.type == CS_OP_IMM), None)
            if imm is not None:
                jump_targets[imm] += 1
                jump_sites[imm].append(ins.address)
        elif m == "cmp" and len(ins.operands) == 2 and ins.operands[0].type == CS_OP_REG \
                and ins.operands[1].type == CS_OP_IMM:
            cmps.append((ins.address, ins.reg_name(ins.operands[0].reg), ins.operands[1].imm))

    def local_ladder(sites, reg_hint=None, window=0x600):
        """Distinct cmp-immediates seen on a single register within `window` bytes of the
        blocks that jump to this dispatcher -- i.e. the ladder actually feeding IT, not the
        whole .text. Returns (best_reg, distinct_count)."""
        lo, hi = min(sites) - window, max(sites) + window
        by_reg = collections.defaultdict(set)
        for addr, reg, imm in cmps:
            if lo <= addr <= hi:
                by_reg[reg].add(imm)
        if not by_reg:
            return None, 0
        reg = max(by_reg, key=lambda r: len(by_reg[r]))
        return reg, len(by_reg[reg])

    cands = []
    for tgt, deg in jump_targets.most_common(12):
        if deg < min_cases:
            continue
        reg, distinct = local_ladder(jump_sites[tgt])
        # CFF signature: a dispatcher with high in-degree AND a local state ladder of
        # comparable size. A big in-degree with a SMALL local ladder is more likely a
        # shared error/landing pad or a hot loop header, not flattening.
        score = min(deg, distinct)
        cands.append({
            "dispatcher_va": hex(tgt), "in_degree": deg,
            "state_reg": reg, "local_state_consts": distinct, "score": score,
            "flattened_likely": score >= min_cases,
        })
    cands.sort(key=lambda c: c["score"], reverse=True)
    # NOTE: a compiler-generated large `match`/switch or jump table (common in Rust/C++)
    # produces the same shape; this flags candidates for review, it does not prove obfuscation.
    return {"insns": len(insns), "candidates": cands}


def _selftest():
    # assemble a tiny flattened-looking stub: a dispatcher at L, reached from many
    # cmp eax,imm / je L sites. We emit raw bytes with keystone-free hand encoding via a
    # known sequence: use `cmp eax, imm32` (3D xx xx xx xx) + `je rel32` targeting one addr,
    # repeated, so one target dominates in-degree and eax has many distinct consts.
    import struct
    base = 0x1000
    code = bytearray()
    sites = []
    N = 20
    # first lay down the body, recording where each je lands (all to the same dispatcher)
    for i in range(N):
        code += b"\x3d" + struct.pack("<I", 0x1000 + i)      # cmp eax, imm32
        sites.append(len(code))
        code += b"\x0f\x84\x00\x00\x00\x00"                  # je rel32 (patch later)
    disp_off = len(code)
    code += b"\x90"                                          # dispatcher landing (nop)
    # patch every je rel32 to point at disp_off
    for s in sites:
        rel = disp_off - (s + 6)
        code[s + 2:s + 6] = struct.pack("<i", rel)
    r = analyze(bytes(code), base, min_cases=12)
    c = r["candidates"][0]
    assert c["in_degree"] >= N, c
    assert c["local_state_consts"] >= N, c
    assert c["flattened_likely"], c
    print(f"selftest OK: dispatcher @ {c['dispatcher_va']} in_degree={c['in_degree']} "
          f"state_reg={c['state_reg']} local_consts={c['local_state_consts']}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("binary", nargs="?")
    ap.add_argument("--min-cases", type=int, default=12)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        _selftest(); return
    if not a.binary:
        ap.error("binary required or --selftest")
    code, base = _load_text(Path(a.binary))
    r = analyze(code, base, a.min_cases)
    if a.json:
        print(json.dumps(r, indent=2)); return
    print(f"{Path(a.binary).name}: {r['insns']} insns disassembled")
    flat = [c for c in r["candidates"] if c["flattened_likely"]]
    if not flat:
        print(f"no dispatcher signature above threshold (min-cases={a.min_cases}). "
              "Top jump targets by in-degree:")
        for c in r["candidates"][:3]:
            print(f"  {c['dispatcher_va']}  in_degree={c['in_degree']}  "
                  f"local_state_consts={c['local_state_consts']}")
        return
    print("dispatcher candidates for review (high in-degree + local state ladder):")
    for c in flat:
        print(f"  {c['dispatcher_va']}  score={c['score']}  in_degree={c['in_degree']}  "
              f"state_reg={c['state_reg']}  local_state_consts={c['local_state_consts']}")
    print("\nnote: a large compiler `match`/switch or jump table has the same shape; "
          "these are candidates to inspect, not proof of obfuscation.")


if __name__ == "__main__":
    main()
