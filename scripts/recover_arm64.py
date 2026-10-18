#!/usr/bin/env python3
"""Static call-site string recoverer for AArch64 (ARM64) Rust binaries.

Port of recover_callsite.py (x86-64) to ARM64. Same idea: find the keyed decode loop,
resolve the key and each call site's ciphertext/length statically, decode. ARM64 idiom:

  key pointer : adrp Xk,#PAGE ; add Xk,Xk,#OFF            (PC-relative, two instructions)
  key index   : and Xi,Xj,#MASK                          (=> key length MASK+1)
  decode op   : eor/add/sub Wd,Wenc,Wkey  with ldrb loads of the enc and key bytes
  call site   : adrp X1,#P; add X1,X1,#O (enc) ; mov W2,#LEN ; bl <decoder>   (AAPCS64)

On ARM64 the mask `and` and the key/enc `ldrb` loads sit AFTER the decode op in the loop
body (loop-carried), so detection scans a window on BOTH sides of the op.

As far as the Oct-2026 survey found, no static string-decoder-recovery tool exists for ARM64
Rust binaries; this covers new ground (Apple-Silicon / ARM Rust malware). Filters shared with
the x86-64 tool.
"""
from __future__ import annotations
import bisect, sys
from pathlib import Path
import lief
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, CS_OP_REG, CS_OP_IMM, CS_OP_MEM

sys.path.insert(0, str(Path(__file__).resolve().parent))
from recover_callsite import looks_like_text, read_va


def _rn(ins, rid):
    return ins.reg_name(rid) if rid else None


def _x(name):
    return "x" + name[1:] if name and name.startswith("w") else name


def recover(path, canaries):
    binary = lief.parse(str(path))
    text = next((s for s in binary.sections if s.name == ".text"), None)
    if text is None:
        return {"error": "no .text", "recall": 0, "n": len(canaries), "decoders": 0, "recovered_texts": []}
    code = bytes(text.content); base = text.virtual_address
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail = True
    insns = list(md.disasm(code, base))
    idx = {ins.address: i for i, ins in enumerate(insns)}

    def resolve_pageadd(i, reg, back=60):
        want = _x(reg)
        for j in range(i, max(0, i - back), -1):
            pj = insns[j]
            if pj.mnemonic == "add" and pj.operands and _rn(pj, pj.operands[0].reg) == want:
                src = _rn(pj, pj.operands[1].reg) if len(pj.operands) > 1 else None
                off = next((o.imm for o in pj.operands if o.type == CS_OP_IMM), None)
                for k in range(j - 1, max(0, j - back), -1):
                    pk = insns[k]
                    if pk.mnemonic == "adrp" and _rn(pk, pk.operands[0].reg) == src:
                        pa = next((o.imm for o in pk.operands if o.type == CS_OP_IMM), None)
                        if pa is not None and off is not None:
                            return pa + off
                break
        return None

    # --- detect decoders: eor/add/sub with a masked key ldrb in the same loop body ---
    decoders = []
    for i, ins in enumerate(insns):
        if ins.mnemonic not in ("eor", "add", "sub"):
            continue
        if not ins.operands or ins.operands[0].type != CS_OP_REG:
            continue
        lo, hi = max(0, i - 8), min(len(insns), i + 12)
        keylen = None
        for j in range(lo, hi):
            if insns[j].mnemonic == "and":
                imm = next((o.imm for o in insns[j].operands if o.type == CS_OP_IMM), None)
                if imm is not None and 0 < imm < 256 and (imm & (imm + 1)) == 0:
                    keylen = imm + 1
        if not keylen:
            continue
        key_va = None
        for j in range(lo, hi):
            pj = insns[j]
            if pj.mnemonic == "ldrb" and pj.operands and pj.operands[-1].type == CS_OP_MEM:
                t = resolve_pageadd(j, _rn(pj, pj.operands[-1].mem.base))
                if t is not None:
                    key_va = t; break
        if key_va is not None:
            decoders.append((ins.address, key_va, keylen, ins.mnemonic))

    seen = {}
    for addr, kva, kl, opn in decoders:
        seen.setdefault((kva, kl), (addr, opn))

    bl_targets = sorted({o.imm for ins in insns if ins.mnemonic == "bl"
                         for o in ins.operands if o.type == CS_OP_IMM})

    def func_entry(a):
        k = bisect.bisect_right(bl_targets, a) - 1
        return bl_targets[k] if k >= 0 else None

    found = set(); texts = []
    for (kva, kl), (xaddr, opn) in seen.items():
        key = read_va(binary, kva, kl)
        if not key:
            continue
        entry = func_entry(xaddr)
        if entry is None:
            continue
        decoder_texts = []
        for i, ins in enumerate(insns):
            if ins.mnemonic != "bl":
                continue
            tgt = next((o.imm for o in ins.operands if o.type == CS_OP_IMM), None)
            if tgt != entry:
                continue
            blob_va = length = None
            for j in range(i - 1, max(0, i - 20), -1):
                pj = insns[j]
                if pj.mnemonic in ("mov", "movz") and pj.operands and _rn(pj, pj.operands[0].reg) in ("x2", "w2"):
                    imm = next((o.imm for o in pj.operands if o.type == CS_OP_IMM), None)
                    if imm is not None:
                        length = imm; break
            for j in range(i - 1, max(0, i - 20), -1):
                pj = insns[j]
                if pj.mnemonic == "add" and pj.operands and _rn(pj, pj.operands[0].reg) == "x1":
                    t = resolve_pageadd(j, "x1")
                    if t is not None:
                        blob_va = t; break
            if blob_va is None or not length or length > 4096:
                continue
            blob = read_va(binary, blob_va, length)
            if not blob:
                continue
            # Op detection on ARM64 is noisy (ops in a loop share a key region), so try all
            # three keyed ops and keep whichever yields clean text -- the cipher self-identifies.
            for cand in (
                bytes(blob[k] ^ key[k % kl] for k in range(len(blob))),
                bytes((blob[k] + key[k % kl]) & 0xff for k in range(len(blob))),
                bytes((blob[k] - key[k % kl]) & 0xff for k in range(len(blob))),
            ):
                if looks_like_text(cand):
                    decoder_texts.append(cand.decode("ascii", "ignore"))
                    break
        if len(decoder_texts) >= 2:
            for t in decoder_texts:
                texts.append(t)
                for c in canaries:
                    if c in t:
                        found.add(c)

    return {"decoders": len(seen), "recovered": sorted(found), "recovered_texts": texts,
            "recall": len(found), "n": len(canaries)}


def main():
    can = [f"canary::{w}" for w in ("alpha", "bravo", "charlie", "delta", "echo")]
    for t in sys.argv[1:]:
        r = recover(t, can)
        print(f"{Path(t).name:<30} recall {r['recall']}/{r['n']}  decoders={r.get('decoders')}"
              + ("  ERR " + r['error'] if r.get('error') else ""))
        for s in r.get("recovered", []):
            print("   +", s)


if __name__ == "__main__":
    main()
