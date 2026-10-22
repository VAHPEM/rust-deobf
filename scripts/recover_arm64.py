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


def _resolve_pageadd(insns, i, reg, back=80):
    """Walk back from index i to the address loaded into register `reg`.

    Handles the usual `adrp Xr,#P; add Xr,Xr,#O` pair (P+O) and the single `adr Xr,#A`
    that linkers such as lld relax it into when the target is within +-1 MiB (`nop; adr`).
    """
    want = _x(reg)
    for j in range(i, max(0, i - back), -1):
        pj = insns[j]
        if pj.mnemonic == "adr" and pj.operands and _x(_rn(pj, pj.operands[0].reg)) == want:
            return next((o.imm for o in pj.operands if o.type == CS_OP_IMM), None)
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


def recover_litcrypt2_arm64(binary, insns, canaries):
    """Recover litcrypt2's `lc!` strings on AArch64 (the x86 recover_litcrypt2 analogue).

    litcrypt2 walks a fixed 64-byte key with stride +2, wrapping to 1 at `nxt == keylen`
    and to 0 beyond -- a permutation of 0..keylen-1, NOT the `key[i % keylen]` the generic
    recover() models (which reads the `cmp #0x40` as keylen 0x41 and resolves nothing, so
    litcrypt2 scores 0/5 on the generic path). The ARM codegen of the wrap is

        add  Xnxt, Xidx, #STRIDE      ; idx + stride
        cmp  Xnxt, #KEYLEN            ; == key length?
        cset Wc, eq                   ; c = (nxt == keylen)   (or `ne`: the mirror image)
        csel Xidx, Xnxt, Wc, lo       ; idx = (nxt < keylen) ? nxt : c

    with `ldrb Wk,[Xkeybase, Xidx]` loading the key byte. The decoder is a shared function
    (one process-wide key, so byte0 const-folds to `cipher[0] ^ key[0]`); each `lc!` site is
    `adrp X1,#P; add X1,X1,#O` (ciphertext) + `mov W2,#LEN` + `bl <decoder>` (AAPCS64). We
    recognise the wrap cluster, read the rip-relative key, and replay the state machine at
    each call site. Same >=2-call-site corroboration as the generic path -> no new FPs.
    """
    out, n = [], len(insns)
    blt = sorted({o.imm for x in insns if x.mnemonic == "bl"
                  for o in x.operands if o.type == CS_OP_IMM})

    def entry_of(a):
        k = bisect.bisect_right(blt, a) - 1
        return blt[k] if k >= 0 else None

    for i, ins in enumerate(insns):
        if ins.mnemonic != "csel" or len(ins.operands) < 3:
            continue
        if ins.op_str.split(",")[-1].strip() != "lo":        # unsigned-< select = the wrap
            continue
        idx_reg = _x(_rn(ins, ins.operands[0].reg))
        nxt_reg = _x(_rn(ins, ins.operands[1].reg))
        c_reg = _x(_rn(ins, ins.operands[2].reg))
        # `cset Wc, eq` wraps idx+STRIDE == KEYLEN to 1 and past it to 0; `cset Wc, ne` is the
        # mirror image. rustc picks one depending on version and key length, so accept both.
        cond = next((insns[j].op_str.split(",")[-1].strip() for j in range(i - 1, max(0, i - 4) - 1, -1)
                     if insns[j].mnemonic == "cset"
                     and _x(_rn(insns[j], insns[j].operands[0].reg)) == c_reg), None)
        if cond not in ("eq", "ne"):
            continue
        wrap_eq, wrap_past = (1, 0) if cond == "eq" else (0, 1)
        keylen = None
        for j in range(max(0, i - 5), i):
            if insns[j].mnemonic == "cmp" and _x(_rn(insns[j], insns[j].operands[0].reg)) == nxt_reg:
                keylen = next((o.imm for o in insns[j].operands if o.type == CS_OP_IMM), None)
        if not keylen or not (8 <= keylen <= 1024):
            continue
        stride = None
        for j in range(max(0, i - 8), i):
            pj = insns[j]
            if pj.mnemonic == "add" and len(pj.operands) == 3 \
               and _x(_rn(pj, pj.operands[0].reg)) == nxt_reg \
               and _x(_rn(pj, pj.operands[1].reg)) == idx_reg \
               and pj.operands[2].type == CS_OP_IMM:
                stride = pj.operands[2].imm
        if not stride or not (0 < stride <= 16):
            continue
        key_va = None
        for j in range(max(0, i - 10), min(n, i + 6)):
            pj = insns[j]
            if pj.mnemonic == "ldrb" and pj.operands[-1].type == CS_OP_MEM:
                mo = pj.operands[-1].mem
                if mo.base and mo.index and _x(_rn(pj, mo.index)) == idx_reg:
                    t = _resolve_pageadd(insns, j, _rn(pj, mo.base))
                    if t is not None:
                        key_va = t; break
        if key_va is None:
            continue
        key = read_va(binary, key_va, keylen)
        if len(key) < keylen:
            continue
        init_k = None
        for j in range(max(0, i - 30), i):
            pj = insns[j]
            if pj.mnemonic in ("mov", "movz") and len(pj.operands) == 2 \
               and pj.operands[0].type == CS_OP_REG and pj.operands[1].type == CS_OP_IMM \
               and _x(_rn(pj, pj.operands[0].reg)) == idx_reg and 0 <= pj.operands[1].imm < keylen:
                init_k = pj.operands[1].imm
        if init_k is None:
            init_k = stride
        c0 = key[0]                                          # const-folded byte-0 key
        entry = entry_of(ins.address)
        if entry is None:
            continue

        def schedule(ln):
            seq, k = [], init_k
            for _ in range(1, ln):
                seq.append(k); nx = k + stride
                k = nx if nx < keylen else (wrap_eq if nx == keylen else wrap_past)
            return seq

        def decode(ct):
            if not ct:
                return b""
            o = bytearray([ct[0] ^ c0])
            for p, kk in enumerate(schedule(len(ct)), 1):
                o.append(ct[p] ^ key[kk])
            return bytes(o)

        texts = []
        for ci, cins in enumerate(insns):
            if cins.mnemonic != "bl":
                continue
            if next((o.imm for o in cins.operands if o.type == CS_OP_IMM), None) != entry:
                continue
            blob = length = None
            for j in range(ci - 1, max(0, ci - 20), -1):
                pj = insns[j]
                if pj.mnemonic in ("add", "adr") and pj.operands \
                   and _rn(pj, pj.operands[0].reg) == "x1" and blob is None:
                    t = _resolve_pageadd(insns, j, "x1")
                    if t is not None:
                        blob = t
                if pj.mnemonic in ("mov", "movz") and pj.operands \
                   and _x(_rn(pj, pj.operands[0].reg)) == "x2" and length is None:
                    im = next((o.imm for o in pj.operands if o.type == CS_OP_IMM), None)
                    if im is not None and 0 < im <= 4096:
                        length = im
                if blob and length:
                    break
            if blob and length:
                dec = decode(read_va(binary, blob, length))
                if dec and looks_like_text(dec):
                    texts.append({"string": dec.decode("ascii", "ignore"), "decoder": entry,
                                  "call": cins.address, "blob": blob, "method": "static-litcrypt2"})
        if len(texts) >= 2:
            out.extend(texts)
            break
    return out


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
        return _resolve_pageadd(insns, i, reg, back)

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
            m = insns[j].mnemonic
            if m == "and":
                imm = next((o.imm for o in insns[j].operands if o.type == CS_OP_IMM), None)
                if imm is not None and 0 < imm < 256 and (imm & (imm + 1)) == 0:
                    keylen = imm + 1
            elif m == "cmp":
                # modulo-by-compare (e.g. litcrypt): cmp Xi,#N followed by a conditional
                # select/negate that wraps the index -> key length N+1
                imm = next((o.imm for o in insns[j].operands if o.type == CS_OP_IMM), None)
                if imm is not None and 0 < imm < 256:
                    for k in range(j + 1, min(len(insns), j + 4)):
                        if insns[k].mnemonic in ("csel", "csinc", "cneg", "csinv", "csneg"):
                            keylen = imm + 1; break
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

    found = set(); texts = []; records = []
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
                if pj.mnemonic in ("add", "adr") and pj.operands and _rn(pj, pj.operands[0].reg) == "x1":
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
                    decoder_texts.append({"string": cand.decode("ascii", "ignore"), "decoder": entry,
                                          "call": ins.address, "blob": blob_va, "method": "static"})
                    break
        if len(decoder_texts) >= 2:
            records.extend(decoder_texts)

    # litcrypt2's stride-permutation schedule is not an `i % keylen` repeat, so the generic
    # path above resolves nothing on it; run the dedicated recogniser as a second pass.
    records.extend(recover_litcrypt2_arm64(binary, insns, canaries))

    for rec in records:
        texts.append(rec["string"])
        for c in canaries:
            if c in rec["string"]:
                found.add(c)
    return {"decoders": len(seen), "recovered": sorted(found), "recovered_texts": texts,
            "records": records, "recall": len(found), "n": len(canaries)}


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
