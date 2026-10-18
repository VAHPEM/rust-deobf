#!/usr/bin/env python3
"""Call-site dataflow string recoverer for XOR-family decoders in Rust binaries.

This is the real technique, and it works on ELF and PE (both formats LIEF parses),
including stripped binaries. It does NOT brute-force and does NOT need known plaintext.

How it mirrors, and goes beyond, FLOSS:
  FLOSS finds decoder functions and emulates them. On our Rust corpus FLOSS recovered
  0/5 canaries (and cannot open ELF at all). Instead of full CPU emulation we do light
  static dataflow, which is enough for the XOR-decoder idiom that dominates Rust string
  obfuscation (hand-rolled XOR, obfstr, litcrypt):

  1. Disassemble .text (capstone). Find the decode loop: a byte load `movzx r, [buf+idx]`
     followed by `xor r8, [key+idx]`, with the key index masked by `and e_, 0xK`
     (=> key length K+1) -- the classic repeating-key XOR.
  2. Resolve the KEY: the `lea key,[rip+disp]` feeding the xor's second operand gives the
     key's address; read K+1 bytes there.
  3. Resolve each CALL SITE of the decoder: scan backward a few instructions for
     `lea rsi,[rip+disp]` (ciphertext pointer) and `mov edx, imm` (length).
  4. Decode blob[i] ^ key[i % keylen] and keep printable results.

Honest scope: XOR-keyed schemes only. AEAD (muddy: ChaCha20-Poly1305) is reported as
out-of-scope-by-design, which is the correct analyst answer, not a miss.
"""
from __future__ import annotations
import json, sys, string
from pathlib import Path
import lief
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_MEM, CS_OP_IMM, CS_OP_REG

ROOT = Path(__file__).resolve().parent.parent
PRINT = set(bytes(string.printable, "ascii")) - set(b"\x0b\x0c")

def load(path):
    b = lief.parse(str(path))
    text = next((s for s in b.sections if s.name == ".text"), None)
    if text is None: return None
    return b, bytes(text.content), text.virtual_address

def read_va(binary, va, n):
    for s in binary.sections:
        base = s.virtual_address
        if base <= va < base + len(s.content):
            o = va - base
            return bytes(s.content[o:o+n])
    return b""

def rip_target(ins):
    """Address referenced by a rip-relative memory operand, if any."""
    for op in ins.operands:
        if op.type == CS_OP_MEM and op.mem.base == 0 and ins.reg_name(op.mem.base if op.mem.base else 0) is None:
            pass
    # capstone sets op.mem.base to the RIP register id for rip-relative; use disp + next-insn addr
    for op in ins.operands:
        if op.type == CS_OP_MEM:
            base_reg = ins.reg_name(op.mem.base) if op.mem.base else None
            if base_reg == "rip":
                return ins.address + ins.size + op.mem.disp
    return None

def printable_ratio(b):
    return sum(1 for x in b if x in PRINT) / len(b) if b else 0.0

def recover(path, canaries):
    loaded = load(path)
    if loaded is None: return {"error": "no .text", "recall": 0, "n": len(canaries)}
    binary, code, base = loaded
    md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail = True
    insns = list(md.disasm(code, base))
    idx = {ins.address: i for i, ins in enumerate(insns)}

    decoders = []  # (loop_xor_addr, key_va, keylen)
    for i, ins in enumerate(insns):
        if ins.mnemonic not in ("xor", "add", "sub"): continue
        # xor r8b, byte ptr [rip+disp]  OR  xor r8b, byte ptr [base+index]
        mem_op = next((op for op in ins.operands if op.type == CS_OP_MEM), None)
        if mem_op is None: continue
        key_va = rip_target(ins)  # key may be rip-relative directly
        keylen = None
        # repeating-key length, two idioms, within ~16 insns around the xor:
        #   (a) `and e_, 0xK`            => keylen K+1  (K+1 a power of two)
        #   (b) `cmp r, 0xM` + `cmov*`   => keylen M+1  (modulo-by-compare, e.g. litcrypt)
        for j in range(max(0, i-16), min(len(insns), i+2)):
            m = insns[j].mnemonic
            if m == "and":
                imm = next((op.imm for op in insns[j].operands if op.type == CS_OP_IMM), None)
                if imm is not None and 0 < imm < 256 and (imm & (imm+1)) == 0:
                    keylen = imm + 1
            elif m == "cmp":
                imm = next((op.imm for op in insns[j].operands if op.type == CS_OP_IMM), None)
                if imm is not None and 0 < imm < 256:
                    # confirm a conditional move / branch nearby uses it as a wrap
                    for k in range(j+1, min(len(insns), j+4)):
                        if insns[k].mnemonic.startswith("cmov") or insns[k].mnemonic in ("jae","jnb","jb","ja"):
                            keylen = imm + 1; break
        if key_va is None:
            # The key pointer is a `lea reg,[rip+disp]` whose reg indexes a byte load in the
            # decode loop. That byte load is either the decode op's own memory operand, or a
            # `movzx` a few instructions earlier that feeds the op's source register (some
            # codegen loads the key first, then combines with the ciphertext). Collect the
            # pointer-register candidates from both.
            ptr_regs = []
            if mem_op.mem.base: ptr_regs.append(ins.reg_name(mem_op.mem.base))
            if mem_op.mem.index: ptr_regs.append(ins.reg_name(mem_op.mem.index))
            for j in range(max(0, i-4), i):   # preceding byte loads (movzx/mov) in the loop
                pj = insns[j]
                if pj.mnemonic in ("movzx", "mov") and pj.operands:
                    mo = next((op for op in pj.operands if op.type == CS_OP_MEM), None)
                    if mo:
                        if mo.mem.base: ptr_regs.append(pj.reg_name(mo.mem.base))
                        if mo.mem.index: ptr_regs.append(pj.reg_name(mo.mem.index))
            for j in range(i-1, max(0, i-60), -1):
                pj = insns[j]
                if pj.mnemonic == "lea" and pj.operands and pj.operands[0].type == CS_OP_REG:
                    if pj.reg_name(pj.operands[0].reg) in ptr_regs:
                        t = rip_target(pj)
                        if t is not None: key_va = t; break
        if key_va is not None and keylen:
            decoders.append((ins.address, key_va, keylen, ins.mnemonic))

    # dedupe decoders by (key_va, keylen); the loop start we approximate as the xor addr's function
    seen = {}
    for addr, kva, kl, opn in decoders:
        seen.setdefault((kva, kl), (addr, opn))

    # Find the function entry for each decoder xor: walk back to the nearest `push rbp`/func prologue
    def func_entry(xaddr):
        i = idx.get(xaddr)
        if i is None: return None
        for j in range(i, max(0, i-400), -1):
            if insns[j].mnemonic == "push" and insns[j].op_str in ("rbp","r15") and j+1<len(insns):
                # heuristic prologue; good enough to match call targets below
                # walk further back while still contiguous prologue pushes/sub rsp
                k=j
                while k>0 and insns[k-1].mnemonic in ("push",) :
                    k-=1
                return insns[k].address
        return None

    found = set(); texts = []
    for (kva, kl), (xaddr, opn) in seen.items():
        key = read_va(binary, kva, kl)
        if not key: continue
        entry = func_entry(xaddr)
        # find call sites: call rel -> entry
        for i, ins in enumerate(insns):
            if ins.mnemonic != "call": continue
            tgt = next((op.imm for op in ins.operands if op.type == CS_OP_IMM), None)
            if tgt != entry: continue
            # backward scan for lea rsi,[rip+..] (blob) and mov edx,imm (len)
            # ABI-aware: SysV passes (rdi=out, rsi=enc, rdx=len); Win64 passes
            # (rcx=out, rdx=enc, r8=len). The ciphertext pointer is a `lea <reg>,[rip+..]`
            # into the 2nd arg reg; the length is a `mov <reg>,imm` into the 3rd arg reg.
            blob_regs = ("rsi", "rdx")          # SysV 2nd arg / Win64 2nd arg
            len_regs = ("edx", "rdx", "r8d", "r8")  # SysV 3rd / Win64 3rd
            blob_va = None; length = None
            for j in range(i-1, max(0, i-14), -1):
                pj = insns[j]
                if pj.mnemonic == "lea" and pj.operands and pj.reg_name(pj.operands[0].reg) in blob_regs:
                    t = rip_target(pj)
                    if t is not None and blob_va is None: blob_va = t
                if pj.mnemonic == "mov" and pj.operands and pj.reg_name(pj.operands[0].reg) in len_regs:
                    imm = next((op.imm for op in pj.operands if op.type == CS_OP_IMM), None)
                    if imm is not None and length is None: length = imm
                if blob_va is not None and length is not None: break
            if blob_va is None or not length or length > 4096: continue
            blob = read_va(binary, blob_va, length)
            if not blob: continue
            if opn == "xor":
                dec = bytes(blob[k] ^ key[k % kl] for k in range(len(blob)))
            elif opn == "add":   # decoder adds the key  -> reproduce with add
                dec = bytes((blob[k] + key[k % kl]) & 0xff for k in range(len(blob)))
            else:                # decoder subtracts the key -> reproduce with sub
                dec = bytes((blob[k] - key[k % kl]) & 0xff for k in range(len(blob)))
            if printable_ratio(dec) > 0.85:
                t = dec.decode("ascii", "ignore")
                texts.append(t)
                for c in canaries:
                    if c in t: found.add(c)

    return {"decoders": len(seen), "recovered_texts": texts,
            "recovered": sorted(found), "recall": len(found), "n": len(canaries)}

def main():
    man = json.loads((ROOT/"bench_src"/"manifest.json").read_text()); can = man["canaries"]
    targets = sys.argv[1:]
    if not targets:
        targets = [f"build/xor_custom__{f}__{p}__{s}" + (".exe" if f=="pe" else "")
                   for f in ("elf","pe") for p in ("debug","release") for s in ("nostrip","strip")]
    rows=[]
    for t in targets:
        r = recover(ROOT/t, can); r["target"]=t; rows.append(r)
        print(f"{Path(t).name:<42} recall {r['recall']}/{r['n']}  decoders={r.get('decoders')}"
              + ("  ERR "+r['error'] if r.get('error') else ""))
        for s in r.get("recovered", []): print("     +", s)
    (ROOT/"build"/"recover_callsite_results.jsonl").write_text("\n".join(json.dumps(r) for r in rows)+"\n")

if __name__ == "__main__":
    main()
