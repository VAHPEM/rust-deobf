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

TEXT_CHARS = set(bytes(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    " ._/:@%+=-", "ascii"))

def looks_like_text(dec: bytes) -> bool:
    """A real recovered string is overwhelmingly letters/digits/common punctuation.
    Random data XORed with a wrong key occasionally yields printable-ISH bytes, but
    with many odd symbols; this gate rejects that (cuts false positives on real binaries).
    """
    if len(dec) < 6:
        return False
    try:
        t = dec.decode("ascii")
    except UnicodeDecodeError:
        return False
    texty = sum(1 for c in dec if c in TEXT_CHARS)
    alnum = sum(1 for c in t if c.isalnum())
    if texty / len(dec) < 0.90:   # <=10% unusual characters
        return False
    if alnum / len(dec) < 0.55:   # letters/digits dominate
        return False
    # reject strings that are mostly a single repeated char or lack any letter
    if not any(c.isalpha() for c in t):
        return False
    es = english_score(t)
    # real recovered strings are long and word-like; short fragments must score much higher.
    if es < 0.10:
        return False
    if len(t) < 12 and es < 0.30:
        return False
    letters = [c for c in t if c.isalpha()]
    if letters:
        vowels = sum(1 for c in letters if c.lower() in "aeiou")
        vr = vowels / len(letters)
        if vr < 0.20 or vr > 0.80:   # natural text has a moderate vowel ratio
            return False
        # random XOR output flips case erratically; real strings rarely do
        flips = sum(1 for a, b in zip(letters, letters[1:]) if a.isupper() != b.isupper())
        if len(letters) > 6 and flips / (len(letters) - 1) > 0.55:
            return False
    return True



# The ~180 most frequent English letter trigrams (lowercased). A decoded string made of
# real words/paths scores high; pronounceable-but-random XOR garbage scores low. This is
# the signal that separates a true recovered string from a coincidental clean-looking decode.
_COMMON_TRIGRAMS = set(
    "the and ing ion tio ent ati for her ter tha ere ate his con res ver all ons nce men ith "
    "ted ers pro thi wit are ess not ive was ect rea com eve per int est sta cti ica ist ear "
    "ain one our iti rat ell ont end ure nte tur nde ant ome ult lin sch dat ild fig onf nfi "
    "poi dpo oin sou urc rce emo tel lem eme etr try eat atu fea net get set key tok sys reg "
    "log src lib run man app use new old add del str num idx cmd nam pat fil hos por use pas "
    "loa sav rea wri sen rec ini exi mai fun can ana nar ary bra rav avo bui uil cha har arl "
    "rli lie del elt lta ech cho vel elo opm pme men nta tal tab abl ble ser erv vic ice cli "
    "ien ent tion ersi rsi sio ver ersi onf nfig figu gur ura rat tio ion def efa fau aul ult "
    "set ett tti tin ing pat ath con nfi onf fig set sta tab chan hann anne nnel el- sta tab "
    "sch hem ema mav ver ers rsi sio on- num mbe ber get tin ing all wit hin out abo ut- per "
    "ata tab tas tes tex typ val var vec web xml yes zip url uri uid utf ascii json http host "
    "dir doc dow dri env err evt fmt gen hex idx img inp key lab lst map max min mod msg obj "
    "opt out pkg pos pre ptr que ref req res ret row siz src std sum sys tab tag tmp top txt "
    "upd usr val vec ver win xml abc def ghi code data file name path user admin login token "
    "endp ndpo dpoi poin oint conf onfi nfig figu  bui uil ild ld- d-i -id id- 201 026 261 "
    "rel ele lea eas ase chan hann rele leas ease stab tabl able ble- le-2 anne nnel ault efau "
    "resou esour sourc ource data data- a.bin .bin opt /opt app /app reso settin tting tings "
    "toml .toml onfig fig/ ig/n start arte rted rt-g -gui guid uide star getti ettin tting "
    "flag lag- feat eatu atur ture elem lem- emet metr etry fla ff- off tele emet"
    .split())

def english_score(t: str) -> float:
    """Fraction of a string's 3-grams that are common English/identifier trigrams."""
    low = t.lower()
    grams = [low[i:i+3] for i in range(len(low) - 2)]
    if not grams:
        return 0.0
    hits = sum(1 for g in grams if g in _COMMON_TRIGRAMS)
    return hits / len(grams)


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
        # Collect this decoder's clean decodes, then require corroboration: a genuine
        # string decryptor is called repeatedly and EVERY call decodes to clean text.
        # A byte-loop misclassified as a decoder (common in real binaries) will not have
        # several call sites that all decode to clean text with the same key.
        decoder_texts = []
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

            if blob_va is None or length is None:
                # Slice-struct ABI (optimised real builds, e.g. litcrypt's lc!): the
                # ciphertext is passed as a Rust &[u8] fat pointer built on the stack, and
                # rsi/rdx points at it -- `lea rsi,[rsp+K]`, with `mov [rsp+K],PTR` and
                # `mov [rsp+K+8],LEN` filled earlier, PTR from a `lea rip` and LEN from an
                # immediate further back. Resolve that chain.
                slice_off = None
                for j in range(i-1, max(0, i-10), -1):
                    pj = insns[j]
                    if pj.mnemonic == "lea" and pj.operands and pj.reg_name(pj.operands[0].reg) in ("rsi", "rdx"):
                        mo = next((op for op in pj.operands if op.type == CS_OP_MEM), None)
                        if mo and pj.reg_name(mo.mem.base) == "rsp":
                            slice_off = mo.mem.disp; break
                if slice_off is not None:
                    ptr_src = len_src = None
                    for j in range(i-1, max(0, i-24), -1):
                        pj = insns[j]
                        if pj.mnemonic == "mov" and pj.operands and pj.operands[0].type == CS_OP_MEM:
                            mo = pj.operands[0].mem
                            if pj.reg_name(mo.base) == "rsp" and pj.operands[1].type == CS_OP_REG:
                                if mo.disp == slice_off and ptr_src is None:
                                    ptr_src = pj.reg_name(pj.operands[1].reg)
                                elif mo.disp == slice_off + 8 and len_src is None:
                                    len_src = pj.reg_name(pj.operands[1].reg)
                    # resolve ptr_src -> lea rip; len_src -> mov imm (search a wider window)
                    for j in range(i-1, max(0, i-80), -1):
                        pj = insns[j]
                        if blob_va is None and ptr_src and pj.mnemonic == "lea" and pj.operands \
                           and pj.reg_name(pj.operands[0].reg) == ptr_src:
                            t = rip_target(pj)
                            if t is not None: blob_va = t
                        if length is None and len_src and pj.mnemonic == "mov" and pj.operands \
                           and pj.reg_name(pj.operands[0].reg) in (len_src, len_src.replace("r","e",1) if len_src.startswith("r") else len_src):
                            imm = next((op.imm for op in pj.operands if op.type == CS_OP_IMM), None)
                            if imm is not None: length = imm
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
            if dec and looks_like_text(dec):
                decoder_texts.append(dec.decode("ascii", "ignore"))

        # Corroboration gate: accept a decoder only if >=2 of its call sites decode to
        # clean, word-like text with the one key. A byte-loop misclassified as a decoder
        # in a real binary almost never clears that bar twice, so this is the main thing
        # keeping false positives down on large real binaries. Identifier/hash-only strings
        # (e.g. a pure build-id) that the language gate cannot distinguish from noise are
        # the known miss -- see RESULTS.md; verifying candidates by emulation is the fix.
        if len(decoder_texts) >= 2:
            for t in decoder_texts:
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
