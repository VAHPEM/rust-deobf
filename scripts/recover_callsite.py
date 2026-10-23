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
import json, re, sys, string
from pathlib import Path
import lief
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_MEM, CS_OP_IMM, CS_OP_REG
sys.path.insert(0, str(Path(__file__).resolve().parent))
from disasm import linear  # noqa: E402

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

_IP = r"(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
_TLD = r"(?:com|net|org|io|ru|cn|xyz|top|info|biz|onion|dev|app|cc|tk|site|online|club|example|local|lan|corp|internal)"
_REG = r"(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU)(?:\\[\w .{}$-]+)+"
_REG_NOHIVE = r"(?:SOFTWARE|Software|SYSTEM|System)\\[\w .{}$-]+(?:\\[\w .{}$-]+)+"
# Windows kernel-object names: mutexes, events, sections in the Global/Local/Session namespaces
_KOBJ = r"(?:Global|Local|Session\\\d+|\\?BaseNamedObjects)\\[\w.{}$#@+-]{3,}"
_WINPATH = r"(?:[A-Za-z]:|\\\\[\w.$-]+\\[\w.$-]+|%[A-Za-z_]+%)\\(?:[\w .$()~-]+\\)*[\w .$()~-]+"

# (kind, pattern). Each pattern describes the whole indicator; looks_like_ioc() matches it
# against the whole string, contains_ioc() finds it inside a longer one.
_IOC_RULES = [
    ("url", r"[a-z][a-z0-9+.-]{1,15}://[^\s/$.?#][^\s]*"),
    ("ip", _IP + r"(?::\d{1,5})?"),
    ("domain", r"(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+" + _TLD + r"(?::\d{1,5})?(?:/\S*)?"),
    ("path", _WINPATH),
    ("path", r"/(?:[\w.-]+/)+[\w.-]*"),
    ("registry", _REG),
    ("registry", _REG_NOHIVE),
    ("mutex", _KOBJ),
    ("email", r"[\w.+-]+@[\w-]+\.[\w.-]+"),
]
_IOC_PATTERNS = [re.compile("^" + p + "$", re.I if k in ("url", "domain", "registry") else 0)
                 for k, p in _IOC_RULES]
_IOC_KINDS = tuple(k for k, _ in _IOC_RULES)
# inside a longer string: not glued to a neighbouring word character on either side
_IOC_SEARCH = [re.compile(r"(?<![\w.\\])" + p.replace("(?=.{4,253}$)", "") + r"(?![\w\\])",
                          re.I if k in ("url", "domain", "registry") else 0)
               for k, p in _IOC_RULES if k != "domain"]
_IOC_SEARCH_KINDS = tuple(k for k, _ in _IOC_RULES if k != "domain")


def looks_like_ioc(t: str) -> bool:
    """Whether a string has the shape of a network/host indicator."""
    return any(p.match(t) for p in _IOC_PATTERNS)


def contains_ioc(t: str) -> bool:
    """An indicator embedded in a longer, otherwise ordinary string (`agent::10.1.2.3:443`,
    `cfg=C:\\ProgramData\\x.db`). The indicator must be a substantial part of the string and the
    rest must be plain text, so a stray dotted quad in random bytes does not qualify."""
    if not all(32 <= ord(c) < 127 for c in t):
        return False
    for p in _IOC_SEARCH:
        for m in p.finditer(t):
            span = m.end() - m.start()
            if span < 7:
                continue
            rest = t[:m.start()] + t[m.end():]
            if span / len(t) >= 0.5:
                return True
            if rest and sum(c.isalnum() or c in " _-:/=.,;@#" for c in rest) / len(rest) >= 0.9:
                return True
    return False


def ioc_tags(t: str) -> list:
    """Indicator kinds a string matches or contains, e.g. ["url"], ["ip"], ["mutex"]."""
    kinds = {kind for kind, p in zip(_IOC_KINDS, _IOC_PATTERNS) if p.match(t)}
    if not kinds and contains_ioc(t):
        kinds = {kind for kind, p in zip(_IOC_SEARCH_KINDS, _IOC_SEARCH) if p.search(t)}
    return sorted(kinds)


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
    # Indicators (URLs, domains, IPs, paths, registry keys) are what triage is after; they are
    # often short, not English (`http://c2.example`) or letter-free (an IP), so the checks below
    # would reject them. Their shape is specific enough to accept them directly.
    if looks_like_ioc(t) or contains_ioc(t):
        return True
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

def _canon_reg(name):
    """Map a sub-register name to its 64-bit parent (r14d->r14, eax->rax) for matching."""
    if name is None:
        return None
    legacy = {"eax": "rax", "ebx": "rbx", "ecx": "rcx", "edx": "rdx", "esi": "rsi",
              "edi": "rdi", "ebp": "rbp", "esp": "rsp",
              "ax": "rax", "bx": "rbx", "cx": "rcx", "dx": "rdx",
              "al": "rax", "bl": "rbx", "cl": "rcx", "dl": "rdx",
              "sil": "rsi", "dil": "rdi", "bpl": "rbp"}
    if name in legacy:
        return legacy[name]
    if name.startswith("r") and (name[-1] in "dwb") and name[1:2].isdigit():
        return name[:-1]            # r14d/r14w/r14b -> r14
    return name


def _imm_into(insns, j, regs):
    """Immediate loaded into one of `regs` by insns[j]: `mov r, imm`, or the size-optimised
    `push imm; pop r` pair that opt-level="z" emits for small constants."""
    pj = insns[j]
    if not pj.operands or pj.operands[0].type != CS_OP_REG:
        return None
    if _canon_reg(pj.reg_name(pj.operands[0].reg)) not in {_canon_reg(r) for r in regs}:
        return None
    if pj.mnemonic == "mov":
        return next((op.imm for op in pj.operands if op.type == CS_OP_IMM), None)
    if pj.mnemonic == "pop" and j > 0 and insns[j - 1].mnemonic == "push":
        return next((op.imm for op in insns[j - 1].operands if op.type == CS_OP_IMM), None)
    return None


def _is_pe(binary) -> bool:
    try:
        return binary.format.name == "PE"
    except Exception:
        return False


def recover_litcrypt2(binary, insns, canaries):
    """Recover strings from litcrypt2's `lc!`, whose index idiom differs from litcrypt v1.

    litcrypt2 walks a fixed-length key (64 bytes here) with a stride (+2) that wraps via
    `lea idx,[idx+STRIDE]; cmp idx,KEYLEN; sete r8; cmovb idx,tmp` -- a permutation of
    0..KEYLEN-1, not the `key[i % keylen]` that recover()'s generic path models (its
    key-length inference reads this as KEYLEN+1 and resolves nothing). This dedicated pass
    recognises the schedule from that instruction cluster, reads the rip-relative key, and
    replays the exact state machine at each call site. Same >=2-call-site corroboration as
    recover(), so it does not add false positives on ordinary binaries.
    """
    out, n = [], len(insns)
    call_tgts = [op.imm for s in insns if s.mnemonic == "call"
                 for op in s.operands if op.type == CS_OP_IMM]
    for i, ins in enumerate(insns):
        if ins.mnemonic != "cmovb" or not ins.operands:
            continue
        idx_reg = _canon_reg(ins.reg_name(ins.operands[0].reg))
        # KEYLEN from a `cmp <reg>, imm` just before the cmovb
        keylen = None
        for j in range(i - 1, max(0, i - 5), -1):
            if insns[j].mnemonic == "cmp":
                im = next((op.imm for op in insns[j].operands if op.type == CS_OP_IMM), None)
                if im and 8 <= im <= 1024:
                    keylen = im
                break
        if not keylen:
            continue
        # STRIDE from a `lea <reg>,[base+disp]` (the index advance) before the cmovb
        stride = None
        for j in range(i - 1, max(0, i - 8), -1):
            pj = insns[j]
            if pj.mnemonic == "lea" and pj.operands:
                mo = next((op for op in pj.operands if op.type == CS_OP_MEM), None)
                if mo and mo.mem.base and not mo.mem.index and 0 < mo.mem.disp <= 16:
                    stride = mo.mem.disp
                    break
        if not stride:
            continue
        # Wrap value: the index register is zeroed, then `set<cc>` writes 0/1 into it, and the
        # `cmovb` keeps `idx+STRIDE` only while it is below KEYLEN. So once the index runs past
        # the key, the next index is 1 when <cc> holds and 0 otherwise. rustc emits either
        # `sete` (idx+STRIDE == KEYLEN -> 1, past it -> 0) or `setne` (== -> 0, past -> 1),
        # depending on version and key length, so read it instead of assuming one.
        wrap_eq, wrap_past = 1, 0
        for j in range(i - 1, max(0, i - 4), -1):
            m = insns[j].mnemonic
            if m in ("sete", "setz"):
                break
            if m in ("setne", "setnz"):
                wrap_eq, wrap_past = 0, 1
                break
        # key base: a `xor r8, byte ptr [A+B]` within a few insns after; A or B is a lea-rip
        key_va = None
        for j in range(i + 1, min(n, i + 10)):
            pj = insns[j]
            if pj.mnemonic == "xor" and len(pj.operands) == 2 \
               and pj.operands[0].type == CS_OP_REG and pj.operands[1].type == CS_OP_MEM:
                mo = pj.operands[1].mem
                for reg in (pj.reg_name(mo.base) if mo.base else None,
                            pj.reg_name(mo.index) if mo.index else None):
                    if not reg:
                        continue
                    for k in range(j - 1, max(0, j - 60), -1):
                        pk = insns[k]
                        if pk.mnemonic == "lea" and pk.operands \
                           and pk.reg_name(pk.operands[0].reg) == reg:
                            t = rip_target(pk)
                            if t is not None:
                                key_va = t
                                break
                    if key_va:
                        break
            if key_va:
                break
        if not key_va:
            continue
        key = read_va(binary, key_va, keylen)
        if len(key) < keylen:
            continue
        # initial index = `mov <idx_reg>, imm` before the loop; first-byte const = `xor r8,imm8`
        init_k = None
        for j in range(i - 1, max(0, i - 20), -1):
            pj = insns[j]
            if pj.mnemonic == "mov" and len(pj.operands) == 2 \
               and pj.operands[0].type == CS_OP_REG and pj.operands[1].type == CS_OP_IMM \
               and _canon_reg(pj.reg_name(pj.operands[0].reg)) == idx_reg \
               and 0 <= pj.operands[1].imm < keylen:
                init_k = pj.operands[1].imm
                break
        if init_k is None:
            init_k = stride
        c0 = None
        for j in range(i - 1, max(0, i - 30), -1):
            pj = insns[j]
            if pj.mnemonic == "xor" and len(pj.operands) == 2 \
               and pj.operands[0].type == CS_OP_REG and pj.operands[1].type == CS_OP_IMM \
               and 0 < pj.operands[1].imm < 256:
                c0 = pj.operands[1].imm
                break
        if c0 is None:
            c0 = key[0]
        entry = max((t for t in call_tgts if t <= ins.address), default=None)
        if entry is None:
            continue

        def schedule(ln):
            seq, k = [], init_k
            for _ in range(1, ln):
                seq.append(k)
                nxt = k + stride
                k = nxt if nxt < keylen else (wrap_eq if nxt == keylen else wrap_past)
            return seq

        def decode(ct):
            if not ct:
                return b""
            o = bytearray([ct[0] ^ c0])
            for p, kk in enumerate(schedule(len(ct)), 1):
                o.append(ct[p] ^ key[kk])
            return bytes(o)

        # lc!(..) calls decrypt_bytes(out, ptr, len): ptr/len are the 2nd/3rd arguments, i.e.
        # rsi/rdx under SysV (ELF) and rdx/r8 under the Win64 ABI (PE)
        blob_reg, len_reg = ("rdx", "r8") if _is_pe(binary) else ("rsi", "rdx")
        texts = []
        for ci, cins in enumerate(insns):
            if cins.mnemonic != "call":
                continue
            if next((op.imm for op in cins.operands if op.type == CS_OP_IMM), None) != entry:
                continue
            blob = length = None
            for j in range(ci - 1, max(0, ci - 20), -1):
                pj = insns[j]
                if pj.mnemonic == "lea" and pj.operands \
                   and pj.reg_name(pj.operands[0].reg) == blob_reg and blob is None:
                    t = rip_target(pj)
                    if t is not None:
                        blob = t
                if length is None:
                    im = _imm_into(insns, j, (len_reg,))
                    if im is not None and 0 < im <= 4096:
                        length = im
                if blob and length:
                    break
            if blob and length:
                dec = decode(read_va(binary, blob, length))
                if dec and looks_like_text(dec):
                    texts.append({"string": dec.decode("ascii", "ignore"), "decoder": entry,
                                  "call": cins.address, "blob": blob, "method": "static-litcrypt2"})
        if len(texts) >= 2:          # same corroboration bar as recover()
            out.extend(texts)
            break
    return out


def recover(path, canaries):
    loaded = load(path)
    if loaded is None: return {"error": "no .text", "recall": 0, "n": len(canaries)}
    binary, code, base = loaded
    md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail = True
    insns = list(linear(md, code, base))
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

    found = set(); texts = []; records = []
    for (kva, kl), (xaddr, opn) in seen.items():
        key = read_va(binary, kva, kl)
        if not key: continue
        # a "key" that is mostly zero bytes leaves the data as it was: the loop is not a decoder,
        # and what it "decodes" is ordinary text with a few bytes flipped (ripgrep's
        # `caused by:` came out as `z4Yaused8by:`)
        if 2 * key.count(0) >= len(key): continue
        entry = func_entry(xaddr)
        if entry is None:
            continue    # (a None entry matched every register-indirect call as a "call site")
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
                if length is None:
                    imm = _imm_into(insns, j, len_regs)
                    if imm is not None: length = imm
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
                decoder_texts.append({"string": dec.decode("ascii", "ignore"), "decoder": entry,
                                      "call": ins.address, "blob": blob_va, "method": "static"})

        # Corroboration gate: accept a decoder only if >=2 of its call sites decode to
        # clean, word-like text with the one key. A byte-loop misclassified as a decoder
        # in a real binary almost never clears that bar twice, so this is the main thing
        # keeping false positives down on large real binaries. Identifier/hash-only strings
        # (e.g. a pure build-id) that the language gate cannot distinguish from noise are
        # the known miss -- see RESULTS.md; verifying candidates by emulation is the fix.
        if len(decoder_texts) >= 2:
            records.extend(decoder_texts)

    # litcrypt2's stride-permutation schedule is not an `i % keylen` repeat, so the generic
    # loop above cannot resolve it; its dedicated recogniser runs as a second pass.
    records.extend(recover_litcrypt2(binary, insns, canaries))

    for rec in records:
        texts.append(rec["string"])
        for c in canaries:
            if c in rec["string"]:
                found.add(c)
    # records: one per recovered string, {"string", "decoder", "call", "blob", "method"} with the
    # decoder function, the call site and the ciphertext as virtual addresses
    return {"decoders": len(seen), "recovered_texts": texts, "records": records,
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
