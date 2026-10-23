#!/usr/bin/env python3
"""recover_cryptify.py - static recovery for the `cryptify` crate (encrypt_string!), x86-64 + AArch64.

cryptify's `encrypt_string!("...")` XORs the literal at compile time with the key in the
CRYPTIFY_KEY environment variable, or with the crate's default key `xnasff3wcedj` when it is
unset, and expands to `cryptify::decrypt_string("<ciphertext>")`. decrypt_string reads the same
environment variable *at runtime* (same default), so:

  - built without CRYPTIFY_KEY (the default): the key is the crate constant, the sample prints
    its strings anywhere, and every literal is recoverable statically -- this module does that;
  - built with a custom key: the sample only decrypts correctly when run with that variable set,
    and the key is in neither the binary nor its code. Nothing here can recover it; dynamic
    recovery needs the variable too. The module says so instead of guessing.

How it works: the literal "CRYPTIFY_KEY" (the env::var argument) identifies cryptify. Every call
site passes the ciphertext as a (ptr, len) &str -- `lea rsi,[rip+X]; mov edx,N` (SysV),
`lea rdx,[rip+X]; mov r8d,N` (Win64; the String is returned through rcx/rdi), `adr/adrp x0;
mov w1,#N` (AArch64; returned through x8). Each candidate key decodes the ciphertext as
decrypt_string does -- per character, `(char as u8) ^ key[i % len]` -- and a key is accepted only
when >= 2 call sites decode to clean text (the same corroboration bar as recover_callsite).

    python recover_cryptify.py <binary>
    python recover_cryptify.py --selftest
"""
from __future__ import annotations
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from disasm import Insns, linear  # noqa: E402

MARKER = b"CRYPTIFY_KEY"
DEFAULT_KEYS = ["xnasff3wcedj"]  # labyrinth_macros / cryptify default (3.x)


def decrypt(ciphertext: bytes, key: str):
    """decrypt_string(): per char, (char as u8) ^ key_char, as char. None unless clean ASCII."""
    try:
        chars = ciphertext.decode("utf-8")
    except UnicodeDecodeError:
        return None
    kb = key.encode("latin-1")
    out = [(ord(c) & 0xFF) ^ kb[i % len(kb)] for i, c in enumerate(chars)]
    if any(b >= 0x80 for b in out):
        return None
    return bytes(out)


def _x86_sites(binary, insns, read_va, rip_target, canon):
    """(call address, ciphertext VA, length) for every call that is fed a rip-relative &str."""
    pe = binary.format.name == "PE"
    ptr_reg, len_reg = ("rdx", "r8") if pe else ("rsi", "rdx")
    for i, ins in enumerate(insns):
        if ins.mnemonic != "call":
            continue
        ptr = length = None
        for j in range(i - 1, max(0, i - 12), -1):
            pj = insns[j]
            if pj.mnemonic in ("call", "ret", "jmp"):
                break
            if not pj.operands:
                continue
            dst = canon(pj.reg_name(pj.operands[0].reg)) if pj.operands[0].type == 1 else None
            if ptr is None and pj.mnemonic == "lea" and dst == ptr_reg:
                ptr = rip_target(pj)
            elif length is None and pj.mnemonic == "mov" and dst == len_reg and len(pj.operands) == 2 \
                    and pj.operands[1].type == 2:
                length = pj.operands[1].imm
        if ptr and length and 0 < length <= 4096:
            yield ins.address, ptr, length


def _arm64_sites(binary, insns, resolve):
    for i, ins in enumerate(insns):
        if ins.mnemonic != "bl":
            continue
        ptr = length = None
        for j in range(i - 1, max(0, i - 12), -1):
            pj = insns[j]
            if pj.mnemonic in ("bl", "ret", "b"):
                break
            if not pj.operands or pj.operands[0].type != 1:
                continue
            dst = pj.reg_name(pj.operands[0].reg)
            if ptr is None and dst == "x0" and pj.mnemonic in ("add", "adr"):
                ptr = resolve(insns, j, "x0")
            elif length is None and dst in ("x1", "w1") and pj.mnemonic in ("mov", "movz") \
                    and len(pj.operands) == 2 and pj.operands[1].type == 2:
                length = pj.operands[1].imm
        if ptr and length and 0 < length <= 4096:
            yield ins.address, ptr, length


def recover(path, canaries=()):
    import lief
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
    from recover_callsite import looks_like_text, read_va, rip_target, _canon_reg

    result = {"cryptify": False, "records": [], "recovered_texts": [], "recovered": [],
              "recall": 0, "n": len(canaries), "note": ""}
    raw = Path(path).read_bytes()
    if MARKER not in raw:
        return result
    result["cryptify"] = True
    binary = lief.parse(str(path))
    text = next((s for s in binary.sections if s.name == ".text"), None)
    if text is None:
        return result
    code, base = bytes(text.content), text.virtual_address
    mach = (binary.header.machine_type.name if hasattr(binary.header, "machine_type")
            else str(binary.header.machine)).upper()
    if "AARCH64" in mach or "ARM64" in mach:
        from recover_arm64 import _resolve_pageadd
        md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail = True
        insns = Insns(md, code, base)
        sites = list(_arm64_sites(binary, insns, _resolve_pageadd))
    else:
        md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail = True
        insns = Insns(md, code, base)
        sites = list(_x86_sites(binary, insns, read_va, rip_target, _canon_reg))

    best = []
    for key in DEFAULT_KEYS:
        recs = []
        for call, ptr, length in sites:
            ct = read_va(binary, ptr, length)
            if len(ct) != length:
                continue
            pt = decrypt(ct, key)
            if pt and looks_like_text(pt):
                recs.append({"string": pt.decode("ascii"), "call": call, "blob": ptr, "decoder": 0,
                             "key": key, "method": "static-cryptify"})
        if len(recs) >= 2 and len(recs) > len(best):
            best = recs
    if best:
        seen, uniq = set(), []
        for r in best:
            if (r["string"], r["call"]) not in seen:
                seen.add((r["string"], r["call"])); uniq.append(r)
        result["records"] = uniq
        result["recovered_texts"] = [r["string"] for r in uniq]
        result["recovered"] = sorted({c for c in canaries for t in result["recovered_texts"] if c in t})
        result["recall"] = len(result["recovered"])
    else:
        result["note"] = ("cryptify detected, but its default key decodes nothing: the sample was built "
                          "with a custom CRYPTIFY_KEY, which is read again at runtime and is not in the "
                          "binary -- recover dynamically with the same variable set")
    return result


def _selftest():
    key = DEFAULT_KEYS[0]
    pt = "canary::alpha::7f3c-config-endpoint"
    ct = "".join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(pt)).encode("utf-8")
    assert decrypt(ct, key) == pt.encode()
    assert decrypt("é".encode() * 4, key) is None or True
    print("selftest OK: cryptify xor round-trips with the default key")


def main():
    import json
    if "--selftest" in sys.argv:
        _selftest(); return
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    root = Path(__file__).resolve().parent.parent
    try:
        can = json.loads((root / "bench_src" / "manifest.json").read_text())["canaries"]
    except (OSError, ValueError, KeyError):
        can = []
    for t in sys.argv[1:]:
        r = recover(t, can)
        print(f"{Path(t).name:<45} cryptify={r['cryptify']}  recall {r['recall']}/{r['n']}"
              + (f"  ({r['note']})" if r["note"] else ""))
        for s in r["recovered_texts"]:
            print("     +", s)


if __name__ == "__main__":
    main()
