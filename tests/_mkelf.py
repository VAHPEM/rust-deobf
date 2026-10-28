"""Tiny ELF builder for tests: 64- or 32-bit x86, one RWX .text + .shstrtab (+ optional NOBITS .bss).

Builds synthetic, benign inputs at test time so no binary has to be committed."""
import struct
def mkelf(code, bits=64, base=0x400000, bss=0):
    shstr = b"\x00.text\x00.shstrtab\x00.bss\x00"
    if bits == 64:
        eh, ph, sh = 64, 56, 64
    else:
        eh, ph, sh = 52, 32, 40
    text_off = 0x1000
    text_va = base + text_off
    shstr_off = text_off + len(code)
    shoff = (shstr_off + len(shstr) + 7) & ~7
    nsh = 4 if bss else 3
    bss_va = (text_va + len(code) + 0xfff) & ~0xfff
    out = bytearray(shoff + sh * nsh)
    ident = b"\x7fELF" + bytes([2 if bits == 64 else 1, 1, 1]) + b"\x00" * 9
    if bits == 64:
        struct.pack_into("<16sHHIQQQIHHHHHH", out, 0, ident, 2, 0x3e, 1, text_va, eh, shoff, 0, eh, ph, 1, sh, nsh, 2)
        struct.pack_into("<IIQQQQQQ", out, eh, 1, 7, text_off, text_va, text_va, len(code), len(code) + (bss_va - text_va + bss if bss else 0), 0x1000)
    else:
        struct.pack_into("<16sHHIIIIIHHHHHH", out, 0, ident, 2, 3, 1, text_va, eh, shoff, 0, eh, ph, 1, sh, nsh, 2)
        struct.pack_into("<IIIIIIII", out, eh, 1, text_off, text_va, text_va, len(code), len(code) + (bss_va - text_va + bss if bss else 0), 7, 0x1000)
    out[text_off:text_off + len(code)] = code
    out[shstr_off:shstr_off + len(shstr)] = shstr
    def shdr(i, name, typ, flags, addr, off, size):
        if bits == 64:
            struct.pack_into("<IIQQQQIIQQ", out, shoff + i * sh, name, typ, flags, addr, off, size, 0, 0, 16, 0)
        else:
            struct.pack_into("<IIIIIIIIII", out, shoff + i * sh, name, typ, flags, addr, off, size, 0, 0, 16, 0)
    shdr(1, 1, 1, 7, text_va, text_off, len(code))          # .text PROGBITS WAX
    shdr(2, 7, 3, 0, 0, shstr_off, len(shstr))               # .shstrtab
    if bss:
        shdr(3, 17, 8, 3, bss_va, shstr_off, bss)            # .bss NOBITS WA
    return bytes(out), text_va, bss_va
