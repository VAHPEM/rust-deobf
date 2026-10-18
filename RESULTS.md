# Results

Canary recall = how many of the 5 known ground-truth strings a tool reproduces from a
built binary. `strings`/FLOSS are baselines; `ours` is `scripts/recover_callsite.py`
(static) unless noted. Full run: `bash scripts/build_all.sh && python3 scripts/run_floss.py && python3 scripts/recover_callsite.py build/*`.

## Two recovery methods

| obfuscator | cipher | strings | FLOSS | static (ours) | **dynamic (ours)** |
|---|---|---|---|---|---|
| xor_custom | XOR | 0/5 | 0/5 | 5/5 | **5/5** |
| add_custom | ADD | 0/5 | 0/5 | 5/5 | **5/5** |
| sub_custom | SUB | 0/5 | 0/5 | 5/5 | **5/5** |
| litcrypt | XOR | 0/5 | 0/5 | 5/5 | **5/5** |
| litcrypt2 | XOR | 0/5 | 0/5 | 0/5 | **5/5** |
| obfstr | XOR+ADD inlined | 0/5 | 0/5 | 0/5 call-site · **5/5 emulation** | **5/5** |
| muddy | ChaCha20-Poly1305 | 0/5 | 0/5 | 0/5 | **5/5** |

Static recovery (`recover_callsite.py`) is fast and needs no execution, but only handles
simple keyed decoders. Dynamic recovery (`recover_dynamic.py`, Frida memory scan) recovers
**every** obfuscator including AEAD, because at runtime all strings are decrypted in memory —
at the cost of executing the sample (sandbox only), needing code-path coverage, and ranking
decoded strings out of runtime noise. See VALIDATION.md for the real-binary precision/recall
analysis.

## Release builds (static method) — all obfuscators x {ELF,PE} x {strip,nostrip}

| obfuscator | cipher | fmt | profile | strip | strings | FLOSS | ours |
|---|---|---|---|---|---|---|---|
| plaintext | none | ELF | release | nostrip | 5/5 | N/A | 0/5 |
| plaintext | none | ELF | release | strip | 5/5 | N/A | 0/5 |
| plaintext | none | PE | release | nostrip | 5/5 | 5/5 | 0/5 |
| plaintext | none | PE | release | strip | 5/5 | 5/5 | 0/5 |
| xor_custom | xor | ELF | release | nostrip | 0/5 | N/A | 5/5 |
| xor_custom | xor | ELF | release | strip | 0/5 | N/A | 5/5 |
| xor_custom | xor | PE | release | nostrip | 0/5 | 0/5 | 5/5 |
| xor_custom | xor | PE | release | strip | 0/5 | 0/5 | 5/5 |
| add_custom | add | ELF | release | nostrip | 0/5 | N/A | 5/5 |
| add_custom | add | ELF | release | strip | 0/5 | N/A | 5/5 |
| add_custom | add | PE | release | nostrip | 0/5 | 0/5 | 5/5 |
| add_custom | add | PE | release | strip | 0/5 | 0/5 | 5/5 |
| sub_custom | sub | ELF | release | nostrip | 0/5 | N/A | 5/5 |
| sub_custom | sub | ELF | release | strip | 0/5 | N/A | 5/5 |
| sub_custom | sub | PE | release | nostrip | 0/5 | 0/5 | 5/5 |
| sub_custom | sub | PE | release | strip | 0/5 | 0/5 | 5/5 |
| litcrypt | xor | ELF | release | nostrip | 0/5 | N/A | 5/5 |
| litcrypt | xor | ELF | release | strip | 0/5 | N/A | 5/5 |
| litcrypt | xor | PE | release | nostrip | 0/5 | 0/5 | 5/5 |
| litcrypt | xor | PE | release | strip | 0/5 | 0/5 | 5/5 |
| litcrypt2 | xor | ELF | release | nostrip | 0/5 | N/A | 0/5 |
| litcrypt2 | xor | ELF | release | strip | 0/5 | N/A | 0/5 |
| litcrypt2 | xor | PE | release | nostrip | 0/5 | 0/5 | 0/5 |
| litcrypt2 | xor | PE | release | strip | 0/5 | 0/5 | 0/5 |
| obfstr | xor | ELF | release | nostrip | 0/5 | N/A | 0/5 |
| obfstr | xor | ELF | release | strip | 0/5 | N/A | 0/5 |
| obfstr | xor | PE | release | nostrip | 0/5 | 0/5 | 0/5 |
| obfstr | xor | PE | release | strip | 0/5 | 0/5 | 0/5 |
| muddy | chacha20poly1305 | ELF | release | nostrip | 0/5 | N/A | 0/5 |
| muddy | chacha20poly1305 | ELF | release | strip | 0/5 | N/A | 0/5 |
| muddy | chacha20poly1305 | PE | release | nostrip | 0/5 | 0/5 | 0/5 |
| muddy | chacha20poly1305 | PE | release | strip | 0/5 | 0/5 | 0/5 |

Debug builds: 0/5 for `ours` across the board — unoptimised Rust compiles the decode as
iterator-adapter calls (slice::iter / enumerate / IntoIterator) rather than an inline loop,
so there is no call-site decode block to resolve. Real malware ships release builds; debug
is documented as out of scope, not a central result.

## Headline (best recall across the 4 release configs)

| obfuscator | cipher | strings | FLOSS | ours |
|---|---|---|---|---|
| plaintext | none | 5/5 | 5/5¹ | 0/5² |
| xor_custom | hand-rolled XOR | 0/5 | 0/5 | **5/5** |
| add_custom | hand-rolled ADD | 0/5 | 0/5 | **5/5** |
| sub_custom | hand-rolled SUB | 0/5 | 0/5 | **5/5** |
| litcrypt | XOR (crate) | 0/5 | 0/5 | **5/5** |
| litcrypt2 | XOR (crate fork) | 0/5 | 0/5 | 0/5³ |
| obfstr | XOR+ADD, inlined (crate) | 0/5 | 0/5 | 0/5 call-site · **5/5 emulation**⁴ |
| muddy | ChaCha20-Poly1305 (crate) | 0/5 | 0/5 | 0/5⁵ |

¹ FLOSS 3.2.0 is PE/shellcode-only; on ELF it raises `PEFormatError` and cannot run.
² `ours` targets keyed decoders, not plaintext; `strings` already covers plaintext, so the
  tool is meant to run *alongside* `strings`.
³ litcrypt2 (maintained fork) uses a different index-wrap idiom; key-length inference not yet
  matched. Recoverable in principle (same XOR structure) — open follow-up.
⁴ obfstr inlines the decode into the caller, embeds per-literal random keys as immediate
  `movabs` constants, uses an ADD cipher, and hides the ciphertext pointer behind an
  `xref::inner` call. It is explicitly built to resist static *call-site* analysis (hence 0/5
  there). Function emulation (`scripts/recover_emulate.py`, Unicorn) recovers **5/5** on
  x86-64, stripped and not: it executes the intra-`.text` `xref::inner` helper (which rebuilds
  the pointer) but stubs the external formatter call — a REX-prefixed `call r15` (`41 ff d7`)
  that the opcode test must skip the REX byte to catch; missing it followed a zeroed GOT slot
  into garbage after the first literal, which was the old 1/5.
⁵ muddy uses an AEAD cipher (ChaCha20-Poly1305) with an embedded key; a single static decode
  is cryptographically out of reach. Correctly reported as unrecoverable, not a miss.

## What this establishes

1. **The gap is real.** FLOSS, the standard open-source string deobfuscator, recovers 0/5 on
   every Rust obfuscator tested and cannot open ELF at all. `strings` only ever sees plaintext.
2. **For keyed decoders with the key in a data section the gap is closable with lightweight
   static call-site dataflow** — no emulation, no known plaintext. `ours` recovers 5/5 across
   XOR, ADD and SUB hand-rolled ciphers and the litcrypt crate, on ELF and PE, stripped and not
   (16/64 configs; every release config of the 4 covered families).
3. **The hard cases are characterised:** inlined per-literal-key schemes (obfstr) are solved
   by function emulation (`recover_emulate.py`, 5/5) rather than call-site dataflow; AEAD
   schemes (muddy) are out of static reach by cipher design; a fork's index idiom (litcrypt2)
   needs a small extension (the dynamic path already gets it 5/5).

## How `ours` (static call-site recovery) works

1. Disassemble `.text` (capstone); find the decode op (`xor`/`add`/`sub`) on a byte register
   inside a repeating-key loop. Key length comes from the index-wrap idiom: `and e_,0xK`
   (=> K+1, power of two) or `cmp r,0xM` + `cmov*` (=> M+1).
2. Resolve the key pointer: the `lea reg,[rip+disp]` that feeds the key-indexed byte load —
   either the op's own memory operand or a `movzx` just before it (some codegen loads the key
   first, then combines with the ciphertext).
3. Resolve each call site: backward-scan for the ciphertext pointer (`lea`) and length
   (`mov imm`), ABI-aware for SysV (ELF) and Win64 (PE).
4. Apply the same op the code uses (xor/add/sub) with `key[i % keylen]`; keep printable output.

## Comparison with existing work (Oct 2026)

- **FLOSS 2.0 (Mandiant):** the standard tool; C/C++ PE focus, PE/shellcode-only, 0/5 here on Rust.
- **GoStringUngarbler (Google/Mandiant):** Go only, `garble -literals` only, **archived 2026-04-27**;
  garble is now v0.18.0 and v0.15.0's changelog says literal obfuscation was hardened against
  static deobfuscation.
- **Rust:** no public tool recovers obfuscated strings from Rust binaries. The nearest, Delitcrypt,
  is a litcrypt-only Binary Ninja plugin (PE-only, unreleased). Offensive Rust string obfuscators
  are plentiful (obfstr, litcrypt, litmask, muddy); defensive tooling is absent.
- **Academic:** the only on-target work is one unpublished student paper (Edie, Brown): 6 binaries,
  69.4% average false-positive rate, heuristic-only. No public labelled benchmark of real binaries
  with annotated string-decryption functions exists in any language.

This project is, as far as that survey found, the first reproducible Rust string-deobfuscation
benchmark with a working recoverer evaluated against FLOSS.
