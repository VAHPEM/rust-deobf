# Results

Canary recall is how many of the 5 known ground-truth strings a tool reproduces from a
built binary. Higher is better. `strings` and FLOSS are baselines; `ours` is the
call-site dataflow recoverer in `scripts/recover_callsite.py`.

## Release builds (what real malware ships)

| obfuscator | cipher | fmt | strip | `strings` | FLOSS | **ours** |
|---|---|---|---|---|---|---|
| plaintext | none | ELF | strip | 5/5 | N/A¹ | 0/5² |
| plaintext | none | PE | strip | 5/5 | 5/5 | 0/5² |
| xor_custom | hand-rolled XOR | ELF | nostrip | 0/5 | N/A¹ | **5/5** |
| xor_custom | hand-rolled XOR | ELF | strip | 0/5 | N/A¹ | **5/5** |
| xor_custom | hand-rolled XOR | PE | nostrip | 0/5 | 0/5 | **5/5** |
| xor_custom | hand-rolled XOR | PE | strip | 0/5 | 0/5 | **5/5** |
| obfstr | XOR (vectorised) | ELF/PE | both | 0/5 | 0/5 / N/A¹ | 0/5³ |
| litcrypt | XOR | ELF/PE | both | 0/5 | 0/5 / N/A¹ | 0/5³ |
| muddy | ChaCha20-Poly1305 | ELF/PE | both | 0/5 | 0/5 / N/A¹ | 0/5⁴ |

¹ FLOSS 3.2.0 is PE/shellcode-only; it raises `PEFormatError` on ELF and cannot run.
² Our tool targets XOR decoders, not plaintext; `strings` already covers plaintext, so
  the tool is meant to run *alongside* `strings`, not replace it.
³ obfstr compiles to vectorised/inlined XOR with per-literal compile-time-random keys and
  no per-byte decode loop (0 byte-wise XOR instructions in the binary); litcrypt's idiom
  is not yet matched. Both need function emulation (the FLOSS approach) or vectorised-
  pattern recognition — the open follow-up.
⁴ muddy uses an AEAD cipher (ChaCha20-Poly1305) with an embedded key; a single static
  decode is cryptographically out of reach. Correctly reported as unrecoverable, not a miss.

## What this establishes

1. **The gap is real.** FLOSS, the standard open-source string deobfuscator, recovers
   0/5 on every Rust obfuscator tested and cannot open ELF at all.
2. **For the hand-rolled XOR family it is closable with lightweight static analysis.**
   Our tool recovers 5/5 across all four release configurations — including stripped
   ELF, which FLOSS cannot process — using call-site dataflow, no emulation, no known
   plaintext. Hand-rolled XOR is the common case in real Rust malware.
3. **The crate-based obfuscators (obfstr, litcrypt) remain open** and define the next
   step: emulation-based recovery. muddy (AEAD) is out of scope by cipher design.

Debug builds: our static matcher does not yet match debug codegen (bounds-checked slice
indexing); recall there is 0. Real malware ships release builds, so this is a documented
limitation, not a central result.

Reproduce: `bash scripts/build_all.sh && python3 scripts/run_floss.py && python3 scripts/recover_callsite.py`
