# rust-string-deobf

A reproducible benchmark and recovery tooling for **string deobfuscation in Rust
binaries** — defensive reverse-engineering research for malware triage.

## Why

Mandiant's FLOSS is the standard open-source tool for pulling obfuscated strings out of
malware, but it is built for C/C++ PE binaries. Rust malware is rising, and defensive
tooling for it is effectively absent (confirmed Oct 2026): the one Go equivalent,
GoStringUngarbler, was archived 2026-04-27 and only ever handled `garble -literals`; no
public tool recovers obfuscated strings from Rust binaries, and no labelled benchmark of
real binaries with annotated string-decryption functions exists in any language.

This project (a) builds such a benchmark for Rust and (b) measures existing tools against
it, then (c) implements a recoverer for the case they miss.

## What's here

```
bench_src/gen_projects.py     generate benign Rust programs that print known canaries,
                              one per obfuscation crate (obfstr, litcrypt, muddy) plus a
                              hand-written XOR decoder and a plaintext control
scripts/build_all.sh          build the matrix {ELF,PE}x{debug,release}x{strip,nostrip}
scripts/run_floss.py          baseline: strings(1) and FLOSS canary recall
scripts/recover_callsite.py   our recoverer: static call-site dataflow for XOR decoders
build/summary.json            consolidated comparison
RESULTS.md                    the results table and what it establishes
```

The sample programs are benign: they only print strings, exactly as Mandiant's own FLOSS
test corpus does. No payloads, no real malware, no live indicators — all strings are
author-generated canaries.

## Headline result

FLOSS recovers **0/5** canaries on every Rust obfuscator and cannot open ELF at all.
Our call-site recoverer gets **5/5** on the hand-rolled XOR family across all four release
configurations (including stripped ELF). obfstr/litcrypt (vectorised/inlined XOR) and
muddy (AEAD) remain open — see RESULTS.md.

## How the recoverer works

No emulation, no known plaintext. It mirrors FLOSS's "find the decoder, recover its
output" idea with lightweight static dataflow instead of a CPU emulator:

1. Disassemble `.text` (capstone); find the repeating-key XOR decode loop
   (`and e_, 0xK` key mask → key length K+1; `xor dst, [key+i]`).
2. Resolve the key: the `lea reg,[rip+disp]` feeding the XOR's key operand (base *or*
   index register).
3. Resolve each call site: backward-scan for the ciphertext pointer (`lea`, 2nd arg) and
   length (`mov imm`, 3rd arg), ABI-aware for both SysV (ELF) and Win64 (PE).
4. Decode `blob[i] ^ key[i % keylen]`, keep printable results.

## Setup

```
rustup target add x86_64-pc-windows-gnu      # PE builds (needs mingw-w64)
pip install lief capstone unicorn
python3 -m venv floss && floss/bin/pip install flare-floss
```

## Scope / ethics

Defensive RE research only. Inputs are synthetic benign binaries; the tooling reads and
decodes binaries, it produces no offensive capability.
