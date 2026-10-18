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
bench_src/gen_projects.py     generate benign Rust programs that print known canaries, one per
                              obfuscation crate (obfstr, litcrypt, litcrypt2, muddy, cryptify)
                              plus hand-written XOR/ADD/SUB decoders and a plaintext control
scripts/recover.py            unified CLI: static recovery + emulation fallback
scripts/build_all.sh          build the matrix {ELF,PE}x{debug,release}x{strip,nostrip}
scripts/run_floss.py          baseline: strings(1) and FLOSS canary recall
scripts/recover_callsite.py   our recoverer: static call-site dataflow for XOR/ADD/SUB decoders
scripts/recover_emulate.py    emulation PoC (Unicorn) for inlined decoders (obfstr)
scripts/recover_dynamic.py    dynamic recovery via runtime memory scan (Frida) — works on real optimised builds
scripts/recover_arm64.py      static recovery ported to AArch64/ARM64 (new: no prior tool)
build/summary.json            consolidated comparison  (build/results_table.md = full matrix)
RESULTS.md                    the micro-benchmark results table
VALIDATION.md                 what happens on REAL binaries (precision + recall findings)
```

The sample programs are benign: they only print strings, exactly as Mandiant's own FLOSS
test corpus does. No payloads, no real malware, no live indicators — all strings are
author-generated canaries.

## Reality check

Micro-benchmark numbers below look strong, but see **VALIDATION.md**: on real binaries the
tool has a filterable precision problem (~5 false positives on 30 MB ripgrep, down from 271)
and an unsolved recall problem (call-site resolution breaks on optimised litcrypt builds;
obfstr needs emulation). It is a PoC, not a finished tool.

## Headline result

FLOSS recovers **0/5** canaries on every Rust obfuscator and cannot open ELF at all.
Our static call-site recoverer gets **5/5** on four keyed-decoder families — hand-rolled
XOR, ADD and SUB, plus the **litcrypt** crate — across every release configuration
(ELF and PE, stripped and not: 16/64 configs). obfstr (inlined per-literal keys, built to
resist static analysis) is partially recovered by emulation (1/5); litcrypt2 (fork) needs a
small extension; muddy (AEAD) is out of static reach by cipher design. Full matrix and a
survey of existing tools: RESULTS.md.

## Usage

```bash
python scripts/recover.py path/to/binary          # recover strings from one binary
python scripts/recover.py binary --no-emulate      # static only (fast)
```

It prints the decoded strings. Static recovery handles keyed XOR/ADD/SUB decoders and
litcrypt; the emulation fallback handles inlined decoders (obfstr, partial).

## How the recoverer works

No emulation, no known plaintext. It mirrors FLOSS's "find the decoder, recover its output"
idea with lightweight static dataflow instead of a CPU emulator:

1. Disassemble `.text` (capstone); find the decode op (`xor`/`add`/`sub`) on a byte register
   in a repeating-key loop. Key length from the index-wrap idiom: `and e_,0xK` (K+1) or
   `cmp r,0xM`+`cmov*` (M+1).
2. Resolve the key pointer: the `lea reg,[rip+disp]` feeding the key-indexed byte load —
   the op's own memory operand or a `movzx` just before it.
3. Resolve each call site: backward-scan for ciphertext pointer (`lea`) and length
   (`mov imm`), ABI-aware for SysV (ELF) and Win64 (PE).
4. Apply the code's own op (xor/add/sub) with `key[i % keylen]`; keep printable output.

obfstr needs the emulation path (`scripts/recover_emulate.py`): it inlines the decode with
per-literal immediate keys and hides the data pointer behind a helper call, so there is no
static key to read.

## Setup

```
rustup target add x86_64-pc-windows-gnu      # PE builds (needs mingw-w64)
pip install lief capstone unicorn
python3 -m venv floss && floss/bin/pip install flare-floss
```

## Scope / ethics

Defensive RE research only. Inputs are synthetic benign binaries; the tooling reads and
decodes binaries, it produces no offensive capability.
