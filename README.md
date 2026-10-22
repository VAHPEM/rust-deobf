# rust-deobf

**Recover obfuscated strings from Rust binaries** — static, emulation, and dynamic recovery,
on **x86-64 and ARM64**, with a reproducible benchmark against Mandiant FLOSS.

Rust malware is rising and the string-deobfuscation tooling for it is effectively absent.
`strings` only ever sees plaintext, and FLOSS — the standard open-source string deobfuscator —
recovers **0/5** planted strings on every common Rust obfuscation crate. This project closes
that gap: three recoverers that get **5/5**, plus the benchmark that measures the difference.

> Defensive reverse-engineering research for malware triage. All test inputs are **benign**
> programs that print author-generated canary strings — no payloads, no real malware, no live
> indicators.

---

## The result

Canary-recall on benign Rust programs, one per obfuscation crate (keys/ciphertext embedded,
release builds):

| obfuscator | cipher | `strings` | FLOSS | **static (ours)** | **dynamic (ours)** |
|---|---|:--:|:--:|:--:|:--:|
| xor_custom | hand-rolled XOR | 0/5 | 0/5 | **5/5** | **5/5** |
| add_custom | hand-rolled ADD | 0/5 | 0/5 | **5/5** | **5/5** |
| sub_custom | hand-rolled SUB | 0/5 | 0/5 | **5/5** | **5/5** |
| litcrypt | XOR, runtime key | 0/5 | 0/5 | **5/5** | **5/5** |
| litcrypt2 | XOR, stride-permuted key | 0/5 | 0/5 | **5/5** | **5/5** |
| obfstr | XOR+ADD, inlined | 0/5 | 0/5 | **5/5** (emulation) | **5/5** |
| tight strings | stack buffer XORed in place by a (vectorised) loop | 0/5 | 0/5 | **5/5** (emulation) | **5/5** |
| cryptify (default key) | XOR, crate-default key | 0/5 | 0/5 | **5/5** | **5/5** |
| cryptify (custom key) | XOR, key from env at build *and* run time | 0/5 | 0/5 | —¹ | **5/5**¹ |
| muddy | ChaCha20-Poly1305 (AEAD) | 0/5 | 0/5 | — | **5/5** |

Across **every** release configuration — ELF and PE, stripped and not — and on **both x86-64
and AArch64**. As far as an Oct-2026 survey found, this is the **first string-deobfuscation
tooling to target ARM64 Rust** at all.

<sub>¹ cryptify reads `CRYPTIFY_KEY` again at runtime: with a custom key the sample only decrypts
when run with that variable set, and the key is not in the binary. `recover_cryptify` detects
the crate and says so.</sub>

<sub>Baseline is FLOSS 3.2.0 (PE/shellcode-only; raises on ELF). FLOSS 4.x adds ELF/Mach-O
layout, but its language string extractors are still PE-oriented and recover **0/5** on
*obfuscated* Rust — only plain `&str` blobs. See `VALIDATION.md` §8 for the full FLOSS
coverage map.</sub>

---

## What it does

Three recoverers, picked by how hard the target is — run the cheap one first:

- **Static call-site recovery** (`recover_callsite.py` x86-64, `recover_arm64.py` AArch64) —
  reads the binary, never runs it. Finds the decode loop, resolves the key and each ciphertext
  pointer with ABI-aware dataflow, and decrypts. 5/5 on all five keyed families, any release
  config, both architectures. Needs only `lief` + `capstone`.
- **Emulation recovery** (`recover_emulate.py`, Unicorn) — for the inlined case (obfstr) where
  there is no static key to read: emulate each function, snapshot the plaintext it materialises
  in memory. 5/5 on obfstr, x86-64 and ARM64, without running the whole program. Works without
  known plaintext: it reports strings that are not already in the file (FLOSS's rule for decoded
  strings) and ranks functions by decoder features first, so obfstr is found after 1–15 functions;
  0 false positives on git, curl, bash, python, openssl, tar, xz and cargo. Unicorn emulates ARM64
  cross-host, so no ARM machine needed.
- **Stack strings** (`recover_stackstrings.py`) — immediates written to the stack frame, including
  the `movabs reg, imm64; mov [rbp-k], reg` form compilers use for 8-byte chunks.
- **Dynamic recovery** (`recover_dynamic.py`, Frida) — runs the sample in a sandbox and diffs
  decrypted memory against the static strings. Cipher- and arch-agnostic, so it even handles
  AEAD (muddy) and inlined (obfstr). **Isolated analysis VM only.**

Beyond strings, the same engines drive config/C2 extraction, hash-obfuscated API-import
resolution, unpacked stage-2 carving, Rust crate+version & panic-site recovery, and
MBA / opaque-predicate / control-flow-flattening analysis — see `ARTIFACT_TIERS.md`.

## Quick start

```bash
git clone https://github.com/VAHPEM/rust-deobf.git
cd rust-deobf
python3 -m pip install lief capstone unicorn z3-solver frida frida-tools

# any host, never runs the sample: auto-detects x86-64/ARM64 + ELF/PE, runs static call-site
# recovery, falls back to Unicorn emulation when that finds nothing, adds stack strings
python3 scripts/recover.py path/to/binary
python3 scripts/recover.py path/to/binary --json                  # records with addresses
python3 scripts/recover.py path/to/binary --floss-json out.json   # open with: floss -n 6 out.json
python3 scripts/recover.py samples/ --jsonl triage.jsonl          # triage a whole directory

# AEAD / runtime-only decoders — inside an isolated analysis VM ONLY
python3 scripts/recover_dynamic.py path/to/binary [-- arg1 arg2 ...]
```

Strings shaped like indicators are tagged (`[url]`, `[ip]`, `[domain]`, `[path]`, `[registry]`,
`[email]`). Every recovered string comes with where it came from: decoder function, call site and ciphertext
address for call-site recovery, the emulated function for inlined decoders, the store instruction
for stack strings. `--floss-json` writes them as a **FLOSS results document**, so the strings
FLOSS cannot recover from Rust show up in `floss`, `floss --html` and the FLOSS web viewer next to
the file's static strings.

Static recovery needs only `lief` + `capstone`; `unicorn` is for emulation, `z3-solver` for
expression analysis, `frida` for the dynamic tools (`pip install -r requirements.txt` covers all
but frida). Every script ships a `--selftest`, and `pytest tests` checks the README's recall and
precision claims on the benchmark — CI rebuilds it with the current stable rustc every week,
because a new compiler can change the decoder idioms the recoverers key on.

---

## Why it exists

FLOSS is built for C/C++ PE binaries. For Rust, defensive tooling is effectively absent
(confirmed Oct 2026): the one Go equivalent, GoStringUngarbler, was archived 2026-04-27 and
only ever handled `garble -literals`; no public tool recovers obfuscated strings from Rust
binaries, and no labelled benchmark of real binaries with annotated string-decryption
functions existed in any language. This project (a) builds that benchmark for Rust, (b)
measures existing tools against it, and (c) implements the recoverers for the cases they miss.

## Honest limitations

This is a **proof-of-concept, not a finished product** (full detail in `VALIDATION.md`):

- **Static precision** is filterable, not perfect: ~5 false positives on a 30 MB `ripgrep`
  (down from 271 before layered filtering) and 0 on 14 other real binaries — reproduce with
  `scripts/measure_fp.py`.
- **Static recall** depends on recognising the decode idiom, and the idiom drifts with the
  compiler: rebuilding with rustc 1.97 changed litcrypt2's index wrap, and `rust-lld` turns ARM64
  `adrp`+`add` into `adr` — both broke recovery until handled (`VALIDATION.md` §9). Rebuild the
  benchmark with the current toolchain (`scripts/build_all.sh`, `ARM64=1` for AArch64) rather
  than trusting old result files. Release builds only; debug builds are not recovered.
- **Emulated strings on ARM64** can keep a few stale bytes at the end (`…-20261018int`): Rust
  strings are not NUL-terminated and the recovered buffer is a stack snapshot.
- **Dynamic recovery** is cipher- and arch-agnostic but only recovers strings on code paths you
  actually execute, and its output must be ranked out of runtime noise.

Full matrix: `RESULTS.md` · reproducible metrics: `METRICS.md` · real-binary precision/recall
and cross-architecture validation: `VALIDATION.md` · artifact-recovery tiers: `ARTIFACT_TIERS.md`.

---

## How the recoverers work

### Static call-site recovery (x86-64 and AArch64)

No known plaintext, no emulation — lightweight static dataflow:

1. Disassemble `.text` (capstone), find the decode op (`xor`/`add`/`sub`, or ARM64
   `eor`/`add`/`sub`) on a byte register inside a repeating-key loop. Key length comes from the
   index-wrap idiom: `and r, 0xK` → K+1, or `cmp r, 0xM` + conditional-move/select → M+1.
2. Resolve the key pointer — x86-64: the `lea reg,[rip+disp]` feeding the key-indexed byte load;
   AArch64: the `adrp`+`add` pair.
3. Resolve each call site: backward-scan for the ciphertext pointer and length, ABI-aware for
   SysV (ELF x86-64), Win64 (PE), and AAPCS64 (ELF ARM64), including slice-struct passing in
   optimised builds.
4. Apply the code's own op with `key[i % keylen]`; keep printable output. Precision is defended
   with a text-likeness filter, an English-trigram gate, and a ≥2-call-site corroboration
   requirement. litcrypt2's stride-permuted key schedule gets a dedicated recogniser on each
   architecture.

### Emulation recovery (Unicorn, for inlined decoders)

obfstr defeats call-site dataflow by design: it inlines the decode with per-literal immediate
keys and hides the data pointer behind an `xref::inner` call, so there is no static key to read.
`recover_emulate.py` emulates each function under an instruction budget and captures the
plaintext it writes to memory. The decisive detail differs by architecture: on x86-64 the
formatter call is an external `call r15` through an unrelocated GOT (a **REX-prefixed**
`41 ff d7` — miss the prefix and emulation follows a zero pointer into garbage after the first
literal) and is *stubbed*; on a static ELF the ARM64 print is an *intra-text* `bl` into the
in-`.text` fmt runtime, so the ARM path snapshots the stack right before each call instead.
**5/5** on obfstr, x86-64 and AArch64, stripped and not.

### Dynamic recovery (runtime memory scan)

Run the sample in a controlled process, let it decrypt its strings in memory, then diff writable
memory against the static `strings` of the loaded images and report the difference, ranked by
text-likeness. Cipher- and architecture-agnostic because it never parses the decoder — it
observes the result. This is the standard malware-analysis route and the reason it handles AEAD
(muddy) and inlined (obfstr) builds that no static method reaches.

---

## Running the benchmark & VMs

| task | environment | why |
|---|---|---|
| **Static / emulation recovery** | any host, no VM | reads the binary; emulation runs under Unicorn, never natively |
| **Building the benchmark** | any host with Rust (`rustup`) | cross-compiles, does not run samples |
| **Dynamic recovery** | **isolated analysis VM — required** | it *executes* the target and scans its whole address space |

Dynamic recovery **must** run inside a dedicated, isolated VM (Kali or Windows 11), never on
your host: you are executing an untrusted sample, and the memory scan reads all readable+writable
memory, so anything else resident in the process surfaces as noise. Snapshot before detonation,
revert after. Rebuild the corpus with `bench_src/gen_projects.py` + `scripts/build_all.sh`;
reproduce the baseline with `scripts/run_floss.py` and `scripts/evaluate_all.py`. FLOSS is only
needed to reproduce the baseline column — the recoverers don't depend on it. Full install notes
(Rust targets, cross-linkers, FLOSS) are below the layout.

<details>
<summary>Repository layout & full install notes</summary>

```
bench_src/   benign Rust programs printing 5 known canaries, one crate per obfuscator
scripts/     recover.py (CLI) + recover_callsite / recover_arm64 / recover_emulate /
             recover_dynamic / recover_stackstrings, the eval harness, and the artifact tiers
build/       built sample binaries + consolidated result JSON/tables
RESULTS.md · METRICS.md · VALIDATION.md · ARTIFACT_TIERS.md
```

Python 3.10+. Static recovery needs `lief` + `capstone`; add `unicorn` for emulation,
`z3-solver` for `deobf_expr`, `frida`/`frida-tools` for the dynamic tools. Rust is needed only
to (re)build the benchmark — install [rustup](https://rustup.rs/), then
`rustup target add x86_64-pc-windows-gnu` (PE, plus the `mingw-w64` linker). For ARM64,
`rustup target add aarch64-unknown-linux-musl` and run `ARM64=1 scripts/build_all.sh`: it links
static binaries with the bundled `rust-lld`, so no ARM machine or cross gcc is needed. FLOSS (optional, baseline only):
`pip install flare-floss` into a venv and point the `FLOSS` constant in `run_floss.py` at it.

</details>

---

## Scope / ethics

Defensive RE research only. All inputs are synthetic, benign binaries that print
author-generated canaries (see `bench_src/manifest.json`); the tooling reads and decodes
binaries and produces no offensive capability. Run dynamic analysis only against samples you are
authorised to analyse, inside an isolated VM.
