# rust-deobf

A reproducible benchmark and recovery tooling for **string deobfuscation in Rust
binaries** — defensive reverse-engineering research for malware triage.

Two recoverers (static + dynamic), a labelled micro-benchmark of benign Rust programs
built against every common string-obfuscation crate, and an honest evaluation against the
standard baseline (Mandiant FLOSS) on both synthetic and real binaries.

---

## Why

Mandiant's FLOSS is the standard open-source tool for pulling obfuscated strings out of
malware, but it is built for C/C++ PE binaries. Rust malware is rising and defensive
tooling for it is effectively absent (confirmed Oct 2026): the one Go equivalent,
GoStringUngarbler, was archived 2026-04-27 and only ever handled `garble -literals`; no
public tool recovers obfuscated strings from Rust binaries, and no labelled benchmark of
real binaries with annotated string-decryption functions exists in any language.

This project (a) builds such a benchmark for Rust, (b) measures existing tools against it,
and (c) implements two recoverers for the cases they miss — a fast static call-site
recoverer and a universal dynamic (runtime memory-scan) recoverer.

## Headline result

FLOSS recovers **0/5** canaries on every Rust obfuscator and cannot open ELF at all.

| obfuscator | cipher | `strings` | FLOSS | static (ours) | **dynamic (ours)** |
|---|---|---|---|---|---|
| xor_custom | XOR | 0/5 | 0/5 | 5/5 | **5/5** |
| add_custom | ADD | 0/5 | 0/5 | 5/5 | **5/5** |
| sub_custom | SUB | 0/5 | 0/5 | 5/5 | **5/5** |
| litcrypt | XOR (runtime key) | 0/5 | 0/5 | 5/5 | **5/5** |
| litcrypt2 | XOR (stride-permuted key) | 0/5 | 0/5 | **5/5** | **5/5** |
| obfstr | XOR+ADD inlined | 0/5 | 0/5 | 0/5 call-site · **5/5 emulation** | **5/5** |
| muddy | ChaCha20-Poly1305 | 0/5 | 0/5 | 0/5 | **5/5** |

- **Static recovery** (`recover_callsite.py` for x86-64, `recover_arm64.py` for AArch64) is
  fast and needs no execution. It gets **5/5** on the four hand-rolled/litcrypt keyed-decoder
  families across every release configuration — ELF and PE, stripped and not — and on
  **both** x86-64 and AArch64 (the first string recoverer to target ARM64 Rust), plus
  litcrypt2's stride-permuted key schedule (**5/5**, x86-64) via a dedicated recogniser.
- **Emulation recovery** (`recover_emulate.py`, Unicorn) handles the inlined case the
  call-site tool cannot: obfstr embeds per-literal keys as immediates and hides the data
  pointer behind an `xref::inner` call, so there is no static key to read. Emulating each
  function (executing the intra-`.text` `xref` helper, stubbing external/formatter calls)
  and scanning the bytes written to memory recovers **5/5** on obfstr, x86-64, stripped and
  not — no execution of the whole program, no known plaintext.
- **Dynamic recovery** (`recover_dynamic.py`, Frida memory scan) recovers **every**
  obfuscator including inlined (obfstr) and AEAD (muddy), because at runtime all strings are
  decrypted in memory — at the cost of executing the sample (**sandbox/VM only**), needing
  code-path coverage, and ranking decoded strings out of runtime noise.

Full matrix: `RESULTS.md`. Reproducible metrics: `METRICS.md`. Real-binary
precision/recall analysis and the cross-architecture validation: `VALIDATION.md`.

## Reality check

The micro-benchmark numbers look strong, but this is a **PoC, not a finished product** —
see `VALIDATION.md`. On real binaries the static tool has a filterable precision problem
(~5 false positives on a 30 MB `ripgrep`, down from 271 after layered filtering — and 0 on
14 other real binaries; reproduce with `scripts/measure_fp.py`) and a
recall problem (call-site resolution breaks on heavily optimised/inlined builds; obfstr
needs the emulation path — now 5/5; litcrypt2's stride-permuted schedule is now handled
statically — 5/5). The dynamic tool is cipher- and
arch-agnostic but only recovers strings on code paths you actually exercise, and its output
must be ranked out of runtime noise.

---

## Repository layout

```
bench_src/
  gen_projects.py        generate benign Rust programs that print 5 known canaries, one
                         crate per obfuscator (obfstr, litcrypt, litcrypt2, muddy, cryptify)
                         plus hand-written XOR/ADD/SUB decoders and a plaintext control
  <obfuscator>/          one Cargo project per obfuscation family (source of the benchmark)
  manifest.json          canaries + per-variant crate/env/cipher metadata
scripts/
  recover.py             unified CLI: auto-detect arch+format, dispatch to the right recoverer
  recover_callsite.py    static call-site dataflow recoverer (x86-64, ELF+PE)
  recover_arm64.py       static call-site dataflow recoverer (AArch64/ELF) — new, no prior tool
  recover_dynamic.py     dynamic recoverer via runtime memory scan (Frida) — works on real builds
  recover_emulate.py     emulation recoverer (Unicorn) for inlined decoders (obfstr 5/5)
  recover_stackstrings.py static stack-string recovery, x86-64 + ARM64 (immediate stores to stack slots)
  build_all.sh           build the matrix {ELF,PE} x {debug,release} x {strip,nostrip}
  run_floss.py           baseline: strings(1) + FLOSS canary recall
  evaluate_all.py        reproducible end-to-end eval -> METRICS.md
  measure_fp.py          precision: false positives of static recovery on real benign binaries
  measure_rust_meta.py   Tier-3 accuracy: crate/version + panic-site recovery vs Cargo.lock
  # artifact-recovery tiers (reuse the same static/dynamic engines; see ARTIFACT_TIERS.md)
  recover_artifacts.py   Tier 2: dynamic config/C2 recovery — URLs, IP:port, JSON, base64 (Frida)
  recover_rust_meta.py   Tier 3: static Rust structure — crates+versions, panic file:line, types
  recover_apihash.py     Tier 2: resolve hash-obfuscated API imports, statically
  dump_unpacked.py       Tier 2: dump + carve an unpacked stage-2 (Frida W->X; static carve core)
  deobf_expr.py          Tier 4: prove/simplify MBA + classify opaque predicates (z3)
  deobf_cff.py           Tier 4: locate control-flow-flattening dispatchers (static)
build/                   built sample binaries + consolidated result JSON/tables
RESULTS.md               micro-benchmark results table (full config matrix)
METRICS.md               machine-generated metrics from evaluate_all.py
VALIDATION.md            what happens on REAL binaries + cross-arch validation
ARTIFACT_TIERS.md        the artifact-recovery tiers above + their live validation
```

The sample programs are **benign**: they only print canary strings, exactly as Mandiant's
own FLOSS test corpus does. No payloads, no real malware, no live indicators — every string
is an author-generated canary (see `bench_src/manifest.json`).

---

## Download

```bash
git clone https://github.com/VAHPEM/rust-deobf.git
cd rust-deobf
```

## Dependencies & installation

### 1. Python (recovery tools) — required

Python 3.10+.

```bash
python3 -m pip install lief capstone unicorn z3-solver frida frida-tools
```

| package | used by | purpose |
|---|---|---|
| `lief` | all recoverers | parse ELF/PE, resolve VAs ↔ file offsets, detect arch/format |
| `capstone` | `recover_callsite.py`, `recover_arm64.py`, `deobf_cff.py`, `recover_apihash.py` | disassemble `.text` |
| `unicorn` | `recover_emulate.py` | CPU emulation for inlined decoders (obfstr) |
| `z3-solver` | `deobf_expr.py` | prove MBA simplifications / classify opaque predicates |
| `frida`, `frida-tools` | `recover_dynamic.py`, `recover_artifacts`/`dump_unpacked` (dynamic) | attach to the running sample and scan memory |
| `pefile` (optional) | `recover_apihash.py` corpus prep | dump a DLL's export names for `--names` |

Static recovery (`recover.py` → callsite/arm64) needs only `lief` + `capstone`. `unicorn`
is needed only for emulation, `z3-solver` only for `deobf_expr`, and `frida` only for the
dynamic tools. Each tool ships a `--selftest`; the artifact-recovery tiers are documented,
with their live validation, in `ARTIFACT_TIERS.md`.

### 2. Rust toolchain — required only to (re)build the benchmark

Install via [rustup](https://rustup.rs/), then add the targets you want to build for:

```bash
rustup target add x86_64-pc-windows-gnu      # PE / Windows cross-build
rustup target add aarch64-unknown-linux-gnu  # ARM64 ELF cross-build (optional)
```

System linkers for cross-building:

```bash
# Debian/Ubuntu/Kali
sudo apt install mingw-w64                    # PE linker (x86_64-pc-windows-gnu)
sudo apt install gcc-aarch64-linux-gnu        # ARM64 cross-linker (optional)
# macOS (Homebrew)
brew install mingw-w64
```

You do **not** need Rust to run the recoverers against a binary you already have — only to
regenerate/rebuild the benchmark corpus.

### 3. FLOSS — optional, for reproducing the baseline

```bash
python3 -m venv /opt/flossenv
/opt/flossenv/bin/pip install flare-floss
```

`run_floss.py` invokes FLOSS at `/opt/flossenv/bin/floss` (the `FLOSS` constant at the top
of the script) — install it there, or edit that one line to point at your own FLOSS. FLOSS
is only used to reproduce the baseline column; the recoverers do not depend on it.

---

## Required VMs / sandbox

| task | environment | why |
|---|---|---|
| **Static recovery** (`recover.py`, x86-64 & ARM64) | any host, no VM | reads the binary, never executes it |
| **Building the benchmark** | any host with Rust | cross-compiles, does not run samples |
| **Dynamic recovery** (`recover_dynamic.py`) | **isolated analysis VM — required** | it *executes* the target and scans its whole address space |

**Dynamic recovery must run inside a dedicated, isolated analysis VM** — never on your host.
Two reasons: (1) you are executing an untrusted sample; (2) the memory scan reads all
readable+writable memory of the process, so anything else resident in that process (env,
other secrets, injected-agent state) surfaces as noise and could leak in a shared
environment. In a clean VM the only interesting memory is the sample's own, which is the
point.

Recommended VMs (both validated):

- **Kali Linux** (ARM64 or x86-64) — used for the clean dynamic validation and for the
  cross-architecture (AArch64) static validation in `VALIDATION.md` §5–§6. Frida installs
  cleanly; reached over SSH. ARM64 Kali additionally lets you build and analyse AArch64 Rust
  binaries natively.
- **Windows 11** — optional, only if you want to detonate **PE** samples dynamically
  (dynamic recovery of a Windows-target binary must run on Windows). Static recovery of PE
  binaries works fine from any host, so this VM is niche.

Snapshot the VM before detonation and revert afterwards, as with any sample analysis.

---

## Usage

### Recover strings from a binary (static, no execution)

```bash
python3 scripts/recover.py path/to/binary
```

`recover.py` auto-detects architecture (x86-64 or AArch64) and format (ELF/PE) via `lief`
and dispatches to the matching static recoverer. It prints the decoded strings. For
optimised/inlined/AEAD builds it tells you to use the dynamic path.

### Recover strings from a hard binary (dynamic — **VM/sandbox only**)

```bash
# inside an isolated analysis VM only:
python3 scripts/recover_dynamic.py path/to/binary [-- arg1 arg2 ...]
```

Runs the sample, lets it decode its strings in memory, scans writable memory, and reports
strings that are **not** present statically (i.e. decoded at runtime), ranked by
text-likeness. Pass representative arguments so the decode paths actually execute — coverage
is exactly like sandbox detonation. Recovers every obfuscator including AEAD, regardless of
crate or inlining, because it observes the result instead of parsing the decoder.

### Rebuild the benchmark corpus

```bash
python3 bench_src/gen_projects.py     # regenerate the Cargo projects (idempotent)
bash   scripts/build_all.sh           # build {ELF,PE} x {debug,release} x {strip,nostrip}
```

### Reproduce the baseline and metrics

```bash
python3 scripts/run_floss.py                      # strings + FLOSS recall -> build/*.json
python3 scripts/evaluate_all.py [--ripgrep /path/to/rg]   # end-to-end -> METRICS.md
```

`--ripgrep` points the precision test at a real unobfuscated binary (optional; any large
release binary works).

---

## How the recoverers work

### Static call-site recovery (x86-64 and AArch64)

No known plaintext, no emulation. It mirrors FLOSS's "find the decoder, recover its output"
idea with lightweight static dataflow:

1. Disassemble `.text` (capstone) and find the decode op (`xor`/`add`/`sub`, or ARM64
   `eor`/`add`/`sub`) on a byte register inside a repeating-key loop. Key length comes from
   the index-wrap idiom: `and r, 0xK` → K+1, or `cmp r, 0xM` + conditional-move/select → M+1.
2. Resolve the key pointer — x86-64: the `lea reg,[rip+disp]` feeding the key-indexed byte
   load; AArch64: the `adrp`+`add` pair.
3. Resolve each call site: backward-scan for the ciphertext pointer and length, ABI-aware
   for SysV (ELF x86-64), Win64 (PE), and AAPCS64 (ELF ARM64), including slice-struct passing
   in optimised builds.
4. Apply the code's own op with `key[i % keylen]`; keep printable output. Precision is
   defended with a text-likeness filter, an English-trigram gate, and a ≥2-call-site
   corroboration requirement.

obfstr defeats call-site dataflow by design: it inlines the decode with per-literal immediate
keys and hides the data pointer behind an `xref::inner` call, so there is no static key to
read. The answer without executing the whole program is emulation.

### Emulation recovery (Unicorn, for inlined decoders)

`recover_emulate.py` emulates each function under an instruction budget and records the bytes
written to memory; the decoded plaintext obfstr materialises in `main`'s frame appears in
those writes. The decisive details: the intra-`.text` `xref::inner` call is *executed* (it
rebuilds the real ciphertext pointer from an argument whose low dword obfstr overwrites with
the key), while the external formatter call — `call r15` through an unrelocated GOT, a
**REX-prefixed** `41 ff d7` — is *stubbed*; miss the REX prefix and emulation follows a zero
pointer into garbage after the first literal (the old 1/5). With it, obfstr is **5/5** on
x86-64, stripped and not. Scope: this is for the inlined case only; keyed-decoder families
take their arguments from a caller and are the static tool's job, and AEAD (muddy) is out of
cryptographic reach.

### Dynamic recovery (runtime memory scan)

Run the sample in a controlled process, let it decrypt its strings in memory, then diff
writable memory against the static `strings` of the loaded images and report the difference.
Cipher- and architecture-agnostic because it never parses the decoder — it observes the
decrypted result. This is the standard malware-analysis route and the reason it handles AEAD
(muddy) and inlined (obfstr) builds that no static method reaches.

---

## Scope / ethics

Defensive RE research only. All inputs are synthetic, benign binaries that print
author-generated canaries; the tooling reads and decodes binaries and produces no offensive
capability. Run dynamic analysis only against samples you are authorised to analyse, inside
an isolated VM.
