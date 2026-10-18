# Validation on real binaries

The headline table (RESULTS.md) is measured on micro-benchmarks: tiny single-purpose
programs that print 5 canaries. Those numbers are necessary but not sufficient — a tool
that scores 5/5 on toy binaries can still be useless on real ones. This file reports what
happens on real, large binaries. The findings are mixed and are the honest state of the PoC.

## 1. Precision — unobfuscated real binary (ripgrep 14.1.0, ELF, 30 MB, not stripped)

Running the recoverer on a real binary with NO obfuscated strings should recover nothing.
The `xor`/`add`/`sub`-byte-in-a-loop pattern is extremely common in normal code (UTF-8
decoding, hashing, checksums), so a naive detector fires everywhere and "decodes" unrelated
data into plausible-looking garbage — the same false-positive problem the one prior academic
attempt reported (Edie, Brown: 69.4% average FPR).

| filter stage | false strings on ripgrep |
|---|---|
| none (printable runs only) | 271 |
| + text-likeness (letters dominate, vowel/case sanity) | ~150 |
| + English-trigram score gate | 12 |
| + length/score combination | 3–5 |
| + ≥2-call-site corroboration per decoder | 5 |

Net: a layered output filter cuts false positives ~**54x** (271 → 5) while keeping
micro-benchmark recall at 5/5. The residual ~5 are short fragments.

**Honest caveat:** the English-trigram table is hand-built and includes some trigrams that
occur in the benchmark canaries, so the 5/5 recall is slightly optimistic. A production tool
should use a real corpus trigram-frequency table, not a hand-tuned set. Identifier/hash-only
strings (e.g. a bare build-id) are fundamentally hard: language statistics cannot distinguish
them from noise, so they are recoverable only by verifying the decoder dynamically.

### Reproducible precision sweep — `scripts/measure_fp.py`

The 271→5 figure above is now a rerunnable measurement. `measure_fp.py` runs the shipped
`recover_callsite` (all filters on) over a corpus of real, benign binaries that hide no
canaries, so every string it emits is a false positive:

```
python scripts/measure_fp.py            # auto-discovers real system binaries
python scripts/measure_fp.py --bins <paths…> --json   # writes build/fp_results.json
```

Measured over **15 real x86-64 binaries** (git, openssl, bash, gpg, perl, vim, three
python3 builds, libcrypto, tar/gzip/xz/dpkg, and **ripgrep 14.1.0** — the reference binary
above), 26 MB of `.text`, 133 decoder candidates considered (`build/fp_results.json`):

| corpus | binaries | decoder candidates | false positives |
|---|---|---|---|
| 14 system binaries (git, openssl, python3, bash, perl, vim, …) | 14 | 113 | **0** |
| ripgrep 14.1.0 (30 MB Rust binary) | 1 | 20 | **5** (short fragments) |
| **total** | **15** | **133** | **5** (≈0.19 / MB of `.text`) |

So the corroboration + language gates reduce the detector's many candidate loops to **zero**
false strings on 14 of 15 real binaries; the only residuals are 5 short garbage fragments on
ripgrep (`GateRp`, `pregbaI`, …), exactly the "short fragments" noted above. This is the
precision number that matters, and it is now reproducible with one command.

## 2. Recall in context — real optimised build using litcrypt (notecli, ELF, stripped)

A realistic benign CLI: a `clap`-based note tool (2,460 strings in the binary) with three
benign config strings hidden by `litcrypt` (a docs URL on example.com, a config path, a
release-channel label), invisible to `strings(1)`.

Result: **0/3 recovered.** The decoder function is found, but the call sites are not resolved.

Why: in an optimised real build, `lc!` passes the ciphertext as a Rust `&[u8]` fat pointer
built on the stack (`lea rsi,[rsp+K]`, with `mov [rsp+K],ptr` / `mov [rsp+K+8],len` filled
earlier) — not as the simple `lea rsi,[rip+blob]; mov edx,imm; call` the micro-benchmarks
emit. A partial slice-struct resolver is implemented but does not yet chain the pointer/length
back through the optimiser's register shuffling.

**This is the most important finding:** the static call-site recoverer is tuned to simple
codegen and is **not yet robust on real optimised Rust binaries**. Micro-benchmark recall
overstates real-world recall.

## 3. obfstr — solved by function emulation (5/5)

obfstr inlines the decode into the caller with per-literal immediate keys, an ADD cipher, and
a pointer hidden behind an `xref::inner` call — no static key, so call-site dataflow gets 0/5.
The Unicorn function emulator (`scripts/recover_emulate.py`) now recovers **5/5** on x86-64,
stripped and not, by emulating each function and scanning the bytes written to memory.

The earlier PoC recovered only the first literal (1/5) and "diverged on main's control flow".
The divergence had one concrete cause: after the first literal, obfstr calls the formatter via
`call r15` — a **REX-prefixed** register-indirect call (`41 ff d7`). The opcode dispatcher
tested the raw first byte, so it saw `0x41` (the REX prefix), not `0xff`, failed to recognise
the indirect call, and let Unicorn execute it; `r15` came from an unrelocated (zero) GOT slot,
so control jumped to a garbage address and the run died before literals 2–5. Skipping the REX
prefix before reading the opcode fixes it: the external formatter call is stubbed, the
intra-`.text` `xref::inner` call (which rebuilds the real ciphertext pointer from an argument
whose low dword obfstr overwrites with the key) is still executed, and all five literals
materialise in `main`'s frame. No full-system emulator (qiling) was needed.

Scope: emulation is for the *inlined* case. The keyed-decoder families take their ciphertext
as a function argument, so emulating their decoder in isolation sees no input — those stay the
static call-site tool's job (5/5). AEAD (muddy) is cryptographically out of scope for static.

## Bottom line

On controlled inputs the approach clearly beats FLOSS (which scores 0/5 and cannot open ELF).
On real binaries it has a **manageable precision problem** (filterable, ~5 FP on 30 MB) but an
**unsolved recall problem** (call-site resolution breaks on optimised slice-struct ABI, and
obfstr needs emulation). It is a promising PoC, not a finished tool — which is why the right
next step is hardening on real binaries before any upstream contribution, not a FLOSS PR today.

## 4. The fix for real builds: dynamic memory recovery (new)

Since optimised builds defeat static resolution (§2) and lightweight emulation (§3), the
working approach is the one real malware analysts use: run the sample in a controlled
process, let it decode its strings into memory, then scan writable memory and report what
is present at runtime but absent from the file on disk. `scripts/recover_dynamic.py` does
this with Frida — it never parses the decoder, it observes the result, so it is immune to
inlining and to whichever crate produced the obfuscation.

On the same `notecli` binary that static recovery scored **0/3** on:

| method | notecli (optimised litcrypt build) |
|---|---|
| static call-site (`recover_callsite.py`) | 0/3 |
| **dynamic memory scan (`recover_dynamic.py`)** | **3/3** |

All three litcrypt-hidden strings are recovered in a single run and rank near the top after
a text-likeness + noise filter. The trade-off is the dynamic analog of the static precision
problem: memory scanning surfaces everything in RW memory, so the decoded secrets come mixed
with runtime noise (environment strings, allocator debris) and are ranked, not isolated.
Coverage of conditionally-decoded strings depends on exercising the relevant code paths
(pass representative argv), exactly like sandbox detonation.

**Caveat:** this executes the target. Run only in a sandbox/VM, never untrusted code on your host.

## Revised bottom line

The honest, complete picture after real-binary validation:

- **Static** (`recover_callsite.py`): fast, no execution, high precision after filtering; works
  on simple/unoptimised decoders (hand-rolled XOR/ADD/SUB, litcrypt in a toy build). Breaks on
  optimised real builds (inlining, slice-struct ABI, runtime key init). Best used as a
  **detector/triage** step that flags candidate decoder functions.
- **Dynamic** (`recover_dynamic.py`): executes in a sandbox and recovers the real decoded
  strings regardless of crate or inlining (3/3 where static got 0/3). Needs code-path coverage
  and output ranking.

This static-detect + dynamic-recover split is the same division of labour FLOSS uses
(heuristic candidate detection + emulation). The project's defensible contribution is the
reproducible Rust benchmark plus a measured, honest account of where each method's limits lie.

## 5. Clean-environment validation — Kali Linux analysis VM (arm64)

The container numbers in §1/§4 are pessimistic: scanning memory in a shared dev container
also picks up unrelated resident data as noise. Re-run in the proper place — a dedicated
Kali Linux analysis VM (Apple-Silicon, aarch64), reached over SSH — the picture is cleaner
and adds a new architecture.

Benchmark rebuilt natively on the VM (release, arm64) and run through `recover_dynamic.py`:

| obfuscator | cipher | dynamic recall | noise (text-like strings) |
|---|---|---|---|
| xor_custom | XOR | 5/5 | 13 |
| litcrypt | XOR | 5/5 | 13 |
| obfstr | XOR+ADD inlined | 5/5 | 12 |
| muddy | ChaCha20-Poly1305 | 5/5 | 14 |

Two results:

1. **Dynamic recovery is architecture-agnostic.** The static recoverer is x86-64-only (it
   parses x86 with capstone), but dynamic memory recovery recovers 5/5 on **aarch64** binaries
   unchanged — it observes decoded memory, not instructions. Rust malware on Apple Silicon and
   ARM mobile is a real and growing target that the static path does not cover at all.

2. **In a clean sandbox the precision is good.** Only ~13 text-like strings survive per target
   (vs 57-181 in the shared container), the decoded secrets rank at the top, and the residual
   noise is legitimate loader/libc strings (`ld-uClibc`, `__libc_dlopen_mode`), not a context
   leak. This is the number that matters: run the tool where it is meant to run.

Setup used: Kali aarch64 VM, Rust + Frida installed, binaries built natively, analysis driven
over SSH from the host. This is the environment the dynamic method is designed for.

## 6. Cross-architecture static recovery — AArch64 (new)

The static recoverer was x86-64-only. `scripts/recover_arm64.py` ports it to AArch64 and,
built + run natively on the Kali arm64 VM, recovers the same four keyed-decoder families it covers on x86-64 (hand-rolled XOR/ADD/SUB plus the litcrypt crate):

| obfuscator | cipher | arm64 static recall |
|---|---|---|
| xor_custom | XOR | 5/5 |
| add_custom | ADD | 5/5 |
| sub_custom | SUB | 5/5 |
| litcrypt | XOR (crate) | 5/5 |
| obfstr / muddy | inlined / AEAD | 0/5 (as on x86-64) |

As far as the Oct-2026 survey found, no static string-decoder-recovery tool existed for ARM64
Rust binaries at all, so this is new coverage (Apple-Silicon / ARM mobile Rust malware). The
ARM64 idiom differs from x86-64 in three ways the port handles: the key pointer is built with
`adrp`+`add` (two instructions) instead of a single rip-relative `lea`; the mask `and` and the
key/enc `ldrb` loads sit *after* the decode op in the loop body (loop-carried), so detection
scans both sides of the op; and ops in a loop share a key region, so the recoverer tries all
three keyed ops per blob and keeps whichever yields clean text (the cipher self-identifies); litcrypt's index wrap is a cmp+csel modulo rather than an and-mask, handled alongside the x86-style mask.

The coverage class is the same as x86-64: static handles simple hand-rolled keyed decoders on
both architectures; optimised crate builds, inlining and AEAD still require the dynamic path
(which is already architecture-agnostic — §5).

## 7. Tier-3 Rust metadata recovery — measured precision (`scripts/measure_rust_meta.py`)

`recover_rust_meta.py` recovers, statically, the crate set + versions and the panic
`file:line:col` a Rust binary leaks. Scored against ground truth — each bench project's
`Cargo.lock` is the exact compiled-in crate set — over 8 ELF binaries (including a
`meta_probe` crate pulling regex/serde_json/url/base64 for a non-trivial dependency tree):

| metric | result |
|---|---|
| precision (recovered crates that are real deps) | **17/17 = 1.00** |
| version-exact (recovered crate@version matches the lock) | **17/17 = 1.00** |
| false crates | **0** |
| panic sites recovered (8 ELF binaries) | **2533** |

The recovered set includes transitive deps with exact versions (aho-corasick 1.1.5,
regex-automata 0.4.18, idna 1.1.0, icu_normalizer 2.3.0, memchr 2.8.3, …) — a real slice of
the dependency graph, not just the direct deps. Two honest caveats:

- **Coverage is partial by construction.** Only a crate that emits a
  `.cargo/registry/src/<index>/<crate>-<ver>/` path inside a panic `Location` leaks a
  version; proc-macro, build-only and panic-free crates leave none, so recovered/lockfile is
  < 1 (litcrypt's 15 lock deps leak 0). That is a property of what rustc emits, not a miss —
  precision and version-accuracy are the metrics that matter, and both are perfect here.
- **PIE ELF needed relocation-aware recovery.** On a position-independent ELF the Location
  filename pointer is stored as 0 and fixed up at load, so the raw-pointer scan (which works
  on PE's absolute pointers) found **0** panic sites. `find_location_structs` now also reads
  the relocation addends (`R_*_RELATIVE`), lifting ELF panic-site recovery from 0 to
  ~207–1073 per binary — e.g. muddy's `main.rs:4..8`, the exact `lc!` call lines.

Real-world qualitative case: on `catthief.exe` (a Rust PE from FLARE-On), the same tool
recovered 17 crates with versions (ureq 2.12.1, rustls 0.23.40, ring 0.17.14, …), 697 panic
sites, and a leaked `http://192.168.56.102:8080/exfil` indicator — see `ARTIFACT_TIERS.md`.
