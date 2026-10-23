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
built + run natively on the Kali arm64 VM, recovers the same five keyed-decoder families it covers on x86-64 (hand-rolled XOR/ADD/SUB plus the litcrypt and litcrypt2 crates):

| obfuscator | cipher | arm64 static recall |
|---|---|---|
| xor_custom | XOR | 5/5 |
| add_custom | ADD | 5/5 |
| sub_custom | SUB | 5/5 |
| litcrypt | XOR (crate) | 5/5 |
| litcrypt2 | XOR, stride-2 key permutation | 5/5 |
| obfstr / muddy | inlined / AEAD | 0/5 (as on x86-64) |

litcrypt2 needed a dedicated second pass (as on x86-64): it walks a fixed 64-byte key with a
`+2` stride that wraps to 1 at `nxt == keylen` and to 0 beyond — a permutation of the key
indices, not the `key[i % keylen]` repeat the generic path models. On ARM64 the wrap compiles
to `add Xnxt,Xidx,#2` / `cmp Xnxt,#0x40` / `cset Wc,eq` / `csel Xidx,Xnxt,Wc,lo`, which the
recogniser matches, then reads the `adrp`+`add` key pointer and replays the state machine at
each `bl <decoder>` call site. The pass fires only on that exact cluster with ≥2 corroborating
call sites, so it added nothing on the other six binaries (muddy/obfstr stayed 0/5 — no new
false positives).

As far as the Oct-2026 survey found, no static string-decoder-recovery tool existed for ARM64
Rust binaries at all, so this is new coverage (Apple-Silicon / ARM mobile Rust malware). The
ARM64 idiom differs from x86-64 in three ways the port handles: the key pointer is built with
`adrp`+`add` (two instructions) instead of a single rip-relative `lea`; the mask `and` and the
key/enc `ldrb` loads sit *after* the decode op in the loop body (loop-carried), so detection
scans both sides of the op; and ops in a loop share a key region, so the recoverer tries all
three keyed ops per blob and keeps whichever yields clean text (the cipher self-identifies); litcrypt's index wrap is a cmp+csel modulo rather than an and-mask, handled alongside the x86-style mask.

obfstr (inlined decode, no callable decoder) needs the emulation path on ARM64 just as on
x86-64, and `scripts/recover_emulate.py` now dispatches on machine type to a Unicorn **ARM64**
emulator — run in the x86 cloud (Unicorn emulates AArch64 cross-host, so no VM is needed to
*run* it, only to build the binary). It recovers **5/5** on obfstr arm64:

| tool | obfstr x86-64 | obfstr arm64 |
|---|---|---|
| `recover_arm64` / `recover_callsite` (static) | 0/5 | 0/5 (inlined — no call site) |
| `recover_emulate` (Unicorn) | **5/5** | **5/5** |

The ARM idiom forced one real change from the x86 emulator. On x86 the print call is a
GOT-indirect `call r15` (external → stubbed); on a **static** ELF the Rust fmt runtime is
linked into `.text`, so obfstr's print is an *intra-text* `bl`. Executing it (some intra-text
calls are load-bearing) would burn the instruction budget inside fmt and clobber the decoded
stack buffer before capture, while stubbing every call diverges before the decode completes.
The port keeps executing intra-text calls but **snapshots the live stack window immediately
before each call** — exactly when obfstr has finished materialising the plaintext and is about
to print it — and reads the printable runs from those snapshots. 5/5, and emulating a keyed
binary (litcrypt2 arm64) still yields 0/5, confirming the path stays scoped to the inlined
case and does not double-count what static already recovers.

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

## 8. Coverage vs FLOSS techniques (what is and isn't covered)

FLOSS (Mandiant) is the reference tool; mapping its techniques onto this project is the
honest way to state coverage. FLOSS recovers strings by emulating every function with
vivisect; this project uses lighter, targeted methods and adds Rust-specific structure.

| FLOSS technique | rust-deobf | notes |
|---|---|---|
| static strings | `strings(1)` baseline | FLOSS's `language/rust` splits Rust's concatenated `&str` blob by its slice lengths; **not yet ported** (open gap). |
| stack strings | `recover_stackstrings.py` (x86-64 + **AArch64**) | immediate stores to `[rbp±k]`/`[rsp+k]`, direct or through a register (`movabs rax, imm64; mov [rbp-k], rax`) on x86, or `strb/str wN,[sp\|x29,#off]` after `mov wN,#imm` (ARM). Static (no vivisect). 0 on git/openssl/gzip at `--min-len 6`; validated on a compiled x86-64 and a compiled aarch64 fixture, and on a C program (§9). |
| tight strings | `recover_emulate.py` | a stack buffer decoded in place by a short loop in the caller; bench variant `tight_xor` (§9d), 5/5 exact on ELF/PE/AArch64. |
| decoded strings (emulation) | `recover_callsite`/`recover_arm64` (keyed), `recover_emulate` (obfstr), `recover_dynamic` (frida, any cipher incl. AEAD) | FLOSS emulates with vivisect; we split static/emulation/dynamic so the cheap path runs first. |
| language-specific (Go/Rust/.NET) | `recover_rust_meta.py` | FLOSS's Rust support is plain-string *layout*; ours goes further — crates+versions, panic `file:line:col`, types — but neither recovers *obfuscated* Rust strings except this project's recoverers. |

Still-open gaps this comparison surfaces: Rust plain-string blob splitting (by `&str` slice
lengths — the same relocation technique §7 uses for Location pointers), tight strings, the
rustc-commit → Rust-version map (FLOSS ships a database; we recover the commit but don't map
it), and the plain `&str`-blob split / tight strings above. The AArch64 port is now complete
across the recovery stack — `recover_arm64` (keyed static incl. litcrypt2), `recover_emulate`
(obfstr inline-decode, below), `recover_stackstrings`, and the architecture-agnostic
`recover_dynamic` all cover ARM64. None of the remaining gaps change the headline result
(FLOSS 0/5 on obfuscated Rust); they are breadth.

## 9. Toolchain drift, canary-free emulation, and FLOSS interop (Oct 2026, rustc 1.97)

Rebuilding the whole benchmark with the current toolchain (rustc 1.97.0, 2026-07-07) instead of
re-reading old binaries surfaced regressions that the committed result files could not show.
All numbers below are reproducible with `scripts/build_all.sh` (`ARM64=1` adds AArch64) and the
recoverers' own CLIs.

**Static recovery, what changed in the generated code and what was fixed**

| finding | before | after |
|---|:-:|:-:|
| litcrypt2 x86-64, release: the key-index wrap is now `cmp idx,KEYLEN; setne; cmovb` (the recogniser assumed `sete`, the mirror image; with a 21-byte key the permutation differs) | 0/5 | **5/5** |
| AArch64 linked by `rust-lld` (static musl): `adrp`+`add` is relaxed to `nop; adr`, which the ARM64 address resolver did not model — every keyed family affected | **0/5** each | **5/5** each |
| litcrypt2 AArch64: same `cset …, ne` wrap as on x86-64 | 0/5 | **5/5** |

The replay now reads the wrap condition (`sete`/`setne`, `cset eq`/`ne`) from the instruction
instead of assuming it, and the ARM64 resolver accepts the single-instruction `adr` form at the
key pointer and at call sites. Pre-existing ARM64 binaries (`build/litcrypt2_arm64`, adrp form)
stay 5/5.

**Emulation (`recover_emulate.py`) works without canaries**

The emulator used to report only matches against known canaries, so on a real sample it reported
nothing — and with an empty canary list it stopped after the first function (`0 == 0`). It now
reports every text-like string a function materialises that does **not** already occur in the
file (FLOSS's definition of a decoded string), drops copies spliced together from static data
(e.g. `TM_deregisterTMC` + `ibc_start_main`) and partial-overwrite views (Rust strings are not
NUL-terminated, so a shorter string leaves a longer one's tail behind). Other changes:

- **function ranking** like FLOSS's feature scoring: functions with 64-bit immediates (obfstr's
  `movabs`/`movk` keys) and non-zeroing XOR/EOR are emulated first — obfstr is found after
  1–15 functions instead of up to 400;
- **syscalls** (`svc #0`, `syscall`) in statically linked runtimes are answered instead of
  ending emulation, and intra-`.text` calls are executed only one level deep, so a static
  `println!` no longer spins in its lock loop until the timeout. AArch64 non-stripped obfstr:
  **1/5 → 5/5**;
- the ARM64 stack snapshot covers the whole live frame, not a fixed 0xA00-byte window.

| canary-free run (`recover(path, [])`) | strings reported |
|---|---|
| obfstr x86-64 release, stripped / not | exactly the 5 canaries |
| obfstr AArch64 release | the 5 canaries; 3 carry a stale tail (`…-20261018int`) — known limitation |
| plaintext, xor_custom, litcrypt, muddy, cryptify (x86-64 and AArch64) | **0** |
| real binaries: git, curl, bash, python3.13, openssl, tar, xz, cargo | **0** |

**Stack strings and indicators**

- `recover_stackstrings` tracks immediates held in registers: x86-64 has no 64-bit immediate
  store, so 8-byte chunks arrive as `movabs rax, imm64; mov [rbp-k], rax`. A plain C fixture with
  two stack strings went from 0 to 2 recovered (`stack-secret-one`, `http://c2.example`). On the
  real binaries above the additions are a handful of genuinely stack-built strings
  (`/proc/self/exe`, SipHash's constant) — no noise.
- The shared text gate accepts strings shaped like indicators (URLs, domains, IPv4[:port],
  Windows/Unix paths, registry keys, e-mail) before its English-trigram scoring, which rejected
  short ones such as `http://c2.example`. `measure_fp.py`: still **0 false positives** on 15
  real binaries (23.4 MB of `.text`).

**FLOSS results documents**

`recover.py --floss-json out.json` writes the findings as a FLOSS (≥ 4.0) results document:
call-site recoveries as decoded strings with decoder / call site / ciphertext addresses,
emulated ones as decoded strings of their function, stack strings, and the file's static
strings. FLOSS 4.0 master loads and renders these documents (`floss -n 6 out.json`; `-n` must be
given until FLOSS stops applying its default minimum length to loaded documents).

| debug builds | release builds |
|---|---|
| 0/5 for every family, static and emulation — not claimed (release is what ships) | 5/5 for xor/add/sub_custom, litcrypt, litcrypt2 (static) and obfstr (emulation), x86-64 and AArch64, stripped and not |

### 9b. Windows (PE) builds and Rust metadata

The PE half of the matrix (x86_64-pc-windows-gnu, mingw-w64) had two failures of its own:

| finding | before | after |
|---|:-:|:-:|
| litcrypt2 PE: its call-site pass read the ciphertext/length from `rsi`/`rdx` (SysV); Win64 passes them in `rdx`/`r8` | 0/5 | **5/5** |
| obfstr PE: COFF symbol values are offsets into their section, not RVAs, so emulation started at the wrong address; functions now come from `.pdata` (RUNTIME_FUNCTION), which also covers stripped PE | 0/5 | **5/5** (2 functions emulated) |

PE release, stripped and not: 5/5 for xor/add/sub_custom, litcrypt, litcrypt2 (static) and obfstr
(emulation); canary-free emulation reports nothing on muddy, cryptify and plaintext. A stress run
emulating 5,700+ functions across ARM64, PE and python3.13 completed without a Unicorn crash.

`recover_rust_meta.py`:

- **Rust release** from the rustc commit: `scripts/data/rust_versions.json` maps 118 stable
  releases (1.22.0 – 1.99.1) to their commit, built by `gen_rust_versions.py` from the official
  channel manifests (`rustc commit: 2d8144b… -> Rust 1.97.0 (2026-07-09)`).
- **Own source tree** reported `src/inflate/core.rs`, `src/read/line.rs`, … — crates vendored
  into std (`/rust/deps/<crate>-<ver>/`, reported separately now), relative `library/core/...`
  std paths (windows-gnu), DWARF file-table names, and paths with rodata glued on
  (`valuesrc/main.rs`). Every build of every bench project (ELF/PE/ARM64, debug/release,
  stripped or not) now reports exactly `src/main.rs`.
- Location records may point inside a longer regex match (the glued case): PE panic sites
  recovered for litcrypt 310 → 395.
- Crate paths under `cargo/registry/src` without the dot (Docker's `/usr/local/cargo`) and
  `vendor/<crate>-<ver>/` are recognised; DWARF sections (including PE `/N` long names, resolved
  through the COFF string table) are no longer scanned — that removed `windows-sys`, a crate not
  in meta_probe's Cargo.lock (PE precision 20/21 → 20/20). ELF precision: 17/17, unchanged.

### 9c. cryptify

cryptify (`encrypt_string!`) was in the benchmark but recovered by nothing (0/5 static, emulation
and — without the build-time variable — dynamic). Its decrypt_string reads `CRYPTIFY_KEY` at
runtime, falling back to the crate's default key `xnasff3wcedj`, the same default the macro uses
at build time. The default key is not a string in the binary: rustc builds it from immediates
(`movabs rax, 0x7733666673616e78` + `mov dword [rcx+8], 0x6a646563` on x86-64; half rodata,
half `movk` on AArch64).

`recover_cryptify.py` identifies the crate by its `CRYPTIFY_KEY` literal, collects every call
site that passes a (ptr, len) `&str` (SysV, Win64 and AAPCS64 argument registers) and decodes
with the default key, requiring >= 2 clean call sites. New bench variant `cryptify_default`
(built without the variable): **5/5** on x86-64 ELF and PE and on AArch64, release and debug,
stripped and not. The custom-key variant is detected and reported as runtime-keyed rather than
guessed at; `plaintext` and the other crates are not flagged.

### 9d. Tight strings

New bench variant `tight_xor`: each string is built on the stack from immediates and XORed in
place by a loop inside the function that uses it (`std::hint::black_box` on the key keeps rustc
from folding the decode) -- no decoder function and nothing in `.rodata`, FLOSS's "tight string"
case. rustc vectorises the loop and schedules the stores out of order (4-, 8- and 16-byte stores
plus single bytes patched in between), which exposed two weaknesses of the emulator's write log:
Unicorn reports at most 8 bytes of a 16-byte SIMD store's value, and out-of-order stores were
spliced into one run. Emulation now also records *which* bytes were written and reads them back
from emulator memory before every call and return (when a buffer is complete and about to be
used); the write log only extends a run on sequential stores and breaks on SIMD stores. A wrong
prefix rule that dropped the full string when a mid-decode view of it was also seen was fixed:
`P + tail` is treated as a stale-tail artefact only when the tail ends another recovered string.

| canary-free emulation, release, stripped and not | ELF x86-64 | PE | AArch64 |
|---|:-:|:-:|:-:|
| tight_xor (exact strings, nothing else) | 5/5 | 5/5 | 5/5 |
| obfstr (exact strings, nothing else) | 5/5 | 5/5 | 2/5 exact + 3 with a stale tail |
| plaintext, muddy, xor_custom (reported strings) | 0 | 0 | 0 |

Real binaries (git, curl, bash, openssl, tar, xz, gzip, perl): 1 string in total
(`.gnu.versign_r` in curl, spliced from section names).

### 9e. Plain Rust literals: splitting the packed string section

`recover_rust_strings.py` recovers the literals a Rust binary does *not* hide. They are the bulk
of what an analyst reads, and `strings` (and FLOSS's static pass) gets them wrong because the
linker packs them back to back without terminators. Every `&str` is a (pointer, length) pair, so
the module collects pairs and cuts at the real boundaries:

- `&str` fields in constant data (`.data.rel.ro`, `.rdata`, panic `Location`s), with ELF
  `R_*_RELATIVE` relocations applied for PIE tables that are zero until load;
- call sites: `lea R,[rip+S]` with the length in the next argument register (SysV / Win64),
  both halves stored to adjacent stack slots, `push N; pop reg`, and shared panic tails reached
  by `jmp` (`lea rdi,msg; lea rdx,loc; jmp tail` / `tail: mov esi,N`); AArch64 `adrp+add`/`adr`
  with the length in x(N+1), following `b tail` the same way;
- `match` arms returning `&str` compiled to lookup tables: i32 offsets from the table (LLVM
  relative lookup tables, rustc 1.97) or relocated pointers (rustc 1.88, 1.99), each next to a
  length table (u64, or u8 in 1.99) -- `io::ErrorKind`'s descriptions are the familiar case;
- two rustc 1.97 encodings: `fmt::Arguments` for a lone literal passes the length as
  `(len << 1) | 1` (both readings are candidates; a candidate that ends where another literal
  starts wins, ties go by what the callee takes elsewhere), and `format_args!` templates are
  compact byte strings -- `\x15memory allocation of \xc0\x0e bytes failed\n\x00`: a byte
  < 0x80 is the length of the next piece, `0xC0` a `{}` argument, `0x00` the end.

`plaintext` benchmark, `-n 6` (literals recovered / printable runs left unexplained):

| rustc | ELF x86-64 | PE | AArch64 |
|---|:-:|:-:|:-:|
| 1.88 | 274 / 47 | | |
| 1.97 | 273 / 26 | 1002 / 157 | 248 / 313 |
| 1.99 | 274 / 17 | 1115 / 144 | 246 / 302 |

The 5 canaries and the `io::ErrorKind` descriptions come out exact in every cell. What stays
unexplained is mostly not literals: digit and hex lookup tables, section-name lists, and on
AArch64 musl the C strings of libunwind. rustc 1.99 narrows the ErrorKind length table to `u8`
(`movzx edx, byte [rax+rcx]`), which the table pairing reads at any element size.

Against FLOSS's Rust extractor (`floss/language/rust`, PE only) on the same PE: FLOSS gets
**0/5** canaries exact (`canary::alpha::7f3c-config-endpointc` -- it deletes `\n` before
splitting at cross-references, so every split after a newline is off by one), **0/8** of the
sampled `io::ErrorKind` strings (the lookup table is not a cross-reference, the 40 descriptions
stay one run), and 33 of the 129 template pieces carry the printable length byte glued in front
(`& is not a char boundary; it is inside `). rust-deobf: 5/5, 8/8, 0. Literal offsets are
checked byte-for-byte against the file in the tests.

### 9f. AArch64: the recoverers were reading two thirds of `.text`

capstone's `disasm()` stops at the first word it cannot decode. AArch64 `.text` contains literal
pools and padding, so on every stripped AArch64 benchmark build a single pass ended at ~67% of
the section -- the call-site recoverer, cryptify, stack strings and the emulator's function
discovery never saw the last third of the program (the benchmark passed only because the test
programs' own code sits near the start). `scripts/disasm.py: linear()` resumes after
undecodable words; all recoverers use it, and a test checks that every format's `.text` is
covered to the end. False positives stay at 0 on a real AArch64 binary (`libstd` for
aarch64-musl, 5.6 MB: static 0, stack strings 0, emulation of 400 functions 0).

Two causes of flaky emulation results are gone. The per-function limit is the instruction
budget alone (a 3-second wall-clock limit on top of it made results depend on machine load).
And each function's Unicorn instance sits in a reference cycle through its hook closures, so it
was freed only when Python's cycle collector happened to run, while its native memory (image,
stack, scratch, translation cache) stayed mapped: after a few hundred functions `mem_map` failed
with `UC_ERR_NOMEM`, the error was swallowed, and every later function yielded nothing -- so
`tight_xor` PE recovered 1/5 when obfstr PE had been analysed first in the same process, which is
what the test suite does. The emulation loop now collects every 16 functions.

### 9g. rustc 1.99 (current stable)

CI builds the benchmark with the current stable compiler, which had moved to 1.99.1 while the
local build was still 1.97, and CI failed on `tight_xor` PE: rustc 1.99 writes the decoded
copy into memory that held another string (the emulator's stubbed allocator hands out the same
block), giving `canary::delta::feature-flag-telemetry-off` + `lpha::7` and a mid-decode view
`canary::echo::sc%{`. The overlap rules now treat a tail that is a piece of another recovered
string (not only its end) as stale, and drop a view that diverges from a longer string only in
its last 1-3 characters after a shared prefix of 12 or more. `scripts/build_all.sh` takes
`BUILD_DIR` and the tests `RUST_DEOBF_BUILD`, so a second toolchain can be checked side by side:

    RUSTUP_TOOLCHAIN=1.99.1 BUILD_DIR=/tmp/b199 ARM64=1 bash scripts/build_all.sh
    RUST_DEOBF_BUILD=/tmp/b199 python -m pytest tests

## 10. Generalisation: held-out shapes and malware build profiles (Oct 2026)

An external review rebuilt all 144 benchmark binaries with rustc 1.97 (x86-64 ELF/PE and
ARM64), reproduced `pytest` 107/107 and the self-tests 10/10, and read the code for cheating:
canaries are used for scoring and early exit only, never as known plaintext. It then wrote its
own held-out programs — eight benign strings spread over several functions: in a struct, in a
`match`, compared but never printed, on a branch that never runs — and found the recoverers
overfitted to the benchmark's single shape (`main()` printing five strings) and single build
profile:

| review finding | reproduced here |
|---|---|
| litcrypt2, malware-style build (LTO, `opt-level="z"`, `panic=abort`): 0/8 ELF and PE — the decode loop is not recognised | yes: 0/8 on `scatter_litcrypt2` `size-lto` and `speed-lto`, ELF and PE |
| litcrypt2, `opt-level=3`: 5/8 — all 8 decoded, the text filter dropped 3 (2 because of a `heldout::` prefix, `Global\HO-91af2` even bare) | yes: 2/8 on `scatter_litcrypt2` release (call sites outside the recogniser's window, and the mutex rejected) |
| obfstr emulation: PE 2 full + 3 truncated, ELF 0–1, `opt-level=3` ELF 0/8 even without the 400-function cap | yes: 1/5 on the canary obfstr ELF once emulation could run the formatter, 0–6/8 on `scatter_obfstr` |
| FLOSS 3.2.0 on the held-out PE files: 0/8 | see the FLOSS row below |
| false positives: ripgrep 2 (static), curl 1 (`.gnu.versign_r`, emulation); bash emulation ran 400/1671 functions | the 400 cap was real |

### Why: the static recogniser keys on idioms, and the idioms move with the profile

`size-lto` litcrypt2, for example: lengths arrive as `push 0xf; pop rdx` instead of
`mov edx, 0xf`; the key is stored into an iterator struct and the XOR sits in
`Iterator::next`, two calls below the call site; `load_config` tail-calls the decoder with
`jmp`. Each can be patched (the call-site resolver now accepts `push imm; pop reg`), but the
next profile or rustc release moves something else. The fix is the engine that does not depend
on the idiom: the emulator.

### What the emulator had to learn

Running real Rust functions (not just obfstr's inlined decode) needed a small loader and C
runtime. Each item below was found by a failing case, not added speculatively:

| problem | effect | fix |
|---|---|---|
| calls below the emulated function were stubbed beyond one level | out-of-line decoders never ran | callees run up to 8 levels; a per-callee instruction budget (6k, 20k for a direct callee) abandons a spinning callee and returns 0 with the caller's callee-saved registers restored |
| allocators returned 0 | `Vec`/`String` writes went to address 0, strings overlapped | imports resolved by name; `malloc`/`calloc`/`realloc`/`HeapAlloc`/`__rust_alloc` hand out separated zeroed blocks; `memcpy`/`memmove`/`memset`/`memcmp`/`bcmp`/`strlen`, `brk`/`mmap` modelled |
| no relocations applied | `__rust_alloc` (called through a GOT slot with an `R_X86_64_RELATIVE` entry), vtables and `call r15` all jumped to 0 | ELF `RELATIVE`/`GLOB_DAT`/`JUMP_SLOT`/`64`, PE `DIR64` base relocations; every import slot points at a named `ret` trampoline |
| LIEF returns file bytes as the "content" of `.bss` (NOBITS) | std's `ENV_LOCK` read as locked (a `.comment` string), `getenv` spun in `RwLock::read_contended` | NOBITS sections are zero |
| no thread pointer | `fs:[0]` read 0, `[rax-8]` faulted, the run ended | fs/gs base (x86-64, a Windows TEB with a TLS array) and `TPIDR_EL0` |
| `GetEnvironmentVariableW` stub returned 0 with `GetLastError()` 0 | Rust read it as "set to the empty string": cryptify decrypted with an empty key (PE 0/8) | unset variables report `ERROR_ENVVAR_NOT_FOUND` |
| ARM64 LSE atomics (`casa`, `swp`) | undefined-instruction exception | CPU model `ARM64_MAX` |
| stripped static musl: `mallocng` cannot run without `__init_libc` (auxv, page size) | every allocation failed | FLIRT-style masked byte signatures for musl's malloc/free/realloc/memcpy/memset/memmove/memcmp/strlen (`gen_runtime_sigs.py`, `scripts/data/runtime_sigs.json`); found among call targets because musl's functions carry no unwind info |
| function starts: `.pdata` only (PE), push-prologue scan (stripped ELF) | leaf functions without unwind info (`settings_key` under `opt-level="z"`) were never emulated | `.eh_frame_hdr` table (kept when stripped), symbols, and every direct call target |
| one path per function, fake arguments | `match` arms and never-taken branches were unreachable | path exploration: forward conditional branches in the emulated function are forced the other way, breadth-first, up to 8 runs and 3 run budgets of instructions per function |
| runs shared state | a store through a fake pointer into `.rodata` (zeroed afterwards) destroyed the next function's ciphertext; after the periodic Unicorn re-creation the reset went to the old instance (also the source of rare segfaults) | written image pages are restored from the loaded image, other written pages zeroed, auto-mapped pages unmapped after every run |
| per-instruction Python hook | ~3.5 µs per instruction | block hook: calls, returns and branch forcing at basic-block boundaries, 1.6–2× faster |

### Exact strings without known plaintext

Rust strings are not NUL-terminated, so reading text back from memory cannot say where a string
ends, and a shorter string decoded over a longer one keeps its tail (the AArch64 `…-20261018int`
limitation the README used to list). Three signals now decide it:

- every write is tagged with its *capture generation*; a run is cut where the generation goes
  **down** (the rest is older than the string in front of it);
- the **(pointer, length)** pairs the code passes on — in two argument registers, or inside the
  `fmt::Arguments` / `&str` structures the arguments point to (followed three levels) — give the
  exact string; when the byte after it is printable and older, the string is complete and longer
  views of it are stale;
- strings that only a **forced** path produced lose to the natural run's when they are a near
  copy (`…telemetry-ofF`) or a piece of one plus junk.

Static explanations were widened the same way: printf templates in the file (`Assertion failed:
%s (%s: %s: %d)` formatted with empty arguments, including views that start inside the template),
static pieces glued with short glue (`23 GNU.sparse.offset=0`), identifiers re-cased at run time
(git's `BAD_DATE_OVERFLOW` → `badDateOverflow`), AArch64 constants built with `movz`/`movk` and
stored to the stack (musl's `/proc/self/fd/`), and fake values the emulator itself made up.

### Text filter

Indicator shapes are accepted before the English-trigram gate, now including kernel-object
names (`Global\…`, `Local\…`, `Session\N\…`, `BaseNamedObjects\…` → `[mutex]`), hive-less
registry keys (`Software\…`), UNC and `%VAR%` paths, and an indicator **inside** a longer string
(`heldout::10.13.37.42:8443`, `cfg=C:\ProgramData\x.db`) when the rest of the string is plain
text.

### Results

**Scatter suite, stripped, default `recover.py` pipeline** (`scripts/eval_scatter.py`; exact matches of 8; `+n` = extra strings; `plaintext` counts every reported string as a false positive). Toolchain: rustc 1.97.0.

Before (the code the review tested):

| scatter program | ELF x86-64<br>release | ELF x86-64<br>size-lto | ELF x86-64<br>speed-lto | PE x86-64<br>release | PE x86-64<br>size-lto | PE x86-64<br>speed-lto | ELF AArch64<br>release | ELF AArch64<br>size-lto | ELF AArch64<br>speed-lto |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| `xor_custom` | 3/8 | 1/8 | 2/8 | 3/8 | 3/8 | 2/8 | 3/8 | 2/8 | 2/8 |
| `litcrypt` | 2/8 | 0/8 | 0/8 | 2/8 | 0/8 | 0/8 | 2/8 | 0/8 | 0/8 |
| `litcrypt2` | 3/8 | 0/8 | 2/8 | 3/8 | 0/8 | 2/8 | 3/8 | 0/8 | 2/8 |
| `obfstr` | 1/8 | 1/8 | 1/8 | 1/8 | 3/8 +3 | 1/8 | 5/8 | 3/8 +1 | 5/8 |
| `cryptify` | 4/8 | 0/8 | 0/8 | 3/8 | 3/8 | 3/8 | 3/8 | 0/8 | 0/8 |
| `plaintext` | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** |

79/360 exact, 4 false positives

After:

| scatter program | ELF x86-64<br>release | ELF x86-64<br>size-lto | ELF x86-64<br>speed-lto | PE x86-64<br>release | PE x86-64<br>size-lto | PE x86-64<br>speed-lto | ELF AArch64<br>release | ELF AArch64<br>size-lto | ELF AArch64<br>speed-lto |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| `xor_custom` | **8/8** | **8/8** | **8/8** | **8/8** | **8/8** | **8/8** | **8/8** | **8/8** | **8/8** |
| `litcrypt` | **8/8** | **8/8** | **8/8** | **8/8** | **8/8** | **8/8** | **8/8** | **8/8** | **8/8** |
| `litcrypt2` | **8/8** | **8/8** | **8/8** | **8/8** | **8/8** | **8/8** | **8/8** | **8/8** | **8/8** |
| `obfstr` | **8/8** | **8/8** | **8/8** | **8/8** | **8/8** | **8/8** | **8/8** | **8/8** | **8/8** |
| `cryptify` | **8/8** | **8/8** | **8/8** | **8/8** | **8/8** | **8/8** | **8/8** | **8/8** | **8/8** |
| `plaintext` | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** |

360/360 exact, 0 false positives

The same 54 binaries, before → after: **79/360 → 360/360** exact strings, 4 → 0 extra strings. `tests/test_scatter.py` asserts every cell (recall *and* that nothing else is reported), plus all eight canary crates under both LTO profiles, ELF/PE/AArch64: 156 tests.

**Canary benchmark** (`tests/test_benchmark.py`, unchanged assertions plus one): still passes in
full (109 tests). One expectation changed because the emulator got better: muddy
(ChaCha20-Poly1305) used to be "AEAD: dynamic only"; emulation now runs its decrypt path and
recovers exactly the five canaries, ELF, PE and AArch64. The canary programs rebuilt `size-lto` and
`speed-lto` (8 crates × 3 formats × 2 profiles) recover 5/5 each.

**Precision on real binaries** (`scripts/measure_fp.py --pipeline`, the whole default pipeline):

| binary | `.text` | functions emulated (120 s budget) | time | false positives |
|---|--:|--:|--:|:-:|
| bash | 945 KB | 2343 / 2343 | 65 s | **0** |
| tar | 292 KB | 607 / 607 | 40 s | **0** |
| xz | 41 KB | 76 / 76 | 8 s | **0** |
| git | 3077 KB | 580 / 4473 (budget) | 139 s | **0** |
| curl | 107 KB | 121 / 121 | 2 s | **0** |
| ripgrep 14.1.1 (Rust, musl, stripped) | 4078 KB | 365 / 8558 (budget) | 156 s | **0** |

Two static-recoverer bugs behind the review's ripgrep garbage were fixed on the way: a decoder whose
function entry could not be resolved had `entry = None`, which matched every register-indirect
`call` as one of its call sites (`RelebsAHAb0i!` from `ReverseHybridGro…`), and a "key" that is
mostly zero bytes was accepted although it leaves the data unchanged (`z4Yaused8by:` from
`caused by:`). Emulation-side noise found on the way and removed: `rep stos` over a fake length
(now a per-run store budget), a page-faulting walk across memory (a per-run cap on auto-mapped
pages), git's fsck message ids re-cased at run time, tar's pax records, printf-formatted runtime
messages. Coverage is reported, not hidden: the large binaries are emulated in decoder-score order
until the budget runs out.


**FLOSS 3.2.0** (`floss.exe -q --json`, run on the Windows VM, every PE of both suites, stripped):
0 decoded strings on all 12 canary PE files and all 18 scatter PE files (release, `size-lto`,
`speed-lto`). Its static pass finds the plaintext programs' literals (5/5; 7/8 to 8/8 on
`scatter_plaintext`) and nothing on the obfuscated ones. FLOSS 4.0.0-alpha.2 could not be measured
there: its Windows build stops with `ArchNotImplemented('ARM64')` on an ARM64 Windows host.

### 10b. Second machine and toolchain: the two VMs

Everything above was also run away from the development container, on the two VMs of
`dual-vm-ai-agent` (Kali Linux and Windows, both ARM64 guests on an Apple-silicon Mac):

- **Kali, rustc 1.99.1** (current stable, native `aarch64-unknown-linux-gnu`): the canary and scatter
  suites rebuilt for PE (mingw), AArch64 musl and — new — AArch64 **glibc** (dynamically linked,
  the default Linux target), every profile. `pytest tests` on the VM: **232 passed**, 85 skipped (the
  x86-64 ELF builds, which an AArch64 host does not make), 0 failed — once `z3-solver` from
  `requirements.txt` was installed there; without it only `deobf_expr.py --selftest` fails. In the
  development container the same suite passes on the rustc 1.97 build (289 passed) and on a
  rustc 1.99 glibc AArch64 build (149 passed, the formats not built there skipped).
- **Windows** (Python 3.14, no Rust toolchain): the self-tests pass (12), and `recover.py` run
  on the Windows host over the 18 stripped scatter PE files built on Kali recovers **120/120**
  strings with 0 extra (`plaintext`: nothing) — the files on which FLOSS 3.2.0, run on the same
  machine, decodes 0 (the FLOSS paragraph above).

The glibc AArch64 build is the one that taught the emulator something new. Its binaries call
atomics through libgcc's outlined helpers (`__aarch64_cas4_acq`, `__aarch64_swp4_rel`, ...), which
test a `__aarch64_have_lse_atomics` byte set by a constructor reading `AT_HWCAP`. The
constructor never runs under emulation, so the helpers took the `ldaxr`/`stxr` path, whose
exclusive access raised a data abort inside std's locks and ended the run after the first
`println!`; and `write` from the dynamically linked libc was an unmodelled import returning 0,
which std reports as `WriteZero` and turns into a "failed printing to stdout" panic. The loader
now finds the flag from the helpers' `adrp x16; ldrb w16; cbz w16` prologue and sets it (the LSE
instructions run on the `ARM64_MAX` CPU), `write`/`writev` report the bytes as written, and a CPU
exception (data abort, undefined instruction) inside a callee abandons that callee like a memory
fault instead of ending the run. Before → after on the glibc AArch64 canary programs under
`size-lto`: obfstr, litcrypt and litcrypt2 1/5 → 5/5. `ARM64_GNU=1 bash scripts/build_all.sh`
builds this target (cross linker `aarch64-linux-gnu-gcc` when not on an AArch64 host) and CI has
a job for it.

## 11. Second evaluation: unseen profiles, a mixed-language corpus, large binaries (Oct 2026)

A re-evaluation after §10 asked the same question of the new code that the external review had
asked of the old: what happens on inputs nobody tuned for? Three findings, then the fixes.

**Findings.**

1. *Build profiles the benchmark never uses* (the benchmark's own programs rebuilt with release
   overridden by `CARGO_PROFILE_RELEASE_*`, stripped, x86-64 ELF and PE): `opt-level="s"` + thin LTO +
   16 codegen units + `panic=unwind`, and `opt-level=1`. 338/340 strings exact, 7 junk strings in 4
   of 64 binaries: obfstr at `-O1` stores a string's 8-byte chunks to scratch out of order before
   the final copy (`C:\ProgrSvc\stat`), litcrypt under thin LTO left `abravo::b`, a mutex came out as
   `Global\NW-5c1e9a0`, one litcrypt2 PE string was dropped as a "partial" of a glued copy.
2. *Precision on binaries the filters were not developed against*: rustfmt 0 and cargo-fmt 0, but
   **age (Go) 17 and Xvfb (C) 68** false positives — run-time formatted messages
   (`(EE) BUG: ../dix/devices.c:1367 in InitValuatorClassDeviceStruct()`,
   `runtime: typeOff 0x40a120 base 0x0`). The "0 FP on six binaries" of §10 was true and overfitted:
   those six were the development set.
3. *Large binaries*: cargo (43 MB), gdb and cmake were killed by the out-of-memory killer at
   5.5–6 GB. The static recoverers built `list(capstone.disasm(.text))` with full details,
   about 1 GB per MB of `.text`. And emulation covered gdb's 15,760 functions at **136** in the
   120 s budget: it explored the first decoder-like functions with full budgets and never reached
   the rest.

**Fixes.**

| problem | fix |
|---|---|
| static stage memory | `disasm.Insns`: a compact table (address, size, mnemonic, operand text) from chunked `disasm_lite`; full capstone details decoded on demand for the few instructions a recogniser inspects. Identical output on all 58 release builds; git 3661 MB → 249 MB and faster; gdb 424 MB, cmake 672 MB |
| capstone decodes a whole buffer before yielding | `linear()` walks 64 KB chunks (an instruction cut by a chunk boundary is decoded again at the next chunk's start; identical instruction stream on x86-64 and AArch64 `.text`) |
| formatted messages reported | numbers (decimal, float, 0x-hex) are taken out and every remaining piece must be static on its own; a printf template in the file whose `%s` arguments are themselves file strings (`BUG: %s:%u in %s()`), behind a prefix of up to 8 static bytes; a message ≥ 90 % covered by static pieces of 4+ bytes. Checked against every expected string of all 320 benchmark binaries: none is explained away |
| 136 of 15,760 functions | two passes: every function once, unforced, 10,000 instructions, in score order, using up to 40 % of the budget; then full budgets and path exploration. Plus processes for binaries with 2,000+ functions (`RUST_DEOBF_WORKERS`, default min(4, CPUs)), direct libunicorn register/memory accessors (the binding spends ~3 µs per register), and argument scans limited to the few calls after text was written |
| out-of-order chunks, junk heads | a string made only of 2–5 non-contiguous pieces of another surviving string is a scramble of it |
| `…5c1e9a` + `0`, an AEAD tag after a plaintext | a string complete in one function, followed by up to 8 characters in a copy from another function, keeps its length |
| used prefix + another whole string (`…endpoint` + `canary::bravo::…`) | glued, not a longer string |
| memcpy/realloc modelled by the emulator marked the whole copy as new | the copy keeps the source bytes' write ages, so a plaintext and the older tag bytes after it stay apart (muddy PE at `opt-level="z"`) |
| `opt-level="z"` without inlining: allocators 8+ calls below a decoder hit the depth limit, `alloc` returned 0 | import jump stubs and functions that reach an allocation import within three calls run at any depth |
| ChaCha20 at `opt-level="z"` runs past the per-run budget (only 2/5 decrypted) | a run or callee that is still writing text when its budget ends gets half a budget more, up to 3–4 times |
| a decode attempt and the decode written side by side (`--skip-update-ch--skip-update-check`), or a forced string behind the start of another (`Mozilla/5.0 (Win` + `Software\…`) | a *stutter* (2–4 pieces of one string, longer than it) and a *glued head* (another string's piece in front of a recovered string) are dropped, and never serve as the yardstick that declares the real string garbled |
| the stale/partial decisions depended on set iteration order (Python's per-process string hashing) and the first pass's extent on the machine's load | two rounds (all stale reasons, then partial views); a binary under 2,000 functions is always swept completely |
| full coverage of large binaries exposed new noise: a static symbol name with a few bytes changed by a loop on fake arguments (vim: `PyFloau_Type`), a piece appended forever (`/usr/share/vimusr/share/vim…`), and one rustfmt function whose forced paths reshuffle .rodata (17 strings like `  secs in tarsihe phaseng pd `) | near-static strings (aligned to a file string, a quarter of the bytes or fewer differ, or a 60 % prefix does) are static; periodic text is degenerate; a function with 6+ forced-only strings, most of them 85 %+ file pieces, loses its forced-only strings that are 60 %+ file pieces |
| the static recognisers decoded every call in full once per decoder | a direct-call index from the operand text (gh: 16 s, docker: 13 s for the static stage) |

Every explanation rule was checked against the expected strings of all 488 benchmark binaries
(both suites, every format and profile, rustc 1.97 and 1.99, and the three held-out sets below):
none of them is explained away.

**Re-measured.**

| | before this round | now |
|---|:-:|:-:|
| set 1: `opt-level="s"` + thin LTO + 16 CGU + `panic=unwind`; `opt-level=1` (ELF, PE; 64 binaries) | 338/340, +7 junk | 340/340, +0 |
| set 2: `opt-level=2`, 1 CGU; `opt-level="z"`, no LTO, `panic=unwind` (ELF, PE, ARM64 musl; 96) | 500/510, +3 *(first measured after the set-1 fixes)* | 510/510, +0 |
| set 3: `opt-level=3`, no LTO, 16 CGU, `panic=unwind`; `opt-level="s"`, fat LTO (ELF, PE, ARM64 glibc; 96) | 504/510, +8 *(first measured after the set-2 fixes)* | 510/510, +0 |
| canary + scatter suites, rustc 1.97 / 1.99 (`pytest tests`) | 289 / 149 passed | 289 / 149 passed |
| Kali VM, rustc 1.99.1, PE + ARM64 musl + ARM64 glibc (`pytest tests`) | 232 passed | 232 passed (the round's first version failed 2 there: the stray-tail case below) |
| Windows VM, `recover.py` on the 18 stripped scatter PE files | 120/120, +0 | 120/120, +0 |
| static stage on git | 3661 MB | 249 MB |
| cargo, gdb, cmake (whole pipeline) | out of memory (5.5–6 GB) | gdb 0.5 GB; cargo 1.0–1.1 GB per process |
| gdb, functions emulated in 120 s | 136 / 15,760 | ≈2,000 / 15,760 (2 CPUs) |
| Xvfb / age, false positives | 68 / 17 | 1 / 2 |

The "first measured" figures are the held-out numbers: each set was built after the fixes for the
previous one and measured once, then its failures were fixed too, so the "now" column is tuned.
Set 3's failures were all obfstr under `opt-level="s"` with fat LTO (a string decoded right behind
the start of another, and a decode attempt written next to the decode) and one tight-XOR view.

**Precision on a mixed corpus** (`scripts/measure_fp.py --pipeline --corpus`, 120 s, 2 CPUs; also
a CI job, informational):

| binary | language | `.text` | functions emulated | false positives |
|---|---|--:|--:|:-:|
| bash | C/C++ | 945 KB | 2343/2343 | 0 |
| tar | C/C++ | 292 KB | 607/607 | 0 |
| xz | C/C++ | 41 KB | 76/76 | 0 |
| git | C/C++ | 3,077 KB | 4473/4473 | 0 |
| curl | C/C++ | 107 KB | 121/121 | 0 |
| gdb | C/C++ | 5,693 KB | 2022/15760 | 0 |
| cmake | C/C++ | 9,318 KB | 4305/18830 | 1 |
| Xvfb | C/C++ | 1,435 KB | 5038/5038 | 1 |
| openssl | C/C++ | 415 KB | 535/535 | 0 |
| perl | C/C++ | 1,858 KB | 2240/2240 | 3 |
| python3.13 | C/C++ | 3,039 KB | 10767/11510 | 0 |
| vim | C/C++ | 3,110 KB | 5302/5302 | 7 |
| age | Go | 1,631 KB | 2353/2353 | 2 |
| gh | Go | 16,710 KB | 1718/13720 | 0 |
| docker | Go | 13,379 KB | 1498/35916 | 1 |
| go | Go | 6,351 KB | 2115/13835 | 2 |
| ripgrep (Debian) | Rust | 3,075 KB | 4947/8530 | 3 |
| rustfmt | Rust | 2,849 KB | 4545/4545 | 4 |
| cargo-fmt | Rust | 874 KB | 1280/1280 | 0 |
| cargo | Rust | 19,594 KB | 3528/43240 | 5 |
| rustdoc | Rust | 5,894 KB | 8531/8531 | 0 |

29 in all (C/C++ 12, Go 5, Rust 12), 11 binaries clean. The CI job's own run on GitHub's
ubuntu runner (other versions of the same programs, 4 CPUs, 60 s) gave 32 on 20 binaries, 13
clean, with more on that runner's Rust toolchain binaries (rustfmt 9, cargo-fmt 6) and none on
kubectl, docker or gh — an independent replication, and a reminder that the figure moves with
the binaries' versions. One lesson worth recording: rustfmt had
**0** when only 990 of its functions fitted in the budget, and 23 once all 4,545 did; coverage and
noise grow together, so a precision figure means little without the coverage next to it. The
remainder is text assembled at run time from the program's own pieces in ways the filters do not
model (`File/Glob.pm`, `SV_YES:UNDEF`, `lib/rustlib/src/rust/`, `session 19700101T000000000Z-`),
vim symbol names with letters inserted as well as changed, and a few reshuffles. Dropping those
would take rules that also drop decoded indicators made of common words (`--skip-update-check`
is three dictionary words), which is the wrong trade for this tool.

**What this round also shows.** The rules that decide which of several overlapping views of a
buffer is the string are heuristics, and they are brittle: the stray-tail rule went through three
versions in this round alone — a fix for an AEAD tag after muddy's plaintext (`…20261018&8fq`)
dropped obfstr's `--skip-update-check` on the Kali VM's rustc 1.99 PE build (a shorter view from
a function that decoded only the first 16 bytes looked like the same string without its "stray"
tail), and the fix for that briefly broke a set-3 ARM64 cell. Every rule is now held by the
suites above and the self-tests, but a new compiler or profile can still land on a combination
they do not cover. The durable fix is information the emulator does not record yet — which
buffer (address) each view came from — so views of one buffer can be told from copies; that is
the next step, not another rule.
