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
they do not cover. The durable fix is information the emulator did not record then — which buffer
(address) each view came from — so views of one buffer can be told from copies.

**That fix is now in place.** Every emulation record carries `addr`, the buffer start address(es)
the string was materialised at (captured in `_Writes.capture`/`_split`, accumulated across the
explore re-runs, and merged across parallel workers). `_drop_overlap_artifacts` uses it as a
*guard*: a prefix/tail pair (`P`, `S = P + tail`) is still resolved by the heuristics when the two
share a buffer start, but when both addresses are known and share no start they are two different
buffers that merely share a prefix, and the stale-tail / partial-view drops are skipped so neither
is lost. The heuristics remain as the fallback where an address is unknown, so this only ever keeps
a string the rules would otherwise have dropped by coincidence — it cannot drop a real one. Verified
against the canary suites (recall unchanged, ELF/Mach-O still 5/5) and the precision tests
(`tests/test_benchmark.py`, `tests/test_obf.py`, `tests/test_scatter.py`).

## 12. First runs on real binaries (Oct 2026, Kali VM, static + emulation only)

The benchmark is synthetic; the README's standing caveat is "benign corpus only". These are the
first runs on real, third-party binaries — four real Rust-malware families plus two controls, on
the Kali VM, **static + emulation only — the sample is never executed** (that is `recover.py`'s
default: it emulates individual functions under Unicorn, no syscalls reach the host; no dynamic
/Frida on real malware). Samples are referenced by hash; none is committed.

| family | sha256 (prefix) | format | `recover_rust_meta` | emulation | decoded (obf.) | result |
|---|---|---|---|---|--:|---|
| **EDDIESTEALER** | `5330cf6a…e995f42` | PE x86-64 | **rust=True**, rustc 6d9f6ae, 157 panic sites | 1376/1376 fns, 11 s, no crash | **32** | **recovered the hidden C2 domain `xxxivi.com` + C2 URL path `/don/api/handler/73da58c0-…`, plus the dynamically-resolved API names it hides (`ReadProcessMemory`, `InternetConnectW`, `NtQuerySystemInformation`, `encryption_key`, `username`…). static/FLOSS get 0; emulation got all 32.** |
| KrustyLoader | `030eb56e…84228b0` | ELF x86-64 | **rust=True**, rustc 1.70.0, **18 crates** (tokio/hyper/socket2/hex/cfb-mode), 220 panic sites | 2072/2072 fns, 6 s, no crash | 0 | metadata + capability profile recovered; **no macro-obfuscated strings** — its config is encrypted at run time (cfb-mode) and loaded dynamically, so static string deobf has nothing to decode (7 benign literal paths only). Correct, not a miss. |
| FickleStealer | `e9bc44cf…a6c599c` | **PE32 i386 (32-bit)** | rust=False | — (arch `?`) | 0 | format gap at the time of this run. **Now (§14):** 32-bit x86 is detected and the PE32 loader works, but PE32 *emulation* of the Windows std path is not yet reliable, so PE32 is routed to literal recovery only; 32-bit x86 ELF is fully emulated (5/5). FickleStealer is also packed, so it needs unpacking first regardless. |
| RustDoor | `a900ec81…9b56faa5` | **Mach-O universal** | rust=False | — (arch `?`) | 0 | format gap at the time of this run. **Now closed (§15):** Mach-O is fully emulated; the recovery got RustDoor's C2 URL. |
| catthief.exe | `904e6720…cb94c22` | PE x86-64 (FLARE-On) | **rust=True**, rustc 1.96, 17 crates | 2391/2391 fns, 10 s | 1 | not string-obfuscated → little to decode, nothing invented |
| ToxicMiner.exe | `ee3a410d…a28a93` | PE x86-64 (C/C++ control) | **rust=False** | 4780/4780 fns, 11 s | 2 | correctly flags non-Rust; 2 runtime-assembled strings |

**What this shows.** On **EDDIESTEALER** the project does exactly what it claims: it recovers
obfuscated strings from real Rust malware that `strings` and FLOSS do not — including the C2
domain and URL path (both known, published EDDIESTEALER indicators) and the Windows API names the
sample hides. That is the end-to-end result the synthetic benchmark was a proxy for. Across all
four families the pipeline is **robust** (full function coverage in seconds, no crash) and the
**metadata tier is strong** (EDDIESTEALER, KrustyLoader, catthief all give exact crate/capability
fingerprints).

**What it also shows, honestly.** (1) Not every Rust malware uses the compile-time string
obfuscators the emulator targets: **KrustyLoader** encrypts its config with a real cipher
(cfb-mode) at run time, so static deobfuscation correctly finds nothing to decode — the win there
is the metadata, and the strings would need dynamic recovery. (2) Two **format gaps** surfaced
immediately on real samples: **32-bit x86 PE** (FickleStealer) and **Mach-O** (RustDoor). Both
drove concrete follow-up work: Mach-O is now fully emulated (§15), and 32-bit x86 ELF is too (§14);
32-bit PE is detected and loads but its Windows-std emulation is not yet reliable, so it is routed
to literals only (§14) — the one gap still open. The
benchmark's obfuscation crates (litcrypt/obfstr/…) model one real pattern (EDDIESTEALER-style),
not all of them.

## 13. Library-function identification across binaries (Oct 2026, rustc 1.97)

`recover_libfuncs.py` (ARTIFACT_TIERS §3) signs library functions in an unstripped reference
build and matches them in a stripped target. Held-out check: signatures from three programs
(litcrypt, obfstr, cryptify) identified **277 library functions in two programs not in the DB
(xor_custom, add_custom), 277/277 correct, 0 misidentified**, scored against each target's own
symbols. `tests/test_libfuncs.py` reruns this (one program's signatures → a different stripped
program) in CI. A signature that matches more than one function start in the target is dropped
for that binary (e.g. `LowerHex`/`UpperHex` share a masked prologue), so an identification is
never a guess. Verified into Ghidra headless on the stripped binary: all 277 functions renamed
`lib_<name>`. The label flattens generic arguments (a monomorphised symbol reads as a long
concatenated path); the identification — which address is which function — is exact.

## 14. 32-bit x86 (i386) emulation (Oct 2026)

The emulation engine was x86-64 + AArch64 only; a 32-bit sample (FickleStealer, §12) fell through
to metadata/literals. The engine is now x86-64 + AArch64 + **32-bit x86**. What it took, found by
building the canary crates for `i686-unknown-linux-gnu` (dynamic glibc PIE — imported libc, the
realistic case that matches how real 32-bit PE malware reaches its runtime) and following the
first derail each time:

- **detection + layout**: ELFCLASS32 / PE32 / I386 → `x32`, pointer size 4; Capstone `CS_MODE_32`,
  Unicorn `UC_MODE_32`; a 32-bit stack address (the 64-bit one does not fit a 4 GB space);
  32-bit registers (ESP/EIP/EAX), cdecl arguments on the stack, 4-byte return addresses.
- **i386 REL relocations** (the key fix): i386 uses REL, not RELA, so a `R_386_RELATIVE`'s addend
  is stored *in place* at the relocated word, which LIEF reports as 0. Taking that 0 left every
  vtable and closure function-pointer null — the stdout `OnceLock` init called a null closure
  (`call eax` with `eax = 0`) and the program unwound to exit after the first decode. Reading the
  in-place addend back fixed it.
- **PIC get-PC idiom**: PIE i386 computes the GOT base with `call $+5 ; pop ebx`. That `call` is
  not a real call — the next instruction pops its pushed address — so tracking a frame for it
  leaked one every time and desynced the frame stack. The call-to-next-instruction case is now
  recognised and not framed.
- **frame/SP reconciliation**: std's sync and unwind paths return through several frames at once;
  frames the live SP has passed are now dropped, so per-`ret` tracking cannot drift.
- **32-bit TLS** (GS/Linux, FS/Windows) via a GDT descriptor, and **`int 0x80`** syscalls with
  i386 numbers (write/brk/mmap2/munmap).

**Result:** every canary crate built for `i686-unknown-linux-gnu` (ELF) returns **5/5** —
`xor_custom`, `add_custom`, `litcrypt`, `litcrypt2`, `obfstr`, `cryptify`. `tests/test_32bit.py`
builds them and asserts it; the x86-64 and AArch64 paths are unchanged (benchmark + self-tests
still pass). The static call-site recoverers, cryptify, stack-strings and libfuncs remain
x86-64/AArch64 only, so on a 32-bit binary strings come from emulation + literal recovery.

**32-bit PE is a separate, harder case and is deliberately not emulated.** The loader *does* handle
PE32 — PE32 `HIGHLOW` base relocations (4-byte, absolute → RVA against the image base; PE32+ used
only `DIR64`) and imagebase rebasing are implemented and verified against clean `i686-pc-windows-gnu`
canaries. But emulation of those same canaries recovers **0/5** (one does 2/5): the Windows std
prologue sends non-decoder functions into fake-argument-driven recursion that overflows the stack,
and the real decoders chain through runtime-initialised globals that bare emulation leaves null.
The net effect is no canaries plus false-positive strings, which would hurt precision on real PE32
malware. So `recover.py` routes PE32 to **literal recovery only** (verified: 128 literals parsed
correctly from the canaries) and skips emulation + libfuncs with an explicit note;
`tests/test_formats.py::test_detect_and_route_32bit_pe` guards that gate. Completing PE32 emulation
(modelling the Windows std init / TEB and stdcall import cleanup) is the open next-work item — the
loader groundwork is already in place.

## 15. Mach-O emulation (Oct 2026)

With 32-bit x86 done (§14), the remaining format gap from §12 was Mach-O (the macOS format; real
Rust macOS malware such as RustDoor and RustBucket ships as Mach-O). The canary crates were built
on an Apple-Silicon Mac for `aarch64-apple-darwin` and staged into the workspace; the engine now
loads Mach-O. What it took:

- **parsing**: the text section is `__text` (not `.text`); the architecture is on the header's
  `cpu_type` (ARM64 / X86_64), not `machine_type`, so a Mach-O was being mis-read as x86 until
  that was added; executable sections are flagged `S_ATTR_PURE_INSTRUCTIONS`/`SOME_INSTRUCTIONS`
  (plus `__stubs`/`__stub_helper`).
- **relocations**: Mach-O internal pointers (REBASE) are correct as long as the image is mapped at
  its native vmaddr (slide 0), which it is, so only **bindings** need fixing — each `__got` /
  `__la_symbol_ptr` / `__tlv` slot that holds an undefined symbol is pointed at a named trampoline.
- **function discovery**: Mach-O reports `is_function = False` for every symbol and has no
  `.eh_frame_hdr`, so only call targets were found and `main` (reached from the entry stub) was
  missed — the pipeline then never ran it. A symbol whose value lands in `__text` is now taken as
  a function, which restored `main` and the rest.

**Result:** every canary crate built for `aarch64-apple-darwin` returns **5/5** with no junk —
`xor_custom`, `litcrypt`, `obfstr`, `litcrypt2`, `add_custom`, `cryptify`. Three are committed as
fixtures (`tests/fixtures/macho/`) and asserted by `tests/test_macho.py` (Mach-O cannot be built
on a Linux CI runner). The ELF/PE x86-64, AArch64 and 32-bit x86 paths are unchanged. The static
call-site recoverers remain ELF/PE x86-64/AArch64, so on Mach-O strings come from emulation (+
literal recovery). The arm64 std path emulated cleanly here — unlike the statically-linked musl
std in §14 — so no further sync/TLS work was needed beyond the loader.

**On a real sample.** The Mach-O x86-64 path was then run on **RustDoor** (§12), a real macOS Rust
backdoor (universal Mach-O, ~2 MB x86-64 slice): it ran clean — 4808/4808 functions in ~16 s, no
crash — and the emulator **recovered an obfuscated C2 URL, `https://juchesoviet48.com/`**, even
though the sample is stripped of Rust metadata (`recover_rust_meta` reported non-Rust). The §12
format gap for Mach-O is closed; `gallery/results.jsonl` records the result by hash.

## 16. Independent held-out evaluation (Oct 2026)

The five canary strings in `bench_src/` are the strings the engine's heuristics were tuned
against, so recall on them overstates how the engine does on strings it has never seen. This
round measures generalisation honestly, with a **disjoint** set and a **frozen** engine:
`scripts/heldout_eval.py` generates ten held-out secrets deliberately varied in shape (a URL with
a query, a unix socket path, a Windows path, a registry key, an `ip:port`, a GUID, an
API-key-shaped token, a 2-character string, a 64-character hyphen-rich string, an HTTP-header
fragment), runs them through the **same real obfuscator crates** (`obfstr`, `litcrypt`,
`litcrypt2`, `cryptify`) and the custom XOR/ADD ciphers but **with fresh keys**, builds each into a
throwaway directory (the committed benchmark is untouched), and scores the current engine. No
engine code was changed after seeing the numbers — the misses below are reported as misses, which
is the whole point of a held-out set.

**Result (rustc 1.97, x86-64 ELF):**

| obfuscator | recall | false positives |
|---|--:|--:|
| xor_custom | 7/10 | 0 |
| add_custom | 7/10 | 0 |
| obfstr | 7/10 | 0 |
| litcrypt | 7/10 | 0 |
| litcrypt2 | 7/10 | 0 |
| cryptify | 7/10 | 0 |
| **total** | **42/60 (70%)** | **0 (precision 100%)** |

**What this shows.** Precision held at **100% across all six obfuscators on strings the engine was
never tuned on** — zero invented strings — which is the result the buffer-address overlap work
(§11) and the junk filters were meant to protect, now confirmed off the tuning set.

**What it also shows, honestly.** Recall is **70%, not the ~100% the canary benchmark reports**,
and the gap is systematic: the *same three* secrets are missed under *every* obfuscator, so the
cause is the string content, not any cipher. All three are decoded correctly by the emulator and
then dropped by the `looks_like_text` gate (verified directly): the GUID
`b3f1a9d0-7c42-4e18-9a55-0cc1e2f67d84`, the token `sk_live_51MeridianQZx7Kp0294aBc`, and the
2-character `no`. That gate is exactly what buys the 100% precision — it rejects high-entropy,
non-natural-language runs — but GUIDs, API keys and random tokens are precisely the indicators a
malware analyst most wants, and the `canary::name::value` benchmark strings (all natural-language)
never exercised that trade-off. So the honest headline is: **strong precision, and a real recall
gap on indicator-shaped high-entropy strings.** Widening the text gate to admit structured IOCs
(GUID / key / token shapes) without losing precision was the next-work item — addressed, and
validated on a *fresh* held-out set rather than this one, in §17.

## 17. Closing the held-out recall gap: structured-IOC recognition (Oct 2026)

§16's held-out set showed the `looks_like_text` gate dropping three decoded strings that are
exactly the indicators triage wants (a GUID, a vendor API-key token, a 2-char string). The gate
already had an accept-path for indicator *shapes* (`looks_like_ioc` / `contains_ioc`: URLs, IPs,
domains, paths, registry keys, mutexes, emails); it was missing two standard ones. Added:

- **canonical UUID/GUID** — `8-4-4-4-12` hex with the exact hyphen positions. The positions make
  it essentially impossible to hit by chance in XOR garbage, so it is accepted directly. Plain
  hex *without* the canonical hyphens is **not** accepted (that would be a generic-hex loosening
  and would cost precision).
- **credential tokens with known vendor prefixes** — Stripe `sk_live_…`, AWS `AKIA…`, GitHub
  `ghp_…`/`github_pat_…`, Slack `xox[baprs]-…`, Google `AIza…`, JWT `eyJ….….…`. Only recognised
  prefixes are accepted, never an arbitrary long alphanumeric run.

These are industry-standard IOC definitions, not shapes reverse-engineered from §16's two
examples, and they also enrich `ioc_tags` (recovered GUIDs/keys are now tagged `guid`/`token`).

**Validation on a *fresh* held-out set** (ten new secrets — different GUID, AWS/GitHub/Slack
tokens, paths, URL, registry key, long hyphenated id — none seen by the engine before), frozen
otherwise:

| | recall | false positives |
|---|--:|--:|
| all six obfuscators | **60/60** | **0** |

Recall on the indicator shapes went from 7/10 (§16) to **10/10 on the fresh set** — generalisation,
not a fit to §16. Precision held: on the 28 MB real unobfuscated binary (`rg`) the engine produced
**no** GUID/token-tagged strings (zero new false positives from these rules), and the full test
suite is unchanged (46 passed). The 2-character `no` from §16 is still dropped by design — below any
useful length and indistinguishable from noise — which is the right precision call.

## 18. Gallery expansion, SOC triage, live dynamic re-validation (Oct 2026)

Run on the Kali analysis VM (static + emulation, never executed unless stated). This round added
three real families to `gallery/results.jsonl` (now nine) and a first-pass triage tool.

**Real-malware wins (by hash; samples never committed).**
- **AmnesiaStealer** (macOS, Mach-O x86-64) — the headline alongside EDDIESTEALER. Emulation
  recovered the full capability picture end-to-end: the C2 exfil URL
  `https://debug.allllowef.space/send/`, the crypto-clipper config
  (`CLIPPER_ATOM/DOGE/TRC20/ENABLED`, wallet-address swapping), the fake macOS password prompt,
  Safari cookie theft, `/tmp` staging paths that expose TCC-database tampering
  (`.tcc_mod.db`/`.snap_tcc`, a privacy bypass) and `safari_cookies_via_sudo`, and AppleScript for
  Telegram/Notes exfiltration. Honest: ~16 of 28 emulation outputs are garbled std-internal
  fragments (precision edge on a large Mach-O); the ~12 genuine strings are the signal.
- **SPICA** (ColdRiver/Star Blizzard backdoor, PE x86-64, 18,598 fns) — recovered its registry
  persistence key `Software\Classes\spica`. One genuine indicator of four outputs.
- **RustyAttr** (Lazarus, macOS, Mach-O universal) — delivered **triple-packed** (zip -> gz ->
  cpio -> `VooV.app`); the payload is `VooV.app/Contents/MacOS/AwesomeTemplate`. Confirmed
  `rust=True` (59 crates) but **no** obfuscated strings — correct, because RustyAttr hides a shell
  script in a file's extended attributes rather than encrypting Mach-O strings. The value is the
  delivery-chain unpack; it drove the nested `.gz/.xz/.bz2/.tar` unpack step in
  `scripts/gallery_fetch_scan.sh`.

`scripts/gallery_fetch_scan.sh` fetches one sample by hash, verifies it is a real (not error-JSON)
zip, decrypts `infected`, unpacks nested archives, and triages every surfaced binary -- never
executing it. Luca Stealer and RustBucket were no longer on MalwareBazaar; Myth Stealer is not
string-obfuscated.

**SOC triage.** `scripts/soc_triage.py` turns one binary into a one-screen analyst card:
format/arch, Rust toolchain + panic sites, a crate capability fingerprint, indicators grouped by
tag (benign Rust std/compiler paths filtered out), a decoded sample, and a calibrated
LOW/MEDIUM/HIGH signal with evidence (an aid, not a verdict). On AmnesiaStealer it rates **HIGH**
and surfaces the C2 URL, the networking/crypto/rusqlite crate profile, and the full `/tmp` staging
set. `--fast` is sub-second (metadata + literals); `--json` feeds a SIEM.
*(Superseded, Oct 2026 review: `--fast` time grows with binary size -- 0.6 s on a canary, 19 s on
rustup, 100 s on uv -- and the signal was recalibrated to require obfuscation evidence, so the
AmnesiaStealer rating above predates the new scoring and has not been re-measured; see the README.)*

**Dynamic recovery, re-validated live.** `scripts/recover_dynamic.py` (Frida) was run on the
benign `muddy` canary (ChaCha20-Poly1305 AEAD) on the VM and recovered **5/5** canaries from
runtime memory. This is the AEAD case the static path is meant to miss -- though the emulation
engine now also decrypts muddy (it simply runs the decrypt), so static+emulation gets 5/5 too.
Dynamic detonation of **real** malware was deliberately **not** auto-run here: this Kali VM is on a
shared (vmnet) network, and a live stealer/loader would beacon and exfiltrate for real; that step
needs a host-only/isolated network and a revertible snapshot, run deliberately, per
`recover_dynamic.py`'s own safety note.

**Deflattening / real OLLVM — now closed.** The deflattener (§17) was validated on goldberg (a
real Rust CFF obfuscator) and a faithful OLLVM-`-fla`-shaped synthetic. The remaining gap — output
from a genuine LLVM flattening *pass* (not hand-written, not a single crate) — is now closed by a
**real LLVM-18 control-flow-flattening pass built from scratch** (the red-team counterpart,
"RustCloak"). The pass flattens via an LLVM `switch`, which clang lowers to a dispatcher that
reloads the state slot before each `sub r,imm; je` rung (no direct scratch->sub) and lowers
conditional transitions to a `cmovCC` select stored to the state slot (not a goldberg XOR delta).
Recovering it took two deflattener changes: the dispatcher detector now skips the reload `mov`s
between the scratch copy and the first `sub`, and `case_transitions` resolves a `mov [state],reg`
by tracing the register back through a `cmovCC` to its two immediate candidates. On RustCloak's
flattened demo the recoverer reports `flattened=true`, `update_slot=None` (direct assignment), all
six states reachable from the start to a single terminal, and both original branches (the loop test
and the parity check) as two-way transitions. Fixture + test:
`tests/fixtures/deflatten/rustcloak_flatten.x64`,
`tests/test_deflatten.py::test_deflatten_switch_dispatcher`. (Full Obfuscator-LLVM/Pluto *fork*
builds remain a separate, heavier setup, but the real-flattening-pass idiom they emit is the same
switch dispatcher now handled here.)

## 19. Cross-architecture deflattening: AArch64 (Oct 2026)

The deflattener (§17–18) was x86-64 only. A control-flow-flattened **AArch64** function does not
look like the x86 `sub imm; je` ladder at all: LLVM materialises each sparse 32-bit state constant
into its own register (`mov w,#lo ; movk w,#hi,lsl#16`) at the top of the function and lowers the
`switch` into a **balanced compare-tree** — `cmp wstate,wREG ; b.gt/b.le` to route the search,
`b.eq` leaves for the matches, and a `b.ne`-chained default that falls through to the `ret`
epilogue. Transitions are `str wCONST,[sp,#off]` (unconditional) or `csel wT,wA,wB,cc ; str`
(an original branch → two next states) — the ARM analogue of x86's `mov`/`cmovCC`.

`deobf_deflatten.py` now detects the architecture from the binary (`_detect_arch`) and routes to
`_deflatten_arm64`, which (1) builds a register→constant map from the `mov`/`movk` defs, (2) walks
the compare-tree (following range splits both ways, recording `b.eq`/`b.ne` leaves, and following
the `b.ne` default chain to the return), and (3) reads each case's `str`/`csel` for its next
state(s). The x86-64 path (`_deflatten_x86`) is unchanged.

Validated on the **same RustCloak-flattened demo decoder built for AArch64** (cross-compiled with
`clang-18 -target aarch64-linux-gnu -O2 -fpass-plugin=libRustCloak.so`). The recoverer reports
`flattened=true`, `arch=aarch64`, **21 states** fully reachable from the start (`0x0e4464bc`) to a
single terminal (`0xd45257b7`, the `ret` epilogue), and **11 two-way transitions** — the original
loop and parity branches surviving as conditional edges. Getting full reachability needed three
idiom-specific details, each now handled: a case may fall straight through into the dispatcher (no
explicit `b`), the `b.ne` default is a chain (not always back to the dispatcher), and a
`csel wd,wd,ws` reuses its own destination so its source constants must be read *at* the csel, not
at the later store. Fixture + test: `tests/fixtures/deflatten/rustcloak_flatten.a64`,
`tests/test_deflatten.py::test_deflatten_switch_dispatcher_aarch64`. With this, deflattening works
on both ARM and x64 — matching the toolkit's string-recovery path, which already covers x86-64
(`recover_callsite.py`) and AArch64 (`recover_arm64.py`).

## 20. Red/blue round 2: x86 compare-tree deflattening; runs on Windows (Oct 2026)

Driving the red/blue loop surfaced a real gap. RustCloak was hardened to stop naming its own
artifacts (its binaries previously leaked `rustcloak.decrypt`/`rustcloak.xor`/`cloak.state` — a
trivial grep/YARA signature; now all injected symbols are seeded random names and local
values/blocks are unnamed). Re-attacking the hardened output exposed that the **x86-64**
deflattener only knew one dispatcher shape: the dense `sub imm; je` ladder. LLVM in fact lowers a
flattened `switch` to **either** that ladder **or** a balanced compare-tree (`mov r,[state]; cmp
r,imm; jg/jle` to route, `je` leaves, a `jne` default chain) — the same shape as AArch64 — and with
the anonymised build's constant distribution the compare-tree is the *common* x86 form. So a
RustCloak binary was sometimes completely unrecoverable ("no dispatcher found"), purely by luck of
the constants.

`deobf_deflatten.py` now tries the compare-tree when the sub/je ladder is absent
(`_x86_cmp_tree_ladder`), reading the state constants straight from the cmp immediates. Its case
walk (`case_transitions`) was rewritten to carry register→immediate values *along* the DFS path and
branch on `cmov`, so a transition that passes through a shared `mov r,const; jmp store` epilogue —
where the constant is set in a different block from the store — resolves; a local backward scan
could not. The sub/je and AArch64 paths are unchanged and still recover fully (6/6 and 21/21
states). On the compare-tree fixture the recoverer detects the dispatcher, enumerates all states,
reaches a terminal from the start, and surfaces the original branches as two-way transitions;
full edge recovery on the messiest codegen (two state registers, multi-`cmov` shared epilogues) is
partial and honestly asserted as such. Fixture + test:
`tests/fixtures/deflatten/rustcloak_tree.x64`,
`tests/test_deflatten.py::test_deflatten_switch_dispatcher_x86_tree`.

**Runs on Windows.** The toolkit was run natively on a Windows 11 VM (Python 3.14, deps present):
`deobf_deflatten.py` recovered both the x86-64 and AArch64 flattened fixtures, and `recover.py`
pulled 5/5 canaries from the Mach-O/AArch64 fixture via Unicorn emulation. With the earlier Kali
(AArch64) runs, the tool is now exercised on Linux, macOS binaries, and Windows hosts.

## 21. Red/blue round 3: MBA + opaque-predicate annihilation; lazy strings vs emulation (Oct 2026)

RustCloak gained three red-team moves; each was validated against — and is now pinned by — the
blue side, so the loop stays honest.

**Opaque predicates and MBA (deobf_expr.py, z3).** RustCloak's `bogus` pass now mixes five
always-true opaque-predicate families per block instead of one known OLLVM shape, and its `subst`
pass now emits mixed boolean-arithmetic (MBA) rewrites (`a+b = (a^b)+2*(a&b)`, etc.) instead of
simple `a-(-b)` identities. `deobf_expr.py` already carries a sound z3 engine — `classify_opaque`
proves a predicate always-true/false/input-dependent, and `simplify_mba` proves an MBA expression
equal to a simple normal form — so it annihilates all five opaque families (every one returns
*always-true*) and reverses all five MBA substitutions back to `+ - ^ & |`. These exact emitted
forms are pinned in `tests/test_expr_rustcloak.py` (10 cases): any future red-team form that the
blue tool cannot defeat fails the suite. (RustCloak used this same engine to verify its predicates
and identities at emit time — the two tools share the proof.)

**Lazy string decryption vs emulation.** RustCloak's `RUSTCLOAK_LAZY` mode decrypts each string on
first use rather than in a startup constructor, so `strings`/FLOSS and the static call-site
recoverers see only ciphertext (0 hits) and a startup memory dump finds nothing. The toolkit's
*emulation* engine defeats it anyway: running the on-demand getter decrypts the string in emulated
memory, and `recover.py` recovered the lazily-encrypted demo secret via emulation (2 strings,
function-level) with zero static leakage. This is the intended division of labour — lazy encryption
raises the bar against static-only tools, and dynamic/emulation recovery is the answer to it.

## 22. Round 4: differential fuzzing, multi-VM testing, two new families (Oct 2026)

**Differential fuzzing of RustCloak.** The strongest behaviour-preservation check so far: one target
(`test/fuzz/target.c` in the RustCloak repo -- loops, nested loops, a switch, add/sub/xor/and/or/
mul/shift, string touches) is compiled three ways -- baseline, eager-obfuscated, lazy-obfuscated --
and the same inputs are fed to all three, aborting on any output divergence. Coverage-guided with
libFuzzer where its runtime is present, else a standalone random driver. Result: **zero divergence
over 13.4M inputs on AArch64 (Kali, libFuzzer) and 20M inputs on x86-64 (container)** -- 33M+ inputs
across both architectures, with 0 string leakage in the obfuscated shared libraries. A diverse
fixed-output corpus (C with recursion/switch/fn-ptr tables, C++ with exceptions + virtual dispatch,
Rust with enums/iterators/HashMap) passes in eager and lazy modes on both arches.

**The toolkit runs on three OSes.** The suite was run natively on the x86-64 container, the Kali
AArch64 VM, and the Windows 11 x64 VM. This surfaced and fixed two cross-platform *test* bugs (the
tools themselves were fine): the goldberg / OLLVM-fla worked examples assumed the x86 lowering and
failed when built as ARM binaries on Kali (now guarded by host arch; ARM deflattening is covered by
the `.a64` fixture), and the lazy static-absence test shelled out to the Unix `strings` binary,
absent on Windows (now scans the file bytes directly). After the fixes: green on all three hosts.

**Two new real families (gallery now 11).** Scanned fresh on the Kali ARM64 VM, static + emulation,
never executed. **RustyStealer** (PE x86-64, 55 crates): 4492/4492 functions emulated clean, two
strings via emulation including a bind indicator, lightly string-obfuscated. **AmosStealer** (Mach-O
**AArch64**, Apple-Silicon): 808/808 functions emulated with no crash, but not string-obfuscated (0
decoded) -- an honest negative, like RustyAttr. The value is robustness: the tool handled two new
real samples across PE and Mach-O/ARM without crashing.

## 23. Round 5: AI-assisted triage layer (Oct 2026)

The hottest current direction in binary analysis is LLM-assisted deobfuscation/triage, and it is
exactly the "AI-assisted malware analysis" the toolkit is building toward. `scripts/llm_triage.py`
adds that layer *on top of* the deterministic recovery, without weakening it.

**Grounded by construction.** The LLM is handed only the facts the deterministic analyzer recovered
(the soc_triage card: format/arch, Rust toolchain, crate/capability fingerprint, indicators by tag,
decoded-string sample, calibrated signal) — never the raw binary. The system prompt forbids inventing
indicators and requires every inference to be tied to a specific piece of evidence and flagged as an
inference; thin evidence must yield an explicitly inconclusive note. The deterministic facts remain
ground truth; the LLM note is a labelled hypothesis.

**Local-first, privacy-preserving backends.** Auto-detected: a self-hosted OpenAI-compatible server
(`RUST_DEOBF_LLM_BASE`, e.g. Ollama/vLLM) so malware data never leaves the host — the right default
for real samples — plus the Anthropic and OpenAI APIs, plus an **offline** mode (no key) that prints
the grounded prompt to paste into any LLM and a deterministic rule-based note, so the tool is useful
with no API at all. An LLM/network error falls back to offline rather than crashing.

**Validated.** `tests/test_llm_triage.py` (7 cases) pins the grounded-evidence subset (no sha/path
leakage into the model context), the anti-hallucination prompt, the rule-based fallback, backend
resolution (incl. a local server needing no key), the request/response handling for both the
OpenAI-compatible and Anthropic shapes (stubbed transport — no network), and the graceful offline
fallback on an LLM error. End to end against a local mock OpenAI-compatible server, the CLI builds
the evidence, calls the endpoint, and prints a labelled AI note with the recovered strings confirmed
in-context. On the committed Mach-O litcrypt fixture the offline mode emits the full grounded prompt
and rule note. (A live cloud/local call needs the analyst's own key/server and open egress; the
container's offline and mock-server paths are what CI exercises.)

## 24. Round 6: anti-emulation (RustCloak) ↔ constructor priming (rust-deobf) (Oct 2026)

A natural red/blue round on the emulation engine itself: the obfuscator attacks the assumption the
deobfuscator's string recovery rests on, and the deobfuscator removes the assumption.

**RED — RustCloak `RUSTCLOAK_ANTIEMU`.** String decryption keys are made to depend on process state
that only a real loader establishes. A marker byte starts at 0; a global constructor (emitted into
`.init_array` at priority 0, so it runs before the string-decrypt constructor) stores a per-build
random `MAGIC` into it. Every key is emitted as `key ^ MAGIC ^ load(marker)` with the marker read
*volatile*, so the compiler cannot fold it away. On a real run the constructor has set
`marker == MAGIC`, the two cancel, and the real key is used — output is byte-identical to a normal
build. Under an analyzer that emulates functions in isolation the constructor never runs, the marker
stays 0, the key is `key ^ MAGIC` (wrong), and nothing decodes. Verified: the anti-emu demo runs
correctly (`rustcloak::flatten-demo::oK`), leaks nothing statically, and rust-deobf's emulation — as
it stood — recovered **0** strings where the plain build gave 1.

**BLUE — constructor priming in `recover_emulate.py`.** The engine now replays the loader's global
constructors before the per-function sweep and bakes their writes into the restore baseline, so the
post-loader state (the marker set, any eagerly-decrypted strings) is present for every later run.
`Image.constructor_vas()` reads `.init_array`/`.ctors` (ELF) or `__mod_init_func` (Mach-O); for a PIE
each entry's target is the *addend* of its relative relocation, not the raw slot. `prime_constructors`
runs each in order on the shared engine, and `_capture_primed` snapshots the writable sections into a
`_primed` baseline that `_writable_sections` returns thereafter — so it survives the periodic engine
rebuild in `_reset` (the same mechanism the AArch64 `lse_flags` fix uses). With priming on (the
shipped default), the anti-emu binary decodes again: emulation recovers `flatten-demo`, identical to
the plain build.

**Validated.** `tests/test_antiemu.py` (3 cases, committed x86-64 fixture) pins: the secret is absent
in the static bytes; the shipped pipeline (priming on) recovers it; and — the full closure on one
engine — an un-primed sweep recovers **nothing** while `prime_constructors()` on the same image flips
it to success. Full suite green (71 passed, arch-gated cases skipped), no regression on the plain or
lazy fixtures. Priming is loader-faithful and safe on ordinary binaries (no anti-emu marker → the
only constructors replayed are the usual `frame_dummy`/registration stubs, which change nothing a
recovery reads).

**Honest limits.** PE CRT constructors (`.CRT$XC*`) are not replayed yet (ELF/Mach-O are); a
constructor that blocks on real I/O or syscalls is abandoned like any other run and simply
contributes no state. The next red move is state that no constructor sets — a value derived at the
first real syscall, or timing/TSC checks — which priming alone will not answer; that is the backlog
item for a future round (syscall/environment modelling vs. anti-analysis timing).

## 25. Round 6b: code virtualization (RustCloak) ↔ VM detection (rust-deobf) (Oct 2026)

The headline red move: RustCloak's new `virt` transform replaces a function's native code with a
custom-bytecode interpreter (the VMProtect/Themida/Tigress technique), at the LLVM-IR level so the
interpreter is portable across x86-64 and AArch64. Round 1 virtualizes single-basic-block integer
functions (mixers, key schedules, branchless checks); later rounds add control-flow, memory and call
opcodes. See the RustCloak repo for the red side.

**RED verified on both arches.** A demo with three eligible functions (`mix`, `check`, `fold64`),
fixed seed. x86-64: all three become dispatch loops over an embedded bytecode blob; the original
magic constants (`0x9e3779b9`, `0x85ebca6b`) are gone from the code (now constant-pool data) and
output is byte-identical to native (`mix=2509559747`, `check=-1`, `fold64=17926040205562134736`).
AArch64 (live on the Kali VM): identical output, and `mix` is a `ldrb`/`cmp`/`b` dispatch loop with
the magic constants (materialised by `movk` in the native build) gone. `main` is left native
(ineligible), as intended. The bytecode and constant pool are mutable globals read through volatile
loads, so `-O2` after the pass cannot constant-fold the interpreter back to the original program.

**BLUE — `scripts/detect_vm.py` (x86-64 precise).** The interpreter has a machine-code fingerprint
unlike ordinary code: a *threaded dispatch* -- many indirect branches through the same register
(each opcode handler re-dispatching) -- plus dense bytecode byte-fetches (`movzx ...byte`). The
detector flags functions matching this and reports confidence; it is a DETECTOR, not a devirtualizer
(that is a later round). On the committed virt-only fixture it flags all three functions
high-confidence (8-12 same-register indirect branches, 33-49 byte-fetches); on the plain build of the
same program it flags nothing. Precision on real binaries: `ls`, `grep`, `openssl`, `bash` -> none;
`python3` -> 2 (correctly: CPython's `_PyEval_EvalFrameDefault` genuinely IS a computed-goto
interpreter). The threaded-dispatch requirement is what rejects ordinary switch/parse loops (a lone
jump table or dense byte-loads alone do not match). Folded into `soc_triage` as a +2 signal and a
card line. *(Superseded, Oct 2026: virtualized functions now count as obfuscation evidence -- not a flat +2 --
and not at all when an interpreter crate such as a regex engine is linked; `--fast` skips the scan.)*

**Validated.** `tests/test_detect_vm.py` (3 cases): detects the 3 virtualized functions (threaded
dispatch, high confidence), stays silent on the plain build, and the classifier unit-test pins that
threaded dispatch is required (a jump table + byte loads alone is not enough). Full suite green
(77 passed), no regression.

**Honest limits / next rounds.** AArch64 detection: the same interpreter lowers to a compare-tree
dispatcher structurally like control-flow flattening, so detecting it well overlaps the deflattener's
CFG analysis -- deferred to the next blue round (deflatten-then-detect pipeline). Flattened
interpreters (RustCloak's full pipeline applies `virt` then `flatten`) hide the threaded dispatch for
the same reason; the intended answer is deflatten-first. And devirtualization proper -- lifting the
bytecode back to IR/pseudocode -- is the multi-round arc this round opens, not closes.

## 26. Round 7: control-flow virtualization (RustCloak) ↔ bytecode lifter (rust-deobf) (Oct 2026)

The VM grows teeth, and the analyzer answers by reading its bytecode back.

**RED — control flow in `virt` (RustCloak).** Round 1 virtualized only single-basic-block integer
functions. Round 2 adds branches and loops: new opcodes `JMP`/`JZ`/`JNZ`, and PHI nodes are
SSA-destructed (split all critical edges, then copy each PHI on its predecessors reading all sources
into temporaries before writing any destination -- so mutually-referencing PHIs, as in a loop, are
correct). The interpreter is restructured so every opcode handler computes the next `pc` (fall
through `pc+4`, or a branch target) feeding one `pc` PHI. `undef`/poison operands (from -O2 loop
unrolling) map to constant 0, a sound refinement. Verified behaviour-identical to native on x86-64
and AArch64: a scalar CRC/hash loop with an in-loop branch virtualizes whole, and a 20,000-input
stress fold over all demo functions matches native exactly on both arches and across seeds.

**BLUE — `scripts/lift_vm.py` (devirtualization to VM-assembly).** `detect_vm` says a function is
virtualized; the lifter decodes the embedded bytecode back to a readable listing. It anchors each
function's blob by its code cross-reference (the blobs are packed contiguously in `.rodata`, so the
`lea` targets are what delimit one from the next), a small alignment search snaps to the true start,
and the 4-byte instructions decode -- including the control-flow opcodes, so branches and loops come
back as labelled `jmp`/`jnz` with the PHI copies visible. On the committed fixture it lifts all four
functions: the three branchless mixers to their exact arithmetic chains (`mix` -> the
`xor/shl/add/mul/lshr/...` of its hash step), and the loop function to an 88-instruction listing with
labels and branches. Gated on the detector, so pointing it at an ordinary binary (`/bin/ls`, the
plain build) lifts nothing.

**Validated.** `tests/test_lift_vm.py` (4 cases): lifts all four virtualized functions (each listing
ends in `ret`, uses only known VM mnemonics); the branchless mixer decodes to its arithmetic; the
loop function lifts *with* control flow (labels + `jmp`/`jz`/`jnz`); the plain build lifts nothing.
`tests/test_detect_vm.py` still green on the control-flow fixture. Full suite green.

**Honest limits / next rounds.** RED: memory (load/store) and calls are still left native -- the next
scope jumps. BLUE: the lifter recovers VM-*assembly*, not yet C/pseudocode (re-SSA, expression
folding and pool-value resolution are the next step), and it targets the x86-64 threaded-dispatch
lowering (ARM, whose dispatch is a compare-tree, is the deferred detection/lift round).

## 27. Round 8: memory virtualization (RustCloak) ↔ lifter keeps pace (rust-deobf) (Oct 2026)

**RED — memory in `virt` (RustCloak).** Round 3 of the VM: loads, stores, `getelementptr`, pointers
and mixed integer widths. The VM becomes a uniform **i64 register file**; each width-sensitive
opcode carries its width (i8/i16/i32/i64) in its two high bits. New opcodes `LOAD`/`STORE`/`SEXT`/
`RETV`. `getelementptr` lowers to i64 address arithmetic (sign-extend the index, multiply by the
stride from the DataLayout, add); pointer arguments enter via `ptrtoint`; `ptrtoint`/`inttoptr`/
`bitcast` are register moves; `zext` is a move (the lane is kept zero-extended), `trunc` an `AND`,
`sext` its own opcode. Loads and stores hit **real process memory** -- the interpreter runs
natively, so there is no memory to emulate and correctness follows from matching the address
arithmetic. Still native: calls, global/constexpr references, floats, vectors (an auto-vectorized
loop stays native). Verified behaviour-identical to native on x86-64 and AArch64 over a
20,000-iteration stress fold that drives the virtualized functions through real buffers (a rolling
byte transform doing i8 load+store, a hash reading an i32 array), matching exactly on both arches and
across seeds.

**BLUE — the lifter keeps pace.** `lift_vm.py` now decodes the width-tagged format: the opcode byte
is `base | (wcode<<6)`, so every arithmetic/compare/load/store/sext instruction prints with its
width (`add.i32`, `load.i8`, `store.i8`), and the new `LOAD`/`STORE`/`SEXT`/`RETV` opcodes render as
`load.iW rD, [rA]` / `store.iW [rA], rB` / `sext.iW` / `ret (void)`. On the regenerated fixture it
lifts all six virtualized functions, the two memory routines showing their load/store streams and
GEP-lowered index arithmetic. detect_vm is unchanged (the threaded-dispatch signature does not
depend on the opcode encoding).

**Validated.** `tests/test_lift_vm.py` grows a case pinning that a buffer function lifts with
load/store and width-tagged ops; detector + lifter suites green; full suite green. The red and blue
halves were developed and verified on both the x86-64 container and the Kali AArch64 VM.

**Honest limits / next rounds.** RED: calls and global references are the remaining native cases;
after that, VM hardening (randomized per-build opcode encoding, multiple dispatch shapes). BLUE: the
lifter still emits VM-*assembly*; raising it to C/pseudocode (re-SSA, expression folding, pool-value
resolution) and recovering a per-build-randomized opcode map are the next steps, along with AArch64
detection/lift.

## 28. Round 9: VM hardening -- randomized opcodes (RustCloak) ↔ opcode-map recovery (rust-deobf) (Oct 2026)

The real VM-protector escalation: shuffle the instruction set per build so a deobfuscator cannot
assume opcode numbers, and answer it by recovering the map from the interpreter itself.

**RED -- per-build, per-function opcode randomization (RustCloak).** The logical-opcode->byte map is
now a seeded random permutation of the low 6 bits (`rustcloak::rng("vmenc:"+function)`), chosen per
build and per function; the width still rides in the top two bits. Two builds -- or two functions in
one build -- share no VM instruction set. It changes only the encoding, not behaviour: verified
byte-identical to native on x86-64 and AArch64 over the 20,000-iteration buffer stress fold, across
seeds 1/5/9 (each a different opcode map). And it defeats the fixed-table lifter outright -- the
round-8 `lift_vm` reports "no virtualized function could be lifted" on a randomized build.

**BLUE -- opcode-map recovery by handler semantics (rust-deobf).** The lifter no longer assumes
opcode numbers. For each VM function it parses the dispatch jump table
(`lea base,[rip+T]; add idx,-min; cmp idx,N; movsxd r,[base+idx*4]; add r,base; jmp r`) to map each
opcode byte to its handler, then classifies the handler by its characteristic native instruction
(an `xor` of two register-file slots -> XOR, `idiv` with the remainder stored -> SREM, a conditional
move into the register file -> CMOVNZ, a rip-relative pool load -> CONST, a load/store through a
register pointer -> LOAD/STORE, a `setCC` -> the matching comparison, ...), recovering the whole
opcode->operation map. It then decodes the bytecode under the recovered map. End to end on a
randomized build it reconstructs `check()`'s exact logic -- `const; mul; add; ashr; xor; srem; eq;
sgt; and; mov; cmovnz; ret` -- i.e. `t = serial*31 + salt ^ serial>>3; ok = (t%97==0) & (serial>K);
return ok ? serial+salt : -1`, from a VM whose opcode bytes are build-specific.

**Validated.** `tests/test_lift_vm.py` grows two cases on a committed randomized fixture: the
randomized build shares no bytes with the fixed-opcode fixture, and the lifter recovers the opcode
map and reconstructs `check()`'s operation set (`mul/ashr/xor/srem/eq/sgt/and/cmovnz`). The
fixed-opcode fixtures and their lift tests still pass (the lifter keeps the fixed-table path as a
fallback). Full suite green (84 passed).

**Honest limits / next rounds.** The handler classifier and jump-table parser are robust enough to
recover a function end to end, but not yet every function in one binary across every LLVM
switch-lowering (some functions' dispatch parses incompletely and are skipped rather than lifted
wrong -- conservative by design). Hardening the recovery to full coverage, raising the lifted
VM-assembly to C/pseudocode (re-SSA + expression folding + pool-value resolution), and the AArch64
dispatch are the open items. On the red side: virtualizing calls and global references, and bytecode
whose operand encoding (not just the opcodes) is also per-build encrypted.

## 29. Round 10: operand encryption (RustCloak) ↔ operand-key recovery + pseudocode (rust-deobf) (Oct 2026)

**RED -- per-build operand encryption (RustCloak).** Round 4 shuffled the opcode bytes; round 5 also
XOR-encrypts the three operand bytes (dst, a, b) with a per-build/per-function key, so the whole
4-byte instruction -- register indices, pool indices and branch targets -- is build-specific. The
opcode stays permuted (not XORed); the interpreter decrypts each operand right after fetch.
Encoding-only: byte-identical to native on x86-64 and AArch64 over the 20,000-iteration buffer
stress fold, across seeds. It defeats the round-9 lifter's operand decoding (the opcode map is still
recovered, but the register/pool indices come out scrambled).

**BLUE -- operand-key recovery and C/pseudocode (rust-deobf).** Two advances:
1. *Operand key.* The lifter recovers the XOR key (kd, ka, kb) from the interpreter -- the three
   `xor reg, IMM` that follow the operand fetches -- and decrypts the operands while decoding, so the
   register and pool indices come back correct.
2. *Pseudocode.* It raises the recovered VM-assembly to C: it resolves the constant pool (reading the
   i64 pool the CONST handler's rip-relative `lea` points at), and for a straight-line function --
   whose VM registers are each assigned once -- folds every temporary into one nested expression,
   naming the inputs a0, a1, ... End to end on a build with **randomized opcodes AND encrypted
   operands**, `check()` comes back as
   `return (((a0 > 1000) & (((((a0 * 31) + a1) ^ (a0 >> 3)) % 97) == 0)) ? (a1 + a0) : 0xffffffff);`
   -- its exact source, constants and all. A function with control flow is emitted as flat C
   statements with labels and `if/goto` (correct, less pretty).

**Validated.** `tests/test_lift_vm.py` (committed operand-encrypted fixture): the opcode map *and*
the operand key are recovered and `check()`'s operation set reconstructed; and the pseudocode comes
back as readable C with the real constants (`* 31`, `% 97`, `> 1000`, the `>> 3` shift and the
select). Full suite green (85 passed). Verified on the x86-64 container and the Kali AArch64 VM.

**Honest limits / next rounds.** Coverage: the opcode-map + operand-key + pool recovery is robust
enough to lift a function end to end to C, but the per-function dispatch/key parser does not yet
handle every register-allocation variant the compiler emits, so some functions in a binary are
skipped rather than lifted wrong (conservative). Hardening that parser to full per-binary coverage,
structuring control-flow pseudocode into real `if`/`while` (rather than `if/goto`), and the AArch64
lift are the open BLUE items; virtualizing calls and global references remain the open RED items.

## 30. Round 11: devirtualizer hardening + control-flow structuring (rust-deobf) (Oct 2026)

A blue-only round: make the opcode/operand recovery more robust, and raise the control-flow
pseudocode from `if/goto` toward structured `while`/`if`.

**Parser robustness.** The per-function dispatch/operand-key parser now handles the
register-allocation variants LLVM actually emits: the operand-decrypt key is read from the three
`xor reg, IMM8` in the dispatch prologue whatever the register width (8/32/64-bit -- `xor dil,0x..`
as well as `xor rcx,0x..`), and the opcode-index normalization is parsed from both `add idx,-min`
and the `lea idx,[src-min]` form. The table extent comes from the `cmp idx,N` range check when
present, else from scanning the jump table until an entry leaves `.text`. Operand keys are now
recovered for the demo's VM functions across all these shapes.

**Control-flow structuring.** `_structure` raises a reducible `if/goto` body to `do { } while (cond)`
(a single back-edge) and `if (cond) { }` (a forward branch over a straight block), by two
correctness-preserving peepholes, dropping the labels they consume; anything irreducible is left as
`if/goto`. Unit-pinned (`tests/test_lift_vm.py::test_structurer_raises_goto_to_while_and_if`): a
loop-plus-conditional body structures to `do/while` + inverted `if`, with no `goto` left.

**Validated.** Full suite green. `check()` still devirtualizes to its exact one-line C from the
randomized+operand-encrypted build.

**Honest limits.** This is real but partial progress on the two open goals. Full *coverage* of a
randomized build is not yet reached: some functions' maps are still incomplete (a handler shape the
classifier doesn't yet label, a dispatch the parser doesn't fully bound), so they are skipped rather
than lifted wrong -- `check()` is the end-to-end demonstration, not every function. And the
structurer handles reducible control flow; the demo's one loop function is an `-O2`-unrolled nest
(odd/even split, shared joins) that stays `if/goto`. Pushing coverage to every function and every
compiler-emitted dispatch shape, and structuring irreducible/unrolled loops (a full relooper), are
the continuing items -- along with the open red-side work (virtualizing calls and global references).

## 31. Round 12: virtualized CALL/PUSHARG (RustCloak) ↔ call devirtualization + switch-lowering coverage (rust-deobf) (Oct 2026)

Red side (RustCloak, committed separately as `38b120e`): the VM can now virtualize a function's
**calls**. Arguments are staged with a `PUSHARG` opcode into an argument buffer and the call is
dispatched through a per-function **callee table** with a `CALL` opcode, via a uniform
`i64(i64×6)` thunk (ABI-safe for ≤6 int/pointer args on SysV and AAPCS). Verified
behaviour-preserving: the `vm_demo` stress checksum (`stress=5438212857779519003`) matches the
native build on x86-64 and on AArch64 (Kali).

Blue side (rust-deobf): the lifter decodes the two new opcodes.

**CALL/PUSHARG decode.** `_classify_handler` labels the `CALL` handler (dispatch through the callee
table → a native `call`) and the `PUSHARG` handler (stage one register into the arg buffer and bump
the arg counter → an `inc`/`add reg,1`). `lift_region` renders `pusharg rN` / `call rD = fn[i](...)`,
and the pseudocode folds staged `PUSHARG`s into the argument list of the following `CALL`:
`wrap() = helper(x,y) + helper(y,x)*3` devirtualizes to the exact C expression
`return ((fn0(a1, a0) * 3) + fn0(a0, a1));`. Unit-pinned
(`tests/test_lift_vm.py::test_virtualized_call_is_devirtualized`) against a committed clean VM-only
fixture (`tests/fixtures/vm/rustcloak_vm_call.x64`).

**Two dispatch-shape fixes this required.** Validating on a freshly built binary surfaced that the
current builds lower the interpreter's `switch` to a *single* base-relative jump table
(`lea base,[rip]; add idx,-min; movsxd r,[base+idx*4]; add r,base; jmp r`), not the threaded
computed-goto of the earlier fixtures — and that LLVM peels hot/out-of-range opcodes (here ADD and
MUL) out of the switch into a `cmp rawop,IMM8; je handler` compare-chain with a fall-through
default. Both are now handled:
- `_handler_insns` stops at **any** unconditional `jmp`, not only an indirect one. In a switch build
  a handler's back-edge to the dispatch loop is a *direct* `jmp`; without this a `PUSHARG` handler
  (whose jump-back is direct) ran straight into the following `CALL` handler's code and was
  misclassified as a call.
- `_recover_map` now also parses the peeled `cmp;je` cases and the fall-through **default** handler,
  and `_decode_map` falls back to that default for any opcode byte absent from the jump table
  (delimiting the program by its first `RET` in that mode). The pool base is resolved from a CONST
  handler's rip-lea *or*, when the handler indexes an already-loaded base register, from the
  prologue `lea` that set it.

**Build note (reproducing the clean VM fixture).** The default `-fpass-plugin` pipeline runs
`virt → subst → bogus → flatten` + `strenc`, so a plain `RUSTCLOAK_VM=1 clang` build further
obfuscates the interpreter itself (the operand-decrypt `xor` becomes MBA; the dispatch is
flattened), which is a *different, harder* target. The VM-only fixtures are built by running the
`virt` pass alone: `clang-18 -O2 -emit-llvm` → `opt-18 -load-pass-plugin=… -passes=virt` → `clang-18 -O2`.

**Validated.** Full suite green; `check()` and `wrap()` both devirtualize to exact C on the clean
switch-lowered build, on top of the round-11 randomized+operand-encrypted recovery.

**Honest limits.** Round 12's goal — virtualize calls (red) and devirtualize them (blue) — is met and
pinned. Full *coverage* is still partial and remains the standing frontier: on the switch-lowered
build, `check()` and `wrap()` devirtualize end-to-end, but the loop/64-bit functions
(`mix`, `fold64`, `crc_ish`, `sum_mix`, `roll`) have their dispatch and operand key recovered yet do
not fully decode — their default/peeled opcode sits in a switch arrangement the default-handler
parser does not yet match, so they are skipped rather than lifted wrong. Generalizing default-handler
detection across every LLVM switch-lowering shape (and, separately, handling the fully-obfuscated
interpreter where the VM itself is run through subst/bogus/flatten) are the continuing items.
Devirtualizing the *interpreter-obfuscated* build is where the MBA simplifier (`deobf_expr`) and the
deflattener would feed the operand-key recovery — a natural next red/blue round.

## 32. Emulation-based devirtualization (premium) ↔ full-coverage push (Oct 2026)

Pattern-matching the interpreter's native dispatch is codegen-specific: every LLVM switch lowering
(jump table, threaded, hoisted/accumulator, guarded/unguarded) needs its own patterns, and each new
function shape risks regressing another (round-12 coverage work drove `check` out when a heuristic
was retuned for `fold64`). It also cannot survive an *obfuscated* interpreter. So full coverage is
pursued a different way.

**`premium/devirt_emulate.py` (AGPL-3.0-or-later OR commercial).** Recovers the VM's instruction set
by *running* the interpreter under Unicorn with several input vectors and observing it interpret its
own bytecode: the bytecode-blob reads give the instruction stream and the raw `[opcode, dst, a, b]`
bytes; each handler's VM register-file slot reads/writes give the operand register *indices*
directly (no operand-key parsing); and the operation is inferred from the observed value relation
(result == a^b, a*b, a>>b, ...). From those it reconstructs the opcode→logical map, the operand key
(raw byte XOR observed index), the constant pool (observed CONST values) and the default, then hands
the exact tuple the core `lift_region` consumes back to the (Apache-2.0) core for folding and
rendering. Premium depends on core; core never imports premium.

This is codegen-agnostic and obfuscation-resistant (it watches what the interpreter *computes*), and
it is the foundation for round 13 (an interpreter hardened with MBA/flattening defeats static
patterns but not execution). The licensing is open-core: this new capability is premium; the
round-12 static-lifter improvements remain core Apache-2.0.

**Correctness gate.** Every emitted result is re-executed in a small verifier over the recovered
program and required to reproduce the return value observed for every input vector; a function that
does not reproduce (or never cleanly returns) comes back as None. So the module never emits
unverified C.

**Validated.** `fold64` -- whose unguarded dense switch with handlers past the detected function
boundary defeats the static lifter -- devirtualizes and verifies through emulation. The combined
`recover_all` (static first, emulation fallback) covers `mix`, `check`, `wrap` (static) plus
`fold64` (emulation) on the clean build. Pinned in `tests/test_devirt_emulate.py`, including that the
memory-loop functions are *refused*, not guessed.

**Honest limits.** This branchless core is correct and self-verifying but not yet complete coverage:
the loop/memory functions (`crc_ish`, `sum_mix`, `roll`, `decode`) use control-flow (JMP/JZ/JNZ) and
memory (LOAD/STORE) opcodes the emulation recovery does not model yet, so they are refused rather
than lifted. Extending the emulation model to control flow (reconstructing loops from the trace) and
memory is the continuing item -- and the same work carries straight into round 13's
interpreter-obfuscated target.

## 33. Emulation: control-flow + memory framework (premium) (Oct 2026)

Extends `premium/devirt_emulate.py` from the branchless core toward full coverage and the
interpreter-obfuscated target (round 13). What is built and verified-safe:

- **Control-flow observation.** The tracer records each VM instruction's *next* bytecode offset, so
  a handler that changes the cursor is seen as a branch: an offset that always jumps is JMP, one that
  sometimes jumps and sometimes falls through is a conditional, and JZ vs JNZ is decided by
  correlating the taken direction with the observed condition-register value.
- **Memory observation.** Dereferences (reads/writes outside the reg file, blob and pool) are
  captured as LOAD/STORE; pointer arguments are pointed into a scratch region filled with
  high-entropy data (and loop-count arguments kept small) so a function that walks its arguments
  runs instead of faulting.
- **Python-VM correctness gate.** The verifier is now a full register machine with control flow and a
  scratch-backed memory model: it re-executes the recovered program and must reproduce both the
  observed return value and the observed memory writes, or the function is refused. Nothing
  unverified is ever emitted.

**Validated.** `fold64` still devirtualizes and verifies; the branchless set is unchanged; the full
suite stays green (`tests/test_devirt_emulate.py`, including that the memory-loop functions are
refused, not guessed).

**Honest limits — the remaining blocker.** The loop/memory functions (`crc_ish`, `sum_mix`, `roll`,
`decode`) are still *refused*, not yet lifted. The framework (branch/memory classification, the VM
verifier) is in place, but recovering each loop body's operands relies on a single global
operand-encryption key, and a few instructions per function violate it -- read-modify-write ops
whose destination is also a source, and dispatch reads that add a spurious slot access -- leaving one
opcode per function unclassified, so the decode is incomplete and the verifier refuses. Landing these
needs per-instruction operand recovery (resolve each instruction's operands from its own observations
rather than a global key), which is the next step -- and it is the same precision the
interpreter-obfuscated round-13 target needs. Until then the module stays strictly safe: it lifts
what it can verify and refuses the rest.

## 34. Emulation: key-free observation-based reconstruction (premium) (Oct 2026)

Replaces the emulation devirtualizer's opcode-map/key recovery with a cleaner model that reads each
instruction's logical op, width and operand register *indices* straight off the observed execution:

- register indices are normalized to one global reg-file base across runs (the base is fixed by a
  deterministic stack, but each run's lowest *written* slot varies);
- each instruction's op/width/operand order is inferred from the observed source values and result
  (widest width first, so a 64-bit op is not mistaken for a 32-bit one on its low half);
- control-flow ops come from the observed next-fetch offset, memory ops from dereferences, CONST from
  a reg written with no reg reads (value observed directly);
- reconstruction runs per argument-type group (value vs pointer vectors) using only cleanly-returning
  runs, so a scalar function fed pointer args -- or a capped run that never returned -- cannot
  pollute it;
- operand *bytes* are synthesized so the core `lift_region` renders directly, with no global
  operand-encryption key to get wrong (a read-modify-write op no longer breaks a function).

This removes the single-global-key fragility of section 33 and now devirtualizes `mix` through
emulation as well as `fold64`, both self-verified.

**Validated.** fold64 and mix devirtualize and verify through emulation; combined `recover_all`
covers mix/check/wrap (static) plus fold64 (emulation). Full suite green.

**Honest limits — still not full coverage.** The loop/memory functions (`crc_ish`, `sum_mix`, `roll`,
`decode`) are still *refused*, not lifted. Reconstruction now classifies all their opcodes, but
control-flow reconstruction from a dynamic trace is not yet correct for them -- branch instructions
are sometimes mis-identified as returns, and some operands in branchy code are mis-recovered, so the
Python-VM verifier (which re-executes the recovered program and compares return value and memory
writes) rejects the result. This keeps the module strictly safe (it emits only what it can verify)
but means branchy loop functions remain the open item: the control-flow recovery needs the branch /
return / back-edge distinction made robust before these verify. That precision is the same thing the
round-13 obfuscated-interpreter target will need.

## 35. Emulation: robust dynamic CFG recovery (premium) (Oct 2026)

Makes control-flow recovery decide branch / return / back-edge from the observed *successor* offset
of each instruction, not from whether it wrote a register. In the hoisted dispatch even a branch gets
a (garbage) result store, so "has a dst" cannot separate a branch from an arithmetic op -- only the
next fetched offset can:

- a terminal instruction (execution returned right after it) is RET;
- two distinct successors (one the fall-through) is a conditional branch (JZ/JNZ, direction from the
  condition register when it was zero);
- a single non-sequential successor is an unconditional JMP;
- a dst-less op that only ever fell through is a branch never taken on these inputs -- a no-op for the
  exercised paths, skipped rather than mis-read as a return.

This fixes the spurious mid-function returns that corrupted the earlier reconstruction. With it,
**sum_mix -- a loop over a memory buffer (load + loop + FNV mixing) -- devirtualizes and verifies
through emulation**, control flow and all, confirmed by the Python-VM gate against both its return
value and its observed loads. Combined `recover_all` now covers mix/check/wrap (static) plus fold64
and sum_mix (emulation): 5 of the demo's functions, every one self-verified.

**Honest limits.** Two function shapes remain refused (never mis-lifted):
- `crc_ish` is `-O2`-unrolled into an irreducible CFG (odd/even split, opaque `r<=r` predicates); its
  reconstruction is not yet correct and the verifier rejects it.
- `roll` / `decode` are store-heavy buffer loops; their reconstruction does not yet verify against the
  observed stores.
These, and the unrolled/irreducible relooping, are the remaining items -- pursued together with the
round-13 obfuscated-interpreter target, which needs the same dynamic recovery.

## 36. Emulation: store-loops close; coverage reaches every virtualized function but one (Oct 2026)

Three fixes land the remaining memory loops:
- a branch whose target is a skipped no-op (a never-taken branch that merely falls through) now
  resolves to the next real instruction, instead of failing the verifier;
- a side-effecting function (one with memory writes) is verified by its stores, not by the value
  left in the return register, which for a `void` function is garbage;
- per-argument-type normalization and a wider set of pointer input vectors (single-count-lane
  variants) let a function whose only scalar is a length run with its real pointer arguments.

With these, **roll** (a rolling-XOR that writes a buffer) and **sum_mix** (a buffer reducer) both
devirtualize and verify, alongside fold64. `recover_all` now covers mix/check/wrap (static) plus
fold64, sum_mix and roll (emulation) -- **every virtualized function in the demo except crc_ish**,
each self-verified against its return value and/or its memory writes.

Note: `decode` is *not virtualized* in the build (the compiler auto-vectorized it; it has no VM
dispatch), so the emulator correctly declines it -- there is nothing to devirtualize.

**Honest limit — one holdout.** `crc_ish` is `-O2`-unrolled into an irreducible CFG (odd/even split,
opaque `r<=r` predicates); its reconstruction still does not verify and it is refused. A relooper for
unrolled/irreducible control flow is the remaining item, pursued with the round-13
obfuscated-interpreter target.

## 37. Round 13 — devirtualizing through an *obfuscated interpreter* (Oct 2026)

The hardest VM target: the interpreter is itself put through the full RustCloak pipeline
(`RUSTCLOAK_VM=1` with no `RUSTCLOAK_OFF`, so `virt → subst → bogus → flatten + strenc` all run).
The operand-decrypt becomes Mixed Boolean-Arithmetic (MBA, *arithmétique booléenne mixte*), the
dispatch is flattened, and bogus control flow is sprinkled through every handler. Fixture:
`tests/fixtures/vm/rustcloak_vm_obf.x64` (same eight functions as the clean VM fixture).

**Static lifter: defeated, as expected.** `lift_vm.lift` pattern-matches the dispatch's *native*
code — the opcode table, the operand-key XORs, the switch lowering. Obfuscating that native code is
exactly what breaks the patterns: on this build the static lifter recovers **0** functions.

**Emulation: sees straight through it.** `devirt_emulate` never looks at the handler's native code;
it *runs* the interpreter under Unicorn and observes what each handler *computes* — the value
relation (`result == a ^ b`, `a * b`, …), the reg-file slots read and written, the successor fetch
offset. MBA and bogus flow change the native code, not the computed values, so they are transparent
to this recovery. On the obfuscated build emulation recovers **mix, fold64, sum_mix and roll** (4),
each self-verified by re-execution — recovery, not a plausible guess. `recover_all`: `static 0,
emulated 4, count 4`, against `static 3, emulated 3, count 6` on the clean build (no regression).

**The one bug this surfaced — the argument-register map.** The verifier re-executes the recovered
program over the same inputs and checks the result. It had assumed VM register *i* holds function
argument *i* (`reg[i] = args[i]`). That held on the clean build by luck of register allocation; the
obfuscated build lays the arguments into *different* VM registers (here arg0 → r10, arg1 → r11, each
narrowed to the parameter's 32-bit width), so the recovered program ran with its real inputs as
zero and computed a consistent wrong value — the ops and operands were all correct, only the inputs
were misplaced. Fix: `_arg_map` recovers the mapping by observation — a VM register read before it is
ever written is an input, and its first observed value equals one argument (under some integer width)
across *every* run; requiring the same argument index across all runs rules out a constant that
coincidentally matches one run. `_vm_exec` then seeds the arguments into the right VM registers.

This is the thesis of the emulation path made concrete: **obfuscating the interpreter buys nothing
against an analyst who executes it** — the harder the native code is made to read, the more decisively
the dynamic, observe-what-it-computes approach wins over static pattern-matching.

**Honest limits — unchanged.** `crc_ish` (an `-O2`-unrolled irreducible loop) is still refused on
both builds; a relooper for unrolled/irreducible control flow is the remaining item. `decode` is not
virtualized in either build (auto-vectorized), so it is correctly declined. `check`/`wrap` are
recovered by the static lifter on the clean build and are not emulation targets.

## 38. Premium audit — `llm_triage` returns to the (Apache-2.0) core (Oct 2026)

An honest pass over what sits in `premium/` and why. The dual-licensed tier should hold the deep,
differentiated capabilities; anything that is a thin wrapper belongs in the core, where it doubles as
a *produit d'appel* (an adoption draw) for a repo that is still building its audience.

- **`devirt_emulate.py`** — strongest premium: §37 just showed it recovers where static analysis is
  defeated outright. Core asset.
- **`lift_vm.py`** — premium: reconstructing a randomized opcode map + operand-key + control flow is
  genuinely hard and differentiated.
- **`deobf_deflatten.py` / `deobf_cff.py`** — premium: OLLVM de-flattening and compare-tree recovery
  are real advanced capabilities.
- **`deobf_expr.py`** — kept premium, but on the strength of the VM/MBA story (§37), not as a
  standalone Z3 wrapper.
- **`llm_triage.py`** — **moved back to core.** It is a thin layer that hands the *already recovered*
  deterministic facts to an LLM; it is not a deep capability, and `LICENSING.md` already describes the
  triage pipeline as part of the free core. Keeping it premium read as padding. Its SPDX header is now
  `Apache-2.0`; `scripts/llm_triage.py`. No code depended on its being premium (it imports only the
  standard library, never a premium module), so the core's "never import premium" rule is preserved.

Net: five modules remain premium (`lift_vm`, `devirt_emulate`, `deobf_deflatten`, `deobf_cff`,
`deobf_expr` — the control-flow and VM analyses), and the triage layer is free.

## 39. The last holdout falls — `crc_ish` devirtualizes (branchless select + unrolled loop) (Oct 2026)

`crc_ish` was the one virtualized function emulation still refused, on both the clean and the
obfuscated builds. Tracing the refusal with a lockstep differential (follow the *observed* control
flow, compute each instruction with the *recovered* op, flag the first value that disagrees) pinned
two distinct root causes -- both now fixed, and neither specific to crc_ish:

1. **A branchless select (CMOVNZ) the emulator dropped.** One instruction is
   `r[dst] = r[cond] ? r[val] : r[dst]`. Compiled as a conditional move (or a tiny branch), the trace
   shows, per occurrence, the condition plus whichever operand *that run* took -- so the source set
   varies between occurrences. The fixed-operand arithmetic inference could not see it and, worse,
   mistook the condition-nonzero majority for `AND(val, val)`; and `_vm_exec` had opcode 27 on its
   "not modelled -> bail" list. Fix: model CMOVNZ in the interpreter, and add a `_cmov` detector that
   recognises the select from two-sided evidence (an occurrence where the condition is zero and the
   result preserves the destination, and one where it is non-zero and the result equals a distinct
   value register), so it never fires on a genuine binary op.

2. **A 32-bit parameter seeded at full width.** `crc_ish` takes a `uint32`; the VM narrows it into the
   register file (`arg & 0xffffffff`). An op reading it had been recovered as 64-bit (its low half
   matched the narrowed operand), so seeding the register with the full 64-bit argument leaked the
   high bits. Fix: `_arg_map` now records the *width* each argument entered at -- the widest mask under
   which the observed value still equals the argument across every run -- and `_vm_exec` seeds at that
   width. A genuine 64-bit argument still matches at full width; a narrowed one falls to 0xffffffff.

With these, `crc_ish` recovers and self-verifies, its branchless select rendered as `cmovnz` and its
FNV constants (`0x1000193`, `0x811c9dc5`) intact. Coverage is now **complete**: clean build
`static 3 / emulated 4 / count 7` -- every virtualized function in the demo -- and obfuscated build
`static 0 / emulated 5`, the whole set recovered through an obfuscated interpreter by emulation alone.
`decode` is still (correctly) declined: it is not virtualized (auto-vectorized), so there is nothing
to devirtualize, and recovery returns None rather than emit anything unverified.

## 40. Generalizing the select detector — both polarities, codegen-agnostic (Oct 2026)

§39 added a CMOVNZ detector keyed to RustCloak's one select form. But emulation recovery is meant to
be codegen-agnostic -- it observes what the interpreter computes, not how a particular obfuscator
spelled it -- so the select detector should recognize a select however it is expressed, not only the
shape this one VM emits.

RustCloak's VM has a single select opcode, `OP_CMOVNZ`, and an LLVM `select` always lowers to
`mov dst, false; cmovnz dst, cond, true` (confirmed in `src/Virt.cpp`): the false branch is the
destination's own prior value. So the CMOVZ polarity (`cond ? prev : val`) and a fused two-operand
select cannot come out of a RustCloak binary at all. They can out of other toolchains, though, so the
recovery now handles both:

- `_cmov` returns `(cond, val, take_nonzero)` and detects **CMOVNZ** (`cond!=0 ? val : prev`) and
  **CMOVZ** (`cond==0 ? val : prev`). It also consults the reg-file snapshot, not only the freshly
  read sources, so a value operand that was live in a CPU register (not re-read from a slot) is still
  found. The two-sided-evidence requirement is unchanged -- one occurrence that preserves the
  destination and one that selects a distinct value register, each consistent across its side -- so it
  still never fires on a genuine binary op (a unit test pins that an `xor` is not seen as a select).
- `_vm_exec` and `lift_vm` gained opcode **31 (CMOVZ)**, rendered `(cond ? prev : val)`, alongside 27
  (CMOVNZ). 31 was unused in the VM's opcode space, so the synthesized reconstruction can emit it
  without colliding with a real opcode.

Because RustCloak cannot produce CMOVZ, the new polarity is exercised by a self-contained unit test
(synthetic observations for detection; a synthetic program for interpretation and rendering) rather
than a binary fixture. crc_ish (a real CMOVNZ) and the full coverage of §39 are unchanged.

## 41. Nested-loop fixture — stressing (and extending) the relooper (Oct 2026)

A fixture of reducible loop *nests* (`tests/fixtures/vm/rustcloak_vm_nested.x64`, source
`rustcloak/test/vm_nested.c`): `nested_sum` (a clean double loop), `tri_mix` (triangular -- inner
bound depends on the outer index), and `find_mix` (an inner `break`). Built VM-only with
`RUSTCLOAK_VM=1 opt-18 -passes=virt` on scalar IR (`-fno-vectorize -fno-slp-vectorize
-fno-unroll-loops`, so the loops stay virtualizable rather than being auto-vectorized like `decode`),
plus an obfuscated-interpreter build via the full `-fpass-plugin` pipeline. It stressed two layers:

**Emulation coverage.** A nest's trip count is the *product* of its bounds, so the existing input
vectors drove the inner loop past the execution budget (a 400k native-instruction cap, ~18k VM
instructions) and left only one or two cleanly-returning runs -- too few to reconstruct from. Fix:
tiny-count input vectors whose every lane is a small value, so a nest still terminates within budget.
With those, all three functions recover and self-verify, on both the clean and the obfuscated builds.

**The relooper.** `_structure` had only `do/while` (a conditional back-edge) and `if-then`. A
top-tested `for`/`while` is a *different* shape -- a single unconditional back-edge `goto L` with the
loop test as a forward `if (cond) goto Lexit` inside the body -- so every loop here was left as
`if/goto`. Added a `while(1)` peephole: a head label with a single unconditional back-edge and the
statement after it a label becomes `while (1) { body }`, with forward branches to that exit label
rewritten to `break`. Applied in the existing fixpoint, so nests fold innermost-first. The inner loop
of each nest now structures (and `sum_mix`/`roll`/`crc_ish` gained structure too, no regression).

**Honest limit still standing.** The peephole needs the loop body *contiguous* between head and
back-edge. The outer loop of a nest is often laid out non-contiguously by the compiler (its back-edge
target sits far from the latch), so it is left as `if/goto` -- correct, just not raised. A general
relooper for non-contiguous / irreducible layouts is the next step. Crucially, structuring only
rewrites control-flow syntax over the already-verified program, so an unstructured loop is less
pretty, never less correct.

## 42. A general relooper — CFG-based block layout for non-contiguous (and irreducible) loops (Oct 2026)

§41 left the honest limit that a loop laid out *non-contiguously* by the compiler stayed as `if/goto`,
because the peephole structurer needs the loop body contiguous in the statement list. Measuring the
outer loop of `nested_sum` showed it is **reducible, merely non-contiguous**: header at `0x48`, the
body jumps forward to the inner loop at `0xa4`, whose exit falls *back* to the latch at `0x74..0x94`
(lower offsets), with the back-edge `0x94 -> 0x48`. Not irreducible -- just out of order. (The probe
also found a latent bug: a branch target that landed on a skipped no-op offset emitted a `goto` to a
label that was never produced -- a dangling `goto`.)

So the relooper is now **CFG-based** (`_cfg_layout`): build the basic-block graph from the recovered
program, resolve every branch target to a real instruction (bumping a no-op target to the next real
offset -- no more dangling `goto`), compute dominators (Cooper-Harvey-Kennedy) and the natural loops
from the back-edges, then lay the blocks out so each loop's body is **contiguous** (a loop header
expands its whole body as a unit before its exits, fall-through edges kept adjacent). Every
inter-block edge is made explicit, so the reordering is semantics-preserving; the existing, verified
peephole structurer then folds the now-contiguous loops. An irreducible back-edge (header does not
dominate the tail) is simply not treated as a loop, so those blocks stay as correct `goto` -- the
layout degrades safely rather than emitting wrong structure.

Results (each still self-verified; structuring only rewrites control-flow syntax over the verified
program, never its logic):
- **`nested_sum`, `tri_mix`: fully structured** -- both the inner and the (previously non-contiguous)
  outer loop raise to nested `while (1)`, zero `goto` left, nothing dangling.
- `crc_ish`, `sum_mix`, `roll`: more structure than before, no dangling `goto`.
- `find_mix`: still `if/goto` -- its inner `break` makes a genuine multi-exit loop, which this
  layout+peephole does not fold (a correct, honest limit); output is valid, just not raised.

Pinned by a fixture test (the nested functions fully structure with no dangling target) and a
self-contained unit test (a hand-built non-contiguous reducible loop folds to `while(1)`). Full suite
green.

**Remaining limit.** Multi-exit loops (an inner `break`/`continue`) and genuinely irreducible nests
are still left as `goto`. The natural next step is labelled `break`/`continue` for multi-exit loops
and node-splitting (or a dispatch block) for irreducible regions -- a full Relooper.

## 43. Completing the relooper — multi-exit loops; and why node-splitting had no target (Oct 2026)

The §42 limit was a loop the peephole could not fold because it was not single-exit. Following the ask
to "finish the relooper" with labelled break/continue and node-splitting, the discipline here was to
**measure first**: a reducibility check over every virtualized loop function (crc_ish, sum_mix, roll,
nested_sum, tri_mix, find_mix) reported **all six reducible**. So there is no irreducible fixture for
node-splitting to act on -- the earlier "irreducible" label on crc_ish was wrong; it is reducible and
merely multi-block. The real gap is **multi-exit** and **multi-latch** *reducible* loops.

- **Multi-exit loop fold (shipped).** find_mix's inner loop has one back-edge but exits to two
  different targets (its normal `j < n` exit and its `break`), so the single-exit `while(1)` peephole
  bailed. Added a generalized fold: a header with a single unconditional back-edge whose body leaves
  to two or more targets becomes `while (1) { ... }` with the back-edge dropped; C has no labelled
  break, so each exit stays a `goto` (the idiomatic C multi-target exit). find_mix's inner loop now
  folds to a while-loop; nested_sum / tri_mix (fully structured) and crc_ish / sum_mix / roll are
  unchanged, and nothing dangles.

- **What was tried and backed out, honestly.** (1) A *topological* block layout (hold a block until
  all its forward predecessors are placed, so a two-predecessor merge lands after both arms) would let
  find_mix's **outer** loop fold -- but it broke the loop *contiguity* the peephole relies on and
  regressed the clean nests (nested_sum went from two `while(1)` to nineteen `goto`), so it was
  reverted. (2) A **multi-latch `continue`** rewrite (a second back-edge to the header) could interact
  with the do/while peephole and emit a malformed (semantically wrong) nesting on a synthetic case, so
  the fold is restricted to a **single** back-edge; a multi-latch loop is left as correct `goto`.

- **Node-splitting: not shipped, by measurement.** No fixture is irreducible, so there is nothing real
  to split or validate against. Rather than add speculative, untested-on-real-data node-splitting to a
  premium module, it is deferred until a genuinely irreducible target exists (which would need a
  hand-built or deliberately-constructed fixture). Structuring remains cosmetic over the verified
  program, so every unfolded loop is valid `goto`, never wrong.

**Remaining limits (honest).** A loop whose latch is a two-predecessor merge (find_mix's outer loop)
and a multi-latch loop stay as `goto`; both need a merge-aware layout that does not sacrifice loop
contiguity. Genuine irreducibility (absent here) needs node-splitting or a dispatch block. These are
the next steps for a full Relooper.

## 44. Arch / format matrix for the VM-devirtualization capabilities (Oct 2026)

The session's new capabilities (emulation-based devirtualization, the branchless-select detector, the
argument-width map, the relooper) were exercised only on x86-64 ELF. Extending the matrix the
toolkit promises (x86-64 / ARM64 / x86-32, ELF / PE / Mach-O), the honest result:

- **x86-64 ELF** -- fully supported (every fixture: the call, obfuscated-interpreter, and nested-loop
  builds). This is the validated path.
- **AArch64 (ARM64) ELF** -- the VM devirtualizer is x86-64 only *by design*: `devirt_emulate.recover`
  and `lift_vm.lift` both guard on `img.arm` / `img.x32` and bail. Confirmed on a real AArch64 ELF
  carrying RustCloak-virtualized functions (`tests/fixtures/vm/rustcloak_vm_arm64.so`, cross-built
  with `clang -target aarch64-linux-gnu` + the VM pass): `lief` loads it, `Image` flags it AArch64,
  and every recovery path returns empty in ~3 ms with no Unicorn run -- a clean decline, never a crash
  or a wrong result. Pinned by a test. (Note: the relooper itself is arch-agnostic -- it structures
  whatever program the recovery produces -- but no ARM64 *recovery* feeds it today.)
- **x86-64 PE** -- **supported; cell closed in §47.** A realistic PE (full mingw-w64 CRT, `.pdata`)
  is now pinned (`tests/fixtures/vm/rustcloak_vm_pe.exe`): `detect_vm` flags the virtualized function
  HIGH and emulation devirt recovers it correctly (numeric equivalence to the C source checked
  offline). The earlier in-cloud gap was only the *toolchain* (no mingw at first), not the analysis.
- **x86-32 ELF/PE, Mach-O** -- not exercised this session; x86-32 is declined by the same guard as
  ARM64, and Mach-O loads via `lief` but the VM devirt path is still x86-64-gated.

Discipline note (measure, don't assume): the above states exactly what was tested on which target and
what was not. The ARM64 decline is measured and pinned; PE and the rest are called out as untested
in-cloud rather than presumed to work.

## 45. False positive fixed — gimli (std's DWARF reader) is not a VM (Oct 2026)

Running the demo surfaced a real false positive: on the benign `obfstr` and `litcrypt` benchmark
binaries, `detect_vm` flagged functions as "VM-protected", pushing the SOC triage card to HIGH on
clean code. The tell (noted from the demo) was that the flagged functions were *identical* across two
unrelated binaries -- the signature of a statically-linked std function, not application code.

Confirmed: the flagged function demangles to `gimli::read::rnglists::RngListIter` -- **gimli**, the
DWARF parser behind Rust's backtraces/unwinder. A DWARF range-list reader is a byte-fetching dispatch
over DWARF opcodes, so it genuinely has the interpreter shape the detector keys on (threaded dispatch
+ dense byte-fetches). It *is* an interpreter -- just not code virtualization.

Measurement separated the two: a RustCloak-virtualized function re-dispatches from every opcode
handler (observed `top` indirect-branches-to-one-register of **8, 10, 12** across the fixtures), while
gimli's reader dispatches only ~**5** times. Two guards, so both symbolized and stripped binaries are
covered:

- **Symbol filter.** `detect()` skips functions whose symbol names a known benign interpreter --
  gimli, the unwinder (`_Unwind`), `backtrace`, `addr2line`, `object` -- the std/runtime machinery
  that walks DWARF/EH formats in every Rust binary. Reliable whenever symbols survive.
- **Raised threshold.** The medium rule moved from `top >= 4` to `top >= 6` (high to `top >= 8`), so
  gimli's `top == 5` no longer matches even with no symbols. Every real VM fixture (top 8-12) still
  flags HIGH; `obfstr`/`litcrypt` (strip and nostrip) now report **0** VM functions and the triage
  card drops from HIGH to LOW/MEDIUM on them.

Pinned by `tests/fixtures/vm/benign_rust_std.x64` (the obfstr strip binary -- old rule: 1 VM hit;
new: 0) and classifier unit tests (`top == 5` is not a VM; the benign-name filter works). The real VM
fixtures are unaffected (same counts before and after). Separately confirmed the stray leading `"` in
some litcrypt strings is **not** a rust-deobf defect: litcrypt mishandles Rust raw strings, so the
sample really contains that quote (and `manifest.json` records it) -- the recovery is faithful.

## 46. Emulation speedup (and a relooper layout that didn't pay off) (Oct 2026)

The nested-loop input vectors (§41) roughly doubled the emulation test time -- enough to push the full
suite past the harness's time budget. Two changes cut it back ~3x (8 fixture functions: ~53s -> ~19s)
with *no* loss of fidelity:

- **Lower trace budget.** A run that hits the per-trace instruction cap did not return and is
  discarded by `_attempt` (only cleanly-returning runs are used), so the cap only has to fit the
  *terminating* runs. Loops are driven by small-count vectors and terminate quickly (longest observed
  ~17k VM-instructions; recovery holds well below 50k native), so the budget dropped 400k -> 120k.
  A big-argument vector that turns an argument into a huge loop count now caps 3x sooner and is thrown
  away just the same.
- **Per-group lazy tracing.** `recover` traces the scalar (value) vectors first and returns the moment
  they verify, so a scalar function never pays for the pointer-vector traces. The laziness is per
  *group*, not per vector -- every value vector is still traced -- so coverage of a data-dependent
  path (find_mix's `break`) is unaffected. (An earlier attempt that withheld the tiny-count vectors as
  a sub-fallback did lose that break's fidelity and was abandoned.)

**A relooper layout that didn't pay off (recorded as a negative result).** To fold find_mix's outer
loop -- whose latch is a two-predecessor merge -- the block layout was reworked to reverse-postorder
of the reduced graph (inner loops collapsed), which places a merge after all its predecessors. On a
*lower-fidelity* recovery of find_mix (where the `break` had collapsed to a cmov) it folded both loops
cleanly, which looked like a win. But on the *full-fidelity* recovery it did not help -- find_mix's
inner loop genuinely exits to two different targets (the normal exit and the `break`), which C cannot
express without `goto` (no labelled break) -- and it *regressed* crc_ish / sum_mix / roll (more
`goto`, because RPO trades away the fall-through adjacency the peephole exploits). So the RPO layout
was dropped and the simpler DFS layout kept. The honest limit stands: a loop with exits to two
different targets stays `goto`; folding it would need a label-variable dispatch, which is less
readable than the `goto`, not more.

## 47. Closing the x86-64 PE cell — and a false alarm that measure-first caught (Oct 2026)

With mingw-w64 available in-cloud, the x86-64 PE cell of the matrix (§44) was closed. A realistic PE
was built from the demo source (`rustcloak/test/vm_demo.c`) with the full Windows CRT and `.pdata`
(`tests/fixtures/vm/rustcloak_vm_pe.exe`, 258 KB, sha256 `3816a8e0…9578`). On it:

- **Detection works.** `detect_vm` flags the virtualized `fold64` (RVA `0x16b0`, 688 bytes) HIGH --
  threaded dispatch + byte-fetches, exactly as on ELF. The address is an **RVA** (lief reports PE
  section addresses relative to the imagebase); detect and `recover` both consume RVAs, so passing an
  imagebase-relative VA finds nothing -- the one PE-specific addressing gotcha.
- **Emulation devirt works.** `recover` lifts it to
  `((((a0 ^ a1) * 0x100000001b3) >>u 41) + (((a0 ^ a1) * 0x80000000d9800000) + (a1 & 255)))`.

Pinned by `test_pe_detection_and_emulation_devirt` (detect HIGH + recover + structural constants).

**The false alarm (and why it is recorded).** The recovered PE expression looked wrong at first
glance: a running demo compared it against the *simpler* `fold64` from a different source file
(`h ^= v; h *= prime; h ^= h >> 32`) and it mismatched on 100% of random inputs. That looked like a
PE-path soundness bug -- a "verified but wrong" recovery, since emulation verifies by re-executing
its own observed trace (a closed loop that cannot catch an emulation error). Several hours went into
localizing it: ruled out argument registers (the Microsoft x64 ABI passes args in RCX/RDX, not
SysV's RDI/RSI -- a real difference, but `recover`'s observed argument-register map already handles
it, so recovery is correct either way), ruled out memory mapping and relocations (no unmapped reads;
the constant pool at RVA `0x9120` is read correctly), and ruled out codegen (plain `fold64` lowers
identically on mingw and Linux clang, only the arg registers differ).

The resolution was that **there was no bug**: `vm_demo.c`'s `fold64` is the *rotate-and-add* variant
`h ^= v; h *= 0x100000001b3; h = rotl(h, 23); return h + (v & 0xff)`, and the recovered expression is
algebraically exactly that -- `rotl(m, 23) == (m << 23) + (m >> 41)` over disjoint bits, and
`(m << 23) == m * (prime << 23)` with `(prime << 23) mod 2**64 == 0x80000000d9800000`. Checked by
re-executing the recovered expression against the real C source: **0 mismatches over 200000 random
64-bit input pairs.** The investigation had been comparing against the wrong source's `fold64`.

Two lessons, both the project's own discipline (*measure before concluding; a result is not a result
until independently confirmed*):

1. The discipline cut the right way in the end -- the "bug" was a verification error of mine, caught
   by finally checking the recovered expression against the *actual* source rather than a remembered
   one. No code was changed to chase it; the exploratory ABI / relocation / held-out-verification
   edits made while hunting were all **reverted** once the recovery proved correct, since they fixed
   nothing measurable and would have been speculative changes to working code.
2. The real, standing limitation is unchanged and worth restating: emulation devirt self-verifies by
   re-executing its own trace, so it is sound *relative to the interpreter's observed behavior* but
   cannot, on its own, catch a case where the emulation itself diverges from the true program. On PE
   that divergence did not occur (confirmed against source); the guard against trusting a recovery
   blindly remains "check the recovered expression against ground truth", which is what settled this.

## 48. Round 8: fuzzing rust-deobf itself — robustness on hostile input (Oct 2026)

§22 fuzzed *RustCloak* (the obfuscator) for behaviour preservation. This round turns the fuzzer on
the *deobfuscator*: rust-deobf runs in SOC pipelines on attacker-controlled files, so a crafted
ELF/PE/Mach-O that crashes, hangs or exhausts memory in the loader/emulator is a real defect — one
bad sample kills an analyst's whole batch run. The property under test is not recovery, it is
**robustness: never take the process down, on any input.**

**The harness — `scripts/fuzz_recover.py`.** A mutation fuzzer over the whole path that touches
attacker bytes — `recover.detect`, `recover_emulate.Image`, the metadata / &str-literal /
stack-string / static-call-site / cryptify / VM-detection primitives, the Unicorn `emulate` sweep,
and the hardened front ends `recover.run` / `soc_triage.triage` — across ELF/PE/Mach-O and
x86-64/aarch64/x86. It mirrors §22's design: coverage-guided via **Atheris/libFuzzer** when its
runtime is present (`--atheris`), else a standalone mutation driver. The committed benign fixtures
(every format/arch) are the seed corpus; mutation is half whole-file (stress the header parsers)
and half body-only past the header (keep the file parseable so the *deep* loader/emulator code
actually runs — the richest crash surface). Each input is run in an isolated child with an
address-space **rlimit** and a wall-clock **timeout**, so a native segfault, an OOM, or a true hang
becomes a recorded *finding* instead of taking the fuzzer down. The contract is explicit: the
never-raise front ends (`recover.run`, `recover.detect`) must return on any input; the lower
primitives may raise a *controlled* parse rejection (`ValueError`, `struct.error`, lief errors,
`soc_triage`'s `UnsupportedInput`) but never an *uncontrolled* failure (`MemoryError`,
`RecursionError`, a C-level abort, or a hang).

**Five bugs found and fixed, over two campaigns (all the `_SEG_CAP` bug class the first review
flagged — raw attacker-controlled size fields and crafted layouts used as loop / allocation bounds).**
A body mutation that writes a huge value into a section's `size` / `VirtualSize` field, or rebases a
section onto the emulator's fixed memory, is parsed fine by lief but then:

1. **`Emulator._fresh` hung.** The per-page image snapshot bounded its `range()` by the raw
   `max(size, VirtualSize)`, so a `0xffff...`-sized section made the loop iterate over ~2^52 pages —
   an effectively infinite hang, *before* any `--time-budget` applied. Fixed to use the same
   `_seg_extent` (per-section `_SEG_CAP`, 128 MB) `map_image` maps; pages past it are unmapped anyway.
2. **`_writable_sections` overflowed / OOM'd.** It re-padded the already-capped section content up to
   the raw `size` with `b"\x00" * (size - len(raw))` — `OverflowError` on an enormous size, a
   multi-gigabyte allocation on a merely-large one, and redundant (`_content` already pads to the
   capped extent). Fixed to use the capped content directly.
3. **Aggregate OOM across many sections.** Per-section `_SEG_CAP` still sums without bound, so a
   binary with many huge-`VirtualSize` sections OOM'd the mapper, the page snapshot and the
   writable-section buffers together. Fixed with a new `_mappable_sections` helper enforcing an
   aggregate `_TOTAL_MAP_CAP` (192 MB — far above any real image, which total well under 70 MB) used
   by all three section loops so they agree on the included set.
4. **Fixed-region collision (`UC_ERR_MAP`).** A section whose rebased VA lands on the emulator's
   fixed STACK/HEAP/TLS/SCRATCH/TRAMP window made the fixed-region `mem_map` raise. Such an image is
   not emulatable; `_emulate` now catches a setup fault and yields nothing cleanly instead of raising.
5. **`prime_constructors` hung.** Each `.init_array`/`.ctors` target was replayed for up to
   `CTOR_BUDGET` instructions with `emu_start(timeout=0)` — finite but, with the per-block Python
   hooks, seconds long, and unbounded across a crafted `.init_array` listing thousands of entries.
   Fixed with a wall-clock bound per constructor run and for the whole priming phase, plus a cap on
   the number replayed. The *sweep* is deliberately left instruction-count-bounded (no wall clock),
   so recovery stays deterministic and reproducible across machines; priming is best-effort state
   setup, so a wall-clock cut there is safe and never fires on a real (sub-millisecond) constructor.

**Validated.** `tests/test_fuzz.py` commits ten reproducers (mutations of the benign canary fixtures
— no malware, no live indicators, just corrupted benign binaries) covering all five root causes;
each used to hang or crash and now finishes in well under a second, checked both in-process and
through the isolated rlimit+timeout runner, which also pins the robustness classifier. The harness's
own pinned-corpus self-test (14 hand-built malformed inputs run clean through every target) runs in
CI via `tests/test_selftests.py`. After the fixes a fresh isolated campaign of **2,500** mutated
inputs over the deep loader/emulator path (seed 20261026) reported **0 findings** where the first
campaigns had found one within ~100 inputs, and 8,000 inputs over the fast parser surface reported
**0**. Full fast suite green (186 passed), with no recovery regression — for a real binary
`_mappable_sections` yields every section and the priming cap never fires, so legit behaviour is
byte-identical.

*(Isolation note: the campaign runner uses a `forkserver` — a fresh clean child per input — not a
plain `fork`; forking after the parent has instantiated Unicorn inherits poisoned JIT state and fails
with "Could not allocate dynamic translator buffer", which a `forkserver`/`spawn` child avoids.)*

**Multi-VM / multi-arch.** The harness is architecture- and OS-agnostic by construction — it mutates
ELF/PE/Mach-O x86-64/aarch64/x86 seeds and drives the same loader/emulator code that runs on every
host — so a loader/emulator defect it surfaces on the x86-64 container is a defect on every target.
To run it natively on the [dual-vm-ai-agent](https://github.com/VAHPEM/dual-vm-ai-agent) Kali AArch64
and Windows x64 VMs (as §22 did for the differential fuzzer), build that host's fixtures
(`bash scripts/build_all.sh`) and run `python3 scripts/fuzz_recover.py --time 1800 --seeds build/`
there; crashing inputs land in `build/fuzz_crashes/` with a `.txt` repro note, replayable with
`--reproduce`.

**Honest limits.** The standalone driver is dumb mutation, not coverage-guided, unless Atheris is
installed (`--atheris` wires it to libFuzzer). The rlimit/timeout isolation catches native crashes
and hangs but a crash that only manifests under a specific real OS/libc (not the container's) still
needs the native VM run above. And robustness is a moving target: new engine code is new crash
surface, so the fuzzer is meant to be re-run, not run once.

## 49. Round 9: a red/blue loop that generates its own held-out cases (Oct 2026)

The reviews' sharpest critique was overfitting: a fixed benchmark proves recovery on *those shapes*,
not in general. `scripts/redblue_loop.py` answers it structurally — it is a fuzzer for the recovery
engine, the analysis-side counterpart to §48's robustness fuzzer. Each round:

1. generates a *random* benign Rust program that plants known indicator-shaped strings (built only
   from reserved documentation placeholders — RFC 5737 TEST-NET ranges, `.invalid`/`.example` TLDs,
   synthetic tokens) in four different places: a plain print, an equality compare, a `match` arm,
   and a branch that never runs (the hardest, exercising path exploration);
2. compiles it under a *random* RustCloak configuration — seed × {string encryption, lazy, anti-
   emulation, virtualization} — via nightly `rustc -Zllvm-plugins` and the RustCloak LLVM plugin;
3. runs rust-deobf and checks every planted string was recovered. Recovery is **ground truth by
   construction**: we planted the strings, so the exact answer is known. A miss is a real, held-out
   gap — the binary is saved as a regression fixture and recorded, so it cannot silently reappear.

**Run here, end to end.** Built `libRustCloak.so` against LLVM 18.1.3 and used
`nightly-2024-06-15` (LLVM 18.1.7). A 5-round run (seed 3, 8 indicators each) compiled all five
obfuscated programs and recovered **20/40** planted strings, saving three miss fixtures. The split
is the finding: the **lazy / virtualized** builds recovered **8/8** (lazy string encryption decrypts
each string in a per-string getter the sweep emulates; the getter *builds* the plaintext, so it is
captured), while the **eager** `strenc` builds recovered only 1–2/8. The gap is specific and
concrete: eager mode decrypts every string once in a global constructor, and constructor priming
(§24) *does* restore that plaintext into the image — but the per-function sweep only reports strings
a function **builds**, so an eagerly-decrypted string that is merely *read* (compared, matched, or
on a dead branch) sits decrypted in memory and is never surfaced, while a printed one (whose bytes
flow through a captured buffer) is. That is why the fixed benchmark, whose canaries print their
strings, reads 5/5 on eager strenc yet these read-only placements do not: exactly the held-out shape
the loop exists to find. The blue follow-up is to report indicator-shaped plaintext that priming
produced in writable memory but no run rebuilt — weighed against the precision floor, since a
constructor that decrypts/initialises data is also ordinary-program behaviour.

**Validated.** `redblue_loop.py --selftest` (run in CI via `tests/test_selftests.py`) pins the
generator (four placements, documentation-placeholder indicators only), the configuration space, the
recovery diff (hit via substring / miss-by-tag / extra), and prerequisite detection — all without a
toolchain. The loop itself needs the plugin and a matching nightly (it detects both and explains what
is missing); its miss fixtures and JSONL report are written under `build/redblue/` (git-ignored, like
the fuzzer's crash corpus). Re-running it on each toolchain update keeps the overfitting answer live.

## 50. Round 10: Rust type-layout recovery — trait-object vtables (Oct 2026)

The first "beyond strings for a decompiler" tier, and the clearest gap vs. academic Rust
decompilers (which recover types but put obfuscation out of scope). `scripts/recover_types.py`
recovers **trait-object vtables**: every `dyn Trait` pointer in Rust is a fat pointer (data, vtable),
and the vtable is a fixed read-only record — `[drop_in_place, size, align, method_0, method_1, ...]`.
Recovering it lets a decompiler resolve dynamic dispatch (which function a `dyn Trait` call reaches),
label each vtable, and recover the concrete type's size/align and method set.

**Precise by construction.** The recogniser requires the exact vtable shape — a drop pointer into
executable code, a plausible type `size` (≤ 1 MB, a multiple of `align`), an `align` that is a power
of two ≤ 4 KB, and at least one method pointer into code — and, crucially, scans only the data
sections where vtables live (`.data.rel.ro`/`.rodata`/`.data`; `__const`/`__data` on Mach-O), not the
symbol/hash/relocation tables whose pointer-shaped bytes otherwise yield absurd false "vtables". It
reuses the emulator's relocation resolver so a PIE's vtable slots (stored as relocation addends or
Mach-O chained fixups, 0 in the raw file) read as real addresses. Layout is position-independent, so
one recogniser covers x86-64/AArch64 and ELF/PE/Mach-O.

**Validated.** `recover_types.py --selftest` (CI via `tests/test_selftests.py`) pins the recogniser
on a synthetic buffer: one real vtable plus decoys (a bad alignment, a size not a multiple of align,
a run of plain pointers) are correctly accepted/rejected, a zero-sized (ZST) vtable is handled, and a
Ghidra struct is emitted per method-count. `tests/test_types.py` runs it end to end on the committed
`benign_rust_std.x64`: it recovers 9 structurally-sound vtables (every drop/method pointer in code,
every size a multiple of a power-of-two align) where the un-whitelisted scan had produced 150+ false
ones — the precision regression guard. `ghidra_annotate.py` lays each `RustVtable_<n>m` struct on its
vtable address, comments it, and renames the method functions behind the trait (`tests/
test_ghidra_annotate.py`, stubbed Ghidra API). Enum-discriminant and Option/Result niche-layout
recovery from `match` jump tables is the next tier.

## 51. Round 11: reversing optimizations before structuring (premium) (Oct 2026)

Oxidizer (IEEE S&P 2026) calls "revert optimizations before structuring" decompilation's #1 open
problem. `premium/opt_reverse.py` is a reusable pass for the two optimizations that most garble
recovered control flow, both mechanical to undo:

* **Un-switch jump tables.** A `match`/`switch` lowers to an indirect jump through an offset table;
  the case→target structure is implicit. `recover_jump_tables()` matches the LLVM rel32 idiom
  (`lea B,[rip+d]; movsxd R,[B+idx*4]; add R,B; jmp R`), takes the arm count from the preceding
  `cmp idx, K` bound, and reads the table back to an explicit `{index: target}` map. The bound is
  **required**: without it the table length is unknown and reading until an entry leaves `.text`
  over-reads into adjacent code-pointing data (observed as 700-case phantom tables), so a bounded
  exact recovery is kept over a guessed one — precision over recall, as everywhere in this project.
  x86-64 and 32-bit x86; AArch64 (adr/ldrsw/add/br) is the next tier. Reusable by the deflattener's
  relooper and the VM devirtualizer (both dispatch through jump tables) and by any downstream
  decompiler.
* **Detect unrolled loops.** `-O2` unrolls a small loop into N identical body copies. `detect_unrolled
  _loops()` finds the repeated-body run by instruction-mnemonic shape plus a constant stride (so it
  is not fooled by the immediates the copies differ in) and reports the stride/count a re-roller
  needs. Detection only; lifting the copies back to one loop body is the next tier.

**Validated.** `opt_reverse.py --selftest` recovers a hand-assembled 3-case rel32 switch to its exact
`{index: target}` map, rejects a plain instruction stream, and detects a 4×-unrolled body with the
right stride/count. `tests/test_opt_reverse.py` also compiles a real dense `match` with rustc (skips
without it) and checks the 8-arm switch is recovered to eight bounded cases whose targets all land in
`.text`, and pins the sub-register canonicalisation (`cmp edi` bounds an index `rdi`). On a real
optimized Rust binary it recovers 52 bounded jump tables, no phantom over-reads.

## 52. Round 12: crypto-primitive identification (Oct 2026)

Malware that encrypts its config/C2/payload embeds the cipher's constants, and those constants are
universal -- identical bytes in every implementation, any language or compiler. `scripts/recover_
crypto.py` recognises them to name the algorithm in a stripped binary: the Rijndael S-boxes, the
ChaCha/Salsa `expand 32-byte k` sigma and the Base64 alphabet as exact byte sequences; SHA-1/256/512,
MD5, CRC32 and BLAKE2b by their round/init constant sets (scanned as little-endian words, flagged
only above a per-algorithm threshold so a stray constant is not a hit). Language-agnostic, so it
covers hand-rolled crypto, a C crypto lib linked via FFI, or a Go binary -- complementing the
Rust-specific `recover_cryptify`/`muddy` which already name and key those two crates.

**Validated.** `--selftest` identifies AES/ChaCha/SHA-256/MD5/CRC32/Base64 from constants salted into
random noise, confirms random noise stays clean, and that a below-threshold constant set is not
flagged. `tests/test_crypto.py` pins `scan()` and, where a system crypto library is present, detects
a real binary's primitives (libcrypto -> AES + SHA; git -> SHA-1/256 + MD5; thin wrappers like the
`openssl` CLI correctly empty, since they dlopen libcrypto). Key/IV extraction ties into the existing
decoder-recovery tiers and is not attempted here.

## 53. Round 13: resolved call graph + code-coverage metric (Oct 2026)

The headline numbers are about strings; this measures and raises *code* coverage. `scripts/
recover_cfg.py` builds the call graph and resolves the indirect control flow that normally leaves it
full of holes: direct calls become internal/import edges; a function whose address is loaded
(`lea reg,[rip+fn]`, a relocation, a vtable slot) is treated as a root -- `main` is reached this way
(the start glue hands its address to `__libc_start_main`), and so are callbacks and vtable methods,
which a naive reachable-from-entry sweep drops; and `dyn Trait` dispatch (`call [vtable+off]`) is
resolved via recover_types' vtables to the methods behind the trait. It then reports functions
reachable from the realistic root set, imports used, unresolved indirect sites, and the **lift** over
an entry-only direct sweep.

**Validated.** On the committed `benign_rust_std.x64`: 524 functions, 501 direct + 51 dynamic-
dispatch edges from 9 vtables, 286 import call sites resolved, **98.5% reachable** from 308 roots --
a **+515-function lift** over the entry-only baseline (which reaches 1, because the entry's real work
goes through `__libc_start_main` indirectly). `tests/test_cfg.py` pins this and, with rustc, builds a
`dyn Trait` program and checks the dispatch edges and the coverage lift; `--selftest` pins the BFS /
lift / dispatch-reach accounting. x86-64 and 32-bit x86 (direct + rip-relative address-taken +
dispatch); AArch64 resolves direct `bl` edges, adrp/add address-taken is the next tier.
