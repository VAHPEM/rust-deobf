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
