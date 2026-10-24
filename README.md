# rust-deobf

**Recover obfuscated strings from Rust binaries** — static, emulation and dynamic recovery, on
**x86-64 and ARM64**, ELF and PE, with a reproducible benchmark against Mandiant FLOSS.

Rust malware is rising and the string-deobfuscation tooling for it is effectively absent.
`strings` only ever sees plaintext, and FLOSS — the standard open-source string deobfuscator —
recovers nothing from the common Rust obfuscation crates. This project closes that gap and
publishes the benchmark that measures it, including the cases where it does *not* work.

> Defensive reverse-engineering research for malware triage. All test inputs are **benign**
> programs built from author-written sources (`bench_src/`) — no payloads, no real malware, no
> live indicators.

---

## What changed in this version (Oct 2026): generalisation

An external review reproduced the published numbers exactly (107/107 tests, all 144 binaries
rebuilt with rustc 1.97) and found no cheating — canaries are used only for scoring — but showed
the tool was **overfitted to the benchmark's shape**: five strings printed from `main()`, one
build profile. On held-out programs written the way real code is written, it fell apart:

| reviewer's held-out finding | before | now |
|---|:-:|:-:|
| litcrypt2, malware-style build (fat LTO, `opt-level="z"`, `panic=abort`), ELF and PE | **0/8** | **8/8** |
| litcrypt2, benchmark profile (`opt-level=3`) | 5/8 (decoded 8, text filter dropped 3) | **8/8** |
| mutex name `Global\…` rejected by the "looks like text" filter | dropped | kept, tagged `[mutex]` |
| IOC with a prefix (`heldout::10.13.37.42:8443`) rejected | dropped | kept, tagged `[ip]` |
| obfstr, strings not printed (`.to_string()`, comparisons) | 0–2 full, rest truncated | **8/8** |
| emulation capped at 400 functions (bash: 400/1671) | capped | no cap; ordered by decoder score, bounded by time |

The review's diagnosis was right, so the fix is not a list of new patterns. The emulator was
rebuilt into the general engine (details below), and the benchmark gained the shapes and build
profiles that exposed the problem, so it cannot silently overfit again:

- **scatter suite** (`bench_src/scatter_*`): 8 indicator-shaped strings — IP:port, Windows path,
  mutex, URL, user agent, argv flag, hive-less registry key, prefixed identifier — in a struct,
  `match` arms, comparisons that are never printed, and a branch that never runs.
- **build profiles**: every program is also built `size-lto` (`opt-level="z"`, fat LTO,
  `codegen-units=1`, `panic=abort`) and `speed-lto` (`opt-level=3`, same LTO settings).

`tests/test_scatter.py` holds recall **and precision** on all of it in CI (one job per
format).

### Second round: what the first round still overfitted

Re-evaluating the result the same way turned up three more problems
([VALIDATION.md §11](VALIDATION.md)):

| finding | before | now |
|---|:-:|:-:|
| build profiles nobody tuned for (3 sets, 256 binaries) | 98–99 % exact, +18 junk | **1360/1360**, 0 junk (see below for what that number means) |
| real binaries outside the development set: Xvfb (C) / age (Go) | 68 / 17 false positives | **1 / 2**; 29 on a 21-binary corpus |
| cargo, gdb, cmake | killed at 5.5–6 GB of memory | run: gdb 0.5 GB, cargo (19 MB `.text`) ≈1.1 GB per process |
| gdb's 15,760 functions in the 120 s budget | 136 emulated | ≈2,000 (2 CPUs) |

A CI job now measures false positives on a C/C++, Go and Rust corpus found on the runner.

---

## Results

### Held-out shapes × malware build profiles (scatter suite, stripped)

`python scripts/eval_scatter.py` — the default `recover.py` pipeline, exact matches out of 8;
`(+n)` = extra strings reported (false positives). `plaintext` is the same program with plain
literals: everything it reports is a false positive.

| scatter program | ELF x86-64<br>release | ELF x86-64<br>size-lto | ELF x86-64<br>speed-lto | PE x86-64<br>release | PE x86-64<br>size-lto | PE x86-64<br>speed-lto | ELF AArch64<br>release | ELF AArch64<br>size-lto | ELF AArch64<br>speed-lto |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| `xor_custom` | **8/8** | **8/8** | **8/8** | **8/8** | **8/8** | **8/8** | **8/8** | **8/8** | **8/8** |
| `litcrypt` | **8/8** | **8/8** | **8/8** | **8/8** | **8/8** | **8/8** | **8/8** | **8/8** | **8/8** |
| `litcrypt2` | **8/8** | **8/8** | **8/8** | **8/8** | **8/8** | **8/8** | **8/8** | **8/8** | **8/8** |
| `obfstr` | **8/8** | **8/8** | **8/8** | **8/8** | **8/8** | **8/8** | **8/8** | **8/8** | **8/8** |
| `cryptify` | **8/8** | **8/8** | **8/8** | **8/8** | **8/8** | **8/8** | **8/8** | **8/8** | **8/8** |
| `plaintext` | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** |

**360/360** exact strings and **0** extra across all 54 binaries (stripped builds); the code the
review tested got **79/360**. Every cell is a test in `tests/test_scatter.py`.

### Canary benchmark (one program per crate, five printed strings)

| obfuscator | cipher | `strings` | FLOSS | **static** | **emulation** | **dynamic** |
|---|---|:--:|:--:|:--:|:--:|:--:|
| xor_custom | hand-rolled XOR | 0/5 | 0/5 | **5/5** | **5/5** | **5/5** |
| add_custom | hand-rolled ADD | 0/5 | 0/5 | **5/5** | **5/5** | **5/5** |
| sub_custom | hand-rolled SUB | 0/5 | 0/5 | **5/5** | **5/5** | **5/5** |
| litcrypt | XOR, runtime key | 0/5 | 0/5 | **5/5** | **5/5** | **5/5** |
| litcrypt2 | XOR, stride-permuted key | 0/5 | 0/5 | **5/5** | **5/5** | **5/5** |
| obfstr | XOR+ADD, inlined | 0/5 | 0/5 | — | **5/5** | **5/5** |
| tight strings | stack buffer XORed in place | 0/5 | 0/5 | — | **5/5** | **5/5** |
| cryptify (default key) | XOR, crate-default key | 0/5 | 0/5 | **5/5** | **5/5** | **5/5** |
| cryptify (custom key) | key only in the build/run environment | 0/5 | 0/5 | —¹ | —¹ | **5/5**¹ |
| muddy | ChaCha20-Poly1305 (AEAD) | 0/5 | 0/5 | — | **5/5** (new) | **5/5** |

Release builds, ELF and PE x86-64 and AArch64, stripped and not; `size-lto`/`speed-lto` builds
of every crate are tested too. Static = reads the decoder's key and the call sites without
running anything; emulation = Unicorn, never runs the sample natively; dynamic = Frida in an
isolated VM.

<sub>¹ cryptify reads `CRYPTIFY_KEY` again at run time: with a custom key the sample only
decrypts when run with that variable set, and the key is not in the binary. `recover_cryptify`
detects the crate and says so.</sub>

### Build profiles nobody tuned for

The benchmark's own programs rebuilt with release settings the benchmark never uses, stripped
(`CARGO_PROFILE_RELEASE_*` overrides). Exact strings; `+n` = junk strings reported.

| set | profiles | formats | first measured | now |
|---|---|---|:-:|:-:|
| 1 | `opt-level="s"` + thin LTO + 16 CGU + `panic=unwind`; `opt-level=1` | ELF, PE | 338/340 +7 | **340/340** +0 |
| 2 | `opt-level=2`, 1 CGU, no LTO; `opt-level="z"`, no LTO, `panic=unwind` | ELF, PE, ARM64 musl | 500/510 +3 | **510/510** +0 |
| 3 | `opt-level=3`, no LTO, 16 CGU, `panic=unwind`; `opt-level="s"`, fat LTO | ELF, PE, ARM64 glibc | 504/510 +8 | **510/510** +0 |

Each set was built after the fixes for the previous one, measured once ("first measured": the
honest held-out number, 98–99 % exact with a few junk strings), and then used to find and fix
its failures — so the "now" column is no longer held-out. The next independent review will say
how the current code does on what nobody has seen.

### Precision on real, unobfuscated binaries

`scripts/measure_fp.py --pipeline --corpus` (static + emulation, 120 s budget): every decoded
string reported is a false positive. The corpus mixes C/C++, Go and Rust binaries, because the six
binaries the filters were developed against (bash, tar, xz, git, curl, ripgrep: 0) overstated
precision — Xvfb and a Go binary had 68 and 17 before this round.

| binary | language | `.text` | functions emulated (120 s, 2 CPUs) | false positives |
|---|---|--:|--:|:-:|
| bash | C/C++ | 945 KB | 2343/2343 | **0** |
| tar | C/C++ | 292 KB | 607/607 | **0** |
| xz | C/C++ | 41 KB | 76/76 | **0** |
| git | C/C++ | 3,077 KB | 4473/4473 | **0** |
| curl | C/C++ | 107 KB | 121/121 | **0** |
| gdb | C/C++ | 5,693 KB | 2022/15760 (budget) | **0** |
| cmake | C/C++ | 9,318 KB | 4305/18830 (budget) | **1** |
| Xvfb | C/C++ | 1,435 KB | 5038/5038 | **1** |
| openssl | C/C++ | 415 KB | 535/535 | **0** |
| perl | C/C++ | 1,858 KB | 2240/2240 | **3** |
| python3.13 | C/C++ | 3,039 KB | 10767/11510 (budget) | **0** |
| vim | C/C++ | 3,110 KB | 5302/5302 | **7** |
| age | Go | 1,631 KB | 2353/2353 | **2** |
| gh | Go | 16,710 KB | 1718/13720 (budget) | **0** |
| docker | Go | 13,379 KB | 1498/35916 (budget) | **1** |
| go (toolchain) | Go | 6,351 KB | 2115/13835 (budget) | **2** |
| ripgrep (Debian) | Rust | 3,075 KB | 4947/8530 (budget) | **3** |
| rustfmt | Rust | 2,849 KB | 4545/4545 | **4** |
| cargo-fmt | Rust | 874 KB | 1280/1280 | **0** |
| cargo | Rust | 19,594 KB | 3528/43240 (budget) | **5** |
| rustdoc | Rust | 5,894 KB | 8531/8531 | **0** |

**29 false positives on 21 binaries** (C/C++ 12, Go 5, Rust 12); 11 have none. Not zero: what
is left is text the program assembles at run time from its own pieces in ways the filters do not
model (`File/Glob.pm`, `lib/rustlib/src/rust/`, a regex help line), symbol names with letters
inserted as well as changed (``PyGIL`EmSure``), and a few reshuffles. Each is reported as decoded,
so a result list on a non-obfuscated binary is not empty — but it is short, and the previous
code reported 68 on Xvfb alone. Coverage grows with CPUs and `--time-budget`, and so can noise.
The CI job on GitHub's runner (other versions of these programs) measured 32 on 20 binaries.

### Second machine, second toolchain

Everything was re-run outside the development container, on the two ARM64 VMs of
[dual-vm-ai-agent](https://github.com/VAHPEM/dual-vm-ai-agent):

- **Kali Linux, rustc 1.99.1** (current stable): both suites rebuilt for PE, AArch64 musl and a
  new target, **AArch64 glibc** (dynamically linked, the default Linux target), every profile.
  `pytest tests`: 232 passed, 0 failed (x86-64 ELF skipped on an AArch64 host).
- **Windows**: `recover.py` on the 18 stripped scatter PE files recovers **120/120** strings
  with 0 extra; FLOSS 3.2.0 on the same machine and files decodes **0**.
- Development container, rustc 1.97: 289 tests pass.

The glibc build needed two emulator fixes — libgcc's outlined atomics (`__aarch64_cas4_acq` &
co.) and a `write` import that must report success — see [VALIDATION.md §10b](VALIDATION.md).

### Third-party obfuscation crates

`bench_src/` is hand-rolled ciphers; `obf_src/` is author-written programs obfuscated with the
crates a real analyst meets. [**goldberg**](https://crates.io/crates/goldberg) applies code-flow
obfuscation plus string and integer encryption; `recover.py` recovers its encrypted strings
**6/6** across ELF, PE and AArch64, release and `size-lto` (`tests/test_obf.py`, a CI job). The
strings are IOC-shaped and chosen not to collide with crate or metadata tokens, so the number
measures recovery rather than a coincidence of the literal text. More crates are planned
(`rustfuscator`, `obfuse`), goldberg first.

### Ghidra integration

`scripts/ghidra_annotate.py` is a Ghidra post-script (PyGhidra) that reads `recover.py --json`
and, in the decompiler, gives every decoding function a plate comment listing its recovered
strings, a bookmark, and — only when the function still has a default `FUN_`/`SUB_` name — a
rename after the strongest indicator. Verified headless on the Kali VM (Ghidra 12.1.3): on the
goldberg AArch64 build, `main` gets a plate comment with both decoded strings
(`C:\ProgramData\Helios\agent-state.db`, `https://cdn.helios-sync.net/v2/push`) and a bookmark,
with real demangled names left untouched. IDA and Binary Ninja exporters are planned next.

### Real-malware reference

`gallery/manifest.json` (built by `scripts/parse_gallery.py` from
[rust-malware-gallery](https://github.com/decoderloop/rust-malware-gallery)) maps **126 sample
hashes across 67 Rust malware families** to family, aliases and writeups. It drives evaluation
and gives triage a hash → family attribution. **Hashes only** — samples are fetched from the
listed source and analysed in an isolated VM, never stored here.

---

## What it does

`recover.py` runs everything that applies and merges the results:

- **Static call-site recovery** (`recover_callsite.py` x86-64, `recover_arm64.py` AArch64,
  `recover_cryptify.py`) — finds the decode loop, resolves key and each call's ciphertext with
  ABI-aware dataflow, decodes. Fast (seconds), exact attribution (decoder, call site,
  ciphertext). Only as good as its idiom recognisers: it recognises the benchmark's release
  idioms, not every build profile — that is what emulation is for.
- **Emulation** (`recover_emulate.py`, Unicorn) — the general engine, x86-64 and AArch64, ELF and
  PE. It runs functions of the binary (never the binary itself) and collects the plaintext the
  code builds. What makes that work on real Rust code:
  - *real calls*: callees run up to 8 levels deep, so a call site runs its out-of-line decoder
    (`lc!` → `decrypt_bytes` → `Iterator::next`); each callee has an instruction budget and a
    callee that overruns it (a spinning lock, a loop over a fake length) or faults is abandoned
    and returns 0, with the caller's registers restored;
  - *a loader*: relocations applied (ELF `RELATIVE`/`GLOB_DAT`/`JUMP_SLOT`, PE base
    relocations), every import pointed at a named trampoline, `.bss` zeroed, thread-local
    storage (fs/gs/`TPIDR_EL0`) set up, AArch64 outlined atomics switched to their LSE path;
  - *a C runtime*: allocators (`malloc`, `HeapAlloc`, `__rust_alloc`, …) hand out separated
    zeroed blocks; `memcpy`/`memmove`/`memset`/`memcmp`/`bcmp`/`strlen`, `brk`/`mmap`, environment
    lookups and `GetLastError` behave; in stripped static (musl) builds the runtime functions are
    found by FLIRT-style byte signatures (`gen_runtime_sigs.py`);
  - *path exploration*: decoder-like functions are re-run with forward branches forced the
    other way, so strings built only in one `match` arm or on a branch that never runs are
    reached;
  - *scheduling*: a first pass runs every function once with a small budget (most decoders
    finish in a few thousand instructions), the second gives full budgets and explores; a run or
    callee still writing text when its budget ends gets more; allocator wrappers and import stubs
    run at any call depth; large binaries are split across processes;
  - *capture*: every store is tracked with its age; written bytes are read back before calls
    and on returns, extended through neighbouring written bytes and cut where writes of
    different ages meet (a short string written over a long one), and the (pointer, length)
    pairs the code passes on give the exact end of a Rust string.
  Reported: text-like strings (including indicator shapes) that are not in the file, not
  stitched from static pieces, printf templates or static text with numbers formatted in, and
  not artefacts of a forced path or of out-of-order stores.
- **Stack strings** (`recover_stackstrings.py`) and **Rust literals**
  (`recover_rust_strings.py`) — the plain strings, cut at their real (pointer, length)
  boundaries instead of `strings`' glued runs.
- **Dynamic recovery** (`recover_dynamic.py`, Frida) — runs the sample and diffs its memory.
  Cipher-agnostic, but only for code paths that execute. **Isolated analysis VM only.**

Every recovered string says where it came from, indicator shapes are tagged (`[url]`, `[ip]`,
`[domain]`, `[path]`, `[registry]`, `[mutex]`, `[email]`), and `--floss-json` writes a FLOSS
results document so the strings appear in `floss`/`floss --html` next to the static ones.

Beyond strings, the same engines drive config/C2 extraction, hash-obfuscated API-import
resolution, unpacked stage-2 carving, Rust crate+version & panic-site recovery,
**library-function identification** (name the std/crate functions in a stripped binary by
byte signature, so the decoders stand out), and MBA / opaque-predicate /
control-flow-flattening analysis — see `ARTIFACT_TIERS.md`.

Recovered strings and identified functions can be pushed straight into a decompiler:
`scripts/ghidra_run.sh <binary>` runs the recovery and annotates a Ghidra project headless
(plate comments + bookmarks on the decoding functions, `lib_<name>` renames on the library
functions). It is a PyGhidra script — Ghidra 11.3+ dropped Jython — and the wrapper handles
the PyGhidra launch for you.

## Quick start

```bash
git clone https://github.com/VAHPEM/rust-deobf.git
cd rust-deobf
python3 -m pip install -r requirements.txt          # lief, capstone, unicorn, z3-solver

python3 scripts/recover.py path/to/binary            # static + emulation (default), never runs it
python3 scripts/recover.py path/to/binary --json
python3 scripts/recover.py path/to/binary --floss-json out.json
python3 scripts/recover.py path/to/binary --emulate never       # static passes only, seconds
python3 scripts/recover.py path/to/binary --time-budget 600     # big binaries: emulate longer
python3 scripts/recover.py path/to/binary --max-ram 2G          # cap memory (fewer processes)
python3 scripts/recover.py path/to/binary --libfuncs            # also name Rust std/crate functions
python3 scripts/recover.py samples/ --jsonl triage.jsonl        # a whole directory

# name library functions in a stripped binary (needs a signature DB for its toolchain):
python3 scripts/recover_libfuncs.py --gen build/*release*nostrip   # build the DB once per toolchain
python3 scripts/recover_libfuncs.py path/to/binary                 # identify; --json for records
# push strings + library names into Ghidra (headless, PyGhidra):
scripts/ghidra_run.sh path/to/binary

# runtime-only decoders, inside an isolated analysis VM ONLY (pip install frida frida-tools)
python3 scripts/recover_dynamic.py path/to/binary [-- arg1 arg2 ...]
```

Emulation runs by default and is bounded by `--time-budget` (120 s): functions are tried in
decoder-score order, and the output says how many were emulated (`functions=412/1671`) and
whether the budget ran out. Memory is the other knob: a large binary is split across worker
processes (`RUST_DEOBF_WORKERS`, default `min(4, CPUs)`), each holding its own loaded image and
Unicorn instance — roughly 250 MB plus 45 MB per MB of `.text`, so ≈0.5 GB for gdb and ≈1.1 GB
for cargo. `--max-ram 2G` (or `RUST_DEOBF_MAX_RAM_MB`) caps the process count to fit that
budget, trading speed for memory; a budget below one process's footprint runs serially, slower,
and the output reports both the process count and the reduction.

---

## Honest limitations

This is research code, not a finished product (details in `VALIDATION.md`):

- **Emulation is not execution.** Arguments are fake, so code that only decodes for specific
  inputs (a key from the network, a path that depends on the environment) can be missed; path
  exploration flips branches one at a time inside the function it starts from, within budgets
  (8 runs per function, instruction budgets per run and per callee).
- **Large binaries are covered partly**: emulation runs Unicorn with Python hooks (≈30k
  instructions/s per process). A first pass runs every function once with a small budget, a
  second explores decoder-like functions, and binaries with 2,000+ functions are split over
  processes (`RUST_DEOBF_WORKERS`), but within 120 s gdb (15,760 functions) is still covered only
  in part (≈2,000 of its 15,760 functions on 2 CPUs). The output reports the coverage; give a
  larger `--time-budget`, or more CPUs, for more. `--max-ram` trades that speed back for memory
  on a small machine.
- **Static recovery is idiom-bound** by design; it covers the release idioms of the benchmark
  crates. Under `size-lto` most keyed decoders are recovered by emulation, not statically.
- **musl runtime signatures** describe the musl that current rustc bundles; another version may
  need `gen_runtime_sigs.py` re-run on an unstripped build.
- **Custom-key cryptify** and anything keyed from the environment at run time needs dynamic
  recovery with that environment.
- **Precision is good, not perfect**: 29 false positives on a 21-binary C/C++, Go and Rust
  corpus (see Results) — run-time assembled text the filters do not model.
- **Overlap rules are heuristics**: which of several overlapping views of a buffer is the string
  is decided from text, write ages and which function produced it, not from buffer addresses;
  fixing one profile's case has broken another before (VALIDATION.md §11). Recording the buffer
  each view came from is the planned fix.
- **Benign corpus only**: the benchmark is synthetic. It now covers the shapes and profiles the
  review asked for, but real malware will find shapes it does not — please report them. First
  runs on real binaries (a real Rust PE and a C/C++ negative control, static + emulation, never
  executed) are in VALIDATION.md §12: robust and correct on metadata, but string *deobfuscation*
  on real **obfuscated** Rust malware is still unvalidated (the real Rust sample to hand does not
  obfuscate its strings). `gallery/manifest.json` lists 67 Rust families by hash for that step.
- **Library-function identification** (`recover_libfuncs.py`) names std/crate functions by byte
  signature; the bundled DB is for one toolchain (rustc 1.97 x86-64) and must be regenerated
  (`--gen`) for another rustc or architecture, and generic-heavy labels flatten their type args.

Full matrix: `RESULTS.md` · reproducible metrics: `METRICS.md` · real-binary validation and the
generalisation work: `VALIDATION.md` (§10) · artifact tiers: `ARTIFACT_TIERS.md`.

---

## Running the benchmark & VMs

| task | environment | why |
|---|---|---|
| **Static / emulation recovery** | any host, no VM | reads the binary; emulation runs functions under Unicorn, never natively |
| **Building the benchmark** | any host with Rust (`rustup`) | cross-compiles, does not run samples |
| **Dynamic recovery** | **isolated analysis VM — required** | it *executes* the target |

```bash
python3 bench_src/gen_projects.py                 # (re)generate bench_src from the canaries
ARM64=1 bash scripts/build_all.sh                 # all crates x {ELF, PE, AArch64} x profiles
FORMATS=pe bash scripts/build_all.sh              # one format (CI runs one job per format)
ARM64_GNU=1 bash scripts/build_all.sh             # + AArch64 glibc (dynamic); cross linker
                                                  # aarch64-linux-gnu-gcc unless on AArch64
python3 -m pytest tests -q                        # recall and precision, canary + scatter
python3 scripts/eval_scatter.py                   # the scatter table above
python3 scripts/measure_fp.py --pipeline          # false positives on real binaries
```

`build_all.sh` profiles: `debug`, `release`, `size-lto`, `speed-lto` (canary suite) and
`release`, `size-lto`, `speed-lto` (scatter suite); `PROFILES=...` and `ONLY=...` narrow it,
`SKIP_EXISTING=1` keeps what is built. Rust targets: `x86_64-pc-windows-gnu` (with the
`mingw-w64` linker), `aarch64-unknown-linux-musl` (linked by the bundled `rust-lld`) and, with
`ARM64_GNU=1`, `aarch64-unknown-linux-gnu`. `BUILD_DIR=...` builds elsewhere and
`RUST_DEOBF_BUILD=...` points the tests at it, so two toolchains can be compared side by side.
FLOSS is only needed to reproduce the baseline column (`scripts/run_floss.py`).

Dynamic recovery must run inside a dedicated, isolated VM (Kali or Windows), never on your
host: snapshot before detonation, revert after.

---

## Scope / ethics

Defensive RE research only. All inputs are synthetic, benign binaries built from the sources in
`bench_src/` (see `bench_src/manifest.json` for every planted string); the tooling reads and
decodes binaries and produces no offensive capability. Run dynamic analysis only against
samples you are authorised to analyse, inside an isolated VM.
