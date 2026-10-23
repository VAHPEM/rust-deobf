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

### Precision on real, unobfuscated binaries

`scripts/measure_fp.py --pipeline` (static + emulation, default 120 s budget): **0** false
positives on bash, tar, xz, git, curl and ripgrep 14.1.1. Small binaries are emulated completely
(bash: all 2343 functions — the old code stopped at 400); git and ripgrep are covered in
decoder-score order until the budget runs out (580/4473 and 365/8558 functions), which the output
reports.

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
  - *capture*: every store is tracked with its age; written bytes are read back before calls
    and on returns, extended through neighbouring written bytes and cut where writes of
    different ages meet (a short string written over a long one), and the (pointer, length)
    pairs the code passes on give the exact end of a Rust string.
  Reported: text-like strings (including indicator shapes) that are not in the file, not
  stitched from static pieces or printf templates, and not artefacts of a forced path.
- **Stack strings** (`recover_stackstrings.py`) and **Rust literals**
  (`recover_rust_strings.py`) — the plain strings, cut at their real (pointer, length)
  boundaries instead of `strings`' glued runs.
- **Dynamic recovery** (`recover_dynamic.py`, Frida) — runs the sample and diffs its memory.
  Cipher-agnostic, but only for code paths that execute. **Isolated analysis VM only.**

Every recovered string says where it came from, indicator shapes are tagged (`[url]`, `[ip]`,
`[domain]`, `[path]`, `[registry]`, `[mutex]`, `[email]`), and `--floss-json` writes a FLOSS
results document so the strings appear in `floss`/`floss --html` next to the static ones.

Beyond strings, the same engines drive config/C2 extraction, hash-obfuscated API-import
resolution, unpacked stage-2 carving, Rust crate+version & panic-site recovery, and
MBA / opaque-predicate / control-flow-flattening analysis — see `ARTIFACT_TIERS.md`.

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
python3 scripts/recover.py samples/ --jsonl triage.jsonl        # a whole directory

# runtime-only decoders, inside an isolated analysis VM ONLY (pip install frida frida-tools)
python3 scripts/recover_dynamic.py path/to/binary [-- arg1 arg2 ...]
```

Emulation runs by default and is bounded by `--time-budget` (120 s): functions are tried in
decoder-score order, and the output says how many were emulated (`functions=412/1671`) and
whether the budget ran out.

---

## Honest limitations

This is research code, not a finished product (details in `VALIDATION.md`):

- **Emulation is not execution.** Arguments are fake, so code that only decodes for specific
  inputs (a key from the network, a path that depends on the environment) can be missed; path
  exploration flips branches one at a time inside the function it starts from, within budgets
  (8 runs per function, instruction budgets per run and per callee).
- **Large binaries need a larger time budget**: emulation is in Python-hooked Unicorn
  (≈10–40 s for a small Rust binary); with the default 120 s budget a large binary is covered in
  decoder-score order, not completely. The output reports the coverage.
- **Static recovery is idiom-bound** by design; it covers the release idioms of the benchmark
  crates. Under `size-lto` most keyed decoders are recovered by emulation, not statically.
- **musl runtime signatures** describe the musl that current rustc bundles; another version may
  need `gen_runtime_sigs.py` re-run on an unstripped build.
- **Custom-key cryptify** and anything keyed from the environment at run time needs dynamic
  recovery with that environment.
- **Benign corpus only**: the benchmark is synthetic. It now covers the shapes and profiles the
  review asked for, but real malware will find shapes it does not — please report them.

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
