# CLAUDE.md — rust-deobf

Guidance for an agent working in this repo. **Read this instead of re-exploring the tree.**
It is the architecture map, the conventions, and the per-session gotchas. Keep it current when
you add a tier or change a convention. If something here is wrong, fix it in the same change.

rust-deobf is a **defensive** static/dynamic analysis toolkit: it *recovers* information from
compiled (mostly Rust) binaries — strings, crates, types, control flow, behavior — to undo
obfuscation. All inputs are benign test fixtures. **Never** add live malware indicators, real C2
strings, or offensive-API catalogs; use RFC 5737 doc IPs (`192.0.2.0/24`) and `.invalid`/`.example`
hosts in fixtures and tests (the safety classifier *has* flagged C2-flavored strings and verbose
injection-API regexes here — keep detection tables compact and neutral).

## Save tokens: cheap-test-first workflow

Running the full suite costs ~3.5 min / 234 tests and a lot of output tokens. Don't do it on every
edit. Instead:

| When | Command | Cost |
|------|---------|------|
| After editing any `scripts/*.py` | `./scripts/check.sh` (selftests + doc-drift guard) | **~8s, 26 tests** |
| Just one module | `python3 scripts/<name>.py --selftest` (prints `selftest OK`) | <1s |
| One module's full test | `python3 -m pytest tests/test_<name>.py -q` | seconds |
| Before committing/pushing | the fast CI subset (below) | ~3.5 min |
| Never locally | `benchmark`/`precision` jobs (need a Rust build) | CI only |

`scripts/check.sh` wraps these: `./scripts/check.sh` = the 8s gate; `./scripts/check.sh changed` =
only the scripts you touched vs `origin/master` (narrow-first); `./scripts/check.sh full` = the fast
CI subset; `./scripts/check.sh <name>` = that module's selftest + test file(s) (found via an explicit
module→test map, `scripts/` or `premium/`). Exit codes: 0 pass, 1 a selftest/test failed, 2 usage
error (unknown module, missing base ref for `changed`). `CHECK_DRY_RUN=1` prints the commands only.

**Narrow before broad** — run the cheapest thing that can fail first, widen only if it passes:
`./scripts/check.sh <name>` → `./scripts/check.sh changed` → `./scripts/check.sh` → `full`. Within
pytest: `-k <expr>` to pick tests by name, `-x` to stop at the first failure, `--lf` to rerun only
last-failed, `--tb=line` to keep tracebacks (and token cost) short. Don't cat a whole test log;
`... -q | tail -20`.

### Keep this map and the gate current (enforced, not optional)
`tests/test_docs_current.py` runs in the 8s gate and **fails** if a script with a `--selftest`, or any
`premium/` module, is missing from this file, or if `check.sh full` and the CI selftest job disagree
on the ignore list. So when you add or rename a tool, or change the CI test split, update the table
below / `check.sh` in the same change — the gate will tell you if you forget.

### Delegate to sub-agents to keep the main context small
A fresh sub-agent's tool output (file dumps, long test logs) stays in *its* context; only its
conclusion returns to yours. Worth it for: a broad "which module/where is X" sweep across many files
(use the `Explore` agent), independent work that can run in parallel (e.g. fuzzing or selftesting
several modules at once — send them in one message), and an unanchored review. Not worth it for a
lookup this file already answers, or a couple of tool calls you'd do inline — a fresh agent re-reads
context and costs more than it looks. Brief it with the goal + the exact files/entry points (from the
tables below) so it doesn't re-explore. Don't delegate and also do the work yourself.

The fast CI subset (what the `selftest` job in `.github/workflows/ci.yml` runs — no Rust build):
```
python3 -m pytest tests -q -rs \
  --ignore=tests/test_benchmark.py --ignore=tests/test_scatter.py \
  --ignore=tests/test_obf.py --ignore=tests/test_libfuncs.py \
  --ignore=tests/test_32bit.py --ignore=tests/test_formats.py
```
Prefer targeted runs; read a test file before running the whole suite to confirm it's relevant.

## Architecture

Two layers. A **language-agnostic engine** (emulation, dataflow, CFG, crypto/MBA/apihash, VM) plus
**Rust-specific tiers** on top (metadata, demangling, types/vtables, crate idioms). `scripts/` is the
Apache-licensed core; `premium/` is AGPL/commercial Tier-4 deobfuscation.

### Conventions (how everything is wired)
- Each analysis script is **standalone**, importable, and has a `--selftest` that needs no binary.
- **`--json` output contract:** every script with a `recover()`/`analyze()` entry point takes
  `--json` and prints the result dict as JSON (multi-target harnesses print a JSON list, or the lone
  dict for a single target), suppressing the human-readable output. Prefer `script --json <bin>` over
  the prose form when an agent or the MCP server consumes the result — verbose stdout is a quiet
  per-run token sink. Enforced by `tests/test_docs_current.py` (exceptions justified in
  `_NO_JSON_OK`: `fuzz_recover`, `redblue_loop`, `mcp_server`, `dump_unpacked`).
- `tests/test_selftests.py` auto-runs `--selftest` for **every `scripts/*.py`** (NOT `premium/`).
  A new `scripts/` tool with a `--selftest` is picked up automatically — no test wiring needed.
- **`premium/` scripts are not auto-tested** — each needs its own `tests/test_*.py`.
- Public entry point is usually `recover(path)` or `analyze(path)` returning a dict; `main()` is the
  CLI. Import shared primitives from `recover_emulate` (`Image`, text bounds) rather than reparsing.
- Fixtures live in `tests/fixtures/` (committed, benign). Don't add large binaries.

### scripts/ — engine (language-agnostic)
| Script | Role |
|--------|------|
| `recover_emulate.py` | Unicorn emulation (x86-64 + AArch64); shared `Image`/section primitives. **Core.** |
| `recover_callsite.py` / `recover_arm64.py` | call-site dataflow string recovery (x64 / ARM64) |
| `recover_stackstrings.py` | stack-constructed strings (x64 + ARM64) |
| `recover_apihash.py` | resolve hash-obfuscated API imports (Tier 2) |
| `recover_imports.py` | PE import reconstruction: IAT map + bind indirect call sites to API names; flag runtime resolution (post-unpack) |
| `recover_crypto.py` | identify crypto primitives by their constants |
| `recover_cfg.py` | resolved call graph + code-coverage metric (`_import_sites`/`_indirect`); x86/x86-64/AArch64, PLT/`.plt.sec`/IAT stubs + tail calls resolved, recursive-descent start seeding when metadata has none (stripped PE32) |
| `recover_behavior.py` | per-function behavior/capability map from imports |
| `recover_lang.py` | per-function source-language map (mixed-language binaries) |
| `detect_vm.py` | flag functions hidden behind a bytecode VM |
| `recover_dynamic.py` / `recover_artifacts.py` | Frida runtime memory-diff recovery |
| `dump_unpacked.py` | Tier 2: dump the stage-2 a runtime packer reveals (dynamic, runs the sample): EXEC flips, the main module's in-memory image at exit (+ a file-layout `.fixed.exe`), MZ sweeps; sample stdio piped away |
| `unpack_emulate.py` | Tier 2: static unpacking — emulate the stub (x86-64/x86/AArch64, ELF incl. section-less, PE with headers + import stubs), report the OEP, carve stage-2, and the import table the stub rebuilt + stage-2 call sites bound to it (no host execution; `--entry`, `--follow`) |
| `emu_backend.py` | emulator-backend helpers: `fast_hook_add(uc, ...)` = drop-in for `uc.hook_add` (block/code/mem-access/invalid-mem/intr/x86 `syscall`) with one Python frame per event instead of three; same exception/`hook_del`/return semantics; `release(uc)` cuts the hooks' references so a discarded emulator is freed by refcount (no `gc.collect()`). icicle-emu evaluated and deliberately not wired in (no Python hooks; see `bench_emu.py`) |
| `unpack.py` | Tier 2: one unpacking command — static (unpack_emulate) first + PE-stage carve; dynamic (dump_unpacked/Frida) only as opt-in fallback behind `--i-understand-this-executes`. Nothing runs a sample by default. |

### scripts/ — Rust & Go tiers
| Script | Role |
|--------|------|
| `recover_rust_meta.py` | Tier 3: static Rust-specific structure recovery |
| `recover_rust_strings.py` | split Rust's concatenated `&str` literals back apart |
| `recover_libfuncs.py` | identify Rust stdlib / crate functions (FLIRT-style); `--db auto` = the per-binary DB below if cached, else the bundled one (reports toolchain match). Signatures are used only for the binary's own rustc (same minor) — never pooled across known toolchains; the bundled prebuilt-std layer (`data/libfunc_sigs_std.json.gz`, rustc 1.97 x86_64-elf/aarch64-elf/x86_64-pe, regenerate with `gen_sigdb.py --bundle-std`) is per arch+format. Stripped PE32: starts from the raw `.eh_frame` FDEs |
| `gen_sigdb.py` | per-binary signature DB: the binary's rustc + target + crates@versions (panic paths, cargo-auditable, symbol roots, `.comment`) → (rustup only with `--allow-download`) resolve a throwaway project (`cargo metadata`), sign prebuilt std rlib objects (relocations masked; + whole-function patterns ≤1 KiB that recover_libfuncs uses to split shared prefixes) + a linked std exerciser, and — only with `--build-crates` (runs crates' build scripts: analysis VM only) — the crate rlibs per feature set; `--profile auto` picks release/LTO from how many always-linked std functions match the prebuilt std; cached `~/.cache/rust-deobf/sigdb/<rustc>-<triple>-<cratehash>.json` (`unknown-<sha256>` when the rustc is unknown). `--db auto` never builds |
| `recover_types.py` | Rust type-layout facts + C++ vtable/RTTI → decompiler |
| `recover_cryptify.py` | static recovery for the `cryptify` crate (`encrypt_string!`) |
| `recover_go.py` | Go function names from the pclntab (Go's metadata analog) |
| `recover_antianalysis.py` | anti-analysis technique inventory + build provenance |
| `recover_enums.py` | enum discriminant/niche layout; variant names via DWARF (pyelftools, optional) else a capstone dispatch-site heuristic (x86-64 + ARM64) |
| `recover_embedded.py` | embedded artifacts: nested exes/archives (magic; LZ4/aPLib/BriefLZ containers header-validated), high-entropy blobs, base64 payloads (file offsets) |
| `decompress.py` | strict pure-Python LZ4 (frame/legacy/block), aPLib (raw/AP32), BriefLZ (raw/blzpack), LZNT1 decoders: output-capped, linear, never raise; headerless decodes need an encoder signature (no literal runs/zero literals a compressor never emits), full consumption, expansion (waived for magic / >= 64 B text) and "interesting" output (validated magic / text / literal-entropy drop / repetitive). Test encoders in `tests/_compress.py`; reference vectors (jibsen BriefLZ, apultra, lz4_flex) in `tests/fixtures/compress/` |
| `recover_async.py` | async state machines (`async fn`/blocks): anchored on the "resumed after completion/panicking" panics; a concrete dispatch interpreter (jump tables + compare chains, no premium import) maps state → target, a pointer/const dataflow locates the state field (self / stack / register) and its pending write-backs; suspend points → inner poll (direct / `dyn` slot / inlined) nesting graph, source `Location`, vtable size, runtime crate. x86-64 + AArch64, ELF + PE |
| `recover_async.py` | async state machines (`async fn`/blocks): anchored on the "resumed after completion/panicking" panics; a concrete dispatch interpreter (jump tables + compare chains, no premium import) maps state → target, a pointer/const dataflow locates the state field (self / stack / register) and its pending write-backs; suspend points → inner poll (direct / `dyn` slot / inlined) nesting graph, source `Location`, vtable size, runtime crate. x86-64 + AArch64 + i386, ELF + PE |
| `recover_async.py` | async state machines (`async fn`/blocks): anchored on the "resumed after completion/panicking" panics; a concrete dispatch interpreter (jump tables + compare chains, no premium import) maps state → target, a pointer/const dataflow locates the state field (self / stack / register) and its pending write-backs; suspend points → inner poll (direct / `dyn` slot / inlined) nesting graph, source `Location`, vtable size, runtime crate. x86-64 + AArch64 + i386, ELF + PE + Mach-O; rustc 1.70 (inline `panic("...")`) to 1.97 (panic_const) |
| `recover_idioms.py` | Rust idioms in stripped binaries: fmt macro sites → `println!("…")` text (newer rustc template encoding (1.97 measured) + older pieces array), panic / safety-check call sites (kind, `Location` file:line:col, guarding branch), drop / `__rust_dealloc` calls, enum-like (Option/Result?) returns; helpers named by symbols / libfuncs / message anchors; per-function register+stack dataflow (x86-64 SysV/Win64, i386, AArch64); `--eval <unstripped> <stripped>` measures P/R; → `ghidra_annotate.py` (`idioms`) |
| `recover_idioms.py` | Rust idioms in stripped binaries: fmt macro sites → `println!("…")` text (newer rustc template encoding (1.97 measured) + older pieces array) with each placeholder's trait (`{:?}` `{:x}` …) from its formatter fn (symbol, else debug-builder / radix / quote / debug-hex-flag anchors), `write!(f, "lit")` lowered to a `dyn fmt::Write` vtable `write_str`, panic / safety-check call sites (kind, `Location` file:line:col, guarding branch), drop / `__rust_dealloc` calls, enum-like (Option/Result?) returns; helpers named by symbols / libfuncs / message anchors; per-function register+stack dataflow (x86-64 SysV/Win64, i386 incl. stdcall callee-pops and PE32 start seeding, AArch64); `--eval <unstripped> <stripped>` measures P/R; → `ghidra_annotate.py` (`idioms`) |
| `recover_embedded.py` | embedded artifacts: nested exes/archives (magic), high-entropy blobs, base64 payloads (file offsets) |
| `gen_runtime_sigs.py` / `gen_rust_versions.py` | generate C-runtime sigs / rustc→release table |

### scripts/ — front ends, export, orchestration
`recover.py` (unified string front end) · `soc_triage.py` / `llm_triage.py` (triage cards) ·
`floss_export.py` / `export_rules.py` (FLOSS / capa+YARA output) · `mcp_server.py` (MCP over stdio;
also `annotations` / `push_annotations`) · `decompiler_bridge.py` (facts → neutral annotation list
`{address, kind: comment|rename|bookmark, scope, text, source_tier, function}`, pushed into a running
GhidraMCP 2.x/1.x or ida-pro-mcp over its loopback HTTP API; mapping verified on function starts,
sha256 identity check; existing comments read back and only `[rust-deobf]` lines rewritten:
GhidraMCP EOL by default, IDA via ida-pro-mcp's `py_eval`; tests use `tests/decompiler_mocks.py`,
which cites the plugin source each stand-in follows) · `decompiler_selfcheck.py` (run on the VM
against a REAL GhidraMCP / ida-pro-mcp: mapping on N function starts, identity, `--write-test`
comment write/read-back/restore; PASS/FAIL report) ·
`ghidra_annotate.py` + `ghidra_run.sh` / `ghidra_dump_annotations.py` (Ghidra) ·
`floss_export.py` / `export_rules.py` (FLOSS / capa+YARA output) · `mcp_server.py` (MCP over stdio) ·
`ghidra_annotate.py` + `ghidra_run.sh` / `ghidra_dump_annotations.py` (Ghidra; also lays out
recover_types vtables and recover_idioms comments/bookmarks/renames, Ghidra-free planning in
`_idiom_plan`, stub-tested) ·
`redblue_loop.py` (RustCloak hide ↔ rust-deobf recover regression; exit 3 = no round was
evaluable, e.g. every build failed or the plugin hid nothing) · `fuzz_recover.py` (fuzz our own
analysis path on malformed binaries; findings grouped by root cause, seed always printed) · `recover_blobs.py` (triage pipeline: carve blobs via
recover_embedded → keyless recovery = decompression (zlib family + `decompress.py`) + magic-anchored
single-byte-XOR (incl. XOR hiding a gzip/zlib/bz2/container stream), chained through up to 3
compressed layers on one MAX_OUT budget (+ containers nested in an output); also at exact starts:
container magics, the PE/ELF overlay, and a bounded second-pass search for headerless streams
(EOF tail, ends of zero padding, around >= 6.0-bit regions; <= 8192 starts/file) → annotate with
recover_crypto's candidate primitives; honest that encrypted blobs need a key).
Eval/measurement only (not analysis): `evaluate_all.py`, `eval_scatter.py`, `heldout_eval.py`,
`measure_fp.py`, `measure_rust_meta.py`, `run_floss.py`, `parse_gallery.py`, `disasm.py`,
`bench_emu.py` (emulation-engine benchmark: Unicorn vs optional icicle-emu, and Unicorn hook layouts, on
equal checked work — `--workload loop|hooks|unpack|setup|funcs`, `--json`; re-run it before any engine decision).

### premium/ — Tier 4 deobfuscation (AGPL/commercial; each needs its own test)
`deobf_cff.py` (detect control-flow flattening) · `deobf_deflatten.py` (recover flattened CF) ·
`deobf_expr.py` (provable MBA/expression simplification) · `deobf_opaque.py` (opaque predicates) ·
`devirt_emulate.py` (recover a VM's ISA by emulating its interpreter) · `lift_vm.py` (lift VM
bytecode to a listing) · `opt_reverse.py` (reverse compiler optimizations: un-switch jump tables,
unrolled loops; x86 + AArch64).

## Toolchain available in this environment
rustc 1.97 stable + nightly-2024-06-15 (LLVM 18.1.7); targets incl. `aarch64-unknown-linux-musl`;
clang/clang++/g++/cmake/llvm-18-dev; go1.24.7. libRustCloak.so built at
`/home/user/rustcloak/build/`. Python deps: lief≥0.16, capstone≥5&lt;6, unicorn≥2.1&lt;3, z3-solver,
pyelftools (optional; DWARF enum/niche names in recover_enums.py), pytest.

## Test matrix (measured — say which targets you ran, never assume an untested one)
The maintainer's lab (see the project's `dual-vm-ai-agent/CLAUDE.md`): **ARM64 Kali** (native ELF /
AArch64; has upx, mingw-w64, rustc with i686/aarch64/windows-gnu targets), **Windows 11 ARM64** VM
(x64 Python runs there under emulation = the x64-Windows target), and x86-64 Linux (cloud / CI).
- **Windows ARM64 *native* Python cannot run this toolkit today**: no win_arm64 wheels for
  `unicorn` (any version) or `capstone<6` (only 6.0 alphas), and no MSVC ARM64 to build them. Use
  x64 Python on Windows-on-ARM.
- Host-built tests follow the host arch: on ARM64 Kali `rustc` emits AArch64 (LLVM tables a match
  only from ~20 arms there, not 8; every import goes through a `.plt` stub).
- Windows: no `/tmp` (use `tempfile`), no `resource` module, no `fork`/`forkserver` (fall back to
  `spawn`), and an open `NamedTemporaryFile` cannot be reopened.
- `tests/test_dump_unpacked_dynamic.py` EXECUTES the benign UPX fixture: opt-in only
  (`RUST_DEOBF_DYNAMIC=1`, frida, Windows), run it on the Windows VM.

## Gotchas (each cost a debugging round once — don't repeat them)
- **PE addresses are RVAs** everywhere in this toolkit (LIEF section VAs, function starts, results);
  LIEF's `binary.entrypoint` for a PE is an absolute VA — subtract `optional_header.imagebase`.
- **ELF mapping symbols** (`$x`/`$d` on AArch64, `$a`/`$t` on ARM) share each function's address:
  skip names starting with `$` when building an address → name map, or they hide the real name.
- **LIEF:** keep the parsed binary alive while iterating `.symbols` (iterating a temporary's
  symbols segfaults); a section/symbol name that is not valid UTF-8 comes back as `bytes`.
- **Unicorn reserves large VIRTUAL memory per instance**: don't run tests under `ulimit -v` (the
  process dies silently); bound real memory instead (the unpacker's write tracking is bit-mapped
  and page-capped).
- **`deobf_opaque` is sound within its model**: it lifts flags per flag at the operand width and
  abandons anything it does not model exactly; `tests/test_opaque_differential.py` checks every
  claim against Unicorn on random blocks (0 false claims is the bar — never relax it).
- **capstone is pinned `>=5,<6`** — the code uses `CS_ARCH_ARM64` (renamed in capstone 6). Don't bump.
- **Unicorn + multiprocessing:** use `forkserver`, not `fork`. Forking after the parent has
  instantiated Unicorn → "Could not allocate dynamic translator buffer".
- **AArch64 musl cross-link** fails with the system `cc`; link with
  `-C linker=rust-lld -C link-self-contained=yes` (see `tests/test_opt_reverse.py`).
- **`recover_emulate.py` has hard resource caps** (segment/map size, VA ceiling, fallback pages, BSS,
  constructor count/timeout) — the fuzzer found real OOM/hang bugs on crafted section sizes. Keep
  bounds when touching mapping or `prime_constructors`.
- **Safety classifier is sensitive here** — compact neutral keyword tables, doc IPs, `.invalid`/
  `.example` hosts. No C2-style strings, no offensive-API enumerations.
- **Decompiler addresses ≠ ours:** annotations are RVAs (PE) / file VAs (ELF, Mach-O); Ghidra rebases
  a PIE (commonly to 0x100000), IDA loads it at 0, both keep a PE at its imagebase; what IDA reports as
  imagebase for a non-PIE ELF is NOT verified here (no IDA in the lab). `decompiler_bridge.resolve_mapping`
  therefore probes the entry point / function starts (reported base, then "addresses as linked")
  instead of trusting a reported base — keep it that way.
  GhidraMCP 2.0 has no read path for PRE comments (only `/disassemble_function` returns comments,
  EOL ones) and no bookmark endpoint: EOL is the default and bookmarks become EOL lines.
  ida-pro-mcp reads comments/bookmark slots only through `py_eval` (exec with separate locals:
  send top-level statements only, data as one JSON string literal).
- **`fmt::Arguments` changed shape between rustc 1.91 and 1.97** (measured: 1.91 pieces, 1.97
  template): `{template: *const u8, args}` (a byte-coded template; `args` = `len << 1 | 1` for a
  plain `&'static str`) instead of `{pieces, fmt, args}` slices. `recover_idioms` decodes both; don't key new fmt code on a `pieces` array alone.
- **recover_libfuncs' short labels drop the last v0 segment** of non-generic symbols
  (`panic_bounds_check` → `core::panicking`); relabel from the match's `sym` (recover_idioms does
  via `_readable`). Its signature DB is rustc-1.97 x86-64 only — AArch64 / i386 / PE get no hits.
- **Emulation time is Python hooks, not the engine** (bench_emu.py): recover_emulate's run ~2% engine,
  unpack_emulate's UPX run ~4%. A faster engine (icicle-emu: 5-14x on hook-free loops) buys ~1%;
  cut hook cost instead (`emu_backend.fast_hook_add`, narrower hook ranges, page-protection write
  tracking). icicle 0.0.11 has no hooks in Python, wedges on self-modifying code (even host
  `mem_write` to a page it has translated raises `SelfModifyingCode`), costs 0.1-0.3 s per instance.
- **Unicorn write-protection tracking:** in a `UC_HOOK_MEM_WRITE_PROT` hook, unprotect the page and
  return **False**, then resume `emu_start` at the faulting PC. Returning True after unprotecting
  silently DROPS the faulting store on Unicorn 2.1 (one wrong byte per page).
- **Never key per-frame state by `id(dict)`** (recover_emulate.run's fault counter did, until the
  count moved onto the frame): CPython reuses a freed frame's address, so a new callee inherited an
  old one's fault count and results depended on allocation patterns (any unrelated change -- e.g.
  fewer hook frames -- moved them). `tests/test_emulate_determinism.py` guards it.
- **Emulation perf changes must keep outputs identical:** `tests/test_emu_equivalence.py` compares a
  `tests/emu_equiv.py` dump (525 functions' runs + explore, recover(), unpack on the pack fixtures)
  with `tests/fixtures/emu/equiv_golden.json.gz`; `python3 tests/emu_equiv.py compare A B` diffs
  two dumps. Regenerate the golden file only for an intended output change.
- **Emulation hot paths are inlined on purpose** (recover_emulate `_on_write` = `_Writes.add`'s
  one-page case, `_capture_args` = `_plausible`, `capture` = `written()`/byte reads; unpack_emulate
  `_on_block` = `_written`): change both copies together. Kept as they are, after measuring: `count=`
  (the deterministic instruction budget; ~15 ns/insn), the 64-run emulator refresh (~5%), and
  unpack_emulate's per-BYTE write bitmaps (page-protection tracking would lose the byte-level
  `self_patches`/region carving semantics).
- **Unicorn 2.1 PC writes from a hook:** only a single `uc_reg_write` of the PC makes Unicorn leave the
  current block; `uc_reg_write_batch` including the PC does not (runs silently diverge). Batch the
  other registers, write the PC alone, last.
- **VALIDATION.md** uses numbered round sections; append the next `§N` rather than editing old ones.

## Maintenance: a new rustc release does NOT mean a rewrite
Rust ships a stable release every 6 weeks, but that is a *release* cadence, not an *architecture*
change — most releases touch nothing this tool keys on. Do **not** update on a calendar. What is
stable across releases: symbol mangling v0, the two-layer design, the emulation/dataflow/CFG engine,
and binary-format parsing. What occasionally drifts (driven by LLVM upgrades, every few releases, not
every one): codegen *idioms* — jump-table shape, stack-string construction, inlining — which can cost
recall only in the pattern-based recoverers. The emulation path (`recover_emulate`) runs the code, so
it survives idiom drift and backs up the brittle pattern matchers.
- **Trust the weekly CI drift detector, act on a red signal.** The `benchmark` job runs on a weekly
  `schedule` (`cron: "17 4 * * 1"` in `ci.yml`), does `rustup update stable`, rebuilds the benchmark
  with *current* stable, and measures recall/precision. Green = nothing to do. Red = one engine
  likely lost recall; patch that engine and add a `§N` round to `VALIDATION.md`. You rarely touch
  emulation.
- **The only periodic *data* refresh** (not code): re-run `gen_rust_versions.py` to extend the rustc
  commit→release table `recover_rust_meta` uses for version attribution. It affects version *dating*,
  not recovery.

## Git
- **Author every commit as the maintainer:** `Ve (VAHPEM) <ve0912084386@gmail.com>` — set
  `git -c user.name="Ve (VAHPEM)" -c user.email=ve0912084386@gmail.com commit ...` (or `--author`
  plus the same committer). **Never** author a commit as Claude / `noreply@anthropic.com`; the agent
  is credited only through the `Co-Authored-By:` trailer at the end of the message.
- Commit on `master` (or a short-lived feature branch the maintainer asked for), not an
  auto-generated `claude/*` branch.
- **Don't push.** The maintainer pushes from his own machine. Never rewrite published history
  without being asked.
- Never commit secrets (`.env`, keys) or malware samples — gallery entries are hashes + results only.
</content>
</invoke>
