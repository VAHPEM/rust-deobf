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
CI subset; `./scripts/check.sh <name>` = that module's selftest + test file.

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
| `recover_crypto.py` | identify crypto primitives by their constants |
| `recover_cfg.py` | resolved call graph + code-coverage metric (`_import_sites`/`_indirect`) |
| `recover_behavior.py` | per-function behavior/capability map from imports |
| `recover_lang.py` | per-function source-language map (mixed-language binaries) |
| `detect_vm.py` | flag functions hidden behind a bytecode VM |
| `recover_dynamic.py` / `recover_artifacts.py` | Frida runtime memory-diff recovery |
| `dump_unpacked.py` | Tier 2: dump the stage-2 a runtime packer reveals |

### scripts/ — Rust & Go tiers
| Script | Role |
|--------|------|
| `recover_rust_meta.py` | Tier 3: static Rust-specific structure recovery |
| `recover_rust_strings.py` | split Rust's concatenated `&str` literals back apart |
| `recover_libfuncs.py` | identify Rust stdlib / crate functions (FLIRT-style) |
| `recover_types.py` | Rust type-layout facts + C++ vtable/RTTI → decompiler |
| `recover_cryptify.py` | static recovery for the `cryptify` crate (`encrypt_string!`) |
| `recover_go.py` | Go function names from the pclntab (Go's metadata analog) |
| `recover_antianalysis.py` | anti-analysis technique inventory + build provenance |
| `gen_runtime_sigs.py` / `gen_rust_versions.py` | generate C-runtime sigs / rustc→release table |

### scripts/ — front ends, export, orchestration
`recover.py` (unified string front end) · `soc_triage.py` / `llm_triage.py` (triage cards) ·
`floss_export.py` / `export_rules.py` (FLOSS / capa+YARA output) · `mcp_server.py` (MCP over stdio) ·
`ghidra_annotate.py` + `ghidra_run.sh` / `ghidra_dump_annotations.py` (Ghidra) ·
`redblue_loop.py` (RustCloak hide ↔ rust-deobf recover regression) · `fuzz_recover.py` (fuzz our own
analysis path on malformed binaries).
Eval/measurement only (not analysis): `evaluate_all.py`, `eval_scatter.py`, `heldout_eval.py`,
`measure_fp.py`, `measure_rust_meta.py`, `run_floss.py`, `parse_gallery.py`, `disasm.py`.

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
pytest.

## Gotchas (each cost a debugging round once — don't repeat them)
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
- **VALIDATION.md** uses numbered round sections; append the next `§N` rather than editing old ones.

## Git
Work on branch `claude/quirky-fermi-kcvuaa`. Commit messages end with the attribution footer this
session is configured to use. Don't add a model identifier to commits or any pushed artifact.
</content>
</invoke>
