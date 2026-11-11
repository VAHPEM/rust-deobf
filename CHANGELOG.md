# Changelog

All notable changes to rust-deobf are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/) (pre-1.0: a minor bump may change a tool's `--json`
shape or CLI flags; a patch bump never does). The `rust-deobf` and `rust-deobf-premium`
distributions always share one version.

## [Unreleased]

Coverage of more obfuscation techniques (VALIDATION §79-§85). Each item: a benign fixture,
before/after measured, a test that fails on the previous code.

### Added
- **Strings that are never plain UTF-8**: UTF-16LE text in emulated memory, and small zlib/gzip
  streams verified by their checksum (new `recover.run` engine "compressed strings",
  `recover_blobs.small_streams`). New benchmark crate `encodings` (§80).
- **Lazy imports**: `recover_emulate` / `recover.run` report `resolved_imports`, the names handed
  to GetProcAddress / LoadLibrary* / GetModuleHandle* / dlsym / dlopen at run time; `in_file=False`
  marks a decoded, hidden import (§81).
- **OLLVM -bcf**: `deobf_opaque` scans every block, treats memory reads as unconstrained values,
  models push/pop / rip-relative lea / adrp / AArch64 writeback, and follows single-predecessor
  paths. Claims are typed opaque / constant / implied (new `constant_branches`,
  `implied_branches`) (§82).
- **garble**: `recover_go` reads a magic-patched pclntab (`pclntab_magic_patched`), and
  `recover_go.function_starts` gives the emulator Go's function starts (§84).

### Fixed
- **macOS: parallel `recover` could abort** (SIGABRT, "crashed on child side of fork pre-exec")
  on a large binary (workers > 1 and >= 2000 functions): the emulation workers were started with a
  bare `fork`. They now use a forkserver (engines preloaded), else spawn -- never a bare fork, on
  any OS (`emu_backend.mp_context`, shared with `fuzz_recover`). **Affects 0.1.0.** A script that
  calls `recover()` in parallel needs an `if __name__ == "__main__":` guard, as with Python's
  default spawn (§86).
- `recover_async` found no state machine in a `panic=abort` build (the LTO profiles): 0 of 9 ->
  all but what LLVM inlines into the executor loop (§79).
- `recover_rust_meta`: remapped registry paths (`--remap-path-prefix`) gave 0 crates (now 14 of
  14), `panic=immediate-abort` builds were reported as not Rust (rustc's `.comment` is now
  evidence), and an empty result carries `notes` saying why (§79).
- `recover_emulate`: a forced run's one-byte overrun of a complete decode no longer replaces the
  string (base64) (§80).
- `unpack_emulate` models Win32 TLS and writes: every Rust std program on Windows aborted before
  main, so a Rust-written packer was never followed to its stage-2 (§83).
- `recover.run` names an architecture it does not emulate (`ELF/riscv`, not `ELF/?`), says
  "WebAssembly module" for a wasm input, and gives the dynamic-analysis hint only when emulation
  actually ran (§85).

## [0.1.0rc2] - 2026-11-11

Second release candidate. 0.1.0rc1 published nothing: its installed-wheel test failed on Windows +
Python 3.10 (release run 42976295297), so neither distribution reached PyPI.

### Fixed
- **Installed std signature layer.** The wheel did not ship `data/libfunc_sigs_std.json.gz`
  (package-data matched `data/*.json` only) and `recover_libfuncs` looked for it under
  `site-packages/scripts/`; an installed rust-deobf therefore loaded no prebuilt-std signatures
  (0 instead of 4989). Both fixed; `rust-deobf doctor` checks the file.
- **Library mode put `site-packages/scripts` first on `sys.path`.** `gen_sigdb` and every premium
  module inserted `<parent of the package>/scripts` -- the clone's `scripts/`, but a foreign
  directory once installed. Had another distribution installed a top-level `scripts` package, its
  modules (`recover`, ...) would have shadowed the host program's. Clone-only paths are now added
  only in a checkout.
- The installed-wheel test compared `sys.path` entries with `==`; Windows Python 3.10 spells a
  venv's site-packages `lib` while the resolved package path is `Lib`. It now compares normalised
  paths, and also fails if importing the modules adds any other `sys.path` entry.
- **capstone / unicorn are always installed.** Their `platform_machine != "ARM64"` marker (meant for
  native ARM64 Python, which has no wheels) also matched x64 Python 3.14 on Windows-on-ARM --
  `platform_machine` is the host CPU there -- so pip left both out of the recommended setup.
  Native ARM64 Python now fails at `pip install` instead (README: use x64 Python).
- **Emulation: an AEAD's last block with its scratch neighbours** is no longer reported as a string
  (`:gUnmetry-offa` next to `...telemetry-off`; obfuse_aes on AArch64).

### Changed
- **The benchmark gate is deterministic.** Four benchmark crates draw fresh keys per build, and the
  per-push verdict followed the key (VALIDATION §77). `bench_src/*/Cargo.lock` is committed, obfuse
  / obfuse_aes / obfuse_xor are built with a fixed `seed=` per literal, and muddy (unseedable) runs
  in the weekly schedule only. Earlier one-build recall/precision figures are single samples.

## [0.1.0rc1] - 2026-11-11

Release candidate for 0.1.0: the first end-to-end run of the release pipeline -- build, the
installed-wheel tests on four operating systems, and Trusted Publishing to PyPI for both
distributions. The content is the 0.1.0 section below.

## [0.1.0] - 2026-11-11

First packaged release on PyPI (`pip install rust-deobf` / `pipx install rust-deobf`; premium
modules via `pip install "rust-deobf[premium]"`). Everything below was developed in the open
before packaging and is summarised by theme.

### Added
- **Packaging and the `rust-deobf` command.** One console command dispatching to every tool
  (`rust-deobf recover|triage|unpack|metadata|imports|cfg|...`), plus `rust-deobf list`,
  `rust-deobf doctor` (Python, dependency, platform and optional-tool checks) and
  `rust-deobf --version`; `python -m rust_deobf` works too. The Apache-2.0 core ships as
  `rust-deobf`; the premium modules ship separately as `rust-deobf-premium`
  (`pip install "rust-deobf[premium]"`). Extras: `dynamic` (Frida), `rules` (yara-python,
  flare-capa), `dev`. Release pipeline on `v*` tags with installed-wheel smoke tests on Linux,
  Windows and macOS, PyPI Trusted Publishing and a GitHub Release. The clone-and-run workflow
  (`python3 scripts/<tool>.py`) is unchanged.
- **String recovery.** Unified front end `recover.py` (static call-site dataflow for x86-64 and
  AArch64, stack strings, Rust `&str` literal splitting, `cryptify`, hash-obfuscated API imports)
  with isolated engines, exit codes, batch/JSONL mode and a FLOSS-compatible export.
- **Emulation.** Unicorn engine with a real loader (ELF/PE/Mach-O, TLS, chained fixups), a C
  runtime, path exploration and global-constructor replay; hard resource caps found by fuzzing
  the analyzer itself (`fuzz_recover.py`).
- **Metadata and structure.** Rust toolchain/crate/panic-site recovery that survives `strip`;
  library-function identification by byte signature with call-graph propagation; trait-object and
  C++ (Itanium) vtables/RTTI; enum discriminant/niche layout (DWARF names when present); Go pclntab
  names; resolved call graph + coverage; per-function behavior and source-language maps;
  crypto-constant identification; anti-analysis inventory and build provenance.
- **Triage and integration.** One-screen SOC triage card with calibrated signal, LLM-assisted
  triage over the deterministic facts, capa + YARA rule export, an MCP server (stdio), headless
  Ghidra annotation, a uniform `--json` output contract across result-producing tools.
- **Deobfuscation tiers (premium, AGPL-3.0-or-later OR commercial).** Control-flow-flattening
  detection and de-flattening (x86-64 + AArch64), provable MBA/expression simplification with Z3,
  opaque-predicate detection with a sound per-flag model, static and emulation-based VM
  devirtualization (randomized opcodes, encrypted operands, relooper structuring), and
  optimization reversal (jump-table un-switching, unrolled loops).
- **Unpacking.** Static unpacking by emulation to the original entry point (UPX and UPX-like,
  PE/ELF, x86-64/x86/AArch64, staged packers) with import-table reconstruction; embedded-artifact
  carving and keyless blob triage; an opt-in dynamic (Frida) dump cross-validated against the
  static result. Nothing executes a sample by default.
- **Cross-platform.** Verified on x86-64 Linux, ARM64 Kali and Windows x64 (x64 Python on
  Windows-on-ARM); test fixtures build for the host architecture.

- **October 2026 round (VALIDATION.md §62–§70).** Keyless LZ4 / aPLib / BriefLZ / LZNT1
  decompression in blob triage (`decompress.py`); async `Future::poll` state machines
  (`recover_async.py`, rustc 1.70–1.99, ELF/PE/Mach-O, x86-64/AArch64/i386); per-binary
  library-signature DBs for the binary's own rustc, target and crates (`gen_sigdb.py`) plus a
  bundled std layer for AArch64 and PE; Rust idioms in stripped binaries -- format strings with
  their traits, panic/safety checks with `file:line:col`, drops, enum-like returns
  (`recover_idioms.py`, annotated in Ghidra); a bridge pushing all of it into a running GhidraMCP or
  ida-pro-mcp (`decompiler_bridge.py`, `decompiler_selfcheck.py`); 32-bit PE emulation; the 2026
  obfuscation crates obfuse and obfany in the benchmark; ~1.4–1.6x faster emulation and 2.5–3.7x
  faster devirtualisation with identical output.

### Fixed
- A full bug-review round across the toolkit (emulator `.bss`/TLS/strlen edge cases, embedded and
  blob carving bounds, import binding past junk bytes and on ARM64, YARA/capa output that always
  compiles, MCP JSON-RPC edge cases, Go pclntab layouts, enum/crypto/lang/antianalysis false
  positives, sound opaque-predicate lifting, ARM64 loop decoding in `opt_reverse`, batch `--json`
  that survives one failing target), plus Windows and AArch64 portability fixes.

[Unreleased]: https://github.com/VAHPEM/rust-deobf/compare/v0.1.0...HEAD
[0.1.0rc2]: https://github.com/VAHPEM/rust-deobf/releases/tag/v0.1.0rc2
[0.1.0rc1]: https://github.com/VAHPEM/rust-deobf/releases/tag/v0.1.0rc1
[0.1.0]: https://github.com/VAHPEM/rust-deobf/releases/tag/v0.1.0
