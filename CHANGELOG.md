# Changelog

All notable changes to rust-deobf are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/) (pre-1.0: a minor bump may change a tool's `--json`
shape or CLI flags; a patch bump never does). The `rust-deobf` and `rust-deobf-premium`
distributions always share one version.

## [Unreleased]

## [0.1.0] - 2026-10-29

First packaged release: `pip install rust-deobf` / `pipx install rust-deobf`. Everything below
was developed in the open before packaging and is summarised by theme.

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
[0.1.0]: https://github.com/VAHPEM/rust-deobf/releases/tag/v0.1.0
