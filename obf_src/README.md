# obf_src — third-party obfuscation crates

Benign, author-written programs obfuscated with the Rust obfuscation crates a real analyst
meets, as opposed to the hand-rolled ciphers in `bench_src/`. Ground truth for each is its
`expected.json`. Build with `./build_obf.sh` (into `../build/`, like the main benchmark);
`tests/test_obf.py` asserts recovery across formats and profiles.

- **goldberg_cff** — [goldberg](https://crates.io/crates/goldberg): code-flow obfuscation
  (`goldberg_stmts!`) over `band()`, plus string (`goldberg_string!`) and integer
  (`goldberg_int!`) encryption. The encrypted strings are IOC-shaped and chosen not to collide
  with crate/metadata tokens, so recovery is measured, not a coincidence of the literal text.

- **lazy_import** — two harmless Win32 API names XOR-decoded at run time and resolved with
  `GetProcAddress` (no import-table entry); `expected.json` lists them as `resolved_imports` (§81).
- **ollvm_fla/fla.c**, **ollvm_bcf/bcf.c**, **hikari_strenc/hikari_ctor.c** — C, no Cargo.toml:
  OLLVM `-fla`, OLLVM `-bcf` (opaque predicates over never-written globals) and Hikari string
  encryption (constants decrypted in place by a global constructor), hand-written in their
  post-pass form and compiled by the tests themselves (`tests/test_deflatten.py`,
  `tests/test_ollvm_shapes.py`, §82).

- **rust_packer** — a Rust std program as a packer stub: RC4-decrypts a 64-byte stage-2 (returns
  42) into fresh RWX memory and calls it; `expected.json` `stage2` is what unpack_emulate must
  carve (§83). Safe to run.

No payloads, no real indicators. Samples of real malware are referenced by hash only, in
`../gallery/manifest.json`, and analysed in an isolated VM.
