# obf_src — third-party obfuscation crates

Benign, author-written programs obfuscated with the Rust obfuscation crates a real analyst
meets, as opposed to the hand-rolled ciphers in `bench_src/`. Ground truth for each is its
`expected.json`. Build with `./build_obf.sh` (into `../build/`, like the main benchmark);
`tests/test_obf.py` asserts recovery across formats and profiles.

- **goldberg_cff** — [goldberg](https://crates.io/crates/goldberg): code-flow obfuscation
  (`goldberg_stmts!`) over `band()`, plus string (`goldberg_string!`) and integer
  (`goldberg_int!`) encryption. The encrypted strings are IOC-shaped and chosen not to collide
  with crate/metadata tokens, so recovery is measured, not a coincidence of the literal text.

No payloads, no real indicators. Samples of real malware are referenced by hash only, in
`../gallery/manifest.json`, and analysed in an isolated VM.
