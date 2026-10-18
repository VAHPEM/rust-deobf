# Artifact-recovery tiers — reusing the memory-observation engine beyond strings

The string recoverers answer *"what strings did this binary hide"*. The tools below
answer the triage questions one level up, by reusing the same two engines the project
already has — **static call-site dataflow** (capstone/LIEF) and **dynamic memory
observation** (Frida memory-diff) — with different *filters* and *structure parsers*.

All tools are **observational**: they read and decode a binary (static) or observe a
sample's own memory in a sandbox (dynamic). They produce no offensive capability. Run
dynamic tools only inside an isolated analysis VM, exactly as `recover_dynamic.py` warns.

Every tool ships a `--selftest` (synthetic ground truth) and was additionally run on the
two FLARE-On samples in `ctf-brain/challenges/`: **catthief.exe** (a Rust PE: ureq/rustls/
ring networking) and **ToxicMiner.exe** (a C/C++ MSVC PE, used as a negative control).

| Tier | Tool | Engine reused | New part |
|---|---|---|---|
| 1 | `recover_callsite.py` / `recover_arm64.py` / `recover_dynamic.py` | — | (existing) strings |
| 2 | `recover_artifacts.py` | dynamic memory-diff | (existing) config/C2 + indicators |
| 2 | **`recover_apihash.py`** | static immediates | resolve hash-obfuscated imports |
| 2 | **`dump_unpacked.py`** | dynamic (W→X hook) | dump + carve unpacked stage-2 |
| 3 | **`recover_rust_meta.py`** | static rodata/struct parse | Rust panic/crate/type recovery |
| 4 | **`deobf_expr.py`** | z3 (new engine) | prove/simplify MBA + opaque predicates |
| 4 | **`deobf_cff.py`** | static CFG heuristic | locate control-flow-flattening dispatchers |

---

## Tier 2 — more artifacts from the same two engines

### `recover_apihash.py` — resolve hash-obfuscated API imports (static)
Samples hide which APIs they use by resolving imports at runtime by **hash**: they carry
32-bit constants and walk a module's export table hashing each name until one matches, so
the static import table shows nothing. The tool collects the candidate constants compared
against in `.text`, hashes a corpus of known export names under every common API-hash
algorithm (`ror13_add`, `djb2`, `sdbm`, `fnv1a32`, `add_ror7`, `rol5_xor`) with case and
UTF-16 variants and several seeds, and reports `const → API [algo, seed]`.
- **Selftest:** recovers 3 planted APIs (incl. a UTF-16 name) from a decoy-laced pool.
- **On the samples:** neither uses hash imports (normal IATs) → correctly reports none.
- **Coverage:** pass the real target DLLs' exports with `--names` (`dumpbin /exports`).

### `dump_unpacked.py` — dump the unpacked stage-2 (dynamic + static carve)
A packer decompresses stage-2 into a fresh region and flips it executable. The Frida layer
hooks `VirtualProtect`/`mprotect`, dumps any region that **gains EXEC** (the W→X flip), and
sweeps RW memory for `MZ`/`PE` images at start; the static core measures the **entropy drop**
(packed→code) and **carves** embedded PE images (`carve_pes`, `shannon_entropy`).
- **Selftest:** entropy ordering holds; carves a synthetic PE32+ at a known offset.
- **On catthief.exe (static carve):** PE32+, machine 0x8664, 5 sections, SizeOfImage
  1 363 968 — header parse correct. (The Frida layer runs on the VM.)

---

## Tier 3 — Rust-specific structure (`recover_rust_meta.py`)

Rust binaries retain structure that survives `strip`, because it lives in read-only data
the runtime needs. Three recoveries, all **static**:

1. **Panic `Location` records** `{ptr→filename, len, u32 line, u32 col}` emitted by every
   `unwrap`/`expect`/bounds-check. Matching the struct shape in rodata rebuilds the source
   tree and a `file:line:col` map of panic sites.
2. **Crate fingerprint + version** from the `.cargo/registry/src/<index>/<crate>-<ver>/`
   prefix in those paths — names each third-party crate and its exact version; the crate
   set implies capability (net / async / tls / crypto / serde / …).
3. **Type/trait names** via Rust symbol demangling when not fully stripped.

A binary is only called Rust on **strong evidence** (a cargo path, a `/rustc/<hash>/` path,
a recovered `Location`, or a mangled Rust symbol) — loose markers do not count, so C/C++
is not misflagged.

**Validated on catthief.exe (zero execution):**
- rustc commit `ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96`
- **17 crates at exact versions**: ureq 2.12.1, rustls 0.23.40, ring 0.17.14, flate2 1.1.9,
  base64 0.22.1, url 2.5.8, idna, percent-encoding, miniz_oxide, … 
- **capability profile**: `net` (ureq HTTP) · `tls` (rustls) · `crypto` (ring) · `compress`
  (flate2) · `encode` (base64) → a networking/exfil-shaped sample
- **697 panic sites** with `file:line:col`
- rodata even surfaced a leaked indicator `http://192.168.56.102:8080/exfil`

**Negative control:** ToxicMiner.exe → `is_rust=False`, no crates (correct).

---

## Tier 4 — code deobfuscation

### `deobf_expr.py` — provable MBA simplification + opaque predicates (z3)
A claimed simplification is **proven over all inputs** by z3, not guessed. Expressions use
a small safe grammar over n-bit words (parsed with `ast` under a strict operator allowlist,
no code eval). `mba` simplifies to the simplest proven normal form; `opaque` classifies a
predicate as always-true / always-false / input-dependent (with witnesses); `equiv` proves
or gives a counterexample.
- **Selftest:** five standard MBA identities for `+ - ^` proven and simplified; a
  non-identity caught with a counterexample; opaque predicates classified. e.g.
  `(x | y) - (x & y) ⇒ x ^ y`.

### `deobf_cff.py` — locate control-flow-flattening dispatchers (static)
CFF turns a function into `while(1){switch(state)}`. The detector finds a **dispatcher**:
a high-in-degree jump target fed by a **local** `cmp <state>, imm` ladder (localised to the
blocks that jump to it, not counted across all of `.text`), scored `min(in_degree, ladder)`.
- **Selftest:** recovers a synthetic dispatcher (in-degree 20, 20 state consts).
- **Honesty:** a large compiler `match`/jump table has the same shape — output is flagged as
  *candidates to inspect*, not proof of obfuscation. On catthief.exe the top in-degree block
  (376) is correctly demoted (small local ladder → score 22); real match-heavy Rust code.

---

## Integration

The static Tier-3/Tier-4 tools fit the `recover.py` front-end dispatch; the dynamic Tier-2
tools follow `recover_dynamic.py`'s spawn-observe-subtract pattern and VM-only safety note.

### Live VM validation (2026-10-18; Windows 11 VM frida 17.18.0, Kali aarch64 frida 17.24.1)

Negative / precision checks:
- **`recover_apihash.py` vs a real 6 360-name corpus** (ntdll + kernel32 + KernelBase +
  advapi32 + ws2_32 + bcrypt + wininet, dumped with pefile): both samples resolve **0**
  constants — no false positives across ~1.1M hashes (6360 names × 6 algos × case/UTF-16
  variants × 5 seeds). Both use normal IATs, not hash imports.
- **`dump_unpacked.py --frida catthief.exe`** (Windows VM): the W→X/memory harness dumped 2
  regions, measured entropy (1.92, 6.52), carved — correctly reported **no stage-2 PE**
  (catthief is not packed). Honest negative, not a hallucinated image.

Positive cases (proving the detectors fire on a true signal):
- **`recover_apihash.py` on a compiled fixture** (x86-64 ELF whose `.text` compares a value
  against the ror13 hashes of 5 API names): **5/5 resolved** with the correct algorithm
  (`ror13_add`, seed 0) — `VirtualAlloc`, `LoadLibraryA`, `GetProcAddress`,
  `NtWriteVirtualMemory`, `CreateRemoteThread`.
- **`dump_unpacked.py --frida` on a JIT-style W→X fixture** (Kali): mmap RW → write a marked
  blob → `mprotect(PROT_EXEC)` → execute. The hook captured exactly the flipped 4096-byte
  region and the planted `UNPACKED_STAGE2_MARKER` was present in the dump.
- **Full benchmark matrix reproduced live** (Kali aarch64, release builds; static via the
  arch-correct `recover_arm64`, dynamic via `recover_dynamic` — the same frida memory-diff
  engine `recover_artifacts`/`dump_unpacked` build on):

  | obfuscator | cipher | static (arm64) | dynamic |
  |---|---|---|---|
  | xor_custom / add_custom / sub_custom | XOR/ADD/SUB | 5/5 | 5/5 |
  | litcrypt | XOR (runtime key) | 5/5 | 5/5 |
  | litcrypt2 | XOR (runtime key) | 0/5 | 5/5 |
  | obfstr | XOR+ADD inlined | 0/5 | 5/5 |
  | muddy | ChaCha20-Poly1305 AEAD | 0/5 | 5/5 |

  Dynamic recovers every family 5/5 including AEAD; the three static misses are the
  by-design cases (inlined / AEAD / litcrypt2's runtime key), matching RESULTS.md. (frida
  17.24.1 is now installed in `~/ctf-venv` on the Kali VM.)

Tier-3 is now scored against ground truth (`scripts/measure_rust_meta.py` vs each bench
project's `Cargo.lock`): **crate precision 17/17 = 1.00, version-exact 17/17 = 1.00, 0 false
crates, 2533 panic sites across 8 ELF binaries**. Panic-site recovery was extended to PIE ELF
by reading relocation addends (the filename pointer is relocated, not absolute). See
`VALIDATION.md §7`.

Still open: a genuinely packed malware/CTF sample for `dump_unpacked`'s dynamic path, and a
real hash-import sample for `recover_apihash --names` (both have synthetic positive cases and
clean negatives, but not yet an in-the-wild positive).
