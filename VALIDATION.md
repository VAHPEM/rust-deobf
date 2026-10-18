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

## 3. obfstr — needs dynamic analysis

obfstr inlines the decode into the caller with per-literal immediate keys, an ADD cipher, and
a pointer hidden behind an `xref::inner` call. A Unicorn function-emulation PoC recovers the
first literal (1/5); full recovery diverges on main's control flow. A full-system emulator
(qiling) is the right tool but did not install in this environment (a hard `unicodecsv`
dependency conflict on Python 3.12). obfstr remains open.

## Bottom line

On controlled inputs the approach clearly beats FLOSS (which scores 0/5 and cannot open ELF).
On real binaries it has a **manageable precision problem** (filterable, ~5 FP on 30 MB) but an
**unsolved recall problem** (call-site resolution breaks on optimised slice-struct ABI, and
obfstr needs emulation). It is a promising PoC, not a finished tool — which is why the right
next step is hardening on real binaries before any upstream contribution, not a FLOSS PR today.
