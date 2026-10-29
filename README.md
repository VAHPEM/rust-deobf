<div align="center">

<img src="assets/hero.png" alt="rust-deobf: strings finds 0 indicators in an obfuscated Rust binary; recover.py recovers all 8 (IP, path, user agent, flag, registry key, mutex, URL, identifier)" width="100%">

**`strings` sees nothing. FLOSS sees nothing. rust-deobf sees the C2.**

rust-deobf recovers what obfuscated Rust binaries hide — C2 addresses, file paths, mutexes, registry
keys, config — **without ever running the sample**.

[![CI](https://github.com/VAHPEM/rust-deobf/actions/workflows/ci.yml/badge.svg)](https://github.com/VAHPEM/rust-deobf/actions/workflows/ci.yml)
![core license](https://img.shields.io/badge/core-Apache--2.0-blue)
![formats](https://img.shields.io/badge/formats-ELF%20%7C%20PE%20%7C%20Mach--O-informational)
![arch](https://img.shields.io/badge/arch-x86--64%20%7C%20ARM64%20%7C%20x86-informational)
![python](https://img.shields.io/badge/python-3.10%2B-blue)
[![PyPI](https://img.shields.io/pypi/v/rust-deobf)](https://pypi.org/project/rust-deobf/)

[Demo](#-30-second-demo) · [Use it from an AI agent](#-use-it-from-an-ai-agent) ·
[Install / quick start](#-quick-start) · [Results](#-results) · [Real malware](#-real-malware) ·
[Limitations](#-honest-limitations)

</div>

---

## ⚡ 30-second demo

A stripped Rust program built the way malware ships (`opt-level="z"`, fat LTO, `panic=abort`),
with its eight indicators encrypted by [`obfstr`](https://crates.io/crates/obfstr) — the strings
sit in a struct, `match` arms, comparisons, and a branch that never runs. None is ever printed.

<p align="center">
  <img src="assets/demo.gif" alt="Terminal: strings | grep finds 0 matches; python3 scripts/recover.py sample recovers 8 decoded strings tagged ip, path, registry, mutex and url" width="100%">
</p>

<sub>Rendered from the captured output of a real run (Linux x86-64, rustc 1.97): the text is
verbatim, the colours and typing animation are added, the ~8 s emulation wait is sped up, and the
output is trimmed to the decoded strings. The plain-text output below is the same run.</sub>

<details>
<summary><b>Plain-text output (copyable)</b></summary>

**What the file shows you:**

```console
$ B=build/scatter_obfstr__elf__size-lto__strip
$ strings $B | grep -ciE 'northwind|10\.66|NW-5c1e9a|skip-update'
0
```

**What rust-deobf recovers** (static + Unicorn emulation; the binary is never executed):

```console
$ python3 scripts/recover.py $B
binary: scatter_obfstr__elf__size-lto__strip   format=ELF   arch=x86_64
  static x86-64 (recover_callsite): 0 strings  decoders=9  seconds=0.2
  emulation (recover_emulate): 8 strings  functions=416/416  timed_out=False  workers=1  seconds=6.8

== decoded strings ==
  10.66.12.7:8443   [ip]
      function 0xf20c  (emulation)
  C:\ProgramData\NorthwindSvc\state.db   [path]
      function 0xf20c  (emulation)
  Mozilla/5.0 (Windows NT 10.0; Win64; x64) NorthwindAgent/2.1
      function 0xf20c  (emulation)
  --skip-update-check
      function 0xf443  (emulation)
  Software\Northwind\Agent\Settings   [registry]
      function 0xf51b  (emulation)
  Global\NW-5c1e9a   [mutex]
      function 0xf5a8  (emulation)
  https://telemetry.northwind.example/api/v3/beacon   [url]
      function 0xfd58  (emulation)
  nw-agent::stage=collect
      function 0xfd58  (emulation)
```

</details>

**8/8 in under 10 seconds**, each string tagged and traced to the function that builds it.
Reproduce it with `ONLY=scatter_obfstr PROFILES=size-lto FORMATS=elf bash scripts/build_all.sh`
(output trimmed to the decoded strings). (The input is a benign benchmark
program; every planted string is listed in `bench_src/manifest.json`.)

---

## 🔥 Why this exists

Rust malware is rising, and its deobfuscation tooling is effectively absent. **FLOSS** — the
standard open-source string deobfuscator — recovers nothing from the common Rust obfuscation
crates:

| obfuscator | `strings` | FLOSS | **rust-deobf** |
|---|:--:|:--:|:--:|
| litcrypt / litcrypt2 | 0/5 | 0/5 | **5/5** |
| obfstr (inlined XOR+ADD) | 0/5 | 0/5 | **5/5** |
| cryptify (default key) | 0/5 | 0/5 | **5/5** |
| muddy (ChaCha20-Poly1305 AEAD) | 0/5 | 0/5 | **5/5** |
| tight stack strings | 0/5 | 0/5 | **5/5** |
| hand-rolled XOR / ADD / SUB | 0/5 | 0/5 | **5/5** |

<sub>Canary benchmark, release builds, ELF and PE x86-64 and AArch64, stripped and not. Full table,
including the one case that needs dynamic recovery (cryptify with a custom key), under
[Results](#-results).</sub>

On real samples: **EDDIESTEALER** (PE) — 32 obfuscated strings including its hidden C2 domain and
URL path, where static tools and FLOSS recover 0. **AmnesiaStealer** (macOS Mach-O) — C2 exfil URL,
crypto-clipper config, staging paths. [More below](#-real-malware).

---

## ✨ What's inside

- **String deobfuscation** — static call-site recovery (seconds) + a Unicorn emulation engine with
  a real loader, a C runtime, path exploration and global-constructor replay. Recovers strings built
  only in one `match` arm or on a branch that never runs.
- **One-screen SOC triage** — `soc_triage.py`: format/arch, Rust toolchain, crate capability
  fingerprint (networking / crypto / recon / persistence / staging), indicators grouped by type, and
  a calibrated LOW / MEDIUM / HIGH signal with its evidence. `--json` for a SIEM, `--fail-on HIGH`
  for scripted gating. `--fast` (metadata + literal indicators, no decoding) scales with binary
  size: under a second on a small sample, ~20 s on a 20 MB binary.
- **Multi-arch, multi-format** — x86-64, ARM64 and 32-bit x86 across ELF, PE and Mach-O.
- **Fits your workflow** — FLOSS-compatible export (`--floss-json`), headless Ghidra annotation
  (plate comments, bookmarks, renames), library-function identification by byte signature
  (`lib_<name>` in stripped binaries), batch mode over a directory (`--jsonl`).
- **Static unpacking** — `unpack.py` emulates the unpacking stub (UPX and UPX-like; PE and ELF,
  x86-64 / x86 / AArch64) to the original entry point, carves stage-2, and recovers the import
  table the stub rebuilds — without running the sample. Verified on UPX-packed PE32/PE32+ and
  AArch64 ELF (OEP = the entry of the binary before packing) and cross-checked against a live
  Frida dump (99% identical).
- **Beyond strings** — config/C2 extraction, hash-obfuscated API-import resolution, control-flow-flattening detection **and reconstruction** (x86-64 and AArch64,
  validated on goldberg, OLLVM `-fla` and a real LLVM-18 flattening pass), MBA / opaque-predicate
  simplification with Z3, Rust trait-object vtable recovery (`recover_types.py`), and
  optimization-reversal (jump-table un-switching, unrolled-loop detection — `premium/opt_reverse.py`).
- **Rust idioms in stripped binaries** — `recover_idioms.py` brings back the format string of every
  `println!` / `format!` / `panic!` site (both `fmt::Arguments` encodings: newer rustc's compact
  template and the older pieces array), marks bounds / overflow / unwrap panic paths as cold
  safety checks with their `file:line:col`, flags drop / dealloc calls and enum-like
  (Option/Result?) returns, and annotates all of it in Ghidra — no symbols needed (measured on
  rustc 1.97 and 1.99.1 builds for x86-64 / AArch64 / i386 ELF and x86-64 / i386 PE).
- **Code virtualization** — `detect_vm.py` flags VMProtect/Themida/Tigress-style bytecode VMs; the
  premium devirtualizer lifts them back. From a VM with **randomized opcodes and encrypted
  operands**, it reconstructs:

  ```c
  return (((a0 > 1000) & (((((a0 * 31) + a1) ^ (a0 >> 3)) % 97) == 0)) ? (a1 + a0) : 0xffffffff);
  ```

  — the function's exact source.
- **Safe by design** — static + emulation by default: emulation runs *functions* of the binary under
  Unicorn, never the binary itself. Dynamic (Frida) recovery is opt-in and for isolated VMs only.
- **Async state machines** — `recover_async.py` finds every `async fn` / async block's state
  machine in a stripped binary (x86-64 / AArch64, ELF / PE): where the state lives, state → resume
  target, each `.await`'s inner poll (direct, `dyn Future` vtable, or inlined) as a nesting graph,
  the coroutine's source line, and the async runtime (tokio, ...) — anchored on rustc's
  "`async fn` resumed after completion" panics.
- **Rust metadata that survives `strip`** — rustc version, third-party crates with exact versions,
  and panic sites, rebuilt from the source paths the compiler leaves in every Rust binary (no
  `cargo-auditable` needed).

---

## 🤖 Use it from an AI agent

A decompiler's string view, `strings`, FLOSS — anything that reads strings from the file — can only
show bytes that *are* in the file. An obfuscation crate makes sure the plaintext never is, so an AI
agent reading a decompiler sees the same nothing you do. rust-deobf gives it the facts instead.

It is a CLI with JSON output, so any agent that can run shell commands (Claude Code, Codex,
Cursor, …) can call it next to whatever decompiler tooling it already drives:

```bash
python3 scripts/soc_triage.py sample.bin --json      # one-screen facts: toolchain, crates, IOCs, signal
python3 scripts/recover.py   sample.bin --json       # every decoded string + the function that builds it
scripts/ghidra_run.sh sample.bin                     # write them into the Ghidra decompiler as plate comments
python3 scripts/mcp_server.py                         # or serve recover/triage/metadata/detect as MCP tools
```

Prefer typed tools over CLI parsing? `scripts/mcp_server.py` exposes `detect` / `metadata` /
`triage` / `recover` as [MCP](https://modelcontextprotocol.io) tools over stdio (no third-party
package needed), so an agent calls them with a JSON schema and gets structured JSON back. And
`scripts/export_rules.py` turns the recovered facts into **capa** rules and **YARA** rules (the
Mandiant detection formats), for the obfuscation crates and from the recovered decoder idioms /
hash-obfuscated imports — `--static-only` emits the crate family ruleset for any corpus.

### Annotate the decompiler the agent is reading (GhidraMCP / ida-pro-mcp)

Run rust-deobf's MCP server next to a decompiler MCP server and the agent can write the recovered
facts straight into the view it reads: decoded strings on the function that builds them and on each
decoder call site, `lib_*` names for identified std/crate functions, vtables and their methods,
panic `Location` records, toolchain/crates/triage at the entry point. Claude Code, e.g.:

```bash
claude mcp add rust-deobf -- python3 /path/to/rust-deobf/scripts/mcp_server.py
claude mcp add ghidra -- uvx --from git+https://github.com/LaurieWired/GhidraMCP ghidra-mcp \
    --ghidra-server http://127.0.0.1:8080/
# or IDA: claude plugin install ida-pro-mcp@mrexodia   (plugin at http://127.0.0.1:13337/mcp)
```

```json
{"mcpServers": {
  "rust-deobf": {"command": "python3", "args": ["/path/to/rust-deobf/scripts/mcp_server.py"]},
  "ghidra": {"command": "uvx", "args": ["--from", "git+https://github.com/LaurieWired/GhidraMCP",
             "ghidra-mcp", "--ghidra-server", "http://127.0.0.1:8080/"]}
}}
```

Two ways to apply them:

- **`push_annotations`** (rust-deobf tool): `{path, backend: "ghidra-mcp" | "ida-mcp", url}` talks to
  the plugin's HTTP API directly. It is a dry run unless `dry_run: false`; loopback URLs only.
- **`annotations`** (rust-deobf tool) returns the neutral list; the agent applies each entry with the
  decompiler's own tools (`set_decompiler_comment` / `rename_function_by_address` in GhidraMCP,
  `append_comments` / `rename` in ida-pro-mcp). Pass `image_base` (GhidraMCP `get_program_info`,
  ida-pro-mcp `server_health`) to get `decompiler_address` filled in.

The same from a shell: `python3 scripts/decompiler_bridge.py sample.bin --backend ghidra-mcp
[--dry-run]` (or `--backend ida-mcp`, or the default `--backend json`). What it guarantees:

- **Addresses are mapped and checked.** Ours are RVAs (PE) or file VAs (ELF/Mach-O); Ghidra usually
  rebases a PIE to 0x100000, IDA loads it at 0. The bridge reads the decompiler's image base, checks that the
  entry point lands on a function start, and refuses to write if it doesn't.
- **It only writes into the right program.** If the decompiler reports a sha256 that differs from
  the file's, the push is refused unless you pass `--force`.
- **Your comments are kept.** The bridge reads the existing comment, rewrites only its own
  `[rust-deobf]` lines (an outdated fact is replaced, not left behind) and keeps your text.
  - Ghidra: GhidraMCP can read end-of-line comments but not PRE comments, so EOL is the default.
    The listing shows them; the decompiler shows them once its EOL-comment display option is on.
    `--ghidra-comment pre` writes PRE comments (visible in the decompiler) but replaces whatever
    PRE comment is already at that address. Addresses outside any function (vtables, panic
    Locations) can't be read back, so they are skipped in EOL mode.
  - IDA: reading a comment needs ida-pro-mcp's `py_eval` tool (enabled in the IDA plugin by
    default; `idalib-mcp --unsafe`). Without it the bridge falls back to appending lines and says
    that stale lines may remain.
- **Bookmarks.** Ghidra has no bookmark API, so a bookmark becomes a `[rust-deobf] bookmark:` line
  in the same comment. IDA bookmarks go only into a free slot or one the bridge set itself, never
  over yours.
- **Renames** touch only `FUN_`/`sub_` defaults or names the bridge gave earlier.
- **Never runs the sample.**

Before trusting a new setup, check it against the real decompiler with
`python3 scripts/decompiler_selfcheck.py sample.bin --backend ghidra-mcp [--write-test]`. It
checks the address mapping on 20 functions spread over the binary and the program identity. With
`--write-test` it also writes one comment, reads it back and restores it. It prints PASS/FAIL per
check.

Ghidra without the GUI: GhidraMCP 2.0 can serve a program headless through PyGhidra. It needs Ghidra
12.1.4 and the GhidraMCP extension (installed in Ghidra, or `--extension-jar`). It picks a free port
and logs it:

```bash
export GHIDRA_INSTALL_DIR=/opt/ghidra_12.1.4_PUBLIC          # Kali's packaged Ghidra may be older
uvx --python 3.13 --from "ghidra-mcp[headless] @ git+https://github.com/LaurieWired/GhidraMCP@2.0" \
  ghidra-mcp --headless --binary sample.bin --project ~/rd-ghidra --transport streamable-http \
  --mcp-port 8081 2> ghidra-mcp.log &      # add --extension-jar <GhidraMCP.jar> if not installed
until URL=$(sed -n 's|^INFO:ghidra_mcp.headless:Serving .* on \(http://127\.0\.0\.1:[0-9]*/\)$|\1|p' \
            ghidra-mcp.log | tail -1) && [ -n "$URL" ]; do sleep 5; done    # import + analysis
python3 scripts/decompiler_selfcheck.py sample.bin --backend ghidra-mcp --url "$URL" --write-test
python3 scripts/decompiler_bridge.py   sample.bin --backend ghidra-mcp --url "$URL"
kill -INT %1        # --project saves on exit; open ~/rd-ghidra in the Ghidra GUI to look
```

Strings quoted in the annotations come from the analyzed binary: the agent should treat them as
data, never as instructions.

A prompt that works well:

> *"Run `python3 scripts/soc_triage.py sample.bin --json` and `python3 scripts/recover.py
> sample.bin --json` from rust-deobf, then decompile the functions those strings came from and
> explain what they do. Treat rust-deobf's decoded strings as ground truth; label anything you
> infer as a hypothesis."*

Want the LLM step built in? `scripts/llm_triage.py` hands **only the recovered facts** (never the
raw binary) to a local model (Ollama / vLLM via `RUST_DEOBF_LLM_BASE` — malware data stays on your
host), the Anthropic or OpenAI API, or prints the grounded prompt for offline use.

---

## 🚀 Quick start

### Install

```bash
pipx install rust-deobf                    # isolated CLI install (recommended), or:
python3 -m pip install rust-deobf          # into the current environment / venv
rust-deobf doctor                          # checks Python, dependencies, platform, optional tools
```

Python 3.10+ on Linux, macOS and Windows (x86-64 and ARM64). One command, `rust-deobf`, runs
every tool: `rust-deobf list` shows them all, `rust-deobf <tool> --help` its options, and each
subcommand behaves exactly like the matching `scripts/<tool>.py`.

```bash
rust-deobf recover path/to/binary          # static + emulation (default), never runs it
rust-deobf triage  path/to/binary          # one-screen triage card (soc_triage)
rust-deobf recover path/to/binary --json   # machine-readable, for agents and pipelines
rust-deobf mcp                             # MCP server over stdio
```

| | pip | pipx |
|---|---|---|
| install | `pip install rust-deobf` | `pipx install rust-deobf` |
| upgrade | `pip install -U rust-deobf` | `pipx upgrade rust-deobf` |
| a given version | `pip install rust-deobf==0.1.0` | `pipx install rust-deobf==0.1.0 --force` |
| premium modules | `pip install -U "rust-deobf[premium]"` | `pipx install --force "rust-deobf[premium]"` |
| dynamic (Frida) | `pip install "rust-deobf[dynamic]"` | `pipx inject rust-deobf frida frida-tools` |
| check | `rust-deobf --version` / `rust-deobf doctor` | same |

- **Premium modules** (`rust-deobf opaque|deflatten|cff|expr|devirt|lift-vm|opt-reverse`;
  AGPL-3.0-or-later OR commercial, see [License](#-license)) are a separate distribution,
  `rust-deobf-premium`, always the same version as the core. Upgrade them together:
  `pip install -U "rust-deobf[premium]"` (a plain `pip install -U rust-deobf` leaves an older
  premium behind, and `rust-deobf` then tells you to upgrade both). The core works without them.
- **Extras:** `[dynamic]` Frida (runs the sample: isolated VM only), `[rules]` yara-python +
  flare-capa to validate exported rules, `[dev]` pytest + build.
- **Windows on ARM:** use the **x64** Python build (it runs under emulation). Native ARM64 Python
  has no `unicorn`/`capstone<6` wheels; `pip install` still completes there, and `rust-deobf`
  explains what to do instead of failing.
- **Upgrades and data:** the signature/data files (`data/*.json`) ship inside the package and are
  replaced on upgrade. Per-user caches live under `~/.cache/rust-deobf` (Linux; macOS
  `~/Library/Caches/rust-deobf`, Windows `%LOCALAPPDATA%\rust-deobf` — `rust-deobf doctor` prints
  the path). Caches are disposable: each carries a format version, a cache from another format is
  ignored and rebuilt rather than misread, and deleting the directory is always safe. Release notes: [CHANGELOG.md](CHANGELOG.md).

### From source (clone and run, or develop)

```bash
git clone https://github.com/VAHPEM/rust-deobf.git
cd rust-deobf
python3 -m pip install -r requirements.txt          # lief, capstone, unicorn, z3-solver, pyelftools, pyyaml

python3 scripts/recover.py path/to/binary            # every tool runs straight from the clone
python3 scripts/soc_triage.py path/to/binary
python3 scripts/cli.py list                          # the `rust-deobf` command, without installing

python3 -m pip install -e . -e premium               # or: an editable install of both distributions
```

The examples below use the clone form (`python3 scripts/<tool>.py`); with an install,
`rust-deobf <subcommand>` is the same (`recover_libfuncs.py` -> `libfuncs`, `recover_types.py` ->
`types`, `soc_triage.py` -> `triage`, `ghidra_run.sh` -> `ghidra`; `rust-deobf list` has the map).
Benchmark/evaluation tools that need the repository's `bench_src/` and `build/` (e.g.
`evaluate_all.py`, `fuzz_recover.py`, `redblue_loop.py`) are clone-only.

<details>
<summary><b>All options</b></summary>

```bash
python3 scripts/recover.py path/to/binary --floss-json out.json   # FLOSS results document
python3 scripts/recover.py path/to/binary --emulate never         # static passes only, seconds
python3 scripts/recover.py path/to/binary --time-budget 600       # big binaries: emulate longer
python3 scripts/recover.py path/to/binary --max-ram 2G            # cap memory (fewer processes)
python3 scripts/recover.py path/to/binary --libfuncs              # also name Rust std/crate functions
python3 scripts/recover.py samples/ --jsonl triage.jsonl          # a whole directory

# name library functions in a stripped binary (needs a signature DB for its toolchain):
python3 scripts/recover_libfuncs.py --gen build/*release*nostrip   # build the DB once per toolchain
python3 scripts/recover_libfuncs.py path/to/binary                 # identify; --json for records
python3 scripts/recover_libfuncs.py path/to/binary --propagate     # + call-graph thunks & drop-glue
python3 scripts/gen_sigdb.py path/to/binary [--allow-download]      # DB for THIS binary's rustc+target (std)
python3 scripts/gen_sigdb.py path/to/binary --build-crates         # + its crates: runs their build scripts,
                                                                   #   so only inside the analysis VM
python3 scripts/recover_libfuncs.py path/to/binary --db auto       # use it (falls back to the bundled DB)
# recover Rust trait-object vtables (dyn Trait dispatch) as Ghidra data types:
python3 scripts/recover_types.py path/to/binary                    # --json for records
# push strings + library names + vtables into Ghidra (headless, PyGhidra):
scripts/ghidra_run.sh path/to/binary

# AI-assisted read over the recovered facts only (local model, API, or --offline):
python3 scripts/llm_triage.py path/to/binary

# runtime-only decoders, inside an isolated analysis VM ONLY (pip install frida frida-tools)
# it EXECUTES the sample, so it refuses to start without the explicit opt-in flag
python3 scripts/recover_dynamic.py path/to/binary --i-understand-this-executes [--argv arg1 arg2 ...]
```

Exit codes (`recover.py`, `soc_triage.py`, `llm_triage.py`): `0` the analysis ran, `2` usage error,
`3` unsupported or unparseable input (not an ELF/PE/Mach-O LIEF can read — e.g. a text file),
`4` analysis error (an engine raised; the other engines still ran and their output is printed; in
directory mode, at least one file failed — the table's error column says which). `soc_triage.py
--fail-on MEDIUM|HIGH` exits `1` when the signal reaches that level. Directory mode analyses every
binary single-file mode supports (32-bit x86 included), and counts the files it skipped.

Emulation runs by default and is bounded by `--time-budget` (120 s): functions are tried in
decoder-score order, and the output says how many were emulated (`functions=412/1671`) and
whether the budget ran out. Memory is the other knob: a large binary is split across worker
processes (`RUST_DEOBF_WORKERS`, default `min(4, CPUs)`), each holding its own loaded image and
Unicorn instance — roughly 250 MB plus 45 MB per MB of `.text`, so ≈0.5 GB for gdb and ≈1.1 GB
for cargo. `--max-ram 2G` (or `RUST_DEOBF_MAX_RAM_MB`) caps the process count to fit that
budget, trading speed for memory; a budget below one process's footprint runs serially, slower,
and the output reports both the process count and the reduction.

</details>

---

## 📊 Results

Every number here is a test or a script in this repo, and the benchmark publishes the cases where
the tool does **not** work too.

| | |
|---|---|
| **360 / 360** | exact strings on held-out shapes × malware build profiles (54 stripped binaries, ELF/PE/AArch64), **0** extra |
| **1360 / 1360** | across build profiles the benchmark never tuned for, 0 junk — see *Build profiles nobody tuned for* below for what that number means |
| **120 / 120 vs 0** | on Windows, stripped PE files: rust-deobf vs FLOSS 3.2.0, same machine, same files |
| **29 FP / 21 binaries** | false positives on real unobfuscated C/C++, Go and Rust programs (bash, git, gdb, docker, cargo…) |
| **9 families** | real Rust malware validated end-to-end (static + emulation, never executed) |

<details>
<summary><b>Held-out shapes × malware build profiles (scatter suite)</b></summary>

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

**360/360** exact strings and **0** extra across all 54 binaries (stripped builds); the code an
external review tested got **79/360**. Every cell is a test in `tests/test_scatter.py`.

</details>

<details>
<summary><b>Canary benchmark (one program per crate, five printed strings)</b></summary>

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
| muddy | ChaCha20-Poly1305 (AEAD) | 0/5 | 0/5 | — | **5/5** | **5/5** |
| obfuse² (default features) | 2–4 random XOR/ADD/SUB/ROT layers per string, runtime-derived keys, flattened state machine | 0/5 | n/m | — | **5/5** | n/m |
| obfuse_aes² | AES-256-GCM (AES-NI / soft, picked by CPUID) | 0/5 | n/m | — | **5/5** | n/m |
| obfuse_xor² | XOR through MBA expressions | 0/5 | n/m | — | **5/5** | n/m |
| obfany² | XorShift keystream XOR, `read_volatile`; `obfstr!`/`obfwide!`/`obfnum!`/`obfstmt!` | 0/5 | n/m | — | **5/5** | n/m |

Release builds, ELF and PE x86-64 and AArch64, stripped and not; `size-lto`/`speed-lto` builds
of every crate are tested too. Static = reads the decoder's key and the call sites without
running anything; emulation = Unicorn, never runs the sample natively; dynamic = Frida in an
isolated VM.

<sub>¹ cryptify reads `CRYPTIFY_KEY` again at run time: with a custom key the sample only
decrypts when run with that variable set, and the key is not in the binary. `recover_cryptify`
detects the crate and says so.</sub>

<sub>² The 2026 crates (obfuse 1.0.1, obfany 0.1.5): 5/5 exact (no extra string) measured on ELF
x86-64 and ELF AArch64 (musl) release (stripped and not), size-lto and speed-lto (stripped), and on
a stripped static i686 musl release build; PE is built and tested by CI's `pe` job but not measured yet,
and FLOSS / dynamic recovery (`n/m`) not run on them. obfuse's default features name
`aes-256-gcm`, but with `polymorphic` on (the default) the macro never calls the AEAD -- the default
binary holds no AES instruction; `obfuse_aes` is the crate's real AES-256-GCM path (AES-NI on
x86-64; on AArch64 the `aes` crate's software AES, ~26k emulated instructions per string). obfuse
draws fresh random keys on every build: four rebuilds of obfuse and obfuse_aes recovered 5/5
each (the stray cipher-state strings two of them also showed are filtered since).</sub>

</details>

<details>
<summary><b>Build profiles nobody tuned for</b></summary>

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

</details>

<details>
<summary><b>Precision on real, unobfuscated binaries (21-binary corpus)</b></summary>

`scripts/measure_fp.py --pipeline --corpus` (static + emulation, 120 s budget): every decoded
string reported is a false positive. The corpus mixes C/C++, Go and Rust binaries, because the six
binaries the filters were developed against (bash, tar, xz, git, curl, ripgrep: 0) overstated
precision — Xvfb and a Go binary had 68 and 17 before the second review round.

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

</details>

<details>
<summary><b>Second machine, second toolchain</b></summary>

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

</details>

<details>
<summary><b>Third-party obfuscation crates: goldberg</b></summary>

`bench_src/` is hand-rolled ciphers; `obf_src/` is author-written programs obfuscated with the
crates a real analyst meets. [**goldberg**](https://crates.io/crates/goldberg) applies code-flow
obfuscation plus string and integer encryption; `recover.py` recovers its encrypted strings
**6/6** across ELF, PE and AArch64, release and `size-lto` (`tests/test_obf.py`, a CI job). The
strings are IOC-shaped and chosen not to collide with crate or metadata tokens, so the number
measures recovery rather than a coincidence of the literal text. More crates are planned
(`rustfuscator`, `obfuse`), goldberg first.

</details>

### Built in the open: two rounds of external review

An external review reproduced the published numbers exactly (107/107 tests, all 144 binaries
rebuilt with rustc 1.97) and found no cheating — but showed the tool was **overfitted to the
benchmark's shape**. The fix was not a list of new patterns: the emulator was rebuilt into a general
engine, and the benchmark gained the shapes and build profiles that exposed the problem, so it
cannot silently overfit again.

<details>
<summary><b>What the reviews found, and what changed</b></summary>

**Round 1 — generalisation**

| reviewer's held-out finding | before | now |
|---|:-:|:-:|
| litcrypt2, malware-style build (fat LTO, `opt-level="z"`, `panic=abort`), ELF and PE | **0/8** | **8/8** |
| litcrypt2, benchmark profile (`opt-level=3`) | 5/8 (decoded 8, text filter dropped 3) | **8/8** |
| mutex name `Global\…` rejected by the "looks like text" filter | dropped | kept, tagged `[mutex]` |
| IOC with a prefix (`heldout::10.13.37.42:8443`) rejected | dropped | kept, tagged `[ip]` |
| obfstr, strings not printed (`.to_string()`, comparisons) | 0–2 full, rest truncated | **8/8** |
| emulation capped at 400 functions (bash: 400/1671) | capped | no cap; ordered by decoder score, bounded by time |

- **scatter suite** (`bench_src/scatter_*`): 8 indicator-shaped strings — IP:port, Windows path,
  mutex, URL, user agent, argv flag, hive-less registry key, prefixed identifier — in a struct,
  `match` arms, comparisons that are never printed, and a branch that never runs.
- **build profiles**: every program is also built `size-lto` (`opt-level="z"`, fat LTO,
  `codegen-units=1`, `panic=abort`) and `speed-lto` (`opt-level=3`, same LTO settings).

`tests/test_scatter.py` holds recall **and precision** on all of it in CI (one job per format).

**Round 2 — what the first round still overfitted** ([VALIDATION.md §11](VALIDATION.md))

| finding | before | now |
|---|:-:|:-:|
| build profiles nobody tuned for (3 sets, 256 binaries) | 98–99 % exact, +18 junk | **1360/1360**, 0 junk |
| real binaries outside the development set: Xvfb (C) / age (Go) | 68 / 17 false positives | **1 / 2**; 29 on a 21-binary corpus |
| cargo, gdb, cmake | killed at 5.5–6 GB of memory | run: gdb 0.5 GB, cargo (19 MB `.text`) ≈1.1 GB per process |
| gdb's 15,760 functions in the 120 s budget | 136 emulated | ≈2,000 (2 CPUs) |

A CI job now measures false positives on a C/C++, Go and Rust corpus found on the runner.

</details>

---

## 🦠 Real malware

Validated on **nine real Rust-malware families** by hash — static + emulation only, samples
**never executed** and **never committed** (only hashes and results, in `gallery/results.jsonl`):

- **EDDIESTEALER** (PE) — **32 obfuscated strings**, including the hidden **C2 domain and URL path**
  (published IOCs) and the Windows API names it hides. Static tools and FLOSS: 0.
- **AmnesiaStealer** (macOS Mach-O) — the C2 exfil URL, crypto-clipper config, Safari-cookie /
  TCC-bypass staging paths and AppleScript for Telegram/Notes theft.
- **SPICA** (ColdRiver) — its registry persistence key.
- **RustyAttr** (Lazarus) — unpacked from a triple-packed zip→gz→cpio→app chain (and honestly no
  obfuscated strings: its evasion is extended-attribute script hiding, not string encryption).
- **KrustyLoader** — an honest non-hit: its config is encrypted at run time (cfb-mode), so static
  string deobfuscation correctly finds nothing; the metadata tier still recovers rustc 1.70.0, 18
  crates and a capability profile.

`gallery/manifest.json` (built from
[rust-malware-gallery](https://github.com/decoderloop/rust-malware-gallery)) maps **126 sample
hashes across 67 Rust malware families** to family, aliases and writeups, for evaluation and
hash → family attribution. Details: [VALIDATION.md §12, §18](VALIDATION.md).

---

## 🔬 How it works

`recover.py` runs everything that applies and merges the results:

```mermaid
flowchart LR
    B["Rust binary<br/>ELF · PE · Mach-O<br/>x86-64 · ARM64 · x86"] --> S["Static call-site recovery<br/>key + ciphertext by dataflow"]
    B --> E["Unicorn emulation<br/>runs functions, never the binary"]
    B --> L["Stack strings +<br/>Rust literals"]
    B --> M["Rust metadata<br/>rustc · crates · panic sites"]
    S --> R["Merge, filter,<br/>tag indicators"]
    E --> R
    L --> R
    M --> T["SOC triage card<br/>LOW / MEDIUM / HIGH"]
    R --> T
    R --> O1["--json / --jsonl"]
    R --> O2["FLOSS results JSON"]
    R --> O3["Ghidra plate comments"]
    T --> O4["llm_triage.py<br/>(facts only, local or API)"]
```

| engine | what it does | speed |
|---|---|---|
| **Static call-site recovery** (`recover_callsite.py`, `recover_arm64.py`, `recover_cryptify.py`) | finds the decode loop, resolves the key and each call's ciphertext with ABI-aware dataflow, decodes | seconds |
| **Emulation** (`recover_emulate.py`, Unicorn) | runs *functions* of the binary (never the binary) and collects the plaintext the code builds | bounded by `--time-budget` |
| **Stack strings / Rust literals** | plain strings cut at their real (pointer, length) boundaries instead of `strings`' glued runs | seconds |
| **Dynamic** (`recover_dynamic.py`, Frida) | runs the sample and diffs its memory — cipher-agnostic, **isolated VM only** | runtime |

<details>
<summary><b>Inside the emulation engine</b></summary>

- **Static call-site recovery** is fast with exact attribution (decoder, call site, ciphertext), but
  only as good as its idiom recognisers: it recognises the benchmark's release idioms, not every
  build profile — that is what emulation is for.
- **Emulation** is the general engine, x86-64, AArch64 and 32-bit x86, across ELF, PE and Mach-O.
  What makes it work on real Rust code:
  - *real calls*: callees run up to 8 levels deep, so a call site runs its out-of-line decoder
    (`lc!` → `decrypt_bytes` → `Iterator::next`); each callee has an instruction budget and a
    callee that overruns it (a spinning lock, a loop over a fake length) or faults is abandoned
    and returns 0, with the caller's registers restored;
  - *a loader*: relocations applied (ELF `RELATIVE`/`GLOB_DAT`/`JUMP_SLOT`, PE base
    relocations), every import pointed at a named trampoline, `.bss` zeroed, thread-local
    storage (fs/gs/`TPIDR_EL0`) set up, AArch64 outlined atomics switched to their LSE path,
    and the image's **global constructors** (ELF `.init_array`/`.ctors`, Mach-O
    `__mod_init_func`) replayed before the sweep so state a loader sets before `main` — e.g. an
    anti-emulation marker a constructor writes, which an isolated-function analyzer would miss
    and whose absence poisons a string key — is in place for every run;
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

Every recovered string says where it came from, indicator shapes are tagged, and `--floss-json`
writes a FLOSS results document so the strings appear in FLOSS next to the static ones: view it with
`floss -l out.json` (checked against FLOSS 3.2.0).

</details>

<details>
<summary><b>Triage, AI-assisted triage, VM detection and devirtualization</b></summary>

**`scripts/soc_triage.py <binary>`** prints a one-screen SOC triage card — format/arch, Rust
toolchain + panic-site count, a crate capability fingerprint (networking / crypto / recon /
persistence / staging), indicators grouped by tag with benign Rust std/compiler paths filtered out,
a decoded-string sample, and a calibrated LOW/MEDIUM/HIGH triage *signal* with its evidence (an
analyst aid, not a verdict). The signal needs **obfuscation evidence** to rise above LOW: decoded
strings (one indicator-shaped, or three or more that are not just formatted from the binary's plain
literals — fewer is within the engines' false-positive floor on big benign binaries), an
indicator-shaped stack-built string, or virtualized functions in a binary that does not link an
interpreter crate (regex engines, wasm runtimes, script VMs look exactly like a VM). Indicator-shaped
*plain literals* (an update URL, an index URL) are listed separately as literal indicators and never
scored, and the ubiquitous HTTP/TLS/hashing/OS-binding crates (tokio, hyper, rustls, ring, base64,
windows-sys) are shown in the fingerprint but add nothing — so unobfuscated tools like `rustup`,
`uv` or `rg` come out LOW. `--fast` skips every decoding pass (static call-site recovery, stack
strings, emulation, the virtualization scan) and keeps metadata + literal indicators; literal
splitting scales with size (measured: 0.6 s on a 0.4 MB canary, 6 s on `rg` 5 MB, 19 s on `rustup`
20 MB, 100 s on `uv` 66 MB), and its signal is always LOW with that caveat.
`--json` emits a record for a SIEM/case system; `--fail-on MEDIUM|HIGH` exits 1 at that level.
Static + emulation only; never executes the sample.

**`scripts/llm_triage.py <binary>`** hands *only* the deterministically recovered facts (the triage
card above — never the raw binary) to an LLM and asks for a grounded verdict, likely capabilities
tied to the evidence, candidate ATT&CK techniques, what is uncertain, and next steps. The
deterministic facts stay ground truth; the LLM note is a clearly labelled hypothesis, and the model
is instructed not to invent indicators. Backends auto-detect: a **local** OpenAI-compatible server
(`RUST_DEOBF_LLM_BASE=http://localhost:11434/v1` for Ollama/vLLM — so malware data never leaves the
host; when it is set it wins over any `ANTHROPIC_API_KEY`/`OPENAI_API_KEY` in the environment
unless `RUST_DEOBF_LLM=anthropic|openai` says otherwise), the Anthropic or OpenAI APIs, or, with no
key, an **offline** mode that prints the grounded prompt to paste into any LLM plus a deterministic
rule-based note. Recovered strings are attacker-controlled text, so they are sent inside
`<untrusted_evidence>` tags, truncated to 200 characters each and capped per list, and the system
prompt tells the model to treat them as data, never as instructions.

**`scripts/detect_vm.py <binary>`** flags functions hidden behind a **bytecode VM (code
virtualization)** — the VMProtect/Themida/Tigress technique, and RustCloak's `virt`. It keys on the
interpreter's machine-code fingerprint: a *threaded dispatch* (many indirect branches through one
register) plus dense bytecode byte-fetches, and folds into the triage card as a signal. Precise on
x86-64 (`ls`/`grep`/`openssl`/`bash` clean; it does flag CPython's eval loop — correctly, that
genuinely is an interpreter); AArch64 detection is the next round.

**`premium/lift_vm.py <binary>`** (premium — AGPL/commercial) **devirtualizes** a detected VM
function: it finds the embedded bytecode blob (anchored by its code cross-reference, since the blobs
are packed in `.rodata`), decodes the register-machine instructions — including the control-flow
opcodes, so branches and loops come back as labelled `jmp`/`jnz` with the SSA PHI copies visible —
and prints the function's logic as a compact VM-assembly listing instead of a dispatch loop. It
decodes the width-tagged format too (`load.i8 rD, [rA]`, `store.i8 [rA], rB`, `add.i32`). When the
VM's opcode bytes are **randomized per build**, the lifter **recovers the opcode map** by parsing
the dispatch jump table and classifying each handler by its native instruction (an `idiv` with the
remainder stored → SREM, a rip-relative pool load → CONST, …). When the operand bytes are also
**encrypted per build**, it recovers the XOR key from the interpreter and **raises the result to C
pseudocode**, resolving the constant pool and folding temporaries into one expression.
Control-flow bodies are raised from `if/goto` toward structured `do/while` + `if` where the flow is
reducible (an `-O2`-unrolled loop nest is left as `if/goto`). **`premium/devirt_emulate.py`**
recovers the VM's instruction set by *running* the interpreter under Unicorn and observing opcode
semantics instead of pattern-matching its native code, with a correctness gate that re-executes the
recovered program. x86-64; recovery is demonstrated end-to-end on a function, with full per-binary
coverage ongoing.

**Ghidra integration.** `scripts/ghidra_run.sh <binary>` runs the recovery and annotates a Ghidra
project headless: every decoding function gets a plate comment listing its recovered strings and a
bookmark, functions with default `FUN_`/`SUB_` names are renamed after their strongest indicator, and
identified library functions get `lib_<name>` renames. It is a PyGhidra script (Ghidra 11.3+ dropped
Jython); verified headless on Ghidra 12.1.3. IDA and Binary Ninja exporters are planned next.

</details>

---

## 🚧 Honest limitations

This is research code, not a finished product. The ones that matter most:

- **Emulation is not execution.** Arguments are fake, so code that only decodes for specific
  inputs (a key from the network, a path that depends on the environment) can be missed.
- **Large binaries are covered partly** within the default 120 s budget (≈2,000 of gdb's 15,760
  functions on 2 CPUs). The output reports coverage; raise `--time-budget` or add CPUs.
- **Precision is good, not perfect**: 29 false positives on a 21-binary C/C++, Go and Rust corpus.
- **32-bit PE is still open**: emulation of the Windows std path is not yet reliable there, so PE32
  is routed to literal recovery only (32-bit x86 ELF and Mach-O are verified 5/5).
- **Runtime-keyed configs** (custom-key cryptify, KrustyLoader's cfb-mode config) need dynamic
  recovery with that environment.
- **Platforms**: Linux (x86-64, ARM64) and Windows x64 are tested. On Windows-on-ARM use x64
  Python — native ARM64 Python has no `unicorn` / `capstone<6` wheels yet.

<details>
<summary><b>Full list</b></summary>

- **Emulation is not execution.** Path exploration flips branches one at a time inside the function
  it starts from, within budgets (8 runs per function, instruction budgets per run and per callee).
- **Large binaries**: emulation runs Unicorn with Python hooks: ≈1 M emulated instructions/s per
  process on the benchmark binary (x86-64 Linux, Unicorn 2.1.4; ≈0.65 M before the Oct 2026 hook
  optimisations). The time is the Python hooks, not the engine (`scripts/bench_emu.py`).
  A first pass runs every function once with a small budget, a second explores decoder-like
  functions, and binaries with 2,000+ functions are split over processes (`RUST_DEOBF_WORKERS`).
  `--max-ram` trades that speed back for memory on a small machine.
- **Static recovery is idiom-bound** by design; it covers the release idioms of the benchmark
  crates. Under `size-lto` most keyed decoders are recovered by emulation, not statically.
- **musl runtime signatures** describe the musl that current rustc bundles; another version may
  need `gen_runtime_sigs.py` re-run on an unstripped build.
- **Precision**: what is left is run-time assembled text the filters do not model (see Results).
- **Overlap rules**: which of several overlapping views of a buffer is the string is settled by the
  **buffer address** each view was materialised at (recorded during emulation), so views of one
  buffer are told from two buffers that merely share a prefix; the text/write-age heuristics remain
  only as the fallback where an address is unknown (VALIDATION.md §11).
- **Real malware**: on large real binaries a minority of emulation outputs are garbled std-internal
  fragments. **32-bit x86 ELF** and **Mach-O** (x86-64 and arm64) are fully emulated, verified at
  **5/5 on all six canary crates** for `i686-unknown-linux-gnu` (VALIDATION.md §14,
  `tests/test_32bit.py`) and for `aarch64-apple-darwin` (§15, `tests/test_macho.py`). **32-bit PE**:
  the loader handles it (PE32 `HIGHLOW` relocations, imagebase rebasing) but emulation of the
  Windows std path gives 0–2/5 plus false positives, so emulation is skipped with a note until it is
  verified 5/5 (VALIDATION.md §14). FickleStealer is also packed, so it needs unpacking regardless
  of arch. The benchmark's obfuscation crates model one real pattern, not all of them.
- **Library-function identification** (`recover_libfuncs.py`) names std/crate functions by byte
  signature on ELF, PE and Mach-O (x86-64, AArch64, 32-bit x86); the bundled DBs are for one
  toolchain, rustc 1.97 (linked-build signatures for x86-64, plus prebuilt-std signatures for
  x86_64 Linux, aarch64 Linux and x86_64 windows-gnu in `scripts/data/libfunc_sigs_std.json.gz`,
  ~600 KB gzip), and are used only for a binary of that rustc (same minor): signatures of another
  rustc mislabel more than they name. For any other rustc / target / crate set build a DB per
  binary with `gen_sigdb.py` and pick it with `--db auto`; generic-heavy labels flatten their
  type args.

Full matrix: `RESULTS.md` · reproducible metrics: `METRICS.md` · real-binary validation and the
generalisation work: `VALIDATION.md` (§10) · artifact tiers: `ARTIFACT_TIERS.md`.

</details>

---

## 🧪 Reproduce the benchmark

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
python3 scripts/fuzz_recover.py --time 300        # robustness fuzz: malformed ELF/PE/Mach-O
python3 scripts/redblue_loop.py --rounds 20       # RustCloak hides random strings, rust-deobf recovers
```

`fuzz_recover.py` fuzzes rust-deobf *itself* — it mutates the committed binary fixtures and feeds the
malformed results through the whole loader/emulator path, each input isolated with an rlimit and a
timeout, so a crafted binary that would hang or crash the analyzer in a SOC pipeline is caught as a
finding (and saved for `--reproduce`). It found and we fixed five such hangs/OOMs; see
[VALIDATION.md §48](VALIDATION.md). `--atheris` drives libFuzzer when the `atheris` package is
installed; otherwise a standalone mutation driver runs.

`redblue_loop.py` is the recovery-side fuzzer and the overfitting answer: each round generates a
*random* benign Rust program that plants known indicator strings (documentation placeholders only),
compiles it under a *random* RustCloak configuration (needs the RustCloak plugin + a matching nightly
`rustc`), and checks rust-deobf recovers every planted string — misses are saved as regression
fixtures. See [VALIDATION.md §49](VALIDATION.md).

<details>
<summary><b>Build details</b></summary>

`build_all.sh` profiles: `debug`, `release`, `size-lto`, `speed-lto` (canary suite) and
`release`, `size-lto`, `speed-lto` (scatter suite); `PROFILES=...` and `ONLY=...` narrow it,
`SKIP_EXISTING=1` keeps what is built. Rust targets: `x86_64-pc-windows-gnu` (with the
`mingw-w64` linker), `aarch64-unknown-linux-musl` (linked by the bundled `rust-lld`) and, with
`ARM64_GNU=1`, `aarch64-unknown-linux-gnu`. `BUILD_DIR=...` builds elsewhere and
`RUST_DEOBF_BUILD=...` points the tests at it, so two toolchains can be compared side by side.
FLOSS is only needed to reproduce the baseline column (`scripts/run_floss.py`).

Dynamic recovery must run inside a dedicated, isolated VM (Kali or Windows), never on your
host: snapshot before detonation, revert after.

</details>

---

## 🛡️ Scope / ethics

Defensive reverse-engineering for malware triage. The benchmark and test inputs are **benign**
programs built from author-written sources (`bench_src/`, every planted string listed in
`bench_src/manifest.json`) — no payloads, no live indicators. The tooling reads and decodes binaries
and produces no offensive capability. Real-malware validation (`gallery/`) is **static + emulation
only**: samples are **never executed** and **never committed** — only their hashes and the results.
Run dynamic analysis solely inside an isolated VM, against samples you are authorised to analyse.

## 📜 License

**Open-core.** The core — everything outside `premium/` — is under the Apache License 2.0 (see
[`LICENSE`](LICENSE)): a standard, OSI-approved permissive license, free for any use including
commercial. Modules under `premium/` (VM devirtualization, control-flow de-flattening, MBA
simplification) are dual-licensed **AGPL-3.0-or-later OR Commercial**. See
[`LICENSING.md`](LICENSING.md) for the model and [`CLA.md`](CLA.md) for contributing.

The defensive-use guidance in this README (run only in an isolated VM, benign test inputs, samples
referenced by hash) is project guidance for using the tool responsibly, not a license term.

---

<div align="center">

**If rust-deobf recovered something your other tools missed, a ⭐ helps others find it.**

Issues and PRs welcome — especially new obfuscation crates and Rust samples (by hash) that beat it.

</div>
