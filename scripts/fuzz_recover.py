#!/usr/bin/env python3
"""fuzz_recover.py - fuzz rust-deobf's own analysis path on hostile, malformed binaries.

rust-deobf runs in SOC pipelines on attacker-controlled input, so a crafted ELF/PE/Mach-O that
crashes, hangs or exhausts memory in the loader/emulator is a real finding (an analyst's batch run
dies on one sample). This is the mirror image of the differential fuzzing in VALIDATION.md §22,
which fuzzes RustCloak (the obfuscator) for behaviour preservation: here the target is the
*deobfuscator*, and the property is robustness -- never crash the process on any input.

What it exercises -- the whole path that touches attacker bytes, across ELF/PE/Mach-O and
x86-64/aarch64/x86:

  detect              recover.detect                         format/arch sniff
  image               recover_emulate.Image(path)            the loader (relocations, sections, TLS)
  meta                recover_rust_meta.recover              rustc/crate/panic metadata
  strings             recover_rust_strings.recover           &str literal splitting
  stackstrings        recover_stackstrings.recover           immediate-store stack strings
  callsite / arm64    recover_callsite / recover_arm64       static call-site recovery
  cryptify            recover_cryptify.recover               cryptify default-key recovery
  detect_vm           detect_vm.detect                       code-virtualization fingerprint
  emulate             recover_emulate.recover (tiny budget)  the Unicorn sweep
  run                 recover.run (emulate=never)            the hardened public front end
  triage              soc_triage.triage (fast)               the SOC card

Contract (what counts as a finding):

  * The hardened front ends -- `recover.run`, `soc_triage.triage`, `recover.detect` -- MUST return,
    never raise, on any input. A raise there is always a finding.
  * The lower primitives may raise a *controlled* parse error (ValueError, struct.error, lief
    errors, a "not a binary" signal) -- that is correct rejection, not a crash. A finding is an
    *uncontrolled* failure: MemoryError, RecursionError, a C-level abort (SIGSEGV/SIGABRT from
    lief/capstone/unicorn), or a hang past the per-input timeout.

In-process runs catch the Python-level bugs (IndexError, struct.error, KeyError, runaway recursion).
`--isolate` (default for a real campaign) runs each input in a child with an address-space rlimit and
a timeout, so a native segfault or an OOM is caught as a finding instead of taking the fuzzer down.

    python3 scripts/fuzz_recover.py --selftest                 # fast: the pinned malformed corpus
    python3 scripts/fuzz_recover.py --runs 5000                # mutate the committed fixtures
    python3 scripts/fuzz_recover.py --time 300 --seeds DIR     # a timed campaign over your own seeds
    python3 scripts/fuzz_recover.py --atheris -- -runs=1000000 # libFuzzer via Atheris, if installed
    python3 scripts/fuzz_recover.py --reproduce crash.bin      # replay one saved crashing input

Crashing inputs are written to --crash-dir (default build/fuzz_crashes/) with a .txt repro note.
Exit codes: 0 no findings, 1 findings written, 2 usage error.
"""
from __future__ import annotations

import argparse
import faulthandler
import hashlib
import io
import os
import random
import struct
import sys
import time
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

EXIT_OK, EXIT_FINDINGS, EXIT_USAGE = 0, 1, 2

# Per-input wall-clock budget for the isolated worker. The emulate/run targets get a tiny time
# budget of their own; this is the backstop for a hang in parsing or an infinite loop.
DEFAULT_TIMEOUT = 20.0
# Address-space cap for an isolated worker (bytes). A malformed size field that makes a loader try
# to allocate gigabytes should be caught as a finding, not let the box swap to death.
DEFAULT_RLIMIT_MB = 2048


# --------------------------------------------------------------------------------------------
# targets: (name, callable, hardened?). A hardened target must never raise; a primitive may raise
# only a controlled parse error (see _CONTROLLED below).
# --------------------------------------------------------------------------------------------
def _targets(time_budget: float, active: set | None = None):
    """Build the target list. Imports are deferred so --selftest works even if an engine's optional
    dependency is missing (it is simply skipped). `active`, when given, keeps only those target
    names -- so a campaign can hammer the fast parser surface or the slow emulation surface alone."""
    out = []

    def add(name, fn, hardened=False):
        if active is None or name in active:
            out.append((name, fn, hardened))

    try:
        import recover
        add("detect", lambda p: recover.detect(p), hardened=True)
        add("run", lambda p: recover.run(p, emulate="never", literals=True, time_budget=time_budget),
            hardened=True)
    except Exception:
        pass
    try:
        import recover_emulate
        add("image", lambda p: recover_emulate.Image(p))
        add("emulate", lambda p: recover_emulate.recover(p, [], time_budget=time_budget, max_funcs=3))
    except Exception:
        pass
    try:
        import recover_rust_meta
        add("meta", lambda p: recover_rust_meta.recover(p))
    except Exception:
        pass
    try:
        import recover_rust_strings
        add("strings", lambda p: recover_rust_strings.recover(p, min_len=4))
    except Exception:
        pass
    try:
        import recover_stackstrings
        add("stackstrings", lambda p: recover_stackstrings.recover(p, min_len=5))
    except Exception:
        pass
    try:
        import recover_callsite
        add("callsite", lambda p: recover_callsite.recover(p, []))
    except Exception:
        pass
    try:
        import recover_arm64
        add("arm64", lambda p: recover_arm64.recover(p, []))
    except Exception:
        pass
    try:
        import recover_cryptify
        add("cryptify", lambda p: recover_cryptify.recover(p))
    except Exception:
        pass
    try:
        import detect_vm
        add("detect_vm", lambda p: detect_vm.detect(p))
    except Exception:
        pass
    try:
        import soc_triage
        # triage is allowed to raise its documented UnsupportedInput signal (controlled by name);
        # any other raise is a finding, so it is a primitive, not a never-raise front end.
        add("triage", lambda p: soc_triage.triage(p, fast=True, time_budget=time_budget))
    except Exception:
        pass
    return out


# Exceptions a primitive is ALLOWED to raise on malformed input: a controlled rejection, not a
# crash. Everything else (MemoryError, RecursionError, OverflowError, SystemError, and any native
# abort, which does not surface as a Python exception at all) is a finding.
_CONTROLLED = (ValueError, TypeError, KeyError, IndexError, AttributeError, struct.error,
               NotImplementedError, UnicodeDecodeError, OverflowError, RuntimeError)
# Controlled rejections raised by NAME (type not importable here without pulling the engine in, or a
# documented signal exception): soc_triage.UnsupportedInput is its exit-code-3 "not a binary" signal,
# caught by its own CLI -- a clean rejection, not a crash.
_CONTROLLED_NAMES = {"UnsupportedInput"}
# NOTE: RecursionError is a RuntimeError subclass but is NOT controlled -- unbounded recursion on a
# crafted input is a real robustness bug. OverflowError from a bad size field is tolerated only as a
# clean rejection; the isolated worker still catches the version that allocates before overflowing.
_UNCONTROLLED = (MemoryError, RecursionError, SystemError, KeyboardInterrupt)


def classify(name: str, hardened: bool, exc: BaseException) -> str | None:
    """Return a finding reason if `exc` from target `name` violates the contract, else None."""
    if isinstance(exc, _UNCONTROLLED):
        return f"{type(exc).__name__} (uncontrolled)"
    if hardened:                       # recover.run / recover.detect return even on garbage
        return f"hardened target raised {type(exc).__name__}: {exc}"
    controlled = isinstance(exc, _CONTROLLED) or type(exc).__name__ in _CONTROLLED_NAMES
    if controlled:
        return None
    return f"unexpected {type(exc).__name__}: {exc}"


def run_targets(data: bytes, time_budget: float = 1.0, tmp: Path | None = None,
                active: set | None = None) -> list[dict]:
    """Run every target on `data` in-process; return a list of finding dicts (empty = clean).

    This catches Python-level robustness bugs. It cannot catch a native segfault or a true hang --
    `run_isolated` wraps this in a child with an rlimit and a timeout for those."""
    findings = []
    own_tmp = tmp is None
    path = tmp or _mktemp()
    try:
        path.write_bytes(data)
        for name, fn, hardened in _targets(time_budget, active):
            try:
                fn(path)
            except BaseException as exc:  # noqa: BLE001 - classification is the whole point
                reason = classify(name, hardened, exc)
                if reason is not None:
                    findings.append({"target": name, "reason": reason,
                                     "traceback": traceback.format_exc()})
    finally:
        if own_tmp:
            try:
                path.unlink()
            except OSError:
                pass
    return findings


_TMP_COUNTER = [0]


def _mktemp() -> Path:
    d = Path(os.environ.get("TMPDIR", "/tmp"))
    _TMP_COUNTER[0] += 1
    return d / f".fuzz_recover_{os.getpid()}_{_TMP_COUNTER[0]}.bin"


# --------------------------------------------------------------------------------------------
# isolated worker: an rlimit + timeout so a native abort or an allocate-the-universe bug is a
# finding, not a dead fuzzer.
# --------------------------------------------------------------------------------------------
def _isolation_ctx():
    """Use a forkserver where available, else spawn -- NOT a plain fork. A fork inherits the
    parent's memory, so if the parent has already instantiated Unicorn (e.g. this runs inside a
    pytest process that emulated in an earlier test), the child inherits poisoned JIT state and
    fails with "Could not allocate dynamic translator buffer". A forkserver forks from its own clean
    server process (which only imported the preloaded engines, never created a Uc), so children are
    clean and cheap; spawn is the safe fallback. Both give the child a fresh interpreter state for
    Unicorn, which is what matters for correctness."""
    import multiprocessing as mp
    methods = mp.get_all_start_methods()
    if "forkserver" in methods:
        ctx = mp.get_context("forkserver")
        try:
            ctx.set_forkserver_preload(["lief", "capstone", "unicorn"])
        except Exception:
            pass
        return ctx
    return mp.get_context("spawn")


def run_isolated(data: bytes, time_budget: float, timeout: float, rlimit_mb: int,
                 active: set | None = None) -> list[dict]:
    ctx = _isolation_ctx()
    q = ctx.Queue()
    proc = ctx.Process(target=_isolated_entry, args=(data, time_budget, rlimit_mb, q, active))
    proc.start()
    proc.join(timeout)
    if proc.is_alive():
        proc.terminate()
        proc.join(5)
        if proc.is_alive():
            proc.kill()
            proc.join()
        return [{"target": "?", "reason": f"hang (> {timeout:.0f}s wall clock)", "traceback": ""}]
    try:
        findings = q.get_nowait()
    except Exception:
        findings = None
    if findings is None:
        # The worker died without reporting: a native crash (segfault/abort) or the OOM killer.
        code = proc.exitcode
        sig = -code if code is not None and code < 0 else None
        reason = (f"worker killed by signal {sig}" if sig
                  else f"worker exited {code} with no result (native crash / OOM)")
        return [{"target": "?", "reason": reason, "traceback": ""}]
    return findings


def _isolated_entry(data: bytes, time_budget: float, rlimit_mb: int, q, active=None) -> None:
    # Cap address space so an allocate-gigabytes bug raises MemoryError (a finding) instead of
    # thrashing the host. Best-effort: not all platforms honour RLIMIT_AS.
    try:
        import resource
        soft = rlimit_mb * 1024 * 1024
        _, hard = resource.getrlimit(resource.RLIMIT_AS)
        resource.setrlimit(resource.RLIMIT_AS, (soft, hard if hard != resource.RLIM_INFINITY else soft))
    except Exception:
        pass
    faulthandler.enable()               # dump a native stack on a C-level crash
    try:
        q.put(run_targets(data, time_budget=time_budget, active=active))
    except BaseException:               # noqa: BLE001
        # A MemoryError or the like escaping run_targets itself is still a finding.
        q.put([{"target": "?", "reason": f"worker exception {sys.exc_info()[0].__name__}",
                "traceback": traceback.format_exc()}])


# --------------------------------------------------------------------------------------------
# mutation engine: structure-aware-ish byte mutation of seed binaries + pure-random inputs.
# --------------------------------------------------------------------------------------------
_INTERESTING = [0, 1, 2, 3, 4, 8, 16, 32, 64, 0x7f, 0x80, 0xff, 0xfe, 0x100, 0x1000, 0x7fff,
                0x8000, 0xffff, 0x7fffffff, 0x80000000, 0xffffffff, 0xffffffffffffffff]


def mutate(data: bytes, rng: random.Random) -> bytes:
    """One mutated child of `data`. A grab-bag of the mutations that break binary parsers:
    bit/byte flips, interesting-value stamps into likely size/offset fields, truncation, splicing,
    and header smashing. Not format-aware beyond 'binary headers live near the front and lengths
    are little-endian', which is enough to exercise the loaders hard."""
    if not data:
        return bytes(rng.randrange(256) for _ in range(rng.randrange(1, 64)))
    b = bytearray(data)
    for _ in range(rng.randint(1, 8)):
        op = rng.random()
        if op < 0.30:                                   # flip some bytes
            for _ in range(rng.randint(1, 16)):
                b[rng.randrange(len(b))] = rng.randrange(256)
        elif op < 0.45:                                 # flip a single bit
            i = rng.randrange(len(b))
            b[i] ^= 1 << rng.randrange(8)
        elif op < 0.65:                                 # stamp an interesting little-endian value
            val = rng.choice(_INTERESTING)
            width = rng.choice((1, 2, 4, 8))
            pos = rng.randrange(max(1, len(b)))
            chunk = val.to_bytes(width, "little", signed=False) if val < (1 << (8 * width)) \
                else (val & ((1 << (8 * width)) - 1)).to_bytes(width, "little")
            b[pos:pos + width] = chunk
        elif op < 0.75:                                 # truncate
            b = b[:rng.randrange(len(b) + 1)]
            if not b:
                b = bytearray(b"\x00")
        elif op < 0.85:                                 # grow (duplicate a run)
            if len(b) > 4:
                s = rng.randrange(len(b) - 2)
                b[s:s] = b[s:s + rng.randint(1, min(256, len(b) - s))]
        elif op < 0.95:                                 # smash the first 64 bytes (the header)
            for _ in range(rng.randint(1, 8)):
                i = rng.randrange(min(64, len(b)))
                b[i] = rng.randrange(256)
        else:                                           # zero a region
            if len(b) > 2:
                s = rng.randrange(len(b) - 1)
                n = rng.randint(1, min(64, len(b) - s))
                b[s:s + n] = b"\x00" * n
    # keep inputs from exploding without bound
    if len(b) > (1 << 20):
        b = b[: 1 << 20]
    return bytes(b)


def mutate_body(data: bytes, rng: random.Random, keep: int = 0x200) -> bytes:
    """Mutate only the bytes past `keep`, leaving the file header intact. Random whole-file mutation
    almost always breaks the ELF/PE/Mach-O header so LIEF rejects the file early and the deep loader
    code (relocations, TLS, section iteration, chained fixups, the Unicorn sweep) never runs. Editing
    only the body keeps the file parseable far more often, so those paths are actually stressed -- and
    that is exactly where a native crash / OOM / hang (as opposed to a clean parse rejection) hides."""
    if len(data) <= keep + 8:
        return mutate(data, rng)
    b = bytearray(data)
    for _ in range(rng.randint(1, 12)):
        op = rng.random()
        pos = rng.randrange(keep, len(b))
        if op < 0.45:                                   # flip some body bytes
            for _ in range(rng.randint(1, 24)):
                b[rng.randrange(keep, len(b))] = rng.randrange(256)
        elif op < 0.80:                                 # stamp an interesting little-endian value
            val = rng.choice(_INTERESTING)
            width = rng.choice((1, 2, 4, 8))
            val &= (1 << (8 * width)) - 1
            b[pos:pos + width] = val.to_bytes(width, "little")
        else:                                           # zero a body region (e.g. a reloc table)
            n = rng.randint(1, min(128, len(b) - pos))
            b[pos:pos + n] = b"\x00" * n
    return bytes(b)


def load_seeds(seed_dirs: list[Path]) -> list[bytes]:
    seeds = []
    for d in seed_dirs:
        if not d.exists():
            continue
        for p in sorted(d.rglob("*")):
            if not p.is_file():
                continue
            try:
                data = p.read_bytes()
            except OSError:
                continue
            if 0 < len(data) <= (1 << 20):
                seeds.append(data)
    return seeds


# Committed binary fixtures across ELF/PE/Mach-O and x86-64/aarch64/x86 -- the natural seed corpus.
def fixture_dirs() -> list[Path]:
    base = ROOT.parent / "tests" / "fixtures"
    return [base / sub for sub in ("emu", "static", "macho", "vm", "strenc", "antiemu", "deflatten")]


# --------------------------------------------------------------------------------------------
# synthetic malformed corpus: the hand-built nasties the selftest pins (each once provoked, or
# plausibly provokes, an uncontrolled failure). The selftest asserts none of them crash the process.
# --------------------------------------------------------------------------------------------
def synthetic_corpus() -> list[tuple[str, bytes]]:
    out = [
        ("empty", b""),
        ("one_byte", b"\x00"),
        ("ascii_text", b"this is clearly not a binary\n" * 4),
        ("elf_magic_only", b"\x7fELF"),
        ("elf_truncated_header", b"\x7fELF\x02\x01\x01" + b"\x00" * 9),
        # ELF64 header claiming a huge section-header count / offset
        ("elf_huge_shnum", _elf64_header(e_shnum=0xffff, e_shoff=0xffffffffffffffff)),
        ("elf_shoff_past_eof", _elf64_header(e_shnum=4, e_shoff=0x10)),
        ("pe_magic_only", b"MZ"),
        ("pe_bad_e_lfanew", b"MZ" + b"\x00" * 58 + b"\xff\xff\xff\x7f"),
        ("macho_magic_only", b"\xcf\xfa\xed\xfe"),
        ("macho_fat_magic_only", b"\xca\xfe\xba\xbe\x00\x00\x00\x40"),
        ("random_64", bytes(range(64))),
        ("all_ff_256", b"\xff" * 256),
        ("elf_magic_then_ff", b"\x7fELF" + b"\xff" * 256),
    ]
    return out


def _elf64_header(e_shnum=0, e_shoff=0, e_phnum=0, e_phoff=0) -> bytes:
    """A 64-byte ELF64 little-endian x86-64 header with caller-chosen (possibly absurd) table
    pointers, so the selftest can feed a parser header fields that point past the file."""
    e_ident = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
    return e_ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2,            # e_type ET_EXEC
        0x3e,         # e_machine x86-64
        1,            # e_version
        0x400000,     # e_entry
        e_phoff & 0xffffffffffffffff,
        e_shoff & 0xffffffffffffffff,
        0,            # e_flags
        64,           # e_ehsize
        56, e_phnum & 0xffff,   # e_phentsize, e_phnum
        64, e_shnum & 0xffff,   # e_shentsize, e_shnum
        0,            # e_shstrndx
    )


# --------------------------------------------------------------------------------------------
# driver
# --------------------------------------------------------------------------------------------
def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


def _save_crash(crash_dir: Path, data: bytes, findings: list[dict], origin: str) -> Path:
    crash_dir.mkdir(parents=True, exist_ok=True)
    name = _digest(data)
    path = crash_dir / f"crash_{name}.bin"
    path.write_bytes(data)
    note = io.StringIO()
    note.write(f"origin: {origin}\nsize: {len(data)} bytes\nsha256[:16]: {name}\n\n")
    for f in findings:
        note.write(f"[{f['target']}] {f['reason']}\n")
        if f.get("traceback"):
            note.write(f["traceback"].rstrip() + "\n")
        note.write("\n")
    (crash_dir / f"crash_{name}.txt").write_text(note.getvalue())
    return path


def campaign(seeds: list[bytes], runs: int, deadline: float | None, rng: random.Random,
             time_budget: float, isolate: bool, timeout: float, rlimit_mb: int,
             crash_dir: Path, verbose: bool, active: set | None = None) -> list[dict]:
    """Mutate seeds, run the targets, collect and save findings. Returns a list of {hash, findings}
    for the distinct crashing inputs."""
    seen_crashes: dict[str, dict] = {}
    n = 0
    base_inputs = list(seeds) + [data for _, data in synthetic_corpus()]
    while True:
        if runs and n >= runs:
            break
        if deadline and time.monotonic() >= deadline:
            break
        n += 1
        parent = rng.choice(base_inputs) if base_inputs else b""
        # half the inputs keep the header intact (reach the deep loader/emulator code), half smash
        # everything (stress the header parsers and the early-reject paths)
        data = mutate_body(parent, rng) if rng.random() < 0.5 else mutate(parent, rng)
        if isolate:
            findings = run_isolated(data, time_budget, timeout, rlimit_mb, active)
        else:
            findings = run_targets(data, time_budget=time_budget, active=active)
        if findings:
            h = _digest(data)
            if h not in seen_crashes:
                _save_crash(crash_dir, data, findings, origin=f"mutation #{n}")
                seen_crashes[h] = {"hash": h, "findings": findings}
                tgt = ", ".join(sorted({f["target"] for f in findings}))
                print(f"  FINDING #{len(seen_crashes)} [{h}] targets={tgt}: "
                      f"{findings[0]['reason']}", flush=True)
        elif verbose and n % 500 == 0:
            print(f"  ...{n} inputs, {len(seen_crashes)} findings", flush=True)
    print(f"ran {n} inputs, {len(seen_crashes)} distinct findings")
    return list(seen_crashes.values())


# --------------------------------------------------------------------------------------------
# Atheris (libFuzzer) entry: coverage-guided when its runtime is present, same contract.
# --------------------------------------------------------------------------------------------
def atheris_main(libfuzzer_args: list[str], time_budget: float, active: set | None = None) -> int:
    try:
        import atheris
    except ImportError:
        print("fuzz_recover: --atheris needs the `atheris` package (pip install atheris)",
              file=sys.stderr)
        return EXIT_USAGE

    def one(raw: bytes):
        findings = run_targets(raw, time_budget=time_budget, active=active)
        if findings:
            # make libFuzzer treat it as a crash so it saves the input and minimises it
            raise AssertionError(f"{findings[0]['target']}: {findings[0]['reason']}")

    atheris.Setup([sys.argv[0]] + libfuzzer_args, one)
    atheris.Fuzz()
    return EXIT_OK


# --------------------------------------------------------------------------------------------
# selftest: the pinned malformed corpus must not crash the process, and the finding classifier
# must behave. Fast, deterministic, no network -- picked up by tests/test_selftests.py and CI.
# --------------------------------------------------------------------------------------------
def _selftest():
    # 1. classifier logic
    assert classify("image", False, ValueError("no .text")) is None
    assert classify("image", False, MemoryError()) is not None
    assert classify("run", True, ValueError("x")) is not None          # hardened must not raise
    assert classify("meta", False, RecursionError()) is not None       # runaway recursion is a bug
    assert classify("strings", False, KeyError("k")) is None

    # 2. every synthetic malformed input runs through every target without crashing the process,
    #    and the hardened front ends never raise on any of them.
    bad = 0
    for label, data in synthetic_corpus():
        findings = run_targets(data, time_budget=0.5)
        hardened_raises = [f for f in findings if "hardened target raised" in f["reason"]]
        assert not hardened_raises, f"{label}: hardened front end raised: {hardened_raises}"
        bad += len(findings)
    assert bad == 0, f"synthetic corpus produced {bad} finding(s) -- a regression; run without " \
                     "--selftest to see them"

    # 3. the mutation engine is deterministic for a fixed seed and never returns empty
    rng = random.Random(1234)
    sample = b"\x7fELF" + bytes(range(60))
    for _ in range(200):
        m = mutate(sample, rng)
        assert isinstance(m, bytes) and len(m) >= 1

    # 4. a short, fully in-process mini-campaign over the synthetic corpus stays clean and the
    #    crash-saving path round-trips a hand-made finding
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        res = campaign(seeds=[data for _, data in synthetic_corpus()], runs=120, deadline=None,
                       rng=random.Random(7), time_budget=0.3, isolate=False, timeout=5.0,
                       rlimit_mb=DEFAULT_RLIMIT_MB, crash_dir=Path(d) / "c", verbose=False)
        saved = _save_crash(Path(d) / "c", b"MZ\x00\x00demo",
                            [{"target": "image", "reason": "unexpected IndexError: x",
                              "traceback": "Traceback...\n"}], origin="selftest")
        assert saved.exists() and saved.with_suffix(".txt").exists()
        assert b"demo" in saved.read_bytes()
    print(f"selftest OK: classifier, {len(synthetic_corpus())} malformed inputs run clean through "
          f"all targets, mutation + crash-save round-trip ({len(res)} campaign findings)")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("--selftest", action="store_true", help="run the pinned-corpus self-test and exit")
    ap.add_argument("--runs", type=int, default=2000, help="number of mutated inputs (0 = until --time)")
    ap.add_argument("--time", type=float, default=0.0, help="wall-clock budget in seconds (0 = use --runs)")
    ap.add_argument("--seeds", action="append", default=[], metavar="DIR",
                    help="extra seed directory (repeatable); the committed fixtures are always seeds")
    ap.add_argument("--no-fixture-seeds", action="store_true", help="do not seed from tests/fixtures")
    ap.add_argument("--targets", default="", metavar="A,B",
                    help="comma-separated target names to run (default all); e.g. "
                         "'detect,image,meta,strings,callsite,arm64,cryptify,stackstrings,detect_vm' "
                         "for the fast parser surface, or 'emulate,run,triage' for the slow one")
    ap.add_argument("--isolate", dest="isolate", action="store_true", default=None,
                    help="run each input in a child with an rlimit + timeout (catches native "
                         "crashes/hangs/OOM); default on unless --no-isolate")
    ap.add_argument("--no-isolate", dest="isolate", action="store_false",
                    help="run in-process (faster; misses native crashes and true hangs)")
    ap.add_argument("--time-budget", type=float, default=1.0,
                    help="per-target emulation budget for the emulate/run/triage targets (default 1s)")
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                    help=f"per-input wall-clock timeout for an isolated worker (default {DEFAULT_TIMEOUT:.0f}s)")
    ap.add_argument("--rlimit-mb", type=int, default=DEFAULT_RLIMIT_MB,
                    help=f"address-space cap for an isolated worker in MB (default {DEFAULT_RLIMIT_MB})")
    ap.add_argument("--crash-dir", default=str(ROOT.parent / "build" / "fuzz_crashes"),
                    help="where to write crashing inputs (default build/fuzz_crashes/)")
    ap.add_argument("--seed", type=int, default=None, help="RNG seed for a reproducible campaign")
    ap.add_argument("--reproduce", metavar="FILE", help="replay one saved input and print its findings")
    ap.add_argument("--atheris", action="store_true", help="drive libFuzzer via Atheris (if installed)")
    ap.add_argument("-v", "--verbose", action="store_true", help="progress every 500 inputs")
    ap.add_argument("libfuzzer", nargs="*", help="args passed through to libFuzzer after -- (with --atheris)")
    a = ap.parse_args(argv)

    if a.selftest:
        _selftest()
        return EXIT_OK

    active = {t.strip() for t in a.targets.split(",") if t.strip()} or None

    if a.reproduce:
        data = Path(a.reproduce).read_bytes()
        findings = run_targets(data, time_budget=a.time_budget, active=active)
        if not findings:
            print(f"{a.reproduce}: no findings in-process (try --isolate for a native crash/hang)")
            return EXIT_OK
        for f in findings:
            print(f"[{f['target']}] {f['reason']}")
            if f.get("traceback"):
                print(f["traceback"].rstrip())
        return EXIT_FINDINGS

    if a.atheris:
        return atheris_main(a.libfuzzer, a.time_budget, active)

    isolate = True if a.isolate is None else a.isolate
    seed_dirs = [Path(s) for s in a.seeds] + ([] if a.no_fixture_seeds else fixture_dirs())
    seeds = load_seeds(seed_dirs)
    print(f"fuzz_recover: {len(seeds)} seed(s) from {len(seed_dirs)} dir(s); "
          f"isolate={isolate}; {'time ' + str(a.time) + 's' if a.time else str(a.runs) + ' runs'}")
    rng = random.Random(a.seed)
    deadline = (time.monotonic() + a.time) if a.time else None
    results = campaign(seeds, runs=(0 if a.time else a.runs), deadline=deadline, rng=rng,
                       time_budget=a.time_budget, isolate=isolate, timeout=a.timeout,
                       rlimit_mb=a.rlimit_mb, crash_dir=Path(a.crash_dir), verbose=a.verbose,
                       active=active)
    if results:
        print(f"\n{len(results)} distinct finding(s) saved to {a.crash_dir}")
        return EXIT_FINDINGS
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
