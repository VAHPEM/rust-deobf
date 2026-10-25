"""Red/blue closure for RustCloak's anti-emulation and rust-deobf's constructor priming.

RUSTCLOAK_ANTIEMU makes the string key depend on a marker byte that a global constructor sets
before `main` (key = key ^ MAGIC ^ marker, and the ctor stores MAGIC into marker). A real run
decrypts correctly. An analyzer that emulates functions in isolation never runs the constructor,
so the marker stays 0, the key is wrong, and nothing decodes -- the RED win.

The BLUE counter replays the loader's global constructors (`.init_array`) on the shared engine
before the sweep and bakes their writes into the restore baseline, so the marker is set for every
later run -- which makes the key correct again. This pins both halves on a committed anti-emulation
binary: statically the secret is absent; emulation WITHOUT priming fails to recover it; emulation
WITH priming (the shipped default) recovers it.

x86-64 fixture (built on an x86-64 host, so the test is arch-guarded):
    RUSTCLOAK_ANTIEMU=1 clang-18 -O1 -fpass-plugin=build/libRustCloak.so test/demo.c -o out
"""
import platform

import pytest
from conftest import ROOT

import recover

FIX = ROOT / "tests" / "fixtures" / "antiemu" / "rustcloak_antiemu.x64"
SECRET = "flatten-demo"
_X64 = platform.machine() in ("x86_64", "AMD64")


@pytest.mark.skipif(not FIX.is_file(), reason="anti-emu fixture missing")
def test_antiemu_secret_absent_statically():
    # the strenc layer still hides the plaintext from `strings`/FLOSS; anti-emu does not change that
    assert SECRET.encode() not in FIX.read_bytes(), "anti-emu secret leaked in static bytes"


@pytest.mark.skipif(not (FIX.is_file() and _X64), reason="anti-emu fixture / x86-64 host required")
def test_antiemu_defeated_by_constructor_priming():
    # the shipped pipeline primes constructors -> the marker is set -> the key is correct
    r = recover.run(FIX)
    decoded = [x["string"] for x in r["decoded"]]
    assert any(SECRET in s for s in decoded), f"priming did not recover the anti-emu secret: {decoded}"


@pytest.mark.skipif(not (FIX.is_file() and _X64), reason="anti-emu fixture / x86-64 host required")
def test_antiemu_beats_emulation_without_priming():
    # the RED half: with the constructors NOT replayed, the marker stays 0 and the sweep recovers
    # nothing; replaying them flips the same engine to success. Both directions on one binary.
    from recover_emulate import Image, Emulator

    img = Image(str(FIX))
    funcs = img.functions()

    def sweep(emu):
        found = set()
        for fva, size in funcs:            # emulate every function start; collect any plaintext
            try:
                strs, _, _ = emu.run(fva, size)
            except Exception:
                continue
            found |= {s for s in strs if SECRET in s}
        return found

    cold = Emulator(img)                       # no priming -> anti-emulation holds
    assert not sweep(cold), "anti-emulation should defeat an un-primed sweep"

    warm = Emulator(img)
    assert warm.prime_constructors() >= 1, "no constructors were replayed"
    assert sweep(warm), "constructor priming should recover the anti-emu secret"
