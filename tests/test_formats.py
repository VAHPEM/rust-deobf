"""Format/arch routing (recover.py detect + run).

The static call-site and emulation engines are ELF/PE loaders for x86-64 and AArch64. 32-bit x86
and Mach-O are not emulated yet, but detection must label them (not arch '?') and recover.py must
still run the arch-agnostic literal recovery instead of bailing out. Covers the 32-bit case by
building an i686 musl Rust binary (self-contained via rust-lld, no multilib); skips if the target
is unavailable.
"""
import shutil
import subprocess
from pathlib import Path

import pytest
from conftest import ROOT

import recover

LITCRYPT = ROOT / "bench_src" / "litcrypt"
TARGET = "i686-unknown-linux-musl"


def _build_i686():
    out = LITCRYPT / "target" / TARGET / "release" / "litcrypt"
    if out.is_file():
        return out
    if shutil.which("rustup") is None and shutil.which("cargo") is None:
        return None
    # ensure the target is installed (no-op if already)
    subprocess.run(["rustup", "target", "add", TARGET], capture_output=True)
    r = subprocess.run(["cargo", "build", "--release", "--target", TARGET],
                       cwd=LITCRYPT, capture_output=True,
                       env={**__import__("os").environ, "RUSTFLAGS": "-C target-feature=+crt-static"})
    return out if out.is_file() else None


def test_detect_and_route_32bit():
    b = _build_i686()
    if b is None:
        pytest.skip("i686 target/build unavailable")
    fmt, arch, _ = recover.detect(b)
    assert (fmt, arch) == ("ELF", "x86"), (fmt, arch)
    res = recover.run(b, emulate="always", stackstrings=True, literals=True, libfuncs=True)
    # 32-bit x86 is now emulated (the engine entry is present); literals still run; the static
    # call-site engine stays x86-64/aarch64 only, noted. (End-to-end 5/5 is in test_32bit.py on
    # the dynamic-glibc build; this static-musl build only needs the routing to be correct.)
    assert any("emulation" in e["engine"] for e in res["engines"]), res["engines"]
    assert not any("recover_callsite" in e["engine"] for e in res["engines"]), res["engines"]
    assert res["literals"], "literal recovery should still run on 32-bit"
    assert any("32-bit x86" in n for n in res["notes"]), res["notes"]


def test_detect_64bit_still_emulates():
    b = ROOT / "bench_src" / "litcrypt" / "target" / "release" / "litcrypt"
    if not b.is_file():
        pytest.skip("x86-64 litcrypt not built")
    fmt, arch, _ = recover.detect(b)
    assert (fmt, arch) == ("ELF", "x86_64")
    res = recover.run(b, emulate="never", stackstrings=False, literals=False)
    # the static call-site engine runs for a supported arch
    assert any("recover_callsite" in e["engine"] for e in res["engines"]), res["engines"]
