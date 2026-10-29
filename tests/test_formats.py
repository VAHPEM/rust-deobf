"""Format/arch routing (recover.py detect + run).

The emulation engine loads ELF/PE/Mach-O and is verified on x86-64, AArch64 and 32-bit x86 for
ELF and Mach-O. 32-bit PE is deliberately NOT emulated (Windows-std under-emulation recovers no
canaries and risks false positives), so it must route to literal recovery only. The static
call-site engine stays x86-64/AArch64 only. Detection must label every case (never arch '?') and
run() must pick the right engines. Covers the 32-bit ELF case by building an i686 musl binary
(self-contained via rust-lld, no multilib) and the 32-bit PE case from any committed i686-windows
canary; skips whichever is unavailable.
"""
import shutil
import subprocess
from pathlib import Path

import pytest
from conftest import BUILD, CANARIES, NOT_BUILT, ROOT

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
    # 32-bit x86 ELF is emulated (the engine entry is present); literals still run; the static
    # call-site engine stays x86-64/aarch64 only. (End-to-end 5/5 is in test_32bit.py on the
    # dynamic-glibc build; this static-musl build only needs the routing to be correct.)
    assert any("emulation" in e["engine"] for e in res["engines"]), res["engines"]
    assert not any("recover_callsite" in e["engine"] for e in res["engines"]), res["engines"]
    assert res["literals"], "literal recovery should still run on 32-bit"


def test_detect_and_route_32bit_pe():
    """32-bit PE detects as PE/x86 and is emulated: its Windows-std path is verified on the
    benchmark (stdcall imports pop their arguments, function starts from .eh_frame, import
    trampolines protected), so an obfuscated canary build gives its five strings and nothing
    else. Library-function identification is still skipped there, with a note."""
    cands = sorted(ROOT.glob("bench_src/xor_custom/target/i686-pc-windows-gnu/release/*.exe")) + \
        sorted(BUILD.glob("xor_custom__pe32__release__strip.exe"))
    b = next((p for p in cands if p.is_file()), None)
    if b is None:
        pytest.skip("no i686-pc-windows-gnu xor_custom build")
    fmt, arch, _ = recover.detect(b)
    assert (fmt, arch) == ("PE", "x86"), (fmt, arch)
    res = recover.run(b, emulate="always", stackstrings=True, literals=True, libfuncs=True,
                      time_budget=300)
    assert any("emulation" in e["engine"] for e in res["engines"]), res["engines"]
    assert not any("libfunc" in e["engine"].lower() for e in res["engines"]), res["engines"]
    assert any("32-bit PE" in n for n in res["notes"]), res["notes"]
    assert res["literals"], "literal recovery should still run on 32-bit PE"
    assert {x["string"] for x in res["decoded"]} == set(CANARIES), res["decoded"]


def test_detect_64bit_still_emulates():
    # build_all.sh builds with --target, so the binary is in the build dir, not target/release
    b = BUILD / "litcrypt__elf__release__nostrip"
    if not b.is_file():
        pytest.skip(NOT_BUILT + b.name)
    fmt, arch, _ = recover.detect(b)
    assert (fmt, arch) == ("ELF", "x86_64")
    res = recover.run(b, emulate="never", stackstrings=False, literals=False)
    # the static call-site engine runs for a supported arch
    assert any("recover_callsite" in e["engine"] for e in res["engines"]), res["engines"]
