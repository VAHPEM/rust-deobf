"""32-bit x86 (i386) emulation.

The emulation engine is x86-64 + AArch64 + 32-bit x86. This builds the canary programs for
i686-unknown-linux-gnu (dynamic glibc PIE — imported libc, the realistic case, matching how real
32-bit PE malware reaches its runtime) and asserts every crate's five canaries come back. Skips a
crate if its i686 build is unavailable (the target/linker not installed on the runner).

Covers the 32-bit path end to end: ELFCLASS32 detection, 32-bit registers/stack/cdecl args,
i386 REL relocations (in-place addend), the PIC get-PC idiom, 32-bit TLS, and `int 0x80` syscalls.
"""
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from conftest import ROOT, CANARIES

import recover_emulate as E

TARGET = "i686-unknown-linux-gnu"
CRATES = ["xor_custom", "add_custom", "litcrypt", "litcrypt2", "obfstr", "cryptify"]
_built = {}


def _build(crate):
    if crate in _built:
        return _built[crate]
    out = ROOT / "bench_src" / crate / "target" / TARGET / "release" / crate
    if not out.is_file():
        if shutil.which("cargo") is None:
            _built[crate] = None
            return None
        subprocess.run(["rustup", "target", "add", TARGET], capture_output=True)
        subprocess.run(["cargo", "build", "--release", "--target", TARGET],
                       cwd=ROOT / "bench_src" / crate, capture_output=True)
    _built[crate] = out if out.is_file() else None
    return _built[crate]


@pytest.mark.parametrize("crate", CRATES)
def test_i686_canaries(crate):
    binary = _build(crate)
    if binary is None:
        pytest.skip(f"{crate} i686 build unavailable")
    img = E.Image(str(binary))
    assert img.x32 and img.ptr == 4, "image should be detected as 32-bit"
    os.environ.setdefault("UC_IGNORE_REG_BREAK", "1")
    r = E.recover(str(binary), [], time_budget=90)
    got = [x["string"] for x in r.get("records", [])]
    want = CANARIES[crate] if isinstance(CANARIES, dict) else \
        [c for c in CANARIES]
    # canary strings are the five planted secrets; accept substring (tags/length may vary)
    secrets = ["7f3c-config-endpoint", "build-id-20261018", "/opt/app/resources/data.bin",
               "feature-flag-telemetry-off", "schema-version-4"]
    missing = [s for s in secrets if not any(s in g for g in got)]
    assert not missing, f"{crate}: missing {missing} (got {len(got)} strings)"
