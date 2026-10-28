"""UPX-packed ELF for the HOST architecture, built at test time (skips without `upx` + a static C
toolchain). On an ARM64 host (Kali on Apple silicon) this exercises the AArch64 path: UPX's ELF stub
re-opens itself (openat + readlinkat /proc/self/exe), mmaps a decompressor into fresh memory (an
intermediate hand-off), which mmaps the program back at its original addresses and jumps to its
entry. The OEP the emulator reports must be the entry point of the binary BEFORE packing."""
import shutil
import subprocess
import sys

import pytest
from conftest import ROOT

sys.path.insert(0, str(ROOT / "scripts"))
pytest.importorskip("unicorn")
lief = pytest.importorskip("lief")
import unpack_emulate as U  # noqa: E402

SRC = r'''
#include <stdio.h>
#include <stdlib.h>
int main(void) { const char *e = getenv("RUST_DEOBF_FIXTURE"); printf("fixture-ok %d\n", e != 0); return 0; }
'''


@pytest.mark.skipif(not shutil.which("upx"), reason="upx not installed")
@pytest.mark.skipif(not (shutil.which("cc") or shutil.which("gcc")), reason="no C compiler")
def test_upx_elf_for_host_arch_reaches_original_entry(tmp_path):
    cc = shutil.which("cc") or shutil.which("gcc")
    (tmp_path / "p.c").write_text(SRC)
    plain, packed = tmp_path / "p", tmp_path / "p_upx"
    r = subprocess.run([cc, "-Os", "-s", "-static", "-o", str(plain), str(tmp_path / "p.c")],
                       capture_output=True, text=True)
    if r.returncode != 0:
        pytest.skip("static link failed: " + r.stderr.strip()[-200:])
    shutil.copy(plain, packed)
    r = subprocess.run(["upx", "-q", "--best", str(packed)], capture_output=True, text=True)
    if r.returncode != 0:
        pytest.skip("upx failed: " + (r.stdout + r.stderr).strip()[-200:])
    original_entry = lief.parse(str(plain)).entrypoint
    res = U.recover(packed)
    assert res.get("error") is None, res.get("error")
    assert res["unpacked_detected"] is True
    assert res["stopped"] == "oep" and res["oep"] == original_entry, (
        res["stopped"], hex(res["oep"] or 0), hex(original_entry), res["handoffs"])
    # the last hand-off is into the file's own image; any before it went to fresh (mmap'd) memory
    assert res["handoffs"][-1]["in_image"] is True
    assert all(not h["in_image"] for h in res["handoffs"][:-1])
