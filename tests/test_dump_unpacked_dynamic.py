"""Dynamic unpack path (dump_unpacked.py via unpack.py --dynamic), OPT-IN.

This EXECUTES a binary: the committed benign UPX fixture tests/fixtures/pack/upx_hello_pe64.exe
(source upx_hello_pe.c: reads an env var, the tick count and its own size, prints them). It runs only
when RUST_DEOBF_DYNAMIC=1 is set, frida is installed, and the host is Windows -- i.e. on the
analysis VM, never in CI by accident.

Cross-validation: the image Frida dumps from the live process at ExitProcess must agree with the
stage-2 the STATIC emulator unpacks (they differ only where the loader relocated absolute pointers
and the IAT was filled at run time). Measured on Windows 11 ARM64 (x64 Python under emulation):
62315/62861 bytes (99.13%) equal.
"""
import os
import sys

import pytest
from conftest import ROOT

sys.path.insert(0, str(ROOT / "scripts"))

FIXTURE = ROOT / "tests" / "fixtures" / "pack" / "upx_hello_pe64.exe"
pytestmark = [
    pytest.mark.skipif(os.environ.get("RUST_DEOBF_DYNAMIC") != "1",
                       reason="executes a sample: opt in with RUST_DEOBF_DYNAMIC=1 on an analysis VM"),
    pytest.mark.skipif(sys.platform != "win32", reason="the fixture is a Windows PE"),
]


def test_dynamic_dump_matches_static_unpack(tmp_path):
    pytest.importorskip("frida")
    import unpack
    import unpack_emulate
    # aim the static pass at the wrong place so the dynamic fallback is what runs
    res = unpack.recover(FIXTURE, entry=0x13f0, dynamic=True, ack=True, timeout=8,
                         outdir=tmp_path / "dyn")
    assert res["dynamic"] and not res["dynamic"].get("error"), res["dynamic"]
    images = sorted((tmp_path / "dyn").glob("image_exit*.bin"))
    assert images, list((tmp_path / "dyn").iterdir())
    dyn = images[0].read_bytes()
    assert dyn[:2] == b"MZ"                                   # the exe's own image, not a DLL
    assert sorted((tmp_path / "dyn").glob("image_exit*.fixed.exe"))   # file-layout copy too
    st = unpack_emulate.recover(FIXTURE)
    stage = next(r for r in st["_regions"] if r["executed"])
    a, b = stage["_bytes"], dyn[stage["va"]:stage["va"] + len(stage["_bytes"])]
    same = sum(x == y for x, y in zip(a, b))
    assert same / len(a) > 0.97, f"static vs dynamic stage-2 agree on {same}/{len(a)} bytes"
