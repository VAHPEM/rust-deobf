"""Red/blue closure for RustCloak's code virtualization (`virt`) and rust-deobf's VM detector.

RUSTCLOAK_VM compiles a function into custom bytecode run by a generated interpreter, so the native
arithmetic is gone and the function is a dispatch loop over a bytecode blob. The detector recognises
the interpreter's machine-code fingerprint -- threaded dispatch (many indirect branches through one
register) plus dense bytecode byte-fetches -- and flags the function as virtualized. (Detection, not
devirtualization; that is a later round.)

This pins: the detector fires on a committed virtualized binary and stays quiet on the plain build
of the same program, and the threaded-dispatch discriminator keeps ordinary switch/parse code from
matching.
"""
import platform

import pytest
from conftest import ROOT

import detect_vm

VMFIX = ROOT / "tests" / "fixtures" / "vm" / "rustcloak_vm.x64"
PLAIN = ROOT / "tests" / "fixtures" / "vm" / "plain.x64"
_X64 = platform.machine() in ("x86_64", "AMD64")

pytestmark = pytest.mark.skipif(not _X64, reason="x86-64 fixtures")


@pytest.mark.skipif(not VMFIX.is_file(), reason="vm fixture missing")
def test_virtualized_functions_detected():
    r = detect_vm.detect(VMFIX)
    assert r["count"] >= 3, f"expected the 3 virtualized functions, got {r['count']}"
    # the signal is the threaded dispatch, not just byte loads
    assert all(h["indirect_same_reg"] >= 4 for h in r["virtualized_functions"])
    assert any(h["confidence"] == "high" for h in r["virtualized_functions"])


@pytest.mark.skipif(not PLAIN.is_file(), reason="plain fixture missing")
def test_plain_build_not_flagged():
    # the same program, built without virtualization, must not look virtualized
    assert detect_vm.detect(PLAIN)["count"] == 0


def test_classifier_requires_threaded_dispatch():
    # a lone jump table + some byte loads (ordinary switch in a parse loop) is NOT enough
    assert _is_vm(0, 1, 50) is False      # no threaded dispatch -> not flagged
    assert _is_vm(2, 0, 40) is False      # weak dispatch, no table -> not flagged
    # threaded dispatch + fetches -> flagged
    assert _is_vm(8, 0, 40) is True
    assert _is_vm(4, 0, 10) is True


def _is_vm(top, jmptab, byteload):
    return detect_vm._classify(top, jmptab, byteload)[0]
