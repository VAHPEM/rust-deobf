"""Red/blue closure: deobf_expr.py (z3) must defeat the exact opaque predicates and MBA
substitutions RustCloak emits. Pinning RustCloak's emitted forms here means any future red-team
change that escapes the blue tool fails this test -- the loop stays honest.

RustCloak's forms (both proven equivalent/constant at emit time with this same engine):
  * opaque predicates (Bogus.cpp): five always-true families mixed per block
  * MBA substitution (Subst.cpp): a+b, a-b, a^b, a&b, a|b rewritten as MBA expressions
"""
import pytest
from conftest import ROOT  # noqa: F401  (adds scripts/ to sys.path)

z3 = pytest.importorskip("z3")
import deobf_expr as E

NBITS = 32

# The exact opaque predicates RustCloak's opaqueTrue() builds, each must be provably always-true.
RUSTCLOAK_OPAQUE = [
    "(x*(x+1)) & 1 == 0",
    "(x*x + x) & 1 == 0",
    "((x*x) ^ x) & 1 == 0",
    "(x | 1) & 1 == 1",
    "((x & 1) * (x & 1)) == (x & 1)",
]

# The exact MBA substitutions RustCloak's SubstPass emits, and the simple op each must reduce to.
RUSTCLOAK_MBA = [
    ("(x ^ y) + 2*(x & y)", "x + y"),      # Add
    ("(x ^ y) - 2*(~x & y)", "x - y"),     # Sub
    ("(x | y) - (x & y)", "x ^ y"),        # Xor
    ("(x | y) - (x ^ y)", "x & y"),        # And
    ("(x & y) + (x ^ y)", "x | y"),        # Or
]


@pytest.mark.parametrize("pred", RUSTCLOAK_OPAQUE)
def test_rustcloak_opaque_predicates_annihilated(pred):
    verdict, _ = E.classify_opaque(pred, NBITS)
    assert verdict == "always-true", f"{pred} classified {verdict}, expected always-true"


@pytest.mark.parametrize("mba,simple", RUSTCLOAK_MBA)
def test_rustcloak_mba_substitution_reversed(mba, simple):
    # the blue tool proves the MBA expression equals the simple op for every 32-bit input ...
    ok, cex = E.prove_equiv(mba, simple, NBITS)
    assert ok, f"{mba} != {simple}: {cex}"
    # ... and recovers it by simplification against its normal-form library
    got = E.simplify_mba(mba, NBITS)
    assert got is not None, f"no simplification found for {mba}"
    assert E.prove_equiv(got, simple, NBITS)[0], f"{mba} simplified to {got}, not equiv to {simple}"
