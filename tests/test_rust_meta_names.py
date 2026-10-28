"""recover_rust_meta on crafted inputs whose section / symbol names are not valid UTF-8: LIEF returns
those names as `bytes`, which crashed the metadata tier with TypeError (seen through the MCP
`metadata` tool on tests/fixtures/fuzz/hang_*.bin). Names are now normalised to text."""
import sys

import pytest
from conftest import ROOT

sys.path.insert(0, str(ROOT / "scripts"))
pytest.importorskip("lief")
import recover_rust_meta as M  # noqa: E402

FUZZ = sorted((ROOT / "tests" / "fixtures" / "fuzz").glob("*.bin"))


def test_name_normalisation():
    assert M._str(b".debug_info") == ".debug_info"
    assert M._str(b"\xff\xfe_R") == "\xff\xfe_R"          # latin-1: never raises
    assert M._str(None) == "" and M._str("_RNv") == "_RNv"
    assert M._is_debug_section(b".debug_line") and not M._is_debug_section(b".rodata")


@pytest.mark.parametrize("path", FUZZ, ids=[p.name for p in FUZZ])
def test_crafted_fuzz_inputs_do_not_raise(path):
    M.recover(path)          # must return (any result), not raise TypeError on bytes names
