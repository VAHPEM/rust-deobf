"""Performance work on the emulation tiers must not change a single output.

tests/fixtures/emu/equiv_golden.json.gz was dumped by tests/emu_equiv.py from the code BEFORE the
hook-body optimisations (Oct 2026): for all 525 functions of benign_rust_std.x64 the QUICK- and
full-budget runs (instruction count, strings, exact/used, branches, covered pairs) and every
decoder-scored function's explore(), recover()'s records, and unpack_emulate on the pack fixtures
(with/without --follow) plus the benign binary. A fresh dump must equal it. (Set
RUST_DEOBF_EQUIV_DEVIRT=1 to also compare devirt_emulate's recover_all on the VM fixtures.)

Regenerate the golden file only for an INTENDED output change, and say so in the commit:
    python3 tests/emu_equiv.py dump tests/fixtures/emu/equiv_golden.json.gz --devirt
"""
import os
import sys

import pytest
from conftest import ROOT

sys.path.insert(0, str(ROOT / "tests"))
pytest.importorskip("unicorn")
import emu_equiv as E  # noqa: E402

GOLDEN = ROOT / "tests" / "fixtures" / "emu" / "equiv_golden.json.gz"


@pytest.mark.skipif(not (GOLDEN.is_file() and E.BENIGN.is_file()), reason="golden/fixture missing")
def test_outputs_identical_to_golden():
    import unicorn
    gold = E.load(GOLDEN)
    if gold.get("unicorn") != unicorn.__version__:
        pytest.skip(f"golden made with unicorn {gold.get('unicorn')}, this is {unicorn.__version__}")
    devirt = os.environ.get("RUST_DEOBF_EQUIV_DEVIRT") == "1"
    now = E.dump(devirt=devirt)
    if not devirt:
        gold.pop("devirt_emulate", None)
    d = E.diff(gold, now)
    assert not d, "emulation outputs changed:\n" + "\n".join(d)
