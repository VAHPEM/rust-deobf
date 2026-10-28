"""--json multi-target batches (Oct 2026 review): one failing target used to raise out of main() and
lose every other target's result. Each bad target must become a {"target", "error"} row."""
import json
import shutil
import subprocess
import sys

import pytest
from conftest import ROOT

GOOD = ROOT / "tests" / "fixtures" / "emu" / "null64"          # a tiny benign x86-64 ELF


@pytest.mark.parametrize("script", ["recover_callsite", "recover_arm64", "recover_cryptify"])
def test_one_bad_target_does_not_lose_the_batch(script, tmp_path):
    shutil.copy(GOOD, tmp_path / "good.bin")
    (tmp_path / "text.bin").write_bytes(b"this is not a binary\n")
    missing = str(tmp_path / "does_not_exist.bin")
    # relative paths, run from tmp_path: they resolve against the cwd (recover_callsite used to
    # look them up under the repo root only)
    r = subprocess.run([sys.executable, str(ROOT / "scripts" / f"{script}.py"), "--json",
                        "good.bin", missing, "text.bin"],
                       cwd=tmp_path, capture_output=True, text=True, timeout=300)
    rows = json.loads(r.stdout)
    assert [row["target"] for row in rows] == ["good.bin", missing, "text.bin"], rows
    assert "recall" in rows[0] and not rows[0].get("error"), rows[0]      # the good one ran
    assert rows[1].get("error"), rows[1]                                  # the bad one reported
    assert r.returncode == 1                                               # ...and flagged
