"""Every script with a --selftest passes it (no binaries needed)."""
import subprocess
import sys

import pytest
from conftest import ROOT

SCRIPTS = sorted(p for p in (ROOT / "scripts").glob("*.py") if "--selftest" in p.read_text())


@pytest.mark.parametrize("script", SCRIPTS, ids=[p.name for p in SCRIPTS])
def test_selftest(script):
    out = subprocess.run([sys.executable, str(script), "--selftest"], capture_output=True, text=True, timeout=600)
    assert out.returncode == 0, out.stdout + out.stderr
    assert "selftest OK" in out.stdout
