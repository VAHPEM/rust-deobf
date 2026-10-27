"""Go pclntab metadata recovery (recover_go.py).

The --selftest (synthetic 1.20+ pclntab round-trip) runs via test_selftests.py. This builds a real Go
binary, strips it, and checks the function names + version are still recovered (the point: pclntab
survives strip), and that a non-Go binary is correctly rejected.
"""
import shutil
import subprocess
import sys

import pytest
from conftest import ROOT

sys.path.insert(0, str(ROOT / "scripts"))
import recover_go as GO  # noqa: E402

pytestmark = pytest.mark.filterwarnings("ignore::RuntimeWarning")


def test_synthetic_pclntab_roundtrip():
    GO._selftest()


def test_non_go_binary_rejected():
    res = GO.recover(ROOT / "tests" / "fixtures" / "vm" / "benign_rust_std.x64")
    assert not res["is_go"] or res.get("function_count", 0) == 0


@pytest.mark.skipif(not shutil.which("go"), reason="go not available")
def test_real_stripped_go_binary(tmp_path):
    src = tmp_path / "g.go"
    src.write_text(
        'package main\nimport "fmt"\n'
        '//go:noinline\n'
        'func beacon() string { return fmt.Sprintf("tick-%d", 1) }\n'
        'func main(){ fmt.Println(beacon()) }\n')
    binp = tmp_path / "bin"
    r = subprocess.run(["go", "build", "-o", str(binp), str(src)],
                       capture_output=True, text=True, cwd=tmp_path)
    if r.returncode != 0:
        pytest.skip("go build failed: " + r.stderr.strip()[-200:])
    subprocess.run(["strip", str(binp)], capture_output=True)   # pclntab must survive this
    res = GO.recover(binp)
    assert res["is_go"] and res["function_count"] > 100
    names = set(res["functions"].values())
    assert "main.main" in names and "main.beacon" in names      # our names survive strip
    assert any(n.startswith("runtime.") for n in names)
    assert res["go_version"] and res["go_version"].startswith("go1.")
