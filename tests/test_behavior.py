"""Per-function behavior/capability map (recover_behavior.py).

The --selftest (classifier + stubbed rollup) runs via test_selftests.py. This runs recover() on the
committed benign binary and, with rustc, on a program that networks + reads a file, checking the
capability attribution lands on the right functions.
"""
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from conftest import ROOT

sys.path.insert(0, str(ROOT / "scripts"))
import recover_behavior as B  # noqa: E402

pytestmark = pytest.mark.filterwarnings("ignore::RuntimeWarning")

FIXTURE = ROOT / "tests" / "fixtures" / "vm" / "benign_rust_std.x64"


def test_classifier_buckets():
    assert B._classify("connect") == {"network"}
    assert B._classify("CreateFileW") == {"file"}
    assert B._classify("VirtualProtect") == {"memory"}
    assert B._classify("getenv") == {"recon"}
    assert B._classify("memcpy") == set() and B._classify("abort") == set()


def test_benign_binary_has_no_network():
    res = B.recover(FIXTURE)
    # a benign std binary touches files / allocates, but does not network
    assert "network" not in res["capabilities_present"], res["capabilities_present"]
    assert res["functions_with_capability"] >= 1


@pytest.mark.skipif(not shutil.which("rustc"), reason="rustc not available")
def test_networking_program_tagged(tmp_path):
    src = tmp_path / "n.rs"
    src.write_text(
        "use std::io::Read;\n"
        "fn main(){\n"
        "    if let Ok(mut s) = std::net::TcpStream::connect(\"127.0.0.1:9\") {\n"
        "        let mut b=[0u8;4]; let _=s.read(&mut b);\n    }\n"
        "    let _ = std::fs::read(\"/etc/hostname\");\n}\n")
    binp = tmp_path / "n"
    r = subprocess.run(["rustc", "-O", str(src), "-o", str(binp)], capture_output=True, text=True)
    if r.returncode != 0:
        pytest.skip("rustc failed: " + r.stderr.strip()[-200:])
    res = B.recover(binp)
    assert "network" in res["capabilities_present"], res["capabilities_present"]
    assert "file" in res["capabilities_present"]
    # the network tag points at specific functions, each carrying a networking import
    net_fns = res["rollup"]["network"]
    assert net_fns
    for fn in net_fns:
        assert res["functions"][fn].get("network")
