"""Resolved call graph + code-coverage metric (recover_cfg.py).

The --selftest (BFS, coverage-lift accounting, dispatch reach) runs via test_selftests.py. This runs
build() end to end on a committed real Rust binary and, when rustc is present, on a freshly-built
dyn-dispatch program, checking the indirect-flow resolution actually lifts code coverage.
"""
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from conftest import ROOT

sys.path.insert(0, str(ROOT / "scripts"))
import recover_cfg as G  # noqa: E402

pytestmark = pytest.mark.filterwarnings("ignore::RuntimeWarning")

FIXTURE = ROOT / "tests" / "fixtures" / "vm" / "benign_rust_std.x64"


def test_build_on_committed_binary_lifts_coverage():
    res = G.build(FIXTURE)
    assert res["arch"] == "x86_64" and res["functions_total"] > 50
    assert res["direct_edges"] > 0
    # resolving address-taken roots + dispatch reaches far more than direct-from-entry-only:
    # for a Rust binary, entry reaches ~nothing directly (main goes via __libc_start_main)
    assert res["reachable"] > res["reachable_from_entry_only"]
    assert res["coverage_lift"] > 10
    assert res["reachable_pct"] >= 70.0
    assert "__libc_start_main" in res["imports_used"]


@pytest.mark.skipif(not shutil.which("rustc"), reason="rustc not available")
def test_dyn_dispatch_adds_edges(tmp_path):
    src = tmp_path / "d.rs"
    src.write_text(
        "pub trait T { fn a(&self)->u64; fn b(&self)->u64; }\n"
        "pub struct X(u64); pub struct Y(u64);\n"
        "impl T for X { fn a(&self)->u64{self.0} fn b(&self)->u64{self.0+1} }\n"
        "impl T for Y { fn a(&self)->u64{self.0*2} fn b(&self)->u64{self.0*3} }\n"
        "#[inline(never)] pub fn pick(n:u64)->Box<dyn T>{ if n&1==0 {Box::new(X(n))} else {Box::new(Y(n))} }\n"
        "fn main(){ let s = pick(std::env::args().count() as u64);\n"
        "    println!(\"{} {}\", s.a(), s.b()); }\n")
    binp = tmp_path / "d"
    r = subprocess.run(["rustc", "-O", str(src), "-o", str(binp)], capture_output=True, text=True)
    if r.returncode != 0:
        pytest.skip("rustc failed: " + r.stderr.strip()[-200:])
    res = G.build(binp)
    assert res["vtables"] >= 1
    assert res["dispatch_edges"] > 0          # dyn T dispatch resolved to method edges
    assert res["reachable_pct"] >= 70.0
    assert res["coverage_lift"] > 10


def test_bfs_and_lift():
    edges = {1: {2}, 2: set(), 3: {4}, 4: set()}
    assert G._bfs({1}, edges) == {1, 2}
    assert G._bfs({1, 3}, edges) == {1, 2, 3, 4}
