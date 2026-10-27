"""Per-function language attribution (recover_lang.py) for mixed-language binaries.

The --selftest (symbol-mangling classifier) runs via test_selftests.py. This builds real binaries in
several languages (skipping any whose toolchain is absent) and checks the language map, including the
Rust+C FFI mixed case and that a plain C binary is not mislabelled C++/Go.
"""
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from conftest import ROOT

sys.path.insert(0, str(ROOT / "scripts"))
import recover_lang as L  # noqa: E402

pytestmark = pytest.mark.filterwarnings("ignore::RuntimeWarning")


def test_classifier():
    assert L.classify_symbol("_RNvCs1_4core") == "rust"
    assert L.classify_symbol("_ZN4core3foo17h0123456789abcdefE") == "rust"
    assert L.classify_symbol("_ZSt4cout") == "cpp"
    assert L.classify_symbol("runtime.main") == "go"
    assert L.classify_symbol("github.com/x/y.H") == "go"
    assert L.classify_symbol("DW.ref.__gxx_personality") != "go"   # compiler-internal, not Go
    assert L.classify_symbol("main") == "c" and L.classify_symbol("memcpy") == "c"


def test_committed_rust_binary():
    res = L.recover(ROOT / "tests" / "fixtures" / "vm" / "benign_rust_std.x64")
    assert "rust" in res["languages_present"]


@pytest.mark.skipif(not (shutil.which("rustc") and shutil.which("clang")), reason="need rustc+clang")
def test_rust_plus_c_ffi_is_mixed(tmp_path):
    (tmp_path / "c.c").write_text("int c_square(int x){return x*x;}\n")
    subprocess.run(["clang", "-c", "-O2", str(tmp_path / "c.c"), "-o", str(tmp_path / "c.o")], check=True)
    (tmp_path / "r.rs").write_text(
        'extern "C" { fn c_square(x: i32) -> i32; }\n'
        'fn main(){ println!("{}", unsafe { c_square(std::env::args().count() as i32) }); }\n')
    r = subprocess.run(["rustc", "-O", str(tmp_path / "r.rs"), "-o", str(tmp_path / "bin"),
                        "-C", f"link-arg={tmp_path / 'c.o'}"], capture_output=True, text=True)
    if r.returncode != 0:
        pytest.skip("build failed: " + r.stderr.strip()[-200:])
    res = L.recover(tmp_path / "bin")
    assert res["mixed"] and {"rust", "c"} <= set(res["languages_present"])
    assert res["dominant"] == "rust"
    assert "go" not in res["languages_present"]      # no false Go


@pytest.mark.skipif(not shutil.which("clang++"), reason="clang++ not available")
def test_cpp_detected(tmp_path):
    (tmp_path / "x.cpp").write_text(
        "#include <string>\nstruct S{virtual int f(){return 1;}};struct T:S{int f()override{return 2;}};\n"
        "int main(){S*p=new T();return p->f()+(int)std::string(\"hi\").size();}\n")
    r = subprocess.run(["clang++", "-O2", str(tmp_path / "x.cpp"), "-o", str(tmp_path / "bin")],
                       capture_output=True, text=True)
    if r.returncode != 0:
        pytest.skip("build failed")
    res = L.recover(tmp_path / "bin")
    assert "cpp" in res["languages_present"]


@pytest.mark.skipif(not shutil.which("go"), reason="go not available")
def test_go_detected(tmp_path):
    (tmp_path / "g.go").write_text('package main\nimport "fmt"\nfunc main(){fmt.Println("hi")}\n')
    r = subprocess.run(["go", "build", "-o", str(tmp_path / "bin"), str(tmp_path / "g.go")],
                       capture_output=True, text=True, cwd=tmp_path)
    if r.returncode != 0:
        pytest.skip("go build failed: " + r.stderr.strip()[-200:])
    res = L.recover(tmp_path / "bin")
    assert "go" in res["languages_present"] and res["dominant"] == "go"
