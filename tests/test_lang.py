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


# ---- regressions (review B): file-name symbols, PE COFF addresses, Mach-O underscore

def _cc():
    return shutil.which("gcc") or shutil.which("clang")


@pytest.mark.skipif(not _cc(), reason="no C compiler")
def test_c_source_file_names_are_not_go(tmp_path):
    """An unstripped C program carries STT_FILE symbols `main.c` / `net.c`; they are file names,
    not Go `pkg.Func` symbols, so a plain C binary must not be reported as mixed C+Go."""
    (tmp_path / "main.c").write_text("int helper_n(int);int main(int c,char**v){return helper_n(c);}\n")
    (tmp_path / "net.c").write_text("int helper_n(int x){return x+1;}\n")
    out = tmp_path / "bin"
    r = subprocess.run([_cc(), "-O1", "-o", str(out), str(tmp_path / "main.c"), str(tmp_path / "net.c")],
                       capture_output=True, text=True)
    if r.returncode != 0:
        pytest.skip("cc failed: " + r.stderr[-200:])
    res = L.recover(out)
    assert "go" not in res["languages_present"], res["languages_present"]
    assert res["languages_present"] == ["c"] and not res["mixed"]


def _gobuild(tmp_path, goos, goarch, name):
    import os
    (tmp_path / "g.go").write_text('package main\nimport "fmt"\nfunc main(){fmt.Println("hi")}\n')
    out = tmp_path / name
    r = subprocess.run(["go", "build", "-o", str(out), str(tmp_path / "g.go")], capture_output=True,
                       text=True, cwd=tmp_path,
                       env=dict(os.environ, GOOS=goos, GOARCH=goarch, CGO_ENABLED="0"))
    if r.returncode != 0:
        pytest.skip("go build failed: " + r.stderr.strip()[-200:])
    return out


@pytest.mark.skipif(not shutil.which("go"), reason="go not available")
def test_pe_coff_symbol_addresses_are_rvas(tmp_path):
    """PE COFF symbol values are section-relative; function addresses must be RVAs in .text."""
    import lief
    p = _gobuild(tmp_path, "windows", "amd64", "g.exe")
    b = lief.parse(str(p))
    text = next(s for s in b.sections if s.name == ".text")
    res = L.recover(p)
    vas = [int(k, 16) for k in res["functions"]]
    assert vas and all(text.virtual_address <= v < text.virtual_address + text.size for v in vas)
    mm = next(s for s in b.symbols if s.name == "main.main")
    assert res["functions"][hex(text.virtual_address + mm.value)] == "go"


@pytest.mark.skipif(not shutil.which("go"), reason="go not available")
def test_macho_go_names_classified(tmp_path):
    """Mach-O prefixes every name with `_`: `_main.main` is Go, and C names are not Rust/C++."""
    res = L.recover(_gobuild(tmp_path, "darwin", "arm64", "g.macho"))
    assert res["dominant"] == "go"
    import lief
    b = lief.parse(str(tmp_path / "g.macho"))
    mm = next(s for s in b.symbols if s.name == "_main.main")
    assert res["functions"].get(hex(mm.value)) == "go"


def test_macho_underscore_classifier():
    c = L.classify_symbol
    assert c("_RSA_new", macho=True) == "c"              # C `RSA_new`, not Rust v0
    assert c("_ZSTD_compress", macho=True) == "c"        # C `ZSTD_compress`, not Itanium
    assert c("_main.main", macho=True) == "go"
    assert c("__RNvCs1_4core3foo", macho=True) == "rust"
    assert c("__ZN3foo3barEv", macho=True) == "cpp"
