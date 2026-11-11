"""Rust type-layout recovery (recover_types.py) - trait-object vtables.

The script's --selftest (synthetic buffer: real vtables vs decoy shapes, ZST, Ghidra structs) runs
via test_selftests.py. This adds end-to-end coverage on a committed real Rust binary and pins that
the recovered vtables are structurally sound and that the scan is precise (restricted to the data
sections, not the symbol/reloc metadata that otherwise yields absurd false vtables).
"""
import sys

import pytest
from conftest import CLANG_TARGET, ROOT, RUSTC_TARGET, exe

sys.path.insert(0, str(ROOT / "scripts"))
import recover_types as RT  # noqa: E402
import recover_emulate as E  # noqa: E402

pytestmark = pytest.mark.filterwarnings("ignore::RuntimeWarning")

FIXTURE = ROOT / "tests" / "fixtures" / "vm" / "benign_rust_std.x64"


def _exec(img, va):
    return img.text_va <= va < img.text_end or any(lo <= va < hi for lo, hi in img.exec_ranges)


def test_vtables_recovered_and_structurally_sound():
    res = RT.recover(FIXTURE)
    assert res["format"] == "ELF" and res["arch"] == "x86_64"
    vts = res["vtables"]
    # a real std Rust binary has several trait-object vtables, but not hundreds -- the section
    # whitelist keeps the symbol/hash/reloc tables (which produced 150+ false "vtables") out.
    assert 3 <= len(vts) <= 60, len(vts)
    img = E.Image(str(FIXTURE))
    for vt in vts:
        # a NULL drop_in_place is legal (type without drop glue) but then needs stronger evidence
        if vt["drop_in_place"] == 0:
            assert vt["size"] > 0 or vt["method_count"] >= 2
        else:
            assert _exec(img, vt["drop_in_place"]), hex(vt["drop_in_place"])
        assert vt["align"] in RT._ALIGNS
        assert vt["size"] <= RT._MAX_SIZE and (vt["align"] == 0 or vt["size"] % vt["align"] == 0)
        assert vt["method_count"] >= 1
        for m in vt["methods"]:
            assert _exec(img, m), hex(m)


def test_recovery_is_deterministic():
    a = RT.recover(FIXTURE)["vtables"]
    b = RT.recover(FIXTURE)["vtables"]
    assert [v["va"] for v in a] == [v["va"] for v in b]


def test_ghidra_types_match_vtables():
    res = RT.recover(FIXTURE)
    counts = {}
    for vt in res["vtables"]:
        counts[vt["method_count"]] = counts.get(vt["method_count"], 0) + 1
    gt = {t["name"]: t for t in res["ghidra_types"]}
    for count, n in counts.items():
        name = f"RustVtable_{count}m"
        assert name in gt and gt[name]["instances"] == n
        t = gt[name]
        assert t["size"] == (3 + count) * res["ptr"]
        assert t["fields"][0]["name"] == "drop_in_place" and t["fields"][1]["name"] == "size"
        assert t["fields"][-1]["name"] == f"method_{count - 1}"


def test_rtti_demangle():
    assert RT.demangle_rtti("3Dog") == "Dog"
    assert RT.demangle_rtti("N3foo3BarE") == "foo::Bar"
    assert RT.demangle_rtti("weird") == "weird"


def test_no_cpp_vtables_in_rust_binary():
    # the C++ scan (offset-to-top + typeinfo + methods) must not fire on Rust vtables
    assert RT.recover(FIXTURE)["cpp_vtables"] == []


_ARCH_FLAGS = {"host": CLANG_TARGET, "macho-x86_64": ["-arch", "x86_64"]}   # host: GNU ABI on Windows


@pytest.mark.skipif(not __import__("shutil").which("clang++"), reason="clang++ not available")
@pytest.mark.parametrize("target", ["host", "macho-x86_64"])
def test_cpp_vtables_and_rtti(tmp_path, target):
    # macho-x86_64 (any Mac: Apple clang cross-builds it): x86-64 RTTI is weak, so each vtable's
    # typeinfo slot is a `<weak-def-coalesce>` bind to the image's own __ZTI*, which used to read as
    # an import trampoline -> no vtable found (CI macos-15-intel); arm64 RTTI is plain rebases
    if target != "host" and sys.platform != "darwin":
        pytest.skip("Apple clang -arch cross-build")
    import subprocess
    src = tmp_path / "v.cpp"
    src.write_text(
        "struct Animal{virtual int sound()const{return 1;}virtual int legs()const{return 4;}virtual ~Animal(){}};\n"
        "struct Dog:Animal{int sound()const override{return 2;}int legs()const override{return 4;}};\n"
        "struct Bird:Animal{int sound()const override{return 3;}int legs()const override{return 2;}};\n"
        "extern \"C\" int pick(int n){Animal*a=(n&1)?(Animal*)new Dog():(Animal*)new Bird();"
        "int r=a->sound()+a->legs();delete a;return r;}\n"
        "int main(){return pick(1);}\n")
    binp = exe(tmp_path / "v") if target == "host" else tmp_path / "v"
    r = subprocess.run(["clang++", *_ARCH_FLAGS[target], "-O1", "-fno-inline", str(src), "-o", str(binp)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        pytest.skip("clang++ failed: " + r.stderr.strip()[-200:])
    res = RT.recover(binp)
    types = {vt["type"] for vt in res["cpp_vtables"]}
    assert {"Animal", "Dog", "Bird"} <= types, types
    for vt in res["cpp_vtables"]:
        assert vt["method_count"] >= 1
        import recover_emulate as E
        img = E.Image(str(binp))
        for m in vt["methods"]:
            assert img.text_va <= m < img.text_end


def test_metadata_sections_not_scanned():
    """The scan must ignore .dynsym/.rela/.gnu.hash etc. (pointer-shaped metadata) -- only the data
    sections hold vtables. Precision regression guard: those sections yielded 150+ false vtables."""
    assert not RT._is_type_section(".dynsym", "ELF")
    assert not RT._is_type_section(".rela.dyn", "ELF")
    assert not RT._is_type_section(".gnu.hash", "ELF")
    assert RT._is_type_section(".data.rel.ro", "ELF")
    assert RT._is_type_section(".rodata", "ELF")


_VT_SRC = r"""
pub trait Shape { fn area(&self) -> u64; fn name(&self) -> &'static str; }
struct Sq(u64);           // Copy-like: no drop glue -> NULL drop_in_place slot in current rustc
struct Named(String);     // needs drop
impl Shape for Sq { fn area(&self) -> u64 { self.0 * self.0 } fn name(&self) -> &'static str { "sq" } }
impl Shape for Named { fn area(&self) -> u64 { self.0.len() as u64 } fn name(&self) -> &'static str { "named" } }
#[inline(never)]
fn mk(n: u64) -> Box<dyn Shape> { if n % 2 == 0 { Box::new(Sq(n)) } else { Box::new(Named(format!("{n}"))) } }
fn main() {
    let n = std::env::args().count() as u64;
    let v: Vec<Box<dyn Shape>> = (0..n + 3).map(mk).collect();
    let t: u64 = v.iter().map(|s| s.area() + s.name().len() as u64).sum();
    println!("{t}");
}
"""


@pytest.mark.skipif(not __import__("shutil").which("rustc"), reason="rustc not available")
def test_null_drop_vtable_of_copy_type(tmp_path):
    """A `dyn Trait` vtable for a type without drop glue has drop_in_place == 0; it must be found,
    and the adjacent vtable (Named, real drop) must stay separate rather than be swallowed."""
    import subprocess
    src = tmp_path / "vt.rs"
    src.write_text(_VT_SRC)
    out = exe(tmp_path / "vt")
    r = subprocess.run(["rustc", "-O", *RUSTC_TARGET, "-C", "symbol-mangling-version=v0", "-o", str(out),
                        str(src)], capture_output=True, text=True)
    if r.returncode != 0:
        pytest.skip("rustc failed: " + r.stderr[-200:])
    # address -> function name in the toolkit's own address space (Image.function_symbols: COFF values
    # are section-relative, CI windows-latest with the GNU target; ELF mapping symbols $x/$d, which
    # share each function's address on AArch64, are not functions and stay out)
    import recover_emulate as E
    syms = dict(E.Image(str(out)).function_symbols())
    res = RT.recover(out)
    by_method = {}
    for vt in res["vtables"]:
        for m in vt["methods"]:
            by_method.setdefault(syms.get(m, ""), []).append(vt)
    sq = [vt for n, vts in by_method.items() if "2SqNtB2_5Shape4area" in n for vt in vts]
    named = [vt for n, vts in by_method.items() if "5NamedNtB4_5Shape4area" in n for vt in vts]
    assert sq, "Sq (NULL drop_in_place) vtable missed"
    assert named, "Named vtable missed"
    assert sq[0]["drop_in_place"] == 0 and sq[0]["size"] == 8 and sq[0]["method_count"] == 2
    assert named[0]["va"] != sq[0]["va"] and named[0]["method_count"] == 2
    # no method run swallows a following vtable's drop_in_place
    for vt in res["vtables"]:
        assert not any("drop_in_place" in syms.get(m, "") or "drop_glue" in syms.get(m, "")
                       for m in vt["methods"]), hex(vt["va"])
