"""Cross-binary library-function identification (recover_libfuncs.py).

Signatures generated from one program's unstripped build must identify the same std/library
functions in a *different, stripped* program of the same toolchain, with no misidentification.
Ground truth is the target's own symbols (read from its nostrip build). Cases skip if the
required builds are absent, so this runs wherever build_all.sh has produced ELF/PE/ARM64 output.
"""
import lief
import pytest
from pathlib import Path
from conftest import BUILD

import recover_libfuncs as L

# (format, extension) pairs; the target is matched stripped, truth read from its nostrip build
FORMATS = [("elf", ""), ("pe", ".exe"), ("elf-arm64", "")]
# reference program (signatures) -> target program (identification); distinct programs
PAIRS = [("litcrypt", "xor_custom"), ("obfstr", "add_custom")]
PROFILE = "release"


def _truth(nostrip: Path):
    import gen_runtime_sigs as G
    b = lief.parse(str(nostrip))
    text = next((s for s in b.sections if s.name == ".text"), None)
    assert text is not None
    base, clen = text.virtual_address, len(bytes(text.content))
    truth = {}
    for s in b.symbols:
        if not getattr(s, "is_function", False):
            continue
        va = G.sym_va(b, s)                    # PE COFF values are section-relative; sym_va -> RVA
        if va and base <= va < base + clen:
            truth[va] = L.readable(s.name)
    return truth


@pytest.mark.parametrize("fmt,ext", FORMATS)
@pytest.mark.parametrize("ref,tgt", PAIRS)
def test_cross_binary_identification(ref, tgt, fmt, ext):
    ref_bin = BUILD / f"{ref}__{fmt}__{PROFILE}__nostrip{ext}"
    tgt_strip = BUILD / f"{tgt}__{fmt}__{PROFILE}__strip{ext}"
    tgt_nostrip = BUILD / f"{tgt}__{fmt}__{PROFILE}__nostrip{ext}"
    for p in (ref_bin, tgt_strip, tgt_nostrip):
        if not p.is_file():
            pytest.skip(f"not built: {p.name}")

    db = L.generate([ref_bin])                       # in-memory DB from the reference only
    assert db, "no signatures generated from reference build"
    res = L.match_binary(tgt_strip, db)

    truth = _truth(tgt_nostrip)
    wrong, no_truth, correct = [], 0, 0
    for r in res:
        t = truth.get(r["va"])
        if t is None:
            no_truth += 1
        elif t == r["name"]:
            correct += 1
        else:
            wrong.append((hex(r["va"]), r["name"], t))

    # every identified address must be a real function in the target, named correctly
    assert not wrong, f"misidentified: {wrong[:5]}"
    assert no_truth == 0, f"{no_truth} matches at addresses with no function in the target"
    assert correct >= 30, f"only {correct} library functions identified (expected many)"


# --- per-binary DB (gen_sigdb.py) end to end: needs cargo + the host toolchain, no network ---------
import os
import shutil
import subprocess

TINY = r'''
use std::collections::HashMap;
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut m: HashMap<String, usize> = HashMap::new();
    for a in &args { *m.entry(a.clone()).or_default() += a.len(); }
    let hay = args.get(1).map(|s| s.as_bytes().to_vec()).unwrap_or_default();
    let hit = DEP;
    let v: Vec<u32> = args.iter().map(|s| s.parse().unwrap_or(0)).collect();
    println!("{} {:?} {:?} {}", m.len(), hit, v.get(3), args.get(9).unwrap().len());
}
'''


def _tiny_build(tmp, with_dep: bool):
    proj = tmp / ("tiny_dep" if with_dep else "tiny")
    (proj / "src").mkdir(parents=True)
    dep = '[dependencies]\nmemchr = "2"\n' if with_dep else ""
    (proj / "Cargo.toml").write_text('[package]\nname = "tiny"\nversion = "0.1.0"\nedition = "2021"\n'
                                     '\n%s\n[workspace]\n' % dep)
    (proj / "src" / "main.rs").write_text(TINY.replace(
        "DEP", "memchr::memmem::find(&hay, b\"needle\")" if with_dep else "hay.iter().position(|&b| b == 7)"))
    env = dict(os.environ, CARGO_TARGET_DIR=str(tmp / "target"), CARGO_NET_OFFLINE="true")
    r = subprocess.run(["cargo", "build", "--release", "--offline"], cwd=proj, env=env,
                       capture_output=True, text=True, timeout=900)
    exe = tmp / "target" / "release" / ("tiny.exe" if os.name == "nt" else "tiny")
    return exe if r.returncode == 0 and exe.is_file() else None


@pytest.mark.skipif(not (shutil.which("cargo") and shutil.which("rustc")), reason="no cargo/rustc")
def test_per_binary_db_end_to_end(tmp_path, monkeypatch):
    import gen_sigdb as S
    strip = shutil.which("llvm-strip") or shutil.which("strip")
    if os.name == "nt" or not strip:
        pytest.skip("needs an ELF/Mach-O strip tool on a POSIX host")
    exe = _tiny_build(tmp_path, True) or _tiny_build(tmp_path, False)   # memchr if cached offline
    if exe is None:
        pytest.skip("tiny program did not build offline")
    nostrip, stripped = tmp_path / "tiny.nostrip", tmp_path / "tiny.strip"
    shutil.copy(exe, nostrip)
    shutil.copy(exe, stripped)
    subprocess.run([strip, str(stripped)], check=True, timeout=120)
    monkeypatch.setenv("RUST_DEOBF_CACHE", str(tmp_path / "cache"))
    # installed toolchains only, offline; crates compiled (opt-in) -- only crates from the local cache
    rep = S.generate_for_binary(stripped, timeout=1200, profiles=("release",), build_crates=True,
                                feature_sets=("default",))
    if rep["status"] == "missing":
        pytest.skip("toolchain/target for the host build not resolvable: %s" % rep["missing"])
    assert rep["status"] == "ok", rep
    assert rep["meta"]["toolchain_match"] == "exact"
    assert S.generate_for_binary(stripped, profiles=("release",), build_crates=True)["status"] == "cached"
    r = L.recover(stripped, db="auto")
    assert r["db"]["source"] == "auto" and r["db"]["toolchain_match"] == "exact", r["db"]
    truth = _truth(nostrip)
    res = r["libfuncs"]
    correct = sum(1 for x in res if truth.get(x["va"]) == x["name"])
    no_truth = sum(1 for x in res if x["va"] not in truth)
    assert no_truth == 0, "matches at addresses with no function"
    assert correct >= 100 and correct >= 0.97 * len(res), (correct, len(res))


@pytest.mark.skipif(not shutil.which("rustc"), reason="no rustc")
def test_bundle_std_roundtrip(tmp_path):
    """gen_sigdb --bundle-std writes a reproducible gzip DB recover_libfuncs can load."""
    import gen_sigdb as S
    host = subprocess.run(["rustc", "-vV"], capture_output=True, text=True).stdout
    triple = next((l.split(":", 1)[1].strip() for l in host.splitlines() if l.startswith("host:")), None)
    if not triple:
        pytest.skip("no host triple")
    out = tmp_path / "std.json.gz"
    meta = S.bundle_std(None, [triple], out)
    first = out.read_bytes()
    S.bundle_std(None, [triple], out)
    assert out.read_bytes() == first                       # byte-reproducible (gzip mtime=0)
    assert meta["targets"][triple] > 500
    import gzip
    import json as _json
    d = _json.loads(gzip.decompress(first))
    arch, fmt = S._triple_arch_fmt(triple)
    tool = [k for k in d if not k.startswith("__")][0]
    assert len(d[tool]["%s-%s" % (arch, fmt)]) == meta["targets"][triple]
