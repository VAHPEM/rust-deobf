"""gen_sigdb.py (per-binary signature DBs) and recover_libfuncs' DB selection -- no network, no
Rust build: target/toolchain detection on committed fixtures, cache keys and paths, object-file
signing on a hand-built ELF relocatable inside an `ar` archive, the process-tree timeout, the
missing-toolchain report, and `--db auto` picking / falling back. The end-to-end build (cargo +
toolchain) is in tests/test_libfuncs.py, which the fast CI subset skips."""
import json
import os
import re
import struct
import subprocess
import sys
import time
from pathlib import Path

import pytest

from conftest import ROOT

sys.path.insert(0, str(ROOT / "scripts"))
import gen_sigdb as S  # noqa: E402
import recover_libfuncs as L  # noqa: E402

FIX = ROOT / "tests" / "fixtures"


@pytest.mark.parametrize("rel,triple", [
    ("emu/null64", "x86_64-unknown-linux-gnu"),            # PIE, /lib64/ld-linux-x86-64.so.2
    ("emu/ct32", "i686-unknown-linux-gnu"),                # i386, /lib/ld-linux.so.2
    ("static/a64_stack", "aarch64-unknown-linux-musl"),    # static AArch64 ELF
    ("static/slice_rcx", "x86_64-unknown-linux-musl"),     # static x86-64 ELF, no glibc strings
    ("emu/mo_classic", "aarch64-apple-darwin"),            # Mach-O arm64
    ("emu/pe64.exe", "x86_64-pc-windows-msvc"),            # PE32+, no mingw markers
])
def test_detect_target(rel, triple):
    p = FIX / rel
    if not p.is_file():
        pytest.skip("fixture missing: %s" % rel)
    assert S.detect_target(p)["triple"] == triple


def test_cache_dir_env(monkeypatch, tmp_path):
    monkeypatch.setenv("RUST_DEOBF_CACHE", str(tmp_path / "c"))
    assert S.cache_dir() == tmp_path / "c" / "sigdb"
    monkeypatch.delenv("RUST_DEOBF_CACHE")
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
    assert S.cache_dir(windows=False) == tmp_path / "xdg" / "rust-deobf" / "sigdb"
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "lad"))     # Windows: %LOCALAPPDATA% wins
    assert S.cache_dir(windows=True) == tmp_path / "lad" / "rust-deobf" / "sigdb"
    assert S.cache_dir(windows=False) == tmp_path / "xdg" / "rust-deobf" / "sigdb"


def test_cache_key_components():
    base = {"rust_version": "1.85.0", "rustc_commit": None, "triple": "x86_64-pc-windows-gnu",
            "crates": [("a", "1.0.0"), ("b", None)]}
    k = S.cache_key(base)
    assert k.startswith("1.85.0-x86_64-pc-windows-gnu-")
    # a version change, an added crate or another target never collide
    others = [dict(base, crates=[("a", "1.0.1"), ("b", None)]),
              dict(base, crates=[("a", "1.0.0"), ("b", None), ("c", "0.1.0")]),
              dict(base, triple="i686-pc-windows-gnu"), dict(base, rust_version="1.85.1")]
    assert len({k} | {S.cache_key(o) for o in others}) == 5
    # the key is a safe file name even from hostile facts
    bad = S.cache_key(dict(base, triple="../../x", rust_version="1.0/../../y"))
    assert "/" not in bad and "\\" not in bad and ".." not in bad.split("-")[0].replace("1.0_.._.._y", "")


def test_binary_facts_non_rust_fixture():
    f = S.binary_facts(FIX / "emu" / "null64")
    assert f["triple"] == "x86_64-unknown-linux-gnu" and f["crates"] == []
    assert re.match(r"unknown-[0-9a-f]{16}-x86_64-unknown-linux-gnu-[0-9a-f]{16}$", f["key"]), f["key"]


# --- object signing: a hand-built ELF64 relocatable (no compiler needed) -------------------------
def _elf_rel(code: bytes, relocs):
    """ET_REL x86-64 with one function `foo` in .text.foo and RELA entries (offset, type, sym)."""
    shstr = b"\x00.text.foo\x00.rela.text.foo\x00.symtab\x00.strtab\x00.shstrtab\x00"
    strtab = b"\x00foo\x00ext\x00"
    sym = lambda name, info, shndx, value, size: struct.pack("<IBBHQQ", name, info, 0, shndx, value, size)
    symtab = sym(0, 0, 0, 0, 0) + sym(1, 0x12, 1, 0, len(code)) + sym(5, 0x10, 0, 0, 0)
    rela = b"".join(struct.pack("<QQq", off, (symi << 32) | typ, -4) for off, typ, symi in relocs)
    blobs = [code, rela, symtab, strtab, shstr]
    off, offs = 64, []
    body = b""
    for bl in blobs:
        pad = (-off) % 8
        body += b"\0" * pad
        off += pad
        offs.append(off)
        body += bl
        off += len(bl)
    shoff = off + ((-off) % 8)
    body += b"\0" * (shoff - off)
    def sh(name, typ, flags, o, size, link=0, info=0, align=1, ent=0):
        return struct.pack("<IIQQQQIIQQ", name, typ, flags, 0, o, size, link, info, align, ent)
    shdrs = (sh(0, 0, 0, 0, 0)
             + sh(1, 1, 6, offs[0], len(code), align=16)                      # .text.foo AX
             + sh(11, 4, 0x40, offs[1], len(rela), link=3, info=1, align=8, ent=24)
             + sh(27, 2, 0, offs[2], len(symtab), link=4, info=1, align=8, ent=24)
             + sh(35, 3, 0, offs[3], len(strtab))
             + sh(43, 3, 0, offs[4], len(shstr)))
    ident = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    hdr = struct.pack("<16sHHIQQQIHHHHHH", ident, 1, 0x3E, 1, 0, 0, shoff, 0, 64, 0, 0, 64, 6, 5)
    return hdr + body + shdrs


def _ar(members):
    out = b"!<arch>\n"
    for name, data in members:
        out += (name + "/").encode().ljust(16) + b"0".ljust(12) + b"0".ljust(6) + b"0".ljust(6) \
            + b"644".ljust(8) + str(len(data)).encode().ljust(10) + b"`\n" + data
        if len(data) & 1:
            out += b"\n"
    return out


def test_sign_rlib_object_masks_relocations(tmp_path):
    code = (b"\x53"                         # push rbx
            b"\x48\x8b\x05\0\0\0\0"         # mov rax,[rip+ext@GOTPCREL] (REX_GOTPCRELX @4)
            b"\x48\x89\xc3"                 # mov rbx,rax
            b"\xe8\0\0\0\0"                 # call ext (PLT32 @12)
            b"\xb8\0\0\0\0"                 # mov eax, ext (R_X86_64_32 @17: absolute, not pc-rel)
            b"\x5b\xc3" + b"\x90" * 9)      # pop rbx; ret; padding to 32 bytes
    obj = _elf_rel(code, [(4, 42, 2), (12, 4, 2), (17, 10, 2)])
    rlib = tmp_path / "libfoo-0123.rlib"
    rlib.write_bytes(_ar([("lib.rmeta", b"meta"), ("foo.cgu.0.o", obj)]))
    entries, st = S.sign_rlibs([rlib], "x86_64")
    assert st["objects"] == 1 and st["functions"] == 1, st
    assert len(entries) == 1 and entries[0]["sym"] == "foo"
    pat = entries[0]["pattern"]
    # REX + opcode of the relaxable GOT load and its disp, the call disp and the ABSOLUTE imm32
    # (which gen_runtime_sigs.mask alone keeps) are all wildcards; the rest is concrete
    assert pat == "53" + ".." * 7 + "4889c3" + "e8" + ".." * 4 + "b8" + ".." * 4 + "5bc3" + "90" * 9, pat
    assert len(pat) // 2 == len(code)


def test_run_kills_the_process_tree(tmp_path):
    pidfile = tmp_path / "pid"
    child = ("import subprocess,sys,time; p=subprocess.Popen([sys.executable,'-c','import time; "
             "time.sleep(60)']); open(%r,'w').write(str(p.pid)); time.sleep(60)" % str(pidfile))
    t0 = time.monotonic()
    rc, _o, err = S.run([sys.executable, "-c", child], 3)
    assert rc is None and "timed out" in err
    assert time.monotonic() - t0 < 30
    if os.name != "nt" and pidfile.exists():
        gpid = int(pidfile.read_text())
        for _ in range(50):
            try:
                os.kill(gpid, 0)
            except ProcessLookupError:
                break
            try:                                  # reap if it became our zombie (it should not)
                os.waitpid(gpid, os.WNOHANG)
            except ChildProcessError:
                pass
            time.sleep(0.1)
        else:
            pytest.fail("grandchild %d survived the timeout" % gpid)


def test_missing_toolchain_is_reported_not_installed(monkeypatch):
    """Without --allow-download nothing is installed: an unknown release is reported missing,
    with the command that would fix it."""
    facts = {"rust_version": "1.0.0", "rustc_commit": "0" * 40, "triple": "x86_64-unknown-linux-gnu",
             "target": {"arch": "x86_64"}, "crates": []}
    calls = []
    real = S.run
    def spy(cmd, *a, **k):
        calls.append([str(c) for c in cmd])
        return real(cmd, *a, **k)
    monkeypatch.setattr(S, "run", spy)
    tc, missing = S.resolve_toolchain(facts, None, False, S._base_env(False), S.Budget(120), lambda m: None)
    assert tc is None and missing and missing[0]["what"] == "toolchain"
    assert "rustup toolchain install 1.0.0" in missing[0]["fix"]
    assert not any("install" in c for cmd in calls for c in cmd), calls


def test_dry_run_plan_and_exit_code(tmp_path, monkeypatch):
    monkeypatch.setenv("RUST_DEOBF_CACHE", str(tmp_path))
    rep = S.generate_for_binary(FIX / "emu" / "null64", dry_run=True,
                                crates_override=[("itoa", "1.0.11"), ("serde", None)])
    assert rep["status"] == "dry-run"
    assert rep["plan"]["crates"] == ["itoa@1.0.11"] and "serde@?" in rep["plan"]["skipped"]
    assert 'package = "itoa", version = "=1.0.11"' in rep["plan"]["manifest"]
    assert not any(tmp_path.iterdir())                    # a dry run writes nothing
    assert S.main([str(FIX / "emu" / "null64"), "--dry-run", "--json"]) == 0
    assert S.main([str(tmp_path / "nope")]) == 2
    assert S.main([str(FIX / "emu" / "null64"), "--crates", 'x"y@1.0.0']) == 2


def test_db_auto_picks_cached_db_and_falls_back(tmp_path, monkeypatch):
    monkeypatch.setenv("RUST_DEOBF_CACHE", str(tmp_path))
    target = FIX / "emu" / "null64"
    # nothing cached -> the bundled DB, with the reason
    db, info = L.select_db(target, "auto")
    assert info["source"] == "bundled" and "no cached DB" in info["fallback_reason"]
    # a cached per-binary DB for this binary's key -> used, with its toolchain-match quality
    facts = S.binary_facts(target)
    import gen_runtime_sigs as G
    import lief
    b = lief.parse(str(target))
    text = next(s for s in b.sections if s.name == ".text")
    start = min(a for a in G.function_starts(b) if text.virtual_address <= a)
    code = bytes(text.content)[start - text.virtual_address:][:L.SIG_LEN]
    fake = {"__meta__": {"format": S.SIGDB_FORMAT, "built": {"rust_version": "1.85.0",
                                                             "rustc_commit": None,
                                                             "triple": facts["triple"]}},
            "rustc-1.85.0": {"x86_64": [{"name": "probe::fn0", "sym": "_probe", "pattern": code.hex()}]}}
    S.write_db(S.cache_path(facts["key"]), fake)
    r = L.recover(target, db="auto")
    assert r["db"]["source"] == "auto" and r["db"]["path"] == str(S.cache_path(facts["key"]))
    assert r["db"]["toolchain_match"] == "unknown"        # the fixture carries no rustc version
    assert [x["name"] for x in r["libfuncs"]] == ["probe::fn0"]
    # an explicit DB file, and the default (bundled) path unchanged
    r2 = L.recover(target, db=str(S.cache_path(facts["key"])))
    assert r2["db"]["source"] == "file" and len(r2["libfuncs"]) == 1
    assert L.select_db(target, "bundled")[1]["source"] == "bundled"
    # the CLI reports the DB only when --db is given
    out = subprocess.run([sys.executable, str(ROOT / "scripts" / "recover_libfuncs.py"), str(target),
                          "--json", "--db", "auto"], capture_output=True, text=True, timeout=300,
                         env=dict(os.environ, RUST_DEOBF_CACHE=str(tmp_path)))
    d = json.loads(out.stdout)
    assert d["db"]["source"] == "auto" and len(d["libfuncs"]) == 1


def test_bundled_quality_from_group_keys():
    meta = {"rustc_commit": None, "rust_release": {"version": "1.97.0"}}
    assert L._bundled_quality({"rustc-1.97.0": {}}, meta)[0] == "exact"
    assert L._bundled_quality({"rustc-1.97.1": {}}, meta)[0] == "same-minor"
    assert L._bundled_quality({"rustc-1.85.0": {}, "__meta__": {}}, meta)[0] == "mismatch"
    assert L._bundled_quality({"rustc-1.85.0": {}, "rustc-1.97.0": {}}, meta)[0] == "exact"


# --- unknown-toolchain binaries no longer share a cache key ---------------------------------------
def test_unknown_rustc_key_includes_binary_fingerprint():
    """Two different binaries with no recoverable rustc and the same (empty) crate set used to get
    the same `unknown-<triple>-<crates>` key, i.e. one would silently use the other's DB."""
    a, b = FIX / "emu" / "null64", FIX / "emu" / "ct64"
    fa, fb = S.binary_facts(a), S.binary_facts(b)
    assert fa["rust_version"] is None and fa["rustc_commit"] is None and fa["crates"] == fb["crates"]
    assert fa["triple"] == fb["triple"]
    assert fa["key"] != fb["key"]
    assert fa["key"] == S.binary_facts(a)["key"]                      # stable for one file


def test_rustc_from_comment_section(tmp_path):
    """ELF `.comment` ("rustc version 1.85.0 (4d91de4e4 2025-02-17)") names the toolchain when no
    /rustc/<hash>/ panic path survived (GNU strip keeps .comment)."""
    p = tmp_path / "bin"
    p.write_bytes((FIX / "emu" / "null64").read_bytes() + b"\0rustc version 1.85.0 (4d91de4e4 2025-02-17)\0")
    f = S.binary_facts(p)
    assert (f["rust_version"], f["rustc_commit"], f["rustc_source"]) == ("1.85.0", "4d91de4e4", ".comment")
    assert f["key"].startswith("1.85.0-x86_64-unknown-linux-gnu-")


# --- more crate evidence: cargo-auditable, symbol roots, name/version strings ----------------------
class _Sec:
    def __init__(self, name, content):
        self.name, self.content = name, content


class _Bin:
    def __init__(self, sections):
        self.sections = sections


def test_auditable_section():
    import zlib
    doc = {"packages": [{"name": "app", "version": "0.1.0", "root": True},
                        {"name": "serde", "version": "1.0.229", "dependencies": []},
                        {"name": "cc", "version": "1.2.0", "kind": "build"},
                        {"name": "bad\"name", "version": "1.0.0"}]}
    b = _Bin([_Sec(".text", b""), _Sec(".dep-v0", zlib.compress(json.dumps(doc).encode()))])
    assert S._auditable(b) == [("serde", "1.0.229")]
    assert S._auditable(_Bin([_Sec(".dep-v0", b"not zlib")])) == []


def test_crate_list_merges_evidence():
    meta = {"crates": {"serde_json": ["1.0.140"], "regex": []}, "panic_sites": []}
    ev = {"auditable": [("ryu", "1.0.23")],
          "symbol_crates": ["serde_core", "regex", "itoa"],
          "name_versions": {"regex": ["1.11.1"], "itoa": ["1.0.18"], "mozilla": ["5.0.0"]}}
    got = dict(S.crate_list(meta, ev))
    assert got == {"serde_json": "1.0.140", "ryu": "1.0.23", "regex": "1.11.1", "itoa": "1.0.18",
                   "serde_core": None}, got           # a lone version string names no crate
    assert S.crate_list(meta) == [("regex", None), ("serde_json", "1.0.140")]   # old behaviour


def test_crate_evidence_name_version_strings(tmp_path):
    p = tmp_path / "bin"
    p.write_bytes((FIX / "emu" / "null64").read_bytes() + b"\0ua: serde_json/1.0.140 x\0ok-crate/0.2.3\0")
    ev = S.crate_evidence(p)
    assert ev["name_versions"]["serde_json"] == ["1.0.140"] and ev["name_versions"]["ok-crate"] == ["0.2.3"]


# --- dependency resolution + feature variants (cargo metadata parsed, no cargo needed) -----------
def _fake_metadata():
    def pkg(i, name, ver, feats=(), proc=False):
        return {"id": i, "name": name, "version": ver, "features": {f: [] for f in feats},
                "targets": [{"kind": ["proc-macro" if proc else "lib"]}]}
    pk = [pkg("root", "rd_sigdb_probe", "0.0.0"), pkg("a", "serde_json", "1.0.140", ["std", "raw_value", "unstable", "_priv"]),
          pkg("b", "ryu", "1.0.23", ["small"]), pkg("c", "serde_derive", "1.0.229", proc=True),
          pkg("d", "syn", "2.0.0"), pkg("e", "cc", "1.2.0")]
    k = lambda kind=None: [{"kind": kind, "target": None}]
    nodes = [{"id": "root", "deps": [{"pkg": "a", "dep_kinds": k()}]},
             {"id": "a", "deps": [{"pkg": "b", "dep_kinds": k()}, {"pkg": "c", "dep_kinds": k()},
                                  {"pkg": "e", "dep_kinds": k("build")}]},
             {"id": "c", "deps": [{"pkg": "d", "dep_kinds": k()}]}]
    return json.dumps({"packages": pk, "resolve": {"root": "root", "nodes": nodes}})


def test_resolve_graph_and_variants(monkeypatch, tmp_path):
    calls = []
    def fake_run(cmd, *a, **k):
        calls.append([str(c) for c in cmd])
        return 0, _fake_metadata(), ""
    monkeypatch.setattr(S, "run", fake_run)
    g = S.resolve_graph(tmp_path, {"cargo": "cargo"}, "x86_64-unknown-linux-gnu", {}, ["--offline"], S.Budget(60))
    assert calls[0][1:3] == ["metadata", "--format-version"] and "--offline" in calls[0]
    # normal deps only: the proc-macro (and its deps) and the build-dependency are not linked
    assert g["normal"] == [("ryu", "1.0.23"), ("serde_json", "1.0.140")]
    assert g["features"][("serde_json", "1.0.140")] == ["raw_value", "std"]   # unstable/_priv skipped
    crates = [("serde_json", "1.0.140")]
    allv = S._variant(crates + [("ryu", "1.0.23")], "all", g["features"])
    man = S.render_manifest(allv, "release", "1.85.0")
    assert 'features = ["raw_value", "std"]' in man and 'package = "ryu"' in man
    assert "default-features = false" in S.render_manifest(S._variant(crates, "none", {}), "release", None)
    with pytest.raises(ValueError):
        S.render_manifest([("x", "1.0.0", {"features": ['a"]']})], "release", None)


def test_choose_profiles():
    assert S.choose_profiles(None) == ["release"]
    assert S.choose_profiles(S.AUTO_RELEASE_MIN) == ["release"]
    assert S.choose_profiles(S.AUTO_LTO_MAX / 2) == ["size-lto", "speed-lto"]
    mid = (S.AUTO_RELEASE_MIN + S.AUTO_LTO_MAX) / 2
    assert S.choose_profiles(mid) == ["release", "size-lto", "speed-lto"]


# --- safety: crates are compiled only on request; --db auto never builds ---------------------------
def test_crates_not_built_without_build_crates(monkeypatch, tmp_path):
    monkeypatch.setenv("RUST_DEOBF_CACHE", str(tmp_path / "cache"))
    sysroot = tmp_path / "sysroot"
    (sysroot / "lib" / "rustlib" / "x86_64-unknown-linux-gnu" / "lib").mkdir(parents=True)
    tc = {"name": "fake", "rustc": "rustc", "cargo": "cargo", "sysroot": str(sysroot), "version": "1.85.0",
          "commit": None, "host": "x86_64-unknown-linux-gnu", "llvm": None}
    monkeypatch.setattr(S, "resolve_toolchain", lambda *a, **k: (tc, []))
    calls = []
    def fake_run(cmd, *a, **k):
        calls.append([str(c) for c in cmd])
        return (0, _fake_metadata(), "") if "metadata" in cmd else (1, "", "should not run")
    monkeypatch.setattr(S, "run", fake_run)
    rep = S.generate_for_binary(FIX / "emu" / "null64", crates_override=[("serde_json", "1.0.140")],
                                exerciser=False, profiles=("release",))
    assert rep["status"] == "ok"
    assert not any(c[1] in ("build", "rustc") for c in calls), calls     # metadata only
    assert any("NOT built" in n for n in rep["meta"]["notes"])
    assert rep["meta"]["built"]["crates_resolved"] == ["ryu@1.0.23"]
    # with --build-crates the build is attempted (and fails here: fake cargo)
    calls.clear()
    rep = S.generate_for_binary(FIX / "emu" / "null64", crates_override=[("serde_json", "1.0.140")],
                                exerciser=False, profiles=("release",), build_crates=True, force=True,
                                feature_sets=("default",))
    assert any(c[1] == "build" for c in calls)


def test_db_auto_only_reads_the_cache(monkeypatch, tmp_path):
    """recover_libfuncs --db auto must never build, install or download: it only looks up the
    cache. Every process-spawning path and the generator are booby-trapped."""
    monkeypatch.setenv("RUST_DEOBF_CACHE", str(tmp_path))
    def boom(*a, **k):
        raise AssertionError("--db auto tried to run something: %r" % (a[:1],))
    monkeypatch.setattr(subprocess, "Popen", boom)
    monkeypatch.setattr(subprocess, "run", boom)
    monkeypatch.setattr(S, "run", boom)
    monkeypatch.setattr(S, "generate_for_binary", boom)
    monkeypatch.setattr(S, "resolve_toolchain", boom)
    r = L.recover(FIX / "emu" / "null64", db="auto")
    assert r["db"]["source"] == "bundled" and "no cached DB" in r["db"]["fallback_reason"]


def test_resolution_retries_without_default_features(monkeypatch, tmp_path):
    """Offline, a crate whose DEFAULT features need a package the cache lacks (clap_builder ->
    anstream when the program used clap without defaults) is resolved without default features
    instead of failing the whole resolution."""
    seen = []
    def fake_run(cmd, *a, **k):
        man = (tmp_path / "Cargo.toml").read_text()
        seen.append(man)
        if "default-features = false" not in man:
            return 101, "", ("error: no matching package named `anstream` found\nrequired by package "
                             "`clap_builder v4.6.7`\n")
        return 0, _fake_metadata(), ""
    monkeypatch.setattr(S, "run", fake_run)
    def wm(deps, profile):
        (tmp_path / "Cargo.toml").write_text(S.render_manifest(deps, profile, "1.85.0"))
    notes = []
    g, crates = S._resolve_with_fallback(tmp_path, [("clap_builder", "4.6.7"), ("anyhow", "1.0.104")],
                                         {"cargo": "cargo"}, "x86_64-unknown-linux-gnu", {}, ["--offline"],
                                         S.Budget(60), wm, notes)
    assert g is not None and len(seen) == 2
    assert crates == [("clap_builder", "4.6.7", {"default_features": False}), ("anyhow", "1.0.104")]
    assert "without default features" in notes[0]


def test_build_fallback_ladder():
    base = [("a", "1.0.0"), ("b", "2.0.0", {"default_features": False})]
    assert S._fallbacks(("a", "1.0.0", {"features": ["x"]}), base) == [("a", "1.0.0")]
    assert S._fallbacks(("a", "1.0.0"), base) == [("a", "1.0.0", {"default_features": False})]
    assert S._fallbacks(("a", "1.0.0", {"default_features": False}), base) == []      # -> dropped
    assert S._fallbacks(("b", "2.0.0", {"default_features": False, "features": ["y"]}), base) == \
        [("b", "2.0.0", {"default_features": False})]


def test_offline_all_features_skip_optional_dependencies():
    """Offline, `all` features must not enable features that pull an optional dependency (another
    crate that would have to be fetched): serde_json's preserve_order -> indexmap."""
    fmap = {"default": ["std"], "std": ["serde/std"], "preserve_order": ["indexmap", "std"],
            "raw_value": [], "arbitrary": ["dep:arbitrary"], "small": ["ryu?/small"],
            "uses_po": ["preserve_order"], "logging": ["aho-corasick?/logging"]}
    pkgs = {"serde_json": [(fmap, {"indexmap", "arbitrary", "ryu", "aho-corasick"},
                            {"serde": "serde", "ryu": "ryu", "aho-corasick": "aho-corasick",
                             "indexmap": "indexmap", "arbitrary": "arbitrary"})],
            "serde": [({"std": []}, set(), {})],
            "ryu": [({"small": []}, set(), {})],
            # a weak `x?/f` still pulls x's optional dependency when f enables one (regex ->
            # aho-corasick/logging -> log)
            "aho-corasick": [({"logging": ["dep:log"]}, {"log"}, {"log": "log"})]}
    pulls = {f for f in fmap if S._pulls_optional_dep("serde_json", f, pkgs)}
    assert pulls == {"preserve_order", "arbitrary", "uses_po", "logging"}, pulls


def test_source_path_glued_to_next_string():
    """rodata strings are not separated: `.../smallvec-1.16.4/src/lib.rsErrorcontext` -- the path
    regex used a word boundary after `.rs` and missed every path followed by an uppercase letter
    (smallvec was undetectable in a stripped clap/smallvec program)."""
    import recover_rust_meta as M
    blob = (b"\0/h/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/smallvec-1.16.4/src/lib.rs"
            b"Errorcontext\0/h/.cargo/registry/src/idx/itoa-1.0.18/src/lib.rs\0")
    paths = M.find_source_paths([(0x1000, blob)])
    crates, _ = M.fingerprint_crates(paths.keys(), "", True)
    assert crates.get("smallvec") == {"1.16.4"} and crates.get("itoa") == {"1.0.18"}, crates
    # a lowercase continuation still does not end a path (`x.rsx` is not a source file)
    assert not M.find_source_paths([(0, b"\0/a/src/x.rsx\0")])
