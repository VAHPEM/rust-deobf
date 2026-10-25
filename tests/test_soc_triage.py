"""SOC triage card (soc_triage.py).

The triage wrapper must, from one binary, produce a structured record with the fields a SOC
analyst needs (format/arch, is_rust, capability fingerprint, indicators grouped by tag, a decoded
sample, a calibrated signal) and must filter benign Rust std/compiler paths out of the indicators
so the card is not flooded. The record-shape test uses --fast against a canary from the build
directory scripts/build_all.sh writes ($RUST_DEOBF_BUILD, default build/); it skips if none is built
(a failure under RUST_DEOBF_REQUIRE_BUILD). The calibration tests check that unobfuscated, benign
Rust tools come out LOW and that obfuscation evidence is what raises the signal.
"""
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from conftest import BUILD, NOT_BUILT, ROOT

import soc_triage

SCRIPT = ROOT / "scripts" / "soc_triage.py"


def _canary(fmt="elf", names=("obfstr", "litcrypt", "plaintext")):
    """A release canary from the build dir (build_all.sh names <proj>__<fmt>__<profile>__<strip>)."""
    for name in names:
        p = BUILD / f"{name}__{fmt}__release__strip"
        if p.is_file():
            return p
    pytest.skip(NOT_BUILT + f"{names[0]}__{fmt}__release__strip")


def test_triage_record_shape():
    b = _canary()
    c = soc_triage.triage(b, fast=True, time_budget=20)
    # required fields
    for k in ("sha256", "format", "arch", "is_rust", "indicators", "literal_indicators",
              "triage_signal", "decoded_sample", "mode"):
        assert k in c, f"missing {k}"
    assert len(c["sha256"]) == 64
    assert c["is_rust"] is True, "a Rust canary must be detected as Rust"
    assert c["triage_signal"] in ("LOW", "MEDIUM", "HIGH")
    assert c["mode"].startswith("static (fast")   # --fast => no emulation
    # --fast decodes nothing: no static call-site pass, no stack strings, no VM scan
    assert c["decoded_total"] == 0 and c["virtualized_functions"] == 0
    assert c["triage_signal"] == "LOW"
    # benign std/compiler paths must be filtered out of the indicators
    flat = [s for grp in ("indicators", "literal_indicators") for vals in c[grp].values() for s in vals]
    assert not any("/rustc/" in s or "/rust/deps/" in s for s in flat), \
        f"benign std paths leaked into indicators: {flat[:3]}"


def test_obfuscated_canary_is_not_low_and_plaintext_is_low():
    """Full triage (static + emulation): hidden strings raise the signal; the plaintext build of the
    same program (nothing hidden) stays LOW."""
    obf = _canary(names=("litcrypt",))
    plain = _canary(names=("plaintext",))
    c = soc_triage.triage(obf, fast=False, time_budget=60)
    assert c["decoded_total"] > 0
    assert c["triage_signal"] in ("MEDIUM", "HIGH"), c["signal_reasons"]
    p = soc_triage.triage(plain, fast=False, time_budget=60)
    assert p["triage_signal"] == "LOW", p["signal_reasons"]


def _benign_rust_tool():
    for cand in (Path.home() / ".cargo" / "bin" / "rustup", shutil.which("rustup"),
                 shutil.which("cargo"), shutil.which("rg")):
        if cand and Path(cand).is_file():
            p = Path(cand).resolve()
            if p.stat().st_size > 1 << 20:     # a real binary, not a shim script
                return p
    pytest.skip("no benign Rust binary (rustup/cargo/rg) on this runner")


def test_benign_rust_tool_is_low_fast():
    # rustup/cargo carry plain update URLs and the tokio/hyper/rustls/windows-sys stack: none of that
    # is obfuscation, so the signal must be LOW and the URLs only listed as literal indicators
    c = soc_triage.triage(_benign_rust_tool(), fast=True, time_budget=20)
    assert c["triage_signal"] == "LOW", c["signal_reasons"]
    assert not c["indicators"], "plain literals must not be reported as hidden indicators"


def _fake_meta(crates):
    return {"is_rust": True, "rustc_commit": None, "rust_release": None, "counts": {},
            "crates": {c: {} for c in crates}}


def _fake_run(decoded=(), stack=(), literals=()):
    from recover_callsite import ioc_tags
    rec = lambda s: {"string": s, "tags": ioc_tags(s)}
    return lambda *a, **k: {"decoded": [rec(s) for s in decoded], "stack": [rec(s) for s in stack],
                            "literals": [rec(s) for s in literals], "notes": [], "engines": []}


@pytest.fixture
def fake(monkeypatch, tmp_path):
    """triage() on a stub binary with injected recover/meta results (no real analysis)."""
    import recover
    import recover_rust_meta
    import detect_vm
    f = tmp_path / "sample.bin"
    f.write_bytes(b"\x7fELF" + b"\0" * 60)
    monkeypatch.setattr(recover, "detect", lambda p: ("ELF", "x86_64", 0))
    monkeypatch.setattr(detect_vm, "detect", lambda p: {"count": 0, "functions": []})

    def setup(crates=(), **kw):
        monkeypatch.setattr(recover_rust_meta, "recover", lambda p: _fake_meta(crates))
        monkeypatch.setattr(recover, "run", _fake_run(**kw))
        return f
    return setup


COMMON = ["tokio", "hyper", "reqwest", "rustls", "ring", "base64", "sha2", "windows-sys", "flate2", "tar"]


def test_common_crates_and_literal_urls_stay_low(fake):
    f = fake(crates=COMMON, literals=["https://static.rust-lang.org/dist", "10.0.0.1",
                                      "HKEY_LOCAL_MACHINE\\SOFTWARE\\Foo"])
    c = soc_triage.triage(f, fast=False, time_budget=1)
    assert c["triage_signal"] == "LOW", c["signal_reasons"]
    assert c["literal_indicators"].get("url") and not c["indicators"]


def test_obfuscation_required_then_hidden_c2_is_high(fake):
    f = fake(crates=["aes-gcm", "winreg"], decoded=["https://c2.evil-example.net/gate",
                                                    "Global\\NW-5c1e9a-mutex"])
    c = soc_triage.triage(f, fast=False, time_budget=1)
    assert c["triage_signal"] == "HIGH", c["signal_reasons"]
    assert "https://c2.evil-example.net/gate" in c["indicators"]["url"]


def test_obfuscation_alone_is_medium(fake):
    f = fake(decoded=["just some hidden configuration text", "another hidden string",
                      "a third hidden string"])
    assert soc_triage.triage(f, fast=False, time_budget=1)["triage_signal"] == "MEDIUM"


def test_decoded_strings_formatted_from_literals_are_not_evidence(fake):
    # rustup: emulation rebuilds tempfile names from the plain literal "rustup-update"
    f = fake(decoded=["/tmp/rustup-updateANmKoZ", "/tmp/rustup-updateWlWrSY", "`/---MbOb/---M"],
             literals=["rustup-update"])
    assert soc_triage.triage(f, fast=False, time_budget=1)["triage_signal"] == "LOW"


def test_stack_strings_count_only_when_indicator_shaped(fake):
    f = fake(stack=["Enter ", "-point:", "datetime", "uespemosarenegylmodnarodsetybdet"])
    assert soc_triage.triage(f, fast=False, time_budget=1)["triage_signal"] == "LOW"
    f = fake(stack=["https://c2.evil-example.net/gate"])
    assert soc_triage.triage(f, fast=False, time_budget=1)["triage_signal"] != "LOW"


def test_one_untagged_decoded_string_is_not_evidence(fake):
    # a single recovered string without an indicator shape is within the engines' FP rate on
    # benign binaries (rg: one emulation FP, '  -e, --regexp=PATTERN')
    f = fake(decoded=["  -e, --regexp=PATTERN"], stack=["/dev/urandom"])
    assert soc_triage.triage(f, fast=False, time_budget=1)["triage_signal"] == "LOW"
    # ... but one hidden C2 URL is
    f = fake(decoded=["https://c2.evil-example.net/gate"])
    assert soc_triage.triage(f, fast=False, time_budget=1)["triage_signal"] != "LOW"


def test_vm_shape_in_interpreter_crate_not_scored(fake, monkeypatch):
    import detect_vm
    monkeypatch.setattr(detect_vm, "detect", lambda p: {"count": 16, "functions": []})
    f = fake(crates=["regex-automata", "memchr"])
    c = soc_triage.triage(f, fast=False, time_budget=1)
    assert c["triage_signal"] == "LOW" and c["virtualized_functions"] == 16
    f = fake(crates=["memchr"])
    assert soc_triage.triage(f, fast=False, time_budget=1)["triage_signal"] == "MEDIUM"


def test_crate_match_is_not_substring():
    assert soc_triage._crate_match("aes-gcm", ("aes",))
    assert soc_triage._crate_match("windows_sys", ("windows",))
    assert not soc_triage._crate_match("tracing-subscriber", ("tar",))
    assert not soc_triage._crate_match("serde_derive", ("des",))


def test_print_card_handles_missing_rustc_commit(capsys):
    card = {"triage_signal": "LOW", "mode": "static", "seconds": 0.1, "file": "/x/s.bin", "size": 10,
            "sha256": "0" * 64, "format": "ELF", "arch": "x86_64", "is_rust": True,
            "rustc_commit": None, "rust_release": None, "panic_sites": None, "capabilities": {},
            "indicators": {}, "literal_indicators": {}, "decoded_sample": [], "decoded_total": 0,
            "signal_reasons": []}
    soc_triage.print_card(card)                 # used to raise TypeError on None[:12]
    assert "rustc commit unknown" in capsys.readouterr().out


def test_non_binary_exit_code(tmp_path):
    t = tmp_path / "notes.txt"
    t.write_text("hello world this is text\n")
    r = subprocess.run([sys.executable, str(SCRIPT), str(t)], capture_output=True, text=True)
    assert r.returncode == 3, r.stderr
    r = subprocess.run([sys.executable, str(SCRIPT), str(tmp_path / "missing.bin")],
                       capture_output=True, text=True)
    assert r.returncode == 2


def test_fail_on(fake, capsys):
    f = fake(decoded=["https://c2.evil-example.net/gate"], crates=["aes"])
    assert soc_triage.main([str(f), "--json", "--fail-on", "HIGH"]) == 1
    assert json.loads(capsys.readouterr().out)["triage_signal"] == "HIGH"
    assert soc_triage.main([str(f), "--json", "--fail-on", "MEDIUM"]) == 1
    f2 = fake(literals=["https://example.com/"])
    assert soc_triage.main([str(f2), "--json", "--fail-on", "MEDIUM"]) == 0


def test_benign_filter():
    assert soc_triage._benign_indicator(
        "/rustc/2d8144b7880597b6e6d3dfd63a9a9efae3f533d3/library/std/src/io/mod.rs")
    assert soc_triage._benign_indicator("/rust/deps/gimli-0.32.3/src/read/abbrev.rs")
    # a real indicator-shaped path must NOT be filtered
    assert not soc_triage._benign_indicator("C:\\ProgramData\\NorthwindSvc\\state.db")
    assert not soc_triage._benign_indicator("/opt/app/resources/data.bin")


def test_crates_from_distro_and_cargo_paths():
    got = soc_triage._crates_from_paths([
        "/usr/share/cargo/registry/regex-automata-0.4.3/src/util/pool.rs",          # Debian layout
        "/cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aho-corasick-1.1.3/src/dfa.rs",
        "C:\\Users\\x\\.cargo\\registry\\src\\index.crates.io-6f17d22bba15001f\\tokio-1.40.0\\src\\a.rs"])
    assert got == {"regex-automata", "aho-corasick", "tokio"}
