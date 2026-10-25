"""Evaluation / CI tooling: evaluate_all (arch dispatch, hand-written sections kept),
measure_fp (one crash does not abort the run), build scripts (a failed build fails the script and
never ships a stale binary)."""
import os
import shutil
import stat
import subprocess
import sys

import pytest
from conftest import ROOT

import evaluate_all as EA
import measure_fp as MF


def test_static_recoverer_dispatch_by_arch():
    assert EA.static_recoverer("elf").__name__ == "recover_callsite"
    assert EA.static_recoverer("pe").__name__ == "recover_callsite"
    assert EA.static_recoverer("elf-arm64").__name__ == "recover_arm64"
    assert EA.static_recoverer("elf-arm64gnu").__name__ == "recover_arm64"
    assert EA.static_recoverer("macho") is None
    # cryptify's default-key build is recovered statically by recover_cryptify, on both arches
    assert EA.static_recoverer("elf", "cryptify_default").__name__ == "recover_cryptify"
    assert EA.static_recoverer("elf-arm64", "cryptify_default").__name__ == "recover_cryptify"


def test_bench_recall_skips_scatter_and_routes_arm64(tmp_path, monkeypatch):
    for n in ("xor_custom__elf__release__strip", "xor_custom__elf-arm64__release__strip",
              "scatter_xor_custom__elf__release__strip", "xor_custom__pe__release__strip.exe",
              "build_manifest.jsonl"):
        (tmp_path / n).write_bytes(b"x")
    seen = []

    class Fake:
        def __init__(self, name): self.__name__ = name
        def recover(self, path, canaries):
            seen.append((self.__name__, path.name))
            return {"recall": 5}
    monkeypatch.setattr(EA, "static_recoverer", lambda fmt, proj="": Fake("arm64" if fmt.startswith("elf-arm64") else "x86"))
    rows = EA.bench_recall(tmp_path)
    assert ("arm64", "xor_custom__elf-arm64__release__strip") in seen
    assert ("x86", "xor_custom__pe__release__strip.exe") in seen
    assert not any("scatter" in n for _, n in seen)
    assert {r[1] for r in rows} == {"elf", "elf-arm64", "pe"}


def test_kept_sections_survive():
    old = "# Metrics\n\n<!-- keep -->\n> hand-written note\n<!-- /keep -->\n\n## table\n| a |\n"
    assert EA.kept_sections(old) == ["<!-- keep -->\n> hand-written note\n<!-- /keep -->"]
    assert "<!-- keep -->" in (ROOT / "METRICS.md").read_text(), "METRICS.md's update note must be marked"


def test_measure_fp_pipeline_error_row(tmp_path):
    p = tmp_path / "bin"
    p.write_bytes(b"\0" * 16)
    row = MF._error_row(p, RuntimeError("boom"))
    assert row["error"] == "RuntimeError: boom" and row["false_positives"] == 0


def test_measure_fp_static_survives_crash(monkeypatch, tmp_path):
    import recover_callsite
    monkeypatch.setattr(recover_callsite, "recover", lambda *a, **k: (_ for _ in ()).throw(ValueError("bad")))
    r = MF.measure(tmp_path)
    assert "ValueError: bad" in r["error"]


@pytest.fixture
def failing_cargo(tmp_path):
    fb = tmp_path / "fakebin"
    fb.mkdir()
    c = fb / "cargo"
    c.write_text("#!/bin/sh\necho 'error: linker `cc` not found (fake cargo)' >&2\nexit 101\n")
    c.chmod(c.stat().st_mode | stat.S_IEXEC)
    env = dict(os.environ, PATH=f"{fb}{os.pathsep}{os.environ['PATH']}")
    return env


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash required")
def test_build_all_fails_loudly_and_ships_nothing_stale(tmp_path, failing_cargo):
    out = tmp_path / "build"
    out.mkdir()
    stale = out / "plaintext__elf__release__strip"
    stale.write_bytes(b"stale from an earlier build")
    env = dict(failing_cargo, BUILD_DIR=str(out), ONLY="plaintext", FORMATS="elf", PROFILES="release")
    r = subprocess.run(["bash", str(ROOT / "scripts" / "build_all.sh")], env=env,
                       capture_output=True, text=True, timeout=120)
    assert r.returncode != 0, r.stdout + r.stderr
    assert "fake cargo" in r.stderr                       # cargo's own error is visible
    assert "FAILED" in r.stderr
    assert not stale.exists(), "a failed build must not leave an earlier binary in the build dir"
    assert not (out / "plaintext__elf__release__nostrip").exists()


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash required")
def test_build_obf_fails_loudly(tmp_path, failing_cargo):
    env = dict(failing_cargo, BUILD_DIR=str(tmp_path), FORMATS="elf")
    r = subprocess.run(["bash", str(ROOT / "obf_src" / "build_obf.sh")], env=env,
                       capture_output=True, text=True, timeout=300)
    assert r.returncode != 0
    assert "fake cargo" in r.stderr and "FAILED" in r.stderr


def test_require_build_formats(monkeypatch):
    import conftest
    monkeypatch.delenv("RUST_DEOBF_REQUIRE_BUILD", raising=False)
    assert not conftest.build_required("obfstr__elf__release__strip")
    monkeypatch.setenv("RUST_DEOBF_REQUIRE_BUILD", "elf pe")
    assert conftest.build_required("obfstr__elf__release__strip")
    assert conftest.build_required("obfstr__pe__release__strip.exe")
    assert not conftest.build_required("obfstr__elf-arm64__release__strip")
    monkeypatch.setenv("RUST_DEOBF_REQUIRE_BUILD", "1")
    assert conftest.build_required("obfstr__elf-arm64__release__strip")


def test_require_build_turns_skip_into_failure(tmp_path):
    """End to end: with an empty build dir, the 'not built' skip fails only for required formats."""
    def run(req):
        env = dict(os.environ, RUST_DEOBF_BUILD=str(tmp_path), RUST_DEOBF_REQUIRE_BUILD=req)
        return subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
                               str(ROOT / "tests" / "test_soc_triage.py") + "::test_triage_record_shape"],
                              env=env, capture_output=True, text=True, cwd=ROOT, timeout=300)
    r = run("elf")
    assert r.returncode == 1 and "RUST_DEOBF_REQUIRE_BUILD" in r.stdout, r.stdout[-800:]
    r = run("pe")
    assert r.returncode == 0 and "skipped" in r.stdout, r.stdout[-800:]
