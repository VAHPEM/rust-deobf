"""redblue_loop.py regressions (Oct 2026 review). No toolchain needed: the build step and the
prerequisite probes are monkeypatched; the evaluated "binaries" are tiny synthetic byte files."""
import json
import subprocess
import sys
from pathlib import Path

from conftest import ROOT

sys.path.insert(0, str(ROOT / "scripts"))
import redblue_loop as rb  # noqa: E402


def _fake_prereqs(monkeypatch):
    monkeypatch.setattr(rb, "find_plugin", lambda _rc: Path("libRustCloak.so"))
    monkeypatch.setattr(rb, "find_nightly", lambda: "nightly-test")


def test_all_builds_failing_is_not_a_pass(tmp_path, monkeypatch, capsys):
    # every round failing to build used to print "0 rounds built, 0/0" and exit 0
    _fake_prereqs(monkeypatch)
    monkeypatch.setattr(rb, "build", lambda *a, **k: (False, "rustc failed: error: boom"))
    rc = rb.main(["--rounds", "3", "--seed", "1", "--out", str(tmp_path)])
    assert rc == rb.EXIT_NO_ROUNDS and rc != rb.EXIT_OK
    out = capsys.readouterr()
    assert "3 skipped" in out.out and "3 build failed" in out.out
    assert "not a pass" in out.err
    rows = [json.loads(x) for x in (tmp_path / "redblue_results.jsonl").read_text().splitlines()]
    assert [r["skipped"] for r in rows] == ["build failed"] * 3


def test_plaintext_round_is_skipped_not_scored(tmp_path, monkeypatch, capsys):
    # a binary where RustCloak hid nothing: every planted string is in plaintext
    _fake_prereqs(monkeypatch)

    def plain_build(src, cfg, nightly, plugin, out):
        out.write_bytes(src.encode())          # the Rust source contains every literal verbatim
        return True, "ok"
    monkeypatch.setattr(rb, "build", plain_build)
    real_eval = rb.evaluate

    def no_recover_eval(binary, iocs, tb, recover_fn=None):
        return real_eval(binary, iocs, tb, recover_fn=lambda _p: (_ for _ in ()).throw(
            AssertionError("recovery must not run on an un-hidden binary")))
    monkeypatch.setattr(rb, "evaluate", no_recover_eval)
    # escaped backslashes in the source differ from the runtime value, so use backslash-free iocs
    monkeypatch.setattr(rb, "gen_iocs", lambda rng, n: [("domain", f"d{i}.q.invalid")
                                                        for i in range(n)])
    rc = rb.main(["--rounds", "2", "--seed", "1", "--out", str(tmp_path)])
    assert rc == rb.EXIT_NO_ROUNDS
    assert "2 plugin had no effect" in capsys.readouterr().out


def test_not_hidden_strings_are_excluded_from_found_and_missed(tmp_path):
    planted = [("domain", "a.b.invalid"), ("path", "/var/tmp/.x/y.dat"), ("flag", "--p-q-mode")]
    b = tmp_path / "bin"
    b.write_bytes(b"\x7fELF.." + "a.b.invalid".encode("utf-16-le") + b"..")
    ev = rb.evaluate(b, planted, 1.0, recover_fn=lambda _p: {"decoded": [
        {"string": "/var/tmp/.x/y.dat"}], "stack": []})
    assert ev["not_hidden"] == [("domain", "a.b.invalid")]
    assert ev["planted"] == 2 and ev["recovered"] == 1
    assert ev["missed"] == [("flag", "--p-q-mode")]          # the plaintext one is not a miss


def test_build_reports_first_error_line(tmp_path, monkeypatch):
    stderr = ("warning: unused variable\n"
              "error: failed to load LLVM plugin libRustCloak.so: undefined symbol\n"
              "error: aborting due to 1 previous error\n")
    monkeypatch.setattr(rb.subprocess, "run",
                        lambda *a, **k: subprocess.CompletedProcess(a, 1, "", stderr))
    ok, msg = rb.build("fn main(){}", {}, "nightly", Path("p.so"), tmp_path / "out")
    assert not ok and "failed to load LLVM plugin" in msg and "aborting" not in msg
