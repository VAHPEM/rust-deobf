"""recover.py front end: exit codes, engine isolation, directory (batch) mode, option handling.

Uses the small committed lazy-strenc fixture and in-process stubs for the engines, so it needs no
benchmark build and runs in seconds.
"""
import json
import subprocess
import sys
from pathlib import Path

import pytest
from conftest import ROOT

import recover

SCRIPT = ROOT / "scripts" / "recover.py"
FIX = ROOT / "tests" / "fixtures" / "strenc" / "rustcloak_lazy.x64"


def _cli(*args):
    return subprocess.run([sys.executable, str(SCRIPT), *map(str, args)], capture_output=True, text=True)


def test_non_binary_exit_3(tmp_path):
    t = tmp_path / "text.txt"
    t.write_text("hello world this is text\n")
    r = _cli(t)
    assert r.returncode == recover.EXIT_UNSUPPORTED == 3, r.stderr
    assert "unsupported input" in r.stderr
    # no ready-to-paste dynamic command for something that is not even a binary
    assert "recover_dynamic" not in r.stdout


def test_usage_errors_exit_2(tmp_path):
    assert _cli(tmp_path / "missing.bin").returncode == 2
    d = tmp_path / "d"
    d.mkdir()
    # single-file outputs make no sense for a directory, and --jsonl none for a single file
    assert _cli(d, "--json").returncode == 2
    assert _cli(d, "--floss-json", tmp_path / "o.json").returncode == 2
    t = tmp_path / "t.txt"
    t.write_text("x")
    assert _cli(t, "--jsonl", tmp_path / "o.jsonl").returncode == 2


def _raise(*a, **k):
    raise RuntimeError("engine exploded")


@pytest.mark.skipif(not FIX.is_file(), reason="lazy fixture missing")
def test_engine_failure_is_isolated(monkeypatch):
    import recover_callsite
    import recover_cryptify
    import recover_emulate
    monkeypatch.setattr(recover_callsite, "recover", _raise)
    monkeypatch.setattr(recover_cryptify, "recover", lambda p: {"cryptify": False, "records": [], "note": None})
    called = {}

    def fake_emu(path, canaries, **kw):
        called["emu"] = True
        return {"records": [{"string": "recovered-by-emulation", "function": 0x1000, "method": "emulation"}],
                "functions_tried": 1, "functions_total": 1}
    monkeypatch.setattr(recover_emulate, "recover", fake_emu)
    res = recover.run(FIX, stackstrings=False, literals=False, time_budget=5)
    assert called.get("emu"), "emulation must still run after the static engine raised"
    assert [x["string"] for x in res["decoded"]] == ["recovered-by-emulation"]
    assert res["errors"] and "engine exploded" in res["errors"][0]["error"]
    assert any("failed" in n for n in res["notes"])


def test_run_dir_counts_and_errors(monkeypatch, tmp_path, capsys):
    (tmp_path / "x86.elf").write_bytes(b"a")
    (tmp_path / "ok.x64").write_bytes(b"b")
    (tmp_path / "boom.x64").write_bytes(b"c")
    (tmp_path / "notes.txt").write_bytes(b"d")
    kinds = {"x86.elf": ("ELF", "x86", 0), "ok.x64": ("ELF", "x86_64", 0),
             "boom.x64": ("ELF", "x86_64", 0), "notes.txt": (None, None, 0)}
    monkeypatch.setattr(recover, "detect", lambda p: kinds[Path(p).name])
    ran = []

    def fake_run(p, **kw):
        ran.append(Path(p).name)
        if Path(p).name == "boom.x64":
            raise ValueError("malformed")
        return {"file": str(p), "format": "ELF", "arch": kinds[Path(p).name][1],
                "decoded": [{"string": "abcdef", "tags": []}], "stack": [], "literals": [],
                "engines": [], "notes": [], "errors": []}
    monkeypatch.setattr(recover, "run", fake_run)
    out = tmp_path / "out.jsonl"
    rc = recover.run_dir(tmp_path, out)
    text = capsys.readouterr().out
    assert "x86.elf" in ran, "32-bit x86 must be analysed in directory mode too"
    assert "notes.txt" not in ran
    assert rc == recover.EXIT_ERROR                      # one file failed
    assert "3 binaries analysed, 1 with errors, 1 files skipped" in text
    assert "ERROR: ValueError: malformed" in text        # not a clean all-zero row
    recs = [json.loads(l) for l in out.read_text().splitlines()]
    assert {Path(r["file"]).name for r in recs} == {"x86.elf", "ok.x64", "boom.x64"}
    assert [r["error"] for r in recs if Path(r["file"]).name == "boom.x64"][0]


def test_run_dir_nothing_parseable(monkeypatch, tmp_path, capsys):
    (tmp_path / "a.txt").write_text("x")
    monkeypatch.setattr(recover, "detect", lambda p: (None, None, 0))
    assert recover.run_dir(tmp_path, None) == recover.EXIT_UNSUPPORTED


def test_dynamic_hint_is_quoted_and_not_a_command(capsys):
    res = {"file": "/tmp/dir with space/s.bin", "format": "ELF", "arch": "x86_64", "engines": [],
           "decoded": [], "stack": [], "literals": [], "notes": [], "errors": []}
    recover.print_text(res)
    out = capsys.readouterr().out
    assert "'/tmp/dir with space/s.bin'" in out
    assert "python " not in out                          # a hint, not a ready-to-paste run line
