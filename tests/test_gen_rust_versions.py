"""gen_rust_versions.py: a failed fetch must never overwrite the commit -> release table.

Run offline it printed "0 releases" and wrote {} over the 118-entry table (found while refreshing it
for rustc 1.100). The fetch is stubbed here: no network."""
import json
import sys

from conftest import ROOT

sys.path.insert(0, str(ROOT / "scripts"))
import gen_rust_versions as G  # noqa: E402

OLD = {"a" * 40: {"version": "1.99.1", "date": "2026-10-15"},
       "b" * 40: {"version": "1.99.0", "date": "2026-10-01"}}


def _fake(found):
    return lambda v: (v, found.get(v))


def test_offline_fetch_keeps_the_table(tmp_path, monkeypatch, capsys):
    out = tmp_path / "rust_versions.json"
    out.write_text(json.dumps(OLD))
    monkeypatch.setattr(G, "fetch", _fake({}))
    assert G.main(["--max-minor", "9", "--max-patch", "0"], out=out) == 1
    assert json.loads(out.read_text()) == OLD
    assert "not written" in capsys.readouterr().err


def test_new_release_is_added_and_old_entries_kept(tmp_path, monkeypatch):
    out = tmp_path / "rust_versions.json"
    out.write_text(json.dumps(OLD))
    found = {"1.8.0": {"hash": "a" * 40, "date": "2026-10-15"},
             "1.9.0": {"hash": "b" * 40, "date": "2026-10-01"},
             "1.10.0": {"hash": "c" * 40, "date": "2026-11-12"}}
    monkeypatch.setattr(G, "fetch", _fake(found))
    assert G.main(["--max-minor", "10", "--max-patch", "0"], out=out) == 0
    t = json.loads(out.read_text())
    assert t["c" * 40] == {"version": "1.10.0", "date": "2026-11-12"} and len(t) == 3


def test_first_run_writes(tmp_path, monkeypatch):
    out = tmp_path / "sub" / "rust_versions.json"
    monkeypatch.setattr(G, "fetch", _fake({"1.8.0": {"hash": "d" * 40, "date": "2016-04-14"}}))
    assert G.main(["--max-minor", "8", "--max-patch", "0"], out=out) == 0
    assert json.loads(out.read_text()) == {"d" * 40: {"version": "1.8.0", "date": "2016-04-14"}}
