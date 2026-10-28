"""Keep CLAUDE.md and scripts/check.sh honest.

These are near-free guards (no binary, no build) that run inside the ~8s selftest gate. They fail
the moment the repo drifts from its own always-loaded map, so a session that adds a tool or changes
the CI test split is *told* to update CLAUDE.md / check.sh instead of silently leaving them stale.
That is the automation behind "if something changes, update CLAUDE.md / check.sh".
"""
import re

from conftest import ROOT

CLAUDE_MD = ROOT / "CLAUDE.md"
CHECK_SH = ROOT / "scripts" / "check.sh"
CI_YML = ROOT / ".github" / "workflows" / "ci.yml"


def test_claude_md_exists():
    assert CLAUDE_MD.is_file(), "CLAUDE.md is the always-loaded architecture map; do not delete it"


def _documented(stem: str, text: str) -> bool:
    """`stem` is named in `text` as a whole word -- a bare substring test would let an undocumented
    `recover_rust.py` pass because `recover_rust_meta` is documented (`_` is a word character, so
    `\b` does not match inside `recover_rust_meta`)."""
    return re.search(rf"\b{re.escape(stem)}\b", text) is not None


def test_documented_is_whole_word():
    text = "| `recover_rust_meta.py` | Tier 3 |  premium `deobf_cff.py` ·"
    assert _documented("recover_rust_meta", text)
    assert _documented("deobf_cff", text)
    assert not _documented("recover_rust", text)
    assert not _documented("rust_meta", text)
    assert not _documented("deobf", text)


def test_every_selftest_script_is_documented():
    """Every scripts/*.py that ships a --selftest must appear by name in CLAUDE.md's map."""
    text = CLAUDE_MD.read_text(encoding="utf-8")
    missing = [
        p.stem
        for p in sorted((ROOT / "scripts").glob("*.py"))
        if "--selftest" in p.read_text(errors="replace") and not _documented(p.stem, text)
    ]
    assert not missing, (
        "These scripts have a --selftest but are not named in CLAUDE.md. Add a one-line row for "
        f"each (and update check.sh if needed): {missing}"
    )


def test_every_premium_module_is_documented():
    """premium/ tools are not auto-tested, so they are especially easy to forget. Pin them here."""
    text = CLAUDE_MD.read_text(encoding="utf-8")
    missing = [p.stem for p in sorted((ROOT / "premium").glob("*.py"))
               if not _documented(p.stem, text)]
    assert not missing, f"These premium/ modules are not named in CLAUDE.md: {missing}"


# Scripts whose entry point is not a headless single-run (front ends, servers, loops, harnesses) or
# that have a documented reason not to carry --json. Keep this list short and justified.
_NO_JSON_OK = {
    "fuzz_recover",      # a fuzzing campaign: streams findings, not one result dict
    "redblue_loop",      # a continuous generate/verify loop, not a one-shot analysis
    "mcp_server",        # already speaks structured JSON over the MCP protocol
    "dump_unpacked",     # writes unpacked stages to files; its output is the dumped bytes
}


def test_result_scripts_support_json():
    """Every script with a recover()/analyze() entry point must accept --json so an agent (or the
    MCP server) can consume a parseable dict instead of paging verbose human output -- a quiet but
    real per-run token cost. Add --json when you add such a script, or justify it in _NO_JSON_OK."""
    import ast

    gaps = []
    for d in ("scripts", "premium"):
        for p in sorted((ROOT / d).glob("*.py")):
            src = p.read_text(errors="replace")
            try:
                top = {n.name for n in ast.parse(src).body if isinstance(n, ast.FunctionDef)}
            except SyntaxError:
                continue
            if top & {"recover", "analyze"} and p.stem not in _NO_JSON_OK and "--json" not in src:
                gaps.append(f"{d}/{p.name}")
    assert not gaps, (
        "These result-producing scripts don't accept --json (add it, or add the stem to "
        f"_NO_JSON_OK with a reason): {gaps}"
    )


def _ignored(text):
    return set(re.findall(r"--ignore=tests/(\S+?\.py)", text))


def _ci_job_text(yml: str, job: str = "selftest") -> str:
    """The `run:` commands of one CI job only -- the ignore list of a *different* job (or a
    comment elsewhere in ci.yml) must not count. Parsed with PyYAML when it is installed, else by
    cutting ci.yml at the job's header and the next job header at the same indentation."""
    try:
        import yaml
    except ImportError:
        yaml = None
    if yaml is not None:
        doc = yaml.safe_load(yml) or {}
        steps = ((doc.get("jobs") or {}).get(job) or {}).get("steps") or []
        return "\n".join(str(s.get("run", "")) for s in steps if isinstance(s, dict))
    lines = yml.splitlines()
    out, indent = [], None
    for line in lines:
        stripped = line.lstrip(" ")
        ind = len(line) - len(stripped)
        if indent is None:
            if stripped.rstrip() == f"{job}:" and ind > 0:
                indent = ind
            continue
        if stripped and ind <= indent and not stripped.startswith("#"):
            break                                   # the next job (or a new top-level key)
        if not stripped.startswith("#"):
            out.append(line)
    return "\n".join(out)


_TWO_JOBS = """\
jobs:
  selftest:
    steps:
      # --ignore=tests/test_in_a_comment.py
      - run: pytest tests --ignore=tests/test_a.py
  benchmark:
    steps:
      - run: pytest tests --ignore=tests/test_b.py
"""


def test_ci_job_text_is_scoped_to_the_job(monkeypatch):
    assert _ignored(_ci_job_text(_TWO_JOBS)) == {"test_a.py"}
    monkeypatch.setitem(__import__("sys").modules, "yaml", None)       # the no-PyYAML fallback
    assert _ignored(_ci_job_text(_TWO_JOBS)) == {"test_a.py"}
    assert _ci_job_text(_TWO_JOBS, "nope") == ""


def test_check_sh_full_matches_ci_selftest_job():
    """`check.sh full` must ignore exactly what the CI selftest job ignores, or the local gate and
    CI disagree about what the fast subset is."""
    check = _ignored(CHECK_SH.read_text(encoding="utf-8"))
    # only the selftest job's commands, not every --ignore anywhere in ci.yml
    ci = _ignored(_ci_job_text(CI_YML.read_text(encoding="utf-8")))
    assert check and ci, "expected --ignore lists in both check.sh and ci.yml"
    assert check == ci, (
        "check.sh `full` and the CI selftest job disagree on the fast-subset ignore list.\n"
        f"  only in check.sh: {sorted(check - ci)}\n"
        f"  only in ci.yml:   {sorted(ci - check)}"
    )
