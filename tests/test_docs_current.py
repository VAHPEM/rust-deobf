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


def test_every_selftest_script_is_documented():
    """Every scripts/*.py that ships a --selftest must appear by name in CLAUDE.md's map."""
    text = CLAUDE_MD.read_text()
    missing = [
        p.stem
        for p in sorted((ROOT / "scripts").glob("*.py"))
        if "--selftest" in p.read_text(errors="replace") and p.stem not in text
    ]
    assert not missing, (
        "These scripts have a --selftest but are not named in CLAUDE.md. Add a one-line row for "
        f"each (and update check.sh if needed): {missing}"
    )


def test_every_premium_module_is_documented():
    """premium/ tools are not auto-tested, so they are especially easy to forget. Pin them here."""
    text = CLAUDE_MD.read_text()
    missing = [p.stem for p in sorted((ROOT / "premium").glob("*.py")) if p.stem not in text]
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


def test_check_sh_full_matches_ci_selftest_job():
    """`check.sh full` must ignore exactly what the CI selftest job ignores, or the local gate and
    CI disagree about what the fast subset is."""
    check = _ignored(CHECK_SH.read_text())
    # the CI selftest job's ignore list (the first run that passes --ignore in ci.yml)
    ci_block = CI_YML.read_text()
    ci = _ignored(ci_block)
    assert check and ci, "expected --ignore lists in both check.sh and ci.yml"
    assert check == ci, (
        "check.sh `full` and the CI selftest job disagree on the fast-subset ignore list.\n"
        f"  only in check.sh: {sorted(check - ci)}\n"
        f"  only in ci.yml:   {sorted(ci - check)}"
    )
