import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "premium"))   # premium modules (AGPL): lift_vm, devirt_emulate, deobf_*
BUILD = Path(os.environ.get("RUST_DEOBF_BUILD", ROOT / "build"))   # scripts/build_all.sh BUILD_DIR
CANARIES = json.loads((ROOT / "bench_src" / "manifest.json").read_text())["canaries"]


# --- RUST_DEOBF_REQUIRE_BUILD: turn "binary missing" skips into failures ---------------------
# Benchmark tests skip when a binary is not built, so `pytest` works on a partial build. In CI that
# same leniency hides a broken build (every test skips, the job passes testing nothing). Set
# RUST_DEOBF_REQUIRE_BUILD to make a "not built: <name>" skip a failure:
#   RUST_DEOBF_REQUIRE_BUILD=1          any missing benchmark binary fails
#   RUST_DEOBF_REQUIRE_BUILD="elf pe"   only binaries of those build formats (the <fmt> field of
#                                       <proj>__<fmt>__<profile>__<strip>) -- what a per-format CI job
#                                       builds; other formats still skip
import re as _re

import pytest

NOT_BUILT = "not built: "          # the skip-reason prefix the tests use for a missing binary


def required_formats():
    v = os.environ.get("RUST_DEOBF_REQUIRE_BUILD", "").strip()
    if not v or v == "0":
        return None
    if v.lower() in ("1", "all", "yes", "true"):
        return "all"
    return set(v.replace(",", " ").split())


def build_required(name: str) -> bool:
    req = required_formats()
    if req is None:
        return False
    if req == "all":
        return True
    stem = name[:-4] if name.endswith(".exe") else name
    parts = stem.split("__")
    return len(parts) == 4 and parts[1] in req


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    rep = outcome.get_result()
    if not rep.skipped or required_formats() is None:
        return
    reason = rep.longrepr[2] if isinstance(rep.longrepr, tuple) and len(rep.longrepr) == 3 \
        else str(rep.longrepr)
    m = _re.search(_re.escape(NOT_BUILT) + r"(\S+)", reason)
    if m and build_required(m.group(1)):
        rep.outcome = "failed"
        rep.longrepr = (f"RUST_DEOBF_REQUIRE_BUILD={os.environ['RUST_DEOBF_REQUIRE_BUILD']!r}: required "
                        f"binary {m.group(1)} is missing from {BUILD} (did build_all.sh / "
                        "build_obf.sh fail?)")
