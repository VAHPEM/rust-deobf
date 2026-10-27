#!/usr/bin/env bash
# check.sh - cheap-test-first gate for rust-deobf (see CLAUDE.md).
#
#   ./scripts/check.sh            the ~8s selftest gate (every scripts/*.py --selftest)
#   ./scripts/check.sh changed    narrow-first: only the scripts changed vs origin/master
#                                 (override base: ./scripts/check.sh changed <ref>)
#   ./scripts/check.sh full       the fast CI subset (no Rust build; ~3.5 min)
#   ./scripts/check.sh <name>     one module's selftest + its tests/test_<name>.py
#
# Run from anywhere; paths resolve relative to the repo root.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
PY="${PYTHON:-python3}"

case "${1:-gate}" in
  gate|"")
    exec "$PY" -m pytest tests/test_selftests.py tests/test_docs_current.py -q
    ;;
  changed)
    base="${2:-origin/master}"
    # scripts touched since <base> (committed) plus anything dirty in the working tree
    { git diff --name-only "$base"...HEAD -- 'scripts/*.py' 'premium/*.py' 2>/dev/null
      git diff --name-only -- 'scripts/*.py' 'premium/*.py' 2>/dev/null
      git diff --name-only --cached -- 'scripts/*.py' 'premium/*.py' 2>/dev/null
    } | sort -u > /tmp/.check_changed.$$ || true
    if [ ! -s /tmp/.check_changed.$$ ]; then
      echo "no changed scripts vs $base -> running the full selftest gate"
      rm -f /tmp/.check_changed.$$
      exec "$PY" -m pytest tests/test_selftests.py tests/test_docs_current.py -q
    fi
    rc=0
    while IFS= read -r f; do
      [ -f "$f" ] || continue
      if grep -q -- "--selftest" "$f"; then
        echo "== $f --selftest =="
        "$PY" "$f" --selftest || rc=1
      fi
    done < /tmp/.check_changed.$$
    rm -f /tmp/.check_changed.$$
    exit "$rc"
    ;;
  full)
    exec "$PY" -m pytest tests -q -rs \
      --ignore=tests/test_benchmark.py --ignore=tests/test_scatter.py \
      --ignore=tests/test_obf.py --ignore=tests/test_libfuncs.py \
      --ignore=tests/test_32bit.py --ignore=tests/test_formats.py
    ;;
  *)
    name="$1"
    script="scripts/${name}.py"
    [ -f "$script" ] || script="premium/${name}.py"
    if [ -f "$script" ]; then
      echo "== $script --selftest =="
      "$PY" "$script" --selftest || true
    fi
    # test files usually drop the recover_ prefix (recover_crypto.py -> test_crypto.py)
    testfile=""
    for cand in "tests/test_${name}.py" "tests/test_${name#recover_}.py"; do
      [ -f "$cand" ] && testfile="$cand" && break
    done
    if [ -n "$testfile" ]; then
      echo "== $testfile =="
      exec "$PY" -m pytest "$testfile" -q
    else
      echo "(no test file for $name)"
    fi
    ;;
esac
