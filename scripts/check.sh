#!/usr/bin/env bash
# check.sh - cheap-test-first gate for rust-deobf (see CLAUDE.md).
#
#   ./scripts/check.sh            the ~8s selftest gate (every scripts/*.py --selftest)
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
    exec "$PY" -m pytest tests/test_selftests.py -q
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
