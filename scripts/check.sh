#!/usr/bin/env bash
# check.sh - cheap-test-first gate for rust-deobf (see CLAUDE.md).
#
#   ./scripts/check.sh            the ~8s selftest gate (every scripts/*.py --selftest)
#   ./scripts/check.sh changed    narrow-first: only the scripts changed vs origin/master
#                                 (override base: ./scripts/check.sh changed <ref>)
#   ./scripts/check.sh full       the fast CI subset (no Rust build; ~3.5 min)
#   ./scripts/check.sh <name>     one module's selftest + its test file(s); <name> is a module in
#                                 scripts/ or premium/ (recover_crypto, scripts/recover_crypto.py, ...)
#
# Exit status: 0 all passed; 1 a selftest or test failed; 2 usage error (unknown module, bad ref).
# CHECK_DRY_RUN=1 prints the commands instead of running them (used by tests/test_check_sh.py).
# Run from anywhere; paths resolve relative to the repo root.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
PY="${PYTHON:-python3}"

# run "$@" (or just print it under CHECK_DRY_RUN=1); never aborts the script on failure -- the
# caller collects the status
run() {
  if [ "${CHECK_DRY_RUN:-0}" = 1 ]; then
    echo "+ $*"
    return 0
  fi
  "$@"
}

# test files for a module: an explicit map for the ones whose test is not named after the module,
# then the conventional names (test_<name>.py, minus a recover_/deobf_ prefix).
tests_for() {
  local name="$1" t
  case "$name" in
    fuzz_recover)     echo tests/test_fuzz.py; return ;;
    deobf_expr)       echo tests/test_expr_rustcloak.py; return ;;
    unpack)           echo tests/test_unpack_unified.py; return ;;
    unpack_emulate)   echo tests/test_unpack.py; return ;;
    recover_emulate)  echo tests/test_emulate_regressions.py; return ;;
    recover)          echo tests/test_recover_cli.py; return ;;
    redblue_loop)     echo tests/test_redblue_loop.py; return ;;
    heldout_eval)     echo tests/test_heldout_scoring.py; return ;;
    evaluate_all|measure_fp) echo tests/test_eval_tools.py; return ;;
    recover_apihash|recover_stackstrings|recover_rust_meta|recover_rust_strings|recover_artifacts|\
    recover_callsite|recover_arm64)
                      echo tests/test_static_regressions.py; return ;;
  esac
  for t in "tests/test_${name}.py" "tests/test_${name#recover_}.py" "tests/test_${name#deobf_}.py"; do
    if [ -f "$t" ]; then echo "$t"; return; fi
  done
}

case "${1:-gate}" in
  gate|"")
    exec "$PY" -m pytest tests/test_selftests.py tests/test_docs_current.py -q
    ;;
  changed)
    base="${2:-origin/master}"
    if ! git rev-parse --verify -q "${base}^{commit}" >/dev/null; then
      echo "check.sh changed: base ref '$base' does not exist (fetch it, or pass one:" \
           "./scripts/check.sh changed <ref>)" >&2
      exit 2
    fi
    list="$(mktemp "${TMPDIR:-/tmp}/check_changed.XXXXXX")"
    trap 'rm -f "$list"' EXIT
    # scripts touched since <base> (committed) plus anything dirty in the working tree
    { git diff --name-only "$base"...HEAD -- 'scripts/*.py' 'premium/*.py'
      git diff --name-only -- 'scripts/*.py' 'premium/*.py'
      git diff --name-only --cached -- 'scripts/*.py' 'premium/*.py'
    } | sort -u > "$list"
    if [ ! -s "$list" ]; then
      echo "no changed scripts vs $base -> running the full selftest gate"
      "$PY" -m pytest tests/test_selftests.py tests/test_docs_current.py -q
      exit $?
    fi
    rc=0
    while IFS= read -r f; do
      [ -f "$f" ] || continue
      if grep -q -- "--selftest" "$f"; then
        echo "== $f --selftest =="
        run "$PY" "$f" --selftest || rc=1
      fi
    done < "$list"
    exit "$rc"
    ;;
  full)
    exec "$PY" -m pytest tests -q -rs \
      --ignore=tests/test_benchmark.py --ignore=tests/test_scatter.py \
      --ignore=tests/test_obf.py --ignore=tests/test_libfuncs.py \
      --ignore=tests/test_32bit.py --ignore=tests/test_formats.py
    ;;
  -h|--help|help)
    sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'
    ;;
  *)
    name="${1##*/}"          # accept scripts/foo.py, premium/foo.py, foo.py or foo
    name="${name%.py}"
    script="scripts/${name}.py"
    [ -f "$script" ] || script="premium/${name}.py"
    if [ ! -f "$script" ]; then
      echo "check.sh: unknown module '$1' (no scripts/${name}.py or premium/${name}.py)." \
           "Modes: gate | changed [ref] | full | <module>" >&2
      exit 2
    fi
    rc=0
    if grep -q -- "--selftest" "$script"; then
      echo "== $script --selftest =="
      run "$PY" "$script" --selftest || rc=1
    fi
    testfile="$(tests_for "$name")"
    if [ -n "$testfile" ] && [ -f "$testfile" ]; then
      echo "== $testfile =="
      run "$PY" -m pytest "$testfile" -q || rc=1
    else
      echo "(no test file for $name)"
    fi
    exit "$rc"
    ;;
esac
