#!/usr/bin/env bash
# ghidra_run.sh — recover strings from a binary and annotate it in Ghidra, headless.
#
# Surfaces rust-deobf's decoded strings inside the Ghidra decompiler: a plate comment and a
# bookmark on every function that decoded something, and a rename of still-default FUN_/SUB_
# functions after the strongest indicator they revealed. Also merges recover_types (vtables) and
# recover_idioms (format strings at println!/format!/panic! sites, safety-check panic paths,
# drop calls, helper names, enum-like returns) into the annotation JSON. Observational only
# (comments, bookmarks, default names). Never executes the target — recover.py uses static + emulation.
#
# Usage:
#   scripts/ghidra_run.sh <binary> [recovered.json] [project_dir]
#
# If no JSON is given, it runs scripts/recover.py <binary> --json itself. Set GHIDRA_INSTALL_DIR
# to your Ghidra install (the dir containing ./Ghidra and ./support); the script also tries to
# locate it from `analyzeHeadless` on PATH (e.g. /usr/bin/ghidra packaging on Kali).
#
# Why not plain analyzeHeadless? Since Ghidra 11.3 the Python API is PyGhidra (Jython is gone),
# and `analyzeHeadless ... -postScript x.py` fails unless Ghidra is launched through PyGhidra.
# This wrapper installs the bundled pyghidra wheel if needed and uses pyghidra.ghidra_launch.
set -euo pipefail

BIN="${1:?usage: ghidra_run.sh <binary> [recovered.json] [project_dir]}"
JSON="${2:-}"
# a relative name starting with '-' would be read as an option (by basename, and by tools that
# do not take `--`): anchor it to the current directory. The python tools also get `--` below.
case "$BIN" in -*) BIN="./$BIN" ;; esac
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(dirname "$HERE")"

# --- locate Ghidra -------------------------------------------------------------------------
if [ -z "${GHIDRA_INSTALL_DIR:-}" ]; then
  if command -v analyzeHeadless >/dev/null 2>&1; then
    AH="$(command -v analyzeHeadless)"
    # resolve symlink, then walk up from .../support/analyzeHeadless
    AH="$(readlink -f "$AH" 2>/dev/null || echo "$AH")"
    CAND="$(dirname "$(dirname "$AH")")"
    [ -d "$CAND/Ghidra" ] && GHIDRA_INSTALL_DIR="$CAND"
  fi
fi
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR to your Ghidra install (dir with ./Ghidra and ./support)}"
export GHIDRA_INSTALL_DIR
if [ ! -d "$GHIDRA_INSTALL_DIR/Ghidra" ]; then
  echo "ghidra_run: '$GHIDRA_INSTALL_DIR' is not a Ghidra install (no ./Ghidra)" >&2; exit 2
fi

# --- ensure pyghidra ------------------------------------------------------------------------
if ! python3 -c "import pyghidra" >/dev/null 2>&1; then
  WHL="$(ls "$GHIDRA_INSTALL_DIR"/Ghidra/Features/PyGhidra/pypkg/dist/pyghidra-*.whl 2>/dev/null | head -1 || true)"
  if [ -n "$WHL" ]; then
    python3 -m pip install --break-system-packages -q "$WHL" || python3 -m pip install -q "$WHL"
  else
    python3 -m pip install --break-system-packages -q pyghidra || python3 -m pip install -q pyghidra
  fi
fi

# --- recover strings if no JSON supplied ----------------------------------------------------
if [ -z "$JSON" ]; then
  # portable mktemp (GNU and BSD/macOS): a template whose X's end the name; removed on exit
  JSON="$(mktemp "${TMPDIR:-/tmp}/rd-recover.XXXXXX")"
  trap 'rm -f "$JSON"' EXIT
  echo "ghidra_run: recovering strings -> $JSON" >&2
  rc=0
  python3 "$REPO/scripts/recover.py" --json -- "$BIN" > "$JSON" || rc=$?
  case "$rc" in
    0) ;;
    4) echo "ghidra_run: warning: an engine failed (see the notes in the JSON); annotating what was recovered" >&2 ;;
    *) echo "ghidra_run: recover.py failed (exit $rc); nothing to annotate" >&2; exit "$rc" ;;
  esac
  # also recover trait-object vtables and merge them into the JSON so ghidra_annotate lays the
  # vtable structs and names the method functions behind the trait (best-effort; never fatal)
  TYPES="$(mktemp "${TMPDIR:-/tmp}/rd-types.XXXXXX")"
  trap 'rm -f "$JSON" "$TYPES"' EXIT
  if python3 "$REPO/scripts/recover_types.py" --json -- "$BIN" > "$TYPES" 2>/dev/null; then
    python3 - "$JSON" "$TYPES" <<'PY' || true
import json, sys
j, t = sys.argv[1], sys.argv[2]
with open(j) as f: data = json.load(f)
with open(t) as f: types = json.load(f)
data["vtables"] = types.get("vtables", [])
data["ghidra_types"] = types.get("ghidra_types", [])
with open(j, "w") as f: json.dump(data, f)
PY
  fi
  # Rust idioms (fmt macro strings, safety-check panic paths, drop calls, enum-like returns):
  # merged as "idioms" so ghidra_annotate comments / bookmarks them (best-effort; never fatal)
  IDIOMS="$(mktemp "${TMPDIR:-/tmp}/rd-idioms.XXXXXX")"
  trap 'rm -f "$JSON" "$TYPES" "$IDIOMS"' EXIT
  if python3 "$REPO/scripts/recover_idioms.py" --json -- "$BIN" > "$IDIOMS" 2>/dev/null; then
    python3 - "$JSON" "$IDIOMS" <<'PY' || true
import json, sys
j, t = sys.argv[1], sys.argv[2]
with open(j) as f: data = json.load(f)
with open(t) as f: idioms = json.load(f)
if isinstance(idioms, dict) and "error" not in idioms:
    data["idioms"] = idioms
with open(j, "w") as f: json.dump(data, f)
PY
  fi
fi

# --- fresh project, import + analyze + annotate ---------------------------------------------
PROJ="${3:-$(mktemp -d)}"
mkdir -p "$PROJ"
NAME="$(basename -- "$BIN")"
echo "ghidra_run: importing $NAME into $PROJ and annotating from $JSON" >&2
# -overwrite: re-running into the same project dir replaces the earlier import instead of failing
python3 -m pyghidra.ghidra_launch ghidra.app.util.headless.AnalyzeHeadless \
  "$PROJ" rd_proj -import "$BIN" -overwrite \
  -postScript "$REPO/scripts/ghidra_annotate.py" "$JSON"
echo "ghidra_run: done. Open project '$PROJ/rd_proj' in Ghidra, or re-run with" >&2
echo "            -process $NAME -noanalysis -postScript ghidra_dump_annotations.py to list them." >&2
