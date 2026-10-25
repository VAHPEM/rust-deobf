#!/usr/bin/env bash
# ghidra_run.sh — recover strings from a binary and annotate it in Ghidra, headless.
#
# Surfaces rust-deobf's decoded strings inside the Ghidra decompiler: a plate comment and a
# bookmark on every function that decoded something, and a rename of still-default FUN_/SUB_
# functions after the strongest indicator they revealed. Observational only (comments,
# bookmarks, default names). Never executes the target — recover.py uses static + emulation.
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
  JSON="$(mktemp --suffix=.rd.json)"
  echo "ghidra_run: recovering strings -> $JSON" >&2
  python3 "$REPO/scripts/recover.py" "$BIN" --json > "$JSON"
fi

# --- fresh project, import + analyze + annotate ---------------------------------------------
PROJ="${3:-$(mktemp -d)}"
mkdir -p "$PROJ"
NAME="$(basename "$BIN")"
echo "ghidra_run: importing $NAME into $PROJ and annotating from $JSON" >&2
python3 -m pyghidra.ghidra_launch ghidra.app.util.headless.AnalyzeHeadless \
  "$PROJ" rd_proj -import "$BIN" \
  -postScript "$REPO/scripts/ghidra_annotate.py" "$JSON"
echo "ghidra_run: done. Open project '$PROJ/rd_proj' in Ghidra, or re-run with" >&2
echo "            -process $NAME -noanalysis -postScript ghidra_dump_annotations.py to list them." >&2
