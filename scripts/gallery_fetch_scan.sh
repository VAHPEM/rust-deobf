#!/usr/bin/env bash
# gallery_fetch_scan.sh - fetch ONE rust-malware-gallery sample by hash and triage it.
#
# STATIC + EMULATION ONLY. The sample is NEVER executed: it is only ever passed as a read
# argument to recover_rust_meta.py and recover.py (which read it and emulate individual functions
# under Unicorn -- no syscalls reach the host). The script never chmods +x or runs the sample, and
# downloads only into an isolated samples dir kept OUT of the git repo.
#
# Usage:
#   MB_KEY=... scripts/gallery_fetch_scan.sh <sha256> [family-label]
#   scripts/gallery_fetch_scan.sh <sha256> [family-label]      # prompts for the key once
#   scripts/gallery_fetch_scan.sh --scan-only <path> [family]  # triage a sample you already have
#
# Env (all optional): SAMPLES (default ~/samples), OUT (default ~/rust-deobf-results),
#                     TIME_BUDGET (default 180), MB_KEY (MalwareBazaar Auth-Key).
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SAMPLES="${SAMPLES:-$HOME/samples}"
OUT="${OUT:-$HOME/rust-deobf-results}"
TIME_BUDGET="${TIME_BUDGET:-180}"
mkdir -p "$SAMPLES" "$OUT"

die() { echo "error: $*" >&2; exit 1; }

# ---- triage one binary file: metadata + string recovery, NEVER executing it ----
scan() {
    local bin="$1" fam="${2:-}" h
    [ -f "$bin" ] || die "not a file: $bin"
    h="$(sha256sum "$bin" | cut -d' ' -f1)"
    echo "==== $(basename "$bin")  sha256=$h  ${fam:+family=$fam} ===="

    python3 "$REPO/scripts/recover_rust_meta.py" --json "$bin" > "$OUT/$h.meta.json" 2>/dev/null || true
    python3 "$REPO/scripts/recover.py" "$bin" --json --libfuncs \
        --time-budget "$TIME_BUDGET" --max-ram 4G > "$OUT/$h.recover.json" 2>"$OUT/$h.err" || \
        { echo "  recover.py failed; see $OUT/$h.err"; tail -3 "$OUT/$h.err" >&2; return 1; }

    MB_FAM="$fam" python3 - "$OUT/$h.meta.json" "$OUT/$h.recover.json" "$h" <<'PY'
import json, os, sys
meta = {}
try: meta = json.load(open(sys.argv[1]))
except Exception: pass
d = json.load(open(sys.argv[2])); h = sys.argv[3]
c = meta.get("counts", {})
dec = d.get("decoded", [])
tags = sorted({t for x in dec for t in x.get("tags", [])})
eng = ", ".join(f"{e['engine'].split('(')[0].strip()}={e.get('strings','?')}" for e in d.get("engines", []))
emu = next((e for e in d.get("engines", []) if "emulation" in e["engine"]), {})
print(f"  rust={meta.get('is_rust','?')} rustc={meta.get('rustc_commit','?')} "
      f"panic={c.get('panic_sites','?')} crates={c.get('crates','?')}")
print(f"  {d['format']}/{d['arch']}  decoded={len(dec)}  indicators={tags or '-'}")
print(f"  engines: {eng}")
for x in dec[:15]:
    tg = f"  [{','.join(x.get('tags',[]))}]" if x.get("tags") else ""
    print(f"    - {x['string'][:96]}{tg}")
if d.get("notes"):
    print("  notes:", d["notes"][0][:120])
# ready-to-edit results.jsonl skeleton
sk = {"sha256": h, "family": os.environ.get("MB_FAM") or "<family>",
      "format": f"{d['format']} {d['arch']}", "mode": "static+emulation (not executed)",
      "is_rust": bool(meta.get("is_rust")), "panic_sites": c.get("panic_sites", 0),
      "functions_emulated": emu.get("functions", "?"), "seconds": emu.get("seconds", 0),
      "crashed": False, "decoded_obfuscated": len(dec),
      "recovered": [f"{x['string'][:60]} (tag={','.join(x.get('tags',[])) or '-'})" for x in dec[:6]],
      "note": "<one-line takeaway>"}
print("\n  results.jsonl skeleton (edit 'family'/'note', then append):")
print("  " + json.dumps(sk))
print(f"\n  full JSON: {sys.argv[2]}")
PY
}

# ---- --scan-only mode: triage a local sample, no download ----
if [ "${1:-}" = "--scan-only" ]; then
    [ -n "${2:-}" ] || die "usage: $0 --scan-only <path> [family]"
    scan "$2" "${3:-}"
    exit 0
fi

# ---- fetch mode ----
H="${1:-}"; FAM="${2:-}"
[[ "$H" =~ ^[0-9a-fA-F]{64}$ ]] || die "pass a 64-hex sha256 as the first argument (got: '${H:-}')"

if [ -z "${MB_KEY:-}" ]; then
    read -rsp "MalwareBazaar Auth-Key (hidden): " MB_KEY; echo
    [ -n "$MB_KEY" ] || die "no key entered"
fi

zip="$SAMPLES/$H.zip"
echo "downloading $H ..."
curl -s https://mb-api.abuse.ch/api/v1/ \
    -H "Auth-Key: $MB_KEY" \
    -d "query=get_file" --data-urlencode "sha256_hash=$H" \
    -o "$zip"

# A real sample is a zip; an API error comes back as a few bytes of JSON.
if [ "$(stat -c%s "$zip" 2>/dev/null || echo 0)" -lt 200 ] || ! file "$zip" | grep -qi zip; then
    echo "download did not return a zip -- API said:" >&2
    cat "$zip" >&2; echo >&2
    die "fetch failed (check the key and that the hash is on MalwareBazaar)"
fi

dest="$SAMPLES/$H.d"; mkdir -p "$dest"
7z x -p infected -y -o"$dest" "$zip" >/dev/null || die "extract failed (need p7zip-full? 'sudo apt install p7zip-full')"

# triage every extracted file that is actually a binary (usually one); NEVER run them
found=0
while IFS= read -r -d '' b; do
    case "$(file -b "$b")" in
        *ELF*|*PE32*|*"PE32+"*|*Mach-O*|*executable*|*shared\ object*)
            scan "$b" "$FAM"; found=1 ;;
    esac
done < <(find "$dest" -type f -print0)
[ "$found" = 1 ] || die "no binary found under $dest (contents: $(ls "$dest"))"

echo
echo "done. Review the summary above, edit the results.jsonl skeleton, then from $REPO:"
echo "  (append your edited line to gallery/results.jsonl)"
echo "  git add gallery/results.jsonl && git commit -m 'gallery: validate ${FAM:-<family>}' && git push"
echo "NEVER git add the sample or the zip. Samples stay in $SAMPLES (outside the repo)."
