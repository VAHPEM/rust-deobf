import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
BUILD = Path(os.environ.get("RUST_DEOBF_BUILD", ROOT / "build"))   # scripts/build_all.sh BUILD_DIR
CANARIES = json.loads((ROOT / "bench_src" / "manifest.json").read_text())["canaries"]
