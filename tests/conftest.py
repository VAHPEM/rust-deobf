import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
BUILD = ROOT / "build"
CANARIES = json.loads((ROOT / "bench_src" / "manifest.json").read_text())["canaries"]
