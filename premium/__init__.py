# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: Ve (VAHPEM) <ve0912084386@gmail.com>
#
# Dual-licensed: AGPL-3.0-or-later OR a commercial license.
# Commercial licensing: Ve (VAHPEM) <ve0912084386@gmail.com>
"""rust_deobf_premium - the installed form of rust-deobf's premium/ directory (Tier-4 modules).

Distributed separately as `rust-deobf-premium` (pip install "rust-deobf[premium]"), version-locked
to the `rust-deobf` core it depends on. The `rust-deobf` command runs these tools as their own
process (`rust-deobf opaque ...`); this file only matters when a program imports them as a library:
it puts the core package directory on sys.path (the premium modules import core modules such as
`recover_emulate` by bare name) and lets `import rust_deobf_premium.deobf_opaque` return the same
module object as the bare `deobf_opaque` the premium modules import among themselves.
Premium depends on the core, never the reverse (premium/README.md).
"""
from __future__ import annotations

from pathlib import Path as _Path

try:
    from importlib.metadata import version as _version
    __version__ = _version("rust-deobf-premium")
except Exception:  # noqa: BLE001 - a clone imported as a package: no distribution metadata
    __version__ = "0+unknown"

try:
    import rust_deobf as _core
except ImportError:            # a clone without the core installed: the scripts' own sys.path
    _core = None               # wiring (premium/ + ../scripts) is all that is needed there

if _core is not None and hasattr(_core, "register_package_dir"):
    _core.register_package_dir(__name__, str(_Path(__file__).resolve().parent))
    _core.ensure_package_dirs_on_path()
