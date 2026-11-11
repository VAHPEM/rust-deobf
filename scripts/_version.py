# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Ve (VAHPEM) <ve0912084386@gmail.com>
"""The rust-deobf version: the single source of truth for both distributions.

Read by setup.py (core) and premium/setup.py at build time, by `rust-deobf --version` at run time,
and checked against the git tag by .github/workflows/release.yml. A plain file (not git-tag
derived) so a git clone, a shallow CI checkout, a GitHub zip download and an sdist all agree.
Bump it together with a new CHANGELOG.md section; see "Releasing" in CLAUDE.md.
"""
__version__ = "0.1.0"
