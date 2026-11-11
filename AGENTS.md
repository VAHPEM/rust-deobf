# AGENTS.md — rust-deobf

The agent guide for this repo is **[CLAUDE.md](CLAUDE.md)**. Read it first: it is the
architecture map, the conventions, the test workflow (`./scripts/check.sh`), the measured test
matrix and the gotchas. It is the single source. Do not copy it here; a second copy drifts, and
`tests/test_docs_current.py` checks CLAUDE.md only.

The essentials, in case you read only this file:
- Defensive toolkit, benign fixtures only: no live malware indicators, no C2-style strings.
  Use RFC 5737 IPs and `.invalid` / `.example` hosts.
- Commits are authored as the maintainer (see "Git" in CLAUDE.md). Never push.
- Say which targets you actually ran. Never infer an untested one.
