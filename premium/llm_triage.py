#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: Ve (VAHPEM) <ve0912084386@gmail.com>
#
# Dual-licensed: AGPL-3.0-or-later OR a commercial license.
# Commercial licensing: Ve (VAHPEM) <ve0912084386@gmail.com>
"""llm_triage.py - AI-assisted triage on top of the deterministic recovery.

soc_triage.py recovers hard facts (format/arch, Rust toolchain, crate/capability fingerprint,
decoded strings, indicators) with no guessing. This layer hands ONLY those recovered facts to an
LLM and asks it to reason over them -- a verdict, likely capabilities tied to the evidence, candidate
ATT&CK techniques, what is uncertain, and next analyst steps. The deterministic facts stay the
ground truth; the LLM note is an advisory hypothesis, clearly labelled.

Anti-hallucination by construction: the model is given the evidence and nothing else (never the raw
binary), and is instructed not to invent indicators. A thin-evidence sample yields an explicitly
inconclusive note, not a confident fabrication.

Backends (auto-detected; keeps malware data local when you want it to):
  * local / self-hosted OpenAI-compatible server (Ollama, vLLM, LM Studio) via RUST_DEOBF_LLM_BASE
    -- nothing leaves the host; the right default for analysing real malware
  * Anthropic API            (ANTHROPIC_API_KEY)
  * OpenAI / compatible API   (OPENAI_API_KEY [+ RUST_DEOBF_LLM_BASE])
  * offline (no key)         -- prints the grounded prompt to paste into any LLM, plus a
                               deterministic rule-based summary, so the tool is useful with no API

    python3 scripts/llm_triage.py <binary> [--fast] [--offline] [--json]
    RUST_DEOBF_LLM_BASE=http://localhost:11434/v1 RUST_DEOBF_LLM_MODEL=llama3.1 \
        python3 scripts/llm_triage.py sample.bin

STATIC + EMULATION ONLY; never executes the sample.
"""
from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path
# premium module: find both premium/ (sibling premium modules) and the Apache core in scripts/
for _p in (str(_Path(__file__).resolve().parent), str(_Path(__file__).resolve().parent.parent / 'scripts')):
    if _p not in _sys.path:
        _sys.path.insert(0, _p)


import argparse
import json
import os
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

SYSTEM_PROMPT = (
    "You are a malware-triage assistant for a reverse engineer. You are given ONLY the facts a "
    "deterministic static+emulation analyzer recovered from a binary -- never the binary itself. "
    "Reason strictly over the facts provided. Do NOT invent strings, domains, IPs, file paths, "
    "capabilities, or family names that are not supported by the evidence. Every inference must be "
    "tied to a specific piece of evidence and flagged as an inference. If the evidence is thin, say "
    "the triage is inconclusive rather than guessing. You are an aid; the analyst makes the call."
)

TASK = (
    "Based ONLY on the evidence JSON above, produce a concise triage note (<=250 words):\n"
    "1. VERDICT: one line -- benign / suspicious / likely-malicious, with a family guess ONLY if the "
    "decoded strings or crate fingerprint strongly indicate one (say 'no confident family' otherwise).\n"
    "2. CAPABILITIES: what it can likely do, each item tied to the specific crate or indicator.\n"
    "3. ATT&CK: candidate technique IDs with a one-line justification each, ONLY where the evidence "
    "supports it; omit if nothing supports any.\n"
    "4. UNCERTAINTY: what is missing and what a dynamic/sandbox run would clarify.\n"
    "5. NEXT STEPS: 2-3 concrete analyst actions.\n"
    "Mark every inference as such. Do not restate the whole evidence block."
)


def build_evidence(card: dict) -> dict:
    """The subset of the triage card that is safe, compact grounding for the model."""
    return {
        "format": card["format"], "arch": card["arch"], "is_rust": card["is_rust"],
        "rust_release": card.get("rust_release"), "panic_sites": card.get("panic_sites"),
        "capability_fingerprint": card.get("capabilities", {}),
        "indicators": card.get("indicators", {}),
        "decoded_strings_sample": card.get("decoded_sample", []),
        "decoded_total": card.get("decoded_total", 0),
        "deterministic_signal": card.get("triage_signal"),
        "signal_reasons": card.get("signal_reasons", []),
    }


def build_prompt(evidence: dict) -> str:
    return ("Evidence (recovered by the deterministic analyzer):\n"
            + json.dumps(evidence, indent=2) + "\n\n" + TASK)


def rule_summary(card: dict) -> str:
    """A deterministic, no-LLM fallback note built from the evidence alone (template, not a guess)."""
    caps = card.get("capabilities", {})
    iocs = card.get("indicators", {})
    net = [k for k in ("url", "domain", "ip") if iocs.get(k)]
    parts = [f"VERDICT (rule-based): deterministic signal {card.get('triage_signal')}"
             + (f" -- {', '.join(card.get('signal_reasons', []))}" if card.get("signal_reasons") else "")]
    if caps:
        parts.append("CAPABILITIES (from crate fingerprint): "
                     + "; ".join(f"{label} [{', '.join(v[:4])}]" for label, v in caps.items()))
    if net:
        parts.append("NETWORK INDICATORS present: "
                     + ", ".join(f"{k}={len(iocs[k])}" for k in net)
                     + " -- pivot on these for C2.")
    if card.get("decoded_total"):
        parts.append(f"{card['decoded_total']} obfuscated strings were recovered "
                     "(the sample hides strings -- a deobfuscation win).")
    parts.append("NEXT STEPS: review the decoded strings + indicators above; for behaviour, run in "
                 "an isolated sandbox; feed this evidence to an LLM (set a backend) for a richer read.")
    return "\n".join(parts)


def _http_json(url: str, headers: dict, body: dict, timeout: float = 90.0) -> dict:
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def call_llm(prompt: str, backend: str, model: str, base: str, key: str) -> str:
    if backend == "anthropic":
        out = _http_json("https://api.anthropic.com/v1/messages",
                         {"x-api-key": key, "anthropic-version": "2023-06-01",
                          "content-type": "application/json"},
                         {"model": model, "max_tokens": 700, "system": SYSTEM_PROMPT,
                          "messages": [{"role": "user", "content": prompt}]})
        return "".join(b.get("text", "") for b in out.get("content", [])).strip()
    # OpenAI-compatible (OpenAI, or a local Ollama/vLLM/LM Studio server via base)
    headers = {"content-type": "application/json"}
    if key:
        headers["Authorization"] = "Bearer " + key
    out = _http_json(base.rstrip("/") + "/chat/completions", headers,
                     {"model": model, "messages": [
                         {"role": "system", "content": SYSTEM_PROMPT},
                         {"role": "user", "content": prompt}]})
    return out["choices"][0]["message"]["content"].strip()


def resolve_backend():
    """(backend, model, base, key). backend 'none' => offline."""
    base = os.environ.get("RUST_DEOBF_LLM_BASE", "")
    model = os.environ.get("RUST_DEOBF_LLM_MODEL", "")
    forced = os.environ.get("RUST_DEOBF_LLM", "").lower()
    if forced == "anthropic" or (not forced and os.environ.get("ANTHROPIC_API_KEY")):
        return "anthropic", model or "claude-3-5-haiku-latest", "", os.environ.get("ANTHROPIC_API_KEY", "")
    if os.environ.get("OPENAI_API_KEY") or base or forced == "openai":
        return ("openai", model or "gpt-4o-mini",
                base or "https://api.openai.com/v1", os.environ.get("OPENAI_API_KEY", ""))
    return "none", "", "", ""


def analyze(path: Path, fast: bool, time_budget: float, force_offline: bool) -> dict:
    import soc_triage
    card = soc_triage.triage(path, fast, time_budget)
    evidence = build_evidence(card)
    prompt = build_prompt(evidence)
    backend, model, base, key = ("none", "", "", "") if force_offline else resolve_backend()
    result = {"card": card, "evidence": evidence, "backend": backend, "model": model}
    if backend == "none":
        result["mode"] = "offline"
        result["prompt"] = prompt
        result["rule_summary"] = rule_summary(card)
    else:
        try:
            result["mode"] = "llm"
            result["analysis"] = call_llm(prompt, backend, model, base, key)
        except Exception as e:                       # network/key/endpoint problem -> graceful offline
            result["mode"] = "offline(llm-error)"
            result["error"] = f"{type(e).__name__}: {e}"
            result["prompt"] = prompt
            result["rule_summary"] = rule_summary(card)
    return result


def print_human(r: dict) -> None:
    import soc_triage
    soc_triage.print_card(r["card"])
    print()
    if r["mode"] == "llm":
        print(f"  AI TRIAGE NOTE  ({r['backend']}:{r['model']})  -- advisory hypothesis, not ground truth")
        print("  " + "-" * 74)
        for ln in r["analysis"].splitlines():
            print("  " + ln)
    else:
        if r.get("error"):
            print(f"  [LLM backend error: {r['error']}; showing offline note]")
        else:
            print("  [no LLM backend configured -- offline mode. Set RUST_DEOBF_LLM_BASE (local "
                  "Ollama/vLLM) or ANTHROPIC_API_KEY/OPENAI_API_KEY for an AI note.]")
        print("  RULE-BASED NOTE (deterministic, no LLM):")
        for ln in r["rule_summary"].splitlines():
            print("    " + ln)
        print("\n  PROMPT (paste into any LLM for a richer read):")
        print("  " + "-" * 74)
        for ln in r["prompt"].splitlines():
            print("  | " + ln)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("binary")
    ap.add_argument("--fast", action="store_true", help="skip emulation (metadata + literals only)")
    ap.add_argument("--time-budget", type=float, default=60.0)
    ap.add_argument("--offline", action="store_true", help="never call an LLM; prompt + rule note only")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    path = Path(a.binary)
    if not path.is_file():
        ap.error(f"no such file: {path}")
    r = analyze(path, a.fast, a.time_budget, a.offline)
    if a.json:
        print(json.dumps(r, indent=2))
    else:
        print_human(r)


if __name__ == "__main__":
    main()
