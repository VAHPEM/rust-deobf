"""llm_triage: grounded prompt construction, backend resolution, offline fallback, and the
request/response handling for each LLM backend (stubbed transport -- no network, no API key)."""
import json

import pytest
from conftest import ROOT  # noqa: F401  (adds scripts/ to sys.path)

import llm_triage as L

CARD = {
    "file": "x", "sha256": "0" * 64, "size": 123, "format": "PE", "arch": "x86_64",
    "is_rust": True, "rustc_commit": "deadbeef", "rust_release": "1.91.1", "panic_sites": 1200,
    "capabilities": {"c2 / networking": ["reqwest", "tokio"], "encryption": ["aes-gcm"]},
    "indicators": {"url": ["https://evil.example/c2"], "ip": ["0.0.0.0:0"]},
    "decoded_sample": ["https://evil.example/c2", "AES key blob"], "decoded_total": 7,
    "triage_signal": "HIGH", "signal_reasons": ["7 obfuscated/decoded strings", "network indicators (C2-shaped)"],
}


def test_evidence_is_grounded_subset():
    ev = L.build_evidence(CARD)
    # only recovered facts; no sha/size/path leakage into the model context
    assert "sha256" not in ev and "file" not in ev
    assert ev["indicators"] == CARD["indicators"]
    assert ev["decoded_strings_sample"] == CARD["decoded_sample"]
    assert ev["capability_fingerprint"] == CARD["capabilities"]


def test_prompt_contains_evidence_and_antihallucination_task():
    prompt = L.build_prompt(L.build_evidence(CARD))
    assert "https://evil.example/c2" in prompt         # the evidence is in the prompt
    assert "ATT&CK" in prompt and "VERDICT" in prompt   # the structured task
    # the system prompt forbids invention
    assert "Do NOT invent" in L.SYSTEM_PROMPT


def test_rule_summary_uses_evidence():
    s = L.rule_summary(CARD)
    assert "HIGH" in s
    assert "c2 / networking" in s and "reqwest" in s
    assert "NETWORK INDICATORS" in s


def test_resolve_backend(monkeypatch):
    for v in ("RUST_DEOBF_LLM", "RUST_DEOBF_LLM_BASE", "RUST_DEOBF_LLM_MODEL",
              "ANTHROPIC_API_KEY", "OPENAI_API_KEY"):
        monkeypatch.delenv(v, raising=False)
    assert L.resolve_backend()[0] == "none"                      # nothing set -> offline
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    assert L.resolve_backend()[0] == "anthropic"
    monkeypatch.delenv("ANTHROPIC_API_KEY")
    monkeypatch.setenv("RUST_DEOBF_LLM_BASE", "http://localhost:11434/v1")  # local Ollama/vLLM
    be, model, base, key = L.resolve_backend()
    assert be == "openai" and base.endswith("/v1")               # local server, no key needed


def test_openai_backend_request_and_parse(monkeypatch):
    captured = {}
    def fake(url, headers, body, timeout=90.0):
        captured.update(url=url, headers=headers, body=body)
        return {"choices": [{"message": {"content": "MOCK ANALYSIS"}}]}
    monkeypatch.setattr(L, "_http_json", fake)
    out = L.call_llm("PROMPT", "openai", "gpt-4o-mini", "http://host/v1", "KEY")
    assert out == "MOCK ANALYSIS"
    assert captured["url"].endswith("/v1/chat/completions")
    assert captured["headers"]["Authorization"] == "Bearer KEY"
    roles = [m["role"] for m in captured["body"]["messages"]]
    assert roles == ["system", "user"] and captured["body"]["messages"][1]["content"] == "PROMPT"


def test_anthropic_backend_request_and_parse(monkeypatch):
    captured = {}
    def fake(url, headers, body, timeout=90.0):
        captured.update(url=url, headers=headers, body=body)
        return {"content": [{"type": "text", "text": "MOCK ANTHROPIC"}]}
    monkeypatch.setattr(L, "_http_json", fake)
    out = L.call_llm("PROMPT", "anthropic", "claude-3-5-haiku-latest", "", "KEY")
    assert out == "MOCK ANTHROPIC"
    assert captured["url"] == "https://api.anthropic.com/v1/messages"
    assert captured["headers"]["x-api-key"] == "KEY"
    assert captured["body"]["system"] == L.SYSTEM_PROMPT


def test_analyze_llm_error_falls_back_offline(monkeypatch, tmp_path):
    # a backend is configured but the call fails -> graceful offline note, never a crash
    monkeypatch.setenv("OPENAI_API_KEY", "k")
    monkeypatch.setattr(L, "call_llm", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    monkeypatch.setattr(L, "build_evidence", lambda card: {"x": 1})
    import soc_triage
    monkeypatch.setattr(soc_triage, "triage", lambda *a, **k: dict(CARD))
    r = L.analyze(tmp_path, fast=True, time_budget=1, force_offline=False)
    assert r["mode"] == "offline(llm-error)" and "rule_summary" in r and "boom" in r["error"]
