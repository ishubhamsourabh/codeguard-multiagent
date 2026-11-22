"""Tests for the reviewer judge: JSON contract, fallback, and node wiring."""

from __future__ import annotations

import json

import pytest
from src.agents.reviewer_agent import (
    ReviewVerdict,
    build_review_prompt,
    deterministic_verdict,
    make_reviewer_node,
    parse_review_json,
)
from src.llm_client import LLMResponse


class FakeLLM:
    """Deterministic stand-in for :class:`src.llm_client.LLMClient`."""

    def __init__(self, text: str):
        self.text = text
        self.calls: list[dict] = []

    def complete(self, system, user, *, temperature=0.0, max_tokens=4000):
        self.calls.append({"system": system, "user": user, "temperature": temperature})
        return LLMResponse(text=self.text, latency_s=0.01)


VALID = {
    "verdict": "FAIL",
    "summary": "Hardcoded credential and unsafe eval.",
    "fix_instructions": ["Remove the API key literal", "Replace eval with json.loads"],
    "severity": "critical",
    "confidence": 0.9,
}


def test_parse_valid_json():
    review = parse_review_json(json.dumps(VALID))
    assert review.verdict == "FAIL"
    assert len(review.fix_instructions) == 2
    assert review.confidence == pytest.approx(0.9)


def test_parse_json_wrapped_in_prose_or_fence():
    text = "Here you go:\n```json\n" + json.dumps(VALID) + "\n```\nDone."
    assert parse_review_json(text).verdict == "FAIL"


def test_empty_response_raises():
    with pytest.raises(ValueError, match="empty"):
        parse_review_json("   ")


def test_non_json_raises():
    with pytest.raises(ValueError, match="no JSON"):
        parse_review_json("I think the code is fine.")


def test_malformed_json_raises():
    with pytest.raises(ValueError):
        parse_review_json('{"verdict": "FAIL", }')


def test_schema_violation_raises():
    bad = {"verdict": "MAYBE", "summary": "x"}
    with pytest.raises(ValueError, match="schema"):
        parse_review_json(json.dumps(bad))


def test_extra_keys_rejected():
    payload = dict(VALID, unexpected="nope")
    with pytest.raises(ValueError, match="schema"):
        parse_review_json(json.dumps(payload))


def test_blank_fix_instructions_stripped():
    payload = dict(VALID, fix_instructions=["fix this ", "  ", ""])
    review = parse_review_json(json.dumps(payload))
    assert review.fix_instructions == ["fix this"]


def test_confidence_bounds_validated():
    payload = dict(VALID, confidence=1.5)
    with pytest.raises(ValueError):
        parse_review_json(json.dumps(payload))


def test_deterministic_fallback_fails_on_blocking_issue():
    blocking = [{"code": "EVAL_EXEC", "line": 4, "message": "eval is unsafe"}]
    review = deterministic_verdict(blocking, {"failures": []})
    assert review.verdict == "FAIL"
    assert "EVAL_EXEC" in review.fix_instructions[0]


def test_deterministic_fallback_passes_clean_evidence():
    review = deterministic_verdict([], {"passed": True, "failures": []})
    assert review.verdict == "PASS"
    assert review.fix_instructions == []


def test_prompt_includes_all_evidence():
    state = {
        "intent_spec": {"title": "T", "description": "D"},
        "generated_code": "x: int = 1",
        "static_issues": [
            {"code": "MISSING_DOCSTRING", "severity": "low", "line": 1, "message": "m"}
        ],
        "security_issues": [
            {"code": "EVAL_EXEC", "severity": "critical", "line": 2, "message": "bad"}
        ],
        "test_results": {
            "passed": False,
            "passed_count": 1,
            "failed_count": 2,
            "failures": ["FAILED test_candidate.py::test_a"],
        },
    }
    prompt = build_review_prompt(state)
    assert "T: D" in prompt
    assert "EVAL_EXEC" in prompt
    assert "MISSING_DOCSTRING" in prompt
    assert "test_a" in prompt


def test_node_runs_at_temperature_zero():
    fake = FakeLLM(json.dumps(VALID))
    node = make_reviewer_node(client=fake)
    out = node(
        {
            "intent_spec": {"title": "t", "description": "d"},
            "generated_code": "pass",
            "static_issues": [],
            "security_issues": [],
            "test_results": {"passed": False, "failures": ["x"]},
            "iterations": 1,
        }
    )
    assert fake.calls[0]["temperature"] == 0.0
    assert out["review_payload"]["source"] == "llm"
    assert out["reviewer_feedback"].startswith("1.")


def test_node_falls_back_when_llm_returns_garbage():
    fake = FakeLLM("I refuse to answer in JSON.")
    node = make_reviewer_node(client=fake)
    out = node(
        {
            "intent_spec": {},
            "generated_code": "eval('1')",
            "static_issues": [],
            "security_issues": [
                {"code": "EVAL_EXEC", "severity": "critical", "line": 1, "message": "eval"}
            ],
            "test_results": {"passed": False, "failures": []},
            "iterations": 1,
        }
    )
    assert out["review_payload"]["source"] == "fallback"
    assert out["review_payload"]["verdict"] == "FAIL"
    assert "EVAL_EXEC" in out["reviewer_feedback"]


def test_node_falls_back_when_llm_raises():
    class Boom:
        def complete(self, *a, **k):
            raise RuntimeError("network down")

    node = make_reviewer_node(client=Boom())
    out = node({"intent_spec": {}, "generated_code": "", "test_results": {}, "iterations": 1})
    assert out["review_payload"]["source"] == "fallback"


def test_review_verdict_defaults():
    review = ReviewVerdict(verdict="PASS", summary="ok")
    assert review.severity == "medium"
    assert review.fix_instructions == []
