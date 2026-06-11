"""Unit tests for SLM/LLM prompt builders."""

from datetime import UTC, datetime
from uuid import uuid4

from aegis.middleware.models import RagContext, SlmResponse, UEBAMetrics, WazuhLog
from aegis.middleware.prompt_builder import build_llm_prompt, build_slm_prompt

_REQUIRED_LLM_KEYS = (
    "attack_confirmed",
    "confidence",
    "attack_type",
    "severity",
    "affected_asset",
    "asset_criticality",
    "plain_language_summary",
    "recommended_action",
    "requires_human_validation",
    "raw_probabilities",
)


def _make_log() -> WazuhLog:
    return WazuhLog(
        id=uuid4(),
        timestamp=datetime.now(UTC),
        source_agent="node1-host",
        source_ip="172.18.0.1",
        rule_id=31152,
        rule_level=10,
        rule_description="Multiple SQL injection attempts from same source ip.",
        full_log="GET /rest/products/search?q=test' UNION SELECT ... FROM Users--",
        mitre_technique="T1190",
        decoder_name="web-accesslog",
    )


def _make_slm() -> SlmResponse:
    return SlmResponse(
        is_suspect=True,
        confidence=0.65,
        behavior_category="normal",
        reasoning_short="Multiple common web attacks from the same source IP.",
        raw_probabilities={"suspect": 0.65, "benign": 0.35},
    )


def _make_rag() -> RagContext:
    return RagContext(
        asset_name="172.18.0.1",
        asset_criticality="tier2",
        asset_description="Unknown asset",
        similar_incidents=[],
        ueba=UEBAMetrics(
            has_baseline=False,
            baseline_description="No baseline",
            associated_users=[],
            normal_activity_window="Unknown",
            recent_anomalies=[],
            anomaly_score=0.0,
        ),
    )


def test_build_slm_prompt_contains_log_payload() -> None:
    prompt = build_slm_prompt(_make_log())
    assert "rule_id=31152" in prompt
    assert "UNION SELECT" in prompt


def test_build_llm_prompt_ends_on_task_with_all_required_keys() -> None:
    # The TASK block must be last (recency) and re-list every required JSON key,
    # so the model cannot degenerate into a single copied field.
    prompt = build_llm_prompt(_make_log(), _make_slm(), _make_rag())

    task_index = prompt.index("--- TASK ---")
    slm_index = prompt.index("--- SLM PRE-ANALYSIS")
    assert task_index > slm_index, "SLM pre-analysis must not be the last block"

    task_block = prompt[task_index:]
    for key in _REQUIRED_LLM_KEYS:
        assert key in task_block, f"required key missing from TASK block: {key}"


def test_build_llm_prompt_marks_slm_as_non_authoritative() -> None:
    prompt = build_llm_prompt(_make_log(), _make_slm(), _make_rag())
    assert "do not copy" in prompt.lower()
    assert "Log:" in prompt
