"""
AEGIS pipeline orchestration: two-stage alert processing workflow.

The pipeline is split across two independently-running RabbitMQ consumers so a
fast SLM triage loop is never blocked behind a slow multi-minute LLM analysis:

Stage 1 — triage_log() (consumer.py, queue aegis.triage):
1. Send to SLM Qwen 2.5 1.5B → quick suspicion score
2. Check if is_suspect and confidence > SUSPICION_THRESHOLD
3. Query PostgreSQL → asset context + UEBA, apply false-positive gate
4. Publish an EscalatedAlert bundle to queue aegis.reports (or discard)

Stage 2 — analyze_log() (consumer_analysis.py, queue aegis.reports):
5. Send to LLM Mistral 7B → detailed threat analysis (with fallback)
6. Compute composite risk_score (danger_score + uncertainty)
7. Build the final AegisReport and send it to Shuffle SOAR
8. Return the complete report for human review (human-in-the-loop)

Timing: Measure total time in milliseconds.
Logging: Structured JSON at each step.

Zero cloud calls. Zero automatic remediation (human validation required).
"""

import json
import logging
import time
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Literal
from uuid import uuid4

from aegis.llm.client import OllamaClient
from aegis.middleware.models import (
    AegisReport,
    AppliedResponse,
    Decision,
    EscalatedAlert,
    LlmResponse,
    SlmResponse,
    WazuhLog,
)
from aegis.middleware.prompt_builder import (
    build_llm_prompt,
    build_slm_prompt,
    extract_request_path,
)
from aegis.middleware.risk_scorer import compute_risk_score
from aegis.monitoring.metrics import MetricsCollector
from aegis.rag.client import ChromaDBClient
from aegis.rag.postgres_client import PostgresIdentityStore
from aegis.soar.client import ShuffleClient
from aegis.soar.response_policy import ResponsePolicy, render_action

logger = logging.getLogger(__name__)

# Fallback model names when a caller doesn't pass one (the consumers always do,
# sourced from Settings/env). Kept as literals so config lives only in Settings.
_DEFAULT_SLM_MODEL = "qwen25-aegis"
_DEFAULT_LLM_MODEL = "mistral-aegis"


async def triage_log(
    log: WazuhLog,
    ollama_client: OllamaClient,
    chromadb_client: ChromaDBClient | PostgresIdentityStore,
    metrics: MetricsCollector | None = None,
    suspicion_threshold: float = 0.5,
    slm_timeout: float = 10.0,
    slm_model: str = _DEFAULT_SLM_MODEL,
    on_unprofiled_asset: Callable[[str], Awaitable[None]] | None = None,
    fp_gate_confidence_ceiling: float = 0.6,
) -> EscalatedAlert | None:
    """
    Run the fast triage stage of the AEGIS pipeline (SLM + RAG + gates).

    Triage steps (strict order):
    1. SLM: Quick suspicion scoring (Qwen 2.5 1.5B)
    2. Gate: If not suspect or low confidence → discard, return None
    3. RAG: Fetch asset context + UEBA from PostgreSQL
    4. Gate: UEBA false-positive filter → discard, return None

    Logs that pass both gates are bundled into an EscalatedAlert for the
    analysis stage (analyze_log) to pick up from the aegis.reports queue.

    Args:
        log: WazuhLog to triage.
        ollama_client: Initialized OllamaClient for SLM inference.
        chromadb_client: Initialized identity store (ChromaDBClient or PostgresIdentityStore).
        metrics: Optional metrics collector for Prometheus reporting.
        suspicion_threshold: Minimum confidence to proceed past SLM (default: 0.5).
        slm_timeout: SLM request timeout in seconds (default: 10).
        fp_gate_confidence_ceiling: The UEBA false-positive gate never suppresses an
            alert whose SLM confidence is at or above this (default: 0.6). A confident
            SLM suspicion plus a fired Wazuh rule are two agreeing signals that a calm
            asset baseline must not silently veto.

    Returns:
        EscalatedAlert: Bundle to publish for analysis, or None if the alert
                        was discarded as benign during triage.
    """
    start_time = time.time()
    total_perf_start = time.perf_counter()
    pipeline_start = datetime.now(UTC)
    report_id = uuid4()

    logger.info(
        json.dumps(
            {
                "event": "pipeline_start",
                "alert_id": str(log.id),
                "report_id": str(report_id),
                "rule_id": log.rule_id,
                "rule_level": log.rule_level,
            }
        )
    )

    # ========================================================================
    # STEP 1: SLM - Quick suspicion scoring
    # ========================================================================
    slm_stage_start = time.perf_counter()
    try:
        logger.debug(
            json.dumps(
                {
                    "event": "slm_start",
                    "rule_id": log.rule_id,
                    "timeout": slm_timeout,
                }
            )
        )

        slm_prompt = build_slm_prompt(log)
        slm_response_dict = await ollama_client.generate(
            model=slm_model,
            prompt=slm_prompt,
            timeout=slm_timeout,
            keep_alive=-1,  # keep SLM permanently in RAM — Pi 16 GB holds both models
            num_predict=180,
        )
        slm = SlmResponse(**slm_response_dict)

        logger.info(
            json.dumps(
                {
                    "event": "slm_complete",
                    "confidence": slm.confidence,
                    "is_suspect": slm.is_suspect,
                    "behavior_category": slm.behavior_category,
                }
            )
        )

        if metrics is not None:
            metrics.record_slm(time.perf_counter() - slm_stage_start)

    except Exception as e:
        if metrics is not None:
            metrics.record_slm(time.perf_counter() - slm_stage_start)
        logger.warning(
            json.dumps(
                {
                    "event": "slm_error",
                    "error": str(e),
                    "rule_id": log.rule_id,
                    "fallback": "escalating_to_llm",
                }
            )
        )
        # SLM failed (model too small, schema mismatch, timeout) — escalate conservatively
        slm = SlmResponse(
            is_suspect=True,
            confidence=0.6,
            behavior_category="normal",
            reasoning_short="SLM triage unavailable — escalating to LLM",
            raw_probabilities={"suspect": 0.6, "benign": 0.4},
        )

    # ========================================================================
    # STEP 2: Gate - Check suspicion threshold
    # ========================================================================
    if not slm.is_suspect or slm.confidence < suspicion_threshold:
        if metrics is not None:
            metrics.record_triage(time.perf_counter() - total_perf_start)
            metrics.record_alert(
                status="discarded",
                severity="low",
                duration_s=time.perf_counter() - total_perf_start,
            )
        logger.info(
            json.dumps(
                {
                    "event": "alert_discarded",
                    "reason": "below_suspicion_threshold",
                    "slm_confidence": slm.confidence,
                    "threshold": suspicion_threshold,
                }
            )
        )
        return None

    logger.debug(
        json.dumps(
            {
                "event": "suspicion_gate_passed",
                "confidence": slm.confidence,
            }
        )
    )

    # ========================================================================
    # STEP 3: RAG - Fetch asset context + UEBA
    # ========================================================================
    rag_stage_start = time.perf_counter()
    try:
        logger.debug(
            json.dumps(
                {
                    "event": "rag_start",
                    "asset_identifier": log.source_ip,
                }
            )
        )

        # record_activity also updates the asset's behavioral anomaly score (Gap 2):
        # each alert is one activity event, scored against the asset's own baseline.
        # Use the alert's own timestamp (when the activity happened) rather than the
        # triage time, so a real burst is not flattened by serial processing lag.
        rag = await chromadb_client.record_activity(log.source_ip, now=log.timestamp.timestamp())

        logger.info(
            json.dumps(
                {
                    "event": "rag_complete",
                    "asset_name": rag.asset_name,
                    "asset_criticality": rag.asset_criticality,
                    "ueba_anomaly_score": rag.ueba.anomaly_score,
                }
            )
        )

        if metrics is not None:
            metrics.record_rag(time.perf_counter() - rag_stage_start)

    except Exception as e:
        if metrics is not None:
            metrics.record_rag(time.perf_counter() - rag_stage_start)
            metrics.record_triage(time.perf_counter() - total_perf_start)
            metrics.record_alert(
                status="error",
                severity="unknown",
                duration_s=time.perf_counter() - total_perf_start,
            )
        logger.error(
            json.dumps(
                {
                    "event": "rag_error",
                    "error": str(e),
                    "asset": log.source_ip,
                }
            )
        )
        return None

    # UEBA self-update: an unprofiled asset (no baseline) triggers an identity sync
    # so its UEBA context is populated for next time. Self-limiting — once synced,
    # has_baseline becomes True and this stops firing. Failures here must not drop
    # the alert, so the publisher swallows its own errors.
    if not rag.ueba.has_baseline and on_unprofiled_asset is not None:
        await on_unprofiled_asset(log.source_ip)

    # ========================================================================
    # STEP 3b: UEBA false-positive gate
    # Discard only when a real behavioural baseline confirms this is normal
    # (low anomaly), the rule is low severity, the asset is not critical
    # infrastructure, AND the SLM was only weakly suspicious. A confident SLM
    # suspicion (>= fp_gate_confidence_ceiling) means the model and a fired Wazuh
    # rule agree it is an attack — a calm asset baseline must not silently veto
    # that (otherwise a level-7 SQLi on a "quiet" profiled asset is dropped before
    # the LLM ever sees it). Without a baseline (has_baseline=False),
    # anomaly_score=0.0 means "unknown", not "normal", so the gate fails open.
    # ========================================================================
    if (
        rag.ueba.has_baseline
        and rag.ueba.anomaly_score < 0.15
        and log.rule_level <= 8
        and rag.asset_criticality != "tier0"
        and slm.confidence < fp_gate_confidence_ceiling
    ):
        if metrics is not None:
            metrics.record_triage(time.perf_counter() - total_perf_start)
            metrics.record_alert(
                status="discarded",
                severity="low",
                duration_s=time.perf_counter() - total_perf_start,
            )
        logger.info(
            json.dumps(
                {
                    "event": "alert_discarded",
                    "reason": "ueba_fp_gate",
                    "ueba_anomaly_score": rag.ueba.anomaly_score,
                    "rule_level": log.rule_level,
                    "asset_criticality": rag.asset_criticality,
                    "slm_confidence": slm.confidence,
                }
            )
        )
        return None

    if metrics is not None:
        metrics.record_triage(time.perf_counter() - total_perf_start)

    logger.info(
        json.dumps(
            {
                "event": "triage_escalated",
                "alert_id": str(log.id),
                "report_id": str(report_id),
                "confidence": slm.confidence,
                "asset_criticality": rag.asset_criticality,
            }
        )
    )

    return EscalatedAlert(
        report_id=report_id,
        pipeline_start=pipeline_start,
        start_time=start_time,
        log=log,
        slm_analysis=slm,
        rag_context=rag,
    )


async def analyze_log(
    escalated: EscalatedAlert,
    ollama_client: OllamaClient,
    shuffle_client: ShuffleClient,
    metrics: MetricsCollector | None = None,
    llm_timeout: float = 45.0,
    llm_model: str = _DEFAULT_LLM_MODEL,
    use_schema: bool = False,
    response_policies: dict[int, ResponsePolicy] | None = None,
) -> AegisReport | None:
    """
    Run the slow analysis stage of the AEGIS pipeline (LLM + risk + report + SOAR).

    Analysis steps (strict order):
    1. LLM: Detailed threat analysis (Mistral 7B) with fallback to SLM confidence
    2. Risk: Compute composite danger_score + uncertainty
    3. Decision: Determine action (always requires human validation)
    4. Report: Create final AegisReport
    5. SOAR: Send to Shuffle webhook
    6. Return: Complete report for human review

    Args:
        escalated: EscalatedAlert bundle produced by triage_log.
        ollama_client: Initialized OllamaClient for LLM inference.
        shuffle_client: Initialized ShuffleClient for webhook delivery.
        metrics: Optional metrics collector for Prometheus reporting.
        llm_timeout: LLM request timeout in seconds (default: 45).

    Returns:
        AegisReport: Complete analysis report, or None if report construction
                     or risk scoring failed.
    """
    log = escalated.log
    slm = escalated.slm_analysis
    rag = escalated.rag_context
    report_id = escalated.report_id
    pipeline_start = escalated.pipeline_start
    start_time = escalated.start_time
    total_perf_start = time.perf_counter()

    # ========================================================================
    # STEP 4: LLM - Detailed threat analysis (with fallback)
    # ========================================================================
    llm = None
    llm_stage_start = time.perf_counter()
    try:
        logger.debug(
            json.dumps(
                {
                    "event": "llm_start",
                    "timeout": llm_timeout,
                }
            )
        )

        llm_prompt = build_llm_prompt(log, slm, rag)
        llm_response_dict = await ollama_client.generate(
            model=llm_model,
            prompt=llm_prompt,
            timeout=llm_timeout,
            keep_alive=-1,  # Pi 16 GB holds both SLM and LLM — no swap needed
            # The full report JSON (10 fields, multi-sentence summary) needs headroom
            # to close. At 450 the model truncated mid-string under format=json, yielding
            # invalid JSON that was discarded into the SLM fallback. Set here (not only in
            # the Modelfile) so the cap holds regardless of the deployed model build.
            num_predict=768,
            format_schema=LlmResponse.model_json_schema() if use_schema else None,
        )

        llm = LlmResponse(**llm_response_dict)

        logger.info(
            json.dumps(
                {
                    "event": "llm_complete",
                    "confidence": llm.confidence,
                    "attack_confirmed": llm.attack_confirmed,
                    "severity": llm.severity,
                    "attack_type": llm.attack_type,
                    "summary": llm.plain_language_summary,
                    "action": llm.recommended_action,
                    "requires_human_validation": llm.requires_human_validation,
                }
            )
        )

        if metrics is not None:
            metrics.record_llm(time.perf_counter() - llm_stage_start)

    except (TimeoutError, Exception) as e:
        if metrics is not None:
            metrics.record_llm(time.perf_counter() - llm_stage_start)
        logger.warning(
            json.dumps(
                {
                    "event": "llm_error",
                    "error": str(e),
                    "fallback": "using_slm_confidence",
                }
            )
        )
        # Fallback: LLM failed, will use SLM confidence in risk_score
        llm = None

    # ========================================================================
    # STEP 5: Risk - Compute composite danger_score
    # ========================================================================
    try:
        logger.debug(
            json.dumps(
                {
                    "event": "risk_computation_start",
                }
            )
        )

        risk_score = compute_risk_score(
            slm=slm,
            llm=llm,
            rule_level=log.rule_level,
            asset_criticality=rag.asset_criticality,
            ueba_anomaly_score=rag.ueba.anomaly_score,
            has_baseline=rag.ueba.has_baseline,
        )

        logger.info(
            json.dumps(
                {
                    "event": "risk_computation_complete",
                    "danger_score": risk_score.danger_score,
                    "uncertainty": risk_score.uncertainty,
                    "confidence_interval": risk_score.confidence_interval,
                }
            )
        )

    except Exception as e:
        if metrics is not None:
            metrics.record_alert(
                status="error",
                severity="unknown",
                duration_s=time.perf_counter() - total_perf_start,
            )
        logger.error(
            json.dumps(
                {
                    "event": "risk_computation_error",
                    "error": str(e),
                }
            )
        )
        return None

    # ========================================================================
    # STEP 6: Decision - Determine severity and action
    # ========================================================================

    # Severity mapping: danger_score → severity (the composite risk floor).
    severity: Literal["critical", "high", "medium", "low"]
    if risk_score.danger_score >= 0.8:
        severity = "critical"
    elif risk_score.danger_score >= 0.6:
        severity = "high"
    elif risk_score.danger_score >= 0.4:
        severity = "medium"
    else:
        severity = "low"

    # A CONFIRMED attack may raise (never lower) the composite severity: the LLM
    # analysed the alert and assigned its own severity, so a confirmed SQLi/XSS is
    # not filed as "medium" just because the host is calm and non-critical. The
    # composite stays the floor; the human gate still applies regardless.
    _rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    if llm is not None and llm.attack_confirmed and _rank.get(llm.severity, 0) > _rank[severity]:
        severity = llm.severity

    # NON-NEGOTIABLE CONSTRAINT: human-in-the-loop is mandatory.
    # Zero automatic remediation (auto_remediation_allowed = False).
    requires_human = True
    auto_remediation = False

    if llm is None:
        # LLM unavailable (timeout OR unparseable/incomplete response) → human validation.
        # Keep the wording cause-agnostic: this path also fires on malformed JSON, so
        # "timed out" would be misleading in the report.
        recommended_action = (
            "LLM analysis unavailable (timeout or invalid response). Manual review "
            "required. Recommend isolating the source workstation and investigating."
        )
        requires_human = True
        auto_remediation = False
    else:
        # The LLM owns the remediation: it has the alert, asset and UEBA context and is
        # expected to name the attacker IP, the endpoint and a concrete step itself. No
        # deterministic playbook override — a sovereign local model must reason about the
        # action, not read it from a hardcoded template.
        recommended_action = llm.recommended_action
        # Even if the LLM says no human is needed, AEGIS always requires it.
        requires_human = True

    # SOAR response policy: a human may pre-define, per Wazuh rule, a containment action
    # (a standing pre-approval). When one matches this alert's rule, record it on the
    # report so the human is told — as a fact tied to the rule code, not the LLM — that a
    # pre-defined response applies. An "auto" policy is dispatched without a per-incident
    # click (auto_remediation_allowed=True); the human still receives the incident.
    applied_response: AppliedResponse | None = None
    policy = (response_policies or {}).get(log.rule_id)
    if policy is not None:
        actor = log.attacker_ip or log.source_ip
        applied_response = AppliedResponse(
            rule_id=log.rule_id,
            action=render_action(
                policy, actor=actor, host=log.source_agent, url=extract_request_path(log.full_log)
            ),
            auto_applied=policy.auto,
        )
        if policy.auto:
            auto_remediation = True

    decision = Decision(
        severity=severity,
        requires_human_validation=requires_human,
        auto_remediation_allowed=auto_remediation,
        recommended_action=recommended_action,
        applied_response=applied_response,
    )

    logger.debug(
        json.dumps(
            {
                "event": "decision_made",
                "severity": severity,
                "requires_human_validation": requires_human,
            }
        )
    )

    # ========================================================================
    # STEP 7: Report - Construct final AegisReport
    # ========================================================================
    try:
        logger.debug(
            json.dumps(
                {
                    "event": "report_construction_start",
                }
            )
        )

        report = AegisReport(
            alert_id=report_id,
            timestamp=pipeline_start,
            pipeline_version="0.3.0",
            source_log=log,
            slm_analysis=slm,
            llm_analysis=llm,
            rag_context=rag,
            risk_score=risk_score,
            decision=decision,
            processing_time_ms=int((time.time() - start_time) * 1000),
        )

        logger.info(
            json.dumps(
                {
                    "event": "report_constructed",
                    "alert_id": str(report.alert_id),
                    "processing_time_ms": report.processing_time_ms,
                    "danger_score": report.risk_score.danger_score,
                }
            )
        )

    except Exception as e:
        if metrics is not None:
            metrics.record_alert(
                status="error",
                severity="unknown",
                duration_s=time.perf_counter() - total_perf_start,
            )
        logger.error(
            json.dumps(
                {
                    "event": "report_construction_error",
                    "error": str(e),
                }
            )
        )
        return None

    # ========================================================================
    # STEP 8: SOAR - Send to Shuffle webhook
    # ========================================================================
    try:
        logger.debug(
            json.dumps(
                {
                    "event": "soar_send_start",
                    "alert_id": str(report.alert_id),
                }
            )
        )

        success = await shuffle_client.send_report(report)
        if success:
            if metrics is not None:
                metrics.record_soar("success")
            logger.info(
                json.dumps(
                    {
                        "event": "soar_send_complete",
                        "alert_id": str(report.alert_id),
                    }
                )
            )

    except Exception as e:
        if metrics is not None:
            metrics.record_soar("failure")
        logger.warning(
            json.dumps(
                {
                    "event": "soar_send_error",
                    "error": str(e),
                }
            )
        )
        # Report remains available for human review even if SOAR delivery fails.

    # ========================================================================
    # STEP 9: Return complete report for human review
    # ========================================================================
    logger.info(
        json.dumps(
            {
                "event": "pipeline_complete",
                "alert_id": str(report.alert_id),
                "total_processing_time_ms": report.processing_time_ms,
                "severity": report.decision.severity,
            }
        )
    )

    if metrics is not None:
        metrics.record_danger_score(
            score=report.risk_score.danger_score,
            criticality=report.rag_context.asset_criticality,
        )
        metrics.record_alert(
            status="processed",
            severity=report.decision.severity,
            duration_s=time.perf_counter() - total_perf_start,
        )

    return report
