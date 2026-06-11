"""
AEGIS pipeline orchestration: two-stage alert processing workflow.

The pipeline is split across two independently-running RabbitMQ consumers so a
fast SLM triage loop is never blocked behind a slow multi-minute LLM analysis:

Stage 1 — triage_log() (consumer.py, queue aegis.triage):
1. Send to SLM Qwen 2.5 1.5B → quick suspicion score
2. Check if is_suspect and confidence > SUSPICION_THRESHOLD
3. Query ChromaDB → asset context + UEBA, apply false-positive gate
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
import os
import time
from datetime import UTC, datetime
from typing import Literal
from uuid import uuid4

from aegis.llm.client import OllamaClient
from aegis.middleware.models import (
    AegisReport,
    Decision,
    EscalatedAlert,
    LlmResponse,
    SlmResponse,
    WazuhLog,
)
from aegis.middleware.prompt_builder import (
    build_llm_prompt,
    build_slm_prompt,
)
from aegis.middleware.risk_scorer import compute_risk_score
from aegis.monitoring.metrics import MetricsCollector
from aegis.rag.client import ChromaDBClient
from aegis.soar.client import ShuffleClient

logger = logging.getLogger(__name__)

# Model names configurable via env — change SLM/LLM without code rebuild.
_SLM_MODEL = os.getenv("SLM_MODEL", "qwen25-aegis")
_LLM_MODEL = os.getenv("LLM_MODEL", "mistral-aegis")


async def triage_log(
    log: WazuhLog,
    ollama_client: OllamaClient,
    chromadb_client: ChromaDBClient,
    metrics: MetricsCollector | None = None,
    suspicion_threshold: float = 0.5,
    slm_timeout: float = 10.0,
) -> EscalatedAlert | None:
    """
    Run the fast triage stage of the AEGIS pipeline (SLM + RAG + gates).

    Triage steps (strict order):
    1. SLM: Quick suspicion scoring (Qwen 2.5 1.5B)
    2. Gate: If not suspect or low confidence → discard, return None
    3. RAG: Fetch asset context + UEBA from ChromaDB
    4. Gate: UEBA false-positive filter → discard, return None

    Logs that pass both gates are bundled into an EscalatedAlert for the
    analysis stage (analyze_log) to pick up from the aegis.reports queue.

    Args:
        log: WazuhLog to triage.
        ollama_client: Initialized OllamaClient for SLM inference.
        chromadb_client: Initialized ChromaDBClient for asset context.
        metrics: Optional metrics collector for Prometheus reporting.
        suspicion_threshold: Minimum confidence to proceed past SLM (default: 0.5).
        slm_timeout: SLM request timeout in seconds (default: 10).

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
            model=_SLM_MODEL,
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

        rag = await chromadb_client.get_asset_context(log.source_ip)

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

    # ========================================================================
    # STEP 3b: UEBA false-positive gate
    # Discard only when a real behavioural baseline confirms this is normal
    # (low anomaly), the rule is low severity, and the asset is not critical
    # infrastructure. Without a baseline (has_baseline=False), anomaly_score=0.0
    # means "unknown", not "normal" — failing open here keeps a suspect alert on
    # an unprofiled asset (the common case before the asset registry is seeded)
    # from being silently dropped before it ever reaches the LLM.
    # ========================================================================
    if (
        rag.ueba.has_baseline
        and rag.ueba.anomaly_score < 0.15
        and log.rule_level <= 8
        and rag.asset_criticality != "tier0"
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
) -> AegisReport | None:
    """
    Run the slow analysis stage of the AEGIS pipeline (LLM + risk + report + SOAR).

    Analysis steps (strict order):
    1. LLM: Detailed threat analysis (Mistral 7B) with fallback to SLM confidence
    2. Risk: Compute composite danger_score + uncertainty
    3. Decision: Determine action (always requires human validation in v0.2)
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
            model=_LLM_MODEL,
            prompt=llm_prompt,
            timeout=llm_timeout,
            keep_alive=-1,  # Pi 16 GB holds both SLM and LLM — no swap needed
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

    # Severity mapping: danger_score → severity
    severity: Literal["critical", "high", "medium", "low"]
    if risk_score.danger_score >= 0.8:
        severity = "critical"
    elif risk_score.danger_score >= 0.6:
        severity = "high"
    elif risk_score.danger_score >= 0.4:
        severity = "medium"
    else:
        severity = "low"

    # CONSTRAINT: In v0.2, human-in-the-loop is mandatory
    # Zero automatic remediation (auto_remediation_allowed = False)
    requires_human = True
    auto_remediation = False

    if llm is None:
        # LLM timeout → force human validation
        recommended_action = (
            "LLM analysis timed out. Manual review required. "
            "Recommend isolating the source workstation and investigating."
        )
        requires_human = True
        auto_remediation = False
    else:
        recommended_action = llm.recommended_action
        requires_human = llm.requires_human_validation
        # Even if LLM says no human needed, v0.2 always requires it
        requires_human = True

    decision = Decision(
        severity=severity,
        requires_human_validation=requires_human,
        auto_remediation_allowed=auto_remediation,
        recommended_action=recommended_action,
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
