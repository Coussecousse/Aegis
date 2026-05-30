"""
AEGIS pipeline orchestration: complete alert processing workflow.

Processes a single Wazuh log through the full pipeline:
1. Consume log from RabbitMQ (handled by consumer.py)
2. Send to SLM TinyLlama → quick suspicion score
3. Check if is_suspect and confidence > SUSPICION_THRESHOLD
4. Query ChromaDB → asset context + UEBA
5. Send to LLM Mistral 7B → detailed threat analysis
6. Compute composite risk_score (danger_score + uncertainty)
7. Send final AegisReport to Shuffle SOAR
8. Return complete report for human review (human-in-the-loop)

Timing: Measure total time in milliseconds.
Logging: Structured JSON at each step.

Zero cloud calls. Zero automatic remediation (human validation required).
"""

import json
import logging
import time
from datetime import UTC, datetime
from typing import Literal
from uuid import uuid4

from aegis.llm.client import OllamaClient
from aegis.middleware.models import (
    AegisReport,
    Decision,
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


async def process_log(
    log: WazuhLog,
    ollama_client: OllamaClient,
    chromadb_client: ChromaDBClient,
    shuffle_client: ShuffleClient,
    metrics: MetricsCollector | None = None,
    suspicion_threshold: float = 0.5,
    slm_timeout: float = 10.0,
    llm_timeout: float = 45.0,
) -> AegisReport | None:
    """
    Process a single Wazuh alert through the complete AEGIS pipeline.

    Pipeline steps (strict order):
    1. SLM: Quick suspicion scoring (TinyLlama)
    2. Gate: If not suspect or low confidence → ACK and return None
    3. RAG: Fetch asset context + UEBA from ChromaDB
    4. LLM: Detailed threat analysis (Mistral 7B) with fallback
    5. Risk: Compute composite danger_score + uncertainty
    6. Decision: Determine action (always requires human validation in v0.2)
    7. Report: Create final AegisReport
    8. SOAR: Send to Shuffle webhook
    9. Return: Complete report for human review

    Args:
        log: WazuhLog to process.
        ollama_client: Initialized OllamaClient for SLM/LLM inference.
        chromadb_client: Initialized ChromaDBClient for asset context.
        shuffle_client: Initialized ShuffleClient for webhook delivery.
        suspicion_threshold: Minimum confidence to proceed past SLM (default: 0.5).
        slm_timeout: SLM request timeout in seconds (default: 10).
        llm_timeout: LLM request timeout in seconds (default: 45).

    Returns:
        AegisReport: Complete analysis report, or None if alert was discarded
                     as benign during SLM gate.
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
            model="tinyllama-aegis",
            prompt=slm_prompt,
            timeout=slm_timeout,
            keep_alive=-1,  # keep SLM permanently in RAM for low-latency triage
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
            model="mistral-aegis",
            prompt=llm_prompt,
            timeout=llm_timeout,
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
