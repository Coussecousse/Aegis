"""
Pydantic v2 models for the AEGIS pipeline.

Defines strict JSON structures for each pipeline step:
- WazuhLog: raw input from RabbitMQ (raw Wazuh log)
- SlmResponse: response from SLM TinyLlama (quick suspicion score)
- LlmResponse: response from LLM Mistral 7B (detailed report)
- RagContext: enriched business context from ChromaDB
- RiskScore: composite danger score calculation
- AegisReport: complete final report sent to Shuffle SOAR

Zero secrets in this file. Type hints are mandatory everywhere.
"""

import difflib
from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


class WazuhLog(BaseModel):
    """Raw log received from Wazuh via RabbitMQ."""

    id: UUID = Field(..., description="Unique log identifier (UUID v4)")
    timestamp: datetime = Field(..., description="ISO 8601 timestamp")
    source_agent: str = Field(..., description="Name of the machine that generated the alert")
    source_ip: str = Field(..., description="Source IP address (IPv4 or IPv6)")
    rule_id: int = Field(..., ge=1, description="Wazuh rule identifier")
    rule_level: int = Field(..., ge=0, le=15, description="Wazuh severity level (0-15)")
    rule_description: str = Field(..., description="Readable rule description")
    full_log: str = Field(..., description="Full log or event content")
    mitre_technique: str | None = Field(
        None, description="Associated MITRE ATT&CK technique (e.g. T1021)"
    )
    decoder_name: str | None = Field(None, description="Decoder used (e.g. windows-eventlog)")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "timestamp": "2026-05-19T14:32:15Z",
                "source_agent": "WORKSTATION-01",
                "source_ip": "192.168.1.105",
                "rule_id": 1234,
                "rule_level": 8,
                "rule_description": "Possible lateral movement detected",
                "full_log": "net.exe user localadmin Password123 /add",
                "mitre_technique": "T1021",
                "decoder_name": "windows-eventlog",
            }
        }
    )


class SlmResponse(BaseModel):
    """Response from SLM TinyLlama: quick suspicion analysis."""

    is_suspect: bool = Field(..., description="Is the log suspicious?")
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="SLM confidence (0.0 to 1.0)",
    )
    behavior_category: Literal[
        "lateral_movement",
        "privilege_escalation",
        "exfiltration",
        "persistence",
        "normal",
    ] = Field(
        ...,
        description="Detected behavior category",
    )
    reasoning_short: str = Field(..., description="Short scoring rationale (< 200 chars)")

    @field_validator("behavior_category", mode="before")
    @classmethod
    def normalize_behavior_category(cls, v: Any) -> str:
        """Fuzzy-match SLM output to the closest valid category (handles model typos)."""
        valid = {
            "lateral_movement",
            "privilege_escalation",
            "exfiltration",
            "persistence",
            "normal",
        }
        if v in valid:
            return str(v)
        matches = difflib.get_close_matches(str(v), valid, n=1, cutoff=0.75)
        return str(matches[0]) if matches else "normal"

    raw_probabilities: dict[str, float] = Field(
        ..., description="Raw probabilities: {'suspect': float, 'benign': float}"
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "is_suspect": True,
                "confidence": 0.87,
                "behavior_category": "lateral_movement",
                "reasoning_short": "Abnormal net.exe execution by a non-admin account",
                "raw_probabilities": {"suspect": 0.87, "benign": 0.13},
            }
        }
    )


class LlmResponse(BaseModel):
    """Response from LLM Mistral 7B: detailed analysis with context."""

    attack_confirmed: bool = Field(..., description="Is the attack confirmed by the LLM?")
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="LLM confidence (0.0 to 1.0)",
    )
    attack_type: str = Field(
        ..., description="Detected attack type (e.g. lateral movement via SMB)"
    )
    severity: Literal["critical", "high", "medium", "low"] = Field(
        ...,
        description=(
            "LLM's own severity estimate — raw, uncalibrated model opinion. "
            "NOT the authoritative severity; see Decision.severity, which is "
            "derived deterministically from RiskScore.danger_score."
        ),
    )
    affected_asset: str = Field(..., description="Affected asset (name or IP)")
    asset_criticality: Literal["tier0", "tier1", "tier2"] = Field(
        ...,
        description="Criticality of the targeted asset",
    )
    plain_language_summary: str = Field(..., description="Plain-language summary (< 500 chars)")
    recommended_action: str = Field(..., description="Recommended remediation action")
    requires_human_validation: bool = Field(
        ..., description="Does the action require human validation?"
    )
    raw_probabilities: dict[str, float] = Field(
        ...,
        description="Raw probabilities: {'attack': float, 'false_positive': float}",
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "attack_confirmed": True,
                "confidence": 0.91,
                "attack_type": "Lateral movement via SMB",
                "severity": "critical",
                "affected_asset": "DC-AEROTECH-01",
                "asset_criticality": "tier0",
                "plain_language_summary": "An attacker appears to be moving laterally...",
                "recommended_action": "Immediately isolate the source workstation",
                "requires_human_validation": True,
                "raw_probabilities": {"attack": 0.91, "false_positive": 0.09},
            }
        }
    )


class UEBAMetrics(BaseModel):
    """User and Entity Behavior Analytics: behavioral baselines and anomalies."""

    has_baseline: bool = Field(
        default=True,
        description=(
            "Whether a real behavioral baseline exists for this asset. False when "
            "the asset is unknown to ChromaDB or has no UEBA profile yet — in which "
            "case anomaly_score (0.0) means 'unknown', not 'confirmed normal', so the "
            "false-positive gate must not use it to discard a suspect alert."
        ),
    )
    baseline_description: str = Field(
        ..., description="Description of the expected normal behavior of this asset"
    )
    associated_users: list[str] = Field(
        default_factory=list,
        description="Users typically active on this asset",
    )
    normal_activity_window: str = Field(
        ...,
        description="Normal activity window (e.g. '08:00-18:00 weekdays')",
    )
    recent_anomalies: list[str] = Field(
        default_factory=list,
        description=("Recent behavioral anomalies " "(e.g. out-of-hours activity, unusual users)"),
    )
    anomaly_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Cumulative anomaly score (0.0=normal, 1.0=very anomalous)",
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "baseline_description": (
                    "Domain Controller: authentications from 08:00-18:00, " "~500-1000 requests/day"
                ),
                "associated_users": ["domain_admin", "svc_replication", "backup_service"],
                "normal_activity_window": "08:00-18:00 weekdays, 09:00-12:00 weekends",
                "recent_anomalies": [
                    "Authentications at 23:45 (out of hours)",
                    "Non-admin access account attempting LDAP operation",
                ],
                "anomaly_score": 0.68,
            }
        }
    )


class RagContext(BaseModel):
    """Enriched business context from ChromaDB (asset metadata + UEBA)."""

    asset_name: str = Field(..., description="Unique asset identifier")
    asset_criticality: Literal["tier0", "tier1", "tier2"] = Field(
        ...,
        description="Criticality tier",
    )
    asset_description: str = Field(..., description="Business description of the asset")
    similar_incidents: list[str] = Field(
        default_factory=list,
        description="UUIDs of similar past incidents",
    )
    ueba: UEBAMetrics = Field(
        ..., description="Behavioral analytics: baselines, anomalies, user context"
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "asset_name": "DC-AEROTECH-01",
                "asset_criticality": "tier0",
                "asset_description": "Primary Domain Controller - Production",
                "similar_incidents": ["550e8400-e29b-41d4-a716-446655440000"],
                "ueba": {
                    "baseline_description": (
                        "Domain Controller: authentications 08:00-18:00, " "~500-1000 requests/day"
                    ),
                    "associated_users": [
                        "domain_admin",
                        "svc_replication",
                        "backup_service",
                    ],
                    "normal_activity_window": "08:00-18:00 weekdays, 09:00-12:00 weekends",
                    "recent_anomalies": [
                        "Authentications at 23:45 (out of hours)",
                        "Non-admin account attempting LDAP operation",
                    ],
                    "anomaly_score": 0.68,
                },
            }
        }
    )


class EscalatedAlert(BaseModel):
    """Bundle handed from the triage stage to the analysis stage via RabbitMQ.

    Carries everything the analysis stage needs to run the LLM, score risk,
    and build the final report — without re-fetching RAG context or re-running
    the SLM. All fields are JSON-serializable so the bundle survives the
    triage → `aegis.reports` queue → analysis process boundary.
    """

    report_id: UUID = Field(..., description="Report identifier carried through to AegisReport")
    pipeline_start: datetime = Field(..., description="Pipeline start timestamp (UTC)")
    start_time: float = Field(
        ..., description="Pipeline start as epoch seconds, used for processing_time_ms"
    )
    log: WazuhLog = Field(..., description="Original Wazuh log being analyzed")
    slm_analysis: SlmResponse = Field(..., description="SLM triage result that escalated this log")
    rag_context: RagContext = Field(..., description="Asset context fetched during triage")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "report_id": "550e8400-e29b-41d4-a716-446655440000",
                "pipeline_start": "2026-05-19T14:32:15Z",
                "start_time": 1747661535.0,
            }
        }
    )


class RiskScore(BaseModel):
    """Composite danger score computed in risk_scorer.py."""

    danger_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Composite danger score (0.0 to 1.0)",
    )
    confidence_interval: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Absolute difference between SLM and LLM",
    )
    uncertainty: Literal["low", "medium", "high"] = Field(
        ...,
        description="Categorical: low (< 0.1) | medium (< 0.25) | high (>= 0.25)",
    )
    score_breakdown: dict[str, float] = Field(
        ...,
        description="Breakdown: slm_contribution, llm_contribution, "
        "rule_contribution, criticality_multiplier",
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "danger_score": 0.94,
                "confidence_interval": 0.06,
                "uncertainty": "low",
                "score_breakdown": {
                    "slm_contribution": 0.26,
                    "llm_contribution": 0.46,
                    "rule_contribution": 0.13,
                    "criticality_multiplier": 1.5,
                },
            }
        }
    )


class Decision(BaseModel):
    """Decision block: recommended action and required validations."""

    severity: Literal["critical", "high", "medium", "low"] = Field(
        ...,
        description=(
            "Authoritative severity for triage routing and human review, derived "
            "deterministically from RiskScore.danger_score via fixed thresholds. "
            "Distinct from LlmResponse.severity (the model's raw, uncalibrated "
            "opinion)."
        ),
    )
    requires_human_validation: bool = Field(
        ..., description="Does the decision require human validation?"
    )
    auto_remediation_allowed: bool = Field(
        ...,
        description="Automatic remediation allowed (always False in v0.2)",
    )
    recommended_action: str = Field(..., description="Recommended remediation action")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "severity": "critical",
                "requires_human_validation": True,
                "auto_remediation_allowed": False,
                "recommended_action": "Isolate the source workstation via Active Directory LDAPS",
            }
        }
    )


class AegisReport(BaseModel):
    """Complete final report sent to Shuffle SOAR.

    `llm_analysis.severity` (when present) is the model's raw, uncalibrated
    opinion and may disagree with `decision.severity` — the binding value
    derived from `risk_score.danger_score`, which is authoritative for triage
    and human review.
    """

    alert_id: UUID = Field(..., description="Unique alert report UUID")
    timestamp: datetime = Field(..., description="Report timestamp (ISO 8601)")
    pipeline_version: str = Field(default="0.3.0", description="AEGIS pipeline version")
    source_log: WazuhLog = Field(..., description="Complete original Wazuh log")
    slm_analysis: SlmResponse = Field(..., description="SLM response")
    llm_analysis: LlmResponse | None = Field(
        None, description="LLM response (None on timeout or error)"
    )
    rag_context: RagContext = Field(..., description="Enriched business context")
    risk_score: RiskScore = Field(..., description="Computed composite score")
    decision: Decision = Field(..., description="Decision block: action & validations")
    processing_time_ms: int = Field(
        ..., ge=0, description="End-to-end processing time in milliseconds"
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "alert_id": "550e8400-e29b-41d4-a716-446655440000",
                "timestamp": "2026-05-19T14:35:42Z",
                "pipeline_version": "0.3.0",
                "source_log": {
                    "id": "550e8400-e29b-41d4-a716-446655440001",
                    "timestamp": "2026-05-19T14:32:15Z",
                    "source_agent": "WORKSTATION-01",
                    "source_ip": "192.168.1.105",
                    "rule_id": 1234,
                    "rule_level": 8,
                    "rule_description": "Possible lateral movement detected",
                    "full_log": "net.exe user localadmin",
                    "mitre_technique": "T1021",
                    "decoder_name": "windows-eventlog",
                },
                "slm_analysis": {
                    "is_suspect": True,
                    "confidence": 0.87,
                    "behavior_category": "lateral_movement",
                    "reasoning_short": "Abnormal net.exe execution by a non-admin account",
                    "raw_probabilities": {"suspect": 0.87, "benign": 0.13},
                },
                "llm_analysis": {
                    "attack_confirmed": True,
                    "confidence": 0.91,
                    "attack_type": "Lateral movement via SMB",
                    "severity": "critical",
                    "affected_asset": "DC-AEROTECH-01",
                    "asset_criticality": "tier0",
                    "plain_language_summary": "An attacker appears to be moving laterally",
                    "recommended_action": "Immediately isolate the source workstation",
                    "requires_human_validation": True,
                    "raw_probabilities": {"attack": 0.91, "false_positive": 0.09},
                },
                "rag_context": {
                    "asset_name": "DC-AEROTECH-01",
                    "asset_criticality": "tier0",
                    "asset_description": "Primary Domain Controller - Production",
                    "similar_incidents": ["550e8400-e29b-41d4-a716-446655440002"],
                    "ueba": {
                        "baseline_description": (
                            "Domain Controller: authentications 08:00-18:00, "
                            "~500-1000 requests/day"
                        ),
                        "associated_users": [
                            "domain_admin",
                            "svc_replication",
                            "backup_service",
                        ],
                        "normal_activity_window": "08:00-18:00 weekdays, 09:00-12:00 weekends",
                        "recent_anomalies": [
                            "Authentications at 23:45 (out of hours)",
                            "Non-admin account attempting LDAP operation",
                        ],
                        "anomaly_score": 0.68,
                    },
                },
                "risk_score": {
                    "danger_score": 0.94,
                    "confidence_interval": 0.06,
                    "uncertainty": "low",
                    "score_breakdown": {
                        "slm_contribution": 0.26,
                        "llm_contribution": 0.46,
                        "rule_contribution": 0.13,
                        "criticality_multiplier": 1.5,
                    },
                },
                "decision": {
                    "severity": "critical",
                    "requires_human_validation": True,
                    "auto_remediation_allowed": False,
                    "recommended_action": (
                        "Isolate the source workstation via Active Directory LDAPS"
                    ),
                },
                "processing_time_ms": 3240,
            }
        }
    )
