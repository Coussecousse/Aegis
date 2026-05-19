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

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field


class WazuhLog(BaseModel):
    """Raw log received from Wazuh via RabbitMQ."""

    id: UUID = Field(..., description="Identifiant unique du log (UUID v4)")
    timestamp: datetime = Field(..., description="Horodatage ISO8601")
    source_agent: str = Field(..., description="Nom de la machine qui a généré l'alerte")
    source_ip: str = Field(..., description="Adresse IP source (IPv4 ou IPv6)")
    rule_id: int = Field(..., ge=1, description="Identifiant de la règle Wazuh")
    rule_level: int = Field(..., ge=0, le=15, description="Niveau de sévérité Wazuh (0-15)")
    rule_description: str = Field(..., description="Description lisible de la règle")
    full_log: str = Field(..., description="Contenu complet du log ou événement")
    mitre_technique: str | None = Field(
        None, description="Technique MITRE ATT&CK associée (ex: T1021)"
    )
    decoder_name: str | None = Field(None, description="Décodeur utilisé (ex: windows-eventlog)")

    class Config:
        """Pydantic v2 config."""

        json_schema_extra = {
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


class SlmResponse(BaseModel):
    """Response from SLM TinyLlama: quick suspicion analysis."""

    is_suspect: bool = Field(..., description="Le log est-il suspect ?")
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confiance du SLM (0.0 à 1.0)",
    )
    behavior_category: Literal[
        "lateral_movement",
        "privilege_escalation",
        "exfiltration",
        "persistence",
        "normal",
    ] = Field(
        ...,
        description="Catégorie du comportement détecté",
    )
    reasoning_short: str = Field(..., description="Justification courte du score (< 200 chars)")
    raw_probabilities: dict[str, float] = Field(
        ..., description="Probabilités brutes : {'suspect': float, 'benign': float}"
    )

    class Config:
        """Pydantic v2 config."""

        json_schema_extra = {
            "example": {
                "is_suspect": True,
                "confidence": 0.87,
                "behavior_category": "lateral_movement",
                "reasoning_short": "Exécution anormale de net.exe par un compte non-admin",
                "raw_probabilities": {"suspect": 0.87, "benign": 0.13},
            }
        }


class LlmResponse(BaseModel):
    """Response from LLM Mistral 7B: detailed analysis with context."""

    attack_confirmed: bool = Field(..., description="L'attaque est-elle confirmée par le LLM ?")
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confiance du LLM (0.0 à 1.0)",
    )
    attack_type: str = Field(
        ..., description="Type d'attaque détecté (ex: Mouvement latéral via SMB)"
    )
    severity: Literal["critical", "high", "medium", "low"] = Field(
        ...,
        description="Sévérité estimée",
    )
    affected_asset: str = Field(..., description="Asset affecté (nom ou IP)")
    asset_criticality: Literal["tier0", "tier1", "tier2"] = Field(
        ...,
        description="Criticité de l'asset ciblé",
    )
    plain_language_summary: str = Field(
        ..., description="Résumé vulgarisé en langage naturel (< 500 chars)"
    )
    recommended_action: str = Field(..., description="Action recommandée pour la remédiation")
    requires_human_validation: bool = Field(
        ..., description="L'action requiert-elle une validation humaine ?"
    )
    raw_probabilities: dict[str, float] = Field(
        ...,
        description="Probabilités brutes : {'attack': float, 'false_positive': float}",
    )

    class Config:
        """Pydantic v2 config."""

        json_schema_extra = {
            "example": {
                "attack_confirmed": True,
                "confidence": 0.91,
                "attack_type": "Mouvement latéral via SMB",
                "severity": "critical",
                "affected_asset": "DC-AEROTECH-01",
                "asset_criticality": "tier0",
                "plain_language_summary": "Un attaquant semble se déplacer latéralement...",
                "recommended_action": "Isoler immédiatement le poste source",
                "requires_human_validation": True,
                "raw_probabilities": {"attack": 0.91, "false_positive": 0.09},
            }
        }


class UEBAMetrics(BaseModel):
    """User and Entity Behavior Analytics: behavioral baselines and anomalies."""

    baseline_description: str = Field(
        ..., description="Description du comportement normal attendu de cet asset"
    )
    associated_users: list[str] = Field(
        default_factory=list,
        description="Utilisateurs habituellement actifs sur cet asset",
    )
    normal_activity_window: str = Field(
        ...,
        description="Fenêtre temporelle d'activité normale (ex: '08:00-18:00 weekdays')",
    )
    recent_anomalies: list[str] = Field(
        default_factory=list,
        description=(
            "Anomalies comportementales détectées récemment "
            "(ex: activité hors heures, utilisateurs inhabituels)"
        ),
    )
    anomaly_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Score d'anomalie cumulée (0.0=normal, 1.0=très anormal)",
    )

    class Config:
        """Pydantic v2 config."""

        json_schema_extra = {
            "example": {
                "baseline_description": (
                    "Contrôleur de Domaine : authentifications de 08:00-18:00, "
                    "~500-1000 requêtes/jour"
                ),
                "associated_users": ["domain_admin", "svc_replication", "backup_service"],
                "normal_activity_window": "08:00-18:00 weekdays, 09:00-12:00 weekends",
                "recent_anomalies": [
                    "Authentifications à 23:45 (hors heures)",
                    "Compte d'accès non-admin tente opération LDAP",
                ],
                "anomaly_score": 0.68,
            }
        }


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

    class Config:
        """Pydantic v2 config."""

        json_schema_extra = {
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


class RiskScore(BaseModel):
    """Composite danger score computed in risk_scorer.py."""

    danger_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Score de danger composite (0.0 à 1.0)",
    )
    confidence_interval: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Écart absolu entre SLM et LLM",
    )
    uncertainty: Literal["low", "medium", "high"] = Field(
        ...,
        description="Catégorique : low (< 0.1) | medium (< 0.25) | high (>= 0.25)",
    )
    score_breakdown: dict[str, float] = Field(
        ...,
        description="Décomposition : slm_contribution, llm_contribution, "
        "rule_contribution, criticality_multiplier",
    )

    class Config:
        """Pydantic v2 config."""

        json_schema_extra = {
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


class Decision(BaseModel):
    """Decision block: recommended action and required validations."""

    severity: Literal["critical", "high", "medium", "low"] = Field(
        ...,
        description="Sévérité finale",
    )
    requires_human_validation: bool = Field(
        ..., description="La décision requiert-elle une validation humaine ?"
    )
    auto_remediation_allowed: bool = Field(
        ...,
        description="Remédiation automatique autorisée (toujours False pour v0.2)",
    )
    recommended_action: str = Field(..., description="Action recommandée pour la remédiation")

    class Config:
        """Pydantic v2 config."""

        json_schema_extra = {
            "example": {
                "severity": "critical",
                "requires_human_validation": True,
                "auto_remediation_allowed": False,
                "recommended_action": "Isoler le poste source via Active Directory LDAPS",
            }
        }


class AegisReport(BaseModel):
    """Complete final report sent to Shuffle SOAR."""

    alert_id: UUID = Field(..., description="UUID unique du rapport d'alerte")
    timestamp: datetime = Field(..., description="Horodatage du rapport (ISO8601)")
    pipeline_version: str = Field(default="0.2.0", description="Version du pipeline AEGIS")
    source_log: WazuhLog = Field(..., description="Log Wazuh original complet")
    slm_analysis: SlmResponse = Field(..., description="Réponse du SLM")
    llm_analysis: LlmResponse | None = Field(
        None, description="Réponse du LLM (None si timeout ou erreur)"
    )
    rag_context: RagContext = Field(..., description="Contexte métier enrichi")
    risk_score: RiskScore = Field(..., description="Score composite calculé")
    decision: Decision = Field(..., description="Bloc décisionnel : action & validations")
    processing_time_ms: int = Field(
        ..., ge=0, description="Temps de traitement complet en millisecondes"
    )

    class Config:
        """Pydantic v2 config."""

        json_schema_extra = {
            "example": {
                "alert_id": "550e8400-e29b-41d4-a716-446655440000",
                "timestamp": "2026-05-19T14:35:42Z",
                "pipeline_version": "0.2.0",
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
                    "reasoning_short": "Exécution anormale de net.exe par un compte non-admin",
                    "raw_probabilities": {"suspect": 0.87, "benign": 0.13},
                },
                "llm_analysis": {
                    "attack_confirmed": True,
                    "confidence": 0.91,
                    "attack_type": "Mouvement latéral via SMB",
                    "severity": "critical",
                    "affected_asset": "DC-AEROTECH-01",
                    "asset_criticality": "tier0",
                    "plain_language_summary": "Un attaquant semble se déplacer latéralement",
                    "recommended_action": "Isoler immédiatement le poste source",
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
                    "recommended_action": "Isoler le poste source via Active Directory LDAPS",
                },
                "processing_time_ms": 3240,
            }
        }
