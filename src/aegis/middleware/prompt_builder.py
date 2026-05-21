"""
Prompt builders for SLM and LLM models in AEGIS pipeline.

Instructions, JSON schema, and model role are defined only once
in Modelfiles (docs/modelfiles/). These functions send only
the raw data needed for analysis, nothing else.

Principle: Small models have limited context windows. Keep prompts minimal.
"""

from aegis.middleware.models import RagContext, SlmResponse, WazuhLog


def build_slm_prompt(log: WazuhLog) -> str:
    """
    Build data-only prompt for SLM (TinyLlama).

    Contains only the Wazuh log fields relevant to suspicion scoring.
    Role, JSON format, and constraints are defined in Modelfile.slm-tinyllama.

    Args:
        log: Raw Wazuh alert log to analyze.

    Returns:
        str: Minimal data prompt for TinyLlama inference.
    """
    full_log_truncated = log.full_log[:300]
    return (
        f"Rule: {log.rule_id} | Level: {log.rule_level}/15\n"
        f"Description: {log.rule_description}\n"
        f"Machine: {log.source_agent} | IP: {log.source_ip}\n"
        f"Decoder: {log.decoder_name or 'unknown'}\n"
        f"MITRE: {log.mitre_technique or 'N/A'}\n"
        f"Log: {full_log_truncated}"
    )


def build_llm_prompt(log: WazuhLog, slm: SlmResponse, rag: RagContext) -> str:
    """
    Build data-only prompt for LLM (Mistral 7B).

    Contains the Wazuh log + SLM quick analysis + RAG asset context (UEBA).
    Role, JSON format, and report structure are defined in Modelfile.llm-mistral.

    Args:
        log: Original Wazuh alert log.
        slm: Quick suspicion score from SLM (pre-analysis context).
        rag: Enriched business context from ChromaDB (asset + UEBA).

    Returns:
        str: Contextual data prompt for Mistral inference.
    """
    # Format recent anomalies on a single line.
    anomalies = " / ".join(rag.ueba.recent_anomalies) if rag.ueba.recent_anomalies else "none"
    users = ", ".join(rag.ueba.associated_users) if rag.ueba.associated_users else "none"
    incidents_count = len(rag.similar_incidents)
    full_log_truncated = log.full_log[:500]

    return (
        f"--- ALERT ---\n"
        f"Rule: {log.rule_id} | Level: {log.rule_level}/15\n"
        f"Description: {log.rule_description}\n"
        f"Machine: {log.source_agent} ({log.source_ip})\n"
        f"MITRE: {log.mitre_technique or 'N/A'}\n"
        f"Log: {full_log_truncated}\n"
        f"\n"
        f"--- INITIAL ANALYSIS (SLM) ---\n"
        f"Category: {slm.behavior_category} | Confidence: {slm.confidence:.0%}\n"
        f"{slm.reasoning_short}\n"
        f"\n"
        f"--- TARGET ASSET ---\n"
        f"Name: {rag.asset_name} | Criticality: {rag.asset_criticality}\n"
        f"Description: {rag.asset_description}\n"
        f"Normal behavior: {rag.ueba.baseline_description}\n"
        f"Normal activity: {rag.ueba.normal_activity_window}\n"
        f"Typical users: {users}\n"
        f"Recent anomalies: {anomalies}\n"
        f"Anomaly score: {rag.ueba.anomaly_score:.2f}/1.0\n"
        f"Known similar incidents: {incidents_count}"
    )
