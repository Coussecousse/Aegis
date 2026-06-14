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
        f"ALERT DATA:\n"
        f"rule_id={log.rule_id} level={log.rule_level}/15\n"
        f"description={log.rule_description}\n"
        f"agent={log.source_agent} ip={log.source_ip}\n"
        f"decoder={log.decoder_name or 'unknown'} mitre={log.mitre_technique or 'N/A'}\n"
        f"raw_log={full_log_truncated}\n\n"
        f"OUTPUT: JSON triage with fields is_suspect, confidence, behavior_category,"
        f" reasoning_short, raw_probabilities."
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
    anomalies = " / ".join(rag.ueba.recent_anomalies) if rag.ueba.recent_anomalies else "none"
    users = ", ".join(rag.ueba.associated_users) if rag.ueba.associated_users else "none"
    incidents_count = len(rag.similar_incidents)
    full_log_truncated = log.full_log[:500]

    # Explicit UEBA signal helps Mistral distinguish FPs from real threats
    score = rag.ueba.anomaly_score
    if score < 0.2:
        ueba_signal = f"NORMAL BASELINE ({score:.2f}) — known pattern, likely false positive"
    elif score < 0.5:
        ueba_signal = f"SLIGHTLY ELEVATED ({score:.2f}) — minor deviation from baseline"
    else:
        ueba_signal = f"ANOMALOUS ({score:.2f}) — strong indicator of real threat"

    # The prompt must NOT end on the SLM reasoning or the asset block: Mistral 7B Q4
    # tends to continue/parrot whatever text comes last, which produced degenerate
    # single-field JSON (just a copied recommended_action example). Ending on an
    # explicit TASK that re-lists every required key, anchored on the Log line,
    # counteracts that recency bias.
    # Name the real actor explicitly: source_ip is the targeted host, attacker_ip (when
    # present) is the remote client — without this the model cites the host, not the attacker.
    if log.attacker_ip:
        actor_line = (
            f"Attacker: {log.attacker_ip} -> "
            f"Target host: {log.source_agent} ({log.source_ip})\n"
        )
    else:
        actor_line = f"Machine: {log.source_agent} ({log.source_ip})\n"

    return (
        f"--- ALERT ---\n"
        f"Rule: {log.rule_id} | Level: {log.rule_level}/15\n"
        f"Description: {log.rule_description}\n"
        f"{actor_line}"
        f"MITRE: {log.mitre_technique or 'N/A'}\n"
        f"Log: {full_log_truncated}\n"
        f"\n"
        f"--- TARGET ASSET ---\n"
        f"Name: {rag.asset_name} | Criticality: {rag.asset_criticality}\n"
        f"Description: {rag.asset_description}\n"
        f"Normal activity window: {rag.ueba.normal_activity_window}\n"
        f"Typical users: {users}\n"
        f"Recent anomalies: {anomalies}\n"
        f"UEBA: {ueba_signal}\n"
        f"Known similar incidents: {incidents_count}\n"
        f"\n"
        f"--- SLM PRE-ANALYSIS (hint only, may be wrong — do not copy) ---\n"
        f"Category: {slm.behavior_category} | Confidence: {slm.confidence:.0%}\n"
        f"{slm.reasoning_short}\n"
        f"\n"
        f"--- TASK ---\n"
        f"Analyse the Log line above. Respond with ONE JSON object containing ALL of "
        f"these keys, every value derived from THIS alert (never from the examples in "
        f"your instructions):\n"
        f"attack_confirmed, confidence, attack_type, severity, affected_asset, "
        f"asset_criticality, plain_language_summary, recommended_action, "
        f"requires_human_validation, raw_probabilities."
    )
