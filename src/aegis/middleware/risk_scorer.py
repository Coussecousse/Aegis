"""
Risk score computation for AEGIS pipeline.

Calculates composite danger_score from:
1. SLM confidence (30% weight) - quick suspicion
2. LLM confidence (50% weight) - detailed analysis
3. Rule level (20% weight) - Wazuh severity baseline
4. Asset criticality multiplier (tier0=1.5, tier1=1.2, tier2=1.0)

Also computes uncertainty (confidence interval between SLM and LLM consensus).
"""

import logging
from typing import Literal

from aegis.middleware.models import LlmResponse, RiskScore, SlmResponse

logger = logging.getLogger(__name__)

# Asset criticality multipliers (human-in-the-loop decision gate)
CRITICALITY_MULTIPLIERS: dict[str, float] = {
    "tier0": 1.5,  # Critical infrastructure: highest urgency
    "tier1": 1.2,  # Important systems: high urgency
    "tier2": 1.0,  # Standard systems: normal urgency
}

# Uncertainty categories based on confidence interval (|SLM - LLM|)
UNCERTAINTY_THRESHOLDS = {
    "low": 0.1,  # < 0.1: SLM and LLM agree closely
    "medium": 0.25,  # 0.1 - 0.25: some disagreement
    "high": float("inf"),  # >= 0.25: significant disagreement
}


def compute_risk_score(
    slm: SlmResponse,
    llm: LlmResponse | None,
    rule_level: int,
    asset_criticality: str,
    ueba_anomaly_score: float = 0.5,
) -> RiskScore:
    """
    Compute composite danger score and uncertainty metrics.

    Applies weighted formula:
    danger_score = clamp(
        (slm.confidence * 0.30 +
         llm.confidence * 0.50 +
         (rule_level / 15) * 0.20) *
        criticality_multiplier,
        0.0, 1.0
    )

    uncertainty = |slm.confidence - llm.confidence|

    Args:
        slm: SLM response with suspicion score.
        llm: LLM response with detailed analysis (can be None if timeout).
        rule_level: Wazuh rule severity (0-15).
        asset_criticality: Asset tier (tier0|tier1|tier2).

    Returns:
        RiskScore: Composite score with breakdown and uncertainty.

    Raises:
        ValueError: If asset_criticality is not recognized.
    """
    logger.debug(
        f"Computing risk score: SLM={slm.confidence:.2f}, "
        f"LLM={'N/A' if llm is None else f'{llm.confidence:.2f}'}, "
        f"rule_level={rule_level}, tier={asset_criticality}"
    )

    # Validate asset criticality
    if asset_criticality not in CRITICALITY_MULTIPLIERS:
        raise ValueError(
            f"Unknown asset_criticality: {asset_criticality}. "
            f"Must be one of {list(CRITICALITY_MULTIPLIERS.keys())}"
        )

    # If LLM failed (timeout), use SLM confidence as fallback
    llm_confidence = llm.confidence if llm is not None else slm.confidence
    logger.warning(
        f"LLM response is None. Using SLM confidence ({slm.confidence:.2f}) "
        f"as fallback for LLM contribution."
    ) if llm is None else None

    # Normalize rule_level (0-15) to 0.0-1.0
    rule_component = rule_level / 15.0

    # Weighted composite score (before criticality and UEBA modifiers)
    base_score = (slm.confidence * 0.30) + (llm_confidence * 0.50) + (rule_component * 0.20)

    # UEBA factor: normal behaviour (score=0) reduces danger by up to 30%;
    # highly anomalous behaviour (score=1) leaves the score unchanged.
    ueba_factor = 0.70 + (min(1.0, max(0.0, ueba_anomaly_score)) * 0.30)

    # Apply criticality multiplier and UEBA factor, then clamp to [0.0, 1.0]
    criticality_mult = CRITICALITY_MULTIPLIERS[asset_criticality]
    danger_score = min(1.0, max(0.0, base_score * criticality_mult * ueba_factor))

    # Compute uncertainty: confidence interval between SLM and LLM
    confidence_interval = abs(slm.confidence - llm_confidence)
    uncertainty = _categorize_uncertainty(confidence_interval)

    # Breakdown for transparency
    score_breakdown = {
        "slm_contribution": round(slm.confidence * 0.30, 3),
        "llm_contribution": round(llm_confidence * 0.50, 3),
        "rule_contribution": round(rule_component * 0.20, 3),
        "criticality_multiplier": criticality_mult,
        "ueba_factor": round(ueba_factor, 3),
    }

    logger.info(
        f"Risk score computed: danger_score={danger_score:.2f}, "
        f"uncertainty={uncertainty} ({confidence_interval:.3f}), "
        f"criticality_multiplier={criticality_mult}"
    )

    return RiskScore(
        danger_score=round(danger_score, 3),
        confidence_interval=round(confidence_interval, 3),
        uncertainty=uncertainty,
        score_breakdown=score_breakdown,
    )


def _categorize_uncertainty(
    confidence_interval: float,
) -> Literal["low", "medium", "high"]:
    """
    Categorize uncertainty level based on confidence interval.

    Args:
        confidence_interval: Absolute difference between SLM and LLM confidence.

    Returns:
        Literal: "low" (<0.1) | "medium" (<0.25) | "high" (>=0.25)
    """
    if confidence_interval < UNCERTAINTY_THRESHOLDS["low"]:
        return "low"
    elif confidence_interval < UNCERTAINTY_THRESHOLDS["medium"]:
        return "medium"
    else:
        return "high"
