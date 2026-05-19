"""
Unit tests for risk_scorer.py.

Tests the composite danger_score formula with various cases:
- tier0/tier1/tier2 criticality multipliers
- Extreme values (0.0, 1.0)
- Uncertainty categories (low, medium, high)
- LLM fallback (None → uses SLM confidence)
"""

import pytest

from aegis.middleware.models import LlmResponse, SlmResponse
from aegis.middleware.risk_scorer import (
    _categorize_uncertainty,
    compute_risk_score,
)


class TestComputeRiskScore:
    """Test suite for compute_risk_score()."""

    def test_tier0_high_confidence(self) -> None:
        """Test tier0 (critical) with high SLM/LLM confidence."""
        slm = SlmResponse(
            is_suspect=True,
            confidence=0.90,
            behavior_category="lateral_movement",
            reasoning_short="Suspicious network activity",
            raw_probabilities={"suspect": 0.90, "benign": 0.10},
        )
        llm = LlmResponse(
            attack_confirmed=True,
            confidence=0.92,
            attack_type="Lateral movement via SMB",
            severity="critical",
            affected_asset="DC-PROD-01",
            asset_criticality="tier0",
            plain_language_summary="Attacker moving laterally.",
            recommended_action="Isolate the source workstation.",
            requires_human_validation=True,
            raw_probabilities={"attack": 0.92, "false_positive": 0.08},
        )

        risk_score = compute_risk_score(
            slm=slm,
            llm=llm,
            rule_level=14,
            asset_criticality="tier0",
        )

        # Formula: (0.90*0.30 + 0.92*0.50 + (14/15)*0.20) * 1.5
        # = (0.27 + 0.46 + 0.187) * 1.5
        # = 0.917 * 1.5 = 1.375 → clamped to 1.0
        assert risk_score.danger_score == 1.0
        assert risk_score.uncertainty == "low"  # |0.90 - 0.92| = 0.02 < 0.1
        assert risk_score.score_breakdown["criticality_multiplier"] == 1.5

    def test_tier1_medium_confidence(self) -> None:
        """Test tier1 (important) with medium SLM/LLM confidence."""
        slm = SlmResponse(
            is_suspect=True,
            confidence=0.65,
            behavior_category="privilege_escalation",
            reasoning_short="Unusual privilege request",
            raw_probabilities={"suspect": 0.65, "benign": 0.35},
        )
        llm = LlmResponse(
            attack_confirmed=True,
            confidence=0.70,
            attack_type="Privilege escalation via sudo",
            severity="high",
            affected_asset="APP-SERVER-02",
            asset_criticality="tier1",
            plain_language_summary="Non-admin user elevated privileges.",
            recommended_action="Review sudo logs and revoke access.",
            requires_human_validation=True,
            raw_probabilities={"attack": 0.70, "false_positive": 0.30},
        )

        risk_score = compute_risk_score(
            slm=slm,
            llm=llm,
            rule_level=9,
            asset_criticality="tier1",
        )

        # Formula: (0.65*0.30 + 0.70*0.50 + (9/15)*0.20) * 1.2
        # = (0.195 + 0.35 + 0.12) * 1.2
        # = 0.665 * 1.2 = 0.798 → ~0.798
        assert 0.79 <= risk_score.danger_score <= 0.81
        assert risk_score.uncertainty == "low"  # |0.65 - 0.70| = 0.05 < 0.1
        assert risk_score.score_breakdown["criticality_multiplier"] == 1.2

    def test_tier2_low_confidence(self) -> None:
        """Test tier2 (standard) with low SLM/LLM confidence."""
        slm = SlmResponse(
            is_suspect=True,
            confidence=0.45,
            behavior_category="normal",
            reasoning_short="Borderline activity",
            raw_probabilities={"suspect": 0.45, "benign": 0.55},
        )
        llm = LlmResponse(
            attack_confirmed=False,
            confidence=0.40,
            attack_type="Possibly normal admin activity",
            severity="low",
            affected_asset="WORKSTATION-05",
            asset_criticality="tier2",
            plain_language_summary="No clear threat detected.",
            recommended_action="Monitor for further activity.",
            requires_human_validation=False,
            raw_probabilities={"attack": 0.40, "false_positive": 0.60},
        )

        risk_score = compute_risk_score(
            slm=slm,
            llm=llm,
            rule_level=3,
            asset_criticality="tier2",
        )

        # Formula: (0.45*0.30 + 0.40*0.50 + (3/15)*0.20) * 1.0
        # = (0.135 + 0.20 + 0.04) * 1.0
        # = 0.375
        assert 0.37 <= risk_score.danger_score <= 0.38
        assert risk_score.uncertainty == "low"  # |0.45 - 0.40| = 0.05 < 0.1
        assert risk_score.score_breakdown["criticality_multiplier"] == 1.0

    def test_llm_fallback_none(self) -> None:
        """Test LLM fallback: if LLM is None, use SLM confidence."""
        slm = SlmResponse(
            is_suspect=True,
            confidence=0.75,
            behavior_category="exfiltration",
            reasoning_short="Large data transfer detected",
            raw_probabilities={"suspect": 0.75, "benign": 0.25},
        )
        # LLM timed out → None

        risk_score = compute_risk_score(
            slm=slm,
            llm=None,
            rule_level=12,
            asset_criticality="tier0",
        )

        # Formula: (0.75*0.30 + 0.75*0.50 + (12/15)*0.20) * 1.5
        # (uses SLM confidence for LLM contribution)
        # = (0.225 + 0.375 + 0.16) * 1.5
        # = 0.76 * 1.5 = 1.14 → clamped to 1.0
        assert risk_score.danger_score == 1.0
        assert risk_score.uncertainty == "low"  # |0.75 - 0.75| = 0.0

    def test_uncertainty_low(self) -> None:
        """Test low uncertainty: SLM and LLM agree closely."""
        slm = SlmResponse(
            is_suspect=True,
            confidence=0.80,
            behavior_category="persistence",
            reasoning_short="Registry persistence detected",
            raw_probabilities={"suspect": 0.80, "benign": 0.20},
        )
        llm = LlmResponse(
            attack_confirmed=True,
            confidence=0.82,
            attack_type="Registry persistence mechanism",
            severity="critical",
            affected_asset="DOMAIN-CONTROLLER",
            asset_criticality="tier0",
            plain_language_summary="Malware persisting via registry.",
            recommended_action="Rebuild the system.",
            requires_human_validation=True,
            raw_probabilities={"attack": 0.82, "false_positive": 0.18},
        )

        risk_score = compute_risk_score(
            slm=slm,
            llm=llm,
            rule_level=11,
            asset_criticality="tier0",
        )

        # |0.80 - 0.82| = 0.02 < 0.1 → low
        assert risk_score.uncertainty == "low"
        assert risk_score.confidence_interval == 0.02

    def test_uncertainty_medium(self) -> None:
        """Test medium uncertainty: SLM and LLM moderately disagree."""
        slm = SlmResponse(
            is_suspect=True,
            confidence=0.70,
            behavior_category="lateral_movement",
            reasoning_short="Network recon detected",
            raw_probabilities={"suspect": 0.70, "benign": 0.30},
        )
        llm = LlmResponse(
            attack_confirmed=True,
            confidence=0.55,
            attack_type="Possible network reconnaissance",
            severity="medium",
            affected_asset="APP-TIER",
            asset_criticality="tier1",
            plain_language_summary="Potential recon activity.",
            recommended_action="Increase monitoring on affected segments.",
            requires_human_validation=True,
            raw_probabilities={"attack": 0.55, "false_positive": 0.45},
        )

        risk_score = compute_risk_score(
            slm=slm,
            llm=llm,
            rule_level=7,
            asset_criticality="tier1",
        )

        # |0.70 - 0.55| = 0.15 → 0.1 <= 0.15 < 0.25 → medium
        assert risk_score.uncertainty == "medium"
        assert risk_score.confidence_interval == 0.15

    def test_uncertainty_high(self) -> None:
        """Test high uncertainty: SLM and LLM significantly disagree."""
        slm = SlmResponse(
            is_suspect=True,
            confidence=0.90,
            behavior_category="privilege_escalation",
            reasoning_short="Clear privilege escalation",
            raw_probabilities={"suspect": 0.90, "benign": 0.10},
        )
        llm = LlmResponse(
            attack_confirmed=False,
            confidence=0.35,
            attack_type="Likely false positive",
            severity="low",
            affected_asset="WORKSTATION",
            asset_criticality="tier2",
            plain_language_summary="Activity appears benign upon detailed analysis.",
            recommended_action="No action needed.",
            requires_human_validation=False,
            raw_probabilities={"attack": 0.35, "false_positive": 0.65},
        )

        risk_score = compute_risk_score(
            slm=slm,
            llm=llm,
            rule_level=5,
            asset_criticality="tier2",
        )

        # |0.90 - 0.35| = 0.55 >= 0.25 → high
        assert risk_score.uncertainty == "high"
        assert risk_score.confidence_interval == 0.55

    def test_extreme_values_zero(self) -> None:
        """Test extreme values: all confidence at 0.0."""
        slm = SlmResponse(
            is_suspect=False,
            confidence=0.0,
            behavior_category="normal",
            reasoning_short="Benign activity",
            raw_probabilities={"suspect": 0.0, "benign": 1.0},
        )
        llm = LlmResponse(
            attack_confirmed=False,
            confidence=0.0,
            attack_type="No threat",
            severity="low",
            affected_asset="WORKSTATION",
            asset_criticality="tier2",
            plain_language_summary="No threat detected.",
            recommended_action="No action needed.",
            requires_human_validation=False,
            raw_probabilities={"attack": 0.0, "false_positive": 1.0},
        )

        risk_score = compute_risk_score(
            slm=slm,
            llm=llm,
            rule_level=0,
            asset_criticality="tier2",
        )

        # (0.0*0.30 + 0.0*0.50 + 0.0*0.20) * 1.0 = 0.0
        assert risk_score.danger_score == 0.0

    def test_extreme_values_one(self) -> None:
        """Test extreme values: all confidence at 1.0."""
        slm = SlmResponse(
            is_suspect=True,
            confidence=1.0,
            behavior_category="exfiltration",
            reasoning_short="Definite threat",
            raw_probabilities={"suspect": 1.0, "benign": 0.0},
        )
        llm = LlmResponse(
            attack_confirmed=True,
            confidence=1.0,
            attack_type="Confirmed critical attack",
            severity="critical",
            affected_asset="CRITICAL-ASSET",
            asset_criticality="tier0",
            plain_language_summary="Critical threat confirmed.",
            recommended_action="Immediate isolation required.",
            requires_human_validation=True,
            raw_probabilities={"attack": 1.0, "false_positive": 0.0},
        )

        risk_score = compute_risk_score(
            slm=slm,
            llm=llm,
            rule_level=15,
            asset_criticality="tier0",
        )

        # (1.0*0.30 + 1.0*0.50 + (15/15)*0.20) * 1.5
        # = (0.30 + 0.50 + 0.20) * 1.5 = 1.0 * 1.5 = 1.5 → clamped to 1.0
        assert risk_score.danger_score == 1.0

    def test_invalid_asset_criticality(self) -> None:
        """Test that invalid asset_criticality raises ValueError."""
        slm = SlmResponse(
            is_suspect=True,
            confidence=0.75,
            behavior_category="normal",
            reasoning_short="Test",
            raw_probabilities={"suspect": 0.75, "benign": 0.25},
        )
        llm = LlmResponse(
            attack_confirmed=False,
            confidence=0.5,
            attack_type="Test",
            severity="low",
            affected_asset="TEST",
            asset_criticality="tier1",
            plain_language_summary="Test",
            recommended_action="Test",
            requires_human_validation=False,
            raw_probabilities={"attack": 0.5, "false_positive": 0.5},
        )

        with pytest.raises(ValueError, match="Unknown asset_criticality"):
            compute_risk_score(
                slm=slm,
                llm=llm,
                rule_level=5,
                asset_criticality="invalid_tier",
            )


class TestCategorizeUncertainty:
    """Test suite for _categorize_uncertainty()."""

    def test_uncertainty_low_boundary(self) -> None:
        """Test low uncertainty boundary (< 0.1)."""
        assert _categorize_uncertainty(0.0) == "low"
        assert _categorize_uncertainty(0.05) == "low"
        assert _categorize_uncertainty(0.099) == "low"

    def test_uncertainty_medium_boundary(self) -> None:
        """Test medium uncertainty boundary (0.1 - 0.25)."""
        assert _categorize_uncertainty(0.1) == "medium"
        assert _categorize_uncertainty(0.15) == "medium"
        assert _categorize_uncertainty(0.249) == "medium"

    def test_uncertainty_high_boundary(self) -> None:
        """Test high uncertainty boundary (>= 0.25)."""
        assert _categorize_uncertainty(0.25) == "high"
        assert _categorize_uncertainty(0.5) == "high"
        assert _categorize_uncertainty(1.0) == "high"
