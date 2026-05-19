"""
Unit tests for Pydantic models.

Validates that models reject malformed JSON and enforce constraints.
"""

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from aegis.middleware.models import (
    AegisReport,
    Decision,
    LlmResponse,
    RagContext,
    RiskScore,
    SlmResponse,
    UEBAMetrics,
    WazuhLog,
)


class TestWazuhLog:
    """Test suite for WazuhLog model."""

    def test_valid_wazuh_log(self) -> None:
        """Test valid WazuhLog creation."""
        log = WazuhLog(
            id=uuid4(),
            timestamp=datetime.now(UTC),
            source_agent="WORKSTATION-01",
            source_ip="192.168.1.105",
            rule_id=1234,
            rule_level=8,
            rule_description="Possible lateral movement detected",
            full_log="net.exe user admin /add",
            mitre_technique="T1021",
            decoder_name="windows-eventlog",
        )
        assert log.source_agent == "WORKSTATION-01"
        assert log.rule_level == 8

    def test_missing_required_field(self) -> None:
        """Test that missing required fields raise ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            WazuhLog(
                id=uuid4(),
                timestamp=datetime.now(UTC),
                # Missing source_agent, source_ip, etc.
                rule_id=1234,
                rule_level=8,
                rule_description="Test",
                full_log="test",
            )
        assert "source_agent" in str(exc_info.value)

    def test_invalid_rule_level_too_high(self) -> None:
        """Test that rule_level > 15 raises ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            WazuhLog(
                id=uuid4(),
                timestamp=datetime.now(UTC),
                source_agent="WORKSTATION",
                source_ip="192.168.1.1",
                rule_id=1234,
                rule_level=16,  # Invalid: > 15
                rule_description="Test",
                full_log="test",
            )
        assert "rule_level" in str(exc_info.value)

    def test_invalid_rule_level_negative(self) -> None:
        """Test that rule_level < 0 raises ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            WazuhLog(
                id=uuid4(),
                timestamp=datetime.now(UTC),
                source_agent="WORKSTATION",
                source_ip="192.168.1.1",
                rule_id=1234,
                rule_level=-1,  # Invalid: < 0
                rule_description="Test",
                full_log="test",
            )
        assert "rule_level" in str(exc_info.value)

    def test_optional_fields_can_be_none(self) -> None:
        """Test that optional fields (mitre_technique, decoder_name) can be None."""
        log = WazuhLog(
            id=uuid4(),
            timestamp=datetime.now(UTC),
            source_agent="WORKSTATION",
            source_ip="192.168.1.1",
            rule_id=1234,
            rule_level=5,
            rule_description="Test",
            full_log="test",
            mitre_technique=None,
            decoder_name=None,
        )
        assert log.mitre_technique is None
        assert log.decoder_name is None


class TestSlmResponse:
    """Test suite for SlmResponse model."""

    def test_valid_slm_response(self) -> None:
        """Test valid SlmResponse creation."""
        response = SlmResponse(
            is_suspect=True,
            confidence=0.87,
            behavior_category="lateral_movement",
            reasoning_short="Exécution anormale de net.exe",
            raw_probabilities={"suspect": 0.87, "benign": 0.13},
        )
        assert response.is_suspect is True
        assert response.confidence == 0.87
        assert response.behavior_category == "lateral_movement"

    def test_confidence_out_of_range_high(self) -> None:
        """Test that confidence > 1.0 raises ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            SlmResponse(
                is_suspect=True,
                confidence=1.5,  # Invalid: > 1.0
                behavior_category="lateral_movement",
                reasoning_short="Test",
                raw_probabilities={"suspect": 1.5, "benign": 0.0},
            )
        assert "confidence" in str(exc_info.value)

    def test_confidence_out_of_range_low(self) -> None:
        """Test that confidence < 0.0 raises ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            SlmResponse(
                is_suspect=False,
                confidence=-0.1,  # Invalid: < 0.0
                behavior_category="normal",
                reasoning_short="Test",
                raw_probabilities={"suspect": 0.0, "benign": 1.0},
            )
        assert "confidence" in str(exc_info.value)

    def test_invalid_behavior_category(self) -> None:
        """Test that invalid behavior_category raises ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            SlmResponse(
                is_suspect=True,
                confidence=0.75,
                behavior_category="invalid_category",  # Invalid enum value
                reasoning_short="Test",
                raw_probabilities={"suspect": 0.75, "benign": 0.25},
            )
        assert "behavior_category" in str(exc_info.value)

    def test_valid_behavior_categories(self) -> None:
        """Test all valid behavior_category enum values."""
        valid_categories = [
            "lateral_movement",
            "privilege_escalation",
            "exfiltration",
            "persistence",
            "normal",
        ]
        for category in valid_categories:
            response = SlmResponse(
                is_suspect=category != "normal",
                confidence=0.75,
                behavior_category=category,
                reasoning_short="Test",
                raw_probabilities={"suspect": 0.75, "benign": 0.25},
            )
            assert response.behavior_category == category


class TestLlmResponse:
    """Test suite for LlmResponse model."""

    def test_valid_llm_response(self) -> None:
        """Test valid LlmResponse creation."""
        response = LlmResponse(
            attack_confirmed=True,
            confidence=0.91,
            attack_type="Mouvement latéral via SMB",
            severity="critical",
            affected_asset="DC-AEROTECH-01",
            asset_criticality="tier0",
            plain_language_summary="Un attaquant semble se déplacer latéralement.",
            recommended_action="Isoler immédiatement le poste source.",
            requires_human_validation=True,
            raw_probabilities={"attack": 0.91, "false_positive": 0.09},
        )
        assert response.attack_confirmed is True
        assert response.severity == "critical"

    def test_invalid_severity(self) -> None:
        """Test that invalid severity raises ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            LlmResponse(
                attack_confirmed=True,
                confidence=0.75,
                attack_type="Test",
                severity="invalid_severity",  # Invalid enum value
                affected_asset="TEST",
                asset_criticality="tier0",
                plain_language_summary="Test",
                recommended_action="Test",
                requires_human_validation=True,
                raw_probabilities={"attack": 0.75, "false_positive": 0.25},
            )
        assert "severity" in str(exc_info.value)

    def test_invalid_asset_criticality(self) -> None:
        """Test that invalid asset_criticality raises ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            LlmResponse(
                attack_confirmed=True,
                confidence=0.75,
                attack_type="Test",
                severity="high",
                affected_asset="TEST",
                asset_criticality="invalid_tier",  # Invalid enum value
                plain_language_summary="Test",
                recommended_action="Test",
                requires_human_validation=True,
                raw_probabilities={"attack": 0.75, "false_positive": 0.25},
            )
        assert "asset_criticality" in str(exc_info.value)

    def test_valid_asset_criticalities(self) -> None:
        """Test all valid asset_criticality enum values."""
        valid_tiers = ["tier0", "tier1", "tier2"]
        for tier in valid_tiers:
            response = LlmResponse(
                attack_confirmed=True,
                confidence=0.75,
                attack_type="Test",
                severity="medium",
                affected_asset="TEST",
                asset_criticality=tier,
                plain_language_summary="Test",
                recommended_action="Test",
                requires_human_validation=True,
                raw_probabilities={"attack": 0.75, "false_positive": 0.25},
            )
            assert response.asset_criticality == tier


class TestRagContext:
    """Test suite for RagContext (with UEBA)."""

    def test_valid_rag_context_with_ueba(self) -> None:
        """Test valid RagContext with complete UEBA metrics."""
        ueba = UEBAMetrics(
            baseline_description="Normal 08:00-18:00 activity",
            associated_users=["admin", "service_account"],
            normal_activity_window="08:00-18:00 weekdays",
            recent_anomalies=["Activity at 23:45"],
            anomaly_score=0.68,
        )
        rag = RagContext(
            asset_name="DC-PROD-01",
            asset_criticality="tier0",
            asset_description="Primary Domain Controller",
            similar_incidents=["uuid-1", "uuid-2"],
            ueba=ueba,
        )
        assert rag.asset_name == "DC-PROD-01"
        assert rag.ueba.anomaly_score == 0.68
        assert "admin" in rag.ueba.associated_users

    def test_rag_context_default_similar_incidents(self) -> None:
        """Test that similar_incidents defaults to empty list."""
        ueba = UEBAMetrics(
            baseline_description="Test",
            normal_activity_window="08:00-18:00",
        )
        rag = RagContext(
            asset_name="TEST",
            asset_criticality="tier2",
            asset_description="Test asset",
            ueba=ueba,
        )
        assert rag.similar_incidents == []

    def test_invalid_asset_criticality_in_rag(self) -> None:
        """Test that invalid asset_criticality in RagContext raises ValidationError."""
        ueba = UEBAMetrics(
            baseline_description="Test",
            normal_activity_window="08:00-18:00",
        )
        with pytest.raises(ValidationError) as exc_info:
            RagContext(
                asset_name="TEST",
                asset_criticality="invalid_tier",  # Invalid
                asset_description="Test",
                ueba=ueba,
            )
        assert "asset_criticality" in str(exc_info.value)


class TestRiskScore:
    """Test suite for RiskScore model."""

    def test_valid_risk_score(self) -> None:
        """Test valid RiskScore creation."""
        risk_score = RiskScore(
            danger_score=0.94,
            confidence_interval=0.06,
            uncertainty="low",
            score_breakdown={
                "slm_contribution": 0.26,
                "llm_contribution": 0.46,
                "rule_contribution": 0.13,
                "criticality_multiplier": 1.5,
            },
        )
        assert risk_score.danger_score == 0.94
        assert risk_score.uncertainty == "low"

    def test_danger_score_out_of_range(self) -> None:
        """Test that danger_score outside [0.0, 1.0] raises ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            RiskScore(
                danger_score=1.5,  # Invalid: > 1.0
                confidence_interval=0.06,
                uncertainty="low",
                score_breakdown={},
            )
        assert "danger_score" in str(exc_info.value)

    def test_invalid_uncertainty(self) -> None:
        """Test that invalid uncertainty raises ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            RiskScore(
                danger_score=0.75,
                confidence_interval=0.06,
                uncertainty="invalid",  # Invalid enum value
                score_breakdown={},
            )
        assert "uncertainty" in str(exc_info.value)


class TestDecision:
    """Test suite for Decision model."""

    def test_valid_decision(self) -> None:
        """Test valid Decision creation."""
        decision = Decision(
            severity="critical",
            requires_human_validation=True,
            auto_remediation_allowed=False,
            recommended_action="Isolate the asset.",
        )
        assert decision.severity == "critical"
        assert decision.requires_human_validation is True
        assert decision.auto_remediation_allowed is False

    def test_invalid_severity(self) -> None:
        """Test that invalid severity raises ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            Decision(
                severity="invalid_severity",  # Invalid
                requires_human_validation=True,
                auto_remediation_allowed=False,
                recommended_action="Test",
            )
        assert "severity" in str(exc_info.value)


class TestAegisReport:
    """Test suite for complete AegisReport model."""

    def test_valid_aegis_report(self) -> None:
        """Test valid AegisReport creation (complete report)."""
        alert_id = uuid4()
        now = datetime.now(UTC)

        log = WazuhLog(
            id=uuid4(),
            timestamp=now,
            source_agent="WORKSTATION",
            source_ip="192.168.1.1",
            rule_id=1234,
            rule_level=8,
            rule_description="Test alert",
            full_log="test log",
        )

        slm = SlmResponse(
            is_suspect=True,
            confidence=0.87,
            behavior_category="lateral_movement",
            reasoning_short="Test",
            raw_probabilities={"suspect": 0.87, "benign": 0.13},
        )

        llm = LlmResponse(
            attack_confirmed=True,
            confidence=0.91,
            attack_type="Test attack",
            severity="critical",
            affected_asset="TEST-ASSET",
            asset_criticality="tier0",
            plain_language_summary="Test summary",
            recommended_action="Test action",
            requires_human_validation=True,
            raw_probabilities={"attack": 0.91, "false_positive": 0.09},
        )

        ueba = UEBAMetrics(
            baseline_description="Test",
            normal_activity_window="08:00-18:00",
        )

        rag = RagContext(
            asset_name="TEST-ASSET",
            asset_criticality="tier0",
            asset_description="Test",
            ueba=ueba,
        )

        risk_score = RiskScore(
            danger_score=0.94,
            confidence_interval=0.06,
            uncertainty="low",
            score_breakdown={},
        )

        decision = Decision(
            severity="critical",
            requires_human_validation=True,
            auto_remediation_allowed=False,
            recommended_action="Isolate",
        )

        report = AegisReport(
            alert_id=alert_id,
            timestamp=now,
            source_log=log,
            slm_analysis=slm,
            llm_analysis=llm,
            rag_context=rag,
            risk_score=risk_score,
            decision=decision,
            processing_time_ms=3240,
        )

        assert report.alert_id == alert_id
        assert report.pipeline_version == "0.2.0"
        assert report.processing_time_ms == 3240

    def test_aegis_report_llm_can_be_none(self) -> None:
        """Test that AegisReport.llm_analysis can be None (timeout fallback)."""
        alert_id = uuid4()
        now = datetime.now(UTC)

        log = WazuhLog(
            id=uuid4(),
            timestamp=now,
            source_agent="WORKSTATION",
            source_ip="192.168.1.1",
            rule_id=1234,
            rule_level=8,
            rule_description="Test",
            full_log="test",
        )

        slm = SlmResponse(
            is_suspect=True,
            confidence=0.75,
            behavior_category="normal",
            reasoning_short="Test",
            raw_probabilities={"suspect": 0.75, "benign": 0.25},
        )

        ueba = UEBAMetrics(
            baseline_description="Test",
            normal_activity_window="08:00-18:00",
        )

        rag = RagContext(
            asset_name="TEST",
            asset_criticality="tier2",
            asset_description="Test",
            ueba=ueba,
        )

        risk_score = RiskScore(
            danger_score=0.5,
            confidence_interval=0.0,
            uncertainty="low",
            score_breakdown={},
        )

        decision = Decision(
            severity="medium",
            requires_human_validation=True,
            auto_remediation_allowed=False,
            recommended_action="Test",
        )

        # llm_analysis can be None
        report = AegisReport(
            alert_id=alert_id,
            timestamp=now,
            source_log=log,
            slm_analysis=slm,
            llm_analysis=None,  # LLM timed out
            rag_context=rag,
            risk_score=risk_score,
            decision=decision,
            processing_time_ms=1500,
        )

        assert report.llm_analysis is None
