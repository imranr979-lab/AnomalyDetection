"""
Test Suite — Anomaly Detector Agent
=====================================
Run: pytest tests/ -v --cov=agents --cov=security --cov=models
"""

import json
import pytest
from unittest.mock import MagicMock, patch
from agents.anomaly_detector import AnomalyDetectorAgent
from security.pii_masker import PIIMasker
from models.schemas import PortingRequest, AnomalyResult


# ── Fixtures ───────────────────────────────────────────────────────────────────

HIGH_RISK_PAYLOAD = {
    "customer_id":            "CX-884412",
    "account_age_months":     5,
    "current_plan":           "Corporate Enterprise Unlimited",
    "requested_plan_or_port": "Student Discount 5G Plan",
    "historical_profile_changes": [
        {"date": "2026-04-10", "field_changed": "employer",
         "old_value": "Deloitte LLP", "new_value": "Freelance Consultant"},
        {"date": "2026-04-12", "field_changed": "occupation_category",
         "old_value": "Enterprise Professional", "new_value": "Student"},
    ],
    "associated_promotions": [
        "Student 5G Launch Promo - $0 activation + 12 months at $15/mo",
        "Port-In Bonus Credit $200",
    ],
}

LOW_RISK_PAYLOAD = {
    "customer_id":            "CX-221089",
    "account_age_months":     14,
    "current_plan":           "Postpaid Individual Unlimited",
    "requested_plan_or_port": "Small Business Shared Data Plan",
    "historical_profile_changes": [
        {"date": "2026-09-03", "field_changed": "employer",
         "old_value": "Accenture", "new_value": "Self-Employed LLC"},
    ],
    "associated_promotions": ["Small Business Q3 Bundle — Free tablet line"],
}

LLM_HIGH_RISK_RESPONSE = json.dumps({
    "is_anomaly":           True,
    "risk_score":           91,
    "primary_trigger":      "DUAL_IDENTITY_COLLAPSE_WITH_PROMOTIONAL_ALIGNMENT",
    "confidence_level":     "HIGH",
    "behavioral_analysis":  "Pattern consistent with 4-6 month deal-hopping.",
    "recommended_action":   "BLOCK_PROMOTION",
})

LLM_LOW_RISK_RESPONSE = json.dumps({
    "is_anomaly":           False,
    "risk_score":           14,
    "primary_trigger":      "NONE",
    "confidence_level":     "LOW",
    "behavioral_analysis":  "Account age outside risk window. Legitimate career change.",
    "recommended_action":   "APPROVE",
})


# ── PII Masker Tests ───────────────────────────────────────────────────────────

class TestPIIMasker:

    def setup_method(self):
        self.masker = PIIMasker()

    def test_customer_id_is_hashed(self):
        result = self.masker.mask({"customer_id": "CX-884412"})
        assert result["customer_id"] != "CX-884412"
        assert len(result["customer_id"]) == 16

    def test_payment_hash_is_dropped(self):
        result = self.masker.mask({"payment_method_hash": "abc123"})
        assert "payment_method_hash" not in result

    def test_device_imei_truncated(self):
        result = self.masker.mask({"device_imei": "490154203237518"})
        assert result["device_imei"].startswith("****")
        assert result["device_imei"].endswith("7518")

    def test_inline_email_redacted(self):
        result = self.masker.mask({"notes": "Contact user@example.com for info"})
        assert "user@example.com" not in result["notes"]
        assert "[EMAIL_REDACTED]" in result["notes"]

    def test_inline_phone_redacted(self):
        result = self.masker.mask({"notes": "Call +1 202 555 0147"})
        assert "+1 202 555 0147" not in result["notes"]

    def test_non_pii_fields_preserved(self):
        result = self.masker.mask({
            "account_age_months": 5,
            "current_plan": "Enterprise",
        })
        assert result["account_age_months"] == 5
        assert result["current_plan"] == "Enterprise"

    def test_original_not_mutated(self):
        original = {"customer_id": "CX-999", "data": "value"}
        _ = self.masker.mask(original)
        assert original["customer_id"] == "CX-999"


# ── Schema Validation Tests ────────────────────────────────────────────────────

class TestPortingRequestSchema:

    def test_valid_payload_parsed(self):
        req = PortingRequest(**HIGH_RISK_PAYLOAD)
        assert req.customer_id == "CX-884412"
        assert req.account_age_months == 5

    def test_invalid_date_raises(self):
        bad = {**HIGH_RISK_PAYLOAD}
        bad["historical_profile_changes"] = [
            {"date": "10-04-2026", "field_changed": "employer",
             "old_value": "A", "new_value": "B"}
        ]
        with pytest.raises(Exception):
            PortingRequest(**bad)

    def test_risk_score_bounds(self):
        with pytest.raises(Exception):
            AnomalyResult(
                detection_id="x", customer_id_hash="x",
                detected_at="2026-01-01T00:00:00Z",
                is_anomaly=True, risk_score=101,
                primary_trigger="X", confidence_level="HIGH",
                behavioral_analysis="X", recommended_action="APPROVE",
            )


# ── Agent Tests ────────────────────────────────────────────────────────────────

class TestAnomalyDetectorAgent:

    def setup_method(self):
        self.agent = AnomalyDetectorAgent()

    def test_temporal_signals_in_window(self):
        req     = PortingRequest(**HIGH_RISK_PAYLOAD)
        signals = self.agent.analyse_temporal(req)
        assert signals["in_risk_window"] is True
        assert signals["account_age_months"] == 5

    def test_temporal_signals_outside_window(self):
        req     = PortingRequest(**LOW_RISK_PAYLOAD)
        signals = self.agent.analyse_temporal(req)
        assert signals["in_risk_window"] is False

    @patch("agents.anomaly_detector.client")
    @patch("agents.anomaly_detector.audit")
    def test_high_risk_detection(self, mock_audit, mock_client):
        mock_msg          = MagicMock()
        mock_msg.content  = [MagicMock(text=LLM_HIGH_RISK_RESPONSE)]
        mock_client.messages.create.return_value = mock_msg

        result = self.agent.run(HIGH_RISK_PAYLOAD)

        assert result.is_anomaly is True
        assert result.risk_score == 91
        assert result.recommended_action == "BLOCK_PROMOTION"
        assert result.confidence_level == "HIGH"
        mock_audit.write.assert_called_once()

    @patch("agents.anomaly_detector.client")
    @patch("agents.anomaly_detector.audit")
    def test_low_risk_detection(self, mock_audit, mock_client):
        mock_msg          = MagicMock()
        mock_msg.content  = [MagicMock(text=LLM_LOW_RISK_RESPONSE)]
        mock_client.messages.create.return_value = mock_msg

        result = self.agent.run(LOW_RISK_PAYLOAD)

        assert result.is_anomaly is False
        assert result.risk_score == 14
        assert result.recommended_action == "APPROVE"

    @patch("agents.anomaly_detector.client")
    @patch("agents.anomaly_detector.audit")
    def test_customer_id_not_in_llm_call(self, mock_audit, mock_client):
        """PII enforcement: raw customer_id must never reach the LLM."""
        mock_msg          = MagicMock()
        mock_msg.content  = [MagicMock(text=LLM_LOW_RISK_RESPONSE)]
        mock_client.messages.create.return_value = mock_msg

        self.agent.run(HIGH_RISK_PAYLOAD)

        call_args = mock_client.messages.create.call_args
        user_msg  = call_args[1]["messages"][0]["content"]
        assert "CX-884412" not in user_msg

    def test_invalid_payload_raises(self):
        with pytest.raises(ValueError):
            self.agent.run({"customer_id": "", "account_age_months": -1})
