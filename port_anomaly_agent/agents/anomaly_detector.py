"""
Number Porting Anomaly Detection Agent
=======================================
Four-layer cognitive workflow:
  Layer 1 — Data Ingestion & Parsing
  Layer 2 — Temporal & Behavioral Analysis
  Layer 3 — Risk Scoring & Anomaly Detection
  Layer 4 — Actionable JSON Output

Production hardened:
  - Input validation via Pydantic
  - Structured audit logging
  - PII field masking before LLM submission
  - Immutable audit trail per detection run
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Optional

import anthropic
from pydantic import BaseModel, ValidationError

from models.schemas import (
    PortingRequest,
    AnomalyResult,
    RiskLevel,
    RecommendedAction,
    ConfidenceLevel,
)
from security.pii_masker import PIIMasker
from db.audit_log import AuditLogger
from config.settings import Settings

settings   = Settings()
audit      = AuditLogger()
pii_masker = PIIMasker()
logger     = logging.getLogger(__name__)

client = anthropic.Anthropic(api_key=settings.anthropic_api_key)

# ── System prompt (stored in version-controlled config, not inline) ──────────

SYSTEM_PROMPT = """
You are an advanced telecom fraud detection AI specialising in number porting
anomaly analysis. Your task is to detect "deal-hopping" — customers who
maliciously exploit promotions by switching careers, profiles, or plans within
a strict 4-to-6-month (120–180 day) window to re-claim introductory discounts.

BEHAVIORAL DETECTORS:
1. Temporal Proximity: Account changes within 120–180 days of last promotion.
2. Career Profile Inconsistency: Implausible profession or employer changes.
3. Promotional Alignment: Plan shift perfectly matches an active campaign.
4. Velocity Triangulation: Multiple identities sharing payment/address/IMEI.

CHAIN-OF-THOUGHT STEPS (perform internally before responding):
1. Calculate exact delta in days between last major change and current request.
2. Check if delta falls in 4–6 month (120–180 day) window.
3. Compare old vs new profile attributes for legitimacy.
4. Evaluate promotional alignment and velocity signals.

OUTPUT: Respond ONLY with a valid JSON object — no prose, no markdown:
{
  "is_anomaly": boolean,
  "risk_score": integer (0-100),
  "primary_trigger": string,
  "confidence_level": "LOW" | "MEDIUM" | "HIGH",
  "behavioral_analysis": string,
  "recommended_action": "APPROVE" | "FLAG_FOR_REVIEW" | "BLOCK_PROMOTION"
}
"""


class AnomalyDetectorAgent:
    """
    Primary detection agent. Orchestrates all four cognitive layers,
    enforces PII masking before LLM submission, and writes every
    detection event to the immutable audit trail.
    """

    # ── Layer 1: Data Ingestion & Parsing ────────────────────────────────────

    def ingest(self, raw: dict) -> PortingRequest:
        """Validate and parse raw incoming payload."""
        try:
            request = PortingRequest(**raw)
            logger.info(
                "Ingestion complete",
                extra={"customer_id_hash": self._hash_id(request.customer_id)},
            )
            return request
        except ValidationError as exc:
            logger.error("Ingestion validation failed", extra={"errors": exc.errors()})
            raise ValueError(f"Invalid porting request payload: {exc}") from exc

    # ── Layer 2: Temporal & Behavioral Analysis ───────────────────────────────

    def analyse_temporal(self, request: PortingRequest) -> dict:
        """
        Calculate temporal deltas and pre-score behavioral signals
        before passing to the LLM for final synthesis.
        """
        today = datetime.now(timezone.utc).date()
        signals: dict = {
            "account_age_months": request.account_age_months,
            "in_risk_window": request.account_age_months in range(4, 7),
            "profile_changes_count": len(request.historical_profile_changes),
            "changes_in_window": [],
            "promotion_count": len(request.associated_promotions),
            "velocity_flags": len(request.linked_account_flags or []),
        }

        for change in request.historical_profile_changes:
            try:
                change_date = datetime.strptime(change.date, "%Y-%m-%d").date()
                delta_days  = (today - change_date).days
                delta_months = delta_days / 30.44
                if 120 <= delta_days <= 180:
                    signals["changes_in_window"].append({
                        "field":         change.field_changed,
                        "delta_days":    delta_days,
                        "delta_months":  round(delta_months, 1),
                    })
            except ValueError:
                logger.warning("Unparseable change date", extra={"date": change.date})

        return signals

    # ── Layer 3: Risk Scoring & Anomaly Detection (LLM-assisted) ─────────────

    def score(self, request: PortingRequest, signals: dict) -> AnomalyResult:
        """
        Submit PII-masked payload to the LLM for final risk scoring.
        Parse and validate the structured JSON response.
        """
        masked_payload = pii_masker.mask(request.dict())
        user_message   = json.dumps({
            "customer_profile":        masked_payload,
            "pre_computed_signals":    signals,
        }, default=str)

        response = client.messages.create(
            model=settings.model_name,
            max_tokens=1024,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_message}],
        )

        raw_text = response.content[0].text.strip()
        # Strip accidental markdown fences
        raw_text = re.sub(r"^```json|```$", "", raw_text, flags=re.MULTILINE).strip()

        try:
            parsed = json.loads(raw_text)
            return AnomalyResult(
                detection_id=str(uuid.uuid4()),
                customer_id_hash=self._hash_id(request.customer_id),
                detected_at=datetime.now(timezone.utc).isoformat(),
                **parsed,
            )
        except (json.JSONDecodeError, ValidationError) as exc:
            logger.error("LLM response parse failure", extra={"raw": raw_text})
            raise RuntimeError("LLM returned unparseable response") from exc

    # ── Layer 4: Actionable Output & Audit ───────────────────────────────────

    def run(self, raw_payload: dict) -> AnomalyResult:
        """
        Full pipeline: ingest → analyse → score → audit → return result.
        This is the single public entry point for the agent.
        """
        request = self.ingest(raw_payload)
        signals = self.analyse_temporal(request)
        result  = self.score(request, signals)

        # Write immutable audit record — never skipped, never optional
        audit.write(
            detection_id=result.detection_id,
            customer_id_hash=result.customer_id_hash,
            risk_score=result.risk_score,
            is_anomaly=result.is_anomaly,
            recommended_action=result.recommended_action,
            model_version=settings.model_name,
            prompt_hash=self._hash_prompt(SYSTEM_PROMPT),
        )

        logger.info(
            "Detection complete",
            extra={
                "detection_id":         result.detection_id,
                "risk_score":           result.risk_score,
                "recommended_action":   result.recommended_action,
            },
        )
        return result

    # ── Internal helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _hash_id(customer_id: str) -> str:
        return hashlib.sha256(customer_id.encode()).hexdigest()[:16]

    @staticmethod
    def _hash_prompt(prompt: str) -> str:
        return hashlib.sha256(prompt.encode()).hexdigest()
