"""
Pydantic data models — typed, validated at runtime.
All fields documented for OpenAPI schema generation.
"""

from __future__ import annotations
from datetime import datetime
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field, validator


# ── Enumerations ──────────────────────────────────────────────────────────────

class RiskLevel(str, Enum):
    LOW      = "LOW"
    MODERATE = "MODERATE"
    ELEVATED = "ELEVATED"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


class ConfidenceLevel(str, Enum):
    LOW    = "LOW"
    MEDIUM = "MEDIUM"
    HIGH   = "HIGH"


class RecommendedAction(str, Enum):
    APPROVE          = "APPROVE"
    FLAG_FOR_REVIEW  = "FLAG_FOR_REVIEW"
    BLOCK_PROMOTION  = "BLOCK_PROMOTION"


class LinkageType(str, Enum):
    SHARED_IMEI    = "SHARED_IMEI"
    SHARED_PAYMENT = "SHARED_PAYMENT"
    SHARED_ADDRESS = "SHARED_ADDRESS"


# ── Request models ─────────────────────────────────────────────────────────────

class ProfileChange(BaseModel):
    date:          str   = Field(..., description="YYYY-MM-DD format")
    field_changed: str
    old_value:     str
    new_value:     str

    @validator("date")
    def validate_date_format(cls, v: str) -> str:
        try:
            datetime.strptime(v, "%Y-%m-%d")
        except ValueError:
            raise ValueError(f"date must be YYYY-MM-DD, got: {v}")
        return v


class LinkedAccountFlag(BaseModel):
    linked_customer_id:   str
    linkage_type:         LinkageType
    days_between_requests: int


class PortingRequest(BaseModel):
    customer_id:               str   = Field(..., min_length=1)
    account_age_months:        int   = Field(..., ge=0, le=600)
    current_plan:              str
    requested_plan_or_port:    str
    historical_profile_changes: List[ProfileChange] = Field(default_factory=list)
    associated_promotions:     List[str]            = Field(default_factory=list)

    # Extended velocity fields (optional)
    device_imei:               Optional[str]                   = None
    payment_method_hash:       Optional[str]                   = None
    linked_account_flags:      Optional[List[LinkedAccountFlag]] = None


# ── Response models ────────────────────────────────────────────────────────────

class AnomalyResult(BaseModel):
    detection_id:       str
    customer_id_hash:   str
    detected_at:        str
    is_anomaly:         bool
    risk_score:         int   = Field(..., ge=0, le=100)
    primary_trigger:    str
    confidence_level:   ConfidenceLevel
    behavioral_analysis: str
    recommended_action: RecommendedAction

    @property
    def risk_level(self) -> RiskLevel:
        if self.risk_score <= 25:
            return RiskLevel.LOW
        if self.risk_score <= 55:
            return RiskLevel.MODERATE
        if self.risk_score <= 75:
            return RiskLevel.ELEVATED
        if self.risk_score <= 89:
            return RiskLevel.HIGH
        return RiskLevel.CRITICAL


class BatchResult(BaseModel):
    batch_id:           str
    processed_at:       str
    total_submitted:    int
    total_anomalies:    int
    total_blocked:      int
    results:            List[AnomalyResult]


class HealthResponse(BaseModel):
    status:         str
    version:        str
    model:          str
    timestamp:      str
