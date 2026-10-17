"""
PII Masker — Security Layer
============================
Strips or hashes all Personally Identifiable Information fields
before any data is transmitted to the LLM API.

Fields masked:
  - customer_id         → SHA-256 hash (first 16 chars)
  - device_imei         → last 4 digits only
  - payment_method_hash → already hashed upstream, pass-through
  - linked_customer_id  → SHA-256 hash
  - employer names      → preserved (needed for career analysis)
    but email/phone patterns within values → redacted

This masker is the ONLY code path through which data reaches the LLM.
Any addition of new PII-bearing fields must be reviewed here first.
"""

import hashlib
import re
from copy import deepcopy
from typing import Any

# Regex patterns for inline PII detection within string values
_EMAIL_RE  = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
_PHONE_RE  = re.compile(r"\+?[\d\s\-\(\)]{10,15}")
_SSN_RE    = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_CC_RE     = re.compile(r"\b(?:\d[ \-]?){13,19}\b")


class PIIMasker:

    # Fields to fully replace with SHA-256 hash
    _HASH_FIELDS = {"customer_id", "linked_customer_id"}

    # Fields to truncate (show last N chars only)
    _TRUNCATE_FIELDS = {"device_imei": 4}

    # Fields to drop entirely from the payload sent to LLM
    _DROP_FIELDS = {"payment_method_hash"}

    def mask(self, payload: dict) -> dict:
        """
        Return a deep copy of payload with all PII fields masked.
        Original payload is never mutated.
        """
        masked = deepcopy(payload)
        return self._mask_recursive(masked)

    def _mask_recursive(self, obj: Any) -> Any:
        if isinstance(obj, dict):
            result = {}
            for key, value in obj.items():
                if key in self._DROP_FIELDS:
                    continue
                if key in self._HASH_FIELDS and isinstance(value, str):
                    result[key] = self._hash(value)
                elif key in self._TRUNCATE_FIELDS and isinstance(value, str):
                    n = self._TRUNCATE_FIELDS[key]
                    result[key] = f"****{value[-n:]}" if len(value) >= n else "****"
                else:
                    result[key] = self._mask_recursive(value)
            return result
        if isinstance(obj, list):
            return [self._mask_recursive(item) for item in obj]
        if isinstance(obj, str):
            return self._scrub_inline_pii(obj)
        return obj

    @staticmethod
    def _hash(value: str) -> str:
        return hashlib.sha256(value.encode()).hexdigest()[:16]

    @staticmethod
    def _scrub_inline_pii(text: str) -> str:
        text = _EMAIL_RE.sub("[EMAIL_REDACTED]", text)
        text = _PHONE_RE.sub("[PHONE_REDACTED]", text)
        text = _SSN_RE.sub("[SSN_REDACTED]", text)
        text = _CC_RE.sub("[CARD_REDACTED]", text)
        return text
