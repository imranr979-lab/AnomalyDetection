"""
Immutable Audit Logger
========================
Every detection event is written to a tamper-evident PostgreSQL table.
The audit log is append-only — no UPDATE or DELETE permissions are
granted to the application database role.

Captured per event:
  - detection_id     (UUID)
  - customer_id_hash (SHA-256, first 16 chars — no raw PII)
  - risk_score
  - is_anomaly
  - recommended_action
  - model_version    (which LLM model produced the result)
  - prompt_hash      (SHA-256 of active system prompt)
  - detected_at      (UTC timestamp)

Retention: 7 years (regulatory minimum for telecom fraud records).
"""

import logging
from datetime import datetime, timezone

from sqlalchemy import text
from db.session import get_sync_session

logger = logging.getLogger(__name__)


class AuditLogger:

    def write(
        self,
        detection_id:       str,
        customer_id_hash:   str,
        risk_score:         int,
        is_anomaly:         bool,
        recommended_action: str,
        model_version:      str,
        prompt_hash:        str,
    ) -> None:
        """
        Append a single detection event to the audit log.
        Uses a raw INSERT — no ORM update path exists for this table.
        """
        sql = text("""
            INSERT INTO audit_detection_log
                (detection_id, customer_id_hash, risk_score,
                 is_anomaly, recommended_action, model_version,
                 prompt_hash, detected_at)
            VALUES
                (:detection_id, :customer_id_hash, :risk_score,
                 :is_anomaly, :recommended_action, :model_version,
                 :prompt_hash, :detected_at)
        """)
        params = {
            "detection_id":       detection_id,
            "customer_id_hash":   customer_id_hash,
            "risk_score":         risk_score,
            "is_anomaly":         is_anomaly,
            "recommended_action": recommended_action,
            "model_version":      model_version,
            "prompt_hash":        prompt_hash,
            "detected_at":        datetime.now(timezone.utc),
        }
        try:
            with get_sync_session() as session:
                session.execute(sql, params)
                session.commit()
        except Exception as exc:
            logger.critical(
                "AUDIT LOG WRITE FAILURE — detection not recorded",
                extra={"detection_id": detection_id, "error": str(exc)},
            )
            # Re-raise so caller can decide whether to fail the request
            raise
