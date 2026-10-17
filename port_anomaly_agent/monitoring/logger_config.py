"""
Structured Logging Configuration
==================================
All logs are emitted as JSON for ingestion by SIEM tools
(Splunk, Datadog, Azure Sentinel).

Log levels:
  INFO  — normal operation events
  WARN  — anomalies detected, rate limits hit
  ERROR — pipeline failures, DB errors
  CRITICAL — audit log write failures (page on-call immediately)

PII policy:
  - customer_id NEVER appears in logs
  - customer_id_hash (16-char) is allowed
  - IP addresses are retained for security investigation (7 days)
"""

import logging
import json
from datetime import datetime, timezone


class JSONFormatter(logging.Formatter):
    """Emit every log record as a single JSON line."""

    SERVICE = "port-anomaly-detection"

    def format(self, record: logging.LogRecord) -> str:
        log_obj = {
            "timestamp":  datetime.now(timezone.utc).isoformat(),
            "level":      record.levelname,
            "service":    self.SERVICE,
            "logger":     record.name,
            "message":    record.getMessage(),
            "module":     record.module,
            "function":   record.funcName,
            "line":       record.lineno,
        }
        # Merge structured extra fields
        for key, value in record.__dict__.items():
            if key not in logging.LogRecord.__dict__ and not key.startswith("_"):
                log_obj[key] = value

        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_obj)


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(JSONFormatter())
    logging.basicConfig(level=getattr(logging, level.upper()), handlers=[handler])

    # Suppress overly verbose third-party loggers
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
    logging.getLogger("anthropic").setLevel(logging.WARNING)
