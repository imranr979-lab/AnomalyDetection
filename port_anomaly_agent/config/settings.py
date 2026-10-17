"""
Centralised Settings — loaded from environment / secrets manager.
NEVER commit secrets to source control.
In production, all secret fields are injected from HashiCorp Vault
or AWS Secrets Manager via the deployment pipeline.
"""

from typing import List
from pydantic_settings import BaseSettings


class Settings(BaseSettings):

    # ── Application ──────────────────────────────────────────────────────
    app_version:        str  = "1.0.0"
    environment:        str  = "development"   # development | staging | production
    log_level:          str  = "INFO"

    # ── Anthropic ────────────────────────────────────────────────────────
    anthropic_api_key:  str  = ""
    model_name:         str  = "claude-sonnet-4-6"

    # ── Database ─────────────────────────────────────────────────────────
    database_url:       str  = "postgresql://port_anomaly_app:REPLACE@localhost/port_anomaly"
    database_url_async: str  = "postgresql+asyncpg://port_anomaly_app:REPLACE@localhost/port_anomaly"

    # ── Redis (API key store + rate limit) ───────────────────────────────
    redis_host:         str  = "localhost"
    redis_port:         int  = 6379
    redis_password:     str  = ""
    redis_ssl:          bool = True

    # ── Security ─────────────────────────────────────────────────────────
    api_key_salt:       str  = ""            # Must be set in production
    allowed_origins:    List[str] = ["*"]   # Tighten in production
    allowed_hosts:      List[str] = ["*"]   # Tighten in production

    # ── Rate Limiting ────────────────────────────────────────────────────
    rate_limit_single:  str  = "60/minute"
    rate_limit_batch:   str  = "10/minute"

    class Config:
        env_file          = ".env"
        env_file_encoding = "utf-8"
        case_sensitive    = False
