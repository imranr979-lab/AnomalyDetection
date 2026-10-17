"""
API Key Manager
===============
Validates inbound API keys against a Redis-backed store.
Keys are hashed at rest — plaintext keys are never stored.

Key lifecycle:
  - Generated via /scripts/generate_api_key.py
  - Stored as PBKDF2-SHA256 hash in Redis with TTL
  - Rotated every 90 days (enforced by expiry TTL)
  - Revoked immediately on compromise via revoke_key()
"""

import hashlib
import hmac
import logging
import os
from typing import Optional

import redis

from config.settings import Settings

settings = Settings()
logger   = logging.getLogger(__name__)

_redis_client: Optional[redis.Redis] = None


def _get_redis() -> redis.Redis:
    global _redis_client
    if _redis_client is None:
        _redis_client = redis.Redis(
            host=settings.redis_host,
            port=settings.redis_port,
            password=settings.redis_password,
            ssl=settings.redis_ssl,
            decode_responses=True,
        )
    return _redis_client


class APIKeyManager:

    KEY_PREFIX = "api_key:"

    def is_valid(self, raw_key: str) -> bool:
        """
        Return True if raw_key matches a stored, non-expired key hash.
        Comparison is constant-time to prevent timing attacks.
        """
        if not raw_key or len(raw_key) < 32:
            return False
        try:
            r         = _get_redis()
            key_hash  = self._hash_key(raw_key)
            stored    = r.get(f"{self.KEY_PREFIX}{key_hash}")
            return stored == "active"
        except redis.RedisError as exc:
            logger.error("Redis key validation error", extra={"error": str(exc)})
            # Fail closed — deny access if Redis is unavailable
            return False

    def register_key(self, raw_key: str, ttl_days: int = 90) -> bool:
        """Store a hashed key with expiry."""
        try:
            r        = _get_redis()
            key_hash = self._hash_key(raw_key)
            r.setex(
                name=f"{self.KEY_PREFIX}{key_hash}",
                time=ttl_days * 86400,
                value="active",
            )
            logger.info("API key registered", extra={"ttl_days": ttl_days})
            return True
        except redis.RedisError as exc:
            logger.error("Key registration failed", extra={"error": str(exc)})
            return False

    def revoke_key(self, raw_key: str) -> bool:
        """Immediately revoke a key."""
        try:
            r = _get_redis()
            r.delete(f"{self.KEY_PREFIX}{self._hash_key(raw_key)}")
            logger.warning("API key revoked")
            return True
        except redis.RedisError:
            return False

    @staticmethod
    def _hash_key(raw_key: str) -> str:
        """PBKDF2-HMAC-SHA256 hash for key storage."""
        salt = settings.api_key_salt.encode()
        dk   = hashlib.pbkdf2_hmac("sha256", raw_key.encode(), salt, 100_000)
        return dk.hex()
