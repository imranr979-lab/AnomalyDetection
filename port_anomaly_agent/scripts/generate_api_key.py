"""
API Key Generator
==================
Generates a cryptographically secure 256-bit API key,
registers the hash in Redis, and prints the plaintext key
ONCE to stdout. Plaintext key is never stored.

Usage:
  python scripts/generate_api_key.py --ttl-days 90 --label "fraud-ops-team"

Security:
  - Requires REDIS_* and API_KEY_SALT env vars (from Vault)
  - Requires Security Team approval before running in production
  - All key generation events logged to SIEM via structured output
"""

import argparse
import os
import secrets
import sys
import json
from datetime import datetime, timezone

# Ensure project root is in path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from security.api_key_manager import APIKeyManager


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a new API key")
    parser.add_argument("--ttl-days", type=int, default=90, help="Key TTL in days")
    parser.add_argument("--label",    type=str, required=True, help="Key label (team/service name)")
    args = parser.parse_args()

    manager = APIKeyManager()
    raw_key = f"pak_{secrets.token_hex(32)}"    # 256-bit prefix-tagged key

    success = manager.register_key(raw_key, ttl_days=args.ttl_days)
    if not success:
        print(json.dumps({"status": "error", "message": "Key registration failed"}))
        sys.exit(1)

    # Emit to stdout in structured JSON — capture in CI/CD secret manager
    print(json.dumps({
        "status":       "success",
        "label":        args.label,
        "api_key":      raw_key,          # ← Show ONCE, then gone
        "ttl_days":     args.ttl_days,
        "expires_at":   (datetime.now(timezone.utc).timestamp() + args.ttl_days * 86400),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "note":         "Store this key immediately. It will not be shown again.",
    }, indent=2))


if __name__ == "__main__":
    main()
