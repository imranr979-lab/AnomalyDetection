# Number Porting Anomaly Detection Service

Production-grade agentic AI system for detecting deal-hopping fraud
in telecom number porting applications.

---

## Architecture

```
Client (Fraud Ops / CRM)
        │
        │ HTTPS + X-API-Key
        ▼
[FastAPI — api/main.py]
        │
        ├── Rate Limiter (slowapi)
        ├── API Key Auth (Redis-backed)
        ├── Access Logger (JSON → SIEM)
        │
        ▼
[AnomalyDetectorAgent — agents/anomaly_detector.py]
        │
        ├── Layer 1: Data Ingestion (Pydantic validation)
        ├── Layer 2: Temporal Analysis (rule-based pre-scoring)
        ├── Layer 3: LLM Risk Scoring (claude-sonnet-4-6)
        │           └── PIIMasker strips PII before API call
        └── Layer 4: Audit + Output
                    ├── AuditLogger → PostgreSQL (append-only)
                    ├── ResultStore → PostgreSQL (queryable)
                    └── MetricsStore → PostgreSQL (aggregated)
```

---

## Quick Start

```bash
# 1. Clone and configure
git clone <repo>
cd port_anomaly_agent
cp .env.example .env
# Edit .env with your credentials from Vault

# 2. Start services
docker-compose up -d

# 3. Run database migrations
docker-compose exec api python scripts/run_migrations.py

# 4. Generate an API key
docker-compose exec api python scripts/generate_api_key.py --label "fraud-ops" --ttl-days 90

# 5. Test
curl -X POST http://localhost:8080/api/v1/detect \
  -H "X-API-Key: pak_YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d @tests/fixtures/high_risk_sample.json

# 6. Run test suite
docker-compose exec api pytest tests/ -v --cov
```

---

## API Endpoints

| Method | Path | Description |
|---|---|---|
| POST | /api/v1/detect | Single request analysis |
| POST | /api/v1/detect/batch | Batch (max 100) |
| GET | /api/v1/detections/{id} | Retrieve past result |
| GET | /api/v1/health | Liveness probe |
| GET | /api/v1/metrics | Aggregated stats |
| GET | /api/docs | Swagger UI (non-prod only) |

---

## Risk Score Reference

| Score | Level | Action |
|---|---|---|
| 0–25 | LOW | APPROVE |
| 26–55 | MODERATE | APPROVE (monitored) |
| 56–75 | ELEVATED | FLAG_FOR_REVIEW |
| 76–89 | HIGH | FLAG_FOR_REVIEW + verify |
| 90–100 | CRITICAL | BLOCK_PROMOTION |

---

## Security Controls

- **PII masking**: customer_id hashed; IMEI truncated; payment hash dropped before LLM
- **Audit log**: append-only PostgreSQL table; 7-year retention
- **API keys**: PBKDF2-SHA256 hashed; 90-day TTL; Redis-backed
- **TLS**: enforced on all connections (internal and external)
- **No raw PII in logs**: customer_id_hash only in all log outputs
- **Fail-closed**: API key validation fails closed if Redis unavailable

---

## File Structure

```
port_anomaly_agent/
├── api/
│   └── main.py              FastAPI application
├── agents/
│   └── anomaly_detector.py  Four-layer detection agent
├── models/
│   └── schemas.py           Pydantic data models
├── security/
│   ├── pii_masker.py        PII stripping before LLM
│   └── api_key_manager.py   Redis-backed key validation
├── db/
│   ├── audit_log.py         Immutable audit writer
│   ├── session.py           DB session factory
│   └── migrations/          SQL schema migrations
├── monitoring/
│   └── logger_config.py     Structured JSON logging
├── config/
│   └── settings.py          Pydantic settings
├── tests/
│   └── test_anomaly_detector.py
├── scripts/
│   └── generate_api_key.py
├── docs/
│   └── PILOT_TO_PRODUCTION_GOVERNANCE.md
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

---

## Governance

See `docs/PILOT_TO_PRODUCTION_GOVERNANCE.md` for:
- Pilot-to-production transition stages with acceptance criteria
- CISO governance gates and sign-off checklist
- Data classification and handling policy
- Secret management and key rotation schedule
- SIEM alert rules and incident response plan
- Responsible AI governance checklist
