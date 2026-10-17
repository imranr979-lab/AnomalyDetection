# Pilot to Production Runbook & CISO Governance Guide
## Number Porting Anomaly Detection Service

---

## PART 1 — PILOT TO PRODUCTION TRANSITION

### Stage 1: Pilot Definition (Weeks 1–4)

**Scope**
- Deploy to staging environment only
- Process 5% of live porting requests in shadow mode (detect but do not block)
- Compare AI recommendations against existing rule-based system outcomes

**Acceptance Criteria to Exit Pilot**
| Metric | Target |
|---|---|
| False positive rate | < 5% of approved requests incorrectly flagged |
| False negative rate | < 10% of confirmed fraud cases missed |
| API p99 latency | < 2 seconds per request |
| Service uptime | > 99.5% over 30-day window |
| Audit log completeness | 100% — zero detection events without audit record |

**Pilot Team**
- Product Owner: signs off on business logic accuracy
- Fraud Operations Lead: validates anomaly classifications
- Security Engineer: verifies PII masking and access controls
- SRE/Platform Engineer: verifies infrastructure stability

---

### Stage 2: Limited Production (Weeks 5–8)

**Actions**
1. Enable BLOCK_PROMOTION action for risk_score ≥ 90 (Critical tier only)
2. FLAG_FOR_REVIEW results routed to Fraud Operations queue for manual review
3. APPROVE results processed automatically — no human touch
4. Daily accuracy review meeting with Fraud Operations team
5. Weekly calibration of risk score thresholds based on confirmed outcomes

**Rollback Trigger**
- If false positive rate exceeds 8% on any single day → automatic feature flag disable
- If audit log write failure rate exceeds 0.1% → page on-call SRE immediately

---

### Stage 3: Full Production (Weeks 9–12)

**Actions**
1. Enable all three recommended actions (APPROVE / FLAG / BLOCK)
2. Remove shadow mode — all porting requests processed
3. Integrate detection results into CRM for case management
4. Enable real-time Splunk/Datadog alerting dashboard
5. Establish monthly model drift review cadence

**Go/No-Go Checklist**
- [ ] All CISO governance gates closed (see Part 2)
- [ ] Penetration test completed and critical findings remediated
- [ ] Disaster recovery runbook tested (database restore, Redis failover)
- [ ] On-call rotation established with detection service runbook
- [ ] Executive sponsor sign-off on risk acceptance document
- [ ] Data Processing Agreement updated to include AI-assisted fraud detection

---

### Stage 4: Steady-State Operations (Ongoing)

**Quarterly Reviews**
- Model drift analysis: compare current detection accuracy against pilot baseline
- Prompt version review: re-evaluate system prompt against new fraud patterns
- API key rotation: rotate all service credentials on 90-day cycle
- Access review: audit all users/roles with database or Redis access
- Penetration retest: targeted assessment of any new endpoints or integrations

**Structural ROI Signals to Track**
| Signal | Measurement |
|---|---|
| Decision Velocity | Time from porting request receipt to APPROVE/BLOCK decision |
| Fraud Prevention Rate | $ value of promotions blocked from confirmed fraudsters |
| Manual Review Reduction | % reduction in cases requiring human fraud analyst time |
| False Positive Cost | $ value of legitimate requests incorrectly blocked |
| Governance Overhead Ratio | Hours spent on compliance vs. hours of fraud analyst capacity recovered |

---

## PART 2 — CISO GOVERNANCE FRAMEWORK

### 2.1 Data Classification & Handling

**Data Tiers in This System**

| Data Element | Classification | Handling Requirement |
|---|---|---|
| customer_id (raw) | PII — Restricted | Never transmitted to LLM; hashed before any external call |
| device_imei | PII — Restricted | Truncated to last 4 digits before LLM submission |
| payment_method_hash | Financial — Confidential | Dropped entirely before LLM submission |
| employer name | PII — Internal | Transmitted to LLM (required for career analysis) — masked of email/phone |
| detection_id | Internal | Used in all logs; no PII association |
| customer_id_hash | De-identified | Safe for logs and dashboards |
| risk_score, anomaly flag | Internal Analytics | Stored in detection_results table |
| Audit log entries | Compliance — Restricted | 7-year retention; append-only; encrypted at rest |

**PII Masking Architecture (CISO Verification Points)**
```
Raw Request → PIIMasker.mask() → Masked Payload → Anthropic API
                                       ↓
                              Masked payload logged
                              Raw payload NOT logged
                              Raw payload NOT stored
```
Verification: Run `grep -r "customer_id" logs/` — result should only show hashed values.

---

### 2.2 Data Residency & Sovereignty

**Requirements for CISO Sign-Off**

1. **Anthropic API Data Policy**: Confirm with Anthropic that:
   - API inputs are not used for model training (Business/Enterprise API tier)
   - Data is not retained beyond the request/response cycle
   - Obtain written confirmation and attach to Data Processing Addendum

2. **Database Region**: PostgreSQL must be deployed in the same region as the primary application infrastructure. Cross-region replication encrypted with AES-256.

3. **Audit Log Immutability**: Verify database role `port_anomaly_app` has INSERT only on `audit_detection_log`. Run:
   ```sql
   SELECT grantee, privilege_type
   FROM information_schema.role_table_grants
   WHERE table_name = 'audit_detection_log';
   -- Expected: INSERT only for port_anomaly_app
   ```

---

### 2.3 Identity & Access Management

**Principle of Least Privilege — Role Matrix**

| Role | Database Access | Redis Access | API Access | Description |
|---|---|---|---|---|
| port_anomaly_app | INSERT detection_results, INSERT audit_log | Read/Write key store | N/A | Service runtime role |
| port_anomaly_readonly | SELECT all tables | None | N/A | Ops/CISO dashboards |
| fraud_analyst | None | None | POST /detect, GET /detections | Operational users |
| sre_oncall | None | None | GET /health, GET /metrics | Monitoring only |
| ciso_auditor | SELECT audit_detection_log | None | None | Compliance read |

**API Key Lifecycle (CISO Enforced)**
1. Keys generated via `scripts/generate_api_key.py` — 256-bit random
2. Stored as PBKDF2-SHA256 hash in Redis — plaintext key shown once only
3. 90-day TTL enforced at Redis key level — automatic expiry
4. Immediate revocation via `scripts/revoke_api_key.py` on compromise
5. Key issuance requires Security Team approval (Jira ticket + manager sign-off)
6. All key issuance/revocation events logged to SIEM

**Privileged Access Management**
- Database admin access via Entra PIM / AWS IAM Identity Center (JIT, 4-hour max session)
- No standing admin access to production database
- All admin sessions logged and reviewable by CISO

---

### 2.4 Network Security Architecture

```
Internet
    │
    ▼
[WAF / DDoS Protection — Cloudflare / AWS Shield]
    │
    ▼
[Load Balancer — TLS 1.3 termination, HSTS enforced]
    │
    ▼
[API Service — Private Subnet — No direct internet egress]
    │           │
    ▼           ▼
[PostgreSQL] [Redis]    ← Internal network only, TLS encrypted
    │
    ▼
[Anthropic API] ← Outbound only, via NAT Gateway with fixed IP allowlist
```

**Network Controls Checklist for CISO**
- [ ] API service has no inbound port except 8080 (via load balancer)
- [ ] Database has no public IP — private subnet only
- [ ] Redis has no public IP — private subnet only
- [ ] Outbound traffic from API service restricted to: Anthropic API (api.anthropic.com:443), PostgreSQL (internal), Redis (internal)
- [ ] WAF rules: block requests > 1MB body; block requests with SQL injection patterns; geo-restrict if applicable
- [ ] TLS 1.2 minimum enforced; TLS 1.3 preferred; SSLv3/TLS 1.0/1.1 disabled

---

### 2.5 Encryption Standards

| Layer | Encryption Standard | Key Management |
|---|---|---|
| Data in transit (external) | TLS 1.3 | Load balancer certificate — auto-rotate via ACM/Let's Encrypt |
| Data in transit (internal) | TLS 1.2+ | Self-signed internal CA |
| Database at rest | AES-256 | Cloud KMS (AWS KMS / Azure Key Vault) |
| Redis at rest | AES-256 | Cloud KMS |
| Anthropic API key | AES-256 | HashiCorp Vault — injected at deploy time |
| API key hashes | PBKDF2-SHA256 (100k iterations) | Application-level salt in Vault |
| Audit log fields | Field-level encryption for customer_id_hash | Cloud KMS |

---

### 2.6 Secret Management Policy

**Approved Secret Storage**
- HashiCorp Vault (on-prem) or AWS Secrets Manager / Azure Key Vault (cloud)
- Secrets injected into containers at runtime via environment variables
- No secrets in: Docker images, Git repositories, CI/CD logs, Helm values files

**Secrets Inventory (CISO Register)**
| Secret | Storage Location | Rotation Frequency | Owner |
|---|---|---|---|
| ANTHROPIC_API_KEY | Vault/path:port-anomaly/anthropic | 90 days | Platform Engineering |
| DB_PASSWORD | Vault/path:port-anomaly/postgres | 90 days | DBA |
| REDIS_PASSWORD | Vault/path:port-anomaly/redis | 90 days | Platform Engineering |
| API_KEY_SALT | Vault/path:port-anomaly/salt | Annual | Security Team |
| DB_TLS_CERT | Vault/pki | Auto-rotate 30 days before expiry | Platform Engineering |

---

### 2.7 Logging, Monitoring & SIEM Integration

**Log Streams to SIEM**
1. Application access log (every API request — method, path, status, client_ip)
2. Detection event log (detection_id, risk_score, recommended_action — no PII)
3. Audit log write events (confirmation of every audit record written)
4. Authentication failures (invalid API key attempts — IP, timestamp, key hash)
5. Rate limit events (IP, endpoint, count)
6. Error log (stack traces, DB connection failures)

**SIEM Alert Rules (CISO to Configure)**
| Alert | Condition | Severity | Escalation |
|---|---|---|---|
| Audit log write failure | Any CRITICAL log event | P1 | Page on-call SRE + notify CISO |
| Authentication spike | > 100 invalid API key attempts in 5 min | P2 | Notify Security Team |
| High anomaly rate | > 30% of requests flagged as anomaly in 1 hour | P2 | Notify Fraud Operations |
| Service down | Health endpoint fails 3 consecutive checks | P1 | Page on-call SRE |
| Unusual data volume | Batch requests > 500/hour from single key | P2 | Notify Security Team |
| Model prompt hash change | prompt_hash in audit log changes without release | P1 | Page CISO immediately |

---

### 2.8 Responsible AI Governance Gate

**Pre-Deployment RAI Checklist**

| RAI Standard | Verification | Status |
|---|---|---|
| Fairness | Bias audit: verify risk scores do not correlate with protected characteristics | Required |
| Reliability & Safety | Adversarial input testing: verify agent handles malformed payloads without exception leakage | Required |
| Privacy & Security | PII masker unit tests pass 100%; no customer_id in any log file | Required |
| Transparency | System prompt version-controlled; prompt hash logged with every detection | Required |
| Accountability | Human review queue active for FLAG_FOR_REVIEW outcomes; no auto-block without human appeal path | Required |
| Explainability | behavioral_analysis field provides human-readable reasoning for every decision | Required |

**Appeal Process (Regulatory Requirement)**
- Any customer whose porting request is BLOCK_PROMOTION must be able to:
  1. Request manual human review within 30 days
  2. Receive a human decision within 5 business days
  3. Receive a plain-language explanation of the blocking reason
- This process must be documented in the customer-facing Terms of Service update

---

### 2.9 Incident Response Plan

**AI-Specific Incident Types**

| Incident Type | Response Steps |
|---|---|
| Mass false positives (legitimate customers blocked) | 1. Disable BLOCK_PROMOTION action via feature flag. 2. Notify Fraud Operations. 3. Re-process affected requests manually. 4. Root cause: prompt drift or model update? |
| PII exposure to LLM (masker bypass) | 1. Immediately disable service. 2. Notify CISO. 3. Obtain data access log from Anthropic. 4. Assess regulatory notification obligation. |
| Prompt injection attack | 1. Review detection logs for anomalous behavioral_analysis text. 2. Update input sanitisation. 3. Rotate system prompt; update prompt_hash in SIEM alert. |
| API key compromise | 1. Revoke key immediately via scripts/revoke_api_key.py. 2. Review access logs for prior unauthorised calls. 3. Issue new key to legitimate holder. |
| Audit log tampering attempt | 1. Database role should make this impossible — if attempted, page CISO. 2. Review pg_audit logs for the offending session. |

---

### 2.10 CISO Sign-Off Checklist

Before authorising production deployment, the CISO must confirm:

**Data Protection**
- [ ] Anthropic Data Processing Addendum executed (no training on API data)
- [ ] PII masking verified by independent security review
- [ ] Database encryption at rest confirmed (AES-256 via KMS)
- [ ] Audit log append-only permissions verified in PostgreSQL

**Access Control**
- [ ] All production credentials stored in approved secret manager
- [ ] Role matrix reviewed and approved (least privilege confirmed)
- [ ] API key issuance process approved and documented
- [ ] JIT admin access configured for database (Entra PIM or equivalent)

**Network Security**
- [ ] Penetration test completed (findings: Critical = 0, High = 0 before go-live)
- [ ] WAF rules active and tested
- [ ] No public IP on database or cache tier

**Monitoring & Compliance**
- [ ] SIEM integration active and alert rules configured
- [ ] 7-year audit log retention policy confirmed
- [ ] Incident response plan tested via tabletop exercise
- [ ] Customer appeal process documented and approved by Legal

**Responsible AI**
- [ ] Fairness bias audit completed
- [ ] RAI checklist signed off
- [ ] Explainability requirement verified
- [ ] Board-level AI governance charter updated to include this system

---

*Document Owner: Chief Risk Officer*
*Review Cadence: Quarterly*
*Next Review Date: January 2027*
*Classification: CONFIDENTIAL — INTERNAL USE ONLY*
