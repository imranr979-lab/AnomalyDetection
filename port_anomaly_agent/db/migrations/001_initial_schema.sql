-- ============================================================
-- Migration 001 — Initial Schema
-- Number Porting Anomaly Detection Service
-- ============================================================
-- SECURITY NOTES:
--   • audit_detection_log has NO UPDATE/DELETE permissions
--     granted to the application role (append-only).
--   • All VARCHAR fields sized to prevent injection via
--     oversized input.
--   • Indexes on detection_id and customer_id_hash only —
--     never on raw PII columns.
-- ============================================================

-- Detection results table (queryable by ops team)
CREATE TABLE IF NOT EXISTS detection_results (
    detection_id        VARCHAR(36)     PRIMARY KEY,
    customer_id_hash    VARCHAR(16)     NOT NULL,
    detected_at         TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    is_anomaly          BOOLEAN         NOT NULL,
    risk_score          SMALLINT        NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
    primary_trigger     VARCHAR(120)    NOT NULL,
    confidence_level    VARCHAR(10)     NOT NULL,
    behavioral_analysis TEXT            NOT NULL,
    recommended_action  VARCHAR(30)     NOT NULL,
    batch_id            VARCHAR(36)     NULL
);

CREATE INDEX idx_results_customer ON detection_results(customer_id_hash);
CREATE INDEX idx_results_detected_at ON detection_results(detected_at);
CREATE INDEX idx_results_anomaly ON detection_results(is_anomaly) WHERE is_anomaly = TRUE;


-- Immutable audit log (application role: INSERT only)
CREATE TABLE IF NOT EXISTS audit_detection_log (
    log_id              BIGSERIAL       PRIMARY KEY,
    detection_id        VARCHAR(36)     NOT NULL,
    customer_id_hash    VARCHAR(16)     NOT NULL,
    risk_score          SMALLINT        NOT NULL,
    is_anomaly          BOOLEAN         NOT NULL,
    recommended_action  VARCHAR(30)     NOT NULL,
    model_version       VARCHAR(60)     NOT NULL,
    prompt_hash         VARCHAR(64)     NOT NULL,
    detected_at         TIMESTAMPTZ     NOT NULL
);

CREATE INDEX idx_audit_detection_id ON audit_detection_log(detection_id);
CREATE INDEX idx_audit_detected_at  ON audit_detection_log(detected_at);


-- Metrics aggregation table (updated by background task)
CREATE TABLE IF NOT EXISTS detection_metrics (
    metric_date         DATE            PRIMARY KEY,
    total_requests      INTEGER         NOT NULL DEFAULT 0,
    total_anomalies     INTEGER         NOT NULL DEFAULT 0,
    total_blocked       INTEGER         NOT NULL DEFAULT 0,
    avg_risk_score      NUMERIC(5,2)    NOT NULL DEFAULT 0,
    updated_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);


-- ── Role and permission setup ──────────────────────────────────────────────

-- Application service role (least privilege)
CREATE ROLE port_anomaly_app LOGIN PASSWORD 'REPLACE_IN_VAULT';

-- detection_results: full CRUD for app
GRANT SELECT, INSERT, UPDATE ON detection_results TO port_anomaly_app;
GRANT USAGE, SELECT ON SEQUENCE detection_results_detection_id_seq TO port_anomaly_app;

-- audit_detection_log: INSERT ONLY — never UPDATE or DELETE
GRANT INSERT ON audit_detection_log TO port_anomaly_app;
-- Explicitly deny UPDATE and DELETE
REVOKE UPDATE, DELETE ON audit_detection_log FROM port_anomaly_app;

-- detection_metrics: full CRUD
GRANT SELECT, INSERT, UPDATE ON detection_metrics TO port_anomaly_app;

-- Read-only reporting role (for CISO/ops dashboards)
CREATE ROLE port_anomaly_readonly LOGIN PASSWORD 'REPLACE_IN_VAULT';
GRANT SELECT ON detection_results, audit_detection_log, detection_metrics
    TO port_anomaly_readonly;
