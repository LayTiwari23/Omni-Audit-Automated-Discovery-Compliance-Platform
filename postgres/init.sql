-- =============================================================================
--  Web Security Compliance Platform — Consolidated Database Initialisation
--  Target: PostgreSQL 15+
--  Includes all tables: Users, Scans, Groups, Discovery, Logs, Admin
-- =============================================================================

-- ── 1. Users ─────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id            SERIAL                      PRIMARY KEY,
    email         CHARACTER VARYING(255)      NOT NULL UNIQUE,
    username      CHARACTER VARYING(255)      UNIQUE,
    full_name     CHARACTER VARYING(255),
    password_hash CHARACTER VARYING(255)      NOT NULL,
    is_admin      BOOLEAN                     NOT NULL DEFAULT FALSE,
    all_access    BOOLEAN                     NOT NULL DEFAULT FALSE,
    allowed_targets TEXT,
    last_login    TIMESTAMP WITHOUT TIME ZONE,
    created_at    TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_users_email ON users (email);
CREATE INDEX IF NOT EXISTS ix_users_username ON users (username);

-- ── 2. Scan Groups (Campaigns) ───────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scan_groups (
    id            SERIAL                      PRIMARY KEY,
    name          CHARACTER VARYING(255)      NOT NULL,
    user_id       INTEGER                     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    description   TEXT,
    created_at    TIMESTAMP WITH TIME ZONE    DEFAULT CURRENT_TIMESTAMP,
    updated_at    TIMESTAMP WITH TIME ZONE    DEFAULT CURRENT_TIMESTAMP
);

-- ── 3. Scans ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scans (
    id                 SERIAL                      PRIMARY KEY,
    user_id            INTEGER                     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id           INTEGER                     REFERENCES scan_groups(id) ON DELETE SET NULL,
    domain             CHARACTER VARYING(255)      NOT NULL,
    scan_type          CHARACTER VARYING(100)      DEFAULT 'web',
    status             CHARACTER VARYING(50)       NOT NULL DEFAULT 'PENDING',
    progress_percent   DOUBLE PRECISION            DEFAULT 0.0,
    compliance_percent DOUBLE PRECISION,
    error_message      TEXT,
    scan_metadata      JSONB,
    created_at         TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at         TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_scans_domain  ON scans (domain);
CREATE INDEX IF NOT EXISTS ix_scans_user_id ON scans (user_id);
CREATE INDEX IF NOT EXISTS ix_scans_group_id ON scans (group_id);

-- ── 4. Scan Summary Results ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scan_results (
    id             SERIAL                      PRIMARY KEY,
    scan_id        INTEGER                     NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    compliance_id  INTEGER,
    status         CHARACTER VARYING(1),       -- 'Y' or 'N'
    remarks        TEXT,
    total_checks   INTEGER,
    passed_checks  INTEGER,
    failed_checks  INTEGER,
    created_at     TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ── 5. Detailed (Raw) Scan Results ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scan_raw_results (
    id                    SERIAL                   PRIMARY KEY,
    scan_id               INTEGER                  NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    check_id              CHARACTER VARYING(100)   NOT NULL,
    check_name            CHARACTER VARYING(255)   NOT NULL,
    tool_name             CHARACTER VARYING(50)    NOT NULL,
    command_executed      TEXT                     NOT NULL,
    raw_output            TEXT,
    decision_logic        TEXT                     NOT NULL,
    result                CHARACTER VARYING(20)    NOT NULL,
    cvss_score            DOUBLE PRECISION         DEFAULT 0.0,
    severity              CHARACTER VARYING(20),
    cve_id                CHARACTER VARYING(50),
    remediation_text      TEXT,
    remediation_example   TEXT,
    remediation_reference TEXT,
    execution_start       TIMESTAMP,
    execution_end         TIMESTAMP,
    execution_duration    DOUBLE PRECISION,
    created_at            TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_scan_raw_results_scan_id  ON scan_raw_results (scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_raw_results_severity ON scan_raw_results(severity);

-- ── 6. Discovery Jobs & Results ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS discovery_jobs (
    id                SERIAL                   PRIMARY KEY,
    user_id           INTEGER                  NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id          INTEGER                  REFERENCES scan_groups(id) ON DELETE SET NULL,
    schedule_id       INTEGER,                 -- FK added via ALTER below
    input_type        CHARACTER VARYING(20),   -- 'list', 'range', 'file'
    raw_input         TEXT,
    status            CHARACTER VARYING(20)    DEFAULT 'pending',
    total_targets     INTEGER                  DEFAULT 0,
    processed_targets INTEGER                  DEFAULT 0,
    created_at        TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at        TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS discovery_results (
    id             SERIAL                      PRIMARY KEY,
    job_id         INTEGER                     NOT NULL REFERENCES discovery_jobs(id) ON DELETE CASCADE,
    target_ip      CHARACTER VARYING(45),
    target_domain  CHARACTER VARYING(255),
    port           INTEGER,
    state          CHARACTER VARYING(20)       DEFAULT 'open',
    service        CHARACTER VARYING(50),
    engine         CHARACTER VARYING(20),
    version_info   CHARACTER VARYING(255),
    error          CHARACTER VARYING(255),
    created_at     TIMESTAMP WITH TIME ZONE    DEFAULT CURRENT_TIMESTAMP
);

-- ── 7. Scan Schedules ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scan_schedules (
    id               SERIAL                   PRIMARY KEY,
    user_id          INTEGER                  NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    discovery_job_id INTEGER                  REFERENCES discovery_jobs(id) ON DELETE SET NULL,
    name             CHARACTER VARYING(255)   NOT NULL,
    description      TEXT,
    target           TEXT                     NOT NULL,
    scan_type        CHARACTER VARYING(100)   NOT NULL,
    scan_mode        CHARACTER VARYING(50)    NOT NULL DEFAULT 'command_only',
    cron_expression  CHARACTER VARYING(100)   NOT NULL,
    enabled          BOOLEAN                  DEFAULT TRUE,
    next_run         TIMESTAMP WITH TIME ZONE,
    selections       JSONB,
    created_at       TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at       TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Now add the circular FK to discovery_jobs
ALTER TABLE discovery_jobs 
ADD CONSTRAINT fk_discovery_schedule FOREIGN KEY (schedule_id) REFERENCES scan_schedules(id) ON DELETE CASCADE;

-- ── 8. Real-time Scan Logs ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scan_logs (
    id         SERIAL                      PRIMARY KEY,
    scan_id    INTEGER                     NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    stage      CHARACTER VARYING(50)       NOT NULL,
    message    TEXT                        NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE    DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scan_edit_history (
    id             SERIAL                      PRIMARY KEY,
    scan_id        INTEGER                     NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    check_id       CHARACTER VARYING(100)      NOT NULL,
    field_name     CHARACTER VARYING(50)       NOT NULL,
    old_value      TEXT,
    new_value      TEXT,
    edited_by      INTEGER                     REFERENCES users(id) ON DELETE SET NULL,
    created_at     TIMESTAMP WITH TIME ZONE    DEFAULT CURRENT_TIMESTAMP
);

-- ── 10. Indexes ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_logs (
    id          SERIAL                      PRIMARY KEY,
    user_id     INTEGER                     REFERENCES users(id) ON DELETE SET NULL,
    action      CHARACTER VARYING(100)      NOT NULL,
    target_type CHARACTER VARYING(50),
    target_id   CHARACTER VARYING(100),
    details     TEXT,
    ip_address  CHARACTER VARYING(45),
    created_at  TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS system_settings (
    id          SERIAL                      PRIMARY KEY,
    key         CHARACTER VARYING(100)      NOT NULL UNIQUE,
    value       JSONB                       NOT NULL,
    description TEXT,
    updated_at  TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS global_blacklist (
    id         SERIAL                      PRIMARY KEY,
    target     CHARACTER VARYING(255)      NOT NULL UNIQUE,
    reason     TEXT,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS admin_broadcasts (
    id         SERIAL                      PRIMARY KEY,
    message    TEXT                        NOT NULL,
    level      CHARACTER VARYING(20)       DEFAULT 'info',
    is_active  BOOLEAN                     DEFAULT TRUE,
    expires_at TIMESTAMP WITHOUT TIME ZONE,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ── 10. Indexes ───────────────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_scan_schedules_next_run ON scan_schedules(next_run) WHERE enabled = TRUE;
CREATE INDEX IF NOT EXISTS idx_scan_raw_results_scan_id ON scan_raw_results(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_logs_scan_id ON scan_logs(scan_id);
