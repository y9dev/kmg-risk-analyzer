CREATE TABLE IF NOT EXISTS targets (
    id          TEXT PRIMARY KEY,
    address     TEXT NOT NULL,
    port        INTEGER NOT NULL,
    server_name TEXT NOT NULL,
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,

    owner       TEXT NOT NULL DEFAULT '',
    criticality TEXT NOT NULL DEFAULT 'LOW',

    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT targets_port_check
        CHECK (port BETWEEN 1 AND 65535),

    CONSTRAINT targets_criticality_check
        CHECK (
            criticality IN (
                'LOW',
                'MEDIUM',
                'HIGH',
                'CRITICAL'
            )
        )
);

CREATE TABLE IF NOT EXISTS scans (
    id               BIGSERIAL PRIMARY KEY,
    target_id        TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,

    scanned_at       TIMESTAMPTZ NOT NULL,

    days_left        INTEGER NOT NULL,
    status           TEXT NOT NULL,

    hostname_status  TEXT NOT NULL,
    hostname_error   TEXT NOT NULL DEFAULT '',

    chain_status     TEXT NOT NULL,
    chain_error      TEXT NOT NULL DEFAULT '',

    self_signed      BOOLEAN NOT NULL DEFAULT FALSE,

    tls_version      INTEGER NOT NULL,
    cipher_suite     INTEGER NOT NULL,

    risk_score       INTEGER NOT NULL,
    risk_level       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS certificates (
    id                   BIGSERIAL PRIMARY KEY,
    scan_id              BIGINT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,

    fingerprint_sha256   TEXT NOT NULL,
    serial_number        TEXT NOT NULL,

    subject              TEXT NOT NULL,
    common_name          TEXT NOT NULL,
    issuer               TEXT NOT NULL,

    valid_from           TIMESTAMPTZ NOT NULL,
    valid_to             TIMESTAMPTZ NOT NULL,

    signature_algorithm  TEXT NOT NULL,
    public_key_algorithm TEXT NOT NULL,
    public_key_size      INTEGER NOT NULL,

    dns_names            JSONB NOT NULL DEFAULT '[]',
    ip_addresses         JSONB NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS findings (
    id          BIGSERIAL PRIMARY KEY,
    scan_id     BIGINT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,

    type        TEXT NOT NULL,
    severity    TEXT NOT NULL,
    message     TEXT NOT NULL
);


CREATE INDEX IF NOT EXISTS idx_targets_enabled
    ON targets (enabled);

CREATE INDEX IF NOT EXISTS idx_targets_owner
    ON targets (owner);

CREATE INDEX IF NOT EXISTS idx_targets_criticality
    ON targets (criticality);


CREATE INDEX IF NOT EXISTS idx_scans_target_id
    ON scans (target_id);

CREATE INDEX IF NOT EXISTS idx_scans_scanned_at
    ON scans (scanned_at DESC);

CREATE INDEX IF NOT EXISTS idx_scans_status
    ON scans (status);

CREATE INDEX IF NOT EXISTS idx_scans_risk_level
    ON scans (risk_level);


CREATE INDEX IF NOT EXISTS idx_certificates_scan_id
    ON certificates (scan_id);

CREATE INDEX IF NOT EXISTS idx_certificates_fingerprint
    ON certificates (fingerprint_sha256);


CREATE INDEX IF NOT EXISTS idx_findings_scan_id
    ON findings (scan_id);

CREATE INDEX IF NOT EXISTS idx_findings_type
    ON findings (type);