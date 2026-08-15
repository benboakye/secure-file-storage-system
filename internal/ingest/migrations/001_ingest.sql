CREATE TABLE IF NOT EXISTS securestore_uploads (
    id text PRIMARY KEY,
    owner_id text NOT NULL REFERENCES securestore_users(id) ON DELETE RESTRICT,
    idempotency_hash bytea NOT NULL CHECK (octet_length(idempotency_hash) = 32),
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 255),
    size_bytes bigint NOT NULL DEFAULT 0 CHECK (size_bytes >= 0),
    declared_media_type text NOT NULL,
    detected_media_type text NOT NULL,
    status text NOT NULL CHECK (status IN ('quarantined', 'inspecting', 'accepted', 'rejected', 'failed')),
    progress integer NOT NULL CHECK (progress BETWEEN 0 AND 100),
    decision_reason text NOT NULL DEFAULT '',
    correlation_id text NOT NULL,
    quarantine_object text NOT NULL,
    content_digest text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE (owner_id, idempotency_hash)
);

CREATE INDEX IF NOT EXISTS securestore_uploads_status_idx
    ON securestore_uploads (status, created_at DESC);

CREATE INDEX IF NOT EXISTS securestore_uploads_owner_idx
    ON securestore_uploads (owner_id, created_at DESC);
