CREATE TABLE IF NOT EXISTS securestore_protected_versions (
    version_id text PRIMARY KEY,
    upload_id text NOT NULL UNIQUE REFERENCES securestore_uploads(id) ON DELETE RESTRICT,
    owner_id text NOT NULL REFERENCES securestore_users(id) ON DELETE RESTRICT,
    blob_object text NOT NULL UNIQUE,
    schema_version text NOT NULL,
    algorithm text NOT NULL,
    kek_id text NOT NULL,
    kek_version text NOT NULL,
    wrapped_dek bytea NOT NULL,
    nonce bytea NOT NULL,
    plaintext_size bigint NOT NULL CHECK (plaintext_size > 0),
    plaintext_digest text NOT NULL,
    media_type text NOT NULL,
    inspection_record_id text NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS securestore_protected_versions_owner_idx
    ON securestore_protected_versions (owner_id, created_at DESC);
