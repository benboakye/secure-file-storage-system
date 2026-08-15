CREATE TABLE IF NOT EXISTS securestore_file_access_grants (
    grant_id text PRIMARY KEY,
    file_id text NOT NULL REFERENCES securestore_files(file_id) ON DELETE RESTRICT,
    owner_id text NOT NULL REFERENCES securestore_users(id) ON DELETE RESTRICT,
    recipient_id text NOT NULL REFERENCES securestore_users(id) ON DELETE RESTRICT,
    permission text NOT NULL CHECK (permission IN ('read', 'download')),
    expires_at timestamptz NULL,
    created_at timestamptz NOT NULL,
    revoked_at timestamptz NULL,
    CHECK (owner_id <> recipient_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS securestore_file_access_grants_active_recipient_idx
    ON securestore_file_access_grants(file_id, recipient_id)
    WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS securestore_file_access_grants_recipient_idx
    ON securestore_file_access_grants(recipient_id, file_id)
    WHERE revoked_at IS NULL;
