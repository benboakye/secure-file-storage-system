CREATE TABLE IF NOT EXISTS securestore_capacity_reservations (
    upload_id text PRIMARY KEY REFERENCES securestore_uploads(id) ON DELETE CASCADE,
    owner_id text NOT NULL REFERENCES securestore_users(id) ON DELETE RESTRICT,
    reserved_bytes bigint NOT NULL CHECK (reserved_bytes > 0),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL CHECK (expires_at > created_at)
);

CREATE INDEX IF NOT EXISTS securestore_capacity_reservations_owner_idx
    ON securestore_capacity_reservations(owner_id, expires_at);

CREATE INDEX IF NOT EXISTS securestore_capacity_reservations_expiry_idx
    ON securestore_capacity_reservations(expires_at);
