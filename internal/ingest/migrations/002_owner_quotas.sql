CREATE TABLE IF NOT EXISTS securestore_owner_quotas (
    owner_id text PRIMARY KEY REFERENCES securestore_users(id) ON DELETE CASCADE,
    quota_bytes bigint NOT NULL CHECK (quota_bytes BETWEEN 1048576 AND 10995116277760),
    updated_at timestamptz NOT NULL
);
