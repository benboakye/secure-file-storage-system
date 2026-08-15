-- Keep the AES-GCM authenticated envelope origin immutable while allowing the
-- DEK wrapper to move to a newer KEK. Existing rows begin with both identities
-- equal, so this migration does not change their cryptographic interpretation.
ALTER TABLE securestore_protected_versions
    ADD COLUMN IF NOT EXISTS wrapping_kek_id text,
    ADD COLUMN IF NOT EXISTS wrapping_kek_version text;

UPDATE securestore_protected_versions
SET wrapping_kek_id = kek_id,
    wrapping_kek_version = kek_version
WHERE wrapping_kek_id IS NULL OR wrapping_kek_version IS NULL;

ALTER TABLE securestore_protected_versions
    ALTER COLUMN wrapping_kek_id SET NOT NULL,
    ALTER COLUMN wrapping_kek_version SET NOT NULL;

CREATE TABLE IF NOT EXISTS securestore_dek_rewrap_operations (
    operation_id text PRIMARY KEY,
    version_id text NOT NULL REFERENCES securestore_protected_versions(version_id) ON DELETE CASCADE,
    from_kek_id text NOT NULL,
    from_kek_version text NOT NULL,
    to_kek_id text NOT NULL,
    to_kek_version text NOT NULL,
    status text NOT NULL CHECK (status IN ('completed','failed')),
    reason_code text NOT NULL,
    attempted_at timestamptz NOT NULL,
    completed_at timestamptz,
    UNIQUE (version_id, to_kek_id, to_kek_version)
);

CREATE INDEX IF NOT EXISTS securestore_dek_rewrap_status_idx
    ON securestore_dek_rewrap_operations(status, attempted_at DESC);
