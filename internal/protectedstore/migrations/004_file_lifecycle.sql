-- Lifecycle metadata is retained as an evidence-bearing tombstone. Permanent
-- deletion destroys wrapped DEKs while preserving non-content audit metadata.
ALTER TABLE securestore_files ADD COLUMN IF NOT EXISTS deleted_at timestamptz NULL;
ALTER TABLE securestore_files ADD COLUMN IF NOT EXISTS purge_after timestamptz NULL;
ALTER TABLE securestore_files ADD COLUMN IF NOT EXISTS retention_until timestamptz NULL;
ALTER TABLE securestore_files ADD COLUMN IF NOT EXISTS legal_hold boolean NOT NULL DEFAULT false;
ALTER TABLE securestore_files ADD COLUMN IF NOT EXISTS legal_hold_reason text NOT NULL DEFAULT '';
ALTER TABLE securestore_files ADD COLUMN IF NOT EXISTS purged_at timestamptz NULL;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='securestore_files_lifecycle_dates') THEN
        ALTER TABLE securestore_files ADD CONSTRAINT securestore_files_lifecycle_dates CHECK (
            (deleted_at IS NULL AND purge_after IS NULL) OR
            (deleted_at IS NOT NULL AND purge_after IS NOT NULL AND purge_after >= deleted_at)
        ) NOT VALID;
    END IF;
END $$;

ALTER TABLE securestore_protected_versions ALTER COLUMN wrapped_dek DROP NOT NULL;

CREATE TABLE IF NOT EXISTS securestore_deletion_operations (
    operation_id text PRIMARY KEY,
    file_id text NOT NULL REFERENCES securestore_files(file_id) ON DELETE RESTRICT,
    owner_id text NOT NULL REFERENCES securestore_users(id) ON DELETE RESTRICT,
    status text NOT NULL CHECK (status IN ('completed')),
    destroyed_keys integer NOT NULL CHECK (destroyed_keys >= 0),
    completed_at timestamptz NOT NULL
);

ALTER TABLE securestore_deletion_operations DROP CONSTRAINT IF EXISTS securestore_deletion_operations_status_check;
ALTER TABLE securestore_deletion_operations ADD COLUMN IF NOT EXISTS attempts integer NOT NULL DEFAULT 1;
ALTER TABLE securestore_deletion_operations ADD COLUMN IF NOT EXISTS reason_code text NOT NULL DEFAULT '';
ALTER TABLE securestore_deletion_operations ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE securestore_deletion_operations ALTER COLUMN completed_at DROP NOT NULL;
ALTER TABLE securestore_deletion_operations ADD CONSTRAINT securestore_deletion_operations_status_check CHECK (status IN ('pending','completed','failed'));

CREATE TABLE IF NOT EXISTS securestore_recovery_drills (
    drill_id text PRIMARY KEY,
    file_id text NOT NULL REFERENCES securestore_files(file_id) ON DELETE RESTRICT,
    version_id text NOT NULL REFERENCES securestore_protected_versions(version_id) ON DELETE RESTRICT,
    requested_by text NOT NULL REFERENCES securestore_users(id) ON DELETE RESTRICT,
    outcome text NOT NULL CHECK (outcome IN ('verified','failed')),
    reason_code text NOT NULL,
    verified_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS securestore_deletion_operations_status_idx ON securestore_deletion_operations(status,updated_at DESC);
CREATE INDEX IF NOT EXISTS securestore_recovery_drills_time_idx ON securestore_recovery_drills(verified_at DESC);

CREATE INDEX IF NOT EXISTS securestore_files_trash_idx ON securestore_files(owner_id, deleted_at DESC) WHERE deleted_at IS NOT NULL AND purged_at IS NULL;
CREATE INDEX IF NOT EXISTS securestore_files_retention_idx ON securestore_files(retention_until) WHERE retention_until IS NOT NULL AND purged_at IS NULL;
