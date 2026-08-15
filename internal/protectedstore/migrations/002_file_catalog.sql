-- Protected records also represent restore operations. The original column
-- name predated version history, so migrate it without rewriting ciphertext.
DO $$
DECLARE
    foreign_key_name text;
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'securestore_protected_versions' AND column_name = 'upload_id'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'securestore_protected_versions' AND column_name = 'operation_id'
    ) THEN
        ALTER TABLE securestore_protected_versions RENAME COLUMN upload_id TO operation_id;
    END IF;

    SELECT conname INTO foreign_key_name
    FROM pg_constraint
    WHERE conrelid = 'securestore_protected_versions'::regclass
      AND contype = 'f'
      AND pg_get_constraintdef(oid) LIKE '%operation_id%';
    IF foreign_key_name IS NOT NULL THEN
        EXECUTE format('ALTER TABLE securestore_protected_versions DROP CONSTRAINT %I', foreign_key_name);
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS securestore_files (
    file_id text PRIMARY KEY,
    owner_id text NOT NULL REFERENCES securestore_users(id) ON DELETE RESTRICT,
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 255),
    current_version_id text NOT NULL UNIQUE REFERENCES securestore_protected_versions(version_id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS securestore_file_versions (
    file_id text NOT NULL REFERENCES securestore_files(file_id) ON DELETE RESTRICT,
    version_id text PRIMARY KEY REFERENCES securestore_protected_versions(version_id) ON DELETE RESTRICT,
    source_version_id text NULL REFERENCES securestore_protected_versions(version_id) ON DELETE RESTRICT,
    operation_id text NOT NULL UNIQUE,
    version_number bigint NOT NULL CHECK (version_number > 0),
    plaintext_size bigint NOT NULL CHECK (plaintext_size > 0),
    media_type text NOT NULL,
    reason text NOT NULL,
    created_at timestamptz NOT NULL,
    UNIQUE (file_id, version_number)
);

CREATE INDEX IF NOT EXISTS securestore_files_owner_idx ON securestore_files(owner_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS securestore_file_versions_file_idx ON securestore_file_versions(file_id, version_number DESC);

-- Backfill already-stored protected uploads as immutable version 1 records.
-- A prior migration run may have inserted an empty duplicate after the real
-- file's current pointer advanced. Catalog writes always insert file+version
-- transactionally, so a file with no version rows is invalid and removable.
DELETE FROM securestore_files f
WHERE NOT EXISTS (SELECT 1 FROM securestore_file_versions v WHERE v.file_id = f.file_id);

INSERT INTO securestore_files (file_id, owner_id, name, current_version_id, created_at, updated_at)
SELECT 'file_' || substr(md5(p.version_id), 1, 24), p.owner_id, u.name, p.version_id, p.created_at, p.created_at
FROM securestore_protected_versions p
JOIN securestore_uploads u ON u.id = p.operation_id
WHERE u.status = 'stored'
  AND NOT EXISTS (SELECT 1 FROM securestore_file_versions v WHERE v.version_id = p.version_id)
ON CONFLICT DO NOTHING;

INSERT INTO securestore_file_versions (file_id, version_id, operation_id, version_number, plaintext_size, media_type, reason, created_at)
SELECT f.file_id, p.version_id, p.operation_id, 1, p.plaintext_size, p.media_type, 'initial_upload', p.created_at
FROM securestore_protected_versions p
JOIN securestore_files f ON f.current_version_id = p.version_id
ON CONFLICT DO NOTHING;
