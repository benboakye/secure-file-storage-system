-- Persist administrator authorization before a filesystem orphan is removed.
-- The object name is internal operational state and is never returned by APIs
-- or copied into audit events.
CREATE TABLE IF NOT EXISTS securestore_orphan_reconciliation_operations (
    operation_id text PRIMARY KEY,
    token text NOT NULL UNIQUE,
    zone text NOT NULL CHECK (zone IN ('quarantine','protected')),
    storage_object text NOT NULL,
    size_bytes bigint NOT NULL CHECK (size_bytes >= 0),
    modified_at timestamptz NOT NULL,
    actor_id text NOT NULL,
    correlation_id text NOT NULL,
    status text NOT NULL CHECK (status IN ('authorized','completed','failed')),
    reason_code text NOT NULL,
    authorized_at timestamptz NOT NULL,
    completed_at timestamptz
);

CREATE INDEX IF NOT EXISTS securestore_orphan_reconciliation_pending_idx
    ON securestore_orphan_reconciliation_operations(status, authorized_at)
    WHERE status = 'authorized';
