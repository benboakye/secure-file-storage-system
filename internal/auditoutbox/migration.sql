-- The outbox is the atomic boundary between operational state and the signed
-- audit chain. Rows contain only the safe audit projection.
CREATE TABLE IF NOT EXISTS securestore_audit_outbox (
    event_id text PRIMARY KEY,
    occurred_at timestamptz NOT NULL,
    actor_type text NOT NULL,
    actor_id text NOT NULL DEFAULT '',
    action text NOT NULL,
    resource_type text NOT NULL,
    resource_id text NOT NULL DEFAULT '',
    outcome text NOT NULL,
    reason_code text NOT NULL DEFAULT '',
    correlation_id text NOT NULL DEFAULT '',
    from_state text NOT NULL DEFAULT '',
    to_state text NOT NULL DEFAULT '',
    dispatched_at timestamptz,
    chain_sequence bigint,
    last_error text NOT NULL DEFAULT '',
    attempts integer NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS securestore_audit_outbox_pending_idx
    ON securestore_audit_outbox (occurred_at, event_id)
    WHERE dispatched_at IS NULL;
