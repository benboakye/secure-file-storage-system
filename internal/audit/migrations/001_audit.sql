-- Version 2 normalizes timestamps to PostgreSQL microsecond precision before
-- signing. The separate tables preserve any development-era v1 evidence.
CREATE TABLE IF NOT EXISTS securestore_audit_events_v2 (
    sequence bigint PRIMARY KEY,
    event_id text NOT NULL UNIQUE,
    occurred_at timestamptz NOT NULL,
    actor_type text NOT NULL,
    actor_id text NOT NULL,
    action text NOT NULL,
    resource_type text NOT NULL,
    resource_id text NOT NULL,
    outcome text NOT NULL,
    reason_code text NOT NULL,
    correlation_id text NOT NULL,
    from_state text NOT NULL DEFAULT '',
    to_state text NOT NULL DEFAULT '',
    key_version text NOT NULL,
    previous_mac bytea NOT NULL,
    event_mac bytea NOT NULL
);

-- The fingerprint is keyed by the audit HMAC secret. It supports incident
-- correlation and IP-based filtering without retaining raw client addresses.
ALTER TABLE securestore_audit_events_v2
    ADD COLUMN IF NOT EXISTS network_source text NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS securestore_audit_checkpoint_v2 (
    chain_id text PRIMARY KEY,
    last_sequence bigint NOT NULL,
    last_mac bytea NOT NULL,
    key_version text NOT NULL,
    updated_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS securestore_audit_events_v2_time_idx
    ON securestore_audit_events_v2 (occurred_at DESC);
CREATE INDEX IF NOT EXISTS securestore_audit_events_v2_action_idx
    ON securestore_audit_events_v2 (action, outcome);
CREATE INDEX IF NOT EXISTS securestore_audit_events_v2_network_idx
    ON securestore_audit_events_v2 (network_source) WHERE network_source <> '';
