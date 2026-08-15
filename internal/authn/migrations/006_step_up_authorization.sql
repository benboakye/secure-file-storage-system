-- A step-up proof is opaque, short-lived, and bound to the exact privileged
-- session that requested it. Session deletion cascades to all associated proofs.
CREATE TABLE IF NOT EXISTS securestore_step_up_proofs (
    token_hash bytea PRIMARY KEY,
    session_token_hash bytea NOT NULL REFERENCES securestore_sessions(token_hash) ON DELETE CASCADE,
    user_id text NOT NULL REFERENCES securestore_users(id) ON DELETE CASCADE,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS securestore_step_up_proofs_expiry_idx ON securestore_step_up_proofs(expires_at);
