-- Privileged identities are provisioned independently from public user
-- registration. Only a digest of the single-use invitation token is stored.
CREATE TABLE IF NOT EXISTS securestore_privileged_invitations (
    token_hash bytea PRIMARY KEY,
    invited_by text NOT NULL REFERENCES securestore_users(id),
    name text NOT NULL,
    email text NOT NULL,
    role text NOT NULL CHECK (role IN ('admin', 'auditor')),
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    accepted_at timestamptz
);

CREATE UNIQUE INDEX IF NOT EXISTS securestore_privileged_invitations_pending_email_idx
    ON securestore_privileged_invitations (lower(email))
    WHERE accepted_at IS NULL;
CREATE INDEX IF NOT EXISTS securestore_privileged_invitations_expiry_idx
    ON securestore_privileged_invitations (expires_at);
