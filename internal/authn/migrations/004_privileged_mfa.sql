-- MFA secrets are encrypted by the application before persistence. Challenges
-- and recovery codes are stored only as one-way hashes and are single-use.
CREATE TABLE IF NOT EXISTS securestore_user_mfa (
    user_id text PRIMARY KEY REFERENCES securestore_users(id) ON DELETE CASCADE,
    secret_ciphertext bytea NOT NULL,
    secret_nonce bytea NOT NULL,
    confirmed_at timestamptz NOT NULL,
    last_counter bigint NOT NULL DEFAULT -1
);
CREATE TABLE IF NOT EXISTS securestore_mfa_challenges (
    token_hash bytea PRIMARY KEY,
    user_id text NOT NULL REFERENCES securestore_users(id) ON DELETE CASCADE,
    pending_secret_ciphertext bytea NULL,
    pending_secret_nonce bytea NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    consumed_at timestamptz NULL
);
CREATE TABLE IF NOT EXISTS securestore_mfa_recovery_codes (
    user_id text NOT NULL REFERENCES securestore_users(id) ON DELETE CASCADE,
    code_hash bytea NOT NULL,
    created_at timestamptz NOT NULL,
    used_at timestamptz NULL,
    PRIMARY KEY(user_id, code_hash)
);
CREATE INDEX IF NOT EXISTS securestore_mfa_challenges_expiry_idx ON securestore_mfa_challenges(expires_at) WHERE consumed_at IS NULL;
