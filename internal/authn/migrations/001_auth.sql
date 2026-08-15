CREATE TABLE IF NOT EXISTS securestore_users (
    id text PRIMARY KEY,
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 120),
    email text NOT NULL UNIQUE CHECK (email = lower(email)),
    password_hash bytea NOT NULL,
    role text NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'auditor', 'admin')),
    email_verified_at timestamptz,
    verification_sent_at timestamptz,
    created_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS securestore_email_verification_tokens (
    token_hash bytea PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    user_id text NOT NULL REFERENCES securestore_users(id) ON DELETE CASCADE,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS securestore_verification_user_idx
    ON securestore_email_verification_tokens (user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS securestore_sessions (
    token_hash bytea PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    user_id text NOT NULL REFERENCES securestore_users(id) ON DELETE CASCADE,
    csrf_token text NOT NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS securestore_sessions_expiry_idx
    ON securestore_sessions (expires_at);
