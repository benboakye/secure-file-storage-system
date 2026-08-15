-- Timed lockout is separate from administrator suspension. Expired lockouts do
-- not require an administrator mutation and are evaluated against server time.
ALTER TABLE securestore_users ADD COLUMN IF NOT EXISTS failed_login_attempts integer NOT NULL DEFAULT 0;
ALTER TABLE securestore_users ADD COLUMN IF NOT EXISTS failed_login_window_started_at timestamptz NULL;
ALTER TABLE securestore_users ADD COLUMN IF NOT EXISTS locked_until timestamptz NULL;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='securestore_users_failed_login_attempts_check') THEN
        ALTER TABLE securestore_users ADD CONSTRAINT securestore_users_failed_login_attempts_check CHECK (failed_login_attempts >= 0) NOT VALID;
    END IF;
END $$;
CREATE INDEX IF NOT EXISTS securestore_users_locked_until_idx ON securestore_users(locked_until) WHERE locked_until IS NOT NULL;
