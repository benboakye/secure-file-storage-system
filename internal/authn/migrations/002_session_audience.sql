ALTER TABLE securestore_sessions
    ADD COLUMN IF NOT EXISTS audience text NOT NULL DEFAULT 'user';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'securestore_sessions_audience_check'
    ) THEN
        ALTER TABLE securestore_sessions
            ADD CONSTRAINT securestore_sessions_audience_check
            CHECK (audience IN ('user', 'privileged'));
    END IF;
END $$;

-- Existing sessions remain standard sessions. They cannot authorize an admin
-- endpoint even if the underlying account is later promoted.
