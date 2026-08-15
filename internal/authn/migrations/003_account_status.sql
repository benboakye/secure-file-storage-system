ALTER TABLE securestore_users
    ADD COLUMN IF NOT EXISTS account_status text NOT NULL DEFAULT 'active';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'securestore_users_account_status_check'
    ) THEN
        ALTER TABLE securestore_users
            ADD CONSTRAINT securestore_users_account_status_check
            CHECK (account_status IN ('active', 'suspended', 'locked'));
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS securestore_users_account_status_idx
    ON securestore_users (account_status);
