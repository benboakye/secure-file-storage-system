DO $$
DECLARE
    constraint_name text;
BEGIN
    SELECT conname INTO constraint_name
    FROM pg_constraint
    WHERE conrelid = 'securestore_uploads'::regclass
      AND contype = 'c'
      AND pg_get_constraintdef(oid) LIKE '%status%';
    IF constraint_name IS NOT NULL THEN
        EXECUTE format('ALTER TABLE securestore_uploads DROP CONSTRAINT %I', constraint_name);
    END IF;
END $$;

ALTER TABLE securestore_uploads
    ADD CONSTRAINT securestore_uploads_status_check
    CHECK (status IN ('quarantined', 'inspecting', 'accepted', 'encrypting', 'stored', 'rejected', 'failed'));
