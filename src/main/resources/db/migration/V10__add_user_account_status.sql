-- 1. Add new account status column
ALTER TABLE users
ADD COLUMN account_status VARCHAR(32);


-- 2. Migrate existing account states
UPDATE users
SET account_status = CASE
    WHEN enabled = TRUE
         AND email_verified = TRUE
        THEN 'ACTIVE'

    WHEN enabled = FALSE
         AND email_verified = TRUE
        THEN 'SUSPENDED'

    ELSE 'PENDING_VERIFICATION'
END;


-- 3. Set default for new users
ALTER TABLE users
ALTER COLUMN account_status
SET DEFAULT 'PENDING_VERIFICATION';


-- 4. Prevent null status
ALTER TABLE users
ALTER COLUMN account_status
SET NOT NULL;


-- 5. Restrict allowed status values
ALTER TABLE users
ADD CONSTRAINT chk_users_account_status
CHECK (
    account_status IN (
        'PENDING_VERIFICATION',
        'ACTIVE',
        'SUSPENDED'
    )
);