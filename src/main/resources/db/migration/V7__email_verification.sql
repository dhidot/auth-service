ALTER TABLE email_verification_tokens
ADD COLUMN revoked BOOLEAN NOT NULL DEFAULT FALSE;

CREATE INDEX idx_email_verification_token
ON email_verification_tokens(token);

CREATE INDEX idx_email_verification_user
ON email_verification_tokens(user_id);

CREATE INDEX idx_email_verification_active
ON email_verification_tokens(user_id, revoked, used_at);