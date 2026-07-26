ALTER TABLE users
ADD COLUMN enabled BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE users
ADD COLUMN email_verified BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE email_verification_tokens
(
    id UUID PRIMARY KEY,

    user_id UUID NOT NULL,

    token UUID NOT NULL UNIQUE,

    expired_at TIMESTAMP NOT NULL,

    used_at TIMESTAMP,

    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP,

    created_by UUID,
    updated_by UUID,

    CONSTRAINT fk_email_verification_user
        FOREIGN KEY (user_id)
        REFERENCES users(id)
);