CREATE TABLE refresh_tokens
(
    id UUID PRIMARY KEY,

    user_id UUID NOT NULL,

    token_hash VARCHAR(64) NOT NULL UNIQUE,

    expired_at TIMESTAMP NOT NULL,

    revoked BOOLEAN NOT NULL,

    created_at TIMESTAMP NOT NULL,

    updated_at TIMESTAMP,

    device_info VARCHAR(255),

    ip_address VARCHAR(50),

    last_used_at TIMESTAMP,

    created_by UUID,

    updated_by UUID,

    CONSTRAINT fk_refresh_user
        FOREIGN KEY (user_id)
        REFERENCES users(id)
);