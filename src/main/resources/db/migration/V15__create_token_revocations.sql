-- ADR 0001, stage C2: revocations that other services (the gateway)
-- poll, so logout and logout-all take effect everywhere within seconds.
--
-- SESSION: every token with sid = session_id is revoked (logout).
-- USER:    every token of user_id issued before not_before is revoked
--          (logout-all; later also suspension / password change).
--
-- Rows are only needed until every affected access token has expired,
-- so expires_at = revocation time + access-token lifetime (+ margin)
-- and expired rows are purged. The table therefore stays small.
CREATE TABLE token_revocations
(
    id              BIGSERIAL PRIMARY KEY,
    revocation_type VARCHAR(16) NOT NULL,
    user_id         UUID        NOT NULL,
    session_id      UUID,
    not_before      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL,

    CONSTRAINT fk_token_revocations_user
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT chk_token_revocations_type
        CHECK (revocation_type IN ('SESSION', 'USER')),
    CONSTRAINT chk_token_revocations_session_has_sid
        CHECK (revocation_type <> 'SESSION' OR session_id IS NOT NULL),
    CONSTRAINT chk_token_revocations_user_has_not_before
        CHECK (revocation_type <> 'USER' OR not_before IS NOT NULL)
);

CREATE INDEX idx_token_revocations_expires_at
    ON token_revocations (expires_at);

CREATE INDEX idx_token_revocations_session_id
    ON token_revocations (session_id);
