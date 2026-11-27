-- ADR 0001: each login is a session (JWT claim "sid") shared by the
-- access and refresh token and kept across refresh-token rotation.
-- Nullable: refresh tokens created before this migration have no session;
-- the next refresh gives them one.
ALTER TABLE refresh_tokens
    ADD COLUMN session_id UUID;

CREATE INDEX idx_refresh_tokens_session_id
    ON refresh_tokens (session_id);
