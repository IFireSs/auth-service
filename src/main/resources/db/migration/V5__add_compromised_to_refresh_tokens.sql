ALTER TABLE refresh_tokens
    ADD COLUMN compromised_at TIMESTAMP NULL,
    ADD COLUMN compromised_reason VARCHAR(32) NULL;

CREATE INDEX idx_refresh_tokens_user_session_compromised
    ON refresh_tokens (user_id, session_id, compromised_at);