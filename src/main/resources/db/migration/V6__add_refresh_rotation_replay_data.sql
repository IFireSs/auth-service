ALTER TABLE refresh_tokens
    ADD COLUMN rotation_attempt_id VARCHAR(128) NULL,
    ADD COLUMN rotation_result_token_cipher TEXT NULL,
    ADD COLUMN rotation_result_expires_at TIMESTAMP WITH TIME ZONE NULL;

CREATE INDEX idx_refresh_tokens_rotation_attempt_id
    ON refresh_tokens (rotation_attempt_id);
