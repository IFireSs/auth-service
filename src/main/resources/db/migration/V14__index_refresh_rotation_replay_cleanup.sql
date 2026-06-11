CREATE INDEX idx_refresh_tokens_rotation_result_expires_at_payload
    ON refresh_tokens (rotation_result_expires_at)
    WHERE rotation_result_expires_at IS NOT NULL;
