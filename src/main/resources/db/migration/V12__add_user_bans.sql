ALTER TABLE users
    ADD COLUMN ban_protected BOOLEAN NOT NULL DEFAULT FALSE;

UPDATE users
SET ban_protected = TRUE
WHERE id IN (
    SELECT target_user_id
    FROM audit_events
    WHERE event_type = 'SUPER_ADMIN_BOOTSTRAPPED'
      AND target_user_id IS NOT NULL
);

CREATE TABLE user_bans (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE,
    reason VARCHAR(500) NOT NULL,
    created_by UUID NOT NULL,
    ended_at TIMESTAMP WITH TIME ZONE,
    ended_by UUID,
    end_type VARCHAR(32),
    CONSTRAINT fk_user_bans_user_id
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT ck_user_bans_expiration
        CHECK (expires_at IS NULL OR expires_at > created_at),
    CONSTRAINT ck_user_bans_ended_at
        CHECK (ended_at IS NULL OR ended_at >= created_at),
    CONSTRAINT ck_user_bans_end_state
        CHECK (
            (ended_at IS NULL AND ended_by IS NULL AND end_type IS NULL)
            OR (ended_at IS NOT NULL AND ended_by IS NULL AND end_type = 'EXPIRED')
            OR (ended_at IS NOT NULL AND ended_by IS NOT NULL AND end_type = 'REVOKED')
        )
);

CREATE UNIQUE INDEX uq_user_bans_current_user
    ON user_bans(user_id)
    WHERE ended_at IS NULL;

CREATE INDEX idx_user_bans_active_lookup
    ON user_bans(user_id, ended_at, expires_at);

CREATE INDEX idx_user_bans_created_at
    ON user_bans(created_at);
