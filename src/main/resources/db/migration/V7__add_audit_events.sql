CREATE TABLE audit_events (
    id UUID PRIMARY KEY,
    event_type VARCHAR(100) NOT NULL,
    occurred_at TIMESTAMP WITH TIME ZONE NOT NULL,
    actor_user_id BIGINT,
    target_user_id BIGINT,
    username VARCHAR(128),
    session_id TEXT,
    ip TEXT,
    user_agent TEXT,
    details_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX idx_audit_events_occurred_at ON audit_events(occurred_at);
CREATE INDEX idx_audit_events_event_type ON audit_events(event_type);
CREATE INDEX idx_audit_events_actor_user_id ON audit_events(actor_user_id);
CREATE INDEX idx_audit_events_target_user_id ON audit_events(target_user_id);
