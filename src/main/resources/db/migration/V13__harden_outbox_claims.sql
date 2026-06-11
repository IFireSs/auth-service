ALTER TABLE outbox_events
    ADD COLUMN claim_id UUID,
    ADD COLUMN lease_until TIMESTAMP WITH TIME ZONE,
    ADD COLUMN last_attempt_at TIMESTAMP WITH TIME ZONE;

UPDATE outbox_events
SET status = 'FAILED',
    attempts = attempts + 1,
    next_attempt_at = CURRENT_TIMESTAMP,
    last_attempt_at = CURRENT_TIMESTAMP,
    last_error = COALESCE(last_error, 'Processing interrupted during outbox claim migration')
WHERE status = 'PROCESSING';

DROP INDEX idx_outbox_events_publishable;

CREATE INDEX idx_outbox_events_publishable
    ON outbox_events(status, next_attempt_at, lease_until, attempts, created_at);
