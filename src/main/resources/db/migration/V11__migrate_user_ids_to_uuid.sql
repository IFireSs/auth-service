ALTER TABLE users
    ADD COLUMN created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now();

CREATE TEMPORARY TABLE user_id_uuid_map (
    old_id BIGINT PRIMARY KEY,
    new_id UUID NOT NULL UNIQUE
) ON COMMIT DROP;

INSERT INTO user_id_uuid_map (old_id, new_id)
SELECT id, gen_random_uuid()
FROM users;

INSERT INTO user_id_uuid_map (old_id, new_id)
SELECT old_id, gen_random_uuid()
FROM (
    SELECT actor_user_id AS old_id FROM audit_events
    UNION
    SELECT target_user_id AS old_id FROM audit_events
) audit_user_ids
WHERE old_id IS NOT NULL
ON CONFLICT (old_id) DO NOTHING;

ALTER TABLE users ADD COLUMN id_uuid UUID;
ALTER TABLE user_roles ADD COLUMN user_id_uuid UUID;
ALTER TABLE refresh_tokens ADD COLUMN user_id_uuid UUID;
ALTER TABLE audit_events ADD COLUMN actor_user_id_uuid UUID;
ALTER TABLE audit_events ADD COLUMN target_user_id_uuid UUID;

UPDATE users
SET id_uuid = user_id_uuid_map.new_id
FROM user_id_uuid_map
WHERE users.id = user_id_uuid_map.old_id;

UPDATE user_roles
SET user_id_uuid = user_id_uuid_map.new_id
FROM user_id_uuid_map
WHERE user_roles.user_id = user_id_uuid_map.old_id;

UPDATE refresh_tokens
SET user_id_uuid = user_id_uuid_map.new_id
FROM user_id_uuid_map
WHERE refresh_tokens.user_id = user_id_uuid_map.old_id;

UPDATE audit_events
SET actor_user_id_uuid = user_id_uuid_map.new_id
FROM user_id_uuid_map
WHERE audit_events.actor_user_id = user_id_uuid_map.old_id;

UPDATE audit_events
SET target_user_id_uuid = user_id_uuid_map.new_id
FROM user_id_uuid_map
WHERE audit_events.target_user_id = user_id_uuid_map.old_id;

ALTER TABLE users ALTER COLUMN id_uuid SET NOT NULL;
ALTER TABLE user_roles ALTER COLUMN user_id_uuid SET NOT NULL;
ALTER TABLE refresh_tokens ALTER COLUMN user_id_uuid SET NOT NULL;

ALTER TABLE user_roles
    DROP CONSTRAINT user_roles_pkey,
    DROP CONSTRAINT user_roles_user_id_fkey;

ALTER TABLE refresh_tokens
    DROP CONSTRAINT fk_refresh_tokens_user_id;

ALTER TABLE users
    DROP CONSTRAINT users_pkey;

DROP INDEX idx_refresh_tokens_user_id_revoked;
DROP INDEX idx_refresh_tokens_user_session_compromised;
DROP INDEX idx_refresh_tokens_user_client_session_active;
DROP INDEX idx_audit_events_actor_user_id;
DROP INDEX idx_audit_events_target_user_id;

ALTER TABLE user_roles DROP COLUMN user_id;
ALTER TABLE refresh_tokens DROP COLUMN user_id;
ALTER TABLE audit_events DROP COLUMN actor_user_id;
ALTER TABLE audit_events DROP COLUMN target_user_id;
ALTER TABLE users DROP COLUMN id;

ALTER TABLE users RENAME COLUMN id_uuid TO id;
ALTER TABLE user_roles RENAME COLUMN user_id_uuid TO user_id;
ALTER TABLE refresh_tokens RENAME COLUMN user_id_uuid TO user_id;
ALTER TABLE audit_events RENAME COLUMN actor_user_id_uuid TO actor_user_id;
ALTER TABLE audit_events RENAME COLUMN target_user_id_uuid TO target_user_id;

ALTER TABLE users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);

ALTER TABLE user_roles
    ADD CONSTRAINT user_roles_pkey PRIMARY KEY (user_id, role),
    ADD CONSTRAINT user_roles_user_id_fkey
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

ALTER TABLE refresh_tokens
    ADD CONSTRAINT fk_refresh_tokens_user_id
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

CREATE INDEX idx_refresh_tokens_user_id_revoked
    ON refresh_tokens(user_id, revoked);

CREATE INDEX idx_refresh_tokens_user_session_compromised
    ON refresh_tokens(user_id, session_id, compromised_at);

CREATE INDEX idx_refresh_tokens_user_client_session_active
    ON refresh_tokens(user_id, client_id, session_id, revoked, expires_at);

CREATE INDEX idx_audit_events_actor_user_id
    ON audit_events(actor_user_id);

CREATE INDEX idx_audit_events_target_user_id
    ON audit_events(target_user_id);
