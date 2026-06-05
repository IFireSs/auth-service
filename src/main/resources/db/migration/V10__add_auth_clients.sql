CREATE TABLE auth_clients (
    id BIGSERIAL PRIMARY KEY,
    client_id VARCHAR(128) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    access_token_ttl_seconds BIGINT NOT NULL,
    refresh_token_ttl_seconds BIGINT NOT NULL,
    token_audience VARCHAR(255) NOT NULL,
    allowed_origins JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

INSERT INTO auth_clients (
    client_id,
    name,
    enabled,
    access_token_ttl_seconds,
    refresh_token_ttl_seconds,
    token_audience,
    allowed_origins
) VALUES (
    'budget-manager-web',
    'Budget Manager Web',
    TRUE,
    600,
    1209600,
    'budget-manager',
    '["http://localhost:3000","http://localhost:5173"]'
);

ALTER TABLE refresh_tokens
    ADD COLUMN client_id VARCHAR(128);

UPDATE refresh_tokens
SET client_id = 'budget-manager-web'
WHERE client_id IS NULL;

ALTER TABLE refresh_tokens
    ALTER COLUMN client_id SET NOT NULL,
    ADD CONSTRAINT fk_refresh_tokens_client_id FOREIGN KEY (client_id) REFERENCES auth_clients(client_id);

CREATE INDEX idx_refresh_tokens_user_client_session_active
    ON refresh_tokens(user_id, client_id, session_id, revoked, expires_at);
