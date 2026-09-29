CREATE TABLE users (
    id                   BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username             TEXT NOT NULL UNIQUE CHECK (username ~ '^[a-z0-9][a-z0-9._-]{1,31}$'),
    password_hash        TEXT NOT NULL,
    must_change_password BOOLEAN NOT NULL DEFAULT TRUE,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    password_changed_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Only a SHA-256 hash of each session token is stored.
CREATE TABLE sessions (
    token_hash BYTEA PRIMARY KEY,
    user_id    BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX sessions_user_id_idx ON sessions (user_id);
CREATE INDEX sessions_expires_at_idx ON sessions (expires_at);

CREATE TABLE casbin_rule (
    id    BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ptype TEXT NOT NULL,
    v0    TEXT NOT NULL DEFAULT '',
    v1    TEXT NOT NULL DEFAULT '',
    v2    TEXT NOT NULL DEFAULT '',
    v3    TEXT NOT NULL DEFAULT '',
    v4    TEXT NOT NULL DEFAULT '',
    v5    TEXT NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX casbin_rule_unique_idx ON casbin_rule (ptype, v0, v1, v2, v3, v4, v5);

-- Default roles: each inherits the permissions of the one below it.
INSERT INTO casbin_rule (ptype, v0, v1, v2) VALUES
    ('p', 'user', '/*', 'read'),
    ('p', 'operator', '/*', 'write'),
    ('p', 'admin', '/*', 'overwrite'),
    ('p', 'superadmin', '/*', '*'),
    ('g', 'operator', 'user', ''),
    ('g', 'admin', 'operator', ''),
    ('g', 'superadmin', 'admin', '');
