-- Links that let people without an account read a file or folder. Only a
-- SHA-256 hash of each link's token is stored, and of its password, if it
-- has one, an Argon2id hash.
CREATE TABLE shares (
    id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    token_hash    BYTEA NOT NULL UNIQUE,
    path          TEXT NOT NULL,
    is_dir        BOOLEAN NOT NULL,
    created_by    BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    password_hash TEXT NOT NULL DEFAULT '',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ NOT NULL
);
CREATE INDEX shares_created_by_idx ON shares (created_by);
CREATE INDEX shares_expires_at_idx ON shares (expires_at);

-- Creating links needs the new share action. Admins get it where they may
-- replace files by default; changed rules are left alone.
INSERT INTO casbin_rule (ptype, v0, v1, v2)
SELECT 'p', 'admin', '/*', 'share'
WHERE EXISTS (
    SELECT 1 FROM casbin_rule
    WHERE (ptype, v0, v1, v2, v3, v4, v5) = ('p', 'admin', '/*', 'overwrite', '', '', ''))
ON CONFLICT DO NOTHING;
