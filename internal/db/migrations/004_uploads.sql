-- Unfinished resumable uploads. The data received so far is in the hidden
-- file temp, in the folder dir next to the file name it will become. Only
-- a SHA-256 hash of each upload's token is stored. user_id is not a
-- foreign key: the uploads of a deleted user just expire.
CREATE TABLE uploads (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    token_hash   BYTEA NOT NULL UNIQUE,
    user_id      BIGINT NOT NULL, -- 0 for anonymous visitors
    dir          TEXT NOT NULL,
    name         TEXT NOT NULL,
    length       BIGINT NOT NULL CHECK (length >= 0),
    replace      BOOLEAN NOT NULL,
    temp         TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL,
    -- The request writing the upload, if any, and until when its claim holds.
    writer       TEXT NOT NULL DEFAULT '',
    writer_until TIMESTAMPTZ NOT NULL DEFAULT '-infinity'
);
CREATE INDEX uploads_expires_at_idx ON uploads (expires_at);
