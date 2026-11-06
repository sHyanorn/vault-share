CREATE TABLE files (
    id               TEXT PRIMARY KEY,
    size_bytes       INTEGER NOT NULL,
    meta_ciphertext  BLOB NOT NULL,
    auth_key         BLOB NOT NULL,
    owner_token_hash BLOB NOT NULL,
    downloads_left   INTEGER NOT NULL,
    expires_at       INTEGER NOT NULL,
    created_at       INTEGER NOT NULL,
    uploaded_at      INTEGER
) STRICT;

CREATE INDEX files_expires_at ON files (expires_at);

CREATE TABLE download_tokens (
    token_hash BLOB PRIMARY KEY,
    file_id    TEXT NOT NULL REFERENCES files (id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL
) STRICT;

CREATE INDEX download_tokens_file_id ON download_tokens (file_id);
