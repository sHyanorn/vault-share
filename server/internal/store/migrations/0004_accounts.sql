-- Accounts (D026, D027). The server never sees an account password: it
-- keeps the salt the browser derives with, an Argon2id hash of the auth
-- secret derived from the password, and the account key sealed under it.
CREATE TABLE users (
    id         INTEGER PRIMARY KEY,
    username   TEXT NOT NULL UNIQUE,
    salt       BLOB NOT NULL,
    auth_hash  TEXT NOT NULL,
    sealed_key BLOB NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;

-- A session is known only by the SHA-256 of its token.
CREATE TABLE sessions (
    token_hash BLOB PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    seen_at    INTEGER NOT NULL
) STRICT;

CREATE INDEX sessions_user_id ON sessions (user_id);

-- Audit entries outlive the account they name, so there is no foreign key.
ALTER TABLE audit_log ADD COLUMN user_id INTEGER;
