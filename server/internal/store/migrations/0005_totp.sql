-- Two-factor sign-in with TOTP (D029). Secrets are sealed under a server
-- key; recovery codes and sign-in tickets are kept only as SHA-256 hashes.
ALTER TABLE users ADD COLUMN totp_secret BLOB;
-- A secret being set up, until its first code proves the app has it.
ALTER TABLE users ADD COLUMN totp_pending BLOB;
-- The last time step used, so no code works twice.
ALTER TABLE users ADD COLUMN totp_step INTEGER NOT NULL DEFAULT 0;
-- Second steps that failed after a right password, shown at the next sign-in.
ALTER TABLE users ADD COLUMN totp_failures INTEGER NOT NULL DEFAULT 0;

CREATE TABLE recovery_codes (
    user_id   INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash BLOB NOT NULL,
    PRIMARY KEY (user_id, code_hash)
) STRICT;

-- A sign-in waiting for its second step: the password was right.
CREATE TABLE login_tickets (
    token_hash BLOB PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL,
    attempts   INTEGER NOT NULL DEFAULT 0
) STRICT;
