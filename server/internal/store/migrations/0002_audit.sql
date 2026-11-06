CREATE TABLE audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    event      TEXT NOT NULL,
    file_id    TEXT,
    ip_hash    BLOB,
    ua_hash    BLOB,
    created_at INTEGER NOT NULL
) STRICT;

CREATE INDEX audit_log_created_at ON audit_log (created_at);
