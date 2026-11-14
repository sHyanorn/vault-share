-- Account ids are never given out twice, since audit entries outlive the
-- account they name (F60, D037). SQLite would reuse the id of a deleted
-- newest account; next starts above every id an account or an audit entry
-- holds, and the trigger keeps it above every id inserted since.
CREATE TABLE account_ids (
    id   INTEGER PRIMARY KEY CHECK (id = 1),
    next INTEGER NOT NULL
) STRICT;

INSERT INTO account_ids (id, next) SELECT 1, MAX(
    COALESCE((SELECT MAX(id) FROM users), 0),
    COALESCE((SELECT MAX(user_id) FROM audit_log), 0)) + 1;

CREATE TRIGGER users_take_id AFTER INSERT ON users BEGIN
    UPDATE account_ids SET next = MAX(next, NEW.id + 1) WHERE id = 1;
END;
