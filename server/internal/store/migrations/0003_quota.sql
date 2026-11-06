-- Storage accounting for the quota (F17). Every record is charged its
-- declared size, its metadata and a fixed overhead (store.RecordOverhead);
-- usage holds the sum, kept current by the triggers below.
ALTER TABLE files ADD COLUMN charge INTEGER NOT NULL DEFAULT 0;

UPDATE files SET charge = size_bytes + length(meta_ciphertext) + 65536;

CREATE TABLE usage (
    id      INTEGER PRIMARY KEY CHECK (id = 1),
    charged INTEGER NOT NULL
) STRICT;

INSERT INTO usage (id, charged) SELECT 1, COALESCE(SUM(charge), 0) FROM files;

CREATE TRIGGER files_charge AFTER INSERT ON files BEGIN
    UPDATE usage SET charged = charged + NEW.charge WHERE id = 1;
END;

CREATE TRIGGER files_release AFTER DELETE ON files BEGIN
    UPDATE usage SET charged = charged - OLD.charge WHERE id = 1;
END;
