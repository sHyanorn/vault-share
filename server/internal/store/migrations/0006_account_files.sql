-- Files kept in an account (D030): the account, and the entry the browser
-- sealed for the file under the account key (D026).
ALTER TABLE files ADD COLUMN user_id INTEGER REFERENCES users (id) ON DELETE SET NULL;
ALTER TABLE files ADD COLUMN entry BLOB;

CREATE INDEX files_user_id ON files (user_id, created_at) WHERE user_id IS NOT NULL;
