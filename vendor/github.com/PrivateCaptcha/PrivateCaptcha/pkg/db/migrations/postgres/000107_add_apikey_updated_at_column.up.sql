ALTER TABLE backend.apikeys ADD COLUMN updated_at TIMESTAMPTZ NOT NULL DEFAULT current_timestamp;

UPDATE backend.apikeys SET updated_at = created_at;
