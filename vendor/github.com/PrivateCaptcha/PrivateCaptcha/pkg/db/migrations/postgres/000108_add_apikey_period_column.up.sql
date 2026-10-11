ALTER TABLE backend.apikeys ADD COLUMN period INTERVAL NOT NULL DEFAULT INTERVAL '0 seconds';

UPDATE backend.apikeys SET period = expires_at - created_at WHERE period = INTERVAL '0 seconds';
