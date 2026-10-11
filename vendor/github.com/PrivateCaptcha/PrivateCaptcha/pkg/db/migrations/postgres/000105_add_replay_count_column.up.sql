ALTER TABLE backend.properties ADD COLUMN max_replay_count INTEGER NOT NULL DEFAULT 1;

ALTER TABLE backend.properties ALTER COLUMN validity_interval SET DEFAULT INTERVAL '30 minutes';
