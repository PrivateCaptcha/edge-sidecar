ALTER TABLE backend.properties ALTER COLUMN validity_interval SET DEFAULT INTERVAL '6 hours';

ALTER TABLE backend.properties DROP COLUMN max_replay_count;
