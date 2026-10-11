CREATE TYPE backend.audit_log_source AS ENUM ('unknown', 'portal', 'api');

ALTER TABLE backend.audit_logs ADD COLUMN source backend.audit_log_source NOT NULL DEFAULT 'unknown';

UPDATE backend.audit_logs SET source = 'portal'::backend.audit_log_source;
