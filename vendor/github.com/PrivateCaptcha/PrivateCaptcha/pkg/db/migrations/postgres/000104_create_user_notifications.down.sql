DROP TRIGGER IF EXISTS deleted_record_insert ON backend.user_notifications CASCADE;

DROP INDEX IF EXISTS index_unique_reference_per_user;

DROP TABLE IF EXISTS backend.user_notifications;
