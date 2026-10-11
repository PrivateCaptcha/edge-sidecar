-- it _will_ take more storage, but we don't plan to have many notifications anyways
ALTER TABLE backend.system_notifications ADD CONSTRAINT unique_system_notification UNIQUE (message, start_date, end_date, user_id, is_active);
