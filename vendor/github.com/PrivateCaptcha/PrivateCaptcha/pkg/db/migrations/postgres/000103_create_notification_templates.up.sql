CREATE TABLE IF NOT EXISTS backend.notification_templates(
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    external_id VARCHAR(64) NOT NULL,
    content_html TEXT NOT NULL,
    content_text TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT current_timestamp,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT current_timestamp
);

CREATE UNIQUE INDEX IF NOT EXISTS index_notification_templates ON backend.notification_templates(external_id);
