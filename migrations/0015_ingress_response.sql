ALTER TABLE events
    ADD COLUMN IF NOT EXISTS response_status INTEGER,
    ADD COLUMN IF NOT EXISTS response_headers JSONB NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS response_body BYTEA;
