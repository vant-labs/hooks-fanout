ALTER TABLE deliveries
    ADD COLUMN IF NOT EXISTS forward_original_body BOOLEAN NOT NULL DEFAULT TRUE;

ALTER TABLE routes
    ADD COLUMN IF NOT EXISTS outbound_auth_mode TEXT NOT NULL DEFAULT 'none',
    ADD COLUMN IF NOT EXISTS outbound_auth_header TEXT,
    ADD COLUMN IF NOT EXISTS outbound_auth_secret_ciphertext TEXT NOT NULL DEFAULT '';

ALTER TABLE routes
    DROP CONSTRAINT IF EXISTS routes_outbound_auth_mode_check;

ALTER TABLE routes
    ADD CONSTRAINT routes_outbound_auth_mode_check
    CHECK (outbound_auth_mode IN ('none', 'static_header', 'hmac_sha512'));

UPDATE deliveries AS d
SET forward_original_body = TRUE;
