ALTER TABLE sources ADD COLUMN IF NOT EXISTS path_slug TEXT;
UPDATE sources SET path_slug = name WHERE path_slug IS NULL OR path_slug = '';
ALTER TABLE sources ALTER COLUMN path_slug SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS sources_path_slug_idx ON sources (path_slug);

ALTER TABLE sources
    ADD COLUMN IF NOT EXISTS credentials_ciphertext TEXT NOT NULL DEFAULT '';
