CREATE TYPE backend.apikey_scope AS ENUM ('puzzle', 'portal');

ALTER TABLE backend.apikeys ADD COLUMN scope backend.apikey_scope;

UPDATE backend.apikeys SET scope = 'puzzle'::backend.apikey_scope;

ALTER TABLE backend.apikeys ALTER COLUMN scope SET NOT NULL;
