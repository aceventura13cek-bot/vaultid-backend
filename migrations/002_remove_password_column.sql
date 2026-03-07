-- Remove password column and old users
BEGIN;

-- Delete old users (they'll re-register with ZKP)
DELETE FROM users;

-- Remove password column
ALTER TABLE users DROP COLUMN password;

-- Make ZKP columns required
ALTER TABLE users ALTER COLUMN zkp_public_key SET NOT NULL;
ALTER TABLE users ALTER COLUMN zkp_salt SET NOT NULL;
ALTER TABLE users ALTER COLUMN zkp_params SET NOT NULL;

COMMIT;
