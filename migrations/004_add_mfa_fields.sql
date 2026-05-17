-- Migration 004: Add MFA Support
-- Date: 2026-03-11

BEGIN;

-- Add MFA columns to users table
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_enabled BOOLEAN DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS backup_codes JSONB;
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_verified_at TIMESTAMP;

COMMENT ON COLUMN users.mfa_enabled IS 'Whether user has enabled MFA';
COMMENT ON COLUMN users.totp_secret IS 'TOTP secret for Google Authenticator (encrypted)';
COMMENT ON COLUMN users.backup_codes IS 'Array of one-time backup codes (hashed)';

COMMIT;
