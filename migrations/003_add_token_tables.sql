-- Migration 003: Token Security System
-- Date: 2026-03-08
-- Purpose: Add tables for secure token management

BEGIN;

-- ========================================
-- 1. TOKEN BLACKLIST TABLE
-- ========================================
-- Stores revoked/invalidated token hashes

CREATE TABLE IF NOT EXISTS token_blacklist (
    id SERIAL PRIMARY KEY,
    jti_hash VARCHAR(64) UNIQUE NOT NULL,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    token_type VARCHAR(20) NOT NULL,  -- 'access' or 'refresh'
    revoked_at TIMESTAMP DEFAULT NOW(),
    reason VARCHAR(50),  -- 'user_logout', 'suspicious', 'admin_revoke', 'token_rotation'
    expires_at TIMESTAMP NOT NULL,
    
    -- Indexes for fast lookup
    CONSTRAINT valid_token_type CHECK (token_type IN ('access', 'refresh'))
);

CREATE INDEX idx_blacklist_jti_hash ON token_blacklist(jti_hash);
CREATE INDEX idx_blacklist_user_id ON token_blacklist(user_id);
CREATE INDEX idx_blacklist_expires ON token_blacklist(expires_at);

COMMENT ON TABLE token_blacklist IS 'Stores hashes of revoked tokens to prevent reuse';
COMMENT ON COLUMN token_blacklist.jti_hash IS 'SHA-256 hash of token JTI (never store raw tokens!)';


-- ========================================
-- 2. SESSIONS TABLE
-- ========================================
-- Tracks all active user sessions with device/location info

CREATE TABLE IF NOT EXISTS sessions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id VARCHAR(64) UNIQUE NOT NULL,
    
    -- Device Information
    device_fingerprint VARCHAR(255),
    device_name VARCHAR(100),  -- 'Chrome on Windows', 'Safari on iPhone'
    user_agent TEXT,
    
    -- Location Information
    ip_address INET,
    ip_hash VARCHAR(64),
    location VARCHAR(100),  -- 'New York, USA' (from IP geolocation)
    
    -- Token Hashes (NEVER store raw tokens!)
    refresh_token_hash VARCHAR(64) UNIQUE,
    current_access_token_jti_hash VARCHAR(64),
    
    -- Session Metadata
    created_at TIMESTAMP DEFAULT NOW(),
    last_activity TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    
    -- Security
    risk_score INTEGER DEFAULT 0,  -- 0-100, calculated on each use
    mfa_verified BOOLEAN DEFAULT FALSE,
    
    CONSTRAINT valid_risk_score CHECK (risk_score >= 0 AND risk_score <= 100)
);

CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_session_id ON sessions(session_id);
CREATE INDEX idx_sessions_refresh_hash ON sessions(refresh_token_hash);
CREATE INDEX idx_sessions_active ON sessions(is_active, expires_at);

COMMENT ON TABLE sessions IS 'Tracks all active user sessions with device and location binding';
COMMENT ON COLUMN sessions.refresh_token_hash IS 'SHA-256 hash of refresh token (one-time use with rotation)';
COMMENT ON COLUMN sessions.device_fingerprint IS 'Unique browser/device identifier for binding';


-- ========================================
-- 3. TOKEN USAGE LOG TABLE
-- ========================================
-- Audit trail for all token operations

CREATE TABLE IF NOT EXISTS token_usage_log (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    session_id VARCHAR(64),
    jti_hash VARCHAR(64),
    
    -- Action details
    action VARCHAR(50) NOT NULL,  -- 'issued', 'refreshed', 'revoked', 'validated', 'rejected'
    token_type VARCHAR(20),  -- 'access' or 'refresh'
    
    -- Request metadata
    ip_address INET,
    user_agent TEXT,
    endpoint VARCHAR(100),  -- '/auth/login', '/auth/refresh', etc.
    
    -- Security
    risk_score INTEGER DEFAULT 0,
    anomaly_detected BOOLEAN DEFAULT FALSE,
    anomaly_reason TEXT,
    
    -- Timestamp
    timestamp TIMESTAMP DEFAULT NOW(),
    
    CONSTRAINT valid_log_action CHECK (action IN ('issued', 'refreshed', 'revoked', 'validated', 'rejected', 'expired'))
);

CREATE INDEX idx_token_log_user_id ON token_usage_log(user_id);
CREATE INDEX idx_token_log_timestamp ON token_usage_log(timestamp);
CREATE INDEX idx_token_log_action ON token_usage_log(action);
CREATE INDEX idx_token_log_anomaly ON token_usage_log(anomaly_detected) WHERE anomaly_detected = TRUE;

COMMENT ON TABLE token_usage_log IS 'Audit log for all token operations and security events';


-- ========================================
-- 4. ADD COLUMNS TO USERS TABLE
-- ========================================
-- Track user-level security settings

ALTER TABLE users ADD COLUMN IF NOT EXISTS last_password_change TIMESTAMP;
ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_login_attempts INTEGER DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS account_locked_until TIMESTAMP;
ALTER TABLE users ADD COLUMN IF NOT EXISTS security_alerts_enabled BOOLEAN DEFAULT TRUE;

COMMENT ON COLUMN users.failed_login_attempts IS 'Counter for rate limiting (reset on successful login)';
COMMENT ON COLUMN users.account_locked_until IS 'Temporary account lock after too many failed attempts';


-- ========================================
-- 5. CLEANUP FUNCTION
-- ========================================
-- Automatically delete expired blacklist entries

CREATE OR REPLACE FUNCTION cleanup_expired_blacklist()
RETURNS void AS $$
BEGIN
    DELETE FROM token_blacklist
    WHERE expires_at < NOW();
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION cleanup_expired_blacklist IS 'Remove expired tokens from blacklist (call periodically)';

COMMIT;

-- Display table info
SELECT 
    table_name,
    (SELECT COUNT(*) FROM information_schema.columns WHERE table_name = t.table_name) as column_count
FROM information_schema.tables t
WHERE table_schema = 'public' 
AND table_name IN ('token_blacklist', 'sessions', 'token_usage_log', 'users')
ORDER BY table_name;