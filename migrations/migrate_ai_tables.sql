-- =============================================================
-- VaultID — AI Tables Migration
-- Run this in PostgreSQL to create the AI-related tables
-- Replaces: MongoDB "logs" and "sessions" collections
-- =============================================================

-- Enable UUID extension (if not already enabled)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";


-- =============================================================
-- login_logs — stores every login event + AI decision
-- Replaces: MongoDB Log model (log.model.js)
-- =============================================================

CREATE TABLE IF NOT EXISTS login_logs (
    id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id          VARCHAR(255) NOT NULL,
    action           VARCHAR(100) NOT NULL,

    -- Raw environment
    ip               VARCHAR(45),
    device           TEXT,
    country          VARCHAR(10)  DEFAULT 'LOCAL',
    region           VARCHAR(50)  DEFAULT 'LOCAL',
    city             VARCHAR(100) DEFAULT 'LOCAL',

    timestamp        TIMESTAMPTZ  DEFAULT NOW(),

    -- Behavioral features (LSTM input)
    time_gap         FLOAT        DEFAULT 0,
    ip_change        SMALLINT     DEFAULT 0,
    device_change    SMALLINT     DEFAULT 0,
    location_change  SMALLINT     DEFAULT 0,

    -- AI decision output
    anomaly_score    FLOAT        DEFAULT 0.0,
    risk_level       VARCHAR(10)  DEFAULT 'LOW',
    action_taken     VARCHAR(10)  DEFAULT 'ALLOW'
);

CREATE INDEX IF NOT EXISTS idx_login_logs_user_id   ON login_logs (user_id);
CREATE INDEX IF NOT EXISTS idx_login_logs_timestamp ON login_logs (timestamp);


-- =============================================================
-- risk_sessions — current risk state per user
-- Replaces: MongoDB Session model (session.model.js)
-- =============================================================

CREATE TABLE IF NOT EXISTS risk_sessions (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id      VARCHAR(255) NOT NULL UNIQUE,
    current_risk VARCHAR(10)  DEFAULT 'LOW',
    last_score   FLOAT        DEFAULT 0.0,
    last_updated TIMESTAMPTZ  DEFAULT NOW(),
    is_active    BOOLEAN      DEFAULT TRUE
);

CREATE INDEX IF NOT EXISTS idx_risk_sessions_user_id ON risk_sessions (user_id);
