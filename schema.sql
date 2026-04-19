-- ============================================================================
-- SpideyAuth v3.4 Backend – Supabase PostgreSQL Schema
-- Run this entire file in the Supabase SQL Editor (Settings → SQL Editor)
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ────────────────────────────────────────────────────────────────────────────
-- Platform users (developers who create scripts)
-- ────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id          UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    email       TEXT        UNIQUE NOT NULL,
    api_key_hash TEXT       NOT NULL,   -- bcrypt hash of the developer's API key
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    updated_at  TIMESTAMPTZ DEFAULT NOW()
);

-- ────────────────────────────────────────────────────────────────────────────
-- Projects (logical groupings of scripts)
-- ────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS projects (
    id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    owner_id   UUID REFERENCES users(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ────────────────────────────────────────────────────────────────────────────
-- Scripts
-- ────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scripts (
    id                UUID    PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id        UUID    REFERENCES projects(id) ON DELETE CASCADE,
    name              TEXT    NOT NULL,
    script_version    TEXT    DEFAULT '0001',
    protected_payload TEXT    DEFAULT '',   -- the Lua source delivered to whitelisted users
    script_note       TEXT    DEFAULT '',   -- shown to user on successful auth
    user_identifier   TEXT    DEFAULT '?',
    user_note         TEXT    DEFAULT '?',
    created_at        TIMESTAMPTZ DEFAULT NOW()
);

-- ────────────────────────────────────────────────────────────────────────────
-- Whitelist entries (license keys)
-- ────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS whitelist_entries (
    id          UUID    PRIMARY KEY DEFAULT uuid_generate_v4(),
    script_id   UUID    REFERENCES scripts(id) ON DELETE CASCADE,
    license_key TEXT    NOT NULL,
    hwid        TEXT,                        -- NULL until first use; then bound
    discord_id  TEXT    DEFAULT '',
    expires_at  TIMESTAMPTZ,                 -- NULL = lifetime
    max_uses    BIGINT  DEFAULT 0,           -- 0 = unlimited
    total_uses  BIGINT  DEFAULT 0,
    is_banned   BOOLEAN DEFAULT FALSE,
    ban_reason  TEXT    DEFAULT '',
    note        TEXT    DEFAULT '',
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (script_id, license_key)
);

-- ────────────────────────────────────────────────────────────────────────────
-- Active sessions
-- ────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS sessions (
    id                 UUID    PRIMARY KEY DEFAULT uuid_generate_v4(),
    script_id          UUID    REFERENCES scripts(id) ON DELETE CASCADE,
    license_key        TEXT    NOT NULL,
    session_token      BIGINT  NOT NULL,        -- numeric token used in heartbeat hash
    session_url_token  TEXT    NOT NULL UNIQUE, -- used in URL paths / ?s= param
    combined_seed      BIGINT  DEFAULT 0,       -- set during /auth/start
    hwid               TEXT    DEFAULT '',
    nonce2             BIGINT  DEFAULT 0,       -- from init request
    server_nonce2_init BIGINT  DEFAULT 0,       -- client's sn[2] from init payload

    -- Extended cipher key components
    ext_key_1 BIGINT DEFAULT 0,
    ext_key_3 BIGINT DEFAULT 0,
    ext_key_5 BIGINT DEFAULT 0,
    ext_key_7 BIGINT DEFAULT 0,

    -- Client token mod-256 values (cipher key bytes)
    ct1 BIGINT DEFAULT 0,
    ct2 BIGINT DEFAULT 0,
    ct3 BIGINT DEFAULT 0,
    ct4 BIGINT DEFAULT 0,

    should_terminate BOOLEAN DEFAULT FALSE,

    created_at      TIMESTAMPTZ DEFAULT NOW(),
    last_heartbeat  TIMESTAMPTZ DEFAULT NOW()
);

-- Index for fast session lookups
CREATE INDEX IF NOT EXISTS idx_sessions_url_token ON sessions (session_url_token);
CREATE INDEX IF NOT EXISTS idx_whitelist_script_key ON whitelist_entries (script_id, license_key);

-- ────────────────────────────────────────────────────────────────────────────
-- Invite codes (for developer registration)
-- ────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS invite_codes (
    code       TEXT PRIMARY KEY,
    created_by UUID REFERENCES users(id),
    used_by    UUID REFERENCES users(id),
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ────────────────────────────────────────────────────────────────────────────
-- Row Level Security (enable for production)
-- ────────────────────────────────────────────────────────────────────────────
-- ALTER TABLE users              ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE projects           ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE scripts            ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE whitelist_entries  ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE sessions           ENABLE ROW LEVEL SECURITY;

-- ────────────────────────────────────────────────────────────────────────────
-- Helper function: increment total_uses atomically
-- ────────────────────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION increment_uses(entry_id UUID)
RETURNS VOID LANGUAGE plpgsql AS $$
BEGIN
    UPDATE whitelist_entries
    SET total_uses = total_uses + 1
    WHERE id = entry_id;
END;
$$;

-- ────────────────────────────────────────────────────────────────────────────
-- Cleanup job: remove sessions older than 2 hours with no recent heartbeat
-- (Schedule via Supabase pg_cron or a Vercel cron)
-- ────────────────────────────────────────────────────────────────────────────
-- SELECT cron.schedule(
--   'cleanup-stale-sessions',
--   '*/30 * * * *',
--   $$DELETE FROM sessions WHERE last_heartbeat < NOW() - INTERVAL '2 hours'$$
-- );