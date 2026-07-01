-- V3__refresh_tokens.sql
-- Opaque, hashed, rotating refresh tokens with reuse-detection.

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(64) NOT NULL UNIQUE,   -- sha256 hex of the opaque token
    family_id UUID NOT NULL,
    used_at TIMESTAMPTZ,                        -- NULL until rotated
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Indexes (token_hash already indexed by its UNIQUE constraint).
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family ON refresh_tokens(family_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id);
