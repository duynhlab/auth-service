-- V4__drop_sessions.sql
-- RFC-0009 Phase 5 (opaque -> JWT cutover): opaque session tokens are gone —
-- RS256 access tokens are the only credential and refresh tokens live in
-- refresh_tokens (000003). The sessions table has no readers or writers left.
DROP TABLE IF EXISTS sessions;
