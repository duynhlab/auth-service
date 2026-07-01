-- =============================================================================
-- Auth Service - Demo Seed Data (DEV ONLY)
-- =============================================================================
-- Purpose: Demo users for local/dev/demo environments only.
-- Applied ONLY by the `seed` subcommand — NEVER by `migrate` or the serve path,
-- so production databases are never seeded with these accounts.
-- Note: Password for all users is "password123" (bcrypt hashed).
-- Plaintext demo session tokens were intentionally dropped — sessions are minted
-- at login time; seeding raw tokens is a credential-leak liability.
-- =============================================================================

-- Password hash: bcrypt of "password123"
-- Generated with: bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
INSERT INTO users (id, username, email, password_hash, created_at, last_login) VALUES
    (1, 'alice', 'alice@example.com', '$2a$10$J22gaM8P6seq9BEc9fRoye/6mc8aaCwm.KS27BmmWN5afiF.cGTrK', NOW() - INTERVAL '30 days', NOW() - INTERVAL '1 hour'),
    (2, 'bob', 'bob@example.com', '$2a$10$J22gaM8P6seq9BEc9fRoye/6mc8aaCwm.KS27BmmWN5afiF.cGTrK', NOW() - INTERVAL '25 days', NOW() - INTERVAL '2 hours'),
    (3, 'carol', 'carol@example.com', '$2a$10$J22gaM8P6seq9BEc9fRoye/6mc8aaCwm.KS27BmmWN5afiF.cGTrK', NOW() - INTERVAL '20 days', NOW() - INTERVAL '3 days'),
    (4, 'david', 'david@example.com', '$2a$10$J22gaM8P6seq9BEc9fRoye/6mc8aaCwm.KS27BmmWN5afiF.cGTrK', NOW() - INTERVAL '15 days', NOW() - INTERVAL '1 day'),
    (5, 'eve', 'eve@example.com', '$2a$10$J22gaM8P6seq9BEc9fRoye/6mc8aaCwm.KS27BmmWN5afiF.cGTrK', NOW() - INTERVAL '60 days', NOW() - INTERVAL '30 days')
ON CONFLICT (email) DO NOTHING;

-- Realign the sequence to MAX(id): the seed rows use explicit ids, so without
-- this the first app INSERT collides on the primary key.
SELECT setval('users_id_seq', (SELECT MAX(id) FROM users));
