-- V3__fix_sequences.sql
-- Fix sequence desynchronization caused by seed data inserting explicit ids.
-- Without this, the first application INSERT (a login session, or a new user
-- registration) collides on the primary key because the *_id_seq still points
-- at 1 while the seeded rows already occupy higher ids.

-- Set the sequence for users table to the max id
SELECT setval('users_id_seq', (SELECT MAX(id) FROM users));

-- Set the sequence for sessions table to the max id
SELECT setval('sessions_id_seq', (SELECT MAX(id) FROM sessions));
