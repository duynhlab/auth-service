package repository

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/duynhlab/auth-service/internal/core/domain"
)

// PgxRefreshTokenRepository implements domain.RefreshTokenRepository using pgxpool.
type PgxRefreshTokenRepository struct {
	pool *pgxpool.Pool
}

// NewRefreshTokenRepository creates a new PgxRefreshTokenRepository.
func NewRefreshTokenRepository(pool *pgxpool.Pool) *PgxRefreshTokenRepository {
	return &PgxRefreshTokenRepository{pool: pool}
}

// Create inserts a new refresh token for the given user in the given family.
func (r *PgxRefreshTokenRepository) Create(ctx context.Context, userID int, tokenHash, familyID string, expiresAt time.Time) error {
	query := `INSERT INTO refresh_tokens (user_id, token_hash, family_id, expires_at) VALUES ($1, $2, $3, $4)`
	_, err := r.pool.Exec(ctx, query, userID, tokenHash, familyID, expiresAt)
	return err
}

// GetByHash looks up a refresh token by its hash and returns the associated
// user data together with the family, used-at, and expiry timestamps.
// Returns (nil, nil) when the hash does not match any refresh token.
func (r *PgxRefreshTokenRepository) GetByHash(ctx context.Context, tokenHash string) (*domain.RefreshTokenRow, error) {
	query := `
		SELECT u.id, u.username, u.email, rt.family_id, rt.used_at, rt.expires_at
		FROM refresh_tokens rt
		JOIN users u ON rt.user_id = u.id
		WHERE rt.token_hash = $1
	`

	var row domain.RefreshTokenRow
	err := r.pool.QueryRow(ctx, query, tokenHash).Scan(
		&row.UserID, &row.Username, &row.Email, &row.FamilyID, &row.UsedAt, &row.ExpiresAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	return &row, nil
}

// Rotate atomically claims oldHash (only if still unused) and, on success,
// inserts newHash in the same family — both in one transaction. Returns
// claimed=false (inserting nothing) when oldHash was already used or absent
// (a concurrent or replayed use).
func (r *PgxRefreshTokenRepository) Rotate(ctx context.Context, oldHash, newHash, familyID string, userID int, expiresAt time.Time) (bool, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after commit
	ct, err := tx.Exec(ctx, `UPDATE refresh_tokens SET used_at = now() WHERE token_hash = $1 AND used_at IS NULL`, oldHash)
	if err != nil {
		return false, err
	}
	if ct.RowsAffected() == 0 {
		return false, nil // already claimed/absent
	}
	if _, err := tx.Exec(ctx, `INSERT INTO refresh_tokens (user_id, token_hash, family_id, expires_at) VALUES ($1,$2,$3,$4)`, userID, newHash, familyID, expiresAt); err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return true, nil
}

// RevokeFamily deletes all refresh tokens in the given family. Idempotent — no
// error if the family has no rows.
func (r *PgxRefreshTokenRepository) RevokeFamily(ctx context.Context, familyID string) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM refresh_tokens WHERE family_id = $1`, familyID)
	return err
}
