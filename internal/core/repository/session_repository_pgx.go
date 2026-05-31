package repository

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/duynhlab/auth-service/internal/core/domain"
)

// PgxSessionRepository implements domain.SessionRepository using pgxpool.
type PgxSessionRepository struct {
	pool *pgxpool.Pool
}

// NewSessionRepository creates a new PgxSessionRepository.
func NewSessionRepository(pool *pgxpool.Pool) *PgxSessionRepository {
	return &PgxSessionRepository{pool: pool}
}

// Delete revokes a session by token. Idempotent — no error if the token is absent.
func (r *PgxSessionRepository) Delete(ctx context.Context, token string) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM sessions WHERE token = $1`, token)
	return err
}

// Create inserts a new session for the given user.
func (r *PgxSessionRepository) Create(ctx context.Context, userID int, token string, expiresAt time.Time) error {
	query := `INSERT INTO sessions (user_id, token, expires_at) VALUES ($1, $2, $3)`
	_, err := r.pool.Exec(ctx, query, userID, token, expiresAt)
	return err
}

// GetUserByToken looks up the session by token and returns the associated
// user data together with the session expiry time.
// Returns (nil, nil) when the token does not match any session.
func (r *PgxSessionRepository) GetUserByToken(ctx context.Context, token string) (*domain.SessionRow, error) {
	query := `
		SELECT u.id, u.username, u.email, s.expires_at
		FROM sessions s
		JOIN users u ON s.user_id = u.id
		WHERE s.token = $1
	`

	var row domain.SessionRow
	err := r.pool.QueryRow(ctx, query, token).Scan(
		&row.UserID, &row.Username, &row.Email, &row.ExpiresAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	return &row, nil
}
