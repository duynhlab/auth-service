package repository

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/duynhlab/auth-service/internal/core/domain"
)

// PgxUserRepository implements domain.UserRepository using pgxpool.
type PgxUserRepository struct {
	pool *pgxpool.Pool
}

// NewUserRepository creates a new PgxUserRepository.
func NewUserRepository(pool *pgxpool.Pool) *PgxUserRepository {
	return &PgxUserRepository{pool: pool}
}

// GetByUsername returns the user matching the given username.
// Returns (nil, nil) when no user is found.
func (r *PgxUserRepository) GetByUsername(ctx context.Context, username string) (*domain.UserRow, error) {
	query := `SELECT id, username, email, password_hash FROM users WHERE username = $1`

	var row domain.UserRow
	err := r.pool.QueryRow(ctx, query, username).Scan(
		&row.ID, &row.Username, &row.Email, &row.PasswordHash,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	return &row, nil
}

// ExistsByUsernameOrEmail returns true when a user with the given
// username or email already exists.
func (r *PgxUserRepository) ExistsByUsernameOrEmail(ctx context.Context, username, email string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM users WHERE username = $1 OR email = $2)`

	var exists bool
	err := r.pool.QueryRow(ctx, query, username, email).Scan(&exists)
	if err != nil {
		return false, err
	}

	return exists, nil
}

// Create inserts a new user and returns the generated user ID.
func (r *PgxUserRepository) Create(ctx context.Context, username, email, passwordHash string) (int, error) {
	query := `INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id`

	var userID int
	err := r.pool.QueryRow(ctx, query, username, email, passwordHash).Scan(&userID)
	if err != nil {
		return 0, err
	}

	return userID, nil
}

// UpdateLastLogin sets the last_login timestamp to now for the given user.
func (r *PgxUserRepository) UpdateLastLogin(ctx context.Context, userID int) error {
	query := `UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1`
	_, err := r.pool.Exec(ctx, query, userID)
	return err
}
