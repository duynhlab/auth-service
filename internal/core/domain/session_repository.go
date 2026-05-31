package domain

import (
	"context"
	"time"
)

// SessionRow represents a session joined with its owner user,
// returned by session lookup queries.
type SessionRow struct {
	UserID    int
	Username  string
	Email     string
	ExpiresAt time.Time
}

// SessionRepository defines the data-access contract for session operations.
// Implementations live in internal/core/repository (Core layer).
type SessionRepository interface {
	// Create inserts a new session for the given user.
	Create(ctx context.Context, userID int, token string, expiresAt time.Time) error

	// GetUserByToken looks up the session by token and returns the associated
	// user data together with the session expiry time.
	// Returns (nil, nil) when the token does not match any session.
	GetUserByToken(ctx context.Context, token string) (*SessionRow, error)

	// Delete revokes a session by token. It is idempotent: deleting a token that
	// does not exist is not an error.
	Delete(ctx context.Context, token string) error
}
