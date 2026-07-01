package domain

import (
	"context"
	"time"
)

// RefreshTokenRow represents a refresh token joined with its owner user,
// returned by refresh-token lookup queries.
type RefreshTokenRow struct {
	UserID    int
	Username  string
	Email     string
	FamilyID  string
	UsedAt    *time.Time // NULL (nil) until the token is rotated
	ExpiresAt time.Time
}

// RefreshTokenRepository defines the data-access contract for refresh-token
// operations. Implementations live in internal/core/repository (Core layer).
//
// Refresh tokens are opaque, stored only as a sha256 hex hash, and rotate on
// use within a family. A replayed (already-used) token signals theft and the
// whole family must be revoked.
type RefreshTokenRepository interface {
	// Create inserts a new refresh token for the given user in the given family.
	Create(ctx context.Context, userID int, tokenHash, familyID string, expiresAt time.Time) error

	// GetByHash looks up a refresh token by its hash and returns the associated
	// user data together with the family, used-at, and expiry timestamps.
	// Returns (nil, nil) when the hash does not match any refresh token.
	GetByHash(ctx context.Context, tokenHash string) (*RefreshTokenRow, error)

	// Rotate atomically claims oldHash (only if still unused) and, on success,
	// inserts newHash in the same family — both in one transaction. Returns
	// claimed=false (inserting nothing) when oldHash was already used or absent
	// (a concurrent or replayed use).
	Rotate(ctx context.Context, oldHash, newHash, familyID string, userID int, expiresAt time.Time) (claimed bool, err error)

	// RevokeFamily deletes all refresh tokens in the given family. It is
	// idempotent: revoking a family with no rows is not an error.
	RevokeFamily(ctx context.Context, familyID string) error
}
