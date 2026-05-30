// Package testutil provides shared, hand-rolled mocks for the auth-service
// repository interfaces. The func-field style lets each test configure only the
// behaviour it cares about; unset fields return zero values (nil, nil).
//
// This package is imported only by _test files, so it is not linked into the
// production binary.
package testutil

import (
	"context"
	"time"

	"github.com/duynhne/auth-service/internal/core/domain"
)

// MockUserRepository is a configurable domain.UserRepository for tests.
type MockUserRepository struct {
	GetByUsernameFunc           func(ctx context.Context, username string) (*domain.UserRow, error)
	ExistsByUsernameOrEmailFunc func(ctx context.Context, username, email string) (bool, error)
	CreateFunc                  func(ctx context.Context, username, email, passwordHash string) (int, error)
	UpdateLastLoginFunc         func(ctx context.Context, userID int) error
}

var _ domain.UserRepository = (*MockUserRepository)(nil)

func (m *MockUserRepository) GetByUsername(ctx context.Context, username string) (*domain.UserRow, error) {
	if m.GetByUsernameFunc != nil {
		return m.GetByUsernameFunc(ctx, username)
	}
	return nil, nil
}

func (m *MockUserRepository) ExistsByUsernameOrEmail(ctx context.Context, username, email string) (bool, error) {
	if m.ExistsByUsernameOrEmailFunc != nil {
		return m.ExistsByUsernameOrEmailFunc(ctx, username, email)
	}
	return false, nil
}

func (m *MockUserRepository) Create(ctx context.Context, username, email, passwordHash string) (int, error) {
	if m.CreateFunc != nil {
		return m.CreateFunc(ctx, username, email, passwordHash)
	}
	return 0, nil
}

func (m *MockUserRepository) UpdateLastLogin(ctx context.Context, userID int) error {
	if m.UpdateLastLoginFunc != nil {
		return m.UpdateLastLoginFunc(ctx, userID)
	}
	return nil
}

// MockSessionRepository is a configurable domain.SessionRepository for tests.
type MockSessionRepository struct {
	CreateFunc         func(ctx context.Context, userID int, token string, expiresAt time.Time) error
	GetUserByTokenFunc func(ctx context.Context, token string) (*domain.SessionRow, error)
}

var _ domain.SessionRepository = (*MockSessionRepository)(nil)

func (m *MockSessionRepository) Create(ctx context.Context, userID int, token string, expiresAt time.Time) error {
	if m.CreateFunc != nil {
		return m.CreateFunc(ctx, userID, token, expiresAt)
	}
	return nil
}

func (m *MockSessionRepository) GetUserByToken(ctx context.Context, token string) (*domain.SessionRow, error) {
	if m.GetUserByTokenFunc != nil {
		return m.GetUserByTokenFunc(ctx, token)
	}
	return nil, nil
}
