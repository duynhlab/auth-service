package v1

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/duynhlab/auth-service/internal/core/domain"
	"golang.org/x/crypto/bcrypt"
)

// errRepo is a shared sentinel used to assert error propagation from the
// repository layer through the logic layer.
var errRepo = errors.New("repository failure")

// fakeUserRepository is a configurable in-memory test double for
// domain.UserRepository. Each field overrides the behaviour of the matching
// method; zero values yield successful no-op results.
type fakeUserRepository struct {
	getByUsername func(ctx context.Context, username string) (*domain.UserRow, error)
	existsByUOE   func(ctx context.Context, username, email string) (bool, error)
	create        func(ctx context.Context, username, email, passwordHash string) (int, error)
	updateLast    func(ctx context.Context, userID int) error

	updateLastCalls int
	createdHash     string
}

func (f *fakeUserRepository) GetByUsername(ctx context.Context, username string) (*domain.UserRow, error) {
	if f.getByUsername != nil {
		return f.getByUsername(ctx, username)
	}
	return nil, nil
}

func (f *fakeUserRepository) ExistsByUsernameOrEmail(ctx context.Context, username, email string) (bool, error) {
	if f.existsByUOE != nil {
		return f.existsByUOE(ctx, username, email)
	}
	return false, nil
}

func (f *fakeUserRepository) Create(ctx context.Context, username, email, passwordHash string) (int, error) {
	f.createdHash = passwordHash
	if f.create != nil {
		return f.create(ctx, username, email, passwordHash)
	}
	return 0, nil
}

func (f *fakeUserRepository) UpdateLastLogin(ctx context.Context, userID int) error {
	f.updateLastCalls++
	if f.updateLast != nil {
		return f.updateLast(ctx, userID)
	}
	return nil
}

// fakeSessionRepository is a configurable in-memory test double for
// domain.SessionRepository.
type fakeSessionRepository struct {
	create         func(ctx context.Context, userID int, token string, expiresAt time.Time) error
	getUserByToken func(ctx context.Context, token string) (*domain.SessionRow, error)
	del            func(ctx context.Context, token string) error

	createCalls int
}

func (f *fakeSessionRepository) Create(ctx context.Context, userID int, token string, expiresAt time.Time) error {
	f.createCalls++
	if f.create != nil {
		return f.create(ctx, userID, token, expiresAt)
	}
	return nil
}

func (f *fakeSessionRepository) GetUserByToken(ctx context.Context, token string) (*domain.SessionRow, error) {
	if f.getUserByToken != nil {
		return f.getUserByToken(ctx, token)
	}
	return nil, nil
}

func (f *fakeSessionRepository) Delete(ctx context.Context, token string) error {
	if f.del != nil {
		return f.del(ctx, token)
	}
	return nil
}

// hashPassword is a test helper producing a bcrypt hash for a known password.
func hashPassword(t *testing.T, password string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	return string(h)
}

func TestAuthService_Login(t *testing.T) {
	const password = "password123"
	validRow := &domain.UserRow{
		ID:           7,
		Username:     "alice",
		Email:        "alice@example.com",
		PasswordHash: hashPassword(t, password),
	}

	tests := []struct {
		name        string
		users       *fakeUserRepository
		sessions    *fakeSessionRepository
		req         domain.LoginRequest
		wantErr     error
		wantUserID  string
		wantUpdates int
		wantSession int
	}{
		{
			name: "success returns token and user",
			users: &fakeUserRepository{
				getByUsername: func(_ context.Context, _ string) (*domain.UserRow, error) {
					return validRow, nil
				},
			},
			sessions:    &fakeSessionRepository{},
			req:         domain.LoginRequest{Username: "alice", Password: password},
			wantUserID:  "7",
			wantUpdates: 1,
			wantSession: 1,
		},
		{
			name: "user not found is ErrUserNotFound",
			users: &fakeUserRepository{
				getByUsername: func(_ context.Context, _ string) (*domain.UserRow, error) {
					return nil, nil
				},
			},
			sessions: &fakeSessionRepository{},
			req:      domain.LoginRequest{Username: "ghost", Password: password},
			wantErr:  ErrUserNotFound,
		},
		{
			name: "repository error is propagated",
			users: &fakeUserRepository{
				getByUsername: func(_ context.Context, _ string) (*domain.UserRow, error) {
					return nil, errRepo
				},
			},
			sessions: &fakeSessionRepository{},
			req:      domain.LoginRequest{Username: "alice", Password: password},
			wantErr:  errRepo,
		},
		{
			name: "wrong password is ErrInvalidCredentials",
			users: &fakeUserRepository{
				getByUsername: func(_ context.Context, _ string) (*domain.UserRow, error) {
					return validRow, nil
				},
			},
			sessions: &fakeSessionRepository{},
			req:      domain.LoginRequest{Username: "alice", Password: "wrong"},
			wantErr:  ErrInvalidCredentials,
		},
		{
			name: "best-effort last-login error does not fail login",
			users: &fakeUserRepository{
				getByUsername: func(_ context.Context, _ string) (*domain.UserRow, error) {
					return validRow, nil
				},
				updateLast: func(_ context.Context, _ int) error { return errRepo },
			},
			sessions:    &fakeSessionRepository{},
			req:         domain.LoginRequest{Username: "alice", Password: password},
			wantUserID:  "7",
			wantUpdates: 1,
			wantSession: 1,
		},
		{
			name: "best-effort session error does not fail login",
			users: &fakeUserRepository{
				getByUsername: func(_ context.Context, _ string) (*domain.UserRow, error) {
					return validRow, nil
				},
			},
			sessions: &fakeSessionRepository{
				create: func(_ context.Context, _ int, _ string, _ time.Time) error { return errRepo },
			},
			req:         domain.LoginRequest{Username: "alice", Password: password},
			wantUserID:  "7",
			wantUpdates: 1,
			wantSession: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := NewAuthService(tt.users, tt.sessions)

			resp, err := svc.Login(context.Background(), tt.req)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Login() error = %v, want wrapping %v", err, tt.wantErr)
				}
				if resp != nil {
					t.Errorf("expected nil response on error, got %+v", resp)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp == nil {
				t.Fatal("expected response, got nil")
			}
			if resp.Token == "" {
				t.Error("expected non-empty session token")
			}
			if resp.User.ID != tt.wantUserID {
				t.Errorf("user ID = %q, want %q", resp.User.ID, tt.wantUserID)
			}
			if tt.users.updateLastCalls != tt.wantUpdates {
				t.Errorf("UpdateLastLogin calls = %d, want %d", tt.users.updateLastCalls, tt.wantUpdates)
			}
			if tt.sessions.createCalls != tt.wantSession {
				t.Errorf("session Create calls = %d, want %d", tt.sessions.createCalls, tt.wantSession)
			}
		})
	}
}

func TestAuthService_Register(t *testing.T) {
	tests := []struct {
		name        string
		users       *fakeUserRepository
		sessions    *fakeSessionRepository
		req         domain.RegisterRequest
		wantErr     error
		wantUserID  string
		wantSession int
	}{
		{
			name: "success creates user and session",
			users: &fakeUserRepository{
				create: func(_ context.Context, _, _, _ string) (int, error) { return 42, nil },
			},
			sessions:    &fakeSessionRepository{},
			req:         domain.RegisterRequest{Username: "bob", Email: "bob@example.com", Password: "secret1"},
			wantUserID:  "42",
			wantSession: 1,
		},
		{
			name: "existing user is ErrUserExists",
			users: &fakeUserRepository{
				existsByUOE: func(_ context.Context, _, _ string) (bool, error) { return true, nil },
			},
			sessions: &fakeSessionRepository{},
			req:      domain.RegisterRequest{Username: "bob", Email: "bob@example.com", Password: "secret1"},
			wantErr:  ErrUserExists,
		},
		{
			name: "exists-check error is propagated",
			users: &fakeUserRepository{
				existsByUOE: func(_ context.Context, _, _ string) (bool, error) { return false, errRepo },
			},
			sessions: &fakeSessionRepository{},
			req:      domain.RegisterRequest{Username: "bob", Email: "bob@example.com", Password: "secret1"},
			wantErr:  errRepo,
		},
		{
			name: "create error is propagated",
			users: &fakeUserRepository{
				create: func(_ context.Context, _, _, _ string) (int, error) { return 0, errRepo },
			},
			sessions: &fakeSessionRepository{},
			req:      domain.RegisterRequest{Username: "bob", Email: "bob@example.com", Password: "secret1"},
			wantErr:  errRepo,
		},
		{
			name: "best-effort session error does not fail register",
			users: &fakeUserRepository{
				create: func(_ context.Context, _, _, _ string) (int, error) { return 42, nil },
			},
			sessions: &fakeSessionRepository{
				create: func(_ context.Context, _ int, _ string, _ time.Time) error { return errRepo },
			},
			req:         domain.RegisterRequest{Username: "bob", Email: "bob@example.com", Password: "secret1"},
			wantUserID:  "42",
			wantSession: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := NewAuthService(tt.users, tt.sessions)

			resp, err := svc.Register(context.Background(), tt.req)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Register() error = %v, want wrapping %v", err, tt.wantErr)
				}
				if resp != nil {
					t.Errorf("expected nil response on error, got %+v", resp)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp == nil {
				t.Fatal("expected response, got nil")
			}
			if resp.Token == "" {
				t.Error("expected non-empty session token")
			}
			if resp.User.ID != tt.wantUserID {
				t.Errorf("user ID = %q, want %q", resp.User.ID, tt.wantUserID)
			}
			if resp.User.Username != tt.req.Username || resp.User.Email != tt.req.Email {
				t.Errorf("user = %+v, want username=%q email=%q", resp.User, tt.req.Username, tt.req.Email)
			}
			if tt.users.createdHash == tt.req.Password {
				t.Error("password was stored in plaintext; expected a bcrypt hash")
			}
			if tt.sessions.createCalls != tt.wantSession {
				t.Errorf("session Create calls = %d, want %d", tt.sessions.createCalls, tt.wantSession)
			}
		})
	}
}

func TestAuthService_GetUserByToken(t *testing.T) {
	tests := []struct {
		name       string
		sessions   *fakeSessionRepository
		wantErr    error
		wantUserID string
	}{
		{
			name: "valid session returns user",
			sessions: &fakeSessionRepository{
				getUserByToken: func(_ context.Context, _ string) (*domain.SessionRow, error) {
					return &domain.SessionRow{
						UserID:    7,
						Username:  "alice",
						Email:     "alice@example.com",
						ExpiresAt: time.Now().Add(time.Hour),
					}, nil
				},
			},
			wantUserID: "7",
		},
		{
			name: "missing session is ErrSessionNotFound",
			sessions: &fakeSessionRepository{
				getUserByToken: func(_ context.Context, _ string) (*domain.SessionRow, error) {
					return nil, nil
				},
			},
			wantErr: ErrSessionNotFound,
		},
		{
			name: "expired session is ErrSessionExpired",
			sessions: &fakeSessionRepository{
				getUserByToken: func(_ context.Context, _ string) (*domain.SessionRow, error) {
					return &domain.SessionRow{
						UserID:    7,
						Username:  "alice",
						Email:     "alice@example.com",
						ExpiresAt: time.Now().Add(-time.Hour),
					}, nil
				},
			},
			wantErr: ErrSessionExpired,
		},
		{
			name: "repository error is propagated",
			sessions: &fakeSessionRepository{
				getUserByToken: func(_ context.Context, _ string) (*domain.SessionRow, error) {
					return nil, errRepo
				},
			},
			wantErr: errRepo,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := NewAuthService(&fakeUserRepository{}, tt.sessions)

			user, err := svc.GetUserByToken(context.Background(), "some-token")

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("GetUserByToken() error = %v, want wrapping %v", err, tt.wantErr)
				}
				if user != nil {
					t.Errorf("expected nil user on error, got %+v", user)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if user == nil {
				t.Fatal("expected user, got nil")
			}
			if user.ID != tt.wantUserID {
				t.Errorf("user ID = %q, want %q", user.ID, tt.wantUserID)
			}
		})
	}
}

func TestAuthService_Logout(t *testing.T) {
	tests := []struct {
		name     string
		sessions *fakeSessionRepository
		wantErr  bool
	}{
		{
			name:     "successful revocation returns no error",
			sessions: &fakeSessionRepository{},
		},
		{
			name: "repository error is propagated",
			sessions: &fakeSessionRepository{
				del: func(_ context.Context, _ string) error { return errRepo },
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := NewAuthService(&fakeUserRepository{}, tt.sessions)

			err := svc.Logout(context.Background(), "some-token")

			if tt.wantErr {
				if !errors.Is(err, errRepo) {
					t.Fatalf("Logout() error = %v, want wrapping %v", err, errRepo)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}
