package v1

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/duynhne/auth-service/internal/core/domain"
	"github.com/duynhne/auth-service/internal/testutil"
	"golang.org/x/crypto/bcrypt"
)

// errRepo is a stand-in repository error used to assert error propagation.
var errRepo = errors.New("repo boom")

// hashFor returns a bcrypt hash of pw using the same cost the service uses.
func hashFor(t *testing.T, pw string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("bcrypt hash: %v", err)
	}
	return string(h)
}

func TestAuthService_Login(t *testing.T) {
	t.Parallel()

	const username, password = "alice", "password123"
	validHash := hashFor(t, password)

	tests := []struct {
		name       string
		users      *testutil.MockUserRepository
		sessions   *testutil.MockSessionRepository
		wantErr    error // sentinel expected via errors.Is; nil means success
		wantToken  bool
		wantUserID string
	}{
		{
			name: "success",
			users: &testutil.MockUserRepository{
				GetByUsernameFunc: func(_ context.Context, _ string) (*domain.UserRow, error) {
					return &domain.UserRow{ID: 1, Username: username, Email: "a@x.io", PasswordHash: validHash}, nil
				},
			},
			sessions:   &testutil.MockSessionRepository{},
			wantToken:  true,
			wantUserID: "1",
		},
		{
			name: "wrong password",
			users: &testutil.MockUserRepository{
				GetByUsernameFunc: func(_ context.Context, _ string) (*domain.UserRow, error) {
					return &domain.UserRow{ID: 1, Username: username, PasswordHash: hashFor(t, "different")}, nil
				},
			},
			sessions: &testutil.MockSessionRepository{},
			wantErr:  ErrInvalidCredentials,
		},
		{
			name: "unknown user",
			users: &testutil.MockUserRepository{
				GetByUsernameFunc: func(_ context.Context, _ string) (*domain.UserRow, error) {
					return nil, nil // not found
				},
			},
			sessions: &testutil.MockSessionRepository{},
			wantErr:  ErrUserNotFound,
		},
		{
			name: "repository error",
			users: &testutil.MockUserRepository{
				GetByUsernameFunc: func(_ context.Context, _ string) (*domain.UserRow, error) {
					return nil, errRepo
				},
			},
			sessions: &testutil.MockSessionRepository{},
			wantErr:  errRepo,
		},
		{
			name: "session create failure is best-effort and still succeeds",
			users: &testutil.MockUserRepository{
				GetByUsernameFunc: func(_ context.Context, _ string) (*domain.UserRow, error) {
					return &domain.UserRow{ID: 7, Username: username, PasswordHash: validHash}, nil
				},
			},
			sessions: &testutil.MockSessionRepository{
				CreateFunc: func(_ context.Context, _ int, _ string, _ time.Time) error { return errRepo },
			},
			wantToken:  true,
			wantUserID: "7",
		},
		{
			name: "update last login failure is best-effort and still succeeds",
			users: &testutil.MockUserRepository{
				GetByUsernameFunc: func(_ context.Context, _ string) (*domain.UserRow, error) {
					return &domain.UserRow{ID: 9, Username: username, PasswordHash: validHash}, nil
				},
				UpdateLastLoginFunc: func(_ context.Context, _ int) error { return errRepo },
			},
			sessions:   &testutil.MockSessionRepository{},
			wantToken:  true,
			wantUserID: "9",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			svc := NewAuthService(tt.users, tt.sessions)
			resp, err := svc.Login(context.Background(), domain.LoginRequest{Username: username, Password: password})

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Login() error = %v, want errors.Is(%v)", err, tt.wantErr)
				}
				if resp != nil {
					t.Errorf("Login() resp = %v, want nil on error", resp)
				}
				return
			}
			if err != nil {
				t.Fatalf("Login() unexpected error: %v", err)
			}
			if tt.wantToken && resp.Token == "" {
				t.Error("Login() token is empty, want non-empty")
			}
			if resp.User.ID != tt.wantUserID {
				t.Errorf("Login() user.ID = %q, want %q", resp.User.ID, tt.wantUserID)
			}
			if resp.User.Password != "" {
				t.Errorf("Login() leaked password field: %q", resp.User.Password)
			}
		})
	}
}

func TestAuthService_Register(t *testing.T) {
	t.Parallel()

	req := domain.RegisterRequest{Username: "bob", Email: "bob@x.io", Password: "password123"}

	tests := []struct {
		name       string
		users      *testutil.MockUserRepository
		wantErr    error
		wantUserID string
	}{
		{
			name: "success",
			users: &testutil.MockUserRepository{
				CreateFunc: func(_ context.Context, _, _, _ string) (int, error) { return 42, nil },
			},
			wantUserID: "42",
		},
		{
			name: "user already exists",
			users: &testutil.MockUserRepository{
				ExistsByUsernameOrEmailFunc: func(_ context.Context, _, _ string) (bool, error) { return true, nil },
			},
			wantErr: ErrUserExists,
		},
		{
			name: "exists check error",
			users: &testutil.MockUserRepository{
				ExistsByUsernameOrEmailFunc: func(_ context.Context, _, _ string) (bool, error) { return false, errRepo },
			},
			wantErr: errRepo,
		},
		{
			name: "create error",
			users: &testutil.MockUserRepository{
				CreateFunc: func(_ context.Context, _, _, _ string) (int, error) { return 0, errRepo },
			},
			wantErr: errRepo,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			svc := NewAuthService(tt.users, &testutil.MockSessionRepository{})
			resp, err := svc.Register(context.Background(), req)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Register() error = %v, want errors.Is(%v)", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Register() unexpected error: %v", err)
			}
			if resp.Token == "" {
				t.Error("Register() token is empty")
			}
			if resp.User.ID != tt.wantUserID {
				t.Errorf("Register() user.ID = %q, want %q", resp.User.ID, tt.wantUserID)
			}
		})
	}
}

func TestAuthService_GetUserByToken(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		sessions *testutil.MockSessionRepository
		wantErr  error
		wantID   string
	}{
		{
			name: "valid session",
			sessions: &testutil.MockSessionRepository{
				GetUserByTokenFunc: func(_ context.Context, _ string) (*domain.SessionRow, error) {
					return &domain.SessionRow{UserID: 3, Username: "carol", Email: "c@x.io", ExpiresAt: time.Now().Add(time.Hour)}, nil
				},
			},
			wantID: "3",
		},
		{
			name: "expired session",
			sessions: &testutil.MockSessionRepository{
				GetUserByTokenFunc: func(_ context.Context, _ string) (*domain.SessionRow, error) {
					return &domain.SessionRow{UserID: 3, ExpiresAt: time.Now().Add(-time.Hour)}, nil
				},
			},
			wantErr: ErrSessionExpired,
		},
		{
			name: "token not found",
			sessions: &testutil.MockSessionRepository{
				GetUserByTokenFunc: func(_ context.Context, _ string) (*domain.SessionRow, error) { return nil, nil },
			},
			wantErr: ErrSessionNotFound,
		},
		{
			name: "repository error",
			sessions: &testutil.MockSessionRepository{
				GetUserByTokenFunc: func(_ context.Context, _ string) (*domain.SessionRow, error) { return nil, errRepo },
			},
			wantErr: errRepo,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			svc := NewAuthService(&testutil.MockUserRepository{}, tt.sessions)
			user, err := svc.GetUserByToken(context.Background(), "tok")

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("GetUserByToken() error = %v, want errors.Is(%v)", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("GetUserByToken() unexpected error: %v", err)
			}
			if user.ID != tt.wantID {
				t.Errorf("GetUserByToken() user.ID = %q, want %q", user.ID, tt.wantID)
			}
		})
	}
}

func TestNewSessionToken(t *testing.T) {
	t.Parallel()

	tok, err := newSessionToken()
	if err != nil {
		t.Fatalf("newSessionToken() error: %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil {
		t.Fatalf("token is not valid base64url: %v", err)
	}
	if len(raw) != 32 {
		t.Errorf("token decodes to %d bytes, want 32 (256 bits of entropy)", len(raw))
	}

	other, _ := newSessionToken()
	if tok == other {
		t.Error("two tokens are identical; generator is not random")
	}
}

func BenchmarkNewSessionToken(b *testing.B) {
	for b.Loop() {
		if _, err := newSessionToken(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGetUserByToken(b *testing.B) {
	sessions := &testutil.MockSessionRepository{
		GetUserByTokenFunc: func(_ context.Context, _ string) (*domain.SessionRow, error) {
			return &domain.SessionRow{UserID: 1, Username: "alice", Email: "a@x.io", ExpiresAt: time.Now().Add(time.Hour)}, nil
		},
	}
	svc := NewAuthService(&testutil.MockUserRepository{}, sessions)
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := svc.GetUserByToken(ctx, "tok"); err != nil {
			b.Fatal(err)
		}
	}
}
