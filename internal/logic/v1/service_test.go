package v1

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"testing/iotest"
	"time"

	"github.com/duynhlab/auth-service/internal/core/domain"
	authjwt "github.com/duynhlab/auth-service/internal/core/jwt"
	"golang.org/x/crypto/bcrypt"
)

// errRepo is a shared sentinel used to assert error propagation from the
// repository layer through the logic layer.
var errRepo = errors.New("repository failure")

// newTestSigner builds a Signer with an ephemeral key for logic-layer tests.
func newTestSigner(t *testing.T) *authjwt.Signer {
	t.Helper()
	s, _, err := authjwt.NewSigner("", "iss", "aud", time.Hour)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	return s
}

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

// fakeRefreshTokenRepository is a configurable in-memory test double for
// domain.RefreshTokenRepository.
type fakeRefreshTokenRepository struct {
	create    func(ctx context.Context, userID int, tokenHash, familyID string, expiresAt time.Time) error
	getByHash func(ctx context.Context, tokenHash string) (*domain.RefreshTokenRow, error)
	rotate    func(ctx context.Context, oldHash, newHash, familyID string, userID int, expiresAt time.Time) (bool, error)
	revoke    func(ctx context.Context, familyID string) error
	created   []string // token hashes passed to Create
	rotated   []string // old token hashes passed to Rotate
	revoked   []string // family IDs passed to RevokeFamily
}

func (f *fakeRefreshTokenRepository) Create(ctx context.Context, userID int, tokenHash, familyID string, expiresAt time.Time) error {
	f.created = append(f.created, tokenHash)
	if f.create != nil {
		return f.create(ctx, userID, tokenHash, familyID, expiresAt)
	}
	return nil
}

func (f *fakeRefreshTokenRepository) GetByHash(ctx context.Context, tokenHash string) (*domain.RefreshTokenRow, error) {
	if f.getByHash != nil {
		return f.getByHash(ctx, tokenHash)
	}
	return nil, nil
}

func (f *fakeRefreshTokenRepository) Rotate(ctx context.Context, oldHash, newHash, familyID string, userID int, expiresAt time.Time) (bool, error) {
	f.rotated = append(f.rotated, oldHash)
	if f.rotate != nil {
		return f.rotate(ctx, oldHash, newHash, familyID, userID, expiresAt)
	}
	return true, nil
}

func (f *fakeRefreshTokenRepository) RevokeFamily(ctx context.Context, familyID string) error {
	f.revoked = append(f.revoked, familyID)
	if f.revoke != nil {
		return f.revoke(ctx, familyID)
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
		req         domain.LoginRequest
		wantErr     error
		wantUserID  string
		wantUpdates int
	}{
		{
			name: "success returns access token and user",
			users: &fakeUserRepository{
				getByUsername: func(_ context.Context, _ string) (*domain.UserRow, error) {
					return validRow, nil
				},
			},
			req:         domain.LoginRequest{Username: "alice", Password: password},
			wantUserID:  "7",
			wantUpdates: 1,
		},
		{
			name: "user not found is ErrUserNotFound",
			users: &fakeUserRepository{
				getByUsername: func(_ context.Context, _ string) (*domain.UserRow, error) {
					return nil, nil
				},
			},
			req:     domain.LoginRequest{Username: "ghost", Password: password},
			wantErr: ErrUserNotFound,
		},
		{
			name: "repository error is propagated",
			users: &fakeUserRepository{
				getByUsername: func(_ context.Context, _ string) (*domain.UserRow, error) {
					return nil, errRepo
				},
			},
			req:     domain.LoginRequest{Username: "alice", Password: password},
			wantErr: errRepo,
		},
		{
			name: "wrong password is ErrInvalidCredentials",
			users: &fakeUserRepository{
				getByUsername: func(_ context.Context, _ string) (*domain.UserRow, error) {
					return validRow, nil
				},
			},
			req:     domain.LoginRequest{Username: "alice", Password: "wrong"},
			wantErr: ErrInvalidCredentials,
		},
		{
			name: "best-effort last-login error does not fail login",
			users: &fakeUserRepository{
				getByUsername: func(_ context.Context, _ string) (*domain.UserRow, error) {
					return validRow, nil
				},
				updateLast: func(_ context.Context, _ int) error { return errRepo },
			},
			req:         domain.LoginRequest{Username: "alice", Password: password},
			wantUserID:  "7",
			wantUpdates: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := NewAuthService(tt.users, nil, newTestSigner(t), 0)

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
			if resp.AccessToken == "" {
				t.Error("expected non-empty access token")
			}
			if resp.User.ID != tt.wantUserID {
				t.Errorf("user ID = %q, want %q", resp.User.ID, tt.wantUserID)
			}
			if tt.users.updateLastCalls != tt.wantUpdates {
				t.Errorf("UpdateLastLogin calls = %d, want %d", tt.users.updateLastCalls, tt.wantUpdates)
			}
		})
	}
}

func TestAuthService_Register(t *testing.T) {
	tests := []struct {
		name       string
		users      *fakeUserRepository
		req        domain.RegisterRequest
		wantErr    error
		wantUserID string
	}{
		{
			name: "success creates user and mints access token",
			users: &fakeUserRepository{
				create: func(_ context.Context, _, _, _ string) (int, error) { return 42, nil },
			},
			req:        domain.RegisterRequest{Username: "bob", Email: "bob@example.com", Password: "secret1"},
			wantUserID: "42",
		},
		{
			name: "existing user is ErrUserExists",
			users: &fakeUserRepository{
				existsByUOE: func(_ context.Context, _, _ string) (bool, error) { return true, nil },
			},
			req:     domain.RegisterRequest{Username: "bob", Email: "bob@example.com", Password: "secret1"},
			wantErr: ErrUserExists,
		},
		{
			name: "exists-check error is propagated",
			users: &fakeUserRepository{
				existsByUOE: func(_ context.Context, _, _ string) (bool, error) { return false, errRepo },
			},
			req:     domain.RegisterRequest{Username: "bob", Email: "bob@example.com", Password: "secret1"},
			wantErr: errRepo,
		},
		{
			name: "create error is propagated",
			users: &fakeUserRepository{
				create: func(_ context.Context, _, _, _ string) (int, error) { return 0, errRepo },
			},
			req:     domain.RegisterRequest{Username: "bob", Email: "bob@example.com", Password: "secret1"},
			wantErr: errRepo,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := NewAuthService(tt.users, nil, newTestSigner(t), 0)

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
			if resp.AccessToken == "" {
				t.Error("expected non-empty access token")
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
		})
	}
}

func TestAuthService_Logout(t *testing.T) {
	const family = "fam-logout"
	row := &domain.RefreshTokenRow{
		UserID:    7,
		FamilyID:  family,
		ExpiresAt: time.Now().Add(time.Hour),
	}

	tests := []struct {
		name        string
		refresh     *fakeRefreshTokenRepository
		wantErr     error
		wantRevoked []string
	}{
		{
			name: "known token revokes its family",
			refresh: &fakeRefreshTokenRepository{
				getByHash: func(_ context.Context, _ string) (*domain.RefreshTokenRow, error) { return row, nil },
			},
			wantRevoked: []string{family},
		},
		{
			name: "unknown token is idempotent success",
			refresh: &fakeRefreshTokenRepository{
				getByHash: func(_ context.Context, _ string) (*domain.RefreshTokenRow, error) { return nil, nil },
			},
			wantRevoked: nil,
		},
		{
			name: "expired token still revokes its family",
			refresh: &fakeRefreshTokenRepository{
				getByHash: func(_ context.Context, _ string) (*domain.RefreshTokenRow, error) {
					expired := *row
					expired.ExpiresAt = time.Now().Add(-time.Hour)
					return &expired, nil
				},
			},
			wantRevoked: []string{family},
		},
		{
			name: "lookup error is propagated",
			refresh: &fakeRefreshTokenRepository{
				getByHash: func(_ context.Context, _ string) (*domain.RefreshTokenRow, error) { return nil, errRepo },
			},
			wantErr: errRepo,
		},
		{
			name: "revoke error is propagated",
			refresh: &fakeRefreshTokenRepository{
				getByHash: func(_ context.Context, _ string) (*domain.RefreshTokenRow, error) { return row, nil },
				revoke:    func(_ context.Context, _ string) error { return errRepo },
			},
			wantErr:     errRepo,
			wantRevoked: []string{family},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := NewAuthService(&fakeUserRepository{}, tt.refresh, newTestSigner(t), time.Hour)

			err := svc.Logout(context.Background(), "raw-refresh-token")

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Logout() error = %v, want wrapping %v", err, tt.wantErr)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(tt.refresh.revoked) != len(tt.wantRevoked) {
				t.Fatalf("RevokeFamily calls = %v, want %v", tt.refresh.revoked, tt.wantRevoked)
			}
			for i := range tt.wantRevoked {
				if tt.refresh.revoked[i] != tt.wantRevoked[i] {
					t.Errorf("RevokeFamily[%d] = %q, want %q", i, tt.refresh.revoked[i], tt.wantRevoked[i])
				}
			}
		})
	}

	t.Run("nil refresh repository is a no-op", func(t *testing.T) {
		svc := NewAuthService(&fakeUserRepository{}, nil, newTestSigner(t), time.Hour)
		if err := svc.Logout(context.Background(), "x"); err != nil {
			t.Errorf("unexpected error with nil repo: %v", err)
		}
	})
}

func TestAuthService_MintMandatory(t *testing.T) {
	const password = "password123"
	validRow := &domain.UserRow{
		ID:           7,
		Username:     "alice",
		Email:        "alice@example.com",
		PasswordHash: hashPassword(t, password),
	}

	t.Run("login mints access token and expiry", func(t *testing.T) {
		users := &fakeUserRepository{
			getByUsername: func(_ context.Context, _ string) (*domain.UserRow, error) { return validRow, nil },
		}
		svc := NewAuthService(users, nil, newTestSigner(t), 0)

		resp, err := svc.Login(context.Background(), domain.LoginRequest{Username: "alice", Password: password})
		if err != nil {
			t.Fatalf("Login: %v", err)
		}
		if resp.AccessToken == "" {
			t.Error("expected non-empty access token")
		}
		if resp.ExpiresIn != int(time.Hour.Seconds()) {
			t.Errorf("ExpiresIn = %d, want %d", resp.ExpiresIn, int(time.Hour.Seconds()))
		}
	})

	t.Run("login fails when signer nil (access token is the only credential)", func(t *testing.T) {
		users := &fakeUserRepository{
			getByUsername: func(_ context.Context, _ string) (*domain.UserRow, error) { return validRow, nil },
		}
		svc := NewAuthService(users, nil, nil, 0)

		if _, err := svc.Login(context.Background(), domain.LoginRequest{Username: "alice", Password: password}); err == nil {
			t.Error("expected error with nil signer, got nil")
		}
	})

	t.Run("register fails when signer nil", func(t *testing.T) {
		users := &fakeUserRepository{
			create: func(_ context.Context, _, _, _ string) (int, error) { return 42, nil },
		}
		svc := NewAuthService(users, nil, nil, 0)

		if _, err := svc.Register(context.Background(), domain.RegisterRequest{
			Username: "bob", Email: "bob@example.com", Password: "secret1",
		}); err == nil {
			t.Error("expected error with nil signer, got nil")
		}
	})
}

func TestAuthService_JWKS(t *testing.T) {
	t.Run("returns body when signer present", func(t *testing.T) {
		svc := NewAuthService(&fakeUserRepository{}, nil, newTestSigner(t), 0)
		body, err := svc.JWKS()
		if err != nil {
			t.Fatalf("JWKS: %v", err)
		}
		if len(body) == 0 {
			t.Error("expected non-empty JWKS body")
		}
	})

	t.Run("errors when signer nil", func(t *testing.T) {
		svc := NewAuthService(&fakeUserRepository{}, nil, nil, 0)
		if _, err := svc.JWKS(); err == nil {
			t.Error("expected error with nil signer, got nil")
		}
	})
}

func TestAuthService_IssueRefreshOnLoginRegister(t *testing.T) {
	const password = "password123"
	validRow := &domain.UserRow{
		ID:           7,
		Username:     "alice",
		Email:        "alice@example.com",
		PasswordHash: hashPassword(t, password),
	}

	t.Run("login sets refresh token when repo present", func(t *testing.T) {
		users := &fakeUserRepository{
			getByUsername: func(_ context.Context, _ string) (*domain.UserRow, error) { return validRow, nil },
		}
		refresh := &fakeRefreshTokenRepository{}
		svc := NewAuthService(users, refresh, newTestSigner(t), time.Hour)

		resp, err := svc.Login(context.Background(), domain.LoginRequest{Username: "alice", Password: password})
		if err != nil {
			t.Fatalf("Login: %v", err)
		}
		if resp.RefreshToken == "" {
			t.Error("expected non-empty refresh token with refresh repo present")
		}
		if len(refresh.created) != 1 {
			t.Errorf("refresh Create calls = %d, want 1", len(refresh.created))
		}
	})

	t.Run("login leaves refresh token empty when repo nil", func(t *testing.T) {
		users := &fakeUserRepository{
			getByUsername: func(_ context.Context, _ string) (*domain.UserRow, error) { return validRow, nil },
		}
		svc := NewAuthService(users, nil, newTestSigner(t), time.Hour)

		resp, err := svc.Login(context.Background(), domain.LoginRequest{Username: "alice", Password: password})
		if err != nil {
			t.Fatalf("Login: %v", err)
		}
		if resp.RefreshToken != "" {
			t.Errorf("expected empty refresh token with nil repo, got %q", resp.RefreshToken)
		}
	})

	t.Run("login best-effort refresh error does not fail login", func(t *testing.T) {
		users := &fakeUserRepository{
			getByUsername: func(_ context.Context, _ string) (*domain.UserRow, error) { return validRow, nil },
		}
		refresh := &fakeRefreshTokenRepository{
			create: func(_ context.Context, _ int, _, _ string, _ time.Time) error { return errRepo },
		}
		svc := NewAuthService(users, refresh, newTestSigner(t), time.Hour)

		resp, err := svc.Login(context.Background(), domain.LoginRequest{Username: "alice", Password: password})
		if err != nil {
			t.Fatalf("Login must not fail on refresh error: %v", err)
		}
		if resp.RefreshToken != "" {
			t.Errorf("expected empty refresh token on create error, got %q", resp.RefreshToken)
		}
		if resp.AccessToken == "" {
			t.Error("access token must still be issued")
		}
	})

	t.Run("register sets refresh token when repo present", func(t *testing.T) {
		users := &fakeUserRepository{
			create: func(_ context.Context, _, _, _ string) (int, error) { return 42, nil },
		}
		refresh := &fakeRefreshTokenRepository{}
		svc := NewAuthService(users, refresh, newTestSigner(t), time.Hour)

		resp, err := svc.Register(context.Background(), domain.RegisterRequest{
			Username: "bob", Email: "bob@example.com", Password: "secret1",
		})
		if err != nil {
			t.Fatalf("Register: %v", err)
		}
		if resp.RefreshToken == "" {
			t.Error("expected non-empty refresh token with refresh repo present")
		}
		if len(refresh.created) != 1 {
			t.Errorf("refresh Create calls = %d, want 1", len(refresh.created))
		}
	})

	t.Run("register leaves refresh token empty when repo nil", func(t *testing.T) {
		users := &fakeUserRepository{
			create: func(_ context.Context, _, _, _ string) (int, error) { return 42, nil },
		}
		svc := NewAuthService(users, nil, newTestSigner(t), time.Hour)

		resp, err := svc.Register(context.Background(), domain.RegisterRequest{
			Username: "bob", Email: "bob@example.com", Password: "secret1",
		})
		if err != nil {
			t.Fatalf("Register: %v", err)
		}
		if resp.RefreshToken != "" {
			t.Errorf("expected empty refresh token with nil repo, got %q", resp.RefreshToken)
		}
	})
}

func TestAuthService_Refresh(t *testing.T) {
	t.Run("happy path rotates token and mints new pair", func(t *testing.T) {
		const family = "fam-1"
		row := &domain.RefreshTokenRow{
			UserID:    7,
			Username:  "alice",
			Email:     "alice@example.com",
			FamilyID:  family,
			UsedAt:    nil,
			ExpiresAt: time.Now().Add(time.Hour),
		}
		refresh := &fakeRefreshTokenRepository{
			getByHash: func(_ context.Context, _ string) (*domain.RefreshTokenRow, error) { return row, nil },
			rotate: func(_ context.Context, _, _, _ string, _ int, _ time.Time) (bool, error) {
				return true, nil
			},
		}
		svc := NewAuthService(&fakeUserRepository{}, refresh, newTestSigner(t), time.Hour)

		resp, err := svc.Refresh(context.Background(), "raw-refresh-token")
		if err != nil {
			t.Fatalf("Refresh: %v", err)
		}
		if resp.AccessToken == "" {
			t.Error("expected new access token")
		}
		if resp.RefreshToken == "" {
			t.Error("expected new refresh token")
		}
		if resp.User.ID != "7" || resp.User.Username != "alice" || resp.User.Email != "alice@example.com" {
			t.Errorf("unexpected user %+v", resp.User)
		}
		// Claim + insert happen atomically inside Rotate (no separate Create).
		if len(refresh.rotated) != 1 {
			t.Errorf("Rotate calls = %d, want 1 (old token atomically claimed)", len(refresh.rotated))
		}
		if len(refresh.created) != 0 {
			t.Errorf("Create calls = %d, want 0 (insert folded into Rotate)", len(refresh.created))
		}
		if len(refresh.revoked) != 0 {
			t.Errorf("RevokeFamily calls = %d, want 0 on happy path", len(refresh.revoked))
		}
	})

	t.Run("nil refresh repository fails closed without panic", func(t *testing.T) {
		svc := NewAuthService(&fakeUserRepository{}, nil, newTestSigner(t), time.Hour)
		if _, err := svc.Refresh(context.Background(), "raw-refresh-token"); !errors.Is(err, ErrRefreshInvalid) {
			t.Errorf("err = %v, want ErrRefreshInvalid", err)
		}
	})

	t.Run("lost rotation race (claimed=false) revokes family and returns ErrRefreshReuse", func(t *testing.T) {
		const family = "fam-race"
		row := &domain.RefreshTokenRow{
			UserID:    7,
			Username:  "alice",
			Email:     "alice@example.com",
			FamilyID:  family,
			UsedAt:    nil,
			ExpiresAt: time.Now().Add(time.Hour),
		}
		refresh := &fakeRefreshTokenRepository{
			getByHash: func(_ context.Context, _ string) (*domain.RefreshTokenRow, error) { return row, nil },
			rotate: func(_ context.Context, _, _, _ string, _ int, _ time.Time) (bool, error) {
				return false, nil
			},
		}
		svc := NewAuthService(&fakeUserRepository{}, refresh, newTestSigner(t), time.Hour)

		resp, err := svc.Refresh(context.Background(), "raced")
		if !errors.Is(err, ErrRefreshReuse) {
			t.Fatalf("error = %v, want ErrRefreshReuse", err)
		}
		if resp != nil {
			t.Errorf("expected nil response on lost race, got %+v", resp)
		}
		if len(refresh.revoked) != 1 || refresh.revoked[0] != family {
			t.Errorf("RevokeFamily = %v, want [%q]", refresh.revoked, family)
		}
	})

	t.Run("reuse of used token revokes family and returns ErrRefreshReuse", func(t *testing.T) {
		used := time.Now().Add(-time.Minute)
		const family = "fam-2"
		row := &domain.RefreshTokenRow{
			UserID:    7,
			Username:  "alice",
			Email:     "alice@example.com",
			FamilyID:  family,
			UsedAt:    &used,
			ExpiresAt: time.Now().Add(time.Hour),
		}
		refresh := &fakeRefreshTokenRepository{
			getByHash: func(_ context.Context, _ string) (*domain.RefreshTokenRow, error) { return row, nil },
		}
		svc := NewAuthService(&fakeUserRepository{}, refresh, newTestSigner(t), time.Hour)

		resp, err := svc.Refresh(context.Background(), "replayed")
		if !errors.Is(err, ErrRefreshReuse) {
			t.Fatalf("error = %v, want ErrRefreshReuse", err)
		}
		if resp != nil {
			t.Errorf("expected nil response on reuse, got %+v", resp)
		}
		if len(refresh.revoked) != 1 || refresh.revoked[0] != family {
			t.Errorf("RevokeFamily = %v, want [%q]", refresh.revoked, family)
		}
	})

	t.Run("reuse with RevokeFamily error returns loud non-reuse error (500)", func(t *testing.T) {
		used := time.Now().Add(-time.Minute)
		row := &domain.RefreshTokenRow{
			UserID:    7,
			FamilyID:  "fam-err",
			UsedAt:    &used,
			ExpiresAt: time.Now().Add(time.Hour),
		}
		refresh := &fakeRefreshTokenRepository{
			getByHash: func(_ context.Context, _ string) (*domain.RefreshTokenRow, error) { return row, nil },
			revoke:    func(_ context.Context, _ string) error { return errRepo },
		}
		svc := NewAuthService(&fakeUserRepository{}, refresh, newTestSigner(t), time.Hour)

		_, err := svc.Refresh(context.Background(), "replayed")
		// A failed revoke must be loud (mapped to 500), NOT a silent 401 reuse.
		if !errors.Is(err, errRepo) {
			t.Fatalf("error = %v, want wrapping %v", err, errRepo)
		}
		if errors.Is(err, ErrRefreshReuse) {
			t.Errorf("error = %v, must NOT be ErrRefreshReuse when revoke fails", err)
		}
		if len(refresh.revoked) != 1 {
			t.Errorf("RevokeFamily calls = %d, want 1", len(refresh.revoked))
		}
	})

	t.Run("expired token returns ErrRefreshInvalid", func(t *testing.T) {
		row := &domain.RefreshTokenRow{
			UserID:    7,
			FamilyID:  "fam-3",
			ExpiresAt: time.Now().Add(-time.Hour),
		}
		refresh := &fakeRefreshTokenRepository{
			getByHash: func(_ context.Context, _ string) (*domain.RefreshTokenRow, error) { return row, nil },
		}
		svc := NewAuthService(&fakeUserRepository{}, refresh, newTestSigner(t), time.Hour)

		_, err := svc.Refresh(context.Background(), "expired")
		if !errors.Is(err, ErrRefreshInvalid) {
			t.Fatalf("error = %v, want ErrRefreshInvalid", err)
		}
	})

	t.Run("unknown token returns ErrRefreshInvalid", func(t *testing.T) {
		refresh := &fakeRefreshTokenRepository{
			getByHash: func(_ context.Context, _ string) (*domain.RefreshTokenRow, error) { return nil, nil },
		}
		svc := NewAuthService(&fakeUserRepository{}, refresh, newTestSigner(t), time.Hour)

		_, err := svc.Refresh(context.Background(), "unknown")
		if !errors.Is(err, ErrRefreshInvalid) {
			t.Fatalf("error = %v, want ErrRefreshInvalid", err)
		}
	})

	t.Run("repository error is propagated", func(t *testing.T) {
		refresh := &fakeRefreshTokenRepository{
			getByHash: func(_ context.Context, _ string) (*domain.RefreshTokenRow, error) { return nil, errRepo },
		}
		svc := NewAuthService(&fakeUserRepository{}, refresh, newTestSigner(t), time.Hour)

		_, err := svc.Refresh(context.Background(), "boom")
		if !errors.Is(err, errRepo) {
			t.Fatalf("error = %v, want wrapping %v", err, errRepo)
		}
	})

	t.Run("Rotate error is propagated during rotation", func(t *testing.T) {
		row := &domain.RefreshTokenRow{
			UserID:    7,
			FamilyID:  "fam-5",
			ExpiresAt: time.Now().Add(time.Hour),
		}
		refresh := &fakeRefreshTokenRepository{
			getByHash: func(_ context.Context, _ string) (*domain.RefreshTokenRow, error) { return row, nil },
			rotate: func(_ context.Context, _, _, _ string, _ int, _ time.Time) (bool, error) {
				return false, errRepo
			},
		}
		svc := NewAuthService(&fakeUserRepository{}, refresh, newTestSigner(t), time.Hour)

		_, err := svc.Refresh(context.Background(), "x")
		if !errors.Is(err, errRepo) {
			t.Fatalf("error = %v, want wrapping %v", err, errRepo)
		}
		// A Rotate error is not reuse — must not revoke and not be ErrRefreshReuse.
		if errors.Is(err, ErrRefreshReuse) {
			t.Errorf("error = %v, must NOT be ErrRefreshReuse on Rotate error", err)
		}
		if len(refresh.revoked) != 0 {
			t.Errorf("RevokeFamily calls = %d, want 0 on Rotate error", len(refresh.revoked))
		}
	})

	t.Run("nil signer returns error", func(t *testing.T) {
		refresh := &fakeRefreshTokenRepository{}
		svc := NewAuthService(&fakeUserRepository{}, refresh, nil, time.Hour)

		if _, err := svc.Refresh(context.Background(), "x"); err == nil {
			t.Error("expected error with nil signer, got nil")
		}
	})
}

func TestMustGenerateDummyHash(t *testing.T) {
	t.Run("produces a valid bcrypt hash from random input", func(t *testing.T) {
		input := bytes.Repeat([]byte{0xA5}, 32)
		h := mustGenerateDummyHash(bytes.NewReader(input))
		// The hash must verify against the exact input bytes...
		if err := bcrypt.CompareHashAndPassword(h, input); err != nil {
			t.Errorf("hash does not verify against its input: %v", err)
		}
		// ...and never against an arbitrary password guess.
		if err := bcrypt.CompareHashAndPassword(h, []byte("password123")); err == nil {
			t.Error("dummy hash unexpectedly matches a real-looking password")
		}
	})

	t.Run("panics when the random source fails", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Error("expected panic on reader failure")
			}
		}()
		mustGenerateDummyHash(iotest.ErrReader(errors.New("entropy exhausted")))
	})
}
