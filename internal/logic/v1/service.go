package v1

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/duynhlab/auth-service/internal/core/domain"
	authjwt "github.com/duynhlab/auth-service/internal/core/jwt"
	"github.com/duynhlab/auth-service/middleware"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/crypto/bcrypt"
)

// dummyHash is a bcrypt hash generated at startup — NOT a real credential. It
// equalizes Login response timing on the user-not-found path so authentication
// does not leak whether a username exists (CompareHashAndPassword runs in both
// branches). It is generated rather than hardcoded so no hash literal ships in
// the source; the input string is a throwaway placeholder, never a password.
var dummyHash = mustGenerateDummyHash()

func mustGenerateDummyHash() []byte {
	h, err := bcrypt.GenerateFromPassword([]byte("not-a-password-placeholder"), bcrypt.DefaultCost)
	if err != nil {
		panic("generate dummy bcrypt hash: " + err.Error())
	}
	return h
}

// newSessionToken returns a cryptographically-random opaque session token.
// It reads 32 bytes from crypto/rand and base64.RawURLEncoding-encodes them.
func newSessionToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate session token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// AuthService implements authentication business rules.
// It depends on repository interfaces (injected via constructor) and
// MUST NOT access the database or SQL directly.
type AuthService struct {
	users    domain.UserRepository
	sessions domain.SessionRepository
	signer   *authjwt.Signer
}

// NewAuthService creates a new AuthService with the given repository
// dependencies. signer may be nil, in which case no signed access token is
// minted (the opaque session token is still issued).
func NewAuthService(users domain.UserRepository, sessions domain.SessionRepository, signer *authjwt.Signer) *AuthService {
	return &AuthService{
		users:    users,
		sessions: sessions,
		signer:   signer,
	}
}

// Login handles user login business logic.
func (s *AuthService) Login(ctx context.Context, req domain.LoginRequest) (*domain.AuthResponse, error) {
	ctx, span := middleware.StartSpan(ctx, "auth.login", trace.WithAttributes(
		attribute.String("layer", "logic"),
		attribute.String("username", req.Username),
	))
	defer span.End()

	// Lookup user by username via repository
	row, err := s.users.GetByUsername(ctx, req.Username)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("query user %q: %w", req.Username, err)
	}
	if row == nil {
		// Run bcrypt against a dummy hash to equalize response timing with the
		// password-mismatch path, preventing username enumeration via timing.
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(req.Password))
		span.SetAttributes(attribute.Bool("auth.success", false))
		span.AddEvent("authentication.failed")
		return nil, fmt.Errorf("authenticate user %q: %w", req.Username, ErrUserNotFound)
	}

	// Verify password
	err = bcrypt.CompareHashAndPassword([]byte(row.PasswordHash), []byte(req.Password))
	if err != nil {
		span.SetAttributes(attribute.Bool("auth.success", false))
		span.AddEvent("authentication.failed")
		return nil, fmt.Errorf("authenticate user %q: %w", req.Username, ErrInvalidCredentials)
	}

	// Update last_login timestamp (best-effort, don't fail login)
	if updateErr := s.users.UpdateLastLogin(ctx, row.ID); updateErr != nil {
		span.RecordError(fmt.Errorf("update last_login: %w", updateErr))
	}

	// Create an opaque, cryptographically-random session token
	token, err := newSessionToken()
	if err != nil {
		span.RecordError(err)
		return nil, err
	}

	// Persist session (best-effort, don't fail login)
	expiresAt := time.Now().Add(24 * time.Hour)
	if sessErr := s.sessions.Create(ctx, row.ID, token, expiresAt); sessErr != nil {
		span.RecordError(fmt.Errorf("create session: %w", sessErr))
	}

	user := domain.User{
		ID:       strconv.Itoa(row.ID),
		Username: row.Username,
		Email:    row.Email,
	}

	response := &domain.AuthResponse{
		Token: token,
		User:  user,
	}

	// Dual-issue: mint a signed RS256 access token alongside the opaque token.
	// Best-effort — a mint failure must not fail the login.
	s.mintAccessToken(span, response)

	span.SetAttributes(
		attribute.String("user.id", user.ID),
		attribute.Bool("auth.success", true),
	)
	span.AddEvent("user.authenticated")

	return response, nil
}

// mintAccessToken adds a signed RS256 access token to response when a signer is
// configured. It is best-effort: on error it records the span error and leaves
// the opaque token untouched.
func (s *AuthService) mintAccessToken(span trace.Span, response *domain.AuthResponse) {
	if s.signer == nil {
		return
	}
	access, expiresIn, err := s.signer.MintAccess(response.User.ID, response.User.Username, response.User.Email)
	if err != nil {
		span.RecordError(fmt.Errorf("mint access token: %w", err))
		return
	}
	response.AccessToken = access
	response.ExpiresIn = expiresIn
}

// Register handles user registration business logic.
func (s *AuthService) Register(ctx context.Context, req domain.RegisterRequest) (*domain.AuthResponse, error) {
	ctx, span := middleware.StartSpan(ctx, "auth.register", trace.WithAttributes(
		attribute.String("layer", "logic"),
		attribute.String("username", req.Username),
		attribute.String("email", req.Email),
	))
	defer span.End()

	// Hash password
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("hash password: %w", err)
	}

	// Check if username or email already exists
	exists, err := s.users.ExistsByUsernameOrEmail(ctx, req.Username, req.Email)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("check existing user: %w", err)
	}
	if exists {
		span.SetAttributes(attribute.Bool("registration.success", false))
		return nil, fmt.Errorf("register user %q: %w", req.Username, ErrUserExists)
	}

	// Insert new user
	userID, err := s.users.Create(ctx, req.Username, req.Email, string(passwordHash))
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("insert user: %w", err)
	}

	// Create an opaque, cryptographically-random session token
	token, err := newSessionToken()
	if err != nil {
		span.RecordError(err)
		return nil, err
	}

	// Persist session (best-effort)
	expiresAt := time.Now().Add(24 * time.Hour)
	if sessErr := s.sessions.Create(ctx, userID, token, expiresAt); sessErr != nil {
		span.RecordError(fmt.Errorf("create session: %w", sessErr))
	}

	user := domain.User{
		ID:       strconv.Itoa(userID),
		Username: req.Username,
		Email:    req.Email,
	}

	response := &domain.AuthResponse{
		Token: token,
		User:  user,
	}

	// Dual-issue: mint a signed RS256 access token alongside the opaque token.
	s.mintAccessToken(span, response)

	span.SetAttributes(
		attribute.String("user.id", user.ID),
		attribute.Bool("registration.success", true),
	)
	span.AddEvent("user.registered")

	return response, nil
}

// JWKS returns the JSON Web Key Set for the access-token signing key. Returns an
// error when no signer is configured.
func (s *AuthService) JWKS() ([]byte, error) {
	if s.signer == nil {
		return nil, errors.New("JWKS unavailable: no signer configured")
	}
	return s.signer.JWKS()
}

// GetUserByToken retrieves user info from a session token (for /auth/me endpoint).
func (s *AuthService) GetUserByToken(ctx context.Context, token string) (*domain.User, error) {
	ctx, span := middleware.StartSpan(ctx, "auth.get_user_by_token", trace.WithAttributes(
		attribute.String("layer", "logic"),
	))
	defer span.End()

	row, err := s.sessions.GetUserByToken(ctx, token)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("query session: %w", err)
	}
	if row == nil {
		span.SetAttributes(attribute.Bool("session.valid", false))
		return nil, fmt.Errorf("lookup session: %w", ErrSessionNotFound)
	}

	// Check if session has expired
	if time.Now().After(row.ExpiresAt) {
		span.SetAttributes(attribute.Bool("session.valid", false))
		return nil, fmt.Errorf("session expired at %v: %w", row.ExpiresAt, ErrSessionExpired)
	}

	user := &domain.User{
		ID:       strconv.Itoa(row.UserID),
		Username: row.Username,
		Email:    row.Email,
	}

	span.SetAttributes(
		attribute.String("user.id", user.ID),
		attribute.Bool("session.valid", true),
	)

	return user, nil
}

// Logout revokes the session for the given opaque token. Idempotent: revoking a
// token that no longer exists is not an error.
func (s *AuthService) Logout(ctx context.Context, token string) error {
	ctx, span := middleware.StartSpan(ctx, "auth.logout", trace.WithAttributes(
		attribute.String("layer", "logic"),
	))
	defer span.End()

	if err := s.sessions.Delete(ctx, token); err != nil {
		span.RecordError(err)
		return fmt.Errorf("revoke session: %w", err)
	}
	span.AddEvent("session.revoked")
	return nil
}
