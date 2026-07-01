package v1

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/duynhlab/auth-service/internal/core/domain"
	authjwt "github.com/duynhlab/auth-service/internal/core/jwt"
	"github.com/duynhlab/auth-service/middleware"
	"github.com/google/uuid"
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

// hashToken returns the sha256 hex digest of an opaque token. Only the hash is
// persisted, so a database leak cannot reveal usable refresh tokens.
func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// newRefreshToken returns a cryptographically-random opaque refresh token
// alongside its sha256 hex hash. It reads 32 bytes from crypto/rand and
// base64.RawURLEncoding-encodes them (like newSessionToken).
func newRefreshToken() (raw, hash string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("generate refresh token: %w", err)
	}
	raw = base64.RawURLEncoding.EncodeToString(b)
	return raw, hashToken(raw), nil
}

// AuthService implements authentication business rules.
// It depends on repository interfaces (injected via constructor) and
// MUST NOT access the database or SQL directly.
type AuthService struct {
	users         domain.UserRepository
	sessions      domain.SessionRepository
	refreshTokens domain.RefreshTokenRepository
	signer        *authjwt.Signer
	refreshTTL    time.Duration
}

// NewAuthService creates a new AuthService with the given repository
// dependencies. signer may be nil, in which case no signed access token is
// minted (the opaque session token is still issued). refreshTokens may be nil,
// in which case no refresh token is issued (opaque + access still returned).
func NewAuthService(
	users domain.UserRepository,
	sessions domain.SessionRepository,
	refreshTokens domain.RefreshTokenRepository,
	signer *authjwt.Signer,
	refreshTTL time.Duration,
) *AuthService {
	return &AuthService{
		users:         users,
		sessions:      sessions,
		refreshTokens: refreshTokens,
		signer:        signer,
		refreshTTL:    refreshTTL,
	}
}

// issueRefresh mints a new opaque refresh token for the user, persists its hash
// in the given family, and returns the raw token to hand back to the caller.
func (s *AuthService) issueRefresh(ctx context.Context, userID int, familyID string) (string, error) {
	raw, hash, err := newRefreshToken()
	if err != nil {
		return "", err
	}
	if err := s.refreshTokens.Create(ctx, userID, hash, familyID, time.Now().Add(s.refreshTTL)); err != nil {
		return "", fmt.Errorf("create refresh token: %w", err)
	}
	return raw, nil
}

// issueRefreshBestEffort attaches a new refresh token (in a fresh family) to
// response when a refresh repository is configured. It is best-effort: on error
// it records the span error and leaves the response untouched, so a refresh
// failure never fails login/registration.
func (s *AuthService) issueRefreshBestEffort(ctx context.Context, span trace.Span, response *domain.AuthResponse, userID int) {
	if s.refreshTokens == nil {
		return
	}
	raw, err := s.issueRefresh(ctx, userID, uuid.NewString())
	if err != nil {
		span.RecordError(err)
		return
	}
	response.RefreshToken = raw
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

	// Issue a rotating refresh token in a fresh family. Best-effort — a refresh
	// failure must not fail the login.
	s.issueRefreshBestEffort(ctx, span, response, row.ID)

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

	// Issue a rotating refresh token in a fresh family. Best-effort.
	s.issueRefreshBestEffort(ctx, span, response, userID)

	span.SetAttributes(
		attribute.String("user.id", user.ID),
		attribute.Bool("registration.success", true),
	)
	span.AddEvent("user.registered")

	return response, nil
}

// handleReuse handles a detected refresh-token reuse (a replayed already-used
// token, or a lost atomic rotation race): it revokes the whole family and
// returns ErrRefreshReuse (401). If the revoke itself fails it records the span
// error and returns a wrapped plain error (500) instead — a failed revoke must
// be loud, never a silent 401 that leaves a compromised family live.
func (s *AuthService) handleReuse(ctx context.Context, span trace.Span, familyID string) error {
	span.SetAttributes(attribute.Bool("refresh.reuse", true))
	span.AddEvent("refresh.reuse_detected")
	if revErr := s.refreshTokens.RevokeFamily(ctx, familyID); revErr != nil {
		span.RecordError(fmt.Errorf("revoke refresh family: %w", revErr))
		return fmt.Errorf("revoke refresh family %q: %w", familyID, revErr)
	}
	return fmt.Errorf("refresh token reuse in family %q: %w", familyID, ErrRefreshReuse)
}

// Refresh rotates a refresh token: it validates the presented opaque token,
// rotates it within its family, and returns a fresh access token + refresh token.
//
// Reuse-detection: presenting an already-rotated token means it was replayed
// (likely stolen), so the entire family is revoked and ErrRefreshReuse returned.
// Unknown or expired tokens return ErrRefreshInvalid. No new opaque session
// token is issued on refresh.
func (s *AuthService) Refresh(ctx context.Context, rawRefreshToken string) (*domain.AuthResponse, error) {
	ctx, span := middleware.StartSpan(ctx, "auth.refresh", trace.WithAttributes(
		attribute.String("layer", "logic"),
	))
	defer span.End()

	if s.signer == nil {
		return nil, errors.New("refresh unavailable: no signer configured")
	}

	hash := hashToken(rawRefreshToken)

	row, err := s.refreshTokens.GetByHash(ctx, hash)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("query refresh token: %w", err)
	}
	if row == nil {
		span.SetAttributes(attribute.Bool("refresh.valid", false))
		return nil, fmt.Errorf("lookup refresh token: %w", ErrRefreshInvalid)
	}

	if time.Now().After(row.ExpiresAt) {
		span.SetAttributes(attribute.Bool("refresh.valid", false))
		return nil, fmt.Errorf("refresh token expired at %v: %w", row.ExpiresAt, ErrRefreshInvalid)
	}

	// Reuse detection: a token already rotated (used_at set) is being replayed.
	// Treat as theft and revoke the whole family.
	if row.UsedAt != nil {
		return nil, s.handleReuse(ctx, span, row.FamilyID)
	}

	// Rotate atomically: claim the presented token and insert its successor in
	// the SAME family within one transaction. A failed claim (claimed=false)
	// means the token was concurrently rotated or replayed — treat as reuse.
	newRaw, newHash, err := newRefreshToken()
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("generate refresh token: %w", err)
	}

	claimed, err := s.refreshTokens.Rotate(ctx, hash, newHash, row.FamilyID, row.UserID, time.Now().Add(s.refreshTTL))
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("rotate refresh token: %w", err)
	}
	if !claimed {
		return nil, s.handleReuse(ctx, span, row.FamilyID)
	}

	access, expiresIn, err := s.signer.MintAccess(strconv.Itoa(row.UserID), row.Username, row.Email)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("mint access token: %w", err)
	}

	span.SetAttributes(
		attribute.String("user.id", strconv.Itoa(row.UserID)),
		attribute.Bool("refresh.valid", true),
	)
	span.AddEvent("refresh.rotated")

	return &domain.AuthResponse{
		AccessToken:  access,
		RefreshToken: newRaw,
		ExpiresIn:    expiresIn,
		User: domain.User{
			ID:       strconv.Itoa(row.UserID),
			Username: row.Username,
			Email:    row.Email,
		},
	}, nil
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
