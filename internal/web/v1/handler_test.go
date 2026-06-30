package v1

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/duynhlab/auth-service/internal/core/domain"
	authjwt "github.com/duynhlab/auth-service/internal/core/jwt"
	logicv1 "github.com/duynhlab/auth-service/internal/logic/v1"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

func init() { gin.SetMode(gin.TestMode) }

// mockUserRepo is a configurable domain.UserRepository double for web tests.
type mockUserRepo struct {
	user      *domain.UserRow
	getErr    error
	exists    bool
	existsErr error
	createID  int
	createErr error
}

func (m *mockUserRepo) GetByUsername(_ context.Context, _ string) (*domain.UserRow, error) {
	return m.user, m.getErr
}
func (m *mockUserRepo) ExistsByUsernameOrEmail(_ context.Context, _, _ string) (bool, error) {
	return m.exists, m.existsErr
}
func (m *mockUserRepo) Create(_ context.Context, _, _, _ string) (int, error) {
	return m.createID, m.createErr
}
func (m *mockUserRepo) UpdateLastLogin(_ context.Context, _ int) error { return nil }

// mockSessionRepo is a configurable domain.SessionRepository double for web tests.
type mockSessionRepo struct {
	session   *domain.SessionRow
	getErr    error
	createErr error
	deleteErr error
}

func (m *mockSessionRepo) Create(_ context.Context, _ int, _ string, _ time.Time) error {
	return m.createErr
}
func (m *mockSessionRepo) GetUserByToken(_ context.Context, _ string) (*domain.SessionRow, error) {
	return m.session, m.getErr
}
func (m *mockSessionRepo) Delete(_ context.Context, _ string) error { return m.deleteErr }

func newHandler(users domain.UserRepository, sessions domain.SessionRepository) *Handler {
	return NewHandler(logicv1.NewAuthService(users, sessions, nil))
}

func newCtx(method, target, body string, hdr map[string]string) (*gin.Context, *httptest.ResponseRecorder) {
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(method, target, strings.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		c.Request.Header.Set(k, v)
	}
	return c, rec
}

// decode returns the parsed JSON body for code assertions.
func decode(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var b map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
		t.Fatalf("invalid JSON body %q: %v", rec.Body.String(), err)
	}
	return b
}

func bcryptHash(t *testing.T, pw string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	return string(h)
}

// --- Login ---

func TestLogin_BadJSON(t *testing.T) {
	c, rec := newCtx(http.MethodPost, "/auth/v1/public/login", "{", nil)
	newHandler(&mockUserRepo{}, &mockSessionRepo{}).Login(c)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if code := decode(t, rec)["code"]; code != "VALIDATION_ERROR" {
		t.Errorf("code = %v, want VALIDATION_ERROR", code)
	}
}

func TestLogin_InvalidCredentials(t *testing.T) {
	users := &mockUserRepo{user: &domain.UserRow{ID: 1, Username: "alice", PasswordHash: bcryptHash(t, "correct")}}
	c, rec := newCtx(http.MethodPost, "/auth/v1/public/login",
		`{"username":"alice","password":"wrong"}`, nil)
	newHandler(users, &mockSessionRepo{}).Login(c)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if code := decode(t, rec)["code"]; code != "UNAUTHORIZED" {
		t.Errorf("code = %v, want UNAUTHORIZED", code)
	}
}

func TestLogin_UserNotFound(t *testing.T) {
	c, rec := newCtx(http.MethodPost, "/auth/v1/public/login",
		`{"username":"ghost","password":"whatever"}`, nil)
	newHandler(&mockUserRepo{user: nil}, &mockSessionRepo{}).Login(c)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if code := decode(t, rec)["code"]; code != "UNAUTHORIZED" {
		t.Errorf("code = %v, want UNAUTHORIZED", code)
	}
}

func TestLogin_ServiceError(t *testing.T) {
	users := &mockUserRepo{getErr: context.DeadlineExceeded}
	c, rec := newCtx(http.MethodPost, "/auth/v1/public/login",
		`{"username":"alice","password":"pw"}`, nil)
	newHandler(users, &mockSessionRepo{}).Login(c)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if code := decode(t, rec)["code"]; code != "INTERNAL_ERROR" {
		t.Errorf("code = %v, want INTERNAL_ERROR", code)
	}
}

func TestLogin_Success(t *testing.T) {
	users := &mockUserRepo{user: &domain.UserRow{ID: 1, Username: "alice", Email: "a@x.io", PasswordHash: bcryptHash(t, "password123")}}
	c, rec := newCtx(http.MethodPost, "/auth/v1/public/login",
		`{"username":"alice","password":"password123"}`, nil)
	newHandler(users, &mockSessionRepo{}).Login(c)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if _, ok := decode(t, rec)["token"]; !ok {
		t.Errorf("response missing token: %s", rec.Body.String())
	}
}

// --- Register ---

func TestRegister_BadJSON(t *testing.T) {
	c, rec := newCtx(http.MethodPost, "/auth/v1/public/register", "{", nil)
	newHandler(&mockUserRepo{}, &mockSessionRepo{}).Register(c)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if code := decode(t, rec)["code"]; code != "VALIDATION_ERROR" {
		t.Errorf("code = %v, want VALIDATION_ERROR", code)
	}
}

func TestRegister_Conflict(t *testing.T) {
	users := &mockUserRepo{exists: true}
	c, rec := newCtx(http.MethodPost, "/auth/v1/public/register",
		`{"username":"alice","email":"a@x.io","password":"password123"}`, nil)
	newHandler(users, &mockSessionRepo{}).Register(c)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
	if code := decode(t, rec)["code"]; code != "CONFLICT" {
		t.Errorf("code = %v, want CONFLICT", code)
	}
}

func TestRegister_ServiceError(t *testing.T) {
	users := &mockUserRepo{existsErr: context.DeadlineExceeded}
	c, rec := newCtx(http.MethodPost, "/auth/v1/public/register",
		`{"username":"alice","email":"a@x.io","password":"password123"}`, nil)
	newHandler(users, &mockSessionRepo{}).Register(c)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if code := decode(t, rec)["code"]; code != "INTERNAL_ERROR" {
		t.Errorf("code = %v, want INTERNAL_ERROR", code)
	}
}

func TestRegister_Success(t *testing.T) {
	users := &mockUserRepo{exists: false, createID: 42}
	c, rec := newCtx(http.MethodPost, "/auth/v1/public/register",
		`{"username":"alice","email":"a@x.io","password":"password123"}`, nil)
	newHandler(users, &mockSessionRepo{}).Register(c)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", rec.Code, rec.Body.String())
	}
	if _, ok := decode(t, rec)["token"]; !ok {
		t.Errorf("response missing token: %s", rec.Body.String())
	}
}

// --- GetMe ---

func TestGetMe_NoHeader(t *testing.T) {
	c, rec := newCtx(http.MethodGet, "/auth/v1/private/me", "", nil)
	newHandler(&mockUserRepo{}, &mockSessionRepo{}).GetMe(c)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if code := decode(t, rec)["code"]; code != "UNAUTHORIZED" {
		t.Errorf("code = %v, want UNAUTHORIZED", code)
	}
}

func TestGetMe_BadFormat(t *testing.T) {
	c, rec := newCtx(http.MethodGet, "/auth/v1/private/me", "", map[string]string{"Authorization": "token"})
	newHandler(&mockUserRepo{}, &mockSessionRepo{}).GetMe(c)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if code := decode(t, rec)["code"]; code != "UNAUTHORIZED" {
		t.Errorf("code = %v, want UNAUTHORIZED", code)
	}
}

func TestGetMe_SessionNotFound(t *testing.T) {
	c, rec := newCtx(http.MethodGet, "/auth/v1/private/me", "", map[string]string{"Authorization": "Bearer tok"})
	newHandler(&mockUserRepo{}, &mockSessionRepo{session: nil}).GetMe(c)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if code := decode(t, rec)["code"]; code != "UNAUTHORIZED" {
		t.Errorf("code = %v, want UNAUTHORIZED", code)
	}
}

func TestGetMe_SessionExpired(t *testing.T) {
	sessions := &mockSessionRepo{session: &domain.SessionRow{UserID: 1, ExpiresAt: time.Now().Add(-time.Hour)}}
	c, rec := newCtx(http.MethodGet, "/auth/v1/private/me", "", map[string]string{"Authorization": "Bearer tok"})
	newHandler(&mockUserRepo{}, sessions).GetMe(c)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if code := decode(t, rec)["code"]; code != "UNAUTHORIZED" {
		t.Errorf("code = %v, want UNAUTHORIZED", code)
	}
}

func TestGetMe_ServiceError(t *testing.T) {
	sessions := &mockSessionRepo{getErr: context.DeadlineExceeded}
	c, rec := newCtx(http.MethodGet, "/auth/v1/private/me", "", map[string]string{"Authorization": "Bearer tok"})
	newHandler(&mockUserRepo{}, sessions).GetMe(c)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if code := decode(t, rec)["code"]; code != "INTERNAL_ERROR" {
		t.Errorf("code = %v, want INTERNAL_ERROR", code)
	}
}

func TestGetMe_Success(t *testing.T) {
	sessions := &mockSessionRepo{session: &domain.SessionRow{UserID: 7, Username: "alice", Email: "a@x.io", ExpiresAt: time.Now().Add(time.Hour)}}
	c, rec := newCtx(http.MethodGet, "/auth/v1/private/me", "", map[string]string{"Authorization": "Bearer tok"})
	newHandler(&mockUserRepo{}, sessions).GetMe(c)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if body := decode(t, rec); body["username"] != "alice" {
		t.Errorf("username = %v, want alice", body["username"])
	}
}

// --- Logout ---

func TestLogout_BadFormat(t *testing.T) {
	c, rec := newCtx(http.MethodPost, "/auth/v1/private/logout", "", map[string]string{"Authorization": "token"})
	newHandler(&mockUserRepo{}, &mockSessionRepo{}).Logout(c)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if code := decode(t, rec)["code"]; code != "UNAUTHORIZED" {
		t.Errorf("code = %v, want UNAUTHORIZED", code)
	}
}

func TestLogout_ServiceError(t *testing.T) {
	sessions := &mockSessionRepo{deleteErr: context.DeadlineExceeded}
	c, rec := newCtx(http.MethodPost, "/auth/v1/private/logout", "", map[string]string{"Authorization": "Bearer tok"})
	newHandler(&mockUserRepo{}, sessions).Logout(c)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if code := decode(t, rec)["code"]; code != "INTERNAL_ERROR" {
		t.Errorf("code = %v, want INTERNAL_ERROR", code)
	}
}

func TestLogout_Success(t *testing.T) {
	c, rec := newCtx(http.MethodPost, "/auth/v1/private/logout", "", map[string]string{"Authorization": "Bearer tok"})
	newHandler(&mockUserRepo{}, &mockSessionRepo{}).Logout(c)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
}

// --- JWKS ---

func TestJWKS_NoSigner(t *testing.T) {
	c, rec := newCtx(http.MethodGet, "/auth/v1/public/jwks", "", nil)
	newHandler(&mockUserRepo{}, &mockSessionRepo{}).JWKS(c)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if code := decode(t, rec)["code"]; code != "NOT_FOUND" {
		t.Errorf("code = %v, want NOT_FOUND", code)
	}
}

func TestJWKS_WithSigner(t *testing.T) {
	signer, _, err := authjwt.NewSigner("", "iss", "aud", time.Hour)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	h := NewHandler(logicv1.NewAuthService(&mockUserRepo{}, &mockSessionRepo{}, signer))

	c, rec := newCtx(http.MethodGet, "/auth/v1/public/jwks", "", nil)
	h.JWKS(c)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type = %q, want application/json", ct)
	}
	body := decode(t, rec)
	if _, ok := body["keys"]; !ok {
		t.Errorf("expected 'keys' in JWKS body, got %v", body)
	}
}
