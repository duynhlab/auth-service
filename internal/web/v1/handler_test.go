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

// mockRefreshRepo is a configurable domain.RefreshTokenRepository double for web tests.
type mockRefreshRepo struct {
	row       *domain.RefreshTokenRow
	getErr    error
	createErr error
	rotate    func() (bool, error)
	revokeErr error
}

func (m *mockRefreshRepo) Create(_ context.Context, _ int, _, _ string, _ time.Time) error {
	return m.createErr
}
func (m *mockRefreshRepo) GetByHash(_ context.Context, _ string) (*domain.RefreshTokenRow, error) {
	return m.row, m.getErr
}
func (m *mockRefreshRepo) Rotate(_ context.Context, _, _, _ string, _ int, _ time.Time) (bool, error) {
	if m.rotate != nil {
		return m.rotate()
	}
	return true, nil
}
func (m *mockRefreshRepo) RevokeFamily(_ context.Context, _ string) error { return m.revokeErr }

// testSigner builds a Signer with an ephemeral key for handler tests — the
// access token is mandatory, so every handler needs one.
func testSigner(t *testing.T) *authjwt.Signer {
	t.Helper()
	signer, _, err := authjwt.NewSigner("", "iss", "aud", time.Hour)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	return signer
}

func newHandler(t *testing.T, users domain.UserRepository) *Handler {
	t.Helper()
	return NewHandler(logicv1.NewAuthService(users, nil, testSigner(t), 0))
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
	c, rec := newCtx(http.MethodPost, "/auth/v1/public/auth/login", "{", nil)
	newHandler(t, &mockUserRepo{}).Login(c)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if code := decode(t, rec)["code"]; code != "VALIDATION_ERROR" {
		t.Errorf("code = %v, want VALIDATION_ERROR", code)
	}
}

func TestLogin_InvalidCredentials(t *testing.T) {
	users := &mockUserRepo{user: &domain.UserRow{ID: 1, Username: "alice", PasswordHash: bcryptHash(t, "correct")}}
	c, rec := newCtx(http.MethodPost, "/auth/v1/public/auth/login",
		`{"username":"alice","password":"wrong"}`, nil)
	newHandler(t, users).Login(c)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if code := decode(t, rec)["code"]; code != "UNAUTHORIZED" {
		t.Errorf("code = %v, want UNAUTHORIZED", code)
	}
}

func TestLogin_UserNotFound(t *testing.T) {
	c, rec := newCtx(http.MethodPost, "/auth/v1/public/auth/login",
		`{"username":"ghost","password":"whatever"}`, nil)
	newHandler(t, &mockUserRepo{user: nil}).Login(c)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if code := decode(t, rec)["code"]; code != "UNAUTHORIZED" {
		t.Errorf("code = %v, want UNAUTHORIZED", code)
	}
}

func TestLogin_ServiceError(t *testing.T) {
	users := &mockUserRepo{getErr: context.DeadlineExceeded}
	c, rec := newCtx(http.MethodPost, "/auth/v1/public/auth/login",
		`{"username":"alice","password":"pw"}`, nil)
	newHandler(t, users).Login(c)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if code := decode(t, rec)["code"]; code != "INTERNAL_ERROR" {
		t.Errorf("code = %v, want INTERNAL_ERROR", code)
	}
}

func TestLogin_Success(t *testing.T) {
	users := &mockUserRepo{user: &domain.UserRow{ID: 1, Username: "alice", Email: "a@x.io", PasswordHash: bcryptHash(t, "password123")}}
	c, rec := newCtx(http.MethodPost, "/auth/v1/public/auth/login",
		`{"username":"alice","password":"password123"}`, nil)
	newHandler(t, users).Login(c)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	body := decode(t, rec)
	if _, ok := body["access_token"]; !ok {
		t.Errorf("response missing access_token: %s", rec.Body.String())
	}
	if _, ok := body["token"]; ok {
		t.Errorf("response must not carry the removed opaque token field: %s", rec.Body.String())
	}
}

// --- Register ---

func TestRegister_BadJSON(t *testing.T) {
	c, rec := newCtx(http.MethodPost, "/auth/v1/public/auth/register", "{", nil)
	newHandler(t, &mockUserRepo{}).Register(c)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if code := decode(t, rec)["code"]; code != "VALIDATION_ERROR" {
		t.Errorf("code = %v, want VALIDATION_ERROR", code)
	}
}

func TestRegister_Conflict(t *testing.T) {
	users := &mockUserRepo{exists: true}
	c, rec := newCtx(http.MethodPost, "/auth/v1/public/auth/register",
		`{"username":"alice","email":"a@x.io","password":"password123"}`, nil)
	newHandler(t, users).Register(c)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
	if code := decode(t, rec)["code"]; code != "CONFLICT" {
		t.Errorf("code = %v, want CONFLICT", code)
	}
}

func TestRegister_ServiceError(t *testing.T) {
	users := &mockUserRepo{existsErr: context.DeadlineExceeded}
	c, rec := newCtx(http.MethodPost, "/auth/v1/public/auth/register",
		`{"username":"alice","email":"a@x.io","password":"password123"}`, nil)
	newHandler(t, users).Register(c)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if code := decode(t, rec)["code"]; code != "INTERNAL_ERROR" {
		t.Errorf("code = %v, want INTERNAL_ERROR", code)
	}
}

func TestRegister_Success(t *testing.T) {
	users := &mockUserRepo{exists: false, createID: 42}
	c, rec := newCtx(http.MethodPost, "/auth/v1/public/auth/register",
		`{"username":"alice","email":"a@x.io","password":"password123"}`, nil)
	newHandler(t, users).Register(c)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", rec.Code, rec.Body.String())
	}
	body := decode(t, rec)
	if _, ok := body["access_token"]; !ok {
		t.Errorf("response missing access_token: %s", rec.Body.String())
	}
	if _, ok := body["token"]; ok {
		t.Errorf("response must not carry the removed opaque token field: %s", rec.Body.String())
	}
}

// --- Refresh ---

func newRefreshHandler(t *testing.T, refresh domain.RefreshTokenRepository) *Handler {
	t.Helper()
	return NewHandler(logicv1.NewAuthService(&mockUserRepo{}, refresh, testSigner(t), time.Hour))
}

func TestRefresh_BadJSON(t *testing.T) {
	h := newRefreshHandler(t, &mockRefreshRepo{})
	c, rec := newCtx(http.MethodPost, "/auth/v1/public/auth/refresh", "{", nil)
	h.Refresh(c)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if code := decode(t, rec)["code"]; code != "VALIDATION_ERROR" {
		t.Errorf("code = %v, want VALIDATION_ERROR", code)
	}
}

func TestRefresh_MissingToken(t *testing.T) {
	h := newRefreshHandler(t, &mockRefreshRepo{})
	c, rec := newCtx(http.MethodPost, "/auth/v1/public/auth/refresh", `{}`, nil)
	h.Refresh(c)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if code := decode(t, rec)["code"]; code != "VALIDATION_ERROR" {
		t.Errorf("code = %v, want VALIDATION_ERROR", code)
	}
}

func TestRefresh_Invalid(t *testing.T) {
	h := newRefreshHandler(t, &mockRefreshRepo{row: nil})
	c, rec := newCtx(http.MethodPost, "/auth/v1/public/auth/refresh", `{"refresh_token":"nope"}`, nil)
	h.Refresh(c)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if code := decode(t, rec)["code"]; code != "UNAUTHORIZED" {
		t.Errorf("code = %v, want UNAUTHORIZED", code)
	}
}

func TestRefresh_Reuse(t *testing.T) {
	used := time.Now().Add(-time.Minute)
	row := &domain.RefreshTokenRow{UserID: 7, Username: "alice", FamilyID: "fam", UsedAt: &used, ExpiresAt: time.Now().Add(time.Hour)}
	h := newRefreshHandler(t, &mockRefreshRepo{row: row})
	c, rec := newCtx(http.MethodPost, "/auth/v1/public/auth/refresh", `{"refresh_token":"replayed"}`, nil)
	h.Refresh(c)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if code := decode(t, rec)["code"]; code != "UNAUTHORIZED" {
		t.Errorf("code = %v, want UNAUTHORIZED", code)
	}
}

func TestRefresh_ServiceError(t *testing.T) {
	h := newRefreshHandler(t, &mockRefreshRepo{getErr: context.DeadlineExceeded})
	c, rec := newCtx(http.MethodPost, "/auth/v1/public/auth/refresh", `{"refresh_token":"x"}`, nil)
	h.Refresh(c)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if code := decode(t, rec)["code"]; code != "INTERNAL_ERROR" {
		t.Errorf("code = %v, want INTERNAL_ERROR", code)
	}
}

func TestRefresh_Success(t *testing.T) {
	row := &domain.RefreshTokenRow{UserID: 7, Username: "alice", Email: "a@x.io", FamilyID: "fam", ExpiresAt: time.Now().Add(time.Hour)}
	h := newRefreshHandler(t, &mockRefreshRepo{row: row})
	c, rec := newCtx(http.MethodPost, "/auth/v1/public/auth/refresh", `{"refresh_token":"valid"}`, nil)
	h.Refresh(c)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	body := decode(t, rec)
	if _, ok := body["access_token"]; !ok {
		t.Errorf("response missing access_token: %s", rec.Body.String())
	}
	if _, ok := body["refresh_token"]; !ok {
		t.Errorf("response missing refresh_token: %s", rec.Body.String())
	}
}

// --- Logout ---

func TestLogout_BadJSON(t *testing.T) {
	h := newRefreshHandler(t, &mockRefreshRepo{})
	c, rec := newCtx(http.MethodPost, "/auth/v1/public/auth/logout", "{", nil)
	h.Logout(c)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if code := decode(t, rec)["code"]; code != "VALIDATION_ERROR" {
		t.Errorf("code = %v, want VALIDATION_ERROR", code)
	}
}

func TestLogout_MissingToken(t *testing.T) {
	h := newRefreshHandler(t, &mockRefreshRepo{})
	c, rec := newCtx(http.MethodPost, "/auth/v1/public/auth/logout", `{}`, nil)
	h.Logout(c)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if code := decode(t, rec)["code"]; code != "VALIDATION_ERROR" {
		t.Errorf("code = %v, want VALIDATION_ERROR", code)
	}
}

func TestLogout_ServiceError(t *testing.T) {
	row := &domain.RefreshTokenRow{UserID: 7, FamilyID: "fam", ExpiresAt: time.Now().Add(time.Hour)}
	h := newRefreshHandler(t, &mockRefreshRepo{row: row, revokeErr: context.DeadlineExceeded})
	c, rec := newCtx(http.MethodPost, "/auth/v1/public/auth/logout", `{"refresh_token":"tok"}`, nil)
	h.Logout(c)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if code := decode(t, rec)["code"]; code != "INTERNAL_ERROR" {
		t.Errorf("code = %v, want INTERNAL_ERROR", code)
	}
}

func TestLogout_Success(t *testing.T) {
	row := &domain.RefreshTokenRow{UserID: 7, FamilyID: "fam", ExpiresAt: time.Now().Add(time.Hour)}
	h := newRefreshHandler(t, &mockRefreshRepo{row: row})
	c, rec := newCtx(http.MethodPost, "/auth/v1/public/auth/logout", `{"refresh_token":"tok"}`, nil)
	h.Logout(c)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
}

func TestLogout_UnknownTokenIdempotent(t *testing.T) {
	h := newRefreshHandler(t, &mockRefreshRepo{row: nil})
	c, rec := newCtx(http.MethodPost, "/auth/v1/public/auth/logout", `{"refresh_token":"unknown"}`, nil)
	h.Logout(c)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (idempotent): %s", rec.Code, rec.Body.String())
	}
}

// --- JWKS ---

func TestJWKS_NoSigner(t *testing.T) {
	h := NewHandler(logicv1.NewAuthService(&mockUserRepo{}, nil, nil, 0))
	c, rec := newCtx(http.MethodGet, "/auth/v1/public/auth/jwks", "", nil)
	h.JWKS(c)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if code := decode(t, rec)["code"]; code != "NOT_FOUND" {
		t.Errorf("code = %v, want NOT_FOUND", code)
	}
}

func TestJWKS_WithSigner(t *testing.T) {
	h := newHandler(t, &mockUserRepo{})

	c, rec := newCtx(http.MethodGet, "/auth/v1/public/auth/jwks", "", nil)
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

// --- Route mounting (v3 canonical + deprecated aliases) ---

// TestRegisterRoutes_CanonicalAndAliasMounted locks the expand phase of the
// v3 path migration (homelab ADR-017): the collection-noun paths are
// canonical and the pre-v3 paths stay mounted as deprecated aliases until
// the contract release removes them.
func TestRegisterRoutes_CanonicalAndAliasMounted(t *testing.T) {
	r := gin.New()
	newHandler(t, &mockUserRepo{}).RegisterRoutes(r)

	for _, tc := range []struct {
		method, path string
	}{
		{http.MethodGet, "/auth/v1/public/auth/jwks"},
		{http.MethodGet, "/auth/v1/public/jwks"}, // deprecated alias
		{http.MethodPost, "/auth/v1/public/auth/login"},
		{http.MethodPost, "/auth/v1/public/login"}, // deprecated alias
		{http.MethodPost, "/auth/v1/public/auth/register"},
		{http.MethodPost, "/auth/v1/public/register"}, // deprecated alias
		{http.MethodPost, "/auth/v1/public/auth/refresh"},
		{http.MethodPost, "/auth/v1/public/refresh"}, // deprecated alias
		{http.MethodPost, "/auth/v1/public/auth/logout"},
		{http.MethodPost, "/auth/v1/public/logout"}, // deprecated alias
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader("{"))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(rec, req)
		if rec.Code == http.StatusNotFound {
			t.Errorf("%s %s not mounted (got 404)", tc.method, tc.path)
		}
	}
}
