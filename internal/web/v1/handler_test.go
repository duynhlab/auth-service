package v1

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/duynhne/auth-service/internal/core/domain"
	logicv1 "github.com/duynhne/auth-service/internal/logic/v1"
	"github.com/duynhne/auth-service/internal/testutil"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)
	m.Run()
}

// newRouter wires a real AuthService over the given mock repositories.
func newRouter(users domain.UserRepository, sessions domain.SessionRepository) *gin.Engine {
	svc := logicv1.NewAuthService(users, sessions)
	h := NewHandler(svc)
	r := gin.New()
	h.RegisterRoutes(r)
	return r
}

func do(r *gin.Engine, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func bcryptHash(t *testing.T, pw string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	return string(h)
}

func TestHandler_Login(t *testing.T) {
	t.Parallel()
	hash := bcryptHash(t, "password123")

	tests := []struct {
		name      string
		body      string
		users     *testutil.MockUserRepository
		wantCode  int
		wantInBdy string
	}{
		{
			name: "success",
			body: `{"username":"alice","password":"password123"}`,
			users: &testutil.MockUserRepository{
				GetByUsernameFunc: func(_ context.Context, _ string) (*domain.UserRow, error) {
					return &domain.UserRow{ID: 1, Username: "alice", Email: "a@x.io", PasswordHash: hash}, nil
				},
			},
			wantCode:  http.StatusOK,
			wantInBdy: `"token"`,
		},
		{
			name:      "malformed json",
			body:      `{not json`,
			users:     &testutil.MockUserRepository{},
			wantCode:  http.StatusBadRequest,
			wantInBdy: "Invalid request body",
		},
		{
			name:      "missing required fields",
			body:      `{"username":"alice"}`,
			users:     &testutil.MockUserRepository{},
			wantCode:  http.StatusBadRequest,
			wantInBdy: "Invalid request body",
		},
		{
			name: "wrong password",
			body: `{"username":"alice","password":"nope"}`,
			users: &testutil.MockUserRepository{
				GetByUsernameFunc: func(_ context.Context, _ string) (*domain.UserRow, error) {
					return &domain.UserRow{ID: 1, Username: "alice", PasswordHash: hash}, nil
				},
			},
			wantCode:  http.StatusUnauthorized,
			wantInBdy: "Invalid credentials",
		},
		{
			name:      "unknown user is indistinguishable from wrong password",
			body:      `{"username":"ghost","password":"whatever"}`,
			users:     &testutil.MockUserRepository{}, // GetByUsername -> (nil,nil)
			wantCode:  http.StatusUnauthorized,
			wantInBdy: "Invalid credentials",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := newRouter(tt.users, &testutil.MockSessionRepository{})
			w := do(r, http.MethodPost, "/auth/v1/public/login", tt.body, nil)
			if w.Code != tt.wantCode {
				t.Fatalf("status = %d, want %d (body=%s)", w.Code, tt.wantCode, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), tt.wantInBdy) {
				t.Errorf("body = %s, want contains %q", w.Body.String(), tt.wantInBdy)
			}
		})
	}
}

func TestHandler_Register(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		body     string
		users    *testutil.MockUserRepository
		wantCode int
	}{
		{
			name: "created",
			body: `{"username":"bob","email":"bob@x.io","password":"password123"}`,
			users: &testutil.MockUserRepository{
				CreateFunc: func(_ context.Context, _, _, _ string) (int, error) { return 42, nil },
			},
			wantCode: http.StatusCreated,
		},
		{
			name: "conflict",
			body: `{"username":"bob","email":"bob@x.io","password":"password123"}`,
			users: &testutil.MockUserRepository{
				ExistsByUsernameOrEmailFunc: func(_ context.Context, _, _ string) (bool, error) { return true, nil },
			},
			wantCode: http.StatusConflict,
		},
		{
			name:     "invalid email",
			body:     `{"username":"bob","email":"not-an-email","password":"password123"}`,
			users:    &testutil.MockUserRepository{},
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "short password",
			body:     `{"username":"bob","email":"bob@x.io","password":"123"}`,
			users:    &testutil.MockUserRepository{},
			wantCode: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := newRouter(tt.users, &testutil.MockSessionRepository{})
			w := do(r, http.MethodPost, "/auth/v1/public/register", tt.body, nil)
			if w.Code != tt.wantCode {
				t.Fatalf("status = %d, want %d (body=%s)", w.Code, tt.wantCode, w.Body.String())
			}
		})
	}
}

func TestHandler_GetMe(t *testing.T) {
	t.Parallel()

	valid := &testutil.MockSessionRepository{
		GetUserByTokenFunc: func(_ context.Context, _ string) (*domain.SessionRow, error) {
			return &domain.SessionRow{UserID: 5, Username: "dave", Email: "d@x.io", ExpiresAt: time.Now().Add(time.Hour)}, nil
		},
	}
	expired := &testutil.MockSessionRepository{
		GetUserByTokenFunc: func(_ context.Context, _ string) (*domain.SessionRow, error) {
			return &domain.SessionRow{UserID: 5, ExpiresAt: time.Now().Add(-time.Hour)}, nil
		},
	}

	tests := []struct {
		name     string
		header   map[string]string
		sessions *testutil.MockSessionRepository
		wantCode int
	}{
		{name: "valid token", header: map[string]string{"Authorization": "Bearer goodtoken"}, sessions: valid, wantCode: http.StatusOK},
		{name: "missing header", header: nil, sessions: valid, wantCode: http.StatusUnauthorized},
		{name: "wrong scheme", header: map[string]string{"Authorization": "Token abc"}, sessions: valid, wantCode: http.StatusUnauthorized},
		{name: "empty bearer token", header: map[string]string{"Authorization": "Bearer "}, sessions: valid, wantCode: http.StatusUnauthorized},
		{name: "expired session", header: map[string]string{"Authorization": "Bearer x"}, sessions: expired, wantCode: http.StatusUnauthorized},
		{name: "unknown token", header: map[string]string{"Authorization": "Bearer x"}, sessions: &testutil.MockSessionRepository{}, wantCode: http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := newRouter(&testutil.MockUserRepository{}, tt.sessions)
			w := do(r, http.MethodGet, "/auth/v1/private/me", "", tt.header)
			if w.Code != tt.wantCode {
				t.Fatalf("status = %d, want %d (body=%s)", w.Code, tt.wantCode, w.Body.String())
			}
			if w.Code == http.StatusOK {
				var u domain.User
				if err := json.Unmarshal(w.Body.Bytes(), &u); err != nil {
					t.Fatalf("decode body: %v", err)
				}
				if u.ID != "5" {
					t.Errorf("user.ID = %q, want \"5\"", u.ID)
				}
			}
		})
	}
}

// FuzzLoginBody ensures arbitrary request bodies never panic and never produce a
// 5xx — a malformed login is always a clean 400 (bad body) or 401 (auth fails).
func FuzzLoginBody(f *testing.F) {
	f.Add(`{"username":"a","password":"b"}`)
	f.Add(`{not json`)
	f.Add(``)
	f.Add(`{"username":123}`)

	r := newRouter(&testutil.MockUserRepository{}, &testutil.MockSessionRepository{}) // unknown user -> 401
	f.Fuzz(func(t *testing.T, body string) {
		w := do(r, http.MethodPost, "/auth/v1/public/login", body, nil)
		if w.Code != http.StatusBadRequest && w.Code != http.StatusUnauthorized {
			t.Fatalf("unexpected status %d for body %q", w.Code, body)
		}
	})
}

// FuzzGetMeAuthHeader ensures arbitrary Authorization headers never panic; with
// no matching session every input must be rejected with 401 (never 5xx).
func FuzzGetMeAuthHeader(f *testing.F) {
	f.Add("Bearer abc")
	f.Add("Bearer ")
	f.Add("")
	f.Add("Basic Zm9v")
	f.Add("Bearer \x00\xff")

	r := newRouter(&testutil.MockUserRepository{}, &testutil.MockSessionRepository{}) // token never found
	f.Fuzz(func(t *testing.T, header string) {
		w := do(r, http.MethodGet, "/auth/v1/private/me", "", map[string]string{"Authorization": header})
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("unexpected status %d for header %q", w.Code, header)
		}
	})
}
