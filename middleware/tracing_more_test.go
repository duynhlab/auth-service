package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

func TestShouldTrace(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/auth/v1/login", true},
		{"/health", false},
		{"/healthz", false},
		{"/ready", false},
		{"/metrics", false},
		{"/favicon.ico", false},
		{"/", true},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := shouldTrace(tt.path); got != tt.want {
				t.Errorf("shouldTrace(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

// TestSetServiceName covers both branches: a non-empty name is recorded for
// the tracer scope, and an empty name must NOT clobber a previously set one
// (main() may pass an unset config value).
func TestSetServiceName(t *testing.T) {
	orig := detectedService
	t.Cleanup(func() { detectedService = orig })

	SetServiceName("auth")
	if detectedService != "auth" {
		t.Errorf("detectedService = %q, want auth", detectedService)
	}
	SetServiceName("")
	if detectedService != "auth" {
		t.Error("SetServiceName(\"\") must not clobber the recorded name")
	}
}

func TestTracingMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(TracingMiddleware())
	r.GET("/work", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	r.GET("/health", func(c *gin.Context) { c.String(http.StatusOK, "ok") })

	for _, path := range []string{"/work", "/health"} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusOK {
			t.Errorf("%s: status = %d, want 200", path, w.Code)
		}
	}
}

func TestStartSpan(t *testing.T) {
	ctx, span := StartSpan(context.Background(), "unit.test")
	if ctx == nil {
		t.Fatal("StartSpan returned nil context")
	}
	span.End()
}

func TestSpanHelpers(t *testing.T) {
	// Non-recording span path (no provider) — helpers must be safe no-ops.
	bg := context.Background()
	AddSpanAttributes(bg, attribute.String("k", "v"))
	AddSpanEvent(bg, "evt", attribute.Int("n", 1))
	RecordError(bg, errors.New("boom"))
	SetSpanStatus(bg, codes.Ok, "ok")

	// Recording span path — exercise the IsRecording() == true branches.
	tp := sdktrace.NewTracerProvider(sdktrace.WithSampler(sdktrace.AlwaysSample()))
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
	ctx, span := tp.Tracer("test").Start(bg, "rec")
	if !span.IsRecording() {
		t.Fatal("expected a recording span")
	}
	AddSpanAttributes(ctx, attribute.String("user.id", "u1"))
	AddSpanEvent(ctx, "cache.hit", attribute.String("key", "k"))
	RecordError(ctx, errors.New("db error"))
	SetSpanStatus(ctx, codes.Error, "failed")
	span.End()
}
