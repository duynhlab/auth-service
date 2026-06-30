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
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
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

func TestShutdown(t *testing.T) {
	// nil provider -> nil error.
	tracerProvider = nil
	if err := Shutdown(context.Background()); err != nil {
		t.Errorf("Shutdown(nil provider) = %v, want nil", err)
	}

	// real provider -> flush + shutdown succeed.
	tracerProvider = sdktrace.NewTracerProvider()
	if err := Shutdown(context.Background()); err != nil {
		t.Errorf("Shutdown() = %v, want nil", err)
	}
	tracerProvider = nil // reset package state for other tests
}

func TestDetectServiceInfo(t *testing.T) {
	t.Run("OTEL_SERVICE_NAME wins", func(t *testing.T) {
		t.Setenv("OTEL_SERVICE_NAME", "auth")
		t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "service.namespace=prod")
		name, ns := detectServiceInfo()
		if name != "auth" {
			t.Errorf("serviceName = %q, want auth", name)
		}
		if ns != "prod" {
			t.Errorf("namespace = %q, want prod", ns)
		}
	})
	t.Run("derive from POD_NAME", func(t *testing.T) {
		t.Setenv("OTEL_SERVICE_NAME", "")
		t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "")
		t.Setenv("POD_NAME", "auth-75c98b4b9c-kdv2n")
		t.Setenv("POD_NAMESPACE", "staging")
		name, ns := detectServiceInfo()
		if name != "auth" {
			t.Errorf("serviceName = %q, want auth (stripped pod hash)", name)
		}
		if ns != "staging" {
			t.Errorf("namespace = %q, want staging", ns)
		}
	})
}

func TestGetServiceName(t *testing.T) {
	res := resource.NewWithAttributes(semconv.SchemaURL, semconv.ServiceNameKey.String("auth"))
	if got := GetServiceName(res); got != "auth" {
		t.Errorf("GetServiceName() = %q, want auth", got)
	}
}
