package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestSplitTraceParent(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want int // number of parts
	}{
		{"full w3c", "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01", 4},
		{"trailing hyphen", "00-abc-", 2},
		{"leading hyphen", "-abc-def", 2},
		{"no hyphen", "abcdef", 1},
		{"empty", "", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := splitTraceParent(tt.in); len(got) != tt.want {
				t.Errorf("splitTraceParent(%q) = %v (len %d), want len %d", tt.in, got, len(got), tt.want)
			}
		})
	}
}

func TestGenerateTraceID(t *testing.T) {
	id := generateTraceID()
	if len(id) != 32 {
		t.Errorf("generateTraceID() len = %d, want 32", len(id))
	}
	if id == generateTraceID() {
		t.Error("generateTraceID() returned identical ids on consecutive calls")
	}
}

func TestGetTraceID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	const traceID = "0af7651916cd43dd8448eb211c80319c"

	tests := []struct {
		name    string
		headers map[string]string
		want    string // "" means "generated (32 hex chars)"
	}{
		{"from traceparent", map[string]string{TraceParentHeader: "00-" + traceID + "-b7ad6b7169203331-01"}, traceID},
		{"from x-trace-id", map[string]string{TraceIDHeader: traceID}, traceID},
		{"generated when absent", nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
			for k, v := range tt.headers {
				c.Request.Header.Set(k, v)
			}
			got := GetTraceID(c)
			if tt.want == "" {
				if len(got) != 32 {
					t.Errorf("GetTraceID() = %q, want a generated 32-char id", got)
				}
				return
			}
			if got != tt.want {
				t.Errorf("GetTraceID() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLoggingMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(LoggingMiddleware())
	r.GET("/ok", func(c *gin.Context) {
		// The middleware must have injected a logger and a trace id by now.
		if GetLoggerFromGinContext(c) == nil {
			t.Error("GetLoggerFromGinContext returned nil inside handler")
		}
		if c.GetString("trace_id") == "" {
			t.Error("trace_id not set in gin context")
		}
		c.String(http.StatusOK, "ok")
	})
	r.GET("/fail", func(c *gin.Context) { c.String(http.StatusInternalServerError, "boom") })

	for _, path := range []string{"/ok", "/fail"} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Header().Get(TraceIDHeader) == "" {
			t.Errorf("%s: response missing %s header", path, TraceIDHeader)
		}
	}
}
