package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
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
	const traceID = "0af7651916cd43dd8448eb211c80319c"

	tests := []struct {
		name      string
		path      string
		status    int
		headers   map[string]string
		wantLevel zapcore.Level
		wantTrace string // "" means "generated (32 hex chars)"
	}{
		{"2xx logs info", "/ok", http.StatusOK, nil, zapcore.InfoLevel, ""},
		{"4xx logs error", "/bad", http.StatusBadRequest, nil, zapcore.ErrorLevel, ""},
		{"5xx logs error", "/fail", http.StatusInternalServerError, nil, zapcore.ErrorLevel, ""},
		{
			"trace_id from traceparent header", "/ok", http.StatusOK,
			map[string]string{TraceParentHeader: "00-" + traceID + "-b7ad6b7169203331-01"},
			zapcore.InfoLevel, traceID,
		},
		{
			"trace_id from x-trace-id header", "/ok", http.StatusOK,
			map[string]string{TraceIDHeader: traceID},
			zapcore.InfoLevel, traceID,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			core, observed := observer.New(zapcore.DebugLevel)
			r := gin.New()
			r.Use(LoggingMiddleware(zap.New(core)))
			r.GET(tt.path, func(c *gin.Context) {
				// The middleware must have injected a logger and a trace id by now.
				if GetLoggerFromGinContext(c) == nil {
					t.Error("GetLoggerFromGinContext returned nil inside handler")
				}
				if c.GetString("trace_id") == "" {
					t.Error("trace_id not set in gin context")
				}
				c.String(tt.status, "done")
			})

			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			r.ServeHTTP(w, req)

			if w.Header().Get(TraceIDHeader) == "" {
				t.Errorf("%s: response missing %s header", tt.path, TraceIDHeader)
			}

			entries := observed.FilterMessage("HTTP request").All()
			if len(entries) != 1 {
				t.Fatalf("got %d %q log entries, want 1", len(entries), "HTTP request")
			}
			entry := entries[0]
			if entry.Level != tt.wantLevel {
				t.Errorf("log level = %v, want %v", entry.Level, tt.wantLevel)
			}

			fields := entry.ContextMap()
			for key, want := range map[string]any{
				"method": http.MethodGet,
				"path":   tt.path,
				"status": int64(tt.status),
			} {
				if got := fields[key]; got != want {
					t.Errorf("field %q = %v, want %v", key, got, want)
				}
			}
			for _, key := range []string{"duration", "client_ip", "user_agent"} {
				if _, ok := fields[key]; !ok {
					t.Errorf("field %q missing from request log", key)
				}
			}
			gotTrace, _ := fields["trace_id"].(string)
			if tt.wantTrace == "" {
				if len(gotTrace) != 32 {
					t.Errorf("trace_id = %q, want a generated 32-char id", gotTrace)
				}
			} else if gotTrace != tt.wantTrace {
				t.Errorf("trace_id = %q, want %q", gotTrace, tt.wantTrace)
			}
		})
	}
}

func TestLoggingMiddlewareInjectsTraceLogger(t *testing.T) {
	gin.SetMode(gin.TestMode)
	core, observed := observer.New(zapcore.DebugLevel)
	r := gin.New()
	r.Use(LoggingMiddleware(zap.New(core)))
	r.GET("/ok", func(c *gin.Context) {
		GetLoggerFromGinContext(c).Info("handler log")
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/ok", nil))

	entries := observed.FilterMessage("handler log").All()
	if len(entries) != 1 {
		t.Fatalf("got %d handler log entries, want 1", len(entries))
	}
	if traceID, _ := entries[0].ContextMap()["trace_id"].(string); traceID != w.Header().Get(TraceIDHeader) {
		t.Errorf("handler log trace_id = %q, want response header %q", traceID, w.Header().Get(TraceIDHeader))
	}
}

func TestGetLoggerFromGinContextFallback(t *testing.T) {
	gin.SetMode(gin.TestMode)
	// Without LoggingMiddleware the helper falls back to the global logger.
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	if GetLoggerFromGinContext(c) == nil {
		t.Error("GetLoggerFromGinContext returned nil without middleware")
	}
}
