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
		// 4xx is a rejected request, not a broken service — for auth a wrong
		// password is a 401, and counting it as an error inflates every
		// log-based error query (observability.md error ownership).
		{"4xx logs warn", "/bad", http.StatusBadRequest, nil, zapcore.WarnLevel, ""},
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
			// No span is active in this test, so the record must carry NO
			// trace_id — not the traceparent-derived one and not a generated
			// one. An id in the log that the tracing backend does not have is
			// worse than an absent field (telemetry audit F-1). The response
			// header still carries it: that is a separate client contract,
			// asserted in TestLoggingMiddlewareOmitsTraceIDWithoutSpan.
			if _, present := fields["trace_id"]; present {
				t.Errorf("no span, yet the record carries trace_id=%v", fields["trace_id"])
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
	// The injected logger carries the trace CONTEXT always (so OTLP records get
	// native ids) but the readable trace_id string only when a span exists.
	// There is no span here, so the field must be absent even though the
	// response header is set.
	if v, present := entries[0].ContextMap()["trace_id"]; present {
		t.Errorf("no span, yet the handler logger carries trace_id=%v", v)
	}
	if w.Header().Get(TraceIDHeader) == "" {
		t.Errorf("missing %s response header", TraceIDHeader)
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

// observedLogger returns a logger whose records land in the returned sink.
func observedLogger() (*zap.Logger, *observer.ObservedLogs) {
	core, logs := observer.New(zapcore.DebugLevel)
	return zap.New(core), logs
}

// The access log must skip routine SUCCESSFUL probes and keep failing ones —
// docs/api/observability.md claims this middleware shares TracingMiddleware's
// skip list, and telemetry audit F-2 found it had none.
func TestLoggingMiddlewareSkipsSuccessfulProbesOnly(t *testing.T) {
	gin.SetMode(gin.TestMode)

	for _, tc := range []struct {
		name       string
		path       string
		status     int
		wantRecord bool
	}{
		{"healthy probe is silent", "/health", http.StatusOK, false},
		{"ready probe is silent", "/readyz", http.StatusOK, false},
		{"metrics scrape is silent", "/metrics", http.StatusOK, false},
		{"FAILING probe is logged", "/health", http.StatusServiceUnavailable, true},
		{"real traffic is logged", "/v1/public/things", http.StatusOK, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logger, logs := observedLogger()
			r := gin.New()
			r.Use(LoggingMiddleware(logger))
			r.GET(tc.path, func(c *gin.Context) { c.String(tc.status, "x") })

			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, tc.path, nil))

			got := logs.FilterMessage("HTTP request").Len()
			if tc.wantRecord && got != 1 {
				t.Errorf("%s %d: got %d access-log records, want 1", tc.path, tc.status, got)
			}
			if !tc.wantRecord && got != 0 {
				t.Errorf("%s %d: got %d access-log records, want 0", tc.path, tc.status, got)
			}
		})
	}
}

// A rejected request is not a broken service: observability.md's error-ownership
// rule says expected business rejections must not read as infrastructure errors.
func TestLoggingMiddlewareLevelByStatusClass(t *testing.T) {
	gin.SetMode(gin.TestMode)

	for _, tc := range []struct {
		status int
		want   zapcore.Level
	}{
		{http.StatusOK, zapcore.InfoLevel},
		{http.StatusNotFound, zapcore.WarnLevel},
		{http.StatusConflict, zapcore.WarnLevel},
		{http.StatusInternalServerError, zapcore.ErrorLevel},
	} {
		logger, logs := observedLogger()
		r := gin.New()
		r.Use(LoggingMiddleware(logger))
		r.GET("/x", func(c *gin.Context) { c.String(tc.status, "x") })

		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/x", nil))

		rec := logs.FilterMessage("HTTP request").All()
		if len(rec) != 1 {
			t.Fatalf("status %d: got %d records, want 1", tc.status, len(rec))
		}
		if rec[0].Level != tc.want {
			t.Errorf("status %d: level = %s, want %s", tc.status, rec[0].Level, tc.want)
		}
	}
}

// Without an active span there is no trace to join, so the record must carry no
// trace_id at all rather than a generated one (telemetry audit F-1).
func TestLoggingMiddlewareOmitsTraceIDWithoutSpan(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger, logs := observedLogger()
	r := gin.New()
	r.Use(LoggingMiddleware(logger))
	r.GET("/x", func(c *gin.Context) { c.String(http.StatusOK, "x") })

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/x", nil))

	rec := logs.FilterMessage("HTTP request").All()
	if len(rec) != 1 {
		t.Fatalf("got %d records, want 1", len(rec))
	}
	for _, f := range rec[0].Context {
		if f.Key == "trace_id" {
			t.Errorf("no span, yet the record carries trace_id=%q — a fabricated id joins to nothing", f.String)
		}
	}
	if w.Header().Get(TraceIDHeader) == "" {
		t.Errorf("missing %s response header", TraceIDHeader)
	}
}
