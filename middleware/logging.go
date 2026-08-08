package middleware

import (
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/duynhlab/pkg/logger/zapx"
	"github.com/duynhlab/pkg/obsx"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const TraceIDHeader = "X-Trace-ID"
const TraceParentHeader = "traceparent"

// GetTraceID returns a trace-id for the request, preferring the active OTel
// span so log lines correlate with the trace exported to the backend. It falls
// back to the inbound trace headers, then a freshly generated id, when tracing
// is disabled or no span is present.
func GetTraceID(c *gin.Context) string {
	// Prefer the span context (tracing middleware runs before logging).
	if id := obsx.TraceIDFromContext(c.Request.Context()); id != "" {
		return id
	}

	// Try W3C Trace Context first (traceparent header)
	if traceParent := c.GetHeader(TraceParentHeader); traceParent != "" {
		// traceparent format: version-trace_id-parent_id-flags
		// Extract trace_id (second part)
		parts := splitTraceParent(traceParent)
		if len(parts) >= 2 && parts[1] != "" {
			return parts[1]
		}
	}

	// Fallback to X-Trace-ID header
	if traceID := c.GetHeader(TraceIDHeader); traceID != "" {
		return traceID
	}

	// Generate new trace-id if not present
	return generateTraceID()
}

// splitTraceParent splits traceparent header value
func splitTraceParent(traceParent string) []string {
	// Simple split by hyphen, traceparent format: 00-<trace_id>-<parent_id>-<flags>
	parts := make([]string, 0, 4)
	start := 0
	for i := range len(traceParent) {
		if traceParent[i] == '-' {
			if start < i {
				parts = append(parts, traceParent[start:i])
			}
			start = i + 1
		}
	}
	if start < len(traceParent) {
		parts = append(parts, traceParent[start:])
	}
	return parts
}

// generateTraceID generates a trace-id using random bytes
func generateTraceID() string {
	// Generate 16 random bytes (32 hex characters)
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Fallback to zero trace ID on entropy failure (extremely unlikely)
		return "00000000000000000000000000000000"
	}
	return hex.EncodeToString(b)
}

// LoggingMiddleware creates a Gin middleware for structured logging with trace-id
func LoggingMiddleware(logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		method := c.Request.Method

		// spanTraceID is the ONLY id that may reach telemetry: the active span's,
		// or empty. This middleware previously logged GetTraceID's value, which
		// never consults the span — so a log line could advertise an id that is
		// not the trace id, and a search by it finds nothing in the backend even
		// when a trace exists. Probes have no span by design (TracingMiddleware
		// skips them), so their records carry no trace_id.
		spanTraceID := obsx.TraceIDFromContext(c.Request.Context())

		// The response header keeps its previous behaviour, generated fallback
		// included: correlate-by-header is a client contract, separate from what
		// this service puts in its own telemetry.
		headerTraceID := spanTraceID
		if headerTraceID == "" {
			headerTraceID = GetTraceID(c)
		}
		c.Set("trace_id", headerTraceID)
		c.Header(TraceIDHeader, headerTraceID)

		// obsx.TraceContext binds the request context so the otelzap bridge
		// stamps the native trace_id/span_id on every OTLP record — the
		// semconv-standard log/trace link. This service never bound it, which is
		// why none of its records carried one (telemetry audit F-1). The readable
		// string field is bound only when a span exists.
		withFields := []zap.Field{obsx.TraceContext(c.Request.Context())}
		if spanTraceID != "" {
			withFields = append(withFields, zap.String("trace_id", spanTraceID))
		}
		loggerWithTrace := logger.With(withFields...)

		// Inject logger into context
		ctx := zapx.WithContext(c.Request.Context(), loggerWithTrace)
		c.Request = c.Request.WithContext(ctx)

		// Process request
		c.Next()

		// Calculate duration
		duration := time.Since(start)
		statusCode := c.Writer.Status()

		// Routine successful probes are traffic about the platform, not the
		// domain. TracingMiddleware already excludes them from spans and RED
		// metrics through the same shouldTrace list; excluding them here is what
		// makes that contract true for logs too. A FAILING probe is kept.
		if !shouldTrace(path) && statusCode < 400 {
			return
		}

		// 4xx is a rejected request, not a broken service: an expected business
		// rejection must not read as an infrastructure error. For auth that
		// matters — a wrong password is a 401, not an outage.
		level := zapcore.InfoLevel
		switch {
		case statusCode >= 500:
			level = zapcore.ErrorLevel
		case statusCode >= 400:
			level = zapcore.WarnLevel
		}

		// Log request/response
		loggerWithTrace.Log(level, "HTTP request",
			zap.String("method", method),
			zap.String("path", path),
			zap.Int("status", statusCode),
			zap.Duration("duration", duration),
			zap.String("client_ip", c.ClientIP()),
			zap.String("user_agent", c.Request.UserAgent()),
		)
	}
}

// GetLoggerFromGinContext - Helper to get the zap logger from context
func GetLoggerFromGinContext(c *gin.Context) *zap.Logger {
	return zapx.FromContext(c.Request.Context())
}
