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

		// Get or generate trace-id
		traceID := GetTraceID(c)

		// Store trace-id in context for handlers to use
		c.Set("trace_id", traceID)

		// Create a sub-logger with trace_id attached
		loggerWithTrace := logger.With(zap.String("trace_id", traceID))

		// Inject logger into context
		ctx := zapx.WithContext(c.Request.Context(), loggerWithTrace)
		c.Request = c.Request.WithContext(ctx)

		// Add trace-id to response header
		c.Header(TraceIDHeader, traceID)

		// Process request
		c.Next()

		// Calculate duration
		duration := time.Since(start)
		statusCode := c.Writer.Status()

		// Single request log; error level for 4xx/5xx, info otherwise.
		level := zapcore.InfoLevel
		if statusCode >= 400 {
			level = zapcore.ErrorLevel
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
