package v1

import (
	"errors"
	"net/http"

	"github.com/duynhlab/auth-service/internal/core/domain"
	logicv1 "github.com/duynhlab/auth-service/internal/logic/v1"
	"github.com/duynhlab/auth-service/middleware"
	"github.com/duynhlab/pkg/httpx"
	"github.com/duynhlab/pkg/logger/zapx"
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// msgInvalidRequestBody is the 400 response body for malformed request JSON.
const msgInvalidRequestBody = "Invalid request body"

// logMsgInvalidRequest is the log message for a request that failed binding.
const logMsgInvalidRequest = "Invalid request"

// Handler groups HTTP handlers for the auth API v1.
// Dependencies are injected via the constructor — no global state.
type Handler struct {
	auth *logicv1.AuthService
}

// NewHandler creates a new Handler with the given AuthService.
func NewHandler(auth *logicv1.AuthService) *Handler {
	return &Handler{auth: auth}
}

// RegisterRoutes mounts auth v1 routes using Variant A edge naming
// (see homelab/docs/api/api-naming-convention.md).
func (h *Handler) RegisterRoutes(r gin.IRouter) {
	r.POST("/auth/v1/public/login", h.Login)
	r.POST("/auth/v1/public/register", h.Register)
	r.POST("/auth/v1/public/refresh", h.Refresh)
	r.GET("/auth/v1/public/jwks", h.JWKS)
	// Logout is public (like refresh): it authenticates by the refresh token in
	// the body, so a client with an expired access token can still revoke.
	r.POST("/auth/v1/public/logout", h.Logout)
}

// JWKS serves the JSON Web Key Set for verifying signed access tokens.
// GET /auth/v1/public/jwks
func (h *Handler) JWKS(c *gin.Context) {
	body, err := h.auth.JWKS()
	if err != nil {
		httpx.RespondError(c, http.StatusNotFound, httpx.CodeNotFound, "JWKS not available")
		return
	}
	// Public keys rotate rarely; let verifiers and CDNs cache the key set.
	c.Header("Cache-Control", "public, max-age=300")
	c.Data(http.StatusOK, "application/json", body)
}

// Logout revokes the presented refresh token's whole family, ending the
// session server-side (the outstanding access token simply expires — JWTs are
// stateless). Idempotent — an unknown or already-revoked token still returns
// 200 so clients can safely clear local state.
// POST /auth/v1/public/logout  Body: {"refresh_token": "..."}
func (h *Handler) Logout(c *gin.Context) {
	ctx, span := middleware.StartSpan(c.Request.Context(), "http.request", trace.WithAttributes(
		attribute.String("layer", "web"),
		attribute.String("method", c.Request.Method),
		attribute.String("path", c.Request.URL.Path),
	))
	defer span.End()

	logger := zapx.FromContext(ctx)

	var req domain.LogoutRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		span.SetAttributes(attribute.Bool("request.valid", false))
		span.RecordError(err)
		logger.Error(logMsgInvalidRequest, zap.Error(err))
		httpx.RespondError(c, http.StatusBadRequest, httpx.CodeValidation, msgInvalidRequestBody)
		return
	}

	if err := h.auth.Logout(ctx, req.RefreshToken); err != nil {
		span.RecordError(err)
		logger.Error("Logout failed", zap.Error(err))
		httpx.RespondError(c, http.StatusInternalServerError, httpx.CodeInternal, "Internal server error")
		return
	}

	logger.Info("Refresh family revoked")
	c.JSON(http.StatusOK, gin.H{"message": "logged out"})
}

// Login handles HTTP request for user login.
func (h *Handler) Login(c *gin.Context) {
	ctx, span := middleware.StartSpan(c.Request.Context(), "http.request", trace.WithAttributes(
		attribute.String("layer", "web"),
		attribute.String("method", c.Request.Method),
		attribute.String("path", c.Request.URL.Path),
	))
	defer span.End()

	logger := zapx.FromContext(ctx)

	var req domain.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		span.SetAttributes(attribute.Bool("request.valid", false))
		span.RecordError(err)
		logger.Error(logMsgInvalidRequest, zap.Error(err))
		httpx.RespondError(c, http.StatusBadRequest, httpx.CodeValidation, msgInvalidRequestBody)
		return
	}

	span.SetAttributes(attribute.Bool("request.valid", true))

	// Call business logic layer
	response, err := h.auth.Login(ctx, req)
	if err != nil {
		span.RecordError(err)
		logger.Error("Login failed", zap.Error(err))

		switch {
		case errors.Is(err, logicv1.ErrInvalidCredentials):
			httpx.RespondError(c, http.StatusUnauthorized, httpx.CodeUnauthorized, "Invalid credentials")
		case errors.Is(err, logicv1.ErrUserNotFound):
			// Don't reveal that user doesn't exist (security best practice)
			httpx.RespondError(c, http.StatusUnauthorized, httpx.CodeUnauthorized, "Invalid credentials")
		case errors.Is(err, logicv1.ErrPasswordExpired):
			httpx.RespondError(c, http.StatusForbidden, httpx.CodeForbidden, "Password expired")
		case errors.Is(err, logicv1.ErrAccountLocked):
			httpx.RespondError(c, http.StatusForbidden, httpx.CodeForbidden, "Account locked")
		default:
			httpx.RespondError(c, http.StatusInternalServerError, httpx.CodeInternal, "Internal server error")
		}
		return
	}

	logger.Info("Login successful", zap.String("user_id", response.User.ID))
	c.JSON(http.StatusOK, response)
}

// Register handles HTTP request for user registration.
func (h *Handler) Register(c *gin.Context) {
	ctx, span := middleware.StartSpan(c.Request.Context(), "http.request", trace.WithAttributes(
		attribute.String("layer", "web"),
		attribute.String("method", c.Request.Method),
		attribute.String("path", c.Request.URL.Path),
	))
	defer span.End()

	logger := zapx.FromContext(ctx)

	var req domain.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		span.SetAttributes(attribute.Bool("request.valid", false))
		span.RecordError(err)
		logger.Error(logMsgInvalidRequest, zap.Error(err))
		httpx.RespondError(c, http.StatusBadRequest, httpx.CodeValidation, msgInvalidRequestBody)
		return
	}

	span.SetAttributes(attribute.Bool("request.valid", true))

	// Call business logic layer
	response, err := h.auth.Register(ctx, req)
	if err != nil {
		span.RecordError(err)
		logger.Error("Registration failed",
			zap.Error(err),
			zap.String("username", req.Username),
		)

		switch {
		case errors.Is(err, logicv1.ErrUserExists):
			httpx.RespondError(c, http.StatusConflict, httpx.CodeConflict, "Username or email already exists")
		default:
			httpx.RespondError(c, http.StatusInternalServerError, httpx.CodeInternal, "Internal server error")
		}
		return
	}

	logger.Info("Registration successful", zap.String("user_id", response.User.ID))
	c.JSON(http.StatusCreated, response)
}

// Refresh rotates a refresh token and returns a fresh access + refresh token.
// POST /auth/v1/public/refresh  Body: {"refresh_token": "..."}
func (h *Handler) Refresh(c *gin.Context) {
	ctx, span := middleware.StartSpan(c.Request.Context(), "http.request", trace.WithAttributes(
		attribute.String("layer", "web"),
		attribute.String("method", c.Request.Method),
		attribute.String("path", c.Request.URL.Path),
	))
	defer span.End()

	logger := zapx.FromContext(ctx)

	var req domain.RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		span.SetAttributes(attribute.Bool("request.valid", false))
		span.RecordError(err)
		logger.Error(logMsgInvalidRequest, zap.Error(err))
		httpx.RespondError(c, http.StatusBadRequest, httpx.CodeValidation, msgInvalidRequestBody)
		return
	}

	span.SetAttributes(attribute.Bool("request.valid", true))

	response, err := h.auth.Refresh(ctx, req.RefreshToken)
	if err != nil {
		span.RecordError(err)
		logger.Warn("Refresh failed", zap.Error(err))

		switch {
		case errors.Is(err, logicv1.ErrRefreshInvalid), errors.Is(err, logicv1.ErrRefreshReuse):
			httpx.RespondError(c, http.StatusUnauthorized, httpx.CodeUnauthorized, "Invalid refresh token")
		default:
			httpx.RespondError(c, http.StatusInternalServerError, httpx.CodeInternal, "Internal server error")
		}
		return
	}

	logger.Info("Refresh successful", zap.String("user_id", response.User.ID))
	c.JSON(http.StatusOK, response)
}

