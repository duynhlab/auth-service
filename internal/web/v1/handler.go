package v1

import (
	"errors"
	"net/http"

	"github.com/duynhlab/auth-service/internal/core/domain"
	logicv1 "github.com/duynhlab/auth-service/internal/logic/v1"
	"github.com/duynhlab/auth-service/middleware"
	"github.com/duynhlab/pkg/httpx"
	pkgzerolog "github.com/duynhlab/pkg/logger/zerolog"
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

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
	r.GET("/auth/v1/private/me", h.GetMe)
	r.POST("/auth/v1/private/logout", h.Logout)
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

// Logout revokes the caller's session token. Idempotent — returns 200 on a
// well-formed request so clients can safely clear local state.
func (h *Handler) Logout(c *gin.Context) {
	ctx, span := middleware.StartSpan(c.Request.Context(), "http.request", trace.WithAttributes(
		attribute.String("layer", "web"),
		attribute.String("method", c.Request.Method),
		attribute.String("path", c.Request.URL.Path),
	))
	defer span.End()

	logger := pkgzerolog.FromContext(ctx)

	authHeader := c.GetHeader("Authorization")
	const bearerPrefix = "Bearer "
	if len(authHeader) <= len(bearerPrefix) || authHeader[:len(bearerPrefix)] != bearerPrefix {
		httpx.RespondError(c, http.StatusUnauthorized, httpx.CodeUnauthorized, "Invalid authorization format")
		return
	}
	token := authHeader[len(bearerPrefix):]

	if err := h.auth.Logout(ctx, token); err != nil {
		span.RecordError(err)
		logger.Error().Err(err).Msg("Logout failed")
		httpx.RespondError(c, http.StatusInternalServerError, httpx.CodeInternal, "Internal server error")
		return
	}

	logger.Info().Msg("Session revoked")
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

	logger := pkgzerolog.FromContext(ctx)

	var req domain.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		span.SetAttributes(attribute.Bool("request.valid", false))
		span.RecordError(err)
		logger.Error().Err(err).Msg("Invalid request")
		httpx.RespondError(c, http.StatusBadRequest, httpx.CodeValidation, "Invalid request body")
		return
	}

	span.SetAttributes(attribute.Bool("request.valid", true))

	// Call business logic layer
	response, err := h.auth.Login(ctx, req)
	if err != nil {
		span.RecordError(err)
		logger.Error().Err(err).Msg("Login failed")

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

	logger.Info().Str("user_id", response.User.ID).Msg("Login successful")
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

	logger := pkgzerolog.FromContext(ctx)

	var req domain.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		span.SetAttributes(attribute.Bool("request.valid", false))
		span.RecordError(err)
		logger.Error().Err(err).Msg("Invalid request")
		httpx.RespondError(c, http.StatusBadRequest, httpx.CodeValidation, "Invalid request body")
		return
	}

	span.SetAttributes(attribute.Bool("request.valid", true))

	// Call business logic layer
	response, err := h.auth.Register(ctx, req)
	if err != nil {
		span.RecordError(err)
		logger.Error().
			Err(err).
			Str("username", req.Username).
			Msg("Registration failed")

		switch {
		case errors.Is(err, logicv1.ErrUserExists):
			httpx.RespondError(c, http.StatusConflict, httpx.CodeConflict, "Username or email already exists")
		default:
			httpx.RespondError(c, http.StatusInternalServerError, httpx.CodeInternal, "Internal server error")
		}
		return
	}

	logger.Info().Str("user_id", response.User.ID).Msg("Registration successful")
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

	logger := pkgzerolog.FromContext(ctx)

	var req domain.RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		span.SetAttributes(attribute.Bool("request.valid", false))
		span.RecordError(err)
		logger.Error().Err(err).Msg("Invalid request")
		httpx.RespondError(c, http.StatusBadRequest, httpx.CodeValidation, "Invalid request body")
		return
	}

	span.SetAttributes(attribute.Bool("request.valid", true))

	response, err := h.auth.Refresh(ctx, req.RefreshToken)
	if err != nil {
		span.RecordError(err)
		logger.Warn().Err(err).Msg("Refresh failed")

		switch {
		case errors.Is(err, logicv1.ErrRefreshInvalid), errors.Is(err, logicv1.ErrRefreshReuse):
			httpx.RespondError(c, http.StatusUnauthorized, httpx.CodeUnauthorized, "Invalid refresh token")
		default:
			httpx.RespondError(c, http.StatusInternalServerError, httpx.CodeInternal, "Internal server error")
		}
		return
	}

	logger.Info().Str("user_id", response.User.ID).Msg("Refresh successful")
	c.JSON(http.StatusOK, response)
}

// GetMe handles HTTP request to get current user from session token.
// GET /auth/v1/private/me
// Authorization: Bearer <token>
func (h *Handler) GetMe(c *gin.Context) {
	ctx, span := middleware.StartSpan(c.Request.Context(), "http.request", trace.WithAttributes(
		attribute.String("layer", "web"),
		attribute.String("method", c.Request.Method),
		attribute.String("path", c.Request.URL.Path),
	))
	defer span.End()

	logger := pkgzerolog.FromContext(ctx)

	// Extract token from Authorization header
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		span.SetAttributes(attribute.Bool("auth.present", false))
		httpx.RespondError(c, http.StatusUnauthorized, httpx.CodeUnauthorized, "Authorization header required")
		return
	}

	// Expect "Bearer <token>"
	const bearerPrefix = "Bearer "
	if len(authHeader) <= len(bearerPrefix) || authHeader[:len(bearerPrefix)] != bearerPrefix {
		span.SetAttributes(attribute.Bool("auth.valid_format", false))
		httpx.RespondError(c, http.StatusUnauthorized, httpx.CodeUnauthorized, "Invalid authorization format")
		return
	}
	token := authHeader[len(bearerPrefix):]

	span.SetAttributes(attribute.Bool("auth.present", true))

	// Lookup user by token
	user, err := h.auth.GetUserByToken(ctx, token)
	if err != nil {
		span.RecordError(err)
		logger.Warn().Err(err).Msg("Token lookup failed")

		switch {
		case errors.Is(err, logicv1.ErrSessionNotFound):
			httpx.RespondError(c, http.StatusUnauthorized, httpx.CodeUnauthorized, "Invalid or expired token")
		case errors.Is(err, logicv1.ErrSessionExpired):
			httpx.RespondError(c, http.StatusUnauthorized, httpx.CodeUnauthorized, "Session expired")
		default:
			httpx.RespondError(c, http.StatusInternalServerError, httpx.CodeInternal, "Internal server error")
		}
		return
	}

	logger.Info().Str("user_id", user.ID).Msg("Token validated")
	c.JSON(http.StatusOK, user)
}
