// Package v1 implements the gRPC transport for auth, version 1. It is a thin
// adapter over the logic layer (mirroring internal/web/v1) so the gRPC and HTTP
// paths share the same business logic and return identical data.
package v1

import (
	"context"
	"errors"

	"github.com/duynhne/auth-service/internal/core/domain"
	logicv1 "github.com/duynhne/auth-service/internal/logic/v1"
	"github.com/duynhne/pkg/grpcx"
	authv1 "github.com/duynhne/pkg/proto/auth/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TokenValidator is the logic-layer dependency the gRPC server needs.
// *logicv1.AuthService satisfies it.
type TokenValidator interface {
	GetUserByToken(ctx context.Context, token string) (*domain.User, error)
}

// Server implements authv1.AuthServiceServer.
type Server struct {
	authv1.UnimplementedAuthServiceServer

	svc TokenValidator
}

// NewServer creates a gRPC AuthService server backed by the logic service.
func NewServer(svc TokenValidator) *Server {
	return &Server{svc: svc}
}

// GetMe validates the bearer token carried in gRPC metadata and returns the
// authenticated user. It mirrors GET /auth/v1/private/me. A missing, malformed,
// invalid, or expired token yields codes.Unauthenticated (fail closed).
func (s *Server) GetMe(ctx context.Context, _ *authv1.GetMeRequest) (*authv1.GetMeResponse, error) {
	authz, ok := grpcx.TokenFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "missing authorization metadata")
	}

	const bearerPrefix = "Bearer "
	if len(authz) <= len(bearerPrefix) || authz[:len(bearerPrefix)] != bearerPrefix {
		return nil, status.Error(codes.Unauthenticated, "invalid authorization format")
	}
	token := authz[len(bearerPrefix):]

	user, err := s.svc.GetUserByToken(ctx, token)
	if err != nil {
		if errors.Is(err, logicv1.ErrSessionNotFound) || errors.Is(err, logicv1.ErrSessionExpired) {
			return nil, status.Error(codes.Unauthenticated, "invalid or expired token")
		}
		return nil, status.Error(codes.Internal, "failed to validate token")
	}

	return &authv1.GetMeResponse{
		User: &authv1.User{
			Id:       user.ID,
			Username: user.Username,
			Email:    user.Email,
		},
	}, nil
}
