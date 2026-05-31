package v1

import (
	"context"
	"errors"
	"testing"

	"github.com/duynhne/auth-service/internal/core/domain"
	logicv1 "github.com/duynhne/auth-service/internal/logic/v1"
	authv1 "github.com/duynhne/pkg/proto/auth/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// stubValidator is a test double for the logic-layer dependency.
type stubValidator struct {
	user *domain.User
	err  error
}

func (s stubValidator) GetUserByToken(_ context.Context, _ string) (*domain.User, error) {
	return s.user, s.err
}

// ctxWithAuth builds an incoming gRPC context carrying an authorization value.
func ctxWithAuth(value string) context.Context {
	return metadata.NewIncomingContext(
		context.Background(),
		metadata.Pairs("authorization", value),
	)
}

func TestServer_GetMe(t *testing.T) {
	validUser := &domain.User{ID: "1", Username: "alice", Email: "alice@example.com"}

	tests := []struct {
		name     string
		ctx      context.Context
		svc      stubValidator
		wantCode codes.Code
		wantUser *authv1.User
	}{
		{
			name:     "no metadata fails closed",
			ctx:      context.Background(),
			wantCode: codes.Unauthenticated,
		},
		{
			name:     "empty authorization fails closed",
			ctx:      ctxWithAuth(""),
			wantCode: codes.Unauthenticated,
		},
		{
			name:     "missing bearer prefix fails closed",
			ctx:      ctxWithAuth("token-without-bearer"),
			wantCode: codes.Unauthenticated,
		},
		{
			name:     "session not found is unauthenticated",
			ctx:      ctxWithAuth("Bearer abc"),
			svc:      stubValidator{err: logicv1.ErrSessionNotFound},
			wantCode: codes.Unauthenticated,
		},
		{
			name:     "session expired is unauthenticated",
			ctx:      ctxWithAuth("Bearer abc"),
			svc:      stubValidator{err: logicv1.ErrSessionExpired},
			wantCode: codes.Unauthenticated,
		},
		{
			name:     "unexpected error is internal",
			ctx:      ctxWithAuth("Bearer abc"),
			svc:      stubValidator{err: errors.New("db unavailable")},
			wantCode: codes.Internal,
		},
		{
			name:     "valid token returns user",
			ctx:      ctxWithAuth("Bearer good-token"),
			svc:      stubValidator{user: validUser},
			wantCode: codes.OK,
			wantUser: &authv1.User{Id: "1", Username: "alice", Email: "alice@example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := NewServer(tt.svc)

			resp, err := srv.GetMe(tt.ctx, &authv1.GetMeRequest{})

			if tt.wantCode == codes.OK {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				got := resp.GetUser()
				if got.GetId() != tt.wantUser.GetId() ||
					got.GetUsername() != tt.wantUser.GetUsername() ||
					got.GetEmail() != tt.wantUser.GetEmail() {
					t.Errorf("user = %+v, want %+v", got, tt.wantUser)
				}
				return
			}

			if status.Code(err) != tt.wantCode {
				t.Errorf("code = %v, want %v (err=%v)", status.Code(err), tt.wantCode, err)
			}
			if resp != nil {
				t.Errorf("expected nil response on error, got %+v", resp)
			}
		})
	}
}
