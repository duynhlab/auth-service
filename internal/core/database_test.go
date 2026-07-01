package database

import (
	"context"
	"testing"
	"time"

	"github.com/duynhlab/auth-service/config"
)

// TestConnect_ParseError forces pgxpool.ParseConfig to reject the DSN by using
// an invalid sslmode, so Connect returns before ever opening a connection.
func TestConnect_ParseError(t *testing.T) {
	cfg := config.DatabaseConfig{
		Host:     "127.0.0.1",
		Port:     "5432",
		Name:     "auth",
		User:     "auth",
		Password: "secret",
		SSLMode:  "bogus",
	}

	pool, err := Connect(context.Background(), cfg)
	if err == nil {
		if pool != nil {
			pool.Close()
		}
		t.Fatal("Connect() error = nil, want non-nil for invalid sslmode")
	}
}

// TestConnect_PingError uses a valid config pointing at an unreachable host so
// the pool is created but Ping fails, exercising the ping-error path.
func TestConnect_PingError(t *testing.T) {
	cfg := config.DatabaseConfig{
		Host:           "127.0.0.1",
		Port:           "1",
		Name:           "auth",
		User:           "auth",
		Password:       "secret",
		SSLMode:        "disable",
		MaxConnections: 25,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	pool, err := Connect(ctx, cfg)
	if err == nil {
		if pool != nil {
			pool.Close()
		}
		t.Fatal("Connect() error = nil, want non-nil for unreachable host")
	}
}
