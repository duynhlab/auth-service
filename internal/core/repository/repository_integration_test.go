//go:build integration

// Integration tests for the PostgreSQL user/session repositories. They run a
// real Postgres via testcontainers-go and apply the service's migrations, so
// they exercise the actual SQL (not a mock). Run with:
//
//	go test -tags=integration ./internal/core/repository/...
//
// Requires a reachable Docker daemon. Excluded from the default `go test ./...`
// unit run by the `integration` build tag.
package repository

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// newTestDB starts a throwaway Postgres, applies the migrations, and returns a
// pool. Everything is torn down via t.Cleanup.
func newTestDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()

	container, err := postgres.Run(ctx, "postgres:16-alpine",
		postgres.WithDatabase("auth"),
		postgres.WithUsername("auth"),
		postgres.WithPassword("secret"),
		testcontainers.WithWaitStrategy(
			wait.ForListeningPort("5432/tcp").WithStartupTimeout(90*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("start postgres container: %v", err)
	}
	t.Cleanup(func() { _ = container.Terminate(ctx) })

	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("connection string: %v", err)
	}

	applyMigrations(t, ctx, dsn)

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("new pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// applyMigrations runs every db/migrations/sql/*.up.sql in lexical order using a
// simple-protocol connection (so multi-statement files execute in one round).
func applyMigrations(t *testing.T, ctx context.Context, dsn string) {
	t.Helper()
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	cfg.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("connect for migrations: %v", err)
	}
	defer conn.Close(ctx)

	// repository -> core -> internal -> <root>/db/migrations/sql
	dir := filepath.Join("..", "..", "..", "db", "migrations", "sql")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read migrations dir: %v", err)
	}
	var files []string
	for _, e := range entries {
		name := e.Name()
		if !e.IsDir() && len(name) > 7 && name[len(name)-7:] == ".up.sql" {
			files = append(files, name)
		}
	}
	sort.Strings(files)
	for _, f := range files {
		sqlBytes, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		if _, err := conn.Exec(ctx, string(sqlBytes)); err != nil {
			t.Fatalf("apply migration %s: %v", f, err)
		}
	}
}

func TestUserRepository_Integration(t *testing.T) {
	pool := newTestDB(t)
	repo := NewUserRepository(pool)
	ctx := context.Background()

	t.Run("GetByUsername finds a seeded user", func(t *testing.T) {
		u, err := repo.GetByUsername(ctx, "alice")
		if err != nil {
			t.Fatalf("GetByUsername: %v", err)
		}
		if u == nil || u.Email != "alice@example.com" || u.PasswordHash == "" {
			t.Errorf("user = %+v, want alice with a password hash", u)
		}
	})

	t.Run("GetByUsername returns nil,nil when absent", func(t *testing.T) {
		u, err := repo.GetByUsername(ctx, "nobody")
		if err != nil {
			t.Fatalf("GetByUsername(absent): %v", err)
		}
		if u != nil {
			t.Errorf("user = %+v, want nil", u)
		}
	})

	t.Run("ExistsByUsernameOrEmail", func(t *testing.T) {
		exists, err := repo.ExistsByUsernameOrEmail(ctx, "alice", "x@x.com")
		if err != nil {
			t.Fatalf("ExistsByUsernameOrEmail: %v", err)
		}
		if !exists {
			t.Error("expected alice to exist")
		}
		exists, err = repo.ExistsByUsernameOrEmail(ctx, "nobody", "none@example.com")
		if err != nil {
			t.Fatalf("ExistsByUsernameOrEmail(absent): %v", err)
		}
		if exists {
			t.Error("did not expect a non-existent user")
		}
	})

	t.Run("Create then UpdateLastLogin", func(t *testing.T) {
		id, err := repo.Create(ctx, "frank", "frank@example.com", "hash")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if id <= 0 {
			t.Errorf("Create id = %d, want > 0", id)
		}
		if err := repo.UpdateLastLogin(ctx, id); err != nil {
			t.Errorf("UpdateLastLogin: %v", err)
		}
	})
}

func TestSessionRepository_Integration(t *testing.T) {
	pool := newTestDB(t)
	repo := NewSessionRepository(pool)
	ctx := context.Background()

	t.Run("GetUserByToken resolves a seeded session", func(t *testing.T) {
		row, err := repo.GetUserByToken(ctx, "demo_token_alice_12345")
		if err != nil {
			t.Fatalf("GetUserByToken: %v", err)
		}
		if row == nil || row.UserID != 1 || row.Username != "alice" {
			t.Errorf("row = %+v, want alice (user 1)", row)
		}
	})

	t.Run("GetUserByToken returns nil,nil for unknown token", func(t *testing.T) {
		row, err := repo.GetUserByToken(ctx, "does-not-exist")
		if err != nil {
			t.Fatalf("GetUserByToken(absent): %v", err)
		}
		if row != nil {
			t.Errorf("row = %+v, want nil", row)
		}
	})

	t.Run("Create then Delete is idempotent", func(t *testing.T) {
		const token = "integration-token"
		if err := repo.Create(ctx, 2, token, time.Now().Add(time.Hour)); err != nil {
			t.Fatalf("Create: %v", err)
		}
		row, err := repo.GetUserByToken(ctx, token)
		if err != nil || row == nil || row.UserID != 2 {
			t.Fatalf("GetUserByToken after create: row=%+v err=%v", row, err)
		}
		if err := repo.Delete(ctx, token); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		row, err = repo.GetUserByToken(ctx, token)
		if err != nil {
			t.Fatalf("GetUserByToken after delete: %v", err)
		}
		if row != nil {
			t.Errorf("row = %+v after delete, want nil", row)
		}
		// Deleting an already-deleted token is a no-op.
		if err := repo.Delete(ctx, token); err != nil {
			t.Errorf("second Delete: %v", err)
		}
	})
}
