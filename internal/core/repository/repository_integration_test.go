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

	// Apply the dev seed (demo users) too — it lives outside the migration chain
	// (db/seed/sql), so read-path tests must load it explicitly here.
	seedDir := filepath.Join("..", "..", "..", "db", "seed", "sql")
	seedEntries, err := os.ReadDir(seedDir)
	if err != nil {
		t.Fatalf("read seed dir: %v", err)
	}
	var seedFiles []string
	for _, e := range seedEntries {
		name := e.Name()
		if !e.IsDir() && len(name) > 7 && name[len(name)-7:] == ".up.sql" {
			seedFiles = append(seedFiles, name)
		}
	}
	sort.Strings(seedFiles)
	for _, f := range seedFiles {
		sqlBytes, err := os.ReadFile(filepath.Join(seedDir, f))
		if err != nil {
			t.Fatalf("read seed %s: %v", f, err)
		}
		if _, err := conn.Exec(ctx, string(sqlBytes)); err != nil {
			t.Fatalf("apply seed %s: %v", f, err)
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

	t.Run("GetUserByToken resolves an inserted session", func(t *testing.T) {
		var uid int
		if err := pool.QueryRow(ctx,
			`INSERT INTO users(username, email, password_hash) VALUES('sessuser','sessuser@example.com','h') RETURNING id`,
		).Scan(&uid); err != nil {
			t.Fatalf("insert user: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO sessions(user_id, token, expires_at) VALUES($1, $2, now() + interval '1 hour')`,
			uid, "sess-token-integration",
		); err != nil {
			t.Fatalf("insert session: %v", err)
		}
		row, err := repo.GetUserByToken(ctx, "sess-token-integration")
		if err != nil {
			t.Fatalf("GetUserByToken: %v", err)
		}
		if row == nil || row.UserID != uid || row.Username != "sessuser" {
			t.Errorf("row = %+v, want sessuser (user %d)", row, uid)
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

func TestRefreshTokenRepository_Integration(t *testing.T) {
	pool := newTestDB(t)
	repo := NewRefreshTokenRepository(pool)
	ctx := context.Background()

	const family = "11111111-1111-1111-1111-111111111111"

	t.Run("Create then GetByHash joins the user", func(t *testing.T) {
		const hash = "aaaa000000000000000000000000000000000000000000000000000000000001"
		if err := repo.Create(ctx, 1, hash, family, time.Now().Add(time.Hour)); err != nil {
			t.Fatalf("Create: %v", err)
		}
		row, err := repo.GetByHash(ctx, hash)
		if err != nil {
			t.Fatalf("GetByHash: %v", err)
		}
		if row == nil || row.UserID != 1 || row.Username != "alice" || row.FamilyID != family {
			t.Errorf("row = %+v, want alice (user 1) family %s", row, family)
		}
		if row.UsedAt != nil {
			t.Errorf("UsedAt = %v, want nil for a fresh token", row.UsedAt)
		}
	})

	t.Run("GetByHash returns nil,nil for unknown hash", func(t *testing.T) {
		row, err := repo.GetByHash(ctx, "deadbeef00000000000000000000000000000000000000000000000000000000")
		if err != nil {
			t.Fatalf("GetByHash(absent): %v", err)
		}
		if row != nil {
			t.Errorf("row = %+v, want nil", row)
		}
	})

	t.Run("Rotate claims the old token and inserts the new one atomically", func(t *testing.T) {
		const oldHash = "aaaa000000000000000000000000000000000000000000000000000000000002"
		const newHash = "aaaa000000000000000000000000000000000000000000000000000000000003"
		if err := repo.Create(ctx, 1, oldHash, family, time.Now().Add(time.Hour)); err != nil {
			t.Fatalf("Create: %v", err)
		}
		claimed, err := repo.Rotate(ctx, oldHash, newHash, family, 1, time.Now().Add(time.Hour))
		if err != nil {
			t.Fatalf("Rotate: %v", err)
		}
		if !claimed {
			t.Fatal("Rotate claimed = false, want true for a fresh unused token")
		}
		oldRow, err := repo.GetByHash(ctx, oldHash)
		if err != nil || oldRow == nil {
			t.Fatalf("GetByHash(old) after Rotate: row=%+v err=%v", oldRow, err)
		}
		if oldRow.UsedAt == nil {
			t.Error("old UsedAt = nil after Rotate, want a timestamp")
		}
		newRow, err := repo.GetByHash(ctx, newHash)
		if err != nil || newRow == nil {
			t.Fatalf("GetByHash(new) after Rotate: row=%+v err=%v", newRow, err)
		}
		if newRow.FamilyID != family || newRow.UsedAt != nil {
			t.Errorf("new row = %+v, want same family and nil UsedAt", newRow)
		}

		// Rotating an already-used token claims nothing (concurrent/replayed use).
		const raceHash = "aaaa000000000000000000000000000000000000000000000000000000000004"
		claimed, err = repo.Rotate(ctx, oldHash, raceHash, family, 1, time.Now().Add(time.Hour))
		if err != nil {
			t.Fatalf("Rotate(used): %v", err)
		}
		if claimed {
			t.Error("Rotate claimed = true for an already-used token, want false")
		}
		if row, _ := repo.GetByHash(ctx, raceHash); row != nil {
			t.Errorf("row = %+v inserted for a failed claim, want nil", row)
		}

		// Rotating an absent token claims nothing.
		claimed, err = repo.Rotate(ctx, "nope", raceHash, family, 1, time.Now().Add(time.Hour))
		if err != nil {
			t.Errorf("Rotate(absent): %v", err)
		}
		if claimed {
			t.Error("Rotate claimed = true for an absent token, want false")
		}
	})

	t.Run("RevokeFamily deletes all rows and is idempotent", func(t *testing.T) {
		const revokeFamily = "22222222-2222-2222-2222-222222222222"
		const h1 = "bbbb000000000000000000000000000000000000000000000000000000000001"
		const h2 = "bbbb000000000000000000000000000000000000000000000000000000000002"
		for _, h := range []string{h1, h2} {
			if err := repo.Create(ctx, 2, h, revokeFamily, time.Now().Add(time.Hour)); err != nil {
				t.Fatalf("Create %s: %v", h, err)
			}
		}
		if err := repo.RevokeFamily(ctx, revokeFamily); err != nil {
			t.Fatalf("RevokeFamily: %v", err)
		}
		for _, h := range []string{h1, h2} {
			row, err := repo.GetByHash(ctx, h)
			if err != nil {
				t.Fatalf("GetByHash after revoke: %v", err)
			}
			if row != nil {
				t.Errorf("row = %+v after revoke, want nil", row)
			}
		}
		// Revoking an empty family is a no-op.
		if err := repo.RevokeFamily(ctx, revokeFamily); err != nil {
			t.Errorf("second RevokeFamily: %v", err)
		}
	})
}
