package database

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/duynhlab/auth-service/config"
	"github.com/duynhlab/pkg/dbx"
)

// Connect builds the service's Postgres pool via the shared dbx helper. dbx
// wires otelpgx query tracing (bounded span names, no bind-parameter or
// connection PII) and pgxpool.* pool-stat metrics, and applies the
// transaction-mode-pooler-safe settings (simple protocol, statement/description
// caches off) required by the PgDog/PgBouncer pooler.
//
// The DSN is cfg.BuildDSN() — the single source shared with the migrate/seed
// subcommands, so the app and those commands connect with an identical DSN.
// MaxConnections stays off the DSN and is applied on the pool config here.
func Connect(ctx context.Context, cfg config.DatabaseConfig) (*pgxpool.Pool, error) {
	return dbx.NewPool(ctx, cfg.BuildDSN(), dbx.WithMaxConns(cfg.MaxConnections))
}
