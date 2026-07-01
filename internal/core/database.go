package database

import (
	"context"
	"fmt"
	"math"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/duynhlab/auth-service/config"
)

// Connect establishes a database connection pool using pgx/v5 from the
// already-parsed application config. Sharing config.DatabaseConfig (and its
// BuildDSN) with the migrate/seed subcommands guarantees the app pool and those
// commands connect with an identical DSN — max connections is applied on the
// pool config here rather than in the DSN string, so it stays a single source
// of truth.
//
// Why pgx instead of lib/pq?
// - pgx uses client-side prepared statements, compatible with PgBouncer
// - lib/pq uses server-side prepared statements which cause errors with connection poolers
// - pgxpool provides built-in connection pooling optimized for PostgreSQL
//
// IMPORTANT: We use SimpleProtocol mode and disable statement caching to work correctly
// with transaction-mode connection poolers (PgCat/PgBouncer). Without this, you may see:
//
//	"prepared statement stmtcache_* does not exist"
func Connect(ctx context.Context, cfg config.DatabaseConfig) (*pgxpool.Pool, error) {
	// Parse DSN into pool config
	poolCfg, err := pgxpool.ParseConfig(cfg.BuildDSN())
	if err != nil {
		return nil, fmt.Errorf("failed to parse database config: %w", err)
	}

	// Apply the configured pool size (kept out of the DSN so the DSN stays
	// identical to the one the migrate/seed subcommands use).
	if cfg.MaxConnections > 0 && cfg.MaxConnections <= math.MaxInt32 {
		poolCfg.MaxConns = int32(cfg.MaxConnections)
	}

	// Configure for transaction-mode poolers (PgCat/PgBouncer):
	// - Use simple protocol to avoid server-side prepared statements
	// - Disable statement cache (prepared statements are connection-scoped)
	// - Disable description cache
	poolCfg.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	poolCfg.ConnConfig.StatementCacheCapacity = 0
	poolCfg.ConnConfig.DescriptionCacheCapacity = 0

	// Create connection pool with the configured settings
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %w", err)
	}

	// Verify connection is working
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return pool, nil
}
