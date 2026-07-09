package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"

	"github.com/duynhlab/auth-service/config"
	migrations "github.com/duynhlab/auth-service/db/migrations"
	seed "github.com/duynhlab/auth-service/db/seed"
	database "github.com/duynhlab/auth-service/internal/core"
	authjwt "github.com/duynhlab/auth-service/internal/core/jwt"
	"github.com/duynhlab/auth-service/internal/core/repository"
	logicv1 "github.com/duynhlab/auth-service/internal/logic/v1"
	webv1 "github.com/duynhlab/auth-service/internal/web/v1"
	"github.com/duynhlab/auth-service/middleware"
	"github.com/duynhlab/pkg/logger/zerolog"
	"github.com/duynhlab/pkg/migratex"
	"github.com/duynhlab/pkg/obsx"
)

func main() {
	// Load configuration
	cfg := config.Load()

	// Initialize Zerolog with LOG_LEVEL from config
	zerolog.Setup(cfg.Logging.Level)

	// Subcommands (`migrate`, `seed`) run an embedded SQL set and exit; no args
	// serves the app.
	if len(os.Args) > 1 {
		if runSubcommand(os.Args[1], cfg) {
			return
		}
	}

	if err := cfg.Validate(); err != nil {
		panic("Configuration validation failed: " + err.Error())
	}

	log.Info().
		Str("service", cfg.Service.Name).
		Str("version", cfg.Service.Version).
		Str("env", cfg.Service.Env).
		Str("port", cfg.Service.Port).
		Msg("Service starting")

	// RS256 access-token signer — the only credential (RFC-0009 Phase 5).
	// Built before the observability defers below so a fatal key-config error is
	// not flagged by gocritic's exitAfterDefer (and fails fast).
	signer, ephemeral, err := authjwt.NewSigner(cfg.JWT.PrivateKeyPEM, cfg.JWT.Issuer, cfg.JWT.Audience, cfg.JWT.AccessTTL)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize JWT signer")
	}
	if ephemeral {
		// An ephemeral per-pod key breaks multi-replica verification (each pod
		// serves a different JWKS) and invalidates all tokens on restart — refuse
		// it in production; keep the convenience for local/dev only.
		if cfg.IsProduction() {
			log.Fatal().Msg("JWT_PRIVATE_KEY_PEM is required in production — refusing to start with an ephemeral signing key")
		}
		log.Warn().Msg("JWT signing key not configured (JWT_PRIVATE_KEY_PEM) — using an EPHEMERAL key; set a stable key in production")
	} else {
		log.Info().Str("kid", signer.Kid()).Msg("JWT signer initialized")
	}

	// Initialize the OTel→Prometheus bridge FIRST (otelgrpc/otelgin metrics on
	// the scraped /metrics endpoint — the flag-off status quo). When
	// OTEL_METRICS_ENABLED=true, SetupObservability below installs the OTLP
	// MeterProvider as the global AFTER this, deliberately superseding the
	// bridge (RFC-0014 dual-emit: client_golang scrape stays untouched either
	// way; only the OTel-instrumented metrics switch transport).
	if cfg.Metrics.Enabled {
		shutdownMetrics, err := obsx.SetupMetrics()
		if err != nil {
			log.Warn().Err(err).Msg("Failed to initialize metrics")
		} else {
			log.Info().Msg("Metrics initialized (gRPC RED metrics on /metrics)")
			defer func() { _ = shutdownMetrics(context.Background()) }()
		}
	}

	// RFC-0014: single OTel wiring point — traces per TRACING_ENABLED, OTLP
	// metrics/logs behind OTEL_METRICS_ENABLED/OTEL_LOGS_ENABLED (default off).
	// The config is built once so the tracer scope name and the startup log
	// reflect the values obsx actually uses.
	otelCfg := obsx.ConfigFromEnv()
	middleware.SetServiceName(otelCfg.ServiceName)
	var tp interface{ Shutdown(context.Context) error }
	obs, err := obsx.SetupObservability(context.Background(), otelCfg)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to initialize OpenTelemetry")
	} else {
		tp = obs
		log.Info().
			Bool("traces", obs.TracerProvider != nil).
			Bool("otlp_metrics", obs.MeterProvider != nil).
			Bool("otlp_logs", obs.LoggerProvider != nil).
			Str("endpoint", otelCfg.Endpoint).
			Float64("sample_rate", otelCfg.SampleRate).
			Msg("OpenTelemetry initialized")
	}

	// Initialize Pyroscope profiling
	if cfg.Profiling.Enabled {
		stopProfiling, err := obsx.SetupProfiling()
		if err != nil {
			log.Warn().Err(err).Msg("Failed to initialize profiling")
		} else {
			log.Info().
				Str("endpoint", cfg.Profiling.Endpoint).
				Msg("Profiling initialized")
			defer func() { _ = stopProfiling(context.Background()) }()
		}
	} else {
		log.Info().Msg("Profiling disabled (PROFILING_ENABLED=false)")
	}

	// Initialize database connection pool (pgx)
	pool, err := database.Connect(context.Background(), cfg.Database)
	if err != nil {
		log.Error().Err(err).Msg("Failed to connect to database")
		return
	}
	// pool.Close() is called explicitly during graceful shutdown (step 2).
	log.Info().Msg("Database connection pool established")

	// Wire dependencies: Core repositories -> Logic service -> Web handler
	userRepo := repository.NewUserRepository(pool)
	refreshRepo := repository.NewRefreshTokenRepository(pool)

	authSvc := logicv1.NewAuthService(userRepo, refreshRepo, signer, cfg.JWT.RefreshTTL)
	handler := webv1.NewHandler(authSvc)

	// Setup router and server, then run with graceful shutdown
	var isShuttingDown atomic.Bool
	srv := setupServer(cfg, handler, &isShuttingDown)
	runGracefulShutdown(cfg, srv, pool, tp, &isShuttingDown)
}

// runSubcommand handles the `migrate` and `seed` subcommands. It returns true
// when a subcommand was recognised and executed (the caller then exits), or
// false to fall through to serving the app.
//
// `migrate` applies the versioned schema migrations and runs in every
// environment (init container, direct DB host). `seed` applies DEV-ONLY demo
// data and is invoked explicitly — never by `migrate` or the serve path — so
// production databases are never seeded.
func runSubcommand(cmd string, cfg *config.Config) bool {
	switch cmd {
	case "migrate":
		if err := migratex.Run(migrations.FS, "sql", cfg.Database.BuildDSN()); err != nil {
			log.Fatal().Err(err).Msg("Schema migration failed")
		}
		log.Info().Msg("Schema migrations applied")
		return true
	case "seed":
		// Demo data is DEV-ONLY; refuse to seed a production database.
		if cfg.IsProduction() {
			log.Fatal().Msg("seed refused in production — demo data is dev-only")
		}
		if err := applySeed(cfg); err != nil {
			log.Fatal().Err(err).Msg("Demo seed failed")
		}
		log.Info().Msg("Demo seed data applied")
		return true
	default:
		return false
	}
}

// applySeed executes the embedded dev-only seed SQL directly against the database.
// It does NOT use golang-migrate: seeds are idempotent (ON CONFLICT) and must not
// share the schema_migrations version table with the schema migrations. Simple
// query protocol lets each multi-statement seed file run in one Exec.
func applySeed(cfg *config.Config) error {
	ctx := context.Background()

	poolCfg, err := pgxpool.ParseConfig(cfg.Database.BuildDSN())
	if err != nil {
		return fmt.Errorf("parse seed DSN: %w", err)
	}
	poolCfg.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return fmt.Errorf("connect for seed: %w", err)
	}
	defer pool.Close()

	entries, err := fs.ReadDir(seed.FS, "sql")
	if err != nil {
		return fmt.Errorf("read seed dir: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".up.sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	for _, name := range names {
		b, readErr := fs.ReadFile(seed.FS, "sql/"+name)
		if readErr != nil {
			return fmt.Errorf("read seed %s: %w", name, readErr)
		}
		if _, execErr := pool.Exec(ctx, string(b)); execErr != nil {
			return fmt.Errorf("apply seed %s: %w", name, execErr)
		}
	}
	return nil
}

// setupServer creates and configures the HTTP server with all routes and middleware.
func setupServer(cfg *config.Config, handler *webv1.Handler, isShuttingDown *atomic.Bool) *http.Server {
	r := gin.Default()

	// Tracing middleware
	r.Use(middleware.TracingMiddleware())

	// Logging middleware
	r.Use(middleware.LoggingMiddleware())

	// Prometheus middleware
	r.Use(middleware.PrometheusMiddleware())

	// Health check
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	// Readiness check
	// Returns 503 once shutdown has started, to drain traffic before HTTP shutdown.
	r.GET("/ready", func(c *gin.Context) {
		if isShuttingDown.Load() {
			c.JSON(http.StatusServiceUnavailable, gin.H{"status": "shutting_down"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// Metrics endpoint
	r.GET("/metrics", gin.WrapH(promhttp.Handler()))

	// Auth v1 routes — Variant A edge naming (see api-naming-convention.md)
	handler.RegisterRoutes(r)

	// Create HTTP server with ReadHeaderTimeout to prevent Slowloris attacks
	return &http.Server{
		Addr:              ":" + cfg.Service.Port,
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
	}
}

// runGracefulShutdown starts the server and handles graceful shutdown.
// Shutdown sequence (VictoriaMetrics pattern): /ready → 503 → drain delay → HTTP → Database → OTel SDK.
func runGracefulShutdown(
	cfg *config.Config,
	srv *http.Server,
	pool *pgxpool.Pool,
	tp interface{ Shutdown(context.Context) error },
	isShuttingDown *atomic.Bool,
) {
	// Start server in a goroutine
	go func() {
		log.Info().Str("port", cfg.Service.Port).Msg("Starting auth service")
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal().Err(err).Msg("Failed to start server")
		}
	}()

	// Graceful shutdown
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	// Wait for shutdown signal
	<-ctx.Done()
	log.Info().Msg("Shutdown signal received")

	// Mark service as shutting down so /ready returns 503 immediately.
	isShuttingDown.Store(true)

	// Fail readiness first and wait for propagation (best practice for K8s rollout).
	drainDelay := cfg.GetReadinessDrainDelayDuration()
	if drainDelay > 0 {
		log.Info().Dur("delay", drainDelay).Msg("Readiness drain delay started")
		time.Sleep(drainDelay)
		log.Info().Dur("delay", drainDelay).Msg("Readiness drain delay completed")
	}

	// Shutdown context with configurable timeout
	shutdownTimeout := cfg.GetShutdownTimeoutDuration()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	log.Info().Dur("timeout", shutdownTimeout).Msg("Shutting down server...")

	// 1. Shutdown HTTP server
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Error().Err(err).Msg("HTTP server shutdown error")
	} else {
		log.Info().Msg("HTTP server shutdown complete")
	}

	// 2. Close database connection pool
	if pool != nil {
		pool.Close()
		log.Info().Msg("Database connection pool closed")
	}

	// 3. Shutdown the OTel SDK — flushes pending spans plus any OTLP
	// metrics/logs providers built behind the RFC-0014 flags.
	if tp != nil {
		if err := tp.Shutdown(shutdownCtx); err != nil {
			log.Error().Err(err).Msg("OpenTelemetry shutdown error")
		} else {
			log.Info().Msg("OpenTelemetry shutdown complete")
		}
	}

	log.Info().Msg("Graceful shutdown complete")
}
