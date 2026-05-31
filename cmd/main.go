package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"

	"github.com/duynhne/auth-service/config"
	database "github.com/duynhne/auth-service/internal/core"
	"github.com/duynhne/auth-service/internal/core/repository"
	grpcv1 "github.com/duynhne/auth-service/internal/grpc/v1"
	logicv1 "github.com/duynhne/auth-service/internal/logic/v1"
	webv1 "github.com/duynhne/auth-service/internal/web/v1"
	"github.com/duynhne/auth-service/middleware"
	"github.com/duynhne/pkg/grpcx"
	"github.com/duynhne/pkg/logger/zerolog"
	authv1 "github.com/duynhne/pkg/proto/auth/v1"
)

func main() {
	// Load configuration
	cfg := config.Load()
	if err := cfg.Validate(); err != nil {
		panic("Configuration validation failed: " + err.Error())
	}

	// Initialize Zerolog with LOG_LEVEL from config
	zerolog.Setup(cfg.Logging.Level)

	log.Info().
		Str("service", cfg.Service.Name).
		Str("version", cfg.Service.Version).
		Str("env", cfg.Service.Env).
		Str("port", cfg.Service.Port).
		Msg("Service starting")

	// Initialize OpenTelemetry tracing
	var tp interface{ Shutdown(context.Context) error }
	var err error
	if cfg.Tracing.Enabled {
		tp, err = middleware.InitTracing(cfg)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to initialize tracing")
		} else {
			log.Info().
				Str("endpoint", cfg.Tracing.Endpoint).
				Float64("sample_rate", cfg.Tracing.SampleRate).
				Msg("Tracing initialized")
		}
	} else {
		log.Info().Msg("Tracing disabled (TRACING_ENABLED=false)")
	}

	// Initialize Pyroscope profiling
	if cfg.Profiling.Enabled {
		if err := middleware.InitProfiling(); err != nil {
			log.Warn().Err(err).Msg("Failed to initialize profiling")
		} else {
			log.Info().
				Str("endpoint", cfg.Profiling.Endpoint).
				Msg("Profiling initialized")
			defer middleware.StopProfiling()
		}
	} else {
		log.Info().Msg("Profiling disabled (PROFILING_ENABLED=false)")
	}

	// Initialize database connection pool (pgx)
	pool, err := database.Connect(context.Background())
	if err != nil {
		log.Error().Err(err).Msg("Failed to connect to database")
		return
	}
	// pool.Close() is called explicitly during graceful shutdown (step 2).
	log.Info().Msg("Database connection pool established")

	// Wire dependencies: Core repositories -> Logic service -> Web handler
	userRepo := repository.NewUserRepository(pool)
	sessionRepo := repository.NewSessionRepository(pool)
	authSvc := logicv1.NewAuthService(userRepo, sessionRepo)
	handler := webv1.NewHandler(authSvc)

	// Optional internal gRPC server (AuthService.GetMe). HTTP :8080 is unaffected.
	grpcSrv := startGRPC(cfg, authSvc)

	// Setup router and server, then run with graceful shutdown
	var isShuttingDown atomic.Bool
	srv := setupServer(cfg, handler, &isShuttingDown)
	runGracefulShutdown(cfg, srv, grpcSrv, pool, tp, &isShuttingDown)
}

// startGRPC starts the internal gRPC server on cfg.GRPC.Port when enabled,
// serving AuthService.GetMe alongside the HTTP listener (dual-port). Returns nil
// when disabled. Uses the shared grpcx bootstrap (OpenTelemetry, health,
// reflection).
func startGRPC(cfg *config.Config, authSvc *logicv1.AuthService) *grpc.Server {
	if !cfg.GRPC.Enabled {
		log.Info().Msg("gRPC server disabled (GRPC_ENABLED=false)")
		return nil
	}

	lc := net.ListenConfig{}
	lis, err := lc.Listen(context.Background(), "tcp", ":"+cfg.GRPC.Port)
	if err != nil {
		log.Error().Err(err).Str("port", cfg.GRPC.Port).Msg("Failed to listen for gRPC")
		return nil
	}

	grpcSrv, _ := grpcx.NewServer()
	authv1.RegisterAuthServiceServer(grpcSrv, grpcv1.NewServer(authSvc))

	go func() {
		log.Info().Str("port", cfg.GRPC.Port).Msg("Starting gRPC server")
		if err := grpcSrv.Serve(lis); err != nil {
			log.Error().Err(err).Msg("gRPC server error")
		}
	}()

	return grpcSrv
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
// Shutdown sequence (VictoriaMetrics pattern): /ready → 503 → drain delay → HTTP → Database → Tracer.
func runGracefulShutdown(
	cfg *config.Config,
	srv *http.Server,
	grpcSrv *grpc.Server,
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

	// 1b. Shutdown gRPC server (if enabled)
	if grpcSrv != nil {
		grpcSrv.GracefulStop()
		log.Info().Msg("gRPC server shutdown complete")
	}

	// 2. Close database connection pool
	if pool != nil {
		pool.Close()
		log.Info().Msg("Database connection pool closed")
	}

	// 3. Shutdown tracer
	if tp != nil {
		if err := tp.Shutdown(shutdownCtx); err != nil {
			log.Error().Err(err).Msg("Tracer shutdown error")
		} else {
			log.Info().Msg("Tracer shutdown complete")
		}
	}

	log.Info().Msg("Graceful shutdown complete")
}
