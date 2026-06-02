# auth-service

> AI Agent context for understanding this repository

## 📋 Overview

Authentication microservice for the monitoring platform. Provides user login, registration, session management, and token validation. Exposes both an HTTP API (browser + in-cluster) and a gRPC `AuthService/GetMe` server — the latter is the east-west authority every other service calls to validate bearer tokens.

Module path: `github.com/duynhlab/auth-service`.

## 🏗️ Architecture Guidelines

### 3-Layer Architecture

| Layer | Location | Responsibility |
|-------|----------|----------------|
| **Web** | `internal/web/v1/handler.go` | HTTP handling, validation, error translation |
| **gRPC** | `internal/grpc/v1/server.go` | gRPC transport for `AuthService/GetMe` — thin adapter over Logic, mirrors Web |
| **Logic** | `internal/logic/v1/service.go` | Business rules (❌ NO SQL) |
| **Core** | `internal/core/` | Domain models, repositories, database |

Both transports (Web HTTP handlers and the gRPC server) sit at the same level and delegate to the shared Logic layer, so they return identical data.

### 3-Layer Coding Rules

**CRITICAL**: Strict layer boundaries. Violations will be rejected in code review.

#### Layer Boundaries

| Layer | Location | ALLOWED | FORBIDDEN |
|-------|----------|---------|-----------|
| **Web** | `internal/web/v1/` | HTTP handling, JSON binding, DTO mapping, call Logic, aggregation | SQL queries, direct DB access, business rules |
| **Logic** | `internal/logic/v1/` | Business rules, call repository interfaces, domain errors | SQL queries, `database.GetPool()`, HTTP handling, `*gin.Context` |
| **Core** | `internal/core/` | Domain models, repository implementations, SQL queries, DB connection | HTTP handling, business orchestration |

#### Dependency Direction

```
Web -> Logic -> Core (one-way only, never reverse)
```

- Web imports Logic and Core/domain
- Logic imports Core/domain and Core/repository interfaces
- Core imports nothing from Web or Logic

#### DO

- Put HTTP handlers, request validation, error-to-status mapping in `web/`
- Put business rules, orchestration, transaction logic in `logic/`
- Put SQL queries in `core/repository/` implementations
- Use repository interfaces (defined in `core/domain/`) for data access in Logic layer
- Use dependency injection (constructor parameters) for all service dependencies

#### DO NOT

- Write SQL or call `database.GetPool()` in Logic layer
- Import `gin` or handle HTTP in Logic layer
- Put business rules in Web layer (Web only translates and delegates)
- Call Logic functions directly from another service (use HTTP aggregation in Web layer)
- Skip the Logic layer (Web must not call Core/repository directly)

### Directory Structure

```
auth-service/
├── cmd/main.go              # Entry point: dual-port (HTTP + gRPC), graceful shutdown
├── config/config.go         # Environment-based configuration
├── db/migrations/sql/       # Flyway SQL migrations
├── internal/
│   ├── core/
│   │   ├── database.go      # PostgreSQL connection pool (pgx)
│   │   ├── domain/          # Domain models + repository interfaces (user, session)
│   │   └── repository/      # pgx repository implementations (user, session)
│   ├── logic/v1/
│   │   ├── service.go       # Business logic layer
│   │   └── errors.go        # Domain errors
│   ├── grpc/v1/server.go    # gRPC AuthService server (GetMe)
│   └── web/v1/handler.go    # HTTP handlers (Gin)
├── middleware/              # tracing, logging, prometheus, profiling, resource
└── Dockerfile
```

## 🛠️ Development Workflow

### Code Quality

**MANDATORY**: All code changes MUST pass lint before committing.

- Linter: `golangci-lint` v2+ with `.golangci.yml` config (60+ linters enabled)
- Zero tolerance: PRs with lint errors will NOT be merged
- CI enforces: `go-check` job runs lint on every PR

#### Commands (run in order)

```bash
go mod tidy              # Clean dependencies
go build ./...           # Verify compilation
go test ./...            # Run tests
golangci-lint run --timeout=10m  # Lint (MUST pass)
```

#### Pre-commit One-liner

```bash
go build ./... && go test ./... && golangci-lint run --timeout=10m
```

### Common Lint Fixes

- `perfsprint`: Use `errors.New()` instead of `fmt.Errorf()` when no format verbs
- `nosprintfhostport`: Use `net.JoinHostPort()` instead of `fmt.Sprintf("%s:%s", host, port)`
- `errcheck`: Always check error returns (or explicitly `_ = fn()`)
- `goconst`: Extract repeated string literals to constants
- `gocognit`: Extract helper functions to reduce complexity
- `noctx`: Use `http.NewRequestWithContext()` instead of `http.NewRequest()`

## 🔧 Tech Stack

| Component | Technology |
|-----------|------------|
| HTTP Framework | Gin |
| gRPC | `AuthService/GetMe` server via shared `pkg/grpcx` |
| Database | PostgreSQL 17 via pgx/v5 |
| Logging | Zerolog (shared `pkg/logger/zerolog`) |
| Tracing | OpenTelemetry (OTLP HTTP) |
| Metrics | OpenTelemetry + Prometheus via shared `pkg/obsx` |
| Profiling | Pyroscope |
| Passwords | bcrypt |
| Sessions | Opaque crypto-random tokens (not JWT), 24h expiry |

## 🏗️ Infrastructure Details

### Database

| Component | Value |
|-----------|-------|
| **Cluster** | auth-db (Zalando Postgres Operator) |
| **PostgreSQL** | 17 |
| **HA** | 3 nodes (1 leader + 2 standbys) |
| **Pooler** | PgBouncer Sidecar (2 instances) |
| **Endpoint** | `auth-db-pooler.auth.svc.cluster.local:5432` |

**Dual Connection Pattern:**
- **Main container**: PgBouncer (`auth-db-pooler:5432`)
- **Init container**: Direct (`auth-db:5432`) - for DDL migrations

### Graceful Shutdown

**VictoriaMetrics Pattern:**
1. `/ready` → 503 when shutting down
2. Drain delay (`READINESS_DRAIN_DELAY`, default 5s)
3. Sequential: HTTP → gRPC (`GracefulStop`) → Database → Tracer

## 📡 gRPC Server (east-west transport)

auth-service runs a gRPC server **alongside** the HTTP listener (dual-port; HTTP `:8080` is unaffected). It serves `auth.v1.AuthService/GetMe` on `GRPC_PORT` (default `9090`), which every other service's auth middleware calls to validate the bearer token carried in gRPC metadata.

- gRPC is the **official east-west transport** — the server always runs (no REST fallback, no `GRPC_ENABLED` flag). Only the port is configurable; `startGRPC` returns `nil` only if it cannot bind.
- Bootstrapped via shared `github.com/duynhlab/pkg/grpcx` (`grpcx.NewServer` wires OpenTelemetry stats handler, health, reflection).
- `internal/grpc/v1` is a thin adapter over the same Logic layer as the HTTP handlers — both paths return identical data.
- Token validation mirrors `GET /auth/v1/private/me`. Missing/malformed/invalid/expired token → `codes.Unauthenticated` (fail closed); other errors → `codes.Internal`.

## 📊 Observability

`obsx.SetupMetrics()` runs in `main` **before** the gRPC server/dial bootstrap so the otelgrpc handlers pick up the global MeterProvider.

- **Metrics**: HTTP RED metrics from `middleware/prometheus.go` (`request_duration_seconds`, `requests_in_flight`, `request_size_bytes`, `response_size_bytes`, with trace exemplars). `obsx.SetupMetrics()` bridges gRPC RED metrics (`rpc_server_*` / `rpc_client_*`) onto the **same** Prometheus registry and the **same** `/metrics` endpoint — there is **no separate metrics port**. The platform ServiceMonitor scrapes `/metrics`. Toggle via `METRICS_ENABLED`.
- **Middleware chain order**: `tracing → logging → metrics` (registered in `setupServer`).
- **Logging**: the logging middleware derives `trace_id` from the active OTel span via `obsx.TraceIDFromContext` for log↔trace correlation, falling back to inbound `traceparent`/`X-Trace-ID` headers, then a generated ID.
- **Tracing**: OpenTelemetry OTLP HTTP export (`OTEL_COLLECTOR_ENDPOINT`, `OTEL_SAMPLE_RATE`). Toggle via `TRACING_ENABLED`.
- **Profiling**: Pyroscope continuous profiling (`PROFILING_ENABLED`, `PYROSCOPE_ENDPOINT`).

## 🔌 API Reference

Routes are mounted directly at `/{service}/v1/{audience}/…` (Variant A — single URL shape across browser and in-cluster callers). Kong is pure pass-through.

| Method | Path | Audience | Description |
|--------|------|----------|-------------|
| `POST` | `/auth/v1/public/login` | public | User login, returns an opaque session token |
| `POST` | `/auth/v1/public/register` | public | User registration, returns a session token |
| `GET` | `/auth/v1/private/me` | private | Returns current user from `Authorization: Bearer <token>` |
| `POST` | `/auth/v1/private/logout` | private | Revokes the caller's session token (idempotent) |

**gRPC** (east-west, not on the gateway): `auth.v1.AuthService/GetMe` on `:9090` — token in gRPC metadata, called by every other service's auth middleware to validate. Mirrors `GET /auth/v1/private/me`.

Full convention + inventory: [`homelab/docs/api/api-naming-convention.md`](https://github.com/duynhlab/homelab/blob/main/docs/api/api-naming-convention.md).
