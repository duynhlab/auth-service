# auth-service

Authentication microservice for user login, registration, session management, and token validation. It is the platform's east-west authority: every other service validates bearer tokens by calling auth-service's gRPC `AuthService/GetMe`.

## Features

- User login with opaque session tokens (bcrypt password verification)
- User registration
- Token validation (`GET /auth/v1/private/me` and gRPC `AuthService/GetMe`)
- Session management (create on login/register, revoke on logout)

## API Endpoints

All HTTP routes follow Variant A naming — single path for browser and in-cluster callers. See [homelab naming convention](https://github.com/duynhlab/homelab/blob/main/docs/api/api-naming-convention.md).

| Method | Path | Audience |
|--------|------|----------|
| `POST` | `/auth/v1/public/login` | public |
| `POST` | `/auth/v1/public/register` | public |
| `GET` | `/auth/v1/private/me` | private |
| `POST` | `/auth/v1/private/logout` | private |

- Browser: `https://gateway.duynhne.me/auth/v1/…`
- Service-to-service (JWT validation): `http://auth.auth.svc.cluster.local:8080/auth/v1/private/me`

## gRPC (east-west transport)

auth-service runs a gRPC **server** alongside the HTTP listener (dual-port). It exposes `auth.v1.AuthService/GetMe` on `:9090` (`GRPC_PORT`, default `9090`), which every other service's auth middleware calls to validate the bearer token carried in gRPC metadata. gRPC is the official east-west transport — the server always runs (no REST fallback, no enable/disable flag); only the port is configurable.

The gRPC server is wired via the shared `github.com/duynhlab/pkg/grpcx` bootstrap (OpenTelemetry stats handler, health, reflection). The transport in `internal/grpc/v1` is a thin adapter over the same logic layer used by the HTTP handlers, so both paths return identical data. A missing, malformed, invalid, or expired token yields `codes.Unauthenticated` (fail closed).

## Observability

- **Metrics**: HTTP RED metrics (`request_duration_seconds`, `requests_in_flight`, request/response sizes) are recorded by the Prometheus middleware. `obsx.SetupMetrics()` additionally bridges gRPC RED metrics (`rpc_server_*` / `rpc_client_*`) from the otelgrpc stats handlers onto the **same** Prometheus registry and the **same** `/metrics` endpoint — no separate metrics port. The platform ServiceMonitor scrapes `/metrics`.
- **Tracing**: OpenTelemetry traces are exported via OTLP HTTP to the OTel Collector. The middleware chain runs in order **tracing → logging → metrics**.
- **Logging**: structured Zerolog. The logging middleware derives `trace_id` from the active OTel span (`obsx.TraceIDFromContext`) for log↔trace correlation, falling back to inbound trace headers or a generated ID.
- **Profiling**: Pyroscope continuous profiling (`PROFILING_ENABLED`, default on).

## Tech Stack

- Go + Gin framework
- gRPC server (`AuthService/GetMe`) via shared `pkg/grpcx`
- PostgreSQL 17 (auth-db cluster, HA) via pgx/v5
- Connection pooler (PgBouncer / transaction-mode pooler) — simple protocol, statement cache disabled
- OpenTelemetry tracing + metrics, Zerolog logging, Pyroscope profiling

## Configuration

Environment-based (12-factor), loaded by `config/config.go` with validation. Selected variables:

| Variable | Default | Purpose |
|----------|---------|---------|
| `SERVICE_NAME` | (required) | Service name (`auth`) |
| `PORT` | `8080` | HTTP listen port |
| `GRPC_PORT` | `9090` | gRPC listen port |
| `ENV` | `development` | `dev`/`staging`/`production` |
| `LOG_LEVEL` / `LOG_FORMAT` | `info` / `json` | Logging |
| `METRICS_ENABLED` / `METRICS_PATH` | `true` / `/metrics` | Prometheus metrics |
| `TRACING_ENABLED` | `true` | OpenTelemetry tracing |
| `OTEL_COLLECTOR_ENDPOINT` | `otel-collector-…:4318` | OTLP HTTP endpoint |
| `OTEL_SAMPLE_RATE` | `0.1` | Trace sample rate (0.0–1.0) |
| `PROFILING_ENABLED` / `PYROSCOPE_ENDPOINT` | `true` / `pyroscope-…:4040` | Pyroscope profiling |
| `DB_HOST` / `DB_PORT` / `DB_NAME` / `DB_USER` / `DB_PASSWORD` | — / `5432` / — / — / — | PostgreSQL connection |
| `DB_SSLMODE` | `disable` | SSL mode |
| `DB_POOL_MAX_CONNECTIONS` | `25` | pgx pool size |
| `SHUTDOWN_TIMEOUT` | `10s` | Graceful shutdown timeout |
| `READINESS_DRAIN_DELAY` | `5s` | Delay after `/ready` → 503 before HTTP shutdown |

## Development

### Prerequisites

- Go 1.26+
- [golangci-lint](https://golangci-lint.run/welcome/install/) v2+

### Local Development

```bash
# Install dependencies
go mod tidy
go mod download

# Build
go build ./...

# Test
go test ./...

# Lint (must pass before PR merge)
golangci-lint run --timeout=10m

# Run locally (requires .env or env vars)
go run cmd/main.go
```

### Pre-push Checklist

```bash
go build ./... && go test ./... && golangci-lint run --timeout=10m
```

## License

MIT
