# auth-service

Authentication microservice for user login, registration, and RS256 JWT issuance (RFC-0009 Phase 5: the access token is the **only** credential). Every other service verifies access tokens **locally** against the published JWKS — there is no east-west validation call to auth.

## Features

- User login/registration issuing RS256 JWT access tokens (1 h TTL) + rotating refresh tokens (bcrypt password verification, constant-time user-not-found path)
- Token refresh with rotation and reuse detection — replaying a rotated token revokes the whole token family
- Logout by refresh token — revokes the token family server-side (idempotent); the outstanding access token simply expires
- JWKS publication (`GET /auth/v1/public/jwks`) for local verification by services and Kong's edge `jwt` plugin

## API Endpoints

All HTTP routes follow Variant A naming — single path for browser and in-cluster callers. See [homelab naming convention](https://github.com/duynhlab/homelab/blob/main/docs/api/api-naming-convention.md).

| Method | Path | Audience |
|--------|------|----------|
| `POST` | `/auth/v1/public/login` | public |
| `POST` | `/auth/v1/public/register` | public |
| `POST` | `/auth/v1/public/refresh` | public |
| `POST` | `/auth/v1/public/logout` | public |
| `GET` | `/auth/v1/public/jwks` | public |

Auth is **public-only**: login/register/refresh return `{access_token, refresh_token, expires_in, user}`; logout takes `{refresh_token}` in the body (so an expired access token can still revoke) and revokes the family. The `/private/` prefix was removed with the opaque tokens.

- Browser: `https://gateway.duynh.me/auth/v1/public/…`
- In-cluster JWKS: `http://auth.auth.svc.cluster.local:8080/auth/v1/public/jwks`

## Token model (JWT-only)

auth-service is **HTTP-only** — the gRPC `GetMe` server was removed in RFC-0009 Phase 5. It signs RS256 access tokens (claims `iss/aud/sub/exp/iat/nbf/jti/username/email`, `kid` in the header) and publishes the matching JWKS. Services verify tokens locally via `pkg/authmw` (`MiddlewareJWT`), and Kong pre-checks them at the edge — no runtime call to auth on the hot path. Refresh tokens are opaque, sha256-hashed at rest, family-tracked, and rotated on every refresh; reuse detection revokes the family.

## Observability

- **Metrics**: HTTP RED metrics (`request_duration_seconds`, `requests_in_flight`, request/response sizes) are recorded by the Prometheus middleware on `/metrics`. The platform ServiceMonitor scrapes `/metrics`.
- **Tracing**: OpenTelemetry traces are exported via OTLP HTTP to the OTel Collector. The middleware chain runs in order **tracing → logging → metrics**.
- **Logging**: structured Zerolog. The logging middleware derives `trace_id` from the active OTel span (`obsx.TraceIDFromContext`) for log↔trace correlation, falling back to inbound trace headers or a generated ID.
- **Profiling**: Pyroscope continuous profiling (`PROFILING_ENABLED`, default on).

## Tech Stack

- Go + Gin framework
- RS256 JWT signing + JWKS (`internal/core/jwt`), refresh-token rotation with reuse detection
- PostgreSQL 17 (auth-db cluster, HA) via pgx/v5
- Connection pooler (PgBouncer / transaction-mode pooler) — simple protocol, statement cache disabled
- OpenTelemetry tracing + metrics, Zerolog logging, Pyroscope profiling

## Configuration

Environment-based (12-factor), loaded by `config/config.go` with validation. Selected variables:

| Variable | Default | Purpose |
|----------|---------|---------|
| `SERVICE_NAME` | (required) | Service name (`auth`) |
| `PORT` | `8080` | HTTP listen port |
| `ENV` | `development` | `dev`/`staging`/`production` |
| `JWT_ISSUER` / `JWT_AUDIENCE` | `https://gateway.duynh.me` / `duynhlab-platform` | Access-token `iss`/`aud` (must match Kong + authmw) |
| `JWT_ACCESS_TTL` / `JWT_REFRESH_TTL` | `1h` / `720h` | Token lifetimes |
| `JWT_PRIVATE_KEY_PEM` | (empty) | RS256 signing key; empty = ephemeral dev key, **required in production** |
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
- Docker (only for the integration tests — see [Testing](#testing))

### Local Development

```bash
# Install dependencies
go mod tidy
go mod download

# Build
go build ./...

# Unit tests (no Docker needed)
go test ./...

# Lint (must pass before PR merge)
golangci-lint run --timeout=10m

# Run locally (requires .env or env vars)
go run cmd/main.go
```

### Testing

Unit tests use the stdlib `testing` package with hand-written mocks and table-driven
subtests (no testify/gomock). The **repository layer** is covered by **integration tests**
against a real PostgreSQL via [testcontainers](https://golang.testcontainers.org/).

```bash
# Unit tests (no Docker)
go test ./...

# With coverage (as CI runs it)
go test -race -coverprofile=coverage.out ./...

# Integration tests — repository layer, real Postgres (needs a running Docker daemon)
go test -tags=integration ./internal/core/repository/...
```

Integration tests are build-tagged `//go:build integration`, so the default `go test ./...`
skips them and the service binary never links testcontainers. CI runs both jobs and merges
their coverage into SonarCloud (gate: ≥ 80% on new code).

### Pre-push Checklist

```bash
go build ./... && \
  go test ./... && \
  go test -tags=integration ./internal/core/repository/... && \
  golangci-lint run --timeout=10m
```

## License

MIT
