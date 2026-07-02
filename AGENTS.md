# auth-service — agent guide

Tight, imperative reference for AI agents. Read this before touching the repo.

## Contribution workflow

**Commits**

- **No attribution trailers.** Never add `Signed-off-by`, `Co-authored-by`, `Assisted-by`, `Generated-by`, or any AI/tool attribution.
- **Subject** ≤ 50 chars, capitalised, imperative, no trailing period (`Add session revocation`, not `Added`/`Adds`).
- **Body** (only if non-trivial): explain *what* and *why*, wrap at 72 chars, one blank line after the subject.
- **No issue refs** in the message (no `Fixes #123`). Put links in the PR description.
- **No @-mentions** of users or teams.

**Branch + PR**

- **Never push to `main`.** Branch first: `feat|fix|chore|docs|refactor|ci/<desc>`.
- Open a PR against `main`. **Squash-merge.**
- Every changed line must trace to the task. Don't refactor or reformat adjacent code.

## Code quality

- Write **idiomatic Go**. Follow existing patterns; match the surrounding style.
- **Wrap errors** with context: `fmt.Errorf("query user %q: %w", name, err)`. Never swallow errors — check or explicit `_ =`.
- **Structured logging** via Zerolog (shared `pkg/logger/zerolog`). No `fmt.Println`.
- **Test** new behaviour. Table-driven tests; keep `go test ./...` green.
- **No secrets** in code, logs, or fixtures. Gitleaks runs in CI.
- Pass `golangci-lint` (v2, `.golangci.yml`) — zero tolerance, CI's `go-check` blocks merge.

## Project overview

`auth-service` — authentication microservice. Module `github.com/duynhlab/auth-service`.

Issues **RS256 JWT access tokens** — the only credential (RFC-0009 Phase 5) — plus rotating, sha256-hashed, family-tracked refresh tokens with reuse detection. Handles login, registration, refresh, and logout (revokes the token family), and publishes the JWKS. **HTTP-only** — there is no gRPC server; every other service verifies JWTs locally against the JWKS.

## Repository layout

```
auth-service/
├── cmd/                     # Entry point: HTTP server, graceful shutdown
├── config/                  # Env-based configuration + validation
├── db/migrations/           # golang-migrate SQL migrations (sql/000001_*.up.sql), embedded in the binary via embed.go
├── internal/
│   ├── web/v1/              # HTTP handlers (Gin) — transport
│   ├── logic/v1/            # Business rules + domain errors (NO SQL)
│   └── core/                # Domain models, repository interfaces, pgx implementations, DB pool
├── middleware/              # tracing, logging, prometheus, profiling, resource
└── Dockerfile
```

## Build, test, lint

```bash
GOTOOLCHAIN=auto go build ./... && go vet ./... && go test ./...   # unit
go test -tags=integration ./internal/core/repository/...           # integration (needs Docker)
golangci-lint run            # v2, .golangci.yml — MUST pass
```

### Testing conventions

- **Unit tests** — stdlib `testing` only (no testify/gomock), hand-written mocks for
  interfaces, table-driven subtests, in `*_test.go` next to the code: Web (`httptest`),
  Logic (pure — mock the repo), gRPC (call handlers directly), `middleware`, `config`. Run
  with `go test ./...` (no Docker).
- **Integration tests** — `internal/core/repository` is tested against a **real Postgres**
  via testcontainers, build-tagged `//go:build integration` (the default `go build`/`go test`
  skip them, so the binary never links testcontainers). Run locally with Docker:
  `go test -tags=integration ./internal/core/repository/...`. CI wires `integration: true`
  (go-check) + `integration-coverage: true` (sonar), and merges both coverage profiles into
  the ≥ 80% new-code gate.
- **Before pushing**, both the unit run *and* the integration suite must be green locally —
  green unit ≠ green CI (CI also runs integration with Docker).

Common lint fixes:

- `perfsprint` — use `errors.New()` over `fmt.Errorf()` when there are no format verbs.
- `nosprintfhostport` — use `net.JoinHostPort()` over `fmt.Sprintf("%s:%s", host, port)`.
- `errcheck` — check every error return (or explicit `_ = fn()`).
- `goconst` / `gocognit` — extract repeated literals / split complex funcs.
- `noctx` — use `http.NewRequestWithContext()`.

## Conventions

### 3-layer architecture (strict)

Dependency direction is **one-way**: `web → logic → core`. Never reverse.

| Layer | Location | Allowed | Forbidden |
|-------|----------|---------|-----------|
| **Web** | `internal/web/v1/` | HTTP handling, JSON binding, DTO mapping, call Logic, aggregation | SQL, direct DB access, business rules |
| **Logic** | `internal/logic/v1/` | Business rules, call repository interfaces, domain errors | SQL, `database.GetPool()`, `*gin.Context`, HTTP |
| **Core** | `internal/core/` | Domain models, repository implementations, SQL, DB pool | HTTP, business orchestration |

- Web is the only transport; it delegates to Logic and returns domain data.
- Use repository interfaces (defined in `core/domain/`) for data access. Constructor-injected dependencies only.
- **Never** call Logic functions across services — use the HTTP transport. **Never** skip Logic (Web must not touch `core/repository` directly).

### JWT issuance (the only credential)

- `internal/core/jwt` signs RS256 access tokens (claims `iss/aud/sub/exp/iat/nbf/jti/username/email`, `kid` header = SHA-256 of the public key) and serves the JWKS.
- `JWT_PRIVATE_KEY_PEM` empty ⇒ ephemeral dev key; **production refuses to start** without a stable key (ephemeral keys break multi-replica verification).
- Minting is **mandatory** — a mint failure fails login/register (there is no other credential).
- Refresh tokens: opaque 32-byte, sha256-hashed at rest, family-tracked (`refresh_tokens`), rotated atomically on refresh; reuse/lost-race revokes the family. Logout revokes the family of the presented refresh token (idempotent).

### Observability

Backed by shared `github.com/duynhlab/pkg/obsx`.

- `obsx.SetupMetrics()` runs in `main`; HTTP RED metrics surface on the single `/metrics` endpoint — **no separate metrics port**. Toggle via `METRICS_ENABLED`.
- HTTP RED metrics come from `middleware/prometheus.go` (`request_duration_seconds`, `requests_in_flight`, `request_size_bytes`, `response_size_bytes`, with trace exemplars).
- `obsx.TraceIDFromContext` gives the logging middleware its `trace_id` for log↔trace correlation (falls back to inbound `traceparent`/`X-Trace-ID`, then a generated ID).
- **Middleware chain order**: `tracing → logging → metrics` (registered in `setupServer`).
- Tracing: OTLP HTTP (`OTEL_COLLECTOR_ENDPOINT`, `OTEL_SAMPLE_RATE`, `TRACING_ENABLED`). Profiling: Pyroscope (`PYROSCOPE_ENDPOINT`, `PROFILING_ENABLED`).

### Diagrams

All diagrams **must** use Mermaid. Never ASCII art.

```mermaid
flowchart LR
    Browser -->|HTTP :8080| Web[web/v1]
    Service -. "JWKS fetch (cached)" .-> Web
    Web --> Logic[logic/v1]
    Logic --> Core[core]
    Core -->|pgx| DB[(auth-db)]
```

## Gotchas

- **Graceful-shutdown order is fixed** (VictoriaMetrics pattern): `/ready` → 503 → drain delay (`READINESS_DRAIN_DELAY`, default 5s) → HTTP `Shutdown` → DB pool `Close` → tracer `Shutdown`. Don't reorder.
- **Kyverno image rules**: deploy images must be `ghcr.io/duynhlab/auth-service/auth:<sha>` (or `:vX.Y.Z`). **Never `:latest`.**
- Migrations run via the `migrate` subcommand (golang-migrate, embedded in the app binary; the init container reuses the app image), applying forward-only `.up.sql` files.
- DB has a **dual connection pattern**: main container via PgBouncer (`auth-db-pooler:5432`), init/migration container direct (`auth-db:5432`) for DDL.

## API reference

Routes mount directly at `/{service}/v1/{audience}/…` (Variant A — one URL shape for browser and in-cluster callers). Kong is pure pass-through.

| Method | Path | Audience | Description |
|--------|------|----------|-------------|
| `POST` | `/auth/v1/public/login` | public | Login → `{access_token, refresh_token, expires_in, user}` |
| `POST` | `/auth/v1/public/register` | public | Register → same response shape as login |
| `POST` | `/auth/v1/public/refresh` | public | Rotate the refresh token, mint a new pair; reuse revokes the family |
| `POST` | `/auth/v1/public/logout` | public | Body `{refresh_token}` — revoke the token family (idempotent) |
| `GET` | `/auth/v1/public/jwks` | public | JWKS for local verification (services + Kong edge) |

Services verify JWTs locally via `pkg/authmw` (`MiddlewareJWT`) against this JWKS — no runtime call to auth-service on the hot path.

Full convention + inventory: [`homelab/docs/api/api-naming-convention.md`](https://github.com/duynhlab/homelab/blob/main/docs/api/api-naming-convention.md).
