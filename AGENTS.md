# auth-service AGENTS guide

Instructions for AI agents and human contributors working in this repository.
Read it before making changes; keep edits surgical and consistent with what is
already here.

## Authority and scope

This repository implements the service. It does **not** define the contract.

- **Canonical contract:** [`homelab/docs/api/auth.md`](https://github.com/duynhlab/homelab/blob/main/docs/api/auth.md)
- **Shared API rules:** [`homelab/docs/api/api.md`](https://github.com/duynhlab/homelab/blob/main/docs/api/api.md)

Implement against those files. When this repository and the contract disagree,
**stop and classify the mismatch** using
[Resolving a mismatch](https://github.com/duynhlab/homelab/blob/main/docs/api/README.md#resolving-a-mismatch)
before changing either side. One class — an implementation that violates the
intended contract — **blocks the release tag**.

No route, payload or error inventory belongs in this file. Manifests, gateway
routing, NetworkPolicy, database topology and platform observability belong to
[duynhlab/homelab](https://github.com/duynhlab/homelab).

## Contribution workflow

- Never commit or push to `main`. Branch first, then open a PR.
- Branch names use conventional prefixes: `feat/`, `fix/`, `docs/`, `chore/`,
  `refactor/`, `test/`.
- Commit subjects: imperative mood, capitalised, ≤ 50 characters, no trailing
  period. Add a body wrapped at 72 characters when the change is non-trivial.
- Do not add attribution trailers (`Signed-off-by`, `Co-authored-by`,
  `Generated-by`, etc.), GitHub issue references, or `@`-mentions in commit
  messages. Put issue links in the PR description.
- PRs are squash-merged. CI (`go-check`) runs build, test and lint on every PR
  and must be green before merge.

## Code quality

- Run `golangci-lint run` (v2+, `.golangci.yml`) and fix every finding before
  committing. Common ones: `perfsprint` (prefer `errors.New` when there are no
  verbs), `nosprintfhostport` (use `net.JoinHostPort`), `errcheck` (check every
  error or explicitly discard it), `noctx` (use the `*WithContext` constructors),
  `goconst` / `gocognit`.
- Keep changes idiomatic: dependency injection via constructor parameters,
  structured logging with zap, context propagation on all I/O.
- Before pushing or opening a PR, verify Sonar new-code coverage ≥80%: run
  `go test -race -coverprofile=coverage.out ./...` and confirm changed lines are
  covered, including BOTH branches of any new conditional. `**/cmd/**`,
  `**/db/migrations/**` and `**/core/repository/**` are coverage-excluded.

## Build, test, lint

These are the commands CI runs, so a green local run means a green pipeline.

```bash
go build ./...
go vet ./...
go test -race ./...
go test -tags=integration ./internal/core/repository/...   # needs Docker (testcontainers)
golangci-lint run
```

Local development against an unreleased `pkg`: `pkg` is one module per package,
so its root has no `go.mod` and a single `replace github.com/duynhlab/pkg` can no
longer resolve. Use one commented `replace` line per module — the trailer in
`go.mod` shows the shape, and
[`docs/api/pkg.md`](https://github.com/duynhlab/homelab/blob/main/docs/api/pkg.md)
explains why.

## Architecture boundaries

**3-layer, dependencies flow one way only: transport → logic → core.**

- **Transport** — `internal/web/v1/` only. **This service is HTTP-only:** there
  is no gRPC package, no gRPC dependency, and nothing to test as a gRPC handler.
- **Logic** — `internal/logic/v1/` holds the credential rules, the refresh-token
  family behaviour, and metrics.
- **Core** — `internal/core/` owns the domain, the repositories, and the RS256
  signer that mints tokens and serves the key set.

Observability is wired once through `github.com/duynhlab/pkg/obsx`; the pool comes
from `github.com/duynhlab/pkg/dbx`; responses use the shared
`github.com/duynhlab/pkg/httpx` envelope; logging is zap via
`github.com/duynhlab/pkg/logger/zapx`.

## Invariants

This service is the platform's root of trust. Each rule below exists because
breaking it either lets someone in or locks everyone out.

- **User enumeration is defended in constant time.** The not-found path still
  runs a password comparison against a dummy hash, so login timing does not
  reveal whether a username exists. That hash is built from fresh random bytes at
  startup — no literal in the source for a scanner to flag, and no hash that
  could correspond to a guessable password.
- **Refresh tokens are hashed at rest.** Only the hash is stored, so a database
  leak cannot yield usable tokens.
- **Rotation is atomic: claim the presented token and insert its successor in the
  same family, in one transaction.** A failed claim means the token was
  concurrently rotated or replayed.
- **A replayed token is theft, and the whole family is revoked.** A token whose
  used marker is already set, or a lost claim race, both mean reuse.
- **Expiry is not theft.** An expired token returns invalid and *returns before*
  the reuse branch, so an ordinary expiry never revokes a family. Reordering
  those checks would log people out for being slow.
- **A failed revoke must be loud.** It records the span error and returns a 500
  rather than a silent 401 — a quiet failure there leaves a compromised family
  live. The reuse metric is counted *before* the revoke, because reuse was
  detected regardless of whether the revoke then succeeded.
- **Logout is idempotent and works with a dead access token.** An unknown or
  already-revoked token is not an error, and the refresh token travels in the
  body precisely so an expired access token can still revoke its family.
- **A nil repository fails closed, never panics.** The repository is optional by
  constructor contract, so a signer-but-no-repository deployment must degrade to
  invalid rather than crash.
- **Minting an access token is mandatory; issuing a refresh token is
  best-effort.** Login and register must fail rather than return a response the
  caller cannot authenticate with — but a refresh-issuance failure must not fail
  the login.
- **An ephemeral signing key is refused in production.** A per-pod key breaks
  multi-replica verification, because each pod would serve a different key set,
  and it invalidates every token on restart. The check runs before the
  observability defers so it fails fast.
- **The key id is derived from the key**, so it is stable for a given key and
  verifiers can cache by it. The key set is served with a five-minute cache
  header; a missing signer answers 404, not 500.
- **Pooler-safe database settings live in `pkg/dbx`.** One DSN serves the app,
  `migrate` and `seed`, so all three connect identically; pool sizing is applied
  to the pool config, not the DSN.
- **`seed` is development-only** and refuses production. It is invoked explicitly
  — never from `migrate` or the serve path — and bypasses golang-migrate so it
  does not share the `schema_migrations` version table.
- **Graceful-shutdown ordering is load-bearing:** readiness 503 → drain delay →
  HTTP shutdown → pool close → OTel last.
- **The log tee mirrors the stdout level**, so debug lines never leave the pod on
  an info-level service.

## Repository map

- `cmd/main.go` — bootstrap, subcommand dispatch, routes, graceful shutdown
- `config/config.go` — env config, validation, `BuildDSN()`
- `internal/web/v1/handler.go` — the HTTP surface, including the deprecated aliases
- `internal/logic/v1/` — credential and refresh-family rules, sentinel errors, metrics
- `internal/core/jwt/signer.go` — RS256 minting and the key set
- `internal/core/domain/`, `internal/core/repository/` — models and Postgres implementations
- `db/migrations/`, `db/seed/` — embedded SQL; seed is development-only
- `middleware/` — tracing and logging only

## Gotchas

- Kyverno admission rejects a workload image tagged `:latest` or unpinned. The
  published image is `ghcr.io/duynhlab/auth-service/auth-service:<tag>` — the
  repository path repeats, and the tag carries no `v` prefix. There is no
  separate migration image; the init container reuses the app image with
  `args: ["migrate"]`.
- Metrics leave over OTLP. There is no `/metrics` endpoint and nothing scrapes
  this service.
- The canonical key-set path is `/auth/v1/public/auth/jwks`. The shorter
  `/auth/v1/public/jwks` is a **deprecated alias** kept for one release — do not
  make it the default anywhere, including in other services' configuration.
- The minted token carries a `roles` claim that is **always an empty array**. It
  is not documented as a platform claim and nothing consumes it; do not build
  authorisation on it without deciding that deliberately.

## API change synchronization

An API change is not done when the code compiles.

- The contract in homelab and this repository move **together** — same change,
  and either the same PR pair or an immediate follow-up.
- Behaviour that is designed but not deployed is marked **`Planned`** in the
  contract; it is never described as current.
- A material mismatch between the contract and this implementation **blocks the
  release tag** until it is reconciled or explicitly accepted.
