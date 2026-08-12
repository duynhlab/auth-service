# auth-service

Issues the platform's credentials: it signs RS256 access tokens, rotates refresh
tokens, and publishes the key set every other service verifies against.

## Responsibilities

- **Owns:** login credentials and password hashes, refresh-token families, the
  signing key and its JWKS, and the `users` table.
- **Does not own:** profile data (`user-service`), authorisation decisions at
  request time — services verify tokens locally against the cached key set, so
  there is no call back here on the hot path — and roles. The token carries a
  `roles` claim that is always empty; nothing populates it yet.

## Tech

| Area | Technology |
|------|------------|
| Runtime | Go 1.26 |
| Transports | HTTP only — no gRPC server, no client, no worker |
| Data | PostgreSQL |
| Platform libraries | `dbx`, `httpx`, `logger/zapx`, `migratex`, `obsx` |

This is the one service that does not use `authmw`: it issues tokens rather than
verifying them.

## API

- **Canonical contract:** [`homelab/docs/api/auth.md`](https://github.com/duynhlab/homelab/blob/main/docs/api/auth.md)
- **Shared conventions:** [`homelab/docs/api/api.md`](https://github.com/duynhlab/homelab/blob/main/docs/api/api.md)
- **Surfaces:** public HTTP for login, register, refresh, logout and the key set,
  plus a set of deprecated pre-v3 aliases kept for one release. HTTP `:8080` also
  carries `/health` and `/ready`.

Routes, payloads, claims and error codes live in the contract, so there is one
place to change when they change.

## Run locally

Prefer the homelab **local-stack** — almost every other service needs a token
from here.

Standalone you need PostgreSQL reachable through the `DB_*` variables. Without a
signing key the service generates an ephemeral one, which is fine locally and
refused in production:

```bash
go run cmd/main.go migrate   # apply schema migrations
go run cmd/main.go seed      # demo users — development only, refuses production
go run cmd/main.go           # serve HTTP :8080
```

## Verify

The commands CI runs, so a green local run means a green pipeline:

```bash
go build ./...
go test -race ./...
go test -tags=integration ./internal/core/repository/...   # needs Docker (testcontainers)
golangci-lint run
```

## Docs

- [Canonical contract](https://github.com/duynhlab/homelab/blob/main/docs/api/auth.md)
- [local-stack guide](https://github.com/duynhlab/homelab/blob/main/local-stack/README.md)

## License

MIT
