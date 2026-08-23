# AGENTS.md

Guidance for coding agents working in this repository.

## Project Overview

`lizard` is an ACME server that issues SSL/TLS certificates signed by its own private CA. It is a single binary built from a fullstack foundation:

- Rust backend using Axum, Tokio, Clap, Serde, Tracing, and `rust-embed`.
- React frontend under `ui/`, built with Vite, TypeScript, Tailwind CSS v4, TanStack Router, and TanStack Query.
- The frontend build output is embedded into the Rust binary from `ui/dist`.

## Repository Layout

- `src/main.rs` wires CLI parsing, configuration, logging, application state, routes, and server startup.
- `src/config.rs` defines TOML configuration and CLI overrides.
- `src/error.rs` defines the shared API error envelope (`AppError`, used by `/api/*`).
- `src/static_assets.rs` serves embedded SPA assets and fallback routing.
- `src/ca.rs` owns the root CA keypair/certificate and signs leaf certificates from CSRs (`rcgen`).
- `src/db.rs` + `src/schema.sql` are the SQLite store for ACME state (accounts, orders, authorizations, challenges, certificates).
- `src/acme/` implements RFC 8555: `jws.rs` (flattened-JSON JWS verification), `nonce.rs` (in-memory anti-replay), `directory.rs`, `account.rs`, `order.rs`, `authz.rs`, `challenge.rs` (real http-01 validation via a background task), `cert.rs` (download + revoke), `error.rs` (`AcmeError`, a separate `application/problem+json` envelope from `AppError`), `urls.rs`. See `ACME.md` for the protocol-level reference and known gaps.
- `src/routes/` contains REST and WebSocket route handlers (`api.rs`, `ws.rs`), and nests `acme::router()` under `/acme/*`.
- `src/services/` contains metrics, task storage, and event broadcasting.
- `ui/src/lib/api.ts` is the typed frontend API client.
- `ui/src/context/` contains Theme, Toast, Config, and WebSocket live data providers.
- `ui/src/components/` contains reusable UI components.
- `ui/src/pages/` contains route pages, including `Certificates.tsx` (CA root cert + issued-certificate table with revoke, live-updating over `/ws`).
- `ui/src/styles/index.css` contains Tailwind entrypoint and theme tokens.

## Common Commands

Backend:

```sh
cargo test
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo run
```

Frontend:

```sh
cd ui && npm test
cd ui && npm run build
cd ui && npm run dev
```

Full build/run:

```sh
make build
make run
```

Development servers:

- Backend: `cargo run` on `127.0.0.1:8080`.
- Frontend: `cd ui && npm run dev` on `localhost:5173`, proxying `/api` and `/ws` to the backend.

## Implementation Notes

- Keep `/api/*` responses using the existing `AppError` / JSON error envelope pattern. `/acme/*` handlers use a deliberately separate `AcmeError` (`application/problem+json`) — do not mix the two envelopes.
- Add new REST handlers in `src/routes/api.rs`, register routes in `src/routes/mod.rs`, and expose typed frontend calls from `ui/src/lib/api.ts`.
- Add new ACME handlers under `src/acme/`, following the existing pattern: `jws::parse_and_check_nonce` → `account::authenticate` (or the embedded `jwk` for new-account) → DB read/write → `super::urls` for any resource URL. See `ACME.md` before touching protocol behavior — several details (nonce handling, ownership-check status codes, SAN matching) are correctness-load-bearing, not stylistic.
- Add new WebSocket event types in `src/services/events.rs` and handle them in `ui/src/context/LiveContext.tsx`.
- Add new pages under `ui/src/pages/`, then update routing and navigation in the existing frontend structure.
- Keep UI styling aligned with the tokens in `ui/src/styles/index.css`; avoid hard-coded one-off colors when a token exists.
- Prefer existing component patterns in `ui/src/components/` before adding new abstractions.
- Do not commit generated artifacts such as `target/`, `ui/dist/`, or `ui/node_modules/` unless explicitly requested.

## Testing Expectations

- For backend changes, run at least `cargo test`; also run `cargo fmt --all -- --check` and `cargo clippy --all-targets -- -D warnings` when practical.
- For frontend changes, run `cd ui && npm test`; run `cd ui && npm run build` for type-checking and production bundle verification.
- For changes spanning backend and frontend contracts, test both sides.

## Configuration

- Runtime config defaults to `config.toml`.
- CLI flags can override config values such as host, port, log level, access log, and config path.
- UI boot configuration is served from `GET /api/config` based on the `[ui]` section of `config.toml`.

