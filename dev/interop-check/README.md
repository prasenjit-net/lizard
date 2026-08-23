# interop-check

Drives the full ACME flow — new-account, new-order, http-01 validation,
finalize, certificate download, revocation — against a running `lizard`
instance using [`instant-acme`](https://docs.rs/instant-acme), a real,
independently maintained Rust ACME client this project doesn't control.

This is deliberately **not** a workspace member of the main `lizard`
crate: it's a standalone Cargo project so its dependencies (and
`instant-acme` pulls in a fair amount) never touch the main binary's
`Cargo.lock` or build.

It exists because hand-written tests miss things a real client catches
immediately — this exact tool caught a genuine RFC 8555 conformance bug
(`/acme/new-nonce` was returning `204` instead of the spec-example's `200`)
that none of this project's own tests noticed. See `../../ACME.md`'s
"Interoperability" section for the full story.

## Run it

1. Start `lizard` in one terminal:

   ```sh
   cd ../.. && cargo run
   ```

2. Run the check in another:

   ```sh
   cargo run
   ```

   By default it targets `http://127.0.0.1:8080/directory`. Pass a
   different directory URL as the first argument to target something else:

   ```sh
   cargo run -- http://127.0.0.1:9000/directory
   ```

You should see each step print (account creation, order, the http-01
token/key-authorization, the issued certificate PEM, revocation), ending
with `INTEROP CHECK PASSED`. A non-zero exit and an `Error: ...` line means
something in the ACME flow broke — the printed step tells you where.

## Why plain HTTP

`instant-acme`'s default HTTP client (`Account::builder()`) is hard-coded
to HTTPS only. `lizard` speaks plain HTTP by design — TLS termination is
meant to be a reverse proxy's job (see the main README) — so this tool
builds its own plain `hyper` client and passes it to
`Account::builder_with_http()` instead. If you point this at a `https://`
URL behind a real reverse proxy, that plain client won't be able to
connect; swap in `Account::builder()` (or `builder_with_root()` for a
self-signed proxy cert) in that case.

## Why not certbot

`certbot --standalone` needs to bind port 80 for its own challenge
responder — ACME identifiers never carry a port, so there's no client-side
flag to change this — which needs root. Not worth the escalation for a
local check; `instant-acme` exercises the same protocol surface without it.
