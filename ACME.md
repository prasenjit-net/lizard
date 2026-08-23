# ACME implementation notes

`lizard` implements the account/order/authorization/challenge/finalize/
revocation slice of [RFC 8555](https://www.rfc-editor.org/rfc/rfc8555)
against a private root CA it generates on first run (see `src/ca.rs` and
the "Configuration" section of the main README). This document is the
protocol-level reference: what's implemented, how the pieces fit together,
and what's deliberately deferred.

## Endpoints

| Method | Path | Notes |
|---|---|---|
| GET | `/directory` | Unauthenticated. Every other URL below is discovered from here — build ACME clients against this URL, not the paths themselves. |
| GET/HEAD | `/acme/new-nonce` | |
| POST | `/acme/new-account` | Create-or-return-existing, keyed on JWK thumbprint |
| POST | `/acme/account/{id}` | Contact update, deactivation |
| POST | `/acme/new-order` | `dns` identifiers only; wildcards rejected (see below) |
| POST | `/acme/order/{id}` | POST-as-GET |
| POST | `/acme/order/{id}/finalize` | CSR's SANs must exactly match the order's identifiers |
| POST | `/acme/authz/{id}` | POST-as-GET |
| POST | `/acme/challenge/{id}` | Triggers real http-01 validation, async |
| POST | `/acme/cert/{id}` | POST-as-GET; `application/pem-certificate-chain` |
| POST | `/acme/revoke-cert` | Account-key-authenticated only (see below) |

Every response under `/acme/*` carries a fresh `Replay-Nonce` header,
success or error, and errors use `application/problem+json`
(`src/acme/error.rs`) — a different envelope from the rest of the app's
`{"error":{"code","message"}}` shape used by `/api/*`.

## What's supported

- **JWS verification** (`src/acme/jws.rs`) — the flattened-JSON form RFC
  8555 actually uses (not compact/dot-form JWT). ES256 and RS256 only;
  `alg: none` is rejected by construction (only those two strings are ever
  matched). Nonces are single-use and in-memory (`src/acme/nonce.rs`) —
  losing them on restart is harmless, a client just fetches a new one.
- **http-01 challenges** (`src/acme/challenge.rs`) — a real outbound fetch
  to `http://{identifier}/.well-known/acme-challenge/{token}` via a shared
  `reqwest::Client` (limited redirects, 10s timeout), run as a background
  task so `respond_challenge` can answer immediately with `processing`.
- **Certificate issuance** (`src/ca.rs`) — ECDSA P-256, signed directly off
  the root (no intermediate). The CSR's own requested extensions
  (`CA:TRUE`, key usage) are always ignored; every issued leaf gets the
  same fixed non-CA, TLS-server key usage regardless of what the CSR asked
  for.
- **Revocation** — matches a client-submitted certificate back to a stored
  row by SHA-256 of its DER bytes (`certificates.der_sha256`), not by
  parsing ASN.1 out of untrusted input.
- **Ownership checks** — reads (order/authz/cert) return 404 rather than
  403 for a resource that exists but isn't yours, so a client can't use
  them to enumerate other accounts' resource ids. Revocation is the one
  exception: it returns 403, per RFC 8555 §7.6, since reaching that check
  already required possessing the certificate's own bytes.

## Known gaps

- **dns-01 / tls-alpn-01** — not implemented. Wildcard identifiers are
  rejected at `new-order` time (an http-01 challenge for one could never
  validate), rather than creating an order that silently can't finish.
- **Certificate-key-authenticated revocation** — RFC 8555 allows revoking
  with either the account's key or the certificate's own key (proving
  possession without needing an ACME account). Only the account-key path
  is implemented; losing the account but keeping the certificate's key
  doesn't let you revoke it here.
- **Key rollover / external account binding** — not implemented.
  `keyChange` is advertised in the directory for spec-completeness but has
  no handler behind it.
- **In-process TLS** — RFC 8555 requires ACME servers to be reachable over
  HTTPS. This server speaks plain HTTP; the supported deployment model is
  a TLS-terminating reverse proxy in front of it, with `[server].base_url`
  set to the externally-visible HTTPS URL so directory/resource URLs are
  correct. Self-bootstrapping in-process TLS from the CA's own root is a
  natural follow-up, not yet done.
- **SSRF hardening** — `validate_http01` fetches whatever host a
  client-submitted `dns` identifier resolves to, with no allow/deny-list on
  the resulting IP. Smaller blast radius for an internal-only CA than a
  public one, but a real gap worth closing before this sits anywhere less
  trusted (see the doc comment on `validate_http01` in
  `src/acme/challenge.rs`).
- **No admin authentication** — the `/api/*` admin endpoints
  (`/api/ca`, `/api/certificates`, `/api/certificates/{id}/revoke`) have no
  auth of their own, matching the rest of this app's `/api/*` surface today.

## Interoperability

Verified against independently-implemented clients during development (see
commit history for the milestone-by-milestone smoke tests): a
Python/`cryptography`-based client exercising the full account → order →
http-01 → finalize → download → revoke flow, with the returned certificate
chain independently verified against the CA root's public key. Running a
real production ACME client (`certbot`, `acme.sh`) against a live instance
is still open — see the implementation plan for the "interop hardening"
milestone.
