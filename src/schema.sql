-- ACME state. Timestamps are RFC 3339 strings (UTC); booleans are 0/1.
--
-- orders.certificate_id and certificates.order_id reference each other:
-- an order is always created first (certificate_id NULL), and only once
-- issuance succeeds does a certificates row get inserted and the order
-- updated to point at it — so the cycle never needs a row on one side to
-- exist before the other.

CREATE TABLE IF NOT EXISTS accounts (
    id             TEXT PRIMARY KEY,
    jwk_thumbprint TEXT NOT NULL UNIQUE,
    jwk_json       TEXT NOT NULL,
    status         TEXT NOT NULL,
    contact_json   TEXT,
    tos_agreed     INTEGER NOT NULL DEFAULT 0,
    created_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS certificates (
    id                TEXT PRIMARY KEY,
    order_id          TEXT NOT NULL,
    serial            TEXT NOT NULL UNIQUE,
    pem_chain         TEXT NOT NULL,
    issued_at         TEXT NOT NULL,
    revoked_at        TEXT,
    revocation_reason INTEGER
);

CREATE TABLE IF NOT EXISTS orders (
    id               TEXT PRIMARY KEY,
    account_id       TEXT NOT NULL REFERENCES accounts(id),
    status           TEXT NOT NULL,
    identifiers_json TEXT NOT NULL,
    not_before       TEXT,
    not_after        TEXT,
    expires          TEXT NOT NULL,
    certificate_id   TEXT REFERENCES certificates(id),
    error_json       TEXT,
    created_at       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS authorizations (
    id               TEXT PRIMARY KEY,
    order_id         TEXT NOT NULL REFERENCES orders(id),
    identifier_type  TEXT NOT NULL,
    identifier_value TEXT NOT NULL,
    status           TEXT NOT NULL,
    wildcard         INTEGER NOT NULL DEFAULT 0,
    expires          TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS challenges (
    id               TEXT PRIMARY KEY,
    authorization_id TEXT NOT NULL REFERENCES authorizations(id),
    type             TEXT NOT NULL,
    token            TEXT NOT NULL,
    status           TEXT NOT NULL,
    validated_at     TEXT,
    error_json       TEXT
);

CREATE INDEX IF NOT EXISTS orders_account_id ON orders(account_id);
CREATE INDEX IF NOT EXISTS authorizations_order_id ON authorizations(order_id);
CREATE INDEX IF NOT EXISTS challenges_authorization_id ON challenges(authorization_id);
