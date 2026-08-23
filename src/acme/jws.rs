//! Parses and verifies the flattened-JSON JWS every authenticated ACME
//! request arrives as (RFC 8555 §6.2) — **not** compact/dot-form JWT.
//! `{"protected": "...", "payload": "...", "signature": "..."}`.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ring::digest;
use ring::signature::{self, UnparsedPublicKey};
use serde::{Deserialize, Serialize};

use super::error::AcmeError;
use super::nonce::NonceStore;

/// A JSON Web Key, restricted to the two algorithms this server accepts
/// (ES256 / P-256 and RS256).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "kty")]
pub enum Jwk {
    #[serde(rename = "EC")]
    Ec { crv: String, x: String, y: String },
    #[serde(rename = "RSA")]
    Rsa { n: String, e: String },
}

impl Jwk {
    /// RFC 7638 thumbprint: SHA-256 over the canonical JSON of only the
    /// required members, in lexicographic key order, with no whitespace.
    ///
    /// Re-derived from decoded key bytes rather than the client's raw
    /// strings — decode-then-reencode both rejects non-base64url input
    /// and guarantees canonical form, so a client that sent technically-
    /// valid-but-non-canonical base64url still gets the same thumbprint a
    /// compliant client computes on its own end.
    pub fn thumbprint(&self) -> Result<String, AcmeError> {
        let canonical = match self {
            Jwk::Ec { crv, x, y } => {
                let x = canonical_b64(x)?;
                let y = canonical_b64(y)?;
                format!(r#"{{"crv":"{crv}","kty":"EC","x":"{x}","y":"{y}"}}"#)
            }
            Jwk::Rsa { n, e } => {
                let n = canonical_b64(n)?;
                let e = canonical_b64(e)?;
                format!(r#"{{"e":"{e}","kty":"RSA","n":"{n}"}}"#)
            }
        };
        let digest = digest::digest(&digest::SHA256, canonical.as_bytes());
        Ok(URL_SAFE_NO_PAD.encode(digest))
    }
}

fn canonical_b64(s: &str) -> Result<String, AcmeError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| AcmeError::malformed("invalid base64url in jwk"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn decode_b64(s: &str) -> Result<Vec<u8>, AcmeError> {
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| AcmeError::malformed("invalid base64url"))
}

#[derive(Debug, Deserialize)]
struct ProtectedHeader {
    alg: String,
    nonce: String,
    url: String,
    jwk: Option<Jwk>,
    kid: Option<String>,
}

#[derive(Debug, Deserialize)]
struct FlattenedJws {
    protected: String,
    payload: String,
    signature: String,
}

/// Which key a JWS asserts it was signed with — an embedded `jwk` (only
/// valid for new-account), or a `kid` URL the caller must resolve to an
/// existing account's stored key.
#[derive(Debug, Clone)]
pub enum KeyId {
    Jwk(Jwk),
    Kid(String),
}

/// A structurally valid, nonce-checked JWS whose signature has *not* been
/// verified yet — the caller still needs to decide which key to check it
/// against (see [`ParsedJws::verify_signature`]).
#[derive(Debug)]
pub struct ParsedJws {
    pub key_id: KeyId,
    alg: String,
    signing_input: Vec<u8>,
    signature: Vec<u8>,
    payload: Vec<u8>,
}

impl ParsedJws {
    /// Verifies the JWS signature against `key` and returns the decoded
    /// payload bytes on success. `key` is the JWS's own embedded `jwk` for
    /// new-account requests, or the caller's DB-resolved account key for
    /// every `kid`-authenticated request — `parse_and_check_nonce` never
    /// picks this itself, since resolving a `kid` requires a database
    /// lookup this module deliberately stays free of.
    pub fn verify_signature(self, key: &Jwk) -> Result<Vec<u8>, AcmeError> {
        verify_raw(&self.alg, key, &self.signing_input, &self.signature)?;
        Ok(self.payload)
    }
}

/// Parses a flattened-JSON JWS request body, checks its `alg` is one this
/// server supports (never `none`), consumes its nonce, and confirms its
/// `url` matches the request it actually arrived on. Does **not** verify
/// the signature — see [`ParsedJws::verify_signature`].
pub fn parse_and_check_nonce(
    body: &[u8],
    expected_url: &str,
    nonces: &NonceStore,
) -> Result<ParsedJws, AcmeError> {
    let jws: FlattenedJws =
        serde_json::from_slice(body).map_err(|_| AcmeError::malformed("invalid JWS"))?;

    let protected_bytes = decode_b64(&jws.protected)?;
    let header: ProtectedHeader = serde_json::from_slice(&protected_bytes)
        .map_err(|_| AcmeError::malformed("invalid JWS protected header"))?;

    if header.alg != "ES256" && header.alg != "RS256" {
        return Err(AcmeError::bad_signature_algorithm());
    }

    // Consumed as soon as it's seen, valid signature or not — a nonce is
    // single-use the moment it's presented in a syntactically valid
    // request; letting a failed request "return" it for reuse isn't part
    // of the anti-replay contract.
    if !nonces.consume(&header.nonce) {
        return Err(AcmeError::bad_nonce());
    }

    if header.url != expected_url {
        return Err(AcmeError::malformed(
            "the JWS protected header's url does not match the request",
        ));
    }

    let key_id = match (header.jwk, header.kid) {
        (Some(jwk), None) => KeyId::Jwk(jwk),
        (None, Some(kid)) => KeyId::Kid(kid),
        (Some(_), Some(_)) => {
            return Err(AcmeError::malformed(
                "the JWS protected header must carry jwk or kid, not both",
            ))
        }
        (None, None) => {
            return Err(AcmeError::malformed(
                "the JWS protected header must carry jwk or kid",
            ))
        }
    };

    let payload = decode_b64(&jws.payload)?;
    let signature = decode_b64(&jws.signature)?;
    let signing_input = format!("{}.{}", jws.protected, jws.payload).into_bytes();

    Ok(ParsedJws {
        key_id,
        alg: header.alg,
        signing_input,
        signature,
        payload,
    })
}

fn verify_raw(
    alg: &str,
    key: &Jwk,
    signing_input: &[u8],
    signature: &[u8],
) -> Result<(), AcmeError> {
    match (alg, key) {
        ("ES256", Jwk::Ec { crv, x, y }) if crv == "P-256" => {
            let x = decode_b64(x)?;
            let y = decode_b64(y)?;
            if x.len() != 32 || y.len() != 32 {
                return Err(AcmeError::malformed("invalid P-256 public key"));
            }
            let mut point = Vec::with_capacity(65);
            point.push(0x04);
            point.extend_from_slice(&x);
            point.extend_from_slice(&y);
            let public_key = UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, point);
            public_key
                .verify(signing_input, signature)
                .map_err(|_| AcmeError::unauthorized("invalid JWS signature"))
        }
        ("RS256", Jwk::Rsa { n, e }) => {
            let n = decode_b64(n)?;
            let e = decode_b64(e)?;
            let public_key = signature::RsaPublicKeyComponents { n, e };
            public_key
                .verify(
                    &signature::RSA_PKCS1_2048_8192_SHA256,
                    signing_input,
                    signature,
                )
                .map_err(|_| AcmeError::unauthorized("invalid JWS signature"))
        }
        _ => Err(AcmeError::bad_signature_algorithm()),
    }
}

#[cfg(test)]
mod tests {
    use axum::response::IntoResponse;
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
    use serde_json::json;

    use super::*;

    struct TestKey {
        key_pair: EcdsaKeyPair,
        jwk: Jwk,
    }

    fn generate_test_key() -> TestKey {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
                .unwrap();
        // Uncompressed SEC1 point: 0x04 || X (32) || Y (32).
        let public = key_pair.public_key().as_ref();
        let x = URL_SAFE_NO_PAD.encode(&public[1..33]);
        let y = URL_SAFE_NO_PAD.encode(&public[33..65]);
        TestKey {
            key_pair,
            jwk: Jwk::Ec {
                crv: "P-256".into(),
                x,
                y,
            },
        }
    }

    /// Builds a flattened-JSON JWS body the way a real ACME client would,
    /// signed with `key`.
    fn sign(
        key: &TestKey,
        url: &str,
        nonce: &str,
        payload_json: serde_json::Value,
        embed_jwk: bool,
        kid: Option<&str>,
    ) -> Vec<u8> {
        let mut header = json!({
            "alg": "ES256",
            "nonce": nonce,
            "url": url,
        });
        if embed_jwk {
            header["jwk"] = serde_json::to_value(&key.jwk).unwrap();
        }
        if let Some(kid) = kid {
            header["kid"] = json!(kid);
        }
        let protected = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload_json).unwrap());
        let signing_input = format!("{protected}.{payload}");

        let rng = SystemRandom::new();
        let sig = key.key_pair.sign(&rng, signing_input.as_bytes()).unwrap();
        let signature = URL_SAFE_NO_PAD.encode(sig.as_ref());

        serde_json::to_vec(&json!({
            "protected": protected,
            "payload": payload,
            "signature": signature,
        }))
        .unwrap()
    }

    #[test]
    fn a_correctly_signed_request_verifies_and_round_trips_the_payload() {
        let key = generate_test_key();
        let nonces = NonceStore::new();
        let nonce = nonces.issue();
        let body = sign(
            &key,
            "https://ca.example/acme/new-account",
            &nonce,
            json!({"termsOfServiceAgreed": true}),
            true,
            None,
        );

        let parsed =
            parse_and_check_nonce(&body, "https://ca.example/acme/new-account", &nonces).unwrap();
        let payload = parsed.verify_signature(&key.jwk).unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(payload["termsOfServiceAgreed"], true);
    }

    #[test]
    fn a_tampered_payload_fails_verification() {
        let key = generate_test_key();
        let nonces = NonceStore::new();
        let nonce = nonces.issue();
        let mut body = sign(
            &key,
            "https://ca.example/acme/new-account",
            &nonce,
            json!({"termsOfServiceAgreed": true}),
            true,
            None,
        );
        // Flip a byte inside the base64url payload field to simulate
        // in-flight tampering.
        let pos = body.windows(6).position(|w| w == b"payloa").unwrap() + 20;
        body[pos] ^= 0x01;

        let parsed =
            parse_and_check_nonce(&body, "https://ca.example/acme/new-account", &nonces).unwrap();
        assert!(parsed.verify_signature(&key.jwk).is_err());
    }

    #[test]
    fn a_url_mismatch_is_rejected() {
        let key = generate_test_key();
        let nonces = NonceStore::new();
        let nonce = nonces.issue();
        let body = sign(
            &key,
            "https://ca.example/acme/new-account",
            &nonce,
            json!({}),
            true,
            None,
        );

        let err =
            parse_and_check_nonce(&body, "https://ca.example/acme/new-order", &nonces).unwrap_err();
        let response = err.into_response();
        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn a_replayed_nonce_is_rejected_the_second_time() {
        let key = generate_test_key();
        let nonces = NonceStore::new();
        let nonce = nonces.issue();
        let url = "https://ca.example/acme/new-account";
        let body = sign(&key, url, &nonce, json!({}), true, None);

        assert!(parse_and_check_nonce(&body, url, &nonces).is_ok());

        // A second request reusing the exact same nonce, even if otherwise
        // well-formed and correctly signed, must be rejected.
        let body2 = sign(&key, url, &nonce, json!({}), true, None);
        let err = parse_and_check_nonce(&body2, url, &nonces).unwrap_err();
        let response = err.into_response();
        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn alg_none_is_rejected_outright() {
        let nonces = NonceStore::new();
        let nonce = nonces.issue();
        let header = json!({"alg": "none", "nonce": nonce, "url": "https://ca.example/x"});
        let protected = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let payload = URL_SAFE_NO_PAD.encode(b"{}");
        let body = serde_json::to_vec(&json!({
            "protected": protected,
            "payload": payload,
            "signature": "",
        }))
        .unwrap();

        let err = parse_and_check_nonce(&body, "https://ca.example/x", &nonces).unwrap_err();
        let response = err.into_response();
        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
        // The nonce must not be silently consumed by a request that never
        // gets far enough to need it protected against replay — but since
        // alg is checked before the nonce, this specific nonce is in fact
        // still outstanding and reusable.
        assert!(nonces.consume(&nonce));
    }

    #[test]
    fn jwk_thumbprint_matches_a_known_rfc7638_test_vector() {
        // The exact key and expected thumbprint from RFC 7638 §3.1.
        let jwk = Jwk::Rsa {
            n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxu\
                hDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_R\
                N5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvR\
                L5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_x\
                BniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
                .to_string(),
            e: "AQAB".to_string(),
        };
        assert_eq!(
            jwk.thumbprint().unwrap(),
            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
        );
    }
}
