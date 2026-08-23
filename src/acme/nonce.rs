use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;

/// Single-use anti-replay nonces for JWS-signed ACME requests (RFC 8555
/// §6.5). Deliberately not persisted in `Db` — they're short-lived and
/// losing them on restart just means an outstanding client fetches a new
/// one, which is exactly the "single-use, expiring" contract already
/// implies.
const NONCE_TTL: Duration = Duration::from_secs(3600);

pub struct NonceStore {
    issued: Mutex<HashMap<String, Instant>>,
}

impl NonceStore {
    pub fn new() -> Self {
        Self {
            issued: Mutex::new(HashMap::new()),
        }
    }

    /// Mints a fresh nonce and remembers it as outstanding.
    pub fn issue(&self) -> String {
        let mut bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut bytes);
        let nonce = URL_SAFE_NO_PAD.encode(bytes);

        let mut issued = self.issued.lock().unwrap();
        prune_expired(&mut issued);
        issued.insert(nonce.clone(), Instant::now());
        nonce
    }

    /// Consumes a nonce if it was issued and hasn't been used yet. Returns
    /// `false` for anything unrecognized, already-consumed, or expired.
    pub fn consume(&self, nonce: &str) -> bool {
        let mut issued = self.issued.lock().unwrap();
        prune_expired(&mut issued);
        issued.remove(nonce).is_some()
    }
}

impl Default for NonceStore {
    fn default() -> Self {
        Self::new()
    }
}

fn prune_expired(issued: &mut HashMap<String, Instant>) {
    let now = Instant::now();
    issued.retain(|_, issued_at| now.duration_since(*issued_at) <= NONCE_TTL);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_freshly_issued_nonce_can_be_consumed_exactly_once() {
        let store = NonceStore::new();
        let nonce = store.issue();

        assert!(store.consume(&nonce));
        assert!(!store.consume(&nonce), "a nonce must not be reusable");
    }

    #[test]
    fn an_unknown_nonce_is_rejected() {
        let store = NonceStore::new();
        assert!(!store.consume("never-issued"));
    }

    #[test]
    fn issued_nonces_are_unique() {
        let store = NonceStore::new();
        let a = store.issue();
        let b = store.issue();
        assert_ne!(a, b);
    }
}
