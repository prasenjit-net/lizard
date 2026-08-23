//! Drives the full ACME flow (new-account -> new-order -> http-01 ->
//! finalize -> download -> revoke) against a live lizard instance using
//! `instant-acme`, a real, independently maintained Rust ACME client this
//! project has no control over. See `dev/interop-check/README.md`.

use std::sync::Arc;

use axum::Router;
use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use instant_acme::{
    Account, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus, RetryPolicy,
    RevocationRequest,
};
use rustls_pki_types::CertificateDer;
use tokio::sync::Mutex;

type ChallengeState = Arc<Mutex<Option<(String, String)>>>; // (token, key_authorization)

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let directory_url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "http://127.0.0.1:8080/directory".to_string());

    // instant-acme's default HTTP client is hard-coded https_only(); lizard
    // speaks plain HTTP by design (TLS termination is meant to be a reverse
    // proxy's job — see the main README), so build a plain-HTTP hyper
    // client and hand it to Account::builder_with_http instead of using
    // Account::builder()'s default.
    let http_client = HyperClient::builder(TokioExecutor::new()).build(HttpConnector::new());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    // ACME identifiers never carry a port for real domains, but lizard
    // doesn't care what's in the identifier string, and this sidesteps
    // needing root to bind :80 for a local check.
    let domain = format!("127.0.0.1:{port}");
    println!("== serving http-01 challenge responses on {domain} ==");

    let challenge_state: ChallengeState = Arc::new(Mutex::new(None));
    let state_for_server = challenge_state.clone();
    let app = Router::new().route(
        "/.well-known/acme-challenge/{token}",
        get(move |Path(token): Path<String>| {
            let state = state_for_server.clone();
            async move {
                let guard = state.lock().await;
                match &*guard {
                    Some((expected_token, key_auth)) if *expected_token == token => {
                        (StatusCode::OK, key_auth.clone()).into_response()
                    }
                    _ => StatusCode::NOT_FOUND.into_response(),
                }
            }
        }),
    );
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    println!("== creating account against {directory_url} ==");
    let (account, _credentials) = Account::builder_with_http(Box::new(http_client))
        .create(
            &NewAccount {
                contact: &[],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            directory_url,
            None,
        )
        .await?;
    println!("account: {}", account.id());

    println!("== creating order for {domain} ==");
    let identifier = Identifier::Dns(domain.clone());
    let mut order = account.new_order(&NewOrder::new(&[identifier])).await?;
    println!("order: {}", order.url());

    println!("== walking authorizations, setting up http-01 ==");
    {
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authz = result?;
            let mut challenge = authz
                .challenge(ChallengeType::Http01)
                .ok_or("server did not offer an http-01 challenge")?;
            let key_authorization = challenge.key_authorization();
            println!(
                "  token={} key_authorization={}",
                challenge.token,
                key_authorization.as_str()
            );
            *challenge_state.lock().await = Some((
                challenge.token.clone(),
                key_authorization.as_str().to_string(),
            ));
            challenge.set_ready().await?;
        }
    }

    println!("== polling for order to become ready ==");
    let status = order.poll_ready(&RetryPolicy::default()).await?;
    println!("order status: {status:?}");
    if status != OrderStatus::Ready {
        return Err(format!("order did not become ready (status: {status:?})").into());
    }

    println!("== finalizing (generating CSR via rcgen, requesting issuance) ==");
    let _private_key_pem = order.finalize().await?;

    println!("== polling for the certificate ==");
    let cert_chain_pem = order.poll_certificate(&RetryPolicy::default()).await?;
    println!("\n== ISSUED CERTIFICATE ==\n{cert_chain_pem}");

    if !cert_chain_pem.contains("BEGIN CERTIFICATE") {
        return Err("returned chain does not look like a PEM certificate".into());
    }

    println!("== revoking the certificate ==");
    let der = pem::parse(&cert_chain_pem)?.into_contents();
    let cert_der = CertificateDer::from(der);
    account
        .revoke(&RevocationRequest {
            certificate: &cert_der,
            reason: None,
        })
        .await?;
    println!("revocation request accepted");

    println!(
        "\nINTEROP CHECK PASSED: instant-acme completed the full ACME flow \
         (new-account -> new-order -> http-01 -> finalize -> download -> revoke) \
         against the live server and received a real certificate."
    );
    Ok(())
}
