//! Every ACME resource URL this server hands out, built off
//! `state.external_base_url` in one place so order/authz/challenge/account
//! responses can never drift from each other or from `directory.rs`.

use crate::state::SharedState;

pub fn new_account(state: &SharedState) -> String {
    format!("{}/acme/new-account", state.external_base_url)
}

pub fn new_order(state: &SharedState) -> String {
    format!("{}/acme/new-order", state.external_base_url)
}

pub fn account(state: &SharedState, id: &str) -> String {
    format!("{}/acme/account/{id}", state.external_base_url)
}

pub fn order(state: &SharedState, id: &str) -> String {
    format!("{}/acme/order/{id}", state.external_base_url)
}

pub fn order_finalize(state: &SharedState, id: &str) -> String {
    format!("{}/acme/order/{id}/finalize", state.external_base_url)
}

pub fn authz(state: &SharedState, id: &str) -> String {
    format!("{}/acme/authz/{id}", state.external_base_url)
}

pub fn challenge(state: &SharedState, id: &str) -> String {
    format!("{}/acme/challenge/{id}", state.external_base_url)
}

pub fn certificate(state: &SharedState, id: &str) -> String {
    format!("{}/acme/cert/{id}", state.external_base_url)
}

pub fn revoke_cert(state: &SharedState) -> String {
    format!("{}/acme/revoke-cert", state.external_base_url)
}
