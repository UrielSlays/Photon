//! Shared scaffolding for the env-gated LIVE JMAP integration tests
//! (`live_jmap.rs`, `live_recovery.rs`). Consumed via `mod common;` in each test binary.
//! `tests/common/mod.rs` (subdir form) is a shared module, not its own test binary.
#![allow(dead_code)] // each test binary uses a subset; unused-by-one is not dead overall.

use std::env;

use aruna::jmap::{AccountId, AccountResolver, MessageRefResolver};
use aruna::read_model::ProviderMessageId;
use aruna::{Action, Command, Facet, LogError};
use aruna_jmap::transport::DestructiveWriteGate;
use serde_json::{json, Value};

/// `(url, user, pass)` when the live test is opted-in (`PHOTON_JMAP_IT=1`), else `None` (skip).
pub fn live_env() -> Option<(String, String, String)> {
    if env::var("PHOTON_JMAP_IT").ok().as_deref() != Some("1") {
        eprintln!("live test: PHOTON_JMAP_IT != 1 — skipping (default suite stays hermetic)");
        return None;
    }
    let url = env::var("PHOTON_JMAP_URL").expect("PHOTON_JMAP_URL");
    // Guardrail (matches the transport's DestructiveWriteGate): the Probe sends Basic-auth BEFORE the
    // connector's gate runs, so validate the host here too — a mistyped production URL must NEVER
    // receive the fixture credentials.
    let host = reqwest::Url::parse(&url)
        .ok()
        .and_then(|u| u.host_str().map(String::from))
        .expect("PHOTON_JMAP_URL must be a valid URL");
    DestructiveWriteGate::allow_test_host(&host).expect(
        "PHOTON_JMAP_URL host must be an actual loopback host (literal `localhost` or a loopback IP) \
         — refusing to send fixture credentials to a non-local host",
    );
    Some((
        url,
        env::var("PHOTON_JMAP_USER").expect("PHOTON_JMAP_USER"),
        env::var("PHOTON_JMAP_PASS").expect("PHOTON_JMAP_PASS"),
    ))
}

/// An independent JMAP client used only to DISCOVER ids and VERIFY mailbox membership over the wire —
/// deliberately separate from the `HttpJmapTransport` under test, so the assertions are an
/// out-of-band check, not the transport grading its own homework.
pub struct Probe {
    http: reqwest::blocking::Client,
    base: String,
    user: String,
    pass: String,
}

impl Probe {
    pub fn new(base: &str, user: &str, pass: &str) -> Self {
        Self {
            // Same no-proxy guard as the transport: never route the
            // loopback fixture's Basic-auth credentials through an ambient HTTP_PROXY.
            http: reqwest::blocking::Client::builder()
                .no_proxy()
                .build()
                .expect("build no-proxy probe client"),
            base: base.trim_end_matches('/').to_string(),
            user: user.to_string(),
            pass: pass.to_string(),
        }
    }

    fn post(&self, method_calls: Value) -> Value {
        let body = json!({
            "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
            "methodCalls": method_calls,
        });
        self.http
            .post(format!("{}/jmap/", self.base))
            .basic_auth(&self.user, Some(&self.pass))
            .json(&body)
            .send()
            .expect("jmap post")
            .json()
            .expect("jmap response json")
    }

    pub fn account_id(&self) -> String {
        let session: Value = self
            .http
            .get(format!("{}/jmap/session", self.base))
            .basic_auth(&self.user, Some(&self.pass))
            .send()
            .expect("session request")
            .json()
            .expect("session json");
        session["primaryAccounts"]["urn:ietf:params:jmap:mail"]
            .as_str()
            .expect("mail primary account")
            .to_string()
    }

    pub fn mailbox_for_role(&self, account: &str, role: &str) -> String {
        let r = self.post(json!([[
            "Mailbox/query",
            {"accountId": account, "filter": {"role": role}},
            "0"
        ]]));
        r["methodResponses"][0][1]["ids"][0]
            .as_str()
            .unwrap_or_else(|| panic!("no mailbox with role {role}"))
            .to_string()
    }

    pub fn email_ids_in(&self, account: &str, mailbox: &str) -> Vec<String> {
        let r = self.post(json!([[
            "Email/query",
            {"accountId": account, "filter": {"inMailbox": mailbox}},
            "0"
        ]]));
        r["methodResponses"][0][1]["ids"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|v| v.as_str().map(String::from))
            .collect()
    }

    /// The mailbox ids the email currently belongs to (`Email/get` `mailboxIds`).
    pub fn email_mailboxes(&self, account: &str, email: &str) -> Vec<String> {
        let r = self.post(json!([[
            "Email/get",
            {"accountId": account, "ids": [email], "properties": ["mailboxIds"]},
            "0"
        ]]));
        r["methodResponses"][0][1]["list"][0]["mailboxIds"]
            .as_object()
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default()
    }
}

/// Resolvers that hand the connector the JMAP ids discovered above (the read-side message store is not available yet;
/// here we seed the resolver from the live server's own ids).
pub struct FixedAccount(pub String);
impl AccountResolver for FixedAccount {
    fn resolve_account(&self, _photon_account: &str) -> Option<AccountId> {
        Some(AccountId(self.0.clone()))
    }
}
pub struct FixedMessage(pub String);
impl MessageRefResolver for FixedMessage {
    fn resolve_message(
        &self,
        _photon_account: &str,
        _message_ref: &str,
    ) -> Result<Option<ProviderMessageId>, LogError> {
        Ok(Some(ProviderMessageId(self.0.clone())))
    }
}

/// Build an M0 mail command with an explicit idempotency key.
pub fn cmd(key: &str, action: Action) -> Command {
    Command::new(key, "photon-live", Facet::Mail, action)
}

/// A unique temp SQLite store for a drill phase, minted by the engine's ONE guard: unique per call, the store family removed when
/// the guard drops, a leak a loud failure. Bind it before the store it names.
pub fn unique_sqlite_path(tag: &str) -> aruna::test_temp::TempFile {
    aruna::test_temp::TempFile::sqlite(&format!("aruna-live-{tag}"))
}
