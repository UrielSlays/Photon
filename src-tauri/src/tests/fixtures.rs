//! Shared test fixtures: parked credentials, guarded stores, and scripted connectors.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::{Arc, Mutex};

use aruna::config_knobs::{BackupsKnob, KnobAct};
use aruna::read_coordinator::MAILBOX_INBOX;
use aruna::read_model::ProviderMessageId;
use aruna::read_surface::HeaderSummary;
use aruna::{Action, Command, CommandBus, Connector, IntentLog, SqliteIntentLog};

use crate::credential::{unix_now, GMAIL_TOKEN_FILE};
use crate::session::{PageAnchor, PageFacts, PhotonSession};
use crate::state::PhotonState;
use crate::{ProviderKind, SessionConfig};

/// The one scope the product's exact set holds (`token_refresh::REQUIRED_SCOPES`), spelled
/// here so a witness fixture and the constant cannot drift silently.
pub(crate) const S0_MODIFY: &str = "https://www.googleapis.com/auth/gmail.modify";
pub(crate) const S0_READONLY: &str = "https://www.googleapis.com/auth/gmail.readonly";
pub(crate) const S0_FULL_MAILBOX: &str = "https://mail.google.com/";
/// The mailbox address the fixture mint observed at `users.getProfile`.
pub(crate) const S0_PRINCIPAL: &str = "owner@example.com";

/// A v2 credential document with an arbitrary `grant` member — the seam every G-witness
/// mutates.
pub(crate) fn s0_token_file(expires_at: i64, grant: Option<&str>) -> String {
    let grant = match grant {
        Some(g) => format!(", \"grant\": {g}"),
        None => String::new(),
    };
    format!(
        "{{\"access_token\": \"tok\", \"refresh_token\": \"rt\", \
             \"expires_at\": {expires_at}{grant}}}"
    )
}

/// The CONFORMANT grant: generation 1, the fixture principal, exactly `{gmail.modify}`.
pub(crate) fn s0_grant() -> String {
    s0_grant_with(1, S0_PRINCIPAL, &[S0_MODIFY])
}

pub(crate) fn s0_grant_with(generation: u64, principal: &str, scopes: &[&str]) -> String {
    let scopes = scopes
        .iter()
        .map(|s| format!("\"{s}\""))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "{{\"grant_generation\": {generation}, \"provider_principal\": \"{principal}\", \
             \"effective_scopes\": [{scopes}]}}"
    )
}

/// Minted by the engine's ONE guard (`aruna::test_temp`) — unique
/// per call (it was pid-only, cleared at the START of the next same-named call and never at
/// the end), the tree removed when the guard drops. Bind it BEFORE the state.
pub(crate) fn s0_dir(tag: &str) -> aruna::test_temp::TempDir {
    aruna::test_temp::TempDir::new(&format!("photon-s0-{tag}"))
}

/// Build a state whose provider arm is the PRODUCTION Gmail arm. A parked token file is all
/// `build_gmail_provider` needs — `HttpGmailTransport::connect` takes no base URL and touches
/// no network, so this is hermetic.
///
/// The parked credential expires an hour from NOW: an already-expired one no longer builds an
/// arm at all, so a fixture that wants the Gmail arm has to park a LIVE
/// credential — which is what the production session requires too.
pub(crate) fn gmail_arm_state(tag: &str) -> (aruna::test_temp::TempDir, PhotonState) {
    gmail_arm_state_expiring(tag, unix_now() + 3_600)
}

/// [`gmail_arm_state`] with the mint's expiry stamp under the test's control — the seam every
/// expiry-stamp witness reaches through.
///
/// The directory is the engine's ONE guard (`aruna::test_temp`;
/// it was a pid-only name nothing removed if a test failed before its `remove_dir_all`), and
/// it comes back FIRST — `let (dir, state) =..` drops the state before the guard deletes.
pub(crate) fn gmail_arm_state_expiring(tag: &str, expires_at: i64) -> (aruna::test_temp::TempDir, PhotonState) {
    let dir = aruna::test_temp::TempDir::new(&format!("photon-{tag}"));
    // A fixture that wants the Gmail arm has to park a CONFORMANT v2
    // credential — grant provenance included — which is what the production session
    // requires too.
    std::fs::write(
        dir.join(GMAIL_TOKEN_FILE),
        s0_token_file(expires_at, Some(&s0_grant())),
    )
    .unwrap();
    let state = PhotonState::new(SessionConfig {
        account: "acct".to_string(),
        store_path: dir.join("store.sqlite"),
        provider_kind: ProviderKind::Gmail,
        gmail_secrets_dir: dir.to_path_buf(),
    });
    (dir, state)
}

/// A store path UNIQUE to one test — pid + wall-clock
/// nanos + a per-process counter — owned by a guard that removes the store and its
/// `-wal`/`-shm`/`-journal`/`.photon-init.lock` siblings on `Drop`. Since H5 the guard is the
/// engine's ONE guard (`aruna::test_temp::TempFile`) — the H4 guard here duplicated it and
/// swallowed a failed delete; this one retries past a transient holder and PANICS naming a
/// leak. DECLARE THE GUARD BEFORE anything that opens the store: locals drop in reverse order
/// of declaration (a tuple pattern's bindings too — right to left), so every handle closes
/// before the guard deletes (Windows refuses to delete an open file). The helpers that hand
/// one back put it FIRST in their tuple for exactly this reason. It derefs to `&Path`, and
/// only `&guard` is `AsRef<Path>` — the guard itself can never be moved into an opener.
type StoreGuard = aruna::test_temp::TempFile;

pub(crate) fn unique_store(tag: &str) -> StoreGuard {
    aruna::test_temp::TempFile::sqlite(&format!("photon-{tag}"))
}

/// What a [`session_for`] session owns on disk: its store and its (JMAP: never created)
/// secrets directory — both the engine's ONE guard (the secrets dir
/// was the FIXED `photon-no-secrets`, shared by every session and every run). Derefs to the
/// STORE path, so `path.to_path_buf()`/`&path` at the call sites name the store as before.
pub(crate) struct SessionTemp {
    store: StoreGuard,
    _secrets: aruna::test_temp::TempDir,
}

impl std::ops::Deref for SessionTemp {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.store
    }
}

/// On the reference only, like the guards it holds: the owner is never moved into an opener.
impl AsRef<Path> for &SessionTemp {
    fn as_ref(&self) -> &Path {
        &self.store
    }
}

pub(crate) fn session_for(tag: &str) -> (SessionTemp, PhotonState, Arc<Mutex<PhotonSession>>) {
    let path = SessionTemp {
        store: unique_store(tag),
        _secrets: aruna::test_temp::TempDir::uncreated(&format!("photon-{tag}-no-secrets")),
    };
    let state = PhotonState::new(SessionConfig {
        account: "acct".to_string(),
        store_path: path.to_path_buf(),
        provider_kind: ProviderKind::Jmap,
        gmail_secrets_dir: path._secrets.to_path_buf(),
    });
    let session = state.session().expect("a fresh store opens a session");
    (path, state, session)
}

pub(crate) fn page_row(id: &str, received_at: i64) -> HeaderSummary {
    HeaderSummary {
        provider_id: ProviderMessageId(id.to_string()),
        received_at,
        from_addr: "s@e.com".to_string(),
        from_name: "S".to_string(),
        subject: "subj".to_string(),
        seen: false,
        flagged: false,
        attachments: aruna::read_surface::AttachmentPresence::default(),
    }
}

pub(crate) fn inbox_refs(session: &Arc<Mutex<PhotonSession>>) -> Vec<String> {
    session
        .lock()
        .expect("session lock")
        .headers
        .folder_first_page("acct", MAILBOX_INBOX, 100)
        .expect("read the projection")
        .into_iter()
        .map(|r| r.message_ref)
        .collect()
}

/// The message a plan-verb (or undo) command acts on.
pub(crate) fn s1_fold_message_ref(action: &Action) -> String {
    match action {
        Action::Trash { message_ref }
        | Action::Untrash { message_ref }
        | Action::MarkSpam { message_ref }
        | Action::UnmarkSpam { message_ref } => message_ref.clone(),
        other => panic!("not a plan-verb action: {other:?}"),
    }
}

/// A STATEFUL label-vector connector (the probe connector): every
/// member starts `{INBOX, UNREAD}`; a Trash lands `TRASH` and drops `INBOX`, plus whatever
/// `ripple` scripts for that member; with `witness` on, the observation and the apply answer the
/// whole label vector (the pre-effect vector and the effect witness). `resolve_fail_after`
/// makes a member's basis stop resolving after that many resolutions; `observe_fail` makes
/// every observation a TRANSIENT failure (a retry that fails at preflight).
#[derive(Default)]
pub(crate) struct R1LabelConnector {
    labels: std::cell::RefCell<std::collections::BTreeMap<String, BTreeSet<String>>>,
    pub(crate) ripple: std::cell::RefCell<std::collections::BTreeMap<String, Vec<String>>>,
    pub(crate) witness: std::cell::Cell<bool>,
    pub(crate) resolve_fail_after: std::cell::RefCell<Option<(String, usize)>>,
    resolves: std::cell::RefCell<std::collections::BTreeMap<String, usize>>,
    pub(crate) applied: std::cell::RefCell<Vec<String>>,
    pub(crate) observe_fail: std::cell::Cell<bool>,
}

impl R1LabelConnector {
    fn current(&self, member: &str) -> BTreeSet<String> {
        self.labels
            .borrow_mut()
            .entry(member.to_string())
            .or_insert_with(|| ["INBOX".to_string(), "UNREAD".to_string()].into_iter().collect())
            .clone()
    }
}

impl Connector for R1LabelConnector {
    fn apply(
        &self,
        command: &Command,
        basis: &aruna::prestate::FrozenBasis,
    ) -> Result<(), aruna::ConnectorError> {
        self.apply_witnessed(command, basis).map(|_| ())
    }
    fn apply_witnessed(
        &self,
        command: &Command,
        _basis: &aruna::prestate::FrozenBasis,
    ) -> Result<aruna::EffectWitness, aruna::ConnectorError> {
        let member = s1_fold_message_ref(&command.action);
        let mut set = self.current(&member);
        set.remove("INBOX");
        set.insert("TRASH".to_string());
        for label in self.ripple.borrow().get(&member).cloned().unwrap_or_default() {
            set.insert(label);
        }
        self.labels.borrow_mut().insert(member.clone(), set.clone());
        self.applied.borrow_mut().push(member);
        Ok(aruna::EffectWitness {
            provider_label_vector: self.witness.get().then_some(set),
        })
    }
    fn resolve_basis(
        &self,
        command: &Command,
    ) -> Result<aruna::prestate::FrozenBasis, aruna::ResolveBasisError> {
        let member = s1_fold_message_ref(&command.action);
        let n = {
            let mut resolves = self.resolves.borrow_mut();
            let n = resolves.entry(member.clone()).or_insert(0);
            *n += 1;
            *n
        };
        if let Some((failing, after)) = self.resolve_fail_after.borrow().as_ref() {
            if *failing == member && n > *after {
                return Err(aruna::ResolveBasisError(
                    "test: the message no longer resolves".to_string(),
                ));
            }
        }
        Ok(aruna::test_support::fixture_basis(command))
    }
    fn observe(
        &self,
        command: &Command,
        basis: &aruna::prestate::FrozenBasis,
    ) -> Result<aruna::prestate::Observation, aruna::ConnectorError> {
        if self.observe_fail.get() {
            return Err(aruna::ConnectorError::transient("test: the observation read failed"));
        }
        let set = self.current(&s1_fold_message_ref(&command.action));
        Ok(aruna::prestate::Observation {
            native_resource_key: basis.native_resource_key.clone(),
            atoms: basis
                .touched_atoms
                .iter()
                .map(|(atom, label)| (atom.clone(), set.contains(label)))
                .collect(),
            request_id: None,
            provider_label_vector: self.witness.get().then_some(set),
        })
    }
    fn restore(
        &self,
        _command: &Command,
        _basis: &aruna::prestate::FrozenBasis,
        _p: &std::collections::BTreeMap<String, bool>,
    ) -> Result<(), aruna::ConnectorError> {
        Ok(())
    }
}

/// `s1_driver_bus`'s store, ratchet and root key over ANY connector, with `backups: off`
/// recorded so an admitted member reaches the connector.
pub(crate) fn plan_bus<C: Connector>(
    tag: &str,
    n: usize,
    connector: impl FnOnce(&Path) -> C,
) -> (SessionTemp, CommandBus<SqliteIntentLog, C>, Vec<String>) {
    let (path, _state, session) = session_for(tag);
    let rows: Vec<HeaderSummary> = (0..n)
        .map(|i| page_row(&format!("R{i:03}"), 1_758_672_000_000 + i as i64 * 1_000))
        .collect();
    session
        .lock()
        .expect("session lock")
        .absorb_page("acct", &rows, None, PageAnchor::FirstPage, 50, PageFacts::chronological(false))
        .expect("absorb");
    let mut refs = inbox_refs(&session);
    refs.sort();
    let mut log = SqliteIntentLog::open(&path).unwrap();
    let root = aruna::key_custody::root_key_verified(&aruna::key_custody::InMemoryCustody::new(), &mut log)
        .unwrap();
    log.record_knob_act(KnobAct::Backups(BackupsKnob::Off)).unwrap();
    let connector = connector(&path);
    let bus = CommandBus::new(log, connector)
        .with_grant_ratchet(Box::new(aruna::InMemoryGrantRatchet { high_water: Some(1), principal: "me@e".into() }))
        .with_root_key(root);
    (path, bus, refs)
}

/// The witness-write failpoint the engine's test arms (`t9_replace_failpoint`'s
/// technique): the production store's own witness UPDATE raises.
pub(crate) const R2_3_WITNESS_WRITE_FAILPOINT: &str =
    "CREATE TRIGGER r2_3_witness_write_failpoint BEFORE UPDATE OF effect_label_vector ON intents
           BEGIN SELECT RAISE(ABORT, 'failpoint: the witness write failed'); END;";
