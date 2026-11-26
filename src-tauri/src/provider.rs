//! The Gmail provider arm: its handles, the mutation fence, and the boot and rebuild paths.

use std::path::Path;
use std::sync::{Arc, Mutex, Weak};

use aruna::gmail::{
    GmailAccountResolver, GmailConnector, GmailMessageId, GmailMessageRefResolver, GmailUserId,
};
use aruna::message_store::SqliteMessageStore;
use aruna::{CommandBus, LogError, SqliteIntentLog};
use aruna_gmail::HttpGmailTransport;

use crate::credential::{credential_absent_diagnosis, load_gmail_credential, GmailCredential};
use crate::credential_cell::{CredentialCell, CredentialCoordinator};
use crate::token_refresh::{
    self, CredentialLock, Cure, FileGen, RefreshLocalError, CREDENTIAL_FILE_NAME,
};
use crate::SessionConfig;
#[cfg(not(test))]
use crate::key_custody_keyring;

/// What the JMAP arm answers until its config seam exists. A constant so the sentence lives in
/// one place and its test is a string comparison, not a paraphrase.
pub const PROVIDER_JMAP_UNCONFIGURED: &str =
    "JMAP is not configured in surface v1: the operator runbook defines an on-disk credential \
     layout for Gmail only (~/.photon/gmail/), and no JMAP session/credential layout exists to \
     read. The dependency and the engine seam are in place; the arm is wired when its config \
     lands.";

/// Why a real-provider mutation cannot happen in this build, so the status field and the verb
/// refusal quote the same sentence.
///
/// This describes a fence that is not built or opened here. `aruna-gmail`'s
/// `HttpGmailTransport::connect` constructs its `DestructiveWriteGate` closed, and the only
/// opener (`allow_test_host`) refuses any non-loopback host, so `gmail.googleapis.com` cannot be
/// authorized. `crates/aruna-gmail/src/lib.rs` (the "real-provider drill is PARKED" section)
/// pins this to ADR Part III and its exit criterion, and states that "a production-authority
/// gate is its own reviewed piece of work". The shell tells the truth about the fence instead of
/// routing around it: a UI offering archive/star buttons the engine always refuses would be
/// the failure.
pub const MUTATIONS_FENCED_REASON: &str =
    "real-provider writes are fence-gated until the production-authority slice (ADR Part III / \
     #21): aruna-gmail's DestructiveWriteGate is default-closed and can only be opened for a \
     loopback host, so a verb against the production Gmail endpoint is refused before any socket \
     exists. Reads are unaffected.";

/// The Photon account to Gmail user id mapping: the one mailbox this session's credential was
/// minted for, as the mint observed it at `users.getProfile` (`emailAddress`).
///
/// It must not answer `me`, the credential-relative alias. `me` is valid on the wire (Google
/// documents `userId` as "the user's email address. The special value `me`…") but not in a
/// frozen basis: a native resource key built from `me` re-reads as a different mailbox after a
/// credential rebind while still comparing equal to what admission froze, which defeats
/// BASIS-6's identity check. `aruna::gmail`'s `resolve_basis` refuses to freeze it. The value is
/// validated at the loader before it can reach a URL.
pub(crate) struct FixedGmailAccount(pub(crate) GmailUserId);

impl GmailAccountResolver for FixedGmailAccount {
    fn resolve_user(&self, _photon_account: &str) -> Option<GmailUserId> {
        // v1 is single-account: the session serves one partition and one mailbox, so the
        // credential, not the Photon-local account key, selects the identity.
        Some(self.0.clone())
    }
}

/// The connector's `message_ref` to Gmail id resolver, over the same projection table ingest
/// writes (`message_placement`), so the verb path and the read path resolve through one table.
pub(crate) struct StoreMessageRefs(pub(crate) SqliteMessageStore);

impl GmailMessageRefResolver for StoreMessageRefs {
    fn resolve_message(
        &self,
        photon_account: &str,
        message_ref: &str,
    ) -> Result<Option<GmailMessageId>, LogError> {
        // A store failure propagates (the connector maps it to transient); only a genuinely
        // absent mapping is `None`. Swallowing the error would read as "unknown message".
        Ok(self
            .0
            .resolve_email_id(photon_account, message_ref)?
            .map(|id| GmailMessageId(id.0)))
    }
}

pub(crate) type GmailBus =
    CommandBus<SqliteIntentLog, GmailConnector<HttpGmailTransport, FixedGmailAccount, StoreMessageRefs>>;

/// The Gmail arm's handles. The read transport and the mutation bus are separate objects:
/// reads take `&self` and must not queue behind a mutation holding the bus's `&mut self`.
pub struct GmailProvider {
    pub(crate) user: GmailUserId,
    pub(crate) reader: HttpGmailTransport,
    /// The mutation boundary. It has its own mutex, separate from the session mutex: a verb
    /// serializes against other verbs (the engine's single-writer discipline), never a store read.
    pub(crate) bus: Mutex<GmailBus>,
}

/// The provider arm, resolved once at setup.
#[derive(Clone)]
pub enum Provider {
    Gmail(Arc<GmailProvider>),
    /// No usable provider, with the operator-facing reason. Every provider command answers
    /// [`SurfaceError::SessionUnconfigured`] carrying it.
    ///
    /// `cure` is the typed remedy beside the sentence, so `session_status_view` can render
    /// `credential_cure` and the frontend's `session_unconfigured` toast has something to branch
    /// on. `None` for arms that owe no credential cure: the JMAP placeholder, an unresolved
    /// session's resolver failure, and a transport/intent-log construction failure.
    Unconfigured {
        reason: String,
        cure: Option<Cure>,
    },
}

/// Can this provider arm perform a mutation, and if not, why not?
///
/// Both arms answer `false` in v1. The Gmail arm is fenced ([`MUTATIONS_FENCED_REASON`]); the
/// unconfigured arm has no provider and quotes the sentence its caller derived for that cell.
/// When the production-authority work lands, this is the function that starts answering `true`.
///
/// It never speaks for an unarmed cell by itself. `Provider::Unconfigured`'s recorded reason is
/// what the last publisher saw, which can differ from the derived sentence that
/// `session_status_view` and [`PhotonState::gmail`] report ([`unconfigured_verdict`]); one payload
/// would then carry two sentences about one cell. So the caller passes the derived sentence in,
/// and `None` means no sentence, never a replayed one.
pub(crate) fn mutation_fence(
    provider: &Provider,
    unconfigured_reason: Option<&str>,
) -> (bool, Option<String>) {
    match provider {
        Provider::Gmail(_) => (false, Some(MUTATIONS_FENCED_REASON.to_string())),
        Provider::Unconfigured { .. } => (false, unconfigured_reason.map(str::to_string)),
    }
}

/// Build the initial credential cell for the Gmail arm from the parked credential, without
/// judging expiry and without touching the network. An expired credential builds the arm marked
/// expired-but-refreshable, and the first command renews it through [`admit_provider`].
///
/// A refusal that still read the file keeps its stamp and digest, so `session_status` can name
/// which credential is parked. A refusal whose observation failed publishes neither: a digest read
/// after a failed load describes a different instant's file and would let the next admission skip
/// its reconcile.
///
/// Boot takes the credential lock first, and boot may write: `build_gmail_arm` admits the
/// credential's grant against the ratchet and latches it (`token_refresh::admit_grant_generation`,
/// one atomic replace of `grant_high_water.json`). Without the lock, a boot that read the ratchet
/// before a mint landed could commit a stale value over the mint's.
///
/// The lock is acquired before the digest and credential are read, so the whole cell (arm, expiry,
/// digest, generation) comes from one observation inside the writer's critical section. Reading
/// first could not admit a stale credential (the mint reserves the higher generation before it
/// publishes) but could publish a stale refusal: a mint finishing in that window left boot
/// unconfigured while a good credential sat on disk, until a provider command or restart.
///
/// Only the fresh-install probe sits ahead of the lock. An absent credential file answers the
/// documented re-mint diagnosis without a lock, because a lock over a nonexistent credential
/// protects nothing and cannot be created in a missing directory. That answer is unlocked, so it
/// publishes no digest or expiry and the next admission reconciles from scratch. A lock timeout
/// refuses with the boot-specific sentence rather than guessing. Every refusal leaves as
/// [`BootCell::Unconfigured`], which has no digest, expiry or generation to carry.
pub(crate) fn build_gmail_provider(
    config: &SessionConfig,
    credential_cell: &Weak<CredentialCoordinator>,
) -> BootCell {
    // The fresh install comes first, and the rule lives in [`credential_absent_diagnosis`], which
    // the reconcile path calls too. A lock serializes writers of a credential; with no credential
    // there is nothing to serialize, and on a never-minted profile `~/.photon/gmail` does not
    // exist, so creating `credential.lock` inside it would fail and report the ordinary
    // unconfigured state as a lock fault on every command. This does not weaken lock-first: that
    // rule governs a credential that exists while a mint may be rewriting it. The probe is a fast
    // path, not a decision: if the file appears between the probe and the read, or the probe is
    // unreadable, control falls through to the locked path, the only one allowed to build an arm.
    let credential_path = config.gmail_secrets_dir.join(CREDENTIAL_FILE_NAME);
    if let Ok(observed) = FileGen::of(&credential_path) {
        if let Some(refusal) = credential_absent_diagnosis(&observed, || {
            load_gmail_credential(&config.gmail_secrets_dir)
        }) {
            // No digest, no expiry. This refusal derives from an observation that failed, and a
            // digest read after that failure describes a different instant's file. If a mint
            // published in between, `Unconfigured` would pair with the new file's digest, and since
            // the digest is the coordinator's only change detector above the live branch, the next
            // admission would compare equal, skip the reconcile, and keep serving a stale re-mint
            // refusal beside a good credential. `BootCell::Unconfigured` has no field to hold
            // either, so no site can regress this.
            return BootCell::Unconfigured {
                // The variant's own cure, not a blanket one.
                cure: Some(refusal.cure()),
                reason: refusal.reason,
            };
        }
    }
    let held = match CredentialLock::try_acquire(
        &token_refresh::credential_lock_path(&config.gmail_secrets_dir),
        token_refresh::CREDENTIAL_LOCK_DEADLINE,
    ) {
        Ok(l) => l,
        Err(e) => {
            return BootCell::Unconfigured {
                reason: e.boot_reason_sentence(),
                // The lock failure keeps the cure it carries on the wave side; the local map is
                // the error type's own.
                cure: Some(e.cure()),
            }
        }
    };
    let file_gen = FileGen::of(&credential_path).ok();
    let credential = match load_gmail_credential(&config.gmail_secrets_dir) {
        Ok(c) => c,
        Err(refusal) => {
            // The digest read succeeded here but is deliberately not published. It would answer
            // "can the next command skip re-reading the file?" for an unarmed cell, and the answer
            // would be wrong for every cure that does not change the credential's own bytes.
            return BootCell::Unconfigured {
                cure: Some(refusal.cure()),
                reason: refusal.reason,
            }
        }
    };
    let expires_at = credential.expires_at;
    match build_gmail_arm(config, &credential, &held, credential_cell) {
        // Everything that describes the arm (the grant generation, plus the other two) is a field
        // of the armed variant, so only a built arm can carry them.
        Ok(Provider::Gmail(arm)) => BootCell::Armed {
            arm,
            expires_at,
            file_gen,
            grant_generation: credential.grant.grant_generation,
        },
        // `build_gmail_arm` answers `Ok` only with an arm; its refusals are `Err`. A total match
        // rather than an unwrap, so a second `Ok` shape becomes a compile error, not a panic.
        Ok(Provider::Unconfigured { reason, cure }) => BootCell::Unconfigured { reason, cure },
        // A credential that loads valid and unexpired but fails at the ratchet (malformed
        // `grant_high_water.json`, an unreadable one, one that could not be raised) must not
        // publish `RetryLater` beside an `expires_at` and `file_gen`. The next command would find
        // an unchanged digest and a live expiry, take `admit`'s live fast path, and re-serve the
        // refusal, and repairing the ratchet would heal nothing until the credential expired or
        // the app restarted. `Unconfigured` has no field for either.
        Err(e) => BootCell::Unconfigured {
            reason: e.reason(),
            cure: e.cure(),
        },
    }
}

/// What boot publishes: an arm and everything that describes it, or a refusal and nothing else.
///
/// If each `return` in [`build_gmail_provider`] chose which descriptive fields to fill, a refusal
/// could end up beside a live expiry and the current digest. [`CredentialCoordinator::admit`]
/// cannot re-examine that state: the digest is its only change detector above the live fast
/// path, so an unchanged file would re-serve the refusal forever. Here that pairing does not
/// exist. `Unconfigured` has two fields, both about the refusal itself, and `grant_generation`
/// is a `u64` rather than an `Option` because an arm always knows the consent it was built under.
/// [`CredentialCell::unconfigured`] is the same rule for publishers other than boot.
pub(crate) enum BootCell {
    Armed {
        arm: Arc<GmailProvider>,
        expires_at: Option<i64>,
        file_gen: Option<FileGen>,
        grant_generation: u64,
    },
    Unconfigured {
        reason: String,
        cure: Option<Cure>,
    },
}

impl BootCell {
    /// The cell's first generation. The only place a boot shape becomes a [`CredentialCell`], so
    /// the mapping cannot drift per call site.
    pub(crate) fn into_cell(self) -> CredentialCell {
        match self {
            BootCell::Armed {
                arm,
                expires_at,
                file_gen,
                grant_generation,
            } => CredentialCell {
                provider: Provider::Gmail(arm),
                expires_at,
                generation: 0,
                file_gen,
                // The generation the boot arm was built from. Its consumer is the status surface
                // (`GrantOnDisk::verdict`); `CredentialCoordinator::admit` names where a retired
                // generation actually refuses.
                grant_generation: Some(grant_generation),
                last_result: None,
            },
            BootCell::Unconfigured { reason, cure } => CredentialCell::unconfigured(reason, cure),
        }
    }
}

/// Why an arm could not be built. There are two kinds because they take different cures and the
/// wave must tell them apart: a grant refusal is typed all the way through so the cell reproduces
/// its `re_mint` cure, while a construction failure keeps the sentence boot has always rendered.
#[derive(Debug)]
pub(crate) enum ArmBuildError {
    /// The grant did not pass the high-water admission. Carried as the typed local error so
    /// `credential_cell`'s cure map answers `ReMint` rather than the generic retry.
    Grant(RefreshLocalError),
    /// The transports, the intent log or the ref resolver refused. Its own sentence.
    Construction(String),
}

impl ArmBuildError {
    /// The operator-facing sentence, the one `Provider::Unconfigured` carries.
    fn reason(&self) -> String {
        match self {
            Self::Grant(e) => e.reason_sentence(),
            Self::Construction(reason) => reason.clone(),
        }
    }

    /// The typed cure beside that sentence. The grant arm answers the local error's own map (the
    /// one the wave reads). A construction failure answers `None`: a transport, intent log or ref
    /// resolver that refused is not a credential verdict, and naming a credential remedy would
    /// send the operator to re-mint a credential that is fine.
    fn cure(&self) -> Option<Cure> {
        match self {
            Self::Grant(e) => Some(e.cure()),
            Self::Construction(_) => None,
        }
    }
}

/// The engine's [`aruna::GrantRatchet`] seam, answered by the credential cell, which is the home
/// of the ratchet file's address and of the published grant
/// ([`CredentialCoordinator::admits_plan_grant`]). The bus consults it once per plan child's send
/// authorization. The handle is weak: the coordinator owns the cell, the cell the arm, the arm the
/// bus, and the bus this ratchet, so a strong pointer back would be a reference cycle. A ratchet
/// whose coordinator is gone refuses `Unavailable`, never admits.
struct ShellGrantRatchet {
    credential: Weak<CredentialCoordinator>,
}

impl aruna::GrantRatchet for ShellGrantRatchet {
    fn admits(
        &self,
        grant_generation: u64,
        provider_principal: &str,
    ) -> Result<(), aruna::GrantRefusal> {
        match self.credential.upgrade() {
            Some(cell) => cell.admits_plan_grant(grant_generation, provider_principal),
            None => Err(aruna::GrantRefusal::Unavailable(
                "the credential cell this bus was built beside no longer exists".to_string(),
            )),
        }
    }
}

/// The custodian the bus's root commitment key is read through: the OS credential store, one
/// entry per canonical store path (`key_custody_keyring::KeyringCustody`; ADR-P010). Its answer
/// is trusted only through `aruna::key_custody::root_key_verified`, which `build_gmail_arm`
/// calls.
#[cfg(not(test))]
fn root_key_custodian(
    store_path: &Path,
) -> Result<Box<dyn aruna::key_custody::KeyCustody>, aruna::key_custody::CustodyError> {
    key_custody_keyring::KeyringCustody::for_store(store_path)
        .map(|custody| Box::new(custody) as Box<dyn aruna::key_custody::KeyCustody>)
}

/// The test build's custodian: the engine's in-memory twin, one per canonical store path
/// ([`test_custody`]). The shell's tests build real arms over temp stores, and through the OS
/// custodian each would write a Windows Credential Manager entry on the dev box and refuse
/// outright on a Linux runner with no secret service. The OS round trip itself is covered by
/// `key_custody_keyring`'s attended test (`PHOTON_KEYRING_IT=1`).
#[cfg(test)]
fn root_key_custodian(
    store_path: &Path,
) -> Result<Box<dyn aruna::key_custody::KeyCustody>, aruna::key_custody::CustodyError> {
    test_custody::for_store(store_path)
}

/// The in-memory custodians the test build's [`root_key_custodian`] answers from, keyed by the
/// canonical store path as the OS custodian scopes its entry, so a rebuilt arm over one store
/// reads the key the first construction stored. A path that does not canonicalize is refused, as
/// `KeyringCustody::for_store` refuses it.
#[cfg(test)]
mod test_custody {
    use aruna::commitment::CommitmentKey;
    use aruna::key_custody::{CustodyError, InMemoryCustody, KeyCustody};
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex, OnceLock};

    type Custodians = Mutex<BTreeMap<PathBuf, Arc<InMemoryCustody>>>;

    fn custodians() -> &'static Custodians {
        static CUSTODIANS: OnceLock<Custodians> = OnceLock::new();
        CUSTODIANS.get_or_init(Default::default)
    }

    fn custodian(store_path: &Path) -> Result<Arc<InMemoryCustody>, CustodyError> {
        let canonical = store_path.canonicalize().map_err(|e| {
            CustodyError::Unavailable(format!("store path could not be canonicalized: {e}"))
        })?;
        let mut all = custodians().lock().expect("the test custodian table");
        Ok(Arc::clone(all.entry(canonical).or_default()))
    }

    struct Shared(Arc<InMemoryCustody>);

    impl KeyCustody for Shared {
        fn load_root(&self) -> Result<Option<CommitmentKey>, CustodyError> {
            self.0.load_root()
        }
        fn store_root(&self, key: &CommitmentKey) -> Result<(), CustodyError> {
            self.0.store_root(key)
        }
    }

    pub(super) fn for_store(store_path: &Path) -> Result<Box<dyn KeyCustody>, CustodyError> {
        Ok(Box::new(Shared(custodian(store_path)?)))
    }

    /// Make this store's custodian answer like a locked OS store (`Some`), or heal it (`None`).
    pub(super) fn set_unavailable(store_path: &Path, why: Option<&str>) {
        custodian(store_path)
            .expect("the store exists before its custodian is scripted")
            .set_unavailable(why);
    }

    /// The key this store's custodian holds, if any.
    pub(super) fn held_key(store_path: &Path) -> Option<CommitmentKey> {
        custodian(store_path).ok()?.load_root().ok()?
    }
}

pub(crate) fn build_gmail_arm(
    config: &SessionConfig,
    credential: &GmailCredential,
    held: &CredentialLock,
    credential_cell: &Weak<CredentialCoordinator>,
) -> Result<Provider, ArmBuildError> {
    // Builds the Gmail arm from one credential, for both construction and the rebuild after a
    // renewal (the `BearerToken` is immutable, so a renewed credential means a rebuilt arm).
    // Two transports, one credential: the reader answers `&self` calls concurrently while the
    // connector's copy sits under the bus mutex. `connect` takes no base URL (the endpoint is a
    // compiled property of `aruna-gmail`) and touches no network.
    //
    // The grant ratchet comes before any construction. A retired grant (a pre-re-consent
    // credential restored over the current one) must never reach a transport, connector or
    // socket, so the comparison and the latch happen first. The latch is max-only, fails closed,
    // and happens only under the cross-process credential lock, of which `held` is the caller's
    // proof. Every caller already holds it: the wave and the reconcile across their whole critical
    // section, and boot in `build_gmail_provider`.
    token_refresh::admit_grant_generation(&config.gmail_secrets_dir, &credential.grant, held)
        .map_err(ArmBuildError::Grant)?;

    let construct = |reason: String| ArmBuildError::Construction(reason);
    let reader = HttpGmailTransport::connect(&credential.access_token)
        .map_err(|e| construct(format!("the Gmail transport refused to connect: {e:?}")))?;
    let writer = HttpGmailTransport::connect(&credential.access_token)
        .map_err(|e| construct(format!("the Gmail transport refused to connect: {e:?}")))?;
    let mut log = SqliteIntentLog::open(&config.store_path)
        .map_err(|e| construct(format!("the mutation boundary has no intent log: {e}")))?;
    // The root key, through the one custody path (`root_key_verified`): the custodian's key
    // checked against the fingerprint this store registered, or minted, stored and registered on a
    // store that has none. A custody refusal refuses the arm; the bus is never built without a key.
    let root = root_key_custodian(&config.store_path)
        .and_then(|custodian| aruna::key_custody::root_key_verified(custodian.as_ref(), &mut log))
        .map_err(|e| construct(format!("the mutation boundary has no root commitment key: {e}")))?;
    let refs = SqliteMessageStore::open(&config.store_path)
        .map(StoreMessageRefs)
        .map_err(|e| construct(format!("the mutation boundary has no ref resolver: {e}")))?;
    // One identity, both halves: the connector's resolver (what `resolve_basis` freezes) and the
    // read transport's `user` (what goes on the wire) are the same value from the same grant. Two
    // sources would be two mailboxes one rebind apart.
    let user = GmailUserId(credential.grant.provider_principal.clone());
    let connector = GmailConnector::new(writer, FixedGmailAccount(user.clone()), refs);
    Ok(Provider::Gmail(Arc::new(GmailProvider {
        user,
        reader,
        bus: Mutex::new(
            CommandBus::new(log, connector)
                .with_grant_ratchet(Box::new(ShellGrantRatchet {
                    credential: Weak::clone(credential_cell),
                }))
                .with_root_key(root),
        ),
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::Duration;

    use crate::credential::{unix_now, GMAIL_TOKEN_FILE};
    use crate::credential_cell;
    use crate::error::SurfaceError;
    use crate::plumbing::lock_bus;
    use crate::state::PhotonState;
    use crate::status::session_status_view;
    use crate::tests::fixtures::{
        gmail_arm_state, s0_dir, s0_grant, s0_grant_with, s0_token_file, S0_PRINCIPAL, S0_READONLY,
    };
    use crate::token_refresh;
    use crate::ProviderKind;

    // -------------------------------------------------------------------------------------------
    // BOOT TAKES THE CREDENTIAL LOCK, AND A HELD LOCK IS A LOUD REFUSAL.
    //
    // The other half; the failing schedule: `build_gmail_provider`
    // called `build_gmail_arm` — and therefore the ratchet's read-compare-replace — holding no
    // lock at all, so a boot could read the ratchet, lose the CPU while an attended mint landed a
    // later consent and raised it, and then commit its stale value over the mint's. The fix puts
    // the bounded cross-process lock around the admission, which means a boot that CANNOT take it
    // does not proceed: `Provider::Unconfigured` with the typed lock sentence, and nothing
    // written.
    //
    // GREEN FROM BIRTH against the fixed code (the pre-fix shape it falsifies is gone by the
    // time this file compiles), so its discriminating power was shown by MUTATION instead:
    // deleting the `CredentialLock::try_acquire` block in `build_gmail_provider` and passing a
    // lock taken-and-dropped makes this witness fail with a Gmail arm and a written ratchet.
    // Observed under the mutation: "a boot that cannot serialize against the mint must not build
    // an arm". The mutation was reverted; the only remaining mention of the probe
    // marker in this tree is this sentence.
    // -------------------------------------------------------------------------------------------
    #[test]
    fn boot_refuses_loudly_and_writes_no_ratchet_while_another_writer_holds_the_lock() {
        let dir = s0_dir("f1rk1b");
        std::fs::write(
            dir.join(GMAIL_TOKEN_FILE),
            s0_token_file(i64::MAX, Some(&s0_grant())),
        )
        .unwrap();

        // A SECOND open file description on the lock address — flock attaches to the open file
        // description and `LockFileEx` conflicts across handles, so this really is another
        // writer (the mint holds this same address, `gmail_drill_mint.py`'s `credential.lock`).
        let holder = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(token_refresh::credential_lock_path(&dir))
            .expect("open the lock address");
        holder.lock().expect("hold the lock as another writer would");

        let BootCell::Unconfigured { reason, .. } = build_gmail_provider(
            &SessionConfig {
                account: "acct".to_string(),
                store_path: dir.join("store.sqlite"),
                provider_kind: ProviderKind::Gmail,
                gmail_secrets_dir: dir.to_path_buf(),
            },
            &Weak::new(),
        ) else {
            panic!("a boot that cannot serialize against the mint must not build an arm");
        };
        assert!(
            reason.contains("credential lock") && reason.contains("nothing was written"),
            "the refusal is the TYPED lock sentence, not a guess: {reason}"
        );
        // "no arm, so no published generation" is now the SHAPE's own statement:
        // `BootCell::Unconfigured` has no generation field to assert `None` about.
        assert!(
            !dir.join(token_refresh::GRANT_HIGH_WATER_FILE_NAME).exists(),
            "FAIL-CLOSED: a boot that never took the lock never latched the ratchet either"
        );

        holder.unlock().expect("release");
        std::fs::remove_dir_all(&dir).ok();
    }

    // ===========================================================================================
    // The BOOT half and the STATUS half.
    // ===========================================================================================

    // -------------------------------------------------------------------------------------------
    // BOOT DERIVES ITS CELL FROM THE LOCKED OBSERVATION, NOT A PRE-LOCK READ.
    //
    // The fix gave boot the credential lock but
    // left `FileGen::of` and `load_gmail_credential` OUTSIDE it. A mint that completes between
    // those reads and the acquisition leaves boot holding the OLD credential — and because the
    // mint reserves the higher generation first, the stale grant is then refused and the session
    // publishes `Provider::Unconfigured` while a perfectly good credential sits on disk. A stale
    // REFUSAL, never a stale admission — but the operator's session is dead until something else
    // reconciles it.
    //
    // The read ORDER is the whole property, so the witness observes it directly: the credential
    // file is REPLACED while the mint holds the lock. A boot that reads before the lock sees the
    // pre-grant file (no grant provenance) and refuses without ever taking the lock; a boot that
    // reads after it sees the conformant one the mint published and builds the arm.
    //
    // Before the fix this test failed:
    //   panicked at 'boot must derive its cell from the LOCKED observation, not a pre-lock read:
    //   the parked Gmail credential carries no grant provenance...'
    // -------------------------------------------------------------------------------------------
    #[test]
    fn boot_reads_the_credential_only_after_it_holds_the_lock() {
        let dir = s0_dir("f2rk1c");
        // The PRE-LOCK observation: the operator's pre-grant file, which the loader refuses.
        std::fs::write(dir.join(GMAIL_TOKEN_FILE), s0_token_file(i64::MAX, None)).unwrap();

        // The mint holds the credential lock across its publication — the same address
        // `gmail_drill_mint.py`'s `credential_writer_lock` takes.
        let holder = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(token_refresh::credential_lock_path(&dir))
            .expect("open the lock address");
        holder.lock().expect("hold the lock as the mint would");

        let config = SessionConfig {
            account: "acct".to_string(),
            store_path: dir.join("store.sqlite"),
            provider_kind: ProviderKind::Gmail,
            gmail_secrets_dir: dir.to_path_buf(),
        };
        let boot = std::thread::spawn(move || build_gmail_provider(&config, &Weak::new()));
        // Long enough for a pre-lock read to have happened (and to be wrong); the boot path's
        // own budget is CREDENTIAL_LOCK_DEADLINE, far above this.
        std::thread::sleep(Duration::from_millis(400));
        // The mint publishes the conformant credential INSIDE its lock hold …
        std::fs::write(
            dir.join(GMAIL_TOKEN_FILE),
            s0_token_file(i64::MAX, Some(&s0_grant())),
        )
        .unwrap();
        // … and releases it.
        holder.unlock().expect("release");

        match boot.join().expect("boot thread") {
            BootCell::Armed {
                expires_at,
                file_gen,
                grant_generation,
                ..
            } => {
                assert_eq!(
                    grant_generation, 1,
                    "the generation published is the one the LOCKED read observed"
                );
                assert_eq!(
                    expires_at,
                    Some(i64::MAX),
                    "and so is the expiry stamp the cell carries"
                );
                assert!(
                    file_gen.is_some(),
                    "and so is the digest the reconcile compares against"
                );
            }
            BootCell::Unconfigured { reason, .. } => panic!(
                "boot must derive its cell from the LOCKED observation, not a pre-lock read: \
                 {reason}"
            ),
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    // -------------------------------------------------------------------------------------------
    // A FRESH INSTALL IS AN UNCONFIGURED SESSION, NOT A LOCK FAILURE.
    //
    // An earlier change moved the credential lock to the FRONT of the
    // boot path so the whole cell derives from one locked observation. On a fresh profile
    // there is no `~/.photon/gmail` yet, so `credential.lock` cannot be created inside a
    // nonexistent parent — the boot path answered `LockUnavailable` and the operator was told the
    // credential lock was the problem, on a machine that has simply never been minted. Every
    // later provider command hit the same error, so the ordinary first-run state presented as a
    // lock fault until someone created the directory by hand.
    //
    // The fix keeps the lock-first ORDER exactly where it matters and refuses to take a lock that
    // has nothing to protect: when the credential file is not there, the documented unconfigured
    // diagnosis (the re-mint sentence `load_gmail_credential` writes) is the answer, before any
    // lock attempt. When the credential IS there, the lock still comes first — the locked-observation witness
    // `boot_reads_the_credential_only_after_it_holds_the_lock` is unchanged and still green.
    //
    // Before the fix this test failed:
    // The absent-dir arm answered the lock sentence, and the absent-file arm created a
    // `credential.lock` it had no credential to protect.
    // -------------------------------------------------------------------------------------------
    #[test]
    fn a_fresh_install_diagnoses_the_missing_credential_before_it_takes_any_lock() {
        // The ONE guard, NOT created — the fresh profile this witness needs.
        let dir = aruna::test_temp::TempDir::uncreated("photon-f3rk1d");
        let config = SessionConfig {
            account: "acct".to_string(),
            store_path: dir.join("store.sqlite"),
            provider_kind: ProviderKind::Gmail,
            gmail_secrets_dir: dir.to_path_buf(),
        };
        let lock_path = token_refresh::credential_lock_path(&dir);

        // (a) THE FRESH PROFILE: the secrets directory does not exist at all.
        assert!(!dir.exists(), "the witness's own premise: nothing has been minted here");
        let BootCell::Unconfigured { reason, .. } = build_gmail_provider(&config, &Weak::new())
        else {
            panic!("a profile with no credential must not build an arm");
        };
        assert!(
            reason.contains("no Gmail credential at") && reason.contains("gmail_drill_mint.py"),
            "a fresh install is told to MINT, not told about a lock: {reason}"
        );
        assert!(
            !reason.contains("credential lock"),
            "the lock is not the operator's problem here: {reason}"
        );
        // "no credential, no expiry / no digest / no generation" is no longer asserted by
        // VALUE here: now the refusal shape has no such fields at all, and the CELL
        // it becomes is pinned by the fresh-install and every-boot-site witnesses.
        assert!(
            !lock_path.exists() && !dir.exists(),
            "nothing was created: no lock file, and no directory conjured to hold one"
        );

        // (b) THE HALF-BUILT PROFILE: the directory exists, the credential does not.
        std::fs::create_dir_all(&dir).expect("the dir exists but has never been minted into");
        let BootCell::Unconfigured { reason, .. } = build_gmail_provider(&config, &Weak::new())
        else {
            panic!("an empty secrets dir must not build an arm");
        };
        assert!(
            reason.contains("no Gmail credential at") && reason.contains("gmail_drill_mint.py"),
            "the same diagnosis, for the same fact: {reason}"
        );
        assert!(
            !lock_path.exists(),
            "the lock has nothing to protect when there is no credential, so it is not taken"
        );

        // (c) AND THE LOCK-FIRST ORDER STANDS the moment there IS a credential to protect:
        //     `boot_reads_the_credential_only_after_it_holds_the_lock` is the witness for that; here we only pin that the door reopens.
        std::fs::write(
            dir.join(GMAIL_TOKEN_FILE),
            s0_token_file(i64::MAX, Some(&s0_grant())),
        )
        .unwrap();
        let BootCell::Armed {
            grant_generation, ..
        } = build_gmail_provider(&config, &Weak::new())
        else {
            panic!("a minted profile builds its arm exactly as before");
        };
        assert_eq!(
            grant_generation, 1,
            "and publishes the generation it was built from"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    // -------------------------------------------------------------------------------------------
    // ONE FRESH-INSTALL DIAGNOSIS, AT BOTH DOORS.
    //
    // The FOURTH finding on this seam and therefore
    // closed ONE LEVEL UP: the design's fresh-install rule — no credential file
    // means the unconfigured/re-mint diagnosis and NO lock, because a lock over a credential that
    // does not exist protects nothing and cannot be created in a directory that does not exist —
    // lived at the BOOT door only. A later change made an unarmed cell reconcile on every
    // admission (it carries no digest, so `Some(observed) != None` always), and the RECONCILE
    // door locks FIRST: on a fresh profile whose secrets directory does not exist, the first
    // provider command failed to create `credential.lock` inside a nonexistent parent and the
    // ordinary never-been-minted state surfaced as `credential_expired` / `retry_later` — on
    // every command, until a mint created the directory. Two doors, one rule, one copy of it.
    //
    // Before the fix this test failed:
    // The boot door answered `re_mint` and the very next command answered
    // `CredentialExpired { cure: RetryLater }` carrying the credential-lock sentence.
    // -------------------------------------------------------------------------------------------
    #[test]
    fn a_fresh_install_answers_one_diagnosis_at_both_doors() {
        // The ONE guard, NOT created — the fresh profile this witness needs.
        let dir = aruna::test_temp::TempDir::uncreated("photon-f7r6f7");
        let config = SessionConfig {
            account: "acct".to_string(),
            store_path: dir.join("store.sqlite"),
            provider_kind: ProviderKind::Gmail,
            gmail_secrets_dir: dir.to_path_buf(),
        };
        let lock_path = token_refresh::credential_lock_path(&dir);
        assert!(!dir.exists(), "the witness's own premise: nothing has been minted here");

        // (a) THE BOOT DOOR — the rule where it has always lived.
        let state = PhotonState::new(config.clone());
        let booted = session_status_view(&state, Some(1), None, unix_now());
        assert!(!booted.configured, "a profile with no credential is not configured");
        assert_eq!(
            booted.credential_cure,
            Some(Cure::ReMint),
            "the fresh install is told to MINT"
        );
        assert!(
            booted
                .provider_reason
                .as_deref()
                .is_some_and(|r| r.contains("no Gmail credential at")
                    && !r.contains("credential lock")),
            "and the sentence names the missing credential, not a lock: {:?}",
            booted.provider_reason
        );

        // (b) THE RECONCILE DOOR — the SAME fact, one command later, and it must answer the SAME
        //     diagnosis. This is the finding: the first provider command used to reach for the
        //     writer lock before it noticed there was nothing to protect.
        match state.admit_provider_sync(unix_now()) {
            Err(SurfaceError::SessionUnconfigured { reason, cure }) => {
                assert_eq!(
                    cure,
                    Some(Cure::ReMint),
                    "the second door answers the first door's cure, not a wait"
                );
                assert!(
                    reason.contains("no Gmail credential at")
                        && reason.contains("gmail_drill_mint.py"),
                    "and the first door's sentence: {reason}"
                );
                assert!(
                    !reason.contains("credential lock"),
                    "the lock is not the operator's problem here: {reason}"
                );
            }
            Err(other) => panic!(
                "a fresh install must diagnose the missing credential at the reconcile door \
                 too, never as a lock fault: {other:?}"
            ),
            Ok(_) => panic!("a profile with no credential must never hand back an arm"),
        }
        assert!(
            !lock_path.exists() && !dir.exists(),
            "nothing was created: no lock file, and no directory conjured to hold one"
        );
        let after = session_status_view(&state, Some(1), None, unix_now());
        assert_eq!(
            (after.configured, after.credential_cure),
            (false, Some(Cure::ReMint)),
            "and the status surface still reads exactly what boot read"
        );

        // (c) THE MINT LANDS — directory, credential and ratchet, as `gmail_drill_mint.py` writes
        //     them — and the NEXT command adopts it with no token-endpoint POST (the credential
        //     is live, so no wave runs; a wave in this fixture would refuse on the absent client
        //     config long before any wire).
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join(GMAIL_TOKEN_FILE),
            s0_token_file(unix_now() + 3_600, Some(&s0_grant())),
        )
        .unwrap();
        std::fs::write(
            dir.join(token_refresh::GRANT_HIGH_WATER_FILE_NAME),
            b"{\"grant_generation\":1}
",
        )
        .unwrap();
        state
            .admit_provider_sync(unix_now())
            .expect("the next command adopts the minted credential");
        let adopted = session_status_view(&state, Some(1), None, unix_now());
        assert_eq!(
            (adopted.credential_cure, adopted.provider_reason),
            (None, None),
            "and the credential half of the status reads clean — nothing left to cure and \
             no refusal to explain (`configured` also answers for the STORE, and this \
             fixture's store directory did not exist when the session was built)"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    // -------------------------------------------------------------------------------------------
    // A FAILED PRE-LOCK LOAD PUBLISHES NO DIGEST, SO THE NEXT ADMISSION ALWAYS
    // RECONCILES.
    //
    // Corroborated
    // (`FRESH_POST_LOAD_PRE_DIGEST_CONSEQUENCE=STICKY_UNCONFIGURED`): on the fresh-install fast
    // path the probe says "no credential", `load_gmail_credential` agrees — and then the early
    // return read the file's DIGEST anyway. A mint that publishes the credential in the window
    // between those two reads pairs `Provider::Unconfigured` with the NEW file's digest, and
    // because the coordinator's only change detector above the live branch is that digest, the
    // next `admit_provider_sync` sees EQUAL and skips the reconcile. A perfectly good credential
    // sits on disk while every command answers the re-mint refusal, until another byte change or
    // a restart.
    //
    // The fix is the shape the lock-timeout path already publishes (the boot lock-timeout witness): a cell derived from
    // an observation that FAILED carries no digest and no expiry, and `None` never compares equal
    // to a disk observation — so the next admission reconciles unconditionally.
    //
    // Before the fix this test failed:
    //   panicked at 'a cell published from a FAILED load carries no digest — a digest read after
    //   the failed load is a different instant's file: Some(Absent)'
    // -------------------------------------------------------------------------------------------
    #[test]
    fn a_failed_prelock_load_publishes_no_digest_so_the_next_admission_reconciles() {
        let dir = s0_dir("f4r4f1");
        let config = SessionConfig {
            account: "acct".to_string(),
            store_path: dir.join("store.sqlite"),
            provider_kind: ProviderKind::Gmail,
            gmail_secrets_dir: dir.to_path_buf(),
        };

        // (a) THE PRE-LOCK REFUSAL, taken through the whole boot: the directory exists and has
        //     never been minted into, so the probe is false and the load fails.
        let state = PhotonState::new(config);
        let boot_cell = state.credential.snapshot();
        let Provider::Unconfigured { reason, .. } = boot_cell.provider.clone() else {
            panic!("a profile with no credential must not build an arm");
        };
        assert!(
            reason.contains("no Gmail credential at"),
            "the premise: this is the fresh-install refusal, not some other one: {reason}"
        );
        assert_eq!(boot_cell.expires_at, None, "a failed load read no expiry");
        assert!(
            boot_cell.file_gen.is_none(),
            "a cell published from a FAILED load carries no digest (the old digest read happened AFTER the failed load — a different instant's file): {:?}",
            boot_cell.file_gen
        );
        assert_eq!(boot_cell.grant_generation, None, "no arm, so no generation");

        // (b) THE MINT LANDS — the very publication whose race the digest read straddled …
        std::fs::write(
            dir.join(GMAIL_TOKEN_FILE),
            s0_token_file(i64::MAX, Some(&s0_grant())),
        )
        .unwrap();

        // … and the next provider command reconciles onto it with no restart and no second
        // byte change.
        state
            .admit_provider_sync(unix_now())
            .expect("the next admission adopts the credential the mint published");
        let healed = state.credential.snapshot();
        assert!(
            matches!(healed.provider, Provider::Gmail(_)),
            "the sticky refusal is gone: the cell now holds the live arm"
        );
        assert_eq!(
            healed.grant_generation,
            Some(1),
            "and names the consent it was rebuilt under"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    // -------------------------------------------------------------------------------------------
    // THE BOOT LOCK-TIMEOUT SENTENCE IS THE BOOT PATH'S OWN.
    //
    // The fix gave boot a lock and, with it, a sentence
    // written for the wave and reconcile call sites — "Retry your command". At those sites the
    // next command genuinely does re-attempt the lock; at BOOT it does not. The operator is told
    // to do the one thing that provably cannot help.
    //
    // Before the fix this test failed:
    //   panicked at 'the BOOT refusal must name the act that actually clears it: the credential
    //   lock at... was held by another writer for the whole 5000 ms budget; nothing was written.
    //   Retry your command — if it persists, a mint script may be wedged.'
    // -------------------------------------------------------------------------------------------
    #[test]
    fn the_boot_lock_timeout_sentence_says_restart_not_retry() {
        let dir = s0_dir("f2rk8");
        std::fs::write(
            dir.join(GMAIL_TOKEN_FILE),
            s0_token_file(i64::MAX, Some(&s0_grant())),
        )
        .unwrap();
        let holder = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(token_refresh::credential_lock_path(&dir))
            .expect("open the lock address");
        holder.lock().expect("hold the lock for the whole boot budget");

        // The whole boot, not just the helper: the sentence is judged where the operator meets
        // it, on the cell `PhotonState::new` publishes.
        let state = PhotonState::new(SessionConfig {
            account: "acct".to_string(),
            store_path: dir.join("store.sqlite"),
            provider_kind: ProviderKind::Gmail,
            gmail_secrets_dir: dir.to_path_buf(),
        });
        let boot_cell = state.credential.snapshot();
        let Provider::Unconfigured { reason, .. } = boot_cell.provider.clone() else {
            panic!("a boot that cannot serialize against the mint must not build an arm");
        };
        assert!(
            reason.contains("Restart Photon"),
            "the BOOT refusal must name the act that actually clears it: {reason}"
        );
        assert!(
            !reason.to_lowercase().contains("retry your command"),
            "and must not prescribe the one act that provably cannot help here: {reason}"
        );
        assert!(
            reason.contains("nothing was written"),
            "the fail-closed fact stays on the sentence: {reason}"
        );

        // The WAVE/RECONCILE sentence is UNCHANGED — there, the next command really does
        // re-attempt the lock, so "retry" is the true instruction.
        let at_the_wave = token_refresh::RefreshLocalError::LockTimeout {
            path: token_refresh::credential_lock_path(&dir),
            waited: Duration::from_millis(5_000),
        }
        .reason_sentence();
        assert!(
            at_the_wave.contains("Retry your command"),
            "the other call sites keep their own true sentence: {at_the_wave}"
        );

        // THE FACTS THE SENTENCE RESTS ON, executed rather than asserted in prose.
        // Fail-closed: a boot that never took the lock never latched the ratchet either.
        assert!(
            !dir.join(token_refresh::GRANT_HIGH_WATER_FILE_NAME).exists(),
            "nothing was written"
        );
        // MEASURED: the post-timeout cell carries NO expiry stamp and NO digest,
        // because the locked-observation order moved BOTH reads inside the lock. That is a change in the stickiness
        // the earlier design had: the earlier cell kept a live expiry and an unchanged digest, so
        // the live fast path answered from it forever. Here the next admission sees a digest it
        // cannot match and reconciles under the lock. The restart the sentence names is the
        // cure that is always available; it is no longer the only one.
        assert_eq!(boot_cell.expires_at, None, "no expiry was read outside the lock");
        assert!(boot_cell.file_gen.is_none(), "and no digest was either");

        holder.unlock().expect("release");
        state
            .admit_provider_sync(unix_now())
            .expect("once the mint finishes, the next provider command reconciles under the lock");

        std::fs::remove_dir_all(&dir).ok();
    }

    // -------------------------------------------------------------------------------------------
    // A BOOT THE RATCHET REFUSED RETRYABLY HEALS ON THE NEXT COMMAND.
    //
    // The SECOND site of the class closed at
    // the fresh-install early return: the credential loads valid and UNEXPIRED, and only
    // `admit_grant_generation` refuses — retryably, because the ratchet file is malformed and a
    // record Photon cannot read is a record it refuses to treat as absent. The boot cell then
    // paired `Provider::Unconfigured { cure: RetryLater }` with the credential's LIVE expiry and
    // its digest. `admit`'s only change detector above the live branch is that digest
    // (`credential_cell.rs`'s `file_changed_since_publish`), and a live expiry takes the live
    // fast path — so the next command compared EQUAL, skipped the reconcile and re-served the
    // refusal. Repairing the ratchet fixed nothing until the credential expired or the app
    // restarted, while the sentence promised a retry on the next command.
    //
    // Before the fix this test failed:
    //   panicked at 'an Unconfigured cell carries no expiry — there is no arm for one to
    //   describe: Some(9223372036854775807)'
    // -------------------------------------------------------------------------------------------
    #[test]
    fn a_boot_the_ratchet_refused_retryably_heals_on_the_next_command() {
        let dir = s0_dir("f6r5f6a");
        // A perfectly good, unexpired credential — the premise: nothing here is wrong with the
        // credential itself.
        std::fs::write(
            dir.join(GMAIL_TOKEN_FILE),
            s0_token_file(i64::MAX, Some(&s0_grant())),
        )
        .unwrap();
        let hw = dir.join(token_refresh::GRANT_HIGH_WATER_FILE_NAME);
        // … and a ratchet file that is not JSON at all: admission can neither confirm the
        // generation nor raise it, so the arm is refused with the RETRYABLE cure.
        std::fs::write(&hw, b"{ not json").unwrap();

        let state = PhotonState::new(SessionConfig {
            account: "acct".to_string(),
            store_path: dir.join("store.sqlite"),
            provider_kind: ProviderKind::Gmail,
            gmail_secrets_dir: dir.to_path_buf(),
        });
        let boot_cell = state.credential.snapshot();
        let Provider::Unconfigured { reason, .. } = boot_cell.provider.clone() else {
            panic!("a grant the ratchet cannot admit must not build an arm");
        };
        assert!(
            reason.contains(token_refresh::GRANT_HIGH_WATER_FILE_NAME),
            "the witness's own premise: the RATCHET is what refused, not the credential: {reason}"
        );
        let status = session_status_view(&state, None, None, unix_now());
        assert!(
            !status.configured,
            "the boot is unconfigured — no arm was published"
        );
        assert_eq!(
            status.credential_cure,
            Some(Cure::RetryLater),
            "and the operator is told the cure is to retry — which is the promise the rest of \
             this witness holds the cell to"
        );

        // THE COMPLEMENT, AT THE TYPE: an unarmed cell has nothing to keep a digest
        // FOR — the digest exists only to skip re-reading a file behind a LIVE arm.
        assert_eq!(
            boot_cell.expires_at, None,
            "an Unconfigured cell carries no expiry — there is no arm for one to describe: {:?}",
            boot_cell.expires_at
        );
        assert!(
            boot_cell.file_gen.is_none(),
            "… and no digest, or the next admission compares EQUAL and never reconciles: {:?}",
            boot_cell.file_gen
        );
        assert_eq!(
            boot_cell.grant_generation, None,
            "… and no grant generation: nothing was admitted"
        );

        // THE REPAIR — the very act `retry_later` prescribes. Nothing else changes: same
        // credential file, same bytes, same process.
        std::fs::write(&hw, b"{\"grant_generation\":1}\n").unwrap();
        state
            .admit_provider_sync(unix_now())
            .expect("the next command re-reads the repaired ratchet and arms the session");
        assert!(
            matches!(state.credential.snapshot().provider, Provider::Gmail(_)),
            "the retryable refusal is gone on the next command, with no restart"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    // -------------------------------------------------------------------------------------------
    // EVERY BOOT SITE THAT PUBLISHES NO ARM, ENUMERATED.
    //
    // The class is closed by TYPE, not by value: `BootCell::Unconfigured` has no digest, expiry
    // or generation FIELD, and `CredentialCell::unconfigured` takes no digest ARGUMENT — so the
    // bad pairing is unconstructible at every site. This witness is the enumeration half: it
    // drives each boot site that publishes an unarmed cell and pins the three fields.
    //
    // WHY A TEST AND NOT A `compile_fail` DOCTEST: `CredentialCell` and `BootCell` are
    // `pub(crate)`/private, and doctests do not run against private items, so a doctest could
    // not name either type. The enumeration over the constructor's callers is the form that
    // actually executes.
    //
    // Two sites are pinned by their OWN witnesses and are not repeated here (they are instance
    // probes of this same class): the fresh-install early return (the fresh-install witness) and the boot lock
    // timeout (the boot lock-timeout witness, which spends the whole 5 s lock budget). The arm-CONSTRUCTION failure
    // (`ArmBuildError::Construction`) returns through the exact same `BootCell` constructor as
    // the ratchet arm below, so the type carries it — there is no hermetic fixture that fails a
    // transport build.
    //
    // Before the fix this test failed:
    //   panicked at src\lib.rs:3598:13:
    //   assertion `left == right` failed: a post-lock load failure: no arm, no digest
    //     left: Some(Sha384("fc8b1b5aa9045ad244d8e53517a8f695606793d79f76046c951ac64aeba5b9f0…"))
    //    right: None
    // -------------------------------------------------------------------------------------------
    #[test]
    fn every_boot_site_that_publishes_no_arm_publishes_no_digest_and_no_expiry() {
        let dir = s0_dir("f6r5f6b");
        let cfg = |kind: ProviderKind, secrets: PathBuf| SessionConfig {
            account: "acct".to_string(),
            store_path: dir.join("store.sqlite"),
            provider_kind: kind,
            gmail_secrets_dir: secrets,
        };
        let unarmed = |cell: &CredentialCell, site: &str| {
            assert!(
                matches!(cell.provider, Provider::Unconfigured { .. }),
                "the site's own premise: {site} publishes no arm"
            );
            assert_eq!(cell.expires_at, None, "{site}: no arm, no expiry");
            assert_eq!(cell.file_gen, None, "{site}: no arm, no digest");
            assert_eq!(cell.grant_generation, None, "{site}: no arm, no generation");
        };

        // (1) THE JMAP PLACEHOLDER — no credential is involved at all.
        let jmap = PhotonState::new(cfg(ProviderKind::Jmap, dir.to_path_buf()));
        unarmed(&jmap.credential.snapshot(), "the JMAP placeholder");

        // (2) THE UNRESOLVED SESSION — not even a path was resolvable.
        let unresolved = PhotonState::unresolved("no home directory".to_string());
        unarmed(&unresolved.credential.snapshot(), "an unresolved session");

        // (3) THE POST-LOCK LOAD FAILURE — the file EXISTS (so the fresh-install probe falls
        //     through to the locked path) and is unparseable.
        let bad = s0_dir("f6r5f6b-load");
        std::fs::write(bad.join(GMAIL_TOKEN_FILE), b"{ not a credential").unwrap();
        let load_failed = PhotonState::new(cfg(ProviderKind::Gmail, bad.to_path_buf()));
        unarmed(&load_failed.credential.snapshot(), "a post-lock load failure");

        // (4) THE GRANT THE RATCHET RETIRED — arm (a)'s site, pinned beside its siblings.
        let retired = s0_dir("f6r5f6b-ratchet");
        std::fs::write(
            retired.join(GMAIL_TOKEN_FILE),
            s0_token_file(i64::MAX, Some(&s0_grant())),
        )
        .unwrap();
        std::fs::write(
            retired.join(token_refresh::GRANT_HIGH_WATER_FILE_NAME),
            b"{\"grant_generation\":9}\n",
        )
        .unwrap();
        let refused = PhotonState::new(cfg(ProviderKind::Gmail, retired.to_path_buf()));
        unarmed(&refused.credential.snapshot(), "a grant the ratchet retired");

        std::fs::remove_dir_all(&dir).ok();
        std::fs::remove_dir_all(&bad).ok();
        std::fs::remove_dir_all(&retired).ok();
    }

    // -------------------------------------------------------------------------------------------
    // A `gmail.readonly`-only grant is refused BEFORE any arm is built (the grant the
    // mint used to write; write verbs cannot run under it).
    //
    // Before the fix: the scope set was never read at load, so a read-only credential built the full
    // arm and the first triage verb would have failed at the WIRE with a raw 403.
    // -------------------------------------------------------------------------------------------
    #[test]
    fn a_readonly_only_grant_is_refused_before_an_arm_exists() {
        let dir = s0_dir("g2");
        std::fs::write(
            dir.join(GMAIL_TOKEN_FILE),
            s0_token_file(42, Some(&s0_grant_with(1, S0_PRINCIPAL, &[S0_READONLY]))),
        )
        .unwrap();

        let err = load_gmail_credential(&dir).expect_err("a read-only grant is not this product's");
        assert!(
            err.reason.contains("read + triage authority"),
            "the refusal renders the EXPECTED authority as Photon's own label: {err}"
        );
        assert!(
            !err.reason.contains("gmail.readonly") && !err.reason.contains(S0_READONLY),
            "no raw scope URI may reach a rendered string (W41 stands): {err}"
        );
        assert!(err.reason.contains("gmail_drill_mint.py"), "the cure is named: {err}");

        // And the whole session refuses: nothing constructs an arm from it.
        let boot = build_gmail_provider(
            &SessionConfig {
                account: "acct".to_string(),
                store_path: dir.join("store.sqlite"),
                provider_kind: ProviderKind::Gmail,
                gmail_secrets_dir: dir.to_path_buf(),
            },
            &Weak::new(),
        );
        assert!(
            matches!(boot, BootCell::Unconfigured { .. }),
            "a non-conformant grant must never reach transport construction"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    // -------------------------------------------------------------------------------------------
    // The arm is seeded with the PRINCIPAL, never the credential-relative `me` alias.
    //
    // `me` is a POINTER to whatever the credential authenticates as, and `aruna::gmail`'s
    // `resolve_basis` refuses to FREEZE it into a native resource key (BASIS-4/-6 — its own
    // witness `resolve_basis_refuses_the_credential_relative_me_alias`, and the admitting half
    // `resolve_basis_freezes_the_native_identity_and_the_constant_label`, both in
    // `crates/aruna/src/gmail.rs`). Before grant provenance there was no other value to give it, so every RED
    // verb would have been refused at admission. This is the Photon half: the resolver and the
    // provider's own `user` both carry the mint-observed address.
    //
    // Before the fix: `FixedGmailAccount` is a unit struct answering the hardcoded `GmailUserId("me")`.
    // -------------------------------------------------------------------------------------------
    #[test]
    fn the_arm_resolves_the_grant_principal_never_the_me_alias() {
        let dir = s0_dir("p2");
        let expires_at = unix_now() + 3_600;
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
        let Provider::Gmail(arm) = state.credential.snapshot().provider else {
            panic!("a conformant v2 credential builds the production arm");
        };
        assert_eq!(
            arm.user,
            GmailUserId(S0_PRINCIPAL.to_string()),
            "the READ transport addresses the mailbox by its account identity, not by `me`"
        );
        assert_eq!(
            FixedGmailAccount(GmailUserId(S0_PRINCIPAL.to_string())).resolve_user("acct"),
            Some(GmailUserId(S0_PRINCIPAL.to_string())),
            "the connector's resolver answers the SAME identity `resolve_basis` freezes"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    // ===========================================================================================
    // THE SHELL'S GRANT RATCHET AND THE BUS CONSTRUCTION.
    //
    // The engine consults `aruna::GrantRatchet` once per plan child's send authorization;
    // the shell answers it from the credential cell — the one home of the ratchet file's address
    // and of the published grant. The bus is built WITH that ratchet and WITH
    // the store's root commitment key, resolved through the one custody door; a custody
    // failure refuses the arm, never builds a bus without a key.
    // ===========================================================================================
    #[test]
    fn the_shell_ratchet_admits_at_or_above_the_high_water_and_refuses_a_retired_generation_or_a_foreign_principal(
    ) {
        use aruna::{GrantRatchet, GrantRefusal};
        let dir = s0_dir("s1-ratchet");
        // The arm is built through `build_gmail_arm`, whose admission latches the ratchet to the
        // credential's generation through token_refresh's own writer — never raw bytes here.
        let coordinator = credential_cell::test_coordinator_with_grant(&dir, 3, "me@example.com");
        assert_eq!(
            token_refresh::read_grant_high_water(&token_refresh::grant_high_water_path(&dir)),
            Ok(Some(3)),
            "the witness's premise: the ratchet records generation 3"
        );
        let ratchet = ShellGrantRatchet {
            credential: Arc::downgrade(&coordinator),
        };
        assert_eq!(ratchet.admits(3, "me@example.com"), Ok(()));
        assert_eq!(
            ratchet.admits(4, "me@example.com"),
            Ok(()),
            "above the high-water is not retired"
        );
        assert_eq!(
            ratchet.admits(2, "me@example.com"),
            Err(GrantRefusal::Retired {
                generation: 2,
                high_water: 3
            })
        );
        assert_eq!(
            ratchet.admits(3, "other@example.com"),
            Err(GrantRefusal::PrincipalMismatch {
                plan: "other@example.com".to_string(),
                current: "me@example.com".to_string()
            }),
            "the principal is compared against the PUBLISHED cell's"
        );
        // An unusable ratchet file REFUSES (never re-admits every retired generation).
        std::fs::write(token_refresh::grant_high_water_path(&dir), b"not a number").unwrap();
        assert!(
            matches!(
                ratchet.admits(3, "me@example.com"),
                Err(GrantRefusal::Unavailable(_))
            ),
            "an unusable ratchet is never read as absent"
        );
        // A ratchet whose credential cell is gone refuses too — never a silent admit.
        drop(coordinator);
        assert!(matches!(
            ratchet.admits(3, "me@example.com"),
            Err(GrantRefusal::Unavailable(_))
        ));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_bus_is_built_with_the_shell_ratchet_and_the_stores_verified_root_key() {
        use aruna::GrantRefusal;
        let (dir, state) = gmail_arm_state("s1-bus-wiring");
        let Provider::Gmail(arm) = state.credential.snapshot().provider else {
            panic!("a conformant v2 credential builds the production arm");
        };
        let bus = lock_bus(&arm).expect("the bus lock");
        // The SHELL's ratchet, not the engine's fail-closed default (which answers every grant
        // `Unavailable`): the published generation + principal admit, another principal refuses
        // by name.
        assert_eq!(bus.grant_ratchet().admits(1, S0_PRINCIPAL), Ok(()));
        assert!(matches!(
            bus.grant_ratchet().admits(1, "someone-else@example.com"),
            Err(GrantRefusal::PrincipalMismatch { .. })
        ));
        // The root key went through `root_key_verified` at construction: the store registered
        // the fingerprint of the key its custodian now holds.
        let held = test_custody::held_key(&dir.join("store.sqlite"))
            .expect("construction minted and stored the store's root key");
        assert_eq!(
            aruna::IntentLog::registered_key_fingerprint(bus.log()).unwrap(),
            Some(aruna::commitment::key_fingerprint(&held))
        );
        assert_eq!(bus.root_key(), Some(&held), "the bus carries THAT key");
        drop(bus);
        drop(arm);
        drop(state);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_root_key_custody_failure_is_a_construction_refusal_never_a_bus_without_a_key() {
        let dir = s0_dir("s1-custody-down");
        std::fs::write(
            dir.join(GMAIL_TOKEN_FILE),
            s0_token_file(unix_now() + 3_600, Some(&s0_grant())),
        )
        .unwrap();
        let store = dir.join("store.sqlite");
        // The store exists first, so its custodian can be named (one custodian per canonical
        // store path, as the OS custodian scopes its entry).
        drop(SqliteIntentLog::open(&store).unwrap());
        test_custody::set_unavailable(&store, Some("the credential store is locked"));
        let state = PhotonState::new(SessionConfig {
            account: "acct".to_string(),
            store_path: store.clone(),
            provider_kind: ProviderKind::Gmail,
            gmail_secrets_dir: dir.to_path_buf(),
        });
        match state.credential.snapshot().provider {
            Provider::Unconfigured { reason, cure } => {
                assert!(
                    reason.contains("key custody unavailable: the credential store is locked"),
                    "the refusal carries the custody error's own sentence: {reason}"
                );
                assert_eq!(cure, None, "a custody failure is not a credential verdict");
            }
            Provider::Gmail(_) => {
                panic!("a custody failure must refuse the arm, never build a bus without a key")
            }
        }
        test_custody::set_unavailable(&store, None);
        drop(state);
        std::fs::remove_dir_all(&dir).ok();
    }
}
