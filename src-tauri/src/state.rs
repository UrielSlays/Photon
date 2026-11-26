//! The managed state every command is handed.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, Weak};
use std::sync::atomic::{AtomicU64, Ordering};

use aruna::Facet;

use crate::credential::unix_now;
use crate::credential_cell::{CredentialCell, CredentialCoordinator};
use crate::error::SurfaceError;
use crate::plumbing::AdmitIoOwned;
use crate::provider::{
    build_gmail_provider, BootCell, GmailProvider, Provider, PROVIDER_JMAP_UNCONFIGURED,
};
use crate::session::PhotonSession;
use crate::single_flight::{InFlight, Pacing};
use crate::status::{unconfigured_verdict, GrantOnDisk};
use crate::token_refresh::RefreshClient;
use crate::{resolved_account, ProviderKind, SessionConfig};
#[cfg(test)]
use std::time::Instant;

/// This run's start stamp in unix millis: the half of a minted idempotency key that keeps a fresh
/// run's keys off a previous run's rows (see [`PhotonState::mint_key`]). An unreadable clock
/// answers 0, as [`unix_now`] does.
fn session_stamp_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// The other half of the session stamp: a random 64-bit hex nonce that keeps two instances
/// started in the same wall-clock millisecond from minting identical idempotency keys.
/// `session_stamp_millis()` alone restarts `verb_seq` at 0 every run, so two processes launched in
/// the same tick would mint the same `{verb}|{message_ref}|{stamp}|{seq}` logical id.
///
/// It uses `lower(hex(randomblob(8)))` (SQLite's CSPRNG, as `aruna` does for opaque ids) on a
/// throwaway in-memory connection, so it works whether or not the store opened
/// (`PhotonState::unresolved` mints one too). If the connection cannot be opened it falls back to
/// 16 zero hex digits, the same "degrade, never panic" shape as an unreadable clock; a collision
/// then is no worse than the millis-only stamp.
fn session_nonce_hex() -> String {
    rusqlite::Connection::open_in_memory()
        .and_then(|conn| conn.query_row("SELECT lower(hex(randomblob(8)));", [], |r| r.get(0)))
        .unwrap_or_else(|_| "0".repeat(16))
}

/// The managed state: the session mutex, the provider handles, the single-flight table.
pub struct PhotonState {
    pub(crate) config: SessionConfig,
    /// `None` when the store itself could not be opened: the app still runs and every command
    /// answers a typed refusal naming why, rather than the window failing to appear.
    session: Option<Arc<Mutex<PhotonSession>>>,
    pub(crate) store_unavailable: Option<String>,
    /// The provider arm and the credential it was built from, as one published generation.
    /// Admission and status read the same cell, so they cannot disagree about which credential is
    /// live or what its cure is. An expired credential builds an arm marked expired-but-refreshable,
    /// and the first command renews it.
    pub(crate) credential: Arc<CredentialCoordinator>,
    /// The blocking HTTP client for the token endpoint, built once (no network at construction).
    /// `None` when the TLS client could not be built; the refresh path then refuses with the
    /// build error instead of dialing.
    pub(crate) refresh_client: Option<RefreshClient>,
    pub(crate) inflight: InFlight,
    /// The cadence floor and the retained provider backoff: two instants, beside the single-flight
    /// table. The credential renewal has its own floor of the same class
    /// (`credential_cell::REFRESH_ATTEMPT_FLOOR`), kept beside the cell it paces.
    pub(crate) pacing: Pacing,
    /// Session-scoped monotonic counter behind the minted idempotency keys (see
    /// [`PhotonState::mint_key`]).
    verb_seq: AtomicU64,
    /// The session's start instant in unix millis, the other half of a key that must not collide
    /// with a previous run's keys (see [`PhotonState::mint_key`]).
    session_stamp: u64,
    /// A random 64-bit hex nonce minted alongside `session_stamp`, so two instances starting in
    /// the same millisecond mint distinct keys (see [`session_nonce_hex`]).
    session_nonce: String,
}

impl PhotonState {
    /// Build the session from resolved config. Never fails: an unopenable store and an absent
    /// credential are states this type carries, because a shell that refuses to start cannot tell
    /// the user why.
    ///
    /// It is not side-effect free. Construction touches no network, but on the Gmail arm it:
    /// - acquires the cross-process credential lock, bounded by
    ///   `token_refresh::CREDENTIAL_LOCK_DEADLINE`;
    /// - may write one file, the grant ratchet `grant_high_water.json`, latched upward by
    ///   `build_gmail_arm`'s admission;
    /// - resolves the store's root commitment key through `aruna::key_custody::root_key_verified`,
    ///   which on a store with no registered key may mint one, store it in the OS credential store
    ///   (`key_custody_keyring`) and register its fingerprint in the store.
    ///
    /// A lock timeout, a failed latch or a custody refusal yields an explicit
    /// `Provider::Unconfigured` carrying the typed sentence, never an arm whose bus has no key.
    pub fn new(config: SessionConfig) -> Self {
        Self::new_at(config, unix_now())
    }

    /// [`PhotonState::new`] with the wall clock as a parameter: the seam the credential-expiry
    /// tests reach through (as [`Pacing`] does for `Instant`).
    pub fn new_at(config: SessionConfig, now_unix_secs: i64) -> Self {
        let (session, store_unavailable) = match PhotonSession::open(&config.store_path) {
            Ok(s) => (Some(Arc::new(Mutex::new(s))), None),
            Err(reason) => (None, Some(reason)),
        };
        let _ = now_unix_secs; // construction no longer judges expiry — the first command does
        // The coordinator is built cyclically: the boot arm's bus carries a [`ShellGrantRatchet`]
        // holding a weak handle back to the coordinator the boot cell is published into (a strong
        // one would be a cycle: coordinator, cell, arm, bus, ratchet). The handle cannot be
        // upgraded until construction returns; the ratchet is consulted only at a plan child's
        // send authorization, after it.
        let credential = Arc::new_cyclic(|cell: &Weak<CredentialCoordinator>| {
            let boot = match config.provider_kind {
                ProviderKind::Jmap => BootCell::Unconfigured {
                    reason: PROVIDER_JMAP_UNCONFIGURED.to_string(),
                    // No credential is involved, so no credential cure is owed.
                    cure: None,
                },
                ProviderKind::Gmail => build_gmail_provider(&config, cell),
            };
            // [`BootCell`] decides what the first generation of the cell may contain, and its
            // unarmed arm has no expiry, digest or generation field to fill in.
            CredentialCoordinator::new(boot.into_cell(), config.gmail_secrets_dir.clone())
        });
        Self {
            config,
            session,
            store_unavailable,
            credential,
            refresh_client: RefreshClient::production().ok(),
            inflight: InFlight::default(),
            pacing: Pacing::default(),
            verb_seq: AtomicU64::new(0),
            session_stamp: session_stamp_millis(),
            session_nonce: session_nonce_hex(),
        }
    }

    /// The state a session takes when its own paths could not be resolved.
    ///
    /// Nothing is opened or read: there is no store path or secrets directory. Both halves of the
    /// session carry the same resolver reason (`store_reason` and `provider_reason`), so
    /// `session_status` reports `configured: false` with the truth in it, and every command
    /// refuses with [`SurfaceError::SessionUnconfigured`] carrying that sentence.
    ///
    /// The config's two path fields are empty, so `store_path` renders as the empty string beside
    /// a reason that says why. A `"."` placeholder would send a real database and credential read
    /// into the process working directory.
    pub fn unresolved(reason: String) -> Self {
        Self {
            config: SessionConfig {
                account: resolved_account(),
                store_path: PathBuf::new(),
                provider_kind: ProviderKind::Gmail,
                gmail_secrets_dir: PathBuf::new(),
            },
            session: None,
            store_unavailable: Some(reason.clone()),
            credential: Arc::new(CredentialCoordinator::new(
                // A path that could not be resolved is not a credential verdict, so no cure, and
                // no arm was built, so no expiry, digest or generation. One constructor answers
                // both halves.
                CredentialCell::unconfigured(reason, None),
                PathBuf::new(),
            )),
            refresh_client: None,
            inflight: InFlight::default(),
            pacing: Pacing::default(),
            verb_seq: AtomicU64::new(0),
            session_stamp: session_stamp_millis(),
            session_nonce: session_nonce_hex(),
        }
    }

    pub(crate) fn session(&self) -> Result<Arc<Mutex<PhotonSession>>, SurfaceError> {
        match (&self.session, &self.store_unavailable) {
            (Some(s), _) => Ok(Arc::clone(s)),
            (None, Some(reason)) => Err(SurfaceError::SessionUnconfigured {
                reason: reason.clone(),
                // The store half owes no credential cure.
                cure: None,
            }),
            (None, None) => Err(SurfaceError::Internal {
                reason: "no session and no reason — this state is unconstructible".to_string(),
            }),
        }
    }

    /// The provider arm as currently published, with no credential judgement.
    ///
    /// Callers: `run_verb` (the v1 verbs and the three YELLOW commands), `undo`,
    /// `undo_presentation`, the plan commands (`plan_mint` through [`Self::gmail_with_grant`],
    /// `plan_review`, `plan_approve`), `set_knob`, and [`admit_provider`]'s unarmed early return.
    /// They are safe today only because the mutation fence is default-closed, so no verb dispatches
    /// and no journaled intent needs compensating; that falls due when mutations are enabled. For a
    /// plan child it is already handled: `plan_apply` admits through [`admit_provider`] and drives
    /// each member through the engine's send fence, whose grant row consults this arm's
    /// `ShellGrantRatchet` (`CommandBus::plan_binding`), where a retired generation refuses on the
    /// write side. The YELLOW verbs and `undo` do not meet it, and the work that opens the fence
    /// still owes them that check. Read commands go through [`admit_provider`], which reconciles
    /// and renews first.
    ///
    /// The refusal's label is derived, not replayed. The cell's recorded `Unconfigured { reason,
    /// cure }` is what the last publisher saw, and these callers never reconcile, so a mint that
    /// lands while the app sits on a boot refusal would keep re-serving `re_mint` here after the
    /// status bar stopped demanding it. The cure and sentence come from [`unconfigured_verdict`],
    /// over the same read-only `GrantOnDisk` observation the status view uses. That read is
    /// lock-free and guarded by [`Self::refresh_armed`], so an unresolved or non-Gmail session
    /// never resolves the credential path against the process CWD.
    ///
    /// It is a label, not a gate or an admission. These callers never call
    /// [`CredentialCoordinator::admit`]: a credential that lands while the app sits here is adopted
    /// only by the provider-read path ([`admit_provider`]), so re-running the same verb adopts
    /// nothing and refuses again. That is why [`ADOPTION_PENDING_REASON`] names no command: it
    /// reports what was observed (a credential has landed, nothing has adopted it). "Your next
    /// command" would be false here, and "refresh the inbox" is false whenever one of that path's
    /// own pre-admit guards refuses (listed on [`ADOPTION_PENDING_REASON`]).
    pub(crate) fn gmail(&self) -> Result<Arc<GmailProvider>, SurfaceError> {
        let cell = self.credential.snapshot();
        match &cell.provider {
            Provider::Gmail(p) => Ok(Arc::clone(p)),
            Provider::Unconfigured { reason, cure } => {
                let (cure, reason) = unconfigured_verdict(reason, *cure, &self.grant_on_disk());
                Err(SurfaceError::SessionUnconfigured { reason, cure })
            }
        }
    }

    /// The published arm and the grant it was built under, from one snapshot of the cell
    /// ([`credential_cell::CredentialCell::published_grant`]). A plan mint binds these
    /// (`PlanSpec::{grant_generation, provider_principal}`), so the plan names the grant of the
    /// arm whose bus mints it. An unarmed cell refuses through [`Self::gmail`], the one place that
    /// labels an unconfigured cell.
    pub(crate) fn gmail_with_grant(&self) -> Result<(Arc<GmailProvider>, u64, String), SurfaceError> {
        self.gmail()?;
        let cell = self.credential.snapshot();
        match (&cell.provider, cell.published_grant()) {
            (Provider::Gmail(arm), Some((generation, principal))) => {
                Ok((Arc::clone(arm), generation, principal))
            }
            // Reached only when the cell was un-armed between the two reads above (a publish landed
            // in between), or by an armed cell carrying no generation. `BootCell::Armed` and every
            // wave publish a generation beside the arm, so no path is known to produce that. The
            // next command reads the new cell.
            _ => Err(SurfaceError::Internal {
                reason: "the credential cell published no armed grant while the plan door read \
                         it; nothing was minted"
                    .to_string(),
            }),
        }
    }

    /// The one read behind every status-side answer about the grant state, taken here so the
    /// [`Self::refresh_armed`] guard cannot be forgotten at one of the two call sites. Read-only
    /// and lock-free, like every other status read.
    pub(crate) fn grant_on_disk(&self) -> GrantOnDisk {
        if self.refresh_armed() {
            GrantOnDisk::read(&self.config.gmail_secrets_dir)
        } else {
            GrantOnDisk::unarmed()
        }
    }

    /// The coordinator handle an async command moves onto the blocking pool.
    pub(crate) fn credential_handle(&self) -> Arc<CredentialCoordinator> {
        Arc::clone(&self.credential)
    }

    /// The credential coordinator may touch the disk only for a resolved Gmail session. A JMAP
    /// session's secrets dir is not the coordinator's to adopt from, so a Gmail credential parked
    /// there must never replace the JMAP arm. An unresolved session's empty path fields would
    /// resolve relative to the process CWD: `FileGen::of` answers `Absent`, not `None`, for a
    /// missing file, so the `file_gen: None` boot cell would read any probe as "changed" and
    /// reconcile, creating a CWD-relative lock file and clobbering the resolver reason with a CWD
    /// load failure. Everything not armed is refuse-only on the published arm.
    pub(crate) fn refresh_armed(&self) -> bool {
        self.config.provider_kind == ProviderKind::Gmail
            && !self.config.gmail_secrets_dir.as_os_str().is_empty()
    }

    /// The I/O the credential coordinator runs inside its critical section: every closure reads
    /// this session's config, and nothing here touches the async runtime.
    pub(crate) fn admit_io(&self) -> AdmitIoOwned {
        AdmitIoOwned {
            config: self.config.clone(),
            refresh_client: self.refresh_client.clone(),
            credential: Arc::downgrade(&self.credential),
            #[cfg(test)]
            now_override: None,
        }
    }

    /// Admit a provider-reading command on the caller's thread: reconcile the file, renew if
    /// expired, and hand back the live arm or the typed refusal with its cure. This is the sync
    /// seam the expiry tests use (`tauri::State` has no constructor outside a running app); the
    /// commands use [`admit_provider`], which runs the same protocol on the blocking pool.
    #[cfg(test)]
    pub(crate) fn admit_provider_sync(&self, now_unix_secs: i64) -> Result<Arc<GmailProvider>, SurfaceError> {
        if !self.refresh_armed() {
            return self.gmail();
        }
        let mut owned = self.admit_io();
        // Time-travel coherently: the whole wave, including the use-time clock the critical
        // section samples through `AdmitIo::now_unix`, sees the test's clock.
        owned.now_override = Some(now_unix_secs);
        self.credential.admit(now_unix_secs, Instant::now(), &owned)
    }

    /// The renderer names the account on every call; this is where that name stops being
    /// load-bearing. v1 is single-account, so a request for any other partition is refused rather
    /// than served, and a hostile renderer cannot address a partition the session was not
    /// configured for.
    pub(crate) fn account(&self, requested: &str) -> Result<String, SurfaceError> {
        if requested == self.config.account {
            return Ok(self.config.account.clone());
        }
        // Terminal: this session was configured for exactly one account at boot, and retrying the
        // identical request can never reach a different one.
        Err(SurfaceError::Refused {
            reason: format!(
                "this session serves the account {:?} only (v1 is single-account)",
                self.config.account
            ),
            terminal: true,
        })
    }

    /// Mint the durable idempotency key for one user action.
    ///
    /// The engine's contract (`aruna::derive_idempotency_key`) asks the caller for a `logical_id`
    /// stable per logical intent across retries, and for account normalization (the connector's
    /// job). For the first, the shell treats one user action as one logical intent. The key
    /// carries the verb, the message ref, this session's start stamp and a monotonic sequence
    /// number, so it is not reused across two separate presses on the same row. Reusing it would
    /// collapse "archive, undo, archive again" into a silent idempotent replay that reports
    /// success and changes nothing, which is worse than an extra journaled intent. Cross-retry
    /// stability comes from the single-flight claim instead: a duplicate request while the first
    /// is in flight is refused (`Busy`), never re-keyed and re-dispatched.
    ///
    /// The session stamp keeps a fresh run's keys off a previous run's rows: a counter alone
    /// would restart at zero and the engine would replay the old intent's stored outcome for a
    /// brand-new user action.
    pub(crate) fn mint_key(&self, verb: &str, message_ref: &str) -> String {
        let seq = self.verb_seq.fetch_add(1, Ordering::Relaxed);
        // `session_nonce` sits beside `session_stamp`: two processes starting in the same
        // wall-clock millisecond (where `session_stamp` alone collides) still mint distinct
        // logical ids because the nonce is independently random per session.
        aruna::derive_idempotency_key(
            &self.config.account,
            &Facet::Mail,
            &format!("{verb}|{message_ref}|{}|{}|{seq}", self.session_stamp, self.session_nonce),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::{CREDENTIAL_EXPIRY_GRACE_SECS, GMAIL_TOKEN_FILE};
    use crate::status::{session_status_view, ADOPTION_PENDING_REASON};
    use crate::tests::fixtures::{
        gmail_arm_state_expiring, s0_dir, s0_grant, s0_token_file, unique_store,
    };
    use crate::token_refresh::{self, Cure};

    // -------------------------------------------------------------------------------------------
    // THE OTHER SURFACE THAT SPEAKS FOR AN UNCONFIGURED CELL.
    //
    // `PhotonState::gmail()` is the seam the three non-admitting doors take — `run_verb`, `undo`
    // and `undo_presentation` (a LIVE READ surface) — and it replayed the cell's RECORDED refusal
    // verbatim: whatever the last publisher saw, forever, with no reconcile and no sight of the
    // disk. So the status bar could stop demanding a consent while these three kept demanding it
    // from the same cell in the same second. It is closed with the SAME derivation, not a second
    // one: `unconfigured_verdict` over one read-only `GrantOnDisk`.
    //
    // NOT A GATE: nothing here decides whether an arm is HANDED OUT — the
    // admission side of this door is separate. This is the LABEL on a refusal that happens
    // either way.
    //
    // The unit seam is `gmail()` itself, as `the_jmap_arm_refuses_with_its_named_reason…` uses:
    // the three doors are async Tauri commands and `tauri::State` has no constructor outside a
    // running app, so each of them reaches the provider through this one call. (The attribute is
    // deliberately not spelled here: `surface_contract.rs`'s door census is a literal-text scan
    // over this file, and naming it in prose enrolls the prose as a door.)
    //
    // Before the fix this test failed — see.
    // -------------------------------------------------------------------------------------------
    #[test]
    fn the_verb_doors_stop_demanding_a_consent_that_already_landed() {
        let dir = s0_dir("f10r8f10b");
        let state = PhotonState::new(SessionConfig {
            account: "acct".to_string(),
            store_path: dir.join("store.sqlite"),
            provider_kind: ProviderKind::Gmail,
            gmail_secrets_dir: dir.to_path_buf(),
        });
        match state.gmail().err() {
            Some(SurfaceError::SessionUnconfigured { cure, .. }) => assert_eq!(
                cure,
                Some(Cure::ReMint),
                "the witness's own premise: the verb doors refuse a credential-less boot with \
                 the re-mint demand"
            ),
            other => panic!("a boot with no credential builds no arm: {other:?}"),
        }

        // THE MINT COMPLETES — and nothing reconciles it, because these doors never do.
        std::fs::write(
            dir.join(token_refresh::GRANT_HIGH_WATER_FILE_NAME),
            b"{\"grant_generation\":1}\n",
        )
        .unwrap();
        std::fs::write(
            dir.join(GMAIL_TOKEN_FILE),
            s0_token_file(unix_now() + 3_600, Some(&s0_grant())),
        )
        .unwrap();

        match state.gmail().err() {
            Some(SurfaceError::SessionUnconfigured { cure, reason }) => {
                assert_eq!(
                    cure, None,
                    "the demanded consent is ALREADY on disk: an undo_presentation read must not \
                     send the operator to the mint a second time"
                );
                assert_eq!(
                    reason, ADOPTION_PENDING_REASON,
                    "…and the sentence reports the state, not a door (r12 F15)"
                );
                // AND WHAT IT SAYS IS TRUE AT *EVERY* DOOR, because
                // it names none. This is the seam `run_verb` · `undo` · `undo_presentation`
                // take, and none of them ever call `CredentialCoordinator::admit` — the acting
                // doors' admission is separate — so "adoption on your next command"
                // was false here. The door that does admit has its own pre-admit guards, one of
                // them permanent (`state.session()?` on an unopenable store), so "refresh the
                // inbox to adopt it" was false there. The sentence is now the STATE.
                assert_eq!(
                    reason, "a credential has landed; Photon has not adopted it yet",
                    "the label mirrors what is on disk and promises no door: the acting doors \
                     never admit (#88), and the read door's own guards can refuse before its \
                     reconcile — the recovery instruction is the runbook's (#87)"
                );
            }
            other => panic!("no arm is published until a command adopts the credential: {other:?}"),
        }

        // The refusal is still a REFUSAL — this change is the label, never the door.
        assert!(
            matches!(
                state.credential.snapshot().provider,
                Provider::Unconfigured { .. }
            ),
            "no arm was handed out by a status-side reading"
        );
        state
            .admit_provider_sync(unix_now())
            .expect("the next command is what adopts it");
        assert!(
            state.gmail().is_ok(),
            "…and THEN the verb doors have an arm to hand out"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_minted_key_is_distinct_per_action_and_carries_the_session_stamp() {
        // The guard is declared BEFORE the state (it drops last). The
        // name is unique per call, so this store can only ever be the one THIS test created.
        let store = unique_store("key-mint-nonexistent");
        let secrets = aruna::test_temp::TempDir::uncreated("photon-key-mint-no-secrets"); // guarded
        let state = PhotonState::new(SessionConfig {
            account: "acct".to_string(),
            store_path: store.to_path_buf(),
            provider_kind: ProviderKind::Jmap,
            gmail_secrets_dir: secrets.to_path_buf(),
        });

        let first = state.mint_key("archive", "msg-1");
        let second = state.mint_key("archive", "msg-1");
        assert_ne!(
            first, second,
            "two presses of the same key on the same row are two logical intents — reusing one \
             key would replay the first outcome and change nothing the second time"
        );
        assert!(first.contains("archive|msg-1|"), "{first}");
        assert!(
            first.contains(&state.session_stamp.to_string()),
            "the session stamp keeps a fresh run's keys off the previous run's rows: {first}"
        );
    }

    /// `session_stamp_millis()` alone restarts at whatever the wall clock reads — two
    /// `PhotonState`s that happen to start within the SAME wall-clock millisecond (a restart, or
    /// two dev instances launched together) land on an identical `session_stamp`, and both
    /// `verb_seq` counters start at 0, so before the fix their FIRST minted key for the same action
    /// collided outright. Relying on the real clock to actually land two constructions in the same
    /// millisecond would make this test flaky (a slow machine could legitimately straddle a tick),
    /// so the collision is forced deterministically here — same discipline `Pacing`/`new_at`'s own
    /// witnesses use elsewhere in this file (the wall clock is a seam, not a dice roll in a test).
    #[test]
    fn two_sessions_with_the_same_session_stamp_still_mint_distinct_keys() {
        // The ONE guard owns both stores and both secrets dirs, bound
        // BEFORE the states. They were FIXED names (every run re-opened the last run's store)
        // removed by a `remove_file(..).ok()` that ran while both states still held them open —
        // refused on Windows, swallowed: `photon-nonce-collision-{a,b}.sqlite` leaked every run.
        let stores = [
            aruna::test_temp::TempFile::sqlite("photon-nonce-collision-a"),
            aruna::test_temp::TempFile::sqlite("photon-nonce-collision-b"),
        ];
        let secrets = [
            aruna::test_temp::TempDir::uncreated("photon-nonce-collision-a-secrets"),
            aruna::test_temp::TempDir::uncreated("photon-nonce-collision-b-secrets"),
        ];
        let cfg = |i: usize| SessionConfig {
            account: "acct".to_string(),
            store_path: stores[i].to_path_buf(),
            provider_kind: ProviderKind::Jmap,
            gmail_secrets_dir: secrets[i].to_path_buf(),
        };
        let a = PhotonState::new(cfg(0));
        let mut b = PhotonState::new(cfg(1));
        // Force exactly the race this fixes: two sessions landing on the SAME millisecond stamp.
        b.session_stamp = a.session_stamp;
        // Sanity: this is a real collision, not a vacuous assertion — both counters truly start at 0.
        assert_eq!(a.verb_seq.load(Ordering::Relaxed), b.verb_seq.load(Ordering::Relaxed));

        assert_ne!(
            a.mint_key("archive", "msg-1"),
            b.mint_key("archive", "msg-1"),
            "two sessions sharing the same session_stamp (same wall-clock millisecond) must not \
             mint the same idempotency key for the same action — only the random nonce can tell \
             them apart, since the stamp and the sequence number are identical"
        );
    }

    #[test]
    fn the_jmap_arm_refuses_with_its_named_reason_rather_than_pretending() {
        // A unique, guarded store (declared before the state).
        let store = unique_store("jmap-arm");
        let secrets = aruna::test_temp::TempDir::uncreated("photon-jmap-no-secrets"); // guarded
        let state = PhotonState::new(SessionConfig {
            account: "acct".to_string(),
            store_path: store.to_path_buf(),
            provider_kind: ProviderKind::Jmap,
            gmail_secrets_dir: secrets.to_path_buf(),
        });
        match state.gmail() {
            Err(SurfaceError::SessionUnconfigured { reason, .. }) => {
                assert_eq!(reason, PROVIDER_JMAP_UNCONFIGURED)
            }
            Err(other) => panic!("the unwired arm must refuse with its named reason: {other:?}"),
            Ok(_) => panic!("an unwired arm must never hand back a provider handle"),
        }
    }

    // -------------------------------------------------------------------------------------------
    // The REFUSAL half: the same cure rides the `session_unconfigured` wire error, so a
    // command refusal and the status bar cannot say two different things about one boot.
    //
    // Asserted through the SERIALIZED form deliberately: the wire shape is the contract the
    // frontend's `SurfaceError` union mirrors (`src/ipc.ts`), and it is what was missing.
    //
    // Before the fix: `wire["cure"]` is `null` — the variant carried a `reason` and nothing else.
    // -------------------------------------------------------------------------------------------
    #[test]
    fn the_unconfigured_refusal_carries_the_same_cure_on_the_wire() {
        let dir = s0_dir("w90-refusal");
        std::fs::write(dir.join(GMAIL_TOKEN_FILE), s0_token_file(42, None)).unwrap();
        let state = PhotonState::new(SessionConfig {
            account: "acct".to_string(),
            store_path: dir.join("store.sqlite"),
            provider_kind: ProviderKind::Gmail,
            gmail_secrets_dir: dir.to_path_buf(),
        });

        let err = match state.admit_provider_sync(unix_now()) {
            Err(e) => e,
            Ok(_) => panic!("a pre-S0 credential admits nothing"),
        };
        let SurfaceError::SessionUnconfigured { .. } = &err else {
            panic!("a boot credential refusal is a SessionUnconfigured refusal: {err:?}");
        };
        let wire = serde_json::to_value(&err).expect("SurfaceError serializes");
        assert_eq!(wire["kind"], serde_json::json!("session_unconfigured"));
        assert_eq!(
            wire["cure"],
            serde_json::json!("re_mint"),
            "the refusal carries the DISCRIMINANT beside its sentence: {wire}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    // A credential that ages out while
    // the app is open makes the next read ATTEMPT a renewal. Hermetic: the temp secrets dir carries
    // no `client_secret.json`, so the attempt fails LOCALLY before any wire — a `ClientConfig`
    // cure naming the missing file, never a raw 401, never a re-mint demand. A second command
    // inside the pacing floor shares that result without a second attempt.
    #[test]
    fn an_expiry_that_passes_while_the_app_is_open_attempts_a_renewal_and_refuses_truthfully() {
        let expires_at = unix_now() + 3_600;
        let (dir, state) = gmail_arm_state_expiring("live-cred", expires_at);
        assert!(
            matches!(state.credential.snapshot().provider, Provider::Gmail(_)),
            "a live credential builds the production arm"
        );

        state
            .admit_provider_sync(expires_at - 600)
            .expect("a credential with ten minutes left admits the read without a renewal");

        match state.admit_provider_sync(expires_at + 1) {
            Err(SurfaceError::CredentialExpired {
                expires_at: stamp,
                cure,
                reason,
            }) => {
                assert_eq!(stamp, expires_at, "the refusal carries the stamp that passed");
                assert_eq!(
                    cure,
                    Cure::ClientConfig,
                    "the renewal failed LOCALLY on the client config — that is the cure named, \
                     not a re-mint: {reason}"
                );
                assert!(reason.contains("client_secret.json"), "{reason}");
                assert!(!reason.contains("re-mint"), "a config failure is not a re-mint: {reason}");
            }
            other => panic!(
                "a read dispatched after the credential died must be a TYPED refusal carrying \
                 its cure, never a raw provider 401: {:?}",
                other.err()
            ),
        }

        // The grace margin is the renewal TRIGGER at command time too, not only a construction
        // judgement: inside the margin the next command tries again (paced) or shares the result.
        match state.admit_provider_sync(expires_at - CREDENTIAL_EXPIRY_GRACE_SECS + 1) {
            Err(SurfaceError::CredentialExpired { cure, .. }) => assert!(
                matches!(cure, Cure::ClientConfig | Cure::RetryLater),
                "inside the margin the outcome is the shared local result or a paced retry: {cure:?}"
            ),
            other => panic!(
                "inside the grace margin the read is not admitted: {:?}",
                other.err()
            ),
        }

        // `configured` stays TRUE — the session IS configured, its credential aged out; the cell's
        // cure rides the status so the UI never invents a re-mint demand.
        let status = session_status_view(&state, Some(1), None, expires_at + 1);
        assert!(status.configured, "the arm built; the credential aged out");
        assert!(status.credential_expired);
        assert_eq!(status.credential_cure, Some(Cure::ClientConfig));
        let wire = serde_json::to_value(&status).expect("SessionStatus serializes");
        assert_eq!(wire["credential_expired"], serde_json::json!(true));
        assert_eq!(wire["configured"], serde_json::json!(true));
        assert_eq!(wire["credential_cure"], serde_json::json!("client_config"));

        std::fs::remove_dir_all(&dir).ok();
    }

    // THE CREDENTIAL GATE IS FOR RESOLVED GMAIL SESSIONS ONLY. A JMAP session
    // whose secrets dir happens to hold a Gmail credential file must NOT have its Unconfigured
    // arm reconciled into a Gmail arm by the coordinator's disk-adoption path (the cell starts
    // `file_gen: None`, so ANY on-disk file reads as "changed").
    #[test]
    fn a_jmap_session_never_reconciles_a_gmail_credential_into_its_arm() {
        let dir = aruna::test_temp::TempDir::new("photon-jmap-guard"); // the ONE guard (`aruna::test_temp`)
        // A FULLY CONFORMANT Gmail credential — the witness is only discriminating if the
        // file is one the Gmail path would happily adopt.
        std::fs::write(
            dir.join(GMAIL_TOKEN_FILE),
            s0_token_file(unix_now() + 3_600, Some(&s0_grant())),
        )
        .unwrap();
        let state = PhotonState::new(SessionConfig {
            account: "acct".to_string(),
            store_path: dir.join("store.sqlite"),
            provider_kind: ProviderKind::Jmap,
            gmail_secrets_dir: dir.to_path_buf(),
        });

        match state.admit_provider_sync(unix_now()) {
            Err(SurfaceError::SessionUnconfigured { reason, .. }) => assert_eq!(
                reason, PROVIDER_JMAP_UNCONFIGURED,
                "the refusal carries the JMAP arm's own sentence"
            ),
            other => panic!(
                "a JMAP session is refuse-only on provider reads — a Gmail credential on disk \
                 must never be adopted into it: {:?}",
                other.err()
            ),
        }
        assert!(
            matches!(
                state.credential.snapshot().provider,
                Provider::Unconfigured { .. }
            ),
            "the published arm is still the JMAP placeholder, not a Gmail arm"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    // An UNRESOLVED session (empty path fields) keeps its resolver
    // reason on provider reads and never opens a CWD-relative credential path. GUARD witness: in a
    // clean working directory the pre-fix code also refuses (no file to adopt) — the discriminating
    // RED for this finding is the JMAP witness above; this one pins the reason and the no-lock
    // property so a regression cannot land silently.
    #[test]
    fn an_unresolved_session_refuses_reads_with_its_resolver_reason() {
        let state = PhotonState::unresolved("no HOME could be resolved".to_string());
        match state.admit_provider_sync(unix_now()) {
            Err(SurfaceError::SessionUnconfigured { reason, .. }) => {
                assert_eq!(reason, "no HOME could be resolved", "the resolver reason survives")
            }
            other => panic!(
                "an unresolved session refuses provider reads with its own reason: {:?}",
                other.err()
            ),
        }
        assert!(
            !std::path::Path::new(token_refresh::CREDENTIAL_LOCK_FILE_NAME).exists(),
            "no CWD-relative credential lock is created by an unresolved session"
        );
    }

    #[test]
    fn an_unresolved_session_refuses_every_door_with_the_resolver_reason_and_opens_no_store() {
        let reason = "the platform app-data directory could not be resolved (injected)";
        let state = PhotonState::unresolved(reason.to_string());

        match state.session().err() {
            Some(SurfaceError::SessionUnconfigured { reason: r, .. }) => assert_eq!(r, reason),
            other => panic!("an unresolved session must refuse with its reason: {other:?}"),
        }
        match state.gmail().err() {
            Some(SurfaceError::SessionUnconfigured { reason: r, .. }) => assert_eq!(r, reason),
            other => panic!("no provider arm may be built from unresolved paths: {other:?}"),
        }

        let status = session_status_view(&state, None, Some(reason.to_string()), unix_now());
        assert!(!status.configured);
        assert_eq!(status.store_reason.as_deref(), Some(reason));
        assert_eq!(status.provider_reason.as_deref(), Some(reason));
        assert_eq!(
            status.store_path, "",
            "no path was resolvable, so none is reported — `.` would be a plausible-looking lie \
             pointing at a real database in the process working directory"
        );
        assert!(
            !std::path::Path::new("photon.sqlite").exists(),
            "constructing an unresolved session must not create a store in the CWD"
        );
    }

    #[test]
    fn a_foreign_account_name_is_refused_rather_than_served() {
        // A unique, guarded store (declared before the state).
        let store = unique_store("account-guard");
        let secrets = aruna::test_temp::TempDir::uncreated("photon-account-guard-no-secrets"); // guarded
        let state = PhotonState::new(SessionConfig {
            account: "acct".to_string(),
            store_path: store.to_path_buf(),
            provider_kind: ProviderKind::Jmap,
            gmail_secrets_dir: secrets.to_path_buf(),
        });
        assert_eq!(state.account("acct").unwrap(), "acct");
        match state.account("someone-elses-partition") {
            Err(SurfaceError::Refused { reason, .. }) => {
                assert!(reason.contains("single-account"), "{reason}")
            }
            other => panic!("a partition this session does not serve must be refused: {other:?}"),
        }
    }
}
