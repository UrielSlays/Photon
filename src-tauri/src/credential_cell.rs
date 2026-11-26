//! The credential cell, the refresh wave and the commit protocol.
//!
//! One process-wide cell holds the Gmail arm and its credential state as a published generation.
//! One wave at a time refreshes it, and every writer of the on-disk credential (this process and
//! the mint script) serializes under the same OS advisory lock. Everything here runs on the
//! blocking pool: the async commands call [`CredentialCoordinator::admit`] from inside
//! `spawn_blocking` (`with_provider`), never on the async runtime.
//!
//! This module does not talk to the network or the disk itself. The exchange, the persistence,
//! the file read and the provider rebuild are injected as closures ([`AdmitIo`]), so the wave
//! protocol is testable without a token endpoint and `token_refresh` stays the one module that
//! touches provider bytes.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::time::{Duration, Instant};

use crate::token_refresh::{
    credential_lock_path, CredentialLock, Cure, FileGen, GrantProvenance, RefreshLocalError,
    RefreshOutcome, CREDENTIAL_LOCK_DEADLINE,
};
use crate::{credential_expired_at, GmailCredential, GmailProvider, Provider, SurfaceError};

/// The floor between refresh attempts after a `Transient`/`UnknownDenied` outcome, measured from
/// the completion of the previous attempt. It is in the class of `MIN_REFRESH_INTERVAL_MS` ("how
/// often is this worth a round trip"), not a quota number.
pub(crate) const REFRESH_ATTEMPT_FLOOR: Duration = Duration::from_secs(30);


/// The published credential state: provider, expiry, generation, the file the generation was
/// built from and the last refresh result. It is one cell written in one place, so admission and
/// status cannot disagree.
#[derive(Clone)]
pub(crate) struct CredentialCell {
    pub(crate) provider: Provider,
    pub(crate) expires_at: Option<i64>,
    /// Advances on every publication. Waiters compare it to learn "a wave finished while I
    /// waited" without a second POST.
    pub(crate) generation: u64,
    /// The content digest of the token file this cell was built from. Always `None` on an unarmed
    /// cell, enforced by [`CredentialCell::unconfigured`], the only way one is made. It is the
    /// sole change detector above `admit`'s live fast path, so a refusal that carried one could
    /// never be re-examined by the next command.
    pub(crate) file_gen: Option<FileGen>,
    /// The grant generation the published arm was built from; `None` when no arm was built.
    ///
    /// It sits beside `file_gen` because they answer different questions: the digest says which
    /// bytes, the generation says which consent, and only the consent can be retired by the
    /// ratchet. Its consumer is the status surface (`GrantOnDisk::verdict`), which tells the
    /// operator that the consent this arm was built under has been superseded, says
    /// `undetermined` when the ratchet cannot be read, and says nothing when the superseding
    /// credential is already on disk and the next command will adopt it. That judgment applies on
    /// both the live and the expired branch: a retirement outranks an expired cell's stamped
    /// `retry_later`, because no renewal un-supersedes a consent. It is not an admission-exit
    /// check; see [`CredentialCoordinator::admit`] for where a retired generation refuses.
    pub(crate) grant_generation: Option<u64>,
    /// The last refresh outcome, lossless (a waiter reproduces the same typed cure).
    pub(crate) last_result: Option<RefreshStamp>,
}

/// A refresh result as the cell remembers it: the full sanitized outcome (never token bytes;
/// `Renewed` is remembered without its secrets), when it completed, and the file generation it
/// was decided against (the latch key).
#[derive(Clone, Debug)]
pub(crate) struct RefreshStamp {
    pub(crate) outcome: RememberedOutcome,
    /// Monotonic; the pacing floor is measured from here (from completion).
    pub(crate) completed_at: Instant,
    pub(crate) file_gen: Option<FileGen>,
    /// Did the wave behind this stamp dial the token endpoint? Recorded at the source by the wave,
    /// the only authority on the question. Deriving it from the error's type was wrong twice: a
    /// post-POST `WriteFailed` and a pre-wire `ClientConfig` share a variant, and a variant-derived
    /// `spent_a_post` let a read-only disk turn sequential reads into an endpoint storm. The floor
    /// paces exactly the stamps that carry `true`.
    pub(crate) spent_post: bool,
    /// Consecutive failures since the last renewal or fresh adoption. Each refusal is individually
    /// accurate, but the aggregate must not be silent: at three and beyond the paced refusal names
    /// the streak, so a permanently failing state eventually says "retrying is not the cure"
    /// instead of an endless "will retry on your next command". Sentence-only; no wire field.
    pub(crate) failures_in_a_row: u32,
}

/// [`RefreshOutcome`] with the secret-bearing `Renewed` payload stripped. Every other variant is
/// carried whole, which is what makes it lossless.
#[derive(Clone, Debug)]
pub(crate) enum RememberedOutcome {
    Renewed,
    Failed(RefreshOutcome),
    /// A local failure (lock timeout, write, rename, rebuild): transient-class, never a silent
    /// wedge.
    Local(RefreshLocalError),
}

impl RememberedOutcome {
    /// Terminal outcomes latch to the file generation: no re-POST until the file changes.
    /// Everything else is retried under the floor.
    fn is_terminal_latch(&self) -> bool {
        match self {
            RememberedOutcome::Failed(o) => o.latches(),
            RememberedOutcome::Renewed | RememberedOutcome::Local(_) => false,
        }
    }

    /// Is the cure this stamp demands the one a landed replacement credential has already
    /// supplied?
    ///
    /// The predicate is the cure map, not a hand-listed set. A re-mint is cured by exactly one
    /// act, a new consent written to the credential file, so "a valid, un-retired replacement is
    /// on disk" is that cure, applied, whichever path recorded the demand. Every other cure lives
    /// in media no credential file observes (`client_secret.json`, the Cloud console,
    /// administrator policy, or the passage of time), so none is answered by a landed replacement.
    ///
    /// This is [`Self::is_terminal_latch`] plus the wave's own pre-exchange ratchet refusal. A
    /// local failure does not latch, so `Local(GrantRetired)` (the wave's stamp for a
    /// retired-and-expired grant) would keep demanding a consent the operator had already given
    /// once the mint finished publishing N+1. The one member this adds is exactly
    /// `Local(GrantRetired)`; every other local failure's cure is `RetryLater` or `Undetermined`.
    fn cured_by_a_landed_replacement(&self) -> bool {
        self.cure() == Cure::ReMint
    }

    fn cure(&self) -> Cure {
        match self {
            RememberedOutcome::Renewed => Cure::RetryLater,
            RememberedOutcome::Failed(o) => o.cure(),
            // The local map lives on the error type and is read from there by this wave-side
            // consumer and by the boot path's `Provider::Unconfigured`, so one local failure
            // cannot take two cures on two surfaces.
            RememberedOutcome::Local(e) => e.cure(),
        }
    }

    fn reason_sentence(&self) -> String {
        match self {
            RememberedOutcome::Renewed => "the credential was renewed".to_string(),
            RememberedOutcome::Failed(o) => o.reason_sentence(),
            RememberedOutcome::Local(e) => e.reason_sentence(),
        }
    }
}

impl CredentialCell {
    /// The one way an unarmed cell is made.
    ///
    /// An `Unconfigured` cell carries no digest, expiry or grant generation, and the constructor
    /// has no parameter to pass one through. The digest exists to let
    /// [`CredentialCoordinator::admit`] skip re-reading the credential file behind a live arm
    /// (`file_changed_since_publish`); a cell with no arm has nothing to skip.
    ///
    /// Pairing them is an invalid state that was reached twice. The fresh-install early return
    /// published a re-mint refusal beside the digest of a file a racing mint had just written. And
    /// a valid, unexpired credential whose ratchet was unreadable published `cure: RetryLater`
    /// beside its own digest and live expiry, so the next admission found the digest unchanged,
    /// took the live fast path and re-served the refusal: a repaired ratchet healed nothing until
    /// the credential expired or the app restarted.
    ///
    /// The cost: `Some(observed) != None` always, so an unarmed cell reconciles on every
    /// admission. That is one lock-and-read per command for a session already refusing every
    /// command, and never a token-endpoint POST.
    pub(crate) fn unconfigured(reason: String, cure: Option<Cure>) -> Self {
        Self {
            provider: Provider::Unconfigured { reason, cure },
            expires_at: None,
            generation: 0,
            file_gen: None,
            grant_generation: None,
            last_result: None,
        }
    }

    /// The grant identity this cell publishes: the generation its arm was built under
    /// ([`CredentialCell::grant_generation`]) and the principal that arm addresses
    /// (`GmailProvider::user`, which `build_gmail_arm` sets from the credential's
    /// `grant.provider_principal`, one identity for both halves). `None` for a cell with no arm.
    /// Read by [`CredentialCoordinator::admits_plan_grant`], which a plan child is checked
    /// against.
    pub(crate) fn published_grant(&self) -> Option<(u64, String)> {
        match (&self.provider, self.grant_generation) {
            (Provider::Gmail(arm), Some(generation)) => Some((generation, arm.user.0.clone())),
            _ => None,
        }
    }

    /// [`CredentialCell::unconfigured`] applied to a cell that already exists, for the
    /// coordinator's publishers. [`CredentialCoordinator::publish`] mutates the live cell, and its
    /// `generation` counter and `last_result` belong to the publisher (a reconcile preserves a
    /// stamp; a wave clears it). Everything the arm described is dropped by the same code path the
    /// constructor uses, so no publisher can keep half of it.
    pub(crate) fn set_unconfigured(&mut self, reason: String, cure: Option<Cure>) {
        let fresh = Self::unconfigured(reason, cure);
        self.provider = fresh.provider;
        self.expires_at = fresh.expires_at;
        self.file_gen = fresh.file_gen;
        self.grant_generation = fresh.grant_generation;
    }

    /// The cure the status surface reports for an expired cell: the last result's, or
    /// `RetryLater` when no attempt has been made yet (the expired-but-refreshable boot state,
    /// never a re-mint demand before a refresh was tried).
    ///
    /// It is the status surface's last resort. `GrantOnDisk::verdict` answers first on both
    /// branches, and this method is reached only when that derivation is `Silent`. They answer
    /// different questions: the stamp says what to do about the step that failed, the derivation
    /// says whether this session's admission still stands. Letting the stamp answer the second is
    /// what put `retry_later` on the bar for an arm the ratchet had retired.
    ///
    /// It is a method on the cell, not the coordinator, because the status view captures one
    /// snapshot and derives every credential field from it. A coordinator-level lookup would take
    /// a second snapshot, and a renewal publishing between the two could pair
    /// `credential_expired: true` with `credential_cure: null` on the wire.
    pub(crate) fn status_cure(&self, now_unix: i64, disk_gen: Option<&FileGen>) -> Option<Cure> {
        credential_expired_at(self.expires_at, now_unix)?;
        let Some(stamp) = self.last_result.as_ref() else {
            return Some(Cure::RetryLater);
        };
        // Status reconcile. A latched cure is keyed to the cell's file generation and its release
        // lives in `admit`, but the operator reads the status bar and `inbox_page` never admits.
        // When the caller's disk observation differs from the published generation, the demanded
        // cure has plausibly been applied (an external re-mint the next provider command will
        // adopt). Continuing to demand it would make the operator re-mint a second time, burning a
        // 300 s consent against the provider's refresh-token ceiling, so report the neutral
        // `RetryLater` instead. `None` (disk unobserved or unreadable) suppresses nothing:
        // undecidable keeps the stamped truth over flapping.
        //
        // The suppression has two conjuncts: the disk must differ from the cell's generation
        // (something new landed) and from the stamp's (otherwise the latch would survive adoption:
        // a disk equal to the stamp's bytes re-latches at the next admission, so promising a retry
        // would be false).
        //
        // The first conjunct is `cured_by_a_landed_replacement`, not `is_terminal_latch`: the
        // question is "has the demanded cure been applied", which belongs to the cure map, not the
        // latch set. They differ by the wave's own `Local(GrantRetired)` stamp, which demands a
        // re-mint and never latches.
        if stamp.outcome.cured_by_a_landed_replacement()
            && disk_gen.is_some()
            && disk_gen != self.file_gen.as_ref()
            && disk_gen != stamp.file_gen.as_ref()
        {
            return Some(Cure::RetryLater);
        }
        Some(stamp.outcome.cure())
    }
}

/// The I/O a wave needs, injected so the protocol is testable hermetically. Every method runs
/// inside the wave's critical section on the blocking pool.
pub(crate) trait AdmitIo {
    /// Read and validate the on-disk credential (`load_gmail_credential`). The failure is typed:
    /// the wave and the reconcile take the cure they publish from the refusal's own variant, never
    /// from a constant standing for the whole set.
    fn load(&self) -> Result<GmailCredential, crate::CredentialLoadFailure>;
    /// Digest the on-disk token file. Absence is a generation (`FileGen::Absent`), not an error;
    /// `Err` means the digest could not be read, which the caller must surface as a typed local
    /// failure and never flatten into "changed" (flattening released a terminal latch and
    /// re-POSTed a refused grant).
    fn file_gen(&self) -> Result<FileGen, RefreshLocalError>;
    /// The token-endpoint exchange for a given refresh token (`token_refresh::RefreshClient`). A
    /// local failure before the wire (client config unreadable, no HTTP client) is an `Err`, so it
    /// lands in the local-failure taxonomy instead of being dressed as a provider outcome.
    ///
    /// `stored_scopes` is the stored grant's scope set, the reference RFC 6749 §6/§5.1 make the
    /// authority comparison against. The wave reads it off the credential it just loaded under the
    /// lock, so a grant that changed on disk cannot be judged against a stale reference.
    fn exchange(
        &self,
        refresh_token: &str,
        now_unix: i64,
        stored_scopes: &BTreeSet<String>,
    ) -> Result<RefreshOutcome, RefreshLocalError>;
    /// Persist a renewed credential atomically (`token_refresh::persist_credential`). Success
    /// returns the generation of the written bytes, computed from the bytes in hand rather than a
    /// post-persist disk read, so the publisher always stamps a known generation.
    ///
    /// The `grant` is written back unchanged: a renewal produces a new access token, never a new
    /// authority.
    fn persist(
        &self,
        access: &str,
        survivor: &str,
        expires_at: i64,
        grant: &GrantProvenance,
    ) -> Result<FileGen, RefreshLocalError>;
    /// Rebuild the provider arm from a credential (`build_gmail_arm`).
    ///
    /// `held` is the caller's proof that the cross-process credential lock is held. Rebuilding
    /// admits the grant against the ratchet and may latch it, and every ratchet write in this
    /// product happens under that one lock. Both call sites already hold it for their whole
    /// critical section, so the parameter costs nothing and makes the obligation type-enforced.
    fn rebuild(
        &self,
        credential: &GmailCredential,
        held: &CredentialLock,
    ) -> Result<Provider, RefreshLocalError>;
    /// Acquire the cross-process writer lock, bounded (token_refresh::CredentialLock).
    fn lock(&self, path: &Path, deadline: Duration) -> Result<CredentialLock, RefreshLocalError>;
    /// The wall clock, sampled at use time. The caller's clocks are captured at the async
    /// boundary and age across lock waits, config loads and the HTTP round trip, so a comparison
    /// made after blocking work samples through this instead. Production reads the system clock;
    /// tests script it.
    fn now_unix(&self) -> i64;
}

/// One in-flight wave: joiners wait on it and receive the same result (the `singleflight` shape,
/// one key).
struct Wave {
    done: Mutex<Option<WaveResult>>,
    cv: Condvar,
}

#[derive(Clone)]
enum WaveResult {
    /// The cell was published with a live provider, and this is the arm the wave produced. Every
    /// caller of one wave, owner and joiners alike, receives this exact `Arc`, never a re-read of
    /// the mutable cell after the lock released (an interleaved external mint and reconcile could
    /// otherwise hand joiners of one wave different generations, or a refusal).
    Live(Arc<GmailProvider>),
    /// The wave finished without a live credential; the cell's `last_result` carries the lossless
    /// outcome and this is its cure and reason for the joiners.
    Refused { expires_at: i64, cure: Cure, reason: String },
}

/// The coordinator: the cell, the single in-flight wave, and the addresses the protocol needs.
pub(crate) struct CredentialCoordinator {
    cell: RwLock<CredentialCell>,
    wave: Mutex<Option<Arc<Wave>>>,
    secrets_dir: PathBuf,
}

impl CredentialCoordinator {
    pub(crate) fn new(initial: CredentialCell, secrets_dir: PathBuf) -> Self {
        Self {
            cell: RwLock::new(initial),
            wave: Mutex::new(None),
            secrets_dir,
        }
    }

    /// A snapshot of the published cell, which `session_status` renders from (status and
    /// admission read the same cell).
    pub(crate) fn snapshot(&self) -> CredentialCell {
        self.cell.read().map(|c| c.clone()).unwrap_or_else(|p| p.into_inner().clone())
    }

    /// [`CredentialCell::status_cure`] over one fresh snapshot, as a test convenience; the status
    /// view calls the cell method on its already-captured snapshot.
    #[cfg(test)]
    pub(crate) fn status_cure(&self, now_unix: i64) -> Option<Cure> {
        // The coordinator-level test shim takes no disk observation (`None`, so no suppression);
        // the suppression is tested at the cell level and wired in the status view.
        self.snapshot().status_cure(now_unix, None)
    }

    /// Admit a provider-reading command: reconcile first, then branch. Returns the live provider
    /// handle, or the typed refusal carrying the cell's cure. Runs the whole protocol on the
    /// caller's (blocking-pool) thread.
    ///
    /// Where a retired generation refuses: at credential load / arm construction
    /// (`build_gmail_arm`, then `token_refresh::admit_grant_generation`), at token refresh
    /// (`run_wave_inner`'s pre-exchange `grant_still_admitted`) and at send admission. Not here: a
    /// live read arm built under a since-retired generation is re-validated at the next reconcile
    /// (any credential-file change) or at expiry (the wave consults the ratchet before spending
    /// anything). Reads under it until then are accepted, bounded by the access-token lifetime,
    /// and no write can ride them (the mutation fence today, send admission after it).
    ///
    /// The widest case is not only a restore of previously published bytes. A mint raises the
    /// ratchet to N+1 before it writes the credential carrying N+1, and a mint that dies in that
    /// gap leaves the ratchet moved and the credential file's digest unchanged. Then
    /// `file_changed_since_publish` is false, there is no reconcile, and the live read arm under
    /// the now-retired generation N serves reads until its access token expires into the wave,
    /// which refuses the retired grant before spending anything. That window is accepted: it is
    /// our own automation, reads only, and bounded by the access-token lifetime.
    ///
    /// There is deliberately no admission-exit ratchet gate. One was tried (per-arm on the live
    /// branch, and `retire_check` over every `Ok(arm)`) and reverted: `Arc<GmailProvider>` carries
    /// no generation and reaches the wire strictly later than any check the coordinator can make,
    /// so an exit check would be observe-at-T / use-at-T' over a handle with no identity.
    pub(crate) fn admit(
        &self,
        now_unix: i64,
        now: Instant,
        io: &dyn AdmitIo,
    ) -> Result<Arc<GmailProvider>, SurfaceError> {
        // Admission is linearized: the whole pre-wave decision (slot check, file pre-check,
        // reconcile, live/latch/floor branch, wave install) runs under one acquisition of the slot
        // guard. A separate join-check would leave an unowned interval (slot says `None`, then
        // blocking precheck and reconcile, then decision) in which a concurrent wave could
        // install, complete, and have its fresh stamp erased by our reconcile. Joiners arriving
        // during a decision serialize briefly behind this guard, then join the installed wave. The
        // decision's reconcile may wait on the writer lock (at most 5 s), which is bounded and
        // POST-free. Every decision input is read under this guard.
        let mut slot = self.wave.lock().map_err(poisoned)?;
        if let Some(wave) = slot.clone() {
            drop(slot);
            return self.join(wave);
        }

        // Reconcile first, between waves (the guard is held). A changed file (an external
        // re-mint, a mint that raced, a persist whose rebuild failed) is adopted before any
        // live/expired/latch/pacing decision, inside the writer critical section, publishing only
        // the locked observation. An unreadable digest is neither "changed" nor "unchanged": a live
        // cell rides through it (nothing about the published arm is in doubt, and an
        // expiry-shaped refusal with a future expiry would be false), while an expired cell
        // refuses typed. The ride-through concerns the digest only. The arm it returns is a live
        // read arm with no ratchet consult of its own, re-validated at the next reconcile or at
        // expiry.
        let changed = match self.file_changed_since_publish(io) {
            Ok(c) => c,
            Err(e) => {
                let cell = self.snapshot();
                if credential_expired_at(cell.expires_at, io.now_unix()).is_none() {
                    drop(slot);
                    return gmail_arm(&cell.provider);
                }
                // Refuse without stamping: a stamp would overwrite `last_result`, and with it a
                // standing terminal latch, a release that is forbidden. The command surface
                // carries the refusal, and the cell is left untouched so the next admission
                // re-reads from unchanged ground truth.
                let expires_at = cell.expires_at.unwrap_or(0);
                return Err(SurfaceError::CredentialExpired {
                    expires_at,
                    cure: RememberedOutcome::Local(e.clone()).cure(),
                    reason: e.reason_sentence(),
                });
            }
        };
        if changed {
            if let Err(e) = self.reconcile_locked(io) {
                // The disk holds a different credential generation and adopting it failed.
                // Silently admitting the previously published arm would ride a superseded
                // (possibly revoked) grant with nothing surfaced. Refuse explicitly; the next
                // admission reconciles again (self-healing), and the stamp carries the same fact.
                // The command is the surface; there is no new wire field.
                let cure = RememberedOutcome::Local(e.clone()).cure();
                let expires_at = self.snapshot().expires_at.unwrap_or(0);
                return Err(SurfaceError::CredentialExpired {
                    expires_at,
                    cure,
                    // A retired grant propagates its own sentence unwrapped. The wrapper is true
                    // for every other adoption failure (transient, and the next command really
                    // does retry them) and false for this one: the file on disk is the older
                    // credential, not a "newer" one, and retrying cannot un-supersede a consent.
                    // The wrapper beside the `re_mint` cure would put two contradictory
                    // instructions on one surface.
                    reason: match &e {
                        RefreshLocalError::GrantRetired { .. } => e.reason_sentence(),
                        _ => format!(
                            "a newer credential is on disk but could not be adopted ({}); \
                             nothing was replaced, and Photon refused rather than serve the \
                             superseded credential",
                            e.reason_sentence()
                        ),
                    },
                });
            }
        }

        // The live check samples the use-time clock. The snapshot is taken under the decision
        // guard, after any reconcile, so it cannot be staler than a wave that completed before we
        // acquired.
        let cell = self.snapshot();
        if credential_expired_at(cell.expires_at, io.now_unix()).is_none() {
            // No ratchet consult here (an exit gate was tried and reverted). The only change
            // detector above this line is the credential file's digest, so a restore of the exact
            // published bytes after a re-consent leaves it equal, and this live read arm keeps
            // serving until the next credential-file change reconciles it or it expires into the
            // wave, which refuses a retired grant before spending anything. That is an accepted
            // residual, not defended by an exit check.
            drop(slot);
            return gmail_arm(&cell.provider);
        }

        // Expired, no wave in flight: the latch and the floor decide, still under the guard, so
        // the decision and the install are one step.
        if let Some(stamp) = &cell.last_result {
            if stamp.outcome.is_terminal_latch() && stamp.file_gen == cell.file_gen {
                return Err(refusal(cell.expires_at, &stamp.outcome));
            }
            // The floor paces token-endpoint traffic: exactly the stamps whose wave dialled
            // (`spent_post`, recorded at the source). A pre-wire local failure carries `false` and
            // retries immediately, so the operator's fix is never delayed.
            if !stamp.outcome.is_terminal_latch()
                && stamp.spent_post
                && now.duration_since(stamp.completed_at) < REFRESH_ATTEMPT_FLOOR
            {
                // The aggregate is not silent: at three failures and beyond the paced sentence
                // names the streak, so retrying is not presented as the cure of a state that has
                // stopped being transient. The wording is stage-neutral: the suffix never names a
                // provider response (after network failures none exists), and the per-attempt
                // reason in the same sentence carries the specifics.
                let streak = if stamp.failures_in_a_row >= 3 {
                    format!(
                        "; this is {} paced attempts in a row without a usable renewal — if \
                         it persists, retrying alone is unlikely to fix it (see the reason \
                         above)",
                        stamp.failures_in_a_row
                    )
                } else {
                    String::new()
                };
                return Err(SurfaceError::CredentialExpired {
                    expires_at: cell.expires_at.unwrap_or(0),
                    // The paced refusal carries the stamped cure. Pacing is the timing, not the
                    // medium; a hardcoded `RetryLater` told a `ClientConfig` operator to wait for
                    // a fix that waiting cannot deliver.
                    cure: stamp.outcome.cure(),
                    reason: format!(
                        "renewal is paced — the previous attempt finished {}s ago ({}); no \
                         renewal was attempted and nothing was written{streak}",
                        now.duration_since(stamp.completed_at).as_secs(),
                        stamp.outcome.reason_sentence()
                    ),
                });
            }
        }

        let wave = Arc::new(Wave {
            done: Mutex::new(None),
            cv: Condvar::new(),
        });
        *slot = Some(Arc::clone(&wave));
        drop(slot);

        self.run_wave(wave, now_unix, io)
    }

    /// Is a loaded credential's grant still at or above the ratchet?
    fn grant_still_admitted(&self, grant: &GrantProvenance) -> Result<(), RefreshLocalError> {
        self.generation_still_admitted(grant.grant_generation)
    }

    /// The shared comparison behind the admission checks. It can refuse but never raises the
    /// ratchet.
    ///
    /// Read-only and lock-free by contract: `token_refresh::read_grant_high_water` writes
    /// nothing. An absent ratchet is `Ok` (nothing retired yet); an unusable one refuses, as
    /// `admit_grant_generation` does, because reading it as absent would re-admit every retired
    /// generation.
    fn generation_still_admitted(&self, generation: u64) -> Result<(), RefreshLocalError> {
        let path = crate::token_refresh::grant_high_water_path(&self.secrets_dir);
        let recorded = crate::token_refresh::read_grant_high_water(&path).map_err(|shape| {
            RefreshLocalError::GrantHighWaterUnusable {
                path: path.clone(),
                shape,
            }
        })?;
        match recorded {
            Some(high_water) if generation < high_water => Err(RefreshLocalError::GrantRetired {
                path,
                credential_generation: generation,
                high_water,
            }),
            _ => Ok(()),
        }
    }

    /// Is a plan's grant identity still the one this cell answers for? It applies the same
    /// [`Self::generation_still_admitted`] comparison as the grant-provenance checks (refuse,
    /// never raise; an unusable ratchet refuses rather than reading as absent), then checks
    /// principal equality against the published cell ([`CredentialCell::published_grant`]). Its
    /// one caller is `ShellGrantRatchet`, which the bus consults through `aruna::GrantRatchet`
    /// once per plan child's send authorization.
    pub(crate) fn admits_plan_grant(
        &self,
        generation: u64,
        principal: &str,
    ) -> Result<(), aruna::GrantRefusal> {
        self.generation_still_admitted(generation)
            .map_err(|e| match e {
                RefreshLocalError::GrantRetired {
                    credential_generation,
                    high_water,
                    ..
                } => aruna::GrantRefusal::Retired {
                    generation: credential_generation,
                    high_water,
                },
                other => aruna::GrantRefusal::Unavailable(other.reason_sentence()),
            })?;
        match self.snapshot().published_grant() {
            Some((_, current)) if current == principal => Ok(()),
            Some((_, current)) => Err(aruna::GrantRefusal::PrincipalMismatch {
                plan: principal.to_string(),
                current,
            }),
            None => Err(aruna::GrantRefusal::Unavailable(
                "no grant is published on the credential cell (no Gmail arm is built)".to_string(),
            )),
        }
    }

    fn file_changed_since_publish(&self, io: &dyn AdmitIo) -> Result<bool, RefreshLocalError> {
        let published = self.snapshot().file_gen;
        Ok(Some(io.file_gen()?) != published)
    }

    /// The stamp a reconcile keeps when it adopts `observed`. Both publishers in this function
    /// (including the fresh-install path above the lock) apply it, so the rule lives here once.
    ///
    /// A stamp recorded against the same generation being adopted keeps its meaning when either
    /// (a) it is a provider verdict (`Failed` or `Renewed`: the endpoint's answer about these
    /// bytes has not changed) or (b) its wave spent a POST (`spent_post`). The floor paces
    /// endpoint traffic, and erasing a spent stamp un-paces it; a two-POST bypass, a
    /// grace-short-renewal erase and a post-persist rebuild-tail erase were all this one rule
    /// leaking. The only stamps that clear on same-generation adoption are pre-wire locals: the
    /// successful adoption is the very local step they assert failed, and they dialled nothing, so
    /// no pacing is lost. A stamp for a different generation clears as always (the re-mint
    /// release).
    fn preserved_stamp(&self, observed: &Option<FileGen>) -> Option<RefreshStamp> {
        self.snapshot().last_result.filter(|s| {
            &s.file_gen == observed
                && (s.spent_post
                    || matches!(
                        s.outcome,
                        RememberedOutcome::Failed(_) | RememberedOutcome::Renewed
                    ))
        })
    }

    /// Adopt a changed on-disk credential under the writer lock: re-read after locking and publish
    /// only that observation, so a wave that published between our pre-check and our lock can
    /// never be overwritten by a stale read.
    ///
    /// `Err` means a different generation is on disk and could not be adopted (lock, rebuild); the
    /// caller must not silently proceed on the superseded cell. A load failure is `Ok`: it
    /// publishes `Unconfigured`, which the caller's own paths surface.
    fn reconcile_locked(&self, io: &dyn AdmitIo) -> Result<(), RefreshLocalError> {
        // The fresh install comes first here too, by the same rule and function as boot: no
        // credential file means the loader's own refusal and no lock. An unarmed cell carries no
        // digest, so the comparison always differs and it reconciles on every admission; locking
        // first would, on a fresh profile whose secrets directory does not exist, try to create
        // `credential.lock` inside a nonexistent parent and report the never-minted state as
        // `credential_expired` / `retry_later`. Lock-first still applies once there is a writer to
        // serialize against: the locked re-read below is the only observation this cell is
        // published from.
        //
        // An unreadable digest is not an absence: it falls through to the lock, where the locked
        // read refuses it typed.
        if let Ok(observed) = io.file_gen() {
            if let Some(refusal) = crate::credential_absent_diagnosis(&observed, || io.load()) {
                let preserved = self.preserved_stamp(&Some(observed));
                self.publish(|c| {
                    c.set_unconfigured(refusal.reason.clone(), Some(refusal.cure()));
                    c.last_result = preserved.clone();
                });
                return Ok(());
            }
        }
        // Named, not `_lock`: the guard is also the proof handed to `rebuild`.
        let lock = match io.lock(&credential_lock_path(&self.secrets_dir), CREDENTIAL_LOCK_DEADLINE) {
            Ok(l) => l,
            // A held lock means a writer is mid-commit: the stamp remembers, the caller refuses
            // explicitly, and the next admission reconciles.
            Err(e) => {
                self.publish_local_failure(e.clone(), io, false);
                return Err(e);
            }
        };
        // The locked digest read. An unreadable digest refuses typed here too: the stamp remembers,
        // the caller refuses, and the next admission retries the read.
        let observed = match io.file_gen() {
            Ok(g) => Some(g),
            Err(e) => {
                self.publish_local_failure(e.clone(), io, false);
                return Err(e);
            }
        };
        if observed == self.snapshot().file_gen {
            return Ok(());
        }
        // Stamp preservation: the rule is documented on `preserved_stamp`.
        let preserved = self.preserved_stamp(&observed);
        match io.load() {
            Ok(cred) => match io.rebuild(&cred, &lock) {
                Ok(provider) => {
                    let published_generation = Some(cred.grant.grant_generation);
                    self.publish(|c| {
                        c.provider = provider;
                        c.expires_at = cred.expires_at;
                        c.file_gen = observed;
                        c.grant_generation = published_generation;
                        c.last_result = preserved.clone();
                    });
                    Ok(())
                }
                Err(e) => {
                    self.publish_local_failure(e.clone(), io, false);
                    Err(e)
                }
            },
            Err(refusal) => {
                // Published as `Unconfigured`; the caller's own fast path surfaces it as a
                // `SessionUnconfigured` refusal, so no `Err` is needed here. The cure is the
                // refusal's own: an unreadable credential file publishes a read-failure cure, not a
                // re-consent demand.
                let cure = refusal.cure();
                let reason = refusal.reason;
                // No arm, so no generation, digest or expiry: all three leave through the one
                // constructor, so this publisher cannot keep any of them. The stamp is the
                // publisher's own and survives (`preserved`).
                self.publish(|c| {
                    c.set_unconfigured(reason, Some(cure));
                    c.last_result = preserved.clone();
                });
                Ok(())
            }
        }
    }

    fn join(&self, wave: Arc<Wave>) -> Result<Arc<GmailProvider>, SurfaceError> {
        let mut done = wave.done.lock().map_err(poisoned)?;
        while done.is_none() {
            done = wave.cv.wait(done).map_err(poisoned)?;
        }
        match done.clone().expect("loop exits only on Some") {
            // The wave's own arm, never a post-lock re-read of the mutable cell.
            WaveResult::Live(arm) => Ok(arm),
            WaveResult::Refused {
                expires_at,
                cure,
                reason,
            } => Err(SurfaceError::CredentialExpired {
                expires_at,
                cure,
                reason,
            }),
        }
    }

    /// The wave's critical section, the commit protocol: lock, re-read, exchange, persist,
    /// rebuild, publish, unlock. One POST per wave, success or failure; joiners get this exact
    /// result. `wave` is the one `admit` installed in the slot under its guard; this function owns
    /// its completion and clears the slot only if it still holds this wave.
    fn run_wave(
        &self,
        wave: Arc<Wave>,
        now_unix: i64,
        io: &dyn AdmitIo,
    ) -> Result<Arc<GmailProvider>, SurfaceError> {
        let result = self.run_wave_inner(now_unix, io);

        // Settle before release: the result is stored and joiners notified before the slot is
        // cleared, so a successor admission can never observe "no wave" while joiners still wait
        // unsettled (as in Go's singleflight). Otherwise a descheduled owner in that window would
        // let a new admission start a second wave, or hand a paced wrapper instead of this wave's
        // exact result. A joiner that grabs the still-slotted, already-settled wave returns
        // immediately.
        *wave.done.lock().map_err(poisoned)? = Some(result.clone());
        wave.cv.notify_all();
        {
            let mut slot = self.wave.lock().map_err(poisoned)?;
            if slot.as_ref().is_some_and(|w| Arc::ptr_eq(w, &wave)) {
                *slot = None;
            }
        }

        match result {
            // The wave's own arm: the owner answers from the same payload the joiners get, never a
            // post-lock re-read of the mutable cell.
            WaveResult::Live(arm) => Ok(arm),
            WaveResult::Refused {
                expires_at,
                cure,
                reason,
            } => Err(SurfaceError::CredentialExpired {
                expires_at,
                cure,
                reason,
            }),
        }
    }

    fn run_wave_inner(&self, now_unix: i64, io: &dyn AdmitIo) -> WaveResult {
        let expires_at = self.snapshot().expires_at.unwrap_or(0);
        // Named, not `_lock`: the wave's guard is also the proof handed to every `rebuild` below,
        // and the ratchet is only ever written while it is held.
        let lock = match io.lock(&credential_lock_path(&self.secrets_dir), CREDENTIAL_LOCK_DEADLINE) {
            Ok(l) => l,
            Err(e) => return self.finish_local(e, io, expires_at, false),
        };

        // The locked re-read is the wave's ground truth. A file that is already live (another
        // process refreshed, or an operator re-minted) is adopted without a POST. An unreadable
        // digest ends the wave pre-wire with a typed refusal: a wave cannot stamp or latch against
        // a generation it could not establish.
        let observed = match io.file_gen() {
            Ok(g) => Some(g),
            Err(e) => return self.finish_local(e, io, expires_at, false),
        };
        let cred = match io.load() {
            Ok(c) => c,
            Err(refusal) => {
                // One source for this cure: the published arm and the refusal this wave hands its
                // joiners both read the refusal's own variant.
                let cure = refusal.cure();
                let reason = refusal.reason;
                // No digest, expiry or generation: the constructor has nowhere to put them.
                // Stamping `observed` here would mean the next admission reconciles only when the
                // file's own bytes change, which is true of a repaired credential and false of
                // every other cure (a permission fix, a restored parent directory, a repaired
                // ratchet).
                self.publish(|c| {
                    c.set_unconfigured(reason.clone(), Some(cure));
                    c.last_result = None;
                });
                return WaveResult::Refused {
                    expires_at,
                    cure,
                    reason,
                };
            }
        };
        // From here on, refusal payloads carry the locked observation's stamp, not the pre-lock
        // snapshot's: the entry snapshot may describe a generation a concurrent reconcile already
        // replaced.
        let expires_at = cred.expires_at.unwrap_or(expires_at);
        // The ratchet, before anything is spent. If the wave only discovered a retired grant at
        // `rebuild`, it would be after the token-endpoint POST and after `persist` had written a
        // rotated credential over the restored file, possibly consuming a refresh-token rotation
        // on a superseded consent. The comparison costs one file read, under the lock the wave
        // already holds, before the live branch and before the exchange. It is read-only: raising
        // is `admit_grant_generation`'s job at `rebuild`; this only refuses.
        if let Err(e) = self.grant_still_admitted(&cred.grant) {
            return self.finish_local(e, io, expires_at, false);
        }
        // The live check inside the critical section samples the use-time clock: the caller's
        // clock is older than the lock wait that just ended.
        if credential_expired_at(cred.expires_at, io.now_unix()).is_none() {
            return match io.rebuild(&cred, &lock) {
                Ok(provider) => match gmail_arm(&provider) {
                    Ok(arm) => {
                        let published_generation = Some(cred.grant.grant_generation);
                        self.publish(|c| {
                            c.provider = provider;
                            c.expires_at = cred.expires_at;
                            c.file_gen = observed;
                            c.grant_generation = published_generation;
                            c.last_result = None;
                        });
                        WaveResult::Live(arm)
                    }
                    Err(_) => self.finish_local(
                        RefreshLocalError::RebuildFailed {
                            reason: "the rebuilt provider is not a Gmail arm".to_string(),
                        },
                        io,
                        expires_at,
                        false,
                    ),
                },
                Err(e) => self.finish_local(e, io, expires_at, false),
            };
        }

        let Some(refresh_token) = cred.refresh_token.as_deref().filter(|t| !t.trim().is_empty())
        else {
            // No refresh material: the cure is a re-mint, latched to this file.
            let outcome = RefreshOutcome::no_refresh_token();
            // Refused before the wire: no POST was spent (the latch, not the floor, governs it).
            self.remember(RememberedOutcome::Failed(outcome.clone()), observed, false);
            return WaveResult::Refused {
                expires_at,
                cure: outcome.cure(),
                reason: outcome.reason_sentence(),
            };
        };

        let outcome = match io.exchange(refresh_token, now_unix, &cred.grant.effective_scopes) {
            Ok(o) => o,
            // A local `Err` from the exchange seam is pre-wire by contract (client config, no HTTP
            // client); an actual dial answers `Ok(outcome)`, whatever the provider said.
            Err(e) => return self.finish_local(e, io, expires_at, false),
        };
        match &outcome {
            RefreshOutcome::Renewed {
                access_token,
                refresh_survivor,
                expires_at: new_expiry,
                ..
            } => {
                // A persist that fails leaves the cell unpublished: an unwritten renewal admits
                // nobody. The caller sees the refusal, and the still-expired cell puts the cure on
                // the status wire. The rare compound (provider rotation plus write failure, so
                // possibly a re-mint) is a known residual.
                let written_gen = match io.persist(
                    access_token.expose(),
                    refresh_survivor.expose(),
                    *new_expiry,
                    // The grant passes through the rotation unchanged.
                    &cred.grant,
                ) {
                    Ok(g) => g,
                    // POST spent: the exchange dialled and renewed before the write failed. The
                    // floor paces the retry so a broken disk cannot storm the endpoint and worsen
                    // rotation loss.
                    Err(e) => return self.finish_local(e, io, expires_at, true),
                };
                let renewed = GmailCredential {
                    access_token: access_token.expose().to_string(),
                    refresh_token: Some(refresh_survivor.expose().to_string()),
                    expires_at: Some(*new_expiry),
                    grant: cred.grant.clone(),
                };
                match io.rebuild(&renewed, &lock) {
                    Ok(provider) => self.publish_renewed(
                        provider,
                        *new_expiry,
                        written_gen,
                        renewed.grant.grant_generation,
                        io,
                    ),
                    // Disk is newer than the cell: the next admission's reconcile adopts it without
                    // a POST. The POST was spent, and the stamp says so.
                    Err(e) => self.finish_local(e, io, expires_at, true),
                }
            }
            failed => {
                self.remember(RememberedOutcome::Failed(failed.clone()), observed, true);
                WaveResult::Refused {
                    expires_at,
                    cure: failed.cure(),
                    reason: failed.reason_sentence(),
                }
            }
        }
    }

    /// Publish a renewed grant into the cell and answer for it. This is the one place a wave turns
    /// a successful exchange into an admission, so the grace recheck cannot diverge between the
    /// persisted and the unwritten-rotation arms.
    ///
    /// Grace recheck: a renewal whose grant already sits inside the safety margin must not answer
    /// `Live`, since `credential_expired_at` would refuse the same stamp on the very next call and
    /// admitting now hands the command a token that can die mid-flight (a raw provider 401). The
    /// renewal stays published and remembered; only the answer refuses.
    fn publish_renewed(
        &self,
        provider: Provider,
        new_expiry: i64,
        written_gen: FileGen,
        published_generation: u64,
        io: &dyn AdmitIo,
    ) -> WaveResult {
        let arm = match gmail_arm(&provider) {
            Ok(a) => a,
            Err(_) => {
                return self.finish_local(
                    RefreshLocalError::RebuildFailed {
                        reason: "the rebuilt provider is not a Gmail arm".to_string(),
                    },
                    io,
                    new_expiry,
                    true,
                )
            }
        };
        // The stamp's generation is the written one, computed from the committed bytes by
        // `persist` and never a post-persist disk read, so no renewal state with an unknown
        // generation can exist. The grace comparison samples the use-time clock once, and the same
        // sample decides both the answer and the streak.
        let answers_live = credential_expired_at(Some(new_expiry), io.now_unix()).is_none();
        // A grace-refused renewal is a spent admission failure: the streak must reach the
        // aggregate warning through a persist-refuse loop, and only a renewal that actually
        // answers live resets it.
        let failures_in_a_row = if answers_live {
            0
        } else {
            self.snapshot()
                .last_result
                .map_or(0, |s| s.failures_in_a_row)
                .saturating_add(1)
        };
        let file_gen = Some(written_gen);
        self.publish(|c| {
            c.provider = provider;
            c.expires_at = Some(new_expiry);
            c.file_gen = file_gen.clone();
            // A renewal is a new access token, never a new authority: the grant passed through
            // `persist` unchanged, so the published generation is the loaded one.
            c.grant_generation = Some(published_generation);
            c.last_result = Some(RefreshStamp {
                outcome: RememberedOutcome::Renewed,
                completed_at: Instant::now(),
                file_gen,
                spent_post: true,
                failures_in_a_row,
            });
        });
        if !answers_live {
            return WaveResult::Refused {
                expires_at: new_expiry,
                cure: Cure::RetryLater,
                reason: format!(
                    "the provider renewed the credential, but the new grant expires within \
                     Photon's {}s safety margin; the renewal was written and published, and \
                     Photon refused this admission rather than hand out a token that can die \
                     mid-flight",
                    crate::CREDENTIAL_EXPIRY_GRACE_SECS
                ),
            };
        }
        WaveResult::Live(arm)
    }

    /// `spent_post` is the wave's own answer to "did this attempt dial the token endpoint?",
    /// recorded on the stamp so the floor paces exactly the attempts that cost provider traffic.
    /// Pre-wire failures (lock, client config, adopt-path rebuilds) pass `false`; anything after
    /// a successful `io.exchange` passes `true`.
    fn finish_local(
        &self,
        e: RefreshLocalError,
        io: &dyn AdmitIo,
        expires_at: i64,
        spent_post: bool,
    ) -> WaveResult {
        let reason = e.reason_sentence();
        let cure = RememberedOutcome::Local(e.clone()).cure();
        self.publish_local_failure(e, io, spent_post);
        WaveResult::Refused {
            expires_at,
            cure,
            reason,
        }
    }

    fn publish_local_failure(&self, e: RefreshLocalError, io: &dyn AdmitIo, spent_post: bool) {
        // `.ok()` is deliberate for the stamp key only: local failures never latch, so an unknown
        // (`None`) key on the stamp decides nothing, and the typed failure itself is what the
        // caller surfaces.
        let file_gen = io.file_gen().ok();
        self.remember(RememberedOutcome::Local(e), file_gen, spent_post);
    }

    fn remember(&self, outcome: RememberedOutcome, file_gen: Option<FileGen>, spent_post: bool) {
        // `remember` records failures only (renewals stamp in `publish_renewed`). The streak counts
        // spent-POST attempts only: a pre-wire local failure neither counts (it never dialled, and
        // "N attempts" would inflate) nor resets (it proves nothing about the endpoint), so it
        // carries the standing count forward unchanged.
        let failures_in_a_row = self
            .snapshot()
            .last_result
            .map_or(0, |s| s.failures_in_a_row)
            .saturating_add(u32::from(spent_post));
        self.publish(|c| {
            c.last_result = Some(RefreshStamp {
                outcome,
                completed_at: Instant::now(),
                file_gen,
                spent_post,
                failures_in_a_row,
            });
        });
    }

    /// The one cell write. Every field change goes through here so `generation` advances with the
    /// publication and no reader can observe a half-written cell.
    fn publish(&self, f: impl FnOnce(&mut CredentialCell)) -> u64 {
        let mut cell = self.cell.write().unwrap_or_else(|p| p.into_inner());
        f(&mut cell);
        cell.generation += 1;
        cell.generation
    }
}

fn gmail_arm(provider: &Provider) -> Result<Arc<GmailProvider>, SurfaceError> {
    match provider {
        Provider::Gmail(p) => Ok(Arc::clone(p)),
        Provider::Unconfigured { reason, cure } => Err(SurfaceError::SessionUnconfigured {
            reason: reason.clone(),
            cure: *cure,
        }),
    }
}

fn refusal(expires_at: Option<i64>, outcome: &RememberedOutcome) -> SurfaceError {
    SurfaceError::CredentialExpired {
        expires_at: expires_at.unwrap_or(0),
        cure: outcome.cure(),
        reason: outcome.reason_sentence(),
    }
}

fn poisoned<T>(_: std::sync::PoisonError<T>) -> SurfaceError {
    SurfaceError::Internal {
        reason: "the credential coordinator's lock is poisoned — a previous refresh panicked"
            .to_string(),
    }
}

/// Test seam: a coordinator whose published cell carries a real Gmail arm, built through
/// `build_gmail_arm` from a credential of this grant generation and principal over a store in
/// `dir` (the arm's admission latches the ratchet in `dir` to at least `generation`, through
/// `token_refresh`'s own writer), constructed cyclically as `PhotonState::new_at` does so the
/// arm's bus ratchet points back at it.
#[cfg(test)]
pub(crate) fn test_coordinator_with_grant(
    dir: &Path,
    generation: u64,
    principal: &str,
) -> Arc<CredentialCoordinator> {
    let config = crate::SessionConfig {
        account: "acct".to_string(),
        store_path: dir.join("store.sqlite"),
        provider_kind: crate::ProviderKind::Gmail,
        gmail_secrets_dir: dir.to_path_buf(),
    };
    let credential = GmailCredential {
        access_token: "ya29.TEST-ACCESS".to_string(),
        refresh_token: Some("1//TEST-refresh-token".to_string()),
        expires_at: None,
        grant: GrantProvenance {
            grant_generation: generation,
            provider_principal: principal.to_string(),
            effective_scopes: ["https://www.googleapis.com/auth/gmail.modify".to_string()]
                .into_iter()
                .collect(),
        },
    };
    Arc::new_cyclic(|cell| {
        let held = CredentialLock::try_acquire(&credential_lock_path(dir), CREDENTIAL_LOCK_DEADLINE)
            .expect("the fixture holds the credential lock while it builds an arm");
        let provider = crate::build_gmail_arm(&config, &credential, &held, cell)
            .unwrap_or_else(|e| panic!("the fixture arm builds: {e:?}"));
        CredentialCoordinator::new(
            CredentialCell {
                provider,
                expires_at: None,
                generation: 0,
                file_gen: None,
                grant_generation: Some(generation),
                last_result: None,
            },
            dir.to_path_buf(),
        )
    })
}

// The I/O in the tests is [`MockIo`], not the disk: this module's contract is the wave protocol
// (who POSTs, who joins, what latches, what paces, what publishes), which is about ordering, not
// bytes. `token_refresh`'s own tests cover the bytes.
//
// The single-flight tests failed against the first cut of this module: `admit` read the wave
// slot and `run_wave` installed it under two separate acquisitions of `self.wave`, so concurrent
// callers released together all observed `None` and each started its own wave. Holding the slot
// guard from the read through the install (see `admit`) fixed it, and the two tests guard
// against its return.

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Barrier;

    use crate::token_refresh::{
        ClientConfigError, ClientConfigShape, LocalIoReason, Sanitized, ScopeConfirmation,
        SecretString, TransientKind, CREDENTIAL_LOCK_FILE_NAME, GRANT_HIGH_WATER_FILE_NAME,
    };
    use crate::{build_gmail_arm, ProviderKind, SessionConfig};

    /// A fixed wall clock. The cell's own pacing is measured in [`Instant`]s, which the tests pass
    /// explicitly, so nothing here ever sleeps to move time.
    const NOW: i64 = 1_700_000_000;
    /// Comfortably outside [`crate::CREDENTIAL_EXPIRY_GRACE_SECS`] — a credential stamped here is
    /// LIVE at [`NOW`].
    const LIVE_UNTIL: i64 = NOW + 3_600;
    /// What the token endpoint hands back as the surviving refresh token (RFC 6749 §6 rotation).
    /// A test asserts THIS is what reaches `persist`, never the original.
    const SURVIVOR: &str = "1//SURVIVING-refresh-token";
    const ORIGINAL: &str = "1//ORIGINAL-refresh-token";

    /// A stand-in file generation. The digest's VALUE is `token_refresh`'s business; all the
    /// cell needs is that two generations compare unequal.
    fn file_generation(tag: &str) -> Option<FileGen> {
        Some(FileGen::Sha384(format!("{tag:0>96}")))
    }

    /// The one scope the product's exact set holds.
    const MODIFY: &str = "https://www.googleapis.com/auth/gmail.modify";
    /// The mailbox the fixture credential was minted for.
    const PRINCIPAL: &str = "owner@example.com";

    /// A CONFORMANT grant record — what every fixture credential carries, because a credential
    /// without one no longer exists as far as the loader is concerned.
    fn fixture_grant() -> GrantProvenance {
        GrantProvenance {
            grant_generation: 1,
            provider_principal: PRINCIPAL.to_string(),
            effective_scopes: [MODIFY.to_string()].into_iter().collect(),
        }
    }

    fn expired_credential() -> GmailCredential {
        GmailCredential {
            access_token: "ya29.OLD-ACCESS".to_string(),
            refresh_token: Some(ORIGINAL.to_string()),
            expires_at: Some(NOW - 10),
            grant: fixture_grant(),
        }
    }

    fn live_credential(expires_at: i64) -> GmailCredential {
        GmailCredential {
            access_token: "ya29.LIVE-ACCESS".to_string(),
            refresh_token: Some(ORIGINAL.to_string()),
            expires_at: Some(expires_at),
            grant: fixture_grant(),
        }
    }

    fn renewed(expires_at: i64) -> RefreshOutcome {
        RefreshOutcome::Renewed {
            access_token: SecretString::new("ya29.NEW-ACCESS"),
            refresh_survivor: SecretString::new(SURVIVOR),
            expires_at,
            scope_confirmed: ScopeConfirmation::AbsentIdenticalGrant,
        }
    }

    fn transient() -> RefreshOutcome {
        RefreshOutcome::Transient {
            kind: TransientKind::Network,
        }
    }

    /// The fixture directory, minted by the engine's ONE guard (`aruna::test_temp`):
    /// `photon-cell-{tag}-{pid}-{nanos}-{seq}`, created empty, the whole tree removed on
    /// `Drop` without following a link — and a removal that still fails after the guard's
    /// deadline is a loud test failure, where this helper's own guard (previously
    /// 8,208 leaked dirs before it) swallowed it with `let _ =`. Bind it BEFORE any state that
    /// opens a file inside it: locals drop in reverse order of declaration.
    type FixtureDirGuard = aruna::test_temp::TempDir;

    fn fixture_dir(tag: &str) -> FixtureDirGuard {
        aruna::test_temp::TempDir::new(&format!("photon-cell-{tag}"))
    }

    // Written and run against the earlier helper above,
    // which return a bare PathBuf with no Drop side effect, so it FAILED at runtime:
    // `the fixture dir must be gone once the guard drops`.
    #[test]
    fn fixture_dir_deletes_the_whole_directory_on_drop() {
        let dir;
        {
            let guard = fixture_dir("drop-guard-fixture");
            dir = guard.to_path_buf();
            std::fs::write(dir.join("inside.txt"), b"x").unwrap();
            assert!(dir.exists(), "precondition: the fixture dir exists before the guard drops");
        }
        assert!(!dir.exists(), "the fixture dir must be gone once the guard drops");
    }

    // RED companion: two calls in the same process (same pid) must never mint the same dir —
    // a reused pid must not let a later call open a leftover run's store (the intermittent
    // `RegisteredButAbsent` failures seen during mutant runs).
    #[test]
    fn fixture_dir_never_shares_a_dir_across_two_calls_in_one_process() {
        let a = fixture_dir("same-tag");
        let b = fixture_dir("same-tag");
        let a_owned: PathBuf = a.to_path_buf();
        let b_owned: PathBuf = b.to_path_buf();
        assert_ne!(a_owned, b_owned, "two calls in the same process must never mint the same dir");
    }

    fn config_for(dir: &Path) -> SessionConfig {
        SessionConfig {
            account: "acct".to_string(),
            store_path: dir.join("store.sqlite"),
            provider_kind: ProviderKind::Gmail,
            gmail_secrets_dir: dir.to_path_buf(),
        }
    }

    /// A REAL `Provider::Gmail`, built through the production path — `HttpGmailTransport::connect`
    /// takes no base URL and touches no network, so this is hermetic (the same reasoning
    /// `lib.rs`'s `gmail_arm_state` fixture states).
    fn arm(dir: &Path) -> Provider {
        // The lock is the RATCHET's linearization and `build_gmail_arm` requires
        // the proof; the fixture takes the real one on its own temp dir.
        let held = CredentialLock::try_acquire(&credential_lock_path(dir), CREDENTIAL_LOCK_DEADLINE)
            .expect("the fixture holds the credential lock while it builds an arm");
        build_gmail_arm(&config_for(dir), &live_credential(LIVE_UNTIL), &held, &std::sync::Weak::new())
            .expect("the Gmail arm builds from a temp store and a parked credential")
    }

    /// Provider IDENTITY, so "the cell kept the OLD arm" and "the cell published the REBUILT arm"
    /// are distinguishable facts rather than two indistinguishable `Provider::Gmail`s.
    fn arm_ptr(provider: &Provider) -> usize {
        match provider {
            Provider::Gmail(p) => Arc::as_ptr(p) as usize,
            Provider::Unconfigured { .. } => 0,
        }
    }

    fn cell(provider: Provider, expires_at: Option<i64>, file_gen: Option<FileGen>) -> CredentialCell {
        CredentialCell {
            provider,
            expires_at,
            generation: 0,
            file_gen,
            // Every fixture credential carries `fixture_grant()` — generation 1.
            grant_generation: Some(fixture_grant().grant_generation),
            last_result: None,
        }
    }

    /// The typed refusal an admission produced, or a panic carrying the witness's own sentence.
    ///
    /// `Result::expect_err` is unavailable on an admission: it needs `T: Debug`, and
    /// `GmailProvider` deliberately has no `Debug` (it holds the bus and the bearer material) — so
    /// the Ok arm is spelled out here rather than the provider growing a derive for a test.
    fn refusal_of(
        result: Result<Arc<GmailProvider>, SurfaceError>,
        expected: &str,
    ) -> (Cure, String) {
        match result {
            Ok(_) => panic!("{expected}"),
            Err(SurfaceError::CredentialExpired { cure, reason, .. }) => (cure, reason),
            Err(other) => {
                panic!("an expired cell must refuse with a typed CredentialExpired: {other:?}")
            }
        }
    }

    // -------------------------------------------------------------------------------------------
    // Cure clause: a RETIRED grant's cure is a RE-MINT, not a wait.
    //
    // Pacing is the TIMING; the cure is the MEDIUM (the ruling that put the STAMPED cure
    // on the paced refusal). A later consent superseded this credential, and no amount of
    // retrying un-supersedes it — telling the operator "Photon will retry on your next command"
    // would be a cure that can never come true.
    //
    // Before the fix: the variant did not exist, and the `Local(_)` arm answered `RetryLater` for
    // everything except `ClientConfig`.
    // -------------------------------------------------------------------------------------------
    #[test]
    fn a_retired_grant_carries_the_re_mint_cure_onto_the_wire() {
        let retired = RememberedOutcome::Local(RefreshLocalError::GrantRetired {
            path: PathBuf::from("grant_high_water.json"),
            credential_generation: 4,
            high_water: 5,
        });
        assert_eq!(retired.cure(), Cure::ReMint);
        assert_eq!(
            serde_json::to_value(retired.cure()).expect("a cure serializes"),
            serde_json::json!("re_mint"),
            "the WIRE spelling the frontend's CURE_COPY map keys on (src/state.ts)"
        );
        assert!(
            retired.reason_sentence().contains("gmail_drill_mint.py"),
            "and the sentence beside it names the same act: {}",
            retired.reason_sentence()
        );

        // The carve-out is exactly ONE variant wide: every other local failure still paces, and
        // the two ratchet-I/O failures are genuinely retryable (a full disk, a read-only dir).
        for still_paced in [
            RefreshLocalError::ClientBuild,
            RefreshLocalError::GrantHighWaterWriteFailed {
                path: PathBuf::from("grant_high_water.json"),
                reason: LocalIoReason(std::io::ErrorKind::PermissionDenied),
            },
        ] {
            assert_eq!(
                RememberedOutcome::Local(still_paced.clone()).cure(),
                Cure::RetryLater,
                "only the RETIRED grant leaves the retry family: {still_paced:?}"
            );
        }
    }


    // ===========================================================================================
    // THE RATCHET REACHES THE REFRESH PATH, WHICH SKIPS `build_gmail_arm`.
    //
    // An earlier per-arm re-check on the live fast path, and a later single exit gate,
    // were REVERTED and their witnesses deleted; what stands in their place is the design's
    // own doors, witnessed by the load and construction witnesses, the refresh witness below,
    // and the re-validation witness (at the
    // next reconcile).
    // ===========================================================================================

    // -------------------------------------------------------------------------------------------
    // THE EXPIRED PATH CHECKS THE RATCHET BEFORE IT SPENDS ANYTHING.
    //
    // An earlier assumption said a rollback discovered mid-wave "costs one
    // POST". Reading `run_wave_inner` it costs a POST *and a durable write* — `exchange` →
    // `persist` (a rotated credential written over the restored file, possibly consuming a
    // refresh-token rotation) → `rebuild` → and only THERE does the ratchet refuse.
    // moves the comparison to immediately after the locked `load`: a retired grant costs nothing.
    // This closes that gap instead of re-wording it.
    //
    // Before the fix: `posts() == 1` and `persists` held one entry — the wave dialled the token
    // endpoint and wrote a renewed credential for a grant a later consent had already retired.
    // -------------------------------------------------------------------------------------------
    #[test]
    fn an_expired_retired_grant_costs_no_post_and_no_durable_write() {
        let dir = fixture_dir("f1rk4");
        let io = mock(&dir);
        // The parked file is a RESTORED generation 4; the ratchet already stands at 5.
        let mut retired = expired_credential();
        retired.grant.grant_generation = 4;
        io.set_disk("retired", Ok(retired));
        // Published against the SAME generation, so nothing reconciles and the wave is the path.
        // The cell is built BEFORE the ratchet moves: the fixture arm goes through the real
        // `build_gmail_arm`, which is itself a ratchet door — and this test is precisely about the
        // steps that run BEFORE the wave ever reaches that door.
        let coord = CredentialCoordinator::new(
            cell(arm(&dir), Some(NOW - 10), file_generation("retired")),
            dir.to_path_buf(),
        );
        std::fs::write(
            dir.join(GRANT_HIGH_WATER_FILE_NAME),
            b"{\"grant_generation\":5}\n",
        )
        .expect("seed the ratchet at 5");

        let (cure, reason) = refusal_of(
            coord.admit(NOW, Instant::now(), io.as_ref()),
            "an expired credential whose grant the ratchet retired is not refreshable",
        );
        assert_eq!(cure, Cure::ReMint, "a superseded consent is not a wait");
        assert!(
            reason.contains("gmail_drill_mint.py"),
            "the refusal carries the re-mint cure: {reason}"
        );
        assert_eq!(io.posts(), 0, "NO POST is spent on a retired grant");
        assert!(
            io.persists.lock().unwrap().is_empty(),
            "and NO durable write lands on the restored file — no rotation is burned"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }


    // -------------------------------------------------------------------------------------------
    // A RETIRED GRANT KEEPS ITS OWN SENTENCE THROUGH THE RECONCILE WRAPPER.
    //
    // When a running process meets a restored pre-re-consent credential,
    // the typed `GrantRetired` went through `admit`'s generic rebuild-error wrapper, which calls
    // the OLDER file "a newer credential", appends "Photon will retry on your next command", and
    // ships that beside a `re_mint` cure — two contradictory instructions on one surface. The
    // wrapper is right for every other adoption failure (they DO heal by retrying) and wrong for
    // exactly this one, so the code special-cases exactly this one.
    //
    // Before the fix: the reason read "a newer credential is on disk but could not be adopted (...);
    // Photon will retry on your next command".
    // -------------------------------------------------------------------------------------------
    #[test]
    fn a_retired_grant_keeps_its_own_sentence_through_the_reconcile_wrapper() {
        let dir = fixture_dir("f1rk6");
        let io = mock(&dir);
        let coord = CredentialCoordinator::new(
            cell(arm(&dir), Some(NOW - 10), file_generation("a")),
            dir.to_path_buf(),
        );
        // A restore agent put a pre-re-consent file back: the digest MOVED, so the admission
        // reconciles — and adopting it refuses typed, with the ratchet's own verdict.
        io.set_disk("restored", Ok(expired_credential()));
        *io.rebuild_fail.lock().unwrap() = Some(RefreshLocalError::GrantRetired {
            path: dir.join(GRANT_HIGH_WATER_FILE_NAME),
            credential_generation: 1,
            high_water: 2,
        });

        let (cure, reason) = refusal_of(
            coord.admit(NOW, Instant::now(), io.as_ref()),
            "a credential the ratchet retired is not adoptable",
        );
        assert_eq!(cure, Cure::ReMint);
        assert!(
            !reason.to_lowercase().contains("retry"),
            "a superseded consent is not a wait — the sentence must not promise a retry: {reason}"
        );
        assert!(
            !reason.contains("newer credential is on disk"),
            "and it must not call the OLDER file the newer one: {reason}"
        );
        assert!(
            reason.contains("gmail_drill_mint.py") && reason.contains("re-mint"),
            "it names the one act that cures it: {reason}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The side effect [`MockIo::lock`] runs while the writer lock is held — the seam for the lock-wait test.
    type LockHook = Box<dyn Fn() + Send + Sync>;

    /// The scripted [`AdmitIo`]. Everything a wave touches is a field a test can move BETWEEN
    /// admissions, which is how "the operator re-minted" and "another writer got there first" are
    /// modelled without a second process.
    ///
    /// **`lock` succeeds without modelling EXCLUSION, deliberately.** The bounded lock is the
    /// CROSS-PROCESS control and `token_refresh` owns its witnesses; the single-flight
    /// property this module claims — "ONE wave at a time refreshes it" — is an IN-PROCESS property
    /// of the wave protocol, so a mock that silently serialized callers would be testing the
    /// kernel's lock instead of the code above it.
    struct MockIo {
        dir: PathBuf,
        /// What the locked re-read answers.
        load_result: Mutex<Result<GmailCredential, crate::CredentialLoadFailure>>,
        /// The generation the mock "disk" reports (`None` models an ABSENT file, answered as
        /// `FileGen::Absent` — absence is a generation, never an error).
        file_gen: Mutex<Option<FileGen>>,
        /// When set, every digest read fails with this typed error (the unreadable-digest
        /// scenario) until a test clears it.
        file_gen_fail: Mutex<Option<RefreshLocalError>>,
        /// The scripted exchange answer, returned for every POST until a test rescripts it.
        outcome: Mutex<Result<RefreshOutcome, RefreshLocalError>>,
        /// How long the exchange takes — the concurrent witnesses need the wave to still be in
        /// flight when the other seven callers arrive.
        exchange_delay: Mutex<Duration>,
        /// THE POST COUNTER. One increment per token-endpoint exchange entered.
        posts: AtomicUsize,
        persists: Mutex<Vec<(String, String, i64)>>,
        persist_result: Mutex<Result<(), RefreshLocalError>>,
        /// The generation a SUCCESSFUL persist publishes onto the mock disk — the real writer
        /// renames a new file into place, so `file_gen` and `load` both move with it.
        persist_gen: Mutex<Option<FileGen>>,
        rebuilds: AtomicUsize,
        /// A ONE-SHOT rebuild failure: taken on the next call, then healed.
        rebuild_fail: Mutex<Option<RefreshLocalError>>,
        rebuild_arm: Mutex<Provider>,
        lock_result: Mutex<Result<(), RefreshLocalError>>,
        lock_paths: Mutex<Vec<PathBuf>>,
        lock_seq: AtomicUsize,
        on_lock: Mutex<Option<LockHook>>,
        /// The USE-TIME clock [`AdmitIo::now_unix`] answers — scripted so a test can model the
        /// admission-to-use staleness (lock waits + HTTP) that this class is about.
        now_unix: Mutex<i64>,
    }

    fn mock(dir: &Path) -> Arc<MockIo> {
        Arc::new(MockIo {
            dir: dir.to_path_buf(),
            load_result: Mutex::new(Ok(expired_credential())),
            file_gen: Mutex::new(file_generation("a")),
            file_gen_fail: Mutex::new(None),
            outcome: Mutex::new(Ok(renewed(LIVE_UNTIL))),
            exchange_delay: Mutex::new(Duration::ZERO),
            posts: AtomicUsize::new(0),
            persists: Mutex::new(Vec::new()),
            persist_result: Mutex::new(Ok(())),
            persist_gen: Mutex::new(file_generation("renewed")),
            rebuilds: AtomicUsize::new(0),
            rebuild_fail: Mutex::new(None),
            rebuild_arm: Mutex::new(arm(dir)),
            lock_result: Mutex::new(Ok(())),
            lock_paths: Mutex::new(Vec::new()),
            lock_seq: AtomicUsize::new(0),
            on_lock: Mutex::new(None),
            now_unix: Mutex::new(NOW),
        })
    }

    impl MockIo {
        fn posts(&self) -> usize {
            self.posts.load(Ordering::SeqCst)
        }
        fn rebuilds(&self) -> usize {
            self.rebuilds.load(Ordering::SeqCst)
        }
        fn set_disk(
            &self,
            gen_tag: &str,
            credential: Result<GmailCredential, crate::CredentialLoadFailure>,
        ) {
            *self.file_gen.lock().unwrap() = file_generation(gen_tag);
            *self.load_result.lock().unwrap() = credential;
        }
    }

    impl AdmitIo for MockIo {
        fn load(&self) -> Result<GmailCredential, crate::CredentialLoadFailure> {
            self.load_result.lock().unwrap().clone()
        }

        fn file_gen(&self) -> Result<FileGen, RefreshLocalError> {
            if let Some(e) = self.file_gen_fail.lock().unwrap().clone() {
                return Err(e);
            }
            Ok(self
                .file_gen
                .lock()
                .unwrap()
                .clone()
                .unwrap_or(FileGen::Absent))
        }

        fn exchange(
            &self,
            refresh_token: &str,
            _now_unix: i64,
            stored_scopes: &BTreeSet<String>,
        ) -> Result<RefreshOutcome, RefreshLocalError> {
            assert_eq!(
                stored_scopes,
                &fixture_grant().effective_scopes,
                "the exchange is judged against the STORED grant (#75 S0 C3), which is the one \
                 the wave loaded under the lock — never a compiled constant"
            );
            assert!(
                !refresh_token.trim().is_empty(),
                "the wave must never spend a blank refresh token — that is the MissingRefreshToken \
                 arm, not an exchange"
            );
            self.posts.fetch_add(1, Ordering::SeqCst);
            let delay = *self.exchange_delay.lock().unwrap();
            if !delay.is_zero() {
                std::thread::sleep(delay);
            }
            self.outcome.lock().unwrap().clone()
        }

        fn persist(
            &self,
            access: &str,
            survivor: &str,
            expires_at: i64,
            grant: &GrantProvenance,
        ) -> Result<FileGen, RefreshLocalError> {
            assert_eq!(
                grant,
                &fixture_grant(),
                "rotation writes the STORED grant back unchanged (#75 S0 C3) — a renewal is a \
                 new access token, never a new authority"
            );
            self.persists
                .lock()
                .unwrap()
                .push((access.to_string(), survivor.to_string(), expires_at));
            self.persist_result.lock().unwrap().clone()?;
            // A committed write is VISIBLE: the disk's generation moves and the file now reads
            // back as the renewed credential, exactly as the atomic rename leaves it — and the
            // RETURNED generation is the written one, exactly as the real persist derives it
            // from the bytes in hand.
            let written = self
                .persist_gen
                .lock()
                .unwrap()
                .clone()
                .unwrap_or(FileGen::Absent);
            *self.file_gen.lock().unwrap() = Some(written.clone());
            *self.load_result.lock().unwrap() = Ok(GmailCredential {
                access_token: access.to_string(),
                refresh_token: Some(survivor.to_string()),
                expires_at: Some(expires_at),
                grant: grant.clone(),
            });
            Ok(written)
        }

        fn rebuild(
            &self,
            _credential: &GmailCredential,
            _held: &CredentialLock,
        ) -> Result<Provider, RefreshLocalError> {
            self.rebuilds.fetch_add(1, Ordering::SeqCst);
            if let Some(e) = self.rebuild_fail.lock().unwrap().take() {
                return Err(e);
            }
            Ok(self.rebuild_arm.lock().unwrap().clone())
        }

        fn lock(&self, path: &Path, deadline: Duration) -> Result<CredentialLock, RefreshLocalError> {
            self.lock_paths.lock().unwrap().push(path.to_path_buf());
            if let Some(hook) = self.on_lock.lock().unwrap().as_ref() {
                hook();
            }
            self.lock_result.lock().unwrap().clone()?;
            // A REAL `CredentialLock` (the type has no test constructor), taken on a per-call
            // address so acquisition succeeds without serializing the callers — see the type's
            // doc comment for why that is the honest model here.
            //
            // The per-call address is a SIBLING INSIDE `self.dir`, which is this
            // coordinator's `secrets_dir` — so the handle is a valid proof for the very
            // directory these waves admit against (`CredentialLock::guards`). Moving this
            // address out of `self.dir` would make every admission in this suite refuse, which
            // is the check working, not a fixture to loosen.
            let n = self.lock_seq.fetch_add(1, Ordering::SeqCst);
            CredentialLock::try_acquire(&self.dir.join(format!("mock-{n}.lock")), deadline)
        }

        fn now_unix(&self) -> i64 {
            *self.now_unix.lock().unwrap()
        }
    }

    // -------------------------------------------------------------------------------------------
    // THE GRACE RECHECK. A renewal whose grant already sits inside the
    // `CREDENTIAL_EXPIRY_GRACE_SECS` safety margin must not answer Live: `credential_expired_at`
    // would refuse this same stamp on the very next call, so admitting now hands the command a
    // token that can die mid-flight — a raw provider 401. The
    // renewal itself is REAL: it is persisted, published, and remembered (the floor paces the
    // next attempt); only the ANSWER is a refusal.
    //
    // Before the fix: `run_wave_inner` answered Live for ANY successful rebuild.
    // -------------------------------------------------------------------------------------------
    #[test]
    fn a_renewal_landing_inside_the_grace_margin_refuses_instead_of_admitting() {
        let dir = fixture_dir("grace-recheck");
        let old = arm(&dir);
        let io = mock(&dir);
        // The provider renews, but the grant dies halfway into the safety margin.
        let short = NOW + crate::CREDENTIAL_EXPIRY_GRACE_SECS / 2;
        *io.outcome.lock().unwrap() = Ok(renewed(short));
        *io.persist_gen.lock().unwrap() = file_generation("short");
        let coord =
            CredentialCoordinator::new(cell(old, Some(NOW - 10), file_generation("a")), dir.to_path_buf());

        let (cure, reason) = refusal_of(
            coord.admit(NOW, Instant::now(), &*io),
            "a renewal already inside the grace margin must refuse — the next call's own \
             predicate would reject this same stamp",
        );
        assert_eq!(io.posts(), 1, "the renewal was attempted exactly once");
        assert_eq!(cure, Cure::RetryLater, "{reason}");
        assert!(reason.contains("safety margin"), "{reason}");
        let snap = coord.snapshot();
        assert_eq!(
            snap.expires_at,
            Some(short),
            "the renewal is PUBLISHED truthfully — only the admission answer refuses"
        );
        assert!(
            matches!(
                snap.last_result.as_ref().map(|s| &s.outcome),
                Some(RememberedOutcome::Renewed)
            ),
            "the stamp remembers the renewal, so the floor paces the next attempt"
        );
    }

    // -------------------------------------------------------------------------------------------
    // An admission arriving while a
    // wave is IN FLIGHT joins the wave even when the on-disk file has changed. Reconciling
    // instead forks the single-flight result: the reconciler can adopt a newer file and answer
    // Live while the wave's owner and joiners receive its Refused — the "overlapping
    // callers share the exact result" broken. The wave's own publication (inside the writer
    // lock) IS that window's reconciliation; an external change is adopted at the NEXT
    // admission (reconcile-first stays the BETWEEN-waves rule — unchanged).
    //
    // Before the fix: the reconcile pre-check ran before the slot check — the second caller
    // adopted the external live file and answered Live while the wave refused transient.
    // -------------------------------------------------------------------------------------------
    #[test]
    fn an_admission_during_a_wave_joins_it_even_when_the_file_changed() {
        let dir = fixture_dir("join-before-reconcile");
        let old = arm(&dir);
        let io = mock(&dir);
        *io.outcome.lock().unwrap() = Ok(transient());
        *io.exchange_delay.lock().unwrap() = Duration::from_millis(400);
        let coord = Arc::new(CredentialCoordinator::new(
            cell(old, Some(NOW - 10), file_generation("a")),
            dir.to_path_buf(),
        ));

        let owner = {
            let coord = Arc::clone(&coord);
            let io = Arc::clone(&io);
            std::thread::spawn(move || {
                refusal_of(
                    coord.admit(NOW, Instant::now(), &*io),
                    "the wave's owner refuses transient",
                )
            })
        };
        // The wave is mid-exchange; an external writer lands a LIVE credential on disk.
        std::thread::sleep(Duration::from_millis(120));
        io.set_disk("external-live", Ok(live_credential(LIVE_UNTIL)));

        let (join_cure, join_reason) = refusal_of(
            coord.admit(NOW, Instant::now(), &*io),
            "an admission overlapping the wave must receive the wave's exact refusal, never a \
             reconciled Live of its own",
        );
        let (owner_cure, owner_reason) = owner.join().expect("owner thread");
        assert_eq!(join_cure, owner_cure);
        assert_eq!(
            join_reason, owner_reason,
            "one wave, one result, every overlapping caller"
        );
        assert_eq!(io.posts(), 1, "joining spends no second POST");

        // The external change is not lost — the NEXT admission reconciles and adopts it
        // without a POST (the floor gates POSTs, never lock-only reconciliations).
        let adopted = coord
            .admit(NOW, Instant::now(), &*io)
            .expect("the next admission adopts the external live credential");
        drop(adopted);
        assert_eq!(io.posts(), 1, "adoption is lock-and-read, never a POST");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -------------------------------------------------------------------------------------------
    // THE DIGEST IS THE ONLY THING THAT DECIDES WHETHER AN
    // UNCONFIGURED CELL EVER HEALS.
    //
    // The fresh-install schedule produces exactly one bad cell: an
    // `Unconfigured` provider paired with the digest of the credential that is, right now, on
    // disk. This witness constructs that cell directly — no race, no sleep — and executes both
    // arms of the branch `admit` takes on it:
    //
    //   * digest EQUAL to disk ⇒ `file_changed_since_publish` is false, no reconcile runs, and
    //     the cell answers the refusal forever (the STICKY state);
    //   * NO digest (`None`) ⇒ `Some(observed) != None` always, so the reconcile ALWAYS runs
    //     and the live arm is adopted on the very next admission.
    //
    // `lib.rs`'s fresh-install witness pins that the boot path publishes the second shape; this pins WHY
    // that is the whole property.
    // -------------------------------------------------------------------------------------------
    #[test]
    fn an_unconfigured_cell_heals_only_when_it_carries_no_digest() {
        let dir = fixture_dir("f4r4f1");
        let io = mock(&dir);
        // The disk holds a perfectly good, LIVE credential — the one the mint just published.
        io.set_disk("minted", Ok(live_credential(LIVE_UNTIL)));
        let on_disk = io.file_gen().expect("the mock disk reports its generation");

        let unconfigured = || Provider::Unconfigured {
            reason: "no Gmail credential at <dir> (NotFound). Mint one with                      scripts/gmail_drill_mint.py."
                .to_string(),
            cure: Some(Cure::ReMint),
        };
        let stuck_cell = |file_gen: Option<FileGen>| CredentialCell {
            provider: unconfigured(),
            // A failed load reads no expiry — the boot path's own shape.
            expires_at: None,
            generation: 0,
            file_gen,
            grant_generation: None,
            last_result: None,
        };

        // (a) THE RACE'S OWN CELL: `Unconfigured`, carrying the digest of the file now on disk.
        let sticky = CredentialCoordinator::new(stuck_cell(Some(on_disk.clone())), dir.to_path_buf());
        let err = sticky
            .admit(NOW, Instant::now(), &*io)
            .err()
            .expect("a cell whose digest already equals the disk never reconciles");
        assert!(
            matches!(err, SurfaceError::SessionUnconfigured { .. }),
            "and answers the stale re-mint refusal instead: {err:?}"
        );
        assert_eq!(io.rebuilds(), 0, "no reconcile ran — nothing was even rebuilt");
        assert!(
            matches!(sticky.snapshot().provider, Provider::Unconfigured { .. }),
            "the cell is STUCK: the good credential on disk is invisible to it"
        );

        // (b) THE SHAPE THE FIX PUBLISHES: no digest at all.
        let healing = CredentialCoordinator::new(stuck_cell(None), dir.to_path_buf());
        let arm = healing
            .admit(NOW, Instant::now(), &*io)
            .expect("a cell with no digest reconciles unconditionally and adopts the credential");
        drop(arm);
        assert_eq!(io.posts(), 0, "adoption is lock-and-read, never a POST");
        assert!(
            matches!(healing.snapshot().provider, Provider::Gmail(_)),
            "the live arm is published on the very next admission"
        );
        assert_eq!(
            healing.snapshot().file_gen,
            Some(on_disk),
            "and the cell now carries the digest it was actually built from"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -------------------------------------------------------------------------------------------
    // THE COORDINATOR'S TWO SITES — A LOAD FAILURE PUBLISHES NO DIGEST EITHER.
    //
    // This was first seen at BOOT, but the class it belongs to is the cell's, so it closes
    // on the CELL: an `Unconfigured` cell carries no digest and no expiry, from every publisher.
    // The wave's load arm and the reconcile's load arm each stamped the LOCKED observation onto
    // the unarmed cell they published. That shape is not wrong by accident today — a repaired
    // credential file changes its own digest, so those two sites do heal — but it is the same
    // invalid state the boot finding exploited, reachable the moment a cure lands somewhere other
    // than in those bytes (a permission change, a restored parent directory, a repaired ratchet).
    // Both now route through `CredentialCell::set_unconfigured`, which has no digest to give.
    //
    // The COST is named in that constructor's doc and executed here: the next admission always
    // reconciles, so an unarmed cell re-reads the file on every command. One lock-and-read for a
    // session that is already refusing every command — and never a POST.
    //
    // Before the fix this test failed:
    //   panicked at src\credential_cell.rs:1729:9:
    //   assertion `left == right` failed: the wave's load failure publishes no digest — an
    //   unarmed cell has nothing to keep one for
    //     left: Some(Sha384("000…00a"))
    //    right: None
    // -------------------------------------------------------------------------------------------
    #[test]
    fn the_wave_and_the_reconcile_publish_no_digest_when_the_load_fails() {
        let unreadable = || crate::CredentialLoadFailure {
            class: crate::CredentialLoadRefusal::Unreadable(std::io::ErrorKind::PermissionDenied),
            reason: "the Gmail credential at <dir> could not be READ (permission denied)"
                .to_string(),
        };

        // (a) THE WAVE: an EXPIRED cell whose locked re-read cannot load the file.
        let dir = fixture_dir("f6r5f6-wave");
        let io = mock(&dir);
        *io.load_result.lock().unwrap() = Err(unreadable());
        let coord = CredentialCoordinator::new(
            cell(arm(&dir), Some(NOW - 10), file_generation("a")),
            dir.to_path_buf(),
        );
        coord
            .admit(NOW, Instant::now(), &*io)
            .err()
            .expect("a wave that cannot read the credential admits nothing");
        let snap = coord.snapshot();
        assert!(
            matches!(snap.provider, Provider::Unconfigured { .. }),
            "the premise: the wave published an unarmed cell"
        );
        assert_eq!(
            snap.file_gen, None,
            "the wave's load failure publishes no digest — an unarmed cell has nothing to keep \
             one for"
        );
        assert_eq!(snap.expires_at, None, "and no expiry");
        assert_eq!(snap.grant_generation, None, "and no generation");
        let _ = std::fs::remove_dir_all(&dir);

        // (b) THE RECONCILE: a LIVE cell whose changed file cannot be loaded.
        let dir = fixture_dir("f6r5f6-reconcile");
        let io = mock(&dir);
        let coord = CredentialCoordinator::new(
            cell(arm(&dir), Some(LIVE_UNTIL), file_generation("a")),
            dir.to_path_buf(),
        );
        io.set_disk("changed-but-unreadable", Err(unreadable()));
        coord
            .admit(NOW, Instant::now(), &*io)
            .err()
            .expect("a reconcile onto an unreadable credential admits nothing");
        let snap = coord.snapshot();
        assert!(
            matches!(snap.provider, Provider::Unconfigured { .. }),
            "the premise: the reconcile published an unarmed cell"
        );
        assert_eq!(
            snap.file_gen, None,
            "the reconcile's load failure publishes no digest either"
        );
        assert_eq!(snap.expires_at, None, "and no expiry");

        // THE CONSEQUENCE: the file is repaired WITHOUT changing the digest the cell
        // would have carried, and the very next admission still reconciles onto it.
        *io.load_result.lock().unwrap() = Ok(live_credential(LIVE_UNTIL));
        let healed = coord
            .admit(NOW, Instant::now(), &*io)
            .expect("an unarmed cell re-reads on every command, so the repair is adopted at once");
        drop(healed);
        assert!(
            matches!(coord.snapshot().provider, Provider::Gmail(_)),
            "the live arm is published on the very next admission"
        );
        assert_eq!(io.posts(), 0, "adoption is lock-and-read, never a POST");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -------------------------------------------------------------------------------------------
    // THE OTHER TWO CALLERS — THE WAVE AND THE RECONCILE TAKE THE REFUSAL'S OWN CURE.
    //
    // `lib.rs`'s load-refusal-cure witnesses judge the two BOOT callers. The load door has two more:
    // `run_wave_inner` (the expired-cell path) and `reconcile_locked` (the changed-file path).
    // Both published `Cure::ReMint` from the same deleted constant, so an unreadable credential
    // file told the operator to re-consent from three surfaces at once.
    //
    // Before the fix: both arms answer `ReMint` for a read failure.
    // -------------------------------------------------------------------------------------------
    #[test]
    fn the_wave_and_the_reconcile_publish_the_load_refusals_own_cure() {
        let unreadable = || crate::CredentialLoadFailure {
            class: crate::CredentialLoadRefusal::Unreadable(std::io::ErrorKind::PermissionDenied),
            reason: "the Gmail credential at <dir> could not be READ (permission denied)"
                .to_string(),
        };

        // (a) THE WAVE: an EXPIRED cell whose locked re-read cannot read the file. The DIGEST is
        //     deliberately unchanged (`mock` publishes generation "a", so does the cell) — a
        //     changed digest would be the reconcile's case, which arm (b) covers.
        let dir = fixture_dir("f4r4f2-wave");
        let io = mock(&dir);
        *io.load_result.lock().unwrap() = Err(unreadable());
        let coord = CredentialCoordinator::new(
            cell(arm(&dir), Some(NOW - 10), file_generation("a")),
            dir.to_path_buf(),
        );
        let err = coord
            .admit(NOW, Instant::now(), &*io)
            .err()
            .expect("a wave that cannot read the credential admits nothing");
        let wave_cure = match &err {
            SurfaceError::CredentialExpired { cure, .. } => *cure,
            other => panic!("the wave refuses typed: {other:?}"),
        };
        assert_eq!(
            wave_cure,
            Cure::Undetermined,
            "the wave hands its joiners the REFUSAL'S cure, not a blanket re-mint"
        );
        assert_eq!(io.posts(), 0, "and it never dialled the endpoint to find out");
        match &coord.snapshot().provider {
            Provider::Unconfigured { cure, .. } => assert_eq!(
                *cure,
                Some(Cure::Undetermined),
                "the PUBLISHED cell says the same thing the joiners were told"
            ),
            Provider::Gmail(_) => panic!("an unreadable credential publishes no arm"),
        }
        let _ = std::fs::remove_dir_all(&dir);

        // (b) THE RECONCILE: a LIVE cell whose changed file cannot be read.
        let dir = fixture_dir("f4r4f2-reconcile");
        let io = mock(&dir);
        let coord = CredentialCoordinator::new(
            cell(arm(&dir), Some(LIVE_UNTIL), file_generation("a")),
            dir.to_path_buf(),
        );
        io.set_disk("changed-but-unreadable", Err(unreadable()));
        let err = coord
            .admit(NOW, Instant::now(), &*io)
            .err()
            .expect("a reconcile that cannot read the changed file admits nothing");
        match &err {
            SurfaceError::SessionUnconfigured { cure, .. } => assert_eq!(
                *cure,
                Some(Cure::Undetermined),
                "the reconcile publishes the REFUSAL'S cure too"
            ),
            other => panic!("the reconcile's published refusal surfaces here: {other:?}"),
        }
        assert_eq!(io.posts(), 0, "adoption failure spends nothing");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -------------------------------------------------------------------------------------------
    // Hermetic end-to-end: an expired cell renews, persists the SURVIVOR, rebuilds, and
    // publishes ONE generation whose status owes no cure.
    //
    // Mutation that proves it can fail: publish the OLD `expires_at` instead of `*new_expiry`.
    // -------------------------------------------------------------------------------------------
    #[test]
    fn an_expired_cell_renews_persists_rebuilds_and_publishes_one_live_generation() {
        let dir = fixture_dir("w6");
        let old = arm(&dir);
        let old_ptr = arm_ptr(&old);
        let io = mock(&dir);
        let coord = CredentialCoordinator::new(cell(old, Some(NOW - 10), file_generation("a")), dir.to_path_buf());

        let provider = coord
            .admit(NOW, Instant::now(), &*io)
            .expect("an expired-but-refreshable cell admits the command after one renewal");

        assert_eq!(io.posts(), 1, "one wave, one exchange");
        let persists = io.persists.lock().unwrap().clone();
        assert_eq!(persists.len(), 1, "the renewal is written exactly once");
        assert_eq!(
            persists[0].1, SURVIVOR,
            "the SURVIVING refresh token is what is persisted — persisting the rotated-away one \
             parks a dead credential while reporting success"
        );
        assert_eq!(persists[0].2, LIVE_UNTIL, "the attested expiry is what is written");
        assert_eq!(io.rebuilds(), 1, "a renewed credential means a rebuilt arm — the BearerToken is immutable");

        let snap = coord.snapshot();
        assert_eq!(snap.generation, 1, "ONE cell write, so exactly one generation");
        assert_ne!(arm_ptr(&snap.provider), old_ptr, "the cell holds the REBUILT arm, not the stale one");
        assert_eq!(
            arm_ptr(&snap.provider),
            Arc::as_ptr(&provider) as usize,
            "the caller was handed the arm that was PUBLISHED — admission and status read one cell"
        );
        assert_eq!(snap.expires_at, Some(LIVE_UNTIL), "the cell carries the NEW expiry");
        assert_eq!(
            snap.file_gen,
            file_generation("renewed"),
            "the cell records the generation the writer produced, so the next admission does not \
             reconcile its own write"
        );
        assert!(
            matches!(
                snap.last_result.as_ref().map(|s| &s.outcome),
                Some(RememberedOutcome::Renewed)
            ),
            "the stamp remembers Renewed — without its secrets"
        );
        assert_eq!(
            coord.status_cure(NOW),
            None,
            "a renewed cell is LIVE, and a live cell owes the status surface no cure"
        );
        assert!(
            io.lock_paths
                .lock()
                .unwrap()
                .iter()
                .all(|p| p.ends_with(CREDENTIAL_LOCK_FILE_NAME)),
            "the wave takes the CREDENTIAL lock address, the one the mint script also takes"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -------------------------------------------------------------------------------------------
    // N concurrent callers + a SUCCESSFUL wave ⇒ exactly ONE POST, every caller admitted,
    // every caller on the SAME generation ("one POST, all callers same generation
    // AND same typed result").
    //
    // RED on the first cut with NO mutation: `admit` read `self.wave` and `run_wave` installed
    // the wave under a SECOND acquisition, so callers released together all saw `None` and each
    // started its own wave. Measured on that cut: 9 of 10 solo runs RED at 2 POSTs; widening the
    // window between the two acquisitions with a 50 ms sleep took it to 8 of 8 callers POSTing.
    // The fix — read and install the slot under ONE guard — turned this witness and its sibling GREEN
    // (10/10 solo runs after the fix). Before the fix the "one POST per wave" claim was held only
    // by the cross-process OS lock underneath (a different property, which does not deliver the
    // shared generation this asserts, and which refuses the loser after the 5 s lock deadline).
    // -------------------------------------------------------------------------------------------
    /// How many independent waves a concurrency witness runs.
    ///
    /// The property under test is a RACE, and one trial does not decide a race. Each trial is
    /// exactly the specified shape — ONE fresh coordinator, [`WAVE_CALLERS`] threads released
    /// together by a barrier — and the repetition only removes the schedule's vote from the answer.
    const WAVE_TRIALS: usize = 8;
    const WAVE_CALLERS: usize = 8;

    #[test]
    fn a_concurrent_successful_wave_posts_once_and_publishes_one_generation() {
        for trial in 0..WAVE_TRIALS {
            let dir = fixture_dir(&format!("w7-{trial}"));
            let old = arm(&dir);
            let io = mock(&dir);
            // The exchange OUTLASTS the barrier release: every caller is inside `admit` while the
            // wave is in flight, which is the only state in which "join" means anything.
            *io.exchange_delay.lock().unwrap() = Duration::from_millis(200);
            let coord = Arc::new(CredentialCoordinator::new(
                cell(old, Some(NOW - 10), file_generation("a")),
                dir.to_path_buf(),
            ));

            let barrier = Arc::new(Barrier::new(WAVE_CALLERS));
            let mut handles = Vec::new();
            for _ in 0..WAVE_CALLERS {
                let coord = Arc::clone(&coord);
                let io = Arc::clone(&io);
                let barrier = Arc::clone(&barrier);
                handles.push(std::thread::spawn(move || {
                    barrier.wait();
                    coord
                        .admit(NOW, Instant::now(), &*io)
                        .map(|p| Arc::as_ptr(&p) as usize)
                }));
            }
            let results: Vec<_> = handles
                .into_iter()
                .map(|h| h.join().expect("no admission panics"))
                .collect();

            assert_eq!(
                io.posts(),
                1,
                "trial {trial}: ONE wave, ONE POST — the joiners rendezvous on the in-flight \
                 exchange instead of each dialling the token endpoint (§3-S4)"
            );
            for r in &results {
                assert!(r.is_ok(), "trial {trial}: every caller in a successful wave is admitted: {r:?}");
            }
            let first = *results[0].as_ref().expect("checked above");
            assert!(
                results.iter().all(|r| *r.as_ref().expect("checked above") == first),
                "trial {trial}: all callers hold the SAME published arm"
            );
            assert_eq!(
                coord.snapshot().generation,
                1,
                "trial {trial}: one wave publishes exactly one generation — §9 W7's 'all callers \
                 same generation'"
            );
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    // -------------------------------------------------------------------------------------------
    // N concurrent callers + a FAILED wave ⇒ exactly ONE POST, and every joiner receives the
    // SAME full typed result (not a genericized kind).
    //
    // RED on the first cut on the same defect as the single-flight test — a failed wave singleflighted through the
    // identical check-then-act, so a Transient answer was dialled once per racing caller instead
    // of once per wave (the joiners that did rendezvous reproduced the sentence exactly; it was
    // the POST count, not the result's fidelity, that failed). GREEN under the one-guard fix.
    // -------------------------------------------------------------------------------------------
    #[test]
    fn a_concurrent_failed_wave_posts_once_and_hands_every_joiner_the_same_typed_refusal() {
        let expected = (Cure::RetryLater, transient().reason_sentence());
        for trial in 0..WAVE_TRIALS {
            let dir = fixture_dir(&format!("w16-{trial}"));
            let old = arm(&dir);
            let io = mock(&dir);
            *io.outcome.lock().unwrap() = Ok(transient());
            *io.exchange_delay.lock().unwrap() = Duration::from_millis(200);
            let coord = Arc::new(CredentialCoordinator::new(
                cell(old, Some(NOW - 10), file_generation("a")),
                dir.to_path_buf(),
            ));

            let barrier = Arc::new(Barrier::new(WAVE_CALLERS));
            let mut handles = Vec::new();
            for _ in 0..WAVE_CALLERS {
                let coord = Arc::clone(&coord);
                let io = Arc::clone(&io);
                let barrier = Arc::clone(&barrier);
                handles.push(std::thread::spawn(move || {
                    barrier.wait();
                    match coord.admit(NOW, Instant::now(), &*io) {
                        Ok(_) => None,
                        Err(SurfaceError::CredentialExpired { cure, reason, .. }) => {
                            Some((cure, reason))
                        }
                        Err(other) => {
                            panic!("a Transient wave refuses with its own type: {other:?}")
                        }
                    }
                }));
            }
            let results: Vec<_> = handles
                .into_iter()
                .map(|h| h.join().expect("no admission panics"))
                .collect();

            assert_eq!(
                io.posts(),
                1,
                "trial {trial}: ONE wave, ONE POST — a failed wave singleflights exactly like a \
                 successful one"
            );
            for r in &results {
                let got = r.as_ref().expect("a Transient wave admits nobody");
                assert_eq!(
                    *got, expected,
                    "trial {trial}: every joiner reproduces the SAME cure and the SAME sentence — \
                     the result is lossless, never a genericized kind"
                );
            }
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    // -------------------------------------------------------------------------------------------
    // Sequential arm: the command AFTER a successful wave does not POST.
    //
    // Mutation that proves it can fail: stop publishing `c.expires_at = Some(*new_expiry)` on the
    // Renewed path, so the cell stays expired and every later command re-refreshes.
    // -------------------------------------------------------------------------------------------
    #[test]
    fn the_command_after_a_successful_wave_does_not_post_again() {
        let dir = fixture_dir("w15");
        let old = arm(&dir);
        let io = mock(&dir);
        let coord = CredentialCoordinator::new(cell(old, Some(NOW - 10), file_generation("a")), dir.to_path_buf());
        let t0 = Instant::now();

        coord.admit(NOW, t0, &*io).expect("the first command renews");
        assert_eq!(io.posts(), 1);

        coord
            .admit(NOW + 5, t0 + Duration::from_secs(5), &*io)
            .expect("the second command rides the published live cell");
        assert_eq!(io.posts(), 1, "a live cell short-circuits BEFORE the wave protocol");
        assert_eq!(coord.snapshot().generation, 1, "and it publishes nothing new");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -------------------------------------------------------------------------------------------
    // The terminal LATCH and its release: `ReauthRequired` refuses with cure re_mint and
    // stops POSTing until THE FILE CHANGES; an external re-mint is then picked up with no restart
    // and no POST.
    //
    // Mutation that proves it can fail: drop the `stamp.file_gen == cell.file_gen` conjunct from
    // the latch condition (the latch then never releases, so the re-mint is never picked up).
    // -------------------------------------------------------------------------------------------
    #[test]
    fn a_terminal_outcome_latches_to_the_file_generation_and_a_re_mint_releases_it() {
        let dir = fixture_dir("w22");
        let old = arm(&dir);
        let io = mock(&dir);
        *io.outcome.lock().unwrap() = Ok(RefreshOutcome::ReauthRequired { subtype: None });
        let coord = CredentialCoordinator::new(cell(old, Some(NOW - 10), file_generation("a")), dir.to_path_buf());
        let t0 = Instant::now();

        let (cure, reason) = refusal_of(coord.admit(NOW, t0, &*io), "a refused grant admits nobody");
        assert_eq!(cure, Cure::ReMint, "reauthorization is required: {reason}");
        assert!(reason.contains("reauthorization is required"), "{reason}");
        assert_eq!(io.posts(), 1);

        // Three more commands, each well PAST the pacing floor: the latch, not the floor, is what
        // is holding — so moving time changes nothing.
        for i in 1..=3u64 {
            let (cure, _) = refusal_of(
                coord.admit(NOW + (i as i64) * 60, t0 + Duration::from_secs(31 * i), &*io),
                "a latched cell keeps refusing",
            );
            assert_eq!(cure, Cure::ReMint);
        }
        assert_eq!(
            io.posts(),
            1,
            "the latch is to the FILE GENERATION: no floor expiry re-POSTs a grant the provider \
             already refused"
        );

        // The operator re-mints. The file generation moves, and the new file is live.
        io.set_disk("re-minted", Ok(live_credential(LIVE_UNTIL)));
        let provider = coord
            .admit(NOW, t0 + Duration::from_secs(200), &*io)
            .expect("a re-minted credential is picked up at the next admission, without a restart");

        assert_eq!(io.posts(), 1, "the pickup is a RECONCILIATION, not an exchange");
        let snap = coord.snapshot();
        assert_eq!(snap.file_gen, file_generation("re-minted"));
        assert_eq!(snap.expires_at, Some(LIVE_UNTIL));
        assert!(snap.last_result.is_none(), "the adopted file clears the refusal that latched");
        assert_eq!(arm_ptr(&snap.provider), Arc::as_ptr(&provider) as usize);
        assert_eq!(coord.status_cure(NOW), None, "the re-minted cell is live");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -------------------------------------------------------------------------------------------
    // An UNREADABLE digest is not a
    // file CHANGE. `FileGen::of` already models absence explicitly (`FileGen::Absent`), so a
    // read error carries no generation at all; the earlier `.ok()` flattened it to a value
    // that compared unequal to every published generation — the coordinator then "reconciled",
    // republished the same credential, CLEARED a terminal latch, and dialled a POST the
    // provider had already answered. An unreadable digest refuses with a typed local failure
    // (retried on the next command, pre-wire so unpaced) and the latch stands.
    //
    // Before the fix: staged as the flattened unknown the old Option surface allowed — the latch
    // released and a second POST went out.
    // -------------------------------------------------------------------------------------------
    #[test]
    fn an_unreadable_file_generation_refuses_and_never_releases_a_latch() {
        let dir = fixture_dir("filegen-unreadable");
        let old = arm(&dir);
        let io = mock(&dir);
        *io.outcome.lock().unwrap() = Ok(RefreshOutcome::ReauthRequired { subtype: None });
        let coord =
            CredentialCoordinator::new(cell(old, Some(NOW - 10), file_generation("a")), dir.to_path_buf());
        let t0 = Instant::now();

        let (cure, _) = refusal_of(coord.admit(NOW, t0, &*io), "a refused grant admits nobody");
        assert_eq!(cure, Cure::ReMint);
        assert_eq!(io.posts(), 1, "the latch is set");

        // The digest read starts failing (transient FS error — AV scan, EBUSY, permissions).
        *io.file_gen_fail.lock().unwrap() =
            Some(RefreshLocalError::FileGenUnreadable { reason: LocalIoReason(std::io::ErrorKind::Other) });

        let (cure, reason) = refusal_of(
            coord.admit(NOW + 60, t0 + Duration::from_secs(60), &*io),
            "an unreadable digest must refuse, not reconcile",
        );
        assert_eq!(cure, Cure::RetryLater, "{reason}");
        assert!(
            reason.contains("generation"),
            "the refusal names the digest read failure: {reason}"
        );
        assert_eq!(
            io.posts(),
            1,
            "an unreadable digest must never release the latch and re-POST a refused grant"
        );

        // The read heals; the latch is still keyed to the unchanged file and still holds.
        *io.file_gen_fail.lock().unwrap() = None;
        let (cure, _) = refusal_of(
            coord.admit(NOW + 120, t0 + Duration::from_secs(120), &*io),
            "the latch survived the unreadable window",
        );
        assert_eq!(cure, Cure::ReMint);
        assert_eq!(io.posts(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -------------------------------------------------------------------------------------------
    // STATUS-RECONCILE: the latch's release
    // lives in `admit`, but the operator reads the STATUS BAR, and `inbox_page` never goes
    // through admission — so before the fix, an operator who did exactly what the app asked (ran the
    // mint) kept seeing "needs a re-mint" until their next provider command, and re-minted a
    // SECOND time: a burned 300 s consent against the provider's 100-refresh-token ceiling.
    // When the caller's disk observation differs from the latched generation, the status
    // surface reports the neutral RetryLater; an unchanged or unobservable disk keeps the
    // stamped truth (no flapping on an unreadable digest).
    // -------------------------------------------------------------------------------------------
    #[test]
    fn a_latched_cure_is_suppressed_on_the_status_surface_once_the_disk_moves() {
        let dir = fixture_dir("status-reconcile");
        let stamped = CredentialCell {
            provider: arm(&dir),
            expires_at: Some(NOW - 10),
            generation: 1,
            file_gen: file_generation("a"),
            grant_generation: Some(fixture_grant().grant_generation),
            last_result: Some(RefreshStamp {
                outcome: RememberedOutcome::Failed(RefreshOutcome::ReauthRequired {
                    subtype: None,
                }),
                completed_at: Instant::now(),
                file_gen: file_generation("a"),
                spent_post: true,
                failures_in_a_row: 1,
            }),
        };
        let moved = FileGen::Sha384(format!("{:0>96}", "re-minted"));
        assert_eq!(
            stamped.status_cure(NOW, Some(&moved)),
            Some(Cure::RetryLater),
            "a latched cure whose fix has landed on disk must not be re-demanded"
        );
        let same = FileGen::Sha384(format!("{:0>96}", "a"));
        assert_eq!(
            stamped.status_cure(NOW, Some(&same)),
            Some(Cure::ReMint),
            "an unchanged file keeps the latched truth"
        );
        assert_eq!(
            stamped.status_cure(NOW, None),
            Some(Cure::ReMint),
            "an unobservable disk suppresses nothing — undecidable keeps the stamped truth"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -------------------------------------------------------------------------------------------
    // STAMP-GENERATION FIDELITY (the floor-bypass mechanism, isolated):
    // A reconcile that ADOPTS an observed generation must PRESERVE
    // a `last_result` recorded against that SAME generation — the stamp describes the adopted
    // bytes, and clearing it un-paces the endpoint (a barrier witness spent POST #2
    // inside the floor exactly this way: left:2 right:1). The re-mint release is
    // untouched: a stamp for a DIFFERENT generation still clears on adoption.
    //
    // Before the fix: the adopt arm unconditionally set last_result = None; posts went to 2.
    // -------------------------------------------------------------------------------------------
    #[test]
    fn reconcile_preserves_a_stamp_recorded_against_the_generation_it_adopts() {
        let dir = fixture_dir("stamp-fidelity");
        let old = arm(&dir);
        let io = mock(&dir);
        *io.outcome.lock().unwrap() = Ok(transient());
        // Disk already at generation "b": the first admission reconciles a→b, then its wave
        // POSTs and stamps Transient/spent_post AGAINST generation "b".
        io.set_disk("b", Ok(expired_credential()));
        let coord =
            CredentialCoordinator::new(cell(old, Some(NOW - 10), file_generation("a")), dir.to_path_buf());
        let t0 = Instant::now();

        let (cure, _) = refusal_of(coord.admit(NOW, t0, &*io), "the transient wave refuses");
        assert_eq!(cure, Cure::RetryLater);
        assert_eq!(io.posts(), 1);
        assert_eq!(coord.snapshot().file_gen, file_generation("b"));

        // Stage the shape: the cell's generation is rolled back to "a" while the stamp
        // stays recorded against "b" — the next admission's reconcile re-adopts "b", the very
        // generation the stamp already describes.
        coord.publish(|c| c.file_gen = file_generation("a"));

        let (cure2, reason2) = refusal_of(
            coord.admit(NOW + 5, t0 + Duration::from_secs(5), &*io),
            "adopting the stamped generation must pace, never re-POST",
        );
        assert_eq!(
            io.posts(),
            1,
            "adopting the generation the stamp already describes must not un-pace the endpoint"
        );
        assert_eq!(cure2, Cure::RetryLater);
        assert!(reason2.contains("paced"), "{reason2}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -------------------------------------------------------------------------------------------
    // The paced refusal carries the STAMPED cure: pacing
    // is the TIMING, not the MEDIUM. Before the fix, a paced ClientConfig stamp hard-coded RetryLater
    // The toast said "wait" while the status and reason required developer action.
    // -------------------------------------------------------------------------------------------
    #[test]
    fn a_paced_refusal_carries_the_stamped_cure_not_a_hardcoded_wait() {
        let dir = fixture_dir("paced-cure");
        let old = arm(&dir);
        let io = mock(&dir);
        *io.outcome.lock().unwrap() = Ok(RefreshOutcome::ClientConfig {
            code: Sanitized::new("invalid_client"),
        });
        let coord =
            CredentialCoordinator::new(cell(old, Some(NOW - 10), file_generation("a")), dir.to_path_buf());
        let t0 = Instant::now();

        let (cure, _) = refusal_of(coord.admit(NOW, t0, &*io), "the wave refuses client-config");
        assert_eq!(cure, Cure::ClientConfig);
        assert_eq!(io.posts(), 1);

        // Inside the floor: the refusal is PACED but its cure is still the stamped medium.
        let (cure2, reason2) = refusal_of(
            coord.admit(NOW + 5, t0 + Duration::from_secs(5), &*io),
            "a paced refusal still refuses",
        );
        assert_eq!(io.posts(), 1, "paced: no second POST");
        assert_eq!(
            cure2,
            Cure::ClientConfig,
            "the paced refusal must carry the stamped cure, not a hardcoded wait: {reason2}"
        );
        assert!(reason2.contains("paced"), "{reason2}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -------------------------------------------------------------------------------------------
    // THE
    // AGGREGATE IS NOT SILENT: each refusal is individually honest, but before the fix nothing ever
    // said "this has failed N times; retrying is not the cure" — a permanently failing
    // contract violation presented forever as "Photon will retry on your next command". The
    // paced refusal now names the streak once it reaches three.
    // -------------------------------------------------------------------------------------------
    #[test]
    fn a_paced_refusal_after_repeated_failures_names_the_streak() {
        let dir = fixture_dir("streak");
        let old = arm(&dir);
        let io = mock(&dir);
        *io.outcome.lock().unwrap() = Ok(transient());
        let coord =
            CredentialCoordinator::new(cell(old, Some(NOW - 10), file_generation("a")), dir.to_path_buf());
        let t0 = Instant::now();

        for i in 0..3u64 {
            refusal_of(
                coord.admit(NOW + (i as i64) * 60, t0 + Duration::from_secs(31 * i), &*io),
                "each transient wave refuses",
            );
        }
        assert_eq!(io.posts(), 3, "three separate floor-cleared attempts each dialled");

        let (_, reason) = refusal_of(
            coord.admit(NOW + 200, t0 + Duration::from_secs(5), &*io),
            "inside the third attempt's floor",
        );
        assert!(
            reason.contains("3 paced attempts in a row"),
            "the paced refusal names the streak so the aggregate is not silent: {reason}"
        );
        // The guidance is
        // STAGE-NEUTRAL — after three NETWORK failures there is no provider response to
        // review, so the suffix must not direct the operator at one.
        assert!(
            !reason.contains("provider response"),
            "the streak guidance must not name a response that may not exist: {reason}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -------------------------------------------------------------------------------------------
    // A RENEWED stamp keyed to
    // the generation the reconcile adopts is PRESERVED (amendment 7's law as written): a
    // short-lived renewal is truthfully grace-refused with its floor mattering; if the cell's
    // generation is then perturbed, the healing reconcile adopts the SAME persisted bytes and
    // once DROPPED the Renewed stamp (the filter was Failed-only) — floor erased, POST #2
    // inside grace.
    // -------------------------------------------------------------------------------------------
    #[test]
    fn a_renewed_stamp_keyed_to_the_adopted_generation_survives_reconcile() {
        let dir = fixture_dir("renewed-preserved");
        let old = arm(&dir);
        let io = mock(&dir);
        let short = NOW + crate::CREDENTIAL_EXPIRY_GRACE_SECS / 2;
        *io.outcome.lock().unwrap() = Ok(renewed(short));
        *io.persist_gen.lock().unwrap() = file_generation("renewed");
        let coord =
            CredentialCoordinator::new(cell(old, Some(NOW - 10), file_generation("a")), dir.to_path_buf());
        let t0 = Instant::now();

        let (cure, _) = refusal_of(coord.admit(NOW, t0, &*io), "a grace-short renewal refuses");
        assert_eq!(cure, Cure::RetryLater);
        assert_eq!(io.posts(), 1);
        assert_eq!(
            coord.snapshot().file_gen,
            file_generation("renewed"),
            "the published generation is the WRITTEN generation — no post-persist read exists"
        );

        // Perturb the cell's generation while the stamp stays keyed to the persisted bytes.
        coord.publish(|c| c.file_gen = file_generation("a"));

        let (cure2, _) = refusal_of(
            coord.admit(NOW + 5, t0 + Duration::from_secs(5), &*io),
            "adopting the stamped generation must pace, never re-POST",
        );
        assert_eq!(
            io.posts(),
            1,
            "the Renewed stamp survived the reconcile and its floor still paces the endpoint"
        );
        assert_eq!(cure2, Cure::RetryLater);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -------------------------------------------------------------------------------------------
    // A
    // SPENT-POST Local stamp keyed to the adopted generation keeps its PACING on reconcile: a
    // POST that renewed and persisted but failed in the rebuild tail must not have its floor
    // erased by the healing adoption — with a grace-short grant on disk, the old clear
    // meant an immediate POST #2 inside the floor. Pre-wire locals (spent_post=false) still
    // clear: the successful adoption refutes them (a heal whose pin recuts to the honest
    // form: live adoption admits without a POST; a retained spent stamp is inert on a live
    // cell).
    // -------------------------------------------------------------------------------------------
    #[test]
    fn a_spent_post_local_stamp_keeps_its_floor_across_reconcile() {
        let dir = fixture_dir("spent-local-floor");
        let old = arm(&dir);
        let io = mock(&dir);
        let short = NOW + crate::CREDENTIAL_EXPIRY_GRACE_SECS / 2;
        *io.outcome.lock().unwrap() = Ok(renewed(short));
        *io.persist_gen.lock().unwrap() = file_generation("renewed");
        *io.rebuild_fail.lock().unwrap() = Some(RefreshLocalError::RebuildFailed {
            reason: "tail failure after a spent POST".to_string(),
        });
        let coord =
            CredentialCoordinator::new(cell(old, Some(NOW - 10), file_generation("a")), dir.to_path_buf());
        let t0 = Instant::now();

        let (cure, _) = refusal_of(
            coord.admit(NOW, t0, &*io),
            "a post-persist rebuild failure refuses",
        );
        assert_eq!(cure, Cure::RetryLater);
        assert_eq!(io.posts(), 1, "the POST was spent before the tail failed");

        // Next admission inside the floor: disk (renewed, grace-short) ≠ cell (a) → reconcile
        // adopts; the rebuild heals (one-shot); the credential is still inside grace, so
        // admission continues past the live check — the preserved SPENT stamp must pace it.
        let (cure2, _) = refusal_of(
            coord.admit(NOW, t0 + Duration::from_secs(5), &*io),
            "the adopted grace-short credential refuses paced, never a second POST",
        );
        assert_eq!(
            io.posts(),
            1,
            "the spent-POST local stamp's floor survives the healing reconcile"
        );
        assert_eq!(cure2, Cure::RetryLater);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -------------------------------------------------------------------------------------------
    // A GRACE-REFUSED renewal is an admission failure for
    // the streak: before the fix, publish_renewed reset the counter to 0 on every persisted-but-
    // refused short grant, so the POST-refuse loop never reached the aggregate warning.
    // -------------------------------------------------------------------------------------------
    #[test]
    fn grace_refused_renewals_count_toward_the_streak() {
        let dir = fixture_dir("grace-streak");
        let old = arm(&dir);
        let io = mock(&dir);
        let short = NOW + crate::CREDENTIAL_EXPIRY_GRACE_SECS / 2;
        *io.outcome.lock().unwrap() = Ok(renewed(short));
        let coord =
            CredentialCoordinator::new(cell(old, Some(NOW - 10), file_generation("a")), dir.to_path_buf());
        let t0 = Instant::now();

        for i in 0..3u64 {
            // Each wave persists a fresh short grant; move the mock disk's post-persist
            // generation forward so every wave re-reads a coherent world.
            *io.persist_gen.lock().unwrap() = file_generation(&format!("r{i}"));
            refusal_of(
                coord.admit(NOW, t0 + Duration::from_secs(31 * i), &*io),
                "each short renewal refuses at the grace recheck",
            );
        }
        assert_eq!(io.posts(), 3);

        let (_, reason) = refusal_of(
            coord.admit(NOW, t0 + Duration::from_secs(5), &*io),
            "inside the third attempt's floor",
        );
        assert!(
            reason.contains("3 paced attempts in a row"),
            "three spent-but-unusable renewals must reach the aggregate warning: {reason}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -------------------------------------------------------------------------------------------
    // The status suppression
    // must NOT fire when the on-disk generation equals the STAMP's: that is the very
    // generation the latch survives adoption onto, so "will retry" would be false.
    // -------------------------------------------------------------------------------------------
    #[test]
    fn suppression_never_fires_when_the_disk_matches_the_stamped_generation() {
        let dir = fixture_dir("suppress-agree");
        let stamped = CredentialCell {
            provider: arm(&dir),
            expires_at: Some(NOW - 10),
            generation: 1,
            file_gen: file_generation("a"),
            grant_generation: Some(fixture_grant().grant_generation),
            last_result: Some(RefreshStamp {
                outcome: RememberedOutcome::Failed(RefreshOutcome::ReauthRequired {
                    subtype: None,
                }),
                completed_at: Instant::now(),
                file_gen: file_generation("b"),
                spent_post: true,
                failures_in_a_row: 1,
            }),
        };
        let disk_b = FileGen::Sha384(format!("{:0>96}", "b"));
        assert_eq!(
            stamped.status_cure(NOW, Some(&disk_b)),
            Some(Cure::ReMint),
            "disk == the STAMP's generation: the latch survives the coming adoption, so \
             promising a retry would lie"
        );
        let disk_c = FileGen::Sha384(format!("{:0>96}", "c"));
        assert_eq!(
            stamped.status_cure(NOW, Some(&disk_c)),
            Some(Cure::RetryLater),
            "a genuinely new generation still suppresses"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -------------------------------------------------------------------------------------------
    // A LIVE cell rides through a transient digest-read
    // failure: nothing about the published live arm is in doubt, and an expiry-shaped refusal
    // with a future expiry is false on its face. Expired cells keep the typed refusal.
    // -------------------------------------------------------------------------------------------
    #[test]
    fn a_live_cell_rides_through_an_unreadable_digest_instead_of_refusing_as_expired() {
        let dir = fixture_dir("live-ride-through");
        let old = arm(&dir);
        let io = mock(&dir);
        *io.file_gen_fail.lock().unwrap() = Some(RefreshLocalError::FileGenUnreadable {
            reason: LocalIoReason(std::io::ErrorKind::Other),
        });
        let coord = CredentialCoordinator::new(
            cell(old, Some(LIVE_UNTIL), file_generation("a")),
            dir.to_path_buf(),
        );

        let arm = coord
            .admit(NOW, Instant::now(), &*io)
            .expect("a LIVE cell must admit through a transient digest failure");
        drop(arm);
        assert_eq!(io.posts(), 0, "riding the live arm dials nothing");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -------------------------------------------------------------------------------------------
    // The pacing floor is measured FROM THE COMPLETION of the previous attempt, not from its
    // start, and the paced refusal SAYS SO.
    //
    // Mutation that proves it can fail: measure the floor from a start stamp instead of
    // `completed_at`.
    // -------------------------------------------------------------------------------------------
    #[test]
    fn the_transient_floor_runs_from_the_previous_attempts_completion() {
        let dir = fixture_dir("w23");
        let old = arm(&dir);
        let io = mock(&dir);
        *io.outcome.lock().unwrap() = Ok(transient());
        // A SLOW exchange is what makes "from COMPLETION" a different answer from "from start":
        // the wave starts at t0 and finishes at t0 + 1.5 s, so a probe at t0 + 31 s is 31 s after
        // the attempt STARTED and only 29.5 s after it COMPLETED — admitted under one reading,
        // paced under the other. With an instant exchange the two readings are indistinguishable
        // and this witness would be asserting nothing about the clause it is named for.
        *io.exchange_delay.lock().unwrap() = Duration::from_millis(1_500);
        let coord = CredentialCoordinator::new(cell(old, Some(NOW - 10), file_generation("a")), dir.to_path_buf());
        let t0 = Instant::now();

        refusal_of(coord.admit(NOW, t0, &*io), "a network failure admits nobody");
        assert_eq!(io.posts(), 1);

        let (cure, reason) = refusal_of(
            coord.admit(NOW, t0 + Duration::from_secs(10), &*io),
            "ten seconds in, the floor is still running",
        );
        assert_eq!(cure, Cure::RetryLater, "a transient failure is a WAIT, never a re-mint demand");
        assert!(reason.contains("paced"), "the refusal names the pacing, not a second failure: {reason}");
        assert!(
            reason.contains(&transient().reason_sentence()),
            "and it carries the ORIGINAL outcome's sentence, losslessly: {reason}"
        );
        assert_eq!(io.posts(), 1, "no POST inside the floor");

        // THE DISCRIMINATOR: 31 s after the attempt STARTED, 29.5 s after it COMPLETED.
        refusal_of(
            coord.admit(NOW, t0 + Duration::from_secs(31), &*io),
            "31 s after the attempt STARTED is still inside a floor measured from its COMPLETION",
        );
        assert_eq!(
            io.posts(),
            1,
            "the floor is measured FROM COMPLETION — a floor measured from the wave's start would \
             have re-POSTed here, which is exactly the storm a long exchange must not license"
        );

        refusal_of(
            coord.admit(NOW, t0 + Duration::from_secs(32), &*io),
            "past the floor a fresh attempt is admitted — and fails the same way",
        );
        assert_eq!(io.posts(), 2, "past the floor, exactly ONE new attempt");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -------------------------------------------------------------------------------------------
    // Persist SUCCEEDS, rebuild FAILS: a typed `RebuildFailed` refusal, the cell keeps the
    // OLD provider, and the next admission reconciles disk-newer-than-cell WITHOUT a POST — even
    // though the pacing floor is still running (the floor gates POSTs, never
    // lock-only reconciliations).
    //
    // Mutation that proves it can fail: move the `file_changed_since_publish` reconciliation to
    // AFTER the live/expired/latch/pacing branch.
    // -------------------------------------------------------------------------------------------
    #[test]
    fn a_failed_rebuild_keeps_the_old_arm_and_the_next_admission_reconciles_without_a_post() {
        let dir = fixture_dir("w34");
        let old = arm(&dir);
        let old_ptr = arm_ptr(&old);
        let io = mock(&dir);
        *io.rebuild_fail.lock().unwrap() = Some(RefreshLocalError::RebuildFailed {
            reason: "the mutation boundary has no intent log".to_string(),
        });
        let coord = CredentialCoordinator::new(cell(old, Some(NOW - 10), file_generation("a")), dir.to_path_buf());
        let t0 = Instant::now();

        let (cure, reason) = refusal_of(
            coord.admit(NOW, t0, &*io),
            "a cell with no rebuilt arm admits nobody",
        );
        assert_eq!(cure, Cure::RetryLater, "a local failure heals by retrying: {reason}");
        assert!(
            reason.contains("could not be rebuilt"),
            "the refusal names the STAGE that failed, never a silent wedge: {reason}"
        );
        assert_eq!(io.posts(), 1);
        assert_eq!(io.persists.lock().unwrap().len(), 1, "the credential WAS written");
        let snap = coord.snapshot();
        assert_eq!(arm_ptr(&snap.provider), old_ptr, "the cell keeps the previous provider");
        assert_eq!(
            snap.file_gen,
            file_generation("a"),
            "and its generation still names the file the OLD arm was built from — the disk is now NEWER"
        );

        // One second later — deep inside the 30 s floor. The reconciliation runs anyway.
        let provider = coord
            .admit(NOW, t0 + Duration::from_secs(1), &*io)
            .expect("disk-newer-than-cell is adopted at the next admission");

        assert_eq!(
            io.posts(),
            1,
            "reconcile-before-branch beats the floor: the recovery is a lock-only reconciliation, \
             not a second exchange"
        );
        let snap = coord.snapshot();
        assert_eq!(snap.file_gen, file_generation("renewed"), "the persisted generation is adopted");
        assert_eq!(snap.expires_at, Some(LIVE_UNTIL));
        // The spent-POST RebuildFailed stamp is keyed to
        // the very generation the reconcile adopts, so it is PRESERVED — erasing it was the
        // floor-bypass already demonstrated. On a LIVE cell a retained spent stamp is INERT (the live
        // fast path admits without consulting it, as the successful admission above proves);
        // what this pin now asserts is the honest pair: the adoption itself spent no POST, and
        // any retained stamp still carries its spent_post pacing fact.
        if let Some(stamp) = &snap.last_result {
            assert!(stamp.spent_post, "only a spent stamp may survive the healing adoption");
        }
        assert_ne!(arm_ptr(&snap.provider), old_ptr, "and the arm is finally rebuilt");
        assert_eq!(arm_ptr(&snap.provider), Arc::as_ptr(&provider) as usize);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -------------------------------------------------------------------------------------------
    // Reconciliation LINEARIZATION. The cell is at A and the pre-check observes B; while the
    // reconciler waits for the writer lock, a concurrent wave publishes C. The reconciler must
    // publish only what it observes UNDER THE LOCK (C) — never the stale pre-lock read (B).
    //
    // Mutation that proves it can fail: hoist `let observed = io.file_gen();` ABOVE the
    // `io.lock(..)` call in `reconcile_locked`.
    // -------------------------------------------------------------------------------------------
    #[test]
    fn a_reconciler_never_republishes_its_pre_lock_read_over_a_newer_generation() {
        const C_EXPIRY: i64 = NOW + 7_200;
        let dir = fixture_dir("w44");
        let old = arm(&dir);
        let io = mock(&dir);
        let coord = Arc::new(CredentialCoordinator::new(
            cell(old, Some(LIVE_UNTIL), file_generation("a")),
            dir.to_path_buf(),
        ));
        // The pre-check sees B — a file that changed since the cell was published.
        io.set_disk("b", Ok(live_credential(NOW + 1_000)));

        let arm_c = arm(&dir);
        let ptr_c = arm_ptr(&arm_c);
        let fired = Arc::new(AtomicBool::new(false));
        {
            let coord_hook = Arc::clone(&coord);
            let io_hook = Arc::clone(&io);
            let fired = Arc::clone(&fired);
            *io.on_lock.lock().unwrap() = Some(Box::new(move || {
                if fired.swap(true, Ordering::SeqCst) {
                    return;
                }
                // A concurrent wave finished between the pre-check and this lock: it wrote C and
                // published C. This is a counterexample made deterministic.
                io_hook.set_disk("c", Ok(live_credential(C_EXPIRY)));
                coord_hook.publish(|c| {
                    c.provider = arm_c.clone();
                    c.expires_at = Some(C_EXPIRY);
                    c.file_gen = file_generation("c");
                    c.last_result = None;
                });
            }));
        }

        let provider = coord
            .admit(NOW, Instant::now(), &*io)
            .expect("a live cell admits the command");

        let snap = coord.snapshot();
        assert_eq!(
            snap.file_gen,
            file_generation("c"),
            "the cell holds C — the LOCKED observation. Publishing the pre-lock read would put B \
             back over a generation that is strictly newer"
        );
        assert_eq!(snap.expires_at, Some(C_EXPIRY), "and C's expiry, not B's");
        assert_eq!(arm_ptr(&snap.provider), ptr_c, "and C's arm");
        assert_eq!(arm_ptr(&snap.provider), Arc::as_ptr(&provider) as usize);
        assert_eq!(
            io.rebuilds(),
            0,
            "the reconciler re-read under the lock, found nothing left to adopt, and rebuilt \
             NOTHING — a rebuild here is the stale republication"
        );
        assert_eq!(io.posts(), 0, "a live credential is never exchanged");
        // BREAK THE CYCLE. The hook lives inside `io` and holds
        // `io_hook` (an `Arc` of `io` itself) plus `coord_hook` and `arm_c` — a reference cycle
        // that is never dropped, so the store connection those arms hold stayed open for the
        // whole test process and the fixture dir could never be removed (the old guard's
        // `let _ = remove_dir_all` swallowed "used by another process"; the one guard's loud
        // drop named it: `photon-cell-w44-*`). Dropping the fired hook frees all three.
        io.on_lock.lock().unwrap().take();
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -------------------------------------------------------------------------------------------
    // Reconcile-before-branch, standalone: an expired cell with a one-second-old `Transient`
    // stamp (so the floor WOULD pace a POST) whose disk is newer AND live ⇒ admitted with no POST.
    //
    // Mutation that proves it can fail: same as the previous test — reconcile after the branch instead of before.
    // -------------------------------------------------------------------------------------------
    #[test]
    fn a_newer_live_file_is_adopted_inside_the_pacing_floor_without_a_post() {
        let dir = fixture_dir("w45");
        let old = arm(&dir);
        let io = mock(&dir);
        *io.outcome.lock().unwrap() = Ok(transient());
        let coord = CredentialCoordinator::new(cell(old, Some(NOW - 10), file_generation("a")), dir.to_path_buf());
        let t0 = Instant::now();

        refusal_of(coord.admit(NOW, t0, &*io), "the network failed");
        assert_eq!(io.posts(), 1);
        assert!(
            coord.snapshot().last_result.is_some(),
            "the floor is now running from that completion"
        );

        // Another writer (a mint, or a sibling process) put a LIVE credential on disk.
        io.set_disk("newer-live", Ok(live_credential(LIVE_UNTIL)));

        coord
            .admit(NOW, t0 + Duration::from_secs(1), &*io)
            .expect("one second later — deep inside the floor — the newer live file is adopted");
        assert_eq!(
            io.posts(),
            1,
            "the pacing floor gates POSTs, never lock-only reconciliations"
        );
        assert_eq!(coord.snapshot().file_gen, file_generation("newer-live"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -------------------------------------------------------------------------------------------
    // A held writer lock times out BOUNDED: a typed refusal that names the lock,
    // no POST, no hang. `token_refresh` owns the acquisition's own witness; this is the cell's.
    //
    // Mutation that proves it can fail: map the lock failure to `Cure::ReMint`.
    // -------------------------------------------------------------------------------------------
    #[test]
    fn cell_a_lock_timeout_refuses_with_a_retryable_cure_that_names_the_lock() {
        let dir = fixture_dir("w28");
        let old = arm(&dir);
        let io = mock(&dir);
        *io.lock_result.lock().unwrap() = Err(RefreshLocalError::LockTimeout {
            path: credential_lock_path(&dir),
            waited: CREDENTIAL_LOCK_DEADLINE,
        });
        let coord = CredentialCoordinator::new(cell(old, Some(NOW - 10), file_generation("a")), dir.to_path_buf());

        let (cure, reason) = refusal_of(
            coord.admit(NOW, Instant::now(), &*io),
            "a wave that cannot take the writer lock admits nobody",
        );
        assert_eq!(cure, Cure::RetryLater, "a contended lock is a WAIT: {reason}");
        assert!(reason.contains("credential lock at"), "the refusal names the lock: {reason}");
        assert!(reason.contains("nothing was written"), "{reason}");
        assert_eq!(io.posts(), 0, "no lock, no POST");
        assert!(io.persists.lock().unwrap().is_empty(), "and nothing was written");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -------------------------------------------------------------------------------------------
    // The LOCAL client-config cure: an exchange that fails BEFORE the wire because the OAuth client
    // file cannot be used is the operator's file to fix — cure `client_config`, never a re-mint.
    //
    // Mutation that proves it can fail: merge `ClientConfig` into the catch-all `Local(_) =>
    // Cure::RetryLater` arm.
    // -------------------------------------------------------------------------------------------
    #[test]
    fn a_local_client_config_failure_carries_the_client_config_cure_not_a_re_mint() {
        let dir = fixture_dir("clientcfg");
        let old = arm(&dir);
        let io = mock(&dir);
        *io.outcome.lock().unwrap() = Err(RefreshLocalError::ClientConfig(ClientConfigError {
            path: dir.join("client_secret.json"),
            shape: ClientConfigShape::Unreadable(std::io::ErrorKind::NotFound),
        }));
        let coord = CredentialCoordinator::new(cell(old, Some(NOW - 10), file_generation("a")), dir.to_path_buf());

        let (cure, reason) = refusal_of(coord.admit(NOW, Instant::now(), &*io), "no client, no renewal");
        assert_eq!(cure, Cure::ClientConfig, "the client file is the cure: {reason}");
        assert!(reason.contains("client_secret.json"), "the reason names the PATH: {reason}");
        assert!(
            !reason.contains("re-mint"),
            "a broken client entry is not cured by re-minting the same client: {reason}"
        );
        assert_eq!(
            coord.status_cure(NOW),
            Some(Cure::ClientConfig),
            "and the status surface reproduces the SAME cure from the SAME cell"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -------------------------------------------------------------------------------------------
    // THE FLOOR'S SCOPE IS DERIVED FROM THE TYPE, not from the report: the
    // floor paces TOKEN-ENDPOINT TRAFFIC, so it covers exactly the RememberedOutcome variants
    // that dialled the endpoint (Renewed, Failed(_)). A Local(_) failure spent no POST — pacing
    // it only delays the operator's own fix, and the paced branch's hardcoded RetryLater
    // contradicted the ClientConfig cure the cell itself retained.
    //
    // Before the fix: the second admission below was refused `RetryLater` by the floor.
    // -------------------------------------------------------------------------------------------
    #[test]
    fn a_local_failure_is_not_paced_by_the_floor() {
        let dir = fixture_dir("local-no-floor");
        let old = arm(&dir);
        let io = mock(&dir);
        *io.outcome.lock().unwrap() = Err(RefreshLocalError::ClientConfig(ClientConfigError {
            path: dir.join("client_secret.json"),
            shape: ClientConfigShape::Unreadable(std::io::ErrorKind::NotFound),
        }));
        let coord =
            CredentialCoordinator::new(cell(old, Some(NOW - 10), file_generation("a")), dir.to_path_buf());
        let (cure, _) = refusal_of(coord.admit(NOW, Instant::now(), &*io), "no client, no renewal");
        assert_eq!(cure, Cure::ClientConfig);

        // The operator fixes the file moments later; the next command must RETRY the local
        // steps immediately, not wait out a floor no local failure ever spent.
        *io.outcome.lock().unwrap() = Ok(renewed(LIVE_UNTIL));
        coord.admit(NOW, Instant::now(), &*io).expect(
            "a LOCAL failure spent no POST — pacing it delays the operator's own fix (the \
             floor's scope = the RememberedOutcome variants that dialled the endpoint)",
        );
        // The mock counts exchange ENTRIES (its local failure is scripted at the exchange seam),
        // so both admissions register — the discriminator is the second admission succeeding.
        assert_eq!(io.posts(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // (The former `a_failed_persist_keeps_the_old_arm_and_never_rebuilds` witness asserted the
    // earlier contract — "an unwritten renewal admits nobody" — which was later inverted:
    // discarding the in-memory survivor turned a write blip into a re-mint. Its replacement is
    // `a_failed_persist_with_a_rotation_publishes_the_survivor_in_memory_and_stamps_the_debt`
    // below.)

    // (An earlier witness `a_failed_persist_with_a_rotation_publishes_the_survivor_in_memory_
    // and_stamps_the_debt` asserted the publish-on-persist-failure arm, which was
    // REVERTED — the arm was surface beyond the design
    // whose debt the wire could not show. Its replacement is the restored witness
    // `a_failed_persist_refuses_keeps_the_old_arm_and_never_rebuilds` below.)

    // -------------------------------------------------------------------------------------------
    // A NEWER ON-DISK CREDENTIAL THAT CANNOT BE ADOPTED REFUSES LOUDLY. The
    // operator re-minted (disk generation changed) while the published cell was still live;
    // if the adoption fails (lock, rebuild), silently admitting the previously published arm
    // rides a superseded — possibly revoked — grant with nothing surfaced anywhere (a live
    // cell's status cure is None by construction, and before the fix the command succeeded).
    //
    // Before the fix: this admission returned Ok with the OLD arm.
    // -------------------------------------------------------------------------------------------
    #[test]
    fn a_failed_adoption_of_a_newer_on_disk_credential_refuses_instead_of_riding_the_old_arm() {
        let dir = fixture_dir("reconcile-loud");
        let old = arm(&dir);
        let io = mock(&dir);
        // Cell LIVE on generation "a"; the disk now shows "b", but the new credential cannot
        // be built into an arm.
        io.set_disk("b", Ok(expired_credential()));
        *io.rebuild_fail.lock().unwrap() = Some(RefreshLocalError::RebuildFailed {
            reason: "bad arm".to_string(),
        });
        let coord = CredentialCoordinator::new(
            cell(old, Some(LIVE_UNTIL), file_generation("a")),
            dir.to_path_buf(),
        );

        let (cure, reason) = refusal_of(
            coord.admit(NOW, Instant::now(), &*io),
            "a newer on-disk credential that cannot be adopted must refuse loudly, never \
             silently ride the superseded arm",
        );
        assert_eq!(cure, Cure::RetryLater, "{reason}");
        assert!(reason.contains("could not be adopted"), "{reason}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -------------------------------------------------------------------------------------------
    // A POST-SPENDING LOCAL FAILURE IS PACED. `WriteFailed`/`RenameFailed`
    // happen AFTER the exchange dialled the endpoint; deriving pacing from the error VARIANT
    // (the earlier `spent_a_post`) was the wrong level — a pre-wire `ClientConfig` and a post-POST
    // `WriteFailed` shared it, so a read-only disk turned sequential reads into an endpoint
    // storm that worsens rotation loss. The WAVE is the only authority on whether it dialled:
    // the fact is recorded on the stamp at the source (`RefreshStamp.spent_post`), and the
    // floor reads the record.
    //
    // Before the fix: the second admission below re-POSTed (posts == 2).
    // -------------------------------------------------------------------------------------------
    #[test]
    fn a_post_spending_local_failure_is_paced_by_the_floor() {
        let dir = fixture_dir("persist-paced");
        let old = arm(&dir);
        let io = mock(&dir);
        *io.persist_result.lock().unwrap() = Err(RefreshLocalError::WriteFailed {
            path: dir.join("gmail_readside_main_token.json"),
            reason: LocalIoReason(std::io::ErrorKind::PermissionDenied),
        });
        let coord = CredentialCoordinator::new(
            cell(old, Some(NOW - 10), file_generation("a")),
            dir.to_path_buf(),
        );
        let t0 = Instant::now();
        let (cure, _) = refusal_of(coord.admit(NOW, t0, &*io), "an unwritten renewal refuses");
        assert_eq!(cure, Cure::RetryLater);

        // Two seconds later, disk still broken: the retry must WAIT OUT the floor — its
        // renewal already dialled the endpoint once.
        let (cure2, reason2) =
            refusal_of(coord.admit(NOW, t0 + Duration::from_secs(2), &*io), "paced");
        assert_eq!(
            io.posts(),
            1,
            "the second admission is PACED — a failed WRITE does not license a second POST"
        );
        assert_eq!(cure2, Cure::RetryLater);
        assert!(reason2.contains("paced"), "{reason2}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -------------------------------------------------------------------------------------------
    // THE RESTORED CONTRACT: a persist-failure arm that
    // published on persist failure was surface beyond the design, and its debt was
    // invisible on the wire, so it is REVERTED: a persist that fails leaves
    // the old arm published, never rebuilds, and refuses with a retryable cure that says the
    // existing file is unchanged. The refusal IS the loudness — visible to the caller AND (via
    // the expired cell's cure) to the status surface.
    // -------------------------------------------------------------------------------------------
    #[test]
    fn a_failed_persist_refuses_keeps_the_old_arm_and_never_rebuilds() {
        let dir = fixture_dir("persistfail-revert");
        let old = arm(&dir);
        let old_ptr = arm_ptr(&old);
        let io = mock(&dir);
        *io.persist_result.lock().unwrap() = Err(RefreshLocalError::WriteFailed {
            path: dir.join("gmail_readside_main_token.json"),
            reason: LocalIoReason(std::io::ErrorKind::PermissionDenied),
        });
        let coord = CredentialCoordinator::new(
            cell(old, Some(NOW - 10), file_generation("a")),
            dir.to_path_buf(),
        );

        let (cure, reason) = refusal_of(
            coord.admit(NOW, Instant::now(), &*io),
            "an unwritten renewal admits nobody (§3-S4 restored)",
        );
        assert_eq!(cure, Cure::RetryLater, "{reason}");
        assert!(
            reason.contains("existing credential file is unchanged"),
            "the refusal states what was NOT done: {reason}"
        );
        assert_eq!(io.posts(), 1);
        assert_eq!(io.rebuilds(), 0, "a credential that was not written is never built into an arm");
        assert_eq!(
            arm_ptr(&coord.snapshot().provider),
            old_ptr,
            "the cell keeps the provider it had"
        );
        assert_eq!(
            coord.status_cure(NOW),
            Some(Cure::RetryLater),
            "the expired cell carries the cure — the debt is ON the wire, not hidden behind a \
             live publish"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -------------------------------------------------------------------------------------------
    // THE GRACE RECHECK SAMPLES THE CLOCK AT USE TIME. The caller's
    // `now_unix` ages across the lock wait + config load + HTTP round trip; comparing the
    // receipt-anchored `new_expiry` against that stale base silently shortens the safety margin
    // by the staleness (35 s elapsed + expires_in 30 ⇒ old_now+65 > old_now+60 ⇒ Live with 30 s
    // of real life). The recheck now samples `AdmitIo::now_unix()` at the comparison.
    // -------------------------------------------------------------------------------------------
    #[test]
    fn the_grace_recheck_uses_the_use_time_clock_not_the_admission_clock() {
        let dir = fixture_dir("grace-use-time");
        let old = arm(&dir);
        let io = mock(&dir);
        // 35 s of lock + HTTP elapse inside the wave: the use-time clock is NOW+35, and the
        // provider's grant dies 30 s after receipt.
        *io.now_unix.lock().unwrap() = NOW + 35;
        *io.outcome.lock().unwrap() = Ok(renewed(NOW + 65));
        *io.persist_gen.lock().unwrap() = file_generation("short-late");
        let coord = CredentialCoordinator::new(
            cell(old, Some(NOW - 10), file_generation("a")),
            dir.to_path_buf(),
        );

        let (cure, reason) = refusal_of(
            coord.admit(NOW, Instant::now(), &*io),
            "a grant with 30 s of real life is inside the 60 s margin — the recheck must see \
             the USE-TIME clock, not the admission clock",
        );
        assert_eq!(cure, Cure::RetryLater, "{reason}");
        assert!(reason.contains("safety margin"), "{reason}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -------------------------------------------------------------------------------------------
    // A LATCH KEYED TO A FILE THE CURE NEVER TOUCHES CANNOT RELEASE. The
    // admin grants access in the Cloud console; no token-file digest moves. The externally-cured
    // terminals (ClientConfig · ProviderPolicy · InvalidScope) are therefore PACED under the
    // floor — one re-probe per command outside 30 s — instead of latched to the token file
    // (the re-mint family stays file-latched, its cure medium IS
    // the file).
    // -------------------------------------------------------------------------------------------
    #[test]
    fn an_externally_cured_terminal_is_paced_not_latched_to_a_file_it_cannot_observe() {
        let dir = fixture_dir("policy-paced");
        let old = arm(&dir);
        let io = mock(&dir);
        *io.outcome.lock().unwrap() = Ok(RefreshOutcome::ProviderPolicy {
            code: Sanitized::new("access_denied"),
        });
        let coord = CredentialCoordinator::new(
            cell(old, Some(NOW - 10), file_generation("a")),
            dir.to_path_buf(),
        );
        let t0 = Instant::now();
        let (cure, _) = refusal_of(coord.admit(NOW, t0, &*io), "policy refuses");
        assert_eq!(cure, Cure::AdminPolicy);

        // The admin applies the cure console-side; after the floor the next command RE-PROBES.
        *io.outcome.lock().unwrap() = Ok(renewed(LIVE_UNTIL));
        coord
            .admit(NOW, t0 + REFRESH_ATTEMPT_FLOOR + Duration::from_secs(1), &*io)
            .expect(
                "the console-side cure is applied; a paced re-probe picks it up without a \
                 re-mint or a restart",
            );
        assert_eq!(io.posts(), 2, "one probe per admission outside the floor — paced, not latched");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ===========================================================================================
    // THE DESIGN'S DOORS. The recut claim, witnessed.
    // ===========================================================================================

    // -------------------------------------------------------------------------------------------
    // A LIVE READ ARM IS RE-VALIDATED AT THE NEXT RECONCILE.
    //
    // The admission-EXIT ratchet gate is REVERTED. What replaces it is not a
    // weaker check: it is the design's own doors — credential load / arm construction,
    // token refresh, and send admission. This witness pins the READ side of
    // the recut claim in both directions, so the acceptance is a fact in the suite rather than a
    // sentence in a doc:
    //
    //   PREMISE (ACCEPTED and NAMED): the ratchet moves to 2 while the credential file
    //   is byte-identical. Nothing reconciles, so the live generation-1 READ arm keeps serving —
    //   bounded by the access-token lifetime, and no WRITE can ride it (the mutation fence
    //   today; send admission after it).
    //
    //   THE DOOR: the moment the re-consent's credential actually LANDS (a new digest), the
    //   next admission reconciles under the writer lock, rebuilds, and publishes the
    //   generation-2 arm. The stale arm is gone without a restart and without an exit gate.
    //
    // Before the exit gate was reverted, this test failed:
    //   thread '...a_live_read_arm_is_revalidated_at_the_next_reconcile'
    //   panicked at src\credential_cell.rs:3131:14:
    //   R-S0-13, NAMED: a live READ arm under a since-retired generation is accepted:
    //   CredentialExpired { expires_at: 1700003600, cure: ReMint, reason: "the parked Gmail
    //   credential was minted under grant 1, but a later consent (grant 2) is recorded at
    // ...\grant_high_water.json; this credential has been retired and Photon will not use it
    //   — re-mint via scripts/gmail_drill_mint.py to consent again." }
    //
    // That failure is the exit gate doing exactly what it was built to do, and it is the shape
    // that was reverted: the refusal is real, but it is a per-command re-validation of a LIVE READ
    // arm, which was never a design property — and repeated findings landed on
    // the machinery that produced it rather than on the product.
    // -------------------------------------------------------------------------------------------
    #[test]
    fn a_live_read_arm_is_revalidated_at_the_next_reconcile() {
        let dir = fixture_dir("f3-design-doors");
        let io = mock(&dir);
        let published = arm(&dir);
        let published_ptr = arm_ptr(&published);
        let coord = CredentialCoordinator::new(
            cell(published, Some(LIVE_UNTIL), file_generation("a")),
            dir.to_path_buf(),
        );
        // A re-consent RESERVED generation 2 (the mint reserves before it publishes). The
        // credential file has not changed yet — the new bytes are still being written.
        std::fs::write(
            dir.join(GRANT_HIGH_WATER_FILE_NAME),
            b"{\"grant_generation\":2}\n",
        )
        .expect("the later consent's reservation");

        let still_serving = coord
            .admit(NOW, Instant::now(), io.as_ref())
            .expect("R-S0-13, NAMED: a live READ arm under a since-retired generation is accepted");
        assert_eq!(
            Arc::as_ptr(&still_serving) as usize,
            published_ptr,
            "the premise of the acceptance: nothing reconciled, so it is the SAME arm"
        );

        // Now the re-consent's credential lands: new bytes, new digest, generation 2.
        let mut reconsented = live_credential(LIVE_UNTIL);
        reconsented.grant.grant_generation = 2;
        io.set_disk("b", Ok(reconsented));

        let readmitted = coord
            .admit(NOW, Instant::now(), io.as_ref())
            .expect("the reconcile adopts the landed re-consent");
        let rebuilt_ptr = arm_ptr(&io.rebuild_arm.lock().unwrap());
        assert_ne!(published_ptr, rebuilt_ptr, "the fixture's two arms are distinct");
        assert_eq!(
            Arc::as_ptr(&readmitted) as usize,
            rebuilt_ptr,
            "THE DOOR: the next admission re-validated the arm by rebuilding it from the landed \
             credential — the generation-1 arm is gone without a restart"
        );
        assert_eq!(
            coord.snapshot().grant_generation,
            Some(2),
            "and the published cell now carries the CURRENT consent, so the status surface \
             (RK7b/RK7c) reports it truthfully"
        );
        assert_eq!(io.posts(), 0, "a reconcile is an adoption, never a token-endpoint dial");
        assert_eq!(io.rebuilds(), 1, "exactly one rebuild — the adoption's own");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ===========================================================================================
    // A census is a flashlight, not a fence — EVERY
    // USER-REACHING REASON STRING IS PINNED TO ITS EXACT SENTENCE.
    //
    // RESIDUAL, NAMED: Label honesty (no sentence predicts a door, asserts a refresh history, or
    // over-claims) is enforced at these sites by exact-literal pins reviewed by a human, not by
    // any predicate or census; a NEW false claim is not automatically caught
    // (the earlier word-list fences were deleted).
    //
    // WHAT WAS HERE, AND WHY IT IS GONE: an earlier version ran a seven-fragment word-list
    // (`DOOR_PREDICTION_FRAGMENTS = ["next command", "will retry", "will be retried", "recheck",
    // "re-check", "refresh the", "restart"]`) over every collected sentence and asserted no hit.
    // That is a CENSUS over an unbounded space — the English phrasings of "a door will run
    // next" — so a green run read as a coverage guarantee the seven fragments never gave. It
    // found its instances (the ten sites rewritten); it is not a fence.
    //
    // WHAT REPLACES IT: the SAME constructor-driven enumeration — every `RefreshLocalError`
    // variant through `reason_sentence()`, every `RefreshOutcome` variant and every
    // `TransientKind` through `reason_sentence()`/`transient_sentence()`, and the coordinator's
    // own four sentences reached by driving REAL `admit` runs — but each row is now compared to
    // its EXACT expected sentence, in order, against `EXACT_SENTENCE_PINS`. Enumerating from the
    // type is still what makes a new variant impossible to add silently: a new variant changes
    // the row count and the pin table goes RED at the byte.
    //
    // THE TEN SITES REWRITTEN, all pinned below: the adopt-failure
    // wrapper, the paced refusal, the grace-margin refusal; and in `token_refresh.rs`:
    // `UnknownDenied`, `transient_sentence`, `RebuildFailed`,
    // `ClientBuild`, `CommitUncertain` (both arms) and `FileGenUnreadable`.
    // Plus the documented KEEP: `boot_reason_sentence()` names a
    // RESTART because the actor is the OPERATOR, not a Photon door
    // (boot runs once and no door re-enters it) — pinned here as its whole exact sentence.
    //
    // THE ONE FIELD THAT IS NOT PINNED, and why: the paced refusal interpolates
    // `now.duration_since(stamp.completed_at).as_secs()`, which is measured wall-clock DATA, not
    // copy — its value depends on how long the first admission took. `normalize_elapsed` folds
    // that one integer to `{n}` before the comparison; every other byte of both paced rows,
    // including the streak clause, is pinned literally.
    // ===========================================================================================

    /// Every sentence the enumeration below produces, pinned literally, in enumeration order.
    /// A wording change goes RED at the byte; a NEW false claim goes to human review.
    const EXACT_SENTENCE_PINS: [(&str, &str); 33] = [
        (
            "RefreshLocalError::LockTimeout",
            "the credential lock at gmail_token.json was held by another writer for the whole 5000 ms budget; nothing was written. Retry your command — if it persists, a mint script may be wedged.",
        ),
        (
            "RefreshLocalError::LockUnavailable",
            "the credential lock at gmail_token.json could not be opened (PermissionDenied); nothing was written.",
        ),
        (
            "RefreshLocalError::WriteFailed",
            "the renewed credential could not be written near gmail_token.json (PermissionDenied); the existing credential file is unchanged.",
        ),
        (
            "RefreshLocalError::RenameFailed",
            "the renewed credential could not replace gmail_token.json (PermissionDenied); the existing credential file is unchanged.",
        ),
        (
            "RefreshLocalError::RebuildFailed",
            "the credential was renewed and written, but the Gmail provider could not be rebuilt from it (bad arm); the credential on disk is the renewed one and the provider in memory is still the previous one.",
        ),
        (
            "RefreshLocalError::ClientBuild",
            "the refresh HTTP client could not be built (no TLS backend); nothing was sent and nothing was written.",
        ),
        (
            "RefreshLocalError::CommitUncertain{observed_replaced:true}",
            "the renewed credential replaced gmail_token.json, but the write did not complete cleanly (durability unconfirmed); Photon did not advance the published provider onto it.",
        ),
        (
            "RefreshLocalError::CommitUncertain{observed_replaced:false}",
            "the credential write at gmail_token.json failed and the on-disk state could not be read to establish which side of the replace it stopped on; Photon did not advance the published provider onto it.",
        ),
        (
            "RefreshLocalError::ClientConfig",
            "the OAuth client file at gmail_token.json cannot be used: it is not valid JSON.",
        ),
        (
            "RefreshLocalError::GrantRetired",
            "the parked Gmail credential was minted under grant 1, but a later consent (grant 2) is recorded at gmail_token.json; this credential has been retired and Photon will not use it — re-mint via scripts/gmail_drill_mint.py to consent again.",
        ),
        (
            "RefreshLocalError::GrantHighWaterUnusable",
            "the grant record at gmail_token.json cannot be used: its top level is not a JSON object. Photon refuses rather than treat an unreadable record as an empty one — that would re-admit a retired credential. Nothing was changed.",
        ),
        (
            "RefreshLocalError::GrantHighWaterWriteFailed",
            "this credential's grant could not be recorded at gmail_token.json (PermissionDenied), so Photon did not admit it: a grant it cannot record is one it could not later retire. Nothing was changed.",
        ),
        (
            "RefreshLocalError::AdmissionLockMismatch",
            "the credential admission for gmail_token.json was handed a lock guarding no directory instead, so the                  grant record could not be read and raised under the lock that serializes it;                  nothing was changed. This is an internal fault, not a state your credential is                  in.",
        ),
        (
            "RefreshLocalError::FileGenUnreadable",
            "the credential file's generation could not be read (PermissionDenied); nothing was dialled and nothing was changed.",
        ),
        (
            "RefreshOutcome::Renewed",
            "the Gmail credential was renewed; it expires at 1700003600 (unix seconds)",
        ),
        (
            "RefreshOutcome::AuthorityMismatch",
            "the provider returned a grant whose authority is not the one on record — missing: read + triage authority; unexpected: none. Re-mint via scripts/gmail_drill_mint.py to consent again with the authority Photon runs under.",
        ),
        (
            "RefreshOutcome::ReauthRequired",
            "the provider refused the refresh token (invalid_grant, subtype token_expired); reauthorization is required — re-mint via scripts/gmail_drill_mint.py, which runs a fresh consent session.",
        ),
        (
            "RefreshOutcome::MissingRefreshToken",
            "the Gmail credential file carries no refresh token, so Photon has nothing to renew it with — re-mint via scripts/gmail_drill_mint.py.",
        ),
        (
            "RefreshOutcome::ClientConfig",
            "the provider refused this app's OAuth client configuration (invalid_client); the client_secret.json entry and its Google Cloud console client must be corrected — re-minting the same client cannot cure it.",
        ),
        (
            "RefreshOutcome::ProviderPolicy(access_denied)",
            "the provider refused under account or administrator policy (access_denied); an administrator must grant this app access — neither a retry nor a re-mint cures it.",
        ),
        (
            "RefreshOutcome::ProviderPolicy(org_internal)",
            "the OAuth client is restricted to an organization this grant's account is not in (org_internal); retrying will not change it — consent with an account inside that organization, or the app's audience configuration must change.",
        ),
        (
            "RefreshOutcome::InvalidScope",
            "the provider refused the credential's scope configuration (invalid_scope); developer/console review is required. What cures it is not established by the provider's response, so nothing further is asserted.",
        ),
        (
            "RefreshOutcome::UnknownDenied(coded)",
            "the provider refused with HTTP 418 and error code teapot; paced — no credential was renewed and nothing was written. A 4xx proves the endpoint was reached — if it persists, review the provider response, not the network.",
        ),
        (
            "RefreshOutcome::UnknownDenied(uncoded)",
            "the provider refused with HTTP 418 and no error code; paced — no credential was renewed and nothing was written. A 4xx proves the endpoint was reached — if it persists, review the provider response, not the network.",
        ),
        (
            "RefreshOutcome::Transient(Network)",
            "the token endpoint could not be reached (network failure); paced — no credential was renewed and nothing was written.",
        ),
        (
            "RefreshOutcome::Transient(ServerError(503))",
            "the token endpoint returned HTTP 503; paced — no credential was renewed and nothing was written.",
        ),
        (
            "RefreshOutcome::Transient(RateLimited(429))",
            "the token endpoint rate-limited this app (HTTP 429); paced — no credential was renewed and nothing was written.",
        ),
        (
            "RefreshOutcome::Transient(ProviderTransient(Sanitized(rate_limit_exceeded)))",
            "the token endpoint reported a transient condition (rate_limit_exceeded); paced — no credential was renewed and nothing was written.",
        ),
        (
            "RefreshOutcome::Transient(ContractViolation(ExpiresInAbsent))",
            "the token endpoint's response broke the response contract (no expires_in); paced — no credential was renewed and nothing was written.",
        ),
        (
            "CredentialCoordinator — a newer credential could not be adopted",
            "a newer credential is on disk but could not be adopted (the credential was renewed and written, but the Gmail provider could not be rebuilt from it (bad arm); the credential on disk is the renewed one and the provider in memory is still the previous one.); nothing was replaced, and Photon refused rather than serve the superseded credential",
        ),
        (
            "CredentialCoordinator — the paced refusal",
            "renewal is paced — the previous attempt finished {n}s ago (the token endpoint could not be reached (network failure); paced — no credential was renewed and nothing was written.); no renewal was attempted and nothing was written",
        ),
        (
            "CredentialCoordinator — the paced refusal, streak arm",
            "renewal is paced — the previous attempt finished {n}s ago (the token endpoint could not be reached (network failure); paced — no credential was renewed and nothing was written.); no renewal was attempted and nothing was written; this is 3 paced attempts in a row without a usable renewal — if it persists, retrying alone is unlikely to fix it (see the reason above)",
        ),
        (
            "CredentialCoordinator — the grace-margin refusal",
            "the provider renewed the credential, but the new grant expires within Photon's 60s safety margin; the renewal was written and published, and Photon refused this admission rather than hand out a token that can die mid-flight",
        ),
    ];

    /// The paced refusal's elapsed-seconds integer is measured wall-clock data, not copy. Fold
    /// it to `{n}` so the pin covers the SENTENCE and nothing else.
    fn normalize_elapsed(label: &str, sentence: &str) -> String {
        if !label.starts_with("CredentialCoordinator — the paced refusal") {
            return sentence.to_string();
        }
        match sentence.split_once("the previous attempt finished ") {
            Some((head, rest)) => match rest.split_once("s ago (") {
                Some((_secs, tail)) => {
                    format!("{head}the previous attempt finished {{n}}s ago ({tail}")
                }
                None => sentence.to_string(),
            },
            None => sentence.to_string(),
        }
    }

    #[test]
    fn every_user_reaching_reason_string_is_pinned_to_its_exact_sentence() {
        use crate::token_refresh::{ContractViolation, GrantHighWaterShape, ScopeSet};

        let path = PathBuf::from("gmail_token.json");
        let io_reason = LocalIoReason(std::io::ErrorKind::PermissionDenied);
        let mut rows: Vec<(String, String)> = Vec::new();

        // (a) EVERY `RefreshLocalError` variant, through `reason_sentence()`.
        for (label, e) in [
            (
                "RefreshLocalError::LockTimeout",
                RefreshLocalError::LockTimeout {
                    path: path.clone(),
                    waited: Duration::from_millis(5_000),
                },
            ),
            (
                "RefreshLocalError::LockUnavailable",
                RefreshLocalError::LockUnavailable {
                    path: path.clone(),
                    reason: io_reason,
                },
            ),
            (
                "RefreshLocalError::WriteFailed",
                RefreshLocalError::WriteFailed {
                    path: path.clone(),
                    reason: io_reason,
                },
            ),
            (
                "RefreshLocalError::RenameFailed",
                RefreshLocalError::RenameFailed {
                    path: path.clone(),
                    reason: io_reason,
                },
            ),
            (
                "RefreshLocalError::RebuildFailed",
                RefreshLocalError::RebuildFailed {
                    reason: "bad arm".to_string(),
                },
            ),
            ("RefreshLocalError::ClientBuild", RefreshLocalError::ClientBuild),
            (
                "RefreshLocalError::CommitUncertain{observed_replaced:true}",
                RefreshLocalError::CommitUncertain {
                    path: path.clone(),
                    observed_replaced: true,
                },
            ),
            (
                "RefreshLocalError::CommitUncertain{observed_replaced:false}",
                RefreshLocalError::CommitUncertain {
                    path: path.clone(),
                    observed_replaced: false,
                },
            ),
            (
                "RefreshLocalError::ClientConfig",
                RefreshLocalError::ClientConfig(ClientConfigError {
                    path: path.clone(),
                    shape: ClientConfigShape::NotJson,
                }),
            ),
            (
                "RefreshLocalError::GrantRetired",
                RefreshLocalError::GrantRetired {
                    path: path.clone(),
                    credential_generation: 1,
                    high_water: 2,
                },
            ),
            (
                "RefreshLocalError::GrantHighWaterUnusable",
                RefreshLocalError::GrantHighWaterUnusable {
                    path: path.clone(),
                    shape: GrantHighWaterShape::NotAnObject,
                },
            ),
            (
                "RefreshLocalError::GrantHighWaterWriteFailed",
                RefreshLocalError::GrantHighWaterWriteFailed {
                    path: path.clone(),
                    reason: io_reason,
                },
            ),
            (
                "RefreshLocalError::AdmissionLockMismatch",
                RefreshLocalError::AdmissionLockMismatch {
                    held: None,
                    secrets_dir: path.clone(),
                },
            ),
            (
                "RefreshLocalError::FileGenUnreadable",
                RefreshLocalError::FileGenUnreadable { reason: io_reason },
            ),
        ] {
            rows.push((label.to_string(), e.reason_sentence()));
        }

        // (b) EVERY `RefreshOutcome` variant, through `reason_sentence()` — the wave's remembered
        //     sentence is what the refusal quotes.
        for (label, o) in [
            ("RefreshOutcome::Renewed", renewed(LIVE_UNTIL)),
            (
                "RefreshOutcome::AuthorityMismatch",
                RefreshOutcome::AuthorityMismatch {
                    missing: ScopeSet::new([MODIFY.to_string()].into_iter().collect()),
                    unexpected: ScopeSet::new(std::collections::BTreeSet::new()),
                },
            ),
            (
                "RefreshOutcome::ReauthRequired",
                RefreshOutcome::ReauthRequired {
                    subtype: Some(Sanitized::new("token_expired")),
                },
            ),
            (
                "RefreshOutcome::MissingRefreshToken",
                RefreshOutcome::MissingRefreshToken,
            ),
            (
                "RefreshOutcome::ClientConfig",
                RefreshOutcome::ClientConfig {
                    code: Sanitized::new("invalid_client"),
                },
            ),
            (
                "RefreshOutcome::ProviderPolicy(access_denied)",
                RefreshOutcome::ProviderPolicy {
                    code: Sanitized::new("access_denied"),
                },
            ),
            (
                "RefreshOutcome::ProviderPolicy(org_internal)",
                RefreshOutcome::ProviderPolicy {
                    code: Sanitized::new("org_internal"),
                },
            ),
            ("RefreshOutcome::InvalidScope", RefreshOutcome::InvalidScope),
            (
                "RefreshOutcome::UnknownDenied(coded)",
                RefreshOutcome::UnknownDenied {
                    status: 418,
                    code: Some(Sanitized::new("teapot")),
                },
            ),
            (
                "RefreshOutcome::UnknownDenied(uncoded)",
                RefreshOutcome::UnknownDenied {
                    status: 418,
                    code: None,
                },
            ),
        ] {
            rows.push((label.to_string(), o.reason_sentence()));
        }

        // …and every transient KIND, because the transient sentence is assembled per kind.
        for kind in [
            TransientKind::Network,
            TransientKind::ServerError(503),
            TransientKind::RateLimited(429),
            TransientKind::ProviderTransient(Sanitized::new("rate_limit_exceeded")),
            TransientKind::ContractViolation(ContractViolation::ExpiresInAbsent),
        ] {
            rows.push((
                format!("RefreshOutcome::Transient({kind:?})"),
                RefreshOutcome::Transient { kind }.reason_sentence(),
            ));
        }

        // (c) The COORDINATOR's own three sentences, reached by driving REAL admissions.
        {
            let dir = fixture_dir("f16b-adopt");
            let old = arm(&dir);
            let io = mock(&dir);
            io.set_disk("b", Ok(expired_credential()));
            *io.rebuild_fail.lock().unwrap() = Some(RefreshLocalError::RebuildFailed {
                reason: "bad arm".to_string(),
            });
            let coord = CredentialCoordinator::new(
                cell(old, Some(LIVE_UNTIL), file_generation("a")),
                dir.to_path_buf(),
            );
            let (_, reason) = refusal_of(
                coord.admit(NOW, Instant::now(), &*io),
                "a newer on-disk credential that cannot be adopted refuses loudly",
            );
            rows.push((
                "CredentialCoordinator — a newer credential could not be adopted".to_string(),
                reason,
            ));
            let _ = std::fs::remove_dir_all(&dir);
        }
        {
            let dir = fixture_dir("f16b-paced");
            let old = arm(&dir);
            let io = mock(&dir);
            *io.outcome.lock().unwrap() = Ok(transient());
            let coord = CredentialCoordinator::new(
                cell(old, Some(NOW - 10), file_generation("a")),
                dir.to_path_buf(),
            );
            let t0 = Instant::now();
            let _ = refusal_of(coord.admit(NOW, t0, &*io), "the transient wave refuses");
            let (_, paced) = refusal_of(
                coord.admit(NOW + 5, t0 + Duration::from_secs(5), &*io),
                "inside the floor the refusal is PACED",
            );
            assert!(paced.contains("renewal is paced"), "{paced}");
            rows.push(("CredentialCoordinator — the paced refusal".to_string(), paced));

            // …and the AGGREGATE arm of the same literal (the `{streak}` suffix, at three).
            coord.publish(|c| {
                if let Some(stamp) = c.last_result.as_mut() {
                    stamp.failures_in_a_row = 3;
                }
            });
            let (_, streak) = refusal_of(
                coord.admit(NOW + 6, t0 + Duration::from_secs(6), &*io),
                "the paced refusal still refuses at the streak",
            );
            assert!(
                streak.contains("paced attempts in a row"),
                "the streak arm is the one measured here: {streak}"
            );
            rows.push((
                "CredentialCoordinator — the paced refusal, streak arm".to_string(),
                streak,
            ));
            let _ = std::fs::remove_dir_all(&dir);
        }
        {
            let dir = fixture_dir("f16b-grace");
            let old = arm(&dir);
            let io = mock(&dir);
            *io.outcome.lock().unwrap() =
                Ok(renewed(NOW + crate::CREDENTIAL_EXPIRY_GRACE_SECS / 2));
            *io.persist_gen.lock().unwrap() = file_generation("short");
            let coord =
                CredentialCoordinator::new(cell(old, Some(NOW - 10), file_generation("a")), dir.to_path_buf());
            let (_, reason) = refusal_of(
                coord.admit(NOW, Instant::now(), &*io),
                "a renewal landing inside the grace margin refuses",
            );
            assert!(reason.contains("safety margin"), "{reason}");
            rows.push((
                "CredentialCoordinator — the grace-margin refusal".to_string(),
                reason,
            ));
            let _ = std::fs::remove_dir_all(&dir);
        }

        assert_eq!(
            rows.len(),
            EXACT_SENTENCE_PINS.len(),
            "the enumeration is driven from the TYPES: a variant was added or removed, so the \
             exact-sentence pins must be re-cut for it. Collected:\n{}",
            rows.iter()
                .map(|(l, s)| format!("  {l}\n      {s}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
        for ((label, sentence), (pinned_label, pinned_sentence)) in
            rows.iter().zip(EXACT_SENTENCE_PINS)
        {
            assert_eq!(
                label, pinned_label,
                "the enumeration order changed — re-cut the pins in order"
            );
            assert_eq!(
                normalize_elapsed(label, sentence),
                pinned_sentence,
                "{label}: the user-reaching sentence changed. A label mirrors STATE and never \
                 says what a door will do next (§4w/§4y); this pin is the review record of the \
                 wording that was checked, not a predicate that can vet a new one."
            );
        }

        // THE DOCUMENTED KEEP, pinned whole rather than exempted: the BOOT lock-timeout sentence
        // names a RESTART because the actor is the OPERATOR, not a Photon door — boot runs once
        // and no door re-enters it (pinned in `lib.rs`'s
        // boot lock-timeout witness).
        let boot = RefreshLocalError::LockTimeout {
            path,
            waited: Duration::from_millis(5_000),
        }
        .boot_reason_sentence();
        assert_eq!(
            boot,
            "Photon started while another writer (the mint script) held the credential lock at \
             gmail_token.json for the whole 5000 ms budget; nothing was written. Restart Photon \
             once the mint has finished.",
            "the boot sentence names the operator's act, and only that"
        );
    }
}
