//! The session status view and the on-disk grant derivation behind it.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::credential::{credential_expired_at, parse_gmail_credential};
use crate::provider::{mutation_fence, Provider};
use crate::state::PhotonState;
use crate::token_refresh::{self, Cure, FileGen, CREDENTIAL_FILE_NAME};
use crate::ProviderKind;

/// What the session is, including the ways it is not working.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionStatus {
    pub provider_kind: ProviderKind,
    pub account: String,
    pub store_path: String,
    /// Both halves must be true for a command to do its job; the reasons say which one is not.
    pub configured: bool,
    pub store_reason: Option<String>,
    /// Why there is no usable provider arm, and the frontend's stage discriminant for
    /// [`SessionStatus::credential_cure`]. `session_status_view` sets it with every boot-stage
    /// cure (a cell that published no arm, and the grant ratchet's `Retired`/`Undetermined`
    /// verdict); `None` means the cell is armed, so the cure beside it can only be the refresh
    /// stage's stamp. `configured` cannot answer that: it is also `false` when the store would not
    /// open, which says nothing about the credential.
    pub provider_reason: Option<String>,
    /// The mint's expiry stamp, when the credential file carried one, read from the published
    /// credential cell (the same cell admission reads).
    pub credential_expires_at: Option<i64>,
    /// Has that stamp passed? Its own axis beside `configured` and `mutations_live`: `configured`
    /// means the store and the arm are constructible, so an expired credential (dead at startup
    /// or aged out mid-session) is `configured: true` with this flag set and
    /// [`SessionStatus::credential_cure`] naming what happens next. It uses the same
    /// [`CREDENTIAL_EXPIRY_GRACE_SECS`] margin as the renewal trigger, so the badge and the
    /// refusal cannot disagree.
    pub credential_expired: bool,
    /// The cell's current cure: `None` exactly when the credential is live; `Some(RetryLater)` for
    /// a credential that is expired but has not had a renewal attempted yet (the app renews it on
    /// the next command, never a re-mint demand); otherwise the last attempt's cure. The frontend
    /// branches on this, not on a hard-coded sentence.
    pub credential_cure: Option<Cure>,
    /// The kill-switch/epoch half of [`SessionStatus`] (BLACK is a status, not a control).
    ///
    /// The current `control_epoch` from `SqliteIntentLog::control_epoch`, the same singleton every
    /// internal fence reads. `None` only when the store read fails (no session, or a live read
    /// error), and [`SessionStatus::epoch_reason`] says why. Severed state still surfaces
    /// per-operation through `undo_presentation` (`AppliedUndoSevered`): this field answers "what
    /// epoch", not "was this operation severed".
    pub epoch: Option<i64>,
    /// Set exactly when `epoch` is `None`: the store-unavailable reason or the live read's own
    /// error, never a placeholder.
    pub epoch_reason: Option<String>,
    /// Whether a verb can reach the provider in this build. `false` on the production Gmail arm,
    /// where writes are fence-gated; staying silent about that would invite the UI to offer
    /// buttons the engine always refuses.
    ///
    /// `configured` and this field answer different questions ("is the session usable at all"
    /// versus "can it mutate"), and reads are live on an arm where this is `false`.
    pub mutations_live: bool,
    /// Set exactly when `mutations_live` is `false`: the named fence
    /// ([`MUTATIONS_FENCED_REASON`]) or the unconfigured arm's own reason. As with
    /// `epoch`/`epoch_reason`, a `false` never travels without its why.
    pub mutations_reason: Option<String>,
}

/// The sentence an unconfigured session reports once the fix is already on disk. It replaces the
/// boot refusal's sentence, which describes a superseded state, with the one thing this side of
/// the app can observe: a usable credential is on disk and no arm has been built from it yet.
///
/// It mirrors the observation and promises nothing about which command adopts it, because both
/// obvious promises are wrong:
///
/// - "Photon adopts it on your next command" is false for the acting commands: `run_verb`,
///   `undo` and `undo_presentation` reach the arm through [`PhotonState::gmail`], which never
///   calls [`CredentialCoordinator::admit`], so the same verb can be re-run forever and adopt
///   nothing.
/// - "refresh the inbox to adopt it" names the one path that does admit ([`admit_provider`], then
///   [`CredentialCoordinator::admit`], the unarmed cell reconciling with no token-endpoint POST),
///   but is false whenever an earlier guard in that path refuses. `refresh_inbox` runs five before
///   the credential check:
///   1. [`PhotonState::account`]: transient; it refuses a partition this session does not serve.
///   2. The single-flight claim: transient, released on drop.
///   3. [`Pacing::admit`]: transient; the cadence floor and provider backoff both expire.
///   4. `state.session()?`: permanent. [`PhotonState::session`] refuses whenever `self.session`
///      is `None` (the store failed to open), and nothing reopens it. A boot with an unopenable
///      store plus a landed credential can never reach the reconcile by refreshing.
///   5. [`PhotonState::refresh_armed`] inside [`admit_provider`]: permanent and config-derived,
///      but handled upstream, since [`PhotonState::grant_on_disk`] answers
///      [`GrantOnDisk::unarmed`] for such a session, so `landed` is `None` and this sentence is
///      never reached.
///
///   (`refresh_more_inbox` and `message_body` add one more local prerequisite each.)
///
/// Which command adopts is the command contract's business, and what to do about a store that
/// will not open is the runbook's.
///
/// The prose above is markdown, not a Rust example: indented four spaces or more past the `///`
/// it is read as a code block and compiled as a doctest, which fails `cargo test --locked`.
pub(crate) const ADOPTION_PENDING_REASON: &str = "a credential has landed; Photon has not adopted it yet";

/// The `(cure, reason)` pair every surface that speaks for a cell with no arm must report:
/// [`session_status_view`]'s status bar, the same view's `mutations_reason`, and
/// [`PhotonState::gmail`]'s refusal (verb, undo, undo_presentation).
///
/// This labels; it does not admit. It reads the disk and publishes nothing. The provider-read path
/// admits ([`admit_provider`], then [`CredentialCoordinator::admit`]) and the acting commands do
/// not, so a label cannot speak for a command it does not stand in for: it promises neither "your
/// next command" nor "refresh the inbox" (see [`ADOPTION_PENDING_REASON`]).
///
/// "A landed replacement has already applied the demanded re-mint" is applied by two other rules,
/// inside [`GrantOnDisk::verdict`] for the retirement and inside `CredentialCell::status_cure` for
/// the stamp. Each is keyed to a generation the cell published and needs the digest conjuncts that
/// go with it. A cell that published no arm has no generation for the verdict to judge (it answers
/// `Silent`) and no digest for the stamp suppression to compare against, so its own recorded cure
/// (a `re_mint` for every load-path refusal) would reach the bar untouched. After an external
/// mint, the operator would be sent through a second 300 s consent for a credential the very next
/// command adopts with zero POSTs.
///
/// A bare `landed` is the right test here and only here. It means "a plausibly usable credential
/// is on disk", and it is `Some` even for the bytes a provider `ReauthRequired` latch was recorded
/// against, which is why the stamp's suppression keeps its digest conjuncts. This cell has no
/// digest to compare (`file_gen: None`, `grant_generation: None`; see
/// `CredentialCell::unconfigured`), so it has judged nothing yet.
///
/// Only a re-mint-class cure is suppressed: the defect is a redundant consent, and other boot
/// cures are not demands the disk can answer. A boot-lock timeout reports `RetryLater` while a good
/// credential sits on disk, which is true since the next command may fail to take the lock again;
/// [`ADOPTION_PENDING_REASON`] there would assert a landing nothing has established. The predicate
/// is read off the cure map (`Cure::ReMint`), not a hand-listed set of producers, and the census
/// test in this file pins the finite set of producers behind it.
///
/// What it says is the observation it just made (a usable credential is on disk, no arm has been
/// built from it) and no command, since the one that admits has pre-admit guards, one of which
/// ([`PhotonState::session`]) refuses for the life of the process once the store failed to open.
pub(crate) fn unconfigured_verdict(
    reason: &str,
    cure: Option<Cure>,
    grant: &GrantOnDisk,
) -> (Option<Cure>, String) {
    if cure == Some(Cure::ReMint) && grant.landed.is_some() {
        return (None, ADOPTION_PENDING_REASON.to_string());
    }
    (cure, reason.to_string())
}

/// The synchronous half of [`session_status`]: every field except the two the epoch read
/// produces, which is the only part of that command that touches the store.
///
/// It is a separate function because `tauri::State` has no constructor outside a running app, so
/// the async command is not unit-testable. This is the seam its tests reach through, and the
/// command is a two-line wrapper over it, so there is no second copy of the field mapping to
/// drift.
pub(crate) fn session_status_view(
    state: &PhotonState,
    epoch: Option<i64>,
    epoch_reason: Option<String>,
    now_unix_secs: i64,
) -> SessionStatus {
    // One cell read for every credential-derived field (provider, stamp, expiry flag, cure), so
    // no two can disagree, and a renewal that just published is visible without a restart.
    let cell = state.credential.snapshot();
    // The read is guarded like every other credential I/O: an unresolved or non-Gmail session
    // must never resolve the credential path against the process CWD. It is taken before the
    // provider match because the unconfigured arm's own answer depends on it.
    let grant = state.grant_on_disk();
    // The unconfigured arm goes through the one helper: a cell that published no arm reports what
    // [`unconfigured_verdict`] says, either its own recorded refusal or the adoption-pending shape
    // when the fix is already on disk. `PhotonState::gmail`'s refusal is the same call over the
    // same reading, so the status bar and a verb refusal cannot disagree about one boot.
    let (provider_reason, unconfigured_cure) = match &cell.provider {
        Provider::Gmail(_) => (None, None),
        Provider::Unconfigured { reason, cure } => {
            let (cure, reason) = unconfigured_verdict(reason, *cure, &grant);
            (Some(reason), cure)
        }
    };
    let credential_expires_at = cell.expires_at;
    let credential_expired = credential_expired_at(credential_expires_at, now_unix_secs).is_some();
    // The cure comes from the same captured cell as every other credential field. A second
    // coordinator read could straddle a publish and pair `credential_expired: true` with
    // `credential_cure: null`.
    //
    // One derivation serves both branches: the ratchet and the on-disk credential are read once,
    // and [`GrantOnDisk`] answers whether the fix has already landed. Without it, a completed
    // external mint (ratchet at N+1, a valid N+1 credential on disk, the cell still at N until the
    // next command adopts it) rendered a second re-mint demand for a fix already applied.
    //
    // The verdict, asked unconditionally, has four answers:
    // - A retired published generation reads `ReMint`. Otherwise the bar would say `configured`
    //   with no cure while every provider command refused with a re-mint demand.
    // - An unusable ratchet reads `Undetermined`: silence would assert a session is usable when
    //   admission cannot be established at all.
    // - A retirement whose fix is already on disk reads `AdoptionPending` and demands nothing; a
    //   second consent would burn a live one against the provider's refresh-token ceiling.
    // - Otherwise `Silent`, the only answer that hands the question back to the stamp.
    //
    // None of this is gated on `credential_expired`. Expiry is the weaker fact (a renewal is due),
    // while retirement says no renewal can help. Gating on expiry would render `configured` /
    // `retry_later` for an expired arm at N with the ratchet at N+1 and no N+1 on disk (the
    // reserve-first mint's crash window), while the next command refuses `re_mint`.
    let live_grant = grant.verdict(cell.grant_generation);
    // An unconfigured arm's own cure comes ahead of the expired cell's stamp (it is the answer
    // `unconfigured_verdict` gave above, `None` when the fix is already on disk). A cell that
    // published no arm carries a refusal that already knows its remedy, and it outranks
    // `status_cure`: an `Unconfigured` cell built from a credential whose stamp had also passed
    // would otherwise report the stamp's neutral `RetryLater` for a session no renewal can fix,
    // since there is nothing to renew. It cannot collide with the verdict above, which is `Silent`
    // for a cell that published no generation.
    //
    // The stamp's status reconcile is the last resort: a re-mint cure whose fix already landed on
    // disk reports neutral renewal copy instead of re-demanding it. It is fed the same `landed`
    // observation as the verdict above and handed over ungated, since `status_cure` already
    // answers `None` for any cell that is not expired. Read failures flatten to `None`:
    // undecidable suppresses nothing.
    let credential_cure = live_grant
        .cure()
        .or(unconfigured_cure)
        .or_else(|| cell.status_cure(now_unix_secs, grant.landed.as_ref()));
    // The verdict's sentence replaces nothing: a cell that already carries an `Unconfigured`
    // reason keeps it (the verdict is `Silent` for a cell that published no generation, so the
    // two never both speak).
    let provider_reason = live_grant.into_reason().or(provider_reason);
    // The fence quotes that same sentence rather than offering a third opinion about this cell.
    // For the Gmail arm the fence has its own reason and this argument is ignored; for a cell
    // with no arm it is the sentence derived directly above, so `mutations_reason` and
    // `provider_reason` are the same bytes on the wire and the fence toast cannot re-tell an
    // instruction the status bar has withdrawn.
    let (mutations_live, mutations_reason) =
        mutation_fence(&cell.provider, provider_reason.as_deref());

    SessionStatus {
        provider_kind: state.config.provider_kind,
        account: state.config.account.clone(),
        store_path: state.config.store_path.display().to_string(),
        configured: state.store_unavailable.is_none() && provider_reason.is_none(),
        store_reason: state.store_unavailable.clone(),
        provider_reason,
        credential_expires_at,
        credential_expired,
        credential_cure,
        epoch,
        epoch_reason,
        mutations_live,
        mutations_reason,
    }
}

/// The status surface's grant derivation, used by every status consumer.
///
/// One read of the ratchet and one read of the on-disk credential, answering the question both
/// status branches ask: has the fix already landed? A mint is reserve-first, so after one
/// completes (ratchet at N+1 and a valid N+1 credential written) the in-memory cell stays at N
/// until the next provider command adopts it. In that window a branch that consulted the ratchet
/// alone would demand a second consent for a fix that already landed, burning a 300 s re-consent
/// against the provider's refresh-token ceiling.
///
/// Read-only and lock-free, like every other status read: nothing here writes, takes a lock, or
/// renders a credential value. Only a digest, a generation comparison and the ratchet's own shape
/// sentence leave this type.
///
/// Every status consumer judges through it, because a verdict derived from part of this state is
/// wrong while a reserve-first mint changes it non-atomically (otherwise the wave's own
/// `Local(GrantRetired)` stamp would keep demanding a consent a landed replacement already
/// supplied). The precedence, on both branches:
///
/// * an unusable ratchet gives `Undetermined`: neither retirement nor admission is established;
/// * retired with no landed replacement gives `Retired`/`ReMint`, and it outranks
///   `credential_expired`, because expiry says a renewal is due while retirement says no renewal
///   can help;
/// * retired with a landed replacement gives `AdoptionPending`: nothing is demanded, and the
///   stale re-mint stamp is suppressed by the same `landed` observation;
/// * anything else is silent.
///
/// Admission does not consult this: `admit_grant_generation`, `grant_still_admitted` and the
/// credential loader consult the ratchet themselves. The cost is one small credential read per
/// status poll beside the ratchet read.
pub(crate) struct GrantOnDisk {
    /// The ratchet's address; the sentences built from it name it.
    path: PathBuf,
    /// The ratchet as this read found it: `Ok(None)` is absent (nothing retired yet, a real
    /// reading rather than a failure to read), `Ok(Some(hw))` the high-water, and `Err(sentence)`
    /// unusable, carrying the same shape sentence the command surface renders for the same bytes.
    high_water: Result<Option<u64>, String>,
    /// The digest of the on-disk credential, present only when that file is the landed fix: it
    /// loads through the full ingress contract (amendment 8's shape checks included), carries
    /// refresh material, and holds a grant the ratchet has not retired. A deletion, malformed
    /// JSON, a legacy no-refresh-token file, a rolled-back generation or an unusable ratchet all
    /// answer `None`, since none establishes that the demanded cure landed, so the stamped truth
    /// stands (the direction every other reader of these files takes).
    ///
    /// One predicate serves both branches, and it is the stricter of the two: the live branch
    /// alone would not care about refresh material. Erring that way keeps the explicit `re_mint`
    /// answer rather than inventing a quiet one.
    landed: Option<FileGen>,
}

impl GrantOnDisk {
    /// The reads, taken once. The credential is read once so the generation and the usability
    /// verdict derive from the same bytes; a digest-then-reload pair could straddle a concurrent
    /// write and answer for a generation that was never the gating one.
    pub(crate) fn read(secrets_dir: &Path) -> Self {
        let path = token_refresh::grant_high_water_path(secrets_dir);
        let high_water = token_refresh::read_grant_high_water(&path).map_err(|shape| {
            token_refresh::RefreshLocalError::GrantHighWaterUnusable {
                path: path.clone(),
                shape,
            }
            .reason_sentence()
        });
        let credential_path = secrets_dir.join(CREDENTIAL_FILE_NAME);
        let landed = match (&high_water, std::fs::read_to_string(&credential_path)) {
            (Ok(high_water), Ok(raw)) => parse_gmail_credential(&raw, &credential_path)
                .ok()
                .filter(|c| c.refresh_token.is_some())
                .filter(|c| !high_water.is_some_and(|hw| c.grant.grant_generation < hw))
                .map(|_| FileGen::of_bytes(raw.as_bytes())),
            _ => None,
        };
        Self {
            path,
            high_water,
            landed,
        }
    }

    /// The derivation for a session with no credential path to resolve (unresolved or non-Gmail):
    /// it reads nothing and says nothing, so it never resolves the path against the process CWD.
    pub(crate) fn unarmed() -> Self {
        Self {
            path: PathBuf::new(),
            high_water: Ok(None),
            landed: None,
        }
    }

    /// What this state says about a cell that published `published`, live or expired. Expiry is
    /// not an input: a retirement is definitive and an unusable ratchet is undecidable whatever
    /// the access token's clock says.
    fn verdict(&self, published: Option<u64>) -> LiveGrantVerdict {
        // No arm, nothing to judge. Checked before the ratchet, so a cell that published no
        // generation stays silent even when the ratchet is unusable.
        let Some(published) = published else {
            return LiveGrantVerdict::Silent;
        };
        let high_water = match &self.high_water {
            Ok(hw) => *hw,
            Err(sentence) => return LiveGrantVerdict::Undetermined(sentence.clone()),
        };
        match high_water {
            Some(hw) if published < hw => {
                if self.landed.is_some() {
                    LiveGrantVerdict::AdoptionPending
                } else {
                    // The status carrier composes its own sentence rather than borrowing the
                    // refusal's. That sentence's "Photon will not use it" is true where a command
                    // is refusing and false here in reserve-first's crash window: `admit`
                    // deliberately carries no ratchet consult, so a live read arm under the
                    // retired generation keeps serving until its access token expires or a
                    // credential-file change reconciles (the accepted residual, documented on
                    // `admit`). The status states that read-window truth; the cure and the facts
                    // are unchanged.
                    LiveGrantVerdict::Retired(format!(
                        "the parked Gmail credential was minted under grant {published}, but \
                         a later consent (grant {hw}) is recorded at {}; this credential is \
                         retired — no renewal can revive it, and every door that consults the \
                         grant record (credential load, token refresh) refuses it. A Gmail \
                         read session already running on it may keep reading until its access \
                         token expires or a credential-file change is adopted (reads only; no \
                         write can ride it) — re-mint via scripts/gmail_drill_mint.py to \
                         consent again.",
                        self.path.display(),
                    ))
                }
            }
            _ => LiveGrantVerdict::Silent,
        }
    }
}

/// What the grant state says about a live published cell. Four answers, because there are four
/// facts and two of them are quiet.
enum LiveGrantVerdict {
    /// Nothing to report: an unarmed session (no credential path to resolve), a cell that
    /// published no arm, an absent ratchet (nothing retired yet), or a generation at or above the
    /// high-water. On an expired cell this is the only answer that hands the question back to the
    /// stamp.
    Silent,
    /// The published generation is below the ratchet and the fix is already on disk: an external
    /// mint completed and the next provider command adopts it with no POST.
    ///
    /// It renders exactly as `Silent` (no cure, `configured` unchanged), which is the neutral
    /// answer: on an expired cell the stamp behind it reports the same neutral `RetryLater`,
    /// because the suppression is fed by the same `landed` observation. It is its own variant
    /// because the two are different facts, and a future "renewal pending" affordance would fill
    /// from this one.
    AdoptionPending,
    /// The published generation is below the ratchet and nothing newer is on disk: the consent
    /// this arm was built under has been superseded. Cure: `ReMint`, which outranks an expired
    /// cell's stamped `RetryLater`, since no renewal un-supersedes a consent and the wave refuses
    /// this grant before the wire.
    Retired(String),
    /// The ratchet could not be read, so neither retirement nor admission can be established.
    /// Cure: `Undetermined`.
    Undetermined(String),
}

impl LiveGrantVerdict {
    fn cure(&self) -> Option<Cure> {
        match self {
            Self::Silent | Self::AdoptionPending => None,
            Self::Retired(_) => Some(Cure::ReMint),
            Self::Undetermined(_) => Some(Cure::Undetermined),
        }
    }

    fn into_reason(self) -> Option<String> {
        match self {
            Self::Silent | Self::AdoptionPending => None,
            Self::Retired(reason) | Self::Undetermined(reason) => Some(reason),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::{unix_now, GMAIL_TOKEN_FILE};
    use crate::credential_cell;
    use crate::error::SurfaceError;
    use crate::provider::MUTATIONS_FENCED_REASON;
    use crate::tests::fixtures::{
        gmail_arm_state, gmail_arm_state_expiring, s0_dir, s0_grant, s0_grant_with, s0_token_file,
        unique_store, S0_MODIFY, S0_PRINCIPAL,
    };
    use crate::token_refresh::{self, RefreshLocalError};
    use crate::SessionConfig;

    // -------------------------------------------------------------------------------------------
    // A RETIRED REPLACEMENT IS NOT A PLAUSIBLY USABLE CURE.
    //
    // The suppression read (today
    // `GrantOnDisk::landed`) called a replacement "plausibly usable" on two facts — it loads
    // through the ingress contract and it carries refresh material — and never asked the
    // ratchet. Injecting `grant_high_water = 2` into the compiled witness
    // `the_status_suppression_requires_a_plausibly_usable_replacement`
    // while its final replacement stayed at generation 1showed the suppression still
    // fired. Not an authority bypass (admission still refuses the file) but a fail-loud defect:
    // it softens a standing `re_mint` demand to `retry_later` until the next real admission.
    //
    // Before the fix: `Some(FileGen)` — the retired replacement suppressed the re-mint cure.
    // -------------------------------------------------------------------------------------------
    #[test]
    fn a_replacement_the_ratchet_has_retired_suppresses_nothing() {
        let dir = s0_dir("f1rk7");
        let hw = dir.join(token_refresh::GRANT_HIGH_WATER_FILE_NAME);
        std::fs::write(
            dir.join(GMAIL_TOKEN_FILE),
            s0_token_file(42, Some(&s0_grant())),
        )
        .unwrap();
        assert!(
            GrantOnDisk::read(&dir).landed.is_some(),
            "the witness's own premise: a conformant generation-1 replacement DOES suppress              while nothing has retired it"
        );

        // A later consent landed. The parked file is now a rollback, and admission will refuse
        // it — so calling it an applied cure is the wrong sentence to put on the status bar.
        std::fs::write(&hw, b"{\"grant_generation\":2}
").unwrap();
        assert!(
            GrantOnDisk::read(&dir).landed.is_none(),
            "a replacement the ratchet has RETIRED is not a cure that landed"
        );

        // And an unusable ratchet is not a usability verdict either: undecidable suppresses
        // nothing, the same direction every other ratchet reader refuses in.
        std::fs::write(&hw, b"not json at all").unwrap();
        assert!(
            GrantOnDisk::read(&dir).landed.is_none(),
            "an unreadable ratchet cannot establish that the replacement is usable"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    // -------------------------------------------------------------------------------------------
    // THE STATUS SURFACE'S LIVE BRANCH CONSULTS THE RATCHET.
    //
    // READ-ONLY hypothesis, now EXECUTED: the status
    // view's credential fields all derive from the published cell, and for a LIVE cell it
    // consults no cure at all — so a reserve-first mint (or a restore after one) leaves the
    // status bar saying `configured` with no cure while every provider command refuses with a
    // re-mint demand. Two surfaces, two answers, one truth.
    //
    // Before the fix this test failed:
    //   panicked at 'assertion `left == right` failed: a live cell the ratchet retired must read
    //   as the re-mint it is, not as a configured session
    //     left: None
    //    right: Some(ReMint)'
    // -------------------------------------------------------------------------------------------
    #[test]
    fn a_live_cell_whose_generation_the_ratchet_retired_reads_re_mint_on_the_status_surface(
    ) {
        let (dir, state) = gmail_arm_state("f2rk7b");
        let before = session_status_view(&state, Some(1), None, unix_now());
        assert!(
            before.configured && before.credential_cure.is_none(),
            "the witness's own premise: a live, admitted cell reads configured with no cure"
        );

        // A later consent reserved generation 2; the published arm is generation 1.
        std::fs::write(
            dir.join(token_refresh::GRANT_HIGH_WATER_FILE_NAME),
            b"{\"grant_generation\":2}\n",
        )
        .unwrap();

        let status = session_status_view(&state, Some(1), None, unix_now());
        assert_eq!(
            status.credential_cure,
            Some(Cure::ReMint),
            "a live cell the ratchet retired must read as the re-mint it is, not as a configured \
             session"
        );
        let reason = status
            .provider_reason
            .expect("and the reason beside it says WHICH consent superseded it");
        assert!(
            reason.contains("gmail_drill_mint.py") && reason.contains("retired"),
            "the status names the retirement and the cure path: {reason}"
        );
        // The status carrier must NOT borrow the door sentence's
        // "Photon will not use it" — in reserve-first's crash window (ratchet moved, digest
        // unchanged) the live READ arm keeps serving until expiry/reconcile (the
        // accepted residual on `admit`'s own doorstep comment), so the status says the
        // read-window truth instead of the opposite of command behavior.
        assert!(
            !reason.contains("will not use it"),
            "the status must not claim the opposite of the accepted read window: {reason}"
        );
        assert!(
            reason.contains("may keep reading"),
            "the status names the accepted read-only window and its bound: {reason}"
        );
        assert!(
            !status.configured,
            "a session whose consent was superseded is not a configured session"
        );

        // An UNUSABLE ratchet is not a RETIREMENT verdict — and it is not silence either
        // (rewritten from the earlier expectation this test used to assert). The full
        // expectation lives in the unusable-ratchet witness below; here it is pinned beside its sibling so the two
        // branches of the same read are never asserted apart.
        std::fs::write(
            dir.join(token_refresh::GRANT_HIGH_WATER_FILE_NAME),
            b"not json at all",
        )
        .unwrap();
        let undecidable = session_status_view(&state, Some(1), None, unix_now());
        assert_eq!(
            undecidable.credential_cure,
            Some(Cure::Undetermined),
            "an unreadable ratchet cannot establish a retirement — but it cannot establish \
             admission either, and UNDETERMINED is never rendered as silence"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    // -------------------------------------------------------------------------------------------
    // A RE-MINT THAT ALREADY LANDED IS ADOPTION PENDING, NOT A SECOND DEMAND.
    //
    // The FOURTH finding on the status seam and therefore
    // closed ONE LEVEL UP: the status surface had TWO ratchet consults with two
    // different rules. The EXPIRED branch suppressed a cure whose fix had already landed on disk
    // (`status_suppression_gen`); the LIVE branch (`live_grant_verdict`) consulted
    // the ratchet ALONE and answered `Retired ⇒ ReMint` for any published generation below it.
    // A mint is reserve-first, so after it COMPLETES — ratchet at N+1 and a valid N+1 credential
    // on disk — the in-memory cell stays at N until the next provider command adopts it, and in
    // that window the status bar demanded a second consent for a fix that had already landed:
    // a burned 300 s re-consent against the provider's refresh-token ceiling, for a state the
    // very next command resolves with zero POSTs.
    //
    // ONE derivation over {cell, ratchet, on-disk credential} now answers both branches, and the
    // question it asks is the one the live branch always asked: HAS THE FIX ALREADY LANDED?
    //
    // Before the fix this test failed:
    // -------------------------------------------------------------------------------------------
    #[test]
    fn a_re_mint_that_already_landed_is_adoption_pending_not_a_second_demand() {
        let (dir, state) = gmail_arm_state("f8r6f8");
        let hw = dir.join(token_refresh::GRANT_HIGH_WATER_FILE_NAME);
        let before = session_status_view(&state, Some(1), None, unix_now());
        assert!(
            before.configured && before.credential_cure.is_none(),
            "the witness's own premise: a live, admitted cell at generation 1 reads \
             configured with no cure"
        );

        // (a) THE MINT HAS RESERVED, NOT YET WRITTEN — the ratchet moved and the credential on
        //     disk is still the retired one. This is the retired-live-cell case and it does NOT move.
        std::fs::write(&hw, b"{\"grant_generation\":2}
").unwrap();
        let reserved = session_status_view(&state, Some(1), None, unix_now());
        assert_eq!(
            reserved.credential_cure,
            Some(Cure::ReMint),
            "a live cell the ratchet retired, with nothing newer on disk, still reads as \
             the re-mint it is"
        );
        assert!(
            !reserved.configured,
            "and a session whose consent was superseded is not a configured session"
        );

        // (b) THE MINT COMPLETED — the ratchet is at 2 AND a valid generation-2 credential is on
        //     disk. The live cell is still at 1 because no provider command has run yet. THE
        //     FINDING: this used to render a second re-mint demand for a fix already applied.
        std::fs::write(
            dir.join(GMAIL_TOKEN_FILE),
            s0_token_file(
                unix_now() + 3_600,
                Some(&s0_grant_with(2, S0_PRINCIPAL, &[S0_MODIFY])),
            ),
        )
        .unwrap();
        assert_eq!(
            state.credential.snapshot().grant_generation,
            Some(1),
            "the witness's own premise: no command has run, so the live cell is still at \
             the superseded generation"
        );
        let landed = session_status_view(&state, Some(1), None, unix_now());
        assert_eq!(
            landed.credential_cure, None,
            "a re-mint that has ALREADY LANDED on disk is adoption pending — the next \
             command adopts it with no POST — and demanding a second consent for it burns \
             a live one"
        );
        assert!(
            landed.configured,
            "and the session is not un-configured by a fix that is sitting on disk"
        );

        // …and the next command really does adopt it, with no token-endpoint POST (the on-disk
        // credential is live, so no wave runs).
        state
            .admit_provider_sync(unix_now())
            .expect("the next command adopts the landed generation");
        assert_eq!(
            state.credential.snapshot().grant_generation,
            Some(2),
            "the adoption the status surface promised is the adoption that happens"
        );

        // (c) AND THE THIRD ANSWER IS UNCHANGED: an unusable ratchet establishes neither
        //     retirement nor admission, and UNDETERMINED is never rendered as silence.
        std::fs::write(&hw, b"not json at all").unwrap();
        let undecidable = session_status_view(&state, Some(1), None, unix_now());
        assert_eq!(
            undecidable.credential_cure,
            Some(Cure::Undetermined),
            "an unreadable ratchet is undetermined at the live branch, landed credential or not"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    // -------------------------------------------------------------------------------------------
    // AN UNDETERMINED RATCHET IS RENDERED, NOT SWALLOWED.
    //
    // Reproduced:
    // with a live cell and an unreadable `grant_high_water.json`, the status
    // surface read `configured: true, credential_cure: none` while every provider command
    // refused with `GrantHighWaterUnusable`. The premise is right — an undecidable ratchet
    // establishes no RETIREMENT — but `configured: true, cure: none` is itself a verdict: it
    // asserts the session is usable, and it is not. The product's posture is UNDETERMINED NEVER
    // SILENT, and `Cure::Undetermined` already existed for exactly this.
    //
    // An earlier witness asserted the old expectation in its own tail; that assertion is
    // rewritten in place rather than left standing beside a contradicting one.
    //
    // Before the fix this test failed:
    // `configured: true`, `credential_cure: None`, `provider_reason: None`.
    // -------------------------------------------------------------------------------------------
    #[test]
    fn an_unusable_ratchet_renders_undetermined_instead_of_a_configured_session() {
        let (dir, state) = gmail_arm_state("f3rk7c");
        let hw = dir.join(token_refresh::GRANT_HIGH_WATER_FILE_NAME);
        let before = session_status_view(&state, Some(1), None, unix_now());
        assert!(
            before.configured && before.credential_cure.is_none(),
            "the witness's own premise: a live, admitted cell reads configured with no cure"
        );

        // Every shape the ratchet can fail on — the operator must never be told "fine" for any
        // of them, and the sentence must say WHICH shape so the file can be fixed.
        for (bytes, shape_clause) in [
            (&b"not json at all"[..], "it is not valid JSON"),
            (&b"[1, 2, 3]"[..], "its top level is not a JSON object"),
            (&b"{}"[..], "it declares no grant_generation"),
            (
                &b"{\"grant_generation\":-1}"[..],
                "its grant_generation is not a non-negative integer",
            ),
            (
                &b"{\"grant_generation\":1,\"grant_generation\":2}"[..],
                "it repeats a member name or carries a member the shared schema has no field for",
            ),
        ] {
            std::fs::write(&hw, bytes).unwrap();
            let status = session_status_view(&state, Some(1), None, unix_now());
            assert_eq!(
                status.credential_cure,
                Some(Cure::Undetermined),
                "UNDETERMINED is never silent: {}",
                String::from_utf8_lossy(bytes)
            );
            let reason = status
                .provider_reason
                .clone()
                .expect("and the sentence beside it says what could not be established");
            assert!(
                reason.contains(token_refresh::GRANT_HIGH_WATER_FILE_NAME)
                    && reason.contains(shape_clause),
                "the SAME sentence the command surface carries, naming the shape: {reason}"
            );
            assert!(
                !status.configured,
                "a session whose admission cannot be established is not a configured session: {}",
                String::from_utf8_lossy(bytes)
            );
        }

        // A ratchet that is merely ABSENT is not undetermined — nothing has been retired yet,
        // and the operator must not be alarmed by the ordinary first-mint state.
        std::fs::remove_file(&hw).unwrap();
        let absent = session_status_view(&state, Some(1), None, unix_now());
        assert!(
            absent.configured && absent.credential_cure.is_none(),
            "absence is a real reading, not a failure to read"
        );

        // …and the EXPIRED branch never reads blank either: the suppression still suppresses
        // nothing on an unusable ratchet, so a cure always stands. WHICH cure the expired branch
        // reports on these same bytes moved later — the verdict is asked there too now,
        // so it is `Undetermined` rather than the stamp's answer, and
        // `an_unusable_ratchet_is_undetermined_on_the_expired_branch_too` is where that
        // is pinned. What this witness asserts is the invariant that survived both changes: the bar
        // is never blank.
        std::fs::write(&hw, b"not json at all").unwrap();
        assert!(
            GrantOnDisk::read(&dir).landed.is_none(),
            "an unusable ratchet cannot establish that the demanded cure LANDED (RK7)"
        );
        let (expired_dir, expired_state) = gmail_arm_state_expiring("f3rk7c-expired", 42);
        std::fs::write(
            expired_dir.join(token_refresh::GRANT_HIGH_WATER_FILE_NAME),
            b"not json at all",
        )
        .unwrap();
        let expired = session_status_view(&expired_state, Some(1), None, unix_now());
        assert!(
            expired.credential_expired && expired.credential_cure.is_some(),
            "an expired cell whose ratchet cannot be read still carries a cure — the bar is \
             never blank on either branch"
        );

        std::fs::remove_dir_all(&dir).ok();
        std::fs::remove_dir_all(&expired_dir).ok();
    }

    // ===========================================================================================
    // EVERY STATUS CONSUMER JUDGES THROUGH THE ONE
    // ON-DISK DERIVATION.
    //
    // An earlier change built the one derivation ([`GrantOnDisk`]) and wired it into the LIVE branch and
    // into the expired branch's SUPPRESSION. Review then found two neighbours the one rule
    // did not reach — both of them the same class: a status verdict derived from a PARTIAL
    // observation of a state a reserve-first mint changes NON-ATOMICALLY, whose parts are
    // {published cell · grant_high_water.json · the on-disk credential's generation · the local
    // stamp}. The neighbourhood is swept here in one change rather than patched case by case,
    // and each of the three witnesses below is one consumer that used to judge from a part.
    // ===========================================================================================

    // -------------------------------------------------------------------------------------------
    // A RETIREMENT OUTRANKS AN EXPIRED CELL'S "WILL RETRY"
    // `lib.rs:2998-3001` @74df8f8).
    //
    // The expired branch DISCARDED the retirement verdict outright — `if credential_expired {
    // LiveGrantVerdict::Silent }` — and handed the question to the stamp. With no stamp yet (the
    // boot state) the stamp's honest answer is `RetryLater`: "Photon will renew on your next
    // command". It cannot. The arm at N expired, the ratchet is at N+1, and the mint died before
    // publishing N+1, so the wave refuses the retired grant BEFORE the wire and the next command
    // demands a re-mint. Two surfaces, two answers, one truth — and expiry is the WEAKER fact:
    // it says a renewal is due, while retirement says no renewal can ever help.
    //
    // Before the fix this test failed (panic output below, without its line pointer —
    // a stale pointer is worse than none; the test name is the stable address):
    //   thread 'tests::a_retired_grant_outranks_an_expired_cells_retry_later' panicked:
    //   assertion `left == right` failed: a RETIREMENT is definitive; expiry only says a renewal
    //   is due, and a renewal cannot un-supersede a consent
    //     left: Some(RetryLater)
    //    right: Some(ReMint)
    // -------------------------------------------------------------------------------------------
    #[test]
    fn a_retired_grant_outranks_an_expired_cells_retry_later() {
        let (dir, state) = gmail_arm_state_expiring("f9r7f9a", 42);
        let cell = state.credential.snapshot();
        assert_eq!(
            cell.grant_generation,
            Some(1),
            "the witness's own premise: the arm published generation 1"
        );
        assert!(
            cell.last_result.is_none(),
            "…and no refresh has been attempted yet, so only the boot state speaks"
        );
        let before = session_status_view(&state, Some(1), None, unix_now());
        assert!(before.credential_expired, "…and the parked credential is long expired");
        assert_eq!(
            before.credential_cure,
            Some(Cure::RetryLater),
            "…so with nothing retired the neutral boot cure is a retry (W39a)"
        );

        // THE MINT RESERVED GENERATION 2 AND DIED before writing the credential carrying it —
        // reserve-first's own crash window. Nothing newer is on disk.
        std::fs::write(
            dir.join(token_refresh::GRANT_HIGH_WATER_FILE_NAME),
            b"{\"grant_generation\":2}\n",
        )
        .unwrap();
        assert!(
            GrantOnDisk::read(&dir).landed.is_none(),
            "the witness's own premise: the ratchet moved ALONE — no replacement landed"
        );

        let status = session_status_view(&state, Some(1), None, unix_now());
        assert_eq!(
            status.credential_cure,
            Some(Cure::ReMint),
            "a RETIREMENT is definitive; expiry only says a renewal is due, and a renewal \
             cannot un-supersede a consent"
        );
        assert!(
            !status.configured,
            "a session whose consent was superseded is not a configured session — expired or not"
        );
        let reason = status
            .provider_reason
            .expect("and the sentence beside it says WHICH consent superseded this one");
        assert!(
            reason.contains("retired") && reason.contains("gmail_drill_mint.py"),
            "the status names the retirement and the cure path: {reason}"
        );
        // Same honesty bound on this carrier (expired + retired) — the conditional
        // read-window clause is vacuously true here (the token is expired, nothing reads).
        assert!(
            !reason.contains("will not use it"),
            "the status must not claim the opposite of the accepted read window: {reason}"
        );

        // …and the command surface really does say exactly that, which is the whole point.
        let err = match state.admit_provider_sync(unix_now()) {
            Err(e) => e,
            Ok(_) => panic!("a retired grant admits nothing"),
        };
        let SurfaceError::CredentialExpired { cure, .. } = &err else {
            panic!("the wave refuses the retired grant before the wire: {err:?}");
        };
        assert_eq!(*cure, Cure::ReMint, "two surfaces, one truth");

        std::fs::remove_dir_all(&dir).ok();
    }

    // -------------------------------------------------------------------------------------------
    // A LANDED REPLACEMENT CLEARS THE STALE RETIRED STAMP
    // `credential_cell.rs:779-780` @74df8f8).
    //
    // The wave's pre-exchange ratchet door records a retired-expired grant as
    // `RememberedOutcome::Local(GrantRetired)` — a `re_mint` demand keyed to nothing. The status
    // suppression released only TERMINAL LATCHES, and a local failure does not latch, so once the
    // mint finished publishing a valid N+1 the stamp kept demanding a consent that had already
    // been given: the operator burns a second 300 s re-consent against the provider's
    // refresh-token ceiling for a state the very next command resolves with zero POSTs. That is
    // the same finding arriving through the OTHER door, which is why the suppression predicate
    // is WIDENED here rather than a second suppression path being added.
    //
    // Before the fix this test failed (line pointer omitted, as on the sibling witness above):
    //   thread 'tests::a_landed_replacement_clears_the_stale_retired_stamp' panicked:
    //   assertion `left != right` failed: the stamped re-mint demand names a cure that has
    //   ALREADY been applied — demanding it again burns a second consent for a state the next
    //   command resolves with no POST
    //     left: Some(ReMint)
    //    right: Some(ReMint)
    // -------------------------------------------------------------------------------------------
    #[test]
    fn a_landed_replacement_clears_the_stale_retired_stamp() {
        let (dir, state) = gmail_arm_state_expiring("f9r7f9b", 42);
        std::fs::write(
            dir.join(token_refresh::GRANT_HIGH_WATER_FILE_NAME),
            b"{\"grant_generation\":2}\n",
        )
        .unwrap();

        // A command runs FIRST: the wave refuses the retired grant before the wire and STAMPS it.
        let err = match state.admit_provider_sync(unix_now()) {
            Err(e) => e,
            Ok(_) => panic!("a retired grant admits nothing"),
        };
        assert!(
            matches!(
                &err,
                SurfaceError::CredentialExpired {
                    cure: Cure::ReMint,
                    ..
                }
            ),
            "the witness's own premise: the refusal is the re-mint demand: {err:?}"
        );
        let stamp = state
            .credential
            .snapshot()
            .last_result
            .expect("…and the wave stamped it onto the cell");
        assert!(
            matches!(
                stamp.outcome,
                credential_cell::RememberedOutcome::Local(RefreshLocalError::GrantRetired { .. })
            ),
            "…as a LOCAL retired-grant refusal, which is exactly the shape that never latches"
        );

        // NOW THE MINT COMPLETES: a valid generation-2 credential lands on disk. No command has
        // reconciled it yet, so the cell is still the superseded, expired arm.
        std::fs::write(
            dir.join(GMAIL_TOKEN_FILE),
            s0_token_file(
                unix_now() + 3_600,
                Some(&s0_grant_with(2, S0_PRINCIPAL, &[S0_MODIFY])),
            ),
        )
        .unwrap();
        assert_eq!(
            state.credential.snapshot().grant_generation,
            Some(1),
            "the witness's own premise: no command has run, so the cell is still at 1"
        );
        assert!(
            GrantOnDisk::read(&dir).landed.is_some(),
            "…and the fix IS on disk — the one derivation already knows it"
        );

        let status = session_status_view(&state, Some(1), None, unix_now());
        assert_ne!(
            status.credential_cure,
            Some(Cure::ReMint),
            "the stamped re-mint demand names a cure that has ALREADY been applied — demanding \
             it again burns a second consent for a state the next command resolves with no POST"
        );
        assert_eq!(
            status.credential_cure,
            Some(Cure::RetryLater),
            "the neutral renewal copy the expired branch already reports for a fix that landed"
        );
        assert!(
            status.configured,
            "and the session is not un-configured by a fix that is sitting on disk"
        );

        // …and the next command really does adopt it, with no token-endpoint POST.
        state
            .admit_provider_sync(unix_now())
            .expect("the next command adopts the landed generation");
        assert_eq!(
            state.credential.snapshot().grant_generation,
            Some(2),
            "the adoption the status surface promised is the adoption that happens"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    // -------------------------------------------------------------------------------------------
    // THE THIRD SOURCE OF A RE-MINT DEMAND: THE CELL THAT PUBLISHED NO ARM
    //
    // A stale re-mint demand was suppressed inside `GrantOnDisk::verdict` (the RETIREMENT)
    // suppressed it inside `status_cure` (the STAMP). Both keep their rule and their digest
    // conjuncts. The source neither can reach is the UNCONFIGURED cell: it published no
    // generation, so the verdict is `Silent` — there is nothing to judge — and no digest, so
    // there is nothing for the stamp suppression to compare. Its own recorded `re_mint` reached
    // the bar untouched. A boot with no admissible credential, an external mint that completes,
    // and the operator is sent through a second 300 s consent for a credential the very next
    // command adopts with ZERO POSTs.
    //
    // BOTH AXES, or the fix is half a fix: a cure of `None` beside the boot's
    // own "no credential file" sentence still tells the operator to go and mint. The cure and the
    // sentence are two renderings of one verdict, so `unconfigured_verdict` answers both, and
    // `configured` stays FALSE — there is no arm yet, and saying otherwise would be a new lie.
    //
    // -------------------------------------------------------------------------------------------
    #[test]
    fn a_landed_replacement_suppresses_the_unconfigured_boots_re_mint() {
        // NO credential file at all: the fresh-install boot, whose one cure IS the re-mint.
        let dir = s0_dir("f10r8f10");
        let state = PhotonState::new(SessionConfig {
            account: "acct".to_string(),
            store_path: dir.join("store.sqlite"),
            provider_kind: ProviderKind::Gmail,
            gmail_secrets_dir: dir.to_path_buf(),
        });
        let before = session_status_view(&state, Some(1), None, unix_now());
        assert_eq!(
            before.credential_cure,
            Some(Cure::ReMint),
            "the witness's own premise: a boot with no credential demands the re-mint ceremony"
        );
        let boot_sentence = before
            .provider_reason
            .clone()
            .expect("…and it says so in words, which is the sentence that must stop being told");
        assert!(
            !before.configured,
            "…and a session with no credential is not a configured session"
        );

        // THE MINT COMPLETES: generation 1 reserved on the ratchet, a valid generation-1
        // credential written. No command has run since boot, so the cell still publishes no arm.
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
        assert_eq!(
            state.credential.snapshot().grant_generation,
            None,
            "the witness's own premise: the boot cell published NO arm and NO digest — there is \
             nothing for the verdict to judge and nothing for the stamp suppression to compare"
        );
        assert!(
            GrantOnDisk::read(&dir).landed.is_some(),
            "…and the fix IS on disk — the one derivation already knows it"
        );

        let landed = session_status_view(&state, Some(1), None, unix_now());
        assert_eq!(
            landed.credential_cure, None,
            "the boot's re-mint demand names a cure that has ALREADY been applied — demanding \
             it again burns a second consent for a state the next command resolves with no POST"
        );
        assert_ne!(
            landed.provider_reason.as_deref(),
            Some(boot_sentence.as_str()),
            "and the SENTENCE is the other half of the same demand: left standing, it sends the \
             operator to the mint the cure just stopped asking for"
        );
        assert_eq!(
            landed.provider_reason.as_deref(),
            Some(ADOPTION_PENDING_REASON),
            "…replaced by the STATE that is true at every door (r12 F15): a credential has \
             landed and nothing has adopted it yet"
        );
        assert!(
            !landed.configured,
            "and the session is still NOT configured — no arm has been built yet; the next \
             command is what builds one"
        );

        // …and the next command really does adopt it, with no token-endpoint POST (the on-disk
        // credential is live, so no wave runs).
        state
            .admit_provider_sync(unix_now())
            .expect("the next command adopts the landed credential");
        assert_eq!(
            state.credential.snapshot().grant_generation,
            Some(1),
            "the adoption the status surface promised is the adoption that happens"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    // -------------------------------------------------------------------------------------------
    // THE THIRD FIELD THAT SPEAKS FOR AN UNARMED CELL.
    //
    // `mutations_reason` is rendered by the frontend as its own operator-facing sentence (the
    // fence toast, `src/render.ts`), and for the unconfigured arm the fence COPIED the cell's
    // RECORDED reason — the boot's "mint a credential" instruction — while `provider_reason` and
    // the `gmail()` refusal beside it had already moved to the derived adoption-pending sentence.
    // One status payload, two sentences about one cell, one of them describing a state that has
    // been superseded. This is the same class closed at the two other surfaces, so it takes
    // the same close: ONE derivation (`unconfigured_verdict`), computed once, feeding every field
    // that speaks for the cell. No new predicate, no second consult of the disk.
    //
    // -------------------------------------------------------------------------------------------
    #[test]
    fn the_mutation_fence_quotes_the_derived_reason_not_the_stale_boot_sentence() {
        let dir = s0_dir("f12r9f12");
        let state = PhotonState::new(SessionConfig {
            account: "acct".to_string(),
            store_path: dir.join("store.sqlite"),
            provider_kind: ProviderKind::Gmail,
            gmail_secrets_dir: dir.to_path_buf(),
        });
        let before = session_status_view(&state, Some(1), None, unix_now());
        let boot_sentence = before
            .mutations_reason
            .clone()
            .expect("the witness's own premise: the unarmed arm's fence quotes a sentence");
        assert_eq!(
            before.mutations_reason, before.provider_reason,
            "…and at boot the two agree, which is why a divergence later is a DEFECT, not a design"
        );

        // THE MINT COMPLETES — nothing has reconciled it, so the cell still publishes no arm.
        std::fs::write(
            dir.join(token_refresh::GRANT_HIGH_WATER_FILE_NAME),
            b"{\"grant_generation\":1}
",
        )
        .unwrap();
        std::fs::write(
            dir.join(GMAIL_TOKEN_FILE),
            s0_token_file(unix_now() + 3_600, Some(&s0_grant())),
        )
        .unwrap();

        let landed = session_status_view(&state, Some(1), None, unix_now());
        assert_eq!(
            landed.provider_reason.as_deref(),
            Some(ADOPTION_PENDING_REASON),
            "the witness's own premise (F10): the status bar has stopped telling the operator \
             to go and mint"
        );
        assert_ne!(
            landed.mutations_reason.as_deref(),
            Some(boot_sentence.as_str()),
            "…so the fence toast must stop telling them to, in the SAME payload — one cell, \
             one sentence"
        );
        assert_eq!(
            landed.mutations_reason.as_deref(),
            Some(ADOPTION_PENDING_REASON),
            "the fence quotes the DERIVED reason, the one `unconfigured_verdict` already gave"
        );
        assert_eq!(
            landed.mutations_reason, landed.provider_reason,
            "…which is exactly the sentence the status and the verb refusal report — never a \
             second phrasing of one cell"
        );
        assert!(
            !landed.mutations_live,
            "and the fence is still CLOSED — this fold is the label, never the door (§4h)"
        );

        // The Gmail arm's own fence sentence is untouched: it is not derived from any credential
        // verdict, it is the default-closed write gate's own named reason.
        state
            .admit_provider_sync(unix_now())
            .expect("the read door is the one that adopts");
        let armed = session_status_view(&state, Some(1), None, unix_now());
        assert_eq!(
            armed.mutations_reason.as_deref(),
            Some(MUTATIONS_FENCED_REASON),
            "the Gmail arm keeps its own fence sentence — only the unarmed arm's copy moved"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    // -------------------------------------------------------------------------------------------
    // THE ADOPTION SENTENCE PROMISES NO DOOR.
    //
    // The sentence said "refresh the inbox to adopt it", and a refresh cannot always reach the
    // adoption. `refresh_inbox` runs FIVE guards before `admit_provider` can reconcile, and two
    // of them hold for the life of the process: `state.session()?`, which refuses
    // while `store_unavailable` is set — nothing in `PhotonState` ever reopens a failed store —
    // and `refresh_armed()` inside `admit_provider`. The label is not the place
    // to enumerate a door's guards, so it stops predicting doors altogether: it MIRRORS the
    // on-disk observation and nothing else. Which command adopts is the door contract's business
    // And what an operator should DO about an unopenable store is the runbook's.
    //
    // THE TWO BOOTS, one difference: an unopenable store. Both must report the SAME state-only
    // sentence, on all three surfaces that speak for an unarmed cell.
    //
    // Before the fix this test failed.
    // -------------------------------------------------------------------------------------------
    #[test]
    fn the_adoption_sentence_names_no_door_at_any_pre_admit_guard() {
        // Two fresh-install boots: Gmail kind, a resolvable secrets dir (so the arm gate
        // is open and the disk IS read), and no credential file — the cell whose one cure is the
        // re-mint ceremony.
        let down_dir = s0_dir("f15r12down");
        let down = PhotonState::new(SessionConfig {
            account: "acct".to_string(),
            // The store path's PARENT does not exist, so the store never opens and
            // `store_unavailable` stays set for the life of the process.
            store_path: down_dir.join("no-such-parent").join("store.sqlite"),
            provider_kind: ProviderKind::Gmail,
            gmail_secrets_dir: down_dir.to_path_buf(),
        });
        let ok_dir = s0_dir("f15r12ok");
        let ok = PhotonState::new(SessionConfig {
            account: "acct".to_string(),
            store_path: ok_dir.join("store.sqlite"),
            provider_kind: ProviderKind::Gmail,
            gmail_secrets_dir: ok_dir.to_path_buf(),
        });
        assert!(
            down.store_unavailable.is_some() && down.session().is_err(),
            "the witness's own premise: the read door's FIRST guard (`state.session()?`) refuses \
             this session, and it will refuse every later call too — no code path reopens the store"
        );
        assert!(
            ok.store_unavailable.is_none() && ok.session().is_ok(),
            "…and the other boot's store is fine, so a refresh really can reach the reconcile"
        );
        for state in [&down, &ok] {
            assert_eq!(
                session_status_view(state, None, None, unix_now()).credential_cure,
                Some(Cure::ReMint),
                "the witness's own premise: a boot with no credential demands the re-mint"
            );
        }

        // THE MINT COMPLETES for both: generation 1 on the ratchet, a valid generation-1
        // credential written. No command has run, so both cells still publish no arm.
        for dir in [&down_dir, &ok_dir] {
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
            assert!(
                GrantOnDisk::read(dir).landed.is_some(),
                "the witness's own premise: the fix IS on disk"
            );
        }

        for (label, state) in [("store unavailable", &down), ("store open", &ok)] {
            let landed = session_status_view(state, None, None, unix_now());
            let reason = landed
                .provider_reason
                .clone()
                .unwrap_or_else(|| panic!("{label}: an unarmed cell always carries a sentence"));
            assert!(
                !reason.contains("refresh"),
                "{label}: the sentence prescribed a REFRESH, and `refresh_inbox` refuses at \
                 `state.session()?` (lib.rs:2415) before `admit_provider` (lib.rs:2419) can \
                 reconcile — a promise no door keeps under every pre-admit guard: {reason:?}"
            );
            assert!(
                !reason.contains("restart") && !reason.contains("next command"),
                "{label}: and it does not swap one door prediction for another: {reason:?}"
            );
            assert_eq!(
                reason, ADOPTION_PENDING_REASON,
                "{label}: one derivation, one sentence, both boots"
            );
            assert_eq!(
                landed.credential_cure, None,
                "{label}: the re-mint demand is still false — the credential IS there"
            );
            assert!(
                !landed.configured,
                "{label}: and no arm has been published, so the session is not configured"
            );
            assert_eq!(
                landed.mutations_reason, landed.provider_reason,
                "{label}: the fence quotes the same derived sentence (F12), never a second one"
            );
            match state.gmail().err() {
                Some(SurfaceError::SessionUnconfigured { reason, cure }) => {
                    assert_eq!(
                        reason, ADOPTION_PENDING_REASON,
                        "{label}: the acting doors' refusal carries the SAME sentence (F10)"
                    );
                    assert_eq!(cure, None, "{label}: and demands no second consent");
                }
                other => panic!("{label}: no arm is published until a command adopts: {other:?}"),
            }
        }

        // THE SENTENCE IS A STATE FACT, not an instruction: no door is named, so there is no
        // guard list for it to be wrong about.
        assert_eq!(
            ADOPTION_PENDING_REASON, "a credential has landed; Photon has not adopted it yet",
            "the label mirrors the on-disk observation; the recovery instruction is the door \
             contract's (#88) and the runbook's (#87), never this string's"
        );

        // The two guards the enumeration names, exercised: the store-down session's read door
        // still refuses at its first guard …
        assert!(
            down.session().is_err(),
            "nothing reopened the store — which is precisely why the sentence must not promise \
             that a refresh adopts"
        );
        // … while the open-store session's read door does adopt, with no token-endpoint POST.
        ok.admit_provider_sync(unix_now())
            .expect("an open store lets the provider-read door reconcile");
        assert_eq!(
            ok.credential.snapshot().grant_generation,
            Some(1),
            "the state the sentence reported is the state that changes when a door does adopt"
        );

        std::fs::remove_dir_all(&down_dir).ok();
        std::fs::remove_dir_all(&ok_dir).ok();
    }

    // -------------------------------------------------------------------------------------------
    // THE THIRD PARTIAL-VIEW CONSUMER THE SWEEP FOUND: an UNUSABLE ratchet is
    // UNDETERMINED on the EXPIRED branch too.
    //
    // An earlier change ruled that
    // `configured: true, cure: none` is a positive verdict about a session the command surface
    // refuses, and rendered `Undetermined` instead; but it wired that ruling into the LIVE branch
    // only, because that was the branch where the bar could read blank. The expired branch went
    // on handing the question to the stamp, so a boot with an unreadable `grant_high_water.json`
    // read `configured: true, cure: retry_later` — "Photon will renew on your next command" —
    // while every command refuses `GrantHighWaterUnusable`. `RetryLater` is the right answer to
    // "what do I do about the step that just failed"; it is the wrong answer to "is this session
    // usable", and the status bar asks the second question.
    //
    // Before the fix this test failed (line pointer omitted, as on the first witness of this block):
    //   thread 'tests::an_unusable_ratchet_is_undetermined_on_the_expired_branch_too'
    //   panicked:
    //   assertion `left == right` failed: an admission that cannot be ESTABLISHED is undetermined
    //   on both branches — the expired branch's stamp answers a different question
    //     left: Some(RetryLater)
    //    right: Some(Undetermined)
    // -------------------------------------------------------------------------------------------
    #[test]
    fn an_unusable_ratchet_is_undetermined_on_the_expired_branch_too() {
        let (dir, state) = gmail_arm_state_expiring("f9r7f9c", 42);
        let before = session_status_view(&state, Some(1), None, unix_now());
        assert!(
            before.credential_expired
                && before.configured
                && before.credential_cure == Some(Cure::RetryLater),
            "the witness's own premise: an expired boot cell reads configured, cure retry_later"
        );

        std::fs::write(
            dir.join(token_refresh::GRANT_HIGH_WATER_FILE_NAME),
            b"not json at all",
        )
        .unwrap();
        let status = session_status_view(&state, Some(1), None, unix_now());
        assert_eq!(
            status.credential_cure,
            Some(Cure::Undetermined),
            "an admission that cannot be ESTABLISHED is undetermined on both branches — the \
             expired branch's stamp answers a different question"
        );
        assert!(
            !status.configured,
            "a session whose admission cannot be established is not a configured session"
        );
        let reason = status
            .provider_reason
            .expect("and the sentence says what could not be established");
        assert!(
            reason.contains(token_refresh::GRANT_HIGH_WATER_FILE_NAME)
                && reason.contains("it is not valid JSON"),
            "the SAME sentence the command surface carries, naming the shape: {reason}"
        );

        // The command surface's own answer to the same bytes is the refusal this rendering
        // stopped contradicting.
        let err = match state.admit_provider_sync(unix_now()) {
            Err(e) => e,
            Ok(_) => panic!("an unusable ratchet admits nothing"),
        };
        assert!(
            matches!(&err, SurfaceError::CredentialExpired { .. }),
            "the wave refuses on the unusable ratchet before the wire: {err:?}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    // The status suppression requires a PLAUSIBLY USABLE
    // replacement: a deletion, malformed JSON, or a legacy no-refresh-token file still needs
    // the re-mint the latch demands, and suppressing to "will retry" on those would lie.
    #[test]
    fn the_status_suppression_requires_a_plausibly_usable_replacement() {
        let dir = aruna::test_temp::TempDir::new("photon-suppress"); // the ONE guard (`aruna::test_temp`)
        // Absent file: FileGen::Absent is a real generation, but a deletion cures nothing.
        assert!(GrantOnDisk::read(&dir).landed.is_none(), "a deleted file suppresses nothing");
        // Malformed JSON: not a credential.
        std::fs::write(dir.join(GMAIL_TOKEN_FILE), "{not json").unwrap();
        assert!(GrantOnDisk::read(&dir).landed.is_none(), "malformed bytes suppress nothing");
        // Legacy file without refresh material: still needs the re-mint the latch demands.
        // It carries a CONFORMANT grant, so refresh-material absence is the only thing under
        // test here (a grantless file suppresses nothing either — the arm below).
        std::fs::write(
            dir.join(GMAIL_TOKEN_FILE),
            format!(
                "{{\"access_token\": \"tok\", \"expires_at\": 42, \"grant\": {}}}",
                s0_grant()
            ),
        )
        .unwrap();
        assert!(
            GrantOnDisk::read(&dir).landed.is_none(),
            "a no-refresh-token file suppresses nothing"
        );
        // A pre-grant file with no grant provenance is not a plausible cure either —
        // it is exactly what the re-mint ceremony replaces.
        std::fs::write(dir.join(GMAIL_TOKEN_FILE), s0_token_file(42, None)).unwrap();
        assert!(
            GrantOnDisk::read(&dir).landed.is_none(),
            "a credential with no grant provenance suppresses nothing"
        );
        // A usable replacement: loads through the full ingress contract with refresh material.
        std::fs::write(
            dir.join(GMAIL_TOKEN_FILE),
            s0_token_file(42, Some(&s0_grant())),
        )
        .unwrap();
        assert!(
            GrantOnDisk::read(&dir).landed.is_some(),
            "a plausibly usable replacement is the one thing that suppresses"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// `session_status`'s epoch field reads `PhotonSession::log.control_epoch()` — this
    /// proves the wiring the async command cannot be unit-tested through directly (no `tauri::State`
    /// constructor exists outside a running app; see `state.rs` in the `tauri` crate).
    #[test]
    fn session_status_epoch_reads_the_control_epoch_off_the_open_store() {
        // A unique, guarded store (declared before the state).
        let store = unique_store("epoch-wiring");
        let secrets = aruna::test_temp::TempDir::uncreated("photon-epoch-wiring-no-secrets"); // guarded
        let state = PhotonState::new(SessionConfig {
            account: "acct".to_string(),
            store_path: store.to_path_buf(),
            provider_kind: ProviderKind::Jmap,
            gmail_secrets_dir: secrets.to_path_buf(),
        });
        let session = state.session().expect("a fresh store opens a session");
        let epoch = session
            .lock()
            .expect("the session lock is not poisoned")
            .log
            .control_epoch()
            .expect("read epoch");
        assert_eq!(
            epoch, 1,
            "a fresh store is seeded at epoch 1 — the same value `session_status`'s `epoch` \
             field now truthfully reports instead of the old `EpochState::Unreadable`"
        );
        drop(session);
    }

    #[test]
    fn a_missing_store_reports_epoch_none_through_the_same_session_unconfigured_reason() {
        // The store path's PARENT directory does not exist, so `SqliteIntentLog::open` cannot
        // create the file — the same "store never opened" shape `session_status` must turn into
        // `epoch: None` + the `store_reason` text, never a whole-command refusal (a down
        // store still reports `configured: false` truthfully, not an error).
        // The ONE guard owns the (never created) parent and the secrets dir.
        let parent = aruna::test_temp::TempDir::uncreated("photon-epoch-missing-parent-does-not-exist");
        let secrets = aruna::test_temp::TempDir::uncreated("photon-epoch-missing-no-secrets");
        let state = PhotonState::new(SessionConfig {
            account: "acct".to_string(),
            store_path: parent.join("store.sqlite"),
            provider_kind: ProviderKind::Jmap,
            gmail_secrets_dir: secrets.to_path_buf(),
        });
        match state.session() {
            Err(SurfaceError::SessionUnconfigured { reason, .. }) => {
                assert_eq!(
                    reason,
                    *state.store_unavailable.as_ref().expect("store_unavailable is set"),
                    "epoch_reason reuses this exact string — the same reason `store_reason` \
                     already carries, never a second invented phrase"
                );
            }
            Err(other) => panic!("an unopenable store must refuse with SessionUnconfigured, not {other:?}"),
            Ok(_) => panic!("a store whose parent directory does not exist must never open a session"),
        }
    }

    // ===========================================================================================
    // AN EXPIRED CREDENTIAL IS NOT A CONFIGURED SESSION.
    //
    // The drill credential's Testing-mode mint lives ~7 days and the token itself an hour; before
    // this, an already-stale `expires_at` changed NOTHING: both transports were built, the status
    // said `configured: true`, and every read came back as an unexplained provider refusal
    // carrying a raw 401. Two moments matter and both are covered here — construction (the file
    // was already stale when the app started) and command time (it went stale while the app was
    // open). Tested at the SYNC SEAM, the same way the [`Pacing`] block above is: the commands
    // themselves need a `tauri::State` that has no constructor outside a running app, so the
    // witness is the function they call — [`PhotonState::admit_credential`], which takes `now` so
    // a test can move time without sleeping. Its call sites are `refresh_inbox` and
    // `message_body`, immediately after their pacing gate.
    // ===========================================================================================

    // An already-expired credential BUILDS the arm — construction carries
    // no network and no judgement — and reports itself expired-but-refreshable: `configured: true`
    // (the store and the arm are constructible), `credential_expired: true`, and the cure is
    // `RetryLater` because no renewal has been attempted yet. Never a re-mint demand at boot.
    #[test]
    fn an_already_expired_credential_builds_a_configured_expired_but_refreshable_session() {
        // 42 = 1970. The mint writes unix SECONDS (`scripts/gmail_drill_mint.py`, the
        // `gmail_readside_main_token.json` write).
        let (dir, state) = gmail_arm_state_expiring("expired-cred", 42);

        assert!(
            matches!(state.credential.snapshot().provider, Provider::Gmail(_)),
            "construction builds the arm from an expired credential — the first command renews it"
        );

        let status = session_status_view(&state, Some(1), None, 1_000_000);
        assert!(
            status.configured,
            "the store and the arm are constructible — `configured` no longer says 'live'"
        );
        assert_eq!(
            status.credential_expires_at,
            Some(42),
            "the stamp is still reported — the status tells the truth about WHICH credential died"
        );
        assert!(
            status.credential_expired,
            "the expiry axis is its own field, not a paraphrase of `configured`"
        );
        assert_eq!(
            status.credential_cure,
            Some(Cure::RetryLater),
            "no attempt has been made yet: the boot state renews on the next command (W39a)"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    // -------------------------------------------------------------------------------------------
    // THE CURE DISCRIMINANT ON THE BOOT PATH.
    //
    // Every boot-time credential refusal already KNOWS its cure — the sentence it renders
    // prescribes one in words ("re-mint via scripts/gmail_drill_mint.py"). What crossed the
    // boundary was only that sentence: `Provider::Unconfigured { reason }` carried no
    // discriminant, so `session_status_view` rendered `credential_cure: null` for a session whose
    // one cure is a re-mint, and the frontend's `session_unconfigured` toast had nothing to branch
    // on. The pre-grant credential file (no `grant` member) is the state EVERY parked profile is in
    // at this build's first boot, so it is the witness.
    //
    // Before the fix: `credential_cure` is `None`, and the wire carries `"credential_cure": null`.
    // -------------------------------------------------------------------------------------------
    #[test]
    fn a_boot_refusal_carries_its_typed_cure_onto_the_status_surface() {
        let dir = s0_dir("w90-status");
        std::fs::write(dir.join(GMAIL_TOKEN_FILE), s0_token_file(42, None)).unwrap();
        let state = PhotonState::new(SessionConfig {
            account: "acct".to_string(),
            store_path: dir.join("store.sqlite"),
            provider_kind: ProviderKind::Gmail,
            gmail_secrets_dir: dir.to_path_buf(),
        });

        let status = session_status_view(&state, Some(1), None, 1_000_000);
        assert!(
            !status.configured,
            "a credential that cannot say which consent authorized it builds no arm"
        );
        assert!(
            status
                .provider_reason
                .as_deref()
                .is_some_and(|r| r.contains("grant provenance")),
            "the sentence still names the class: {:?}",
            status.provider_reason
        );
        assert_eq!(
            status.credential_cure,
            Some(Cure::ReMint),
            "the boot refusal's cure is the one its own sentence prescribes — a re-mint"
        );

        let wire = serde_json::to_value(&status).expect("SessionStatus serializes");
        assert_eq!(wire["configured"], serde_json::json!(false));
        assert_eq!(
            wire["credential_cure"],
            serde_json::json!("re_mint"),
            "the discriminant, not the sentence, is what the frontend branches on"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// THE TRUTHFUL-UNAVAILABILITY ARM. The production Gmail arm CANNOT
    /// mutate: `HttpGmailTransport::connect` builds a default-closed `DestructiveWriteGate` that
    /// can only ever be opened for a loopback host (`crates/aruna-gmail/src/lib.rs:109-128` — ADR
    /// Part III + its exit criterion), so every verb is refused pre-wire. A status that reports
    /// `configured: true` and says nothing about that fence invites the UI to offer buttons the
    /// engine will always refuse.
    #[test]
    fn the_gmail_arm_reports_its_mutation_fence_truthfully_on_the_wire() {
        let (dir, state) = gmail_arm_state("mutation-fence");
        assert!(
            matches!(state.credential.snapshot().provider, Provider::Gmail(_)),
            "a parked token file must build the production Gmail arm"
        );

        let status = session_status_view(&state, Some(1), None, unix_now());
        assert!(
            status.configured,
            "the session IS configured — reads work; the fence is a separate axis"
        );
        let wire = serde_json::to_value(&status).expect("SessionStatus serializes");
        assert_eq!(
            wire["mutations_live"],
            serde_json::json!(false),
            "real-provider writes are fence-gated — the status must say so: {wire}"
        );
        let reason = wire["mutations_reason"].as_str().unwrap_or_default();
        assert!(
            reason.contains("fence-gated"),
            "the reason must NAME the fence, not leave the UI to guess: {reason:?}"
        );
        assert_eq!(
            reason, MUTATIONS_FENCED_REASON,
            "one sentence, quoted by the status AND by the verb refusal — never two phrasings"
        );

        std::fs::remove_dir_all(&dir).ok();
    }
}
