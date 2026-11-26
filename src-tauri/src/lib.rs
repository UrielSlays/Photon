//! Photon's Tauri shell.
//!
//! One process, one engine session, and exactly twenty typed commands between the renderer and
//! the engine: the v1 ten (nine, plus the continuation command `refresh_more_inbox`) and the
//! triage ten (`trash` · `untrash` · `mark_spam` · `unmark_spam` · `set_seen` · `plan_mint` ·
//! `plan_review` · `plan_approve` · `plan_apply` · `set_knob`). The crate contains no mail logic:
//! ingest/reconcile/projection live in [`aruna::read_coordinator`], HTML→text conversion in
//! [`aruna::body_view`], the verbs and the undo spine in [`aruna::CommandBus`]. What lives here is
//! the wiring, the refusals, and the bounds.
//!
//! # Disciplines
//!
//! 1. **No lock across provider I/O.** The session lock covers store access only. A command that
//!    touches the provider acquires, copies out what it needs, drops the guard, calls the
//!    provider on the blocking pool, then re-acquires to write. The session mutex guards a struct
//!    of store handles only, so the transport is not reachable through it.
//! 2. **Single-flight, not a quota accountant.** A second concurrent operation of the same kind
//!    is refused with a typed [`SurfaceError::Busy`]. There is no counting, window or quota table.
//! 3. **Typed refusals, no panic across IPC.** Every command returns `Result<T, SurfaceError>`;
//!    command paths do not `unwrap()` engine results or `expect()` on a lock.
//!
//! # The IPC surface contract
//!
//! `tests/surface_contract.rs` checks manifest, plugins, config and registration together: no
//! plugin is registered, `capabilities/default.json` grants `core:default` alone,
//! `withGlobalTauri` is off, the CSP names only local assets and Tauri's IPC sources, and
//! `generate_handler!` lists exactly the commands that test names. There is no sever actuator:
//! BLACK is a status in v1, never a renderer-callable control (that would hand a compromised
//! webview an engine DoS).
//!
//! The adversary is a hostile script in the renderer; these checks are defense in depth, not a
//! wall against an actor who already owns the box. The accepted residual: a compromised renderer
//! can drive the permitted YELLOW verbs the user could drive, each journaled,
//! pre-state-captured, undoable and epoch-fenced. The RED plan commands take the approval as the
//! renderer's echo of what it showed, so the engine checks the echo against the plan
//! (`plan_approve`), not that a human saw it, and `set_knob` can set the RED-bypass knob. What
//! stands between those commands and the provider on the Gmail arm today is the mutation fence
//! (`mutation_fence`, default-closed).

use std::path::PathBuf;
use std::time::Instant;

use serde::{Deserialize, Serialize};

use aruna::body_view::{to_body_view, BodyAvailability};
use aruna::gmail::{GmailMessageId, GmailTransport};
use aruna::plan::PlanVerb;
use aruna::read_coordinator::VerbDelta;
use aruna::read_model::ProviderMessageId;
use aruna::read_surface::clamp_page_size;
use aruna::{Action, MailFlag};
use tauri::Manager;

use credential::unix_now;
use error::surface_error_reason;
use plan::{
    plan_apply_door, plan_approve_door, plan_mint_door, plan_review_door, red_verb_door,
    set_knob_door,
};
use plumbing::{admit_provider, lock_bus, with_provider, with_session};
use session::{local_page_with_lookahead, PageAnchor, PageFacts};
use status::session_status_view;
use verbs::{run_verb, run_yellow_door, undo_outcome_after_undo, YellowDoor};

/// Compile-time check that the JMAP arm still satisfies the engine seam. `aruna-jmap` is a
/// declared dependency, but v1 wires the Gmail arm only: there is no on-disk JMAP credential
/// layout to read (the operator runbook defines `~/.photon/gmail/` and nothing else), and
/// inventing one here would be design work. The assertion fails to compile the day the live JMAP
/// transport stops satisfying the seam the future arm will plug into. See
/// [`PROVIDER_JMAP_UNCONFIGURED`] for what the arm answers today.
const _JMAP_SEAM_HOLDS: fn() = || {
    fn satisfies_the_engine_seam<T: aruna::jmap::JmapTransport>() {}
    satisfies_the_engine_seam::<aruna_jmap::transport::HttpJmapTransport>();
};

mod credential;
mod error;
mod ipc;
mod plan;
mod plumbing;
mod provider;
mod session;
mod single_flight;
mod state;
mod status;
mod verbs;

// Credential renewal lives in two sibling modules: the token-endpoint exchange (persistence,
// file generation, the OS lock) and the cell/wave/commit protocol that publishes what it renews.
// `lib.rs` wires them at the three admission points and the status view.
mod credential_cell;
// The OS custodian of the root commitment key; its one caller is `root_key_custodian`, at bus
// construction (`build_gmail_arm`).
mod key_custody_keyring;
mod token_refresh;

/// The Rust half of the ratchet-reader parity differential (see the module doc). Lives in the
/// lib, not `tests/`, because `read_grant_high_water` is `pub(crate)` and stays that way.
#[cfg(test)]
mod ratchet_parity_differential;

pub use credential::{CREDENTIAL_EXPIRY_GRACE_SECS, GMAIL_TOKEN_FILE};
pub use error::{MemberDiffView, SurfaceError};
pub use ipc::{
    FreshnessView, InboxPage, InboxRow, PageCursor, ProjectionState, RefreshOutcome,
    RestorationView, UndoOutcome, UndoPresentationReadView, UndoPresentationView, VerbOutcome,
};
pub use plan::{
    KnobActWire, KnobOutcome, LaneView, MemberStateView, PlanApplyOutcome, PlanApproveOutcome,
    PlanHeaderView, PlanPresentationView, PlanReviewView, PlanRowView, PlanSummaryView,
    PlanUndoKeyView, PreflightView, RenderedViewWire, PLAN_TTL_SECONDS,
};
pub use provider::{GmailProvider, Provider, MUTATIONS_FENCED_REASON, PROVIDER_JMAP_UNCONFIGURED};
pub use session::{PhotonSession, NO_CONTINUATION_REASON};
pub use single_flight::{
    InFlight, InFlightClaim, OperationKind, Pacing, MIN_REFRESH_INTERVAL_MS, PROVIDER_BACKOFF_MS,
};
pub use state::PhotonState;
pub use status::SessionStatus;
pub use token_refresh::Cure;

pub(crate) use credential::{
    credential_absent_diagnosis, credential_expired_at, CredentialLoadFailure, GmailCredential,
};
#[cfg(test)]
pub(crate) use credential::CredentialLoadRefusal;
#[cfg(test)]
pub(crate) use provider::build_gmail_arm;

// Configuration + the credential seam

/// Which provider this session speaks to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    Gmail,
    Jmap,
}

/// Where the session gets its store, its account key and its credential: the platform app-data
/// dir plus the existing `~/.photon/gmail/` layout. There is no in-app OAuth in this release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionConfig {
    /// The Photon-local account key — the store's partition column, NOT an identity claim.
    pub account: String,
    /// The SQLite store (intent log + read model) inside the platform app-data dir.
    pub store_path: PathBuf,
    pub provider_kind: ProviderKind,
    /// The operator's parked-secrets directory for the Gmail arm.
    pub gmail_secrets_dir: PathBuf,
}

/// The default Photon-local account key.
///
/// It is a partition key, not a mailbox identity: v1 is single-account and the credential alone
/// decides which mailbox is reached (the token file carries no email address to name it by).
/// `PHOTON_ACCOUNT` overrides it for the drill lanes. Re-minting the credential against a
/// different Google account under the same key would mix two mailboxes' rows in one partition;
/// fixing that needs an account-identity read.
pub const DEFAULT_ACCOUNT: &str = "gmail:me";

/// The store file inside the app-data dir.
pub const STORE_FILE: &str = "photon.sqlite";

impl SessionConfig {
    /// Resolve the config from the platform directories plus the two env overrides
    /// (`PHOTON_ACCOUNT`, `PHOTON_STORE_PATH`), which let the env-gated drill lanes point a
    /// session at their own store/partition.
    ///
    /// The arguments are `Result`s because resolver failure must be a value. Falling back to
    /// `PathBuf::from(".")` would silently redirect the SQLite store and the credential read into
    /// the launch directory while `session_status` reported a configured session. Instead the
    /// reason travels: [`PhotonState::unresolved`] turns it into a session that refuses every
    /// command and says which directory could not be resolved.
    ///
    /// `PHOTON_STORE_PATH` wins over the app-data dir, and before the app-data error is
    /// consulted: a lane that names its own store does not depend on a platform directory.
    pub fn try_resolve(
        app_data_dir: Result<PathBuf, String>,
        home_dir: Result<PathBuf, String>,
    ) -> Result<Self, String> {
        let store_path = match store_path_override() {
            Some(path) => path,
            None => app_data_dir
                .map_err(|e| {
                    format!(
                        "the platform app-data directory could not be resolved ({e}), so there is \
                         nowhere to put the Photon store. Set PHOTON_STORE_PATH to name one \
                         explicitly."
                    )
                })?
                .join(STORE_FILE),
        };
        let gmail_secrets_dir = home_dir
            .map_err(|e| {
                format!(
                    "the home directory could not be resolved ({e}), so the parked Gmail \
                     credential directory (~/.photon/gmail/) cannot be located."
                )
            })?
            .join(".photon")
            .join("gmail");
        Ok(Self {
            account: resolved_account(),
            store_path,
            provider_kind: ProviderKind::Gmail,
            gmail_secrets_dir,
        })
    }
}

/// The Photon-local account key for this process: the env override or [`DEFAULT_ACCOUNT`].
/// It does not depend on the platform directories, so it resolves the same either way.
fn resolved_account() -> String {
    std::env::var("PHOTON_ACCOUNT")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_ACCOUNT.to_string())
}

/// The `PHOTON_STORE_PATH` override, when it names something.
fn store_path_override() -> Option<PathBuf> {
    std::env::var("PHOTON_STORE_PATH")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .map(PathBuf::from)
}

// The commands

/// One page of the local inbox projection. A pure store read: it never touches the provider, so
/// it is not single-flighted (single-flight bounds provider traffic, and a local keyset page is
/// not provider traffic).
#[tauri::command]
async fn inbox_page(
    state: tauri::State<'_, PhotonState>,
    account: String,
    page_size: i64,
    cursor: Option<PageCursor>,
) -> Result<InboxPage, SurfaceError> {
    let account = state.account(&account)?;
    let session = state.session()?;
    let limit = clamp_page_size(page_size);

    // No lock across I/O: the only lock here is taken inside the blocking closure and dropped when
    // it returns. Nothing here calls the provider.
    with_session(session, move |s| {
        let (rows, next_cursor) =
            local_page_with_lookahead(&s.headers, &account, cursor.as_ref(), limit)
                .map_err(SurfaceError::store)?;
        let freshness = s.last_freshness.as_ref().map(FreshnessView::from);

        Ok(InboxPage {
            rows: rows
                .into_iter()
                .map(|r| InboxRow {
                    message_ref: r.message_ref,
                    received_at: r.received_at,
                    from_addr: r.from_addr,
                    from_name: r.from_name,
                    subject: r.subject,
                    seen: r.seen,
                    flagged: r.flagged,
                })
                .collect(),
            next_cursor,
            freshness,
        })
    })
    .await
}

/// Fetch page 1 from the provider, ingest it, and reconcile the window. Single-flight: a second
/// concurrent refresh is refused, never queued. Paced: a refresh arriving inside
/// [`MIN_REFRESH_INTERVAL_MS`] of the last completed one, or while a provider backoff holds, is
/// refused with a typed error.
///
/// The provider's continuation is kept on the session for [`refresh_more_inbox`] to spend.
/// Discarding it would mean a mailbox larger than one page could never ingest past its newest
/// page, since page 1 is always the same page. `has_more` on the answer reports whether one is
/// held.
#[tauri::command]
async fn refresh_inbox(
    state: tauri::State<'_, PhotonState>,
    account: String,
    page_size: i64,
) -> Result<RefreshOutcome, SurfaceError> {
    let account = state.account(&account)?;
    let kind = OperationKind::RefreshInbox;
    let _claim = state
        .inflight
        .claim(kind.clone())
        .ok_or_else(|| SurfaceError::busy(&kind))?;
    // Cadence and backoff check, after the single-flight claim and before any provider handle is
    // taken: a refused refresh spends no round trip and releases its claim on the way out.
    state.pacing.admit(&kind, Instant::now())?;
    // Local prerequisites first: a store-less session refuses before any credential work, so a
    // renewal POST is never spent on a command that cannot run.
    let session = state.session()?;
    let limit = clamp_page_size(page_size);
    // Credential check, after every local check and before the round trip: a dead credential can
    // only produce a 401, so the trip is refused before it is spent.
    let provider = admit_provider(&state).await?;

    // Provider I/O: the session mutex is not held here, and the provider handle is reachable only
    // from `state`, never through the session.
    //
    // The transport's own error survives the hop unmapped so the 429-class case is still
    // recognizable; `SurfaceError` has no variant that could carry that distinction back.
    let listed = with_provider(provider, move |p| {
        Ok(p.reader.list_inbox_page(&p.user, limit, None))
    })
    .await?;
    // The round trip is spent, so the pacing floor starts now regardless of outcome.
    state.pacing.refresh_completed(Instant::now());

    let page = match listed {
        Ok(page) => page,
        Err(e) => return Err(note_provider_backoff(&state, e, "listing")),
    };

    // Re-acquire to write: the provider call is finished and its result is an owned value, so the
    // lock is taken for the store writes only.
    //
    // Page-1-anchored: this command fetches with `continuation: None`, the provider's newest
    // page, so the reconcile's coverage is open-ended above. A local row newer than everything
    // page 1 returned is externally gone, not un-looked-at.
    //
    // Both page facts are the transport's answers, passed through untouched.
    // `page.rows.is_empty()` is the filtered count; using it here would let a page of real
    // messages that the membership re-check dropped read as "the Inbox is empty", which deletes
    // every local row. `page.chronological` is the transport's verdict on whether the page came
    // back ordered newest-first, which nothing above the transport can re-derive.
    with_session(session, move |s| {
        s.absorb_page(
            &account,
            &page.rows,
            page.next,
            PageAnchor::FirstPage,
            limit,
            PageFacts {
                raw_page_was_empty: page.raw_page_was_empty,
                chronological: page.chronological,
            },
        )
    })
    .await
}

/// Fetch the next provider page of the walk this session's last refresh started and ingest it,
/// additively.
///
/// `refresh_inbox` fetches page 1 only, so without this command rows below the newest provider
/// page would never ingest and the projection would report `stale_below: N` forever. Ingest is
/// UI-driven (no background scheduler in v1): the continuation is spent by an explicit call.
///
/// It ingests, appends and advances the cursor but runs no reconcile, so it deletes no local row
/// and revises no coverage claim; see [`PhotonSession::absorb_page`]. It answers the last page-1
/// refresh's freshness plus [`RefreshOutcome::ingested`] and `has_more`.
///
/// A walk is not a snapshot. Both providers' offsets are position-based (JMAP `Email/query`
/// position, Gmail's `pageToken`), so a message arriving or leaving above the cursor shifts every
/// later page. Because continuations are additive, the damage is limited to ingest: a row
/// returned twice is deduped by provider identity, and a skipped row stays absent or locally
/// stale, which the freshness marker reports. The next page-1 refresh clears both. Closing this
/// needs the provider's own change cursor (JMAP `Email/queryChanges`, Gmail's `historyId`).
///
/// It claims [`OperationKind::RefreshInbox`], the same single-flight slot as a refresh, and passes
/// the same [`Pacing::admit`] check: it is the same listing route and quota, so a "load more"
/// within [`MIN_REFRESH_INTERVAL_MS`] of the previous listing call is refused with
/// [`SurfaceError::TooSoon`]. A separate slot would be a second, unpaced route to the same
/// endpoint.
#[tauri::command]
async fn refresh_more_inbox(
    state: tauri::State<'_, PhotonState>,
    account: String,
) -> Result<RefreshOutcome, SurfaceError> {
    let account = state.account(&account)?;
    let kind = OperationKind::RefreshInbox;
    let _claim = state
        .inflight
        .claim(kind.clone())
        .ok_or_else(|| SurfaceError::busy(&kind))?;
    state.pacing.admit(&kind, Instant::now())?;
    let session = state.session()?;

    // Store read under the lock, released before the fetch: the held cursor is copied out as an
    // owned value. A session with no cursor refuses here, before any credential work or round
    // trip is spent.
    let wanted = account.clone();
    let cursor = with_session(state.session()?, move |s| s.continuation_for(&wanted)).await?;

    // Credential check, after every local prerequisite.
    let provider = admit_provider(&state).await?;

    // Provider I/O with no lock held, as in `refresh_inbox`, with the same unmapped transport
    // error so the 429-class answer stays recognizable.
    let page_size = cursor.page_size;
    let listed = with_provider(provider, move |p| {
        Ok(p.reader
            .list_inbox_page(&p.user, page_size, Some(&cursor.token)))
    })
    .await?;
    state.pacing.refresh_completed(Instant::now());

    let page = match listed {
        Ok(page) => page,
        Err(e) => return Err(note_provider_backoff(&state, e, "listing continuation")),
    };

    with_session(session, move |s| {
        s.absorb_page(
            &account,
            &page.rows,
            page.next,
            PageAnchor::Continuation,
            page_size,
            PageFacts {
                raw_page_was_empty: page.raw_page_was_empty,
                chronological: page.chronological,
            },
        )
    })
    .await
}

/// Map a provider read failure onto its typed refusal, and remember a 429-class answer. Both
/// read commands funnel their transport error through here, so the backoff is recorded in one
/// place.
///
/// The call that receives the 429 also answers with the typed `ProviderBackoff`. Callers admitted
/// afterwards already get it via `Pacing::admit`; the request that triggered the backoff would
/// otherwise get a generic `Refused`, the least informative answer in the window. The window is
/// the one just installed (`PROVIDER_BACKOFF_MS` from `now`).
fn note_provider_backoff(
    state: &PhotonState,
    e: aruna::gmail::GmailError,
    what: &str,
) -> SurfaceError {
    if matches!(e, aruna::gmail::GmailError::RateLimit) {
        state.pacing.provider_asked_us_to_back_off(Instant::now());
        return SurfaceError::ProviderBackoff {
            operation: what.to_string(),
            retry_after_ms: PROVIDER_BACKOFF_MS,
        };
    }
    // Transient, by judgment: this is a raw, otherwise unclassified `GmailError` (the one named
    // transient signal, `RateLimit`, is handled above). A provider answer this function cannot
    // classify is treated as retryable rather than terminal, since a provider-side hiccup is at
    // least as likely as a permanent rejection and a caller that gives up here loses no more
    // than one wasted retry either way.
    SurfaceError::Refused {
        reason: format!("the provider refused the {what}: {e:?}"),
        terminal: false,
    }
}

/// One message's body, on demand, plain text only. Single-flight per message, and refused while a
/// recorded provider backoff holds (a 429 on the listing route means the provider wants us to
/// stop asking on this one too).
#[tauri::command]
async fn message_body(
    state: tauri::State<'_, PhotonState>,
    account: String,
    message_ref: String,
) -> Result<BodyAvailability, SurfaceError> {
    let account = state.account(&account)?;
    let kind = OperationKind::MessageBody(message_ref.clone());
    let _claim = state
        .inflight
        .claim(kind.clone())
        .ok_or_else(|| SurfaceError::busy(&kind))?;
    state.pacing.admit(&kind, Instant::now())?;
    let session = state.session()?;

    // Store read under the lock, released before the fetch. The identity check runs first: a
    // message with no provider identity refuses before any credential work is spent on it.
    let wanted = message_ref.clone();
    let provider_id: ProviderMessageId = with_session(session, move |s| {
        s.placements
            .resolve_email_id(&account, &wanted)
            .map_err(SurfaceError::store)?
            // Transient: the message's own text names the cure ("refresh, then retry"), since a
            // later local projection may hold the identity this one lacks.
            .ok_or_else(|| SurfaceError::Refused {
                reason: "no provider identity for this message — it is not in the local \
                         projection (refresh, then retry)"
                    .to_string(),
                terminal: false,
            })
    })
    .await?;

    // Credential check, as on the listing route, after the local identity check and before the
    // round trip.
    let provider = admit_provider(&state).await?;

    // Provider I/O with no lock held: the id above is an owned value, and the session guard died
    // with the closure that produced it.
    let fetched = with_provider(provider, move |p| {
        Ok(p.reader.fetch_body(&p.user, &GmailMessageId(provider_id.0)))
    })
    .await?;
    let raw = match fetched {
        Ok(raw) => raw,
        Err(e) => return Err(note_provider_backoff(&state, e, "body read")),
    };

    // The conversion boundary: raw HTML dies in the engine, and the type that leaves this
    // function has no html field to carry it. The transport's own cap is re-applied after
    // conversion because a small HTML source can expand.
    // Terminal: a deterministic conversion failure over this message's own already-fetched bytes;
    // retrying the identical fetch cannot produce different bytes to convert.
    to_body_view(raw, aruna_gmail::transport::BODY_FETCH_CAP).map_err(|e| SurfaceError::Refused {
        reason: e.to_string(),
        terminal: true,
    })
}

#[tauri::command]
async fn archive(
    state: tauri::State<'_, PhotonState>,
    account: String,
    message_ref: String,
) -> Result<VerbOutcome, SurfaceError> {
    let action = Action::Archive {
        message_ref: message_ref.clone(),
    };
    run_verb(
        state,
        account,
        message_ref,
        "archive",
        action,
        VerbDelta::Archived,
    )
    .await
}

#[tauri::command]
async fn unarchive(
    state: tauri::State<'_, PhotonState>,
    account: String,
    message_ref: String,
) -> Result<VerbOutcome, SurfaceError> {
    let action = Action::Unarchive {
        message_ref: message_ref.clone(),
    };
    run_verb(
        state,
        account,
        message_ref,
        "unarchive",
        action,
        VerbDelta::Unarchived,
    )
    .await
}

#[tauri::command]
async fn set_star(
    state: tauri::State<'_, PhotonState>,
    account: String,
    message_ref: String,
    value: bool,
) -> Result<VerbOutcome, SurfaceError> {
    let action = Action::SetFlag {
        message_ref: message_ref.clone(),
        flag: MailFlag::Flagged,
        value,
    };
    run_verb(
        state,
        account,
        message_ref,
        "set_star",
        action,
        VerbDelta::StarSet(value),
    )
    .await
}

/// Undo a verb by the key its command returned.
///
/// The projection comes back stale rather than re-derived here. Undo restores the captured
/// pre-state through the connector (`aruna::Action::inverse` is a descriptor, not what dispatch
/// derives from), so an archive that changed nothing is undone by changing nothing. The shell
/// cannot tell those apart: it would have to read the captured atom map and translate
/// provider-native atoms into placements, which is provider semantics the surface layer must not
/// grow, and a naive inverse delta would misreport any no-op undo. So the local projection is
/// reported unchecked, with the reason, and a refresh re-derives it.
#[tauri::command]
async fn undo(
    state: tauri::State<'_, PhotonState>,
    undo_key: String,
) -> Result<UndoOutcome, SurfaceError> {
    let kind = OperationKind::Undo(undo_key.clone());
    let _claim = state
        .inflight
        .claim(kind.clone())
        .ok_or_else(|| SurfaceError::busy(&kind))?;

    let provider = state.gmail()?;
    let key = undo_key.clone();

    // Provider I/O with no session lock held; this command never takes it.
    with_provider(provider, move |p| {
        let mut bus = lock_bus(p)?;
        bus.undo(&key).map_err(SurfaceError::execute)?;
        undo_outcome_after_undo(&mut *bus, &key)
    })
    .await
}

/// The undo lifecycle as a display truth, including the severed arm, and the restoration verdict
/// beside it. A read: it mints and mutates nothing.
#[tauri::command]
async fn undo_presentation(
    state: tauri::State<'_, PhotonState>,
    undo_key: String,
) -> Result<UndoPresentationReadView, SurfaceError> {
    let provider = state.gmail()?;
    let read = with_provider(provider, move |p| {
        lock_bus(p)?
            .undo_presentation(&undo_key)
            .map_err(SurfaceError::execute)
    })
    .await?;
    Ok(UndoPresentationReadView::from(read))
}

// The triage commands

#[tauri::command]
async fn untrash(
    state: tauri::State<'_, PhotonState>,
    account: String,
    message_ref: String,
) -> Result<VerbOutcome, SurfaceError> {
    run_yellow_door(state, account, message_ref, YellowDoor::Untrash).await
}

#[tauri::command]
async fn unmark_spam(
    state: tauri::State<'_, PhotonState>,
    account: String,
    message_ref: String,
) -> Result<VerbOutcome, SurfaceError> {
    run_yellow_door(state, account, message_ref, YellowDoor::UnmarkSpam).await
}

/// Mark read (`true`) / unread (`false`) — `set_star`'s shape over `MailFlag::Seen`.
#[tauri::command]
async fn set_seen(
    state: tauri::State<'_, PhotonState>,
    account: String,
    message_ref: String,
    value: bool,
) -> Result<VerbOutcome, SurfaceError> {
    run_yellow_door(state, account, message_ref, YellowDoor::SetSeen(value)).await
}

/// A RED verb on one message: mints a one-member plan and answers its review. Never a dispatch.
#[tauri::command]
async fn trash(
    state: tauri::State<'_, PhotonState>,
    account: String,
    message_ref: String,
) -> Result<PlanReviewView, SurfaceError> {
    red_verb_door(&state, PlanVerb::Trash, account, message_ref).await
}

/// A RED verb on one message: mints a one-member plan and answers its review. Never a dispatch.
#[tauri::command]
async fn mark_spam(
    state: tauri::State<'_, PhotonState>,
    account: String,
    message_ref: String,
) -> Result<PlanReviewView, SurfaceError> {
    red_verb_door(&state, PlanVerb::MarkSpam, account, message_ref).await
}

#[tauri::command]
async fn plan_mint(
    state: tauri::State<'_, PhotonState>,
    account: String,
    verb: String,
    member_refs: Vec<String>,
    rationale: Option<String>,
) -> Result<PlanReviewView, SurfaceError> {
    plan_mint_door(&state, account, verb, member_refs, rationale).await
}

#[tauri::command]
async fn plan_review(
    state: tauri::State<'_, PhotonState>,
    plan_id: String,
) -> Result<PlanReviewView, SurfaceError> {
    plan_review_door(&state, plan_id).await
}

#[tauri::command]
async fn plan_approve(
    state: tauri::State<'_, PhotonState>,
    plan_id: String,
    rendered: RenderedViewWire,
    approver: String,
) -> Result<PlanApproveOutcome, SurfaceError> {
    plan_approve_door(&state, plan_id, rendered, approver).await
}

#[tauri::command]
async fn plan_apply(
    state: tauri::State<'_, PhotonState>,
    plan_id: String,
) -> Result<PlanApplyOutcome, SurfaceError> {
    plan_apply_door(&state, plan_id).await
}

#[tauri::command]
async fn set_knob(
    state: tauri::State<'_, PhotonState>,
    act: KnobActWire,
) -> Result<KnobOutcome, SurfaceError> {
    set_knob_door(&state, act).await
}

/// What this session is, including every way it is not working.
///
/// The one exception to every other command's "no I/O, no lock" shape: the epoch half reads
/// `control_epoch` off the store through `with_session`, with no lock held across I/O. A down
/// store (`state.session()` refused) never turns this command into a refusal: the caller still
/// gets `configured: false` and every other field, with `epoch: None` and the reason
/// `store_reason` already carries.
#[tauri::command]
async fn session_status(state: tauri::State<'_, PhotonState>) -> Result<SessionStatus, SurfaceError> {
    let (epoch, epoch_reason) = match state.session() {
        Ok(session) => {
            match with_session(session, |s| s.log.control_epoch().map_err(SurfaceError::store)).await
            {
                Ok(e) => (Some(e), None),
                Err(e) => (None, Some(surface_error_reason(&e))),
            }
        }
        Err(e) => (None, Some(surface_error_reason(&e))),
    };

    Ok(session_status_view(&state, epoch, epoch_reason, unix_now()))
}

// The app

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        // No plugin is registered. Every plugin is an IPC capability surface; the opener plugin
        // that shipped in the scaffold is removed along with its dependency
        // (`tests/surface_contract.rs` checks both halves).
        .setup(|app| {
            let paths = app.path();
            // The platform app-data dir is the store's home; `home_dir` locates the operator's
            // parked `~/.photon/gmail/`. A resolver failure is neither fatal nor silent: the
            // resolvers' own errors are handed to `try_resolve` as values, and a session that
            // cannot know where its data lives is built unconfigured, carrying the reason. It is
            // never redirected into the process working directory.
            let state = match SessionConfig::try_resolve(
                paths.app_data_dir().map_err(|e| e.to_string()),
                paths.home_dir().map_err(|e| e.to_string()),
            ) {
                Ok(config) => {
                    // The store's own directory, created where the config actually points: the
                    // app-data dir, or the `PHOTON_STORE_PATH` override's parent.
                    if let Some(parent) = config.store_path.parent() {
                        if !parent.as_os_str().is_empty() {
                            if let Err(e) = std::fs::create_dir_all(parent) {
                                eprintln!(
                                    "photon: could not create the store directory {}: {e}",
                                    parent.display()
                                );
                            }
                        }
                    }
                    PhotonState::new(config)
                }
                Err(reason) => {
                    eprintln!("photon: {reason}");
                    PhotonState::unresolved(reason)
                }
            };
            app.manage(state);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            inbox_page,
            refresh_inbox,
            refresh_more_inbox,
            message_body,
            archive,
            unarchive,
            set_star,
            undo,
            undo_presentation,
            session_status,
            trash,
            untrash,
            mark_spam,
            unmark_spam,
            set_seen,
            plan_mint,
            plan_review,
            plan_approve,
            plan_apply,
            set_knob
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    mod census;
    pub(crate) mod fixtures;

    /// THE ROUTE WITNESS (route-CORRECT per door). Its
    /// KEY SET is DERIVED: the commands this source declares — every function
    /// carrying Tauri's command attribute, the same scan `tests/surface_contract.rs`'s
    /// `declared_commands` runs and pins equal to `generate_handler!`'s set — must be exactly the
    /// commands this table routes, so a new command with no route entry FAILS here instead of
    /// passing unexamined. Each of the ten triage commands is exactly ONE delegation to its own door
    /// with its own verb / route value; each v1 command's body carries its own operation. A SOURCE
    /// witness, for the reason `tests/surface_contract.rs` gives for its own: a command needs a
    /// running app (`tauri::State` has no constructor outside one), so the command body is
    /// observable only as bytes; the doors it delegates to are exercised behaviourally by the tests
    /// above. The attribute is assembled at runtime so this test's own text never reads as a
    /// declared command to either scan.
    #[test]
    fn each_new_command_is_one_delegation_to_its_own_door() {
        enum Route {
            /// The whole body, whitespace-folded.
            Exactly(&'static str),
            /// Fragments the whitespace-folded body must carry (a v1 command's own operation).
            Carries(&'static [&'static str]),
        }
        let source = include_str!("lib.rs").replace("\r\n", "\n");
        let attribute = ["#[tauri", "::command]"].concat();
        let head = format!("{attribute}\nasync fn ");
        let declared: BTreeSet<String> = source
            .match_indices(&head)
            .map(|(at, _)| {
                let name = &source[at + head.len()..];
                name[..name.find('(').expect("a command's argument list")].to_string()
            })
            .collect();
        let body = |name: &str| -> String {
            let at = source
                .find(&format!("{head}{name}("))
                .unwrap_or_else(|| panic!("the `{name}` command is declared"));
            let rest = &source[at..];
            let open = rest.find("{\n").expect("a body opens") + 2;
            let close = rest[open..].find("\n}\n").expect("a body closes") + open;
            rest[open..close].split_whitespace().collect::<Vec<_>>().join(" ")
        };
        let routes: Vec<(&str, Route)> = vec![
            ("inbox_page", Route::Carries(&["local_page_with_lookahead("])),
            ("refresh_inbox", Route::Carries(&["OperationKind::RefreshInbox", "admit_provider(&state)"])),
            ("refresh_more_inbox", Route::Carries(&["OperationKind::RefreshInbox", "admit_provider(&state)"])),
            (
                "message_body",
                Route::Carries(&["OperationKind::MessageBody(message_ref.clone())", "admit_provider(&state)"]),
            ),
            (
                "archive",
                Route::Exactly(
                    "let action = Action::Archive { message_ref: message_ref.clone(), }; run_verb( state, \
                     account, message_ref, \"archive\", action, VerbDelta::Archived, ) .await",
                ),
            ),
            (
                "unarchive",
                Route::Exactly(
                    "let action = Action::Unarchive { message_ref: message_ref.clone(), }; run_verb( state, \
                     account, message_ref, \"unarchive\", action, VerbDelta::Unarchived, ) .await",
                ),
            ),
            (
                "set_star",
                Route::Exactly(
                    "let action = Action::SetFlag { message_ref: message_ref.clone(), flag: MailFlag::Flagged, \
                     value, }; run_verb( state, account, message_ref, \"set_star\", action, \
                     VerbDelta::StarSet(value), ) .await",
                ),
            ),
            ("undo", Route::Carries(&["OperationKind::Undo(undo_key.clone())", "bus.undo(&key)"])),
            ("undo_presentation", Route::Carries(&[".undo_presentation(&undo_key)"])),
            ("session_status", Route::Carries(&["session_status_view("])),
            ("trash", Route::Exactly("red_verb_door(&state, PlanVerb::Trash, account, message_ref).await")),
            ("mark_spam", Route::Exactly("red_verb_door(&state, PlanVerb::MarkSpam, account, message_ref).await")),
            ("untrash", Route::Exactly("run_yellow_door(state, account, message_ref, YellowDoor::Untrash).await")),
            (
                "unmark_spam",
                Route::Exactly("run_yellow_door(state, account, message_ref, YellowDoor::UnmarkSpam).await"),
            ),
            (
                "set_seen",
                Route::Exactly("run_yellow_door(state, account, message_ref, YellowDoor::SetSeen(value)).await"),
            ),
            ("plan_mint", Route::Exactly("plan_mint_door(&state, account, verb, member_refs, rationale).await")),
            ("plan_review", Route::Exactly("plan_review_door(&state, plan_id).await")),
            ("plan_approve", Route::Exactly("plan_approve_door(&state, plan_id, rendered, approver).await")),
            ("plan_apply", Route::Exactly("plan_apply_door(&state, plan_id).await")),
            ("set_knob", Route::Exactly("set_knob_door(&state, act).await")),
        ];
        let routed: BTreeSet<String> = routes.iter().map(|(name, _)| name.to_string()).collect();
        assert_eq!(routed.len(), routes.len(), "one route per command");
        assert_eq!(
            routed, declared,
            "the route table must name EXACTLY the declared commands — a declared command with no \
             route entry is a door nobody witnessed"
        );
        for (name, route) in routes {
            let body = body(name);
            match route {
                Route::Exactly(expected) => {
                    assert_eq!(body, expected, "the `{name}` command routes to its own door")
                }
                Route::Carries(fragments) => {
                    for fragment in fragments {
                        assert!(body.contains(fragment), "the `{name}` command carries `{fragment}`: {body}");
                    }
                }
            }
        }
    }

    // ===========================================================================================
    // THE REQUEST THAT RECEIVES THE 429 RETURNS THE TYPED BACKOFF ITSELF.
    //
    // `note_provider_backoff` INSTALLED the backoff window (`provider_asked_us_to_back_off`) but
    // then answered a generic `SurfaceError::Refused` — so the FIRST caller to actually see the
    // 429 got the least informative refusal of anyone: every SUBSEQUENT caller (admitted through
    // `Pacing::admit`) sees `ProviderBackoff { retry_after_ms }`, a wait the UI can render, while
    // the one request that triggered it is told nothing but "refused". The fix maps a `RateLimit`
    // straight to `ProviderBackoff` using the window it just installed.
    // ===========================================================================================
    #[test]
    fn note_provider_backoff_answers_the_typed_backoff_on_the_triggering_call_itself() {
        // The ONE guard, bound before the state. It was a FIXED "nonexistent" name —
        // which the state CREATES (a 300 KB store left per run, re-opened by the next one).
        let store = aruna::test_temp::TempFile::sqlite("photon-f4-backoff-nonexistent");
        let secrets = aruna::test_temp::TempDir::uncreated("photon-f4-backoff-no-secrets");
        let state = PhotonState::new(SessionConfig {
            account: "acct".to_string(),
            store_path: store.to_path_buf(),
            provider_kind: ProviderKind::Jmap,
            gmail_secrets_dir: secrets.to_path_buf(),
        });

        match note_provider_backoff(&state, aruna::gmail::GmailError::RateLimit, "listing") {
            SurfaceError::ProviderBackoff {
                operation,
                retry_after_ms,
            } => {
                assert_eq!(operation, "listing");
                assert!(
                    retry_after_ms > 0 && retry_after_ms <= PROVIDER_BACKOFF_MS,
                    "the freshly-installed window: {retry_after_ms}"
                );
            }
            other => panic!(
                "the call that RECEIVED the 429 must answer the typed backoff, never a generic \
                 refusal: {other:?}"
            ),
        }

        // The window really was installed — a caller admitted right after also sees it.
        match state.pacing.admit(&OperationKind::RefreshInbox, Instant::now()) {
            Err(SurfaceError::ProviderBackoff { .. }) => {}
            other => panic!("the backoff must be recorded, not just reported once: {other:?}"),
        }
    }

    #[test]
    fn note_provider_backoff_leaves_a_non_rate_limit_error_a_plain_refusal() {
        // The ONE guard, bound before the state (a fixed name the state created).
        let store = aruna::test_temp::TempFile::sqlite("photon-f4-non-ratelimit-nonexistent");
        let secrets = aruna::test_temp::TempDir::uncreated("photon-f4-non-ratelimit-no-secrets");
        let state = PhotonState::new(SessionConfig {
            account: "acct".to_string(),
            store_path: store.to_path_buf(),
            provider_kind: ProviderKind::Jmap,
            gmail_secrets_dir: secrets.to_path_buf(),
        });

        match note_provider_backoff(&state, aruna::gmail::GmailError::Backend(500), "listing") {
            SurfaceError::Refused { .. } => {}
            other => panic!("a non-429 transport failure stays a plain refusal: {other:?}"),
        }
    }

    // ===========================================================================================
    // AN UNRESOLVABLE PATH IS A REASON, NEVER THE PROCESS WORKING DIRECTORY.
    // ===========================================================================================

    /// Both halves of the resolver seam live in ONE test because both drive the same process-wide
    /// environment variable, and `cargo test` runs tests on parallel threads: two tests toggling
    /// `PHOTON_STORE_PATH` would race each other into a flake that has nothing to do with the
    /// property either is checking.
    #[test]
    fn an_unresolvable_app_data_dir_is_an_error_carrying_the_reason_not_a_dot_fallback() {
        // The `PHOTON_STORE_PATH` override must not be set for the first half: it legitimately
        // makes the app-data failure irrelevant, which is the second half.
        let previous = std::env::var("PHOTON_STORE_PATH").ok();
        std::env::remove_var("PHOTON_STORE_PATH");

        let err = SessionConfig::try_resolve(
            Err("no app data dir on this platform".to_string()),
            Ok(PathBuf::from("/home/someone")),
        )
        .expect_err("an unresolvable app-data dir has no honest fallback");
        assert!(
            err.contains("no app data dir on this platform"),
            "the resolver's OWN error must travel: {err}"
        );
        assert!(
            err.contains("PHOTON_STORE_PATH"),
            "the reason must name the way out: {err}"
        );

        let err = SessionConfig::try_resolve(
            Ok(PathBuf::from("/app/data")),
            Err("no home dir".to_string()),
        )
        .expect_err("an unresolvable home dir cannot locate the parked credential");
        assert!(err.contains("no home dir"), "{err}");
        assert!(err.contains(".photon/gmail"), "the reason names what it could not locate: {err}");

        // ...and a lane that NAMES its own store does not depend on the platform directory at all,
        // so the same app-data failure must not refuse it.
        std::env::set_var("PHOTON_STORE_PATH", "/explicit/store.sqlite");
        let config = SessionConfig::try_resolve(
            Err("no app data dir".to_string()),
            Ok(PathBuf::from("/home/someone")),
        )
        .expect("an explicitly named store needs no app-data dir");
        assert_eq!(config.store_path, PathBuf::from("/explicit/store.sqlite"));

        match previous {
            Some(v) => std::env::set_var("PHOTON_STORE_PATH", v),
            None => std::env::remove_var("PHOTON_STORE_PATH"),
        }
    }
}
