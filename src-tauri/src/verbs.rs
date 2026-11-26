//! The single-message verb path: dispatch, the outcome after the effect, undo, the YELLOW verbs.

use std::sync::{Arc, Mutex};

use aruna::read_coordinator::VerbDelta;
use aruna::{
    Action, Command, CommandBus, Connector, Executed, Facet, IntentLog, MailFlag, WitnessRecord,
};

use crate::error::{surface_error_reason, SurfaceError};
use crate::ipc::{
    ProjectionState, RestorationView, UndoOutcome, UndoPresentationReadView, UndoPresentationView,
    VerbOutcome,
};
use crate::plumbing::{lock_bus, with_provider, with_session};
use crate::provider::mutation_fence;
use crate::session::PhotonSession;
use crate::single_flight::OperationKind;
use crate::state::PhotonState;

/// The verdict a verb command owes right after its verb applied ([`CommandBus::restoration`]). A
/// read that fails is [`RestorationView::Unreadable`]: the verb happened, and its undo key must
/// still reach the renderer.
pub(crate) fn restoration_after_verb<L: IntentLog, C: Connector>(
    bus: &CommandBus<L, C>,
    key: &str,
) -> Option<RestorationView> {
    match bus.restoration(key) {
        Ok(verdict) => verdict.as_ref().map(RestorationView::from),
        Err(_) => Some(RestorationView::Unreadable),
    }
}

/// The restoration verdict for an operation this call's dispatch applied. A witness write that
/// failed after the settlement is named for what it is ([`RestorationView::WitnessWriteFailed`]);
/// otherwise the stored witness is read ([`restoration_after_verb`]).
fn restoration_after_execute<L: IntentLog, C: Connector>(
    bus: &CommandBus<L, C>,
    key: &str,
    executed: &Executed,
) -> Option<RestorationView> {
    match executed.witness {
        WitnessRecord::WriteFailed(_) => Some(RestorationView::WitnessWriteFailed),
        WitnessRecord::Persisted | WitnessRecord::NotDispatched => restoration_after_verb(bus, key),
    }
}

/// `run_verb`'s dispatch, on the bus the caller locked: execute, then the restoration verdict the
/// effect witness allows. An engine refusal is projected through [`SurfaceError::execute_fenced`]
/// under this arm's fence sentence. An applied operation whose witness write failed is `Ok`: the
/// caller keeps the undo key it minted, writes the projection and names the unrecorded witness
/// beside the offer. A retry of the key re-dispatches nothing.
pub(crate) fn verb_on_bus<L: IntentLog, C: Connector>(
    bus: &mut CommandBus<L, C>,
    command: &Command,
    fence_reason: Option<&str>,
) -> Result<Option<RestorationView>, SurfaceError> {
    let executed = bus
        .execute(command)
        .map_err(|e| SurfaceError::execute_fenced(e, fence_reason))?;
    Ok(restoration_after_execute(bus, &command.idempotency_key, &executed))
}

/// The three YELLOW verbs, one path. Applied through `CommandBus` (journaled,
/// pre-state-captured, undoable, epoch-fenced), then the projection is maintained from
/// engine-known data only: the coordinator's post-verb API takes `(account, ref, delta)` and has
/// no header-content parameter a renderer could forge through.
pub(crate) async fn run_verb(
    state: tauri::State<'_, PhotonState>,
    account: String,
    message_ref: String,
    verb: &'static str,
    action: Action,
    // Not read here: the projection path derives its own delta from the intent row it looks up by
    // key (`verb_delta_for_action`, engine-side), so a caller-supplied delta can never disagree
    // with what the store recorded. Kept so each call site still names its verb's delta, but
    // unused past this signature.
    _delta: VerbDelta,
) -> Result<VerbOutcome, SurfaceError> {
    let account = state.account(&account)?;
    let kind = OperationKind::Verb(message_ref.clone());
    let _claim = state
        .inflight
        .claim(kind.clone())
        .ok_or_else(|| SurfaceError::busy(&kind))?;

    let provider = state.gmail()?;
    let session = state.session()?;
    let undo_key = state.mint_key(verb, &message_ref);
    // The fence is read before the dispatch and carried into the closure as an owned value: it is
    // a property of this session's arm, not of the failure, and the refusal it explains is decided
    // below the seam where this string cannot reach. `None` is the unconfigured arm's sentence:
    // this path is past `state.gmail()?`, so the arm in hand is the Gmail one and the fence
    // sentence is its own. Nothing here derives an unconfigured verdict, so nothing here may quote
    // one.
    let (_mutations_live, fence_reason) =
        mutation_fence(&state.credential.snapshot().provider, None);

    // Provider I/O (through the mutation boundary) with no session lock held. The bus's own mutex
    // is taken inside the blocking closure and released before the projection write below. The
    // restoration verdict is read under the same lock, right after the verb applied.
    let key = undo_key.clone();
    let acct = account.clone();
    let restoration = with_provider(provider, move |p| {
        let command = Command::new(key, acct, Facet::Mail, action);
        verb_on_bus(&mut *lock_bus(p)?, &command, fence_reason.as_deref())
    })
    .await?;

    verb_outcome_after_effect(session, undo_key, restoration).await
}

/// `run_verb`'s tail: everything after the provider effect applied.
///
/// Re-acquire to write. The verb has already succeeded, so a projection failure here is not a
/// verb failure: it becomes the `Stale` arm, returned to the UI as a visible row state. The
/// write goes through the single projection entry point, keyed by the intent alone: it reads the
/// row itself (account, message_ref, action, status, projected, basis_ingest_revision), because
/// a caller-supplied basis could disagree with the row and yield a false `Current`. The marker
/// and the placement/header write commit as one transaction inside it, and `run_verb`'s own
/// verb still marks itself `projected` (nothing else visits a lone, non-plan intent to do it).
///
/// The session re-acquisition itself can fail after the verb applied (`with_session`'s
/// `Internal`: a poisoned lock, a failed join). [`projection_after_effect`] folds that into the
/// `Stale` arm rather than a bare error that would discard an applied verb's undo key. Always
/// `Ok`: this tail is the verb's outcome, and the verb already happened.
async fn verb_outcome_after_effect(
    session: Arc<Mutex<PhotonSession>>,
    undo_key: String,
    restoration: Option<RestorationView>,
) -> Result<VerbOutcome, SurfaceError> {
    let key_for_projection = undo_key.clone();
    let projection = projection_after_effect(session, move |s| {
        ProjectionState::from(s.coordinator.project_applied_intent(&key_for_projection))
    })
    .await;

    Ok(VerbOutcome {
        applied: true,
        undo_key,
        projection,
        restoration,
    })
}

/// The rule for every step after the provider effect: a bookkeeping failure after an effect is a
/// labelled field of the outcome, never a replacement of it. The local-projection write runs
/// under a re-acquired session; if that fails (`with_session`'s `Internal`: a poisoned lock, a
/// failed join), the projection is `Stale { reason }` naming why, and the caller's applied
/// outcome stands. Used by both commands that write a projection after an effect (`run_verb`'s
/// tail, [`verb_outcome_after_effect`], and `plan_apply_door`).
pub(crate) async fn projection_after_effect<F>(session: Arc<Mutex<PhotonSession>>, write: F) -> ProjectionState
where
    F: FnOnce(&mut PhotonSession) -> ProjectionState + Send + 'static,
{
    match with_session(session, move |s| Ok(write(s))).await {
        Ok(projection) => projection,
        Err(e) => ProjectionState::Stale {
            reason: format!(
                "the effect applied, but the session could not be re-acquired to write the local row: {}",
                surface_error_reason(&e)
            ),
        },
    }
}

/// The `undo` command's tail: everything after `bus.undo` committed, namely the presentation
/// read-back and the outcome built from it.
///
/// A read-back that fails after the undo committed must not replace the undo's outcome with a
/// bare error. It becomes [`UndoPresentationView::UnreadableAfterUndo`] with restoration
/// [`RestorationView::Unreadable`] and `undone: false` (`undone` is true only on a read-back
/// `Undone`). Always `Ok`: the undo already happened.
pub(crate) fn undo_outcome_after_undo<L: IntentLog, C: Connector>(
    bus: &mut CommandBus<L, C>,
    key: &str,
) -> Result<UndoOutcome, SurfaceError> {
    let read = match bus.undo_presentation(key) {
        Ok(read) => UndoPresentationReadView::from(read),
        Err(_) => UndoPresentationReadView {
            presentation: UndoPresentationView::UnreadableAfterUndo,
            restoration: Some(RestorationView::Unreadable),
        },
    };

    Ok(UndoOutcome {
        undone: read.presentation == UndoPresentationView::Undone,
        presentation: read.presentation,
        restoration: read.restoration,
        projection: ProjectionState::Stale {
            reason: UNDO_PROJECTION_STALE_REASON.to_string(),
        },
    })
}

/// Why an undo's local projection is always reported stale (see [`undo`]'s doc).
const UNDO_PROJECTION_STALE_REASON: &str = "the undo restored the captured pre-state below the surface; the local row is \
                     re-derived by a refresh, never guessed here";

/// The three YELLOW commands: one route table, so each one's action and projection delta are
/// decided in one place and tested together. Each runs [`run_verb`]'s shape: single-flight per
/// message, the fence sentence carried, the projection written from engine-known data only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum YellowDoor {
    Untrash,
    UnmarkSpam,
    SetSeen(bool),
}

impl YellowDoor {
    /// The verb token the session's idempotency key is minted under.
    pub(crate) fn verb(self) -> &'static str {
        match self {
            YellowDoor::Untrash => "untrash",
            YellowDoor::UnmarkSpam => "unmark_spam",
            YellowDoor::SetSeen(_) => "set_seen",
        }
    }

    pub(crate) fn action(self, message_ref: &str) -> Action {
        let message_ref = message_ref.to_string();
        match self {
            YellowDoor::Untrash => Action::Untrash { message_ref },
            YellowDoor::UnmarkSpam => Action::UnmarkSpam { message_ref },
            YellowDoor::SetSeen(value) => Action::SetFlag {
                message_ref,
                flag: MailFlag::Seen,
                value,
            },
        }
    }

    pub(crate) fn delta(self) -> VerbDelta {
        match self {
            YellowDoor::Untrash => VerbDelta::Untrashed,
            YellowDoor::UnmarkSpam => VerbDelta::SpamSet(false),
            YellowDoor::SetSeen(value) => VerbDelta::SeenSet(value),
        }
    }
}

pub(crate) async fn run_yellow_door(
    state: tauri::State<'_, PhotonState>,
    account: String,
    message_ref: String,
    door: YellowDoor,
) -> Result<VerbOutcome, SurfaceError> {
    let action = door.action(&message_ref);
    run_verb(state, account, message_ref, door.verb(), action, door.delta()).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use aruna::SqliteIntentLog;

    use crate::provider::MUTATIONS_FENCED_REASON;
    use crate::tests::fixtures::{
        plan_bus, session_for, unique_store, R1LabelConnector, R2_3_WITNESS_WRITE_FAILPOINT,
    };

    #[test]
    fn e7_the_verb_and_undo_doors_carry_the_verdict_and_a_failed_read_never_hides_an_applied_verb() {
        // Pid-only name → a unique, guarded store (declared before the bus).
        let path = unique_store("e7-verb");
        let mut bus = CommandBus::new(SqliteIntentLog::open(&path).unwrap(), aruna::CountingConnector::new());
        let archive = |key: &str| {
            Command::new(key, "acct", Facet::Mail, Action::Archive { message_ref: format!("m-{key}") })
        };
        // A connector on the trait default observes no vector: the verb door's verdict is
        // UNDETERMINED (no effect witness), never the ordinary offer.
        bus.execute(&archive("k-e7")).unwrap();
        assert_eq!(restoration_after_verb(&bus, "k-e7"), Some(RestorationView::NoEffectWitness));
        assert_eq!(restoration_after_verb(&bus, "k-e7-nobody"), None);
        // The undo_presentation door's answer: the bare-string presentation (trap 2) beside the
        // tagged verdict; an unknown key is `unknown` with no verdict.
        let read = UndoPresentationReadView::from(bus.undo_presentation("k-e7").unwrap());
        assert_eq!(
            serde_json::to_value(&read).unwrap(),
            serde_json::json!({ "presentation": "none", "restoration": { "verdict": "no_effect_witness" } })
        );
        assert_eq!(
            serde_json::to_value(UndoPresentationReadView::from(None)).unwrap(),
            serde_json::json!({ "presentation": "unknown", "restoration": null })
        );
        // A witness that does not read back (a non-canonical vector — the store refuses it as a
        // `LogError`): the verb APPLIED, so its door answers `unreadable`, never an error that
        // would lose the undo key.
        bus.execute(&archive("k-e7-bad")).unwrap();
        rusqlite::Connection::open(&path)
            .unwrap()
            .execute(
                "UPDATE intents SET effect_label_vector = '[\"b\",\"a\"]' WHERE idempotency_key = 'k-e7-bad';",
                [],
            )
            .unwrap();
        assert!(bus.restoration("k-e7-bad").is_err(), "precondition: the witness read fails");
        assert_eq!(restoration_after_verb(&bus, "k-e7-bad"), Some(RestorationView::Unreadable));
        drop(bus);
        std::fs::remove_file(&path).ok();
    }

    /// Reproduction probe, adapted:
    /// the original probe drove ONLY `verb_on_bus` (the shared dispatch primitive) and asserted the intent
    /// was marked immediately after — but `verb_on_bus` is generic over `L: IntentLog` alone, with
    /// NO coordinator in scope, so it can never reach `ReadCoordinator::project_applied_intent`
    /// (the ONE place `intents.projected` may now be written, atomically with the placement/header
    /// write — build note (b): the marker and the write are ONE transaction, so marking eagerly at
    /// dispatch time, decoupled from the write, would be exactly the unsafe shape the fix closes,
    /// not a fix). This witness instead drives `run_verb`'s OWN real two-step shape by hand —
    /// dispatch through `verb_on_bus` over the bus, then project through the door over a SEPARATE
    /// `ReadCoordinator` opened on the SAME store (the
    /// concrete Gmail connector needs a real network round trip run_verb() end-to-end would incur,
    /// which no test in this suite makes) — and asserts the intent is marked after both steps,
    /// which is what "a single verb run marks its own intent projected" means once `verb_on_bus`
    /// alone cannot be the one to do it.
    #[test]
    fn a_single_verb_marks_its_intent_projected() {
        let (path, mut bus, refs) = plan_bus("driver-r5-p4", 1, |_| R1LabelConnector::default());
        let command = Command::new(
            "k-driver-r5-p4".to_string(),
            "acct".to_string(),
            Facet::Mail,
            Action::Untrash { message_ref: refs[0].clone() },
        );
        let result = verb_on_bus(&mut bus, &command, None);
        assert!(result.is_ok(), "the single verb must apply successfully: {result:?}");
        assert_eq!(
            bus.log().get("k-driver-r5-p4").unwrap().expect("recorded").status,
            aruna::IntentStatus::Applied
        );
        // `run_verb`'s own remaining step: project through the ONE door, on a separate
        // coordinator over the SAME store — exactly what `run_verb`'s real second acquisition
        // does (`with_session`, after the dispatch's bus lock is released).
        // The door is now KEYED BY THE INTENT ALONE — it reads account, message_ref,
        // action and basis from the row itself, so this call site no longer derives a delta or
        // reads a basis to pass in.
        let mut coordinator =
            aruna::read_coordinator::ReadCoordinator::open(&path).expect("open the coordinator on the same store");
        coordinator
            .project_applied_intent(&command.idempotency_key)
            .expect("project the single verb's own effect");
        let unprojected = bus
            .log()
            .applied_unprojected_forward_intents()
            .expect("read unprojected");
        assert!(
            unprojected.is_empty(),
            "RED at 6c49b97: a single successful verb run must mark its own intent projected — \
             nothing else will ever visit a lone (non-plan) intent to do it, but \
             applied_unprojected_forward_intents() still returns it: {:?}",
            unprojected
                .iter()
                .map(|i| i.command.idempotency_key.clone())
                .collect::<Vec<_>>()
        );
        drop(bus);
        drop(coordinator);
        std::fs::remove_file(&path).ok();
    }

    /// The VERB door: a witness write that fails after the effect
    /// settled is the applied result, NAMED — `run_verb`'s dispatch (`verb_on_bus`) answers `Ok`
    /// with the `witness_write_failed` verdict (so the door keeps the undo key it minted and writes
    /// the projection), the operation is durably `Applied` under that ONE key, and a retry of the
    /// key re-dispatches nothing and mints nothing.
    #[test]
    fn a_witness_write_failure_after_settlement_keeps_the_verbs_undo_key_and_names_the_unrecorded_witness() {
        let (path, mut bus, refs) = plan_bus("cli-r2-r2-3-verb", 1, |_| R1LabelConnector::default());
        bus.connector().witness.set(true);
        rusqlite::Connection::open(&path)
            .unwrap()
            .execute_batch(R2_3_WITNESS_WRITE_FAILPOINT)
            .expect("arm the failpoint");
        let command = Command::new("k-r2-3".to_string(), "acct".to_string(), Facet::Mail, Action::Untrash { message_ref: refs[0].clone() });
        assert_eq!(
            verb_on_bus(&mut bus, &command, Some(MUTATIONS_FENCED_REASON)),
            Ok(Some(RestorationView::WitnessWriteFailed)),
            "the applied result, the unrecorded witness named"
        );
        assert_eq!(bus.log().get("k-r2-3").unwrap().expect("recorded").status, aruna::IntentStatus::Applied);
        assert_eq!(bus.connector().applied.borrow().len(), 1, "dispatched once");
        // A retry under the SAME key: the settled operation's replay — no second dispatch, and the
        // stored verdict reads UNDETERMINED (no effect witness).
        assert_eq!(
            verb_on_bus(&mut bus, &command, Some(MUTATIONS_FENCED_REASON)),
            Ok(Some(RestorationView::NoEffectWitness))
        );
        assert_eq!(bus.connector().applied.borrow().len(), 1, "a retry never re-dispatches an applied operation");
        let intents: i64 = rusqlite::Connection::open(&path)
            .unwrap()
            .query_row("SELECT COUNT(*) FROM intents;", [], |r| r.get(0))
            .unwrap();
        assert_eq!(intents, 1, "one operation, one key — never a second key for an applied operation");
        drop(bus);
        std::fs::remove_file(&path).ok();
    }

    /// The verb APPLIED; re-acquiring the session to write the local projection then
    /// fails (a poisoned session lock — `with_session`'s `Internal`). That used to replace the
    /// whole `VerbOutcome` with a bare `Internal`, losing the undo key of an applied verb. The
    /// outcome is kept with the failure folded into `Stale { reason }`.
    #[test]
    fn a_poisoned_session_after_the_effect_keeps_the_verb_outcome_with_a_stale_projection() {
        let (path, state, session) = session_for("r6-e3-poisoned-session");
        let poisoner = Arc::clone(&session);
        let _ = std::thread::spawn(move || {
            let _guard = poisoner.lock().expect("lock before poisoning");
            panic!("test: poison the session lock");
        })
        .join();
        assert!(session.is_poisoned(), "precondition: the session lock is poisoned");
        let outcome = tauri::async_runtime::block_on(verb_outcome_after_effect(
            Arc::clone(&session),
            "k-r6-e3-verb".to_string(),
            Some(RestorationView::WithinClosure),
        ))
        .expect("the verb applied: its outcome and undo key are kept, never a bare error");
        assert!(outcome.applied);
        assert_eq!(outcome.undo_key, "k-r6-e3-verb");
        assert_eq!(outcome.restoration, Some(RestorationView::WithinClosure));
        match outcome.projection {
            ProjectionState::Stale { reason } => assert!(reason.contains("poisoned"), "the real reason: {reason}"),
            other => panic!("a projection that was never written is never Current: {other:?}"),
        }
        drop(session);
        drop(state);
        drop(path);
    }

    /// `bus.undo` COMMITTED, then the presentation read-back failed (the restoration witness's own
    /// corruption: a stored effect vector the store refuses to read back). That used to replace the
    /// undo's outcome with a bare error. The door answers the NEW named arm —
    /// `unreadable_after_undo` — with restoration `unreadable`, never `unknown` (which means "no
    /// intent under this key") and never an error.
    #[test]
    fn an_undo_whose_presentation_read_fails_answers_the_named_arm_never_a_bare_error() {
        let path = unique_store("r6-e3-undo-read-back");
        let mut bus = CommandBus::new(SqliteIntentLog::open(&path).unwrap(), aruna::CountingConnector::new());
        let archive = Command::new(
            "k-r6-e3-undo",
            "acct",
            Facet::Mail,
            Action::Archive { message_ref: "m-r6-e3-undo".to_string() },
        );
        bus.execute(&archive).unwrap();
        rusqlite::Connection::open(&path)
            .unwrap()
            .execute(
                "UPDATE intents SET effect_label_vector = '[\"b\",\"a\"]' WHERE idempotency_key = 'k-r6-e3-undo';",
                [],
            )
            .unwrap();
        bus.undo("k-r6-e3-undo").expect("the undo itself commits");
        assert!(bus.undo_presentation("k-r6-e3-undo").is_err(), "precondition: the presentation read-back fails");
        let outcome = undo_outcome_after_undo(&mut bus, "k-r6-e3-undo")
            .expect("the undo committed: its outcome is answered, never a bare error");
        let wire = serde_json::to_value(&outcome).unwrap();
        assert_eq!(wire["presentation"], "unreadable_after_undo", "{wire}");
        assert_eq!(wire["restoration"], serde_json::json!({ "verdict": "unreadable" }), "{wire}");
        assert_eq!(wire["undone"], false, "not confirmed — the read-back failed: {wire}");
        assert_eq!(wire["projection"]["state"], "stale", "{wire}");
        drop(bus);
        drop(path);
    }
}
