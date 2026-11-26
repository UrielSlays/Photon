//! Settlement-outcome classes: outcome propagation, terminal overwrite, and races with adjudication.

use super::*;
use crate::bus::UndoDriveOutcome;
use crate::fact_store::fact_payload_from_json;
use crate::keys::undo_child_key;

// ═══════════════════════════════════════════════════════════════════════════════════
// THE OUTCOME-PROPAGATION CLASS, swept. Four edges
// are one shape: a settlement outcome exists and a CALLER discards or mis-projects an
// axis of it. Each RED below is the discriminating probe for one edge of that class.
// ═══════════════════════════════════════════════════════════════════════════════════

/// A forward action + its DEFERRED undo child, admitted for real and left `Pending` — the
/// row every undo witness drives. Returns the child's key.
fn deferred_undo_child<C: Connector>(
    path: &std::path::Path,
    bus: &mut CommandBus<SqliteIntentLog, C>,
    key: &str,
) -> String {
    bus.execute(&archive_cmd(key))
        .expect("the forward action applies");
    let peer_key = format!("{key}-peer");
    seed_pending_peer(path, bus, &peer_key);
    assert!(
        matches!(bus.undo(key), Err(ExecuteError::InProgress)),
        "precondition: the child is ADMITTED and deferred behind a live predecessor"
    );
    let child_key = undo_child_key(&opaque_intent_id(path, key));
    terminalize_peer(path, &peer_key);
    child_key
}

/// The crash `verify_undo`'s HEAL ORDER leaves behind: the parent's `Undone` committed and
/// the process died before the child's own settlement. Hand-written, because the window is
/// exactly one statement wide and no seam can be placed inside it.
fn crash_after_the_parent_flip(path: &std::path::Path, parent_key: &str) {
    raw_conn(path)
        .execute(
            "UPDATE intents SET status = 'undone' WHERE idempotency_key = ?1;",
            rusqlite::params![parent_key],
        )
        .expect("the parent flip commits");
}

#[test]
fn crash_convergence_settles_a_claimed_undo_attempt_through_the_ledger() {
    // ═══, arm 1 (CLAIMED, never authorized) ═══ The convergence heal
    // wrote a BARE child terminal — `set_status(Applied)` and nothing else — while the
    // child's attempt chain still held a LIVE `CLAIM`. The operation is then terminal and
    // its attempt is not, so §5.2a's lifecycle atomicity is broken in the loudest possible
    // way: an equally-current driver can still AUTHORIZE that attempt and put a restore on
    // the wire for an undo the ledger has already closed.
    let path = unique_temp_db_path("r5-p1-converge-claimed");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        UndoStageConnector::single(false, true),
    );
    let child_key = deferred_undo_child(&path, &mut bus, "k-r5-p1a");
    // The §3.2 `AlreadyRestored` lineage's crash window: the drive CLAIMED (pre-wire — it
    // never authorizes on that arm), `verify_undo` flipped the parent, then the crash.
    let attempt = {
        let mut side = SqliteIntentLog::open(&path).expect("side connection");
        claim_now(&mut side, &child_key, 0)
    };
    crash_after_the_parent_flip(&path, "k-r5-p1a");

    let child = bus.log().get(&child_key).unwrap().expect("the child row");
    let converged = bus.drive_undo_child(&child);

    assert!(
        matches!(converged, Ok(UndoDriveOutcome::Verified)),
        "the convergence still converges — the parent is `Undone` and the restore is \
         moot; got {converged:?}"
    );
    assert_eq!(
        status_str(&path, &child_key),
        "applied",
        "…and the child's own terminal is written"
    );
    // THE RED: the attempt must carry the terminal ATTRIBUTION that justifies it.
    assert!(
        chain_kinds(&path, &attempt).contains(&"failed_pre_send".to_string()),
        "a converged operation's live attempt must be SETTLED through the ledger — the \
         proven-no-wire attribution the never-authorized attempt has earned — never left \
         dangling behind a bare status write: {:?}",
        chain_kinds(&path, &attempt)
    );
    // …and the sharpest proof of the dangle, which no status column can give: an
    // unsettled attempt is STILL AUTHORIZABLE by an equally-current peer.
    let mut peer = SqliteIntentLog::open(&path).expect("peer connection");
    let re_authorized = authorize(&mut peer, &child_key, &attempt)
        .expect("the peer's authorization attempt");
    assert!(
        !matches!(re_authorized, SendAuthOutcome::Authorized { .. }),
        "the attempt of a CONVERGED undo must not still be authorizable — that is a \
         restore dispatched for an undo the ledger closed; got {re_authorized:?}"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn crash_convergence_never_terminalizes_over_an_issued_unknown_attempt() {
    // ═══, arm 2 (AUTHORIZED, unacked) ═══ The other crash lineage: the
    // §3.2 `Restore` arm authorized, dispatched, `verify_undo` flipped the parent, and the
    // process died before the `ACK_APPLIED`. That attempt is ISSUED_OR_UNKNOWN, and the
    // engine's own rule for that class is written at `boot_quarantine`: "we cannot prove
    // non-issuance, so boot writes nothing — adjudication is the only door out, and it is a
    // human's." The convergence heal ignored it and wrote a bare `Applied` anyway, closing
    // the OPERATION over an attempt no fact settles — a terminal row whose live attempt
    // nothing will ever adjudicate, because `unknown_review` and the sweep both look for
    // OPEN operations.
    let path = unique_temp_db_path("r5-p1-converge-authorized");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        UndoStageConnector::single(false, true),
    );
    let child_key = deferred_undo_child(&path, &mut bus, "k-r5-p1b");
    let attempt = {
        let mut side = SqliteIntentLog::open(&path).expect("side connection");
        let attempt = claim_now(&mut side, &child_key, 0);
        authorize_now(&mut side, &child_key, &attempt);
        attempt
    };
    crash_after_the_parent_flip(&path, "k-r5-p1b");

    let child = bus.log().get(&child_key).unwrap().expect("the child row");
    let converged = bus.drive_undo_child(&child);

    assert!(
        matches!(converged, Err(ExecuteError::InProgress)),
        "an ISSUED_OR_UNKNOWN attempt may not be settled and may not be stepped over: the \
         honest disposition is the in-flight park every unresolved dispatch takes; got \
         {converged:?}"
    );
    assert_eq!(
        status_str(&path, &child_key),
        "pending",
        "…and NO terminal is written over it — the operation stays open until its real \
         settlement or a human's adjudication resolves the attempt"
    );
    assert_eq!(
        chain_kinds(&path, &attempt),
        vec!["claim".to_string(), "send_authorized".to_string()],
        "nothing was appended to an attempt whose issuance nobody can prove: {:?}",
        chain_kinds(&path, &attempt)
    );
    std::fs::remove_file(&path).ok();
}

/// A connector that ADJUDICATES the in-flight attempt and lands a `LATE_ACK_APPLIED` on it
/// — inside `apply`, i.e. while this dispatch is on the wire — and then answers with a
/// DEFINITIVE provider REFUSAL (`ProvenRefusedNoEffect`). The mirror image of
/// [`AdjudicateAndRefuseDuringApply`], aimed at the FAILURE boundary.
struct AdjudicateAndApplyDuringApply {
    inner: UndoStageConnector,
    path: std::path::PathBuf,
}

impl Connector for AdjudicateAndApplyDuringApply {
    fn apply(
        &self,
        command: &Command,
        _basis: &prestate::FrozenBasis,
    ) -> Result<(), ConnectorError> {
        let key = command.idempotency_key.as_str();
        let attempt = attempt_id_of(&self.path, key);
        let mut side = SqliteIntentLog::open(&self.path).expect("the control plane opens");
        adjudicate_now(&mut side, key, &attempt);
        let first = side
            .record_late_ack(key, &attempt, crate::attempt::LateAck::Applied)
            .expect("the first late ack lands");
        assert!(
            matches!(first, LateAckOutcome::Resolved { .. }),
            "precondition: the APPLIED late ack is the chain's ACCEPTED truth, got {first:?}"
        );
        // …and only NOW does the provider answer, with a definitive refusal.
        Err(ConnectorError::deterministic("provider refused").proven_refused_no_effect())
    }
    fn resolve_basis(
        &self,
        command: &Command,
    ) -> Result<prestate::FrozenBasis, ResolveBasisError> {
        self.inner.resolve_basis(command)
    }
    fn observe(
        &self,
        command: &Command,
        basis: &prestate::FrozenBasis,
    ) -> Result<prestate::Observation, ConnectorError> {
        self.inner.observe(command, basis)
    }
    fn restore(
        &self,
        command: &Command,
        basis: &prestate::FrozenBasis,
        p: &std::collections::BTreeMap<String, bool>,
    ) -> Result<(), ConnectorError> {
        self.inner.restore(command, basis, p)
    }
}

#[test]
fn a_contradicted_connector_failure_reports_the_chains_truth() {
    // ═══ ═══ The FAILURE boundary projected the settlement down to
    // `.terminal` and threw the rest away. So when an accepted `LATE_ACK_APPLIED` won the
    // race and the in-flight call then came back a proven refusal, the settlement's
    // `contradicted` answer — "the chain's ACCEPTED verdict is the OPPOSITE of yours, and
    // here it is" — was DISCARDED and the caller got the connector error. An identical
    // replay reads the very same accepted late ack through `decision_outcome` and answers
    // it: two answers, one chain. This is the rule, at the call sites left.
    //
    // rework WHAT that answer is: `AdjudicatedLate(Applied)`, not the plain
    // `Ok(())` this test used to name. The effect provably landed AND an adjudication closed
    // the operation — a caller handed a bare `Ok` could not see the second half. The
    // property under test (in-flight answer == replay answer) is untouched.
    let path = unique_temp_db_path("r5-p2-failure-contradicted");
    let command = archive_cmd("k-r5-p3");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        AdjudicateAndApplyDuringApply {
            inner: UndoStageConnector::single(false, true),
            path: path.to_path_buf(),
        },
    );

    let answered = bus.execute(&command);
    let attempt = attempt_id_of(&path, "k-r5-p3");

    assert!(
        chain_kinds(&path, &attempt).contains(&"late_ack_applied".to_string()),
        "precondition: the ACCEPTED late ack is the APPLIED one: {:?}",
        chain_kinds(&path, &attempt)
    );
    assert_eq!(
        answered,
        Err(ExecuteError::AdjudicatedLate(
            crate::attempt::LateAck::Applied
        )),
        "the caller is owed the FIRST ACCEPTED late ack's truth — the ledger proves the \
         effect landed, on an operation an adjudication closed — never this driver's own \
         refused verdict, which the chain refused"
    );

    let mut replay = CommandBus::new(
        SqliteIntentLog::open(&path).expect("reopen"),
        AlwaysOkConnector,
    );
    assert_eq!(
        replay.execute(&command),
        Err(ExecuteError::AdjudicatedLate(
            crate::attempt::LateAck::Applied
        )),
        "the in-flight answer and the replay answer are ONE truth table"
    );
    std::fs::remove_file(&path).ok();
}

/// A connector that ADJUDICATES the in-flight attempt (nothing else — no late ack) and then
/// answers with an INDETERMINATE failure: the timeout that lands after the operator has
/// already decided. The engine's own verdict for it is `ACK_AMBIGUOUS`, which §5.2a's
/// post-adjudication whitelist refuses — a LEGAL race, not a store incident.
struct AdjudicateThenTimeOut {
    inner: UndoStageConnector,
    path: std::path::PathBuf,
    /// Only this key races; every other intent in the sweep applies normally.
    key: String,
}

impl Connector for AdjudicateThenTimeOut {
    fn apply(
        &self,
        command: &Command,
        basis: &prestate::FrozenBasis,
    ) -> Result<(), ConnectorError> {
        if command.idempotency_key != self.key {
            return self.inner.apply(command, basis);
        }
        let attempt = attempt_id_of(&self.path, &self.key);
        let mut side = SqliteIntentLog::open(&self.path).expect("the control plane opens");
        adjudicate_now(&mut side, &self.key, &attempt);
        Err(ConnectorError::transient("provider timed out"))
    }
    fn resolve_basis(
        &self,
        command: &Command,
    ) -> Result<prestate::FrozenBasis, ResolveBasisError> {
        self.inner.resolve_basis(command)
    }
    fn observe(
        &self,
        command: &Command,
        basis: &prestate::FrozenBasis,
    ) -> Result<prestate::Observation, ConnectorError> {
        self.inner.observe(command, basis)
    }
    fn restore(
        &self,
        command: &Command,
        basis: &prestate::FrozenBasis,
        p: &std::collections::BTreeMap<String, bool>,
    ) -> Result<(), ConnectorError> {
        self.inner.restore(command, basis, p)
    }
}

#[test]
fn an_ambiguous_outcome_racing_adjudication_never_aborts_the_sweep() {
    // ═══ ═══ An `ACK_AMBIGUOUS` verdict arriving AFTER adjudication is a
    // LEGAL RACE with its own designed home: §5.2a — "a late non-definitive observation
    // lives in the adjudication record's ancillary audit trail, never the closed grammar".
    // The settle door instead let it fall through to the catch-all and raised a
    // STORE-CORRUPTION `LogError`, which `recover` (rightly) treats as fatal — so one
    // operator decision taken at the wrong microsecond ABORTED THE WHOLE SWEEP and stranded
    // every unrelated intent behind it.
    let path = unique_temp_db_path("r5-p2-ambiguous-after-adjudication");
    {
        let mut log = SqliteIntentLog::open(&path).expect("open");
        admit(&mut log, &archive_of("k-r5-p4", "msg-1"));
        // A SECOND, INDEPENDENT resource — swept after, and nothing about it is ambiguous.
        admit(&mut log, &archive_of("k-r5-p4-other", "msg-2"));
    }
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        AdjudicateThenTimeOut {
            inner: UndoStageConnector::single(false, true),
            path: path.to_path_buf(),
            key: "k-r5-p4".to_string(),
        },
    );

    let report = bus.recover();

    let report = match report {
        Ok(report) => report,
        Err(other) => panic!(
            "a legal adjudication race is not a store incident and must never abort the \
             sweep: {other:?}"
        ),
    };
    assert_eq!(
        status_str(&path, "k-r5-p4-other"),
        "applied",
        "…and the unrelated intent behind it recovers, which is what the abort destroyed"
    );
    assert_eq!(report.recovered, 1, "exactly the unrelated intent: {report:?}");
    assert_eq!(
        status_str(&path, "k-r5-p4"),
        "adjudicated",
        "the raced operation keeps the operator's own decision — never a second story"
    );
    let attempt = attempt_id_of(&path, "k-r5-p4");
    assert!(
        !chain_kinds(&path, &attempt).contains(&"ack_ambiguous".to_string()),
        "the CLOSED grammar still refuses the ack: the chain is unchanged: {:?}",
        chain_kinds(&path, &attempt)
    );
    assert_eq!(
        annotation_kinds(&path, &adjudication_id_of(&path, &attempt)),
        vec!["late-ambiguous-observation".to_string()],
        "…and the observation lands in the ANCILLARY trail the design names for it, never \
         silently dropped"
    );
    std::fs::remove_file(&path).ok();
}

/// A connector whose `observe` lets a PEER re-enter and AUTHORIZE the very child attempt
/// this driver claimed, and only then FAILS the observation. The §3.2 decision is never
/// reached: the failure boundary is entered holding a pre-wire compare that has already
/// lost.
struct PeerAuthorizesThenObserveFails {
    inner: UndoStageConnector,
    path: std::path::PathBuf,
    armed: std::cell::RefCell<Option<String>>,
    /// Answer a REBOUND observation instead of failing — the deterministic-terminalization
    /// edge of the same class.
    rebind: bool,
}

impl Connector for PeerAuthorizesThenObserveFails {
    fn apply(
        &self,
        command: &Command,
        basis: &prestate::FrozenBasis,
    ) -> Result<(), ConnectorError> {
        self.inner.apply(command, basis)
    }
    fn resolve_basis(
        &self,
        command: &Command,
    ) -> Result<prestate::FrozenBasis, ResolveBasisError> {
        self.inner.resolve_basis(command)
    }
    fn observe(
        &self,
        command: &Command,
        basis: &prestate::FrozenBasis,
    ) -> Result<prestate::Observation, ConnectorError> {
        let armed = self.armed.borrow_mut().take();
        if let Some(child_key) = armed {
            let attempt = attempt_of(&self.path, &child_key);
            let mut peer = SqliteIntentLog::open(&self.path).expect("peer opens the store");
            match authorize(&mut peer, &child_key, &attempt).expect("peer authorizes") {
                SendAuthOutcome::Authorized { .. } => {}
                other => panic!("the peer's re-entry must authorize, got {other:?}"),
            }
            if self.rebind {
                // A BASIS-6 rebound answer: the provider answered for an identity that is
                // not the admission-frozen one.
                let mut obs = self.inner.observe(command, basis)?;
                obs.native_resource_key = "photon:jmap:rebound".to_string();
                return Ok(obs);
            }
            return Err(ConnectorError::transient("observe failed").proven_no_wire());
        }
        self.inner.observe(command, basis)
    }
    fn restore(
        &self,
        command: &Command,
        basis: &prestate::FrozenBasis,
        p: &std::collections::BTreeMap<String, bool>,
    ) -> Result<(), ConnectorError> {
        self.inner.restore(command, basis, p)
    }
}

#[test]
fn a_superseded_undo_observation_failure_is_in_flight_not_a_connector_failure() {
    // ═══ ═══ `reconcile_undo_connector_failure` threw the settlement's
    // `superseded_pre_wire` half away and reported the connector failure regardless. But a
    // LOST pre-wire compare wrote NOTHING: the peer owns the attempt and is dispatching the
    // restore right now. The drive's two OTHER pre-wire arms (the §3.2 conflict and the
    // verification) already answer `InProgress` here; the failure arm did not, so one
    // reconciliation door out of three reported a disposition the ledger does not hold.
    let path = unique_temp_db_path("r5-p2-undo-failure-superseded");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        PeerAuthorizesThenObserveFails {
            inner: UndoStageConnector::single(false, true),
            path: path.to_path_buf(),
            armed: std::cell::RefCell::new(None),
            rebind: false,
        },
    );
    let child_key = deferred_undo_child(&path, &mut bus, "k-r5-p5");
    let child = bus.log().get(&child_key).unwrap().expect("the child row");

    *bus.connector().armed.borrow_mut() = Some(child_key.clone());
    let outcome = bus.drive_undo_child(&child);

    assert!(
        matches!(outcome, Err(ExecuteError::InProgress)),
        "a LOST pre-wire compare wrote nothing and reached no wire — the peer owns the \
         attempt; this driver may not report a failure it never recorded, got {outcome:?}"
    );
    let attempt = attempt_of(&path, &child_key);
    assert_eq!(
        chain_kinds(&path, &attempt),
        vec!["claim".to_string(), "send_authorized".to_string()],
        "…and the ledger proves it: nothing was appended over the peer's authorization: {:?}",
        chain_kinds(&path, &attempt)
    );
    assert!(
        !bus.log()
            .get(&child_key)
            .unwrap()
            .expect("child")
            .status
            .is_terminal(),
        "the child stays non-terminal — the peer's restore is still in flight"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn a_superseded_deterministic_undo_refusal_is_in_flight_too() {
    // THE FOURTH EDGE OF THE SAME CLASS, found by enumerating the callers rather than the
    // findings: `terminalize_undo_deterministic` discarded the settlement WHOLESALE. Its
    // three basis-rebind sites all pass a LIVE pre-wire compare, so exactly that shape
    // reaches it — and there it claimed a deterministic dead-letter the ledger does not
    // hold, over an attempt a peer had authorized.
    let path = unique_temp_db_path("r5-p2-undo-rebind-superseded");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        PeerAuthorizesThenObserveFails {
            inner: UndoStageConnector::single(false, true),
            path: path.to_path_buf(),
            armed: std::cell::RefCell::new(None),
            rebind: true,
        },
    );
    let child_key = deferred_undo_child(&path, &mut bus, "k-r5-p5b");
    let child = bus.log().get(&child_key).unwrap().expect("the child row");

    *bus.connector().armed.borrow_mut() = Some(child_key.clone());
    let outcome = bus.drive_undo_child(&child);

    assert!(
        matches!(outcome, Err(ExecuteError::InProgress)),
        "the deterministic terminalization LOST its pre-wire compare — nothing was \
         written and the attempt is the peer's, got {outcome:?}"
    );
    let attempt = attempt_of(&path, &child_key);
    assert_eq!(
        chain_kinds(&path, &attempt),
        vec!["claim".to_string(), "send_authorized".to_string()],
        "nothing was appended over the peer's authorization: {:?}",
        chain_kinds(&path, &attempt)
    );
    assert!(
        !bus.log()
            .get(&child_key)
            .unwrap()
            .expect("child")
            .status
            .is_terminal(),
        "…and no dead-letter was written for a refusal the ledger never recorded"
    );
    std::fs::remove_file(&path).ok();
}

// ═══════════════════════════════════════════════════════════════════════════════════
// THE TERMINAL-OVERWRITE CLASS, swept. Two edges are ONE shape at its
// second appearance: a status write that ignores a concurrent sever's TERMINAL
// disposition. `terminalize_operation`'s `WHERE status IN (non-terminal)` is the house
// guard; the defects are the writes that bypass it — and the callers that then report a
// success or a failure the ledger does not hold. Each RED below is one edge.
// ═══════════════════════════════════════════════════════════════════════════════════

/// A connector that runs a REAL sever (from its own connection) inside the CAPTURE
/// pipeline's `observe`, and then refuses DETERMINISTICALLY — the exact interleave:
/// the operation holds NO attempt at that point (the claim is taken after the pipeline),
/// so the sever catches it as an `OperationMember` and terminalizes it `Severed`, and the
/// no-attempt reconcile boundary then meets a row it did not expect.
struct SeverInsideObserve {
    inner: UndoStageConnector,
    path: std::path::PathBuf,
    armed: std::cell::Cell<bool>,
}

impl Connector for SeverInsideObserve {
    fn apply(
        &self,
        command: &Command,
        basis: &prestate::FrozenBasis,
    ) -> Result<(), ConnectorError> {
        self.inner.apply(command, basis)
    }
    fn resolve_basis(
        &self,
        command: &Command,
    ) -> Result<prestate::FrozenBasis, ResolveBasisError> {
        self.inner.resolve_basis(command)
    }
    fn observe(
        &self,
        command: &Command,
        basis: &prestate::FrozenBasis,
    ) -> Result<prestate::Observation, ConnectorError> {
        if self.armed.replace(false) {
            sever_from_control_plane(&self.path, "authority:operator-r6");
            return Err(definitive_refusal("the provider refused the pre-state read"));
        }
        self.inner.observe(command, basis)
    }
    fn restore(
        &self,
        command: &Command,
        basis: &prestate::FrozenBasis,
        p: &std::collections::BTreeMap<String, bool>,
    ) -> Result<(), ConnectorError> {
        self.inner.restore(command, basis, p)
    }
}

#[test]
fn a_severed_undo_child_replays_the_sever_not_in_progress() {
    // ═══, arm 1 (SEVERED) ═══ A child terminalized `Severed` by the
    // kill switch leaves the parent `Applied`. A later `undo(parent)` finds that child and
    // the existing-child verdict's WILDCARD mapped every non-`Applied`/non-`Failed` status
    // to `InProgress` — "recovery owns it" — while a terminal child never appears in
    // `unreconciled()`, so no sweep will ever change that answer. The caller is told to
    // wait forever for an undo the kill switch closed.
    let path = unique_temp_db_path("r6-p1-1-severed-child");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        UndoStageConnector::single(false, true),
    );
    let child_key = deferred_undo_child(&path, &mut bus, "k-r6-p11");
    sever_from_control_plane(&path, "authority:operator-r6");
    assert_eq!(
        status_str(&path, &child_key),
        "severed",
        "precondition: the kill switch closed the child as an OperationMember"
    );
    assert_eq!(
        status_str(&path, "k-r6-p11"),
        "applied",
        "precondition: the parent is a TERMINAL `applied` row the sever cannot touch"
    );

    assert_eq!(
        bus.undo("k-r6-p11"),
        Err(ExecuteError::Severed),
        "§7a's replay contract for a severed operation — never `InProgress` for a row \
         nothing will ever drive again"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn an_adjudicated_undo_child_replays_the_historical_axis() {
    // ═══, arm 2 (ADJUDICATED) ═══ Same wildcard, the other terminal:
    // an undo child whose issuance was UNKNOWN and which an operator then closed in place.
    // The honest answer is §5.2d's HISTORICAL axis, through the ONE table every replay
    // reads — `AdjudicatedUnresolved` while nobody knows, and the RESOLVED outcome once a
    // late ack proves what happened.
    let path = unique_temp_db_path("r6-p1-1-adjudicated-child");
    let wire = SharedWire::new(UndoStageConnector::single(false, true));
    let mut bus = CommandBus::new(SqliteIntentLog::open(&path).expect("open"), wire.clone());
    bus.execute(&archive_cmd("k-r6-p11b"))
        .expect("the forward action applies");
    // C == A ⇒ the undo requalifies to RESTORE, and the restore's answer is lost.
    wire.wire().set_state(atoms(&[("membership:INBOX", false)]));
    wire.wire()
        .fail_restore(ConnectorError::transient("connection lost mid-restore"), 1);
    assert!(
        bus.undo("k-r6-p11b").is_err(),
        "precondition: the restore's outcome is UNKNOWN"
    );
    let child_key = undo_child_key(&opaque_intent_id(&path, "k-r6-p11b"));
    let child_attempt = attempt_of(&path, &child_key);
    let mut log = SqliteIntentLog::open(&path).expect("store handle");
    adjudicate_now(&mut log, &child_key, &child_attempt);
    drop(log);
    assert_eq!(
        status_str(&path, &child_key),
        "adjudicated",
        "precondition: the operator closed the OPERATIONAL axis in place"
    );

    assert_eq!(
        bus.undo("k-r6-p11b"),
        Err(ExecuteError::AdjudicatedUnresolved),
        "an adjudicated child with an UNRESOLVED history says so — never `InProgress`"
    );

    // …and once the provider's definitive answer arrives, the replay follows the EVIDENCE.
    let mut log = SqliteIntentLog::open(&path).expect("store handle");
    log.record_late_ack(
        &child_key,
        &child_attempt,
        crate::attempt::LateAck::RefusedNoEffect,
    )
    .expect("the historical axis resolves REFUSED_NO_EFFECT");
    drop(log);
    assert_eq!(
        bus.undo("k-r6-p11b"),
        Err(ExecuteError::AdjudicatedLate(
            crate::attempt::LateAck::RefusedNoEffect
        )),
        "a PROVEN no-effect restore names its ROUTE — the adjudication that closed the child \
         plus the late ack that resolved it — exactly as a replay reads it, and never the \
         generic dead-letter a provider refusal would give (@codex bot r1 P2)"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn a_capture_failure_never_dead_letters_a_severed_operation() {
    // ═══ ═══ The reconcile boundary's OPERATION-GRAIN arm (no attempt
    // exists yet — the capture pipeline runs ahead of the claim) wrote `Failed`
    // UNCONDITIONALLY. A sever that landed while the observation was in flight had already
    // witnessed and terminalized this operation `Severed`; the write erased that
    // disposition, and `execute` then reported a fresh connector failure for an operation
    // the kill switch had closed.
    let path = unique_temp_db_path("r6-p1-2-capture-over-sever");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        SeverInsideObserve {
            inner: UndoStageConnector::single(false, true),
            path: path.to_path_buf(),
            armed: std::cell::Cell::new(true),
        },
    );

    let outcome = bus.execute(&archive_cmd("k-r6-p12"));

    assert_eq!(
        status_str(&path, "k-r6-p12"),
        "severed",
        "the sever's witnessed disposition is the one the store holds — a capture failure \
         may not overwrite it with `failed`"
    );
    assert_eq!(
        outcome,
        Err(ExecuteError::Severed),
        "…and the caller is owed the SEVER, never a fresh dead-letter: {outcome:?}"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn a_deferred_noop_undo_never_erases_a_concurrent_sever() {
    // ═══ ═══ The §4.1 no-op arm is wire-free and therefore sits AHEAD
    // of the epoch fence — deliberately. But it acted on the caller's STALE child read and
    // then wrote the pair UNCONDITIONALLY: a sever between the read and the flip witnessed
    // the child and terminalized it `Severed`, and the pair write then buried that under
    // parent `Undone` + child `Applied` — reporting a completed undo after the kill switch.
    let path = unique_temp_db_path("r6-p1-3-noop-over-sever");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        // P == A: the provider already holds the forward target, so the undo is the §4.1
        // no-op kill — the arm that runs above the fence.
        UndoStageConnector::single(false, false),
    );
    let child_key = deferred_undo_child(&path, &mut bus, "k-r6-p13");
    // THE STALE READ — taken before the sever, exactly as a sweep's `unreconciled()` read is.
    let stale_child = bus
        .log()
        .get(&child_key)
        .unwrap()
        .expect("the deferred no-op child");
    assert_eq!(stale_child.status, IntentStatus::Pending, "precondition");
    sever_from_control_plane(&path, "authority:operator-r6");
    assert_eq!(
        status_str(&path, &child_key),
        "severed",
        "precondition: the kill switch closed the child under the stale read"
    );

    let outcome = bus.drive_undo_child(&stale_child);

    assert_eq!(
        status_str(&path, &child_key),
        "severed",
        "the sever's disposition SURVIVES — the pair write may not bury it as `applied`"
    );
    assert_eq!(
        status_str(&path, "k-r6-p13"),
        "applied",
        "…and the parent never flips `undone` over an undo the kill switch closed"
    );
    assert!(
        matches!(outcome, Err(ExecuteError::Severed)),
        "…and the drive reports the SEVER, never a verified undo: {outcome:?}"
    );
    std::fs::remove_file(&path).ok();
}

// ═══════════════════════════════════════════════════════════════════════════════════
// — THE DEFINITIVE ACK THAT RACED AN ADJUDICATION, on the UNDO path. 
// closed this race at the verdict door (`settle_dispatch` converts a definitive verdict on
// an adjudicated chain into its `LATE_ACK_*`); the undo drive's PAIR-transition arm
// returned BEFORE ever reaching that door.
// ═══════════════════════════════════════════════════════════════════════════════════

/// A connector that runs a REAL adjudication of the undo CHILD (from its own connection)
/// while the restore is on the wire, and then answers `Ok` — the operator deciding at the
/// one microsecond that makes the provider's definitive answer a LATE ack.
struct AdjudicateInsideRestore {
    inner: SharedWire,
    path: std::path::PathBuf,
    parent_key: String,
    armed: std::cell::Cell<bool>,
}

impl Connector for AdjudicateInsideRestore {
    fn apply(
        &self,
        command: &Command,
        basis: &prestate::FrozenBasis,
    ) -> Result<(), ConnectorError> {
        self.inner.apply(command, basis)
    }
    fn resolve_basis(
        &self,
        command: &Command,
    ) -> Result<prestate::FrozenBasis, ResolveBasisError> {
        self.inner.resolve_basis(command)
    }
    fn observe(
        &self,
        command: &Command,
        basis: &prestate::FrozenBasis,
    ) -> Result<prestate::Observation, ConnectorError> {
        self.inner.observe(command, basis)
    }
    fn restore(
        &self,
        command: &Command,
        basis: &prestate::FrozenBasis,
        p: &std::collections::BTreeMap<String, bool>,
    ) -> Result<(), ConnectorError> {
        // The restore IS on the wire (the drive authorized it a few lines above the call).
        if self.armed.replace(false) {
            let child_key = undo_child_key(&opaque_intent_id(&self.path, &self.parent_key));
            let child_attempt = attempt_of(&self.path, &child_key);
            let mut log = SqliteIntentLog::open(&self.path).expect("control-plane handle");
            adjudicate_now(&mut log, &child_key, &child_attempt);
        }
        // …and THEN the provider confirms the restoration.
        self.inner.restore(command, basis, p)
    }
}

#[test]
fn a_definitive_restore_ack_racing_an_adjudicated_child_settles_as_its_late_ack() {
    // ═══ ═══ THE RED. `verify_undo`'s pair transition finds the child
    // MOVED (an operator adjudicated it mid-restore), answers with
    // `status_replay_outcome` and RETURNS — so the definitive `Applied` this driver is
    // holding never reaches `settle_dispatch`, never becomes `LATE_ACK_APPLIED`, and the
    // ledger keeps saying "nobody knows" over a restoration the provider confirmed:
    // the EXP-2 obligations stay LIVE and the parent stays `applied`.
    let path = unique_temp_db_path("r7-p1-adjudicated-mid-restore");
    let wire = SharedWire::new(UndoStageConnector::single(false, true));
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        AdjudicateInsideRestore {
            inner: wire.clone(),
            path: path.to_path_buf(),
            parent_key: "k-r7-p1".to_string(),
            armed: std::cell::Cell::new(true),
        },
    );
    bus.execute(&archive_cmd("k-r7-p1"))
        .expect("the forward action applies");
    // C == A ⇒ the undo requalifies to RESTORE and reaches the wire.
    wire.wire().set_state(atoms(&[("membership:INBOX", false)]));

    let outcome = bus.undo("k-r7-p1");

    let child_key = undo_child_key(&opaque_intent_id(&path, "k-r7-p1"));
    let child_attempt = attempt_of(&path, &child_key);
    assert_eq!(
        status_str(&path, &child_key),
        "adjudicated",
        "precondition: the operator closed the child's OPERATIONAL axis mid-restore"
    );
    assert_eq!(
        wire.wire().restore_call_count(),
        1,
        "precondition: the restore DID go out and the provider confirmed it"
    );
    assert!(
        chain_kinds(&path, &child_attempt).contains(&"late_ack_applied".to_string()),
        "the provider's definitive answer must land through the LATE-ACK door — it is what \
         `unknown at decision time != unknown forever` means: {:?}",
        chain_kinds(&path, &child_attempt)
    );
    assert!(
        obligation_rows(&path)
            .iter()
            .all(|(_, _, _, _, retired)| *retired),
        "…so EXP-8 retirement rides it: no obligation may stay live over a restoration the \
         ledger now proves happened — got {:?}",
        obligation_rows(&path)
    );
    assert_eq!(
        status_str(&path, "k-r7-p1"),
        "undone",
        "…and the undo-parent flip rides the accepted late ack (Task 10's door, reused)"
    );
    assert_eq!(
        outcome,
        Err(ExecuteError::AdjudicatedLate(
            crate::attempt::LateAck::Applied
        )),
        "…and the caller is owed the RESOLVED-APPLIED history — never `AdjudicatedUnresolved`, \
         and (@codex bot r1 P2) never a bare `Ok(())` either: this undo was closed THROUGH an \
         adjudication, which is exactly what the caller cannot see if the answer is the same \
         one an ordinary verified restore gives. It is the `ExternallySatisfied` shape — a \
         non-failure `Err` that names the route — and it is byte-identical to what a replay of \
         the child's own key reads, which is the property the shared table exists for"
    );
    std::fs::remove_file(&path).ok();
}

/// A connector that runs a REAL sever (from its own connection) inside the undo drive's
/// `observe` and then answers NORMALLY — the one interleave that can put a `severed` CHILD
/// under an attempt-bearing verification: the dispatch claim is already taken and is still
/// UNAUTHORIZED, so §5.2c classes it `SEVERED_BEFORE_ISSUANCE` and closes it.
struct SeverInsideUndoObserve {
    inner: UndoStageConnector,
    path: std::path::PathBuf,
    armed: std::cell::Cell<bool>,
}

impl Connector for SeverInsideUndoObserve {
    fn apply(
        &self,
        command: &Command,
        basis: &prestate::FrozenBasis,
    ) -> Result<(), ConnectorError> {
        self.inner.apply(command, basis)
    }
    fn resolve_basis(
        &self,
        command: &Command,
    ) -> Result<prestate::FrozenBasis, ResolveBasisError> {
        self.inner.resolve_basis(command)
    }
    fn observe(
        &self,
        command: &Command,
        basis: &prestate::FrozenBasis,
    ) -> Result<prestate::Observation, ConnectorError> {
        let obs = self.inner.observe(command, basis)?;
        if self.armed.replace(false) {
            sever_from_control_plane(&self.path, "authority:operator-r7");
        }
        Ok(obs)
    }
    fn restore(
        &self,
        command: &Command,
        basis: &prestate::FrozenBasis,
        p: &std::collections::BTreeMap<String, bool>,
    ) -> Result<(), ConnectorError> {
        self.inner.restore(command, basis, p)
    }
}

#[test]
fn a_severed_child_under_a_verification_never_reaches_the_late_ack_door() {
    // ═══, the SIBLING arm — its EXEMPTION witnessed rather than assumed.
    //
    // THE TRACE. §5.2c never closes an `ISSUED_OR_UNKNOWN` member ("we cannot prove
    // non-issuance, so we do not claim it"), so a sever landing over an AUTHORIZED,
    // in-flight restore leaves the child operationally ACTIVE — `ChildMoved(Severed)` is
    // therefore UNREACHABLE from the §3.2 `Restore` lineage, the only one that has a wire
    // result to convert. The single interleave that CAN put `severed` under an
    // attempt-bearing verification is this one: a claim taken, never authorized, closed
    // `SEVERED_BEFORE_ISSUANCE`, whose verification is the wire-free `AlreadyRestored`
    // arm. There is no provider result in existence to settle — and the grammar refuses
    // one twice over (a terminal attribution, and no adjudication record for a
    // `LATE_ACK_*` to attach to). So the arm answers the SEVER and writes nothing.
    let path = unique_temp_db_path("r7-p1-severed-child-exempt");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        SeverInsideUndoObserve {
            inner: UndoStageConnector::single(false, true),
            path: path.to_path_buf(),
            armed: std::cell::Cell::new(false),
        },
    );
    bus.execute(&archive_cmd("k-r7-p1s"))
        .expect("the forward action applies");
    // C == P: another client already put the pre-state back ⇒ the §3.2 `AlreadyRestored`
    // lineage, which claims an attempt and NEVER authorizes it.
    bus.connector().inner.set_state(atoms(&[("membership:INBOX", true)]));
    bus.connector().armed.set(true);

    let outcome = bus.undo("k-r7-p1s");

    let child_key = undo_child_key(&opaque_intent_id(&path, "k-r7-p1s"));
    assert_eq!(
        status_str(&path, &child_key),
        "severed",
        "precondition: the kill switch closed the child BEFORE issuance, under the drive"
    );
    let severed_attempt = attempt_of(&path, &child_key);
    let kinds = chain_kinds(&path, &severed_attempt);
    assert_eq!(
        kinds,
        vec!["claim".to_string(), "severed_before_issuance".to_string()],
        "precondition: never SEND_AUTHORIZED — the attribution is the sever's, and it is \
         terminal"
    );
    assert!(
        !kinds
            .iter()
            .any(|k| k.starts_with("late_ack") || k.starts_with("ack_")),
        "…and NO verdict or late ack is ever appended over it: {kinds:?}"
    );
    assert_eq!(
        status_str(&path, "k-r7-p1s"),
        "applied",
        "…and the parent never flips over an undo the kill switch closed"
    );
    assert!(
        matches!(outcome, Err(ExecuteError::Severed)),
        "…and the caller is owed the SEVER: {outcome:?}"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn the_reverse_gap_scan_covers_the_new_dispatched_terminals() {
    // ═══ ═══ The reverse-gap scan asks "did this row reach the wire?"
    // and enumerated only `applied`/`undone`/`undoing`. Stage 4 added two terminals that a
    // row reaches ONLY from a post-dispatch state — `adjudicated` (the operational axis
    // closed over an attempt that was SEND-AUTHORIZED) and `externally_satisfied` (the
    // retry requalification's `C == A` no-op, reached with a live capture) — so a
    // `journal_required=1` row that lost its journal row opened with NO evidence at all.
    //
    // `severed` is deliberately NOT included: an operation can be severed PRE-PREPARE (the
    // sever closes every non-terminal member, including one that never captured), so its
    // missing row is legitimate and reporting it would be a false gap.
    let path = build_store_with("r6-p2-5-new-terminals", |conn| {
        let basis = |n: &str| {
            format!(
                r#"{{"native_resource_key":"{n}","touched_atoms":{{"a":"a"}},"freshness":"immutable_constants"}}"#
            )
        };
        seed_intent(conn, "k-adj", "adjudicated", 1, "forward", Some(&basis("t:1")));
        seed_intent(
            conn,
            "k-ext",
            "externally_satisfied",
            1,
            "forward",
            Some(&basis("t:2")),
        );
        // The one that must stay SILENT — a pre-PREPARE sever owes no journal row.
        seed_intent(conn, "k-sev", "severed", 1, "forward", Some(&basis("t:3")));
        // …and the tombstone explainer still explains an adjudicated row.
        seed_intent(conn, "k-adj-tomb", "adjudicated", 1, "forward", Some(&basis("t:4")));
        seed_tombstone(conn, "k-adj-tomb", "j-adj-tomb");
    });
    let report = open_integrity_report(&path);
    for key in ["k-adj", "k-ext"] {
        assert!(
            report.iter().any(|e| matches!(
                e,
                IntegrityEvidence::JournalGapUnexplained { key: k } if k == key
            )),
            "a dispatched terminal that OWES a journal row and has none is a gap: {report:?}"
        );
    }
    for key in ["k-sev", "k-adj-tomb"] {
        assert!(
            !report.iter().any(|e| matches!(
                e,
                IntegrityEvidence::JournalGapUnexplained { key: k } if k == key
            )),
            "a pre-PREPARE sever and a tombstoned row are NOT gaps: {report:?}"
        );
    }
    std::fs::remove_file(&path).ok();
}

#[test]
fn the_authorization_consumes_the_generation_its_decision_read() {
    // ═══ ═══ TWO recovery buses re-enter the same retry. Each observes
    // the provider for itself, and the requalification REPLACE commits independently of
    // the authorization that follows it: bus A decides against journal generation 1, bus B
    // then RE-PREPARES (generation 2), and A — still holding a decision about a row that no
    // longer exists — authorizes and dispatches. A later undo restores B's snapshot, not
    // the one A dispatched against.
    //
    // §5.2a names the REPLACE as VERSIONED for exactly this reason:
    // `capture_generation` is the CAS token, and the authorizing transaction is where it
    // has to be spent.
    let path = unique_temp_db_path("r9-p1-capture-cas");
    let wire = SharedWire::new(UndoStageConnector::pair(true, false));
    let mut bus = CommandBus::new(SqliteIntentLog::open(&path).expect("open"), wire.clone());
    wire.wire().fail_apply(1);
    park_in_the_retry_gap(&mut bus, "k-r9-cas");

    // ── BUS A ── the capture its requalification decision is made against…
    let mut a = SqliteIntentLog::open(&path).expect("bus A");
    let p_a = a
        .captured_pre_state("k-r9-cas")
        .expect("A reads the capture")
        .expect("a capture-ON operation owns a journal row");
    // …and the retry attempt it owns (the door mints ordinal 2 out of the chain).
    let attempt_a = match a
        .claim_attempt(
            "k-r9-cas",
            &AttemptClaim {
                ordinal: 1,
                predecessor: None,
                observed_attempts: 1,
            },
        )
        .expect("A claims the retry")
    {
        ClaimOutcome::Won { attempt_id, .. } => attempt_id,
        other => panic!("A must own the retry attempt: {other:?}"),
    };

    // ── BUS B ── its own requalification finds a third state and RE-PREPARES. Legal: every
    // attempt of the operation holds a proven-no-wire terminal or is pre-issuance.
    let mut b = SqliteIntentLog::open(&path).expect("bus B");
    let fresh = crate::prestate::JournalRow {
        observed: r#"{"membership:mb-a":true,"membership:mb-i":true}"#.into(),
        touched_atom: r#"{"membership:mb-a":true,"membership:mb-i":true}"#.into(),
        resolved_operands: r#"{"membership:mb-a":"mb-a","membership:mb-i":"mb-i"}"#.into(),
        request_id: None,
        observed_label_vector: None,
    };
    assert!(
        matches!(
            b.replace_journal_row("k-r9-cas", &fresh)
                .expect("B re-prepares"),
            JournalReplaceOutcome::Replaced { generation: 2 }
        ),
        "precondition: B's REPLACE is committed and VERSIONED"
    );

    // ── BUS A authorizes ── holding a decision made against generation 1.
    let authorized = a
        .authorize_send(
            "k-r9-cas",
            &attempt_a,
            // A's decision was made against generation 1 — the CAS token it must spend.
            CaptureBinding::Generation(p_a.capture_generation),
            crate::plan::PlanBinding::Plain,
        )
        .expect("the door answers");
    assert!(
        !matches!(authorized, SendAuthOutcome::Authorized { .. }),
        "A's authorization must NOT survive B's REPLACE: A decided against generation 1 \
         ({p_a:?}) and the durable row is now generation 2 — got {authorized:?}"
    );
    assert_eq!(
        authorized,
        SendAuthOutcome::CaptureSuperseded {
            expected: CaptureBinding::Generation(1),
            found: Some(2),
        },
        "…and the refusal NAMES both generations rather than a bare 'no'"
    );
    assert_eq!(
        send_authorized_count(&path, &attempt_a),
        0,
        "the refusal is PRE-WIRE and wrote NOTHING: no authorization exists to dispatch under"
    );
    assert_eq!(
        status_str(&path, "k-r9-cas"),
        "pending",
        "…and nothing terminalized: the loser simply re-runs requalification"
    );
    // …which it does, through the ORDINARY doors: the next sweep requalifies against the
    // row as it now IS (generation 2, both mailboxes = the §3.1a third state ⇒ RE-PREPARE
    // is unnecessary and `C == P` proceeds), authorizes with THAT generation, and exactly
    // one coherent (decision, capture, dispatch) triple reaches the wire.
    wire.wire().set_state(atoms(&[
        ("membership:mb-i", true),
        ("membership:mb-a", true),
    ]));
    bus.recover().expect("the loser's next sweep");
    assert_eq!(
        wire.wire().apply_count(),
        1,
        "exactly ONE dispatch — and it is the one whose decision matches the durable capture"
    );
    assert_eq!(status_str(&path, "k-r9-cas"), "applied");
    assert_eq!(
        capture_generation_of(&path, "k-r9-cas"),
        2,
        "…against B's generation, which is the one the ledger holds"
    );
    std::fs::remove_file(&path).ok();
}

/// A PEER that settles ANOTHER operation while this sweep is on the wire for the first one
/// — the window between `recover`'s `unreconciled()` read and the CLAIM it takes for that
/// operation later in the SAME pass.
struct PeerInsideTheDispatchWindow {
    wire: UndoStageConnector,
    path: std::path::PathBuf,
    victim: String,
    armed: std::cell::Cell<bool>,
}

impl PeerInsideTheDispatchWindow {
    fn new(path: &std::path::Path, victim: &str) -> Self {
        Self {
            wire: UndoStageConnector::single(false, true),
            path: path.to_path_buf(),
            victim: victim.to_string(),
            armed: std::cell::Cell::new(true),
        }
    }
}

impl Connector for PeerInsideTheDispatchWindow {
    fn apply(
        &self,
        command: &Command,
        basis: &prestate::FrozenBasis,
    ) -> Result<(), ConnectorError> {
        let out = self.wire.apply(command, basis);
        if out.is_ok() && self.armed.replace(false) {
            let written = SqliteIntentLog::open(&self.path)
                .expect("the peer's connection")
                .dead_letter_if_quiescent(&self.victim)
                .expect("the peer settles the victim");
            assert!(
                matches!(written, DeadLetterWrite::Written),
                "precondition: the peer really closed the victim — got {written:?}"
            );
        }
        out
    }
    fn resolve_basis(
        &self,
        command: &Command,
    ) -> Result<prestate::FrozenBasis, ResolveBasisError> {
        self.wire.resolve_basis(command)
    }
    fn observe(
        &self,
        command: &Command,
        basis: &prestate::FrozenBasis,
    ) -> Result<prestate::Observation, ConnectorError> {
        self.wire.observe(command, basis)
    }
    fn restore(
        &self,
        command: &Command,
        basis: &prestate::FrozenBasis,
        p: &std::collections::BTreeMap<String, bool>,
    ) -> Result<(), ConnectorError> {
        self.wire.restore(command, basis, p)
    }
}

/// Record a Pending, unprepared intent on `message_ref` — admitted, never dispatched.
/// (`archive_of` is the existing NAMED-resource command fixture: the connector derives the
/// native key from the message ref, so a distinct ref is a distinct resource — and a
/// distinct ordering barrier.)
fn seed_pending_on<C: Connector>(
    path: &std::path::Path,
    bus: &CommandBus<SqliteIntentLog, C>,
    key: &str,
    message_ref: &str,
) {
    let mut log = SqliteIntentLog::open(path).expect("open");
    let command = archive_of(key, message_ref);
    let basis = bus
        .connector()
        .resolve_basis(&command)
        .expect("resolve the seed basis");
    log.record(&command, &basis).expect("seed the pending row");
}

#[test]
fn a_claim_over_a_terminal_row_is_not_an_in_flight_predecessor() {
    // ═══ ═══ The park-over-terminal class, THIRD arm. `claim_dispatch`
    // maps `AlreadyClaimed` to `Park` unconditionally — but the claim door's FIRST compare
    // half is "the operation is already TERMINAL", so a peer that settles between the
    // caller's read and its claim leaves a row that is closed forever while the caller
    // reports in-flight and the sweep raises a per-resource barrier over it. Every LATER
    // intent on that resource is then stranded behind a row nothing will ever sweep again.
    let path = unique_temp_db_path("r9-p2-1-claim-terminal");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        PeerInsideTheDispatchWindow::new(&path, "k-r9-victim"),
    );
    // (1) THE TRIGGER, on its own resource: the sweep dispatches it first, and the peer
    //     fires inside its wire call.
    seed_pending_on(&path, &bus, "k-r9-trigger", "msg-trigger");
    // (2) THE VICTIM: Pending and PREPARED, parked in its §5.2c retry gap.
    bus.connector().wire.fail_apply(1);
    let parked = bus.execute(&archive_of("k-r9-victim", "msg-victim"));
    assert!(
        matches!(parked, Err(ExecuteError::Connector(_))),
        "precondition: the victim parks in its retry gap; got {parked:?}"
    );
    // (3) THE SUCCESSOR on the victim's resource, admitted after it.
    seed_pending_on(&path, &bus, "k-r9-successor", "msg-victim");

    bus.recover().expect("the sweep");

    assert_eq!(
        status_str(&path, "k-r9-victim"),
        "failed",
        "precondition: the peer closed the victim mid-sweep, between the sweep's \
         `unreconciled()` read and its CLAIM"
    );
    assert_eq!(
        status_str(&path, "k-r9-successor"),
        "applied",
        "a row a peer settled FOREVER is not an in-flight predecessor: the claim door owes \
         the same re-read every authorization refusal already takes, and a barrier raised \
         over a terminal row strands every later intent on its resource"
    );
    std::fs::remove_file(&path).ok();
}

/// A PEER that SEVERS from a second connection inside this driver's `observe` — the §2.2
/// capture pipeline's own window, which sits between the caller's read of the intent row
/// and the PREPARE transaction that re-reads it. Fires once, on the first observation.
struct PeerSeversInsideTheCaptureWindow {
    wire: UndoStageConnector,
    path: std::path::PathBuf,
    armed: std::cell::Cell<bool>,
}

impl PeerSeversInsideTheCaptureWindow {
    fn new(path: &std::path::Path) -> Self {
        Self {
            wire: UndoStageConnector::single(false, true),
            path: path.to_path_buf(),
            armed: std::cell::Cell::new(true),
        }
    }
}

impl Connector for PeerSeversInsideTheCaptureWindow {
    fn apply(
        &self,
        command: &Command,
        basis: &prestate::FrozenBasis,
    ) -> Result<(), ConnectorError> {
        self.wire.apply(command, basis)
    }
    fn resolve_basis(
        &self,
        command: &Command,
    ) -> Result<prestate::FrozenBasis, ResolveBasisError> {
        self.wire.resolve_basis(command)
    }
    fn observe(
        &self,
        command: &Command,
        basis: &prestate::FrozenBasis,
    ) -> Result<prestate::Observation, ConnectorError> {
        let observed = self.wire.observe(command, basis)?;
        if self.armed.replace(false) {
            let outcome = SqliteIntentLog::open(&self.path)
                .expect("the peer's connection")
                .sever("authority:kill-switch", &sever_now())
                .expect("sever");
            assert!(
                outcome.terminalized > 0,
                "precondition: the kill switch really closed the operation(s) under this \
                 capture — got {outcome:?}"
            );
        }
        Ok(observed)
    }
    fn restore(
        &self,
        command: &Command,
        basis: &prestate::FrozenBasis,
        p: &std::collections::BTreeMap<String, bool>,
    ) -> Result<(), ConnectorError> {
        self.wire.restore(command, basis, p)
    }
}

#[test]
fn a_sever_racing_prepare_answers_the_closure_instead_of_a_store_error() {
    // ═══ PREEMPTIVE FIX — the adjacent defect scoped OUT earlier ═══
    // PREPARE's pre-dispatch guard refuses EVERY non-pre-dispatch
    // row with the same hard `LogError` — "a post-effect observation is never journaled".
    // That is right about `Undoing` (a forward row in that state is a store nobody wrote)
    // and WRONG about a TERMINAL row: §5.2c's sever closes an active operation with no live
    // attempt inside its own transaction, and the capture pipeline's provider read is a
    // window that transaction can land in. The operation is then closed FOREVER — a normal
    // closure — and the caller was handed "the durable store is inconsistent".
    let path = unique_temp_db_path("s4-preempt-prepare-sever");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        PeerSeversInsideTheCaptureWindow::new(&path),
    );

    let answer = bus.execute(&archive_cmd("k-sever-race"));

    assert_eq!(
        status_str(&path, "k-sever-race"),
        "severed",
        "precondition: the kill switch closed this operation between our `record()` and \
         the PREPARE transaction that re-reads it"
    );
    assert_eq!(
        bus.connector().wire.apply_count(),
        0,
        "precondition: the race is entirely PRE-WIRE — nothing was dispatched"
    );
    let replay = bus.execute(&archive_cmd("k-sever-race"));
    assert_eq!(
        replay,
        Err(ExecuteError::Severed),
        "precondition: an identical replay reads the closed row through the ONE truth table"
    );
    assert_eq!(
        answer, replay,
        "a sever racing PREPARE owes its caller exactly what a replay owes it — never a \
         `LogError` claiming the durable store is inconsistent about a row the kill switch \
         closed legitimately"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn a_terminal_racing_prepare_does_not_abort_the_rest_of_the_recovery_sweep() {
    // THE HARM, and why it is not merely a cosmetic answer at one door: `recover` treats a
    // `LogError` as FATAL TO THE WHOLE SWEEP ("the store can no longer be trusted"). So one
    // operation closed by a peer between the sweep's `unreconciled()` read and its PREPARE
    // aborted recovery of every OTHER operation in the same pass — including operations on
    // unrelated resources that nothing had touched.
    let path = unique_temp_db_path("s4-preempt-prepare-terminal-sweep");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        PeerInsideTheDispatchWindow::new(&path, "k-pp-victim"),
    );
    // (1) THE TRIGGER, on its own resource: the sweep dispatches it first, and the peer
    //     fires inside its wire call — the window before the victim's own PREPARE.
    seed_pending_on(&path, &bus, "k-pp-trigger", "msg-pp-trigger");
    // (2) THE VICTIM: Pending and UNPREPARED, so the sweep reaches it through the capture
    //     pipeline rather than the already-prepared short-circuit.
    seed_pending_on(&path, &bus, "k-pp-victim", "msg-pp-victim");
    // (3) THE UNRELATED operation, on a third resource: it shares no barrier with either.
    seed_pending_on(&path, &bus, "k-pp-unrelated", "msg-pp-unrelated");

    let report = bus
        .recover()
        .expect("a peer's terminal is not a corrupt store — the sweep must survive it");

    assert_eq!(
        status_str(&path, "k-pp-victim"),
        "failed",
        "precondition: the peer closed the victim mid-sweep, inside the trigger's wire call"
    );
    assert_eq!(
        status_str(&path, "k-pp-unrelated"),
        "applied",
        "THE HARM: a row a peer closed under our capture is a normal closure, so the sweep \
         skips it and keeps going — an unrelated pending operation must not be stranded by \
         it"
    );
    assert_eq!(
        report.recovered, 2,
        "the trigger and the unrelated operation both recovered in THIS pass"
    );
    assert!(
        report.failed.is_empty(),
        "…and nothing failed: a closure is not a failure, got {:?}",
        report.failed
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn a_sever_landing_mid_sweep_closes_the_sweep_honestly_instead_of_aborting_it() {
    // The KILL SWITCH's own face of the row above. A sever closes every active operation
    // with no live attempt in ONE transaction (§5.2c), so a sweep in flight meets its own
    // rows already terminal at PREPARE. Pre-fix the first one killed the pass with a
    // `LogError`; the sweep must instead walk every row it read and answer each honestly.
    let path = unique_temp_db_path("s4-preempt-prepare-sever-sweep");
    let bus_seed = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        PeerSeversInsideTheCaptureWindow::new(&path),
    );
    seed_pending_on(&path, &bus_seed, "k-ss-first", "msg-ss-first");
    seed_pending_on(&path, &bus_seed, "k-ss-second", "msg-ss-second");
    drop(bus_seed);
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("reopen"),
        PeerSeversInsideTheCaptureWindow::new(&path),
    );

    let report = bus
        .recover()
        .expect("a kill switch is not a corrupt store — the sweep must survive it");

    assert_eq!(status_str(&path, "k-ss-first"), "severed");
    assert_eq!(status_str(&path, "k-ss-second"), "severed");
    assert_eq!(
        bus.connector().wire.observe_count(),
        2,
        "THE CONTINUATION, proven at the provider seam: the sweep VISITED the second row \
         instead of dying on the first"
    );
    assert_eq!(
        bus.connector().wire.apply_count(),
        0,
        "…and no severed operation reached the wire"
    );
    assert_eq!(report.recovered, 0, "a closure is not a recovery");
    assert!(
        report.failed.is_empty(),
        "…nor a failure, got {:?}",
        report.failed
    );
    std::fs::remove_file(&path).ok();
}

// ═══════════════════════════════════════════════════════════════════════════════════
// — AN ISSUED RETRY NEVER REQUALIFIES PRE-WIRE, and the exposure
// refusal surfaces an id-free ENGINE reference.
// ═══════════════════════════════════════════════════════════════════════════════════

#[test]
fn a_crashed_authorized_retry_never_requalifies_pre_wire() {
    // ═══ ═══ THE PRE-WIRE REQUALIFICATION RAN OVER AN ISSUED ATTEMPT.
    //
    // The trace: an ordinal>1 retry crashes AFTER its `SEND_AUTHORIZED` commits and
    // BEFORE any verdict — §8 residual 9's irreducible commit-to-socket gap. Recovery
    // re-enters and the claim door hands the SAME ordinal back (the re-entry arm), so
    // the sweep's `ordinal > 1` test still fires and the retry-requalification gate runs
    // pre-wire. It observes `C == A`, and writes the deterministic no-effect terminal:
    // `FAILED_PRE_SEND{ProvenNoWire}` on an attempt that may already have spent the wire,
    // plus `EXTERNALLY_SATISFIED` on an operation that may already have APPLIED at the
    // provider. That is the engine claiming proof of non-issuance it does not have.
    //
    // THE RULE: requalification is for attempts that are provably wire-free. An attempt
    // whose chain already holds `SEND_AUTHORIZED` is `ISSUED_OR_UNKNOWN` and takes the
    // ordinary issued path — park, never re-authorized, never settled, surfaced for
    // adjudication — which is the boot quarantine's own rule for authorized-unacked
    // attempts, applied at this door.
    let path = unique_temp_db_path("r11-p1-issued-retry-requalifies");
    let wire = SharedWire::new(UndoStageConnector::single(false, true));
    let mut bus = CommandBus::new(SqliteIntentLog::open(&path).expect("open"), wire.clone());
    wire.wire().fail_apply_with(
        ConnectorError::transient("connect refused").proven_no_wire(),
        1,
    );
    park_in_the_retry_gap(&mut bus, "k-r11-p1");
    drop(bus);

    // ── THE CRASHED DRIVER ── it claims the RETRY and AUTHORIZES it, then dies between
    // the authorizing commit and its socket. Nothing else is written: that IS the crash.
    let mut crashed = SqliteIntentLog::open(&path).expect("the crashing driver");
    let retry = match crashed
        .claim_attempt(
            "k-r11-p1",
            &AttemptClaim {
                ordinal: 1,
                predecessor: None,
                observed_attempts: 1,
            },
        )
        .expect("the retry claim")
    {
        ClaimOutcome::Won {
            attempt_id,
            ordinal,
            ..
        } => {
            assert_eq!(ordinal, 2, "precondition: the claim door mints the SUCCESSOR");
            attempt_id
        }
        other => panic!("the retry claim must win, got {other:?}"),
    };
    assert!(
        matches!(
            authorize(&mut crashed, "k-r11-p1", &retry).expect("authorize"),
            SendAuthOutcome::Authorized { .. }
        ),
        "precondition: the crashed driver AUTHORIZED the retry"
    );
    drop(crashed);
    assert_eq!(
        chain_kinds(&path, &retry),
        vec!["claim", "send_authorized"],
        "precondition: authorized, no verdict — ISSUED_OR_UNKNOWN"
    );

    // ── THE WORLD MOVED TO THE TARGET ── which is exactly the reading the requalification
    // gate turns into `EXTERNALLY_SATISFIED`. Whether THIS operation's own authorized
    // dispatch is what moved it is unknowable, which is the point.
    wire.wire().set_state(atoms(&[("membership:INBOX", false)]));
    let mut bus = CommandBus::new(SqliteIntentLog::open(&path).expect("reopen"), wire.clone());
    let report = bus.recover().expect("the sweep");

    assert_eq!(
        chain_kinds(&path, &retry),
        vec!["claim", "send_authorized"],
        "THE RED: no verdict fact may be appended to an issued attempt by a PRE-WIRE gate \
         — a `failed_pre_send` here is a proven-no-wire claim over a spent authorization"
    );
    assert_eq!(
        status_str(&path, "k-r11-p1"),
        "pending",
        "…and the operation stays open: `externally_satisfied` would tell the caller the \
         target was reached by SOMEBODY ELSE about a request that may have applied as OURS"
    );
    assert_eq!(
        bus.execute(&archive_cmd("k-r11-p1")),
        Err(ExecuteError::InProgress),
        "the replay says what is true — in flight, unknown — never a terminal"
    );
    let review = bus
        .unknown_review(2_000_000_000, 0)
        .expect("the §5.2d surfacing report");
    assert!(
        review.rows.iter().any(|row| row.attempt_id == retry),
        "…and the attempt SURFACES for adjudication, which is the only door that may close \
         an authorized-unacked attempt; got {:?}",
        review.rows
    );
    assert_eq!(report.recovered, 0, "a park is not a recovery");
    assert!(
        report.failed.is_empty(),
        "…nor a failure, got {:?}",
        report.failed
    );
    std::fs::remove_file(&path).ok();
}

// ═══════════════════════════════════════════════════════════════════════════════════
// THE SETTLEMENT-DECISION CLASS, UNIFIED. Two edges of one family that
// has recurred: a lifecycle decision taken with a LOCAL predicate
// that a stronger sibling predicate already exists for. One is the no-attempt failure
// write against the quiescence door; the other is the settlement-epoch fence against the
// existing rule. Each RED below is one edge, and each fix DELETES its weaker sibling.
// ═══════════════════════════════════════════════════════════════════════════════════

/// A connector whose CAPTURE `observe` blocks long enough for a PEER driver — on its own
/// connection — to claim AND authorize the same operation, and which then FAILS in the class
/// the test asks for. The exact interleave: driver B's pipeline failure has no attempt
/// of its own (the claim is taken after the pipeline), while driver A's authorized attempt
/// is live and may already be on the wire.
///
/// The failure CLASS is a parameter because the interleave is one and the reconcile boundary
/// is two arms: DETERMINISTIC dead-letters at once, TRANSIENT charges the budget
/// and dead-letters on exhaustion. Same window, same peer, both terminals.
struct PeerAuthorizesInsideObserve {
    inner: UndoStageConnector,
    path: std::path::PathBuf,
    armed: std::cell::Cell<bool>,
    /// The budget the PEER's claim observed — the claim door's optimistic episode check, so
    /// a pre-charged row is claimed at the count it actually holds.
    peer_observes: u32,
    /// The class this capture failure then reports.
    failure: FailureKind,
}

impl Connector for PeerAuthorizesInsideObserve {
    fn apply(
        &self,
        command: &Command,
        basis: &prestate::FrozenBasis,
    ) -> Result<(), ConnectorError> {
        self.inner.apply(command, basis)
    }
    fn resolve_basis(
        &self,
        command: &Command,
    ) -> Result<prestate::FrozenBasis, ResolveBasisError> {
        self.inner.resolve_basis(command)
    }
    fn observe(
        &self,
        command: &Command,
        basis: &prestate::FrozenBasis,
    ) -> Result<prestate::Observation, ConnectorError> {
        if self.armed.replace(false) {
            let key = &command.idempotency_key;
            let mut peer = SqliteIntentLog::open(&self.path).expect("the peer's connection");
            let attempt = claim_now(&mut peer, key, self.peer_observes);
            authorize_now(&mut peer, key, &attempt);
            return Err(match self.failure {
                FailureKind::Deterministic => {
                    definitive_refusal("the provider refused the pre-state read")
                }
                FailureKind::Transient => {
                    ConnectorError::transient("the provider was unreachable for the pre-state read")
                }
            });
        }
        self.inner.observe(command, basis)
    }
    fn restore(
        &self,
        command: &Command,
        basis: &prestate::FrozenBasis,
        p: &std::collections::BTreeMap<String, bool>,
    ) -> Result<(), ConnectorError> {
        self.inner.restore(command, basis, p)
    }
}

#[test]
fn a_no_attempt_failure_never_dead_letters_over_a_live_attempt() {
    // ═══ ═══ The reconcile boundary's OPERATION-GRAIN arm guarded its
    // `Failed` with `StatusPrecondition::NonTerminal` ONLY — the guard, which answers
    // "did another authority already close this row" and says NOTHING about a live attempt.
    // Two drivers capture the same unprepared operation; A finishes PREPARE + claim +
    // authorize and enters apply, B's earlier observe fails afterwards, and B's `Failed`
    // lands over A's in-flight authorized attempt — after which A's `ACK_APPLIED` can never
    // replace the terminal (`settle_attempt`'s lifecycle guard refuses to rewrite a settled
    // disposition). The predicate that answers this exists: it is 's, and it is atomic.
    let path = unique_temp_db_path("r13-p1-1-capture-over-live");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        PeerAuthorizesInsideObserve {
            inner: UndoStageConnector::single(false, true),
            path: path.to_path_buf(),
            armed: std::cell::Cell::new(true),
            peer_observes: 0,
            failure: FailureKind::Deterministic,
        },
    );

    let outcome = bus.execute(&archive_cmd("k-r13-p11"));

    let peer_attempt = attempt_id_of(&path, "k-r13-p11");
    assert_eq!(
        chain_kinds(&path, &peer_attempt),
        vec!["claim", "send_authorized"],
        "precondition: the PEER owns this operation's dispatch and has authorized it"
    );
    assert_eq!(
        status_str(&path, "k-r13-p11"),
        "pending",
        "THE RED: a no-attempt capture failure may not dead-letter an operation whose \
         dispatch a peer holds — `failed` is an ATTRIBUTION of no-effect over a request \
         that may already be on the wire, and the peer's ACK can never replace it"
    );
    assert_eq!(
        outcome,
        Err(ExecuteError::Connector(definitive_refusal(
            "the provider refused the pre-state read"
        ))),
        "…and this driver still reports its OWN failure: it wrote nothing, and the \
         operation is not its to close: {outcome:?}"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn the_last_unit_of_budget_never_dead_letters_over_a_live_attempt() {
    // ═══ ═══ THE SAME CLASS, THE OTHER ARM. The earlier fix closed the
    // reconcile boundary's DETERMINISTIC write over a live attempt; its TRANSIENT twin wrote
    // the same terminal through the budget charge, whose single CASE statement carried only
    // the `NonTerminal` compare. Driven end-to-end: the operation sits at `RETRY_CAP - 1`,
    // the sweep's capture `observe` fails TRANSIENTLY while a peer claims and AUTHORIZES in
    // that window, and the last unit of budget must not bury the peer's in-flight dispatch.
    let path = unique_temp_db_path("r13-s6-budget-over-live");
    {
        let mut log = SqliteIntentLog::open(&path).expect("open");
        admit(&mut log, &archive_of("k-r13-s6", "msg-1"));
        // CRAFT: real calls only — the engine's own budget writer under a lifted cap.
        for _ in 0..RETRY_CAP - 1 {
            assert_eq!(
                log.charge_and_dead_letter_if_quiescent("k-r13-s6", u32::MAX)
                    .expect("charge the durable budget without terminalizing"),
                TransientCharge::ChargedOnly
            );
        }
    }
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("reopen"),
        PeerAuthorizesInsideObserve {
            inner: UndoStageConnector::single(false, true),
            path: path.to_path_buf(),
            armed: std::cell::Cell::new(true),
            peer_observes: RETRY_CAP - 1,
            failure: FailureKind::Transient,
        },
    );

    let report = bus.recover().expect("sweep");

    let peer_attempt = attempt_id_of(&path, "k-r13-s6");
    assert_eq!(
        chain_kinds(&path, &peer_attempt),
        vec!["claim", "send_authorized"],
        "precondition: the PEER owns this operation's dispatch and has authorized it"
    );
    assert_eq!(
        attempts_of(&path, "k-r13-s6"),
        i64::from(RETRY_CAP),
        "the charge itself always lands — a transient failure under a peer's dispatch is \
         not free, or the budget would never exhaust"
    );
    assert_eq!(
        status_str(&path, "k-r13-s6"),
        "pending",
        "THE RED: an exhausted budget is not authority to close an operation whose dispatch \
         a peer holds — `failed` is an ATTRIBUTION of no-effect over a request that may \
         already be on the wire, and the peer's ACK can never replace it"
    );
    assert_eq!(
        report.recovered, 0,
        "…nothing was recovered by this sweep"
    );
    assert_eq!(
        report.failed.len(),
        1,
        "…and the sweep reports its OWN transient failure, honestly: {:?}",
        report.failed
    );
    std::fs::remove_file(&path).ok();
}

/// A connector that runs a REAL sever mid-dispatch and then refuses DETERMINISTICALLY with
/// proven-no-wire evidence — the verdict pair. `SeverDuringApply`'s TRANSIENT twin
/// takes the `ChargeTransient` branch (which held the epoch check); this one resolves
/// `Complete(Failed)` and skipped the fence entirely.
struct SeverDuringApplyDeterministic {
    inner: UndoStageConnector,
    path: std::path::PathBuf,
}

impl Connector for SeverDuringApplyDeterministic {
    fn apply(&self, _command: &Command, _basis: &prestate::FrozenBasis) -> Result<(), ConnectorError> {
        sever_from_control_plane(&self.path, "authority:mid-dispatch-r13");
        Err(ConnectorError::deterministic("the request was refused before dispatch")
            .proven_no_wire())
    }
    fn resolve_basis(
        &self,
        command: &Command,
    ) -> Result<prestate::FrozenBasis, ResolveBasisError> {
        self.inner.resolve_basis(command)
    }
    fn observe(
        &self,
        command: &Command,
        basis: &prestate::FrozenBasis,
    ) -> Result<prestate::Observation, ConnectorError> {
        self.inner.observe(command, basis)
    }
    fn restore(
        &self,
        command: &Command,
        basis: &prestate::FrozenBasis,
        p: &std::collections::BTreeMap<String, bool>,
    ) -> Result<(), ConnectorError> {
        self.inner.restore(command, basis, p)
    }
}

#[test]
fn a_deterministic_proven_no_wire_settlement_under_a_newer_epoch_severs() {
    // ═══ ═══ The settlement-epoch fence (§5.2a) lived
    // INSIDE the `ChargeTransient` lifecycle branch, so it was reachable only through the
    // retry taxonomy. A send-authorized request racing a sever that answers a DETERMINISTIC
    // proven-no-wire refusal resolves `Complete(Failed)` in `verdict_mapping` — the epoch
    // branch is never entered, and the row closes `failed` where the contract says a
    // proven-no-wire settlement under a newer epoch is `Severed`. The rule is about the
    // verdict's EVIDENCE, not about which lifecycle branch the retry taxonomy picked.
    let path = unique_temp_db_path("r13-p1-2-deterministic-late-sever");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        SeverDuringApplyDeterministic {
            inner: UndoStageConnector::single(false, true),
            path: path.to_path_buf(),
        },
    );

    let answered = bus.execute(&archive_cmd("k-r13-p12"));

    assert!(matches!(answered, Err(ExecuteError::Connector(_))));
    let attempt = attempt_id_of(&path, "k-r13-p12");
    assert_eq!(
        chain_kinds(&path, &attempt),
        vec!["claim", "send_authorized", "failed_pre_send"],
        "the ATTRIBUTION is untouched — the connector proved no wire and a moved epoch \
         cannot make that untrue"
    );
    assert_eq!(
        status_str(&path, "k-r13-p12"),
        "severed",
        "THE RED: a proven-no-wire settlement landing under a NEWER epoch completes \
         `severed` — the sever's own classification — whichever lifecycle branch the retry \
         taxonomy would otherwise have taken"
    );
    std::fs::remove_file(&path).ok();
}

// ═══════════════════════════════════════════════════════════════════════════════════
// The three cases, each with its own RED.
// ═══════════════════════════════════════════════════════════════════════════════════

/// The `basis_epoch` the LAST fact of an attempt's chain carries, durable side.
fn last_fact_basis_epoch(path: &std::path::Path, attempt_id: &str) -> i64 {
    raw_conn(path)
        .query_row(
            "SELECT basis_epoch FROM attempt_fact
                  WHERE attempt_id = ?1 ORDER BY revision DESC LIMIT 1;",
            rusqlite::params![attempt_id],
            |r| r.get(0),
        )
        .expect("the attempt has a chain")
}

#[test]
fn a_post_sever_settlement_records_the_current_epoch_on_both_doors() {
    // ═══ ═══ `basis_epoch` is "the epoch this fact was written UNDER".
    // The durable settlement reads `control_epoch` inside its own transaction and stamps
    // THAT; the mirror stamped `claim.claim_epoch` — the epoch the attempt was CLAIMED
    // under, which a sever mid-dispatch has already superseded. So a verdict landing after
    // a sever back-dated itself into the dead epoch on one door and not the other, and the
    // epoch-scoped reads (`… AND basis_epoch = (SELECT epoch FROM control_epoch …)`) that
    // decide what a recovery may act on answer differently over the same history.
    //
    // ISSUED_OR_UNKNOWN is the shape that makes this reachable: a sever may not close it,
    // so the attempt survives the fence and its verdict is written under the NEW epoch.
    let path = unique_temp_db_path("r17-p2-1-settlement-basis-epoch");
    let mut durable = SqliteIntentLog::open(&path).expect("open");
    let command = archive_of("k-r17-epoch", "msg-r17-epoch");
    admit(&mut durable, &command);
    let attempt = claim_now(&mut durable, "k-r17-epoch", 0);
    assert!(matches!(
        authorize(&mut durable, "k-r17-epoch", &attempt).expect("authorize"),
        SendAuthOutcome::Authorized { .. }
    ));
    let severed = durable
        .sever("authority:r17-operator", "2026-08-09T00:00:00Z")
        .expect("sever");
    assert!(severed.epoch > 1, "precondition: the fence moved");
    durable
        .settle_attempt(
            "k-r17-epoch",
            &attempt,
            ConnectorVerdict::Applied,
            RETRY_CAP,
            None,
        )
        .expect("the effect provably happened, after the sever");
    assert_eq!(
        chain_kinds(&path, &attempt),
        vec!["claim", "send_authorized", "ack_applied"],
        "precondition: the settlement really landed on the surviving attempt"
    );
    assert_eq!(
        last_fact_basis_epoch(&path, &attempt),
        severed.epoch,
        "precondition (the durable door already does this): a settlement is stamped with \
         the epoch it was WRITTEN under"
    );

    // The SAME history on the mirror.
    let mut mirror = InMemoryIntentLog::new();
    record_basis(&mut mirror, &archive_cmd("k-r17-epoch")).expect("admit");
    let mem_attempt = in_memory_claim(&mut mirror, "k-r17-epoch");
    in_memory_authorize(&mut mirror, "k-r17-epoch", &mem_attempt);
    let mem_severed = mirror
        .sever("authority:r17-operator", "2026-08-09T00:00:00Z")
        .expect("sever");
    assert_eq!(
        mem_severed.epoch, severed.epoch,
        "precondition: both fences moved the same way"
    );
    mirror
        .settle_attempt(
            "k-r17-epoch",
            &mem_attempt,
            ConnectorVerdict::Applied,
            RETRY_CAP,
            None,
        )
        .expect("the effect provably happened, after the sever");
    let mirrored = mirror
        .attempt_facts()
        .iter()
        .rfind(|f| f.attempt_id == mem_attempt)
        .expect("the mirror's chain ends at the settlement")
        .clone();
    assert_eq!(
        mirrored.kind,
        crate::attempt::FactKind::AckApplied,
        "precondition: the same verdict fact"
    );
    assert_eq!(
        mirrored.basis_epoch,
        last_fact_basis_epoch(&path, &attempt),
        "THE RED: the mirror stamped the CLAIM's dead epoch onto a fact it wrote under the \
         current one — a fake that dates the same settlement differently from the engine"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn a_payload_free_fact_kind_refuses_a_payload() {
    // ═══ ═══ `fact_payload_json` emits EXACTLY `{}` for the six
    // payload-free kinds, and `fact_payload_from_json`'s own contract is that "a payload the
    // writer cannot have produced means the ledger is not trustworthy, which is never a
    // repair". The payload-free arm ignored `v` entirely: a scalar, an array, or an object
    // full of durable bytes all decoded to `FactPayload::None` — the one place in this
    // decoder where unreadable durable state was silently discarded instead of raised.
    //
    // ARM 1 — the decoder's own contract, at the byte.
    for crafted in [
        r#"{"exposure_key":"deleted-atom"}"#,
        r#"[1,2,3]"#,
        r#""applied""#,
        "null",
        "7",
    ] {
        let decoded = fact_payload_from_json(crate::attempt::FactKind::AckApplied, crafted);
        assert!(
            decoded.is_err(),
            "THE RED: `ack_applied` carrying `{crafted}` is a row this writer cannot have \
             produced, got {decoded:?}"
        );
    }
    // …and the empty object the writer DOES emit still decodes.
    assert_eq!(
        fact_payload_from_json(crate::attempt::FactKind::AckApplied, "{}").expect("the writer's own shape"),
        crate::attempt::FactPayload::None,
    );

    // ARM 2 — the same defect as a STORED ROW, read through a real door. Same craft as
    // `a_claim_door_refuses_an_attempt_whose_owner_drifted`: the row is grafted onto the
    // REAL chain (append-only triggers refuse rewriting the engine's own `{}`).
    let path = unique_temp_db_path("r17-p2-3-ack-payload");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        UndoStageConnector::single(false, true),
    );
    bus.execute(&archive_cmd("k-r17-payload")).expect("the forward applies");
    let attempt = attempt_id_of(&path, "k-r17-payload");
    let (owner, created_at): (String, String) = raw_conn(&path)
        .query_row(
            "SELECT operation_id, created_at FROM attempt_fact
                  WHERE attempt_id = ?1 AND fact_kind = 'claim';",
            rusqlite::params![attempt],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("the CLAIM exists");
    let conn = raw_conn(&path);
    conn.execute(
        "INSERT INTO attempt_fact (operation_id, attempt_id, revision, fact_kind,
                                       attempt_ordinal, basis_epoch, created_at, payload,
                                       prior_revision)
             VALUES (?1, ?2, 4, 'ack_applied', NULL, 1, ?3, '{\"observation\":\"x\"}', 3);",
        rusqlite::params![owner, attempt, created_at],
    )
    .expect("hand-graft an ack fact carrying bytes the writer never emits");
    conn.execute(
        "UPDATE intents SET status = 'pending' WHERE idempotency_key = 'k-r17-payload';",
        [],
    )
    .expect("re-open the operation");
    drop(conn);

    let err = bus
        .recover()
        .expect_err("a chain carrying an unreadable payload is never dispatched over");
    match err {
        ExecuteError::Log(LogError(message)) => assert!(
            message.contains("must be the empty object"),
            "THE RED: the refusal must NAME the payload defect — pre-fix the decode passed \
             clean and the chain failed (if at all) for an unrelated reason, got '{message}'"
        ),
        other => panic!("expected a fail-loud Log error, got {other:?}"),
    }
    std::fs::remove_file(&path).ok();
}

// ═══════════════════════════════════════════════════════════════════════════════════
// — A TERMINAL UNDO CHILD IS A SETTLED CHILD, NOT A SWEEP INCIDENT.
// ═══════════════════════════════════════════════════════════════════════════════════

#[test]
fn a_severed_undo_child_never_aborts_the_recovery_sweep() {
    // ═══ ═══ THE LAST UNSWEPT MEMBER OF THE PARK-OVER-TERMINAL CLASS,
    // on the UNDO arm of the sweep.
    //
    // The trace: `recover()` snapshots a PENDING undo child; a peer's `sever()` lands
    // before that child's drive reaches the epoch fence; the fence's own terminal arm
    // reads the row (`terminal_disposition` ⇒ `Severed`) and answers it exactly as a
    // replay would (`status_replay_outcome` ⇒ `Err(ExecuteError::Severed)`) — which is
    // RIGHT. What was wrong is what the SWEEP did with that answer: the undo arm's
    // catch-all is "a durable-log error is not something a sweep may paper over", so a
    // NORMAL concurrent terminalization aborted the whole pass, exactly the harm the
    // forward arm's `DispatchOwnership::Terminal` arm was cut to end.
    //
    // THE CONSTRUCTION, and why each piece is load-bearing:
    //   • a global sever terminalizes EVERY pending row, so "an unrelated pending op still
    //     gets recovered" is unconstructible. The continuation is proven at the PROVIDER
    //     SEAM instead — a later UNPREPARED forward op still gets its `observe` called
    //     (the capture pipeline reads before PREPARE's status guard can answer `Closed`),
    //     so `observe_count` is the witness that the loop walked PAST the child. Same
    //     technique as `a_sever_landing_mid_sweep_closes_the_sweep_honestly_instead_of_aborting_it`.
    //   • the sever must land INSIDE the sweep, after the snapshot: the first operation's
    //     own `observe` fires it from a second connection.
    //   • the child must reach the EPOCH FENCE, not the §4.1 no-op kill that runs above it
    //     — so the captured `P` is asserted `!= A` below. (The other pre-fence terminal
    //     answer, `verify_undo`'s ChildMoved, returns the same replay error and is caught
    //     by the same arm; the fence is the path exercised here.)
    let path = unique_temp_db_path("r18-p2-severed-child-sweep");

    // ── THE SNAPSHOT, IN SEQ ORDER (`unreconciled()` is `ORDER BY seq`) ──
    let mut seed = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        UndoStageConnector::single(false, true),
    );
    // (A) THE TRIGGER, on its own resource: Pending and UNPREPARED, so the sweep reaches
    //     it through the capture pipeline — and its `observe` is where the peer severs.
    seed_pending_on(&path, &seed, "k-r18-a", "msg-r18-a");
    // (P + C) the parent APPLIES and its undo child is admitted PENDING behind a live
    //     predecessor, which is then terminalized: a deferred child, undriven.
    let child_key = deferred_undo_child(&path, &mut seed, "k-r18-parent");
    // (D) THE CONTINUATION WITNESS, on a third resource: LATER in seq than the child and
    //     UNPREPARED, so its `observe` can only happen if the sweep survived the child.
    seed_pending_on(&path, &seed, "k-r18-d", "msg-r18-d");
    drop(seed);

    assert_eq!(
        status_str(&path, "k-r18-parent"),
        "applied",
        "precondition: the parent is NOT pre-flipped — the child is the only undo truth"
    );
    assert_eq!(
        status_str(&path, &child_key),
        "pending",
        "precondition: the child is admitted and undriven"
    );
    let mut journal_read = SqliteIntentLog::open(&path).expect("reopen for the journal read");
    let captured_p = journal_read
        .undo_context("k-r18-parent")
        .expect("undo_context reads")
        .expect("the parent exists")
        .journal
        .expect("a journal-required forward intent owns a row")
        .p;
    drop(journal_read);
    assert_eq!(
        captured_p,
        atoms(&[("membership:INBOX", true)]),
        "precondition: P != A ({{INBOX: false}}), so the §4.1 no-op kill — which runs \
         ABOVE the fence — cannot fire and the child reaches the EPOCH FENCE"
    );

    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("reopen"),
        PeerSeversInsideTheCaptureWindow::new(&path),
    );

    let report = bus
        .recover()
        .expect("a peer's sever is a settled child, not a store the sweep may not trust");

    assert_eq!(
        status_str(&path, &child_key),
        "severed",
        "precondition: the kill switch closed the child mid-sweep, between the snapshot \
         and the child's own epoch fence"
    );
    assert_eq!(
        bus.connector().wire.observe_count(),
        2,
        "THE HARM, proven at the provider seam: the sweep must WALK PAST the settled \
         child and still reach the later operation — pre-fix the child's `Err(Severed)` \
         hit the undo arm's catch-all and aborted the whole pass at 1 observation"
    );
    assert_eq!(
        status_str(&path, "k-r18-d"),
        "severed",
        "…and the later operation's own closure is answered honestly too"
    );
    assert_eq!(
        bus.connector().wire.restore_call_count(),
        0,
        "no severed child reached the restore socket"
    );
    assert_eq!(
        bus.connector().wire.apply_count(),
        0,
        "…and no severed forward operation reached the wire"
    );
    assert_eq!(report.recovered, 0, "a closure is not a recovery");
    assert!(
        report.failed.is_empty(),
        "…nor a failure: nothing was dispatched and nothing was dead-lettered, got {:?}",
        report.failed
    );
    assert!(
        report.undo_conflicts.is_empty(),
        "…nor a §3.2 conflict: no table was read, got {:?}",
        report.undo_conflicts
    );
    std::fs::remove_file(&path).ok();
}

// ═══════════════════════════════════════════════════════════════════════════════════
// A RESOLVED ADJUDICATION IS ITS OWN REPLAY CLASS, NOT PLAIN SUCCESS.
// ═══════════════════════════════════════════════════════════════════════════════════

#[test]
fn an_adjudicated_late_undo_child_never_aborts_the_recovery_sweep() {
    // The settled-truth table, extended to the class this fold adds. `AdjudicatedLate`
    // is a NEW error value on a path that previously answered `Ok(())` (resolved-applied)
    // or `Err(Failed)` (resolved-refused, already in catch set), so without an arm of
    // its own it would fall to the undo arm's catch-all — "the store can no longer be
    // trusted" — and ONE ordinary post-adjudication late ack would abort the whole pass,
    // exactly the harm was cut to end. Its settled-truth argument is the unresolved
    // arm's, one step further on: §5.2d closed this child, and a late ack resolves the
    // HISTORICAL axis only — it never re-opens the operation or re-authorizes dispatch. So
    // the child is terminal, is not an in-flight predecessor, and raises no barrier.
    //
    // THE INTERLEAVE ('s, inside a sweep): the sweep drives a deferred undo child; an
    // operator adjudicates it while its restore is on the wire; the provider then confirms
    // the restoration, and §5.2a's whitelist converts this driver's `Applied` verdict into
    // the `LATE_ACK_APPLIED` that RESOLVES the axis. The settlement's `outranked` axis
    // hands the drive `AdjudicatedLate(Applied)`.
    let path = unique_temp_db_path("bot-r1-p2-adjudicated-late-sweep");
    let wire = SharedWire::new(UndoStageConnector::single(false, true));
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        AdjudicateInsideRestore {
            inner: wire.clone(),
            path: path.to_path_buf(),
            parent_key: "k-bot-r1-parent".to_string(),
            armed: std::cell::Cell::new(true),
        },
    );
    // (P + C) the parent applies and its undo child is admitted PENDING behind a live
    //     predecessor, which is then terminalized: a deferred, undriven child.
    let child_key = deferred_undo_child(&path, &mut bus, "k-bot-r1-parent");
    // (D) THE CONTINUATION WITNESS: LATER in seq, on its OWN resource (so no per-resource
    //     barrier can explain its fate), and recoverable — it can only reach `applied` if
    //     the sweep survived the child.
    seed_pending_on(&path, &bus, "k-bot-r1-d", "msg-bot-r1-d");
    // C == A ⇒ the child's §3.2 requalification RESTORES, and the restore reaches the wire.
    wire.wire().set_state(atoms(&[("membership:INBOX", false)]));

    let report = bus
        .recover()
        .expect("a late-ack-resolved adjudication is a settled child, not a store the \
                 sweep may not trust");

    let child_attempt = attempt_of(&path, &child_key);
    assert_eq!(
        status_str(&path, &child_key),
        "adjudicated",
        "precondition: the operator closed the child's OPERATIONAL axis mid-restore"
    );
    assert!(
        chain_kinds(&path, &child_attempt).contains(&"late_ack_applied".to_string()),
        "precondition: the provider's definitive answer landed through the LATE-ACK door, \
         so the drive's answer is the RESOLVED class and not `AdjudicatedUnresolved`: {:?}",
        chain_kinds(&path, &child_attempt)
    );
    assert_eq!(
        status_str(&path, "k-bot-r1-parent"),
        "undone",
        "…and the parent flip rode that accepted late ack, so the pair is genuinely \
         settled — the child is nothing this sweep may drive again"
    );
    assert_eq!(
        status_str(&path, "k-bot-r1-d"),
        "applied",
        "THE HARM: the sweep must WALK PAST the settled child and still recover the later \
         operation — without the `AdjudicatedLate(_)` arm the child's own error hits the \
         undo arm's catch-all and aborts the pass before this row is ever reached"
    );
    assert_eq!(
        report.recovered, 1,
        "…and exactly ONE row was recovered: the later operation. A closure somebody \
         else's authority made is not this sweep's recovery"
    );
    assert!(
        report.failed.is_empty(),
        "nothing was dead-lettered and no connector rejected: {:?}",
        report.failed
    );
    assert!(
        report.undo_conflicts.is_empty(),
        "…nor is this a §3.2 conflict: the restore LANDED, got {:?}",
        report.undo_conflicts
    );
    std::fs::remove_file(&path).ok();
}
