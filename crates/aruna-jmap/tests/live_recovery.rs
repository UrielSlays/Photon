//! Env-gated LIVE recovery drills against a real Stalwart JMAP server (M0 DoD §1 crash-recovery
//! and §3 ambiguous-outcome/lost-ack). OPT-IN: runs only when `PHOTON_JMAP_IT=1`; otherwise skips
//! so the default `cargo test` stays hermetic. Bring the fixture up first (see fixtures/stalwart).
//!
//! A "crash" = drop the CommandBus and reopen the SQLite file (the only surviving state). The
//! fault/observer decorators below are TEST-ONLY; production code carries no fault hooks. D1 and D2
//! are sequential phases of ONE test fn because integration tests run in parallel and the fixture
//! seeds a single message — two test fns mutating it would race. D1 archives, D2 unarchives, so the
//! fixture ends back in the Inbox (re-runnable).
//!
//! Non-vacuity: each recovery phase wraps the REAL connector
//! in `CountingForward` so the drill INDEPENDENTLY witnesses what `recover()` did at the PROVIDER —
//! not merely what the engine reported. In D1 that witness is POSITIVE (exactly one re-dispatch);
//! in D2 it is the ZERO (see below), and it is load-bearing in both directions for the same reason:
//! the final provider state alone cannot distinguish a real dispatch from a phantom one.
//!
//! **D2 PROVES THE NO-DUPLICATE-SEND PROPERTY, WHICH IS STRONGER THAN AT-LEAST-ONCE.** These
//! drills were first written against at-least-once semantics, where a lost ack simply left
//! the intent retryable and recovery re-sent the mutation. §5.2b's ack-verdict/one-wire contract
//! ends that: a post-authorization failure the connector cannot POSITIVELY prove was never issued is
//! `ACK_AMBIGUOUS`/ISSUANCE_UNKNOWN, and "no retry from `ACK_AMBIGUOUS`/`ISSUANCE_UNKNOWN`, ever
//! (adjudication is the only path)". So D2's old assertions asserted the very DUPLICATE SEND the
//! contract forbids; the drill now witnesses the no-duplicate-send guarantee against a real server,
//! which is strictly stronger than the at-least-once it used to claim.

mod common;

use std::cell::Cell;

use aruna::jmap::JmapConnector;
use aruna::prestate::{FrozenBasis, Observation};
use aruna::{
    Action, Command, CommandBus, Connector, ConnectorError, ExecuteError, IntentLog, IntentStatus,
    ResolveBasisError, SqliteIntentLog,
};
use aruna_jmap::transport::HttpJmapTransport;
use common::{cmd, live_env, unique_sqlite_path, FixedAccount, FixedMessage, Probe};

/// D1 fault: simulate a crash BEFORE the provider effect. The fault is on the APPLY ONLY —
/// resolution and observation delegate to the wrapped REAL connector, exactly like
/// [`CrashAfterEffect`], so the pre-crash phase freezes a basis that identifies the REAL JMAP
/// object and journals a REAL observation of it. The provider is never MUTATED (apply never
/// forwards), and the failure is the PROVEN-NO-WIRE one — `FAILED_PRE_SEND`, which leaves the
/// intent `Pending` (retryable) for `recover()`.
///
/// This decorator used to answer its own local `drill:` basis with a literal `INBOX` atom, which
/// made the drill grade its own homework: recovery skipped real observation and the persisted
/// pre-state identified nothing that exists. A crash-recovery drill whose journal is a
/// placeholder cannot witness the property it was written for.
struct CrashBeforeEffect<C: Connector> {
    inner: C,
}
impl<C: Connector> Connector for CrashBeforeEffect<C> {
    fn apply(&self, _command: &Command, _basis: &FrozenBasis) -> Result<(), ConnectorError> {
        // THE fault injection point — and the only one. `inner.apply` is deliberately NOT called:
        // the provider must not see this mutation.
        //
        // …AND THAT WITHHELD CALL IS EXACTLY WHY THIS DECORATOR MAY CLAIM `proven_no_wire`. The claim is a POSITIVE proof about the MUTATION's
        // issuance (`aruna::EffectEvidence::ProvenNoWire`), and this fault is decided from local
        // values before any mutation request is built or handed to the transport — the decorator
        // KNOWS no `Email/set` left the host, because it is the thing that refused to make the
        // call. A bare `ConnectorError::transient` defaults to `Indeterminate`, and §5.2b's
        // mapping table then records this post-send-authorization failure as `ACK_AMBIGUOUS`:
        // the operation parks AwaitingAdjudication, no retry is ever legal from it, and D1's
        // crash-RECOVERY phase below would have nothing left to recover. That would not be a
        // defect — it is the honest answer to a connector that stayed silent about a
        // proof it holds, and the fix is to speak it.
        Err(ConnectorError::transient("simulated crash before provider effect").proven_no_wire())
    }
    fn resolve_basis(&self, command: &Command) -> Result<FrozenBasis, ResolveBasisError> {
        self.inner.resolve_basis(command)
    }
    fn observe(
        &self,
        command: &Command,
        basis: &FrozenBasis,
    ) -> Result<Observation, ConnectorError> {
        self.inner.observe(command, basis)
    }
    // The restore seam delegates for the same reason resolution and observation
    // do — THE fault is `apply`, and only `apply`.
    fn restore(
        &self,
        command: &Command,
        basis: &FrozenBasis,
        p: &std::collections::BTreeMap<String, bool>,
    ) -> Result<(), ConnectorError> {
        self.inner.restore(command, basis, p)
    }
}

/// D2 fault: simulate a LOST ACK — forward to the real connector (the provider effect REALLY
/// happens), then drop the ack by returning a transient error.
///
/// **THE ERROR IS DELIBERATELY EVIDENCE-FREE, and that is the whole drill**. A lost ack is precisely the outcome about which the connector can prove
/// NOTHING: bytes left the host and no answer came back. `ConnectorError::transient` defaults to
/// [`aruna::EffectEvidence::Indeterminate`] (the honest default — "a connector that says nothing
/// has proven nothing"), so §5.2b's mapping table records `ACK_AMBIGUOUS` and the operation parks
/// AwaitingAdjudication: no status write, no retry budget spent, and no second dispatch — ever.
/// It must NOT be tagged `proven_no_wire` the way [`CrashBeforeEffect`] is; here the mutation
/// demonstrably DID reach the provider, and the drill's own out-of-band probe proves it below.
struct CrashAfterEffect<C: Connector> {
    inner: C,
}
impl<C: Connector> Connector for CrashAfterEffect<C> {
    fn apply(&self, command: &Command, basis: &FrozenBasis) -> Result<(), ConnectorError> {
        self.inner.apply(command, basis)?; // real provider mutation happens here
        Err(ConnectorError::transient(
            "simulated lost ack after provider success",
        ))
    }
    // The fault is on the ACK, not on resolution or observation — both delegate to the real
    // connector so the drill exercises the live seam.
    fn resolve_basis(&self, command: &Command) -> Result<FrozenBasis, ResolveBasisError> {
        self.inner.resolve_basis(command)
    }
    fn observe(
        &self,
        command: &Command,
        basis: &FrozenBasis,
    ) -> Result<Observation, ConnectorError> {
        self.inner.observe(command, basis)
    }
    // The restore seam delegates — the fault is the ACK of `apply`, nothing else.
    fn restore(
        &self,
        command: &Command,
        basis: &FrozenBasis,
        p: &std::collections::BTreeMap<String, bool>,
    ) -> Result<(), ConnectorError> {
        self.inner.restore(command, basis, p)
    }
}

/// Forwarding counter: wraps the REAL recovery connector and counts each `apply`, so a drill can
/// INDEPENDENTLY witness what `recover()` did at the provider — not merely what the engine wrote
/// on the intent. Closes the "grades its own homework" gap in BOTH directions, because the final
/// provider state alone cannot distinguish a real dispatch from a phantom one:
///
/// * D1 reads it as a POSITIVE witness — exactly one re-dispatch, so `Applied` is backed by a
///   wire touch this drill saw;
/// * D2 reads it as the ZERO witness — the message is ALREADY
///   in its target mailbox from the lost-ack phase, so nothing about the final state could catch
///   a forbidden duplicate `Email/set`. This counter can, and it is the only thing that can.
struct CountingForward<C: Connector> {
    inner: C,
    count: Cell<usize>,
}
impl<C: Connector> CountingForward<C> {
    fn new(inner: C) -> Self {
        Self {
            inner,
            count: Cell::new(0),
        }
    }
    fn count(&self) -> usize {
        self.count.get()
    }
}
impl<C: Connector> Connector for CountingForward<C> {
    // Only APPLIES are counted: an observation is a read, never a dispatch, so it must not
    // satisfy the non-vacuity witness.
    fn resolve_basis(&self, command: &Command) -> Result<FrozenBasis, ResolveBasisError> {
        self.inner.resolve_basis(command)
    }
    fn observe(
        &self,
        command: &Command,
        basis: &FrozenBasis,
    ) -> Result<Observation, ConnectorError> {
        self.inner.observe(command, basis)
    }
    fn apply(&self, command: &Command, basis: &FrozenBasis) -> Result<(), ConnectorError> {
        self.count.set(self.count.get() + 1);
        self.inner.apply(command, basis)
    }
    // A restore IS a dispatch, but it is not a FORWARD apply — it must never
    // increment the counter this drill reads as its forward-re-dispatch witness. These drills
    // never undo; one that does needs its own separate counter, not this one.
    fn restore(
        &self,
        command: &Command,
        basis: &FrozenBasis,
        p: &std::collections::BTreeMap<String, bool>,
    ) -> Result<(), ConnectorError> {
        self.inner.restore(command, basis, p)
    }
}

/// Assert the message belongs to EXACTLY one mailbox — sharp set-equality, not `contains && !contains`
/// (the predicate is exactly "X only", not weaker). `actual`
/// is the live `Email/get` mailboxIds membership; a surprise extra label now fails the drill.
///
/// Failure output is ID-FREE (count + booleans only): provider-native mailbox ids must never reach
/// test logs, matching the `live_jmap` confinement.
fn assert_sole_mailbox(actual: &[String], expected: &str, context: &str) {
    let count = actual.len();
    let contains_expected = actual.iter().any(|m| m == expected);
    assert!(
        count == 1 && contains_expected,
        "{context}: message must belong to EXACTLY the expected mailbox \
         (membership_count={count}, contains_expected={contains_expected}; ids redacted)"
    );
}

#[test]
fn live_recovery_drills() {
    let Some((url, user, pass)) = live_env() else {
        return;
    };
    let probe = Probe::new(&url, &user, &pass);
    let account = probe.account_id();
    let inbox = probe.mailbox_for_role(&account, "inbox");
    let archive = probe.mailbox_for_role(&account, "archive");
    let email = probe
        .email_ids_in(&account, &inbox)
        .first()
        .expect("a seeded inbox message (run setup.sh first)")
        .clone();

    // Sharp baseline: assert the seed starts Inbox-only, so "the provider was
    // untouched before the crash" in D1 is a state-sharp claim, not merely "contains inbox".
    let start = probe.email_mailboxes(&account, &email);
    assert_sole_mailbox(&start, &inbox, "fixture precondition: seed must start in Inbox only");

    // ---------- D1: crash BEFORE the provider effect (DoD §1) ----------
    let path = unique_sqlite_path("d1");
    // Phase 1: claim the intent, fault before the provider sees it -> Pending, provider untouched.
    {
        let log = SqliteIntentLog::open(&path).expect("open log");
        // The REAL connector under the fault: admission resolves the live JMAP basis and the
        // capture pipeline takes a REAL observation of the seeded message — only the apply is
        // faulted, so the provider stays untouched (asserted immediately after this block).
        let transport =
            HttpJmapTransport::connect_for_test_fixture(&url, &user, &pass).expect("connect");
        let conn = JmapConnector::new(
            transport,
            FixedAccount(account.clone()),
            FixedMessage(email.clone()),
        );
        let mut bus = CommandBus::new(log, CrashBeforeEffect { inner: conn });
        let err = bus
            .execute(&cmd(
                "recover-d1",
                Action::Archive {
                    message_ref: "seed".into(),
                },
            ))
            .expect_err("the fault must surface as an error, never a false Ok");
        assert!(
            matches!(err, ExecuteError::Connector(_)),
            "a transient connector failure, not a log/conflict error"
        );
        assert_eq!(
            bus.log().get("recover-d1").unwrap().unwrap().status,
            IntentStatus::Pending,
            "a single transient fault leaves the intent Pending (retryable), not Failed"
        );
    } // bus dropped == process death; only the SQLite file survives.
    let before = probe.email_mailboxes(&account, &email);
    assert_sole_mailbox(
        &before,
        &inbox,
        "D1: provider must NOT be mutated before the crash (still Inbox only)",
    );
    // Phase 2: reopen from disk, recover with the REAL transport (counter-wrapped to witness dispatch).
    {
        let log = SqliteIntentLog::open(&path).expect("reopen log");
        let transport =
            HttpJmapTransport::connect_for_test_fixture(&url, &user, &pass).expect("connect");
        let conn = JmapConnector::new(
            transport,
            FixedAccount(account.clone()),
            FixedMessage(email.clone()),
        );
        let mut bus = CommandBus::new(log, CountingForward::new(conn));
        let report = bus.recover().expect("recover sweep");
        assert_eq!(
            bus.connector().count(),
            1,
            "D1: recover dispatched the Email/set to the provider exactly once"
        );
        assert_eq!(
            report.recovered, 1,
            "D1: recover re-dispatched the one Pending intent"
        );
        assert_eq!(
            bus.log().get("recover-d1").unwrap().unwrap().status,
            IntentStatus::Applied,
            "D1: the intent reconciles to Applied after crash-recovery"
        );
    }
    let after_d1 = probe.email_mailboxes(&account, &email);
    assert_sole_mailbox(
        &after_d1,
        &archive,
        "D1: after crash-recovery the message is in Archive only (the single witnessed dispatch)",
    );
    let _ = std::fs::remove_file(&path);

    // ---------- D2: lost ack AFTER the provider effect (DoD §3) ----------
    // State: message in Archive (from D1). Drive Unarchive so the fixture ends as originally seeded.
    //
    // WHAT THIS PHASE PROVES, POST-STAGE-4. The old drill asserted
    // at-least-once: the lost ack left the intent retryable and `recover()` re-sent the same
    // `Email/set`. §5.2b retired that: the engine cannot prove the mutation was never issued, so
    // the attempt is `ACK_AMBIGUOUS`/ISSUANCE_UNKNOWN and NOTHING may re-dispatch it. The drill
    // therefore now witnesses, against a real server, the NO-DUPLICATE-SEND guarantee — the
    // duplication hazard the design's §5.2b closes — and it is the live half that makes the
    // witness sharp: the provider effect DID land, the out-of-band probe SEES it, and the engine
    // still honestly refuses to claim it. Only a human's §5.2d adjudication closes the operation.
    let path = unique_sqlite_path("d2");
    // Phase 1: the REAL provider effect happens, then the ack is "lost" -> ISSUANCE_UNKNOWN.
    {
        let log = SqliteIntentLog::open(&path).expect("open log");
        let transport =
            HttpJmapTransport::connect_for_test_fixture(&url, &user, &pass).expect("connect");
        let conn = JmapConnector::new(
            transport,
            FixedAccount(account.clone()),
            FixedMessage(email.clone()),
        );
        let mut bus = CommandBus::new(log, CrashAfterEffect { inner: conn });
        let err = bus
            .execute(&cmd(
                "recover-d2",
                Action::Unarchive {
                    message_ref: "seed".into(),
                },
            ))
            .expect_err("the lost ack must surface as an error, never a false Ok");
        assert!(
            matches!(err, ExecuteError::Connector(_)),
            "a transient (lost-ack) connector failure"
        );
        let row = bus.log().get("recover-d2").unwrap().unwrap();
        assert_eq!(
            row.status,
            IntentStatus::Pending,
            "an ACK_AMBIGUOUS settlement writes NO status: the operation is neither completed \
             nor dead-lettered — it is OPEN, awaiting adjudication"
        );
        assert_eq!(
            row.attempts, 0,
            "…and spends NO retry budget: no retry is authorized from ISSUANCE_UNKNOWN, so \
             nothing may be charged for one"
        );
    }
    // The provider DID apply despite the lost ack: the message is already back in Inbox.
    let mid_d2 = probe.email_mailboxes(&account, &email);
    assert_sole_mailbox(
        &mid_d2,
        &inbox,
        "D2: provider effect happened before the ack was lost (already Inbox only)",
    );
    // Phase 2: reopen, sweep (counter-wrapped). The counter is the load-bearing witness in the
    // NEGATIVE direction now: it proves recover() put NO second Email/set on the wire. The final
    // Inbox-only state cannot prove that — phase 1 already put the message there, so a forbidden
    // duplicate dispatch would leave exactly the same provider state behind.
    {
        let log = SqliteIntentLog::open(&path).expect("reopen log");
        let transport =
            HttpJmapTransport::connect_for_test_fixture(&url, &user, &pass).expect("connect");
        let conn = JmapConnector::new(
            transport,
            FixedAccount(account.clone()),
            FixedMessage(email.clone()),
        );
        let mut bus = CommandBus::new(log, CountingForward::new(conn));
        let report = bus.recover().expect("recover sweep");
        assert_eq!(
            bus.connector().count(),
            0,
            "D2: NO RETRY EVER from an ambiguous attempt — the sweep must not touch the wire \
             again with a mutation that may already have applied"
        );
        assert_eq!(
            report.recovered, 0,
            "D2: nothing was recovered — the sweep PARKED the operation, it did not close it"
        );
        assert!(
            report.failed.is_empty(),
            "…and a park is not a failure either: the operation is open, not rejected"
        );
        let row = bus.log().get("recover-d2").unwrap().unwrap();
        assert_eq!(
            row.status,
            IntentStatus::Pending,
            "D2: still OPEN after the sweep — an unknown issuance is closed by §5.2d \
             adjudication, which is a human's decision, and by nothing else"
        );
        assert_eq!(row.attempts, 0, "D2: still no retry budget spent");
        // …AND IT IS SURFACED FOR THAT HUMAN. §5.2d's unknown-age report is where an
        // ISSUANCE_UNKNOWN attempt becomes visible; a park that nobody can see would be a silent
        // stall, which is the opposite of what the honest refusal buys. Threshold 0 = "list
        // everything unresolved" (the report SURFACES, it never auto-decides).
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs();
        let review = bus.unknown_review(now, 0).expect("the §5.2d surfacing report");
        assert_eq!(
            review.rows.len(),
            1,
            "D2: exactly the lost-ack attempt is surfaced as unresolved"
        );
        assert_eq!(review.rows[0].idempotency_key, "recover-d2");
        assert!(
            review.rows[0].review_due,
            "D2: at threshold 0 the unknown is due for a human's review"
        );
        assert!(
            !review.rows[0].reconcile_cap_reached,
            "no RECONCILE writer exists in this build, so the cap is not reached"
        );
        assert!(
            !review.clock_rollback_detected,
            "the fixture clock did not step back, so the age verdict is the ORDINARY one"
        );
    }
    // Provider truth: still Inbox only. The mutation of phase 1 DID land — this out-of-band probe
    // is the only party that knows it — and the sweep added nothing on top of it. That pairing is
    // the whole point: the engine refused to claim an effect it cannot prove, and refusing cost
    // the provider nothing.
    let after_d2 = probe.email_mailboxes(&account, &email);
    assert_sole_mailbox(
        &after_d2,
        &inbox,
        "D2: the applied provider effect stands and the parked sweep added no second one \
         (Inbox only — no double-apply / corruption)",
    );
    let _ = std::fs::remove_file(&path);
}
