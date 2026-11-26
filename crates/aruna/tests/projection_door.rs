//! (THE PROJECTION DOOR / THE DOOR'S PRECONDITIONS) —
//! permanent witnesses against `ReadCoordinator::project_applied_intent` DIRECTLY (never through
//! the shell): the marker and the placement/header write commit or roll back as ONE transaction,
//! a `None` basis marks the intent without ever writing the placement/header (never a guess at
//! freshness it cannot prove), the door's own row precondition (`status = 'applied' AND
//! projected = 0`) is enforced before anything is derived, and two siblings recorded against the
//! same observation both project.
mod common;

use aruna::prestate::{Freshness, FrozenBasis};
use aruna::read_coordinator::{ProjectionWrite, ReadCoordinator};
use aruna::{Action, Command, Facet, IntentLog, IntentStatus, MailFlag, SqliteIntentLog};
use common::{seed_inbox, temp_db};
use std::collections::BTreeMap;

fn raw(path: &std::path::Path) -> rusqlite::Connection {
    rusqlite::Connection::open(path).unwrap()
}

fn placement_of(path: &std::path::Path, message_ref: &str) -> String {
    raw(path)
        .query_row(
            "SELECT placement FROM message_placement WHERE account = 'acct' AND message_ref = ?1;",
            [message_ref],
            |r| r.get(0),
        )
        .unwrap()
}

fn mailbox_of(path: &std::path::Path, message_ref: &str) -> String {
    raw(path)
        .query_row(
            "SELECT mailbox FROM message_header WHERE account = 'acct' AND message_ref = ?1;",
            [message_ref],
            |r| r.get(0),
        )
        .unwrap()
}

fn flagged_of(path: &std::path::Path, message_ref: &str) -> i64 {
    raw(path)
        .query_row(
            "SELECT flagged FROM message_header WHERE account = 'acct' AND message_ref = ?1;",
            [message_ref],
            |r| r.get(0),
        )
        .unwrap()
}

fn projected_of(path: &std::path::Path, key: &str) -> i64 {
    raw(path)
        .query_row("SELECT projected FROM intents WHERE idempotency_key = ?1;", [key], |r| r.get(0))
        .unwrap()
}

fn status_of(path: &std::path::Path, key: &str) -> String {
    raw(path)
        .query_row("SELECT status FROM intents WHERE idempotency_key = ?1;", [key], |r| r.get(0))
        .unwrap()
}

/// the header row's ACTUAL `ingest_revision` — a test basis is built
/// from this, never assumed to be `1`, so the witness proves the door's own `current <= basis`
/// comparison rather than a coincidence of a fresh store's first-assigned revision.
fn ingest_revision_of(path: &std::path::Path, message_ref: &str) -> i64 {
    raw(path)
        .query_row(
            "SELECT ingest_revision FROM message_header WHERE account = 'acct' AND message_ref = ?1;",
            [message_ref],
            |r| r.get(0),
        )
        .unwrap()
}

/// the door now reads `basis_ingest_revision` from the row itself, so
/// a fixture that wants a SPECIFIC basis (rather than whatever `record_applied` happened to leave
/// NULL at) sets it directly through a raw write — the same shape the shell's own `mod tests`
/// (`src-tauri/src/lib.rs`) uses for the identical need.
fn set_basis_ingest_revision(path: &std::path::Path, key: &str, basis: Option<i64>) {
    raw(path)
        .execute(
            "UPDATE intents SET basis_ingest_revision = ?1 WHERE idempotency_key = ?2;",
            rusqlite::params![basis, key],
        )
        .unwrap();
}

/// A command's basis — the SAME stateless, provider-constant shape `capacity_seize_bound.rs`'s
/// own `fixture_basis_for` builds for Archive (see that file's doc: "the SAME stateless,
/// provider-constant basis shape `lib.rs`'s own `fixture_basis` test helper builds"). Reused
/// unchanged across every action this file records: `record`'s admission checks are about
/// capacity/readability, never about matching the basis's atoms to the action's own semantics, so
/// one opaque fixture basis serves Trash, Archive and SetFlag alike.
fn fixture_basis(message_ref: &str) -> FrozenBasis {
    FrozenBasis {
        native_resource_key: aruna::prestate::native_resource_key("projection-door-fixture", &[message_ref]),
        touched_atoms: [
            ("membership:INBOX".to_string(), "INBOX".to_string()),
            ("label:TRASH".to_string(), "TRASH".to_string()),
        ]
        .into_iter()
        .collect(),
        atom_targets: [("membership:INBOX".to_string(), false), ("label:TRASH".to_string(), true)]
            .into_iter()
            .collect(),
        role_bindings: BTreeMap::new(),
        freshness: Freshness::ImmutableConstants,
    }
}

/// Record a real intent through the public admission door and settle it to `Applied` — mirroring
/// what a real dispatch does before any projection door ever runs, so the door's
/// `idempotency_key` marker names a REAL row, never a bare string with no row behind it.
/// generalized over `action` (was Trash-only) so the sibling witness can
/// record a Star and an Archive on the SAME message, and takes `basis` directly (the door
/// reads `basis_ingest_revision` from the row, never from a caller-supplied parameter) —
/// `record()` freezes the header's revision at record time (NULL when no header row exists), and
/// [`set_basis_ingest_revision`] then states the basis each witness wants explicitly (including
/// `None`), so no witness depends on what `record()` happened to freeze.
fn record_applied(path: &std::path::Path, key: &str, action: Action, basis: Option<i64>) {
    let message_ref = match &action {
        Action::Archive { message_ref }
        | Action::Unarchive { message_ref }
        | Action::SetFlag { message_ref, .. }
        | Action::Trash { message_ref }
        | Action::Untrash { message_ref }
        | Action::MarkSpam { message_ref }
        | Action::UnmarkSpam { message_ref } => message_ref.clone(),
    };
    let mut log = SqliteIntentLog::open(path).unwrap();
    let command = Command::new(key.to_string(), "acct".to_string(), Facet::Mail, action);
    log.record(&command, &fixture_basis(&message_ref)).unwrap();
    log.set_status_forced(key, IntentStatus::Applied).unwrap();
    set_basis_ingest_revision(path, key, basis);
}

fn record_applied_trash(path: &std::path::Path, key: &str, message_ref: &str, basis: Option<i64>) {
    record_applied(path, key, Action::Trash { message_ref: message_ref.to_string() }, basis);
}

/// (build item (b)): a `None` basis carries NO freshness claim — the
/// door marks the intent `projected` (it is accounted for; nothing will ever retry it) but never
/// writes the placement/header, because it cannot prove the effect is still the newest truth.
#[test]
fn a_null_basis_marks_without_writing() {
    let path = temp_db("projection-door-null-basis");
    drop(SqliteIntentLog::open(&path).unwrap()); // bootstrap the store first
    let refs = seed_inbox(&path, 1);
    let message_ref = refs[0].clone();
    record_applied_trash(&path, "k-null-basis", &message_ref, None);
    assert_eq!(placement_of(&path, &message_ref), "inbox", "precondition: still in the Inbox");

    let mut coordinator = ReadCoordinator::open(&path).unwrap();
    let outcome = coordinator
        .project_applied_intent("k-null-basis")
        .expect("the door itself does not error on a null basis");
    assert_eq!(outcome, ProjectionWrite::SupersededByNewerObservation);

    assert_eq!(placement_of(&path, &message_ref), "inbox", "the null-basis intent never wrote the placement");
    assert_eq!(mailbox_of(&path, &message_ref), "Inbox", "nor the header's mailbox");
    assert_eq!(projected_of(&path, "k-null-basis"), 1, "but it IS marked projected — accounted for, never retried");
}

/// the marker and the
/// placement/header write are ONE transaction — a failure between the placement UPDATE and the
/// header UPDATE (`write_verb_delta_tx`'s own two-row pair) rolls back EVERYTHING this door did,
/// including the `intents.projected` marker, never a half-written state where one lands and not
/// the other.
#[test]
fn the_marker_and_the_placement_write_are_one_transaction() {
    let path = temp_db("projection-door-one-tx");
    drop(SqliteIntentLog::open(&path).unwrap()); // bootstrap the store first
    let refs = seed_inbox(&path, 1);
    let message_ref = refs[0].clone();
    record_applied_trash(&path, "k-one-tx", &message_ref, Some(1));
    assert_eq!(placement_of(&path, &message_ref), "inbox", "precondition: still in the Inbox");
    assert_eq!(projected_of(&path, "k-one-tx"), 0, "precondition: not yet marked");

    // The repo's own failpoint-trigger idiom (`R2_3_WITNESS_WRITE_FAILPOINT`,
    // `read_coordinator.rs`'s own `injected placement/projection write failure` triggers): fail
    // the SECOND of `write_verb_delta_tx`'s two UPDATEs (the header move), which runs AFTER the
    // placement UPDATE already landed inside the SAME transaction as this door's own marker.
    raw(&path)
        .execute_batch(
            "CREATE TRIGGER projection_door_one_tx_failpoint BEFORE UPDATE OF mailbox ON message_header
               BEGIN SELECT RAISE(ABORT, 'failpoint: header write failed'); END;",
        )
        .unwrap();

    let mut coordinator = ReadCoordinator::open(&path).unwrap();
    let err = coordinator
        .project_applied_intent("k-one-tx")
        .expect_err("the injected header-write failure must surface, not be swallowed");
    assert!(format!("{err:?}").contains("failpoint"), "{err:?}");

    // NEITHER half landed: the placement UPDATE that ran BEFORE the failpoint rolled back with
    // the transaction, and the marker (which would have run AFTER, in the same transaction) never
    // committed either.
    assert_eq!(placement_of(&path, &message_ref), "inbox", "the placement half rolled back too");
    assert_eq!(mailbox_of(&path, &message_ref), "Inbox", "the header never moved");
    assert_eq!(projected_of(&path, "k-one-tx"), 0, "the marker did not land on a rolled-back effect");
}

/// (the written arm, witnessed): the ONE path `r5_a_null_basis_marks_
/// without_writing` and `the_marker_and_the_placement_write_are_one_transaction` never exercise
/// on a clean commit — a basis AT the row's actual `ingest_revision` (`current <= b` with equality)
/// writes the placement/header move AND marks the intent, in one successful transaction.
#[test]
fn a_fresh_basis_writes_and_marks() {
    let path = temp_db("projection-door-fresh-basis");
    drop(SqliteIntentLog::open(&path).unwrap()); // bootstrap the store first
    let refs = seed_inbox(&path, 1);
    let message_ref = refs[0].clone();
    record_applied_trash(&path, "k-fresh-basis", &message_ref, None);
    assert_eq!(placement_of(&path, &message_ref), "inbox", "precondition: still in the Inbox");

    let basis = ingest_revision_of(&path, &message_ref);
    set_basis_ingest_revision(&path, "k-fresh-basis", Some(basis));

    let mut coordinator = ReadCoordinator::open(&path).unwrap();
    let outcome = coordinator
        .project_applied_intent("k-fresh-basis")
        .expect("a fresh basis does not error");
    assert_eq!(outcome, ProjectionWrite::Written);

    assert_eq!(placement_of(&path, &message_ref), "trash", "the fresh-basis intent wrote the trash placement");
    assert_ne!(mailbox_of(&path, &message_ref), "Inbox", "and moved the header off the Inbox mailbox");
    assert_eq!(projected_of(&path, "k-fresh-basis"), 1, "and marked the intent projected");
}

/// the complement of the fresh-basis witness above — a basis STRICTLY
/// OLDER than the row's actual `ingest_revision` (the intent was decided against a truth the store
/// has since moved past) is superseded: marked, never written, and the row's placement/mailbox are
/// held exactly where the fresh-basis test found them precondition.
#[test]
fn an_older_basis_is_superseded_and_still_marked() {
    let path = temp_db("projection-door-older-basis");
    drop(SqliteIntentLog::open(&path).unwrap()); // bootstrap the store first
    let refs = seed_inbox(&path, 1);
    let message_ref = refs[0].clone();
    record_applied_trash(&path, "k-older-basis", &message_ref, None);
    assert_eq!(placement_of(&path, &message_ref), "inbox", "precondition: still in the Inbox");

    let actual = ingest_revision_of(&path, &message_ref);
    set_basis_ingest_revision(&path, "k-older-basis", Some(actual - 1));

    let mut coordinator = ReadCoordinator::open(&path).unwrap();
    let outcome = coordinator
        .project_applied_intent("k-older-basis")
        .expect("an older basis does not error, it is superseded");
    assert_eq!(outcome, ProjectionWrite::SupersededByNewerObservation);

    assert_eq!(placement_of(&path, &message_ref), "inbox", "the older-basis intent never wrote the placement");
    assert_eq!(mailbox_of(&path, &message_ref), "Inbox", "nor the header's mailbox");
    assert_eq!(projected_of(&path, "k-older-basis"), 1, "but it IS marked projected — accounted for, never retried");
}

/// (build item (b), THE SIBLING RULE): two intents recorded against the
/// SAME observation (star, then archive — for example: "star-then-archive
/// leaves it starred in Inbox") must BOTH project. Pre-fix (or with the sibling UPDATE reverted),
/// projecting the star first bumps `ingest_revision`, so the archive — recorded against the SAME
/// pre-star revision — reads the row as superseded by an observation that was actually its own
/// sibling's write, and skips: the message stays starred in the Inbox instead of moving to
/// Archive.
#[test]
fn two_siblings_recorded_against_one_observation_both_project() {
    let path = temp_db("projection-door-siblings");
    drop(SqliteIntentLog::open(&path).unwrap()); // bootstrap the store first
    let refs = seed_inbox(&path, 1);
    let message_ref = refs[0].clone();
    let observed = ingest_revision_of(&path, &message_ref);

    record_applied(
        &path,
        "k-sib-star",
        Action::SetFlag { message_ref: message_ref.clone(), flag: MailFlag::Flagged, value: true },
        Some(observed),
    );
    record_applied(&path, "k-sib-archive", Action::Archive { message_ref: message_ref.clone() }, Some(observed));

    let mut coordinator = ReadCoordinator::open(&path).unwrap();
    let star_outcome = coordinator.project_applied_intent("k-sib-star").expect("star projects");
    assert_eq!(star_outcome, ProjectionWrite::Written, "the star half writes");

    let archive_outcome = coordinator.project_applied_intent("k-sib-archive").expect("archive projects");
    assert_eq!(
        archive_outcome,
        ProjectionWrite::Written,
        "the archive sibling must still write even though the star sibling's own write bumped \
         the row's ingest_revision past the basis BOTH intents were recorded against"
    );

    assert_eq!(placement_of(&path, &message_ref), "archive", "archived");
    assert_eq!(flagged_of(&path, &message_ref), 1, "still starred — the archive did not clobber the star");
    assert_eq!(projected_of(&path, "k-sib-star"), 1);
    assert_eq!(projected_of(&path, "k-sib-archive"), 1);
}

/// an intent UNDONE between the shell's
/// enumeration and this door's own transaction must not be written, and must not be marked —
/// `NotApplicable`, placement/header untouched, `projected` still 0 (so a later, correct sweep can
/// still account for it if the store ever needs to).
#[test]
fn an_intent_undone_before_projection_is_not_written_and_not_marked() {
    let path = temp_db("projection-door-undone");
    drop(SqliteIntentLog::open(&path).unwrap()); // bootstrap the store first
    let refs = seed_inbox(&path, 1);
    let message_ref = refs[0].clone();
    let observed = ingest_revision_of(&path, &message_ref);
    record_applied_trash(&path, "k-undone", &message_ref, Some(observed));

    // The shell's enumeration already named this key `Applied` and unprojected; before the door's
    // own transaction runs, the operation is undone through the store (`set_status_forced` is the
    // fixture door for exactly this: "a starting world", not a decision against a stale read).
    let mut log = SqliteIntentLog::open(&path).unwrap();
    log.set_status_forced("k-undone", IntentStatus::Undone).unwrap();
    drop(log);
    assert_eq!(status_of(&path, "k-undone"), "undone", "precondition: undone before projection ran");
    assert_eq!(placement_of(&path, &message_ref), "inbox", "precondition: still in the Inbox");

    let mut coordinator = ReadCoordinator::open(&path).unwrap();
    let outcome = coordinator
        .project_applied_intent("k-undone")
        .expect("the door itself does not error on an undone intent");
    match outcome {
        ProjectionWrite::NotApplicable { reason } => {
            assert!(reason.contains("k-undone"), "{reason}");
        }
        other => panic!("an undone intent must never write — RED at the pin: {other:?}"),
    }

    assert_eq!(placement_of(&path, &message_ref), "inbox", "the undone intent never wrote the placement");
    assert_eq!(mailbox_of(&path, &message_ref), "Inbox", "nor the header's mailbox");
    assert_eq!(projected_of(&path, "k-undone"), 0, "never marked — it was never applicable to begin with");
}

/// (build item (a); doc corrected): the marker UPDATE must
/// affect EXACTLY one row or the whole transaction fails. NOT a race witness: the door runs under
/// `BEGIN IMMEDIATE`, so no second connection can flip the row between the precondition SELECT
/// and the marker UPDATE. The count check is a SECOND LINE, reachable only from a statement
/// INSIDE the door's own transaction — here a trigger on the header write flips the row's status,
/// so the marker's `WHERE status = 'applied' AND projected = 0 AND compensates IS NULL` finds zero
/// rows and `refuse_unprojected` must refuse rather than silently accept a no-op UPDATE. (Its
/// mutant form, run in the fold: remove the SELECT's status gate and an `undone` intent
/// reaches the write and then fails the transaction on this same count check.)
#[test]
fn the_marker_must_affect_exactly_one_row() {
    let path = temp_db("projection-door-marker-exactly-one");
    drop(SqliteIntentLog::open(&path).unwrap()); // bootstrap the store first
    let refs = seed_inbox(&path, 1);
    let message_ref = refs[0].clone();
    let observed = ingest_revision_of(&path, &message_ref);
    record_applied_trash(&path, "k-marker-race", &message_ref, Some(observed));

    // The failpoint fires AFTER the placement/header write already landed inside the door's own
    // transaction (the header UPDATE this door's `write_verb_delta_tx` issues) but BEFORE the
    // marker UPDATE would run: flip the row out from under the marker's own WHERE clause.
    raw(&path)
        .execute_batch(
            "CREATE TRIGGER projection_door_marker_race BEFORE UPDATE OF mailbox ON message_header
               BEGIN
                 UPDATE intents SET status = 'undone' WHERE idempotency_key = 'k-marker-race';
               END;",
        )
        .unwrap();

    let mut coordinator = ReadCoordinator::open(&path).unwrap();
    let err = coordinator
        .project_applied_intent("k-marker-race")
        .expect_err("a marker UPDATE that affects zero rows must fail the transaction, not be silently accepted");
    assert!(format!("{err:?}").contains("expected exactly 1"), "{err:?}");

    // The whole transaction rolled back — the trigger's own status flip is a statement INSIDE
    // the SAME transaction as the write and the marker, so rollback undoes all three together:
    // the placement/header write, the marker's own (never-committed) attempt, AND the race that
    // caused it.
    assert_eq!(placement_of(&path, &message_ref), "inbox", "the write rolled back with the failed marker");
    assert_eq!(status_of(&path, "k-marker-race"), "applied", "the racing status flip rolled back too");
    assert_eq!(projected_of(&path, "k-marker-race"), 0, "never marked — the transaction never committed");
}

fn seen_of(path: &std::path::Path, message_ref: &str) -> i64 {
    raw(path)
        .query_row(
            "SELECT seen FROM message_header WHERE account = 'acct' AND message_ref = ?1;",
            [message_ref],
            |r| r.get(0),
        )
        .unwrap()
}

fn basis_of(path: &std::path::Path, key: &str) -> Option<i64> {
    raw(path)
        .query_row("SELECT basis_ingest_revision FROM intents WHERE idempotency_key = ?1;", [key], |r| r.get(0))
        .unwrap()
}

/// (an executed construction): two intents on the
/// SAME column recorded against ONE observation, projected OUT of seq order. k1 stars (seq 1),
/// k2 unstars (seq 2); both applied, so the provider ends unstarred. `run_verb` projects only its
/// own key and the `Verb(message_ref)` claim serializes `run_verb` against `run_verb` only, so a
/// plan-door leftover k1 can be projected AFTER a later k2. The landed sibling rule moved k1 to
/// k2's post-write revision and then wrote flagged=1 — a false `Current` over a starred row the
/// provider holds unstarred. A same-column sibling is never carried forward: k1 is superseded and
/// the row keeps k2's flagged=0.
#[test]
fn an_earlier_same_column_sibling_projected_after_a_later_one_is_superseded() {
    let path = temp_db("projection-door-same-column-out-of-order");
    drop(SqliteIntentLog::open(&path).unwrap()); // bootstrap the store first
    let refs = seed_inbox(&path, 1);
    let message_ref = refs[0].clone();
    let observed = ingest_revision_of(&path, &message_ref);

    record_applied(
        &path,
        "k-star-on",
        Action::SetFlag { message_ref: message_ref.clone(), flag: MailFlag::Flagged, value: true },
        Some(observed),
    );
    record_applied(
        &path,
        "k-star-off",
        Action::SetFlag { message_ref: message_ref.clone(), flag: MailFlag::Flagged, value: false },
        Some(observed),
    );

    let mut coordinator = ReadCoordinator::open(&path).unwrap();
    assert_eq!(coordinator.project_applied_intent("k-star-off").unwrap(), ProjectionWrite::Written);
    assert_eq!(flagged_of(&path, &message_ref), 0, "the later unstar wrote flagged=0");

    let earlier = coordinator.project_applied_intent("k-star-on").unwrap();
    assert_eq!(
        earlier,
        ProjectionWrite::SupersededByNewerObservation,
        "the earlier star must read the later unstar's write as newer than its own decision"
    );
    assert_eq!(flagged_of(&path, &message_ref), 0, "the row keeps the later unstar — never re-starred");
    assert_eq!(projected_of(&path, "k-star-on"), 1, "accounted for, never retried");
    assert_eq!(
        basis_of(&path, "k-star-on"),
        Some(observed),
        "a same-column sibling is never carried forward past a write it was decided without"
    );
}

/// (an executed construction): two intents on the
/// SAME column (placement) in seq order. k1 Trash (a plan member, applied, not yet projected),
/// then k2 Archive recorded against the SAME observation. Gmail Archive is `removeLabelIds INBOX`
/// only (`crates/aruna/src/gmail.rs`), so the provider keeps TRASH. The landed rule wrote Trash,
/// carried k2 forward and then wrote Archive — both `Current`, the provider has it trashed. A
/// same-column sibling decided before a written projection reads it as newer: k2 is superseded
/// (the shell answers `Stale`) and the row stays Trash.
#[test]
fn a_same_column_sibling_decided_before_a_written_projection_answers_stale() {
    let path = temp_db("projection-door-same-column-in-order");
    drop(SqliteIntentLog::open(&path).unwrap()); // bootstrap the store first
    let refs = seed_inbox(&path, 1);
    let message_ref = refs[0].clone();
    let observed = ingest_revision_of(&path, &message_ref);

    record_applied_trash(&path, "k-trash-first", &message_ref, Some(observed));
    record_applied(&path, "k-archive-second", Action::Archive { message_ref: message_ref.clone() }, Some(observed));

    let mut coordinator = ReadCoordinator::open(&path).unwrap();
    assert_eq!(coordinator.project_applied_intent("k-trash-first").unwrap(), ProjectionWrite::Written);
    assert_eq!(placement_of(&path, &message_ref), "trash");

    let second = coordinator.project_applied_intent("k-archive-second").unwrap();
    assert_eq!(
        second,
        ProjectionWrite::SupersededByNewerObservation,
        "a same-column sibling decided before the trash write was projected must not overwrite it"
    );
    assert_eq!(placement_of(&path, &message_ref), "trash", "the row stays Trash — the provider keeps TRASH");
    assert_eq!(projected_of(&path, "k-archive-second"), 1, "accounted for, never retried");
}

/// (KEEP-GREEN): the sibling rule's surviving half — siblings that
/// write DIFFERENT columns (placement · flagged · seen) recorded against ONE observation all
/// project, in any order. Green before and after the narrowing: the landed rule moved every
/// sibling, the narrowed rule moves every different-column sibling, and these are all
/// different-column.
#[test]
fn a_different_column_sibling_still_projects() {
    let path = temp_db("projection-door-different-column");
    drop(SqliteIntentLog::open(&path).unwrap()); // bootstrap the store first
    let refs = seed_inbox(&path, 1);
    let message_ref = refs[0].clone();
    let observed = ingest_revision_of(&path, &message_ref);

    record_applied(&path, "k-dc-archive", Action::Archive { message_ref: message_ref.clone() }, Some(observed));
    record_applied(
        &path,
        "k-dc-star",
        Action::SetFlag { message_ref: message_ref.clone(), flag: MailFlag::Flagged, value: true },
        Some(observed),
    );
    record_applied(
        &path,
        "k-dc-seen",
        Action::SetFlag { message_ref: message_ref.clone(), flag: MailFlag::Seen, value: true },
        Some(observed),
    );

    let mut coordinator = ReadCoordinator::open(&path).unwrap();
    for key in ["k-dc-archive", "k-dc-seen", "k-dc-star"] {
        assert_eq!(coordinator.project_applied_intent(key).unwrap(), ProjectionWrite::Written, "{key}");
        assert_eq!(projected_of(&path, key), 1, "{key}");
    }
    assert_eq!(placement_of(&path, &message_ref), "archive");
    assert_eq!(flagged_of(&path, &message_ref), 1);
    assert_eq!(seen_of(&path, &message_ref), 1);
}

/// (build item (b), KEEP-GREEN): no header row for the intent's
/// (account, message_ref) ⇒ the write is SKIPPED and the intent is still marked — never
/// `write_verb_delta_tx` against a row that does not exist. Green at the pin and at the landed
/// door alike (the `(Some(b), Some(current))` arm needs a row); pinned so the narrowing cannot
/// regress it.
#[test]
fn no_header_row_is_superseded_and_marked() {
    let path = temp_db("projection-door-no-header-row");
    drop(SqliteIntentLog::open(&path).unwrap()); // bootstrap the store first
    record_applied_trash(&path, "k-no-header", "m-never-ingested", Some(1));

    let mut coordinator = ReadCoordinator::open(&path).unwrap();
    let outcome = coordinator.project_applied_intent("k-no-header").unwrap();
    assert_eq!(outcome, ProjectionWrite::SupersededByNewerObservation);
    assert_eq!(projected_of(&path, "k-no-header"), 1, "marked — accounted for, never retried");
    let header_rows: i64 = raw(&path)
        .query_row("SELECT COUNT(*) FROM message_header WHERE message_ref = 'm-never-ingested';", [], |r| r.get(0))
        .unwrap();
    assert_eq!(header_rows, 0, "no row was conjured");
}

/// (build item (b)): an UNDO key never enters the door. A compensation
/// (`compensates` set) carries its parent's INVERSE action; writing that through the door is the
/// naive inverse `undo`'s own doc forbids (an undo restores the journaled pre-state, never the
/// inverse verb). `NotApplicable`, nothing written, nothing marked.
#[test]
fn an_undo_key_never_enters_the_door() {
    let path = temp_db("projection-door-undo-key");
    drop(SqliteIntentLog::open(&path).unwrap()); // bootstrap the store first
    let refs = seed_inbox(&path, 1);
    let message_ref = refs[0].clone();
    let observed = ingest_revision_of(&path, &message_ref);
    record_applied_trash(&path, "k-undo-child", &message_ref, Some(observed));
    // `Command::compensates` is crate-private; a raw write is this file's fixture door for a
    // column the public surface does not set (the same shape as `set_basis_ingest_revision`).
    raw(&path)
        .execute("UPDATE intents SET compensates = 'k-parent' WHERE idempotency_key = 'k-undo-child';", [])
        .unwrap();

    let mut coordinator = ReadCoordinator::open(&path).unwrap();
    match coordinator.project_applied_intent("k-undo-child").unwrap() {
        ProjectionWrite::NotApplicable { reason } => assert!(reason.contains("k-undo-child"), "{reason}"),
        other => panic!("an undo key must never be projected through the door: {other:?}"),
    }
    assert_eq!(placement_of(&path, &message_ref), "inbox", "the inverse was never written");
    assert_eq!(projected_of(&path, "k-undo-child"), 0, "never marked");
}
