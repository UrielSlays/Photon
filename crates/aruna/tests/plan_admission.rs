//! The plan child and the send-admission law, witnessed on the durable store.
mod common;

use aruna::attempt::MemberDiff;
use aruna::commitment::CommitmentKey;
use aruna::config_knobs::*;
use aruna::episode::*;
use aruna::key_custody::{root_key_verified, InMemoryCustody};
use aruna::plan::*;
use aruna::{Action, CaptureBinding, Claim, Command, CommandBus, Connector, ConnectorError, CountingConnector, ExecuteError, Facet, InMemoryGrantRatchet, IntentLog, IntentStatus, SendAuthOutcome, SqliteIntentLog};
use common::{seed_inbox, temp_db};

/// Drive one child to the send fence through the STORE doors (the bus is D5): record → PREPARE
/// (the capture the state recheck compares over — INBOX set, TRASH clear, which is what a
/// seeded Inbox member froze at mint) → claim. Returns the key and the won attempt.
fn claim_child(log: &mut SqliteIntentLog, plan: &TriagePlan, member: &str) -> (String, String) {
    claim_child_observing(log, plan, member, &[("membership:INBOX", true), ("label:TRASH", false)])
}

/// [`claim_child`] with the capture's atom values named by the caller.
fn claim_child_observing(log: &mut SqliteIntentLog, plan: &TriagePlan, member: &str, atoms: &[(&str, bool)]) -> (String, String) {
    let c = Command::plan_child(plan, member);
    let basis = aruna::test_support::fixture_basis(&c);
    assert_eq!(log.record(&c, &basis).unwrap(), Claim::Inserted);
    let obs = aruna::test_support::fixture_observation_with(&basis, atoms);
    assert_eq!(
        log.prepare(&c.idempotency_key, &aruna::prestate::journal_row_from_observation(&obs, &basis)).unwrap(),
        aruna::prestate::PrepareOutcome::Prepared,
        "the child's capture is written"
    );
    let claimed = log.claim_attempt(&c.idempotency_key, &aruna::test_support::first_claim()).unwrap();
    (c.idempotency_key, aruna::test_support::won_attempt_id(claimed))
}

/// The binding a bus with an admitting ratchet and the account key hands the fence.
fn binding(key: &CommitmentKey) -> PlanBinding {
    PlanBinding::Child { grant: GrantVerdict::Admitted, account_key: key.clone() }
}

/// Mint + approve a Trash plan over the given members under the knobs in force; returns the plan
/// as the store reads it back, and the account key its digests are under.
///
/// Takes the ROOT rather than minting one: `root_key_verified` over a fresh `InMemoryCustody`
/// registers the key's fingerprint on first use, and a SECOND fresh custody on the same store
/// holds no key and is refused (`RegisteredButAbsent`) — so a test obtains the root once.
pub fn approved_plan(log: &mut SqliteIntentLog, root: &CommitmentKey, members: &[String]) -> (TriagePlan, CommitmentKey) {
    let minted = log.mint_plan(root, PlanSpec { member_refs: members.to_vec(), ..PlanSpec::for_test("acct") }).unwrap();
    log.record_approval(root, &minted.plan_id, "clinton", RenderedView::FullList(minted.presentation.clone())).unwrap();
    let plan = log.plan(&minted.plan_id).unwrap().unwrap();
    (plan, aruna::commitment::derive_account_key(root, "acct").unwrap())
}

fn raw(path: &std::path::Path) -> rusqlite::Connection {
    rusqlite::Connection::open(path).unwrap()
}

fn intent_count(path: &std::path::Path) -> i64 {
    raw(path).query_row("SELECT COUNT(*) FROM intents;", [], |r| r.get(0)).unwrap()
}

/// A HAND-BUILT `intents` row (raw SQL — the belt tests' whole point is a row no door wrote).
fn raw_intent(conn: &rusqlite::Connection, key: &str, plan_id: Option<&str>, member: Option<&str>) -> rusqlite::Result<usize> {
    conn.execute(
        "INSERT INTO intents (idempotency_key, account, facet, action_kind, message_ref, status, seq,
                              intent_id, kind, journal_required, capture_mode_generation,
                              admitted_control_epoch, plan_id, plan_member)
         VALUES (?1, 'acct', 'mail', 'trash', COALESCE(?3, 'x'), 'pending',
                 (SELECT COALESCE(MAX(seq), 0) + 1 FROM intents), lower(hex(randomblob(16))),
                 'forward', 1, 1, 1, ?2, ?3);",
        rusqlite::params![key, plan_id, member],
    )
}

#[test]
fn a_plan_child_command_is_keyed_deterministically_and_the_row_carries_the_link() {
    let path = temp_db("child-key");
    let mut log = SqliteIntentLog::open(&path).unwrap();
    let refs = seed_inbox(&path, 2);
    log.record_knob_act(KnobAct::Backups(BackupsKnob::Off)).unwrap();
    let root = root_key_verified(&InMemoryCustody::new(), &mut log).unwrap();
    let (plan, _) = approved_plan(&mut log, &root, &refs);
    let c1 = Command::plan_child(&plan, &refs[0]);
    let c2 = Command::plan_child(&plan, &refs[0]);
    assert_eq!(c1, c2, "same (plan, member) ⇒ same command, same key");
    assert_eq!(c1.idempotency_key, aruna::derive_idempotency_key("acct", &Facet::Mail, &plan_child_logical_id(&plan.plan_id, &refs[0])));
    assert_ne!(Command::plan_child(&plan, &refs[1]).idempotency_key, c1.idempotency_key, "another member ⇒ another key");
    assert_eq!(c1.account, "acct");
    assert_eq!(c1.action, Action::Trash { message_ref: refs[0].clone() });
    assert_eq!(c1.plan_child_link().unwrap(), &PlanChildLink { plan_id: plan.plan_id.clone(), member_ref: refs[0].clone() });
    // An ordinary command carries no link.
    assert_eq!(Command::new("k", "acct", Facet::Mail, Action::Trash { message_ref: refs[0].clone() }).plan_child_link(), None);
    // A recorded child persists the link and reads back with it.
    log.start_episode(&plan.plan_id).unwrap();
    log.mark_ready(&plan.plan_id).unwrap();
    let basis = aruna::test_support::fixture_basis(&c1);
    assert_eq!(log.record(&c1, &basis).unwrap(), Claim::Inserted);
    let row = log.get(&c1.idempotency_key).unwrap().unwrap();
    assert_eq!(row.command.plan_child_link(), c1.plan_child_link());
    assert_eq!(row.command, c1);
    // The member's second child cannot exist: same key ⇒ AlreadyExisted …
    assert_eq!(log.record(&c1, &basis).unwrap(), Claim::AlreadyExisted);
    // … and the SAME key carrying no link is a different command — the rewrite refusal.
    let unlinked = Command::new(c1.idempotency_key.clone(), "acct", Facet::Mail, c1.action.clone());
    assert!(log.record(&unlinked, &basis).is_err(), "a link-less command under a child's key is a key rewrite");
    let conn = raw(&path);
    let n: i64 = conn.query_row("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_intents_plan_child'", [], |r| r.get(0)).unwrap();
    assert_eq!(n, 1);
    let (p, m): (String, String) = conn.query_row("SELECT plan_id, plan_member FROM intents WHERE idempotency_key = ?1", [&c1.idempotency_key], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
    assert_eq!((p.as_str(), m.as_str()), (plan.plan_id.0.as_str(), refs[0].as_str()));
}

#[test]
fn the_partial_unique_belt_refuses_a_second_row_for_one_member_and_the_check_refuses_half_a_link() {
    let path = temp_db("child-belt");
    let mut log = SqliteIntentLog::open(&path).unwrap();
    let refs = seed_inbox(&path, 1);
    let root = root_key_verified(&InMemoryCustody::new(), &mut log).unwrap();
    let (plan, _) = approved_plan(&mut log, &root, &refs);
    log.start_episode(&plan.plan_id).unwrap();
    log.mark_ready(&plan.plan_id).unwrap();
    let c = Command::plan_child(&plan, &refs[0]);
    assert_eq!(log.record(&c, &aruna::test_support::fixture_basis(&c)).unwrap(), Claim::Inserted);
    let conn = raw(&path);
    // A hand-built row for the SAME (plan, member) under ANOTHER key: the partial UNIQUE index.
    let second = raw_intent(&conn, "hand-built", Some(&plan.plan_id.0), Some(&refs[0]));
    assert!(format!("{second:?}").contains("UNIQUE"), "the belt refuses a second child row for one member, got {second:?}");
    // Half a link, either half: the column CHECK.
    for (k, p, m) in [("half-1", Some(plan.plan_id.0.as_str()), None), ("half-2", None, Some(refs[0].as_str()))] {
        let half = raw_intent(&conn, k, p, m);
        assert!(format!("{half:?}").contains("CHECK"), "half a plan link is refused by the table, got {half:?}");
    }
    // Rows with NO link are outside the partial index: any number of them coexist.
    raw_intent(&conn, "plain-1", None, None).unwrap();
    raw_intent(&conn, "plain-2", None, None).unwrap();
}

#[test]
fn record_refuses_a_plan_child_by_name_and_writes_nothing() {
    let path = temp_db("child-refuse");
    let mut log = SqliteIntentLog::open(&path).unwrap();
    let refs = seed_inbox(&path, 2);
    let root = root_key_verified(&InMemoryCustody::new(), &mut log).unwrap();
    // Minted but never approved.
    let unapproved = log.mint_plan(&root, PlanSpec { member_refs: vec![refs[0].clone()], ..PlanSpec::for_test("acct") }).unwrap();
    let unapproved = log.plan(&unapproved.plan_id).unwrap().unwrap();
    let (plan, _) = approved_plan(&mut log, &root, &refs[..1]);
    let refused = |log: &mut SqliteIntentLog, c: &Command| -> PlanChildRefusal {
        match log.record(c, &aruna::test_support::fixture_basis(c)).unwrap() {
            Claim::PlanChildRefused(r) => {
                assert!(log.get(&c.idempotency_key).unwrap().is_none(), "nothing durable was written for {r:?}");
                r
            }
            other => panic!("expected a named refusal, got {other:?}"),
        }
    };
    let c = Command::plan_child(&plan, &refs[0]);
    // A link on a verb that needs no plan.
    let mut yellow = c.clone();
    yellow.action = Action::Archive { message_ref: refs[0].clone() };
    assert_eq!(refused(&mut log, &yellow), PlanChildRefusal::NotARedVerb);
    // No such plan.
    let mut ghost = plan.clone();
    ghost.plan_id = PlanId("0".repeat(32));
    assert_eq!(refused(&mut log, &Command::plan_child(&ghost, &refs[0])), PlanChildRefusal::NoPlan);
    // The plan's account, verb and derived key — each hand-built mismatch refuses by name.
    let mut other_account = c.clone();
    other_account.account = "other".into();
    assert_eq!(refused(&mut log, &other_account), PlanChildRefusal::AccountMismatch);
    let mut other_verb = c.clone();
    other_verb.action = Action::MarkSpam { message_ref: refs[0].clone() };
    assert_eq!(refused(&mut log, &other_verb), PlanChildRefusal::VerbMismatch);
    let mut other_key = c.clone();
    other_key.idempotency_key = "hand-built-key".into();
    assert_eq!(refused(&mut log, &other_key), PlanChildRefusal::KeyMismatch);
    // Not approved.
    assert_eq!(refused(&mut log, &Command::plan_child(&unapproved, &refs[0])), PlanChildRefusal::NotApproved);
    // Approved, but no episode; then an episode that preflight never marked ready.
    assert_eq!(refused(&mut log, &c), PlanChildRefusal::NoEpisode);
    log.start_episode(&plan.plan_id).unwrap();
    assert_eq!(refused(&mut log, &c), PlanChildRefusal::NotReady);
    log.mark_ready(&plan.plan_id).unwrap();
    // Not a member of the (approved, ready) plan.
    assert_eq!(refused(&mut log, &Command::plan_child(&plan, &refs[1])), PlanChildRefusal::NotAMember(refs[1].clone()));
    // A sever moved the control epoch past the plan's.
    log.sever("authority:test", "2026-09-24T00:00:00Z").unwrap();
    assert_eq!(refused(&mut log, &c), PlanChildRefusal::EpochMismatch { plan: 1, current: 2 });
    // An episode no longer active refuses by its token.
    log.invalidate_episode(&plan.plan_id, InvalidationReason::EpochMismatch { plan: 1, current: 2 }).unwrap();
    assert_eq!(refused(&mut log, &c), PlanChildRefusal::EpisodeNotActive(EpisodeStatusToken::Invalidated));
    // Expired on the sticky clock: a plan minted under the new epoch, and the latch set to
    // EXACTLY its expiry — `expires_at <= effective_now` is expired, AT the instant …
    let later = log.mint_plan(&root, PlanSpec { member_refs: vec![refs[0].clone()], ttl_seconds: 3600, ..PlanSpec::for_test("acct") }).unwrap();
    log.record_approval(&root, &later.plan_id, "clinton", RenderedView::FullList(later.presentation.clone())).unwrap();
    let later = log.plan(&later.plan_id).unwrap().unwrap();
    log.start_episode(&later.plan_id).unwrap();
    log.mark_ready(&later.plan_id).unwrap();
    aruna::test_support::latch_time_high_water(&path, &later.expires_at);
    assert_eq!(
        refused(&mut log, &Command::plan_child(&later, &refs[0])),
        PlanChildRefusal::Expired { expires_at: later.expires_at.clone(), effective_now: later.expires_at.clone() }
    );
    // … and past it.
    aruna::test_support::latch_time_high_water(&path, "2099-01-01T00:00:00Z");
    assert_eq!(
        refused(&mut log, &Command::plan_child(&later, &refs[0])),
        PlanChildRefusal::Expired { expires_at: later.expires_at.clone(), effective_now: "2099-01-01T00:00:00Z".into() }
    );
    assert_eq!(intent_count(&path), 0, "no refusal wrote an intents row");
}

#[test]
fn record_refuses_a_plan_child_by_name_before_anything_durable_when_the_plan_is_not_ready() {
    let path = temp_db("child-not-ready");
    let mut log = SqliteIntentLog::open(&path).unwrap();
    let refs = seed_inbox(&path, 2);
    log.record_knob_act(KnobAct::Backups(BackupsKnob::Off)).unwrap();
    let root = root_key_verified(&InMemoryCustody::new(), &mut log).unwrap();
    let (plan, _) = approved_plan(&mut log, &root, &refs[..1]);
    let c = Command::plan_child(&plan, &refs[0]);
    let basis = aruna::test_support::fixture_basis(&c);
    // No episode yet.
    assert_eq!(log.record(&c, &basis).unwrap(), Claim::PlanChildRefused(PlanChildRefusal::NoEpisode));
    log.start_episode(&plan.plan_id).unwrap();
    // Episode active but preflight never marked ready.
    assert_eq!(log.record(&c, &basis).unwrap(), Claim::PlanChildRefused(PlanChildRefusal::NotReady));
    assert!(log.get(&c.idempotency_key).unwrap().is_none(), "nothing durable was written");
    // Not a member.
    log.mark_ready(&plan.plan_id).unwrap();
    let mut foreign = Command::plan_child(&plan, &refs[1]);
    assert_eq!(log.record(&foreign, &aruna::test_support::fixture_basis(&foreign)).unwrap(), Claim::PlanChildRefused(PlanChildRefusal::NotAMember(refs[1].clone())));
    // Verb mismatch: a child whose action is not the plan's verb (hand-built) refuses.
    foreign = c.clone();
    foreign.action = Action::MarkSpam { message_ref: refs[0].clone() };
    assert_eq!(log.record(&foreign, &aruna::test_support::fixture_basis(&foreign)).unwrap(), Claim::PlanChildRefused(PlanChildRefusal::VerbMismatch));
    // …and the ready child admits.
    assert_eq!(log.record(&c, &basis).unwrap(), Claim::Inserted);
}

#[test]
fn an_episode_starts_once_per_plan_marks_ready_under_zero_dispatch_and_reads_back() {
    let path = temp_db("episode");
    let mut log = SqliteIntentLog::open(&path).unwrap();
    let refs = seed_inbox(&path, 1);
    log.record_knob_act(KnobAct::Backups(BackupsKnob::Off)).unwrap();
    let root = root_key_verified(&InMemoryCustody::new(), &mut log).unwrap();
    let (plan, _) = approved_plan(&mut log, &root, &refs);
    assert_eq!(log.episode_status_check(&plan.plan_id).unwrap(), None);
    assert_eq!(log.episode(&plan.plan_id).unwrap(), None);
    assert_eq!(log.mark_ready(&plan.plan_id).unwrap_err(), EpisodeRefusal::NoEpisode);
    let started = log.start_episode(&plan.plan_id).unwrap();
    assert!(matches!(started, EpisodeStart::Started(ref e) if e.status == EpisodeStatus::Active && e.generation == 1 && e.ready_at.is_none()));
    let EpisodeStart::Started(first) = started else { unreachable!() };
    assert_eq!(first.claim_epoch, log.control_epoch().unwrap());
    assert_eq!(first.plan_id, plan.plan_id);
    assert_eq!(first.episode_id.len(), 32, "an opaque 128-bit id, lowercase hex");
    assert!(matches!(log.start_episode(&plan.plan_id).unwrap(), EpisodeStart::Resumed(ref e) if e.generation == 1 && e.episode_id == first.episode_id), "a second start RESUMES the same uncompleted episode");
    assert_eq!(log.mark_ready(&plan.plan_id).unwrap(), ReadyOutcome::Ready);
    assert_eq!(log.mark_ready(&plan.plan_id).unwrap(), ReadyOutcome::AlreadyReady);
    let e = log.episode(&plan.plan_id).unwrap().unwrap();
    assert_eq!(e.generation, 2, "every episode write bumps the generation");
    assert!(e.ready_at.is_some());
    assert_eq!(e.episode_id, first.episode_id);
    assert_eq!(log.episode_status_check(&plan.plan_id).unwrap(), Some(EpisodeStatusToken::Active));
    // The journal holds every write in order.
    let conn = raw(&path);
    let rows: Vec<(i64, String, String)> = conn
        .prepare("SELECT generation, status, event FROM episode_journal WHERE plan_id = ?1 ORDER BY generation")
        .unwrap()
        .query_map([&plan.plan_id.0], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    assert_eq!(rows, vec![(1, "active".to_string(), "start".to_string()), (2, "active".to_string(), "ready".to_string())]);
    assert!(conn.execute("DELETE FROM episode_journal", []).is_err(), "append-only");
    assert!(conn.execute("UPDATE episode_journal SET event = 'start'", []).is_err(), "append-only");
    assert!(conn.execute("INSERT OR REPLACE INTO episode_journal (plan_id, generation, status, event, at) VALUES (?1, 1, 'active', 'start', 'x')", [&plan.plan_id.0]).is_err(), "no replace");
    // One episode per plan, EVER: the head's primary key.
    assert!(conn.execute("INSERT INTO execution_episode (plan_id, episode_id, status, generation, claim_epoch, started_at, updated_at) VALUES (?1, 'e2', 'active', 1, 1, 'x', 'x')", [&plan.plan_id.0]).is_err());
}

#[test]
fn an_unapproved_or_expired_or_epoch_moved_plan_cannot_start_an_episode() {
    let path = temp_db("episode-refuse");
    let mut log = SqliteIntentLog::open(&path).unwrap();
    let refs = seed_inbox(&path, 1);
    let root = root_key_verified(&InMemoryCustody::new(), &mut log).unwrap();
    assert_eq!(log.start_episode(&PlanId("0".repeat(32))).unwrap_err(), EpisodeRefusal::NoPlan);
    let minted = log.mint_plan(&root, PlanSpec { member_refs: refs.clone(), ..PlanSpec::for_test("acct") }).unwrap();
    assert_eq!(log.start_episode(&minted.plan_id).unwrap_err(), EpisodeRefusal::NotApproved);
    // Approved, then a sever moves the epoch ⇒ the unminted remainder is invalid: start refuses.
    log.record_approval(&root, &minted.plan_id, "clinton", RenderedView::FullList(minted.presentation.clone())).unwrap();
    log.sever("authority:test", "2026-09-24T00:00:00Z").unwrap();
    assert_eq!(log.start_episode(&minted.plan_id).unwrap_err(), EpisodeRefusal::EpochMismatch { plan: 1, current: 2 });
    // Expired (ttl 1s, and the sticky latch pushed past it): refuses even after a wall-clock rollback.
    let short = log.mint_plan(&root, PlanSpec { member_refs: refs.clone(), ttl_seconds: 1, ..PlanSpec::for_test("acct") }).unwrap();
    log.record_approval(&root, &short.plan_id, "clinton", RenderedView::FullList(short.presentation.clone())).unwrap();
    aruna::test_support::latch_time_high_water(&path, "2099-01-01T00:00:00Z");
    assert!(matches!(log.start_episode(&short.plan_id).unwrap_err(), EpisodeRefusal::Expired { ref effective_now, .. } if effective_now == "2099-01-01T00:00:00Z"));
    // Nothing was started by any refusal.
    for id in [&minted.plan_id, &short.plan_id] {
        assert_eq!(log.episode(id).unwrap(), None);
    }
    let journal: i64 = raw(&path).query_row("SELECT COUNT(*) FROM episode_journal", [], |r| r.get(0)).unwrap();
    assert_eq!(journal, 0);
}

#[test]
fn completed_is_a_transactional_exact_n_predicate_and_expiry_is_the_abandonment_bound() {
    let path = temp_db("exact-n");
    let mut log = SqliteIntentLog::open(&path).unwrap();
    let refs = seed_inbox(&path, 2);
    log.record_knob_act(KnobAct::Backups(BackupsKnob::Off)).unwrap();
    let root = root_key_verified(&InMemoryCustody::new(), &mut log).unwrap();
    let (plan, _) = approved_plan(&mut log, &root, &refs);
    assert_eq!(log.complete_episode_if_done(&plan.plan_id).unwrap(), Completion::NoEpisode);
    log.start_episode(&plan.plan_id).unwrap();
    log.mark_ready(&plan.plan_id).unwrap();
    assert_eq!(log.complete_episode_if_done(&plan.plan_id).unwrap(), Completion::Incomplete { total: 2, minted: 0, terminal: 0 });
    for m in &refs {
        let c = Command::plan_child(&plan, m);
        assert_eq!(log.record(&c, &aruna::test_support::fixture_basis(&c)).unwrap(), Claim::Inserted);
    }
    assert_eq!(log.complete_episode_if_done(&plan.plan_id).unwrap(), Completion::Incomplete { total: 2, minted: 2, terminal: 0 });
    // Terminalize ONE child: still incomplete — every member must hold a TERMINAL child.
    let first = Command::plan_child(&plan, &refs[0]).idempotency_key;
    assert_eq!(log.set_status_if(&first, aruna::StatusPrecondition::NonTerminal, IntentStatus::Applied).unwrap(), aruna::StatusWrite::Written);
    assert_eq!(log.complete_episode_if_done(&plan.plan_id).unwrap(), Completion::Incomplete { total: 2, minted: 2, terminal: 1 });
    // Terminalize the other through the store's own status door (fixture shape).
    let second = Command::plan_child(&plan, &refs[1]).idempotency_key;
    assert_eq!(log.set_status_if(&second, aruna::StatusPrecondition::NonTerminal, IntentStatus::Failed).unwrap(), aruna::StatusWrite::Written);
    assert_eq!(log.complete_episode_if_done(&plan.plan_id).unwrap(), Completion::Completed);
    let done = log.episode(&plan.plan_id).unwrap().unwrap();
    assert_eq!(done.status, EpisodeStatus::Completed);
    assert!(done.completed_at.is_some());
    assert_eq!(done.generation, 3);
    assert_eq!(log.complete_episode_if_done(&plan.plan_id).unwrap(), Completion::AlreadyTerminal(EpisodeStatusToken::Completed));
    // A completed plan never starts a second episode.
    assert_eq!(log.start_episode(&plan.plan_id).unwrap_err(), EpisodeRefusal::Terminal(EpisodeStatusToken::Completed));
    // Abandonment: a second plan left with an unminted member past expiry lands invalidated{expired}.
    let p2 = log.mint_plan(&root, PlanSpec { member_refs: vec![refs[0].clone()], ttl_seconds: 3600, ..PlanSpec::for_test("acct") }).unwrap();
    log.record_approval(&root, &p2.plan_id, "clinton", RenderedView::FullList(p2.presentation.clone())).unwrap();
    log.start_episode(&p2.plan_id).unwrap();
    assert_eq!(log.complete_episode_if_done(&p2.plan_id).unwrap(), Completion::Incomplete { total: 1, minted: 0, terminal: 0 }, "before expiry, work outstanding is only incomplete");
    aruna::test_support::latch_time_high_water(&path, "2099-01-01T00:00:00Z");
    assert_eq!(log.complete_episode_if_done(&p2.plan_id).unwrap(), Completion::Invalidated(InvalidationReason::Expired));
    assert_eq!(log.episode(&p2.plan_id).unwrap().unwrap().status, EpisodeStatus::Invalidated(InvalidationReason::Expired));
    assert_eq!(log.episode_status_check(&p2.plan_id).unwrap(), Some(EpisodeStatusToken::Invalidated));
    assert_eq!(log.complete_episode_if_done(&p2.plan_id).unwrap(), Completion::AlreadyTerminal(EpisodeStatusToken::Invalidated));
}

#[test]
fn the_ready_barrier_and_a_stale_preflight_invalidation_refuse_once_a_child_is_send_authorized() {
    let path = temp_db("barrier");
    let mut log = SqliteIntentLog::open(&path).unwrap();
    let refs = seed_inbox(&path, 2);
    log.record_knob_act(KnobAct::Backups(BackupsKnob::Off)).unwrap();
    let root = root_key_verified(&InMemoryCustody::new(), &mut log).unwrap();
    let (plan, key) = approved_plan(&mut log, &root, &refs);
    log.start_episode(&plan.plan_id).unwrap();
    log.mark_ready(&plan.plan_id).unwrap();
    // One child admitted, captured, claimed and SEND-AUTHORIZED through the store's own doors
    // (since D4 the fence runs the plan law, so the child carries a capture and a Child binding).
    let (k, attempt_id) = claim_child(&mut log, &plan, &refs[0]);
    assert!(matches!(log.authorize_send(&k, &attempt_id, CaptureBinding::Generation(1), binding(&key)).unwrap(), SendAuthOutcome::Authorized { .. }));
    let stale = InvalidationReason::StalePreflight { diverged: vec![(refs[1].clone(), vec![MemberDiff { atom: "membership:INBOX".into(), expected: true, observed: Some(false) }])] };
    // A wholesale (preflight) invalidation after dispatch began is refused — the phase boundary.
    assert_eq!(log.invalidate_episode(&plan.plan_id, stale.clone()).unwrap_err(), EpisodeRefusal::DispatchBegan { send_authorized_children: 1 });
    let head = log.episode(&plan.plan_id).unwrap().unwrap();
    assert_eq!((head.status.clone(), head.generation), (EpisodeStatus::Active, 2), "the refusal wrote nothing");
    // The ready marker cleared BY HAND (no door clears it): the barrier refuses to set it again.
    raw(&path).execute("UPDATE execution_episode SET ready_at = NULL WHERE plan_id = ?1", [&plan.plan_id.0]).unwrap();
    assert_eq!(log.mark_ready(&plan.plan_id).unwrap_err(), EpisodeRefusal::DispatchBegan { send_authorized_children: 1 });
    assert_eq!(log.episode(&plan.plan_id).unwrap().unwrap().ready_at, None);
    // Every other reason applies whenever the transition is legal …
    log.invalidate_episode(&plan.plan_id, InvalidationReason::Expired).unwrap();
    let head = log.episode(&plan.plan_id).unwrap().unwrap();
    assert_eq!((head.status, head.generation), (EpisodeStatus::Invalidated(InvalidationReason::Expired), 3));
    // … and a terminal episode has no legal edge left.
    assert_eq!(log.invalidate_episode(&plan.plan_id, InvalidationReason::Expired).unwrap_err(), EpisodeRefusal::IllegalTransition { from: EpisodeStatusToken::Invalidated, to: EpisodeStatusToken::Invalidated });
    assert_eq!(log.mark_ready(&plan.plan_id).unwrap_err(), EpisodeRefusal::Terminal(EpisodeStatusToken::Invalidated));
    // A second plan with NOTHING dispatched: the stale preflight commits wholesale, diff and all.
    let (p2, _) = approved_plan(&mut log, &root, &refs[1..]);
    log.start_episode(&p2.plan_id).unwrap();
    log.invalidate_episode(&p2.plan_id, stale.clone()).unwrap();
    assert_eq!(log.episode(&p2.plan_id).unwrap().unwrap().status, EpisodeStatus::Invalidated(stale));
    let journal: Vec<(i64, String, Option<String>, String)> = raw(&path)
        .prepare("SELECT generation, status, reason, event FROM episode_journal WHERE plan_id = ?1 ORDER BY generation")
        .unwrap()
        .query_map([&p2.plan_id.0], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    assert_eq!(journal.len(), 2);
    assert_eq!((journal[1].0, journal[1].1.as_str(), journal[1].3.as_str()), (2, "invalidated", "transition"));
    assert!(journal[1].2.as_deref().is_some_and(|r| r.contains("stale_preflight")), "the journal row carries the typed reason");
}


// ── (D4): THE SEND-ADMISSION LAW inside `authorize_send` ──────────────────────

#[test]
fn the_binding_is_total_a_plain_binding_on_a_child_row_and_a_child_binding_on_a_plain_row_both_fail_loud() {
    let path = temp_db("binding-total");
    let mut log = SqliteIntentLog::open(&path).unwrap();
    let refs = seed_inbox(&path, 2);
    log.record_knob_act(KnobAct::Backups(BackupsKnob::Off)).unwrap();
    let root = root_key_verified(&InMemoryCustody::new(), &mut log).unwrap();
    let (plan, key) = approved_plan(&mut log, &root, &refs[..1]);
    log.start_episode(&plan.plan_id).unwrap();
    log.mark_ready(&plan.plan_id).unwrap();
    let (k, a) = claim_child(&mut log, &plan, &refs[0]);
    assert!(log.authorize_send(&k, &a, CaptureBinding::Generation(1), PlanBinding::Plain).is_err(), "a plan child under a Plain binding is a caller bug — LogError");
    assert_eq!(log.get(&k).unwrap().unwrap().status, IntentStatus::Pending, "the mismatch wrote nothing");
    assert_eq!(log.plan_refusal(&k).unwrap(), None);
    assert!(matches!(log.authorize_send(&k, &a, CaptureBinding::Generation(1), binding(&key)).unwrap(), SendAuthOutcome::Authorized { .. }), "the attempt is still the caller's to authorize under the right binding");
    let ordinary = Command::new("k-plain", "acct", Facet::Mail, Action::Archive { message_ref: refs[1].clone() });
    assert_eq!(log.record(&ordinary, &aruna::test_support::fixture_basis(&ordinary)).unwrap(), Claim::Inserted);
    let a2 = aruna::test_support::won_attempt_id(log.claim_attempt("k-plain", &aruna::test_support::first_claim()).unwrap());
    assert!(log.authorize_send("k-plain", &a2, CaptureBinding::NoJournalRow, binding(&key)).is_err(), "an ordinary operation under a Child binding is a caller bug — LogError");
    assert!(matches!(log.authorize_send("k-plain", &a2, CaptureBinding::NoJournalRow, PlanBinding::Plain).unwrap(), SendAuthOutcome::Authorized { .. }));
}

#[test]
fn a_child_that_satisfies_every_row_is_authorized_and_a_bypass_lane_plan_admits_with_no_approver_row() {
    let path = temp_db("admit");
    let mut log = SqliteIntentLog::open(&path).unwrap();
    let refs = seed_inbox(&path, 3);
    log.record_knob_act(KnobAct::Backups(BackupsKnob::Off)).unwrap();
    let root = root_key_verified(&InMemoryCustody::new(), &mut log).unwrap();
    let (plan, key) = approved_plan(&mut log, &root, &refs[..1]);
    log.start_episode(&plan.plan_id).unwrap();
    log.mark_ready(&plan.plan_id).unwrap();
    let (k, a) = claim_child(&mut log, &plan, &refs[0]);
    assert!(matches!(log.authorize_send(&k, &a, CaptureBinding::Generation(1), binding(&key)).unwrap(), SendAuthOutcome::Authorized { .. }));
    // Bypass lane: knob ON at mint ⇒ the mechanical Bypassed evidence admits.
    log.record_knob_act(KnobAct::RedBypass(RedBypassKnob::On)).unwrap();
    let minted = log.mint_plan(&root, PlanSpec { member_refs: vec![refs[1].clone()], ..PlanSpec::for_test("acct") }).unwrap();
    assert!(matches!(minted.admission_lane, AdmissionLane::Bypassed { .. }));
    let ev = log.record_approval(&root, &minted.plan_id, "mechanical", RenderedView::FullList(minted.presentation.clone())).unwrap();
    assert!(matches!(ev.comprehension, Comprehension::Bypassed { .. }));
    let plan2 = log.plan(&minted.plan_id).unwrap().unwrap();
    log.start_episode(&plan2.plan_id).unwrap();
    log.mark_ready(&plan2.plan_id).unwrap();
    // Each plan's child is on its own member: the store's head rule (one live operation per
    // resource) would otherwise park the second capture behind the first, still-pending child.
    let (k2, a2) = claim_child(&mut log, &plan2, &refs[1]);
    assert!(matches!(log.authorize_send(&k2, &a2, CaptureBinding::Generation(1), binding(&key)).unwrap(), SendAuthOutcome::Authorized { .. }));
    // Bypass toggled OFF after mint ⇒ the bound generation diverges ⇒ terminal refusal.
    let minted3 = log.mint_plan(&root, PlanSpec { member_refs: vec![refs[2].clone()], ..PlanSpec::for_test("acct") }).unwrap();
    log.record_approval(&root, &minted3.plan_id, "mechanical", RenderedView::FullList(minted3.presentation.clone())).unwrap();
    let plan3 = log.plan(&minted3.plan_id).unwrap().unwrap();
    let AdmissionLane::Bypassed { bypass_config_generation: frozen } = plan3.admission_lane else { unreachable!("minted under bypass ON") };
    log.start_episode(&plan3.plan_id).unwrap();
    log.mark_ready(&plan3.plan_id).unwrap();
    let (k3, a3) = claim_child(&mut log, &plan3, &refs[2]);
    log.record_knob_act(KnobAct::RedBypass(RedBypassKnob::Off)).unwrap();
    let current = log.knob_state().unwrap().red_bypass.generation;
    assert_eq!(
        log.authorize_send(&k3, &a3, CaptureBinding::Generation(1), binding(&key)).unwrap(),
        SendAuthOutcome::PlanRefused(PlanSendRefusal::EvidenceInvalid(PlanRefusal::BypassGenerationMismatch { plan: frozen, current }))
    );
    assert_eq!(log.get(&k3).unwrap().unwrap().status, IntentStatus::Failed);
    let rec = log.plan_refusal(&k3).unwrap().unwrap();
    assert_eq!(rec.reason, "evidence_invalid");
    assert_eq!(rec.member_ref, refs[2]);
    assert_eq!(
        PlanSendRefusal::from_record(&rec).unwrap(),
        PlanSendRefusal::EvidenceInvalid(PlanRefusal::BypassGenerationMismatch { plan: frozen, current }),
        "the record rebuilds the refusal the fence answered"
    );
}

#[test]
fn the_terminal_refusals_each_write_failed_pre_send_with_the_named_record_and_the_held_ones_write_nothing() {
    // One store, one plan per row of the table; each child driven to the fence, then the row's
    // condition is created, then the fence is asked.
    let path = temp_db("rows");
    let mut log = SqliteIntentLog::open(&path).unwrap();
    let refs = seed_inbox(&path, 4);
    let (m1, m2, m3, m4) = (&refs[0], &refs[1], &refs[2], &refs[3]);
    log.record_knob_act(KnobAct::Backups(BackupsKnob::Off)).unwrap();
    let root = root_key_verified(&InMemoryCustody::new(), &mut log).unwrap();
    let (plan, key) = approved_plan(&mut log, &root, &refs);
    log.start_episode(&plan.plan_id).unwrap();
    log.mark_ready(&plan.plan_id).unwrap();
    // COVERAGE: a backups act after mint diverges the generation ⇒ terminal.
    let (k1, a1) = claim_child(&mut log, &plan, m1);
    log.record_knob_act(KnobAct::Backups(BackupsKnob::On)).unwrap();
    log.record_knob_act(KnobAct::Backups(BackupsKnob::Off)).unwrap(); // the ABA round trip — still diverged
    assert!(matches!(log.authorize_send(&k1, &a1, CaptureBinding::Generation(1), binding(&key)).unwrap(), SendAuthOutcome::PlanRefused(PlanSendRefusal::CoverageDiverged { .. })));
    assert_eq!(log.get(&k1).unwrap().unwrap().status, IntentStatus::Failed);
    assert_eq!(log.plan_refusal(&k1).unwrap().unwrap().reason, "coverage_diverged");
    // GRANT: the ratchet's verdict is the bus's; the store honours a Refused verdict terminally.
    let (plan_b, key_b) = approved_plan(&mut log, &root, &refs[1..2]);
    log.start_episode(&plan_b.plan_id).unwrap();
    log.mark_ready(&plan_b.plan_id).unwrap();
    let (k2, a2) = claim_child(&mut log, &plan_b, m2);
    let refused = PlanBinding::Child { grant: GrantVerdict::Refused(GrantDenial::Retired { generation: 1, high_water: 2 }), account_key: key_b.clone() };
    assert_eq!(
        log.authorize_send(&k2, &a2, CaptureBinding::Generation(1), refused).unwrap(),
        SendAuthOutcome::PlanRefused(PlanSendRefusal::GrantRetired(GrantDenial::Retired { generation: 1, high_water: 2 }))
    );
    assert_eq!(log.get(&k2).unwrap().unwrap().status, IntentStatus::Failed);
    assert_eq!(log.plan_refusal(&k2).unwrap().unwrap().reason, "grant_retired");
    // STATE: the capture disagrees with the approval-time state ⇒ STALE_NOT_ATTEMPTED with the diff; the neighbour continues.
    let (plan_c, key_c) = approved_plan(&mut log, &root, &[m3.clone(), m4.clone()]);
    log.start_episode(&plan_c.plan_id).unwrap();
    log.mark_ready(&plan_c.plan_id).unwrap();
    let (k3, a3) = claim_child_observing(&mut log, &plan_c, m3, &[("membership:INBOX", false), ("label:TRASH", false)]); // archived since approval
    match log.authorize_send(&k3, &a3, CaptureBinding::Generation(1), binding(&key_c)).unwrap() {
        SendAuthOutcome::PlanRefused(PlanSendRefusal::StateDiverged { diff }) => {
            assert_eq!(diff, vec![MemberDiff { atom: "membership:INBOX".into(), expected: true, observed: Some(false) }]);
        }
        other => panic!("{other:?}"),
    }
    let rec = log.plan_refusal(&k3).unwrap().unwrap();
    assert_eq!(rec.reason, "state_diverged");
    assert_eq!(&rec.member_ref, m3);
    assert_eq!(rec.diff, vec![MemberDiff { atom: "membership:INBOX".into(), expected: true, observed: Some(false) }]);
    assert_eq!(log.get(&k3).unwrap().unwrap().status, IntentStatus::Failed);
    let reason: String = rusqlite::Connection::open(&path)
        .unwrap()
        .query_row(
            "SELECT json_extract(f.payload, '$.reason') FROM attempt_fact f JOIN intents i ON i.intent_id = f.operation_id WHERE i.idempotency_key = ?1 AND f.fact_kind = 'failed_pre_send'",
            [&k3],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(reason, "stale_not_attempted", "a diverged state is the STALE_NOT_ATTEMPTED terminal");
    let (k4, a4) = claim_child(&mut log, &plan_c, m4);
    assert!(matches!(log.authorize_send(&k4, &a4, CaptureBinding::Generation(1), binding(&key_c)).unwrap(), SendAuthOutcome::Authorized { .. }), "a drifted neighbour does not un-approve m4");
    // EPISODE CLOSED (cancelled ⇒ terminal) and HELD (paused ⇒ nothing written).
    // (paused is unreachable in through a door; the fixture door sets it to prove the arm)
    let (plan_d, key_d) = approved_plan(&mut log, &root, &refs[..1]);
    log.start_episode(&plan_d.plan_id).unwrap();
    log.mark_ready(&plan_d.plan_id).unwrap();
    let (k5, a5) = claim_child(&mut log, &plan_d, m1);
    aruna::test_support::set_episode_status_for_test(&path, &plan_d.plan_id, "paused", Some(r#"{"kind":"operator"}"#));
    assert_eq!(log.authorize_send(&k5, &a5, CaptureBinding::Generation(1), binding(&key_d)).unwrap(), SendAuthOutcome::PlanRefused(PlanSendRefusal::EpisodeHeld(EpisodeStatusToken::Paused)));
    assert_eq!(log.get(&k5).unwrap().unwrap().status, IntentStatus::Pending, "held: nothing written");
    assert_eq!(log.plan_refusal(&k5).unwrap(), None, "held: no terminal fact");
    aruna::test_support::set_episode_status_for_test(&path, &plan_d.plan_id, "cancelled", None);
    assert_eq!(log.authorize_send(&k5, &a5, CaptureBinding::Generation(1), binding(&key_d)).unwrap(), SendAuthOutcome::PlanRefused(PlanSendRefusal::EpisodeClosed(EpisodeStatusToken::Cancelled)));
    assert_eq!(log.get(&k5).unwrap().unwrap().status, IntentStatus::Failed);
    assert_eq!(log.plan_refusal(&k5).unwrap().unwrap().reason, "episode_closed");
}

#[test]
fn snapshot_absent_refuses_by_name_under_backups_on_and_expiry_survives_a_clock_rollback() {
    let path = temp_db("snapshot-expiry");
    let mut log = SqliteIntentLog::open(&path).unwrap();
    let refs = seed_inbox(&path, 3);
    let root = root_key_verified(&InMemoryCustody::new(), &mut log).unwrap();
    // backups ON (the default): has no snapshot machinery ⇒ SnapshotAbsent, terminal, named.
    let (plan, key) = approved_plan(&mut log, &root, &refs[..1]);
    assert!(plan.backups_on);
    log.start_episode(&plan.plan_id).unwrap();
    log.mark_ready(&plan.plan_id).unwrap();
    let (k, a) = claim_child(&mut log, &plan, &refs[0]);
    assert_eq!(log.authorize_send(&k, &a, CaptureBinding::Generation(1), binding(&key)).unwrap(), SendAuthOutcome::PlanRefused(PlanSendRefusal::SnapshotAbsent));
    assert_eq!(log.plan_refusal(&k).unwrap().unwrap().reason, "snapshot_absent");
    assert_eq!(log.get(&k).unwrap().unwrap().status, IntentStatus::Failed);
    // EXPIRY on the sticky clock: latch forward past expires_at, then "roll the wall clock back"
    // (the latch is what the fence reads) ⇒ still expired.
    log.record_knob_act(KnobAct::Backups(BackupsKnob::Off)).unwrap();
    let (plan2, key2) = approved_plan(&mut log, &root, &refs[1..2]);
    log.start_episode(&plan2.plan_id).unwrap();
    log.mark_ready(&plan2.plan_id).unwrap();
    let (k2, a2) = claim_child(&mut log, &plan2, &refs[1]);
    aruna::test_support::latch_time_high_water(&path, "2099-01-01T00:00:00Z");
    assert!(matches!(log.authorize_send(&k2, &a2, CaptureBinding::Generation(1), binding(&key2)).unwrap(), SendAuthOutcome::PlanRefused(PlanSendRefusal::Expired { .. })));
    assert_eq!(log.get(&k2).unwrap().unwrap().status, IntentStatus::Failed);
    assert_eq!(log.episode(&plan2.plan_id).unwrap().unwrap().status, EpisodeStatus::Invalidated(InvalidationReason::Expired));
    // AN ALREADY-AUTHORIZED attempt re-entering the fence (a second writer holding the same won
    // claim) is refused by the law but gets NO proven-no-wire terminal: it may be on the wire.
    // The EXP-3 arm's rule, copied. (plan3 is minted at the latched 2099 instant; its hour runs
    // from there.)
    let (plan3, key3) = approved_plan(&mut log, &root, &refs[2..]);
    log.start_episode(&plan3.plan_id).unwrap();
    log.mark_ready(&plan3.plan_id).unwrap();
    let (k3, a3) = claim_child(&mut log, &plan3, &refs[2]);
    assert!(matches!(log.authorize_send(&k3, &a3, CaptureBinding::Generation(1), binding(&key3)).unwrap(), SendAuthOutcome::Authorized { .. }));
    aruna::test_support::latch_time_high_water(&path, "2100-01-01T00:00:00Z");
    assert!(matches!(log.authorize_send(&k3, &a3, CaptureBinding::Generation(1), binding(&key3)).unwrap(), SendAuthOutcome::PlanRefused(PlanSendRefusal::Expired { .. })));
    assert_eq!(log.get(&k3).unwrap().unwrap().status, IntentStatus::Pending, "an authorized attempt is never closed proven-no-wire");
    assert_eq!(log.plan_refusal(&k3).unwrap(), None);
    assert_eq!(log.episode(&plan3.plan_id).unwrap().unwrap().status, EpisodeStatus::Active, "nothing written on that arm");
}

// ── (D5): the bus over the durable store ────────────────────────────────────

#[test]
fn a_bus_over_the_durable_store_runs_a_plan_end_to_end_and_every_member_reads_applied() {
    // start → preflight → apply each member → settle == Completed → every member Applied, with
    // the crate's fixture connector answering the approval-time state (INBOX set, TRASH clear)
    // and `backups: off` in force at mint.
    let path = temp_db("bus-run");
    let mut log = SqliteIntentLog::open(&path).unwrap();
    let refs = seed_inbox(&path, 2);
    log.record_knob_act(KnobAct::Backups(BackupsKnob::Off)).unwrap();
    let root = root_key_verified(&InMemoryCustody::new(), &mut log).unwrap();
    let (plan, _) = approved_plan(&mut log, &root, &refs);
    let mut bus = CommandBus::new(log, CountingConnector::observing(&[("membership:INBOX", true), ("label:TRASH", false)]))
        .with_grant_ratchet(Box::new(InMemoryGrantRatchet { high_water: Some(1), principal: "me@e".into() }))
        .with_root_key(root.clone());
    assert!(matches!(bus.log_mut().start_episode(&plan.plan_id).unwrap(), EpisodeStart::Started(_)));
    assert_eq!(bus.preflight_plan(&plan.plan_id).unwrap(), PreflightOutcome::Ready);
    for m in &refs {
        bus.apply_plan_member(&plan.plan_id, m).unwrap();
    }
    assert_eq!(bus.connector().apply_count(), 2, "one dispatch per member");
    assert_eq!(bus.settle_plan_progress(&plan.plan_id).unwrap(), Completion::Completed);
    assert_eq!(bus.log().episode(&plan.plan_id).unwrap().unwrap().status, EpisodeStatus::Completed);
    assert_eq!(bus.plan_member_states(&plan.plan_id).unwrap(), plan.members.iter().map(|m| (m.message_ref.clone(), MemberState::Applied)).collect::<Vec<_>>(), "in the plan's member order");
    // A bare RED verb is refused at the bus's one admission door, before anything durable.
    let bare = Command::new("k-bare", "acct", Facet::Mail, Action::Trash { message_ref: refs[0].clone() });
    assert_eq!(bus.execute(&bare).unwrap_err(), ExecuteError::PlanRequired);
    assert!(bus.log().get("k-bare").unwrap().is_none());
}

// ── The two-writer race and the crash truth table on the durable store ─

/// Design v7 §3 Staleness, gate: "two drivers race preflight-vs-first-dispatch in both
/// orders; no RED effect ever lands in a run whose preflight refused." Two connections on one
/// store; the store doors are the actors (the bus adds nothing to the race). Order A: the
/// invalidation lands first ⇒ the child's fence refuses `EpisodeClosed(Invalidated)`. Order B:
/// the child's `SEND_AUTHORIZED` lands first ⇒ the invalidation refuses `DispatchBegan`. NEVER
/// both. The order is forced by a barrier and a 150 ms head start; each door is ONE immediate
/// transaction, so the second one reads what the first committed.
#[test]
fn two_drivers_race_preflight_refusal_against_first_dispatch_in_both_orders_and_never_both_win() {
    for first in ["invalidate", "dispatch"] {
        let path = temp_db(&format!("race-{first}"));
        let mut log = SqliteIntentLog::open(&path).unwrap();
        let refs = seed_inbox(&path, 1);
        log.record_knob_act(KnobAct::Backups(BackupsKnob::Off)).unwrap();
        let root = root_key_verified(&InMemoryCustody::new(), &mut log).unwrap();
        let (plan, key) = approved_plan(&mut log, &root, &refs);
        log.start_episode(&plan.plan_id).unwrap();
        log.mark_ready(&plan.plan_id).unwrap(); // writer 1's preflight passed…
        let (k, a) = claim_child(&mut log, &plan, &refs[0]);
        drop(log);
        let stale = InvalidationReason::StalePreflight {
            diverged: vec![(refs[0].clone(), vec![MemberDiff { atom: "membership:INBOX".into(), expected: true, observed: Some(false) }])],
        };
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let (p1, p2) = (path.to_path_buf(), path.to_path_buf());
        let pid = plan.plan_id.clone();
        let (b1, b2) = (barrier.clone(), barrier.clone());
        let inv = std::thread::spawn(move || {
            let mut l = SqliteIntentLog::open(&p1).unwrap();
            b1.wait();
            if first == "dispatch" {
                std::thread::sleep(std::time::Duration::from_millis(150));
            }
            l.invalidate_episode(&pid, stale)
        });
        let disp = std::thread::spawn(move || {
            let mut l = SqliteIntentLog::open(&p2).unwrap();
            b2.wait();
            if first == "invalidate" {
                std::thread::sleep(std::time::Duration::from_millis(150));
            }
            l.authorize_send(&k, &a, CaptureBinding::Generation(1), PlanBinding::Child { grant: GrantVerdict::Admitted, account_key: key })
        });
        let inv_result = inv.join().unwrap();
        let disp_result = disp.join().unwrap().unwrap();
        let authorized = matches!(disp_result, SendAuthOutcome::Authorized { .. });
        let invalidated = inv_result.is_ok();
        assert!(authorized != invalidated, "order {first}: exactly one wins — authorized={authorized} invalidated={invalidated} ({inv_result:?} / {disp_result:?})");
        if invalidated {
            assert_eq!(first, "invalidate", "the head start decided the order");
            assert_eq!(disp_result, SendAuthOutcome::PlanRefused(PlanSendRefusal::EpisodeClosed(EpisodeStatusToken::Invalidated)));
        } else {
            assert_eq!(first, "dispatch", "the head start decided the order");
            assert_eq!(inv_result.unwrap_err(), EpisodeRefusal::DispatchBegan { send_authorized_children: 1 });
        }
    }
}

/// v3 §3's crash truth table, the reachable row this witness pins: a member whose child was
/// recorded before a "crash" is never re-minted under a fresh key — the resumed episode is the
/// SAME episode, the same `(plan, member)` answers the same key (`AlreadyExisted`), and exactly
/// one `intents` row carries the plan.
#[test]
fn a_member_with_a_child_is_never_re_minted_under_a_fresh_key_across_a_resume() {
    let path = temp_db("resume");
    let mut log = SqliteIntentLog::open(&path).unwrap();
    let refs = seed_inbox(&path, 1);
    log.record_knob_act(KnobAct::Backups(BackupsKnob::Off)).unwrap();
    let root = root_key_verified(&InMemoryCustody::new(), &mut log).unwrap();
    let (plan, _) = approved_plan(&mut log, &root, &refs);
    let EpisodeStart::Started(first) = log.start_episode(&plan.plan_id).unwrap() else { panic!("the first start starts") };
    log.mark_ready(&plan.plan_id).unwrap();
    let c = Command::plan_child(&plan, &refs[0]);
    assert_eq!(log.record(&c, &aruna::test_support::fixture_basis(&c)).unwrap(), Claim::Inserted);
    drop(log); // "crash"
    let mut log = SqliteIntentLog::open(&path).unwrap();
    match log.start_episode(&plan.plan_id).unwrap() {
        EpisodeStart::Resumed(e) => assert_eq!(e.episode_id, first.episode_id, "the SAME episode resumes"),
        other => panic!("a start after the crash resumes, got {other:?}"),
    }
    let again = Command::plan_child(&plan, &refs[0]);
    assert_eq!(again.idempotency_key, c.idempotency_key, "the member's key is a function of (plan, member)");
    assert_eq!(log.record(&again, &aruna::test_support::fixture_basis(&again)).unwrap(), Claim::AlreadyExisted);
    let n: i64 = rusqlite::Connection::open(&path).unwrap().query_row("SELECT COUNT(*) FROM intents WHERE plan_id = ?1", [&plan.plan_id.0], |r| r.get(0)).unwrap();
    assert_eq!(n, 1);
    let episodes: i64 = rusqlite::Connection::open(&path).unwrap().query_row("SELECT COUNT(*) FROM execution_episode WHERE plan_id = ?1", [&plan.plan_id.0], |r| r.get(0)).unwrap();
    assert_eq!(episodes, 1);
}

// ── (pin 62cbbd1) ──────────────────────────────────────────────

/// The observation an agreeing provider answers for a Trash member still in the Inbox.
const IN_INBOX: [(&str, bool); 2] = [("membership:INBOX", true), ("label:TRASH", false)];

/// (probe1's shape): a SEVER crossing an ACTIVE episode lands it
/// `invalidated{epoch_mismatch}` — decided before the exact-N branch, so neither (A) a plan whose
/// every child the sever closed reads `completed`, nor (B) a plan with an unminted member stays
/// `active` until expiry. (C) `start_episode`'s resume path invalidates an existing episode on
/// the epoch refusal, and (D) on the expiry refusal, inside its committing transaction.
#[test]
fn f3_a_sever_crossing_an_active_episode_lands_invalidated_epoch_mismatch_on_the_durable_store() {
    let path = temp_db("f3-sever");
    let mut log = SqliteIntentLog::open(&path).unwrap();
    let refs = seed_inbox(&path, 5);
    log.record_knob_act(KnobAct::Backups(BackupsKnob::Off)).unwrap();
    let root = root_key_verified(&InMemoryCustody::new(), &mut log).unwrap();
    let (a, _) = approved_plan(&mut log, &root, &refs[..1]);
    let (b, _) = approved_plan(&mut log, &root, &refs[1..3]);
    let (c, _) = approved_plan(&mut log, &root, &refs[3..4]);
    for p in [&a, &b, &c] {
        log.start_episode(&p.plan_id).unwrap();
        log.mark_ready(&p.plan_id).unwrap();
    }
    let ca = Command::plan_child(&a, &refs[0]);
    assert_eq!(log.record(&ca, &aruna::test_support::fixture_basis(&ca)).unwrap(), Claim::Inserted);
    let cb = Command::plan_child(&b, &refs[1]);
    assert_eq!(log.record(&cb, &aruna::test_support::fixture_basis(&cb)).unwrap(), Claim::Inserted);
    log.sever("authority:test", "2026-09-24T00:00:00Z").unwrap();
    assert_eq!(log.get(&ca.idempotency_key).unwrap().unwrap().status, IntentStatus::Severed, "precondition: the sever closed the pending child");
    let moved = InvalidationReason::EpochMismatch { plan: 1, current: 2 };
    // A: every member holds a terminal (severed) child — the exact-N predicate alone says completed.
    assert_eq!(log.complete_episode_if_done(&a.plan_id).unwrap(), Completion::Invalidated(moved.clone()));
    assert_eq!(log.episode(&a.plan_id).unwrap().unwrap().status, EpisodeStatus::Invalidated(moved.clone()));
    // B: one member unminted, the plan unexpired — the epoch decides, not the expiry bound.
    assert_eq!(log.complete_episode_if_done(&b.plan_id).unwrap(), Completion::Invalidated(moved.clone()));
    assert_eq!(log.episode(&b.plan_id).unwrap().unwrap().status, EpisodeStatus::Invalidated(moved.clone()));
    // C: the resume path refuses by name AND closes the existing episode, journaled.
    assert_eq!(log.start_episode(&c.plan_id).unwrap_err(), EpisodeRefusal::EpochMismatch { plan: 1, current: 2 });
    assert_eq!(log.episode(&c.plan_id).unwrap().unwrap().status, EpisodeStatus::Invalidated(moved.clone()));
    let last: (String, Option<String>) = raw(&path)
        .query_row("SELECT status, reason FROM episode_journal WHERE plan_id = ?1 ORDER BY generation DESC LIMIT 1", [&c.plan_id.0], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap();
    assert_eq!(last.0, "invalidated");
    assert!(last.1.as_deref().is_some_and(|r| r.contains("epoch_mismatch")), "{last:?}");
    // D: the resume path on the expiry refusal (a plan minted under the new epoch).
    let (d, _) = approved_plan(&mut log, &root, &refs[4..]);
    log.start_episode(&d.plan_id).unwrap();
    aruna::test_support::latch_time_high_water(&path, "2099-01-01T00:00:00Z");
    assert!(matches!(log.start_episode(&d.plan_id).unwrap_err(), EpisodeRefusal::Expired { .. }));
    assert_eq!(log.episode(&d.plan_id).unwrap().unwrap().status, EpisodeStatus::Invalidated(InvalidationReason::Expired));
}

/// (probe2 promoted onto the durable store): a `PrincipalMismatch` grant refusal
/// names NO provider principal to the caller or to the ledger — the error's Debug, the raw
/// `FAILED_PRE_SEND` payload and a replay's answer carry no `@`, and the record's `detail` is the
/// bare token.
#[test]
fn f2_a_principal_mismatch_reaches_neither_the_caller_nor_the_ledger_as_an_address() {
    let path = temp_db("f2-principal");
    let mut log = SqliteIntentLog::open(&path).unwrap();
    let refs = seed_inbox(&path, 1);
    log.record_knob_act(KnobAct::Backups(BackupsKnob::Off)).unwrap();
    let root = root_key_verified(&InMemoryCustody::new(), &mut log).unwrap();
    let (plan, _) = approved_plan(&mut log, &root, &refs);
    let mut bus = CommandBus::new(log, CountingConnector::observing(&IN_INBOX))
        .with_grant_ratchet(Box::new(InMemoryGrantRatchet { high_water: Some(1), principal: "other@elsewhere.example".into() }))
        .with_root_key(root.clone());
    bus.log_mut().start_episode(&plan.plan_id).unwrap();
    assert_eq!(bus.preflight_plan(&plan.plan_id).unwrap(), PreflightOutcome::Ready);
    let err = bus.apply_plan_member(&plan.plan_id, &refs[0]).unwrap_err();
    assert!(matches!(err, ExecuteError::PlanRefused { reason: PlanSendRefusal::GrantRetired(_), .. }), "{err:?}");
    assert!(!format!("{err:?}").contains('@'), "the caller is handed no address: {err:?}");
    let key = Command::plan_child(&plan, &refs[0]).idempotency_key;
    let payload: String = raw(&path)
        .query_row(
            "SELECT f.payload FROM attempt_fact f JOIN intents i ON i.intent_id = f.operation_id WHERE i.idempotency_key = ?1 AND f.fact_kind = 'failed_pre_send'",
            [&key],
            |r| r.get(0),
        )
        .unwrap();
    assert!(!payload.contains('@'), "the ledger holds no address: {payload}");
    let detail = bus.log().plan_refusal(&key).unwrap().unwrap().detail.expect("grant_retired carries a detail");
    assert_eq!(serde_json::from_str::<serde_json::Value>(&detail).unwrap(), serde_json::json!({ "kind": "principal_mismatch" }), "{detail}");
    let replay = bus.apply_plan_member(&plan.plan_id, &refs[0]).unwrap_err();
    assert_eq!(replay, err, "a replay reads the identical refusal back from the record");
    assert_eq!(bus.connector().apply_count(), 0);
}

/// `GrantRetired(Unavailable)` is HELD — "the ratchet could not be consulted" is
/// not a verdict about the grant. A bus with NO ratchet leaves the child in flight (nothing
/// terminal written, nothing sent); the same store re-opened on a bus WITH a ratchet applies it.
#[test]
fn f5_a_bus_with_no_grant_ratchet_holds_the_child_in_flight_and_a_bus_with_one_applies_it() {
    let path = temp_db("f5-held");
    let mut log = SqliteIntentLog::open(&path).unwrap();
    let refs = seed_inbox(&path, 1);
    log.record_knob_act(KnobAct::Backups(BackupsKnob::Off)).unwrap();
    let root = root_key_verified(&InMemoryCustody::new(), &mut log).unwrap();
    let (plan, _) = approved_plan(&mut log, &root, &refs);
    let mut bus = CommandBus::new(log, CountingConnector::observing(&IN_INBOX)).with_root_key(root.clone());
    bus.log_mut().start_episode(&plan.plan_id).unwrap();
    assert_eq!(bus.preflight_plan(&plan.plan_id).unwrap(), PreflightOutcome::Ready);
    let key = Command::plan_child(&plan, &refs[0]).idempotency_key;
    assert_eq!(bus.apply_plan_member(&plan.plan_id, &refs[0]).unwrap_err(), ExecuteError::InProgress, "held: in flight, never a terminal refusal");
    assert_eq!(bus.log().get(&key).unwrap().unwrap().status, IntentStatus::Pending);
    assert_eq!(bus.log().plan_refusal(&key).unwrap(), None, "held: no FAILED_PRE_SEND");
    assert_eq!(bus.plan_member_states(&plan.plan_id).unwrap()[0].1, MemberState::InFlight);
    assert_eq!(bus.connector().apply_count(), 0);
    drop(bus);
    let log = SqliteIntentLog::open(&path).unwrap();
    let mut bus = CommandBus::new(log, CountingConnector::observing(&IN_INBOX))
        .with_grant_ratchet(Box::new(InMemoryGrantRatchet { high_water: Some(1), principal: "me@e".into() }))
        .with_root_key(root);
    bus.recover().unwrap();
    assert_eq!(bus.log().get(&key).unwrap().unwrap().status, IntentStatus::Applied, "the held child applies once a ratchet answers");
    assert_eq!(bus.connector().apply_count(), 1);
    assert_eq!(bus.plan_member_states(&plan.plan_id).unwrap()[0].1, MemberState::Applied);
}

/// The fence's expiry row AT the instant — `expires_at <= effective_now` is
/// expired (probe7), terminal, and the episode is invalidated{expired}.
#[test]
fn f6_the_send_fence_at_exactly_expires_at_is_expired() {
    let path = temp_db("f6-expiry-at");
    let mut log = SqliteIntentLog::open(&path).unwrap();
    let refs = seed_inbox(&path, 1);
    log.record_knob_act(KnobAct::Backups(BackupsKnob::Off)).unwrap();
    let root = root_key_verified(&InMemoryCustody::new(), &mut log).unwrap();
    let (plan, key) = approved_plan(&mut log, &root, &refs);
    log.start_episode(&plan.plan_id).unwrap();
    log.mark_ready(&plan.plan_id).unwrap();
    let (k, a) = claim_child(&mut log, &plan, &refs[0]);
    aruna::test_support::latch_time_high_water(&path, &plan.expires_at);
    assert_eq!(
        log.authorize_send(&k, &a, CaptureBinding::Generation(1), binding(&key)).unwrap(),
        SendAuthOutcome::PlanRefused(PlanSendRefusal::Expired { expires_at: plan.expires_at.clone(), effective_now: plan.expires_at.clone() }),
        "AT the instant is expired"
    );
    assert_eq!(log.get(&k).unwrap().unwrap().status, IntentStatus::Failed);
    assert_eq!(log.episode(&plan.plan_id).unwrap().unwrap().status, EpisodeStatus::Invalidated(InvalidationReason::Expired));
}

/// A connector for the preflight edges (probe8's `Hook`): it answers the approval-time state,
/// fails `observe` for one named member (deterministically or transiently), answers another
/// native identity when told to, and may invalidate the plan's episode from a second connection
/// on its first observe — optionally answering a divergence after it.
struct Hook {
    fail_for: Option<(String, bool)>,
    peer_invalidates: Option<(std::path::PathBuf, PlanId, bool)>,
    foreign_identity: bool,
    fired: std::cell::Cell<bool>,
}
impl Hook {
    fn agreeing() -> Self {
        Hook { fail_for: None, peer_invalidates: None, foreign_identity: false, fired: std::cell::Cell::new(false) }
    }
}
impl Connector for Hook {
    fn apply(&self, _: &Command, _: &aruna::prestate::FrozenBasis) -> Result<(), ConnectorError> {
        Ok(())
    }
    fn resolve_basis(&self, c: &Command) -> Result<aruna::prestate::FrozenBasis, aruna::ResolveBasisError> {
        Ok(aruna::test_support::fixture_basis(c))
    }
    fn observe(&self, c: &Command, basis: &aruna::prestate::FrozenBasis) -> Result<aruna::prestate::Observation, ConnectorError> {
        let mut inbox = true;
        if let Some((path, pid, diverge)) = &self.peer_invalidates {
            if !self.fired.replace(true) {
                SqliteIntentLog::open(path).unwrap().invalidate_episode(pid, InvalidationReason::Expired).unwrap();
            }
            inbox = !*diverge;
        }
        if let (Some((member, deterministic)), Action::Trash { message_ref }) = (&self.fail_for, &c.action) {
            if member == message_ref {
                return Err(if *deterministic { ConnectorError::deterministic("gmail: message not found") } else { ConnectorError::transient("gmail: 503") });
            }
        }
        let mut obs = aruna::test_support::fixture_observation_with(basis, &[("membership:INBOX", inbox), ("label:TRASH", false)]);
        if self.foreign_identity {
            obs.native_resource_key = "test:another-identity".into();
        }
        Ok(obs)
    }
    fn restore(&self, _: &Command, _: &aruna::prestate::FrozenBasis, _: &std::collections::BTreeMap<String, bool>) -> Result<(), ConnectorError> {
        Ok(())
    }
}

/// An approved plan over `n` fresh Inbox members with its episode started (not ready), on a
/// fresh store; returns the path's guard (FIRST, so a tuple pattern drops it LAST), the
/// store, the members and the plan.
fn started_plan(tag: &str, n: usize) -> (aruna::test_temp::TempFile, SqliteIntentLog, Vec<String>, TriagePlan) {
    let (path, log, refs, plan, _) = started_plan_keyed(tag, n);
    (path, log, refs, plan)
}

/// [`started_plan`], also answering the plan account's key.
fn started_plan_keyed(tag: &str, n: usize) -> (aruna::test_temp::TempFile, SqliteIntentLog, Vec<String>, TriagePlan, CommitmentKey) {
    let path = temp_db(tag);
    let mut log = SqliteIntentLog::open(&path).unwrap();
    let refs = seed_inbox(&path, n);
    log.record_knob_act(KnobAct::Backups(BackupsKnob::Off)).unwrap();
    let root = root_key_verified(&InMemoryCustody::new(), &mut log).unwrap();
    let (plan, key) = approved_plan(&mut log, &root, &refs);
    log.start_episode(&plan.plan_id).unwrap();
    (path, log, refs, plan, key)
}

/// Preflight handed an observation for ANOTHER native identity refuses as
/// `ensure_prepared` refuses it (BASIS-6, a deterministic basis-rebound error) and writes nothing.
#[test]
fn f6_preflight_given_another_native_identity_refuses_basis_rebound_and_writes_nothing() {
    let (_path, log, _refs, plan) = started_plan("f6-identity", 1);
    let before = log.episode(&plan.plan_id).unwrap().unwrap();
    let mut bus = CommandBus::new(log, Hook { foreign_identity: true, ..Hook::agreeing() });
    match bus.preflight_plan(&plan.plan_id).unwrap_err() {
        ExecuteError::Connector(e) => assert!(e.message.contains("basis rebound"), "{e:?}"),
        other => panic!("expected the basis-rebound connector error, got {other:?}"),
    }
    assert_eq!(bus.log().episode(&plan.plan_id).unwrap().unwrap(), before, "nothing written");
}

/// (b) (probe8a): a DETERMINISTIC `observe` failure for one member is that member's
/// divergence — every atom `observed: None` — and the run is refused wholesale naming it; a
/// TRANSIENT failure stays an error with nothing written.
#[test]
fn f8_a_deterministic_observe_failure_is_a_named_divergence_and_a_transient_one_stays_an_error() {
    let (_path, log, refs, plan) = started_plan("f8-vanished", 2);
    let mut bus = CommandBus::new(log, Hook { fail_for: Some((refs[1].clone(), true)), ..Hook::agreeing() });
    let unobserved = vec![
        MemberDiff { atom: "label:TRASH".into(), expected: false, observed: None },
        MemberDiff { atom: "membership:INBOX".into(), expected: true, observed: None },
    ];
    assert_eq!(bus.preflight_plan(&plan.plan_id).unwrap(), PreflightOutcome::Refused { diverged: vec![(refs[1].clone(), unobserved.clone())] });
    assert_eq!(
        bus.log().episode(&plan.plan_id).unwrap().unwrap().status,
        EpisodeStatus::Invalidated(InvalidationReason::StalePreflight { diverged: vec![(refs[1].clone(), unobserved)] })
    );
    let (_path, log, refs, plan) = started_plan("f8-transient", 2);
    let before = log.episode(&plan.plan_id).unwrap().unwrap();
    let mut bus = CommandBus::new(log, Hook { fail_for: Some((refs[1].clone(), false)), ..Hook::agreeing() });
    assert!(matches!(bus.preflight_plan(&plan.plan_id).unwrap_err(), ExecuteError::Connector(ref e) if e.message.contains("503")));
    assert_eq!(bus.log().episode(&plan.plan_id).unwrap().unwrap(), before, "a transient failure writes nothing");
}

/// THE BYPASS-LANE NOTICE (design v7 §3: "that journaled emission is itself a
/// bypass-lane admission check; the bypass waives the screen, never the notice"). A screen-lane
/// plan never carries one; a bypass plan minted under `backups: off` freezes the verb's warning
/// and admits; a bypass plan whose row carries NO notice — the shape a row minted before the
/// column existed reads back with (the in-version ALTER's NULL) — is refused by name at fence row
/// 6b, terminally; a bypass plan minted under `backups: on` carries none and meets the snapshot
/// row instead.
#[test]
fn f1_a_bypass_plan_under_backups_off_admits_with_its_frozen_notice_and_refuses_by_name_without_one() {
    let path = temp_db("f1-notice");
    let mut log = SqliteIntentLog::open(&path).unwrap();
    let refs = seed_inbox(&path, 4);
    log.record_knob_act(KnobAct::Backups(BackupsKnob::Off)).unwrap();
    let root = root_key_verified(&InMemoryCustody::new(), &mut log).unwrap();
    let key = aruna::commitment::derive_account_key(&root, "acct").unwrap();
    let screen = log.mint_plan(&root, PlanSpec { member_refs: vec![refs[0].clone()], ..PlanSpec::for_test("acct") }).unwrap();
    assert_eq!((screen.admission_lane, screen.bypass_notice.clone()), (AdmissionLane::PerMember, None), "a screen lane never carries a notice");
    assert_eq!(log.plan(&screen.plan_id).unwrap().unwrap().bypass_notice, None);
    log.record_knob_act(KnobAct::RedBypass(RedBypassKnob::On)).unwrap();
    let bypass_plan = |log: &mut SqliteIntentLog, member: &str| -> TriagePlan {
        let minted = log.mint_plan(&root, PlanSpec { member_refs: vec![member.to_string()], ..PlanSpec::for_test("acct") }).unwrap();
        assert!(matches!(minted.admission_lane, AdmissionLane::Bypassed { .. }));
        log.record_approval(&root, &minted.plan_id, "mechanical", RenderedView::FullList(minted.presentation.clone())).unwrap();
        let plan = log.plan(&minted.plan_id).unwrap().unwrap();
        assert_eq!(plan.bypass_notice, minted.bypass_notice, "the mint's answer is the stored row");
        plan
    };
    // Minted normally: the notice is frozen, it is the verb's warning, and the child admits.
    let noticed = bypass_plan(&mut log, &refs[1]);
    assert_eq!(noticed.bypass_notice.as_deref(), Some(TRASH_UNCOVERED_WARNING));
    log.start_episode(&noticed.plan_id).unwrap();
    log.mark_ready(&noticed.plan_id).unwrap();
    let (k1, a1) = claim_child(&mut log, &noticed, &refs[1]);
    assert!(matches!(log.authorize_send(&k1, &a1, CaptureBinding::Generation(1), binding(&key)).unwrap(), SendAuthOutcome::Authorized { .. }));
    // The same plan shape with the column NULL (hand-set — the row an earlier v10 build minted):
    // refused by name at row 6b, terminally, the record naming it.
    let legacy = bypass_plan(&mut log, &refs[2]);
    raw(&path)
        .execute_batch(&format!(
            "DROP TRIGGER triage_plan_no_update; UPDATE triage_plan SET bypass_notice = NULL WHERE plan_id = '{}';",
            legacy.plan_id.0
        ))
        .unwrap();
    assert_eq!(log.plan(&legacy.plan_id).unwrap().unwrap().bypass_notice, None, "precondition: the row carries no notice");
    log.start_episode(&legacy.plan_id).unwrap();
    log.mark_ready(&legacy.plan_id).unwrap();
    let (k2, a2) = claim_child(&mut log, &legacy, &refs[2]);
    assert_eq!(log.authorize_send(&k2, &a2, CaptureBinding::Generation(1), binding(&key)).unwrap(), SendAuthOutcome::PlanRefused(PlanSendRefusal::BypassNoticeAbsent));
    assert_eq!(log.get(&k2).unwrap().unwrap().status, IntentStatus::Failed);
    let rec = log.plan_refusal(&k2).unwrap().unwrap();
    assert_eq!((rec.reason.as_str(), rec.detail.clone()), ("bypass_notice_absent", None));
    assert_eq!(PlanSendRefusal::from_record(&rec).unwrap(), PlanSendRefusal::BypassNoticeAbsent);
    // A bypass plan minted under backups ON: no notice owed (coverage is on), and the snapshot row
    // answers — never row 6b.
    log.record_knob_act(KnobAct::Backups(BackupsKnob::On)).unwrap();
    let covered = bypass_plan(&mut log, &refs[3]);
    assert_eq!(covered.bypass_notice, None);
    log.start_episode(&covered.plan_id).unwrap();
    log.mark_ready(&covered.plan_id).unwrap();
    let (k3, a3) = claim_child(&mut log, &covered, &refs[3]);
    assert_eq!(log.authorize_send(&k3, &a3, CaptureBinding::Generation(1), binding(&key)).unwrap(), SendAuthOutcome::PlanRefused(PlanSendRefusal::SnapshotAbsent));
}

/// at the fence: a `GrantDenial::Unavailable` verdict is HELD — the refusal names it,
/// writes no terminal and no status, and reads no clock (the latch set below every real instant
/// stays exactly where it was); the same attempt, handed an admitting verdict, is authorized.
#[test]
fn f5_a_grant_unavailable_verdict_is_held_at_the_fence_writes_nothing_and_reads_no_clock() {
    let path = temp_db("f5-fence");
    let mut log = SqliteIntentLog::open(&path).unwrap();
    let refs = seed_inbox(&path, 1);
    log.record_knob_act(KnobAct::Backups(BackupsKnob::Off)).unwrap();
    let root = root_key_verified(&InMemoryCustody::new(), &mut log).unwrap();
    let (plan, key) = approved_plan(&mut log, &root, &refs);
    log.start_episode(&plan.plan_id).unwrap();
    log.mark_ready(&plan.plan_id).unwrap();
    let (k, a) = claim_child(&mut log, &plan, &refs[0]);
    aruna::test_support::latch_time_high_water(&path, "2000-01-01T00:00:00Z");
    let unavailable = PlanBinding::Child { grant: GrantVerdict::Refused(GrantDenial::Unavailable), account_key: key.clone() };
    assert_eq!(log.authorize_send(&k, &a, CaptureBinding::Generation(1), unavailable).unwrap(), SendAuthOutcome::PlanRefused(PlanSendRefusal::GrantRetired(GrantDenial::Unavailable)));
    assert_eq!((log.get(&k).unwrap().unwrap().status, log.plan_refusal(&k).unwrap()), (IntentStatus::Pending, None), "held: nothing written");
    let latch: String = raw(&path).query_row("SELECT max_seen FROM time_high_water WHERE id = 1", [], |r| r.get(0)).unwrap();
    assert_eq!(latch, "2000-01-01T00:00:00Z", "held before the clock is read: no latch advance");
    assert_eq!(log.episode(&plan.plan_id).unwrap().unwrap().status, EpisodeStatus::Active);
    assert!(matches!(log.authorize_send(&k, &a, CaptureBinding::Generation(1), binding(&key)).unwrap(), SendAuthOutcome::Authorized { .. }));
}

/// The approval door runs the two checks
/// `start_episode` runs and refuses by name — the latch set to EXACTLY `expires_at` is expired
/// (no approval written, the latch reads `expires_at`), and after a sever the plan's epoch has
/// moved (no approval written). Record honesty, not a control: the fence, `start_episode` and
/// `record()` already refuse both later.
#[test]
fn f7_the_approval_door_refuses_an_expired_or_epoch_moved_plan_by_name() {
    let path = temp_db("f7-approve");
    let mut log = SqliteIntentLog::open(&path).unwrap();
    let refs = seed_inbox(&path, 2);
    let root = root_key_verified(&InMemoryCustody::new(), &mut log).unwrap();
    let minted = log.mint_plan(&root, PlanSpec { member_refs: vec![refs[0].clone()], ..PlanSpec::for_test("acct") }).unwrap();
    let plan = log.plan(&minted.plan_id).unwrap().unwrap();
    aruna::test_support::latch_time_high_water(&path, &plan.expires_at);
    assert_eq!(
        log.record_approval(&root, &minted.plan_id, "clinton", RenderedView::FullList(minted.presentation.clone())).unwrap_err(),
        PlanStoreError::Expired { expires_at: plan.expires_at.clone(), effective_now: plan.expires_at.clone() }
    );
    assert_eq!(log.approval(&minted.plan_id).unwrap(), None);
    let latch: String = raw(&path).query_row("SELECT max_seen FROM time_high_water WHERE id = 1", [], |r| r.get(0)).unwrap();
    assert_eq!(latch, plan.expires_at);
    let second = log.mint_plan(&root, PlanSpec { member_refs: vec![refs[1].clone()], ..PlanSpec::for_test("acct") }).unwrap();
    log.sever("authority:test", "2100-01-01T00:00:00Z").unwrap();
    assert_eq!(
        log.record_approval(&root, &second.plan_id, "clinton", RenderedView::FullList(second.presentation.clone())).unwrap_err(),
        PlanStoreError::EpochMismatch { plan: 1, current: 2 }
    );
    assert_eq!(log.approval(&second.plan_id).unwrap(), None);
}

/// A preflight whose invalidation lost the barrier to a send-authorized child
/// answers `Raced` WITH what it observed — the diverged members and their diffs — as `Refused`
/// carries them; the episode stays active (the per-child recheck owns staleness from here).
#[test]
fn a_raced_preflight_carries_the_divergence_it_observed() {
    let (_path, mut log, refs, plan, key) = started_plan_keyed("r8-raced", 1);
    log.mark_ready(&plan.plan_id).unwrap();
    let (k, a) = claim_child(&mut log, &plan, &refs[0]);
    assert!(matches!(log.authorize_send(&k, &a, CaptureBinding::Generation(1), binding(&key)).unwrap(), SendAuthOutcome::Authorized { .. }));
    let mut bus = CommandBus::new(log, CountingConnector::observing(&[("membership:INBOX", false), ("label:TRASH", false)]));
    assert_eq!(
        bus.preflight_plan(&plan.plan_id).unwrap(),
        PreflightOutcome::Raced { diverged: vec![(refs[0].clone(), vec![MemberDiff { atom: "membership:INBOX".into(), expected: true, observed: Some(false) }])] }
    );
    assert_eq!(bus.log().episode(&plan.plan_id).unwrap().unwrap().status, EpisodeStatus::Active);
}

/// (a) (probe8b): a peer's invalidation landing between preflight's status check and
/// its write is `PlanChildRefused(EpisodeNotActive(invalidated))` — on the ready arm AND on the
/// invalidation arm — never a store error.
#[test]
fn f8_a_peer_invalidation_inside_the_preflight_is_a_named_refusal_on_both_arms() {
    for diverge in [false, true] {
        let (path, log, _refs, plan) = started_plan(&format!("f8-race-{diverge}"), 1);
        let mut bus = CommandBus::new(log, Hook { peer_invalidates: Some((path.to_path_buf(), plan.plan_id.clone(), diverge)), ..Hook::agreeing() });
        assert_eq!(
            bus.preflight_plan(&plan.plan_id).unwrap_err(),
            ExecuteError::PlanChildRefused(PlanChildRefusal::EpisodeNotActive(EpisodeStatusToken::Invalidated)),
            "diverge={diverge}"
        );
        assert_eq!(bus.log().episode(&plan.plan_id).unwrap().unwrap().status, EpisodeStatus::Invalidated(InvalidationReason::Expired), "the peer's write stands");
    }
}

/// (a): the Gmail connector's classification, unmodified — every read and
/// write answers HTTP 401 (`GmailError::Unauthorized`, an access token that aged out) while
/// `expired` is set; otherwise every message reads `{INBOX}`.
struct R1Gmail {
    expired: std::rc::Rc<std::cell::Cell<bool>>,
}

impl aruna::gmail::GmailTransport for R1Gmail {
    fn modify_labels(&self, _: &aruna::gmail::GmailUserId, _: &aruna::gmail::GmailMessageId, _: &aruna::gmail::GmailModifyRequest) -> Result<(), aruna::gmail::GmailError> {
        Err(aruna::gmail::GmailError::Unknown)
    }
    fn modify_labels_observed(&self, _: &aruna::gmail::GmailUserId, _: &aruna::gmail::GmailMessageId, _: &aruna::gmail::GmailModifyRequest) -> Result<std::collections::BTreeSet<String>, aruna::gmail::GmailError> {
        Err(aruna::gmail::GmailError::Unknown)
    }
    fn trash_message(&self, _: &aruna::gmail::GmailUserId, _: &aruna::gmail::GmailMessageId) -> Result<std::collections::BTreeSet<String>, aruna::gmail::GmailError> {
        Err(aruna::gmail::GmailError::Unknown)
    }
    fn untrash_message(&self, _: &aruna::gmail::GmailUserId, _: &aruna::gmail::GmailMessageId) -> Result<std::collections::BTreeSet<String>, aruna::gmail::GmailError> {
        Err(aruna::gmail::GmailError::Unknown)
    }
    fn message_labels(&self, _: &aruna::gmail::GmailUserId, _: &aruna::gmail::GmailMessageId) -> Result<std::collections::BTreeSet<String>, aruna::gmail::GmailError> {
        if self.expired.get() {
            return Err(aruna::gmail::GmailError::Unauthorized);
        }
        Ok(["INBOX".to_string()].into_iter().collect())
    }
}

struct R1Account;
impl aruna::gmail::GmailAccountResolver for R1Account {
    fn resolve_user(&self, _: &str) -> Option<aruna::gmail::GmailUserId> {
        Some(aruna::gmail::GmailUserId("me@e".to_string()))
    }
}

struct R1Messages;
impl aruna::gmail::GmailMessageRefResolver for R1Messages {
    fn resolve_message(&self, _: &str, message_ref: &str) -> Result<Option<aruna::gmail::GmailMessageId>, aruna::LogError> {
        Ok(Some(aruna::gmail::GmailMessageId(format!("G-{message_ref}"))))
    }
}

/// (a) (`reve_q5b`): an AUTH-class observe failure at the preflight — an
/// expired access token, classified by the real Gmail connector — is an ERROR that writes nothing
/// and leaves the episode active, never "this member diverged" (the (b) rule above keeps its
/// shape for every other deterministic failure). Once the credential is fine, the same plan's
/// preflight is ready.
#[test]
fn an_auth_class_observe_failure_at_preflight_is_an_error_and_the_plan_runs_once_the_credential_is_fine() {
    let (_path, log, _refs, plan) = started_plan("r1-f3-auth", 2);
    let before = log.episode(&plan.plan_id).unwrap().unwrap();
    let expired = std::rc::Rc::new(std::cell::Cell::new(true));
    let connector = aruna::gmail::GmailConnector::with_capabilities(
        R1Gmail { expired: std::rc::Rc::clone(&expired) },
        R1Account,
        R1Messages,
        aruna::gmail::CapabilityMap::triage_verbs(),
    );
    let mut bus = CommandBus::new(log, connector);
    match bus.preflight_plan(&plan.plan_id) {
        Err(ExecuteError::Connector(e)) => assert_eq!(e.kind, aruna::FailureKind::Deterministic, "{e:?}"),
        other => panic!("an expired credential at preflight is an error, never a divergence: {other:?}"),
    }
    assert_eq!(
        bus.log().episode(&plan.plan_id).unwrap().unwrap(),
        before,
        "nothing written: the episode is still active, never invalidated"
    );
    expired.set(false);
    assert_eq!(bus.preflight_plan(&plan.plan_id).unwrap(), PreflightOutcome::Ready);
}
