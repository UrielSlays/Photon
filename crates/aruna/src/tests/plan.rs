//! Triage plans: the plan store on the twin, episodes, the send-admission law, and the plan doors.

use super::*;
use crate::fixtures::{fixture_basis, fixture_restore};
use crate::plan_store::{write_episode_in, EpisodeWrite};

// ═══════════════════════════════════════════════════════════════════════════════════════
// The plan store half on the IN-MEMORY TWIN (the durable store's witnesses
// are `tests/plan_witnesses.rs`), the shared sticky clock on both stores, the grant ratchet.
// ═══════════════════════════════════════════════════════════════════════════════════════

/// A twin with two Inbox members `m1` (named sender) and `m2` (bare address), and its root key
/// through the ONE door (`root_key_verified` — the twin IS a key registry).
fn s1_twin_with_two() -> (InMemoryIntentLog, crate::commitment::CommitmentKey) {
    use crate::read_model::Placement;
    let mut twin = InMemoryIntentLog::new();
    twin.seed_header_for_test("acct", "m1", "deals@shop.example", "Deals", "Your order", 1_758_672_000_000);
    twin.seed_placement_for_test("acct", "m1", Placement::Inbox);
    twin.seed_header_for_test("acct", "m2", "news@list.example", "", "Weekly digest", 1_758_585_600_000);
    twin.seed_placement_for_test("acct", "m2", Placement::Inbox);
    let root = crate::key_custody::root_key_verified(&crate::key_custody::InMemoryCustody::new(), &mut twin).unwrap();
    (twin, root)
}

#[test]
fn s1_twin_mint_plan_freezes_members_from_its_mirrors_and_the_knobs_and_reads_back_identically() {
    use crate::plan::*;
    let (mut twin, root) = s1_twin_with_two();
    let spec = PlanSpec { account: "acct".into(), provider_principal: "me@e".into(), grant_generation: 2, verb: PlanVerb::Trash, member_refs: vec!["m2".into(), "m1".into(), "m1".into()], rationale: Some("bulk trash".into()), ttl_seconds: 3600 };
    let minted = twin.mint_plan(&root, spec).unwrap();
    let plan = twin.plan(&minted.plan_id).unwrap().expect("stored");
    assert_eq!(plan.members.iter().map(|m| m.message_ref.as_str()).collect::<Vec<_>>(), vec!["m1", "m2"], "deduplicated and canonical");
    assert!(plan.members[0].observed_state["membership:INBOX"]);
    assert!(!plan.members[0].observed_state["label:TRASH"]);
    // The name half and the address half are frozen SEPARATELY —
    // a named sender's address is bracketed (the old composed spelling, isolated); a nameless
    // one's is bare, matching the inbox row's own convention for a nameless sender.
    assert_eq!(plan.members[0].display.sender, "Deals");
    assert_eq!(plan.members[0].display.sender_address, "<deals@shop.example>");
    assert_eq!(plan.members[1].display.sender, "");
    assert_eq!(plan.members[1].display.sender_address, "news@list.example");
    assert_eq!(plan.members[0].display.date, "2025-09-24T00:00:00Z", "received_at is epoch MILLISECONDS");
    assert_eq!(plan.admission_lane, AdmissionLane::PerMember);
    assert_eq!(plan.approval_mode, ApprovalMode::FullList);
    assert_eq!(plan.coverage_generation, 0);
    assert!(plan.backups_on);
    assert_eq!(plan.grant_generation, 2);
    assert_eq!(plan.control_epoch, 1, "the twin's seeded control epoch");
    assert_eq!(minted.presentation.rows.len(), 2);
    assert_eq!(plan.digests.presentation, minted.presentation_digest);
    assert_eq!(minted.presentation.summary.sender_domains, vec![("list.example".to_string(), 1), ("shop.example".to_string(), 1)], "a named sender counts under its address domain");
    // Unknown member ⇒ refuse at mint, nothing stored — a header without a placement is
    // unknown too (the durable JOIN's answer).
    twin.seed_header_for_test("acct", "m3", "x@y.example", "", "no placement", 1_758_585_600_000);
    for missing in ["nope", "m3"] {
        let bad = PlanSpec { member_refs: vec!["m1".into(), missing.into()], ..PlanSpec::for_test("acct") };
        assert_eq!(twin.mint_plan(&root, bad).unwrap_err(), PlanStoreError::UnknownMember(missing.into()));
    }
    assert_eq!(twin.plans.len(), 1, "the refused mints stored nothing");
    let other_account = PlanSpec { member_refs: vec!["m1".into()], ..PlanSpec::for_test("other") };
    assert_eq!(twin.mint_plan(&root, other_account).unwrap_err(), PlanStoreError::UnknownMember("m1".into()));
    assert_eq!(twin.mint_plan(&root, PlanSpec { member_refs: vec!["m1".into()], ttl_seconds: 0, ..PlanSpec::for_test("acct") }).unwrap_err(), PlanStoreError::TtlZero);
    assert_eq!(twin.mint_plan(&root, PlanSpec::for_test("acct")).unwrap_err(), PlanStoreError::Refused(PlanRefusal::EmptyMembers));
}

#[test]
fn s1_twin_freezes_the_aggregate_lane_the_bypassed_lane_and_an_uncovered_header_from_the_knobs() {
    use crate::config_knobs::*;
    use crate::plan::*;
    let (mut twin, root) = s1_twin_with_two();
    twin.record_knob_act(KnobAct::ApprovalMode(ApprovalModeKnob::SummarySample { configured_k: 5 })).unwrap();
    let minted = twin.mint_plan(&root, PlanSpec { member_refs: vec!["m1".into(), "m2".into()], ..PlanSpec::for_test("acct") }).unwrap();
    let plan = twin.plan(&minted.plan_id).unwrap().unwrap();
    assert_eq!(plan.admission_lane, AdmissionLane::Aggregate);
    assert_eq!(plan.approval_mode, ApprovalMode::SummarySample { configured_k: 5, effective_k: 2 }, "effective_k = min(5, 2)");
    assert_eq!(minted.effective_k, Some(2));
    let g = twin.record_knob_act(KnobAct::RedBypass(RedBypassKnob::On)).unwrap();
    let minted = twin.mint_plan(&root, PlanSpec { member_refs: vec!["m1".into()], ..PlanSpec::for_test("acct") }).unwrap();
    assert_eq!(twin.plan(&minted.plan_id).unwrap().unwrap().admission_lane, AdmissionLane::Bypassed { bypass_config_generation: g });
    let evidence = twin.record_approval(&root, &minted.plan_id, "mechanical", RenderedView::FullList(minted.presentation.clone())).unwrap();
    assert_eq!(evidence.comprehension, Comprehension::Bypassed { bypass_config_generation: g });
    assert_eq!(evidence.view_digest, minted.presentation_digest);
    // A bypass knob flip since mint: the evidence binds the FROZEN
    // generation, which is no longer the one in force — refused by name, nothing written.
    let minted = twin.mint_plan(&root, PlanSpec { member_refs: vec!["m2".into()], ..PlanSpec::for_test("acct") }).unwrap();
    let flipped = twin.record_knob_act(KnobAct::RedBypass(RedBypassKnob::Off)).unwrap();
    assert_eq!(
        twin.record_approval(&root, &minted.plan_id, "mechanical", RenderedView::FullList(minted.presentation.clone())).unwrap_err(),
        PlanStoreError::Refused(PlanRefusal::BypassGenerationMismatch { plan: g, current: flipped })
    );
    assert!(twin.approval(&minted.plan_id).unwrap().is_none());
    let off = twin.record_knob_act(KnobAct::Backups(BackupsKnob::Off)).unwrap();
    let minted = twin.mint_plan(&root, PlanSpec { verb: PlanVerb::MarkSpam, member_refs: vec!["m1".into()], ..PlanSpec::for_test("acct") }).unwrap();
    let plan = twin.plan(&minted.plan_id).unwrap().unwrap();
    assert!(!plan.backups_on);
    assert_eq!(plan.coverage_generation, off);
    assert!(!minted.presentation.header.backup_coverage);
    assert_eq!(minted.presentation.header.warning.as_deref(), Some(MARK_SPAM_UNCOVERED_WARNING));
    // A malformed knob head ⇒ Knob, nothing minted.
    let before = twin.plans.len();
    twin.append_raw_knob_act_for_test(KIND_BACKUPS, r#"{"backups":"maybe"}"#);
    let err = twin.mint_plan(&root, PlanSpec { member_refs: vec!["m1".into()], ..PlanSpec::for_test("acct") }).unwrap_err();
    assert!(matches!(&err, PlanStoreError::Knob(why) if why.contains("maybe")), "{err:?}");
    assert_eq!(twin.plans.len(), before);
}

#[test]
fn s1_twin_record_approval_validates_through_the_pure_core_and_is_write_once() {
    use crate::plan::*;
    let (mut twin, root) = s1_twin_with_two();
    let minted = twin.mint_plan(&root, PlanSpec { member_refs: vec!["m1".into()], ..PlanSpec::for_test("acct") }).unwrap();
    let ok = twin.record_approval(&root, &minted.plan_id, "clinton", RenderedView::FullList(minted.presentation.clone())).unwrap();
    assert_eq!(ok.comprehension, Comprehension::PerMember);
    assert_eq!(twin.approval(&minted.plan_id).unwrap().unwrap().view_digest, minted.presentation_digest);
    assert_eq!(twin.record_approval(&root, &minted.plan_id, "clinton", RenderedView::FullList(minted.presentation.clone())).unwrap_err(), PlanStoreError::AlreadyApproved);
    // Display substitution ⇒ ViewMismatch, nothing written.
    let minted2 = twin.mint_plan(&root, PlanSpec { member_refs: vec!["m2".into()], ..PlanSpec::for_test("acct") }).unwrap();
    let mut forged = minted2.presentation.clone();
    forged.rows[0].subject = "forged".into();
    assert_eq!(twin.record_approval(&root, &minted2.plan_id, "clinton", RenderedView::FullList(forged)).unwrap_err(), PlanStoreError::Refused(PlanRefusal::ViewMismatch));
    assert!(twin.approval(&minted2.plan_id).unwrap().is_none());
    assert_eq!(twin.record_approval(&root, &PlanId("f".repeat(32)), "clinton", RenderedView::FullList(minted2.presentation.clone())).unwrap_err(), PlanStoreError::PlanNotFound(PlanId("f".repeat(32))));
    // Aggregate: the rendered sample must be the DERIVED one.
    let (mut twin, root) = s1_twin_with_two();
    for i in 3..=5 {
        twin.seed_header_for_test("acct", &format!("m{i}"), &format!("s{i}@x.example"), "", "s", 1_758_585_600_000);
        twin.seed_placement_for_test("acct", &format!("m{i}"), crate::read_model::Placement::Inbox);
    }
    twin.record_knob_act(crate::config_knobs::KnobAct::ApprovalMode(crate::config_knobs::ApprovalModeKnob::SummarySample { configured_k: 2 })).unwrap();
    let minted = twin.mint_plan(&root, PlanSpec { member_refs: (1..=5).map(|i| format!("m{i}")).collect(), ..PlanSpec::for_test("acct") }).unwrap();
    let plan = twin.plan(&minted.plan_id).unwrap().unwrap();
    let derived = derive_sample(&crate::commitment::derive_account_key(&root, "acct").unwrap(), &plan.digests, &plan.members, 2).unwrap();
    let render = |sample: &[String]| AggregateRender {
        header: minted.presentation.header.clone(),
        summary: minted.presentation.summary.clone(),
        sample_k: 2,
        sample_rows: sample.iter().map(|r| minted.presentation.rows.iter().find(|row| &row.message_ref == r).unwrap().clone()).collect(),
    };
    let not_derived: Vec<String> = plan.members.iter().map(|m| m.message_ref.clone()).filter(|r| !derived.contains(r)).take(2).collect();
    assert_eq!(twin.record_approval(&root, &minted.plan_id, "clinton", RenderedView::Aggregate(render(&not_derived))).unwrap_err(), PlanStoreError::Refused(PlanRefusal::ViewMismatch));
    let evidence = twin.record_approval(&root, &minted.plan_id, "clinton", RenderedView::Aggregate(render(&derived))).unwrap();
    assert_eq!(evidence.comprehension, Comprehension::Aggregate { shape_digest: plan.digests.shape, sample_k: 2, sample_members: derived });
}

#[test]
fn s1_the_plan_doors_stamp_from_the_shared_sticky_clock_and_never_lower_the_latch_on_both_stores() {
    use crate::plan::*;
    // A latch AHEAD of the wall clock (a rollback happened): minted_at / approved_at take it,
    // expires_at is minted_at + ttl, and the latch is still exactly that value afterwards.
    const AHEAD: &str = "2099-01-01T00:00:00Z";
    let path = unique_temp_db_path("s1-plan-sticky");
    let mut sqlite = SqliteIntentLog::open(&path).unwrap();
    let refs = {
        let mut c = crate::read_coordinator::ReadCoordinator::open(&path).unwrap();
        c.ingest_page("acct", &[crate::read_surface::HeaderSummary {
            provider_id: crate::read_model::ProviderMessageId("P-1".into()),
            received_at: 1_758_672_000_000,
            from_addr: "a@b.example".into(),
            from_name: String::new(),
            subject: "s".into(),
            seen: false,
            flagged: false,
            attachments: crate::read_surface::AttachmentPresence::default(),
        }])
        .unwrap()
    };
    raw_conn(&path)
        .execute("INSERT INTO time_high_water (id, max_seen) VALUES (1, ?1) ON CONFLICT(id) DO UPDATE SET max_seen = excluded.max_seen;", [AHEAD])
        .unwrap();
    let sqlite_root = crate::key_custody::root_key_verified(&crate::key_custody::InMemoryCustody::new(), &mut sqlite).unwrap();
    let (mut twin, twin_root) = s1_twin_with_two();
    twin.time_high_water = AHEAD.to_string();
    let cases: [(&mut dyn IntentLog, &crate::commitment::CommitmentKey, String); 2] = [(&mut sqlite, &sqlite_root, refs[0].clone()), (&mut twin, &twin_root, "m1".to_string())];
    for (log, root, member) in cases {
        let minted = log.mint_plan(root, PlanSpec { member_refs: vec![member.clone()], ttl_seconds: 7200, ..PlanSpec::for_test("acct") }).unwrap();
        let plan = log.plan(&minted.plan_id).unwrap().unwrap();
        assert_eq!(plan.minted_at, AHEAD, "minted_at is the sticky clock's effective now");
        assert_eq!(plan.expires_at, "2099-01-01T02:00:00Z");
        let evidence = log.record_approval(root, &minted.plan_id, "clinton", RenderedView::FullList(minted.presentation.clone())).unwrap();
        assert_eq!(evidence.approved_at, AHEAD, "approved_at is the sticky clock's effective now");
        // A TTL the canonical clock cannot spell refuses by name.
        assert_eq!(log.mint_plan(root, PlanSpec { member_refs: vec![member], ttl_seconds: u64::MAX, ..PlanSpec::for_test("acct") }).unwrap_err(), PlanStoreError::TtlOutOfRange);
    }
    let durable: String = raw_conn(&path).query_row("SELECT max_seen FROM time_high_water WHERE id = 1;", [], |r| r.get(0)).unwrap();
    assert_eq!((durable.as_str(), twin.time_high_water.as_str()), (AHEAD, AHEAD), "the latch never goes down");
    drop(sqlite);
    std::fs::remove_file(&path).ok();
}

#[test]
fn s1_a_corrupt_latch_refuses_the_plan_doors_and_is_never_repaired_on_both_stores() {
    use crate::plan::*;
    let path = unique_temp_db_path("s1-plan-corrupt-latch");
    let mut sqlite = SqliteIntentLog::open(&path).unwrap();
    let refs = {
        let mut c = crate::read_coordinator::ReadCoordinator::open(&path).unwrap();
        c.ingest_page("acct", &[crate::read_surface::HeaderSummary {
            provider_id: crate::read_model::ProviderMessageId("P-1".into()),
            received_at: 1_758_672_000_000,
            from_addr: "a@b.example".into(),
            from_name: String::new(),
            subject: "s".into(),
            seen: false,
            flagged: false,
            attachments: crate::read_surface::AttachmentPresence::default(),
        }])
        .unwrap()
    };
    let sqlite_root = crate::key_custody::root_key_verified(&crate::key_custody::InMemoryCustody::new(), &mut sqlite).unwrap();
    raw_conn(&path)
        .execute("INSERT INTO time_high_water (id, max_seen) VALUES (1, '!') ON CONFLICT(id) DO UPDATE SET max_seen = excluded.max_seen;", [])
        .unwrap();
    let err = sqlite.mint_plan(&sqlite_root, PlanSpec { member_refs: refs.clone(), ..PlanSpec::for_test("acct") }).unwrap_err();
    assert!(matches!(&err, PlanStoreError::Store(why) if why.contains("mint_plan: non-canonical time high-water latch")), "{err:?}");
    let (latch, plans): (String, i64) = raw_conn(&path)
        .query_row("SELECT (SELECT max_seen FROM time_high_water WHERE id = 1), (SELECT COUNT(*) FROM triage_plan);", [], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap();
    assert_eq!((latch.as_str(), plans), ("!", 0), "refused, never repaired, nothing minted");
    let (mut twin, twin_root) = s1_twin_with_two();
    twin.time_high_water = "!".into();
    let err = twin.mint_plan(&twin_root, PlanSpec { member_refs: vec!["m1".into()], ..PlanSpec::for_test("acct") }).unwrap_err();
    assert!(matches!(&err, PlanStoreError::Store(why) if why.contains("mint_plan: non-canonical time high-water latch")), "{err:?}");
    assert_eq!((twin.time_high_water.as_str(), twin.plans.len()), ("!", 0));
    drop(sqlite);
    std::fs::remove_file(&path).ok();
}

#[test]
fn s1_the_observed_state_is_the_local_placement_belief_on_each_closure_atom() {
    use crate::plan::*;
    use crate::read_model::Placement;
    // Each placement asserts at most one closure atom (read off `gmail_atom_targets`): Inbox
    // ⇒ membership:INBOX, Trash ⇒ label:TRASH, Spam ⇒ label:SPAM, Archive ⇒ none.
    let (mut twin, root) = s1_twin_with_two();
    for (r, placement) in [("pi", Placement::Inbox), ("pt", Placement::Trash), ("ps", Placement::Spam), ("pa", Placement::Archive)] {
        twin.seed_header_for_test("acct", r, "a@b.example", "", "s", 1_758_585_600_000);
        twin.seed_placement_for_test("acct", r, placement);
    }
    let refs: Vec<String> = ["pi", "pt", "ps", "pa"].iter().map(|r| r.to_string()).collect();
    let expect = [
        (PlanVerb::Trash, [("pi", true, false), ("pt", false, true), ("ps", false, false), ("pa", false, false)], "label:TRASH"),
        (PlanVerb::MarkSpam, [("pi", true, false), ("pt", false, false), ("ps", false, true), ("pa", false, false)], "label:SPAM"),
    ];
    for (verb, rows, label) in expect {
        let minted = twin.mint_plan(&root, PlanSpec { verb, member_refs: refs.clone(), ..PlanSpec::for_test("acct") }).unwrap();
        let plan = twin.plan(&minted.plan_id).unwrap().unwrap();
        for (r, inbox, labelled) in rows {
            let m = plan.member(r).unwrap();
            assert_eq!(m.observed_state.len(), 2, "{verb:?} {r}: exactly the verb's closure atoms");
            assert_eq!((m.observed_state["membership:INBOX"], m.observed_state[label]), (inbox, labelled), "{verb:?} {r}");
            assert_eq!(m.forward_target, crate::gmail::gmail_atom_targets(&verb.action(r)), "the forward target is the verb's closure");
        }
    }
}

#[test]
fn s1_a_refused_twin_mint_leaves_the_latch_where_it_was() {
    use crate::plan::*;
    // The durable mint's refusals roll the latch advance back with the transaction; the twin
    // puts it back by hand. A refusal AFTER the clock read (here an out-of-range TTL) must
    // leave the latch as it found it.
    let (mut twin, root) = s1_twin_with_two();
    assert_eq!(twin.time_high_water, "");
    assert_eq!(twin.mint_plan(&root, PlanSpec { member_refs: vec!["m1".into()], ttl_seconds: u64::MAX, ..PlanSpec::for_test("acct") }).unwrap_err(), PlanStoreError::TtlOutOfRange);
    assert_eq!(twin.time_high_water, "", "the refused mint did not advance the latch");
}

#[test]
fn s1_the_frozen_warning_column_is_present_exactly_when_backups_are_off() {
    let path = unique_temp_db_path("s1-warning-check");
    drop(SqliteIntentLog::open(&path).unwrap());
    let conn = raw_conn(&path);
    let row = |plan_id: &str, backups_on: i64, warning: &str| format!("INSERT INTO triage_plan (plan_id, account, provider_principal, grant_generation, control_epoch, verb, tier, minted_at, expires_at, member_count, admission_lane, approval_mode, coverage_generation, backups_on, warning, set_digest, set_randomizer, state_digest, state_randomizer, presentation_digest, presentation_randomizer, shape_digest, shape_randomizer, sample_seed, sample_seed_randomizer, aggregate_view_randomizer, key_ref_namespace, key_ref_epoch) VALUES ('{plan_id}','a','pr',1,1,'trash','red','t','t2',1,'per_member','full_list',0,{backups_on},{warning},'s','r','s','r','s','r','s','r','s','r','r','ns',1)");
    assert!(conn.execute_batch(&row("a", 0, "NULL")).is_err(), "backups OFF requires the warning");
    assert!(conn.execute_batch(&row("b", 0, "''")).is_err(), "…and never an empty one");
    assert!(conn.execute_batch(&row("c", 1, "'w'")).is_err(), "backups ON carries no warning");
    conn.execute_batch(&row("d", 0, "'w'")).unwrap();
    conn.execute_batch(&row("e", 1, "NULL")).unwrap();
    drop(conn);
    std::fs::remove_file(&path).ok();
}

#[test]
fn s1_the_grant_ratchet_seam_fails_closed_by_default_and_the_in_memory_ratchet_admits_at_or_above_the_high_water() {
    assert!(matches!(NoGrantRatchet.admits(1, "me@e"), Err(GrantRefusal::Unavailable(_))), "no ratchet is a refusal, never a skipped check");
    let r = InMemoryGrantRatchet { high_water: Some(3), principal: "me@e".into() };
    assert_eq!(r.admits(3, "me@e"), Ok(()), "AT the high-water admits");
    assert_eq!(r.admits(4, "me@e"), Ok(()));
    assert_eq!(r.admits(2, "me@e"), Err(GrantRefusal::Retired { generation: 2, high_water: 3 }));
    assert_eq!(r.admits(3, "other@e"), Err(GrantRefusal::PrincipalMismatch { plan: "other@e".into(), current: "me@e".into() }));
    assert_eq!(InMemoryGrantRatchet { high_water: None, principal: "me@e".into() }.admits(0, "me@e"), Ok(()), "nothing retired yet");
    // The bus: fail-closed until wired; wired, it consults the ratchet it was given.
    let bus = CommandBus::new(InMemoryIntentLog::new(), AlwaysOkConnector);
    assert!(matches!(bus.grant_ratchet().admits(5, "me@e"), Err(GrantRefusal::Unavailable(_))));
    assert!(bus.root_key.is_none(), "no root key until one is wired");
    let bus = bus.with_grant_ratchet(Box::new(r)).with_root_key(crate::commitment::CommitmentKey::from_bytes(&[7u8; 48]).unwrap());
    assert_eq!(bus.grant_ratchet().admits(3, "me@e"), Ok(()));
    assert_eq!(bus.grant_ratchet().admits(2, "me@e"), Err(GrantRefusal::Retired { generation: 2, high_water: 3 }));
    assert!(bus.root_key.is_some());
}

// ---- the plan child on the Command and the intents row ----------

#[test]
fn s1_intent_from_raw_reads_a_whole_plan_link_and_refuses_half_of_one() {
    // The ONE row parser: both link columns ⇒ the link; neither ⇒ none; exactly one ⇒ a
    // `LogError` naming the key (never a silent `None`, never a link with a hole in it).
    let path = unique_temp_db_path("s1-raw-plan-link");
    let mut log = SqliteIntentLog::open(&path).unwrap();
    log.record(&s1_trash_cmd("k-raw", "msg-1"), &crate::prestate::FrozenBasis::for_test_trash()).unwrap();
    let read = || {
        raw_conn(&path)
            .query_row(&format!("SELECT {INTENT_COLUMNS} FROM intents WHERE idempotency_key = 'k-raw';"), [], raw_intent_from_row)
            .unwrap()
    };
    assert_eq!(intent_from_raw(read()).unwrap().command.plan_child, None);
    let mut whole = read();
    whole.plan_id = Some("p-1".into());
    whole.plan_member = Some("msg-1".into());
    assert_eq!(
        intent_from_raw(whole).unwrap().command.plan_child,
        Some(crate::plan::PlanChildLink { plan_id: crate::plan::PlanId("p-1".into()), member_ref: "msg-1".into() })
    );
    for (p, m) in [(Some("p-1"), None), (None, Some("msg-1"))] {
        let mut half = read();
        half.plan_id = p.map(str::to_string);
        half.plan_member = m.map(str::to_string);
        let err = intent_from_raw(half).unwrap_err();
        assert!(err.0.contains("half a plan link") && err.0.contains("k-raw"), "{err:?}");
    }
    std::fs::remove_file(&path).ok();
}

#[test]
fn s1_the_plan_link_columns_and_their_belt_arrive_in_version_on_an_upgraded_store() {
    // `plan_id` / `plan_member` arrive through `IN_VERSION_COLUMN_UPGRADES` (SCHEMA_VERSION
    // stays 10) and the partial UNIQUE index after them: a store an earlier v10 build created
    // without them must come up with the same columns, the same index and the same CHECK a
    // fresh store has.
    let fresh = unique_temp_db_path("s1-plan-link-fresh");
    drop(SqliteIntentLog::open(&fresh).expect("mint the store"));
    let upgraded = unique_temp_db_path("s1-plan-link-upgraded");
    drop(SqliteIntentLog::open(&upgraded).expect("mint the store"));
    // `projected` is a LATER in-version column than `plan_id`/
    // `plan_member` (it sits after them in `IN_VERSION_COLUMN_UPGRADES`), so it is ALSO
    // dropped here — otherwise it would survive the reduction below and re-arrive (via the
    // fixture's OWN first open, not this test's DROP) ahead of the re-added `plan_id`/
    // `plan_member` on re-open, when the fresh store added all three in one pass with
    // `plan_id`/`plan_member` first — a column-ORDER mismatch this test's fingerprint compare
    // would (correctly) catch, but for a reason unrelated to what this test names. 
    // `basis_ingest_revision` is LATER still (the very last entry in the
    // ladder) — same reason, same fix.
    raw_conn(&upgraded)
        .execute_batch(
            "DROP INDEX idx_intents_plan_child;
                 ALTER TABLE intents DROP COLUMN plan_member;
                 ALTER TABLE intents DROP COLUMN plan_id;
                 ALTER TABLE intents DROP COLUMN projected;
                 ALTER TABLE intents DROP COLUMN basis_ingest_revision;",
        )
        .expect("reduce the store to the pre-D2 v10 shape");
    let has = |path: &std::path::Path, column: &str| -> bool {
        raw_conn(path)
            .query_row("SELECT COUNT(*) FROM pragma_table_info('intents') WHERE name = ?1;", [column], |r| r.get::<_, i64>(0))
            .expect("table_info")
            > 0
    };
    assert!(!has(&upgraded, "plan_id"), "precondition: pre-D2 shape");
    drop(SqliteIntentLog::open(&upgraded).expect("open upgrades the table"));
    assert_eq!(schema_fingerprint(&fresh), schema_fingerprint(&upgraded), "the upgraded store is the fresh store's shape");
    for path in [&fresh, &upgraded] {
        assert!(has(path, "plan_id") && has(path, "plan_member"), "{path:?}");
        let (unique, partial): (i64, i64) = raw_conn(path)
            .query_row(r#"SELECT "unique", partial FROM pragma_index_list('intents') WHERE name = 'idx_intents_plan_child';"#, [], |r| Ok((r.get(0)?, r.get(1)?)))
            .expect("the belt exists");
        assert_eq!((unique, partial), (1, 1), "a partial UNIQUE index on {path:?}");
        let mut log = SqliteIntentLog::open(path).expect("reopen");
        log.record(&s1_trash_cmd("k-c", "msg-1"), &crate::prestate::FrozenBasis::for_test_trash()).expect("record");
        drop(log);
        let refused = raw_conn(path).execute("UPDATE intents SET plan_id = 'p-1' WHERE idempotency_key = 'k-c';", []);
        assert!(format!("{refused:?}").contains("CHECK"), "half a link is refused by the CHECK on {path:?}, got {refused:?}");
        raw_conn(path)
            .execute("UPDATE intents SET plan_id = 'p-1', plan_member = 'msg-1' WHERE idempotency_key = 'k-c';", [])
            .unwrap_or_else(|e| panic!("a whole link is a legal shape on {path:?}: {e}"));
    }
    std::fs::remove_file(&fresh).ok();
    std::fs::remove_file(&upgraded).ok();
}

#[test]
fn s1_twin_record_refuses_a_plan_child_by_name_and_admits_a_valid_one() {
    // The in-memory twin's arm, over its own maps: the same refusal VALUES the durable arm
    // answers (`tests/plan_admission.rs` pins those), nothing written by a refusal, and an
    // admitted child that reads back with its link.
    use crate::plan::{PlanChildRefusal as R, PlanId, PlanSpec, RenderedView};
    let (mut twin, root) = s1_twin_with_two();
    let minted = twin.mint_plan(&root, PlanSpec { member_refs: vec!["m1".into(), "m2".into()], ..PlanSpec::for_test("acct") }).unwrap();
    twin.record_approval(&root, &minted.plan_id, "clinton", RenderedView::FullList(minted.presentation.clone())).unwrap();
    let plan = twin.plan(&minted.plan_id).unwrap().unwrap();
    let unapproved = twin.mint_plan(&root, PlanSpec { member_refs: vec!["m1".into()], ..PlanSpec::for_test("acct") }).unwrap();
    let unapproved = twin.plan(&unapproved.plan_id).unwrap().unwrap();
    let refused = |twin: &mut InMemoryIntentLog, c: &Command| -> R {
        match twin.record(c, &fixture_basis(c)).unwrap() {
            Claim::PlanChildRefused(r) => {
                assert!(twin.get(&c.idempotency_key).unwrap().is_none(), "nothing written for {r:?}");
                r
            }
            other => panic!("expected a named refusal, got {other:?}"),
        }
    };
    let c = Command::plan_child(&plan, "m1");
    let mut yellow = c.clone();
    yellow.action = Action::Archive { message_ref: "m1".into() };
    assert_eq!(refused(&mut twin, &yellow), R::NotARedVerb);
    let mut ghost = plan.clone();
    ghost.plan_id = PlanId("0".repeat(32));
    assert_eq!(refused(&mut twin, &Command::plan_child(&ghost, "m1")), R::NoPlan);
    let mut other = c.clone();
    other.account = "other".into();
    assert_eq!(refused(&mut twin, &other), R::AccountMismatch);
    let mut other = c.clone();
    other.action = Action::MarkSpam { message_ref: "m1".into() };
    assert_eq!(refused(&mut twin, &other), R::VerbMismatch);
    let mut other = c.clone();
    other.idempotency_key = "hand-built-key".into();
    assert_eq!(refused(&mut twin, &other), R::KeyMismatch);
    assert_eq!(refused(&mut twin, &Command::plan_child(&unapproved, "m1")), R::NotApproved);
    assert_eq!(refused(&mut twin, &c), R::NoEpisode);
    twin.start_episode(&plan.plan_id).unwrap();
    assert_eq!(refused(&mut twin, &c), R::NotReady);
    twin.mark_ready(&plan.plan_id).unwrap();
    assert_eq!(refused(&mut twin, &Command::plan_child(&plan, "m3")), R::NotAMember("m3".into()));
    assert_eq!(twin.record(&c, &fixture_basis(&c)).unwrap(), Claim::Inserted);
    assert_eq!(twin.get(&c.idempotency_key).unwrap().unwrap().command.plan_child_link(), c.plan_child_link());
    assert_eq!(twin.record(&c, &fixture_basis(&c)).unwrap(), Claim::AlreadyExisted);
    twin.sever("authority:test", "2026-09-24T00:00:00Z").unwrap();
    assert_eq!(refused(&mut twin, &Command::plan_child(&plan, "m2")), R::EpochMismatch { plan: 1, current: 2 });
    twin.invalidate_episode(&plan.plan_id, crate::episode::InvalidationReason::EpochMismatch { plan: 1, current: 2 }).unwrap();
    assert_eq!(refused(&mut twin, &Command::plan_child(&plan, "m2")), R::EpisodeNotActive(crate::episode::EpisodeStatusToken::Invalidated));
    let later = twin.mint_plan(&root, PlanSpec { member_refs: vec!["m1".into()], ttl_seconds: 3600, ..PlanSpec::for_test("acct") }).unwrap();
    twin.record_approval(&root, &later.plan_id, "clinton", RenderedView::FullList(later.presentation.clone())).unwrap();
    let later = twin.plan(&later.plan_id).unwrap().unwrap();
    twin.start_episode(&later.plan_id).unwrap();
    twin.mark_ready(&later.plan_id).unwrap();
    // The latch at EXACTLY the expiry is expired (AT the instant), and past it too.
    twin.time_high_water = later.expires_at.clone();
    assert_eq!(
        refused(&mut twin, &Command::plan_child(&later, "m1")),
        R::Expired { expires_at: later.expires_at.clone(), effective_now: later.expires_at.clone() }
    );
    twin.time_high_water = "2099-01-01T00:00:00Z".into();
    assert_eq!(
        refused(&mut twin, &Command::plan_child(&later, "m1")),
        R::Expired { expires_at: later.expires_at.clone(), effective_now: "2099-01-01T00:00:00Z".into() }
    );
}

// ---- the episode doors on the twin, and the generation CAS -----

#[test]
fn s1_twin_episode_doors_mirror_the_durable_store() {
    // The twin's episode doors answer the durable store's values (`tests/plan_admission.rs`
    // pins those): start once / resume, the ready barrier, the exact-N completion, the
    // expiry bound, the stale-preflight barrier, and a journal row per write.
    use crate::episode::*;
    use crate::plan::{PlanId, PlanSpec, RenderedView};
    let (mut twin, root) = s1_twin_with_two();
    // backups: off — since D4 the send fence refuses a `backups: on` child (`SnapshotAbsent`).
    twin.record_knob_act(crate::config_knobs::KnobAct::Backups(crate::config_knobs::BackupsKnob::Off)).unwrap();
    assert_eq!(twin.start_episode(&PlanId("0".repeat(32))).unwrap_err(), EpisodeRefusal::NoPlan);
    let minted = twin.mint_plan(&root, PlanSpec { member_refs: vec!["m1".into(), "m2".into()], ..PlanSpec::for_test("acct") }).unwrap();
    assert_eq!(twin.start_episode(&minted.plan_id).unwrap_err(), EpisodeRefusal::NotApproved);
    twin.record_approval(&root, &minted.plan_id, "clinton", RenderedView::FullList(minted.presentation.clone())).unwrap();
    let plan = twin.plan(&minted.plan_id).unwrap().unwrap();
    assert_eq!(twin.episode_status_check(&plan.plan_id).unwrap(), None);
    assert_eq!(twin.mark_ready(&plan.plan_id).unwrap_err(), EpisodeRefusal::NoEpisode);
    assert_eq!(twin.complete_episode_if_done(&plan.plan_id).unwrap(), Completion::NoEpisode);
    let EpisodeStart::Started(first) = twin.start_episode(&plan.plan_id).unwrap() else { panic!("the first start starts") };
    assert_eq!((first.status.clone(), first.generation, first.ready_at.clone(), first.claim_epoch), (EpisodeStatus::Active, 1, None, 1));
    assert!(matches!(twin.start_episode(&plan.plan_id).unwrap(), EpisodeStart::Resumed(ref e) if e.episode_id == first.episode_id && e.generation == 1));
    assert_eq!(twin.mark_ready(&plan.plan_id).unwrap(), ReadyOutcome::Ready);
    assert_eq!(twin.mark_ready(&plan.plan_id).unwrap(), ReadyOutcome::AlreadyReady);
    assert_eq!(twin.episode(&plan.plan_id).unwrap().unwrap().generation, 2);
    assert_eq!(twin.episode_status_check(&plan.plan_id).unwrap(), Some(EpisodeStatusToken::Active));
    assert_eq!(twin.complete_episode_if_done(&plan.plan_id).unwrap(), Completion::Incomplete { total: 2, minted: 0, terminal: 0 });
    // One child admitted, captured, claimed and send-authorized through the twin's own doors
    // (since D4 the fence runs the plan law: a capture and a Child binding).
    let c1 = Command::plan_child(&plan, "m1");
    assert_eq!(twin.record(&c1, &fixture_basis(&c1)).unwrap(), Claim::Inserted);
    s1_twin_prepare_child(&mut twin, &c1, true);
    let attempt = match twin.claim_attempt(&c1.idempotency_key, &AttemptClaim { ordinal: 1, predecessor: None, observed_attempts: 0 }).unwrap() {
        ClaimOutcome::Won { attempt_id, .. } => attempt_id,
        other => panic!("the first claim wins, got {other:?}"),
    };
    assert!(matches!(twin.authorize_send(&c1.idempotency_key, &attempt, CaptureBinding::Generation(1), s1_child_binding(&root)).unwrap(), SendAuthOutcome::Authorized { .. }));
    let stale = InvalidationReason::StalePreflight { diverged: vec![("m2".into(), vec![crate::attempt::MemberDiff { atom: "membership:INBOX".into(), expected: true, observed: Some(false) }])] };
    assert_eq!(twin.invalidate_episode(&plan.plan_id, stale.clone()).unwrap_err(), EpisodeRefusal::DispatchBegan { send_authorized_children: 1 });
    twin.episodes.get_mut(&plan.plan_id).unwrap().ready_at = None;
    assert_eq!(twin.mark_ready(&plan.plan_id).unwrap_err(), EpisodeRefusal::DispatchBegan { send_authorized_children: 1 });
    twin.episodes.get_mut(&plan.plan_id).unwrap().ready_at = Some("2026-09-24T00:00:00Z".into());
    // Exact-N: minted is not enough, every member's child must be TERMINAL.
    let c2 = Command::plan_child(&plan, "m2");
    assert_eq!(twin.record(&c2, &fixture_basis(&c2)).unwrap(), Claim::Inserted);
    assert_eq!(twin.complete_episode_if_done(&plan.plan_id).unwrap(), Completion::Incomplete { total: 2, minted: 2, terminal: 0 });
    assert_eq!(twin.set_status_if(&c1.idempotency_key, StatusPrecondition::NonTerminal, IntentStatus::Applied).unwrap(), StatusWrite::Written);
    assert_eq!(twin.complete_episode_if_done(&plan.plan_id).unwrap(), Completion::Incomplete { total: 2, minted: 2, terminal: 1 });
    assert_eq!(twin.set_status_if(&c2.idempotency_key, StatusPrecondition::NonTerminal, IntentStatus::Failed).unwrap(), StatusWrite::Written);
    assert_eq!(twin.complete_episode_if_done(&plan.plan_id).unwrap(), Completion::Completed);
    let done = twin.episode(&plan.plan_id).unwrap().unwrap();
    assert_eq!((done.status, done.generation, done.completed_at.is_some()), (EpisodeStatus::Completed, 3, true));
    assert_eq!(twin.complete_episode_if_done(&plan.plan_id).unwrap(), Completion::AlreadyTerminal(EpisodeStatusToken::Completed));
    assert_eq!(twin.start_episode(&plan.plan_id).unwrap_err(), EpisodeRefusal::Terminal(EpisodeStatusToken::Completed));
    // The journal: start, ready, completed — one row per write, generation order.
    let rows: Vec<(u64, EpisodeStatusToken, EpisodeEvent)> = twin.episode_journal.iter().filter(|r| r.plan_id == plan.plan_id).map(|r| (r.generation, r.status, r.event)).collect();
    assert_eq!(rows, vec![(1, EpisodeStatusToken::Active, EpisodeEvent::Start), (2, EpisodeStatusToken::Active, EpisodeEvent::Ready), (3, EpisodeStatusToken::Completed, EpisodeEvent::Transition)]);
    // Abandonment past expiry, and a stale preflight with nothing dispatched.
    let p2 = twin.mint_plan(&root, PlanSpec { member_refs: vec!["m1".into()], ..PlanSpec::for_test("acct") }).unwrap();
    twin.record_approval(&root, &p2.plan_id, "clinton", RenderedView::FullList(p2.presentation.clone())).unwrap();
    twin.start_episode(&p2.plan_id).unwrap();
    let p3 = twin.mint_plan(&root, PlanSpec { member_refs: vec!["m2".into()], ..PlanSpec::for_test("acct") }).unwrap();
    twin.record_approval(&root, &p3.plan_id, "clinton", RenderedView::FullList(p3.presentation.clone())).unwrap();
    twin.start_episode(&p3.plan_id).unwrap();
    twin.invalidate_episode(&p3.plan_id, stale.clone()).unwrap();
    assert_eq!(twin.episode(&p3.plan_id).unwrap().unwrap().status, EpisodeStatus::Invalidated(stale));
    twin.time_high_water = "2099-01-01T00:00:00Z".into();
    assert_eq!(twin.complete_episode_if_done(&p2.plan_id).unwrap(), Completion::Invalidated(InvalidationReason::Expired));
    assert_eq!(twin.invalidate_episode(&p2.plan_id, InvalidationReason::Expired).unwrap_err(), EpisodeRefusal::IllegalTransition { from: EpisodeStatusToken::Invalidated, to: EpisodeStatusToken::Invalidated });
    // Past expiry a plan cannot start (p4 is minted at the latched 2099 instant, so its hour
    // runs from there); after a sever, an epoch-moved plan cannot either — the epoch is
    // checked before the clock.
    let p4 = twin.mint_plan(&root, PlanSpec { member_refs: vec!["m1".into()], ..PlanSpec::for_test("acct") }).unwrap();
    twin.record_approval(&root, &p4.plan_id, "clinton", RenderedView::FullList(p4.presentation.clone())).unwrap();
    twin.time_high_water = "2099-01-01T02:00:00Z".into();
    assert!(matches!(twin.start_episode(&p4.plan_id).unwrap_err(), EpisodeRefusal::Expired { ref effective_now, .. } if effective_now == "2099-01-01T02:00:00Z"));
    twin.sever("authority:test", "2026-09-24T00:00:00Z").unwrap();
    assert_eq!(twin.start_episode(&p4.plan_id).unwrap_err(), EpisodeRefusal::EpochMismatch { plan: 1, current: 2 });
}

#[test]
fn s1_every_episode_write_is_a_generation_cas_and_a_stale_expected_generation_conflicts_on_both_stores() {
    use crate::episode::*;
    use crate::plan::{PlanSpec, RenderedView};
    let write = EpisodeWrite {
        status: EpisodeStatus::Invalidated(InvalidationReason::Expired),
        ready_at: None,
        completed_at: None,
        event: EpisodeEvent::Transition,
        at: "2026-09-24T00:00:00Z".into(),
    };
    // The durable store: a head at generation 2 (start + ready) refuses a write that names 1.
    let path = unique_temp_db_path("s1-episode-cas");
    let mut sqlite = SqliteIntentLog::open(&path).unwrap();
    let refs = crate::read_coordinator::ReadCoordinator::open(&path)
        .unwrap()
        .ingest_page("acct", &[crate::read_surface::HeaderSummary {
            provider_id: crate::read_model::ProviderMessageId("P-1".into()),
            received_at: 1_758_672_000_000,
            from_addr: "a@b.example".into(),
            from_name: String::new(),
            subject: "s".into(),
            seen: false,
            flagged: false,
            attachments: crate::read_surface::AttachmentPresence::default(),
        }])
        .unwrap();
    let root = crate::key_custody::root_key_verified(&crate::key_custody::InMemoryCustody::new(), &mut sqlite).unwrap();
    let minted = sqlite.mint_plan(&root, PlanSpec { member_refs: refs.clone(), ..PlanSpec::for_test("acct") }).unwrap();
    sqlite.record_approval(&root, &minted.plan_id, "clinton", RenderedView::FullList(minted.presentation.clone())).unwrap();
    sqlite.start_episode(&minted.plan_id).unwrap();
    sqlite.mark_ready(&minted.plan_id).unwrap();
    let journal_rows = |path: &std::path::Path| -> i64 { raw_conn(path).query_row("SELECT COUNT(*) FROM episode_journal", [], |r| r.get(0)).unwrap() };
    assert_eq!(
        sqlite.with_immediate_tx(|tx| write_episode_in(tx, &minted.plan_id, 1, &write)).unwrap(),
        Err(EpisodeRefusal::GenerationConflict { expected: 1, found: 2 })
    );
    let head = sqlite.episode(&minted.plan_id).unwrap().unwrap();
    assert_eq!((head.status, head.generation, journal_rows(&path)), (EpisodeStatus::Active, 2, 2), "a stale write changes nothing");
    assert_eq!(sqlite.with_immediate_tx(|tx| write_episode_in(tx, &minted.plan_id, 2, &write)).unwrap(), Ok(3));
    let head = sqlite.episode(&minted.plan_id).unwrap().unwrap();
    assert_eq!((head.status, head.generation, journal_rows(&path)), (write.status.clone(), 3, 3));
    // The twin: the same CAS over its map.
    let (mut twin, twin_root) = s1_twin_with_two();
    let minted = twin.mint_plan(&twin_root, PlanSpec { member_refs: vec!["m1".into()], ..PlanSpec::for_test("acct") }).unwrap();
    twin.record_approval(&twin_root, &minted.plan_id, "clinton", RenderedView::FullList(minted.presentation.clone())).unwrap();
    twin.start_episode(&minted.plan_id).unwrap();
    twin.mark_ready(&minted.plan_id).unwrap();
    assert_eq!(twin.write_episode(&minted.plan_id, 1, &write), Err(EpisodeRefusal::GenerationConflict { expected: 1, found: 2 }));
    assert_eq!((twin.episode(&minted.plan_id).unwrap().unwrap().generation, twin.episode_journal.len()), (2, 2));
    assert_eq!(twin.write_episode(&minted.plan_id, 2, &write), Ok(3));
    assert_eq!((twin.episode(&minted.plan_id).unwrap().unwrap().status, twin.episode_journal.len()), (write.status.clone(), 3));
    std::fs::remove_file(&path).ok();
}

// ---- the send-admission law on the twin ------------------------------

/// PREPARE a Trash child's capture on the twin: TRASH clear, INBOX as given (an Inbox member
/// froze INBOX set at mint, so `false` is a member archived since approval).
fn s1_twin_prepare_child(twin: &mut InMemoryIntentLog, c: &Command, inbox: bool) {
    let basis = fixture_basis(c);
    let obs = test_support::fixture_observation_with(&basis, &[("membership:INBOX", inbox), ("label:TRASH", false)]);
    assert_eq!(
        twin.prepare(&c.idempotency_key, &prestate::journal_row_from_observation(&obs, &basis)).unwrap(),
        prestate::PrepareOutcome::Prepared
    );
}

/// The binding a bus with an admitting ratchet hands the fence for an `acct` plan child.
fn s1_child_binding(root: &crate::commitment::CommitmentKey) -> crate::plan::PlanBinding {
    crate::plan::PlanBinding::Child {
        grant: crate::plan::GrantVerdict::Admitted,
        account_key: crate::commitment::derive_account_key(root, "acct").unwrap(),
    }
}

#[test]
fn s1_twin_send_admission_law_answers_the_durable_values_and_writes_the_same_things() {
    // The twin's arm over its maps: the binding check, a held refusal that writes nothing, an
    // admitted child, and the terminal rows that write `FAILED_PRE_SEND` + `Failed` (and, for
    // expiry, invalidate the episode) — the values `tests/plan_admission.rs` pins on SQLite.
    use crate::episode::{EpisodeStatus, EpisodeStatusToken, InvalidationReason, PauseReason};
    use crate::plan::{PlanBinding, PlanSendRefusal as R, PlanSpec, RenderedView, TriagePlan};
    let (mut twin, root) = s1_twin_with_two();
    let off = |twin: &mut InMemoryIntentLog| {
        twin.record_knob_act(crate::config_knobs::KnobAct::Backups(crate::config_knobs::BackupsKnob::Off)).unwrap();
    };
    off(&mut twin);
    let ready_plan = |twin: &mut InMemoryIntentLog, member: &str| -> TriagePlan {
        let minted = twin.mint_plan(&root, PlanSpec { member_refs: vec![member.into()], ..PlanSpec::for_test("acct") }).unwrap();
        twin.record_approval(&root, &minted.plan_id, "clinton", RenderedView::FullList(minted.presentation.clone())).unwrap();
        twin.start_episode(&minted.plan_id).unwrap();
        twin.mark_ready(&minted.plan_id).unwrap();
        twin.plan(&minted.plan_id).unwrap().unwrap()
    };
    let claimed_child = |twin: &mut InMemoryIntentLog, plan: &TriagePlan, member: &str, inbox: bool| -> (String, String) {
        let c = Command::plan_child(plan, member);
        assert_eq!(twin.record(&c, &fixture_basis(&c)).unwrap(), Claim::Inserted);
        s1_twin_prepare_child(twin, &c, inbox);
        let a = test_support::won_attempt_id(twin.claim_attempt(&c.idempotency_key, &test_support::first_claim()).unwrap());
        (c.idempotency_key, a)
    };
    let g1 = CaptureBinding::Generation(1);
    // The binding is total: a plan child under `Plain` is a LogError, nothing written.
    let p = ready_plan(&mut twin, "m1");
    let (k, a) = claimed_child(&mut twin, &p, "m1", true);
    assert!(twin.authorize_send(&k, &a, g1, PlanBinding::Plain).is_err());
    assert_eq!(twin.get(&k).unwrap().unwrap().status, IntentStatus::Pending);
    // HELD: a paused episode refuses and writes nothing.
    twin.episodes.get_mut(&p.plan_id).unwrap().status = EpisodeStatus::Paused(PauseReason::Operator);
    assert_eq!(twin.authorize_send(&k, &a, g1, s1_child_binding(&root)).unwrap(), SendAuthOutcome::PlanRefused(R::EpisodeHeld(EpisodeStatusToken::Paused)));
    assert_eq!((twin.get(&k).unwrap().unwrap().status, twin.plan_refusal(&k).unwrap()), (IntentStatus::Pending, None));
    twin.episodes.get_mut(&p.plan_id).unwrap().status = EpisodeStatus::Active;
    // Every row satisfied ⇒ authorized.
    assert!(matches!(twin.authorize_send(&k, &a, g1, s1_child_binding(&root)).unwrap(), SendAuthOutcome::Authorized { .. }));
    // STATE: m2 archived since approval ⇒ STALE_NOT_ATTEMPTED with the diff, terminal.
    let p2 = ready_plan(&mut twin, "m2");
    let (k2, a2) = claimed_child(&mut twin, &p2, "m2", false);
    let diff = vec![crate::attempt::MemberDiff { atom: "membership:INBOX".into(), expected: true, observed: Some(false) }];
    assert_eq!(twin.authorize_send(&k2, &a2, g1, s1_child_binding(&root)).unwrap(), SendAuthOutcome::PlanRefused(R::StateDiverged { diff: diff.clone() }));
    assert_eq!(twin.get(&k2).unwrap().unwrap().status, IntentStatus::Failed);
    let rec = twin.plan_refusal(&k2).unwrap().unwrap();
    assert_eq!((rec.reason.as_str(), rec.member_ref.as_str(), rec.diff.clone()), ("state_diverged", "m2", diff));
    // COVERAGE: a backups act after mint ⇒ terminal.
    let p3 = ready_plan(&mut twin, "m2");
    let (k3, a3) = claimed_child(&mut twin, &p3, "m2", true);
    twin.record_knob_act(crate::config_knobs::KnobAct::Backups(crate::config_knobs::BackupsKnob::On)).unwrap();
    assert!(matches!(twin.authorize_send(&k3, &a3, g1, s1_child_binding(&root)).unwrap(), SendAuthOutcome::PlanRefused(R::CoverageDiverged { .. })));
    assert_eq!((twin.get(&k3).unwrap().unwrap().status, twin.plan_refusal(&k3).unwrap().unwrap().reason), (IntentStatus::Failed, "coverage_diverged".to_string()));
    // EXPIRY on the sticky clock ⇒ terminal, and the episode is invalidated{expired}.
    off(&mut twin);
    let p4 = ready_plan(&mut twin, "m2");
    let (k4, a4) = claimed_child(&mut twin, &p4, "m2", true);
    twin.time_high_water = "2099-01-01T00:00:00Z".into();
    assert!(matches!(twin.authorize_send(&k4, &a4, g1, s1_child_binding(&root)).unwrap(), SendAuthOutcome::PlanRefused(R::Expired { .. })));
    assert_eq!(twin.get(&k4).unwrap().unwrap().status, IntentStatus::Failed);
    assert_eq!(twin.episode(&p4.plan_id).unwrap().unwrap().status, EpisodeStatus::Invalidated(InvalidationReason::Expired));
}

// ---- the bus — requires_plan, preflight, the child driver ---------

/// BOTH stores: three header rows as the
/// transport stores them — a parsed mailbox, an EMPTY From, and a malformed From kept as its
/// raw text — minted into one plan. The summary's sender domains count only the parsed
/// mailbox's domain: an empty or a malformed sender is never a domain entry (the failure was
/// `sender_domains=[("",1)]`).
#[test]
fn both_stores_count_only_a_parsed_mailboxs_domain_never_an_empty_or_malformed_sender() {
    use crate::plan::PlanSpec;
    let senders = [("m1", "real@evil.example"), ("m2", ""), ("m3", "<a@x.example> <b@y.example>")];
    let spec = || PlanSpec { member_refs: vec!["m1".into(), "m2".into(), "m3".into()], ..PlanSpec::for_test("acct") };
    // The twin.
    let mut twin = InMemoryIntentLog::new();
    for (i, (m, from)) in senders.iter().enumerate() {
        twin.seed_header_for_test("acct", m, from, "", &format!("subject {m}"), 1_758_672_000_000 + i as i64 * 1_000);
        twin.seed_placement_for_test("acct", m, crate::read_model::Placement::Inbox);
    }
    let root = test_root_key();
    let twin_minted = twin.mint_plan(&root, spec()).unwrap();
    // The durable store, through the read side's own ingest door.
    let path = unique_temp_db_path("council-r2-s31-both-stores");
    let mut log = SqliteIntentLog::open(&path).expect("open");
    let rows: Vec<crate::read_surface::HeaderSummary> = senders
        .iter()
        .enumerate()
        .map(|(i, (m, from))| crate::read_surface::HeaderSummary {
            provider_id: crate::read_model::ProviderMessageId(format!("P-{m}")),
            received_at: 1_758_672_000_000 + i as i64 * 1_000,
            from_addr: from.to_string(),
            from_name: String::new(),
            subject: format!("subject {m}"),
            seen: false,
            flagged: false,
            attachments: crate::read_surface::AttachmentPresence::default(),
        })
        .collect();
    let refs = crate::read_coordinator::ReadCoordinator::open(&path).unwrap().ingest_page("acct", &rows).unwrap();
    let sqlite_minted = log.mint_plan(&root, PlanSpec { member_refs: refs, ..PlanSpec::for_test("acct") }).unwrap();
    for (store, minted) in [("twin", &twin_minted), ("sqlite", &sqlite_minted)] {
        assert_eq!(
            minted.presentation.summary.sender_domains,
            vec![("evil.example".to_string(), 1)],
            "{store}: only the parsed mailbox's domain is a domain entry"
        );
        assert_eq!(minted.presentation.summary.sender_domain_unavailable, 1, "{store}: the empty From is counted as unavailable");
        assert_eq!(minted.presentation.summary.sender_header_malformed, 1, "{store}: the malformed From is counted as malformed");
    }
    // Each member froze its STRUCTURED sender, and it reads back from each store.
    use crate::plan::FrozenSender;
    let parsed = FrozenSender::Parsed { addr: "real@evil.example".into(), local: "real".into(), domain: "evil.example".into() };
    let twin_plan = twin.plan(&twin_minted.plan_id).unwrap().expect("stored");
    let sqlite_plan = log.plan(&sqlite_minted.plan_id).unwrap().expect("stored");
    for (store, plan) in [("twin", &twin_plan), ("sqlite", &sqlite_plan)] {
        // `sender` is the NAME half only (empty for every member
        // here — none of these headers carried a display name), so the address half that
        // used to distinguish these rows lives in `sender_address` now (bare, since there is
        // no name to bracket it beside — `frozen_plan_member`'s "no name ⇒ bare address" rule).
        let mut frozen: Vec<(&str, &FrozenSender)> = plan.members.iter().map(|m| (m.display.sender_address.as_str(), &m.display.sender_parse)).collect();
        frozen.sort_by(|a, b| a.0.cmp(b.0));
        assert_eq!(
            frozen,
            vec![
                ("", &FrozenSender::Unavailable),
                ("<a@x.example> <b@y.example>", &FrozenSender::Malformed),
                ("real@evil.example", &parsed),
            ],
            "{store}: the display text beside the structured sender (the malformed one's raw text is its display)"
        );
        assert!(plan.members.iter().all(|m| m.display.sender.is_empty()), "{store}: no header here carried a display name");
    }
    drop(log);
    std::fs::remove_file(&path).ok();
}

/// Seed each member as an Inbox message on the bus's twin, record `backups: off`, mint a Trash
/// plan over `members` under [`test_root_key`] and approve it (full list). Returns the plan
/// as the twin reads it back and the plan account's key.
fn in_memory_approved_plan<C: Connector>(
    bus: &mut CommandBus<InMemoryIntentLog, C>,
    members: &[&str],
) -> (crate::plan::TriagePlan, crate::commitment::CommitmentKey) {
    use crate::plan::{PlanSpec, RenderedView};
    let root = test_root_key();
    let log = bus.log_mut();
    for (i, m) in members.iter().enumerate() {
        log.seed_header_for_test("acct", m, &format!("sender{i}@list.example"), "", &format!("subject {m}"), 1_758_672_000_000 + i as i64 * 1_000);
        log.seed_placement_for_test("acct", m, crate::read_model::Placement::Inbox);
    }
    log.record_knob_act(crate::config_knobs::KnobAct::Backups(crate::config_knobs::BackupsKnob::Off)).unwrap();
    let minted = log
        .mint_plan(&root, PlanSpec { member_refs: members.iter().map(|m| m.to_string()).collect(), ..PlanSpec::for_test("acct") })
        .unwrap();
    log.record_approval(&root, &minted.plan_id, "clinton", RenderedView::FullList(minted.presentation.clone())).unwrap();
    let plan = log.plan(&minted.plan_id).unwrap().unwrap();
    (plan, crate::commitment::derive_account_key(&root, "acct").unwrap())
}

/// The observation an agreeing provider answers for a Trash member still in the Inbox.
const S1_IN_INBOX: [(&str, bool); 2] = [("membership:INBOX", true), ("label:TRASH", false)];

#[test]
fn s1_a_red_verb_without_a_plan_child_is_refused_pre_durable_and_a_yellow_verb_with_one_is_refused_too() {
    let mut bus = CommandBus::new(InMemoryIntentLog::new(), CountingConnector::default());
    let red = Command::new("k-red", "acct", Facet::Mail, Action::Trash { message_ref: "m1".into() });
    assert_eq!(bus.execute(&red).unwrap_err(), ExecuteError::PlanRequired);
    assert!(bus.log().get("k-red").unwrap().is_none(), "nothing durable");
    assert_eq!(bus.execute(&red).unwrap_err(), ExecuteError::PlanRequired, "the same answer on every replay");
    let spam = Command::new("k-spam", "acct", Facet::Mail, Action::MarkSpam { message_ref: "m1".into() });
    assert_eq!(bus.execute(&spam).unwrap_err(), ExecuteError::PlanRequired);
    let (plan, _) = in_memory_approved_plan(&mut bus, &["m1"]);
    let mut yellow = Command::plan_child(&plan, "m1");
    yellow.action = Action::Untrash { message_ref: "m1".into() };
    assert_eq!(bus.execute(&yellow).unwrap_err(), ExecuteError::PlanChildRefused(crate::plan::PlanChildRefusal::NotARedVerb));
    assert!(bus.log().get(&yellow.idempotency_key).unwrap().is_none(), "nothing durable");
    assert_eq!(bus.connector().observe_count() + bus.connector().apply_count(), 0, "no provider call for either refusal");
    // A YELLOW verb with no plan link is untouched by the rule.
    bus.execute(&Command::new("k-archive", "acct", Facet::Mail, Action::Archive { message_ref: "m9".into() })).unwrap();
}

#[test]
fn s1_preflight_marks_ready_on_agreement_and_invalidates_wholesale_naming_the_diverged_members() {
    let mut bus = CommandBus::new(InMemoryIntentLog::new(), CountingConnector::default());
    let (plan, _) = in_memory_approved_plan(&mut bus, &["m1", "m2"]);
    bus.log_mut().start_episode(&plan.plan_id).unwrap();
    // The default fixture connector observes every atom FALSE (an empty provider): the plan
    // froze INBOX=true ⇒ diverged, both members.
    match bus.preflight_plan(&plan.plan_id).unwrap() {
        crate::plan::PreflightOutcome::Refused { diverged } => {
            assert_eq!(diverged.iter().map(|(m, _)| m.as_str()).collect::<Vec<_>>(), vec!["m1", "m2"]);
            assert_eq!(diverged[0].1, vec![crate::attempt::MemberDiff { atom: "membership:INBOX".into(), expected: true, observed: Some(false) }]);
        }
        other => panic!("{other:?}"),
    }
    let head = bus.log().episode(&plan.plan_id).unwrap().unwrap();
    assert!(matches!(head.status, crate::episode::EpisodeStatus::Invalidated(crate::episode::InvalidationReason::StalePreflight { .. })));
    assert_eq!(head.ready_at, None, "a refused preflight never sets the ready marker");
    assert_eq!(bus.connector().apply_count(), 0);
    // A connector that agrees ⇒ ready.
    let mut agreeing = CommandBus::new(InMemoryIntentLog::new(), CountingConnector::observing(&S1_IN_INBOX));
    let (plan2, _) = in_memory_approved_plan(&mut agreeing, &["m1"]);
    agreeing.log_mut().start_episode(&plan2.plan_id).unwrap();
    assert_eq!(agreeing.preflight_plan(&plan2.plan_id).unwrap(), crate::plan::PreflightOutcome::Ready);
    assert!(agreeing.log().episode(&plan2.plan_id).unwrap().unwrap().ready_at.is_some());
    assert_eq!(agreeing.preflight_plan(&plan2.plan_id).unwrap(), crate::plan::PreflightOutcome::Ready, "a second preflight of a ready plan is still ready");
    // No episode ⇒ refused by name.
    let (plan3, _) = in_memory_approved_plan(&mut agreeing, &["m2"]);
    assert_eq!(agreeing.preflight_plan(&plan3.plan_id).unwrap_err(), ExecuteError::PlanChildRefused(crate::plan::PlanChildRefusal::NoEpisode));
}

#[test]
fn s1_apply_plan_member_drives_one_child_through_the_law_and_completion_is_exact_n() {
    let mut bus = CommandBus::new(InMemoryIntentLog::new(), CountingConnector::observing(&S1_IN_INBOX))
        .with_grant_ratchet(Box::new(crate::InMemoryGrantRatchet { high_water: Some(1), principal: "me@e".into() }))
        .with_root_key(test_root_key());
    let (plan, _) = in_memory_approved_plan(&mut bus, &["m1", "m2"]);
    bus.log_mut().start_episode(&plan.plan_id).unwrap();
    assert_eq!(bus.preflight_plan(&plan.plan_id).unwrap(), crate::plan::PreflightOutcome::Ready);
    assert_eq!(bus.plan_member_states(&plan.plan_id).unwrap()[0].1, crate::plan::MemberState::NotMinted);
    bus.apply_plan_member(&plan.plan_id, "m1").unwrap();
    assert_eq!(bus.log().get(&Command::plan_child(&plan, "m1").idempotency_key).unwrap().unwrap().status, IntentStatus::Applied);
    assert_eq!(bus.connector().apply_count(), 1);
    assert_eq!(bus.settle_plan_progress(&plan.plan_id).unwrap(), crate::episode::Completion::Incomplete { total: 2, minted: 1, terminal: 1 });
    bus.apply_plan_member(&plan.plan_id, "m2").unwrap();
    assert_eq!(bus.settle_plan_progress(&plan.plan_id).unwrap(), crate::episode::Completion::Completed);
    let states = bus.plan_member_states(&plan.plan_id).unwrap();
    assert_eq!(states, vec![("m1".to_string(), crate::plan::MemberState::Applied), ("m2".to_string(), crate::plan::MemberState::Applied)]);
    // A retired grant ⇒ the child terminalizes GrantRetired and the caller is told by name —
    // and an identical replay reads the SAME refusal back from the record.
    let mut retired = CommandBus::new(InMemoryIntentLog::new(), CountingConnector::observing(&S1_IN_INBOX))
        .with_grant_ratchet(Box::new(crate::InMemoryGrantRatchet { high_water: Some(9), principal: "me@e".into() }))
        .with_root_key(test_root_key());
    let (p, _) = in_memory_approved_plan(&mut retired, &["m1"]);
    retired.log_mut().start_episode(&p.plan_id).unwrap();
    retired.preflight_plan(&p.plan_id).unwrap();
    let named = ExecuteError::PlanRefused {
        reason: crate::plan::PlanSendRefusal::GrantRetired(crate::plan::GrantDenial::Retired { generation: 1, high_water: 9 }),
        member_ref: "m1".into(),
    };
    assert_eq!(retired.apply_plan_member(&p.plan_id, "m1").unwrap_err(), named);
    assert_eq!(retired.execute(&Command::plan_child(&p, "m1")).unwrap_err(), named, "the replay names the same refusal");
    assert_eq!(retired.connector().apply_count(), 0, "nothing reached the wire");
    assert_eq!(retired.plan_member_states(&p.plan_id).unwrap()[0].1, crate::plan::MemberState::Refused { reason: "grant_retired".into(), diff: vec![] });
    // A bus with NO ratchet fails closed — and HOLDS: "the ratchet could
    // not be consulted" is no verdict about the grant, so the child stays in flight, nothing
    // terminal is written and nothing reaches the wire.
    let mut none = CommandBus::new(InMemoryIntentLog::new(), CountingConnector::observing(&S1_IN_INBOX)).with_root_key(test_root_key());
    let (p2, _) = in_memory_approved_plan(&mut none, &["m1"]);
    none.log_mut().start_episode(&p2.plan_id).unwrap();
    none.preflight_plan(&p2.plan_id).unwrap();
    assert_eq!(none.apply_plan_member(&p2.plan_id, "m1").unwrap_err(), ExecuteError::InProgress);
    let held = Command::plan_child(&p2, "m1").idempotency_key;
    assert_eq!((none.log().get(&held).unwrap().unwrap().status, none.log().plan_refusal(&held).unwrap()), (IntentStatus::Pending, None));
    assert_eq!(none.plan_member_states(&p2.plan_id).unwrap()[0].1, crate::plan::MemberState::InFlight);
    assert_eq!(none.connector().apply_count(), 0);
    // A bus with no ROOT KEY cannot bind a plan child: a named store error, nothing sent.
    let mut keyless = CommandBus::new(InMemoryIntentLog::new(), CountingConnector::observing(&S1_IN_INBOX))
        .with_grant_ratchet(Box::new(crate::InMemoryGrantRatchet { high_water: Some(1), principal: "me@e".into() }));
    let (p3, _) = in_memory_approved_plan(&mut keyless, &["m1"]);
    keyless.log_mut().start_episode(&p3.plan_id).unwrap();
    keyless.preflight_plan(&p3.plan_id).unwrap();
    match keyless.apply_plan_member(&p3.plan_id, "m1").unwrap_err() {
        ExecuteError::Log(e) => assert!(e.0.contains("no root key"), "{e:?}"),
        other => panic!("{other:?}"),
    }
    assert_eq!(keyless.connector().apply_count(), 0);
    // An episode no longer active is refused at the cheap status check, by its token.
    let (p4, _) = in_memory_approved_plan(&mut bus, &["m3"]);
    assert_eq!(bus.apply_plan_member(&p4.plan_id, "m3").unwrap_err(), ExecuteError::PlanChildRefused(crate::plan::PlanChildRefusal::NoEpisode));
    assert_eq!(bus.apply_plan_member(&plan.plan_id, "m1").unwrap_err(), ExecuteError::PlanChildRefused(crate::plan::PlanChildRefusal::EpisodeNotActive(crate::episode::EpisodeStatusToken::Completed)));
}

#[test]
fn a_sever_crossing_an_active_episode_lands_invalidated_epoch_mismatch_on_the_twin() {
    // The durable half is `tests/plan_admission.rs`
    // `f3_a_sever_crossing_an_active_episode_lands_invalidated_epoch_mismatch_on_the_durable_store`;
    // this is the twin's, the same four arms (A all-terminal, B one unminted, C the resume path
    // on the epoch refusal, D the resume path on the expiry refusal).
    use crate::episode::{Completion, EpisodeRefusal, EpisodeStatus, InvalidationReason};
    let mut twin = s1_twin_seeded(&["m1", "m2", "m3", "m4", "m5"]);
    let a = s1_plan_ready(&mut twin, &["m1".to_string()]);
    let b = s1_plan_ready(&mut twin, &["m2".to_string(), "m3".to_string()]);
    let c = s1_plan_ready(&mut twin, &["m4".to_string()]);
    let ca = Command::plan_child(&a, "m1");
    assert_eq!(twin.record(&ca, &fixture_basis(&ca)).unwrap(), Claim::Inserted);
    let cb = Command::plan_child(&b, "m2");
    assert_eq!(twin.record(&cb, &fixture_basis(&cb)).unwrap(), Claim::Inserted);
    twin.sever("authority:test", "2026-09-24T00:00:00Z").unwrap();
    assert_eq!(twin.get(&ca.idempotency_key).unwrap().unwrap().status, IntentStatus::Severed, "precondition: the sever closed the pending child");
    let moved = InvalidationReason::EpochMismatch { plan: 1, current: 2 };
    assert_eq!(twin.complete_episode_if_done(&a.plan_id).unwrap(), Completion::Invalidated(moved.clone()));
    assert_eq!(twin.episode(&a.plan_id).unwrap().unwrap().status, EpisodeStatus::Invalidated(moved.clone()));
    assert_eq!(twin.complete_episode_if_done(&b.plan_id).unwrap(), Completion::Invalidated(moved.clone()));
    assert_eq!(twin.start_episode(&c.plan_id).unwrap_err(), EpisodeRefusal::EpochMismatch { plan: 1, current: 2 });
    assert_eq!(twin.episode(&c.plan_id).unwrap().unwrap().status, EpisodeStatus::Invalidated(moved.clone()));
    assert!(
        twin.episode_journal.iter().any(|r| r.plan_id == c.plan_id && r.reason.as_deref().is_some_and(|x| x.contains("epoch_mismatch"))),
        "the resume path's invalidation is journaled"
    );
    let d = s1_plan_ready(&mut twin, &["m5".to_string()]);
    twin.time_high_water = "2099-01-01T00:00:00Z".into();
    assert!(matches!(twin.start_episode(&d.plan_id).unwrap_err(), EpisodeRefusal::Expired { .. }));
    assert_eq!(twin.episode(&d.plan_id).unwrap().unwrap().status, EpisodeStatus::Invalidated(InvalidationReason::Expired));
}

#[test]
fn the_twin_freezes_the_bypass_notice_and_its_fence_refuses_a_bypass_plan_without_one() {
    // The durable half is `tests/plan_admission.rs`
    // `f1_a_bypass_plan_under_backups_off_admits_with_its_frozen_notice_and_refuses_by_name_without_one`.
    use crate::plan::{PlanSendRefusal as R, PlanSpec, RenderedView, TRASH_UNCOVERED_WARNING};
    let (mut twin, root) = s1_twin_with_two();
    twin.record_knob_act(crate::config_knobs::KnobAct::Backups(crate::config_knobs::BackupsKnob::Off)).unwrap();
    let screen = twin.mint_plan(&root, PlanSpec { member_refs: vec!["m1".into()], ..PlanSpec::for_test("acct") }).unwrap();
    assert_eq!(screen.bypass_notice, None, "a screen lane never carries a notice");
    twin.record_knob_act(crate::config_knobs::KnobAct::RedBypass(crate::config_knobs::RedBypassKnob::On)).unwrap();
    let ready = |twin: &mut InMemoryIntentLog, member: &str| -> (crate::plan::TriagePlan, String, String) {
        let minted = twin.mint_plan(&root, PlanSpec { member_refs: vec![member.into()], ..PlanSpec::for_test("acct") }).unwrap();
        assert_eq!(minted.bypass_notice.as_deref(), Some(TRASH_UNCOVERED_WARNING));
        twin.record_approval(&root, &minted.plan_id, "mechanical", RenderedView::FullList(minted.presentation.clone())).unwrap();
        twin.start_episode(&minted.plan_id).unwrap();
        twin.mark_ready(&minted.plan_id).unwrap();
        let plan = twin.plan(&minted.plan_id).unwrap().unwrap();
        assert_eq!(plan.bypass_notice, minted.bypass_notice);
        let c = Command::plan_child(&plan, member);
        assert_eq!(twin.record(&c, &fixture_basis(&c)).unwrap(), Claim::Inserted);
        s1_twin_prepare_child(twin, &c, true);
        let a = test_support::won_attempt_id(twin.claim_attempt(&c.idempotency_key, &test_support::first_claim()).unwrap());
        (plan, c.idempotency_key, a)
    };
    let (_, k1, a1) = ready(&mut twin, "m1");
    assert!(matches!(twin.authorize_send(&k1, &a1, CaptureBinding::Generation(1), s1_child_binding(&root)).unwrap(), SendAuthOutcome::Authorized { .. }));
    let (legacy, k2, a2) = ready(&mut twin, "m2");
    twin.plans.get_mut(&legacy.plan_id).unwrap().bypass_notice = None;
    assert_eq!(twin.authorize_send(&k2, &a2, CaptureBinding::Generation(1), s1_child_binding(&root)).unwrap(), SendAuthOutcome::PlanRefused(R::BypassNoticeAbsent));
    assert_eq!(twin.get(&k2).unwrap().unwrap().status, IntentStatus::Failed);
    assert_eq!(twin.plan_refusal(&k2).unwrap().unwrap().reason, "bypass_notice_absent");
}

/// A ready one-member Trash plan on the twin over `member` under the knobs in force, its child
/// recorded, captured (INBOX set, TRASH clear) and claimed; the plan, the key and the attempt.
fn s1_twin_claimed_child(twin: &mut InMemoryIntentLog, root: &crate::commitment::CommitmentKey, member: &str) -> (crate::plan::TriagePlan, String, String) {
    use crate::plan::{PlanSpec, RenderedView};
    let minted = twin.mint_plan(root, PlanSpec { member_refs: vec![member.into()], ..PlanSpec::for_test("acct") }).unwrap();
    twin.record_approval(root, &minted.plan_id, "clinton", RenderedView::FullList(minted.presentation.clone())).unwrap();
    twin.start_episode(&minted.plan_id).unwrap();
    twin.mark_ready(&minted.plan_id).unwrap();
    let plan = twin.plan(&minted.plan_id).unwrap().unwrap();
    let c = Command::plan_child(&plan, member);
    assert_eq!(twin.record(&c, &fixture_basis(&c)).unwrap(), Claim::Inserted);
    s1_twin_prepare_child(twin, &c, true);
    let a = test_support::won_attempt_id(twin.claim_attempt(&c.idempotency_key, &test_support::first_claim()).unwrap());
    (plan, c.idempotency_key, a)
}

#[test]
fn the_twin_fence_holds_a_grant_unavailable_verdict_without_reading_the_clock() {
    // The durable half is `tests/plan_admission.rs`
    // `f5_a_grant_unavailable_verdict_is_held_at_the_fence_writes_nothing_and_reads_no_clock`.
    use crate::plan::{GrantDenial, GrantVerdict, PlanBinding, PlanSendRefusal as R};
    let (mut twin, root) = s1_twin_with_two();
    twin.record_knob_act(crate::config_knobs::KnobAct::Backups(crate::config_knobs::BackupsKnob::Off)).unwrap();
    let (plan, k, a) = s1_twin_claimed_child(&mut twin, &root, "m1");
    twin.time_high_water = "2000-01-01T00:00:00Z".into();
    let unavailable = PlanBinding::Child { grant: GrantVerdict::Refused(GrantDenial::Unavailable), account_key: crate::commitment::derive_account_key(&root, "acct").unwrap() };
    assert_eq!(twin.authorize_send(&k, &a, CaptureBinding::Generation(1), unavailable).unwrap(), SendAuthOutcome::PlanRefused(R::GrantRetired(GrantDenial::Unavailable)));
    assert_eq!((twin.get(&k).unwrap().unwrap().status, twin.plan_refusal(&k).unwrap()), (IntentStatus::Pending, None));
    assert_eq!(twin.time_high_water, "2000-01-01T00:00:00Z", "held before the clock is read");
    assert_eq!(twin.episode(&plan.plan_id).unwrap().unwrap().status, crate::episode::EpisodeStatus::Active);
    assert!(matches!(twin.authorize_send(&k, &a, CaptureBinding::Generation(1), s1_child_binding(&root)).unwrap(), SendAuthOutcome::Authorized { .. }));
}

#[test]
fn the_twin_fence_at_exactly_expires_at_is_expired() {
    // The durable half is `tests/plan_admission.rs` `f6_the_send_fence_at_exactly_expires_at_is_expired`.
    use crate::plan::PlanSendRefusal as R;
    let (mut twin, root) = s1_twin_with_two();
    twin.record_knob_act(crate::config_knobs::KnobAct::Backups(crate::config_knobs::BackupsKnob::Off)).unwrap();
    let (plan, k, a) = s1_twin_claimed_child(&mut twin, &root, "m1");
    twin.time_high_water = plan.expires_at.clone();
    assert_eq!(
        twin.authorize_send(&k, &a, CaptureBinding::Generation(1), s1_child_binding(&root)).unwrap(),
        SendAuthOutcome::PlanRefused(R::Expired { expires_at: plan.expires_at.clone(), effective_now: plan.expires_at.clone() })
    );
    assert_eq!(twin.get(&k).unwrap().unwrap().status, IntentStatus::Failed);
}

#[test]
fn the_twin_fence_refuses_snapshot_absent_under_backups_on() {
    // The durable half is `tests/plan_admission.rs`
    // `snapshot_absent_refuses_by_name_under_backups_on_and_expiry_survives_a_clock_rollback`.
    use crate::plan::PlanSendRefusal as R;
    let (mut twin, root) = s1_twin_with_two();
    let (plan, k, a) = s1_twin_claimed_child(&mut twin, &root, "m1");
    assert!(plan.backups_on, "backups: on is the default");
    assert_eq!(twin.authorize_send(&k, &a, CaptureBinding::Generation(1), s1_child_binding(&root)).unwrap(), SendAuthOutcome::PlanRefused(R::SnapshotAbsent));
    assert_eq!((twin.get(&k).unwrap().unwrap().status, twin.plan_refusal(&k).unwrap().unwrap().reason), (IntentStatus::Failed, "snapshot_absent".to_string()));
}

#[test]
fn s1_review_f1_the_bypass_notice_column_arrives_in_version_on_an_upgraded_store() {
    // `triage_plan.bypass_notice` arrives through `IN_VERSION_COLUMN_UPGRADES` (SCHEMA_VERSION
    // stays 10): a store an earlier v10 build created without it comes up with the fresh
    // store's shape, the column's CHECK included, and a plan it minted reads back with it.
    let fresh = unique_temp_db_path("s1-f1-notice-fresh");
    drop(SqliteIntentLog::open(&fresh).expect("mint the store"));
    let upgraded = unique_temp_db_path("s1-f1-notice-upgraded");
    drop(SqliteIntentLog::open(&upgraded).expect("mint the store"));
    raw_conn(&upgraded).execute_batch("ALTER TABLE triage_plan DROP COLUMN bypass_notice;").expect("reduce the store to the pre-fold v10 shape");
    let has = |path: &std::path::Path| -> bool {
        raw_conn(path)
            .query_row("SELECT COUNT(*) FROM pragma_table_info('triage_plan') WHERE name = 'bypass_notice';", [], |r| r.get::<_, i64>(0))
            .expect("table_info")
            > 0
    };
    assert!(!has(&upgraded), "precondition: the pre-fold shape");
    drop(SqliteIntentLog::open(&upgraded).expect("open upgrades the table"));
    assert_eq!(schema_fingerprint(&fresh), schema_fingerprint(&upgraded), "the upgraded store is the fresh store's shape");
    for path in [&fresh, &upgraded] {
        assert!(has(path), "{path:?}");
        let sql: String = raw_conn(path).query_row("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'triage_plan';", [], |r| r.get(0)).unwrap();
        assert!(sql.contains("bypass_notice") && sql.contains("CHECK (bypass_notice IS NULL"), "the CHECK rides the column on {path:?}: {sql}");
        let mut log = SqliteIntentLog::open(path).expect("reopen");
        let refs = s1_sqlite_seeded(path, 1);
        let plan = s1_plan_ready(&mut log, &refs);
        assert_eq!(plan.bypass_notice, None, "a screen-lane plan reads back without one on {path:?}");
    }
    std::fs::remove_file(&fresh).ok();
    std::fs::remove_file(&upgraded).ok();
}

#[test]
fn council_r2_s3_1_the_sender_columns_arrive_in_version_on_an_upgraded_store() {
    // `message_header.from_status` /
    // `from_domain` and `plan_member.sender_status` / `sender_addr` / `sender_domain` /
    // `sender_address` arrive through `IN_VERSION_COLUMN_UPGRADES` (SCHEMA_VERSION stays 10).
    // A store an earlier build created
    // comes up with the fresh store's shape, CHECKs included; a header row that build wrote —
    // its From split by the LAST-`<…>` rule, so its `from_addr` is the comment's address — reads
    // `unavailable` and is never re-parsed into a domain; the next ingest of that message
    // rewrites it with the parse.
    use crate::plan::PlanSpec;
    let fresh = unique_temp_db_path("council-r2-sender-fresh");
    drop(SqliteIntentLog::open(&fresh).expect("mint the store"));
    let upgraded = unique_temp_db_path("council-r2-sender-upgraded");
    drop(SqliteIntentLog::open(&upgraded).expect("mint the store"));
    raw_conn(&upgraded)
        .execute_batch(
            "ALTER TABLE plan_member DROP COLUMN sender_address;
                 ALTER TABLE plan_member DROP COLUMN sender_domain;
                 ALTER TABLE plan_member DROP COLUMN sender_local;
                 ALTER TABLE plan_member DROP COLUMN sender_addr;
                 ALTER TABLE plan_member DROP COLUMN sender_status;
                 ALTER TABLE message_header DROP COLUMN from_domain;
                 ALTER TABLE message_header DROP COLUMN from_status;",
        )
        .expect("reduce the store to the pre-fold shape");
    assert_ne!(schema_fingerprint(&upgraded), schema_fingerprint(&fresh), "precondition: the pre-fold shape");
    // The input as the earlier transport stored it.
    raw_conn(&upgraded)
        .execute(
            "INSERT INTO message_header (account, message_ref, mailbox, received_at, from_addr, from_name, subject, seen, flagged)
                 VALUES ('acct', 'm-legacy', 'Inbox', 1758672000000, 'billing@trusted.example', 'Notice <real@evil.example> (routing note', 's', 0, 0);",
            [],
        )
        .expect("a pre-fold header row");
    raw_conn(&upgraded)
        .execute(
            "INSERT INTO message_placement (account, message_ref, email_id, placement) VALUES ('acct', 'm-legacy', 'P-legacy', ?1);",
            [crate::read_model::Placement::Inbox.as_str()],
        )
        .expect("its placement");
    drop(SqliteIntentLog::open(&upgraded).expect("open upgrades the tables"));
    assert_eq!(schema_fingerprint(&fresh), schema_fingerprint(&upgraded), "the upgraded store is the fresh store's shape");
    // The vocabulary CHECK is GONE from BOTH the fresh
    // DDL and the ALTER — a column added fresh here (this store never had it at all, so the
    // ALTER runs in full) carries no `_status IN (` on either path. The CHECK-free ALTER's
    // OWN escape hatch (a column that already existed under a STALE CHECK) is
    // `rebuild_status_check_tables`'s job, witnessed separately.
    for path in [&fresh, &upgraded] {
        for table in ["message_header", "plan_member"] {
            let sql: String = raw_conn(path)
                .query_row("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1;", [table], |r| r.get(0))
                .unwrap();
            assert!(!sql.contains("_status IN ("), "no vocabulary CHECK on {path:?}: {sql}");
        }
    }
    let legacy = |path: &std::path::Path| -> (String, Option<String>) {
        raw_conn(path)
            .query_row("SELECT from_status, from_domain FROM message_header WHERE message_ref = 'm-legacy';", [], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
    };
    assert_eq!(legacy(&upgraded), ("unavailable".to_string(), None), "a pre-fold row is never re-parsed into a domain");
    let root = test_root_key();
    let mut log = SqliteIntentLog::open(&upgraded).expect("reopen");
    let minted = log.mint_plan(&root, PlanSpec { member_refs: vec!["m-legacy".into()], ..PlanSpec::for_test("acct") }).unwrap();
    assert!(minted.presentation.summary.sender_domains.is_empty(), "never the comment's `trusted.example`");
    assert_eq!(minted.presentation.summary.sender_domain_unavailable, 1);
    let stored = log.plan(&minted.plan_id).unwrap().expect("reads back");
    assert_eq!(stored.members[0].display.sender_parse, crate::plan::FrozenSender::Unavailable);
    // The next ingest of the message rewrites the row with the parse.
    let row = crate::read_surface::HeaderSummary {
        provider_id: crate::read_model::ProviderMessageId("P-legacy".into()),
        received_at: 1_758_672_000_000,
        from_addr: "real@evil.example".into(),
        from_name: "Notice".into(),
        subject: "s".into(),
        seen: false,
        flagged: false,
        attachments: crate::read_surface::AttachmentPresence::default(),
    };
    let refs = crate::read_coordinator::ReadCoordinator::open(&upgraded).unwrap().ingest_page("acct", &[row]).unwrap();
    assert_eq!(refs, vec!["m-legacy".to_string()], "the same message, the same ref");
    assert_eq!(legacy(&upgraded), ("ok".to_string(), Some("evil.example".to_string())));
    let again = log.mint_plan(&root, PlanSpec { member_refs: vec!["m-legacy".into()], ..PlanSpec::for_test("acct") }).unwrap();
    assert_eq!(again.presentation.summary.sender_domains, vec![("evil.example".to_string(), 1)]);
    let stored = log.plan(&again.plan_id).unwrap().expect("reads back");
    assert_eq!(
        stored.members[0].display.sender_parse,
        crate::plan::FrozenSender::Parsed { addr: "real@evil.example".into(), local: "real".into(), domain: "evil.example".into() }
    );
    drop(log);
    std::fs::remove_file(&fresh).ok();
    std::fs::remove_file(&upgraded).ok();
}

/// A store
/// whose `message_header`/`plan_member` still carry the STALE vocabulary CHECK (the earlier
/// three-value spelling — `upgrade_in_version_columns`'s "column present, skip" guard cannot
/// see this: the ALTER that would carry today's shape never runs again once the column
/// exists) is REBUILT, wholesale, the first time this build opens it — never a per-token
/// migration. RED before `rebuild_status_check_tables` existed: a group address
/// (`SenderStatus::Unsupported`) hits the stale CHECK on ingest.
#[test]
fn a_stale_status_check_is_rebuilt_wholesale_never_a_per_token_migration() {
    use crate::plan::PlanSpec;
    let path = unique_temp_db_path("a2-tar-pit-q4");
    drop(SqliteIntentLog::open(&path).expect("mint the store")); // today's shape, everything else current
    // Reduce message_header/plan_member to the earlier shape (before this
    // change): the THREE-value CHECK `IN_VERSION_COLUMN_UPGRADES` wrote back then, and no
    // `sender_address` column at all (added later by class C). SQLite's own documented
    // rebuild procedure, run BY HAND here to SIMULATE an earlier build's bytes — never a
    // shortcut this test itself needs blessed.
    raw_conn(&path)
        .execute_batch(
            "PRAGMA foreign_keys=OFF;
                 BEGIN;
                 CREATE TABLE message_header_pre_fold (
                     account TEXT NOT NULL, message_ref TEXT NOT NULL, mailbox TEXT NOT NULL,
                     received_at INTEGER NOT NULL, from_addr TEXT NOT NULL, from_name TEXT NOT NULL,
                     subject TEXT NOT NULL, seen INTEGER NOT NULL DEFAULT 0, flagged INTEGER NOT NULL DEFAULT 0,
                     ingest_revision INTEGER NOT NULL DEFAULT 0,
                     from_status TEXT NOT NULL DEFAULT 'unavailable' CHECK (from_status IN ('ok','unavailable','malformed')),
                     from_domain TEXT CHECK ((from_domain IS NOT NULL) = (from_status = 'ok')),
                     PRIMARY KEY (account, message_ref)
                 );
                 INSERT INTO message_header_pre_fold
                     (rowid, account, message_ref, mailbox, received_at, from_addr, from_name, subject,
                      seen, flagged, ingest_revision, from_status, from_domain)
                     SELECT rowid, account, message_ref, mailbox, received_at, from_addr, from_name, subject,
                            seen, flagged, ingest_revision, from_status, from_domain FROM message_header;
                 DROP TABLE message_header;
                 ALTER TABLE message_header_pre_fold RENAME TO message_header;
                 CREATE TABLE plan_member_pre_fold (
                     plan_id TEXT NOT NULL REFERENCES triage_plan(plan_id), message_ref TEXT NOT NULL,
                     sender TEXT NOT NULL, subject TEXT NOT NULL, date TEXT NOT NULL, size INTEGER,
                     observed_state TEXT NOT NULL, forward_target TEXT NOT NULL,
                     sender_status TEXT NOT NULL DEFAULT 'unavailable' CHECK (sender_status IN ('ok','unavailable','malformed')),
                     sender_addr TEXT CHECK ((sender_addr IS NOT NULL) = (sender_status = 'ok')),
                     sender_domain TEXT CHECK ((sender_domain IS NOT NULL) = (sender_status = 'ok')),
                     PRIMARY KEY (plan_id, message_ref)
                 );
                 INSERT INTO plan_member_pre_fold
                     (plan_id, message_ref, sender, subject, date, size, observed_state, forward_target,
                      sender_status, sender_addr, sender_domain)
                     SELECT plan_id, message_ref, sender, subject, date, size, observed_state, forward_target,
                            sender_status, sender_addr, sender_domain FROM plan_member;
                 DROP TABLE plan_member;
                 ALTER TABLE plan_member_pre_fold RENAME TO plan_member;
                 COMMIT;
                 PRAGMA foreign_keys=ON;",
        )
        .expect("reduce to the pre-fold shape");
    // The pin the earlier binary wrote (`SCHEMA_VERSION` — unchanged by this whole change,
    // every step in it is IN-VERSION accretion).
    raw_conn(&path).execute_batch(&format!("PRAGMA user_version = {SCHEMA_VERSION};")).expect("stamp the pre-fold pin's own version");
    let sql_of = |table: &str| -> String {
        raw_conn(&path)
            .query_row("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1;", [table], |r| r.get(0))
            .unwrap()
    };
    assert!(sql_of("message_header").contains("CHECK (from_status IN ('ok','unavailable','malformed'))"), "precondition: the stale three-value CHECK");
    assert!(sql_of("plan_member").contains("CHECK (sender_status IN ('ok','unavailable','malformed'))"), "precondition: the stale three-value CHECK");
    let has_sender_address: i64 = raw_conn(&path)
        .query_row("SELECT COUNT(*) FROM pragma_table_info('plan_member') WHERE name = 'sender_address';", [], |r| r.get(0))
        .unwrap();
    assert_eq!(has_sender_address, 0, "precondition: no sender_address column yet either — this store predates class C too");
    // One pre-existing row, so column-preservation is witnessed on REAL data, not an empty
    // table.
    raw_conn(&path)
        .execute(
            "INSERT INTO message_header (account, message_ref, mailbox, received_at, from_addr, from_name, subject, seen, flagged)
                 VALUES ('acct', 'm-preexisting', 'Inbox', 1758672000000, 'real@evil.example', 'Notice', 's-preexisting', 1, 0);",
            [],
        )
        .expect("a pre-existing header row");
    raw_conn(&path)
        .execute(
            "INSERT INTO message_placement (account, message_ref, email_id, placement) VALUES ('acct', 'm-preexisting', 'P-preexisting', ?1);",
            [crate::read_model::Placement::Inbox.as_str()],
        )
        .expect("its placement");

    // OPEN THROUGH THE REAL CHOKEPOINT — the one door this whole class rides. Opening itself
    // never refuses; the rebuild (or its absence, earlier) shows up on the FIRST write that
    // needs the shape it changes.
    let mut log = SqliteIntentLog::open(&path).expect("open");
    let root = test_root_key();
    let group_row = crate::read_surface::HeaderSummary {
        provider_id: crate::read_model::ProviderMessageId("P-group".into()),
        received_at: 1_758_672_001_000,
        from_addr: "Authors:user@target.example;".into(),
        from_name: String::new(),
        subject: "s-group".into(),
        seen: false,
        flagged: false,
        attachments: crate::read_surface::AttachmentPresence::default(),
    };
    let refs = crate::read_coordinator::ReadCoordinator::open(&path)
        .unwrap()
        .ingest_page("acct", &[group_row])
        .expect("the header write: `Unsupported` fits the rebuilt (shape-only) column — RED before the rebuild existed, a CHECK violation on the stale three-value list");
    assert_eq!(refs.len(), 1);
    let group_ref = refs[0].clone();
    let minted = log
        .mint_plan(&root, PlanSpec { member_refs: vec![group_ref], ..PlanSpec::for_test("acct") })
        .expect("the plan-member write: same shape, same rebuild");
    assert_eq!(minted.presentation.summary.sender_header_unsupported, 1, "the group address froze Unsupported, never a CHECK refusal");

    // Post-conditions: the rebuild's own promises.
    assert!(!sql_of("message_header").contains("_status IN ("), "message_header carries no vocabulary CHECK after the rebuild");
    assert!(!sql_of("plan_member").contains("_status IN ("), "plan_member carries no vocabulary CHECK after the rebuild");
    let preexisting: (String, String, i64, String) = raw_conn(&path)
        .query_row(
            "SELECT from_addr, from_name, seen, subject FROM message_header WHERE message_ref = 'm-preexisting';",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap();
    assert_eq!(
        preexisting,
        ("real@evil.example".to_string(), "Notice".to_string(), 1, "s-preexisting".to_string()),
        "every pre-existing column value survives the rebuild"
    );
    let header_count: i64 = raw_conn(&path).query_row("SELECT COUNT(*) FROM message_header;", [], |r| r.get(0)).unwrap();
    assert_eq!(header_count, 2, "the pre-existing row AND the new one — nothing lost, nothing duplicated");
    // The indexes/triggers the one-source DDL names all survive the rebuild (dropped along
    // with the old table when it was, recreated by the post-rebuild `schema_ddl()` re-run).
    let names: std::collections::BTreeSet<String> = raw_conn(&path)
        .prepare("SELECT name FROM sqlite_master WHERE type IN ('index','trigger') AND tbl_name IN ('message_header','plan_member');")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    for expected in [
        "idx_folder",
        "message_header_ai",
        "message_header_ad",
        "message_header_au",
        "message_header_ingest_revision_ai",
        "message_header_ingest_revision_au",
        "plan_member_no_update",
        "plan_member_no_delete",
        "plan_member_no_replace",
        "plan_member_within_member_count",
    ] {
        assert!(names.contains(expected), "{expected} survives the rebuild: {names:?}");
    }
    drop(log);
    std::fs::remove_file(&path).ok();
}

/// The database polices SHAPE only now — the closed
/// token table in code (`mailbox::SenderStatus::from_token`) is the ONE vocabulary authority,
/// so a token it does not know MUST still refuse, fail-closed, never a silent default. Both
/// read doors already called `from_token` before this fold (`read_member_facts_in` at mint;
/// the plan_member read-back at `plan()`); this forces a token past the now-shape-only CHECK
/// (which would have refused it before A2) to confirm the CODE-side refusal still holds.
#[test]
fn a2_the_read_path_refuses_an_unknown_status_token_fail_closed_never_a_silent_default() {
    use crate::plan::PlanSpec;
    let path = unique_temp_db_path("a2-unknown-token-fail-closed");
    let mut log = SqliteIntentLog::open(&path).expect("mint the store");
    let refs = s1_sqlite_seeded(&path, 1);
    raw_conn(&path)
        .execute(
            "UPDATE message_header SET from_status = 'quarantined', from_domain = NULL WHERE message_ref = ?1;",
            [&refs[0]],
        )
        .expect("force an unrecognized token past the (now shape-only) CHECK — from_domain \
                 cleared too, to satisfy the cross-column shape CHECK the rebuild leaves intact");
    let root = test_root_key();
    let err = log
        .mint_plan(&root, PlanSpec { member_refs: refs.clone(), ..PlanSpec::for_test("acct") })
        .expect_err("an unrecognized from_status token is refused, never silently read as unavailable/ok");
    assert!(format!("{err:?}").contains("unknown sender status"), "{err:?}");
    drop(log);
    std::fs::remove_file(&path).ok();
}

/// The SECOND read door — `plan()`'s read-back of an
/// already-minted `plan_member` row (distinct from the mint-time door witnessed just above,
/// which never gets far enough to write `plan_member` at all once `from_status` refuses).
/// A plan mints clean here (its member's sender parses `Ok`), so `plan_member.sender_status`
/// is written `'ok'` — then this corrupts THAT column directly (as the now-shape-only CHECK
/// on `sender_status` alone would have refused before A2, but no longer does) and confirms
/// `SenderStatus::from_token`'s fail-closed refusal at the `plan()` door still fires, named
/// `does_not_read_back` (lib.rs, the `plan_member` read-back's `sender_parse` line).
#[test]
fn a2_the_plan_read_back_door_also_refuses_an_unknown_sender_status_token_fail_closed() {
    use crate::plan::PlanSpec;
    let path = unique_temp_db_path("a2-unknown-token-plan-readback");
    let mut log = SqliteIntentLog::open(&path).expect("mint the store");
    let refs = s1_sqlite_seeded(&path, 1);
    let root = test_root_key();
    let minted = log
        .mint_plan(&root, PlanSpec { member_refs: refs.clone(), ..PlanSpec::for_test("acct") })
        .expect("a well-formed sender mints clean");
    // `plan_member` is append-only by design (`plan_member_no_update`'s own trigger, named in
    // the rebuild's own survivor list above) — a real corruption never goes through an UPDATE
    // either, so this simulates one the SAME way the sibling `a2_tar_pit_q4` test simulates a
    // earlier-shape store: drop the guard, force the byte, put the IDENTICAL guard straight back
    // before the read door below ever runs. Never a shortcut this test itself needs blessed.
    raw_conn(&path)
        .execute_batch(&format!(
            "DROP TRIGGER plan_member_no_update;
                 UPDATE plan_member SET sender_status = 'quarantined', sender_local = NULL, sender_addr = NULL, sender_domain = NULL
                  WHERE plan_id = '{}';
                 CREATE TRIGGER plan_member_no_update BEFORE UPDATE ON plan_member
                     BEGIN SELECT RAISE(ABORT, 'plan_member is append-only'); END;",
            minted.plan_id.0
        ))
        .expect("force an unrecognized token past the (now shape-only) sender_status CHECK, \
                 guard dropped and replaced around the one forced write");
    let err = log
        .plan(&minted.plan_id)
        .expect_err("an unrecognized sender_status token does not read back, never silently ok/unavailable");
    assert!(format!("{err:?}").contains("is not a frozen sender"), "{err:?}");
    drop(log);
    std::fs::remove_file(&path).ok();
}

#[test]
fn the_twin_approval_door_refuses_an_expired_or_epoch_moved_plan_by_name() {
    // The durable half is `tests/plan_admission.rs`
    // `f7_the_approval_door_refuses_an_expired_or_epoch_moved_plan_by_name`.
    use crate::plan::{PlanSpec, PlanStoreError, RenderedView};
    let (mut twin, root) = s1_twin_with_two();
    let minted = twin.mint_plan(&root, PlanSpec { member_refs: vec!["m1".into()], ..PlanSpec::for_test("acct") }).unwrap();
    let plan = twin.plan(&minted.plan_id).unwrap().unwrap();
    twin.time_high_water = plan.expires_at.clone();
    assert_eq!(
        twin.record_approval(&root, &minted.plan_id, "clinton", RenderedView::FullList(minted.presentation.clone())).unwrap_err(),
        PlanStoreError::Expired { expires_at: plan.expires_at.clone(), effective_now: plan.expires_at.clone() }
    );
    assert_eq!(twin.approval(&minted.plan_id).unwrap(), None);
    assert_eq!(twin.time_high_water, plan.expires_at);
    let second = twin.mint_plan(&root, PlanSpec { member_refs: vec!["m2".into()], ..PlanSpec::for_test("acct") }).unwrap();
    twin.sever("authority:test", "2100-01-01T00:00:00Z").unwrap();
    assert_eq!(
        twin.record_approval(&root, &second.plan_id, "clinton", RenderedView::FullList(second.presentation.clone())).unwrap_err(),
        PlanStoreError::EpochMismatch { plan: 1, current: 2 }
    );
    assert_eq!(twin.approval(&second.plan_id).unwrap(), None);
}

#[test]
fn an_expired_approval_refusal_commits_the_latch_advance_on_both_stores() {
    // The second half: the approval door's expired refusal COMMITS the sticky
    // clock's latch advance, as `start_episode`'s `Ok(Err)` refusals do (§4.4). Observable only
    // when the wall clock itself passes `expires_at` with the latch behind it: a 1-second plan,
    // then a real wait, so the refusal's `effective_now` is the wall clock — above the latch the
    // mint left — and the latch must read it afterwards (a rolled-back refusal leaves it at
    // `minted_at`).
    use crate::plan::{PlanSpec, PlanStoreError, RenderedView};
    let path = unique_temp_db_path("s1-review-f7-latch");
    let mut sqlite = SqliteIntentLog::open(&path).unwrap();
    let refs = s1_sqlite_seeded(&path, 1);
    let root = test_root_key();
    let durable = sqlite.mint_plan(&root, PlanSpec { member_refs: refs.clone(), ttl_seconds: 1, ..PlanSpec::for_test("acct") }).unwrap();
    let durable_minted_at = sqlite.plan(&durable.plan_id).unwrap().unwrap().minted_at;
    let mut twin = s1_twin_seeded(&["m1"]);
    let mirrored = twin.mint_plan(&root, PlanSpec { member_refs: vec!["m1".into()], ttl_seconds: 1, ..PlanSpec::for_test("acct") }).unwrap();
    let twin_minted_at = twin.plan(&mirrored.plan_id).unwrap().unwrap().minted_at;
    std::thread::sleep(std::time::Duration::from_millis(2_200));
    match sqlite.record_approval(&root, &durable.plan_id, "clinton", RenderedView::FullList(durable.presentation.clone())).unwrap_err() {
        PlanStoreError::Expired { effective_now, .. } => {
            assert!(effective_now > durable_minted_at, "the wall clock passed the plan: {effective_now} vs {durable_minted_at}");
            let latch: String = raw_conn(&path).query_row("SELECT max_seen FROM time_high_water WHERE id = 1", [], |r| r.get(0)).unwrap();
            assert_eq!(latch, effective_now, "the refusal committed its latch advance");
        }
        other => panic!("expected Expired, got {other:?}"),
    }
    match twin.record_approval(&root, &mirrored.plan_id, "clinton", RenderedView::FullList(mirrored.presentation.clone())).unwrap_err() {
        PlanStoreError::Expired { effective_now, .. } => {
            assert!(effective_now > twin_minted_at, "{effective_now} vs {twin_minted_at}");
            assert_eq!(twin.time_high_water, effective_now, "the twin keeps its latch advance");
        }
        other => panic!("expected Expired, got {other:?}"),
    }
    std::fs::remove_file(&path).ok();
}

/// a connector whose provider STATE follows the effect — every message starts in
/// the Inbox (INBOX set, TRASH and SPAM clear); `apply` drives the frozen basis's targets,
/// `restore` writes the captured `P` back, `observe` reads the state — so an undo meets the
/// forward effect as the provider holds it (never the fixture's constant answer).
struct S1EffectMirror {
    state: std::cell::RefCell<std::collections::BTreeMap<String, std::collections::BTreeMap<String, bool>>>,
    restores: std::cell::Cell<usize>,
}
impl S1EffectMirror {
    fn new() -> Self {
        Self { state: std::cell::RefCell::new(std::collections::BTreeMap::new()), restores: std::cell::Cell::new(0) }
    }
    fn atoms_of(&self, message_ref: &str) -> std::collections::BTreeMap<String, bool> {
        self.state.borrow().get(message_ref).cloned().unwrap_or_else(|| {
            [("membership:INBOX", true), ("label:TRASH", false), ("label:SPAM", false)].into_iter().map(|(a, v)| (a.to_string(), v)).collect()
        })
    }
    fn write(&self, message_ref: &str, atoms: &std::collections::BTreeMap<String, bool>) {
        let mut now = self.atoms_of(message_ref);
        now.extend(atoms.iter().map(|(a, v)| (a.clone(), *v)));
        self.state.borrow_mut().insert(message_ref.to_string(), now);
    }
}
impl Connector for S1EffectMirror {
    fn apply(&self, command: &Command, basis: &prestate::FrozenBasis) -> Result<(), ConnectorError> {
        self.write(action_message_ref(&command.action), &basis.atom_targets);
        Ok(())
    }
    fn resolve_basis(&self, command: &Command) -> Result<prestate::FrozenBasis, ResolveBasisError> {
        Ok(fixture_basis(command))
    }
    fn observe(&self, command: &Command, basis: &prestate::FrozenBasis) -> Result<prestate::Observation, ConnectorError> {
        let now = self.atoms_of(action_message_ref(&command.action));
        Ok(prestate::Observation {
            native_resource_key: basis.native_resource_key.clone(),
            atoms: basis.touched_atoms.keys().map(|a| (a.clone(), now.get(a).copied().unwrap_or(false))).collect(),
            request_id: None,
            provider_label_vector: None,
        })
    }
    fn restore(&self, command: &Command, basis: &prestate::FrozenBasis, p: &std::collections::BTreeMap<String, bool>) -> Result<(), ConnectorError> {
        fixture_restore(basis, p)?;
        self.restores.set(self.restores.get() + 1);
        self.write(action_message_ref(&command.action), p);
        Ok(())
    }
}

/// UNDO of an `Applied` plan child, on both stores, for both RED verbs (Trash's
/// undo is Untrash, MarkSpam's is UnmarkSpam — the fixture's two-atom closure covers all four):
/// the restore is dispatched exactly once, the parent reads `Undone` and the member
/// `Terminal(Undone)`.
#[test]
fn undo_of_an_applied_plan_child_restores_once_on_both_stores_for_both_red_verbs() {
    use crate::plan::{MemberState, PlanSpec, PlanVerb, RenderedView};
    fn drive<L: IntentLog>(mut log: L, member: &str, verb: PlanVerb, store: &str) {
        let root = test_root_key();
        log.record_knob_act(crate::config_knobs::KnobAct::Backups(crate::config_knobs::BackupsKnob::Off)).unwrap();
        let minted = log.mint_plan(&root, PlanSpec { member_refs: vec![member.to_string()], verb, ..PlanSpec::for_test("acct") }).unwrap();
        log.record_approval(&root, &minted.plan_id, "clinton", RenderedView::FullList(minted.presentation.clone())).unwrap();
        log.start_episode(&minted.plan_id).unwrap();
        let plan = log.plan(&minted.plan_id).unwrap().unwrap();
        let mut bus = s1_plan_bus(log, S1EffectMirror::new());
        assert_eq!(bus.preflight_plan(&plan.plan_id).unwrap(), crate::plan::PreflightOutcome::Ready, "{store} {verb:?}");
        bus.apply_plan_member(&plan.plan_id, member).unwrap();
        let key = Command::plan_child(&plan, member).idempotency_key;
        assert_eq!(bus.log().get(&key).unwrap().unwrap().status, IntentStatus::Applied, "{store} {verb:?}");
        assert_eq!(bus.undo(&key), Ok(()), "{store} {verb:?}");
        assert_eq!(bus.connector().restores.get(), 1, "{store} {verb:?}: the restore is dispatched exactly once");
        assert_eq!(bus.log().get(&key).unwrap().unwrap().status, IntentStatus::Undone, "{store} {verb:?}");
        assert_eq!(bus.plan_member_states(&plan.plan_id).unwrap(), vec![(member.to_string(), MemberState::Terminal(IntentStatus::Undone))], "{store} {verb:?}");
        assert!(bus.connector().atoms_of(member)["membership:INBOX"], "{store} {verb:?}: the provider holds the captured pre-state again");
    }
    for verb in [PlanVerb::Trash, PlanVerb::MarkSpam] {
        drive(s1_twin_seeded(&["m1"]), "m1", verb, "memory");
        let path = unique_temp_db_path(&format!("s1-review-f4-undo-{}", verb.as_token()));
        let log = SqliteIntentLog::open(&path).unwrap();
        let refs = s1_sqlite_seeded(&path, 1);
        drive(log, &refs[0], verb, "sqlite");
        std::fs::remove_file(&path).ok();
    }
}
