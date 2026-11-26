//! The plan store half, witnessed on the durable store.
mod common;

use aruna::commitment::derive_account_key;
use aruna::config_knobs::*;
use aruna::key_custody::{root_key_verified, InMemoryCustody};
use aruna::plan::*;
use aruna::{IntentLog, SqliteIntentLog};
use common::{seed, summary, temp_db};

/// Two messages: a named sender whose subject carries a bidi override (the chokepoint strips it)
/// and a bare-address sender.
fn seed_two(path: &std::path::Path) -> Vec<String> {
    seed(
        path,
        &[
            summary("P-1", 1_758_672_000_000, "Deals", "deals@shop.example", "Your order\u{202E}gpj.exe"),
            summary("P-2", 1_758_585_600_000, "", "news@list.example", "Weekly digest"),
        ],
    )
}

fn sorted(mut v: Vec<String>) -> Vec<String> {
    v.sort();
    v
}

fn raw(path: &std::path::Path) -> rusqlite::Connection {
    rusqlite::Connection::open(path).unwrap()
}

fn count(path: &std::path::Path, table: &str) -> i64 {
    raw(path).query_row(&format!("SELECT COUNT(*) FROM {table};"), [], |r| r.get(0)).unwrap()
}

#[test]
fn mint_plan_freezes_members_from_the_store_and_the_knobs_in_force_and_reads_back_identically() {
    let path = temp_db("mint");
    let mut log = SqliteIntentLog::open(&path).unwrap();
    let refs = seed_two(&path);
    let custody = InMemoryCustody::new();
    let root = root_key_verified(&custody, &mut log).unwrap();
    let spec = PlanSpec { account: "acct".into(), provider_principal: "me@e".into(), grant_generation: 2, verb: PlanVerb::Trash, member_refs: vec![refs[1].clone(), refs[0].clone(), refs[0].clone()], rationale: Some("bulk trash".into()), ttl_seconds: 3600 };
    let minted = log.mint_plan(&root, spec).unwrap();
    let plan = log.plan(&minted.plan_id).unwrap().expect("stored");
    assert_eq!(plan.members.iter().map(|m| m.message_ref.clone()).collect::<Vec<_>>(), sorted(refs.clone()), "deduplicated and canonical");
    let first = plan.member(&refs[0]).unwrap();
    assert!(first.observed_state["membership:INBOX"]);
    assert!(!first.observed_state["label:TRASH"]);
    assert!(first.forward_target["label:TRASH"], "the forward target is the verb's closure");
    assert!(!first.forward_target["membership:INBOX"]);
    // The frozen display is the store's NORMALIZED row: the bidi override never reaches it.
    assert_eq!(first.display.subject, "Your ordergpj.exe");
    // the name half and the address half are frozen SEPARATELY now —
    // never one composed string — so the row can isolate them into two `<bdi>`s.
    assert_eq!(first.display.sender, "Deals");
    assert_eq!(first.display.sender_address, "<deals@shop.example>");
    assert_eq!(first.display.date, "2025-09-24T00:00:00Z", "received_at is epoch MILLISECONDS");
    assert_eq!(first.display.size, None);
    assert_eq!(plan.member(&refs[1]).unwrap().display.sender, "", "no display name ⇒ empty");
    assert_eq!(plan.member(&refs[1]).unwrap().display.sender_address, "news@list.example", "no display name ⇒ the bare address");
    assert_eq!(plan.admission_lane, AdmissionLane::PerMember);
    assert_eq!(plan.approval_mode, ApprovalMode::FullList);
    assert_eq!(plan.coverage_generation, 0);
    assert!(plan.backups_on);
    assert_eq!(plan.grant_generation, 2);
    assert_eq!(plan.provider_principal, "me@e");
    assert_eq!(plan.rationale.as_deref(), Some("bulk trash"));
    assert_eq!(plan.control_epoch, log.control_epoch().unwrap());
    assert_eq!(plan.key_ref.namespace_key_id(), "photon.account.acct");
    assert_eq!(minted.presentation.rows.len(), 2);
    assert_eq!(minted.presentation.header.tier, PLAN_TIER);
    assert_eq!(minted.presentation.header.warning, None);
    assert_eq!(plan.digests.presentation, minted.presentation_digest);
    assert_eq!(plan.digests.presentation_view, minted.presentation, "the read-back presentation is the minted one, byte for byte");
    assert_eq!(minted.effective_k, None);
    // Expiry is minted_at + ttl on the sticky clock's own instants.
    let secs = |t: &str| aruna::prestate::unix_secs_from_rfc3339_utc(t).unwrap();
    assert_eq!(secs(&plan.expires_at) - secs(&plan.minted_at), 3600);
    // The digests re-derive under the ACCOUNT key from the stored randomizers: the presentation
    // commitment over the read-back view IS the stored tag.
    let account_key = derive_account_key(&root, "acct").unwrap();
    assert_eq!(view_commitment(&account_key, &plan.key_ref, &plan.digests, &RenderedView::FullList(plan.digests.presentation_view.clone())).unwrap(), plan.digests.presentation);
    // Unknown member ⇒ refuse at mint, nothing stored.
    let bad = PlanSpec { member_refs: vec![refs[0].clone(), "nope".into()], ..PlanSpec::for_test("acct") };
    assert_eq!(log.mint_plan(&root, bad).unwrap_err(), PlanStoreError::UnknownMember("nope".into()));
    assert_eq!((count(&path, "triage_plan"), count(&path, "plan_member")), (1, 2), "the refused mint wrote nothing");
    // A ref of ANOTHER account is unknown here too — the read is account-scoped.
    let other = PlanSpec { member_refs: vec![refs[0].clone()], ..PlanSpec::for_test("other") };
    assert_eq!(log.mint_plan(&root, other).unwrap_err(), PlanStoreError::UnknownMember(refs[0].clone()));
    // A zero TTL and an empty member list refuse by name.
    assert_eq!(log.mint_plan(&root, PlanSpec { member_refs: vec![refs[0].clone()], ttl_seconds: 0, ..PlanSpec::for_test("acct") }).unwrap_err(), PlanStoreError::TtlZero);
    assert_eq!(log.mint_plan(&root, PlanSpec::for_test("acct")).unwrap_err(), PlanStoreError::Refused(PlanRefusal::EmptyMembers));
    assert_eq!(count(&path, "triage_plan"), 1);
    assert_eq!(log.plan(&PlanId("0".repeat(32))).unwrap(), None);
}

#[test]
fn a_plan_minted_under_summary_sample_freezes_the_aggregate_lane_and_effective_k() {
    let path = temp_db("agg");
    let mut log = SqliteIntentLog::open(&path).unwrap();
    let refs = seed_two(&path);
    let generation = log.record_knob_act(KnobAct::ApprovalMode(ApprovalModeKnob::SummarySample { configured_k: 5 })).unwrap();
    assert!(generation > 1);
    let root = root_key_verified(&InMemoryCustody::new(), &mut log).unwrap();
    let minted = log.mint_plan(&root, PlanSpec { member_refs: refs.clone(), ..PlanSpec::for_test("acct") }).unwrap();
    let plan = log.plan(&minted.plan_id).unwrap().unwrap();
    assert_eq!(plan.admission_lane, AdmissionLane::Aggregate);
    assert_eq!(plan.approval_mode, ApprovalMode::SummarySample { configured_k: 5, effective_k: 2 }, "effective_k = min(5, 2)");
    assert_eq!(minted.admission_lane, AdmissionLane::Aggregate);
    assert_eq!(minted.effective_k, Some(2));
}

#[test]
fn red_bypass_on_freezes_the_bypassed_lane_with_the_generation_in_force() {
    let path = temp_db("bypass");
    let mut log = SqliteIntentLog::open(&path).unwrap();
    let refs = seed_two(&path);
    let generation = log.record_knob_act(KnobAct::RedBypass(RedBypassKnob::On)).unwrap();
    let root = root_key_verified(&InMemoryCustody::new(), &mut log).unwrap();
    let minted = log.mint_plan(&root, PlanSpec { member_refs: refs.clone(), ..PlanSpec::for_test("acct") }).unwrap();
    let plan = log.plan(&minted.plan_id).unwrap().unwrap();
    assert_eq!(plan.admission_lane, AdmissionLane::Bypassed { bypass_config_generation: generation });
    // The bypass lane has no screen: its evidence binds the plan's own presentation digest and
    // the bypass generation the plan FROZE at mint (still the one in force here).
    let evidence = log.record_approval(&root, &minted.plan_id, "mechanical", RenderedView::FullList(minted.presentation.clone())).unwrap();
    assert_eq!(evidence.comprehension, Comprehension::Bypassed { bypass_config_generation: generation });
    assert_eq!(evidence.view_digest, plan.digests.presentation);
    assert_eq!(log.approval(&minted.plan_id).unwrap(), Some(evidence));
    // A bypass knob flip since mint: the evidence binds the generation the
    // plan FROZE, `validate_evidence` compares it with the one in force now, and the approval
    // refuses BY NAME with both numbers — nothing is written.
    let minted2 = log.mint_plan(&root, PlanSpec { member_refs: refs.clone(), ..PlanSpec::for_test("acct") }).unwrap();
    let flipped = log.record_knob_act(KnobAct::RedBypass(RedBypassKnob::Off)).unwrap();
    assert_eq!(
        log.record_approval(&root, &minted2.plan_id, "mechanical", RenderedView::FullList(minted2.presentation.clone())).unwrap_err(),
        PlanStoreError::Refused(PlanRefusal::BypassGenerationMismatch { plan: generation, current: flipped })
    );
    assert_eq!(log.approval(&minted2.plan_id).unwrap(), None);
    assert_eq!(count(&path, "approval_evidence"), 1, "only the first plan's evidence");
}

#[test]
fn the_frozen_sender_is_normalized_display_text_and_the_header_identity_stays_raw() {
    // (REAL — a remote sender's address bytes reach the frozen display). The
    // plan's `sender` is a DISPLAY COPY of `Name <addr>` (the member's identity is its
    // `message_ref`), so its address half passes the display chokepoint too; the header row's
    // `from_addr` IDENTITY column stays exactly as the provider sent it. Seeded through the ingest
    // door (`ingest_page`), which stores `from_addr` raw by contract.
    let path = temp_db("sender-normalized");
    let mut log = SqliteIntentLog::open(&path).unwrap();
    let (rlo, zwsp) = ('\u{202e}', '\u{200b}');
    let named_addr = format!("deals{rlo}moc.evil@shop{zwsp}.example");
    let bare_addr = format!("news{rlo}@list{zwsp}.example");
    let refs = seed(&path, &[summary("P-1", 1_758_672_000_000, "Deals", &named_addr, "s1"), summary("P-2", 1_758_585_600_000, "", &bare_addr, "s2")]);
    let root = root_key_verified(&InMemoryCustody::new(), &mut log).unwrap();
    let minted = log.mint_plan(&root, PlanSpec { member_refs: refs.clone(), ..PlanSpec::for_test("acct") }).unwrap();
    let plan = log.plan(&minted.plan_id).unwrap().unwrap();
    let hostile = |s: &str| s.contains(rlo) || s.contains(zwsp);
    for r in &refs {
        let member = plan.member(r).expect("the member still resolves by its message_ref");
        assert!(!hostile(&member.display.sender), "frozen sender carries a Cf codepoint: {:?}", member.display.sender);
        // the address half is its OWN frozen field now — it passes the
        // SAME display chokepoint, so it is checked here too, never only the name half.
        assert!(
            !hostile(&member.display.sender_address),
            "frozen sender address carries a Cf codepoint: {:?}",
            member.display.sender_address
        );
    }
    assert_eq!(plan.member(&refs[0]).unwrap().display.sender, "Deals");
    assert_eq!(plan.member(&refs[0]).unwrap().display.sender_address, "<dealsmoc.evil@shop.example>");
    assert_eq!(plan.member(&refs[1]).unwrap().display.sender, "");
    assert_eq!(plan.member(&refs[1]).unwrap().display.sender_address, "news@list.example");
    for row in &minted.presentation.rows {
        assert!(!hostile(&row.sender), "presentation row sender: {:?}", row.sender);
        assert!(!hostile(&row.sender_address), "presentation row sender address: {:?}", row.sender_address);
    }
    for (domain, _) in &minted.presentation.summary.sender_domains {
        assert!(!hostile(domain), "sender domain: {domain:?}");
    }
    // (-1): the domains are the PARSED senders' now, and an address
    // carrying a codepoint that cannot be shown (the RLO, the ZWSP) is not a mailbox a human can
    // read — it is `malformed`, counted, never a domain the summary names. Before the fold the
    // summary named `shop.example` / `list.example`: the NORMALIZED display's domains, which are
    // not the addresses' own (`shop\u{200b}.example` renders as, and normalizes to, `shop.example`).
    assert!(minted.presentation.summary.sender_domains.is_empty(), "no domain is named for an address a human cannot read faithfully");
    assert_eq!(minted.presentation.summary.sender_header_malformed, 2);
    // The identity column is untouched: both raw addresses are still in `message_header`.
    let stored: Vec<String> = raw(&path)
        .prepare("SELECT from_addr FROM message_header WHERE account = 'acct' ORDER BY message_ref;")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(sorted(stored), sorted(vec![named_addr, bare_addr]), "from_addr is identity: stored exactly as sent");
}

#[test]
fn a_rendered_full_list_whose_warning_is_not_the_minted_one_refuses_view_mismatch_and_writes_nothing() {
    // The store witness for one approval-bound frame: the §4.7 warning,
    // varied ALONE (coverage, rows and every other field held). A renderer that softened the
    // warning did not show the plan the human is approving.
    let path = temp_db("warning-view");
    let mut log = SqliteIntentLog::open(&path).unwrap();
    let refs = seed_two(&path);
    log.record_knob_act(KnobAct::Backups(BackupsKnob::Off)).unwrap();
    let root = root_key_verified(&InMemoryCustody::new(), &mut log).unwrap();
    let minted = log.mint_plan(&root, PlanSpec { member_refs: refs, ..PlanSpec::for_test("acct") }).unwrap();
    assert_eq!(minted.presentation.header.warning.as_deref(), Some(TRASH_UNCOVERED_WARNING));
    let mut softened = minted.presentation.clone();
    softened.header.warning = Some("snapshot recovery is OFF".into());
    assert_eq!(
        log.record_approval(&root, &minted.plan_id, "clinton", RenderedView::FullList(softened)).unwrap_err(),
        PlanStoreError::Refused(PlanRefusal::ViewMismatch)
    );
    assert_eq!(log.approval(&minted.plan_id).unwrap(), None);
    assert_eq!(count(&path, "approval_evidence"), 0, "nothing written");
    // The minted render admits: the refusal was the warning's alone.
    log.record_approval(&root, &minted.plan_id, "clinton", RenderedView::FullList(minted.presentation.clone())).unwrap();
}

#[test]
fn an_aggregate_approval_with_configured_k_above_the_member_count_admits_at_the_effective_k() {
    // Configured_k 5 over two members freezes effective_k 2; the approval's
    // sample, its k and the evidence all run at the EFFECTIVE k (the sample degenerates to every
    // member, in canonical order), never the configured one.
    let path = temp_db("agg-k-above");
    let mut log = SqliteIntentLog::open(&path).unwrap();
    let refs = seed_two(&path);
    log.record_knob_act(KnobAct::ApprovalMode(ApprovalModeKnob::SummarySample { configured_k: 5 })).unwrap();
    let root = root_key_verified(&InMemoryCustody::new(), &mut log).unwrap();
    let minted = log.mint_plan(&root, PlanSpec { member_refs: refs.clone(), ..PlanSpec::for_test("acct") }).unwrap();
    let plan = log.plan(&minted.plan_id).unwrap().unwrap();
    assert_eq!(plan.approval_mode, ApprovalMode::SummarySample { configured_k: 5, effective_k: 2 });
    let derived = derive_sample(&derive_account_key(&root, "acct").unwrap(), &plan.digests, &plan.members, 2).unwrap();
    assert_eq!(derived, sorted(refs), "k >= count: every member, in canonical order");
    let render = AggregateRender { header: minted.presentation.header.clone(), summary: minted.presentation.summary.clone(), sample_k: 2, sample_rows: minted.presentation.rows.clone() };
    let evidence = log.record_approval(&root, &minted.plan_id, "clinton", RenderedView::Aggregate(render)).unwrap();
    assert_eq!(evidence.comprehension, Comprehension::Aggregate { shape_digest: plan.digests.shape, sample_k: 2, sample_members: derived });
    assert_eq!(log.approval(&minted.plan_id).unwrap(), Some(evidence));
}

#[test]
fn backups_off_freezes_an_uncovered_plan_whose_header_carries_the_verb_warning() {
    let path = temp_db("uncovered");
    let mut log = SqliteIntentLog::open(&path).unwrap();
    let refs = seed_two(&path);
    let generation = log.record_knob_act(KnobAct::Backups(BackupsKnob::Off)).unwrap();
    let root = root_key_verified(&InMemoryCustody::new(), &mut log).unwrap();
    for (verb, warning) in [(PlanVerb::Trash, TRASH_UNCOVERED_WARNING), (PlanVerb::MarkSpam, MARK_SPAM_UNCOVERED_WARNING)] {
        let minted = log.mint_plan(&root, PlanSpec { verb, member_refs: refs.clone(), ..PlanSpec::for_test("acct") }).unwrap();
        let plan = log.plan(&minted.plan_id).unwrap().unwrap();
        assert!(!plan.backups_on);
        assert_eq!(plan.coverage_generation, generation, "the coverage generation is the backups act's");
        assert!(!minted.presentation.header.backup_coverage);
        assert_eq!(minted.presentation.header.warning.as_deref(), Some(warning));
        assert_eq!(verb.uncovered_warning(), warning);
        assert_eq!(plan.digests.presentation_view.header.warning.as_deref(), Some(warning), "the warning is frozen and read back");
        if verb == PlanVerb::MarkSpam {
            assert!(!warning.contains("Trash"), "never Trash wording for MarkSpam");
            let member = plan.member(&refs[0]).unwrap();
            assert!(!member.observed_state["label:SPAM"]);
            assert!(member.forward_target["label:SPAM"]);
        }
    }
}

#[test]
fn a_malformed_knob_head_refuses_the_mint_and_nothing_is_minted() {
    let path = temp_db("knob-malformed");
    let mut log = SqliteIntentLog::open(&path).unwrap();
    let refs = seed_two(&path);
    raw(&path)
        .execute(
            "INSERT INTO engine_config (generation, recorded_at, kind, payload)
             VALUES ((SELECT MAX(generation) + 1 FROM engine_config), strftime('%s','now'), ?1, ?2);",
            rusqlite::params![KIND_APPROVAL_MODE, r#"{"mode":"summary_sample","configured_k":0}"#],
        )
        .unwrap();
    let root = root_key_verified(&InMemoryCustody::new(), &mut log).unwrap();
    let err = log.mint_plan(&root, PlanSpec { member_refs: refs, ..PlanSpec::for_test("acct") }).unwrap_err();
    assert!(matches!(&err, PlanStoreError::Knob(why) if why.contains("configured_k")), "{err:?}");
    assert_eq!((count(&path, "triage_plan"), count(&path, "plan_member")), (0, 0));
}

#[test]
fn record_approval_validates_through_the_pure_core_and_is_write_once() {
    let path = temp_db("approve");
    let mut log = SqliteIntentLog::open(&path).unwrap();
    let refs = seed_two(&path);
    let root = root_key_verified(&InMemoryCustody::new(), &mut log).unwrap();
    let minted = log.mint_plan(&root, PlanSpec { member_refs: vec![refs[0].clone()], ..PlanSpec::for_test("acct") }).unwrap();
    let ok = log.record_approval(&root, &minted.plan_id, "clinton", RenderedView::FullList(minted.presentation.clone())).unwrap();
    assert_eq!(ok.comprehension, Comprehension::PerMember);
    assert_eq!(ok.decision, Decision::Approved);
    assert!(aruna::prestate::is_canonical_rfc3339_utc(&ok.approved_at));
    assert_eq!(log.approval(&minted.plan_id).unwrap().unwrap().view_digest, minted.presentation_digest);
    assert_eq!(log.approval(&minted.plan_id).unwrap().unwrap(), ok, "the evidence reads back as recorded");
    assert!(matches!(log.record_approval(&root, &minted.plan_id, "clinton", RenderedView::FullList(minted.presentation.clone())).unwrap_err(), PlanStoreError::AlreadyApproved));
    assert_eq!(count(&path, "approval_evidence"), 1);
    // Display substitution at approval ⇒ ViewMismatch, nothing written.
    let path2 = temp_db("approve2");
    let mut log2 = SqliteIntentLog::open(&path2).unwrap();
    let refs2 = seed_two(&path2);
    let root2 = root_key_verified(&InMemoryCustody::new(), &mut log2).unwrap();
    let minted2 = log2.mint_plan(&root2, PlanSpec { member_refs: vec![refs2[0].clone()], ..PlanSpec::for_test("acct") }).unwrap();
    let mut forged = minted2.presentation.clone();
    forged.rows[0].subject = "forged".into();
    assert!(matches!(log2.record_approval(&root2, &minted2.plan_id, "clinton", RenderedView::FullList(forged)).unwrap_err(), PlanStoreError::Refused(PlanRefusal::ViewMismatch)));
    assert!(log2.approval(&minted2.plan_id).unwrap().is_none());
    // A screen lane with no approver ⇒ refused by name, nothing written.
    assert!(matches!(log2.record_approval(&root2, &minted2.plan_id, " ", RenderedView::FullList(minted2.presentation.clone())).unwrap_err(), PlanStoreError::Refused(PlanRefusal::ApproverMissing)));
    assert!(log2.approval(&minted2.plan_id).unwrap().is_none());
    // An unknown plan.
    let ghost = PlanId("f".repeat(32));
    assert_eq!(log2.record_approval(&root2, &ghost, "clinton", RenderedView::FullList(minted2.presentation.clone())).unwrap_err(), PlanStoreError::PlanNotFound(ghost));
}

#[test]
fn an_aggregate_approval_re_derives_the_sample_and_refuses_a_rendered_sample_that_is_not_the_derived_one() {
    let path = temp_db("agg-approve");
    let mut log = SqliteIntentLog::open(&path).unwrap();
    let refs = seed(
        &path,
        &(1..=5).map(|i| summary(&format!("P-{i}"), 1_758_000_000_000 + i, "", &format!("s{i}@x.example"), &format!("subject {i}"))).collect::<Vec<_>>(),
    );
    log.record_knob_act(KnobAct::ApprovalMode(ApprovalModeKnob::SummarySample { configured_k: 2 })).unwrap();
    let root = root_key_verified(&InMemoryCustody::new(), &mut log).unwrap();
    let minted = log.mint_plan(&root, PlanSpec { member_refs: refs.clone(), ..PlanSpec::for_test("acct") }).unwrap();
    let plan = log.plan(&minted.plan_id).unwrap().unwrap();
    let account_key = derive_account_key(&root, "acct").unwrap();
    let derived = derive_sample(&account_key, &plan.digests, &plan.members, 2).unwrap();
    let render = |sample: &[String]| AggregateRender {
        header: minted.presentation.header.clone(),
        summary: minted.presentation.summary.clone(),
        sample_k: 2,
        sample_rows: sample.iter().map(|r| minted.presentation.rows.iter().find(|row| &row.message_ref == r).unwrap().clone()).collect(),
    };
    let not_derived: Vec<String> = plan.members.iter().map(|m| m.message_ref.clone()).filter(|r| !derived.contains(r)).take(2).collect();
    assert!(matches!(log.record_approval(&root, &minted.plan_id, "clinton", RenderedView::Aggregate(render(&not_derived))).unwrap_err(), PlanStoreError::Refused(PlanRefusal::ViewMismatch)));
    assert_eq!(log.approval(&minted.plan_id).unwrap(), None);
    // A full-list render against an aggregate plan is not the view this plan's lane shows.
    assert!(matches!(log.record_approval(&root, &minted.plan_id, "clinton", RenderedView::FullList(minted.presentation.clone())).unwrap_err(), PlanStoreError::Refused(PlanRefusal::ViewMismatch)));
    let evidence = log.record_approval(&root, &minted.plan_id, "clinton", RenderedView::Aggregate(render(&derived))).unwrap();
    assert_eq!(evidence.comprehension, Comprehension::Aggregate { shape_digest: plan.digests.shape, sample_k: 2, sample_members: derived.clone() }, "the journal says 'summary + sample of k', with the derived sample");
    assert_eq!(log.approval(&minted.plan_id).unwrap(), Some(evidence));
}

#[test]
fn a_stored_plan_that_disagrees_with_itself_reads_back_as_a_store_error_never_a_plan() {
    let path = temp_db("shape-corrupt");
    let mut log = SqliteIntentLog::open(&path).unwrap();
    let refs = seed_two(&path);
    let root = root_key_verified(&InMemoryCustody::new(), &mut log).unwrap();
    let minted = log.mint_plan(&root, PlanSpec { member_refs: refs.clone(), ..PlanSpec::for_test("acct") }).unwrap();
    // A second row copied from the good one but with the per_member lane beside a summary mode —
    // every column parses; only the plan's own shape check can see it (raw SQL: the corruption /
    // out-of-band-writer shape).
    let conn = raw(&path);
    conn.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
    conn.execute(
        "INSERT INTO triage_plan
         SELECT 'forged', account, provider_principal, grant_generation, control_epoch, verb, tier, rationale, minted_at,
                expires_at, member_count, 'per_member', NULL, 'summary_sample', 1, 1, coverage_generation, backups_on, warning,
                set_digest, set_randomizer, state_digest, state_randomizer, presentation_digest, presentation_randomizer,
                shape_digest, shape_randomizer, sample_seed, sample_seed_randomizer, aggregate_view_randomizer,
                key_ref_namespace, key_ref_epoch, bypass_notice
           FROM triage_plan WHERE plan_id = ?1;",
        [&minted.plan_id.0],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO plan_member SELECT 'forged', message_ref, sender, subject, date, size, observed_state, forward_target,
                sender_status, sender_addr, sender_domain, sender_address, sender_local FROM plan_member WHERE plan_id = ?1;",
        [&minted.plan_id.0],
    )
    .unwrap();
    let err = log.plan(&PlanId("forged".into())).unwrap_err();
    assert!(err.0.contains("PlanShape(PerMemberLaneRequiresFullList)"), "refused by the named shape rule: {err:?}");
    // …and an approval over it is a store error too, never evidence.
    assert!(matches!(log.record_approval(&root, &PlanId("forged".into()), "clinton", RenderedView::FullList(minted.presentation.clone())).unwrap_err(), PlanStoreError::Store(_)));
    assert!(log.plan(&minted.plan_id).unwrap().is_some(), "the good row still reads");
}
