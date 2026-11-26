//! Helpers shared by the durable-store witnesses (`plan_witnesses.rs`, `plan_admission.rs`).
//! Each test binary compiles this module on its own, so a helper one binary does not call is
//! dead code THERE — hence the allow.
#![allow(dead_code)]

use aruna::read_coordinator::ReadCoordinator;
use aruna::read_model::ProviderMessageId;
use aruna::read_surface::{AttachmentPresence, HeaderSummary};

/// A fresh store per call, minted by the ONE guard (`aruna::test_temp`):
/// `photon-plan-{tag}-{pid}-{nanos}-{seq}.sqlite`, removed with its store siblings when the guard
/// drops, a leak a loud failure. It was a directory per call that nothing ever removed (6,115
/// `photon-plan-*` leftovers in the 2026-09-24/25 sweep). Bind it BEFORE anything that opens it.
pub fn temp_db(tag: &str) -> aruna::test_temp::TempFile {
    aruna::test_temp::TempFile::sqlite(&format!("photon-plan-{tag}"))
}

pub fn summary(provider_id: &str, received_at_ms: i64, from_name: &str, from_addr: &str, subject: &str) -> HeaderSummary {
    HeaderSummary {
        provider_id: ProviderMessageId(provider_id.to_string()),
        received_at: received_at_ms,
        from_addr: from_addr.to_string(),
        from_name: from_name.to_string(),
        subject: subject.to_string(),
        seen: false,
        flagged: false,
        attachments: AttachmentPresence::default(),
    }
}

/// Seed header + placement rows for account `acct` through the crate's own INGEST CHOKEPOINT —
/// never raw SQL: the frozen display must be the NORMALIZED text that chokepoint writes.
/// `ReadCoordinator::ingest_page` is the public door (the read_coordinator tests' own seeding
/// shape); it MINTS the refs, so they are returned in the order given, and every seeded message
/// lands in the Inbox.
pub fn seed(path: &std::path::Path, rows: &[HeaderSummary]) -> Vec<String> {
    let mut c = ReadCoordinator::open(path).unwrap();
    c.ingest_page("acct", rows).unwrap()
}

/// Seed `n` Inbox messages for `acct` (provider ids `P-1`..`P-n`) and return the refs the ingest
/// door minted for them, in that order.
pub fn seed_inbox(path: &std::path::Path, n: usize) -> Vec<String> {
    let rows: Vec<HeaderSummary> = (1..=n)
        .map(|i| summary(&format!("P-{i}"), 1_758_672_000_000 + i as i64 * 1_000, "", &format!("sender{i}@list.example"), &format!("subject {i}")))
        .collect();
    seed(path, &rows)
}
