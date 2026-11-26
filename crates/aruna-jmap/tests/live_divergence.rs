//! Env-gated LIVE drill: divergence-correction over the wire (M0 DoD §2). A *wrong* optimistic
//! projection is corrected to real provider truth read via JMAP `Email/get`.
//!
//! Opt-in (`PHOTON_JMAP_IT=1`); otherwise skips so the default suite stays hermetic. Bring the
//! fixture up first:
//!   bash crates/aruna-jmap/tests/fixtures/stalwart/setup.sh
//! then:
//!   PHOTON_JMAP_IT=1 PHOTON_JMAP_URL=http://localhost:18080 \
//!   PHOTON_JMAP_USER=testuser@example.test PHOTON_JMAP_PASS=photon-jmap-fixture-7x9k \
//!   cargo test -p aruna-jmap --test live_divergence -- --nocapture
//!
//! READ-ONLY against the provider: the seeded email's real placement (Inbox) is the truth; we poison
//! the LOCAL projection to claim Archive and prove reconcile flips it back to Inbox. The fixture
//! stays pristine (no provider mutation), so the test is freely re-runnable.

mod common;

use aruna::jmap::{AccountId, MailboxId};
use aruna::message_store::{Corrected, SqliteMessageStore};
use aruna::read_model::{Placement, ProviderMessageId};
use aruna::reconcile::reconcile_divergence;
use aruna::{
    derive_idempotency_key, Action, Command, Facet, IntentLog, IntentStatus, SqliteIntentLog,
};
use aruna_jmap::transport::{HttpJmapTransport, JmapProviderPlacement};
use common::{live_env, unique_sqlite_path, Probe};

#[test]
fn live_divergence_correction_converges_to_provider_truth() {
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
    // Provider truth: the seeded email lives in Inbox.

    // The live placement reader — real JMAP Email/get behind the ProviderPlacement seam.
    let transport =
        HttpJmapTransport::connect_for_test_fixture(&url, &user, &pass).expect("live connect");
    let provider = JmapProviderPlacement::new(
        &transport,
        AccountId(account.clone()),
        MailboxId(inbox.clone()),
        MailboxId(archive.clone()),
    );

    // A terminal (Applied) intent governs the message; the projection is POISONED to Archive.
    let photon_acct = "photon-live";
    let db = unique_sqlite_path("divergence");
    let mut log = SqliteIntentLog::open(&db).expect("open intent log");
    let cmd = Command::new(
        derive_idempotency_key(photon_acct, &Facet::Mail, "seed-logical"),
        photon_acct,
        Facet::Mail,
        Action::Archive {
            message_ref: "seed".to_string(),
        },
    );
    // Admission freezes a native basis. This drill seeds the intent
    // directly to set up a POISONED projection — it never dispatches — so it supplies a
    // well-formed placeholder basis rather than a live resolution.
    log.record(
        &cmd,
        &aruna::prestate::FrozenBasis {
            // Through the ONE encoding authority — a drill that
            // hand-spelled the key shape would drift from the connector it stands in for.
            native_resource_key: aruna::prestate::native_resource_key(
                aruna::jmap::JMAP_KEY_PROVIDER,
                &[&account, &email],
            ),
            touched_atoms: [("membership:INBOX".to_string(), "INBOX".to_string())]
                .into_iter()
                .collect(),
            // The forward target vector `A`, keyed identically to
            // `touched_atoms` (FrozenBasis::validate enforces the equality both ways).
            // Archive's target is "no longer in INBOX".
            atom_targets: [("membership:INBOX".to_string(), false)]
                .into_iter()
                .collect(),
            role_bindings: std::collections::BTreeMap::new(),
            freshness: aruna::prestate::Freshness::ImmutableConstants,
        },
    )
    .expect("record");
    log.set_status_forced(&cmd.idempotency_key, IntentStatus::Applied)
        .expect("applied");

    let mut store = SqliteMessageStore::open(&db).expect("open store");
    store
        .record_optimistic_placement(
            photon_acct,
            "seed",
            &ProviderMessageId(email.clone()),
            Placement::Archive, // the WRONG belief
        )
        .expect("seed poisoned projection");

    // Reconcile against real provider truth read over the wire.
    let out = reconcile_divergence(&log, &mut store, &provider, photon_acct, "seed")
        .expect("reconcile over the wire");

    assert_eq!(
        out,
        Corrected { changed: true },
        "a poisoned projection must be corrected (non-vacuous)"
    );
    assert_eq!(
        store.placement(photon_acct, "seed").expect("read placement"),
        Some(Placement::Inbox),
        "projection must converge to real provider truth (Inbox)"
    );

    std::fs::remove_file(&db).ok();
}
