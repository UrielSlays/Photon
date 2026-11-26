//! Env-gated LIVE integration test: archive/unarchive over the wire against a real self-hosted
//! Stalwart JMAP server (the M0 "works end-to-end against a JMAP test account" DoD proof).
//!
//! This test is OPT-IN — it runs only when `PHOTON_JMAP_IT=1`; otherwise it skips so the default
//! `cargo test` stays hermetic (no server required). Bring the fixture up first:
//!   bash crates/aruna-jmap/tests/fixtures/stalwart/setup.sh
//! then:
//!   PHOTON_JMAP_IT=1 PHOTON_JMAP_URL=http://localhost:18080 \
//!   PHOTON_JMAP_USER=testuser@example.test PHOTON_JMAP_PASS=photon-jmap-fixture-7x9k \
//!   cargo test -p aruna-jmap --test live_jmap -- --nocapture
//!
//! IDs are DISCOVERED at runtime (session → Mailbox/query → Email/query), never hardcoded — the
//! fixture's short opaque ids are stable only on a clean install. Credentials come from env and are
//! never printed. Shared scaffolding (Probe, live_env, resolvers, helpers) lives in `tests/common`.

mod common;

use aruna::jmap::JmapConnector;
use aruna::{Action, Connector, FailureKind};
use aruna_jmap::transport::HttpJmapTransport;
use common::{cmd, live_env, FixedAccount, FixedMessage, Probe};

#[test]
fn live_archive_then_unarchive_moves_a_real_message_over_the_wire() {
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

    let transport =
        HttpJmapTransport::connect_for_test_fixture(&url, &user, &pass).expect("live connect");
    let conn = JmapConnector::new(
        transport,
        FixedAccount(account.clone()),
        FixedMessage(email.clone()),
    );

    // Archive: Inbox -> Archive, over the wire. FREEZE FIRST, DISPATCH SECOND — the engine's own
    // two-step: `apply` consumes the admission-frozen basis and never re-resolves the role pair, so a live dispatch supplies the freeze the bus would take.
    let archive_cmd = cmd(
        "live-k1",
        Action::Archive {
            message_ref: "seed".to_string(),
        },
    );
    let archive_basis = conn
        .resolve_basis(&archive_cmd)
        .expect("freeze the archive basis against the live provider");
    conn.apply(&archive_cmd, &archive_basis)
        .expect("archive over the wire");
    let after = probe.email_mailboxes(&account, &email);
    // Report only id-free booleans — never the raw provider mailbox-id list (confinement also
    // applies to test/log output).
    let (in_archive, in_inbox) = (after.contains(&archive), after.contains(&inbox));
    assert!(
        in_archive && !in_inbox,
        "after archive the message should be in Archive only (in_archive={in_archive}, in_inbox={in_inbox})"
    );

    // Unarchive: Archive -> Inbox (the inverse). Leaves the fixture re-runnable. Its OWN freeze:
    // the forward move re-dated the Mailbox namespace, and a fresh admission is what a second
    // operation gets.
    let unarchive_cmd = cmd(
        "live-k1",
        Action::Unarchive {
            message_ref: "seed".to_string(),
        },
    );
    let unarchive_basis = conn
        .resolve_basis(&unarchive_cmd)
        .expect("freeze the unarchive basis against the live provider");
    conn.apply(&unarchive_cmd, &unarchive_basis)
        .expect("unarchive over the wire");
    let back = probe.email_mailboxes(&account, &email);
    let (in_inbox, in_archive) = (back.contains(&inbox), back.contains(&archive));
    assert!(
        in_inbox && !in_archive,
        "after unarchive the message should be back in Inbox only (in_inbox={in_inbox}, in_archive={in_archive})"
    );
}

#[test]
fn live_archive_of_a_nonexistent_email_is_deterministic() {
    let Some((url, user, pass)) = live_env() else {
        return;
    };
    let probe = Probe::new(&url, &user, &pass);
    let account = probe.account_id();

    // Resolve to an email id that does not exist: the surgical Email/set returns notUpdated[id] =
    // notFound, which the taxonomy classifies Deterministic (real failure, over the wire).
    let transport =
        HttpJmapTransport::connect_for_test_fixture(&url, &user, &pass).expect("live connect");
    let conn = JmapConnector::new(
        transport,
        FixedAccount(account),
        FixedMessage("nonexistent-email-id-xyz".to_string()),
    );

    let command = cmd(
        "live-k1",
        Action::Archive {
            message_ref: "seed".to_string(),
        },
    );
    let basis = conn
        .resolve_basis(&command)
        .expect("the freeze names the (existing) account and the (nonexistent) email");
    let err = conn
        .apply(&command, &basis)
        .expect_err("archiving a nonexistent email must fail");
    assert_eq!(
        err.kind,
        FailureKind::Deterministic,
        "a notFound SetError over the wire must be deterministic"
    );
}
