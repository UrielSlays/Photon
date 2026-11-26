//! The SQLite-backed durable `IntentLog`, its row decode, and the engine-config ledger reads.

use std::path::Path;

use rusqlite::OptionalExtension;

use crate::adjudication::{
    fact_clock, link_supersessions, mint_opaque_id, note_exposure_materialization,
    obligation_generation, write_annotation, EXPOSURE_OVERLAP_SQL,
    EXPOSURE_RETIREMENT_BY_CONTRIBUTOR_SQL, FACT_CLOCK_HIGH_WATER_SQL, RETRY_SUCCESSOR_SQL,
};
use crate::boot::boot_quarantine;
use crate::command::{action_from_parts, action_to_parts, facet_from_str, facet_to_str};
use crate::connector::{effect_witness_already_recorded, effect_witness_row};
use crate::fact_store::{
    fact_payload_from_json, fact_payload_json, fold_stored_attempt, fold_stored_attempt_if_present,
    read_attempt_chain, verified_state_json,
};
use crate::intent::{non_terminal_native_predecessor_sql, status_from_str, NON_TERMINAL_STATUS_SQL};
use crate::intent_log::{
    belt_refuses_send_if_severing, capture_binding_holds, key_rewrite_rejected,
    unknown_review_rollback,
};
use crate::keys::{reject_inadmissible_basis, reject_reserved_user_key, reject_unreadable_basis};
use crate::plan_store::{
    assemble_plan, build_approval_evidence, complete_episode_if_done_in, insert_evidence_row,
    insert_plan_rows, invalidate_episode_in_tx, knob_state_in, mark_ready_in, plan_child_admission,
    plan_send_admission, plan_spec_preflight, read_episode_in, read_evidence_in,
    read_member_facts_in, read_plan_in, start_episode_in, sticky_effective_now, PlanMintInputs,
    PlanTxError,
};
use crate::settle::{
    append_fact_with_head, retry_reason_of, settle_status, settlement_proves_no_effect,
    terminalize_operation, verdict_mapping, LifecycleIntent,
};
use crate::sever::{
    insert_sever_attribution, lead_sever_service, live_attempt_from, live_attempts_of,
    self_appended_attribution_kind, sever_attribution_seam, sever_disposition,
    sever_outcome_of_epoch, sever_service_gate, validated_authority_ref, SeverSeam,
};
use crate::{
    status_to_str, store_open, writer_gate, ActionEnvelope, AdjudicatedHistory, AdjudicationOutcome,
    AttemptClaim, CaptureBinding, CapturedJournal, CapturedPreState, Claim, ClaimOutcome, Command,
    ConnectorVerdict, DeadLetterWrite, EffectWitness, EffectWitnessRow, ExposureObligation,
    IntegrityEvidence, Intent, IntentLog, IntentStatus, JournalReplaceOutcome, LateAckOutcome,
    LiveAttempt, LogError, SendAuthOutcome, SettleOutcome, SettledLifecycle, SeverOutcome,
    StatusPrecondition, StatusWrite, TransientCharge, UndoContext, UndoPairChild, UndoPairFlip,
    UnknownReviewReport, UnknownReviewRow,
};

/// SQLite-backed durable `IntentLog`: the store-first system of record. Survives process
/// restart, unlike `InMemoryIntentLog`.
pub struct SqliteIntentLog {
    /// The verified connection and the writer gate for the file it has open, minted together at
    /// one entry point (`store_open::GatedConnection`). Every write transaction this type runs
    /// goes through [`SqliteIntentLog::with_immediate_tx`], whose enrollment spans the
    /// transaction; reads reach the connection through `Deref`.
    pub(crate) conn: crate::store_open::GatedConnection,
    /// The open-time integrity evidence, computed once at open (post-DDL) and held for the
    /// driver to surface. Read it via [`SqliteIntentLog::integrity_report`].
    integrity: Vec<IntegrityEvidence>,
}

/// Durable-log schema version, stamped into SQLite's `PRAGMA user_version` on open. Lets later
/// migrations distinguish an older database from a newer layout instead of guessing. Bump when
/// the on-disk schema changes.
///
/// - v4: the `message_placement` read-side projection table.
/// - v5: the `message_header` read side (headers, folder index, FTS5 search).
/// - v6: the durable `action_kind` token grammar gains the `set_flag:<flag>:<bool>` family
///   (no DDL change; an older binary must refuse the newer grammar via the version guard).
/// - v7: the grammar gains `set_flag:flagged:*` (no DDL change; a v6 binary reads a flagged
///   row as a row-level `LogError`, and the stamp makes it refuse at open instead).
/// - v8: pre-v8 stores are refused, never stamped; PHTN `application_id` ownership;
///   append-only `engine_config` ledger; `control_epoch` singleton; admission-binding columns
///   on `intents`.
/// - v9: the read-model rework. `message_header` gains provider-neutral state (`seen`,
///   `flagged`), and `message_placement` gains the identity inverse `UNIQUE (account,
///   email_id)` that makes a stable `message_ref` mint possible. The first version with an
///   in-place upgrade: a v8 store is admitted and brought up to this shape at the open
///   chokepoint (see `store_open::MIN_UPGRADABLE_VERSION`).
/// - v10: `triage_plan` / `plan_member` / `approval_evidence` (append-only), joining the
///   `commitment_key_registry` and the effect-evidence columns. A v9 store upgrades in place:
///   the three tables are new, so the open's one DDL transaction creates them and stamps v10
///   in the same write.
pub(crate) const SCHEMA_VERSION: i64 = 10;

impl SqliteIntentLog {
    /// Open the intent log at `path` under the store-open contract.
    ///
    /// The version/ownership decision is made by the crate-internal `store_open::preflight`
    /// (not a doc link: it is private) from the raw file family before any connection exists,
    /// so nothing is created, recovered, or mutated on a store this binary is going to refuse
    /// (even the durability profile's `journal_mode=WAL` is a persistent file mutation). A
    /// pre-v8 store is refused with an operator-visible reset message and never auto-stamped.
    /// Only a fresh bootstrap or a version-verified store proceeds to profile activation, FK
    /// activation and DDL.
    pub fn open(path: impl AsRef<Path>) -> rusqlite::Result<Self> {
        use crate::store_open::{BootstrapOutcome, Preflight};
        let path = path.as_ref();
        // Bounded to two passes: losing the fresh-install race is not a failure to open. The
        // store the loser wanted now exists, so it re-runs the preflight once and follows
        // whatever verdict the winner's installed store earns. A second lost race would mean
        // the destination is being installed and removed underneath us, which is a real
        // surprise, not a retry.
        for pass in 1..=2u32 {
            match store_open::preflight(path)? {
                Preflight::FreshBootstrap => match store_open::bootstrap_fresh(path)? {
                    BootstrapOutcome::Installed => {}
                    BootstrapOutcome::LostRace if pass == 1 => continue,
                    BootstrapOutcome::LostRace => {
                        return Err(rusqlite::Error::SqliteFailure(
                            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_ERROR),
                            Some(format!(
                                "{} lost the fresh-install race twice — the store is being \
                                 created and removed concurrently; refusing to loop",
                                path.display()
                            )),
                        ))
                    }
                },
                // Verified and hot-sidecar (probe) stores are handled by the chokepoint
                // below (`open_verified_connection`), the one home for the open decision tree.
                Preflight::OpenVerifiedSupported | Preflight::RecoveryProbe => {}
            }
            break;
        }

        // Pin the test store's inode. The writer-gate registry keys by (dev, ino) on unix and
        // never evicts (see the writer_gate module doc); test stores are deleted at test end
        // and ext4/tmpfs promptly reuse a freed inode, so a later test's fresh store resolved
        // to an earlier test's accumulated gate state. Leaking one descriptor keeps the inode
        // allocated for the process lifetime. Test-only (unit tests share one process and
        // registry) and unix-only (Windows file identities do not recycle this way). Pinned
        // once per identity, because reopen-heavy tests open one store hundreds of times and a
        // descriptor per open could reach EMFILE on a low-ulimit runner.
        #[cfg(all(test, unix))]
        {
            use std::os::unix::fs::MetadataExt as _;
            static PINNED: std::sync::OnceLock<
                std::sync::Mutex<std::collections::HashSet<(u64, u64)>>,
            > = std::sync::OnceLock::new();
            let file = std::fs::File::open(path).expect("pin the test store's inode");
            let meta = file.metadata().expect("read the test store's identity");
            let newly_pinned = PINNED
                .get_or_init(Default::default)
                .lock()
                .expect("the test pin registry mutex")
                .insert((meta.dev(), meta.ino()));
            if newly_pinned {
                std::mem::forget(file);
            }
        }

        // The open path runs alone per identity: from here the store file exists (the preflight
        // loop either verified or bootstrapped it), so it has an identity to serialize on, and
        // this guard holds through the connection open, the persistent profile, the DDL
        // transaction and the boot quarantine. The serializer is reentrant:
        // `open_verified_connection` takes it again.
        let _open_serialization = writer_gate::serialize_open_path(path)?;
        // The shared chokepoint verifies ownership and version through this connection, then
        // activates the profile and FK checks, and returns the connection paired with this
        // store's writer gate.
        let mut conn = store_open::open_verified_connection(path)?;
        // Stamp the current version raise-only, under an IMMEDIATE write lock. The stamp
        // re-reads user_version inside the write transaction and only raises it, never lowers
        // it. That closes the race where a concurrent newer binary stamps a higher version
        // between our pre-DDL read and our write: we must never overwrite its higher marker.
        //
        // This is an enrolled transaction like every other write this type runs: the
        // DDL/migration transaction is a writer to the store file and the arbiter must see it.
        // `open` mints its own `GatedConnection` before a `Self` exists, so it calls the pair's
        // closure entry point directly.
        conn.with_immediate_tx(|tx| -> rusqlite::Result<()> {
            let current: i64 = tx.query_row("PRAGMA user_version;", [], |r| r.get(0))?;
            // A version above ours inside this write lock means a newer binary stamped the store
            // between the open-time verification and here. Raise-only kept us from lowering the
            // marker, but proceeding would run this version's DDL and writes against a store
            // this binary has already declared itself too old for. Refuse.
            if current > SCHEMA_VERSION {
                return Err(rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_ERROR),
                    Some(format!(
                        "database schema version {current} is newer than this binary supports \
                     (max {SCHEMA_VERSION}); refusing to open"
                    )),
                ));
            }
            // The schema lives in one place, `store_open::schema_ddl()`, so the fresh bootstrap
            // and this reopen path cannot drift apart. The DDL runs inside this write
            // transaction, after the version re-read above: running it earlier would let a
            // concurrent newer binary's store be mutated by this DDL before the refusal fired.
            //
            // Before the DDL, one v9 schema change can fail on data an older store legitimately
            // holds: the `(account, email_id)` identity inverse is UNIQUE, and v8 never forbade
            // two refs naming one provider message. The scan refuses by name with the colliding
            // identity; letting `CREATE UNIQUE INDEX` discover it would abort with a bare
            // constraint string, and deduping would make the engine pick which of the operator's
            // rows survives. It runs inside this transaction, so a refused store is left
            // byte-identical.
            //
            // Upgrade only: it is a full `GROUP BY` over `message_placement`, and on a store
            // already stamped `SCHEMA_VERSION` the unique index has been enforcing the constraint
            // since the version was stamped, so it could only answer "none". Running it every
            // open would cost a full placement scan on each start of a large mailbox.
            if current < SCHEMA_VERSION {
                store_open::refuse_duplicate_placement_identity(tx)?;
            }
            tx.execute_batch(&store_open::schema_ddl())?;
            // The half `CREATE TABLE IF NOT EXISTS` cannot do: a column this build added to a
            // table an earlier build of the same version already created. Such a store reaches
            // this line with a `pre_state` missing `capture_generation`; without the ALTER it
            // would open clean and fail deep at the first statement naming the column. Same write
            // transaction as the DDL and after the newer-version refusal, for the same reason.
            store_open::upgrade_in_version_columns(tx)?;
            // The ingest-revision high water, after the ALTER that can add the
            // `message_header.ingest_revision` column it reads, in this same write transaction.
            // On an older store it seeds the high water at the greatest per-row counter already
            // written, so the first value this build issues exceeds every earlier one (see
            // `store_open::seed_ingest_revision_seq`).
            store_open::seed_ingest_revision_seq(tx)?;
            if current < SCHEMA_VERSION {
                // The half no schema change can do: display bytes a v8 binary wrote predate
                // `header_normalize::normalize_display`, so an upgraded store would render the
                // persisted bidi override or injected newline the ingest path exists to strip.
                // The migration runs the existing population through the same function, on
                // `from_name` and `subject` only (`from_addr` is identity and round-trips
                // verbatim). Gated on the version: on a v9 store every row already went through
                // that path, so this is a migration step, not a per-open scan.
                store_open::normalize_legacy_display_headers(tx)?;
                tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
            }
            Ok(())
        })?;
        // This is the reopen site the bootstrap path's comment points at. After the
        // transaction above commits (so a store old enough to need `sender_address` already has
        // it, from `upgrade_in_version_columns`), it catches a store whose `from_status` /
        // `sender_status` CHECK is stale because the column already existed (the ALTER was
        // skipped) even though its CHECK text is not what this build writes today. It runs
        // outside that transaction, on the raw connection: the rebuild opens its own
        // `BEGIN`/`COMMIT` and toggles `PRAGMA foreign_keys` around itself (a no-op inside an
        // open transaction), and SQLite refuses a nested `BEGIN`. It is a no-op on a store whose
        // tables never carried the vocabulary CHECK, and is called anyway to avoid drift
        // between schema sites.
        store_open::rebuild_status_check_tables(conn.conn())?;
        // The boot quarantine, after the DDL and before anything can dispatch: this constructor
        // is the only way to reach a durable store, so "before any dispatch" holds by structure.
        // It verifies every attempt head against its chain, classifies every live attempt from
        // its facts, and reconciles the sever evidence.
        //
        // A head that diverges from its chain refuses the open. That differs from the scan
        // below, which reports facts about rows and never refuses: a head/fold divergence means
        // the engine's own projection is a second authority that every dispatch decision reads,
        // so opening on one would hand callers a value nothing can vouch for.
        let quarantine = boot_quarantine(&mut conn).map_err(|e| {
            rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_ERROR),
                Some(e.0),
            )
        })?;
        // The open-time integrity scan, after the DDL so the tables it reads exist. Its findings
        // are evidence, never a refusal: a store with an unexplained journal gap still opens,
        // because refusing would deny an operator the very rows they need to inspect. The report
        // is carried on the log the caller already holds.
        let mut integrity = store_open::integrity_scan(&conn)?;
        integrity.extend(quarantine);
        Ok(Self { conn, integrity })
    }

    /// Every write transaction this type runs goes through here: one `BEGIN IMMEDIATE`
    /// transaction, bracketed by one enrollment in this store file's writer gate that spans
    /// it, from before `BEGIN` to after `COMMIT`/rollback.
    ///
    /// The closure shape is the point: a `(WriteScope, Transaction)` pair cannot enforce the
    /// ordering, since tuple members drop separately and declaration order releases the scope
    /// first. See `store_open::GatedConnection::with_immediate_tx` for the ownership argument,
    /// and `enrollment_spans_the_transaction_not_the_statement` for its test.
    ///
    /// Two consequences for callers:
    /// - **No re-entrancy.** `f` must not call another method that enrolls (any `&mut self`
    ///   write method, or `begin_sever`): one gate per store means a nested enrollment would
    ///   wait for itself. The gate refuses it explicitly rather than hanging, but that is a
    ///   bug report, not control flow. Work that needs `&self` after the transaction (such as
    ///   `record`'s duplicate re-read) belongs after this call returns.
    /// - `f` runs while every other writer to this file is blocked, including a pending
    ///   sever. Keep it to the transaction's own work: no I/O, no waiting.
    pub(crate) fn with_immediate_tx<T>(
        &mut self,
        f: impl FnOnce(&rusqlite::Transaction<'_>) -> Result<T, LogError>,
    ) -> Result<T, LogError> {
        self.conn.with_immediate_tx(f)
    }

    /// The open-time integrity evidence for this store, as computed by the open chokepoint: the
    /// scan's findings plus what the boot quarantine reconciled and closed. Empty on a healthy
    /// store. Never a refusal; see [`IntegrityEvidence`].
    pub fn integrity_report(&self) -> &[IntegrityEvidence] {
        &self.integrity
    }

    /// The current `control_epoch`: the singleton row every internal fence reads (seeded at 1;
    /// [`IntentLog::sever`] is its only writer and bumps it by exactly 1). Read-only: unlike
    /// `sever`'s bump, this never opens a write transaction, so it is safe to call freely.
    pub fn control_epoch(&self) -> Result<i64, LogError> {
        self.conn
            .query_row("SELECT epoch FROM control_epoch WHERE id = 1;", [], |r| {
                r.get(0)
            })
            .map_err(|e| LogError(format!("control_epoch read: {e}")))
    }

    /// The freshness basis one named intent was recorded against (see
    /// [`Intent::basis_ingest_revision`]): a targeted read for a caller that knows the key and
    /// needs only this column, since the intent it just recorded is not in hand as a live
    /// [`Intent`]. `Ok(None)` both when the key names no row and when the row's own basis is
    /// NULL; the caller ([`crate::read_coordinator::ReadCoordinator::project_applied_intent`])
    /// treats both the same way (no freshness claim, never overwrite).
    pub fn basis_ingest_revision_of(&self, idempotency_key: &str) -> Result<Option<i64>, LogError> {
        let row: Option<Option<i64>> = self
            .conn
            .query_row(
                "SELECT basis_ingest_revision FROM intents WHERE idempotency_key = ?1;",
                rusqlite::params![idempotency_key],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| LogError(format!("basis_ingest_revision_of read: {e}")))?;
        Ok(row.flatten())
    }
}

/// Raw column values from an `intents` row, before enum parsing. Splitting SQL extraction
/// (which fails as `rusqlite::Error`) from enum parsing (which fails as `LogError`) keeps a
/// corrupt/unknown stored value a returned error, never a panic that unwinds recovery.
pub(crate) struct RawIntent {
    idempotency_key: String,
    account: String,
    facet: String,
    action_kind: String,
    message_ref: String,
    status: String,
    principal: Option<String>,
    epoch: Option<i64>,
    evidence_ref: Option<String>,
    snapshot_ref: Option<String>,
    tier: Option<String>,
    compensates: Option<String>,
    seq: i64,
    attempts: i64,
    frozen_basis: Option<String>,
    journal_required: i64,
    /// The plan-child link, both halves or neither (`intent_from_raw` refuses
    /// one without the other).
    pub(crate) plan_id: Option<String>,
    pub(crate) plan_member: Option<String>,
    /// See [`Intent::projected`].
    projected: i64,
    /// See [`Intent::basis_ingest_revision`].
    basis_ingest_revision: Option<i64>,
}

/// The `intents` column list every read path selects, in the order [`raw_intent_from_row`]
/// indexes. A single const so a column added here cannot drift out of one of the read sites (a
/// mis-ordered list is a silent mis-parse, not a compile error).
pub(crate) const INTENT_COLUMNS: &str = "idempotency_key, account, facet, action_kind, message_ref, status,
                              principal, epoch, evidence_ref, tier, seq, snapshot_ref,
                              compensates, attempts, frozen_basis, journal_required,
                              plan_id, plan_member, projected, basis_ingest_revision";

/// Extract the raw columns in [`INTENT_COLUMNS`] order. No enum parsing here.
pub(crate) fn raw_intent_from_row(row: &rusqlite::Row) -> rusqlite::Result<RawIntent> {
    Ok(RawIntent {
        idempotency_key: row.get(0)?,
        account: row.get(1)?,
        facet: row.get(2)?,
        action_kind: row.get(3)?,
        message_ref: row.get(4)?,
        status: row.get(5)?,
        principal: row.get(6)?,
        epoch: row.get(7)?,
        evidence_ref: row.get(8)?,
        tier: row.get(9)?,
        seq: row.get(10)?,
        snapshot_ref: row.get(11)?,
        compensates: row.get(12)?,
        attempts: row.get(13)?,
        frozen_basis: row.get(14)?,
        journal_required: row.get(15)?,
        plan_id: row.get(16)?,
        plan_member: row.get(17)?,
        projected: row.get(18)?,
        basis_ingest_revision: row.get(19)?,
    })
}

/// Parse a raw row into an `Intent`, returning `LogError` (not a panic) on an unknown facet,
/// action or status: one corrupt durable row must not crash startup or recovery.
pub(crate) fn intent_from_raw(raw: RawIntent) -> Result<Intent, LogError> {
    // NULL → None (a row that was never frozen). A present but malformed value is a LogError,
    // never a silent None: "unreadable" and "absent" are different facts, and only the first
    // is a corruption the read path must fail closed on.
    let frozen_basis = raw
        .frozen_basis
        .map(|json| {
            crate::prestate::FrozenBasis::from_json(&json).map_err(|e| {
                LogError(format!(
                    "intent '{}': stored frozen_basis is not a well-formed basis: {e}",
                    raw.idempotency_key
                ))
            })
        })
        .transpose()?;
    // The plan-child link is both columns or neither. One without the other is a row no writer
    // produces (the column CHECK refuses it on write too): a `LogError` naming the key, never
    // a silent `None` and never a link with a hole in it.
    let plan_child = match (raw.plan_id, raw.plan_member) {
        (Some(plan_id), Some(member_ref)) => Some(crate::plan::PlanChildLink { plan_id: crate::plan::PlanId(plan_id), member_ref }),
        (None, None) => None,
        _ => {
            return Err(LogError(format!(
                "intent '{}': half a plan link (plan_id and plan_member are both set or both NULL)",
                raw.idempotency_key
            )))
        }
    };
    Ok(Intent {
        command: Command {
            idempotency_key: raw.idempotency_key,
            account: raw.account,
            facet: facet_from_str(&raw.facet)?,
            action: action_from_parts(&raw.action_kind, raw.message_ref)?,
            envelope: ActionEnvelope {
                principal: raw.principal,
                epoch: raw.epoch.map(|e| e as u64),
                evidence_ref: raw.evidence_ref,
                snapshot_ref: raw.snapshot_ref,
                tier: raw.tier,
            },
            compensates: raw.compensates,
            plan_child,
        },
        status: status_from_str(&raw.status)?,
        seq: raw.seq as u64,
        attempts: raw.attempts as u32,
        frozen_basis,
        journal_required: raw.journal_required != 0,
        projected: raw.projected != 0,
        basis_ingest_revision: raw.basis_ingest_revision,
    })
}

/// The `engine_config` kinds whose payload carries the capture mode (`"capture"`):
/// - `first_run`: the generation-1 act `store_open::write_first_run_config_act` writes at
///   bootstrap (`"capture":"on"`);
/// - `capacity`: every [`IntentLog::record_capacity_config`] act restates the capture mode in
///   force (the carry-forward below);
/// - `mode_change`: a capture-mode change act. No production writer exists in this tree; the
///   tests write it raw to switch the mode, and a future capture-mode entry point writes this
///   kind.
///
/// Every kind in [`ENGINE_CONFIG_KINDS`] is either in this list or outside it:
/// `capacity_activated` (a pointer, `{"activates_generation":N}`) and the three knob kinds
/// ([`crate::config_knobs::KNOB_KINDS`], whose payload carries only its own member). The
/// capture read skips those. A kind outside [`ENGINE_CONFIG_KINDS`] is one this build cannot
/// classify: at the ledger head it refuses the read by name ([`read_capture_act`]); below the
/// head it is history. A new kind joins [`ENGINE_CONFIG_KINDS`] through this list or through
/// the non-carrying half. `s1_every_engine_config_writer_s_kind_is_listed_iff_it_carries_capture`
/// checks both lists against the rows the writers actually produce.
pub(crate) const CAPTURE_KINDS: [&str; 3] = ["first_run", "capacity", "mode_change"];

/// Every `engine_config` kind this build writes: [`CAPTURE_KINDS`] ∪ `capacity_activated` ∪
/// [`crate::config_knobs::KNOB_KINDS`], concatenated at compile time so the union has one
/// spelling. The durable store's capture read refuses a head act of any other kind
/// ([`read_capture_act`]). The in-memory twin models no `engine_config` acts for the capture
/// mode, so this partition has no twin half.
pub(crate) const ENGINE_CONFIG_KINDS: [&str; CAPTURE_KINDS.len() + 1 + crate::config_knobs::KNOB_KINDS.len()] = {
    let knobs = crate::config_knobs::KNOB_KINDS;
    let mut out = [""; CAPTURE_KINDS.len() + 1 + crate::config_knobs::KNOB_KINDS.len()];
    let mut i = 0;
    while i < CAPTURE_KINDS.len() {
        out[i] = CAPTURE_KINDS[i];
        i += 1;
    }
    out[i] = "capacity_activated";
    let mut j = 0;
    while j < knobs.len() {
        out[i + 1 + j] = knobs[j];
        j += 1;
    }
    out
};

/// The capture-mode act read, a partition of the ledger by kind. `record`'s admission read
/// and `record_capacity_config`'s carry-forward both call it, so the two read the ledger one
/// way. First the head act of the whole ledger: a kind outside [`ENGINE_CONFIG_KINDS`]
/// refuses by name, since this build cannot tell whether it restates the capture mode and
/// skipping it would be a guess. Then the capture mode in force: the latest act of a kind in
/// [`CAPTURE_KINDS`]. An unknown kind below the head is history and is not consulted. `door`
/// names the caller in both the refusal (`"{door} refused: …"`) and a SQL failure
/// (`"{door} capture read: …"`).
fn read_capture_act(tx: &rusqlite::Transaction<'_>, door: &str) -> Result<(i64, String), LogError> {
    let (head_generation, head_kind): (i64, String) = tx
        .query_row(
            "SELECT generation, kind FROM engine_config ORDER BY generation DESC LIMIT 1;",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map_err(|e| LogError(format!("{door} capture read: {e}")))?;
    if !ENGINE_CONFIG_KINDS.contains(&head_kind.as_str()) {
        return Err(LogError(format!(
            "{door} refused: engine_config kind '{head_kind}' at generation {head_generation} is not one this build knows — \
             refusing rather than guessing whether it carries the capture mode"
        )));
    }
    let [first_run, capacity, mode_change] = CAPTURE_KINDS;
    tx.query_row(
        "SELECT generation, payload FROM engine_config
          WHERE kind IN (?1, ?2, ?3)
          ORDER BY generation DESC LIMIT 1;",
        rusqlite::params![first_run, capacity, mode_change],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .map_err(|e| LogError(format!("{door} capture read: {e}")))
}

/// Read the capture mode out of a config-act payload, strictly and fail-closed.
///
/// The payload must be JSON whose top-level `"capture"` is exactly the string `"on"` or
/// `"off"`. Anything else (malformed JSON, a missing field, a non-string, an unknown word)
/// refuses admission. A SQL `payload LIKE '%"capture":"on"%'` substring match would fail open
/// twice over: a pretty-printed act (`"capture": "on"`) reads as capture off and binds
/// `journal_required=0` on an operation that owes a pre-state journal, and an unreadable act
/// reads as off rather than refusing. The mode is bound as provenance, so a mode that cannot
/// be read is not a mode; it is a refusal.
pub(crate) fn capture_mode_is_on(generation: i64, payload: &str) -> Result<bool, LogError> {
    let refuse = |why: String| {
        LogError(format!(
            "admission refused: config act generation {generation} {why} — the capture mode is \
             unreadable and is never assumed off (design §1c)"
        ))
    };
    // Parse through a named-field struct, never `serde_json::Value`: Value's map keeps the
    // last duplicate member, so {"capture":"on","capture":"off"} would read as off and
    // reversing the order would flip the verdict. serde's named-field visitor refuses a
    // duplicate `capture` ("duplicate field") and a missing one ("missing field"), and unknown
    // sibling members (retention, durability, schema_version…) stay ignored.
    #[derive(serde::Deserialize)]
    struct CapturePayload {
        capture: serde_json::Value,
    }
    let parsed: CapturePayload = serde_json::from_str(payload)
        .map_err(|e| refuse(format!("is not a readable config act ({e})")))?;
    match parsed.capture {
        serde_json::Value::String(s) if s == "on" => Ok(true),
        serde_json::Value::String(s) if s == "off" => Ok(false),
        serde_json::Value::String(s) => {
            Err(refuse(format!("carries capture=\"{s}\", not \"on\" or \"off\"")))
        }
        _ => Err(refuse("carries a non-string \"capture\" field".into())),
    }
}

/// Read [`crate::capacity::EffectiveBounds`] off the ledger's two act families, through
/// `crate::capacity::effective_bounds`'s pure derivation. Shared by `record`'s admission read
/// and `record_capacity_config`'s no-traffic fit-check, so the two read the ledger one way.
///
/// Both act families are parsed in Rust by the shared authorities: the capacity acts by
/// `crate::capacity::CapacityConfig::from_engine_payload` inside `effective_bounds`, and the
/// activation pointer by `crate::capacity::parse_activation_pointer` here. The SQL selects the
/// payload and nothing else (no `json_extract`, no `CAST`). Collapsing the pointer through
/// `Option<i64>` would make an act whose pointer is missing, null, wrong-typed or negative
/// indistinguishable from "no activation act exists", and the latter legitimately seats the
/// compiled default as current. See `crate::capacity`'s "ONE STRICT PARSE AUTHORITY" section.
pub(crate) fn read_effective_bounds(
    tx: &rusqlite::Transaction<'_>,
) -> Result<crate::capacity::EffectiveBounds, LogError> {
    // `Option<(generation, payload)>` carries the two facts SQL may answer here: whether a
    // `capacity_activated` row exists, and where in the ledger it sits. What the payload says
    // is Rust's business, and the row's own generation is load-bearing (below).
    let activation_row: Option<(i64, String)> = tx
        .query_row(
            "SELECT generation, payload FROM engine_config WHERE kind = 'capacity_activated'
              ORDER BY generation DESC LIMIT 1;",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(|e| LogError(format!("activation read: {e}")))?;
    let activation: Option<(i64, i64)> = match activation_row {
        None => None,
        Some((row_generation, payload)) => {
            let pointer = crate::capacity::parse_activation_pointer(&payload)
                // Lossless: the parser refuses anything past `i64::MAX` because
                // `engine_config.generation` is an INTEGER PRIMARY KEY.
                .map(|g| g as i64)
                .map_err(|e| {
                    LogError(format!(
                        "the capacity ledger is unreadable ({e}) — the capacity domain is \
                         never assumed (design §5.3 CONFIGURATION-DOMAIN-PINNING)"
                    ))
                })?;
            // Both ordering refusals (an activation naming its own past, and a stranded act)
            // live in one place: `capacity::effective_bounds` receives the row generation and
            // enforces them for every caller. A synced or restored store is data, not
            // box-owner theater; the authority's doc has the full adversary story.
            Some((row_generation, pointer))
        }
    };
    let activated_generation: Option<i64> = activation.map(|(_, pointer)| pointer);
    // Fetch at most the two rows `effective_bounds` can ever parse: the act the pointer names
    // (a PK lookup) and the newest act past the last activation (an indexed DESC LIMIT 1),
    // rather than every `kind='capacity'` act ever recorded inside this enrolled transaction.
    // Fetching and dropping superseded acts would make every admission's ledger read grow
    // with config history, which is unbounded work a pending sever then waits behind. The
    // strict-greater filter is the one `effective_bounds` applies to the full set, and an
    // activation naming a missing act still reaches `effective_bounds` as an empty lookup, so
    // its refusal by name still fires. The SQL still selects payloads only; parsing stays with
    // the strict authority.
    let mut capacity_acts: Vec<(i64, String)> = Vec::with_capacity(2);
    if let Some(gen) = activated_generation {
        let current_act: Option<(i64, String)> = tx
            .query_row(
                "SELECT generation, payload FROM engine_config
                  WHERE kind = 'capacity' AND generation = ?1;",
                rusqlite::params![gen],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|e| LogError(format!("capacity-acts read: {e}")))?;
        if let Some(row) = current_act {
            capacity_acts.push(row);
        }
    }
    let newest_pending: Option<(i64, String)> = tx
        .query_row(
            "SELECT generation, payload FROM engine_config
              WHERE kind = 'capacity' AND generation > ?1
              ORDER BY generation DESC LIMIT 1;",
            rusqlite::params![activated_generation.unwrap_or(0)],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(|e| LogError(format!("capacity-acts read: {e}")))?;
    if let Some(row) = newest_pending {
        capacity_acts.push(row);
    }
    crate::capacity::effective_bounds(&capacity_acts, activation).map_err(|e| {
        LogError(format!(
            "the capacity ledger is unreadable ({e}) — the capacity domain is never assumed \
             (design §5.3 CONFIGURATION-DOMAIN-PINNING)"
        ))
    })
}

impl IntentLog for SqliteIntentLog {
    fn record(
        &mut self,
        command: &Command,
        basis: &crate::prestate::FrozenBasis,
    ) -> Result<Claim, LogError> {
        reject_reserved_user_key(command)?;
        reject_unreadable_basis(basis)?;
        // The atomic claim: INSERT the fresh Pending row, or DO NOTHING if the key already
        // exists (an existing row is never overwritten; the system of record is immutable).
        // `inserted == 1` means this call inserted, so the caller owns the dispatch
        // (`Inserted`). `inserted == 0` means a row already existed; re-read to distinguish an
        // identical concurrent or prior claim (`AlreadyExisted`, never status-regressed since
        // DO NOTHING touches no row) from a different command (rejected). This signal makes the
        // claim authoritative under same-key concurrency (no double dispatch). See ADR-P013.
        //
        // This is the admission transaction. The claim and the provenance binding
        // (journal_required, capture_mode_generation, admitted_control_epoch, read from the
        // config ledger and the control-epoch singleton) commit together, so a row never exists
        // without the mode generation it was admitted under. Both reads are local (no I/O
        // inside the transaction). `intent_id` is minted opaquely by SQLite's `randomblob(16)`.
        let (action_kind, message_ref) = action_to_parts(&command.action);
        // `Some(claim)` means the admission transaction answered; `None` means the key was
        // already taken and the answer needs a read the enrolled closure must not make.
        let admitted: Option<Claim> = self.with_immediate_tx(|tx| {
            // Duplicate claims resolve before config validation. An existing row already carries
            // the provenance it was admitted under, and ADR-P013's replay contract (identical
            // retry gives AlreadyExisted; a different command is rejected) must hold even when
            // the current config head is unreadable: a broken generation-N act must never turn an
            // idempotent replay into an error.
            let existing = tx
                .query_row(
                    &format!("SELECT {INTENT_COLUMNS} FROM intents WHERE idempotency_key = ?1;"),
                    rusqlite::params![command.idempotency_key],
                    raw_intent_from_row,
                )
                .optional()
                .map_err(|e| LogError(e.to_string()))?
                .map(intent_from_raw)
                .transpose()?;
            if let Some(existing) = existing {
                return if existing.command == *command {
                    Ok(Some(Claim::AlreadyExisted))
                } else {
                    Err(key_rewrite_rejected(&command.idempotency_key))
                };
            }
            // Fresh insert: the admission tier applies (see `reject_inadmissible_basis`). It runs
            // after the duplicate-claim resolution above and before the config read, so an
            // existing legacy row still replays identically while a genuinely new row can never
            // be committed without its target vector.
            reject_inadmissible_basis(basis)?;
            // The plan-child admission, inside this transaction and before the capacity read: a
            // refusal answers `Ok(Some(PlanChildRefused))` before the INSERT, so no `intents` row
            // is written (see `plan_child_admission` for the one write a refusal can leave, the
            // sticky clock's latch on the expiry check).
            if let Some(link) = &command.plan_child {
                if let Some(refusal) = plan_child_admission(tx, command, link)? {
                    return Ok(Some(Claim::PlanChildRefused(refusal)));
                }
            }
            // The capture-mode read and the capacity read are two separate questions over the
            // ledger. A `kind='capacity_activated'` act carries neither `capture` nor `capacity`
            // (it is a pure activation pointer the trigger writes), so reading capture mode off
            // "the latest act" would refuse the next admission after an activation lands. Capture
            // mode reads the latest act of a kind that carries it (`CAPTURE_KINDS`: first_run,
            // capacity, mode_change; every capacity act carries it forward, see
            // `record_capacity_config`), so an activation pointer and a knob act are skipped. A
            // kind this build does not know (outside `ENGINE_CONFIG_KINDS`) at the ledger head
            // refuses admission by name (`read_capture_act`).
            let (generation, capture_payload): (i64, String) = read_capture_act(tx, "admission")?;
            let capture_on = capture_mode_is_on(generation, &capture_payload)?;
            // The derived-occupancy admission check, inside the same `Immediate` transaction as
            // the claim. COUNT and INSERT are atomic because `BEGIN IMMEDIATE` serializes writer
            // transactions entirely, which holds as long as every write transaction is
            // `Immediate` (as this admission path is).
            //
            // The bounds come from `effective_bounds` over the ledger's two act families, never
            // "the latest act", because a `capacity_activated` act can be the latest row without
            // carrying any bounds itself.
            let effective = read_effective_bounds(tx)?;
            let (active_forward, active_undo): (i64, i64) = tx
                .query_row(
                    &format!(
                        "SELECT COUNT(*) FILTER (WHERE compensates IS NULL),
                            COUNT(*) FILTER (WHERE compensates IS NOT NULL)
                       FROM intents WHERE status IN {NON_TERMINAL_STATUS_SQL};"
                    ),
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(|e| LogError(format!("admission occupancy read: {e}")))?;
            let occupancy = crate::capacity::Occupancy {
                active_forward: active_forward as u32,
                active_undo: active_undo as u32,
            };
            // Undo iff this command carries `compensates`, the same discriminator the INSERT
            // below uses for `kind` (`CASE WHEN compensates IS NULL THEN 'forward' ELSE 'undo'`).
            let admission_kind = if command.compensates.is_some() {
                crate::capacity::AdmissionKind::Undo
            } else {
                crate::capacity::AdmissionKind::Forward
            };
            // While a reduction sits pending, forward admission answers to the new (pending)
            // bounds immediately; remedies keep answering to the bounds still current (activation
            // has not yet released enough of the pool for the trigger to fire).
            let capacity_cfg = match (&admission_kind, &effective.pending) {
                (crate::capacity::AdmissionKind::Forward, Some((_, pending))) => pending,
                _ => &effective.current,
            };
            match crate::capacity::admission_check(admission_kind, 1, occupancy, capacity_cfg) {
                Ok(()) => {}
                Err(crate::capacity::CapacityError::Refused(refusal)) => {
                    // Abort before the INSERT: the transaction is dropped without a commit below
                    // (rusqlite rolls back an uncommitted `Transaction` on `Drop`), so nothing
                    // durable is written.
                    return Ok(Some(Claim::CapacityRefused(refusal.to_string())));
                }
                Err(crate::capacity::CapacityError::Domain(e)) => {
                    return Err(LogError(format!(
                        "admission refused: capacity domain error: {e}"
                    )));
                }
            }
            // Serialize the already-resolved basis inside the admission transaction, so the
            // freeze and the claim commit together: a row never exists without the native
            // identity it was admitted against. Serialization is pure (no I/O, no resolver call).
            let frozen_basis = basis
                .to_json()
                .map_err(|e| LogError(format!("admission basis serialization: {e}")))?;
            let epoch: i64 = tx
                .query_row("SELECT epoch FROM control_epoch WHERE id=1;", [], |r| {
                    r.get(0)
                })
                .map_err(|e| LogError(format!("admission epoch read: {e}")))?;
            let inserted = tx
                .execute(
                    "INSERT INTO intents
                   (idempotency_key, account, facet, action_kind, message_ref, status,
                    principal, epoch, evidence_ref, snapshot_ref, tier, compensates, seq,
                    intent_id, kind, parent_intent_id, journal_required,
                    capture_mode_generation, admitted_control_epoch, frozen_basis,
                    plan_id, plan_member, basis_ingest_revision)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                         (SELECT COALESCE(MAX(seq), 0) + 1 FROM intents),
                         lower(hex(randomblob(16))),
                         CASE WHEN ?12 IS NULL THEN 'forward' ELSE 'undo' END,
                         (SELECT intent_id FROM intents WHERE idempotency_key = ?12),
                         ?13, ?14, ?15, ?16, ?17, ?18,
                         -- #75 S1 r5 fold (class P3): the observation this effect will be
                         -- committed against — the header's ingest_revision AT RECORD TIME, the
                         -- last one BEFORE the provider call ever runs. NULL when no header row
                         -- exists yet for this (account, message_ref).
                         (SELECT ingest_revision FROM message_header WHERE account = ?2 AND message_ref = ?5))
                 ON CONFLICT(idempotency_key) DO NOTHING;",
                    rusqlite::params![
                        command.idempotency_key,
                        command.account,
                        facet_to_str(&command.facet),
                        action_kind,
                        message_ref,
                        status_to_str(&IntentStatus::Pending),
                        command.envelope.principal,
                        command.envelope.epoch.map(|e| e as i64),
                        command.envelope.evidence_ref,
                        command.envelope.snapshot_ref,
                        command.envelope.tier,
                        command.compensates,
                        capture_on as i64,
                        generation,
                        epoch,
                        frozen_basis,
                        command.plan_child.as_ref().map(|l| l.plan_id.0.as_str()),
                        command.plan_child.as_ref().map(|l| l.member_ref.as_str()),
                    ],
                )
                .map_err(|e| LogError(e.to_string()))?;
            if inserted == 1 {
                // The audit edge, written inside the admission transaction: the link commits
                // atomically with the successor's admission, before any preparation or dispatch,
                // so a store can never hold an overlapping successor whose edge is missing. It is
                // an audit pointer only. Nothing gates on it; the refusal this successor will
                // meet at the send-authorization check is decided by the obligation rows.
                let successor: String = tx
                    .query_row(
                        "SELECT intent_id FROM intents WHERE idempotency_key = ?1;",
                        rusqlite::params![command.idempotency_key],
                        |r| r.get(0),
                    )
                    .map_err(|e| LogError(format!("admission successor read: {e}")))?;
                let exposure_key = crate::attempt::ExposureKey::from_basis(basis);
                link_supersessions(tx, &successor, &exposure_key, epoch)?;
            }
            if inserted == 1 {
                return Ok(Some(Claim::Inserted));
            }
            // A row already exists for this key. `None` says so: resolving which claim it is
            // needs `self.get`, and the enrolled-write rule forbids calling another method that
            // enrolls from inside an enrolled transaction (one gate per store, so a nested
            // enrollment would wait for itself). The re-read happens below, after the enrollment
            // ends.
            Ok(None)
        })?;
        if let Some(claim) = admitted {
            return Ok(claim);
        }
        // A row already exists for this key. Identical payload: a safe concurrent or prior
        // claim. Different payload: refuse, never overwrite the durable command.
        match self.get(&command.idempotency_key)? {
            Some(existing) if existing.command == *command => Ok(Claim::AlreadyExisted),
            Some(_) => Err(key_rewrite_rejected(&command.idempotency_key)),
            None => Err(LogError(format!(
                "idempotency key '{}' conflicted on insert but no row is present",
                command.idempotency_key
            ))),
        }
    }

    fn get(&self, idempotency_key: &str) -> Result<Option<Intent>, LogError> {
        let raw = self
            .conn
            .query_row(
                &format!("SELECT {INTENT_COLUMNS} FROM intents WHERE idempotency_key = ?1;"),
                rusqlite::params![idempotency_key],
                raw_intent_from_row,
            )
            .optional()
            .map_err(|e| LogError(e.to_string()))?;
        raw.map(intent_from_raw).transpose()
    }

    fn unreconciled(&self) -> Result<Vec<Intent>, LogError> {
        // Parse every row, then filter to non-terminal statuses in Rust; never filter by status
        // in SQL. SQL filtering would silently exclude a corrupt or unknown status row (it
        // matches no known value), so recovery would report success while leaving a bad durable
        // row behind (fail-open). Parsing first surfaces such a row as a `LogError`
        // (`status_from_str`), so the system of record fails closed.
        let mut stmt = self
            .conn
            .prepare(
                &format!("SELECT {INTENT_COLUMNS} FROM intents ORDER BY seq;"),
            )
            .map_err(|e| LogError(e.to_string()))?;
        let rows = stmt
            .query_map([], raw_intent_from_row)
            .map_err(|e| LogError(e.to_string()))?;
        let mut unreconciled = Vec::new();
        for row in rows {
            let raw = row.map_err(|e| LogError(e.to_string()))?;
            let intent = intent_from_raw(raw)?;
            // The status domain comes from the one authority, never a hand-enumerated subset.
            if !intent.status.is_terminal() {
                unreconciled.push(intent);
            }
        }
        Ok(unreconciled)
    }

    fn applied_unprojected_forward_intents(&self) -> Result<Vec<Intent>, LogError> {
        // Same fail-closed shape as `unreconciled`: parse every row and filter in Rust, never a
        // SQL `WHERE status = 'applied'`, so a corrupt or unknown status value surfaces as a
        // `LogError` rather than silently sorting outside every listing.
        let mut stmt = self
            .conn
            .prepare(&format!("SELECT {INTENT_COLUMNS} FROM intents ORDER BY seq;"))
            .map_err(|e| LogError(e.to_string()))?;
        let rows = stmt
            .query_map([], raw_intent_from_row)
            .map_err(|e| LogError(e.to_string()))?;
        let mut intents = Vec::new();
        for row in rows {
            let raw = row.map_err(|e| LogError(e.to_string()))?;
            let intent = intent_from_raw(raw)?;
            if intent.status == IntentStatus::Applied && !intent.projected && intent.command.compensates.is_none() {
                intents.push(intent);
            }
        }
        Ok(intents)
    }

    fn set_status_if(
        &mut self,
        idempotency_key: &str,
        precondition: StatusPrecondition,
        status: IntentStatus,
    ) -> Result<StatusWrite, LogError> {
        // Routed through the `settle_status` chokepoint (every status write goes through it),
        // inside its own governed `Immediate` transaction. This method has no fact of its own to
        // append (unlike `terminalize_operation`'s callers, which are already inside a
        // fact-appending transaction), so it opens one here: the compare-and-set and the
        // `intents_status_activation` trigger's observation of any release it causes commit
        // together. The compare stays inside the write (see `settle_status`); a read-then-write
        // would be a TOCTOU.
        self.with_immediate_tx(|tx| {
            let outcome = settle_status(tx, idempotency_key, &precondition, status)?;
            Ok(outcome)
        })
    }

    fn record_capacity_config(
        &mut self,
        new: crate::capacity::CapacityConfig,
    ) -> Result<(), LogError> {
        new.validate()
            .map_err(|e| LogError(format!("record_capacity_config refused: {e}")))?;
        self.with_immediate_tx(|tx| {
            // Carry the current capture mode forward unchanged: `record`'s admission read takes
            // capture mode from the latest act of a kind in `CAPTURE_KINDS`, and `capacity` is
            // one of them, so every capacity act restates it. This uses the same read `record`
            // makes (`read_capture_act`), including its refusal of an unknown kind at the ledger
            // head.
            let (capture_generation, capture_payload): (i64, String) = read_capture_act(tx, "record_capacity_config")?;
            let capture_on = capture_mode_is_on(capture_generation, &capture_payload)?;
            let capacity_payload = format!(
                "{{\"capture\":\"{}\",\"capacity\":{{\"max_active_ops\":{},\"undo_reserve\":{},\
             \"writer_chunk_budget_ms\":{},\"sever_watchdog_ms\":{},\"sever_joiner_cap\":{}}}}}",
                if capture_on { "on" } else { "off" },
                new.max_active_ops,
                new.undo_reserve,
                new.writer_chunk_budget_ms,
                new.sever_watchdog_ms,
                new.sever_joiner_cap,
            );
            tx.execute(
                "INSERT INTO engine_config (generation, recorded_at, kind, payload)
             VALUES ((SELECT MAX(generation) + 1 FROM engine_config), strftime('%s','now'),
                     'capacity', ?1);",
                rusqlite::params![capacity_payload],
            )
            .map_err(|e| LogError(format!("record_capacity_config append: {e}")))?;
            let new_generation: i64 = tx
                .query_row("SELECT MAX(generation) FROM engine_config;", [], |r| r.get(0))
                .map_err(|e| LogError(format!("record_capacity_config generation read: {e}")))?;
            // The same fit-check `activation_fits` answers, over current occupancy: this
            // transaction's own no-traffic activation check. It is separate from the
            // `intents_status_activation` SQL trigger because the event here is a new config act,
            // never a status write, so there is no dual-authority drift.
            let (active_forward, active_undo): (i64, i64) = tx
                .query_row(
                    &format!(
                        "SELECT COUNT(*) FILTER (WHERE compensates IS NULL),
                            COUNT(*) FILTER (WHERE compensates IS NOT NULL)
                       FROM intents WHERE status IN {NON_TERMINAL_STATUS_SQL};"
                    ),
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(|e| LogError(format!("record_capacity_config occupancy read: {e}")))?;
            let occupancy = crate::capacity::Occupancy {
                active_forward: active_forward as u32,
                active_undo: active_undo as u32,
            };
            if crate::capacity::activation_fits(occupancy, &new) {
                tx.execute(
                    "INSERT INTO engine_config (generation, recorded_at, kind, payload)
                 VALUES ((SELECT MAX(generation) + 1 FROM engine_config), strftime('%s','now'),
                         'capacity_activated', json_object('activates_generation', ?1));",
                    rusqlite::params![new_generation],
                )
                .map_err(|e| LogError(format!("record_capacity_config activate: {e}")))?;
            }
            Ok(())
        })
    }

    fn registered_key_fingerprint(&self) -> Result<Option<String>, LogError> {
        self.conn
            .query_row(
                "SELECT fingerprint FROM commitment_key_registry WHERE id = 1;",
                [],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| LogError(format!("commitment_key_registry read: {e}")))
    }

    fn register_key_fingerprint(&mut self, fingerprint: &str) -> Result<(), LogError> {
        if fingerprint.is_empty() {
            return Err(LogError("register_key_fingerprint: empty fingerprint".into()));
        }
        let fingerprint = fingerprint.to_string();
        self.with_immediate_tx(move |tx| {
            // INSERT, never OR REPLACE: a second registration is refused by the
            // `commitment_key_registry_no_replace` trigger (and behind it the PK on id = 1).
            tx.execute(
                "INSERT INTO commitment_key_registry (id, fingerprint, registered_at)
                 VALUES (1, ?1, strftime('%Y-%m-%dT%H:%M:%SZ','now'));",
                rusqlite::params![fingerprint],
            )
            .map_err(|e| LogError(format!("commitment_key_registry register: {e}")))?;
            Ok(())
        })
    }

    fn record_knob_act(&mut self, act: crate::config_knobs::KnobAct) -> Result<u64, LogError> {
        // Re-read through the kind's own reader before the INSERT: an act the reader refuses
        // (`SummarySample { configured_k: 0 }`) is refused at set time and nothing is appended,
        // rather than stored as a head act no read can use.
        let kind = act.kind();
        let payload = act.checked_payload().map_err(|e| LogError(format!("record_knob_act: {e}")))?;
        self.with_immediate_tx(|tx| {
            // The same append shape as `record_capacity_config`: the next generation on the one
            // ledger (append-only by `engine_config_no_update/_no_delete/_no_replace`),
            // unix-seconds `recorded_at`, then the generation read back in the same transaction.
            tx.execute(
                "INSERT INTO engine_config (generation, recorded_at, kind, payload)
             VALUES ((SELECT MAX(generation) + 1 FROM engine_config), strftime('%s','now'),
                     ?1, ?2);",
                rusqlite::params![kind, payload],
            )
            .map_err(|e| LogError(format!("record_knob_act append: {e}")))?;
            let generation: i64 = tx
                .query_row("SELECT MAX(generation) FROM engine_config;", [], |r| r.get(0))
                .map_err(|e| LogError(format!("record_knob_act generation read: {e}")))?;
            u64::try_from(generation)
                .map_err(|_| LogError(format!("record_knob_act: generation {generation} is negative")))
        })
    }

    fn knob_state(&self) -> Result<crate::config_knobs::KnobState, LogError> {
        // One deferred read transaction (it writes nothing), so the three heads are one snapshot
        // of the ledger: a knob act committing between two reads cannot make this answer a
        // state that never existed. The heads are read by `knob_state_in`, the same read the
        // plan mint and the approval make inside their own transactions.
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| LogError(format!("knob_state txn begin: {e}")))?;
        knob_state_in(&tx)?.map_err(|e| LogError(format!("knob_state: {e}")))
    }

    fn mint_plan(&mut self, root_key: &crate::commitment::CommitmentKey, spec: crate::plan::PlanSpec) -> Result<crate::plan::MintedPlan, crate::plan::PlanStoreError> {
        use crate::plan::{MintedPlan, PlanId, PlanStoreError};
        plan_spec_preflight(&spec)?;
        let plan_id = PlanId::mint()?;
        // One immediate transaction: the member rows, the knob heads, the control epoch and the
        // sticky clock are one snapshot, and every refusal below rolls it back, so a mint that
        // refuses writes nothing (not even the latch advance).
        let plan = self
            .conn
            .with_immediate_tx(|tx| -> Result<crate::plan::TriagePlan, PlanTxError> {
                let facts = read_member_facts_in(tx, &spec.account, &spec.member_refs)?;
                let knobs = knob_state_in(tx)?.map_err(|e| PlanStoreError::Knob(e.to_string()))?;
                let control_epoch: i64 = tx.query_row("SELECT epoch FROM control_epoch WHERE id = 1;", [], |r| r.get(0))?;
                let minted_at = sticky_effective_now(tx, "mint_plan")?;
                let plan = assemble_plan(root_key, spec, plan_id, facts, PlanMintInputs { knobs, control_epoch, minted_at })?;
                insert_plan_rows(tx, &plan)?;
                Ok(plan)
            })
            .map_err(PlanStoreError::from)?;
        Ok(MintedPlan::of(&plan))
    }

    fn plan(&self, plan_id: &crate::plan::PlanId) -> Result<Option<crate::plan::TriagePlan>, LogError> {
        // A deferred read transaction (it writes nothing), so the plan row and its member rows
        // are one snapshot.
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| LogError(format!("plan txn begin: {e}")))?;
        read_plan_in(&tx, plan_id)
    }

    fn record_approval(&mut self, root_key: &crate::commitment::CommitmentKey, plan_id: &crate::plan::PlanId, approver: &str, rendered: crate::plan::RenderedView) -> Result<crate::plan::ApprovalEvidence, crate::plan::PlanStoreError> {
        use crate::plan::PlanStoreError;
        // `start_episode`'s two checks run here too (an honesty check, not a control; the
        // send guard, `start_episode` and `record()` refuse both later). A refusal from them is
        // answered as `Ok(Err(..))` so the transaction commits, keeping the expiry check's
        // sticky-clock latch advance exactly as `start_episode_in`'s refusals do; every other
        // refusal rolls the transaction back.
        self.conn
            .with_immediate_tx(|tx| -> Result<Result<crate::plan::ApprovalEvidence, PlanStoreError>, PlanTxError> {
                let plan = read_plan_in(tx, plan_id)?.ok_or_else(|| PlanStoreError::PlanNotFound(plan_id.clone()))?;
                let approved: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM approval_evidence WHERE plan_id = ?1);",
                    rusqlite::params![plan_id.0],
                    |r| r.get(0),
                )?;
                if approved {
                    return Err(PlanStoreError::AlreadyApproved.into());
                }
                let current: i64 = tx.query_row("SELECT epoch FROM control_epoch WHERE id = 1;", [], |r| r.get(0))?;
                if current != plan.control_epoch {
                    return Ok(Err(PlanStoreError::EpochMismatch { plan: plan.control_epoch, current }));
                }
                let knobs = knob_state_in(tx)?.map_err(|e| PlanStoreError::Knob(e.to_string()))?;
                let approved_at = sticky_effective_now(tx, "record_approval")?;
                if plan.expires_at.as_str() <= approved_at.as_str() {
                    return Ok(Err(PlanStoreError::Expired { expires_at: plan.expires_at.clone(), effective_now: approved_at }));
                }
                let evidence = build_approval_evidence(root_key, &plan, approver, approved_at, rendered, knobs.red_bypass.generation)?;
                insert_evidence_row(tx, &evidence)?;
                Ok(Ok(evidence))
            })
            .map_err(PlanStoreError::from)?
    }

    fn approval(&self, plan_id: &crate::plan::PlanId) -> Result<Option<crate::plan::ApprovalEvidence>, LogError> {
        read_evidence_in(&self.conn, plan_id)
    }

    fn start_episode(&mut self, plan_id: &crate::plan::PlanId) -> Result<crate::episode::EpisodeStart, crate::episode::EpisodeRefusal> {
        // A refusal is answered as `Ok(Err(..))` from inside the transaction so the sticky
        // clock's latch advance (when the call read the clock) commits with it; see
        // `start_episode_in`.
        self.with_immediate_tx(|tx| start_episode_in(tx, plan_id))?
    }

    fn episode(&self, plan_id: &crate::plan::PlanId) -> Result<Option<crate::episode::Episode>, LogError> {
        read_episode_in(&self.conn, plan_id)
    }

    fn episode_status_check(&self, plan_id: &crate::plan::PlanId) -> Result<Option<crate::episode::EpisodeStatusToken>, LogError> {
        let status: Option<String> = self
            .conn
            .query_row("SELECT status FROM execution_episode WHERE plan_id = ?1;", rusqlite::params![plan_id.0], |r| r.get(0))
            .optional()
            .map_err(|e| LogError(format!("episode_status_check: {e}")))?;
        status
            .map(|s| {
                crate::episode::EpisodeStatusToken::from_token(&s)
                    .ok_or_else(|| LogError(format!("episode_status_check: status token '{s}' is not one this build writes")))
            })
            .transpose()
    }

    fn mark_ready(&mut self, plan_id: &crate::plan::PlanId) -> Result<crate::episode::ReadyOutcome, crate::episode::EpisodeRefusal> {
        self.with_immediate_tx(|tx| mark_ready_in(tx, plan_id))?
    }

    fn invalidate_episode(&mut self, plan_id: &crate::plan::PlanId, reason: crate::episode::InvalidationReason) -> Result<(), crate::episode::EpisodeRefusal> {
        self.with_immediate_tx(|tx| invalidate_episode_in_tx(tx, plan_id, &reason))?
    }

    fn complete_episode_if_done(&mut self, plan_id: &crate::plan::PlanId) -> Result<crate::episode::Completion, LogError> {
        self.with_immediate_tx(|tx| complete_episode_if_done_in(tx, plan_id))
    }

    fn dead_letter_if_quiescent(
        &mut self,
        idempotency_key: &str,
    ) -> Result<DeadLetterWrite, LogError> {
        // One IMMEDIATE transaction: the write lock is taken at BEGIN, so a peer's CLAIM or
        // `SEND_AUTHORIZED` either committed before this transaction read the chain or waits
        // behind it. A version that read the head in one transaction and wrote the terminal in
        // another could not close the window the caller left between them, since SQLite's
        // single writer cannot linearize it.
        self.with_immediate_tx(|tx| {
            let owner: Option<String> = tx
                .query_row(
                    "SELECT intent_id FROM intents WHERE idempotency_key = ?1;",
                    rusqlite::params![idempotency_key],
                    |r| r.get(0),
                )
                .optional()
                .map_err(|e| LogError(format!("dead_letter_if_quiescent read: {e}")))?;
            let Some(owner) = owner else {
                return Ok(DeadLetterWrite::StatusMoved(None));
            };
            // The head predicate, inside this transaction: the same partition and the same
            // projection [`IntentLog::live_attempt`] answers with, so this method and the read
            // cannot describe one store differently (a multi-live-attempt store defect also fails
            // loudly here exactly as it does there).
            let live = live_attempts_of(tx, &owner)?;
            if let Some(live) = live_attempt_from(sever_disposition(&owner, &live)?) {
                return Ok(DeadLetterWrite::LiveAttempt(live.class));
            }
            // And the status transition, under the same non-terminal guard `set_status_if` takes,
            // interpolated from the one authority.
            let changed = tx
                .execute(
                    &format!(
                        "UPDATE intents SET status = 'failed'
                      WHERE idempotency_key = ?1 AND status IN {NON_TERMINAL_STATUS_SQL};"
                    ),
                    rusqlite::params![idempotency_key],
                )
                .map_err(|e| LogError(format!("dead_letter_if_quiescent write: {e}")))?;
            if changed == 0 {
                // Refused: the refusal names the world, read through the fail-closed mapper.
                let raw: Option<String> = tx
                    .query_row(
                        "SELECT status FROM intents WHERE idempotency_key = ?1;",
                        rusqlite::params![idempotency_key],
                        |r| r.get(0),
                    )
                    .optional()
                    .map_err(|e| LogError(format!("dead_letter_if_quiescent read back: {e}")))?;
                let actual = raw.map(|s| status_from_str(&s)).transpose()?;
                return Ok(DeadLetterWrite::StatusMoved(actual));
            }
            Ok(DeadLetterWrite::Written)
        })
    }

    fn verify_undo_pair(
        &mut self,
        parent_key: &str,
        child_key: &str,
        child: UndoPairChild,
    ) -> Result<UndoPairFlip, LogError> {
        // One IMMEDIATE transaction: the write lock is taken at BEGIN, so a concurrent sever
        // either committed before this transaction saw the rows or waits behind it. Nothing
        // commits unless both preconditions hold (see the trait doc for why guarding the child
        // write alone is not enough: the parent's `Undone` would already be durable).
        self.with_immediate_tx(|tx| {
            let status_of = |key: &str| -> Result<Option<IntentStatus>, LogError> {
                let raw: Option<String> = tx
                    .query_row(
                        "SELECT status FROM intents WHERE idempotency_key = ?1;",
                        rusqlite::params![key],
                        |r| r.get(0),
                    )
                    .optional()
                    .map_err(|e| LogError(format!("verify_undo_pair read '{key}': {e}")))?;
                raw.map(|s| status_from_str(&s)).transpose()
            };
            let child_status = status_of(child_key)?;
            if child_status.as_ref().is_none_or(IntentStatus::is_terminal) {
                return Ok(UndoPairFlip::ChildMoved(child_status));
            }
            let parent_status = status_of(parent_key)?;
            // `Undone` is accepted because the crash-heal re-drive legitimately re-verifies a
            // pair whose parent flip already committed. Every other status is a pair that moved
            // under this verification.
            if !matches!(
                parent_status,
                Some(IntentStatus::Applied | IntentStatus::Undone)
            ) {
                return Ok(UndoPairFlip::ParentMoved(parent_status));
            }
            tx.execute(
                "UPDATE intents SET status = 'undone' WHERE idempotency_key = ?1;",
                rusqlite::params![parent_key],
            )
            .map_err(|e| LogError(format!("verify_undo_pair parent flip: {e}")))?;
            if child == UndoPairChild::Terminalize {
                tx.execute(
                    &format!(
                        "UPDATE intents SET status = 'applied'
                      WHERE idempotency_key = ?1 AND status IN {NON_TERMINAL_STATUS_SQL};"
                    ),
                    rusqlite::params![child_key],
                )
                .map_err(|e| LogError(format!("verify_undo_pair child terminal: {e}")))?;
            }
            Ok(UndoPairFlip::Flipped)
        })
    }

    fn charge_and_dead_letter_if_quiescent(
        &mut self,
        idempotency_key: &str,
        cap: u32,
    ) -> Result<TransientCharge, LogError> {
        // One IMMEDIATE transaction: the write lock is taken at BEGIN, so a peer's CLAIM or
        // `SEND_AUTHORIZED` either committed before this transaction read the chain or waits
        // behind it. A transaction keeps the atomicity of the earlier single CASE statement (the
        // charge and the terminal commit together or neither does, so a crash can never leave
        // `attempts >= cap` on a non-terminal row) and also holds the head predicate, because a
        // head read outside the write that acts on it is the window `dead_letter_if_quiescent`
        // exists to close.
        self.with_immediate_tx(|tx| {
            let row: Option<(String, String)> = tx
                .query_row(
                    "SELECT intent_id, status FROM intents WHERE idempotency_key = ?1;",
                    rusqlite::params![idempotency_key],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()
                .map_err(|e| LogError(format!("charge_and_dead_letter read: {e}")))?;
            let Some((owner, raw_status)) = row else {
                return Ok(TransientCharge::ChargeRefusedTerminal(None));
            };
            // Read through the fail-closed mapper: a corrupt status token is a `LogError` here as
            // everywhere else, never a silent "not terminal".
            let status = status_from_str(&raw_status)?;
            if status.is_terminal() {
                return Ok(TransientCharge::ChargeRefusedTerminal(Some(status)));
            }
            // The charge, which must survive every refusal below it.
            tx.execute(
                "UPDATE intents SET attempts = attempts + 1 WHERE idempotency_key = ?1;",
                rusqlite::params![idempotency_key],
            )
            .map_err(|e| LogError(format!("charge_and_dead_letter charge: {e}")))?;
            let attempts: i64 = tx
                .query_row(
                    "SELECT attempts FROM intents WHERE idempotency_key = ?1;",
                    rusqlite::params![idempotency_key],
                    |r| r.get(0),
                )
                .map_err(|e| LogError(format!("charge_and_dead_letter attempts read: {e}")))?;
            if attempts < i64::from(cap) {
                return Ok(TransientCharge::ChargedOnly);
            }
            // The head predicate, inside this transaction: the same partition and projection
            // [`IntentLog::live_attempt`] answers with, exactly as `dead_letter_if_quiescent`
            // reads it (a multi-live-attempt store defect also fails loudly here). The budget
            // counter cannot attribute anything to an attempt this caller does not own.
            let live = live_attempts_of(tx, &owner)?;
            if live_attempt_from(sever_disposition(&owner, &live)?).is_some() {
                return Ok(TransientCharge::ChargedOnly);
            }
            // And the status transition, under the same non-terminal guard `set_status_if` takes,
            // interpolated from `NON_TERMINAL_STATUS_SQL`. Nothing can have moved the row inside
            // this transaction, so the compare can only agree; the domain is derived, not
            // re-stated.
            let changed = tx
                .execute(
                    &format!(
                        "UPDATE intents SET status = 'failed'
                      WHERE idempotency_key = ?1 AND status IN {NON_TERMINAL_STATUS_SQL};"
                    ),
                    rusqlite::params![idempotency_key],
                )
                .map_err(|e| LogError(format!("charge_and_dead_letter write: {e}")))?;
            if changed == 0 {
                // Impossible inside this transaction: the row was read non-terminal above and
                // nothing but this transaction can have written it since. A refusal here would
                // mean the compare and the read disagree about one store, so it is an explicit
                // error, never a quiet `false` and never a commit of a charge described as refused.
                return Err(LogError(format!(
                    "charge_and_dead_letter: '{idempotency_key}' read non-terminal ({status:?}) and \
                 then refused the non-terminal compare inside the same transaction"
                )));
            }
            Ok(TransientCharge::ChargedAndDeadLettered)
        })
    }

    fn dead_letters(&self) -> Result<Vec<Intent>, LogError> {
        // Parse every row, then filter to `Failed` in Rust; never SQL-filter by status (a
        // corrupt status row would silently vanish from the SELECT, fail-open). Parsing first
        // surfaces a bad row as a LogError, the same fail-closed discipline as `unreconciled`.
        let mut stmt = self
            .conn
            .prepare(
                &format!("SELECT {INTENT_COLUMNS} FROM intents ORDER BY seq;"),
            )
            .map_err(|e| LogError(e.to_string()))?;
        let rows = stmt
            .query_map([], raw_intent_from_row)
            .map_err(|e| LogError(e.to_string()))?;
        let mut dead = Vec::new();
        for row in rows {
            let raw = row.map_err(|e| LogError(e.to_string()))?;
            let intent = intent_from_raw(raw)?;
            if matches!(intent.status, IntentStatus::Failed) {
                dead.push(intent);
            }
        }
        Ok(dead)
    }

    fn latest_intent_for_message_ref(
        &self,
        account: &str,
        message_ref: &str,
    ) -> Result<Option<Intent>, LogError> {
        // Column order must match `raw_intent_from_row` (the shared mapper). Filtering by
        // account/message_ref/seq in SQL is safe (these are not enum-parsed columns); the single
        // row is then parsed via the fail-closed `intent_from_raw`.
        let raw = self
            .conn
            .query_row(
                &format!(
                    "SELECT {INTENT_COLUMNS} FROM intents
                       WHERE account = ?1 AND message_ref = ?2 ORDER BY seq DESC LIMIT 1;"
                ),
                rusqlite::params![account, message_ref],
                raw_intent_from_row,
            )
            .optional()
            .map_err(|e| LogError(e.to_string()))?;
        raw.map(intent_from_raw).transpose()
    }

    fn has_non_terminal_native_predecessor(
        &self,
        native_key: &str,
        fallback_message_ref: &str,
        account: &str,
        before_seq: u64,
        exclude_idempotency_key: &str,
    ) -> Result<bool, LogError> {
        // The predicate, from its one home (`non_terminal_native_predecessor_sql`): the same
        // text PREPARE's in-transaction re-verify runs, so the gate and the re-verify cannot
        // drift. Status is filtered in SQL here, unlike `unreconciled()`: this is an existence
        // predicate over the non-terminal domain, so an unknown or corrupt status token is not
        // silently dropped from a set the caller must act on; it simply is not one of the
        // states that block the head. The domain comes from `NON_TERMINAL_STATUS_SQL`.
        let blocked: i64 = self
            .conn
            .query_row(
                &non_terminal_native_predecessor_sql(true),
                rusqlite::params![
                    // Saturating: the "whole tail" sentinel (u64::MAX) must not wrap to -1 and
                    // silently make the predicate always false.
                    before_seq.min(i64::MAX as u64) as i64,
                    account,
                    native_key,
                    fallback_message_ref,
                    exclude_idempotency_key
                ],
                |r| r.get(0),
            )
            .map_err(|e| LogError(e.to_string()))?;
        Ok(blocked == 1)
    }

    fn prepare(
        &mut self,
        key: &str,
        journal: &crate::prestate::JournalRow,
    ) -> Result<crate::prestate::PrepareOutcome, LogError> {
        use crate::prestate::PrepareOutcome;
        self.with_immediate_tx(|tx| {
            #[allow(clippy::type_complexity)]
            let (intent_id, kind, jr, cmg, ace, seq, fb, message_ref, account, status): (
                String,
                String,
                i64,
                i64,
                i64,
                i64,
                Option<String>,
                String,
                String,
                String,
            ) = tx
                .query_row(
                    "SELECT intent_id, kind, journal_required, capture_mode_generation,
                        admitted_control_epoch, seq, frozen_basis, message_ref, account, status
                   FROM intents WHERE idempotency_key = ?1;",
                    rusqlite::params![key],
                    |r| {
                        Ok((
                            r.get(0)?,
                            r.get(1)?,
                            r.get(2)?,
                            r.get(3)?,
                            r.get(4)?,
                            r.get(5)?,
                            r.get(6)?,
                            r.get(7)?,
                            r.get(8)?,
                            r.get(9)?,
                        ))
                    },
                )
                .map_err(|e| LogError(format!("prepare read: {e}")))?;
            if kind != "forward" || jr != 1 {
                // Capture-off and undo rows never own a journal row.
                return Err(LogError(format!(
                    "prepare refused: intent '{key}' is not a journal-required forward intent"
                )));
            }
            let basis = fb
                .as_deref()
                .map(crate::prestate::FrozenBasis::from_json)
                .transpose()
                .map_err(|e| LogError(format!("prepare refused: {e}")))?
                .ok_or_else(|| {
                    LogError(format!("prepare refused: intent '{key}' has no frozen_basis"))
                })?;
            // The row is the phase, so the boundary validates it against the frozen basis before
            // anything can persist (`JournalRow::validate`, the `FrozenBasis::validate` twin): a
            // malformed or mismatched row would flip `prepared()` true and recovery would skip
            // the real observation.
            journal
                .validate(&basis)
                .map_err(|e| LogError(format!("prepare refused: {e}")))?;
            // Never persist a label vector its own read boundary would refuse.
            journal
                .observed_label_vector_set()
                .map_err(|e| LogError(format!("prepare refused: {}", e.0)))?;
            // Already prepared? Never re-capture.
            let exists: i64 = tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM pre_state WHERE intent_id = ?1);",
                    rusqlite::params![intent_id],
                    |r| r.get(0),
                )
                .map_err(|e| LogError(e.to_string()))?;
            if exists == 1 {
                return Ok(PrepareOutcome::AlreadyPrepared);
            }
            // The INSERT path requires a pre-dispatch state: journaling an Applied, Undoing or
            // Undone intent would persist a post-effect observation (which poisons no-op
            // detection) and suppress the open-time JournalGapUnexplained evidence. The
            // existing-row answer above stays idempotent: the row, not the status, is the
            // phase. `IntentStatus::is_pre_dispatch` is the single authority for the axis,
            // reached through the same status parser every read path uses.
            //
            // The refusal splits, because two different situations reach it, and `recover`
            // treats a `LogError` as fatal to the whole sweep:
            //   - Terminal: a sever's atomic closure, or a peer driver's settlement, committed
            //     between the caller's read and this transaction. The capture pipeline's
            //     provider read is a wide window, and this is the race `terminal_disposition`
            //     exists for: a normal closure, reported as a replay is, never "the durable
            //     store is inconsistent" and never an aborted sweep over every unrelated
            //     operation in the same pass.
            //   - Non-terminal and still not pre-dispatch (`Undoing`, and nothing else, as the
            //     axis is exhaustive): a forward journal-required row in that phase is a store
            //     no writer in this engine produces, so it stays an explicit error.
            let parsed = status_from_str(&status)?;
            if !parsed.is_pre_dispatch() {
                if parsed.is_terminal() {
                    return Ok(PrepareOutcome::Closed(parsed));
                }
                return Err(LogError(format!(
                    "prepare refused: intent '{key}' is '{status}', not pre-dispatch — \
                 a post-effect observation is never journaled"
                )));
            }
            // The bound config row exists (existence, never head-equality).
            let cfg: i64 = tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM engine_config WHERE generation = ?1);",
                    rusqlite::params![cmg],
                    |r| r.get(0),
                )
                .map_err(|e| LogError(e.to_string()))?;
            if cfg != 1 {
                return Err(LogError(format!(
                    "prepare refused: bound config act generation {cmg} is missing"
                )));
            }
            // Epoch check: a sever between admission and prepare parks the intent.
            let epoch: i64 = tx
                .query_row("SELECT epoch FROM control_epoch WHERE id = 1;", [], |r| {
                    r.get(0)
                })
                .map_err(|e| LogError(e.to_string()))?;
            if epoch != ace {
                return Ok(PrepareOutcome::EpochFenced);
            }
            // Still at head, re-verified inside the transaction. Same non-terminal domain as the
            // pre-transaction gate, from the one authority: a re-verify using a narrower set than
            // the gate it re-verifies would be worse than none.
            let blocked: i64 = tx
                .query_row(
                    &non_terminal_native_predecessor_sql(false),
                    rusqlite::params![seq, account, basis.native_resource_key, message_ref],
                    |r| r.get(0),
                )
                .map_err(|e| LogError(e.to_string()))?;
            if blocked == 1 {
                return Ok(PrepareOutcome::NotAtHead);
            }
            tx.execute(
                "INSERT INTO pre_state (journal_id, intent_id, observed, touched_atom, resolved_operands,
                                    fetched_at, source, request_id, captured_epoch, mode_generation,
                                    undo_offer_until, observed_label_vector)
             VALUES (lower(hex(randomblob(16))), ?1, ?2, ?3, ?4,
                     strftime('%Y-%m-%dT%H:%M:%SZ','now'), 'live_read', ?5, ?6, ?7,
                     strftime('%Y-%m-%dT%H:%M:%SZ','now', '+' || ?8 || ' seconds'), ?9);",
                rusqlite::params![
                    intent_id,
                    journal.observed,
                    journal.touched_atom,
                    journal.resolved_operands,
                    journal.request_id,
                    epoch,
                    cmg,
                    crate::prestate::UNDO_OFFER_SECONDS as i64,
                    journal.observed_label_vector
                ],
            )
            .map_err(|e| LogError(format!("prepare insert: {e}")))?;
            Ok(PrepareOutcome::Prepared)
        })
    }

    fn prepared(&self, idempotency_key: &str) -> Result<bool, LogError> {
        let exists: i64 = self
            .conn
            .query_row(
                "SELECT EXISTS (SELECT 1 FROM pre_state p
                   JOIN intents i ON i.intent_id = p.intent_id
                  WHERE i.idempotency_key = ?1);",
                rusqlite::params![idempotency_key],
                |r| r.get(0),
            )
            .map_err(|e| LogError(e.to_string()))?;
        Ok(exists == 1)
    }

    fn captured_pre_state(
        &self,
        idempotency_key: &str,
    ) -> Result<Option<CapturedPreState>, LogError> {
        let basis_json: Option<String> = self
            .conn
            .query_row(
                "SELECT frozen_basis FROM intents WHERE idempotency_key = ?1;",
                rusqlite::params![idempotency_key],
                |r| r.get(0),
            )
            .map_err(|e| LogError(format!("captured_pre_state read '{idempotency_key}': {e}")))?;
        // The value and its `capture_generation` in one row read: the CAS token has to name the
        // capture the caller's decision was actually made about.
        let row: Option<(String, String, String, i64, Option<String>)> = self
            .conn
            .query_row(
                "SELECT p.observed, p.touched_atom, p.resolved_operands, p.capture_generation,
                        p.observed_label_vector
                   FROM pre_state p JOIN intents i ON i.intent_id = p.intent_id
                  WHERE i.idempotency_key = ?1;",
                rusqlite::params![idempotency_key],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .optional()
            .map_err(|e| LogError(format!("captured_pre_state row read: {e}")))?;
        let Some((observed, touched_atom, resolved_operands, capture_generation, observed_label_vector)) =
            row
        else {
            return Ok(None);
        };
        let capture_generation = u64::try_from(capture_generation).map_err(|_| {
            LogError(format!(
                "captured_pre_state: '{idempotency_key}' holds a negative capture_generation"
            ))
        })?;
        let row = crate::prestate::JournalRow {
            observed,
            touched_atom,
            resolved_operands,
            request_id: None,
            observed_label_vector,
        };
        // The read boundary, the same one `undo_context` holds: a syntactically valid but
        // inconsistent stored row would forge the comparison this value feeds. Validate only
        // when a basis exists; a legacy row without one keeps its own degradation path, as
        // PREPARE does.
        if let Some(raw) = basis_json.as_deref() {
            let basis = crate::prestate::FrozenBasis::from_json(raw)
                .map_err(|e| LogError(format!("captured_pre_state frozen_basis: {e}")))?;
            row.validate(&basis).map_err(|e| {
                LogError(format!(
                    "captured_pre_state: inconsistent persisted journal row: {e}"
                ))
            })?;
        }
        Ok(Some(CapturedPreState {
            atoms: serde_json::from_str(&row.touched_atom)
                .map_err(|e| LogError(format!("captured_pre_state: corrupt touched_atom: {e}")))?,
            capture_generation,
            observed_label_vector: row.observed_label_vector_set()?,
        }))
    }

    fn record_effect_witness(
        &mut self,
        idempotency_key: &str,
        witness: &EffectWitness,
        pre: Option<&std::collections::BTreeSet<String>>,
    ) -> Result<(), LogError> {
        self.with_immediate_tx(|tx| {
            // The operation, and the basis its closure comes from, read inside the writing
            // transaction.
            let basis_json: Option<Option<String>> = tx
                .query_row(
                    "SELECT frozen_basis FROM intents WHERE idempotency_key = ?1;",
                    rusqlite::params![idempotency_key],
                    |r| r.get(0),
                )
                .optional()
                .map_err(|e| LogError(format!("record_effect_witness read: {e}")))?;
            let Some(basis_json) = basis_json else {
                return Err(LogError(format!(
                    "record_effect_witness refused: no operation '{idempotency_key}'"
                )));
            };
            let basis = basis_json
                .as_deref()
                .map(crate::prestate::FrozenBasis::from_json)
                .transpose()
                .map_err(|e| LogError(format!("record_effect_witness frozen_basis: {e}")))?;
            let row = effect_witness_row(idempotency_key, witness, pre, basis.as_ref())?;
            let (verdict, unexpected) = match row.ripple_verdict.as_ref().map(|v| v.to_columns()) {
                Some((token, unexpected)) => (Some(token), unexpected),
                None => (None, None),
            };
            // Write-once, enforced by the store: the guard is in the UPDATE itself, so a second
            // record cannot land between a read and a write.
            let changed = tx
                .execute(
                    "UPDATE intents
                        SET effect_label_vector = ?2, ripple_verdict = ?3, ripple_unexpected = ?4
                      WHERE idempotency_key = ?1 AND effect_label_vector IS NULL;",
                    rusqlite::params![
                        idempotency_key,
                        row.effect_label_vector.as_ref().map(crate::prestate::label_vector_json),
                        verdict,
                        unexpected
                    ],
                )
                .map_err(|e| LogError(format!("record_effect_witness write: {e}")))?;
            if changed == 0 {
                // The row exists (read above, in this transaction), so the guard is what refused.
                return Err(effect_witness_already_recorded(idempotency_key));
            }
            Ok(())
        })
    }

    fn effect_witness(&self, idempotency_key: &str) -> Result<Option<EffectWitnessRow>, LogError> {
        let stored: Option<(Option<String>, Option<String>, Option<String>)> = self
            .conn
            .query_row(
                "SELECT effect_label_vector, ripple_verdict, ripple_unexpected
                   FROM intents WHERE idempotency_key = ?1;",
                rusqlite::params![idempotency_key],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(|e| LogError(format!("effect_witness read: {e}")))?;
        let Some((vector, token, unexpected)) = stored else {
            return Err(LogError(format!("effect_witness: no operation '{idempotency_key}'")));
        };
        let ripple_verdict =
            crate::prestate::RippleVerdict::from_columns(token.as_deref(), unexpected.as_deref())
                .map_err(|e| LogError(format!("effect_witness: {e}")))?;
        let Some(vector) = vector else {
            if ripple_verdict.is_some() {
                return Err(LogError(
                    "effect_witness: a ripple verdict is stored with no effect vector".into(),
                ));
            }
            return Ok(None);
        };
        let effect_label_vector = crate::prestate::parse_label_vector("effect_label_vector", &vector)
            .map_err(|e| LogError(format!("effect_witness: {e}")))?;
        Ok(Some(EffectWitnessRow {
            effect_label_vector: Some(effect_label_vector),
            ripple_verdict,
        }))
    }

    fn replace_journal_row(
        &mut self,
        idempotency_key: &str,
        journal: &crate::prestate::JournalRow,
    ) -> Result<JournalReplaceOutcome, LogError> {
        use crate::attempt::AttemptClass;
        // One IMMEDIATE writer transaction: the legality check, the DELETE and the INSERT are
        // indivisible, so a crash leaves either the old complete row or the new complete row,
        // never a blend.
        self.with_immediate_tx(|tx| {
            let (intent_id, basis_json, cmg): (String, Option<String>, i64) = tx
                .query_row(
                    "SELECT intent_id, frozen_basis, capture_mode_generation
                   FROM intents WHERE idempotency_key = ?1;",
                    rusqlite::params![idempotency_key],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .map_err(|e| LogError(format!("replace_journal_row read '{idempotency_key}': {e}")))?;
            let basis = basis_json
                .as_deref()
                .map(crate::prestate::FrozenBasis::from_json)
                .transpose()
                .map_err(|e| LogError(format!("replace_journal_row refused: {e}")))?
                .ok_or_else(|| {
                    LogError(format!(
                        "replace_journal_row refused: intent '{idempotency_key}' has no frozen_basis"
                    ))
                })?;
            // The row is the phase, and a REPLACE writes one: the same write-side validation
            // PREPARE performs, at the same grain, before anything can persist.
            journal
                .validate(&basis)
                .map_err(|e| LogError(format!("replace_journal_row refused: {e}")))?;
            journal
                .observed_label_vector_set()
                .map_err(|e| LogError(format!("replace_journal_row refused: {}", e.0)))?;
            let existing: Option<(String, i64)> = tx
                .query_row(
                    "SELECT journal_id, capture_generation FROM pre_state WHERE intent_id = ?1;",
                    rusqlite::params![intent_id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()
                .map_err(|e| LogError(format!("replace_journal_row row read: {e}")))?;
            let Some((_, generation)) = existing else {
                return Ok(JournalReplaceOutcome::NoRowToReplace);
            };
            // The legality condition: legal only while every prior attempt of the operation holds
            // a proven-no-wire terminal. Derived from facts, per attempt, through the class
            // authority; never a status read, and never a count of `intents.attempts`, which is a
            // budget and proves nothing about issuance. `PreIssuance` is admitted because it is
            // the retry's own live attempt: claimed, unauthorized, and therefore provably
            // wire-free.
            let attempt_ids: Vec<String> = {
                let mut stmt = tx
                    .prepare(
                        "SELECT attempt_id FROM attempt_fact
                      WHERE operation_id = ?1 AND fact_kind = 'claim'
                      ORDER BY attempt_ordinal;",
                    )
                    .map_err(|e| LogError(format!("replace_journal_row attempt read: {e}")))?;
                let ids = stmt
                    .query_map(rusqlite::params![intent_id], |r| r.get::<_, String>(0))
                    .map_err(|e| LogError(format!("replace_journal_row attempt read: {e}")))?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| LogError(format!("replace_journal_row attempt read: {e}")))?;
                ids
            };
            for attempt_id in &attempt_ids {
                let state = fold_stored_attempt(tx, attempt_id)?;
                let class = state.class().ok_or_else(|| {
                    LogError(format!(
                        "replace_journal_row: attempt '{attempt_id}' folds to no class"
                    ))
                })?;
                if !matches!(
                    class,
                    AttemptClass::PreIssuance
                        | AttemptClass::TerminalFailedPreSend
                        | AttemptClass::TerminalSeveredBeforeIssuance
                ) {
                    return Ok(JournalReplaceOutcome::RefusedAttemptNotProvenNoWire {
                        attempt_id: attempt_id.clone(),
                    });
                }
            }
            let epoch: i64 = tx
                .query_row("SELECT epoch FROM control_epoch WHERE id = 1;", [], |r| {
                    r.get(0)
                })
                .map_err(|e| LogError(format!("replace_journal_row epoch read: {e}")))?;
            // DELETE + INSERT, never UPDATE (see the trait doc): the `journal_id` is the capture's
            // identity, and a new observation is a new capture. `pre_state` carries no append-only
            // trigger, so nothing is circumvented; the insert-or-nothing rule is a posture of the
            // PREPARE path.
            tx.execute(
                "DELETE FROM pre_state WHERE intent_id = ?1;",
                rusqlite::params![intent_id],
            )
            .map_err(|e| LogError(format!("replace_journal_row delete: {e}")))?;
            let generation = generation
                .checked_add(1)
                .ok_or_else(|| LogError("replace_journal_row: capture generation overflow".into()))?;
            tx.execute(
                "INSERT INTO pre_state (journal_id, intent_id, observed, touched_atom, resolved_operands,
                                    fetched_at, source, request_id, captured_epoch, mode_generation,
                                    undo_offer_until, capture_generation, observed_label_vector)
             VALUES (lower(hex(randomblob(16))), ?1, ?2, ?3, ?4,
                     strftime('%Y-%m-%dT%H:%M:%SZ','now'), 'live_read', ?5, ?6, ?7,
                     strftime('%Y-%m-%dT%H:%M:%SZ','now', '+' || ?8 || ' seconds'), ?9, ?10);",
                rusqlite::params![
                    intent_id,
                    journal.observed,
                    journal.touched_atom,
                    journal.resolved_operands,
                    journal.request_id,
                    epoch,
                    cmg,
                    crate::prestate::UNDO_OFFER_SECONDS as i64,
                    generation,
                    journal.observed_label_vector
                ],
            )
            .map_err(|e| LogError(format!("replace_journal_row insert: {e}")))?;
            Ok(JournalReplaceOutcome::Replaced {
                generation: u64::try_from(generation).unwrap_or(u64::MAX),
            })
        })
    }

    fn undo_context(&mut self, key: &str) -> Result<Option<UndoContext>, LogError> {
        // One transaction: every fact the derivation consumes is read from a single consistent
        // snapshot, and the high-water advance commits with it, so two concurrent evaluations
        // cannot each read a latch the other is about to raise.
        self.with_immediate_tx(|tx| {
            let row: Option<(String, Option<String>)> = tx
                .query_row(
                    "SELECT intent_id, frozen_basis FROM intents WHERE idempotency_key = ?1;",
                    rusqlite::params![key],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()
                .map_err(|e| LogError(e.to_string()))?;
            let Some((intent_id, frozen_basis)) = row else {
                return Ok(None);
            };
            // The full persisted journal row, read so it can be re-validated against the frozen
            // basis on the read boundary, the twin of PREPARE's write-side `JournalRow::validate`
            // and `FrozenBasis::from_json`'s validate-on-read.
            #[allow(clippy::type_complexity)]
            let journal: Option<(String, String, String, Option<String>, String)> = tx
                .query_row(
                    "SELECT observed, touched_atom, resolved_operands, request_id, undo_offer_until \
                   FROM pre_state WHERE intent_id = ?1;",
                    rusqlite::params![intent_id],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
                )
                .optional()
                .map_err(|e| LogError(e.to_string()))?;
            let tombstoned: i64 = tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM pre_state_tombstone WHERE intent_id = ?1);",
                    rusqlite::params![intent_id],
                    |r| r.get(0),
                )
                .map_err(|e| LogError(e.to_string()))?;
            // The sticky clock: effective_now = max(now, the latch), the latch validated as
            // stored and advanced monotonically, through the durable helper
            // (`sticky_effective_now`) the plan methods share.
            let effective_now = sticky_effective_now(tx, "undo_context")?;
            let journal = journal
                .map(
                    |(observed, touched, resolved_operands, request_id, until)| -> Result<CapturedJournal, LogError> {
                    // The read boundary for the persisted journal row mirrors PREPARE's
                    // write-side `JournalRow::validate` and `FrozenBasis::from_json`'s
                    // validate-on-read, so the two directions cannot drift. `touched_atom` is
                    // handed to `drive_undo_child` as `P`, so a syntactically valid but
                    // inconsistent row (an earlier-branch build, or valid-text on-disk
                    // corruption) would forge a false no-op or a wrong restore. Validate only when
                    // a basis exists; a legacy row keeps the `PredatesSubstrate` degradation path,
                    // as PREPARE does.
                    if let Some(basis_json) = frozen_basis.as_deref() {
                        let basis = crate::prestate::FrozenBasis::from_json(basis_json).map_err(|e| {
                            LogError(format!(
                                "undo_context: stored frozen_basis is not a well-formed basis: {e}"
                            ))
                        })?;
                        let stored_row = crate::prestate::JournalRow {
                            observed,
                            touched_atom: touched.clone(),
                            resolved_operands,
                            request_id,
                            // Not selected here: `validate` does not read the vector, and this
                            // read hands out only `P` and the offer deadline.
                            observed_label_vector: None,
                        };
                        stored_row.validate(&basis).map_err(|e| {
                            LogError(format!(
                                "undo_context: inconsistent persisted journal row: {e}"
                            ))
                        })?;
                    }
                    let p: std::collections::BTreeMap<String, bool> = serde_json::from_str(&touched)
                        .map_err(|e| LogError(format!("undo_context: corrupt touched_atom: {e}")))?;
                    // The same for the offer deadline: a malformed deadline must never reach the
                    // compare, where `"2026-…" < "invalid"` reads as an open offer. The message
                    // stays value-free and id-free, like the arm above it.
                    if !crate::prestate::is_canonical_rfc3339_utc(&until) {
                        return Err(LogError(
                            "undo_context: non-canonical undo_offer_until".into(),
                        ));
                    }
                    Ok(CapturedJournal {
                        p,
                        undo_offer_until: until,
                    })
                    },
                )
                .transpose()?;
            Ok(Some(UndoContext {
                parent_intent_id: intent_id,
                journal,
                tombstoned: tombstoned == 1,
                effective_now,
            }))
        })
    }

    fn admitted_epoch_is_current(&self, idempotency_key: &str) -> Result<bool, LogError> {
        let current: Option<Option<i64>> = self
            .conn
            .query_row(
                "SELECT admitted_control_epoch = (SELECT epoch FROM control_epoch WHERE id = 1)
                   FROM intents WHERE idempotency_key = ?1;",
                rusqlite::params![idempotency_key],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| LogError(e.to_string()))?;
        // A missing key is an error, never a silent `true`: the caller is fencing a dispatch,
        // and "I could not find the row" must not read as "the fence is clear". A NULL
        // comparison (the singleton itself missing, which open refuses) is `false`: fail closed
        // on an unanswerable fence.
        match current {
            Some(v) => Ok(v == Some(1)),
            None => Err(LogError(format!(
                "admitted_epoch_is_current: no intent '{idempotency_key}'"
            ))),
        }
    }

    fn claim_attempt(
        &mut self,
        idempotency_key: &str,
        claim: &AttemptClaim,
    ) -> Result<ClaimOutcome, LogError> {
        use crate::attempt::{DerivedState, Fact, FactKind, FactPayload, OperationalAxis};
        // One IMMEDIATE transaction: the compares and the append must be indivisible, or the
        // window between them is the race this method exists to close. SQLite's single writer
        // is what linearizes two engines over one file.
        self.with_immediate_tx(|tx| {
            let (owner, status, attempts, admitted_epoch): (String, String, i64, i64) = tx
                .query_row(
                    "SELECT intent_id, status, attempts, admitted_control_epoch
                   FROM intents WHERE idempotency_key = ?1;",
                    rusqlite::params![idempotency_key],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .map_err(|e| LogError(format!("claim_attempt read '{idempotency_key}': {e}")))?;
            // Compare 1: the operation settled under this driver. Exact shape: a driver holding a
            // `Pending` read taken before another driver terminalized the row. Read through the
            // status authority, so a status this build does not know is an error rather than a
            // permissive default.
            if status_from_str(&status)?.is_terminal() {
                return Ok(ClaimOutcome::AlreadyClaimed);
            }
            // Compare 2: the durable dispatch episode moved under this driver (another driver
            // charged a failure against the row this one was deciding about).
            if attempts != i64::from(claim.observed_attempts) {
                return Ok(ClaimOutcome::AlreadyClaimed);
            }
            let epoch: i64 = tx
                .query_row("SELECT epoch FROM control_epoch WHERE id = 1;", [], |r| {
                    r.get(0)
                })
                .map_err(|e| LogError(format!("claim_attempt epoch read: {e}")))?;
            if epoch != admitted_epoch {
                return Ok(ClaimOutcome::EpochFenced);
            }
            // The operation's highest-ordinal attempt, if it has one. Keyed by the CLAIM row's
            // `attempt_ordinal` column, the same column `UNIQUE (operation_id, attempt_ordinal)`
            // arbitrates, so the lookup and the arbiter cannot disagree.
            let latest: Option<(String, i64)> = tx
                .query_row(
                    "SELECT attempt_id, attempt_ordinal FROM attempt_fact
                  WHERE operation_id = ?1 AND fact_kind = 'claim'
                  ORDER BY attempt_ordinal DESC LIMIT 1;",
                    rusqlite::params![owner],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()
                .map_err(|e| LogError(format!("claim_attempt head read: {e}")))?;
            // What this claim will actually take. A caller naming an ordinal the operation has
            // not reached is minted verbatim (the grammar judges it); a caller arriving at an
            // operation whose attempts are settled is minted as their successor (see the retry
            // arm).
            let mut ordinal = claim.ordinal;
            let mut predecessor = claim.predecessor.clone();
            if let Some((latest_id, latest_ordinal)) = latest {
                if latest_ordinal as u64 >= claim.ordinal {
                    let state = fold_stored_attempt(tx, &latest_id)?;
                    // ISSUANCE_UNKNOWN: no retry from `ACK_AMBIGUOUS` or `ISSUANCE_UNKNOWN`
                    // (adjudication is the only path), and no re-entry either: the attempt is
                    // operationally open, but one attempt is at most one potentially effectful wire
                    // dispatch, and this one has already spent it. Derived from facts, so it holds
                    // however the operation's counters move.
                    if state.ambiguous_recorded && state.terminal_attribution.is_none() {
                        return Ok(ClaimOutcome::AwaitingAdjudication);
                    }
                    if state.operational == OperationalAxis::Active {
                        // The re-entry arm. It is not exclusive, and cannot be made so without a
                        // mutation (two drivers whose reads are equally current compare equal to
                        // anything this transaction could test). So it hands back the head
                        // revision it saw, and exclusivity is enforced at the two writes that
                        // follow: `authorize_send`'s at-most-one `SEND_AUTHORIZED`, and
                        // `settle_attempt`'s compare-and-append against this revision. Without the
                        // second, a re-entering peer's pre-wire verdict could terminalize an
                        // attempt the first driver had already authorized and put on the wire.
                        return Ok(ClaimOutcome::Won {
                            attempt_id: latest_id,
                            ordinal: latest_ordinal as u64,
                            observed_revision: state.current_revision,
                            // And the attempt's class, from the same fold. Re-entry is the only
                            // way a caller can be handed an attempt whose `SEND_AUTHORIZED` is
                            // already committed, so it is the only path that can tell a caller
                            // its pre-wire decisions are no longer honest. A folded chain that
                            // holds a `CLAIM` always has a class, so a missing one is an error.
                            class: state.class().ok_or_else(|| {
                                LogError("claim_attempt: a claimed attempt has no class".into())
                            })?,
                        });
                    }
                    // The retry gap: the operation is active (compare 1 proved it) with no live
                    // attempt, because its last attempt holds a terminal attribution. This
                    // dispatch is therefore the successor attempt, and its ordinal and mandatory
                    // lineage are derived here because only this transaction can read the chain
                    // and append against it atomically.
                    //
                    // Transient-only, without a second taxonomy: a deterministic failure's
                    // verdict dead-letters the operation in the settling transaction, so compare 1
                    // has already refused it. The eligibility the fact chain adds is the terminal
                    // attribution: an ambiguous or adjudicated attempt has none, and falls
                    // through to `AlreadyClaimed`.
                    match retry_reason_of(&state) {
                        Some(reason) => {
                            ordinal = latest_ordinal as u64 + 1;
                            predecessor = Some(crate::attempt::RetryPredecessor {
                                attempt_id: latest_id,
                                reason,
                            });
                        }
                        None => return Ok(ClaimOutcome::AlreadyClaimed),
                    }
                }
            }
            // `created_at` goes through the clamp authority: max(now, max persisted), with a
            // backward wall-clock step surfaced rather than absorbed. No aging policy exists yet
            // to act on it, so the flag is carried by the helper and nothing here invents one.
            let now: String = tx
                .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%SZ','now');", [], |r| {
                    r.get(0)
                })
                .map_err(|e| LogError(format!("claim_attempt clock read: {e}")))?;
            let max_persisted: String = tx
                .query_row(FACT_CLOCK_HIGH_WATER_SQL, [], |r| r.get(0))
                .map_err(|e| LogError(format!("claim_attempt clock high-water read: {e}")))?;
            let clamped = crate::attempt::clamped_now(&now, &max_persisted)
                .map_err(|e| LogError(format!("claim_attempt clock: {e}")))?;
            let attempt_id: String = tx
                .query_row("SELECT lower(hex(randomblob(16)));", [], |r| r.get(0))
                .map_err(|e| LogError(format!("claim_attempt id mint: {e}")))?;
            let fact = Fact {
                operation_id: owner.clone(),
                attempt_id: attempt_id.clone(),
                revision: 1,
                kind: FactKind::Claim,
                basis_epoch: epoch,
                created_at: clamped.value.clone(),
                payload: FactPayload::Claim {
                    ordinal,
                    predecessor: predecessor.clone(),
                },
                prior_revision: None,
            };
            // The one legality predicate. A `CLAIM` is legal only against the empty state, which
            // is what a chainless attempt id folds to, so this is the grammar's own answer, not a
            // second copy of it.
            if let Err(refusal) = crate::attempt::append_legal(&DerivedState::empty(), &fact) {
                return Ok(ClaimOutcome::RefusedByGrammar(refusal));
            }
            // The cross-attempt half of the ordinal/retry rule, over the lineage this method
            // derived (or the caller supplied), never a second copy of the rule.
            if let Some(link) = predecessor.as_ref() {
                // Only an actually absent predecessor is "unclaimed". Collapsing a read failure
                // to the empty state would be wrong: the empty state is what the grammar answers
                // `PredecessorUnclaimed` to, so a predecessor whose chain does not fold, whose
                // payload will not parse, or whose `attempt_head` disagrees with its own chain
                // would come back as the ordinary refusal for an attempt that was never claimed:
                // durable corruption passing as a routine "no" on the path that decides whether a
                // retry may exist. [`fold_stored_attempt_if_present`] splits it: `None` is
                // absence, the empty state and the `PredecessorUnclaimed` below, while every
                // other failure is a `LogError` that propagates and drops this transaction
                // uncommitted. That is the rule the head/fold-divergence case already has at the
                // boot chokepoint and inside `fold_stored_attempt`.
                let predecessor = fold_stored_attempt_if_present(tx, &link.attempt_id)?
                    .unwrap_or_else(DerivedState::empty);
                // The single-successor probe, scoped to this operation and using its index; see
                // [`RETRY_SUCCESSOR_SQL`] for why the scope is the rule's own domain.
                let has_successor: i64 = tx
                    .query_row(
                        RETRY_SUCCESSOR_SQL,
                        rusqlite::params![owner, link.attempt_id],
                        |r| r.get(0),
                    )
                    .map_err(|e| LogError(format!("claim_attempt successor read: {e}")))?;
                if let Err(refusal) =
                    crate::attempt::retry_lineage_legal(&fact, &predecessor, has_successor == 1)
                {
                    return Ok(ClaimOutcome::RefusedByGrammar(refusal));
                }
            }
            // Compare-and-append. `UNIQUE (attempt_id, revision)` and `UNIQUE (operation_id,
            // attempt_ordinal)` are the mechanical arbiters: losing to one is a lost race, which
            // is `AlreadyClaimed`, a normal outcome of two drivers doing their job, never an
            // error. (The append-only INSERT-OR-REPLACE trigger raises on the same conflict key
            // and lands here too, which is correct: it means the row already exists.)
            let insert = tx.execute(
                "INSERT INTO attempt_fact (operation_id, attempt_id, revision, fact_kind,
                                       attempt_ordinal, basis_epoch, created_at, payload,
                                       prior_revision)
             VALUES (?1, ?2, 1, 'claim', ?3, ?4, ?5, ?6, NULL);",
                rusqlite::params![
                    owner,
                    attempt_id,
                    ordinal as i64,
                    epoch,
                    clamped.value,
                    fact_payload_json(&fact.payload),
                ],
            );
            match insert {
                Ok(_) => {}
                Err(rusqlite::Error::SqliteFailure(e, _))
                    if e.code == rusqlite::ErrorCode::ConstraintViolation =>
                {
                    return Ok(ClaimOutcome::AlreadyClaimed)
                }
                Err(e) => return Err(LogError(format!("claim_attempt append: {e}"))),
            }
            // The head projection, in the same transaction as the append: maintained
            // transactionally with the append and re-derivable from the chain. Its content comes
            // from the fold of the chain this transaction just wrote, never from a parallel
            // hand computation.
            let state = crate::attempt::fold(&[fact])
                .map_err(|d| LogError(format!("claim_attempt fold: {d}")))?;
            let class = state
                .class()
                .ok_or_else(|| LogError("claim_attempt: a claimed attempt has no class".into()))?;
            tx.execute(
                "INSERT INTO attempt_head (attempt_id, operation_id, current_revision,
                                       derived_class, last_verified_revision, verified_state)
             VALUES (?1, ?2, ?3, ?4, ?3, ?5);",
                rusqlite::params![
                    attempt_id,
                    owner,
                    state.current_revision as i64,
                    class.as_sql(),
                    verified_state_json(&state),
                ],
            )
            .map_err(|e| LogError(format!("claim_attempt head upsert: {e}")))?;
            Ok(ClaimOutcome::Won {
                attempt_id,
                ordinal,
                // A freshly minted attempt's chain is exactly the `CLAIM` fact this transaction
                // appended, so its head revision is 1, read off the fold above, never guessed.
                observed_revision: state.current_revision,
                // Its class is the one just persisted into `attempt_head.derived_class`, from the
                // same fold, so the caller's answer and the store's projection cannot disagree.
                class,
            })
        })
    }

    fn authorize_send(
        &mut self,
        idempotency_key: &str,
        attempt_id: &str,
        capture: CaptureBinding,
        plan: crate::plan::PlanBinding,
    ) -> Result<SendAuthOutcome, LogError> {
        use crate::attempt::{ExposureKey, Fact, FactKind, FactPayload, WireEvidence};
        // The belt's handle, captured here before `with_immediate_tx` borrows `self` mutably,
        // so the closure below cannot reach `self.conn` at all. `WriterGate::clone` is a
        // pointer clone (Arc-backed state), never a fresh registry lookup.
        let belt_gate = self.conn.gate().clone();
        // One IMMEDIATE transaction. This is the last pre-wire authority: the epoch re-read, the
        // exposure check and the append have to be indivisible, and SQLite's single writer
        // linearizes them against the sever transaction, so exactly one of {send-auth, sever}
        // goes first and both orders are safe.
        self.with_immediate_tx(move |tx| {
            // The belt: the first act inside the transaction, before this attempt's own state is
            // touched at all. See `belt_refuses_send_if_severing`'s doc for the race this closes
            // and why it writes nothing.
            if let Some(fenced) = belt_refuses_send_if_severing(&belt_gate)? {
                return Ok(fenced);
            }
            // The Photon-local `account` column is deliberately not read here: the exposure
            // scope is the provider's, and it lives inside the frozen basis.
            let (owner, basis_json): (String, Option<String>) = tx
                .query_row(
                    "SELECT intent_id, frozen_basis FROM intents WHERE idempotency_key = ?1;",
                    rusqlite::params![idempotency_key],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(|e| LogError(format!("authorize_send read '{idempotency_key}': {e}")))?;
            let chain = read_attempt_chain(tx, attempt_id)?;
            let state = fold_stored_attempt(tx, attempt_id)?;
            // Ownership is checked, not assumed: the caller names an attempt it was told it owns,
            // and this is the last check before the wire. An attempt belonging to another
            // operation, or none at all, is an explicit incident, never a silent authorization.
            let claim = state.claim.as_ref().ok_or_else(|| {
                LogError(format!(
                    "authorize_send: attempt '{attempt_id}' has no CLAIM to authorize"
                ))
            })?;
            if claim.operation_id != owner {
                return Err(LogError(format!(
                    "authorize_send: attempt '{attempt_id}' is owned by operation \
                 '{}', not by '{idempotency_key}'",
                    claim.operation_id
                )));
            }
            // The capture CAS: the requalification REPLACE is versioned, and this is where the
            // version is spent. The caller states the generation its dispatch decision was made
            // against, and this transaction (the last pre-wire boundary, linearized by SQLite's
            // single writer against `replace_journal_row`) refuses if the durable row is no
            // longer that one. It sits ahead of every write below because a refusal must leave
            // nothing behind: nothing was sent, nothing is attributed, and the loser re-runs
            // requalification through the ordinary paths.
            let found: Option<i64> = tx
                .query_row(
                    "SELECT p.capture_generation FROM pre_state p
                   JOIN intents i ON i.intent_id = p.intent_id
                  WHERE i.idempotency_key = ?1;",
                    rusqlite::params![idempotency_key],
                    |r| r.get(0),
                )
                .optional()
                .map_err(|e| LogError(format!("authorize_send capture generation read: {e}")))?;
            let found = found
                .map(u64::try_from)
                .transpose()
                .map_err(|_| LogError("authorize_send: negative capture_generation".into()))?;
            if !capture_binding_holds(capture, found) {
                return Ok(SendAuthOutcome::CaptureSuperseded {
                    expected: capture,
                    found,
                });
            }
            // Nothing below reads the operation's status. Attribution is facts-only, and the fold
            // above is the authority on whether this attempt may still be authorized: a settled
            // attempt refuses through the grammar (post-terminal append), the same answer
            // arrived at from the ledger instead of a projection.
            let epoch: i64 = tx
                .query_row("SELECT epoch FROM control_epoch WHERE id = 1;", [], |r| {
                    r.get(0)
                })
                .map_err(|e| LogError(format!("authorize_send epoch read: {e}")))?;
            let now: String = tx
                .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%SZ','now');", [], |r| {
                    r.get(0)
                })
                .map_err(|e| LogError(format!("authorize_send clock read: {e}")))?;
            let max_persisted: String = tx
                .query_row(FACT_CLOCK_HIGH_WATER_SQL, [], |r| r.get(0))
                .map_err(|e| LogError(format!("authorize_send clock high-water read: {e}")))?;
            let created_at = crate::attempt::clamped_now(&now, &max_persisted)
                .map_err(|e| LogError(format!("authorize_send clock: {e}")))?
                .value;
            let next = Fact {
                operation_id: owner.clone(),
                attempt_id: attempt_id.to_string(),
                revision: state.current_revision + 1,
                kind: FactKind::SendAuthorized,
                basis_epoch: epoch,
                created_at: created_at.clone(),
                payload: FactPayload::None, // replaced below; the kind decides the shape
                prior_revision: Some(state.current_revision),
            };
            // The epoch check. The claim-fact epoch check was the earlier cheap gate; this is the
            // authorization.
            if epoch != claim.claim_epoch {
                // Sever first: the send-auth refuses and the attempt terminalizes
                // `SEVERED_BEFORE_ISSUANCE`, in this transaction with the operation's lifecycle,
                // because recording without closing would strand the slot and the resource tail
                // forever.
                let severed = Fact {
                    kind: FactKind::SeveredBeforeIssuance,
                    payload: FactPayload::None,
                    ..next
                };
                if let Some(refusal) = append_fact_with_head(tx, &chain, &severed)? {
                    // The one reachable refusal here: the attempt is already authorized, so
                    // `SEVERED_BEFORE_ISSUANCE` is a claim the grammar refuses to record, since we
                    // cannot prove non-issuance. It stays ISSUED_OR_UNKNOWN for the sever to classify.
                    return Ok(SendAuthOutcome::RefusedByGrammar(refusal));
                }
                terminalize_operation(tx, idempotency_key, IntentStatus::Severed)?;
                return Ok(SendAuthOutcome::EpochFenced);
            }
            // The plan-admission arm. The binding is total: the row's link columns and the
            // caller's binding must name the same shape, or this is a caller bug answered before
            // anything is written. For a plan child the law (`plan_send_admission`) reads durable
            // rows and the capture the CAS above verified; the one external input, the grant
            // verdict, is carried on the binding.
            let plan_link: (Option<String>, Option<String>) = tx
                .query_row(
                    "SELECT plan_id, plan_member FROM intents WHERE idempotency_key = ?1;",
                    rusqlite::params![idempotency_key],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(|e| LogError(format!("authorize_send plan link read: {e}")))?;
            match (plan_link, &plan) {
                ((None, None), crate::plan::PlanBinding::Plain) => {}
                ((Some(plan_id), Some(member_ref)), crate::plan::PlanBinding::Child { grant, account_key }) => {
                    let plan_id = crate::plan::PlanId(plan_id);
                    if let Some(refusal) =
                        plan_send_admission(tx, &plan_id, &member_ref, idempotency_key, grant, account_key, capture)?
                    {
                        // The terminal is only written where it is true (as in the exposure arm
                        // below): proven-no-wire is honest only for an attempt never authorized. An
                        // attempt already holding its `SEND_AUTHORIZED` (a second driver on the same
                        // won claim) may have touched the wire, so it is refused with nothing
                        // written and stays ISSUED_OR_UNKNOWN. A held refusal writes nothing either.
                        if refusal.is_terminal() && !state.send_authorized {
                            let closed = Fact {
                                kind: FactKind::FailedPreSend,
                                payload: FactPayload::FailedPreSend {
                                    wire_evidence: WireEvidence::ProvenNoWire,
                                    reason: refusal.pre_send_reason(),
                                    exposure_block: None,
                                    plan_refusal: Some(refusal.record(&member_ref)),
                                },
                                ..next.clone()
                            };
                            if let Some(g) = append_fact_with_head(tx, &chain, &closed)? {
                                return Ok(SendAuthOutcome::RefusedByGrammar(g));
                            }
                            terminalize_operation(tx, idempotency_key, IntentStatus::Failed)?;
                            // An expired or epoch-moved plan closes its episode in this transaction
                            // too. The transition table guards it: an episode already terminal keeps
                            // its status, and that inner refusal is dropped on purpose.
                            let invalidation = match &refusal {
                                crate::plan::PlanSendRefusal::Expired { .. } => Some(crate::episode::InvalidationReason::Expired),
                                crate::plan::PlanSendRefusal::PlanEpochMismatch { plan, current } => {
                                    Some(crate::episode::InvalidationReason::EpochMismatch { plan: *plan, current: *current })
                                }
                                _ => None,
                            };
                            if let Some(reason) = invalidation {
                                let _ = invalidate_episode_in_tx(tx, &plan_id, &reason)?;
                            }
                        }
                        return Ok(SendAuthOutcome::PlanRefused(refusal));
                    }
                }
                ((row_plan, row_member), binding) => {
                    return Err(LogError(format!(
                        "authorize_send: '{idempotency_key}' carries {} and the caller's binding is {} — a caller bug, never a skipped law",
                        match (row_plan.is_some(), row_member.is_some()) {
                            (true, true) => "a plan link",
                            (false, false) => "no plan link",
                            _ => "half a plan link",
                        },
                        if matches!(binding, crate::plan::PlanBinding::Plain) { "Plain" } else { "Child" }
                    )));
                }
            }
            // The exposure key, derived from the operation's own admission-frozen basis inside
            // this transaction: dispatch never re-resolves. A binding change between admission
            // and dispatch refuses and never retargets; the frozen basis is the identity the wire
            // is permitted to touch. Never from the `pre_state` row: capture-off operations
            // legally have none and the check must still reach them.
            let exposure_key = match basis_json {
                Some(raw) => {
                    let basis = crate::prestate::FrozenBasis::from_json(&raw)
                        .map_err(|e| LogError(format!("authorize_send frozen_basis: {e}")))?;
                    // Only the frozen basis: the Photon-local `account` handle is deliberately not
                    // an input, because the scope is the provider's and two local handles onto one
                    // provider account must land on one exposure identity.
                    ExposureKey::from_basis(&basis)
                }
                // A legacy row (NULL basis) names no provider-native atoms at all; see the
                // constructor's doc.
                None => ExposureKey::legacy_unscoped(),
            };
            // The exposure check. The join lives here because the authoritative exposure decision
            // sits at the final effect-release boundary and nowhere earlier. Its rows are written
            // by [`IntentLog::adjudicate`] and retired by [`IntentLog::record_late_ack`].
            //
            // Bound: one lookup per touched atom, on the partial index
            // `idx_exposure_obligation_live` (`(primitive_atom) WHERE retired_at IS NULL`), so the
            // cost is this operation's frozen atom set times the live obligations on each, and is
            // independent of how much retired history the store holds (on the UNIQUE index alone
            // the absence proof walked a settled history that only grows). The `EXPLAIN QUERY
            // PLAN` test in `store_open` runs this exact text. Nothing here scans or evicts; the
            // growth of that table is surfaced at open
            // (`IntegrityEvidence::UnresolvedExposureOutstanding`).
            //
            // The atom key is the whole join key and is provider-scoped; a Photon-local account
            // column beside it would miss when two local aliases name one provider account.
            for atom in &exposure_key.atoms {
                let overlap: Option<String> = tx
                    .query_row(
                        EXPOSURE_OVERLAP_SQL,
                        rusqlite::params![atom.atom_key],
                        |r| r.get(0),
                    )
                    .optional()
                    .map_err(|e| LogError(format!("authorize_send exposure gate: {e}")))?;
                // The blocking row's own engine identity. The absence proof already selects
                // `obligation_id`; it is the Photon-local reference the refusal surfaces in place
                // of the provider-native atom key, so it is read from the same query.
                if let Some(obligation_id) = overlap {
                    // Fail closed, pre-wire. No risk-acceptance capability exists in this build,
                    // so nothing could authorize the overlap, same-direction or not.
                    //
                    // The terminal is only written where it is true. A deterministic no-effect
                    // terminal asserts proven-no-wire, which is honest only for an attempt never
                    // authorized. An already-authorized attempt reaching this check on a later
                    // dispatch episode may have touched the wire under its first, so it refuses
                    // without a fact and stays ISSUED_OR_UNKNOWN, the truthful class. The verdict
                    // fact that finally settles it belongs to a later step; inventing one here
                    // would claim a truth the engine does not have.
                    if state.send_authorized {
                        return Ok(SendAuthOutcome::ExposureBlocked {
                            atom_key: atom.atom_key.clone(),
                        });
                    }
                    let blocked = Fact {
                        kind: FactKind::FailedPreSend,
                        payload: FactPayload::FailedPreSend {
                            wire_evidence: WireEvidence::ProvenNoWire,
                            reason: crate::attempt::PreSendReason::Failure,
                            // What refused, durably. The terminal is the only durable place that
                            // outlives the call, and `exposure_block` reads it back for the
                            // replay; the in-memory `SendAuthOutcome` alone would leave an operator
                            // with a bare `Failed` and no way to tell which of several gated
                            // resources closed the operation.
                            //
                            // Both identities are written together: the atom for the audit and the
                            // join, the obligation id for the caller. Because both live in this one
                            // fact, a dispatching call and an identical replay read the same bytes
                            // and cannot disagree.
                            exposure_block: Some(crate::attempt::ExposureBlock {
                                atom_key: atom.atom_key.clone(),
                                obligation_id,
                            }),
                            plan_refusal: None,
                        },
                        ..next
                    };
                    if let Some(refusal) = append_fact_with_head(tx, &chain, &blocked)? {
                        return Ok(SendAuthOutcome::RefusedByGrammar(refusal));
                    }
                    terminalize_operation(tx, idempotency_key, IntentStatus::Failed)?;
                    return Ok(SendAuthOutcome::ExposureBlocked {
                        atom_key: atom.atom_key.clone(),
                    });
                }
            }
            // The authorization: at most one per attempt, with nothing qualifying it. Every retry
            // claims a fresh attempt through the claim path's retry-gap arm, so a second
            // authorization on one attempt has exactly one meaning: a peer trying to put a second
            // potentially effectful dispatch on the wire under an attempt that already spent its
            // one. The grammar refuses it below without consulting any counter. There is no
            // episode to advance past, and the fresh-attempt path is what separates peers.
            let authorized = Fact {
                payload: FactPayload::SendAuthorized {
                    exposure_key: exposure_key.clone(),
                },
                ..next
            };
            if let Some(refusal) = append_fact_with_head(tx, &chain, &authorized)? {
                return Ok(SendAuthOutcome::RefusedByGrammar(refusal));
            }
            Ok(SendAuthOutcome::Authorized { exposure_key })
        })
    }

    fn settle_attempt(
        &mut self,
        idempotency_key: &str,
        attempt_id: &str,
        verdict: ConnectorVerdict,
        retry_cap: u32,
        pre_wire_at_revision: Option<u64>,
    ) -> Result<SettleOutcome, LogError> {
        use crate::attempt::Fact;
        // One IMMEDIATE transaction, the point of this method: the verdict fact, the head
        // projection and the operation's lifecycle are one durable write.
        self.with_immediate_tx(|tx| {
            let owner: String = tx
                .query_row(
                    "SELECT intent_id FROM intents WHERE idempotency_key = ?1;",
                    rusqlite::params![idempotency_key],
                    |r| r.get(0),
                )
                .map_err(|e| LogError(format!("settle_attempt read '{idempotency_key}': {e}")))?;
            let chain = read_attempt_chain(tx, attempt_id)?;
            let state = fold_stored_attempt(tx, attempt_id)?;
            // Ownership is checked, not assumed, as in the authorization path: a verdict written
            // onto another operation's attempt is an explicit incident.
            let claim = state.claim.as_ref().ok_or_else(|| {
                LogError(format!(
                    "settle_attempt: attempt '{attempt_id}' has no CLAIM to settle"
                ))
            })?;
            if claim.operation_id != owner {
                return Err(LogError(format!(
                    "settle_attempt: attempt '{attempt_id}' is owned by operation '{}', not by \
                 '{idempotency_key}'",
                    claim.operation_id
                )));
            }
            // The pre-wire compare-and-append, inside the transaction so the window between the
            // compare and the append is not the race this exists to close. A caller that decided
            // its verdict before the wire is making a claim about a chain it read; if that chain
            // has moved (above all because a peer that re-entered the same live attempt got its
            // `SEND_AUTHORIZED` in) the claim is false, and settling on it would terminalize an
            // attempt that is mid-dispatch. The caller re-reads and exits silently, as for a lost
            // claim race.
            if let Some(observed_revision) = pre_wire_at_revision {
                if state.current_revision != observed_revision {
                    return Ok(SettleOutcome::SupersededPreWire {
                        observed_revision,
                        current_revision: state.current_revision,
                    });
                }
            }
            let epoch: i64 = tx
                .query_row("SELECT epoch FROM control_epoch WHERE id = 1;", [], |r| {
                    r.get(0)
                })
                .map_err(|e| LogError(format!("settle_attempt epoch read: {e}")))?;
            let now: String = tx
                .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%SZ','now');", [], |r| {
                    r.get(0)
                })
                .map_err(|e| LogError(format!("settle_attempt clock read: {e}")))?;
            let max_persisted: String = tx
                .query_row(FACT_CLOCK_HIGH_WATER_SQL, [], |r| r.get(0))
                .map_err(|e| LogError(format!("settle_attempt clock high-water read: {e}")))?;
            let created_at = crate::attempt::clamped_now(&now, &max_persisted)
                .map_err(|e| LogError(format!("settle_attempt clock: {e}")))?
                .value;
            // The mapping: one table, shared with the in-memory implementation.
            let (kind, payload, intent) = verdict_mapping(state.send_authorized, verdict);
            // The settlement-epoch check, in one place and evidence-driven: decided here from the
            // verdict about to be appended and the epoch this transaction read, ahead of
            // lifecycle-branch selection, so no branch can skip it or carry its own copy. See
            // `settlement_proves_no_effect` for why the rule belongs to the evidence axis.
            let epoch_fenced =
                epoch != claim.claim_epoch && settlement_proves_no_effect(kind, &payload);
            let fact = Fact {
                operation_id: owner.clone(),
                attempt_id: attempt_id.to_string(),
                revision: state.current_revision + 1,
                kind,
                basis_epoch: epoch,
                created_at,
                payload,
                prior_revision: Some(state.current_revision),
            };
            if let Some(refusal) = append_fact_with_head(tx, &chain, &fact)? {
                return Ok(SettleOutcome::RefusedByGrammar(refusal));
            }
            // The other order: this attempt's effect provably happened. If an unresolved exposure
            // covers an atom it touched, that is the multi-contributor trace, recorded on the
            // other party's adjudication record in this same transaction (a materialization when
            // that party has already resolved APPLIED, the durable half-trace when it has not).
            // Which of the two effects resolves first must not decide whether a notice exists.
            if kind == crate::attempt::FactKind::AckApplied {
                if let Some(exposure_key) = state.exposure_key.as_ref() {
                    note_exposure_materialization(
                        tx,
                        attempt_id,
                        exposure_key,
                        state.adjudication_id.as_deref(),
                        &fact.created_at,
                    )?;
                }
            }
            let lifecycle = if epoch_fenced {
                // The epoch check, for every lifecycle this verdict could otherwise have taken: no
                // effect existed and no retry is authorized under the new epoch, so the operation
                // completes on the sever's own classification and the slot and resource tail
                // release instead of stranding. Read back for the reason every branch below does.
                SettledLifecycle::Completed(terminalize_operation(
                    tx,
                    idempotency_key,
                    IntentStatus::Severed,
                )?)
            } else {
                match intent {
                    LifecycleIntent::Complete(status) => {
                        // Read back, never predict.
                        // guard inside `terminalize_operation` is what makes this write
                        // skippable, so reporting the status we asked for would announce a
                        // disposition the store does not hold whenever another authority closed the
                        // row first.
                        SettledLifecycle::Completed(terminalize_operation(
                            tx,
                            idempotency_key,
                            status,
                        )?)
                    }
                    LifecycleIntent::AwaitingAdjudication => {
                        // No status write and no budget charge: ISSUANCE_UNKNOWN is neither a
                        // completion nor a retry, and treating it as either would claim a truth the
                        // engine does not have.
                        SettledLifecycle::AwaitingAdjudication
                    }
                    LifecycleIntent::ChargeTransient => {
                        // The atomic increment-and-maybe-terminalize as one statement (no two-write
                        // crash window), inside the verdict's own transaction.
                        //
                        // This is not `charge_and_dead_letter_if_quiescent`, which exists because a
                        // caller holding no attempt cannot attribute an exhausted budget to one
                        // somebody else owns. Here this transaction establishes the opposite: the
                        // verdict fact appended above is this attempt's own terminal, and the CLAIM
                        // grammar permits at most one live attempt per operation (`sever_disposition`
                        // refuses more by name). So the operation is quiescent at this line, the
                        // guarded method would answer identically, and it cannot be called anyway:
                        // it opens its own transaction and this one holds the write lock. The status
                        // half keeps the non-terminal compare, the other half the guarded method
                        // carries.
                        tx.execute(
                            &format!(
                                "UPDATE intents
                                SET attempts = attempts + 1,
                                    status = CASE
                                        WHEN attempts + 1 >= ?2
                                             AND status IN {NON_TERMINAL_STATUS_SQL}
                                        THEN 'failed' ELSE status END
                              WHERE idempotency_key = ?1;"
                            ),
                            rusqlite::params![idempotency_key, retry_cap],
                        )
                        .map_err(|e| LogError(format!("settle_attempt charge: {e}")))?;
                        // Read back, never predict: the CASE above is guarded by the non-terminal
                        // domain, so a row a peer terminalized under this transaction would make an
                        // arithmetic prediction ("attempts + 1 >= cap") disagree with the store.
                        let status: String = tx
                            .query_row(
                                "SELECT status FROM intents WHERE idempotency_key = ?1;",
                                rusqlite::params![idempotency_key],
                                |r| r.get(0),
                            )
                            .map_err(|e| LogError(format!("settle_attempt status read: {e}")))?;
                        let status = status_from_str(&status)?;
                        if status.is_terminal() {
                            SettledLifecycle::Completed(status)
                        } else {
                            SettledLifecycle::RetryGap
                        }
                    }
                }
            };
            Ok(SettleOutcome::Settled { verdict: kind, lifecycle })
        })
    }

    fn sever(&mut self, authority_ref: &str, now: &str) -> Result<SeverOutcome, LogError> {
        use crate::writer_gate::SeverRole;
        let authority_ref = validated_authority_ref(authority_ref)?;
        // Coalescing: this method does not assume it is the only sever in flight. It asks the
        // arbiter for a role first, and only one role runs a kill transaction.
        let gate = sever_service_gate(&self.conn)?;
        let mut entry = gate.begin_sever(&authority_ref)?;
        match entry.role() {
            // The leader: the one epoch bump every coalesced requester shares.
            SeverRole::Leader { .. } => {
                let served = lead_sever_service(self, &entry, &authority_ref, now);
                // Complete after the commit, never before: `with_service_tx` has already
                // committed (or rolled back) by the time it returns, so the epoch this relays is a
                // durable fact rather than a promise.
                let relay = match &served {
                    Ok(outcome) => crate::writer_gate::SeverOutcome::Served {
                        epoch: outcome.epoch as u64,
                    },
                    Err(e) => crate::writer_gate::SeverOutcome::Failed {
                        detail: e.0.clone(),
                    },
                };
                let relayed = entry.complete(relay);
                match served {
                    // A leader that committed but could not publish (a poisoned gate is the only
                    // way) fails with an explicit error rather than returning an Ok whose joiners
                    // were told `Failed` by `SeverEntry`'s Drop. The store is still truthful (the
                    // evidence row is there), and every later gate call fails explicitly too.
                    Ok(outcome) => {
                        relayed?;
                        Ok(outcome)
                    }
                    // The service's own failure is the answer; a failed relay cannot improve it,
                    // and replacing it would hide why the sever did not happen.
                    Err(e) => Err(e),
                }
            }
            // Every other role: no second bump, no new ticket.
            role => {
                let epoch = match entry.await_outcome()? {
                    crate::writer_gate::SeverOutcome::Served { epoch } => epoch as i64,
                    crate::writer_gate::SeverOutcome::Failed { detail } => {
                        return Err(LogError(format!(
                            "sever: the service this request coalesced into did not complete, \
                             so no epoch was bumped on its behalf: {detail}"
                        )))
                    }
                };
                // An in-snapshot joiner's row was committed by the leader, atomically with the
                // evidence row, so it is already durable and re-appending would double-count it.
                // An overflow or post-snapshot requester owns its own append and does not return
                // until that row is durable (a crash in this window leaves the request truthfully
                // unacknowledged, never confirmed-then-lost).
                if let Some(kind) = self_appended_attribution_kind(role) {
                    sever_attribution_seam(SeverSeam::BeforeAttributionAppend, &authority_ref);
                    self.with_immediate_tx(|tx| {
                        insert_sever_attribution(tx, epoch, &authority_ref, kind)
                    })?;
                }
                // The shared outcome, read back from what the leader durably wrote.
                sever_outcome_of_epoch(&self.conn, epoch)
            }
        }
    }

    fn live_attempt(&self, idempotency_key: &str) -> Result<Option<LiveAttempt>, LogError> {
        // A read that must be atomic against an in-flight append, so it takes a deferred
        // transaction like every other fact read.
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| LogError(format!("live_attempt txn begin: {e}")))?;
        let owner: Option<String> = tx
            .query_row(
                "SELECT intent_id FROM intents WHERE idempotency_key = ?1;",
                rusqlite::params![idempotency_key],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| LogError(format!("live_attempt read: {e}")))?;
        let Some(owner) = owner else {
            return Ok(None);
        };
        let live = live_attempts_of(&tx, &owner)?;
        // More than one live attempt is the same store defect the sever's own partition refuses
        // (`sever_disposition`): one rule, one place.
        Ok(live_attempt_from(sever_disposition(&owner, &live)?))
    }

    fn adjudicate(
        &mut self,
        idempotency_key: &str,
        attempt_id: &str,
        principal_ref: &str,
        reason: crate::attempt::AdjudicationReason,
        accepted_risk: crate::attempt::AcceptedRisk,
    ) -> Result<AdjudicationOutcome, LogError> {
        use crate::attempt::{Fact, FactKind, FactPayload};
        // Shape only, the same authority-reference check the sever holds, with the same limit:
        // whether a reference resolves to a real principal is the caller's authority model, and
        // an on-box engine cannot check it.
        let principal_ref = validated_authority_ref(principal_ref)?;
        // One IMMEDIATE transaction: the record, fact, head, lifecycle and obligations are one
        // durable write or none of them are.
        self.with_immediate_tx(|tx| {
            let owner: String = tx
                .query_row(
                    "SELECT intent_id FROM intents WHERE idempotency_key = ?1;",
                    rusqlite::params![idempotency_key],
                    |r| r.get(0),
                )
                .map_err(|e| LogError(format!("adjudicate read '{idempotency_key}': {e}")))?;
            let chain = read_attempt_chain(tx, attempt_id)?;
            let state = fold_stored_attempt(tx, attempt_id)?;
            let claim = state.claim.as_ref().ok_or_else(|| {
                LogError(format!(
                    "adjudicate: attempt '{attempt_id}' has no CLAIM to adjudicate"
                ))
            })?;
            if claim.operation_id != owner {
                return Err(LogError(format!(
                    "adjudicate: attempt '{attempt_id}' is owned by operation '{}', not by \
                 '{idempotency_key}'",
                    claim.operation_id
                )));
            }
            let epoch: i64 = tx
                .query_row("SELECT epoch FROM control_epoch WHERE id = 1;", [], |r| {
                    r.get(0)
                })
                .map_err(|e| LogError(format!("adjudicate epoch read: {e}")))?;
            let created_at = fact_clock(tx, "adjudicate")?;
            let adjudication_id = mint_opaque_id(tx, "adjudicate")?;
            let fact = Fact {
                operation_id: owner.clone(),
                attempt_id: attempt_id.to_string(),
                revision: state.current_revision + 1,
                kind: FactKind::AdjudicatedUnresolved,
                basis_epoch: epoch,
                created_at: created_at.clone(),
                payload: FactPayload::Adjudicated {
                    adjudication_id: adjudication_id.clone(),
                },
                prior_revision: Some(state.current_revision),
            };
            // Ask the grammar before writing anything. The record is immutable and the
            // obligations are durable: neither may outlive a fact the closed grammar refuses, so
            // the legality question is asked first and the transaction carries no writes when the
            // answer is no.
            if let Err(refusal) = crate::attempt::append_legal(&state, &fact) {
                return Ok(AdjudicationOutcome::RefusedByGrammar(refusal));
            }
            // The exposure key is copied, never re-derived: it comes from the attempt's own
            // `SEND_AUTHORIZED` payload, itself a copy of the admission-frozen basis, so a
            // capture-off attempt (no journal row) is reached like every other and a binding that
            // moved since admission cannot retarget it here.
            let exposure_key = state.exposure_key.clone().ok_or_else(|| {
                LogError(format!(
                    "adjudicate: attempt '{attempt_id}' passed the grammar without an authorization \
                 payload — the fold and the grammar disagree"
                ))
            })?;
            let exposure_json = serde_json::to_string(&exposure_key)
                .map_err(|e| LogError(format!("adjudicate exposure key: {e}")))?;
            tx.execute(
                "INSERT INTO adjudication_record (adjudication_id, attempt_id, principal_ref,
                                              basis_epoch, accepted_risk, reason,
                                              opaque_reference, known_at_snapshot, exposure_key,
                                              created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7, ?8, ?9);",
                rusqlite::params![
                    adjudication_id,
                    attempt_id,
                    principal_ref,
                    epoch,
                    accepted_risk.as_sql(),
                    reason.as_sql(),
                    // Derived from facts and content-free: the same snapshot the head's verified
                    // baseline persists, so "what was known at decision time" is the engine's own
                    // fold and not a second hand-built summary that could flatter it.
                    verified_state_json(&state),
                    exposure_json,
                    created_at,
                ],
            )
            .map_err(|e| LogError(format!("adjudication record insert: {e}")))?;
            if let Some(refusal) = append_fact_with_head(tx, &chain, &fact)? {
                return Err(LogError(format!(
                    "adjudicate: the grammar accepted then refused the same fact on attempt \
                 '{attempt_id}': {refusal}"
                )));
            }
            // The status moves here, in this transaction. `ADJUDICATED_UNRESOLVED` is not a
            // terminal attribution, so the lifecycle-atomicity rule does not reach it, and
            // without the status here a crash leaves the fact saying closed while replay,
            // capacity and the resource tail still see a live row.
            terminalize_operation(tx, idempotency_key, IntentStatus::Adjudicated)?;
            // The obligations: a possibly effectful attempt whose historical attribution remains
            // unknown after adjudication creates a durable obligation over every primitive atom it
            // may have touched. One row per atom, direction-aware and generation-keyed.
            let mut obligations = 0u64;
            for atom in &exposure_key.atoms {
                let generation = obligation_generation(tx, &atom.atom_key)?;
                let obligation_id = mint_opaque_id(tx, "adjudicate")?;
                tx.execute(
                    "INSERT INTO exposure_obligation (obligation_id, provider_scope, primitive_atom,
                                                  direction, generation, contributor_attempt_id,
                                                  created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7);",
                    rusqlite::params![
                        obligation_id,
                        exposure_key.provider_scope,
                        atom.atom_key,
                        atom.direction.as_sql(),
                        generation,
                        attempt_id,
                        created_at,
                    ],
                )
                .map_err(|e| LogError(format!("exposure obligation insert: {e}")))?;
                obligations += 1;
            }
            Ok(AdjudicationOutcome::Adjudicated {
                adjudication_id,
                obligations,
            })
        })
    }

    fn record_late_ack(
        &mut self,
        idempotency_key: &str,
        attempt_id: &str,
        ack: crate::attempt::LateAck,
    ) -> Result<LateAckOutcome, LogError> {
        use crate::attempt::{AnomalyKind, Fact, FactPayload, GrammarRefusal, LateAck};
        self.with_immediate_tx(|tx| {
            let (owner, parent): (String, Option<String>) = tx
                .query_row(
                    "SELECT intent_id, parent_intent_id FROM intents WHERE idempotency_key = ?1;",
                    rusqlite::params![idempotency_key],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(|e| LogError(format!("record_late_ack read '{idempotency_key}': {e}")))?;
            let chain = read_attempt_chain(tx, attempt_id)?;
            let state = fold_stored_attempt(tx, attempt_id)?;
            let claim = state.claim.as_ref().ok_or_else(|| {
                LogError(format!(
                    "record_late_ack: attempt '{attempt_id}' has no CLAIM"
                ))
            })?;
            if claim.operation_id != owner {
                return Err(LogError(format!(
                    "record_late_ack: attempt '{attempt_id}' is owned by operation '{}', not by \
                 '{idempotency_key}'",
                    claim.operation_id
                )));
            }
            let epoch: i64 = tx
                .query_row("SELECT epoch FROM control_epoch WHERE id = 1;", [], |r| {
                    r.get(0)
                })
                .map_err(|e| LogError(format!("record_late_ack epoch read: {e}")))?;
            let created_at = fact_clock(tx, "record_late_ack")?;
            let fact = Fact {
                operation_id: owner.clone(),
                attempt_id: attempt_id.to_string(),
                revision: state.current_revision + 1,
                kind: ack.fact_kind(),
                basis_epoch: epoch,
                created_at: created_at.clone(),
                payload: FactPayload::None,
                prior_revision: Some(state.current_revision),
            };
            match crate::attempt::append_legal(&state, &fact) {
                // The refusal is the correctness half (the chain never records two contradicting
                // attributions) and the annotation is the honesty half (a provider that answered
                // both ways is an incident, and silently dropping the second answer would hide it).
                // Both, in one transaction.
                Err(GrammarRefusal::ContradictoryLateAckAnomaly { .. }) => {
                    let record = state.adjudication_id.clone().ok_or_else(|| {
                        LogError(format!(
                            "record_late_ack: attempt '{attempt_id}' contradicts a late ack it has \
                         no adjudication record for"
                        ))
                    })?;
                    let annotation_id = write_annotation(
                        tx,
                        &record,
                        AnomalyKind::ContradictoryLateAck,
                        Some(attempt_id),
                        None,
                        &created_at,
                    )?;
                    return Ok(LateAckOutcome::RefusedAsContradiction { annotation_id });
                }
                Err(refusal) => return Ok(LateAckOutcome::RefusedByGrammar(refusal)),
                Ok(()) => {}
            }
            if let Some(refusal) = append_fact_with_head(tx, &chain, &fact)? {
                return Err(LogError(format!(
                    "record_late_ack: the grammar accepted then refused the same fact on attempt \
                 '{attempt_id}': {refusal}"
                )));
            }
            // Retirement: no exposure state retires while an unresolved contributor exists. This
            // contributor is no longer unresolved, so its rows retire, and only its own. Any
            // other contributor's live row on the same atom keeps the exposure check closed, so
            // "the last contributor's resolution silences it" is a property of the join rather
            // than of a counter.
            let retired = tx
                .execute(
                    EXPOSURE_RETIREMENT_BY_CONTRIBUTOR_SQL,
                    rusqlite::params![attempt_id, created_at],
                )
                .map_err(|e| LogError(format!("exposure retirement: {e}")))? as u64;
            // The multi-contributor trace, and the undo-parent arm.
            let mut notices = 0u64;
            let mut parent_undone = false;
            if ack == LateAck::Applied {
                if let Some(exposure_key) = state.exposure_key.as_ref() {
                    notices = note_exposure_materialization(
                        tx,
                        attempt_id,
                        exposure_key,
                        state.adjudication_id.as_deref(),
                        &created_at,
                    )?;
                }
                // A late APPLIED on an undo child's attempt is the verification that never
                // arrived (the parent flips at verification only). The guard is the exact
                // precondition `verify_undo` holds, an `Applied` parent, so a parent some other
                // path already moved is never overwritten, and the flip is part of this
                // transaction rather than a second write a crash could lose.
                if let Some(parent) = parent.as_ref() {
                    parent_undone = tx
                        .execute(
                            "UPDATE intents SET status = 'undone'
                          WHERE intent_id = ?1 AND status = 'applied';",
                            rusqlite::params![parent],
                        )
                        .map_err(|e| LogError(format!("late-ack parent flip: {e}")))?
                        > 0;
                }
            }
            Ok(LateAckOutcome::Resolved {
                historical: ack.attribution(),
                retired,
                notices,
                parent_undone,
            })
        })
    }

    fn annotate_late_ambiguous_observation(
        &mut self,
        idempotency_key: &str,
        attempt_id: &str,
    ) -> Result<String, LogError> {
        // One transaction, as for every other write here: the fold that proves the attempt is
        // adjudicated and the annotation that hangs on its record are one durable
        // read-then-write.
        self.with_immediate_tx(|tx| {
            let owner: String = tx
                .query_row(
                    "SELECT intent_id FROM intents WHERE idempotency_key = ?1;",
                    rusqlite::params![idempotency_key],
                    |r| r.get(0),
                )
                .map_err(|e| {
                    LogError(format!("annotate_late_ambiguous read '{idempotency_key}': {e}"))
                })?;
            let state = fold_stored_attempt(tx, attempt_id)?;
            // Ownership is checked, not assumed, as in the settle and late-ack paths: an
            // annotation written onto another operation's record is an explicit incident.
            let claim = state.claim.as_ref().ok_or_else(|| {
                LogError(format!(
                    "annotate_late_ambiguous: attempt '{attempt_id}' has no CLAIM"
                ))
            })?;
            if claim.operation_id != owner {
                return Err(LogError(format!(
                    "annotate_late_ambiguous: attempt '{attempt_id}' is owned by operation '{}', \
                 not by '{idempotency_key}'",
                    claim.operation_id
                )));
            }
            let record = state.adjudication_id.clone().ok_or_else(|| {
                LogError(format!(
                    "annotate_late_ambiguous: attempt '{attempt_id}' carries a late observation \
                 but no adjudication record to hang it on"
                ))
            })?;
            let created_at = fact_clock(tx, "annotate_late_ambiguous")?;
            let annotation_id = write_annotation(
                tx,
                &record,
                crate::attempt::AnomalyKind::LateAmbiguousObservation,
                Some(attempt_id),
                None,
                &created_at,
            )?;
            Ok(annotation_id)
        })
    }

    fn adjudicated_history(&self, idempotency_key: &str) -> Result<AdjudicatedHistory, LogError> {
        // Keyed, not scanned: `attempt_fact`'s `UNIQUE (operation_id, attempt_ordinal)` index
        // has `operation_id` as its prefix, and the whitelist admits at most one `LATE_ACK_*`
        // per adjudicated attempt, so this reads one operation's own facts and nothing else.
        let kind: Option<String> = self
            .conn
            .query_row(
                "SELECT f.fact_kind FROM attempt_fact f
                   JOIN intents i ON i.intent_id = f.operation_id
                  WHERE i.idempotency_key = ?1
                    AND f.fact_kind IN ('late_ack_applied', 'late_ack_refused_no_effect')
                  LIMIT 1;",
                rusqlite::params![idempotency_key],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| LogError(format!("adjudicated_history read '{idempotency_key}': {e}")))?;
        Ok(match kind.as_deref() {
            Some("late_ack_applied") => AdjudicatedHistory::ResolvedApplied,
            Some("late_ack_refused_no_effect") => AdjudicatedHistory::ResolvedRefusedNoEffect,
            // No late ack: adjudication's own answer, still standing.
            None => AdjudicatedHistory::Unresolved,
            // The `IN` list above is the whole domain, so this is unreachable unless the store
            // answered a question it was not asked. Fail with an explicit error rather than guess.
            Some(other) => {
                return Err(LogError(format!(
                    "adjudicated_history: the store answered with fact kind '{other}'"
                )))
            }
        })
    }

    fn exposure_block(
        &self,
        idempotency_key: &str,
    ) -> Result<Option<crate::attempt::ExposureBlock>, LogError> {
        // Keyed on `operation_id` (the prefix of the `UNIQUE (operation_id, attempt_ordinal)`
        // index), as in `adjudicated_history` above: one operation's own facts, nothing else.
        // The payload is decoded through the one codec so the read and the write cannot drift.
        let mut stmt = self
            .conn
            .prepare(
                "SELECT f.payload FROM attempt_fact f
                   JOIN intents i ON i.intent_id = f.operation_id
                  WHERE i.idempotency_key = ?1 AND f.fact_kind = 'failed_pre_send'
                  ORDER BY f.rowid;",
            )
            .map_err(|e| LogError(format!("exposure_block '{idempotency_key}': {e}")))?;
        let rows = stmt
            .query_map(rusqlite::params![idempotency_key], |r| {
                r.get::<_, String>(0)
            })
            .map_err(|e| LogError(format!("exposure_block '{idempotency_key}': {e}")))?;
        for raw in rows {
            let raw = raw.map_err(|e| LogError(format!("exposure_block row: {e}")))?;
            if let crate::attempt::FactPayload::FailedPreSend {
                exposure_block: Some(block),
                ..
            } = fact_payload_from_json(crate::attempt::FactKind::FailedPreSend, &raw)?
            {
                return Ok(Some(block));
            }
        }
        Ok(None)
    }

    fn plan_refusal(
        &self,
        idempotency_key: &str,
    ) -> Result<Option<crate::attempt::PlanRefusalRecord>, LogError> {
        // `exposure_block`'s read for the other typed record the same fact kind carries: this
        // operation's own `FAILED_PRE_SEND` facts in append order, decoded through the one codec.
        let mut stmt = self
            .conn
            .prepare(
                "SELECT f.payload FROM attempt_fact f
                   JOIN intents i ON i.intent_id = f.operation_id
                  WHERE i.idempotency_key = ?1 AND f.fact_kind = 'failed_pre_send'
                  ORDER BY f.rowid;",
            )
            .map_err(|e| LogError(format!("plan_refusal '{idempotency_key}': {e}")))?;
        let rows = stmt
            .query_map(rusqlite::params![idempotency_key], |r| r.get::<_, String>(0))
            .map_err(|e| LogError(format!("plan_refusal '{idempotency_key}': {e}")))?;
        for raw in rows {
            let raw = raw.map_err(|e| LogError(format!("plan_refusal row: {e}")))?;
            if let crate::attempt::FactPayload::FailedPreSend { plan_refusal: Some(record), .. } =
                fact_payload_from_json(crate::attempt::FactKind::FailedPreSend, &raw)?
            {
                return Ok(Some(record));
            }
        }
        Ok(None)
    }

    fn exposure_obligation(
        &self,
        obligation_id: &str,
    ) -> Result<Option<ExposureObligation>, LogError> {
        // The resolution lookup is a primary-key read, and the projection is the contract:
        // `primitive_atom` and `provider_scope` are deliberately not selected, so no path from
        // the surfaced reference back to the provider's identifiers exists through this method
        // either. Nothing is evicted from this table, so a reference the engine ever surfaced
        // resolves forever.
        self.conn
            .query_row(
                "SELECT obligation_id, direction, generation, contributor_attempt_id,
                        created_at, retired_at
                   FROM exposure_obligation WHERE obligation_id = ?1;",
                rusqlite::params![obligation_id],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, String>(4)?,
                        r.get::<_, Option<String>>(5)?,
                    ))
                },
            )
            .optional()
            .map_err(|e| LogError(format!("exposure_obligation '{obligation_id}': {e}")))?
            .map(|(id, direction, generation, contributor, created_at, retired_at)| {
                Ok(ExposureObligation {
                    obligation_id: id,
                    // Through the enum's own spelling authority: a token this build never wrote
                    // fails explicitly rather than defaulting into a direction (the `AttemptClass`
                    // round-trip discipline).
                    direction: crate::attempt::ExposureDirection::from_sql(&direction)
                        .ok_or_else(|| {
                            LogError(format!(
                                "exposure_obligation '{obligation_id}' has unknown \
                                 direction '{direction}'"
                            ))
                        })?,
                    generation,
                    contributor_attempt_id: contributor,
                    created_at,
                    retired_at,
                })
            })
            .transpose()
    }

    fn unknown_review(
        &self,
        now_unix_secs: u64,
        review_after_seconds: u64,
    ) -> Result<UnknownReviewReport, LogError> {
        use crate::attempt::FactKind;
        // The age cutoff as canonical RFC 3339 text, which sorts lexicographically in
        // chronological order, so the comparison below uses the same shape authority every
        // stored timestamp already cleared and invents no date arithmetic of its own.
        let cutoff = crate::prestate::rfc3339_utc(now_unix_secs.saturating_sub(review_after_seconds));
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| LogError(format!("unknown_review txn begin: {e}")))?;
        // The clock question is asked inside the same transaction the rows are read in, so the
        // high-water and the chains this report presents are one snapshot, and through
        // `FACT_CLOCK_HIGH_WATER_SQL`, the text `fact_clock` clamps against on the write side.
        // One authority, one index, no second high-water row.
        let high_water: String = tx
            .query_row(FACT_CLOCK_HIGH_WATER_SQL, [], |r| r.get(0))
            .map_err(|e| LogError(format!("unknown_review clock high-water read: {e}")))?;
        let clock_rollback_detected =
            unknown_review_rollback(&crate::prestate::rfc3339_utc(now_unix_secs), &high_water)?;
        let mut heads: Vec<(String, String)> = Vec::new();
        {
            let mut stmt = tx
                .prepare(
                    "SELECT h.attempt_id, i.idempotency_key
                       FROM attempt_head h JOIN intents i ON i.intent_id = h.operation_id
                      WHERE h.derived_class = ?1 ORDER BY i.seq;",
                )
                .map_err(|e| LogError(format!("unknown_review scan: {e}")))?;
            let rows = stmt
                .query_map(
                    rusqlite::params![crate::attempt::AttemptClass::IssuedOrUnknown.as_sql()],
                    |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
                )
                .map_err(|e| LogError(format!("unknown_review scan: {e}")))?;
            for row in rows {
                heads.push(row.map_err(|e| LogError(format!("unknown_review scan: {e}")))?);
            }
        }
        let mut report = Vec::new();
        for (attempt_id, idempotency_key) in heads {
            let chain = read_attempt_chain(&tx, &attempt_id)?;
            let state = crate::attempt::fold(&chain)
                .map_err(|d| LogError(format!("attempt '{attempt_id}' does not fold: {d}")))?;
            // The head narrowed the scan; the fold decides what is listed. The rule against
            // read-derived attribution is about decisions and this is a report, but a report an
            // operator adjudicates from is one read away from a decision, so the class is taken
            // from the chain, and a head that disagreed would drop the row here rather than
            // surface an attempt whose facts say something else.
            if state.class() != Some(crate::attempt::AttemptClass::IssuedOrUnknown) {
                continue;
            }
            // When it became unknown: the recorded ambiguity, else the authorization (an
            // authorized-unacked attempt has been unknown since the moment it could have touched
            // the wire; dating it from anything later would under-report the age the threshold
            // exists to surface).
            let unknown_since = chain
                .iter()
                .rev()
                .find(|f| f.kind == FactKind::AckAmbiguous)
                .or_else(|| chain.iter().find(|f| f.kind == FactKind::SendAuthorized))
                .map(|f| f.created_at.clone())
                .ok_or_else(|| {
                    LogError(format!(
                        "unknown_review: attempt '{attempt_id}' classifies ISSUED_OR_UNKNOWN with \
                         no authorization fact"
                    ))
                })?;
            report.push(UnknownReviewRow {
                attempt_id,
                idempotency_key,
                // A detected rollback is review-now, unconditionally (see the in-memory twin).
                review_due: clock_rollback_detected || unknown_since <= cutoff,
                unknown_since,
                reconcile_cap_reached: state.reconcile_count
                    >= crate::attempt::GrammarLimits::DEFAULT.reconcile_lifetime_cap,
            });
        }
        Ok(UnknownReviewReport {
            clock_rollback_detected,
            rows: report,
        })
    }
}
