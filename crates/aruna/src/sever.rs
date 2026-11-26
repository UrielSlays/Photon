//! The sever half: per-operation classification, the witness codec, and the coalescing sever service.

use crate::adjudication::FACT_CLOCK_HIGH_WATER_SQL;
use crate::fact_store::{fold_stored_attempt, read_attempt_chain};
use crate::intent::NON_TERMINAL_STATUS_SQL;
use crate::settle::{append_fact_with_head, terminalize_operation};
use crate::sqlite_log::read_effective_bounds;
use crate::{IntentStatus, LiveAttempt, LogError, SeverOutcome, SeverWitness, SqliteIntentLog};

// The sever half: the per-operation classification rule (one copy, shared by both stores),
// the witness row's codec, and the reconciliation check. The canonical encoding and the
// digest live in `attempt.rs` and nowhere else.

/// What a sever owes one active operation. Derived by [`sever_disposition`], the one copy of
/// the rule, shared by the durable and in-memory stores so they cannot classify the same
/// store differently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SeverDisposition {
    /// Active with no non-terminal attempt (never-claimed work, or the retry gap).
    /// `OperationMember`/`NO_ACTIVE_ATTEMPT`; the operation terminalizes `Severed`.
    OperationMember,
    /// Claimed, never authorized. `AttemptMember`/`SEVERED_BEFORE_ISSUANCE`; the attempt gains
    /// its closure fact and the operation terminalizes `Severed`.
    ClosedBeforeIssuance {
        /// The live attempt.
        attempt_id: String,
        /// Its revision at the sever: the state the classification observed, before the
        /// closure fact this sever appends.
        revision: u64,
    },
    /// Authorized without terminal attribution. `AttemptMember`/`ISSUED_OR_UNKNOWN`; nothing
    /// is written to it: non-issuance cannot be proven, so it is not claimed, and the
    /// operation stays active.
    IssuedOrUnknown {
        /// The live attempt.
        attempt_id: String,
        /// Its revision at the sever.
        revision: u64,
    },
}

/// Classify one active operation from the folds of its attempts. Pure: the caller supplies
/// the operation's non-terminal attempts (operational axis `Active`) and this decides which
/// member it is.
///
/// More than one live attempt on one operation is a store defect and an error, not a case:
/// the CLAIM path's ordinal totality permits exactly one, and the partition's own claim that
/// each active operation appears exactly once is only true because of it. Silently picking one
/// would publish a witness that omits real in-flight work.
pub(crate) fn sever_disposition(
    operation_id: &str,
    live: &[(String, crate::attempt::DerivedState)],
) -> Result<SeverDisposition, LogError> {
    use crate::attempt::WitnessClass;
    match live {
        [] => Ok(SeverDisposition::OperationMember),
        [(attempt_id, state)] => {
            let revision = state.current_revision;
            match state.witness_class_at_sever() {
                Some(WitnessClass::SeveredBeforeIssuance) => {
                    Ok(SeverDisposition::ClosedBeforeIssuance {
                        attempt_id: attempt_id.clone(),
                        revision,
                    })
                }
                Some(WitnessClass::IssuedOrUnknown) => Ok(SeverDisposition::IssuedOrUnknown {
                    attempt_id: attempt_id.clone(),
                    revision,
                }),
                // `witness_class_at_sever` returns exactly those two for a live attempt (a
                // terminal or adjudicated one is operationally closed and never reaches here).
                // Anything else means the fold and this function disagree about what "live"
                // means.
                other => Err(LogError(format!(
                    "sever: operation '{operation_id}' holds a live attempt '{attempt_id}' \
                     that classifies {other:?} — a live attempt is SEVERED_BEFORE_ISSUANCE or \
                     ISSUED_OR_UNKNOWN and nothing else"
                ))),
            }
        }
        many => Err(LogError(format!(
            "sever: operation '{operation_id}' holds {} non-terminal attempts at once; the \
             CLAIM grammar permits exactly one, and the §5.2c partition is total only because \
             of it",
            many.len()
        ))),
    }
}

/// The partition's answer, read as an operation's live attempt. Shared by the durable and
/// in-memory stores (like `sever_disposition`) so they cannot describe the same store
/// differently. Two live classes; the no-live-attempt member is `None`.
pub(crate) fn live_attempt_from(disposition: SeverDisposition) -> Option<LiveAttempt> {
    match disposition {
        SeverDisposition::OperationMember => None,
        SeverDisposition::ClosedBeforeIssuance {
            attempt_id,
            revision,
        } => Some(LiveAttempt {
            attempt_id,
            revision,
            class: crate::attempt::AttemptClass::PreIssuance,
        }),
        SeverDisposition::IssuedOrUnknown {
            attempt_id,
            revision,
        } => Some(LiveAttempt {
            attempt_id,
            revision,
            class: crate::attempt::AttemptClass::IssuedOrUnknown,
        }),
    }
}

/// The canonical member order: bytewise ascending over each member's fully encoded byte
/// string (tag byte included). [`crate::attempt::encode_sever_witness`] sorts internally, so
/// the digest does not depend on this; the stored member set does, since it must be in the
/// same order the digest was taken in, or the row stops being a mechanical recomputation of
/// itself.
pub(crate) fn canonical_witness_order(
    mut members: Vec<crate::attempt::WitnessMember>,
) -> Vec<crate::attempt::WitnessMember> {
    members.sort_by_cached_key(crate::attempt::WitnessMember::encode);
    members
}

/// Every non-terminal attempt of one operation, folded: the fact-derived half of the
/// classification. Keyed off the CLAIM rows' `operation_id` (the immutable owner), so an
/// attempt can never be read into the wrong operation's partition.
pub(crate) fn live_attempts_of(
    tx: &rusqlite::Transaction<'_>,
    operation_id: &str,
) -> Result<Vec<(String, crate::attempt::DerivedState)>, LogError> {
    let mut stmt = tx
        .prepare(
            "SELECT attempt_id FROM attempt_fact
              WHERE operation_id = ?1 AND fact_kind = 'claim' ORDER BY attempt_ordinal;",
        )
        .map_err(|e| LogError(format!("sever attempt read: {e}")))?;
    let ids = stmt
        .query_map(rusqlite::params![operation_id], |r| r.get::<_, String>(0))
        .map_err(|e| LogError(format!("sever attempt read: {e}")))?;
    let mut live = Vec::new();
    for id in ids {
        let attempt_id = id.map_err(|e| LogError(format!("sever attempt read: {e}")))?;
        let state = fold_stored_attempt(tx, &attempt_id)?;
        if state.operational == crate::attempt::OperationalAxis::Active {
            live.push((attempt_id, state));
        }
    }
    Ok(live)
}

/// The durable spelling of a witness class: the `member_set` JSON's `class` token. The byte
/// mapping is the fixed encoding and lives in [`crate::attempt::WitnessClass::as_byte`]; this
/// is only how the row spells the same class in text.
fn witness_class_token(class: crate::attempt::WitnessClass) -> &'static str {
    use crate::attempt::WitnessClass;
    match class {
        WitnessClass::NoActiveAttempt => "no_active_attempt",
        WitnessClass::Completed => "completed",
        WitnessClass::SeveredBeforeIssuance => "severed_before_issuance",
        WitnessClass::IssuedOrUnknown => "issued_or_unknown",
    }
}

/// The inverse; `None` for a spelling this build never wrote.
fn witness_class_from_token(token: &str) -> Option<crate::attempt::WitnessClass> {
    crate::attempt::WitnessClass::ALL
        .iter()
        .copied()
        .find(|c| witness_class_token(*c) == token)
}

/// The `sever_witness.member_set` column: the member tagged union as canonical JSON, members
/// in the same canonical order the digest is computed over. Deterministic (`serde_json`'s
/// object keys are ordered), so the stored bytes of one member set are one byte string, and a
/// reader re-deriving the digest from this column gets the sever's own answer.
///
/// Ids are persisted as text because every id this engine mints is text (`intents.intent_id`,
/// `attempt_fact.attempt_id`; opaque hex). A non-UTF-8 id is an error rather than a lossy
/// escape: the witness must be re-derivable, and a lossy id is not.
pub(crate) fn witness_member_set_json(members: &[crate::attempt::WitnessMember]) -> Result<String, LogError> {
    use crate::attempt::{WitnessClass, WitnessMember};
    let text = |id: &[u8]| -> Result<String, LogError> {
        String::from_utf8(id.to_vec()).map_err(|_| {
            LogError("sever witness: an opaque id is not UTF-8 text and cannot be witnessed".into())
        })
    };
    let mut out: Vec<serde_json::Value> = Vec::with_capacity(members.len());
    for member in members {
        out.push(match member {
            WitnessMember::Operation { operation_id } => serde_json::json!({
                "kind": "operation",
                "id": text(operation_id)?,
                "class": witness_class_token(WitnessClass::NoActiveAttempt),
            }),
            WitnessMember::Attempt {
                attempt_id,
                attempt_revision,
                class_at_sever,
            } => serde_json::json!({
                "kind": "attempt",
                "id": text(attempt_id)?,
                "revision": attempt_revision,
                "class": witness_class_token(*class_at_sever),
            }),
        });
    }
    Ok(serde_json::Value::Array(out).to_string())
}

/// The inverse of [`witness_member_set_json`]: anything that is not a member this build could
/// have written is a `LogError`, never a skipped element (a witness that silently drops a
/// member it cannot read under-reports the seizure).
fn witness_members_from_json(raw: &str) -> Result<Vec<crate::attempt::WitnessMember>, LogError> {
    use crate::attempt::{WitnessClass, WitnessMember};
    let v: serde_json::Value = serde_json::from_str(raw)
        .map_err(|e| LogError(format!("sever witness member_set is not JSON: {e}")))?;
    let array = v
        .as_array()
        .ok_or_else(|| LogError("sever witness member_set is not a JSON array".into()))?;
    let mut members = Vec::with_capacity(array.len());
    for element in array {
        let field = |name: &str| -> Result<String, LogError> {
            element
                .get(name)
                .and_then(|x| x.as_str())
                .map(|s| s.to_string())
                .ok_or_else(|| LogError(format!("sever witness member has no '{name}'")))
        };
        let class_token = field("class")?;
        let class = witness_class_from_token(&class_token).ok_or_else(|| {
            LogError(format!(
                "sever witness member class '{class_token}' is not one this build writes"
            ))
        })?;
        let id = field("id")?.into_bytes();
        members.push(match field("kind")?.as_str() {
            "operation" => {
                if class != WitnessClass::NoActiveAttempt {
                    return Err(LogError(format!(
                        "sever witness: an OperationMember carries class '{}' — the only \
                         operation-grain class is NO_ACTIVE_ATTEMPT",
                        witness_class_token(class)
                    )));
                }
                WitnessMember::Operation { operation_id: id }
            }
            "attempt" => {
                // The attempt-grain class domain, the mirror of the operation-grain check above.
                // The partition emits exactly two classes at attempt grain:
                // `severed_before_issuance` (claimed, never authorized) and `issued_or_unknown`
                // (authorized without terminal attribution). The other two are operation-grain
                // by definition: `no_active_attempt` describes an operation with no live
                // attempt at all, and `completed` is the lifecycle-terminal class the witness
                // leaves out entirely. Either on an attempt member is audit data no sever
                // transaction could have produced, so it fails reconciliation rather than
                // parsing into a member the digest then blesses.
                if !matches!(
                    class,
                    WitnessClass::SeveredBeforeIssuance | WitnessClass::IssuedOrUnknown
                ) {
                    return Err(LogError(format!(
                        "sever witness: an AttemptMember carries class '{}' — the only \
                         attempt-grain classes are SEVERED_BEFORE_ISSUANCE and ISSUED_OR_UNKNOWN",
                        witness_class_token(class)
                    )));
                }
                WitnessMember::Attempt {
                    attempt_id: id,
                    attempt_revision: element.get("revision").and_then(|x| x.as_u64()).ok_or_else(
                        || LogError("sever witness attempt member has no 'revision'".into()),
                    )?,
                    class_at_sever: class,
                }
            }
            other => {
                return Err(LogError(format!(
                    "sever witness member kind '{other}' is not one this build writes"
                )))
            }
        });
    }
    Ok(members)
}

/// One `sever_witness` row exactly as stored, before reconciliation. Nothing reads a witness
/// through this type: [`verify_sever_witness`] is the only way out of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RawSeverWitness {
    pub(crate) witness_id: String,
    pub(crate) epoch: i64,
    pub(crate) severed_at: String,
    pub(crate) authority_ref: String,
    pub(crate) member_count: i64,
    pub(crate) member_set: String,
    pub(crate) digest: String,
}

/// The reconciliation check for a stored sever witness (ADR-P008): every required field must be
/// present, the stored count must equal the stored member set, and the digest must recompute from
/// that member set through the pure core's canonical encoding. An epoch-only or membership-only
/// witness fails. It is a `Result`-returning parse, not a Boolean, so a witness cannot be read
/// without having been reconciled.
///
/// It runs in the open-time quarantine ([`boot_quarantine`]) for every stored witness, and a
/// failure is surfaced as [`IntegrityEvidence::SeverWitnessUnreconciled`]: evidence, not a
/// refusal, because the witness is audit substrate and no dispatch decision reads it.
pub(crate) fn verify_sever_witness(raw: &RawSeverWitness) -> Result<SeverWitness, LogError> {
    // (1) Element presence. The list is a minimum: if the post-sever audit is lost, this row
    // is the only surviving evidence. A row missing any of them is not a weaker witness, it
    // is not a witness.
    let missing = |field: &str| LogError(format!(
        "sever witness for epoch {} carries no {field} — §5.1's element-(3) minimum is the \
         post-sever epoch, the timestamp, the authority reference, the member count, the \
         member set and the digest",
        raw.epoch
    ));
    if raw.witness_id.trim().is_empty() {
        return Err(missing("witness id"));
    }
    // The floor is 2. Epoch 1 is the seeded pre-sever value the `control_epoch` singleton
    // opens with, and a witness is written by the sever transaction that bumped the epoch, so
    // the lowest value one can carry is 2. A row at 1 is a row no sever wrote.
    if raw.epoch < 2 {
        return Err(LogError(format!(
            "sever witness '{}' carries epoch {} — a post-sever epoch is at least 2 (the \
             singleton is seeded 1 and every sever bumps it)",
            raw.witness_id, raw.epoch
        )));
    }
    if !crate::prestate::is_canonical_rfc3339_utc(&raw.severed_at) {
        return Err(LogError(format!(
            "sever witness '{}' carries timestamp '{}', which is not canonical RFC-3339 UTC",
            raw.witness_id, raw.severed_at
        )));
    }
    if raw.authority_ref.trim().is_empty() {
        return Err(missing("seizing-authority reference"));
    }
    if raw.digest.trim().is_empty() {
        return Err(missing("digest"));
    }
    // (2) The member set, parsed through the one codec.
    let members = witness_members_from_json(&raw.member_set)?;
    // (3) Count versus membership. The count is a stored element of its own; a row whose
    // count disagrees with its member set cannot be reconciled by anyone, and picking one of
    // the two would be inventing the answer.
    if raw.member_count < 0 || raw.member_count as u64 != members.len() as u64 {
        return Err(LogError(format!(
            "sever witness '{}' says {} members but its member set holds {}",
            raw.witness_id,
            raw.member_count,
            members.len()
        )));
    }
    // (4) The digest, recomputed: not compared to a second stored copy, but re-derived from
    // the member set through the canonical encoding. This is what makes a hand-edited
    // membership detectable at all.
    let recomputed = crate::attempt::sever_witness_digest_hex(&members);
    if recomputed != raw.digest {
        return Err(LogError(format!(
            "sever witness '{}' does not reconcile: its {} member(s) digest to {recomputed}, \
             the row records {}",
            raw.witness_id,
            members.len(),
            raw.digest
        )));
    }
    Ok(SeverWitness {
        witness_id: raw.witness_id.clone(),
        epoch: raw.epoch,
        severed_at: raw.severed_at.clone(),
        authority_ref: raw.authority_ref.clone(),
        members,
        digest: raw.digest.clone(),
    })
}

/// Every `sever_witness` row in the store, oldest epoch first, raw. Reconciliation is the
/// caller's ([`verify_sever_witness`]); [`boot_quarantine`] runs it over the whole table at
/// every open.
pub(crate) fn read_sever_witnesses(
    conn: &rusqlite::Connection,
) -> Result<Vec<RawSeverWitness>, LogError> {
    let mut stmt = conn
        .prepare(
            "SELECT witness_id, epoch, severed_at, authority_ref, member_count, member_set,
                    digest
               FROM sever_witness ORDER BY epoch;",
        )
        .map_err(|e| LogError(format!("sever witness read: {e}")))?;
    let rows = stmt
        .query_map([], |r| {
            Ok(RawSeverWitness {
                witness_id: r.get(0)?,
                epoch: r.get(1)?,
                severed_at: r.get(2)?,
                authority_ref: r.get(3)?,
                member_count: r.get(4)?,
                member_set: r.get(5)?,
                digest: r.get(6)?,
            })
        })
        .map_err(|e| LogError(format!("sever witness read: {e}")))?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|e| LogError(format!("sever witness read: {e}")))
}

// Sever coalescing: the child attribution table, the shared outcome, and the test seam.

/// `sever_attribution.kind` for an arrival inside the leader's still-open witness snapshot,
/// within `sever_joiner_cap`. Written by the leader, in the kill transaction.
const ATTRIBUTION_IN_SNAPSHOT: &str = "in-snapshot";
/// `sever_attribution.kind` for an arrival inside the snapshot but past the cap. Appends
/// itself after the leader commits.
const ATTRIBUTION_OVERFLOW: &str = "overflow-joiner";
/// `sever_attribution.kind` for an arrival after the snapshot closed and before the service
/// completed. Appends itself after the leader commits.
const ATTRIBUTION_POST_SNAPSHOT: &str = "post-snapshot";

/// The `sever_attribution.kind` a requester appends for itself after the leader commits; `None`
/// for the two roles that must not.
///
/// `Leader` gives `None`: its attribution is its `sever_witness.authority_ref`, and a child row
/// too would record the same fact twice and let the two disagree. `InSnapshotJoiner` gives `None`
/// **even though its row exists**: the leader committed that row inside the kill transaction,
/// atomically with the witness, and a self-append would double-count it
/// (`coalesced_severs_share_one_epoch_bump`). This is the only producer of the strings, so they
/// cannot drift from the table's `CHECK`.
pub(crate) fn self_appended_attribution_kind(role: crate::writer_gate::SeverRole) -> Option<&'static str> {
    match role {
        crate::writer_gate::SeverRole::Leader { .. }
        | crate::writer_gate::SeverRole::InSnapshotJoiner { .. } => None,
        crate::writer_gate::SeverRole::OverflowJoiner => Some(ATTRIBUTION_OVERFLOW),
        crate::writer_gate::SeverRole::PostSnapshot => Some(ATTRIBUTION_POST_SNAPSHOT),
    }
}

/// The child table's only writer. `created_at` is unix seconds through SQLite's own clock, the
/// `engine_config.recorded_at` convention for ledger rows, deliberately not the clamped fact
/// clock: nothing orders an attribution row against an attempt-fact chain, and borrowing that
/// clock would imply an ordering guarantee this row does not have.
pub(crate) fn insert_sever_attribution(
    tx: &rusqlite::Transaction<'_>,
    epoch: i64,
    requester_ref: &str,
    kind: &str,
) -> Result<(), LogError> {
    tx.execute(
        "INSERT INTO sever_attribution (epoch, requester_ref, kind, created_at)
         VALUES (?1, ?2, ?3, strftime('%s','now'));",
        rusqlite::params![epoch, requester_ref, kind],
    )
    .map_err(|e| {
        LogError(format!(
            "sever attribution append ('{kind}' against epoch {epoch}): {e}"
        ))
    })?;
    Ok(())
}

/// The shared outcome a coalesced requester returns, read back from what the leader durably wrote
/// rather than relayed. The gate's rendezvous carries only the epoch, which is the witness row's
/// UNIQUE key, so the whole outcome is recoverable from the store and a joiner reports a durable
/// fact. It goes through [`verify_sever_witness`], so a joiner can never report a witness the
/// engine would refuse.
///
/// `terminalized` is derived by reading the leader's partition backwards: the kill transaction
/// terminalizes every member except the `ISSUED_OR_UNKNOWN` attempts, which it witnesses and
/// leaves alive. `coalesced_severs_share_one_epoch_bump` checks that equality against the
/// leader's returned value on a store where the count is non-zero.
pub(crate) fn sever_outcome_of_epoch(
    conn: &rusqlite::Connection,
    epoch: i64,
) -> Result<SeverOutcome, LogError> {
    let raw = conn
        .query_row(
            "SELECT witness_id, epoch, severed_at, authority_ref, member_count, member_set,
                    digest
               FROM sever_witness WHERE epoch = ?1;",
            rusqlite::params![epoch],
            |r| {
                Ok(RawSeverWitness {
                    witness_id: r.get(0)?,
                    epoch: r.get(1)?,
                    severed_at: r.get(2)?,
                    authority_ref: r.get(3)?,
                    member_count: r.get(4)?,
                    member_set: r.get(5)?,
                    digest: r.get(6)?,
                })
            },
        )
        .map_err(|e| {
            LogError(format!(
                "sever: the service reported epoch {epoch} but its witness is unreadable — a \
                 coalesced requester answers from the durable record, never from a relay: {e}"
            ))
        })?;
    let witness = verify_sever_witness(&raw)?;
    let terminalized = witness
        .members
        .iter()
        .filter(|m| {
            !matches!(
                m,
                crate::attempt::WitnessMember::Attempt {
                    class_at_sever: crate::attempt::WitnessClass::IssuedOrUnknown,
                    ..
                }
            )
        })
        .count() as u64;
    Ok(SeverOutcome {
        epoch,
        witness,
        terminalized,
    })
}

/// The two points inside the sever service where a test can intervene.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SeverSeam {
    /// On the leader, inside its transaction, immediately after the join window closed and
    /// before the witness row is written: the window a post-snapshot arrival has to land in.
    AfterCloseSnapshot,
    /// On a non-leader, immediately before it appends its own attribution row. A crash here
    /// leaves the requester's attribution unacknowledged.
    BeforeAttributionAppend,
}

/// What a seam does when it fires: it is handed the point and the requester reference.
#[cfg(test)]
type SeverSeamHook = Box<dyn Fn(SeverSeam, &str)>;

#[cfg(test)]
thread_local! {
    /// Thread-local on purpose: a test installs the seam on exactly the thread it means to
    /// stop or kill, so parallel tests in one process cannot see each other's seam and no
    /// global state has to be torn down. `#[cfg(not(test))]` compiles the whole mechanism
    /// (storage, enum and call sites) to nothing.
    static SEVER_SEAM: std::cell::RefCell<Option<SeverSeamHook>> =
        const { std::cell::RefCell::new(None) };
}

/// Install this thread's sever seam (test-only).
#[cfg(test)]
pub(crate) fn install_sever_seam(f: SeverSeamHook) {
    SEVER_SEAM.with(|c| *c.borrow_mut() = Some(f));
}

#[cfg(test)]
pub(crate) fn sever_attribution_seam(point: SeverSeam, requester_ref: &str) {
    SEVER_SEAM.with(|c| {
        if let Some(f) = c.borrow().as_ref() {
            f(point, requester_ref);
        }
    });
}

/// In a non-test build there is no seam: the call sites compile away entirely.
#[cfg(not(test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SeverSeam {
    AfterCloseSnapshot,
    BeforeAttributionAppend,
}

#[cfg(not(test))]
#[inline]
pub(crate) fn sever_attribution_seam(_point: SeverSeam, _requester_ref: &str) {}

/// The gate handle a sever service runs under.
///
/// `WriterGate::for_connection` mints handles carrying [`crate::capacity::DEFAULT`] because it has
/// no transaction to read the `engine_config` ledger through. The sever service's joiner cap is a
/// `capacity` act, so this reads the store's current bounds through [`read_effective_bounds`]
/// (the same derivation admission uses, so the two cannot read the ledger differently) and hands
/// them to a pointer-clone of the same arbiter.
///
/// The read runs in its own deferred transaction: it writes nothing, and enrolling a write here
/// would mean enrolling before asking whether we may lead. A capacity act landing before the join
/// window closes cannot split a service: the leader's cap is captured into the window
/// (`writer_gate::JoinWindow`), and every arrival is bounded by that one number.
pub(crate) fn sever_service_gate(
    conn: &crate::store_open::GatedConnection,
) -> Result<crate::writer_gate::WriterGate, LogError> {
    let tx = conn
        .unchecked_transaction()
        .map_err(|e| LogError(format!("sever config read txn begin: {e}")))?;
    let bounds = read_effective_bounds(&tx)?;
    Ok(conn.gate().with_config(bounds.current))
}

/// The kill transaction, run by the one leader of a coalesced service.
///
/// One `Immediate` transaction in which the epoch bump, the partition, the canonical witness and
/// the member closures are one durable write, so the witness is atomic with the sever and the
/// operations are terminalized atomically with it. SQLite's single writer linearizes it against
/// `authorize_send`: exactly one goes first, and both orders are safe.
///
/// Coalescing adds the join window close (`SeverEntry::close_snapshot`) at the moment the member
/// set freezes, and the in-snapshot joiners' `sever_attribution` rows inside this transaction. A
/// joiner cannot be added to a running transaction, so the window closes before the witness is
/// written and everything frozen into it commits with the witness.
///
/// It runs through [`crate::store_open::GatedConnection::with_service_tx`], not
/// `with_immediate_tx`: the leader's own raised ticket blocks ordinary enrollment, so the
/// ordinary path would wait for itself.
pub(crate) fn lead_sever_service(
    log: &mut SqliteIntentLog,
    entry: &crate::writer_gate::SeverEntry,
    authority_ref: &str,
    now: &str,
) -> Result<SeverOutcome, LogError> {
    use crate::attempt::{Fact, FactKind, FactPayload, WitnessClass, WitnessMember};
    let authority_ref = authority_ref.to_string();
    log.conn.with_service_tx(entry, |tx| {
        let authority_ref = authority_ref.clone();

        // (1) The epoch bump. This function is the singleton's only writer.
        let bumped = tx
            .execute("UPDATE control_epoch SET epoch = epoch + 1 WHERE id = 1;", [])
            .map_err(|e| LogError(format!("sever epoch bump: {e}")))?;
        if bumped != 1 {
            // The open path already refuses a store with no fence row; reaching here would
            // mean it vanished under us. A sever that cannot raise the fence has not severed
            // anything, and reporting otherwise would be false.
            return Err(LogError(
                "sever: the control_epoch singleton is missing — a store with no fence cannot \
             be severed"
                    .into(),
            ));
        }
        let epoch: i64 = tx
            .query_row("SELECT epoch FROM control_epoch WHERE id = 1;", [], |r| {
                r.get(0)
            })
            .map_err(|e| LogError(format!("sever epoch read: {e}")))?;
        // The sever instant, through the same clamp every fact uses: the witness and the
        // closure facts it justifies share one timestamp, and neither can sort before the
        // chain it closes.
        let max_persisted: String = tx
            .query_row(FACT_CLOCK_HIGH_WATER_SQL, [], |r| r.get(0))
            .map_err(|e| LogError(format!("sever clock high-water read: {e}")))?;
        let severed_at = crate::attempt::clamped_now(now, &max_persisted)
            .map_err(|e| LogError(format!("sever clock: {e}")))?
            .value;

        // (2) The partition, over a pristine pre-closure snapshot. This is the only status
        // read here: an operation whose lifecycle is already terminal before the sever
        // (its status is terminal) is completed and absent from the witness. Everything below
        // operation grain is fact-derived: which attempt is live, and what class it is,
        // comes from the fold and never from a status read.
        let mut actives: Vec<(String, String)> = Vec::new();
        {
            let mut stmt = tx
                .prepare(&format!(
                    "SELECT intent_id, idempotency_key FROM intents
                  WHERE status IN {NON_TERMINAL_STATUS_SQL} ORDER BY seq;"
                ))
                .map_err(|e| LogError(format!("sever active read: {e}")))?;
            let rows = stmt
                .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
                .map_err(|e| LogError(format!("sever active read: {e}")))?;
            for row in rows {
                actives.push(row.map_err(|e| LogError(format!("sever active read: {e}")))?);
            }
        }
        let mut members: Vec<WitnessMember> = Vec::new();
        let mut closures: Vec<(String, String, SeverDisposition)> = Vec::new();
        for (operation_id, key) in actives {
            let live = live_attempts_of(tx, &operation_id)?;
            let disposition = sever_disposition(&operation_id, &live)?;
            members.push(match &disposition {
                SeverDisposition::OperationMember => WitnessMember::Operation {
                    operation_id: operation_id.clone().into_bytes(),
                },
                SeverDisposition::ClosedBeforeIssuance {
                    attempt_id,
                    revision,
                } => WitnessMember::Attempt {
                    attempt_id: attempt_id.clone().into_bytes(),
                    attempt_revision: *revision,
                    class_at_sever: WitnessClass::SeveredBeforeIssuance,
                },
                SeverDisposition::IssuedOrUnknown {
                    attempt_id,
                    revision,
                } => WitnessMember::Attempt {
                    attempt_id: attempt_id.clone().into_bytes(),
                    attempt_revision: *revision,
                    class_at_sever: WitnessClass::IssuedOrUnknown,
                },
            });
            closures.push((operation_id, key, disposition));
        }

        // (3) The witness. The canonical order, the encoding and the digest all come from the
        // pure core, so there is one implementation.
        let members = canonical_witness_order(members);
        let digest = crate::attempt::sever_witness_digest_hex(&members);
        let member_set = witness_member_set_json(&members)?;

        // (3a) The join window closes here. The member set is frozen; the witness row is the
        // next statement. Every requester that arrives from now on is a post-snapshot arrival
        // and owns its own append, since attribution is never appended into a running
        // transaction.
        let in_snapshot = entry.close_snapshot()?;
        sever_attribution_seam(SeverSeam::AfterCloseSnapshot, &authority_ref);

        let witness_id: String = tx
            .query_row("SELECT lower(hex(randomblob(16)));", [], |r| r.get(0))
            .map_err(|e| LogError(format!("sever witness id mint: {e}")))?;
        tx.execute(
            "INSERT INTO sever_witness (witness_id, epoch, severed_at, authority_ref,
                                    member_count, member_set, digest)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7);",
            rusqlite::params![
                witness_id,
                epoch,
                severed_at,
                authority_ref,
                members.len() as i64,
                member_set,
                digest,
            ],
        )
        .map_err(|e| LogError(format!("sever witness insert: {e}")))?;

        // (3b) The in-snapshot joiners, atomically with the witness. Bounded by
        // `sever_joiner_cap`: the gate froze at most that many into the window, since an
        // unbounded requester payload would grow the kill transaction's write work past its
        // time bound. The foreign key to `sever_witness(epoch)` is satisfied by the statement
        // immediately above, in this same transaction.
        for (_join_id, requester_ref) in &in_snapshot {
            insert_sever_attribution(tx, epoch, requester_ref, ATTRIBUTION_IN_SNAPSHOT)?;
        }

        // (4) The closures.
        let mut terminalized = 0u64;
        for (operation_id, key, disposition) in closures {
            match disposition {
                SeverDisposition::IssuedOrUnknown { .. } => {
                    // Witnessed and deliberately left alive: non-issuance cannot be proven.
                }
                SeverDisposition::OperationMember => {
                    terminalize_operation(tx, &key, IntentStatus::Severed)?;
                    terminalized += 1;
                }
                SeverDisposition::ClosedBeforeIssuance {
                    attempt_id,
                    revision,
                } => {
                    let chain = read_attempt_chain(tx, &attempt_id)?;
                    let fact = Fact {
                        operation_id: operation_id.clone(),
                        attempt_id: attempt_id.clone(),
                        revision: revision + 1,
                        kind: FactKind::SeveredBeforeIssuance,
                        basis_epoch: epoch,
                        created_at: severed_at.clone(),
                        payload: FactPayload::None,
                        prior_revision: Some(revision),
                    };
                    // The grammar cannot refuse this one: `SEVERED_BEFORE_ISSUANCE` is legal
                    // exactly on a claimed-unauthorized chain, which the classification above
                    // proved this is, in this same transaction. A refusal therefore means the
                    // fold and the grammar disagree, so fail and roll the whole sever back
                    // rather than publish a witness whose closure did not happen.
                    if let Some(refusal) = append_fact_with_head(tx, &chain, &fact)? {
                        return Err(LogError(format!(
                            "sever: the closure of attempt '{attempt_id}' was refused by the \
                         grammar: {refusal}"
                        )));
                    }
                    terminalize_operation(tx, &key, IntentStatus::Severed)?;
                    terminalized += 1;
                }
            }
        }
        Ok(SeverOutcome {
            epoch,
            witness: SeverWitness {
                witness_id,
                epoch,
                severed_at,
                authority_ref,
                members,
                digest,
            },
            terminalized,
        })
    })
}

/// Validates the shape of the seizing-authority reference, and nothing more. The witness wants
/// a reference (never personal data), and a reference is a token: non-empty,
/// control-character-free, bounded. An on-box engine cannot verify what a reference means or
/// stop a caller that passes a sentence; code already running on the user's machine with the
/// user's privileges is not defended against, and this is a shape check, not a control.
pub(crate) fn validated_authority_ref(authority_ref: &str) -> Result<String, LogError> {
    const MAX: usize = 256;
    if authority_ref.trim().is_empty() {
        return Err(LogError(
            "sever: the seizing-authority reference is empty — §5.1's witness records the \
             authority BY REFERENCE, and a witness without one is not evidence"
                .into(),
        ));
    }
    if authority_ref.chars().any(|c| c.is_control()) {
        return Err(LogError(
            "sever: the seizing-authority reference carries control characters — it is an \
             opaque token, not free text"
                .into(),
        ));
    }
    if authority_ref.len() > MAX {
        return Err(LogError(format!(
            "sever: the seizing-authority reference is {} bytes; a reference is bounded at \
             {MAX} (shape, not a content control — see the T2 note on the door)",
            authority_ref.len()
        )));
    }
    Ok(authority_ref.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sever_witness_at_epoch_one_cannot_exist_and_is_refused() {
        // ═══ ═══ The condition disagreed with its OWN message: the singleton
        // is seeded 1 and every sever bumps it, so the LOWEST post-sever epoch a witness can
        // carry is 2 — but the guard admitted 1. A row a sever could never have written is not
        // a weaker witness, it is not a witness.
        let members = vec![crate::attempt::WitnessMember::Operation {
            operation_id: b"op-impossible".to_vec(),
        }];
        let raw = RawSeverWitness {
            witness_id: "w-epoch-1".into(),
            epoch: 1,
            severed_at: "2026-08-08T00:00:00Z".into(),
            authority_ref: "authority:operator-1".into(),
            member_count: 1,
            member_set: witness_member_set_json(&members).expect("member set"),
            digest: crate::attempt::sever_witness_digest_hex(&members),
        };
        let verdict = verify_sever_witness(&raw);
        assert!(
            verdict.is_err(),
            "epoch 1 is PRE-sever — no sever transaction can have produced this row, got {verdict:?}"
        );
        // …and the honest floor still reconciles.
        let mut ok = raw.clone();
        ok.epoch = 2;
        verify_sever_witness(&ok).expect("epoch 2 is the lowest a sever can write");
    }

    #[test]
    fn an_attempt_witness_member_may_only_carry_a_class_the_sever_emits() {
        // ═══ ═══ The attempt arm accepted ANY class token the build can
        // spell. The §5.2c partition emits exactly two classes at attempt grain
        // (`severed_before_issuance` | `issued_or_unknown`); `completed` is the
        // lifecycle-terminal OPERATION class §5.2c leaves OUT of the witness, and
        // `no_active_attempt` is operation-grain by definition. Either on an ATTEMPT member is
        // audit data no sever wrote — it must fail reconciliation, not parse.
        for impossible in [
            crate::attempt::WitnessClass::Completed,
            crate::attempt::WitnessClass::NoActiveAttempt,
        ] {
            let member_set = serde_json::json!([{
                "kind": "attempt",
                "id": "attempt-impossible",
                "revision": 2,
                "class": witness_class_token(impossible),
            }])
            .to_string();
            // The digest is RECOMPUTED from the member set, so a hand-built row must be given
            // its own honest digest — otherwise the digest check, not the class check, refuses.
            let members = witness_members_from_json(&member_set).unwrap_or_default();
            let raw = RawSeverWitness {
                witness_id: "w-impossible-class".into(),
                epoch: 2,
                severed_at: "2026-08-08T00:00:00Z".into(),
                authority_ref: "authority:operator-1".into(),
                member_count: 1,
                member_set,
                digest: crate::attempt::sever_witness_digest_hex(&members),
            };
            let verdict = verify_sever_witness(&raw);
            assert!(
                verdict.is_err(),
                "class '{}' on an ATTEMPT member is impossible audit data, got {verdict:?}",
                witness_class_token(impossible)
            );
        }
    }
}
