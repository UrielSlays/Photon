//! The settlement chokepoints: the verdict mapping, `settle_status`, and the attempt-fact append.

use rusqlite::OptionalExtension;

use crate::fact_store::{fact_payload_json, verified_state_json};
use crate::intent::{status_from_str, status_precondition_sql};
use crate::{
    status_to_str, ConnectorVerdict, EffectEvidence, FailureKind, IntentStatus, LogError,
    StatusPrecondition, StatusWrite,
};

/// Is this settled attempt an eligible retry predecessor, and under which reason? The two
/// eligible terminals are `FAILED_PRE_SEND` and `ACK_REFUSED_NO_EFFECT`. `None` for every
/// other closed attempt: an `ACK_APPLIED` needs no retry, a `SEVERED_BEFORE_ISSUANCE` is
/// behind a bumped epoch, and an adjudicated one has no terminal attribution at all.
///
/// The vocabulary is the grammar's own ([`crate::attempt::RetryReason`]), so this function
/// cannot invent a reason the grammar would refuse.
pub(crate) fn retry_reason_of(state: &crate::attempt::DerivedState) -> Option<crate::attempt::RetryReason> {
    use crate::attempt::{FactKind, RetryReason};
    match state.terminal_attribution? {
        FactKind::FailedPreSend => Some(RetryReason::FailedPreSend),
        FactKind::AckRefusedNoEffect => Some(RetryReason::AckRefusedNoEffect),
        _ => None,
    }
}

/// What a settlement owes the operation's lifecycle, before the epoch is consulted. Private:
/// the public answer is [`SettledLifecycle`], which reports what actually happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LifecycleIntent {
    /// A terminal status, written in the settling transaction.
    Complete(IntentStatus),
    /// The existing transient budget charge (increment; dead-letter only on exhaustion).
    ChargeTransient,
    /// `ISSUANCE_UNKNOWN`: nothing is owed and nothing is spent.
    AwaitingAdjudication,
}

/// The verdict-mapping table, pure. The table is documented on
/// [`IntentLog::settle_attempt`] and evaluated here, in one place, so the durable store and
/// the in-memory one cannot answer differently.
///
/// `send_authorized` is the fact-derived half (only the settling transaction can read it) and
/// `verdict` is the connector-derived half. Nothing else participates: no status read, and no
/// inference from [`FailureKind`] about what the provider proved.
pub(crate) fn verdict_mapping(
    send_authorized: bool,
    verdict: ConnectorVerdict,
) -> (
    crate::attempt::FactKind,
    crate::attempt::FactPayload,
    LifecycleIntent,
) {
    use crate::attempt::{FactKind, FactPayload, PreSendReason, WireEvidence};
    // A failure's lifecycle follows the existing retry taxonomy (ADR-P013).
    let by_taxonomy = |kind: FailureKind| match kind {
        FailureKind::Deterministic => LifecycleIntent::Complete(IntentStatus::Failed),
        FailureKind::Transient => LifecycleIntent::ChargeTransient,
    };
    // An attempt with no committed `SEND_AUTHORIZED` cannot have issued anything; that is
    // the engine's own contract, not the connector's word.
    let no_wire = FactPayload::FailedPreSend {
        wire_evidence: WireEvidence::ProvenNoWire,
        reason: PreSendReason::Failure,
        // Settlement never blocks on exposure: the exposure check is a pre-wire step in
        // `authorize_send`, which is the only writer of this field.
        exposure_block: None,
        plan_refusal: None,
    };
    match verdict {
        // The retry-requalification `C == A` branch. It is not folded into the `Applied` rows
        // below: those claim this operation's effect, and here the effect is somebody else's. The
        // attempt records the proven-no-wire terminal with the deterministic reason; the
        // operation completes on its own terminal, which makes it undo-ineligible and makes an
        // identical replay answer `Err(ExternallySatisfied)` rather than a silent `Ok`.
        //
        // `send_authorized` is not consulted: the requalification check is entered only for a
        // `PreIssuance` attempt, so that premise is checked at its entry. The grammar would
        // allow a post-auth `FAILED_PRE_SEND` on `ProvenNoWire`, so the evidence has to be
        // established before the verdict is minted.
        ConnectorVerdict::ExternallySatisfied => (
            FactKind::FailedPreSend,
            FactPayload::FailedPreSend {
                wire_evidence: WireEvidence::ProvenNoWire,
                reason: PreSendReason::ExternallySatisfied,
                exposure_block: None,
                plan_refusal: None,
            },
            LifecycleIntent::Complete(IntentStatus::ExternallySatisfied),
        ),
        ConnectorVerdict::Applied if send_authorized => (
            FactKind::AckApplied,
            FactPayload::None,
            LifecycleIntent::Complete(IntentStatus::Applied),
        ),
        // The objective holds, and this attempt did not produce it (it was never authorized,
        // e.g. the undo drive's `AlreadyRestored`, where another actor had already put the
        // pre-state back). The two axes disagree, which the two-axis design allows: the
        // attempt records no effect, the operation completes.
        ConnectorVerdict::Applied => (
            FactKind::FailedPreSend,
            no_wire,
            LifecycleIntent::Complete(IntentStatus::Applied),
        ),
        ConnectorVerdict::Failed { kind, .. } if !send_authorized => {
            (FactKind::FailedPreSend, no_wire, by_taxonomy(kind))
        }
        ConnectorVerdict::Failed {
            kind,
            evidence: EffectEvidence::ProvenNoWire,
        } => (FactKind::FailedPreSend, no_wire, by_taxonomy(kind)),
        ConnectorVerdict::Failed {
            kind,
            evidence: EffectEvidence::ProvenRefusedNoEffect,
        } => (
            FactKind::AckRefusedNoEffect,
            FactPayload::None,
            by_taxonomy(kind),
        ),
        // Anything else (a 5xx per Gmail's own retry guidance is not proof of no effect; nor is
        // a truncated or missing post-dispatch response) is `ISSUANCE_UNKNOWN`, with no retry.
        ConnectorVerdict::Failed {
            evidence: EffectEvidence::Indeterminate,
            ..
        } => (
            FactKind::AckAmbiguous,
            FactPayload::None,
            LifecycleIntent::AwaitingAdjudication,
        ),
    }
}

/// Does this settlement's own evidence prove that no effect was issued? This is the single input
/// to the settlement-epoch check: a proven-no-wire settlement under a newer epoch becomes
/// `Severed`.
///
/// It is a function of the verdict, not of a lifecycle branch. Putting the comparison inside the
/// `ChargeTransient` arm would miss a send-authorized request racing a sever that then answers a
/// deterministic proven-no-wire refusal: that resolves `Complete(Failed)` in [`verdict_mapping`],
/// never enters the epoch branch, and closes `failed` instead of `Severed`. The retry taxonomy
/// asks whether another attempt is worth making; the epoch check asks whether anything reached
/// the wire and a retry is still authorized. So it is taken once, from the verdict fact about to
/// be appended, ahead of lifecycle-branch selection.
///
/// Exactly two kinds prove it: `FAILED_PRE_SEND` carrying
/// [`crate::attempt::WireEvidence::ProvenNoWire`] (whether the connector proved it or the absent
/// `SEND_AUTHORIZED` did), and `ACK_REFUSED_NO_EFFECT`. `ACK_APPLIED` proves the opposite;
/// `ACK_AMBIGUOUS` proves nothing, and an unknown issuance is closed by adjudication, never by an
/// epoch.
///
/// The rule also covers the proven-no-wire rows that complete on an objective rather than a
/// failure (`EXTERNALLY_SATISFIED`, and the undo drive's unauthorized-`Applied`
/// `AlreadyRestored`). Both are `PreIssuance`, where the sever's partition already terminalizes the
/// operation `Severed` in its own transaction, so a later settlement is refused by the grammar
/// ([`SettleOutcome::RefusedByGrammar`]); the widening is unreachable there. The reachable case
/// is a send-authorized attempt, which the sever leaves alive. The attribution is untouched: a
/// connector's proof does not become false because an epoch moved.
pub(crate) fn settlement_proves_no_effect(
    kind: crate::attempt::FactKind,
    payload: &crate::attempt::FactPayload,
) -> bool {
    use crate::attempt::{FactKind, FactPayload, WireEvidence};
    match kind {
        FactKind::AckRefusedNoEffect => true,
        FactKind::FailedPreSend => matches!(
            payload,
            FactPayload::FailedPreSend {
                wire_evidence: WireEvidence::ProvenNoWire,
                ..
            }
        ),
        _ => false,
    }
}

/// **The status-write chokepoint.** A compare-and-set over a `&Transaction`, never an autocommit
/// statement, so every status-changing write in the engine funnels through this one function and
/// the set of occupancy-changing sites is closed by construction.
///
/// No activation call lives here: the `intents_status_activation` SQL trigger
/// (`store_open::schema_ddl`) is the only status-side authority that closes a pending capacity
/// reduction, and it fires on the `status` column itself, so it sees every write this function
/// makes. A Rust-side call would be a second authority over the same event.
///
/// Returns the row's actual status after the attempted write, never a bare "changed" bool: a
/// caller that reported the status it asked for would announce a disposition the store does not
/// hold. It is read back inside the same transaction, so it is what will commit.
pub(crate) fn settle_status(
    tx: &rusqlite::Transaction<'_>,
    idempotency_key: &str,
    precondition: &StatusPrecondition,
    status: IntentStatus,
) -> Result<StatusWrite, LogError> {
    // The compare is inside the write; see `IntentLog::set_status_if`'s doc for why a
    // read-then-write here would be a TOCTOU race.
    let (guard, expected) = status_precondition_sql(precondition);
    let sql = format!("UPDATE intents SET status = ?2 WHERE idempotency_key = ?1 AND {guard};");
    let changed = match expected {
        Some(expected) => tx.execute(
            &sql,
            rusqlite::params![idempotency_key, status_to_str(&status), expected],
        ),
        None => tx.execute(&sql, rusqlite::params![idempotency_key, status_to_str(&status)]),
    }
    .map_err(|e| LogError(format!("settle_status '{idempotency_key}': {e}")))?;
    if changed > 0 {
        return Ok(StatusWrite::Written);
    }
    // Refused: report the row's actual status (through the same fail-closed mapper
    // `IntentLog::get` uses, so a corrupt status token is a `LogError` here too).
    let raw: Option<String> = tx
        .query_row(
            "SELECT status FROM intents WHERE idempotency_key = ?1;",
            rusqlite::params![idempotency_key],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| LogError(format!("settle_status read-back '{idempotency_key}': {e}")))?;
    let actual = raw.map(|s| status_from_str(&s)).transpose()?;
    Ok(StatusWrite::Refused(actual))
}

/// Terminalize an operation's lifecycle inside a fact-appending transaction: the status moves in
/// the same write as the fact that justifies it, so no window exists where the ledger says closed
/// while replay, capacity and the resource tail still see a live row.
///
/// A thin wrapper over [`settle_status`] with [`StatusPrecondition::NonTerminal`], so it never
/// overwrites a terminal another authority already wrote. It returns the row's actual status,
/// since the guard makes the write skippable. A row that does not exist at all is a `LogError`
/// here (unlike `settle_status`'s general `Refused(None)`): every caller knows the row exists, so a
/// vanished row is a store integrity defect, not an ordinary refusal.
pub(crate) fn terminalize_operation(
    tx: &rusqlite::Transaction<'_>,
    idempotency_key: &str,
    status: IntentStatus,
) -> Result<IntentStatus, LogError> {
    match settle_status(tx, idempotency_key, &StatusPrecondition::NonTerminal, status.clone())? {
        StatusWrite::Written => Ok(status),
        StatusWrite::Refused(Some(actual)) => Ok(actual),
        StatusWrite::Refused(None) => Err(LogError(format!(
            "terminalize '{idempotency_key}': row vanished under the write"
        ))),
    }
}

/// Append one fact to an attempt whose current chain is `chain`, and maintain the
/// `attempt_head` projection in the same transaction. The head is maintained transactionally
/// with the append (so it cannot drift) and is re-derivable from the chain, which is why the
/// new head state is a fold of the new chain and never a hand-computed edit of the old one.
///
/// Returns `Some(refusal)`, having written nothing, when the closed grammar refuses.
pub(crate) fn append_fact_with_head(
    tx: &rusqlite::Transaction<'_>,
    chain: &[crate::attempt::Fact],
    fact: &crate::attempt::Fact,
) -> Result<Option<crate::attempt::GrammarRefusal>, LogError> {
    let state = crate::attempt::fold(chain)
        .map_err(|d| LogError(format!("append_fact_with_head fold: {d}")))?;
    if let Err(refusal) = crate::attempt::append_legal(&state, fact) {
        return Ok(Some(refusal));
    }
    tx.execute(
        "INSERT INTO attempt_fact (operation_id, attempt_id, revision, fact_kind,
                                   attempt_ordinal, basis_epoch, created_at, payload,
                                   prior_revision)
         VALUES (?1, ?2, ?3, ?4, NULL, ?5, ?6, ?7, ?8);",
        rusqlite::params![
            fact.operation_id,
            fact.attempt_id,
            fact.revision as i64,
            fact.kind.as_sql(),
            fact.basis_epoch,
            fact.created_at,
            fact_payload_json(&fact.payload),
            fact.prior_revision.map(|r| r as i64),
        ],
    )
    .map_err(|e| LogError(format!("attempt_fact append: {e}")))?;
    let mut grown: Vec<crate::attempt::Fact> = chain.to_vec();
    grown.push(fact.clone());
    let next = crate::attempt::fold(&grown)
        .map_err(|d| LogError(format!("append_fact_with_head re-fold: {d}")))?;
    let class = next.class().ok_or_else(|| {
        LogError("append_fact_with_head: an appended-to attempt has no class".into())
    })?;
    // Check the UPDATE's affected-row count. Ignoring it would let an append onto an attempt
    // whose head row is missing write the fact, update nothing, and commit, leaving an orphan
    // chain the projections do not cover while chain-reading paths keep dispatching it. A zero
    // is a `LogError`, so the caller's `?` drops its transaction uncommitted and the fact
    // never lands either.
    let updated = tx
        .execute(
            "UPDATE attempt_head SET current_revision = ?2, derived_class = ?3,
                                     last_verified_revision = ?2, verified_state = ?4
              WHERE attempt_id = ?1;",
            rusqlite::params![
                fact.attempt_id,
                next.current_revision as i64,
                class.as_sql(),
                verified_state_json(&next),
            ],
        )
        .map_err(|e| LogError(format!("attempt_head update: {e}")))?;
    if updated != 1 {
        return Err(LogError(format!(
            "attempt_head update for '{}' matched {updated} rows — the projection this append \
             must maintain transactionally does not exist",
            fact.attempt_id
        )));
    }
    Ok(None)
}
