//! The boot quarantine: the attempt-head verification and the open-time scan.

use rusqlite::OptionalExtension;

use crate::adjudication::FACT_CLOCK_HIGH_WATER_SQL;
use crate::fact_store::{
    fact_payload_from_json, ordinal_column_divergence, read_attempt_chain, read_attempt_facts,
    verified_state_from_json, verified_state_json,
};
use crate::settle::{append_fact_with_head, terminalize_operation};
use crate::sever::{read_sever_witnesses, verify_sever_witness};
use crate::{IntegrityEvidence, IntentStatus, LogError};

// Boot quarantine: on start, before any dispatch, every non-terminal attempt is classified
// from its facts, with no read-derived attribution.

/// One `attempt_head` row exactly as stored: the raw projection, before it has been checked
/// against anything.
struct StoredAttemptHead {
    attempt_id: String,
    /// The owner the projection names. It is compared with the owner the fold derives from
    /// the `CLAIM` fact, because "whose attempt is this" is read by send authorization,
    /// settlement, late-ack and the sever partition. A projection that answers that question
    /// differently from the chain would be a second authority.
    operation_id: String,
    current_revision: i64,
    derived_class: String,
    last_verified_revision: i64,
    verified_state: String,
}

/// The head/fold owner comparison, shared so the boot check and the in-transaction probe
/// cannot drift. `None` when the chain holds no `CLAIM` (an empty chain, which the
/// revision/class checks already answer).
pub(crate) fn head_owner_divergence(
    projected: &str,
    state: &crate::attempt::DerivedState,
) -> Option<String> {
    let folded = &state.claim.as_ref()?.operation_id;
    (folded != projected).then(|| {
        format!("head says operation '{projected}', the CLAIM fact says '{folded}'")
    })
}

/// Incremental open-time verification of one attempt: replay only the facts appended since
/// `last_verified_revision`, from the persisted baseline, and check the projection against the
/// result.
///
/// A full re-fold of a years-old `ISSUANCE_UNKNOWN` chain would make boot unbounded, so the head
/// persists the verified fold state at a watermark and open replays only the delta from it: two
/// reads per attempt (the anchor row and the delta), never the history. The baseline is trusted,
/// since it was verified in the transaction that wrote it, but it is parsed rather than assumed
/// ([`verified_state_from_json`]) and its own `current_revision` must equal the watermark. Facts
/// after the watermark are re-folded through the pure core, so a stored fact the append path would
/// have refused cannot be laundered into a plausible state.
///
/// A divergence is an `Err`: the head is a projection maintained with the append and re-derivable
/// from the chain, and a projection that is neither is a second authority.
fn verify_attempt_head(
    tx: &rusqlite::Transaction<'_>,
    head: &StoredAttemptHead,
) -> Result<crate::attempt::DerivedState, LogError> {
    let attempt_id = head.attempt_id.as_str();
    let diverges = |what: String| {
        LogError(format!(
            "attempt_head for '{attempt_id}' diverges from its chain: {what}"
        ))
    };
    let watermark = u64::try_from(head.last_verified_revision)
        .map_err(|_| diverges("its verified watermark is negative".into()))?;
    let current = u64::try_from(head.current_revision)
        .map_err(|_| diverges("its current revision is negative".into()))?;
    if watermark > current {
        return Err(diverges(format!(
            "the verified watermark {watermark} is ahead of the current revision {current}"
        )));
    }
    let baseline = verified_state_from_json(&head.verified_state)
        .map_err(|e| diverges(format!("its stored baseline is unreadable — {}", e.0)))?;
    if baseline.current_revision != watermark {
        return Err(diverges(format!(
            "its stored baseline folds to revision {} but is filed at watermark {watermark}",
            baseline.current_revision
        )));
    }
    // The monotonicity anchor for the first delta fact. It comes from the chain, not the
    // snapshot, so the seam is checked against the same authority as the intra-delta
    // comparisons; its absence means the watermark points at a fact that does not exist.
    let anchor: String = if watermark == 0 {
        String::new()
    } else {
        tx.query_row(
            "SELECT created_at FROM attempt_fact WHERE attempt_id = ?1 AND revision = ?2;",
            rusqlite::params![attempt_id, watermark as i64],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| LogError(format!("attempt baseline anchor read: {e}")))?
        .ok_or_else(|| {
            diverges(format!("no fact exists at its verified watermark {watermark}"))
        })?
    };
    let delta = read_attempt_facts(tx, attempt_id, watermark)?;
    let state = crate::attempt::fold_delta(
        &crate::attempt::FoldBaseline {
            state: &baseline,
            revision: watermark,
            created_at: &anchor,
        },
        &delta,
    )
    .map_err(|d| diverges(format!("the {} fact(s) since its baseline do not fold: {d}", delta.len())))?;
    let derived = state.class().map(|c| c.as_sql().to_string());
    if state.current_revision != current || Some(head.derived_class.clone()) != derived {
        return Err(diverges(format!(
            "head says revision {current}/class '{}', the fold says revision {}/class {:?}",
            head.derived_class, state.current_revision, derived
        )));
    }
    if let Some(what) = head_owner_divergence(&head.operation_id, &state) {
        return Err(diverges(what));
    }
    Ok(state)
}

/// The boot quarantine's head scan: the rows open actually has work for.
///
/// Scanning every `attempt_head` row on every open would parse, re-fold and `UPDATE` each one,
/// but `append_fact_with_head` writes `last_verified_revision = current_revision` in the same
/// transaction as the append, so in a healthy store the delta is always empty and the `UPDATE`
/// would rewrite the bytes it just read: N durable writes on every reopen.
///
/// A head is loaded when either holds:
///
/// - `last_verified_revision <> current_revision`: an unverified delta exists. It is `<>`, not
///   `<`, on purpose: a watermark ahead of the current revision is durable damage that
///   [`verify_attempt_head`] refuses by name.
/// - the class is not terminally attributed (`pre_issuance`, `issued_or_unknown` or
///   `adjudicated_unresolved`), which is the quarantine's actual job. The list is derived from
///   [`crate::attempt::AttemptClass::is_terminally_attributed`] so the SQL cannot drift from the
///   enum, and an unrecognized spelling is not in the list, so it is loaded and
///   [`verify_attempt_head`] fails over it.
///
/// The skipped set is the verified chains with one of the four terminal attributions;
/// `append_legal` forbids further appends to them, so nothing can give them a delta.
///
/// Residual: a skipped head corrupted at rest by something outside this engine is caught when a
/// live path reads it ([`fold_stored_attempt`]'s head-equals-fold probe), not at boot. Open
/// verification is O(delta) so it does not re-read a verified prefix. The orphan anti-join and
/// the ordinal-column probe keep their own full pass.
fn boot_head_scan_sql() -> String {
    let settled = crate::attempt::AttemptClass::ALL
        .iter()
        .filter(|class| class.is_terminally_attributed())
        .map(|class| format!("'{}'", class.as_sql()))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "SELECT attempt_id, operation_id, current_revision, derived_class,
                last_verified_revision, verified_state
           FROM attempt_head
          WHERE last_verified_revision <> current_revision
             OR derived_class NOT IN ({settled})
          ORDER BY attempt_id;"
    )
}

/// The boot quarantine: the open-time check that runs before any dispatch can exist. On start,
/// every non-terminal attempt is classified from its facts, with no read-derived attribution.
/// In one transaction:
///
/// 1. **Every `attempt_head` is verified incrementally** ([`verify_attempt_head`]) and its
///    baseline advanced, so the next boot's delta is empty. A divergence returns, and the caller
///    turns it into an open refusal.
/// 2. **Every live attempt is classified from its facts.** A claimed-but-never-authorized attempt
///    whose claim epoch is no longer current can never be authorized again, so it terminalizes
///    `SEVERED_BEFORE_ISSUANCE` here (fact, head and operation lifecycle together). An authorized
///    attempt without a verdict is `ISSUED_OR_UNKNOWN` and is left alone: non-issuance cannot be
///    proven, so it is never re-authorized, re-dispatched or settled. A current-epoch claim is
///    untouched.
/// 3. **Every stored sever witness is reconciled** ([`verify_sever_witness`]), and a failure
///    becomes evidence. The witness is audit substrate, not a dispatch gate.
///
/// The stale-epoch arm is not dead code: `IntentLog::sever` closes its own claimed-unauthorized
/// members, but not an operation whose lifecycle is already terminal (absent from the witness)
/// nor a store whose epoch moved without this engine's closure running.
///
/// It takes the `GatedConnection` itself from its one caller, `SqliteIntentLog::open`, so the
/// transaction is enrolled for the file it is writing and a caller cannot pass a gate for a
/// different file.
pub(crate) fn boot_quarantine(
    conn: &mut crate::store_open::GatedConnection,
) -> Result<Vec<IntegrityEvidence>, LogError> {
    use crate::attempt::{AttemptClass, Fact, FactKind, FactPayload};
    let mut evidence: Vec<IntegrityEvidence> = Vec::new();
    conn.with_immediate_tx(|tx| {
        let epoch: i64 = tx
            .query_row("SELECT epoch FROM control_epoch WHERE id = 1;", [], |r| {
                r.get(0)
            })
            .map_err(|e| LogError(format!("boot quarantine epoch read: {e}")))?;
        // Orphan-chain probe. The loop below verifies each head against its chain, but only in
        // that direction: a chain whose `attempt_head` row is gone is invisible to it, so it
        // would open unclassified, while `unknown_review` (which scans heads) could not see it
        // and `live_attempt` / the sever partition (which fold the chain) could. That is two
        // authorities disagreeing about one attempt, the head/fold divergence case, so it
        // refuses the open. One anti-join over the `attempt_fact` index prefix, not per attempt.
        let orphan: Option<String> = tx
            .query_row(
                "SELECT f.attempt_id FROM attempt_fact f
              WHERE NOT EXISTS (SELECT 1 FROM attempt_head h WHERE h.attempt_id = f.attempt_id)
              ORDER BY f.attempt_id LIMIT 1;",
                [],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| LogError(format!("boot quarantine orphan probe: {e}")))?;
        if let Some(attempt_id) = orphan {
            return Err(LogError(format!(
                "attempt '{attempt_id}' has facts but no attempt_head row: its chain is an ORPHAN, \
             so the head projection and the fold do not cover the same attempts"
            )));
        }
        // Ordinal-column probe. `read_attempt_facts` checks the `attempt_ordinal` column
        // against the `CLAIM` payload's own ordinal on every chain read, but open-time
        // verification is O(delta) and does not re-read the prefix, so a corrupted ordinal
        // behind the watermark would never be read at boot. This closes that gap with one pass
        // over the rows that can carry an ordinal (every `claim`, plus any row whose column is
        // non-NULL, which in a healthy store is the same set). It never re-folds history and
        // never decodes the payload in SQL: the crate's own parser and comparison rule decide.
        {
            let mut stmt = tx
                .prepare(
                    "SELECT attempt_id, revision, fact_kind, attempt_ordinal, payload
                   FROM attempt_fact
                  WHERE fact_kind = 'claim' OR attempt_ordinal IS NOT NULL
                  ORDER BY attempt_id, revision;",
                )
                .map_err(|e| LogError(format!("boot quarantine ordinal probe: {e}")))?;
            let rows = stmt
                .query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, Option<i64>>(3)?,
                        r.get::<_, String>(4)?,
                    ))
                })
                .map_err(|e| LogError(format!("boot quarantine ordinal probe: {e}")))?;
            for row in rows {
                let (attempt_id, revision, kind, ordinal, payload) =
                    row.map_err(|e| LogError(format!("boot quarantine ordinal probe: {e}")))?;
                let kind = crate::attempt::FactKind::from_sql(&kind).ok_or_else(|| {
                    LogError(format!(
                        "attempt '{attempt_id}' carries fact kind '{kind}', which is not in the grammar"
                    ))
                })?;
                let payload = fact_payload_from_json(kind, &payload)?;
                if let Some(what) = ordinal_column_divergence(kind, &payload, ordinal) {
                    return Err(LogError(format!(
                        "attempt '{attempt_id}' revision {revision}: {what}"
                    )));
                }
            }
        }
        let mut heads: Vec<StoredAttemptHead> = Vec::new();
        {
            let mut stmt = tx
                .prepare(&boot_head_scan_sql())
                .map_err(|e| LogError(format!("boot quarantine head read: {e}")))?;
            let rows = stmt
                .query_map([], |r| {
                    Ok(StoredAttemptHead {
                        attempt_id: r.get(0)?,
                        operation_id: r.get(1)?,
                        current_revision: r.get(2)?,
                        derived_class: r.get(3)?,
                        last_verified_revision: r.get(4)?,
                        verified_state: r.get(5)?,
                    })
                })
                .map_err(|e| LogError(format!("boot quarantine head read: {e}")))?;
            for row in rows {
                heads.push(row.map_err(|e| LogError(format!("boot quarantine head read: {e}")))?);
            }
        }
        // The sever instant every closure this boot writes shares, through the same clamp every
        // fact uses, so a closure fact can never sort before the chain it closes.
        let now: String = tx
            .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%SZ','now');", [], |r| {
                r.get(0)
            })
            .map_err(|e| LogError(format!("boot quarantine clock read: {e}")))?;
        let max_persisted: String = tx
            .query_row(FACT_CLOCK_HIGH_WATER_SQL, [], |r| r.get(0))
            .map_err(|e| LogError(format!("boot quarantine clock high-water read: {e}")))?;
        let closed_at = crate::attempt::clamped_now(&now, &max_persisted)
            .map_err(|e| LogError(format!("boot quarantine clock: {e}")))?
            .value;
        for head in &heads {
            let state = verify_attempt_head(tx, head)?;
            // Advance the baseline: what this boot verified, the next boot does not
            // re-verify. The head's projected values were just proven equal to the fold, so
            // only the watermark and the snapshot move. Write only when they actually move:
            // `append_fact_with_head` advances the watermark in the same transaction as the
            // append, so for a healthy head the delta is empty and the statement would spend
            // a durable write and a WAL frame storing back the bytes it just read.
            if state.current_revision as i64 != head.last_verified_revision {
                tx.execute(
                    "UPDATE attempt_head SET last_verified_revision = ?2, verified_state = ?3
                  WHERE attempt_id = ?1;",
                    rusqlite::params![
                        head.attempt_id,
                        state.current_revision as i64,
                        verified_state_json(&state),
                    ],
                )
                .map_err(|e| LogError(format!("boot quarantine baseline advance: {e}")))?;
            }
            // Classify from the facts this fold just verified.
            let Some(claim) = state.claim.as_ref() else {
                continue;
            };
            match state.class() {
                // Claimed, never authorized, under an epoch that is gone. No authorization can
                // follow (send authorization refuses a claim-epoch mismatch), so leaving it
                // live would strand the operation and its resource tail forever.
                Some(AttemptClass::PreIssuance) if claim.claim_epoch != epoch => {
                    let chain = read_attempt_chain(tx, &head.attempt_id)?;
                    let fact = Fact {
                        operation_id: claim.operation_id.clone(),
                        attempt_id: head.attempt_id.clone(),
                        revision: state.current_revision + 1,
                        kind: FactKind::SeveredBeforeIssuance,
                        basis_epoch: epoch,
                        created_at: closed_at.clone(),
                        payload: FactPayload::None,
                        prior_revision: Some(state.current_revision),
                    };
                    // The grammar cannot refuse this: `SEVERED_BEFORE_ISSUANCE` is legal exactly on
                    // a claimed-unauthorized chain, which the class above proved this is, from
                    // the fold, in this transaction. A refusal means the fold and the grammar
                    // disagree; fail explicitly rather than open a half-classified store.
                    if let Some(refusal) = append_fact_with_head(tx, &chain, &fact)? {
                        return Err(LogError(format!(
                            "boot quarantine: the closure of attempt '{}' was refused by the \
                         grammar: {refusal}",
                            head.attempt_id
                        )));
                    }
                    // The operation's lifecycle, in the same transaction. The write is guarded by
                    // the non-terminal domain, so an operation that is already terminal (the
                    // sever's own blind spot) keeps its terminal: boot closes the attempt and
                    // never rewrites a settled lifecycle.
                    let key: Option<String> = tx
                        .query_row(
                            "SELECT idempotency_key FROM intents WHERE intent_id = ?1;",
                            rusqlite::params![claim.operation_id],
                            |r| r.get(0),
                        )
                        .optional()
                        .map_err(|e| LogError(format!("boot quarantine owner read: {e}")))?;
                    let key = key.ok_or_else(|| {
                        LogError(format!(
                            "boot quarantine: attempt '{}' names operation '{}', which no intent \
                         row owns",
                            head.attempt_id, claim.operation_id
                        ))
                    })?;
                    terminalize_operation(tx, &key, IntentStatus::Severed)?;
                    evidence.push(IntegrityEvidence::AttemptSeveredAtBoot {
                        attempt_id: head.attempt_id.clone(),
                        claim_epoch: claim.claim_epoch,
                    });
                }
                // `ISSUED_OR_UNKNOWN`, and everything else, is left as it is. Non-issuance
                // cannot be proven for an authorized attempt, so boot writes nothing: no
                // re-authorization, no re-dispatch, no settlement. Adjudication, which is a
                // human decision, is the only way out.
                _ => {}
            }
        }
        // Sever-witness roster: reconciled, never a gate.
        for raw in read_sever_witnesses(tx)? {
            if let Err(reason) = verify_sever_witness(&raw) {
                evidence.push(IntegrityEvidence::SeverWitnessUnreconciled {
                    witness_id: raw.witness_id.clone(),
                    reason: reason.0,
                });
            }
        }
        // Surface the capacity posture. Nothing evicts an obligation silently, so growth is
        // made visible: an operator who sees dispatches refusing must be able to see, at open
        // and without querying the store by hand, how many unresolved exposures are causing
        // it. The check's own cost does not depend on this number (a keyed join per touched
        // atom).
        let (unretired, total): (i64, i64) = tx
            .query_row(
                "SELECT COUNT(*) FILTER (WHERE retired_at IS NULL), COUNT(*)
               FROM exposure_obligation;",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|e| LogError(format!("exposure obligation census: {e}")))?;
        if unretired > 0 {
            evidence.push(IntegrityEvidence::UnresolvedExposureOutstanding { unretired, total });
        }
        Ok(())
    })?;
    Ok(evidence)
}
