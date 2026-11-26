//! The attempt-fact store half: the payload codec, the verified-state snapshot, and the stored-chain fold.

use rusqlite::OptionalExtension;

use crate::boot::head_owner_divergence;
use crate::LogError;

// The grammar lives in `attempt.rs` and nowhere else; everything here is persistence: turning
// rows into the values that module already knows how to judge.

/// Encode a fact payload as the `attempt_fact.payload` JSON object. Total over the kinds
/// (`FactPayload` is closed), so a future writer of any kind has its shape here already and
/// cannot invent a second spelling. `None` payloads are `{}`, never SQL NULL: the column is
/// NOT NULL and "carries nothing the grammar reads" is a shape, not an absence.
pub(crate) fn fact_payload_json(payload: &crate::attempt::FactPayload) -> String {
    use crate::attempt::{FactPayload, WireEvidence};
    let v = match payload {
        FactPayload::Claim {
            ordinal,
            predecessor,
        } => match predecessor {
            None => serde_json::json!({ "ordinal": ordinal }),
            Some(p) => serde_json::json!({
                "ordinal": ordinal,
                "predecessor_attempt_id": p.attempt_id,
                "retry_reason": retry_reason_str(p.reason),
            }),
        },
        // The exposure key is a structure, not a token: the touched atoms and their effect
        // directions themselves are in the payload (the adjudication record derives its own
        // `exposure_key` from this, and the obligation rows are one per atom). `serde` is the
        // codec on both sides so the two spellings cannot drift.
        FactPayload::SendAuthorized { exposure_key } => {
            serde_json::json!({ "exposure_key": exposure_key })
        }
        FactPayload::FailedPreSend {
            wire_evidence,
            reason,
            exposure_block,
            plan_refusal,
        } => serde_json::json!({
            "wire_evidence": match wire_evidence {
                WireEvidence::ProvenNoWire => "proven_no_wire",
                WireEvidence::Indeterminate => "indeterminate",
            },
            "reason": reason.as_token(),
            // `null` when there is no exposure block. The decoder reads missing and `null`
            // alike as `None`, so an earlier row (the key absent entirely) and a later
            // non-exposure row are the same value, with no repair rule and no second spelling
            // of "no atom".
            //
            // Two keys, one value: the block is a [`crate::attempt::ExposureBlock`] (the
            // internal atom and the surfaceable obligation reference), written together by one
            // writer in one transaction. The decoder refuses a half block for that reason.
            "blocked_atom": exposure_block.as_ref().map(|b| &b.atom_key),
            "blocked_obligation": exposure_block.as_ref().map(|b| &b.obligation_id),
            // The typed plan-admission refusal, beside the exposure block and on the same
            // terms: `null` when there is none, and the decoder reads missing and `null` alike
            // as `None`, so a row written before this key existed and a row with no plan
            // refusal are the same value. `serde` spells the record on both sides.
            "plan_refusal": plan_refusal,
        }),
        FactPayload::Reconcile { observation } => serde_json::json!({ "observation": observation }),
        FactPayload::Adjudicated { adjudication_id } => {
            serde_json::json!({ "adjudication_id": adjudication_id })
        }
        FactPayload::SupersededBy {
            successor_operation_id,
        } => serde_json::json!({ "successor_operation_id": successor_operation_id }),
        FactPayload::None => serde_json::json!({}),
    };
    v.to_string()
}

/// The durable spelling of a retry reason: the CLAIM payload's `retry_reason` token.
fn retry_reason_str(reason: crate::attempt::RetryReason) -> &'static str {
    match reason {
        crate::attempt::RetryReason::FailedPreSend => "failed_pre_send",
        crate::attempt::RetryReason::AckRefusedNoEffect => "ack_refused_no_effect",
    }
}

/// The inverse of [`fact_payload_json`], driven by the row's own kind: the grammar never sees
/// a payload whose shape disagrees with its kind, because this is where the two are married.
/// Anything unreadable is a `LogError`: a payload the writer cannot have produced means the
/// ledger is not trustworthy, and nothing here repairs it.
pub(crate) fn fact_payload_from_json(
    kind: crate::attempt::FactKind,
    raw: &str,
) -> Result<crate::attempt::FactPayload, LogError> {
    use crate::attempt::{FactKind, FactPayload, RetryPredecessor, RetryReason, WireEvidence};
    let v: serde_json::Value = serde_json::from_str(raw)
        .map_err(|e| LogError(format!("attempt_fact payload is not JSON: {e}")))?;
    let text = |field: &str| -> Result<String, LogError> {
        v.get(field)
            .and_then(|x| x.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| LogError(format!("attempt_fact payload is missing '{field}'")))
    };
    Ok(match kind {
        FactKind::Claim => {
            let ordinal = v
                .get("ordinal")
                .and_then(|x| x.as_u64())
                .ok_or_else(|| LogError("attempt_fact claim payload has no ordinal".into()))?;
            let predecessor = match v.get("predecessor_attempt_id") {
                None => None,
                Some(_) => Some(RetryPredecessor {
                    attempt_id: text("predecessor_attempt_id")?,
                    reason: match text("retry_reason")?.as_str() {
                        "failed_pre_send" => RetryReason::FailedPreSend,
                        "ack_refused_no_effect" => RetryReason::AckRefusedNoEffect,
                        other => {
                            return Err(LogError(format!(
                                "attempt_fact claim payload has unknown retry_reason '{other}'"
                            )))
                        }
                    },
                }),
            };
            FactPayload::Claim {
                ordinal,
                predecessor,
            }
        }
        FactKind::SendAuthorized => FactPayload::SendAuthorized {
            exposure_key: serde_json::from_value(
                v.get("exposure_key")
                    .cloned()
                    .ok_or_else(|| LogError("attempt_fact payload is missing 'exposure_key'".into()))?,
            )
            .map_err(|e| LogError(format!("attempt_fact exposure_key is not one: {e}")))?,
        },
        FactKind::FailedPreSend => FactPayload::FailedPreSend {
            wire_evidence: match text("wire_evidence")?.as_str() {
                "proven_no_wire" => WireEvidence::ProvenNoWire,
                "indeterminate" => WireEvidence::Indeterminate,
                other => {
                    return Err(LogError(format!(
                        "attempt_fact payload has unknown wire_evidence '{other}'"
                    )))
                }
            },
            // The closed reason vocabulary, read through its own parser. Every
            // `FAILED_PRE_SEND` this build appends carries one, so a missing one is a payload
            // this writer cannot have produced: fail, never default it quietly to `Failure` and
            // lose the `EXTERNALLY_SATISFIED` distinction the operation's terminal rests on.
            reason: crate::attempt::PreSendReason::from_token(&text("reason")?).ok_or_else(
                || LogError("attempt_fact payload has an unknown failed_pre_send reason".into()),
            )?,
            // Optional by design, unlike `reason` above: exactly one writer sets it (the
            // exposure check), so absent or `null` is the ordinary case and means "no exposure
            // block". An empty string is not a legal atom key (`exposure_atom_key` is
            // length-prefixed and never empty) nor a legal obligation id (`mint_opaque_id`),
            // so either is refused rather than read as a nameless block.
            //
            // All or nothing: the two keys are written by one writer in one transaction, so a
            // row holding exactly one of them is a row this build cannot have produced. Fail
            // rather than surface a block with no reference to resolve.
            exposure_block: match (v.get("blocked_atom"), v.get("blocked_obligation")) {
                (None | Some(serde_json::Value::Null), None | Some(serde_json::Value::Null)) => {
                    None
                }
                (
                    Some(serde_json::Value::String(atom)),
                    Some(serde_json::Value::String(obligation)),
                ) if !atom.is_empty() && !obligation.is_empty() => {
                    Some(crate::attempt::ExposureBlock {
                        atom_key: atom.to_string(),
                        obligation_id: obligation.to_string(),
                    })
                }
                _ => {
                    return Err(LogError(
                        "attempt_fact payload has a malformed failed_pre_send exposure block"
                            .into(),
                    ))
                }
            },
            // Optional like `exposure_block`: absent or `null` means "no plan refusal". A
            // present value must be a record this writer can have produced: it parses as a
            // `PlanRefusalRecord` (unknown keys refused via `deny_unknown_fields`) and names
            // both its refusal and its member; anything else fails. The error names the shape,
            // never the bytes (the no-content rule `json_shape` keeps).
            plan_refusal: match v.get("plan_refusal") {
                None | Some(serde_json::Value::Null) => None,
                Some(raw) => {
                    let malformed = || {
                        LogError(format!(
                            "attempt_fact payload has a malformed failed_pre_send plan_refusal ({})",
                            json_shape(raw)
                        ))
                    };
                    let rec: crate::attempt::PlanRefusalRecord =
                        serde_json::from_value(raw.clone()).map_err(|_| malformed())?;
                    if rec.reason.is_empty() || rec.member_ref.is_empty() {
                        return Err(malformed());
                    }
                    Some(rec)
                }
            },
        },
        FactKind::ReconcileStateMatches | FactKind::ReconcileStateDiffers => {
            FactPayload::Reconcile {
                observation: text("observation")?,
            }
        }
        FactKind::AdjudicatedUnresolved => FactPayload::Adjudicated {
            adjudication_id: text("adjudication_id")?,
        },
        FactKind::SupersededBy => FactPayload::SupersededBy {
            successor_operation_id: text("successor_operation_id")?,
        },
        // The payload-free kinds are checked rather than assumed. [`fact_payload_json`] emits
        // exactly `{}` for every kind below, and no branch of this build writes anything else
        // onto one of them. Ignoring `v` here would decode a scalar, an array, or an object
        // carrying durable bytes all to `FactPayload::None`, silently discarding a row the
        // writer cannot have produced instead of raising it, against this function's contract.
        // The refusal names the shape, never the bytes: a ledger defect message is not a place
        // to surface a payload that may hold what the store deliberately does not persist
        // elsewhere.
        FactKind::AckApplied
        | FactKind::AckRefusedNoEffect
        | FactKind::AckAmbiguous
        | FactKind::SeveredBeforeIssuance
        | FactKind::LateAckApplied
        | FactKind::LateAckRefusedNoEffect => match v.as_object() {
            Some(members) if members.is_empty() => FactPayload::None,
            _ => {
                return Err(LogError(format!(
                    "attempt_fact payload for '{}' must be the empty object this writer emits, \
                     got {}",
                    kind.as_sql(),
                    json_shape(&v)
                )))
            }
        },
    })
}

/// A JSON value's shape, with no value bytes in it: what a ledger error message may say about
/// a payload it refuses (the no-content rule applies to diagnostics too).
fn json_shape(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Null => "null".to_string(),
        serde_json::Value::Bool(_) => "a boolean".to_string(),
        serde_json::Value::Number(_) => "a number".to_string(),
        serde_json::Value::String(_) => "a string".to_string(),
        serde_json::Value::Array(items) => format!("an array of {}", items.len()),
        serde_json::Value::Object(members) => format!("an object of {} member(s)", members.len()),
    }
}

/// The historical-axis token vocabulary.
fn historical_token(axis: crate::attempt::HistoricalAttribution) -> &'static str {
    use crate::attempt::HistoricalAttribution;
    match axis {
        HistoricalAttribution::Unknown => "unknown",
        HistoricalAttribution::Applied => "applied",
        HistoricalAttribution::RefusedNoEffect => "refused_no_effect",
        HistoricalAttribution::FailedPreSend => "failed_pre_send",
        HistoricalAttribution::SeveredBeforeIssuance => "severed_before_issuance",
    }
}

/// The operational-axis token vocabulary.
fn operational_token(axis: crate::attempt::OperationalAxis) -> &'static str {
    use crate::attempt::OperationalAxis;
    match axis {
        OperationalAxis::Active => "active",
        OperationalAxis::Closed => "closed",
    }
}

/// The `attempt_head.verified_state` snapshot: the fold's own value, spelled canonically so
/// the projection can be compared to a re-derivation rather than trusted. Deterministic
/// (fixed key order, no maps), which is what makes the comparison meaningful.
///
/// **It must be lossless.** This snapshot is the baseline the open-time O(delta) re-fold
/// starts from, so anything it drops is a rule the delta is then judged without: a missing
/// `last_reconcile` would silently defeat the changed-only rule at the seam, and a missing
/// lineage would defeat owner/ordinal totality. [`verified_state_from_json`] is its exact
/// inverse, and a round-trip test pins that.
pub(crate) fn verified_state_json(state: &crate::attempt::DerivedState) -> String {
    serde_json::json!({
        "operation_id": state.claim.as_ref().map(|c| c.operation_id.clone()),
        "attempt_id": state.claim.as_ref().map(|c| c.attempt_id.clone()),
        "ordinal": state.claim.as_ref().map(|c| c.ordinal),
        "claim_epoch": state.claim.as_ref().map(|c| c.claim_epoch),
        "predecessor": state
            .claim
            .as_ref()
            .and_then(|c| c.predecessor.as_ref())
            .map(|p| serde_json::json!({
                "attempt_id": p.attempt_id,
                "reason": retry_reason_str(p.reason),
            })),
        "current_revision": state.current_revision,
        "send_authorized": state.send_authorized,
        "exposure_key": state.exposure_key,
        "terminal_attribution": state.terminal_attribution.map(|k| k.as_sql()),
        "historical": historical_token(state.historical),
        "operational": operational_token(state.operational),
        "ambiguous_recorded": state.ambiguous_recorded,
        "reconcile_count": state.reconcile_count,
        "last_reconcile": state.last_reconcile.as_ref().map(|(kind, observation)| {
            serde_json::json!({ "kind": kind.as_sql(), "observation": observation })
        }),
        // The cadence baseline, carried for the same reason as `last_reconcile`: a baseline
        // that drops it would let the seam silently accept the back-to-back append the bound
        // exists to refuse.
        "last_reconcile_at": state.last_reconcile_at,
        "adjudication_id": state.adjudication_id,
        "late_ack": state.late_ack.map(|k| k.as_sql()),
        "superseded_by": state.superseded_by,
    })
    .to_string()
}

/// The exact inverse of [`verified_state_json`], strict on the read side like
/// `FrozenBasis::from_json` and `undo_context`: a persisted snapshot this build could not have
/// written is a `LogError`, never a defaulted field. The baseline of an incremental
/// verification is trusted, so the only safe way to trust it is to refuse one that is not
/// well-formed.
pub(crate) fn verified_state_from_json(raw: &str) -> Result<crate::attempt::DerivedState, LogError> {
    use crate::attempt::{
        ClaimIdentity, DerivedState, FactKind, HistoricalAttribution, OperationalAxis,
        RetryPredecessor, RetryReason,
    };
    let bad = |what: &str| LogError(format!("attempt_head.verified_state {what}"));
    let v: serde_json::Value =
        serde_json::from_str(raw).map_err(|e| bad(&format!("is not JSON: {e}")))?;
    let field = |name: &str| -> Result<&serde_json::Value, LogError> {
        v.get(name)
            .ok_or_else(|| bad(&format!("has no '{name}' — it was not written by this build")))
    };
    let text = |name: &str| -> Result<Option<String>, LogError> {
        match field(name)? {
            serde_json::Value::Null => Ok(None),
            serde_json::Value::String(s) => Ok(Some(s.clone())),
            _ => Err(bad(&format!("'{name}' is not text"))),
        }
    };
    let u64_of = |name: &str| -> Result<Option<u64>, LogError> {
        match field(name)? {
            serde_json::Value::Null => Ok(None),
            other => other
                .as_u64()
                .map(Some)
                .ok_or_else(|| bad(&format!("'{name}' is not a non-negative integer"))),
        }
    };
    let bool_of = |name: &str| -> Result<bool, LogError> {
        field(name)?
            .as_bool()
            .ok_or_else(|| bad(&format!("'{name}' is not a Boolean")))
    };
    let kind_of = |name: &str| -> Result<Option<FactKind>, LogError> {
        match text(name)? {
            None => Ok(None),
            Some(token) => FactKind::from_sql(&token)
                .map(Some)
                .ok_or_else(|| bad(&format!("'{name}' spells a fact kind outside the grammar"))),
        }
    };
    // The claim identity is present as a whole or absent as a whole (the fold's empty state
    // has no claim). A half-present claim is a snapshot no fold produced.
    let claim = match (
        text("operation_id")?,
        text("attempt_id")?,
        u64_of("ordinal")?,
        u64_of("claim_epoch")?,
    ) {
        (None, None, None, None) => None,
        (Some(operation_id), Some(attempt_id), Some(ordinal), Some(claim_epoch)) => {
            let predecessor = match field("predecessor")? {
                serde_json::Value::Null => None,
                link => {
                    let attempt_id = link
                        .get("attempt_id")
                        .and_then(|x| x.as_str())
                        .ok_or_else(|| bad("'predecessor' has no attempt id"))?
                        .to_string();
                    let reason = match link.get("reason").and_then(|x| x.as_str()) {
                        Some("failed_pre_send") => RetryReason::FailedPreSend,
                        Some("ack_refused_no_effect") => RetryReason::AckRefusedNoEffect,
                        _ => {
                            return Err(bad(
                                "'predecessor' carries a reason outside the closed retry \
                                 vocabulary",
                            ))
                        }
                    };
                    Some(RetryPredecessor { attempt_id, reason })
                }
            };
            Some(ClaimIdentity {
                operation_id,
                attempt_id,
                ordinal,
                predecessor,
                claim_epoch: i64::try_from(claim_epoch)
                    .map_err(|_| bad("'claim_epoch' does not fit the epoch column"))?,
            })
        }
        _ => return Err(bad("carries a PARTIAL claim identity")),
    };
    let historical = match text("historical")?.as_deref() {
        Some("unknown") => HistoricalAttribution::Unknown,
        Some("applied") => HistoricalAttribution::Applied,
        Some("refused_no_effect") => HistoricalAttribution::RefusedNoEffect,
        Some("failed_pre_send") => HistoricalAttribution::FailedPreSend,
        Some("severed_before_issuance") => HistoricalAttribution::SeveredBeforeIssuance,
        _ => return Err(bad("'historical' is not one of the five attributions")),
    };
    let operational = match text("operational")?.as_deref() {
        Some("active") => OperationalAxis::Active,
        Some("closed") => OperationalAxis::Closed,
        _ => return Err(bad("'operational' is neither active nor closed")),
    };
    let last_reconcile = match field("last_reconcile")? {
        serde_json::Value::Null => None,
        entry => {
            let kind = entry
                .get("kind")
                .and_then(|x| x.as_str())
                .and_then(FactKind::from_sql)
                .ok_or_else(|| bad("'last_reconcile' spells a kind outside the grammar"))?;
            let observation = entry
                .get("observation")
                .and_then(|x| x.as_str())
                .ok_or_else(|| bad("'last_reconcile' has no observation"))?
                .to_string();
            Some((kind, observation))
        }
    };
    // The cadence baseline, checked by the canonical-instant parser on the way in from storage:
    // a persisted instant that cannot be ordered must never reach the grammar's lexicographic
    // compare, where it would read as "long enough ago".
    let last_reconcile_at = match text("last_reconcile_at")? {
        None => None,
        Some(at) if crate::prestate::is_canonical_rfc3339_utc(&at) => Some(at),
        Some(_) => return Err(bad("'last_reconcile_at' is not a canonical RFC-3339 UTC instant")),
    };
    let exposure_key = match field("exposure_key")? {
        serde_json::Value::Null => None,
        raw => Some(
            serde_json::from_value(raw.clone())
                .map_err(|e| bad(&format!("'exposure_key' does not parse: {e}")))?,
        ),
    };
    Ok(DerivedState {
        claim,
        current_revision: u64_of("current_revision")?
            .ok_or_else(|| bad("has no 'current_revision'"))?,
        send_authorized: bool_of("send_authorized")?,
        exposure_key,
        terminal_attribution: kind_of("terminal_attribution")?,
        historical,
        operational,
        ambiguous_recorded: bool_of("ambiguous_recorded")?,
        reconcile_count: u32::try_from(
            u64_of("reconcile_count")?.ok_or_else(|| bad("has no 'reconcile_count'"))?,
        )
        .map_err(|_| bad("'reconcile_count' does not fit the cap counter"))?,
        last_reconcile,
        last_reconcile_at,
        adjudication_id: text("adjudication_id")?,
        late_ack: kind_of("late_ack")?,
        superseded_by: text("superseded_by")?,
    })
}

/// Read one stored attempt's fact chain, in revision order, as the pure core's values.
/// Payload shape is matched to the row's own kind here ([`fact_payload_from_json`]), so the
/// grammar never sees a payload whose shape disagrees with its kind.
pub(crate) fn read_attempt_chain(
    tx: &rusqlite::Transaction<'_>,
    attempt_id: &str,
) -> Result<Vec<crate::attempt::Fact>, LogError> {
    read_attempt_facts(tx, attempt_id, 0)
}

/// The `attempt_ordinal` column-versus-payload rule: the column equals the `CLAIM` payload's
/// ordinal on a claim fact and is NULL on every other kind. `Some(what)` describes a divergence;
/// `None` means the two agree.
///
/// `UNIQUE (operation_id, attempt_ordinal)` referees the retry lineage on the column, while the
/// same ordinal also lives in the `CLAIM` payload, so something must compare them. A `CLAIM` row
/// whose column disagreed would enroll the attempt in the referee's uniqueness under an ordinal
/// the grammar never saw; a non-`CLAIM` row with a non-NULL column would enroll a second row of
/// the same attempt (UNIQUE treats each NULL as distinct, which is what keeps only the one CLAIM
/// in that index). That is the projection-versus-fold divergence class, which fails: at open the
/// open is refused, at a live path the read errors. The two writers keep them equal
/// (`claim_attempt` binds the payload's ordinal, `append_fact_with_head` binds `NULL`), so a
/// difference is state no code of this build wrote.
///
/// **An unrepresentable ordinal is divergence, not agreement.** `None` means "agree", so a
/// conversion like `i64::try_from(*ordinal).ok()?` would report no divergence for a payload
/// ordinal above `i64::MAX`, and the check built to fail closed would fail open. The column is an
/// `i64`, so no value it holds equals such an ordinal.
pub(crate) fn ordinal_column_divergence(
    kind: crate::attempt::FactKind,
    payload: &crate::attempt::FactPayload,
    stored: Option<i64>,
) -> Option<String> {
    let expected: Option<i64> = match payload {
        crate::attempt::FactPayload::Claim { ordinal, .. } => match i64::try_from(*ordinal) {
            Ok(ordinal) => Some(ordinal),
            Err(_) => {
                return Some(format!(
                    "the fact kind '{}' carries attempt_ordinal {stored:?} in SQL but {ordinal} \
                     in its payload — a value no INTEGER column can hold, so the retry-lineage \
                     referee's column and the grammar's own value can never agree",
                    kind.as_sql()
                ))
            }
        },
        _ => None,
    };
    (stored != expected).then(|| {
        format!(
            "the fact kind '{}' carries attempt_ordinal {stored:?} in SQL but {expected:?} in \
             its payload — the retry-lineage referee's column and the grammar's own value \
             disagree",
            kind.as_sql()
        )
    })
}

/// [`read_attempt_chain`] restricted to the facts appended after `after_revision`. The
/// O(delta) open-time verification reads exactly this, and nothing else, per attempt.
/// `after_revision = 0` is the whole chain.
///
/// Every row read here has its `attempt_ordinal` column checked against its payload
/// ([`ordinal_column_divergence`]).
pub(crate) fn read_attempt_facts(
    tx: &rusqlite::Transaction<'_>,
    attempt_id: &str,
    after_revision: u64,
) -> Result<Vec<crate::attempt::Fact>, LogError> {
    let mut stmt = tx
        .prepare(
            "SELECT operation_id, revision, fact_kind, basis_epoch, created_at, payload,
                    prior_revision, attempt_ordinal
               FROM attempt_fact WHERE attempt_id = ?1 AND revision > ?2 ORDER BY revision;",
        )
        .map_err(|e| LogError(format!("attempt chain read: {e}")))?;
    let rows = stmt
        .query_map(rusqlite::params![attempt_id, after_revision as i64], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, Option<i64>>(6)?,
                r.get::<_, Option<i64>>(7)?,
            ))
        })
        .map_err(|e| LogError(format!("attempt chain read: {e}")))?;
    let mut chain: Vec<crate::attempt::Fact> = Vec::new();
    for row in rows {
        let (operation_id, revision, kind, basis_epoch, created_at, payload, prior, ordinal) =
            row.map_err(|e| LogError(format!("attempt chain read: {e}")))?;
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
        chain.push(crate::attempt::Fact {
            operation_id,
            attempt_id: attempt_id.to_string(),
            revision: revision as u64,
            kind,
            basis_epoch,
            created_at,
            payload,
            prior_revision: prior.map(|p| p as u64),
        });
    }
    Ok(chain)
}

/// Fold one stored attempt's chain: read the rows, turn them into the pure core's values, and
/// let [`crate::attempt::fold`] be the authority.
///
/// The `attempt_head` row is cross-checked against the fold here, not trusted: the projection
/// is maintained transactionally with the append and re-derivable from the chain, and a
/// projection that cannot be checked is a second authority. Divergence is a `LogError`, never
/// a silent re-derive.
pub(crate) fn fold_stored_attempt(
    tx: &rusqlite::Transaction<'_>,
    attempt_id: &str,
) -> Result<crate::attempt::DerivedState, LogError> {
    fold_stored_attempt_if_present(tx, attempt_id)?.ok_or_else(|| {
        LogError(format!(
            "attempt '{attempt_id}' does not fold: {}",
            crate::attempt::FoldDefect::EmptyChain
        ))
    })
}

/// [`fold_stored_attempt`], split on a distinction its callers were losing: `Ok(None)` means the
/// attempt does not exist; every `Err` means something is durably wrong.
///
/// `fold_stored_attempt` answers `Err` for both an absent attempt (`FoldDefect::EmptyChain`) and a
/// chain that does not fold, an unreadable payload, or a projection that disagrees with its
/// chain. Mapping that `Err` to `DerivedState::empty()` would turn every kind of durable
/// corruption on a predecessor into the routine `PredecessorUnclaimed` refusal, and a driver's
/// natural response to a routine refusal is to try something else.
///
/// **Absence is proved, not inferred from a missing chain.** Zero facts under an existing
/// `attempt_head` row is not an absent attempt; it is the inverse of the orphan case boot
/// refuses the open over, and gets the same verdict. The orphan itself (facts without a head
/// row) is an `Err` here too, so `Ok(None)` means zero facts and no head row. A head deleted
/// mid-session must not be believed until the next restart.
///
/// **What "head equals fold" means.** Every persisted value is checked, not just the summary
/// columns: the `verified_state` snapshot is compared against what the chain folds to at
/// `last_verified_revision`. A fact behind that watermark corrupted at rest, which the O(delta)
/// open never re-reads, is therefore caught by the caller that would have trusted it.
pub(crate) fn fold_stored_attempt_if_present(
    tx: &rusqlite::Transaction<'_>,
    attempt_id: &str,
) -> Result<Option<crate::attempt::DerivedState>, LogError> {
    let chain = read_attempt_chain(tx, attempt_id)?;
    if chain.is_empty() {
        let projected: i64 = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM attempt_head WHERE attempt_id = ?1);",
                rusqlite::params![attempt_id],
                |r| r.get(0),
            )
            .map_err(|e| LogError(format!("attempt head presence read: {e}")))?;
        if projected == 1 {
            return Err(LogError(format!(
                "attempt_head for '{attempt_id}' diverges from its chain: the projection exists \
                 but the attempt holds no facts at all"
            )));
        }
        return Ok(None);
    }
    let state = crate::attempt::fold(&chain)
        .map_err(|d| LogError(format!("attempt '{attempt_id}' does not fold: {d}")))?;
    // Head equals fold, on every value the projection persists: the projected columns
    // (revision, class and owner; `head_owner_divergence` is the same comparison the boot
    // check runs, so the two cannot drift) and the verified baseline itself.
    let head: Option<(i64, String, String, i64, String)> = tx
        .query_row(
            "SELECT current_revision, derived_class, operation_id,
                    last_verified_revision, verified_state
               FROM attempt_head WHERE attempt_id = ?1;",
            rusqlite::params![attempt_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .optional()
        .map_err(|e| LogError(format!("attempt head read: {e}")))?;
    // A nonempty chain with no head row is corruption at every reader. Boot refuses the open
    // over precisely this shape (the orphan anti-join in `boot_quarantine`), but a head row
    // deleted mid-session is not seen again until the next restart, and until then every live
    // path would read an attempt the head projections do not cover: the same
    // two-authorities-disagreeing case boot rules on, arriving at a call instead of at an
    // open. `Ok(None)` is reserved for a genuinely absent attempt (zero facts and no head row),
    // which the empty-chain arm above already decided; this is that arm's mirror.
    let Some((revision, class, owner, verified_revision, verified_state)) = head else {
        return Err(LogError(format!(
            "attempt '{attempt_id}' has facts but no attempt_head row: its chain is an ORPHAN, \
             so the head projection and the fold do not cover the same attempts"
        )));
    };
    let derived = state.class().map(|c| c.as_sql().to_string());
    if revision as u64 != state.current_revision || Some(class.clone()) != derived {
        return Err(LogError(format!(
            "attempt_head for '{attempt_id}' diverges from its chain: head says \
             revision {revision}/class '{class}', the fold says revision {}/class {:?}",
            state.current_revision, derived
        )));
    }
    let diverges = |what: String| {
        LogError(format!(
            "attempt_head for '{attempt_id}' diverges from its chain: {what}"
        ))
    };
    if let Some(what) = head_owner_divergence(&owner, &state) {
        return Err(diverges(what));
    }
    // Verify the persisted baseline. The columns above are the head's summary; `verified_state`
    // is the whole snapshot the engine proved correct when it wrote it. Without comparing it, a
    // fact behind `last_verified_revision` corrupted at rest without moving revision, class or
    // owner (a `SEND_AUTHORIZED` exposure key, say) would pass this probe, and adjudication
    // would copy the altered key into the adjudication record and the obligations that gate every
    // later overlapping admission. Boot cannot catch this: open verification is O(delta) and
    // never re-reads a verified prefix.
    //
    // Cost: no extra I/O. The head row is already fetched and the chain already read and folded
    // whole; this adds the snapshot decode, one more in-memory fold over the prefix, and an
    // equality.
    let watermark = u64::try_from(verified_revision)
        .map_err(|_| diverges("its verified watermark is negative".into()))?;
    if watermark > state.current_revision {
        return Err(diverges(format!(
            "the verified watermark {watermark} is ahead of the current revision {}",
            state.current_revision
        )));
    }
    // Strict parse, as in `verify_attempt_head`: a stored snapshot this build could not have
    // written is an error, never a defaulted field.
    let baseline = verified_state_from_json(&verified_state)
        .map_err(|e| diverges(format!("its stored baseline is unreadable — {}", e.0)))?;
    if baseline.current_revision != watermark {
        return Err(diverges(format!(
            "its stored baseline folds to revision {} but is filed at watermark {watermark}",
            baseline.current_revision
        )));
    }
    let prefix = &chain[..chain.partition_point(|f| f.revision <= watermark)];
    let at_watermark = if watermark == 0 {
        crate::attempt::DerivedState::empty()
    } else {
        crate::attempt::fold(prefix).map_err(|d| {
            diverges(format!(
                "the {} fact(s) up to its verified watermark {watermark} do not fold: {d}",
                prefix.len()
            ))
        })?
    };
    if at_watermark != baseline {
        return Err(diverges(format!(
            "its stored baseline is not what the chain itself folds to at revision {watermark} \
             — the snapshot the engine verified and the facts behind that watermark disagree"
        )));
    }
    Ok(Some(state))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unrepresentable_ordinal_is_divergence_not_agreement() {
        // ═══ ═══ `i64::try_from(ordinal).ok()?` returned `None` FROM THE
        // FUNCTION — and `None` is this function's word for "the column and the payload
        // AGREE". A persisted `CLAIM` payload carrying an ordinal above `i64::MAX` therefore
        // read as no divergence at all, which is the projection-versus-fold class answering
        // fail-OPEN at the one door built to answer it fail-LOUD.
        let payload = crate::attempt::FactPayload::Claim {
            ordinal: u64::MAX,
            predecessor: None,
        };
        let divergence =
            ordinal_column_divergence(crate::attempt::FactKind::Claim, &payload, Some(1));
        assert!(
            divergence.is_some(),
            "an ordinal the SQL column cannot represent can never EQUAL that column — it is a \
             divergence, and a divergence fails loud"
        );
        // …and the column being NULL does not rescue it either: there is still no value the
        // column could hold that equals the payload's.
        assert!(
            ordinal_column_divergence(crate::attempt::FactKind::Claim, &payload, None).is_some(),
            "…including against a NULL column"
        );
    }

    #[test]
    fn s1_the_failed_pre_send_codec_carries_the_plan_refusal_record_and_reads_absent_as_none() {
        // The record rides the payload beside the exposure block — written
        // by `fact_payload_json`, read back EQUAL by `fact_payload_from_json`; a row with no key
        // (written before the field existed) and a `null` both read as `None`; a present value
        // this writer cannot have produced, and a reason token outside the closed vocabulary,
        // are `LogError`s.
        use crate::attempt::{FactKind, FactPayload, MemberDiff, PlanRefusalRecord, PreSendReason, WireEvidence};
        let rec = PlanRefusalRecord {
            reason: "state_diverged".into(),
            member_ref: "msg-1".into(),
            diff: vec![
                MemberDiff { atom: "label:TRASH".into(), expected: false, observed: Some(true) },
                MemberDiff { atom: "membership:INBOX".into(), expected: true, observed: None },
            ],
            detail: Some(r#"{"k":1}"#.into()),
        };
        for reason in [PreSendReason::StaleNotAttempted, PreSendReason::PlanRefused] {
            let payload = FactPayload::FailedPreSend { wire_evidence: WireEvidence::ProvenNoWire, reason, exposure_block: None, plan_refusal: Some(rec.clone()) };
            let json = fact_payload_json(&payload);
            assert_eq!(fact_payload_from_json(FactKind::FailedPreSend, &json).unwrap(), payload, "the record round-trips: {json}");
        }
        let none = FactPayload::FailedPreSend { wire_evidence: WireEvidence::ProvenNoWire, reason: PreSendReason::Failure, exposure_block: None, plan_refusal: None };
        let json = fact_payload_json(&none);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v.get("plan_refusal"), Some(&serde_json::Value::Null), "written as null: {json}");
        assert_eq!(fact_payload_from_json(FactKind::FailedPreSend, &json).unwrap(), none);
        // A row written before the key existed.
        let legacy = r#"{"wire_evidence":"proven_no_wire","reason":"failure","blocked_atom":null,"blocked_obligation":null}"#;
        assert_eq!(fact_payload_from_json(FactKind::FailedPreSend, legacy).unwrap(), none);
        for crafted in [
            r#"{"wire_evidence":"proven_no_wire","reason":"plan_refused","plan_refusal":7}"#,
            r#"{"wire_evidence":"proven_no_wire","reason":"plan_refused","plan_refusal":{"reason":"","member_ref":"m"}}"#,
            r#"{"wire_evidence":"proven_no_wire","reason":"plan_refused","plan_refusal":{"reason":"expired","member_ref":""}}"#,
            r#"{"wire_evidence":"proven_no_wire","reason":"plan_refused","plan_refusal":{"reason":"expired"}}"#,
            r#"{"wire_evidence":"proven_no_wire","reason":"plan_refused","plan_refusal":{"reason":"expired","member_ref":"m","extra":1}}"#,
            r#"{"wire_evidence":"proven_no_wire","reason":"stale","plan_refusal":null}"#,
        ] {
            assert!(fact_payload_from_json(FactKind::FailedPreSend, crafted).is_err(), "a row this writer cannot have produced: {crafted}");
        }
    }
}
