//! The adjudication and exposure-obligation helpers the store methods call inside their
//! transactions. Every helper here is called from inside a single transaction; none opens one.

use crate::fact_store::{fold_stored_attempt, read_attempt_chain};
use crate::settle::append_fact_with_head;
use crate::LogError;

/// An opaque engine-minted id from SQLite's own CSPRNG, the minting used for `intent_id`,
/// `witness_id` and the adjudication rows. Content-free: it is derived from nothing the caller
/// supplied.
pub(crate) fn mint_opaque_id(tx: &rusqlite::Transaction<'_>, door: &str) -> Result<String, LogError> {
    tx.query_row("SELECT lower(hex(randomblob(16)));", [], |r| r.get(0))
        .map_err(|e| LogError(format!("{door} id mint: {e}")))
}

/// The fact-clock high-water read, as one text.
///
/// Every method that appends an attempt fact clamps its instant against this. `attempt_fact` is
/// append-only, so an unindexed `MAX(created_at)` is a full pass over all history and would make
/// every fact write's cost grow with what the store has ever done. An ordinary index on
/// `created_at` (`idx_attempt_fact_created_at`) lets SQLite's MIN/MAX optimization seek to the
/// last entry. It is a single text, like `EXPOSURE_OVERLAP_SQL`, because SQLite matches indexes
/// against the text it is given and the `EXPLAIN QUERY PLAN` test in `store_open` must plan the
/// query actually run. It is deliberately not a stored high-water row: that would be a second
/// authority for the clock beside the ledger it derives from.
pub(crate) const FACT_CLOCK_HIGH_WATER_SQL: &str =
    "SELECT COALESCE(MAX(created_at), '') FROM attempt_fact;";

/// The clamped-monotonic instant every durable write of one operation shares: `max(now,
/// persisted high-water)` through the pure core's clamp, so no row this transaction writes can
/// sort before the facts it is about.
pub(crate) fn fact_clock(tx: &rusqlite::Transaction<'_>, door: &str) -> Result<String, LogError> {
    let now: String = tx
        .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%SZ','now');", [], |r| {
            r.get(0)
        })
        .map_err(|e| LogError(format!("{door} clock read: {e}")))?;
    let max_persisted: String = tx
        .query_row(FACT_CLOCK_HIGH_WATER_SQL, [], |r| r.get(0))
        .map_err(|e| LogError(format!("{door} clock high-water read: {e}")))?;
    Ok(crate::attempt::clamped_now(&now, &max_persisted)
        .map_err(|e| LogError(format!("{door} clock: {e}")))?
        .value)
}

/// The exposure check's absence proof, as one text, so the `EXPLAIN QUERY PLAN` test in
/// `store_open` asserts the plan of the query the check actually runs, not a hand-written
/// look-alike (SQLite matches indexes against the text it is given).
pub(crate) const EXPOSURE_OVERLAP_SQL: &str = "SELECT obligation_id FROM exposure_obligation
                      WHERE retired_at IS NULL AND primitive_atom = ?1
                      LIMIT 1;";

/// The overlapping-contributor lookup, as one text (the `EXPLAIN QUERY PLAN` test in
/// `store_open` must plan the query [`note_exposure_materialization`] actually runs).
///
/// `?1` is the primitive atom, `?2` the applying attempt (excluded from its own trace), `?3` the
/// applying attempt's `SEND_AUTHORIZED` instant: the effect-release boundary an episode has to
/// have been live at to overlap it.
///
/// **Split, because an `OR` defeats an index.** As one predicate,
/// `(retired_at IS NULL OR retired_at >= ?3)`, SQLite cannot use an index unless every arm is
/// independently indexable, so `idx_exposure_obligation_live` would sit unused and the plan would
/// walk every row the atom ever had, live and retired. Nothing evicts an obligation, and this
/// runs inside the settling writer transaction once per touched atom. The two arms each get an
/// index:
/// - `retired_at IS NULL` uses `idx_exposure_obligation_live`;
/// - `retired_at IS NOT NULL AND retired_at >= ?3` uses `idx_exposure_obligation_retired`, whose
///   `(primitive_atom, retired_at)` key makes the bound a range seek. The redundant-looking
///   `IS NOT NULL` lets SQLite prove the WHERE implies that partial index's own.
///
/// `UNION` (not `UNION ALL`) de-duplicates, so a row matching both arms would still yield one
/// contributor.
pub(crate) const EXPOSURE_CONTRIBUTORS_SQL: &str =
    "SELECT contributor_attempt_id FROM exposure_obligation
      WHERE primitive_atom = ?1 AND retired_at IS NULL
        AND contributor_attempt_id <> ?2
     UNION
     SELECT contributor_attempt_id FROM exposure_obligation
      WHERE primitive_atom = ?1 AND retired_at IS NOT NULL AND retired_at >= ?3
        AND contributor_attempt_id <> ?2;";

/// The retirement write, as one text. No exposure state retires while an unresolved contributor
/// exists: once a late ack resolves an attempt, its rows (and only its own) retire, inside the
/// same transaction that appends the fact.
///
/// No other index starts with `contributor_attempt_id`: every existing `exposure_obligation`
/// index keys off `primitive_atom` first, so `WHERE contributor_attempt_id = ?1 AND retired_at IS
/// NULL` would `SCAN` the whole live partition (every live obligation in the store) inside the
/// writer transaction on every late ack, and that partition only grows. The partial index
/// `idx_exposure_obligation_contributor` on `(contributor_attempt_id) WHERE retired_at IS NULL`
/// turns it into a seek. It is partial because a retired row can never again match this
/// `UPDATE`, so indexing it would be pure write cost. `EXPLAIN QUERY PLAN` accepts `UPDATE`, so
/// the `store_open` test plans the statement the late-ack path actually runs.
pub(crate) const EXPOSURE_RETIREMENT_BY_CONTRIBUTOR_SQL: &str =
    "UPDATE exposure_obligation SET retired_at = ?2
      WHERE contributor_attempt_id = ?1 AND retired_at IS NULL;";

/// The single-successor probe: the predecessor "has no other retry successor"
/// ([`crate::attempt::retry_lineage_legal`]'s last rule, which takes this answer as an
/// argument). `?1` is the operation, `?2` the predecessor attempt.
///
/// **Operation-scoped, because the rule is.** Matching `fact_kind = 'claim'` and
/// `json_extract(payload, '$.predecessor_attempt_id') = ?` over the whole ledger gives no
/// equality term an index could serve, so it would `SCAN attempt_fact` inside the CLAIM
/// transaction on every retry, a cost that grows with history. Retry lineage is internal to one
/// operation's ordinal sequence (`retry_lineage_legal` refuses a cross-operation predecessor
/// before it consults this answer), so the `operation_id` term is the rule's own domain. It uses
/// the autoindex of `UNIQUE (operation_id, attempt_ordinal)` on its `operation_id` prefix, so
/// the walk is bounded by one operation's facts (bounded by the retry cap), with no new index.
pub(crate) const RETRY_SUCCESSOR_SQL: &str = "SELECT EXISTS(SELECT 1 FROM attempt_fact
                                    WHERE operation_id = ?1
                                      AND fact_kind = 'claim'
                                      AND json_extract(payload, '$.predecessor_attempt_id') = ?2);";

/// The generation high-water read, as one text: the fallback half of [`obligation_generation`],
/// run once the live-obligation probe comes back empty (the atom's current episode is over). The
/// next generation is `max(generation over the atom's whole history) + 1`, retired rows included.
///
/// **A scan wearing a `SEARCH` label.** `UNIQUE (primitive_atom, direction, generation,
/// contributor_attempt_id)` puts `direction` between the equality-constrained `primitive_atom` and
/// `generation`, so SQLite's MIN/MAX single-row optimization cannot fire. `EXPLAIN QUERY PLAN`
/// still reports `SEARCH ... (primitive_atom=?)`, but underneath SQLite walks every row the atom
/// ever had, inside the adjudication transaction. The `store_open` test records the exact unfixed
/// plan text because asserting `!contains("SCAN")` would pass on the broken shape.
///
/// `idx_exposure_obligation_generation` puts `generation` immediately after `primitive_atom`, so
/// the aggregate is a single seek. It is not partial: this read's domain is the whole history.
pub(crate) const EXPOSURE_GENERATION_HIGH_WATER_SQL: &str =
    "SELECT COALESCE(MAX(generation), 0) + 1 FROM exposure_obligation
      WHERE primitive_atom = ?1;";

/// The generation for a new obligation on `(account, atom)`.
///
/// After an atom's exposure fully resolves and settles, a later independent unresolved episode is
/// a new exposure generation, and old acceptances and notices never authorize or contaminate it.
/// While an unretired row exists the atom is in its current episode and a second contributor
/// joins that generation; once every row has retired, the next episode is `max + 1`. Retired
/// rows are never deleted, so the max is over the whole history and generations never repeat.
pub(crate) fn obligation_generation(
    tx: &rusqlite::Transaction<'_>,
    atom_key: &str,
) -> Result<i64, LogError> {
    let live: Option<i64> = tx
        .query_row(
            "SELECT MAX(generation) FROM exposure_obligation
              WHERE primitive_atom = ?1 AND retired_at IS NULL;",
            rusqlite::params![atom_key],
            |r| r.get(0),
        )
        .map_err(|e| LogError(format!("exposure generation read: {e}")))?;
    if let Some(generation) = live {
        return Ok(generation);
    }
    tx.query_row(
        EXPOSURE_GENERATION_HIGH_WATER_SQL,
        rusqlite::params![atom_key],
        |r| r.get(0),
    )
    .map_err(|e| LogError(format!("exposure generation mint: {e}")))
}

/// Append one row to the `adjudication_annotation` ledger, the append-only home of the two
/// things that must never be silent (an immutable record cannot carry them itself). Returns
/// the minted annotation id.
pub(crate) fn write_annotation(
    tx: &rusqlite::Transaction<'_>,
    adjudication_id: &str,
    kind: crate::attempt::AnomalyKind,
    related_attempt_id: Option<&str>,
    atom_key: Option<&str>,
    created_at: &str,
) -> Result<String, LogError> {
    let annotation_id = mint_opaque_id(tx, "annotation")?;
    tx.execute(
        "INSERT INTO adjudication_annotation (annotation_id, adjudication_id, kind,
                                              related_attempt_id, atom_key, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6);",
        rusqlite::params![
            annotation_id,
            adjudication_id,
            kind.as_sql(),
            related_attempt_id,
            atom_key,
            created_at
        ],
    )
    .map_err(|e| LogError(format!("adjudication annotation insert: {e}")))?;
    Ok(annotation_id)
}

/// Notice that a duplicate or reversal risk actually materialized. Called from both paths that
/// can make an attempt's historical axis say `APPLIED` (the ordinary settlement and the
/// post-adjudication late ack), so that a durable notice is discoverable from the relevant
/// adjudication records, including when two same-atom effects both resolve `APPLIED`.
///
/// For every other contributor holding an obligation over an atom this attempt applied to: if it
/// already resolved `APPLIED`, both applied, and [`crate::attempt::AnomalyKind::ExposureMaterialized`]
/// goes on its record; if it is still unknown,
/// [`crate::attempt::AnomalyKind::AppliedOverUnresolved`] goes on its record, the durable half of
/// the trace, so the materialization is decidable from the records alone when its own late ack
/// lands. Symmetrically, if the applying attempt is itself adjudicated (this is its late ack) and
/// its own record already carries a half-trace, the notice lands on it now.
///
/// **The scan is bounded to overlapping episodes.** Reading every obligation row on the atom
/// would let a later operation on a long-settled message mint a false `EXPOSURE_MATERIALIZED`
/// notice against a stranger's adjudication record. A candidate episode must have been live when
/// this attempt's effect was authorized: `retired_at IS NULL`, or retired at or after its
/// `SEND_AUTHORIZED`. Retired-but-overlapping rows are still read: they are the durable evidence
/// an episode existed, and dropping them would make the notice depend on which effect resolved
/// first.
///
/// Residual: `created_at` has second resolution, so a retirement and an authorization in the same
/// second compare equal and count as overlapping. That tie resolves toward writing a notice, the
/// safe direction.
///
/// Every lookup is keyed on `primitive_atom`, so the cost is the number of contributors on the
/// atoms this one attempt touched, independent of history; see [`EXPOSURE_CONTRIBUTORS_SQL`].
pub(crate) fn note_exposure_materialization(
    tx: &rusqlite::Transaction<'_>,
    attempt_id: &str,
    exposure_key: &crate::attempt::ExposureKey,
    own_adjudication_id: Option<&str>,
    created_at: &str,
) -> Result<u64, LogError> {
    // The applying attempt's own effect-release boundary: the instant an episode has to have
    // been live to overlap it. Read from the chain (never predicted): an attempt reaching this
    // function has settled with a definitive `APPLIED`, which the grammar only admits after a
    // `SEND_AUTHORIZED`.
    let authorized_at: String = tx
        .query_row(
            "SELECT created_at FROM attempt_fact
              WHERE attempt_id = ?1 AND fact_kind = 'send_authorized';",
            rusqlite::params![attempt_id],
            |r| r.get(0),
        )
        .map_err(|e| {
            LogError(format!(
                "materialization scan: attempt '{attempt_id}' applied without a \
                 SEND_AUTHORIZED fact to date its exposure window by: {e}"
            ))
        })?;
    let mut notices = 0u64;
    for atom in &exposure_key.atoms {
        let mut contributors: Vec<String> = Vec::new();
        {
            let mut stmt = tx
                .prepare(EXPOSURE_CONTRIBUTORS_SQL)
                .map_err(|e| LogError(format!("materialization scan: {e}")))?;
            let rows = stmt
                .query_map(
                    rusqlite::params![atom.atom_key, attempt_id, authorized_at],
                    |r| r.get::<_, String>(0),
                )
                .map_err(|e| LogError(format!("materialization scan: {e}")))?;
            for row in rows {
                contributors.push(row.map_err(|e| LogError(format!("materialization scan: {e}")))?);
            }
        }
        for other in contributors {
            let state = fold_stored_attempt(tx, &other)?;
            // An obligation exists only where an adjudication wrote one, so a contributor with
            // no record is a store defect, not a case to skip quietly.
            let Some(record) = state.adjudication_id.clone() else {
                return Err(LogError(format!(
                    "exposure obligation names contributor attempt '{other}', which holds no \
                     adjudication record"
                )));
            };
            // A contributor whose late ack said `REFUSED_NO_EFFECT` is proven to have had no
            // effect. Nothing materialized, and it is not "unresolved" either; reading "not
            // `LATE_ACK_APPLIED`" as "still unknown" would durably annotate ambiguity over a
            // settled fact. No notice at all is the truth.
            if state.late_ack == Some(crate::attempt::FactKind::LateAckRefusedNoEffect) {
                continue;
            }
            let kind = if state.late_ack == Some(crate::attempt::FactKind::LateAckApplied) {
                crate::attempt::AnomalyKind::ExposureMaterialized
            } else {
                crate::attempt::AnomalyKind::AppliedOverUnresolved
            };
            write_annotation(
                tx,
                &record,
                kind,
                Some(attempt_id),
                Some(&atom.atom_key),
                created_at,
            )?;
            if kind == crate::attempt::AnomalyKind::ExposureMaterialized {
                notices += 1;
            }
        }
    }
    // The other order: a same-atom effect applied while this exposure was unresolved, and this
    // is the late ack that makes it two applied effects.
    if let Some(record) = own_adjudication_id {
        let half: i64 = tx
            .query_row(
                ADJUDICATION_ANNOTATION_HALF_TRACE_SQL,
                rusqlite::params![
                    record,
                    crate::attempt::AnomalyKind::AppliedOverUnresolved.as_sql()
                ],
                |r| r.get(0),
            )
            .map_err(|e| LogError(format!("materialization half-trace read: {e}")))?;
        if half > 0 {
            write_annotation(
                tx,
                record,
                crate::attempt::AnomalyKind::ExposureMaterialized,
                Some(attempt_id),
                None,
                created_at,
            )?;
            notices += 1;
        }
    }
    Ok(notices)
}

/// The materialization half-trace read, as one text: the symmetric arm of
/// [`note_exposure_materialization`]. Has an earlier contributor already left the
/// `AppliedOverUnresolved` half on this attempt's own adjudication record? If so, this late ack
/// completes the pair and the notice fires now instead of never.
///
/// `adjudication_annotation` is indexed only by its `PRIMARY KEY` (`annotation_id`), so
/// `WHERE adjudication_id = ?1 AND kind = ?2` would `SCAN` every annotation ever written, inside
/// the late-ack writer transaction. The table is append-only, so that grows with history.
/// `idx_adjudication_annotation_lookup`, an ordinary two-column index on
/// `(adjudication_id, kind)`, matches the equality prefix exactly. It is not partial, since every
/// row carries both columns. The `EXPLAIN QUERY PLAN` test plans this exact text.
pub(crate) const ADJUDICATION_ANNOTATION_HALF_TRACE_SQL: &str =
    "SELECT COUNT(*) FROM adjudication_annotation
      WHERE adjudication_id = ?1 AND kind = ?2;";

/// The audit edge: link every adjudicated attempt whose unresolved exposure this newly admitted
/// operation overlaps to this operation, as its first successor. At most one edge is legal per
/// attempt, only on adjudicated attempts; later overlapping admissions carry no edge (their audit
/// trail is their acceptance record). The edge is an audit pointer; no check depends on it.
///
/// Called inside the admission transaction, after the operation row is inserted and before it
/// commits, so `SUPERSEDED_BY` and the admission it points at are one durable write.
///
/// First-successor-only is the `superseded_by.is_none()` test against the adjudicated attempt's
/// own folded chain (the grammar refuses a second one anyway; this stops the caller offering
/// one). Only unretired obligations count: a retired episode is closed, and an edge into it
/// would let old state contaminate a later independent episode.
pub(crate) fn link_supersessions(
    tx: &rusqlite::Transaction<'_>,
    successor_operation_id: &str,
    exposure_key: &crate::attempt::ExposureKey,
    epoch: i64,
) -> Result<u64, LogError> {
    use crate::attempt::{Fact, FactKind, FactPayload};
    let mut candidates: Vec<String> = Vec::new();
    for atom in &exposure_key.atoms {
        let mut stmt = tx
            .prepare(
                "SELECT DISTINCT contributor_attempt_id FROM exposure_obligation
                  WHERE primitive_atom = ?1 AND retired_at IS NULL;",
            )
            .map_err(|e| LogError(format!("supersession scan: {e}")))?;
        let rows = stmt
            .query_map(rusqlite::params![atom.atom_key], |r| r.get::<_, String>(0))
            .map_err(|e| LogError(format!("supersession scan: {e}")))?;
        for row in rows {
            let id = row.map_err(|e| LogError(format!("supersession scan: {e}")))?;
            if !candidates.contains(&id) {
                candidates.push(id);
            }
        }
    }
    // Nothing to link, nothing spent. The scan above is one keyed index lookup per touched
    // atom (`idx_exposure_obligation_live`); the clock below is not, since it reads the fact
    // table's high-water, so the ordinary admission, which overlaps no unresolved exposure,
    // must not pay for it.
    if candidates.is_empty() {
        return Ok(0);
    }
    let created_at = fact_clock(tx, "admission")?;
    let mut linked = 0u64;
    for attempt_id in candidates {
        let chain = read_attempt_chain(tx, &attempt_id)?;
        let state = fold_stored_attempt(tx, &attempt_id)?;
        // Only on an adjudicated attempt, and only for the first successor.
        if state.adjudication_id.is_none() || state.superseded_by.is_some() {
            continue;
        }
        let Some(claim) = state.claim.as_ref() else {
            return Err(LogError(format!(
                "supersession: attempt '{attempt_id}' has no CLAIM"
            )));
        };
        let fact = Fact {
            operation_id: claim.operation_id.clone(),
            attempt_id: attempt_id.clone(),
            revision: state.current_revision + 1,
            kind: FactKind::SupersededBy,
            basis_epoch: epoch,
            created_at: created_at.clone(),
            payload: FactPayload::SupersededBy {
                successor_operation_id: successor_operation_id.to_string(),
            },
            prior_revision: Some(state.current_revision),
        };
        // The grammar cannot refuse this one: the state was just folded in this transaction
        // and satisfies the whitelist. A refusal therefore means the fold and the grammar
        // disagree, so fail and roll the admission back rather than admit a successor whose
        // audit edge silently did not happen.
        if let Some(refusal) = append_fact_with_head(tx, &chain, &fact)? {
            return Err(LogError(format!(
                "supersession: the audit edge on attempt '{attempt_id}' was refused by the \
                 grammar: {refusal}"
            )));
        }
        linked += 1;
    }
    Ok(linked)
}
