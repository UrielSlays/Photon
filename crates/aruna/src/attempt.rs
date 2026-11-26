//! The attempt-fact grammar core.
//!
//! Pure: enums, a fold over the immutable fact chain, one legality predicate, one canonical
//! encoding. No `rusqlite`, no clock, no filesystem; every input is an argument. The store half
//! (compare-and-append, the head upsert, the epoch fence) lives in `lib.rs` and calls through
//! this module, so the grammar has exactly one home and a second hand-written legality table
//! cannot drift into existence.
//!
//! **Why a pure core.** The grammar is closed and enforced by one append function that fails
//! closed on any illegal fact. A closed grammar is only as closed as the number of places that
//! decide legality, so legality is decided here, over a value, with no I/O in reach, and the
//! store transaction's job reduces to "ask, then persist or refuse".
//!
//! **The head is a projection, never a second authority.** The `attempt_head` row is
//! maintained transactionally with the append and is re-derivable from the chain; `fold` is the
//! re-derivation, and the head is compared against it, never trusted over it.
//!
//! **Two axes, not one.** An attempt carries a historical attribution axis (`UNKNOWN`, then at
//! most one of `APPLIED` | `REFUSED_NO_EFFECT` | `FAILED_PRE_SEND` | `SEVERED_BEFORE_ISSUANCE`,
//! or permanently `UNKNOWN`) and an operational axis (`ACTIVE` then `CLOSED`, by a terminal
//! attribution or by adjudication). The rule is at most one terminal attribution: an
//! adjudicated attempt may permanently have none, and that is the truthful record.
//!
//! Content-free, like the rest of the substrate: ids, ordinals, epochs, opaque observation
//! tokens and exposure keys, never bodies, subjects or headers. That includes a
//! `FAILED_PRE_SEND`'s plan refusal record ([`crate::attempt::PlanRefusalRecord`]): its
//! `detail` carries tokens, numbers, instants, commitment tags, engine-written sentences and
//! Photon identities, and a grant refusal's payload is the `String`-free
//! `crate::plan::GrantDenial`.

use std::fmt;

use sha2::{Digest, Sha384};

use crate::prestate::is_canonical_rfc3339_utc;

// ---------------------------------------------------------------------------------------
// Fact kinds: the closed 13-kind vocabulary, in the SQL CHECK constraint's order
// ---------------------------------------------------------------------------------------

/// The 13 fact kinds of `attempt_fact.fact_kind`. Closed: a 14th kind is a schema change (the
/// CHECK constraint in `store_open.rs` refuses it) and a compile error here (every match over
/// this enum is exhaustive on purpose).
///
/// The `as_sql`/`from_sql` spellings are the SQL tokens themselves. The test
/// `fact_kind_vocabulary_matches_the_ddl_check_constraint` regenerates the CHECK list from
/// this enum and compares it to the DDL source text, so the two cannot drift silently (the
/// `NON_TERMINAL_STATUS_SQL` pattern, applied to a vocabulary that lives in another module's
/// DDL string).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FactKind {
    /// The ownership-establishing fact: owner `operation_id`, attempt ordinal, and (for
    /// ordinal > 1) the mandatory retry predecessor and reason.
    Claim,
    /// The epoch-fenced authorization committed immediately before connector socket entry. At
    /// most one, only after `Claim`.
    SendAuthorized,
    /// Terminal attribution: the provider response definitively proves the requested effect.
    AckApplied,
    /// Terminal attribution: definitively proves rejection before effect (e.g. a 4xx).
    AckRefusedNoEffect,
    /// Terminal attribution: no effect exists, either from an engine-side failure before
    /// `SendAuthorized` or from a post-auth failure carrying the connector's positive
    /// proven-no-wire proof.
    FailedPreSend,
    /// Not a terminal attribution: ISSUANCE_UNKNOWN. At most one per attempt; further ambiguous
    /// observations route through the capped `Reconcile*` path.
    AckAmbiguous,
    /// Cadence- and lifetime-bounded observation annotation: the observed state matches.
    ReconcileStateMatches,
    /// Cadence- and lifetime-bounded observation annotation: the observed state differs.
    ReconcileStateDiffers,
    /// Terminal attribution: caught by a sever before any authorization existed.
    SeveredBeforeIssuance,
    /// Closes the operational axis only, never the historical one.
    AdjudicatedUnresolved,
    /// Post-adjudication whitelist: resolves the historical axis to APPLIED, nothing else.
    LateAckApplied,
    /// Post-adjudication whitelist: resolves the historical axis to REFUSED_NO_EFFECT.
    LateAckRefusedNoEffect,
    /// Post-adjudication whitelist: links the adjudicated attempt to its one successor
    /// operation (the audit edge; nothing gates on it).
    SupersededBy,
}

impl FactKind {
    /// Every kind, in the DDL CHECK constraint's order. Not test-only: the store half spells
    /// its `fact_kind` column through [`FactKind::as_sql`], and the guard test derives the
    /// CHECK list from this array.
    pub const ALL: [FactKind; 13] = [
        FactKind::Claim,
        FactKind::SendAuthorized,
        FactKind::AckApplied,
        FactKind::AckRefusedNoEffect,
        FactKind::FailedPreSend,
        FactKind::AckAmbiguous,
        FactKind::ReconcileStateMatches,
        FactKind::ReconcileStateDiffers,
        FactKind::SeveredBeforeIssuance,
        FactKind::AdjudicatedUnresolved,
        FactKind::LateAckApplied,
        FactKind::LateAckRefusedNoEffect,
        FactKind::SupersededBy,
    ];

    /// The SQL spelling: the exact token the `attempt_fact.fact_kind` CHECK constraint
    /// enumerates. Exhaustive: a new variant does not compile until it takes a position.
    pub fn as_sql(&self) -> &'static str {
        match self {
            FactKind::Claim => "claim",
            FactKind::SendAuthorized => "send_authorized",
            FactKind::AckApplied => "ack_applied",
            FactKind::AckRefusedNoEffect => "ack_refused_no_effect",
            FactKind::FailedPreSend => "failed_pre_send",
            FactKind::AckAmbiguous => "ack_ambiguous",
            FactKind::ReconcileStateMatches => "reconcile_state_matches",
            FactKind::ReconcileStateDiffers => "reconcile_state_differs",
            FactKind::SeveredBeforeIssuance => "severed_before_issuance",
            FactKind::AdjudicatedUnresolved => "adjudicated_unresolved",
            FactKind::LateAckApplied => "late_ack_applied",
            FactKind::LateAckRefusedNoEffect => "late_ack_refused_no_effect",
            FactKind::SupersededBy => "superseded_by",
        }
    }

    /// The inverse. `None` for anything the CHECK constraint would itself have refused: a row
    /// spelling an unknown kind is a corrupt store, not a new grammar rule.
    pub fn from_sql(s: &str) -> Option<FactKind> {
        FactKind::ALL.iter().copied().find(|k| k.as_sql() == s)
    }

    /// Is this one of the four terminal-attribution facts? `AckAmbiguous`, `Reconcile*`,
    /// `AdjudicatedUnresolved`, `LateAck*` and `SupersededBy` are not; that is the point of the
    /// two-axis split.
    pub fn is_terminal_attribution(&self) -> bool {
        matches!(
            self,
            FactKind::AckApplied
                | FactKind::AckRefusedNoEffect
                | FactKind::FailedPreSend
                | FactKind::SeveredBeforeIssuance
        )
    }
}

// ---------------------------------------------------------------------------------------
// Payloads: typed per kind, carrying exactly what the grammar reads
// ---------------------------------------------------------------------------------------

/// The retry reason vocabulary: closed, and exactly the two eligible predecessor terminals,
/// `FAILED_PRE_SEND` and `ACK_REFUSED_NO_EFFECT`. `ACK_AMBIGUOUS`/ISSUANCE_UNKNOWN is
/// deliberately absent (no retry from either, ever): the type enforces the prohibition, not
/// only a check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryReason {
    /// The predecessor holds a proven-no-wire terminal.
    FailedPreSend,
    /// The predecessor holds a definitive provider refusal before effect.
    AckRefusedNoEffect,
}

impl RetryReason {
    /// The historical attribution a predecessor must hold for this declared reason.
    fn required_attribution(&self) -> HistoricalAttribution {
        match self {
            RetryReason::FailedPreSend => HistoricalAttribution::FailedPreSend,
            RetryReason::AckRefusedNoEffect => HistoricalAttribution::RefusedNoEffect,
        }
    }
}

/// The mandatory lineage tuple every ordinal > 1 CLAIM carries: immutable and atomic with the
/// claim (there is no standalone `RETRY_OF` fact, so lineage cannot exist apart from the claim
/// that asserts it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryPredecessor {
    /// The predecessor attempt's opaque id.
    pub attempt_id: String,
    /// Why this retry is eligible — checked against the predecessor's own folded state by
    /// [`retry_lineage_legal`].
    pub reason: RetryReason,
}

/// Did the connector positively prove that no request bytes left the host? The default is
/// `Indeterminate`: absence of proof is never proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WireEvidence {
    /// The connector proved the failure occurred before any request bytes were written
    /// (DNS/connect/TLS stage; Gmail's `send_stage_verdict` split).
    ProvenNoWire,
    /// Anything else. An unproven post-auth failure is ISSUANCE_UNKNOWN, never no-effect.
    #[default]
    Indeterminate,
}

/// Why a `FAILED_PRE_SEND` terminal was written: a closed vocabulary, carried in the fact
/// payload rather than reconstructed from the operation's status later.
/// [`PreSendReason::ALL`] lists every member.
///
/// The distinction is not cosmetic: every member is truthfully "no effect exists", but only
/// some mean the operation's objective is unmet. `Failure` leaves the retry taxonomy in charge
/// (charge the budget, or dead-letter); `ExternallySatisfied` says the objective was produced
/// by someone else while this operation was between attempts, which completes the operation on
/// a terminal of its own and makes it undo-ineligible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PreSendReason {
    /// The ordinary proven-before-issuance failure: the connector, the capture pipeline, or a
    /// local pre-wire check refused. The retry taxonomy decides what the operation does next.
    #[default]
    Failure,
    /// The retry-requalification `C == A` branch: at the head of a retry, the forward target
    /// already held (another actor produced it). Nothing was dispatched, so the attribution is
    /// proven-no-wire; the operation completes `EXTERNALLY_SATISFIED`, and the retained journal
    /// row can never offer a restore, since a stale captured `P` must never reverse the other
    /// actor's change.
    ExternallySatisfied,
    /// A plan child whose member's durable capture no longer equals the approval-time observed
    /// state: never acted on, with the diff carried in the payload's `plan_refusal`
    /// ([`PlanRefusalRecord::diff`]). Terminal for the child; its neighbours continue. Written
    /// only by the plan arm of `IntentLog::authorize_send` (`lib.rs`), for a
    /// `crate::plan::PlanSendRefusal::StateDiverged` refusal.
    StaleNotAttempted,
    /// A plan-admission refusal other than a diverged state that terminalizes the child; which
    /// one is carried in `plan_refusal.reason`. Written only by the plan arm of
    /// `IntentLog::authorize_send` (`lib.rs`), for every terminal `crate::plan::PlanSendRefusal`
    /// but `StateDiverged`.
    PlanRefused,
}

impl PreSendReason {
    /// Every member, in wire-token order. [`PreSendReason::from_token`] reads this list, and the
    /// test `s1_pre_send_reason_vocabulary_has_four_members_and_round_trips` pins that every
    /// variant is in it.
    pub const ALL: [PreSendReason; 4] = [
        PreSendReason::Failure,
        PreSendReason::ExternallySatisfied,
        PreSendReason::StaleNotAttempted,
        PreSendReason::PlanRefused,
    ];

    /// The wire token (the payload JSON's `reason`): one spelling, both directions.
    pub fn as_token(&self) -> &'static str {
        match self {
            PreSendReason::Failure => "failure",
            PreSendReason::ExternallySatisfied => "externally_satisfied",
            PreSendReason::StaleNotAttempted => "stale_not_attempted",
            PreSendReason::PlanRefused => "plan_refused",
        }
    }

    /// Parse the wire token; `None` for anything outside the closed vocabulary (`ALL`).
    pub fn from_token(s: &str) -> Option<PreSendReason> {
        PreSendReason::ALL.into_iter().find(|r| r.as_token() == s)
    }
}

/// One atom's divergence between a plan member's approval-time observed state and the durable
/// capture. Its fields are an atom name, a boolean and an optional boolean (`observed: None`
/// means the capture did not cover the atom); none holds a subject, sender or address.
/// Unknown JSON keys are refused on read (`deny_unknown_fields`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberDiff {
    /// The engine's atom name (e.g. `label:TRASH`, `membership:INBOX`).
    pub atom: String,
    /// The approval-time observed value.
    pub expected: bool,
    /// The capture's value; `None` means the capture did not cover this atom.
    pub observed: Option<bool>,
}

/// What the plan-admission arm refused, when that is what closed this attempt: carried in the
/// `FAILED_PRE_SEND` payload (the key `plan_refusal`, see `lib.rs` `fact_payload_json` /
/// `fact_payload_from_json`), like [`ExposureBlock`]. Written only by the plan arm of
/// `IntentLog::authorize_send` (the value `crate::plan::PlanSendRefusal::record` builds) and
/// read only by `IntentLog::plan_refusal`.
///
/// `reason` is a refusal token (the closed set is `crate::plan::PlanSendRefusal::TOKENS`);
/// `diff` is non-empty only for a diverged state; `detail` is the JSON of the refusal
/// variant's payload (`None` for a variant with none beyond the diff), which
/// `crate::plan::PlanSendRefusal::from_record` reads back. Unknown JSON keys are refused on
/// read (`deny_unknown_fields`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanRefusalRecord {
    /// The refusal's token. Never empty (the decoder refuses an empty one).
    pub reason: String,
    /// The member (a Photon `message_ref`) whose child was refused. Never empty (same).
    pub member_ref: String,
    /// The diverged atoms; empty unless the refusal is a diverged state.
    #[serde(default)]
    pub diff: Vec<MemberDiff>,
    /// The refusal variant's payload as JSON; `None` for a variant with none beyond the diff.
    #[serde(default)]
    pub detail: Option<String>,
}

impl PlanRefusalRecord {
    /// The atom names the diff carries, in diff order.
    pub fn atom_names(&self) -> Vec<&str> {
        self.diff.iter().map(|d| d.atom.as_str()).collect()
    }
}

// ---------------------------------------------------------------------------------------
// The touched-atom exposure key: the `SEND_AUTHORIZED` payload's whole cargo
// ---------------------------------------------------------------------------------------

/// The effect direction, where direction matters: which way the forward action moves the
/// atom. Derived from the operation's admission-frozen `atom_targets`, the value the atom
/// holds after the action applies.
///
/// `Unknown` is a real member, not a hole: a basis admitted before directional targets were
/// captured parses with an empty `atom_targets` (serde default), and the honest record of that
/// is "we do not know the direction", never a guessed `Clear`. An unknown direction is the most
/// conservative possible input, because this build holds no risk-acceptance capability and
/// every overlap refuses whatever the directions are (see [`ExposureKey`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExposureDirection {
    /// The action leaves the atom TRUE (e.g. adds the label, sets the keyword).
    Set,
    /// The action leaves the atom FALSE (e.g. removes the label, the archive verb).
    Clear,
    /// The frozen basis carries no target for this atom (an older row).
    Unknown,
}

impl ExposureDirection {
    /// The durable spelling: the `exposure_obligation.direction` column's token.
    pub fn as_sql(&self) -> &'static str {
        match self {
            ExposureDirection::Set => "set",
            ExposureDirection::Clear => "clear",
            ExposureDirection::Unknown => "unknown",
        }
    }

    /// The inverse; `None` for a spelling this build never wrote (the same shape
    /// [`AttemptClass::from_sql`] has), so a stored token nobody wrote fails explicitly at the
    /// reader rather than defaulting into a direction.
    pub fn from_sql(s: &str) -> Option<ExposureDirection> {
        [
            ExposureDirection::Set,
            ExposureDirection::Clear,
            ExposureDirection::Unknown,
        ]
        .into_iter()
        .find(|d| d.as_sql() == s)
    }
}

/// One primitive touched atom: the atom's identity (resource-scoped) plus the direction the
/// effect moves it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct ExposureAtom {
    /// The atom identity: [`exposure_atom_key`] over the frozen native resource key and the
    /// primitive atom name. Opaque above that function: compared and joined on, never parsed
    /// apart.
    pub atom_key: String,
    /// Which way the effect moves it.
    pub direction: ExposureDirection,
}

/// The touched-atom exposure key: derived from the operation's admission-frozen basis and
/// copied into the attempt's `SEND_AUTHORIZED` fact payload, never re-resolved and never read
/// from the `pre_state` row (capture-off operations legally have no journal row, and the check
/// must still reach them).
///
/// Content-free: an account handle, provider-native identities, and the engine's own atom
/// vocabulary; no bodies, subjects or headers.
///
/// **What the exposure check does with it.** It asks whether any unretired
/// `exposure_obligation` row overlaps these atoms, and refuses on any overlap, same-direction
/// or opposite. The direction would select which risk acceptance has to cover the overlap, and
/// this build has no risk-acceptance capability, so every overlap refuses and reading the
/// direction to choose between two refusals would be decoration. It is recorded because the
/// obligation rows are keyed by it and an acceptance feature will need it.
///
/// **The scope is the provider's, never the local alias.** An obligation is keyed by the
/// account/provider scope plus the provider-native primitive touched atom, derived from the
/// operation's immutable frozen basis and never from a re-resolved local alias. If this type
/// carried the Photon-local `Command::account` handle, two local handles resolving to one
/// provider account would produce the same `atom_key` under different `account` values, the
/// join would miss the live obligation, and the overlapping wire effect would be authorized.
/// The local handle is absent from this type: [`ExposureKey::from_basis`] takes only the
/// frozen basis, so no channel exists through which an alias could re-enter.
///
/// The provider scope is not a second join column: [`exposure_atom_key`] is built over
/// `FrozenBasis::native_resource_key`, which every connector constructs from the provider's
/// own identity vector (`jmap:[<provider account id>, <email id>]`,
/// `gmail:[<user id>, <message id>]`) through the crate's one injective encoding. The atom key
/// is therefore fully provider-scoped and the check joins on it alone. `provider_scope` is
/// recorded (it is the obligation row's own scope column) and is never a check input.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ExposureKey {
    /// The account/provider scope as the operation's frozen basis states it: the
    /// provider-native resource key (provider tag plus the provider's own account/resource
    /// identities). Durable audit scope, never a join column and never a local alias.
    pub provider_scope: String,
    /// Every primitive touched atom, sorted by `atom_key` (canonical: the same basis always
    /// produces the same key, so two derivations can be compared for equality).
    pub atoms: Vec<ExposureAtom>,
}

impl ExposureKey {
    /// Derive the key from an operation's admission-frozen basis. This is the one derivation,
    /// so no caller can hand the check a key of its own construction, and the only input is the
    /// frozen provider identity.
    ///
    /// `touched_atoms` supplies the atom set and `atom_targets` the direction; an atom with no
    /// target is [`ExposureDirection::Unknown`] rather than a default.
    pub fn from_basis(basis: &crate::prestate::FrozenBasis) -> ExposureKey {
        let mut atoms: Vec<ExposureAtom> = basis
            .touched_atoms
            .keys()
            .map(|atom| ExposureAtom {
                atom_key: exposure_atom_key(&basis.native_resource_key, atom),
                direction: match basis.atom_targets.get(atom) {
                    Some(true) => ExposureDirection::Set,
                    Some(false) => ExposureDirection::Clear,
                    None => ExposureDirection::Unknown,
                },
            })
            .collect();
        atoms.sort();
        atoms.dedup();
        ExposureKey {
            provider_scope: basis.native_resource_key.clone(),
            atoms,
        }
    }

    /// The key of a legacy operation (NULL `frozen_basis`): it names no provider-native atoms,
    /// so there is nothing an obligation could be intersected with, and it names no provider
    /// scope either (the empty string is the honest absence, not a stand-in local handle).
    ///
    /// The check is vacuous for such a row. Legacy rows are already an open-time integrity
    /// finding (`FrozenBasisMissing`), and deciding to stop dispatching that generation is the
    /// scan's call at admission grain, not a wire check's on a row it can say nothing true
    /// about.
    pub fn legacy_unscoped() -> ExposureKey {
        ExposureKey {
            provider_scope: String::new(),
            atoms: Vec::new(),
        }
    }
}

/// The atom identity: the frozen native resource key joined to the primitive atom name
/// through the crate's one injective encoding ([`crate::prestate::native_resource_key`]).
///
/// **Why the resource scope is part of it.** `touched_atoms` keys are per-resource by context,
/// not by spelling: `membership:INBOX` names "this message's INBOX membership" only because
/// the basis it lives in names the message. Keying an obligation on the bare atom would let an
/// unresolved exposure on one message gate every other message's INBOX mutation.
///
/// **Why that encoding and not a delimiter.** Provider ids are opaque; joining two opaque
/// strings with a separator is not injective, and this key is compared and joined on by string
/// equality. `native_resource_key` already solves that problem.
pub fn exposure_atom_key(native_resource_key: &str, primitive_atom: &str) -> String {
    crate::prestate::native_resource_key(
        "photon.exposure-atom.v1",
        &[native_resource_key, primitive_atom],
    )
}

/// What the exposure check refused, as the refusing transaction recorded it: the payload of a
/// `FAILED_PRE_SEND` the check wrote.
///
/// It is a struct because the two identities of the same refusal have different confinement
/// rules:
///
/// * `atom_key` is [`exposure_atom_key`]'s encoding of a frozen `native_resource_key` and a
///   primitive atom name, i.e. provider identifiers (a user/account, a message, a mailbox).
///   The crate's confinement discipline covers provider-native identifiers too, not only
///   content (see `crate::jmap`'s `no_provider_ids_leak_into_surfaced_errors`). So this half
///   stays durable-internal (audit, the join key, the operator's own store) and never crosses
///   the caller-facing error boundary.
/// * `obligation_id` is the engine-minted opaque row id of the blocking `exposure_obligation`
///   (the same `mint_opaque_id` shape as an adjudication record or a sever record). It is
///   Photon-local, carries nothing of the provider's, and is what the caller is told: a
///   reference an operator resolves through [`crate::IntentLog::exposure_obligation`] to the
///   obligation's contributor, generation, age and retirement.
///
/// Both halves live in the same durable payload so a dispatching call and an identical replay
/// read one fact and cannot disagree, and one writer writes both at once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExposureBlock {
    /// The atom identity that refused. **Internal**: provider-native, never surfaced.
    pub atom_key: String,
    /// The blocking obligation's engine-minted opaque row id. **The surfaceable half.**
    pub obligation_id: String,
}

// ---------------------------------------------------------------------------------------
// Adjudication vocabulary: closed, durable, content-free
// ---------------------------------------------------------------------------------------

/// The declared unknown-age threshold (`unknown_review_after`, default 7 days).
///
/// It surfaces long-ambiguous attempts for a human decision (`IntentLog::unknown_review`) and
/// never auto-decides. It is a constant rather than an `engine_config` row, like
/// [`crate::prestate::UNDO_OFFER_SECONDS`]: it is a decision-surfacing horizon, not an
/// admission-time provenance binding, so no operation needs to record the generation it was
/// admitted under. Changing the threshold changes only which rows a report lists.
///
/// The methods take it as an argument (a report cannot be written against a horizon it cannot
/// vary), and this is the value the engine passes.
pub const UNKNOWN_REVIEW_AFTER_SECONDS: u64 = 604_800; // 7 days

/// The closed reason vocabulary for adjudication. No free text exists anywhere on this path:
/// a pasted excerpt would durably store mailbox content while deletion is dormant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdjudicationReason {
    /// The operator abandons the unresolved attempt: no further evidence is expected.
    OperatorAbandonedUnresolved,
    /// The transport is presumed to have lost the request or its answer.
    PresumedTransportLoss,
    /// A newer user instruction supersedes the unresolved one.
    SupersedingUserInstruction,
    /// The unknown is closed to recover capacity (in place, net -1).
    CapacityRecovery,
}

impl AdjudicationReason {
    /// Every reason, for the round-trip guard.
    pub const ALL: [AdjudicationReason; 4] = [
        AdjudicationReason::OperatorAbandonedUnresolved,
        AdjudicationReason::PresumedTransportLoss,
        AdjudicationReason::SupersedingUserInstruction,
        AdjudicationReason::CapacityRecovery,
    ];

    /// The durable spelling: the `adjudication_record.reason` CHECK constraint's token.
    pub fn as_sql(&self) -> &'static str {
        match self {
            AdjudicationReason::OperatorAbandonedUnresolved => "operator-abandoned-unresolved",
            AdjudicationReason::PresumedTransportLoss => "presumed-transport-loss",
            AdjudicationReason::SupersedingUserInstruction => "superseding-user-instruction",
            AdjudicationReason::CapacityRecovery => "capacity-recovery",
        }
    }

    /// The inverse; `None` for a spelling this build never wrote.
    pub fn from_sql(s: &str) -> Option<AdjudicationReason> {
        AdjudicationReason::ALL.iter().copied().find(|r| r.as_sql() == s)
    }
}

/// The closed accepted-risk vocabulary.
///
/// **Recorded, never honored: this build ships no acceptance capability.** With none, the
/// exposure check refuses every overlap, so [`AcceptedRisk::DuplicateEffectPossible`] and
/// [`AcceptedRisk::ReversalPossible`] authorize exactly as much as
/// [`AcceptedRisk::NoneClaimed`] does: nothing. The vocabulary is durable now so the
/// adjudicator's stated posture is on the record when the capability lands. Do not read this
/// type as a permission bit (see `IntentLog::adjudicate`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptedRisk {
    /// The adjudicator states a duplicate effect may result from closing this unknown.
    DuplicateEffectPossible,
    /// The adjudicator states a reversal may result.
    ReversalPossible,
    /// No risk is claimed. `none-claimed` authorizes no overlap, and in this build neither
    /// does anything else.
    NoneClaimed,
}

impl AcceptedRisk {
    /// Every value, for the round-trip guard.
    pub const ALL: [AcceptedRisk; 3] = [
        AcceptedRisk::DuplicateEffectPossible,
        AcceptedRisk::ReversalPossible,
        AcceptedRisk::NoneClaimed,
    ];

    /// The durable spelling: the `adjudication_record.accepted_risk` CHECK constraint's token.
    pub fn as_sql(&self) -> &'static str {
        match self {
            AcceptedRisk::DuplicateEffectPossible => "duplicate-effect-possible",
            AcceptedRisk::ReversalPossible => "reversal-possible",
            AcceptedRisk::NoneClaimed => "none-claimed",
        }
    }

    /// The inverse; `None` for a spelling this build never wrote.
    pub fn from_sql(s: &str) -> Option<AcceptedRisk> {
        AcceptedRisk::ALL.iter().copied().find(|r| r.as_sql() == s)
    }
}

/// The polarity of a post-adjudication late ack: the two whitelisted resolutions of the
/// historical axis. A typed pair rather than a raw [`FactKind`], so a caller cannot hand the
/// late-ack path a `Claim`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LateAck {
    /// The effect provably happened after all: `LATE_ACK_APPLIED`.
    Applied,
    /// The provider provably refused before any effect: `LATE_ACK_REFUSED_NO_EFFECT`.
    RefusedNoEffect,
}

impl LateAck {
    /// The fact kind this polarity appends.
    pub fn fact_kind(&self) -> FactKind {
        match self {
            LateAck::Applied => FactKind::LateAckApplied,
            LateAck::RefusedNoEffect => FactKind::LateAckRefusedNoEffect,
        }
    }

    /// The historical attribution this polarity resolves the axis to.
    pub fn attribution(&self) -> HistoricalAttribution {
        match self {
            LateAck::Applied => HistoricalAttribution::Applied,
            LateAck::RefusedNoEffect => HistoricalAttribution::RefusedNoEffect,
        }
    }
}

/// The closed annotation vocabulary of the `adjudication_annotation` ledger: the durable home
/// for the facts that must never be silent.
///
/// It is a ledger and not a column because `adjudication_record` is immutable by trigger, and
/// both facts become true strictly after the record is written. An append-only sibling keyed
/// by `adjudication_id` records them on the adjudication record without making the record
/// itself rewritable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnomalyKind {
    /// A second, contradictory late ack is refused, and the contradiction is durably recorded
    /// as an anomaly annotation on the adjudication record.
    ContradictoryLateAck,
    /// The half-trace: a same-atom effect resolved APPLIED while this exposure was still
    /// unresolved. Not yet a materialization (the other axis is still `UNKNOWN`); it is the
    /// durable half, so that whichever order the second APPLIED arrives in, the notice below is
    /// decidable from the records alone.
    AppliedOverUnresolved,
    /// If later attribution establishes that an accepted duplicate/reversal risk actually
    /// materialized (including the multi-contributor trace where two same-atom effects both
    /// resolve APPLIED), a durable notice exists.
    ExposureMaterialized,
    /// A late non-definitive observation lives in the adjudication record's ancillary audit
    /// trail, never the closed grammar.
    ///
    /// The whitelist rightly refuses an `ACK_AMBIGUOUS` on an adjudicated chain, since it
    /// resolves nothing and the operational axis is closed. But the refusal is not a store
    /// incident and the observation is not nothing: an operator adjudicating while a dispatch
    /// is in flight is a legal race, and the provider's indeterminate answer arriving
    /// afterwards is a fact about the world. Nothing decides on it, which is why it is an
    /// annotation and not a fact.
    LateAmbiguousObservation,
}

impl AnomalyKind {
    /// Every kind, for the round-trip guard.
    pub const ALL: [AnomalyKind; 4] = [
        AnomalyKind::ContradictoryLateAck,
        AnomalyKind::AppliedOverUnresolved,
        AnomalyKind::ExposureMaterialized,
        AnomalyKind::LateAmbiguousObservation,
    ];

    /// The durable spelling: the `adjudication_annotation.kind` CHECK constraint's token.
    pub fn as_sql(&self) -> &'static str {
        match self {
            AnomalyKind::ContradictoryLateAck => "contradictory-late-ack",
            AnomalyKind::AppliedOverUnresolved => "applied-over-unresolved",
            AnomalyKind::ExposureMaterialized => "exposure-materialized",
            AnomalyKind::LateAmbiguousObservation => "late-ambiguous-observation",
        }
    }

    /// The inverse; `None` for a spelling this build never wrote.
    pub fn from_sql(s: &str) -> Option<AnomalyKind> {
        AnomalyKind::ALL.iter().copied().find(|k| k.as_sql() == s)
    }
}

/// The typed payload of a fact. Shape and kind must agree: [`append_legal`] refuses a mismatch
/// at the door (the grammar never reads a field the kind does not promise).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FactPayload {
    /// `Claim`: the attempt ordinal plus, for ordinal > 1, the mandatory predecessor/reason.
    Claim {
        /// 1-based attempt ordinal within the owning operation (`UNIQUE (operation_id,
        /// attempt_ordinal)` is the SQL half).
        ordinal: u64,
        /// `None` iff `ordinal == 1`.
        predecessor: Option<RetryPredecessor>,
    },
    /// `SendAuthorized`: the touched-atom exposure key copied from the frozen basis after
    /// verification, never re-resolved and never read from the journal row.
    ///
    /// It carries nothing else, deliberately. An earlier staging carried a `dispatch_episode`
    /// field so the boundary could tell an equally current peer (which must lose the wire) from
    /// a genuine next-episode retry (which must not be strangled), while a retry re-entered the
    /// attempt it had already claimed. Every retry now claims a fresh attempt with its own
    /// `CLAIM`, so the strict rule holds: at most one `SEND_AUTHORIZED` per attempt, decided by
    /// the grammar alone with no counter to consult. The field was deleted rather than left
    /// inert, because an unused escape hatch in a guard is still an escape hatch.
    SendAuthorized {
        /// Content-free exposure key: the account scope plus every touched primitive atom with
        /// its effect direction ([`ExposureKey`]).
        exposure_key: ExposureKey,
    },
    /// `FailedPreSend`: the connector's wire evidence, plus which pre-send truth this is.
    FailedPreSend {
        /// `ProvenNoWire` is the only thing that makes a post-auth `FailedPreSend` legal.
        wire_evidence: WireEvidence,
        /// Why the attempt closed before issuance: a closed vocabulary, never free text.
        reason: PreSendReason,
        /// What the exposure check refused, when that is what closed this attempt. `None` for
        /// every other pre-send close.
        ///
        /// It is a field and not a `PreSendReason` member because the reason vocabulary is
        /// closed and answers "which pre-send truth is this", which decides the operation's
        /// lifecycle. An exposure block is an ordinary [`PreSendReason::Failure`] on that axis
        /// (the retry taxonomy's treatment is unchanged) and differs only in carrying evidence,
        /// which is variable-width and would make a closed enum non-`Copy` and its vocabulary
        /// unbounded.
        ///
        /// Durable-internal; its two halves are surfaced differently (see [`ExposureBlock`]).
        /// It has one writer (the exposure check in `IntentLog::authorize_send`, in both
        /// implementations) and one reader ([`crate::IntentLog::exposure_block`]), so nothing
        /// infers or reconstructs it.
        exposure_block: Option<ExposureBlock>,
        /// What the plan-admission arm refused, when that is what closed this attempt. `None`
        /// for every other pre-send close, and for every older row (the decoder reads a missing
        /// key and `null` alike as `None`). See [`PlanRefusalRecord`].
        plan_refusal: Option<PlanRefusalRecord>,
    },
    /// `ReconcileStateMatches` / `ReconcileStateDiffers`: the opaque observation token. The
    /// changed-only rule compares `(kind, observation)` for equality and nothing else.
    Reconcile {
        /// A content-free canonical observation token (compared, never parsed).
        observation: String,
    },
    /// `AdjudicatedUnresolved`: the immutable FK into `adjudication_record`.
    Adjudicated {
        /// The record's engine-minted id.
        adjudication_id: String,
    },
    /// `SupersededBy`: the successor operation (not attempt) this adjudicated attempt hands off
    /// to; acyclic, at most one.
    SupersededBy {
        /// The successor operation's id.
        successor_operation_id: String,
    },
    /// Every kind whose payload carries nothing the grammar reads: the acks, the ambiguous
    /// verdict, `SeveredBeforeIssuance`, and the late acks. (Ack detail is a store-side
    /// concern; the grammar's decisions do not depend on it.)
    None,
}

impl FactPayload {
    /// Does this payload shape match the kind that carries it?
    fn matches(&self, kind: FactKind) -> bool {
        matches!(
            (kind, self),
            (FactKind::Claim, FactPayload::Claim { .. })
                | (FactKind::SendAuthorized, FactPayload::SendAuthorized { .. })
                | (FactKind::FailedPreSend, FactPayload::FailedPreSend { .. })
                | (FactKind::ReconcileStateMatches, FactPayload::Reconcile { .. })
                | (FactKind::ReconcileStateDiffers, FactPayload::Reconcile { .. })
                | (FactKind::AdjudicatedUnresolved, FactPayload::Adjudicated { .. })
                | (FactKind::SupersededBy, FactPayload::SupersededBy { .. })
                | (FactKind::AckApplied, FactPayload::None)
                | (FactKind::AckRefusedNoEffect, FactPayload::None)
                | (FactKind::AckAmbiguous, FactPayload::None)
                | (FactKind::SeveredBeforeIssuance, FactPayload::None)
                | (FactKind::LateAckApplied, FactPayload::None)
                | (FactKind::LateAckRefusedNoEffect, FactPayload::None)
        )
    }
}

/// One row of `attempt_fact`, as a value. The store maps this to/from SQL; the grammar only
/// ever sees this.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fact {
    /// The immutable owner, identical on every fact of the attempt.
    pub operation_id: String,
    /// The attempt's opaque id, minted at the `Claim`.
    pub attempt_id: String,
    /// `UNIQUE (attempt_id, revision)`; 1-based, contiguous.
    pub revision: u64,
    /// Which of the 13.
    pub kind: FactKind,
    /// The `control_epoch` this fact was written under.
    pub basis_epoch: i64,
    /// The clamped-monotonic occurrence timestamp ([`clamped_now`] produced it).
    pub created_at: String,
    /// Typed per kind.
    pub payload: FactPayload,
    /// The revision this fact was appended against — `None` only for the first fact.
    pub prior_revision: Option<u64>,
}

// ---------------------------------------------------------------------------------------
// The two-axis state
// ---------------------------------------------------------------------------------------

/// The historical attribution axis: what we can truthfully say about the wire effect.
/// `Unknown` is a permanent, honest answer, not a placeholder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoricalAttribution {
    /// No definitive knowledge. ISSUANCE_UNKNOWN lives here.
    Unknown,
    /// The effect provably happened.
    Applied,
    /// The provider provably refused before any effect.
    RefusedNoEffect,
    /// No effect exists (pre-auth failure, or post-auth with proven-no-wire).
    FailedPreSend,
    /// A sever caught the attempt before any authorization existed.
    SeveredBeforeIssuance,
}

/// The operational axis: is this attempt still a live thing the engine is waiting on? Closed
/// by a terminal attribution or by adjudication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationalAxis {
    /// Still live.
    Active,
    /// Settled operationally, whatever the historical axis says.
    Closed,
}

/// The derived class of an attempt (the `attempt_head.derived_class` column).
///
/// Note the grain: `NO_ACTIVE_ATTEMPT` is an operation-grain class and is deliberately not a
/// variant here, since an attempt that does not exist has no class. The sever's
/// operation-grain partition belongs over the store; this module owns the per-attempt half.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptClass {
    /// Claimed, never authorized. A sever classifies this `SEVERED_BEFORE_ISSUANCE`.
    PreIssuance,
    /// Authorized, no terminal attribution: we cannot prove issuance either way.
    IssuedOrUnknown,
    /// Terminal attribution `ACK_APPLIED`.
    TerminalApplied,
    /// Terminal attribution `ACK_REFUSED_NO_EFFECT`.
    TerminalRefusedNoEffect,
    /// Terminal attribution `FAILED_PRE_SEND`.
    TerminalFailedPreSend,
    /// Terminal attribution `SEVERED_BEFORE_ISSUANCE`.
    TerminalSeveredBeforeIssuance,
    /// Operationally closed by adjudication with the historical axis still open ("unknown at
    /// decision time" is not "unknown forever": a `LATE_ACK_*` may still resolve it).
    AdjudicatedHistoricalOpen,
}

impl AttemptClass {
    /// Every class, for the round-trip guard.
    pub const ALL: [AttemptClass; 7] = [
        AttemptClass::PreIssuance,
        AttemptClass::IssuedOrUnknown,
        AttemptClass::TerminalApplied,
        AttemptClass::TerminalRefusedNoEffect,
        AttemptClass::TerminalFailedPreSend,
        AttemptClass::TerminalSeveredBeforeIssuance,
        AttemptClass::AdjudicatedHistoricalOpen,
    ];

    /// The spelling persisted in `attempt_head.derived_class`.
    pub fn as_sql(&self) -> &'static str {
        match self {
            AttemptClass::PreIssuance => "pre_issuance",
            AttemptClass::IssuedOrUnknown => "issued_or_unknown",
            AttemptClass::TerminalApplied => "applied",
            AttemptClass::TerminalRefusedNoEffect => "refused_no_effect",
            AttemptClass::TerminalFailedPreSend => "failed_pre_send",
            AttemptClass::TerminalSeveredBeforeIssuance => "severed_before_issuance",
            AttemptClass::AdjudicatedHistoricalOpen => "adjudicated_unresolved",
        }
    }

    /// The inverse; `None` for a spelling this build never wrote.
    pub fn from_sql(s: &str) -> Option<AttemptClass> {
        AttemptClass::ALL.iter().copied().find(|c| c.as_sql() == s)
    }

    /// Does this class name a chain the grammar can never be appended to again?
    ///
    /// True exactly for the four terminal-attribution classes, matching [`append_legal`]'s
    /// rule 4: both axes closed by a terminal attribution, and no whitelist was ever opened, so
    /// nothing may follow. The two cannot come apart because they read the same two fields:
    /// [`DerivedState::class`] returns a `Terminal*` variant only when `terminal_attribution` is
    /// `Some`, and an adjudication can neither precede a terminal attribution (rule 4 refuses
    /// it) nor follow one (rule 3's post-adjudication whitelist admits no `ACK_*`), so a
    /// `Terminal*` class also proves `adjudication_id` is `None`.
    ///
    /// `AdjudicatedHistoricalOpen` is deliberately false: the operational axis is closed, but
    /// the historical one is open and so is the whitelist, so a `LATE_ACK_*` or a
    /// `SUPERSEDED_BY` may still land. It is a live chain for every purpose that asks.
    ///
    /// Its caller is the boot quarantine's head scan: a head in this set whose verified
    /// watermark already equals its current revision has nothing left to verify and nothing
    /// that could change it.
    pub fn is_terminally_attributed(self) -> bool {
        match self {
            AttemptClass::TerminalApplied
            | AttemptClass::TerminalRefusedNoEffect
            | AttemptClass::TerminalFailedPreSend
            | AttemptClass::TerminalSeveredBeforeIssuance => true,
            AttemptClass::PreIssuance
            | AttemptClass::IssuedOrUnknown
            | AttemptClass::AdjudicatedHistoricalOpen => false,
        }
    }
}

/// The ownership identity established by the one `Claim` fact, immutable for the life of the
/// attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimIdentity {
    /// The owning operation (exactly one owner).
    pub operation_id: String,
    /// The attempt's opaque id.
    pub attempt_id: String,
    /// 1-based ordinal within the operation.
    pub ordinal: u64,
    /// The retry lineage, `Some` iff `ordinal > 1`.
    pub predecessor: Option<RetryPredecessor>,
    /// The epoch the claim was taken under (the store's retry-eligibility check compares it to
    /// the current `control_epoch`; the pure core only records it).
    pub claim_epoch: i64,
}

/// Configuration bounds the grammar itself enforces, threaded explicitly rather than read
/// from a global: a pure core has no ambient configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrammarLimits {
    /// The lifetime reconcile cap (config, default 32). Hitting it surfaces the attempt for
    /// adjudication immediately; post-cap changed observations land in the explicitly
    /// non-authoritative `last_observation` projection column, never in the fact chain (so the
    /// fold's input stays bounded).
    pub reconcile_lifetime_cap: u32,
    /// The reconcile cadence bound (config, default 1h): the minimum interval between two
    /// `RECONCILE_*` facts on one attempt.
    ///
    /// It is separate from the changed-only rule, and neither implies the other. Changed-only
    /// bounds repetition and the lifetime cap bounds the total, but neither bounds the rate: a
    /// provider flapping between two observations produces an unbounded stream of genuinely
    /// changed facts, all legal, as fast as a caller can poll, and the cap would then surface
    /// the attempt for adjudication in seconds rather than describing a real divergence.
    ///
    /// The floor is 60 seconds and is enforced at construction ([`GrammarLimits::new`]): the
    /// value a pure core is handed must already be a legal one.
    pub reconcile_min_interval_seconds: u64,
}

/// Why [`GrammarLimits::new`] refused a configuration (an illegal bound never becomes a
/// `GrammarLimits`, so no rule downstream has to re-check it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrammarLimitsRefusal {
    /// The reconcile cadence is below the 60-second floor.
    ReconcileIntervalBelowFloor {
        seconds: u64,
        floor: u64,
    },
}

impl fmt::Display for GrammarLimitsRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl GrammarLimits {
    /// The declared floor for the reconcile cadence: a configuration below it is refused
    /// rather than clamped, since a silently widened bound is a bound nobody can audit.
    pub const RECONCILE_MIN_INTERVAL_FLOOR_SECONDS: u64 = 60;

    /// The design's declared defaults.
    pub const DEFAULT: GrammarLimits = GrammarLimits {
        reconcile_lifetime_cap: 32,
        reconcile_min_interval_seconds: 3600,
    };

    /// The constructor for a non-default configuration, and the only place the cadence floor is
    /// checked, so a `GrammarLimits` value in hand is already legal.
    pub fn new(
        reconcile_lifetime_cap: u32,
        reconcile_min_interval_seconds: u64,
    ) -> Result<GrammarLimits, GrammarLimitsRefusal> {
        if reconcile_min_interval_seconds < Self::RECONCILE_MIN_INTERVAL_FLOOR_SECONDS {
            return Err(GrammarLimitsRefusal::ReconcileIntervalBelowFloor {
                seconds: reconcile_min_interval_seconds,
                floor: Self::RECONCILE_MIN_INTERVAL_FLOOR_SECONDS,
            });
        }
        Ok(GrammarLimits {
            reconcile_lifetime_cap,
            reconcile_min_interval_seconds,
        })
    }
}

impl Default for GrammarLimits {
    fn default() -> Self {
        GrammarLimits::DEFAULT
    }
}

/// The pure fold of an attempt's fact chain: derived state is a pure fold over the chain, and
/// nothing mutates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedState {
    /// `None` before the `Claim` — the only state in which a `Claim` is legal.
    pub claim: Option<ClaimIdentity>,
    /// The chain's current revision (0 = no facts yet).
    pub current_revision: u64,
    /// Has the epoch-fenced `SendAuthorized` committed?
    pub send_authorized: bool,
    /// The exposure key copied into the `SendAuthorized` payload, if any.
    pub exposure_key: Option<ExposureKey>,
    /// The ONE terminal-attribution fact, if any.
    pub terminal_attribution: Option<FactKind>,
    /// The HISTORICAL axis.
    pub historical: HistoricalAttribution,
    /// The OPERATIONAL axis.
    pub operational: OperationalAxis,
    /// Has the (at most one) `AckAmbiguous` been recorded?
    pub ambiguous_recorded: bool,
    /// Lifetime count of `Reconcile*` facts (the cap's counter).
    pub reconcile_count: u32,
    /// The last recorded `(kind, observation)` pair — the changed-only rule's baseline.
    pub last_reconcile: Option<(FactKind, String)>,
    /// `created_at` of the last recorded `Reconcile*` fact, the cadence bound's baseline.
    /// Canonical RFC 3339 UTC, like every instant this grammar folds, so the comparison
    /// against it stays lexicographic.
    pub last_reconcile_at: Option<String>,
    /// The adjudication record FK, if the operational axis was closed by adjudication.
    pub adjudication_id: Option<String>,
    /// The (at most one) post-adjudication late ack.
    pub late_ack: Option<FactKind>,
    /// The (at most one) successor operation link.
    pub superseded_by: Option<String>,
}

impl DerivedState {
    /// The pre-`Claim` state: the fold's identity element, and the only state in which a
    /// `Claim` is legal. One spelling, shared with [`FoldBaseline::PRISTINE`].
    pub fn empty() -> DerivedState {
        PRISTINE_STATE.clone()
    }

    /// The derived class for the head projection. `None` before the `Claim` (an attempt that
    /// has not been claimed has no class; see [`AttemptClass`]'s grain note).
    pub fn class(&self) -> Option<AttemptClass> {
        self.claim.as_ref()?;
        Some(match self.terminal_attribution {
            Some(FactKind::AckApplied) => AttemptClass::TerminalApplied,
            Some(FactKind::AckRefusedNoEffect) => AttemptClass::TerminalRefusedNoEffect,
            Some(FactKind::FailedPreSend) => AttemptClass::TerminalFailedPreSend,
            Some(FactKind::SeveredBeforeIssuance) => AttemptClass::TerminalSeveredBeforeIssuance,
            // `is_terminal_attribution` is the authority for what can land here; anything else
            // would be a fold defect, not a class.
            Some(_) | None => {
                if self.adjudication_id.is_some() {
                    AttemptClass::AdjudicatedHistoricalOpen
                } else if self.send_authorized {
                    AttemptClass::IssuedOrUnknown
                } else {
                    AttemptClass::PreIssuance
                }
            }
        })
    }

    /// How a sever classifies this attempt as an `AttemptMember`. `None` when the attempt is
    /// not a live member: a terminal or adjudicated attempt's operation classifies at operation
    /// grain (COMPLETED means absent from the evidence, or `OperationMember` if the operation is
    /// still active).
    pub fn witness_class_at_sever(&self) -> Option<WitnessClass> {
        match self.class()? {
            AttemptClass::PreIssuance => Some(WitnessClass::SeveredBeforeIssuance),
            AttemptClass::IssuedOrUnknown => Some(WitnessClass::IssuedOrUnknown),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------------------
// Refusals and defects
// ---------------------------------------------------------------------------------------

/// Why the closed grammar refuses an append. Every variant is a design rule; the store maps
/// this to its `RefusedByGrammar(reason)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrammarRefusal {
    /// The payload shape does not match the kind that carries it.
    PayloadKindMismatch {
        kind: FactKind,
    },
    /// Any fact other than `Claim` on an unclaimed chain.
    FactBeforeClaim {
        kind: FactKind,
    },
    /// "exactly one `CLAIM` per attempt".
    DuplicateClaim,
    /// Ordinals are 1-based.
    ClaimOrdinalZero,
    /// "ordinal 1 carries NO predecessor".
    FirstOrdinalCarriesPredecessor,
    /// "every ordinal > 1 carries exactly one (predecessor_attempt_id, reason)".
    RetryOrdinalMissingPredecessor {
        ordinal: u64,
    },
    /// "at most one `SEND_AUTHORIZED`".
    DuplicateSendAuthorized,
    /// `ACK_APPLIED`/`ACK_REFUSED_NO_EFFECT`/`ACK_AMBIGUOUS` before authorization (`CLAIM →
    /// ACK_APPLIED` would classify an unsent operation as completed).
    AckWithoutSendAuthorization {
        kind: FactKind,
    },
    /// `SEVERED_BEFORE_ISSUANCE` is legal only when no `SEND_AUTHORIZED` exists.
    SeveredAfterSendAuthorization,
    /// A post-auth `FAILED_PRE_SEND` without the connector's positive no-wire proof: an
    /// unproven post-auth failure remains ISSUANCE_UNKNOWN.
    FailedPreSendPostAuthWithoutProvenNoWire,
    /// "AT MOST one `ACK_AMBIGUOUS` per attempt".
    DuplicateAckAmbiguous,
    /// `Reconcile*` before authorization.
    ReconcileWithoutSendAuthorization,
    /// The changed-only rule: an observation identical to the last recorded one.
    ReconcileObservationUnchanged,
    /// The lifetime cap — the attempt surfaces for adjudication instead.
    ReconcileLifetimeCapReached {
        cap: u32,
    },
    /// The cadence bound: this `RECONCILE_*` is earlier than the last one plus the configured
    /// minimum interval.
    ReconcileTooSoon {
        /// The earliest instant a next reconcile may carry (canonical RFC 3339 UTC), or the
        /// empty string when the arithmetic could not be performed on the stored values: a
        /// fail-closed refusal, never an accepted append over an instant nobody can order.
        earliest: String,
    },
    /// "adjudication likewise operates only on a send-authorized unresolved attempt".
    AdjudicationWithoutSendAuthorization,
    /// Anything at all after a terminal attribution (both axes closed, no whitelist).
    PostTerminalAppend {
        kind: FactKind,
        terminal: FactKind,
    },
    /// The post-adjudication whitelist: only `LATE_ACK_*` and `SUPERSEDED_BY` may follow.
    PostAdjudicationWhitelistViolation {
        kind: FactKind,
    },
    /// A `LATE_ACK_*` on a chain that was never adjudicated.
    LateAckWithoutAdjudication {
        kind: FactKind,
    },
    /// A second late ack of the same polarity: at most one `LATE_ACK_*`.
    DuplicateLateAck {
        existing: FactKind,
    },
    /// A second, contradictory late ack is refused, and the contradiction is durably recorded
    /// as an anomaly annotation on the adjudication record. The refusal is this variant; the
    /// annotation is the store's obligation on seeing it.
    ContradictoryLateAckAnomaly {
        existing: FactKind,
        offered: FactKind,
    },
    /// A `SUPERSEDED_BY` on a chain that was never adjudicated.
    SupersededByWithoutAdjudication,
    /// "at most ONE successor per adjudicated attempt".
    DuplicateSupersededBy,
    /// Acyclicity at the operation grain: an attempt cannot be superseded by its own owner.
    SupersedesOwnOperation,
    /// Retry lineage: the predecessor belongs to a different operation.
    PredecessorOtherOperation,
    /// Retry lineage: an attempt cannot be its own predecessor.
    PredecessorIsSelf,
    /// Retry lineage: the predecessor never took a `Claim`.
    PredecessorUnclaimed,
    /// Retry lineage: the predecessor holds no terminal attribution at all.
    PredecessorNotTerminal,
    /// Retry lineage: the declared reason does not match the predecessor's actual
    /// attribution.
    PredecessorAttributionMismatch {
        /// What the CLAIM declared.
        declared: RetryReason,
        /// What the predecessor's chain actually folds to.
        actual: HistoricalAttribution,
    },
    /// No retry from `ACK_AMBIGUOUS`/`ISSUANCE_UNKNOWN`, ever (adjudication is the only path).
    RetryFromAmbiguity,
    /// "the predecessor … has no other retry successor".
    PredecessorAlreadyHasSuccessor,
    /// "successor ordinal = predecessor ordinal + 1".
    OrdinalNotPredecessorPlusOne {
        predecessor_ordinal: u64,
        offered: u64,
    },
}

impl fmt::Display for GrammarRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The Debug spelling is the message: every variant names a design rule, and a
        // hand-written second phrasing would be one more thing to drift.
        write!(f, "{self:?}")
    }
}

/// Why a stored chain does not fold. Distinct from [`GrammarRefusal`]: a refusal says "this
/// append would be illegal", a defect says "what is already persisted is not a legal chain",
/// which is an explicit failure, never a repair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FoldDefect {
    /// No facts at all: an attempt is its chain, and an empty chain is not an attempt.
    EmptyChain,
    /// An incremental baseline claims a revision > 0 but carries no `Claim` (see
    /// [`FoldBaseline`]): revision 1 of every attempt is its claim, so a claimless baseline at
    /// a positive revision is a snapshot no fold of this grammar could have produced.
    BaselineUnclaimed {
        revision: u64,
    },
    /// An incremental baseline at revision > 0 carries a `created_at` anchor that is not what
    /// [`crate::prestate::rfc3339_utc`] emits: the monotonicity comparison against the first
    /// delta fact would be over an unparsed value.
    BaselineNonCanonicalCreatedAt,
    /// The chain's first revision is not 1.
    FirstRevisionNotOne {
        found: u64,
    },
    /// The first fact carries a `prior_revision`.
    FirstFactHasPriorRevision {
        found: u64,
    },
    /// Revisions must be contiguous and ascending (duplicates and reordering land here).
    RevisionNotContiguous {
        index: usize,
        expected: u64,
        found: u64,
    },
    /// The compare-and-append link does not point at the previous revision.
    PriorRevisionMismatch {
        index: usize,
        expected: u64,
        /// The link found (`None` = NULL).
        found: Option<u64>,
    },
    /// The attempt id changed mid-chain — these are not one attempt's facts.
    AttemptIdMismatch {
        index: usize,
    },
    /// The owner changed mid-chain. `operation_id` is the immutable owner.
    OwnerMismatch {
        index: usize,
    },
    /// A persisted `created_at` that is not what [`crate::prestate::rfc3339_utc`] emits: no
    /// stored timestamp participates in any comparison without clearing the shape authority at
    /// its read boundary first.
    NonCanonicalCreatedAt {
        index: usize,
    },
    /// The clamped-monotonic contract is a write-side promise and this is its read-side proof:
    /// a chain whose timestamps go backwards was not written through [`clamped_now`].
    CreatedAtWentBackward {
        index: usize,
    },
    /// A persisted fact the closed grammar would have refused.
    IllegalFact {
        index: usize,
        /// Which rule it broke.
        refusal: GrammarRefusal,
    },
}

impl fmt::Display for FoldDefect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ---------------------------------------------------------------------------------------
// The fold
// ---------------------------------------------------------------------------------------

/// Fold a complete attempt chain into its derived state, under the default limits.
///
/// This is the re-derivation half of the head's safety rule: `head == fold` is asserted on
/// every probe, so this function, not the head row, is the authority.
pub fn fold(facts: &[Fact]) -> Result<DerivedState, FoldDefect> {
    fold_with_limits(facts, &GrammarLimits::DEFAULT)
}

/// [`fold`] with explicit limits (the reconcile lifetime cap is configuration, and a pure core
/// has no ambient configuration).
pub fn fold_with_limits(facts: &[Fact], limits: &GrammarLimits) -> Result<DerivedState, FoldDefect> {
    // An attempt is its chain. An empty chain is not an attempt with unknown state; it is a
    // caller asking about something that does not exist, and saying so is the honest answer (a
    // silently empty `DerivedState` would fold as "unclaimed", a lie a boot-time classifier
    // would act on).
    if facts.is_empty() {
        return Err(FoldDefect::EmptyChain);
    }
    fold_delta_with_limits(&FoldBaseline::PRISTINE, facts, limits)
}

/// A verified starting point for [`fold_delta`]: the incremental-verification watermark
/// (`attempt_head.last_verified_revision` plus `verified_state`), made explicit.
///
/// Without it, a full re-fold of a years-old ISSUANCE_UNKNOWN chain would make boot unbounded;
/// open verifies only the facts appended since the baseline and advances it, O(delta). The
/// baseline is trusted (it was verified when written). This type adds what the delta's first
/// fact must be checked against, so verifying the delta is no weaker than verifying the chain
/// at the seam: contiguity, the compare-and-append link, owner identity and `created_at`
/// monotonicity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FoldBaseline<'a> {
    /// The verified fold state at [`FoldBaseline::revision`].
    pub state: &'a DerivedState,
    /// The revision that state was verified at. `0` = nothing verified yet (a full fold).
    pub revision: u64,
    /// `created_at` of the fact at `revision`, the monotonicity anchor for the first delta
    /// fact. Ignored (and conventionally empty) when `revision == 0`.
    pub created_at: &'a str,
}

impl FoldBaseline<'_> {
    /// The nothing-verified-yet baseline: a full fold from the identity element.
    pub const PRISTINE: FoldBaseline<'static> = FoldBaseline {
        state: &PRISTINE_STATE,
        revision: 0,
        created_at: "",
    };
}

/// Backing storage for [`FoldBaseline::PRISTINE`] (a `const` cannot borrow a temporary).
const PRISTINE_STATE: DerivedState = DerivedState {
    claim: None,
    current_revision: 0,
    send_authorized: false,
    exposure_key: None,
    terminal_attribution: None,
    historical: HistoricalAttribution::Unknown,
    operational: OperationalAxis::Active,
    ambiguous_recorded: false,
    reconcile_count: 0,
    last_reconcile: None,
    last_reconcile_at: None,
    adjudication_id: None,
    late_ack: None,
    superseded_by: None,
};

/// Fold only the facts appended since a verified baseline (the O(delta) open-time
/// verification), under the default limits. An empty delta is legal and yields the baseline
/// unchanged, the steady state of a chain whose finalization already advanced the watermark.
pub fn fold_delta(baseline: &FoldBaseline<'_>, delta: &[Fact]) -> Result<DerivedState, FoldDefect> {
    fold_delta_with_limits(baseline, delta, &GrammarLimits::DEFAULT)
}

/// [`fold_delta`] with explicit limits. [`fold_with_limits`] is this function from
/// [`FoldBaseline::PRISTINE`], one loop, so a full fold and an incremental one cannot enforce
/// different rules.
pub fn fold_delta_with_limits(
    baseline: &FoldBaseline<'_>,
    delta: &[Fact],
    limits: &GrammarLimits,
) -> Result<DerivedState, FoldDefect> {
    // The identity of the chain the delta must belong to. From revision 1 onward that is the
    // `Claim` fact's own owner pair, which is why a positive baseline revision with no claim is
    // a defect rather than a permissive "no anchor to check against".
    let anchor: Option<(&str, &str)> = if baseline.revision == 0 {
        None
    } else {
        match baseline.state.claim.as_ref() {
            Some(claim) => Some((claim.attempt_id.as_str(), claim.operation_id.as_str())),
            None => {
                return Err(FoldDefect::BaselineUnclaimed {
                    revision: baseline.revision,
                })
            }
        }
    };
    if baseline.revision > 0 && !is_canonical_rfc3339_utc(baseline.created_at) {
        return Err(FoldDefect::BaselineNonCanonicalCreatedAt);
    }

    let mut state = baseline.state.clone();
    state.current_revision = baseline.revision;
    // The virtual predecessor: the baseline at the seam, then each fact in turn. One variable,
    // so the seam check and the intra-delta checks are the same code.
    let mut prev: Option<(u64, &str)> = if baseline.revision == 0 {
        None
    } else {
        Some((baseline.revision, baseline.created_at))
    };
    let mut identity: Option<(&str, &str)> = anchor;
    for (index, fact) in delta.iter().enumerate() {
        // A stored timestamp clears the shape authority before it participates in any
        // comparison, including the monotonicity comparison inside the match below.
        if !is_canonical_rfc3339_utc(&fact.created_at) {
            return Err(FoldDefect::NonCanonicalCreatedAt { index });
        }
        match prev {
            None => {
                // The head of a pristine fold: revision 1, no compare-and-append link.
                if fact.revision != 1 {
                    return Err(FoldDefect::FirstRevisionNotOne {
                        found: fact.revision,
                    });
                }
                if let Some(found) = fact.prior_revision {
                    return Err(FoldDefect::FirstFactHasPriorRevision { found });
                }
            }
            Some((previous_revision, previous_created_at)) => {
                // Contiguity is what makes the chain we were handed the same object as the chain
                // that is stored: a gap means a row was withheld, a repeat means one was
                // duplicated, and either way the fold would run over a different history than the
                // one the head claims to project. Reordering lands here too.
                let expected = previous_revision + 1;
                if fact.revision != expected {
                    return Err(FoldDefect::RevisionNotContiguous {
                        index,
                        expected,
                        found: fact.revision,
                    });
                }
                if fact.prior_revision != Some(previous_revision) {
                    return Err(FoldDefect::PriorRevisionMismatch {
                        index,
                        expected: previous_revision,
                        found: fact.prior_revision,
                    });
                }
                if let Some((attempt_id, operation_id)) = identity {
                    if fact.attempt_id != attempt_id {
                        return Err(FoldDefect::AttemptIdMismatch { index });
                    }
                    // The owner is immutable: identical on every fact of the attempt, exactly one
                    // owner. Drift in it is the ambiguity the column exists to remove.
                    if fact.operation_id != operation_id {
                        return Err(FoldDefect::OwnerMismatch { index });
                    }
                }
                // `clamped_now` promises monotonicity on the write side; verifying it on the read
                // side makes the promise checkable rather than assumed. The baseline's anchor
                // cleared the shape authority above, as a fact does.
                if fact.created_at.as_str() < previous_created_at {
                    return Err(FoldDefect::CreatedAtWentBackward { index });
                }
            }
        }
        // The grammar, applied to what is already persisted. A stored fact the append path
        // would have refused is an explicit failure, never a repair: the fold is the authority
        // the head is checked against, so it must not launder a defect into a plausible state.
        append_legal_with_limits(&state, fact, limits)
            .map_err(|refusal| FoldDefect::IllegalFact { index, refusal })?;
        apply(&mut state, fact);
        identity = Some((fact.attempt_id.as_str(), fact.operation_id.as_str()));
        prev = Some((fact.revision, fact.created_at.as_str()));
    }
    Ok(state)
}

/// Apply a fact that has already been judged legal. Infallible: every condition that could
/// fail is a [`GrammarRefusal`], checked before we get here.
fn apply(state: &mut DerivedState, fact: &Fact) {
    state.current_revision = fact.revision;
    match (&fact.kind, &fact.payload) {
        (FactKind::Claim, FactPayload::Claim { ordinal, predecessor }) => {
            state.claim = Some(ClaimIdentity {
                operation_id: fact.operation_id.clone(),
                attempt_id: fact.attempt_id.clone(),
                ordinal: *ordinal,
                predecessor: predecessor.clone(),
                claim_epoch: fact.basis_epoch,
            });
        }
        (FactKind::SendAuthorized, FactPayload::SendAuthorized { exposure_key }) => {
            state.send_authorized = true;
            state.exposure_key = Some(exposure_key.clone());
        }
        (FactKind::AckApplied, _) => {
            state.terminal_attribution = Some(FactKind::AckApplied);
            state.historical = HistoricalAttribution::Applied;
            state.operational = OperationalAxis::Closed;
        }
        (FactKind::AckRefusedNoEffect, _) => {
            state.terminal_attribution = Some(FactKind::AckRefusedNoEffect);
            state.historical = HistoricalAttribution::RefusedNoEffect;
            state.operational = OperationalAxis::Closed;
        }
        (FactKind::FailedPreSend, _) => {
            state.terminal_attribution = Some(FactKind::FailedPreSend);
            state.historical = HistoricalAttribution::FailedPreSend;
            state.operational = OperationalAxis::Closed;
        }
        (FactKind::SeveredBeforeIssuance, _) => {
            state.terminal_attribution = Some(FactKind::SeveredBeforeIssuance);
            state.historical = HistoricalAttribution::SeveredBeforeIssuance;
            state.operational = OperationalAxis::Closed;
        }
        // Not a terminal attribution: ISSUANCE_UNKNOWN leaves both axes where they were.
        (FactKind::AckAmbiguous, _) => state.ambiguous_recorded = true,
        (FactKind::ReconcileStateMatches | FactKind::ReconcileStateDiffers, FactPayload::Reconcile { observation }) => {
            state.reconcile_count = state.reconcile_count.saturating_add(1);
            state.last_reconcile = Some((fact.kind, observation.clone()));
            state.last_reconcile_at = Some(fact.created_at.clone());
        }
        (FactKind::AdjudicatedUnresolved, FactPayload::Adjudicated { adjudication_id }) => {
            // The operational axis only. The historical axis stays where it was, which is the
            // content of "unknown at decision time".
            state.adjudication_id = Some(adjudication_id.clone());
            state.operational = OperationalAxis::Closed;
        }
        (FactKind::LateAckApplied, _) => {
            state.late_ack = Some(FactKind::LateAckApplied);
            state.historical = HistoricalAttribution::Applied;
        }
        (FactKind::LateAckRefusedNoEffect, _) => {
            state.late_ack = Some(FactKind::LateAckRefusedNoEffect);
            state.historical = HistoricalAttribution::RefusedNoEffect;
        }
        (FactKind::SupersededBy, FactPayload::SupersededBy { successor_operation_id }) => {
            state.superseded_by = Some(successor_operation_id.clone());
        }
        // Unreachable: `append_legal` rejects every kind/payload disagreement at the door.
        _ => {}
    }
}

// ---------------------------------------------------------------------------------------
// Legality: the closed grammar, one function
// ---------------------------------------------------------------------------------------

/// May `fact` be appended to an attempt whose chain folds to `state`? Default limits.
///
/// Intra-attempt only: everything decidable from this attempt's own chain. The cross-attempt
/// half of the ordinal/retry rule (same operation, eligible-terminal predecessor, single
/// successor, ordinal = predecessor + 1) needs the predecessor's folded state and lives in
/// [`retry_lineage_legal`]; a claim admission calls both.
pub fn append_legal(state: &DerivedState, fact: &Fact) -> Result<(), GrammarRefusal> {
    append_legal_with_limits(state, fact, &GrammarLimits::DEFAULT)
}

/// [`append_legal`] with explicit limits.
pub fn append_legal_with_limits(
    state: &DerivedState,
    fact: &Fact,
    limits: &GrammarLimits,
) -> Result<(), GrammarRefusal> {
    // (0) Parse, don't validate, at the door: no rule below reads a field the kind does not
    // promise, because a kind/payload disagreement never gets past here.
    if !fact.payload.matches(fact.kind) {
        return Err(GrammarRefusal::PayloadKindMismatch { kind: fact.kind });
    }

    // (1) The unclaimed chain. `CLAIM` is the one fact legal here, and it is legal only here:
    // ownership is established once or not at all.
    let Some(claim) = state.claim.as_ref() else {
        if fact.kind != FactKind::Claim {
            return Err(GrammarRefusal::FactBeforeClaim { kind: fact.kind });
        }
        let FactPayload::Claim {
            ordinal,
            predecessor,
        } = &fact.payload
        else {
            return Err(GrammarRefusal::PayloadKindMismatch { kind: fact.kind });
        };
        // The half of the ordinal/retry rule decidable from the CLAIM alone. The cross-attempt
        // half (same operation, eligible predecessor, single successor, ordinal = predecessor
        // + 1) is `retry_lineage_legal`'s.
        if *ordinal == 0 {
            return Err(GrammarRefusal::ClaimOrdinalZero);
        }
        if *ordinal == 1 && predecessor.is_some() {
            return Err(GrammarRefusal::FirstOrdinalCarriesPredecessor);
        }
        if *ordinal > 1 && predecessor.is_none() {
            return Err(GrammarRefusal::RetryOrdinalMissingPredecessor { ordinal: *ordinal });
        }
        return Ok(());
    };

    // (2) Exactly one `CLAIM` per attempt, checked before every other post-claim rule so a
    // second claim is always named as what it is, never as a whitelist or terminal violation.
    if fact.kind == FactKind::Claim {
        return Err(GrammarRefusal::DuplicateClaim);
    }

    // (3) The post-adjudication whitelist. It governs from adjudication onward and outranks the
    // both-axes-closed rule below, which is why a `SUPERSEDED_BY` is still legal after a
    // `LATE_ACK_*` has resolved the historical axis.
    if state.adjudication_id.is_some() {
        return match fact.kind {
            FactKind::LateAckApplied | FactKind::LateAckRefusedNoEffect => {
                match state.late_ack {
                    None => Ok(()),
                    Some(existing) if existing == fact.kind => {
                        Err(GrammarRefusal::DuplicateLateAck { existing })
                    }
                    // A second, contradictory late ack is refused and the contradiction is
                    // durably recorded as an anomaly annotation on the adjudication record. The
                    // grammar's job is the refusal; the distinct variant tells the store an
                    // annotation is owed.
                    Some(existing) => Err(GrammarRefusal::ContradictoryLateAckAnomaly {
                        existing,
                        offered: fact.kind,
                    }),
                }
            }
            FactKind::SupersededBy => {
                if state.superseded_by.is_some() {
                    return Err(GrammarRefusal::DuplicateSupersededBy);
                }
                let FactPayload::SupersededBy {
                    successor_operation_id,
                } = &fact.payload
                else {
                    return Err(GrammarRefusal::PayloadKindMismatch { kind: fact.kind });
                };
                // Acyclic at the operation grain: an attempt cannot be superseded by the
                // operation that owns it.
                if *successor_operation_id == claim.operation_id {
                    return Err(GrammarRefusal::SupersedesOwnOperation);
                }
                Ok(())
            }
            // Every other fact kind (including `RECONCILE_*` and `ACK_AMBIGUOUS`) is refused: a
            // late non-definitive observation lives in the adjudication record's ancillary audit
            // trail, never in the closed grammar.
            kind => Err(GrammarRefusal::PostAdjudicationWhitelistViolation { kind }),
        };
    }

    // (4) Both axes closed by a terminal attribution, and no whitelist was ever opened:
    // nothing may follow.
    if let Some(terminal) = state.terminal_attribution {
        return Err(GrammarRefusal::PostTerminalAppend {
            kind: fact.kind,
            terminal,
        });
    }

    // (5) The live attempt: claimed, unterminated, unadjudicated.
    match fact.kind {
        FactKind::Claim => Err(GrammarRefusal::DuplicateClaim), // unreachable; (2) caught it
        FactKind::SendAuthorized => {
            if state.send_authorized {
                Err(GrammarRefusal::DuplicateSendAuthorized)
            } else {
                Ok(())
            }
        }
        // Without the authorization requirement, `CLAIM → ACK_APPLIED` could classify an unsent
        // operation as completed and hide it from the sever set.
        FactKind::AckApplied | FactKind::AckRefusedNoEffect => {
            if state.send_authorized {
                Ok(())
            } else {
                Err(GrammarRefusal::AckWithoutSendAuthorization { kind: fact.kind })
            }
        }
        FactKind::AckAmbiguous => {
            if !state.send_authorized {
                return Err(GrammarRefusal::AckWithoutSendAuthorization { kind: fact.kind });
            }
            // A re-entered completion path must not grow the chain; subsequent ambiguous
            // observations route through the capped `RECONCILE_*` path.
            if state.ambiguous_recorded {
                return Err(GrammarRefusal::DuplicateAckAmbiguous);
            }
            Ok(())
        }
        FactKind::SeveredBeforeIssuance => {
            if state.send_authorized {
                Err(GrammarRefusal::SeveredAfterSendAuthorization)
            } else {
                Ok(())
            }
        }
        FactKind::FailedPreSend => {
            let FactPayload::FailedPreSend { wire_evidence, .. } = &fact.payload else {
                return Err(GrammarRefusal::PayloadKindMismatch { kind: fact.kind });
            };
            // Legal before authorization unconditionally (nothing was authorized, so nothing
            // could have been sent); legal after it only on the connector's positive
            // proven-no-wire proof. The proof requirement keeps ack-only attribution honest: an
            // unproven post-auth failure remains ISSUANCE_UNKNOWN.
            if state.send_authorized && *wire_evidence != WireEvidence::ProvenNoWire {
                return Err(GrammarRefusal::FailedPreSendPostAuthWithoutProvenNoWire);
            }
            Ok(())
        }
        FactKind::ReconcileStateMatches | FactKind::ReconcileStateDiffers => {
            if !state.send_authorized {
                return Err(GrammarRefusal::ReconcileWithoutSendAuthorization);
            }
            let FactPayload::Reconcile { observation } = &fact.payload else {
                return Err(GrammarRefusal::PayloadKindMismatch { kind: fact.kind });
            };
            // Total-bounded, not just rate-bounded. Hitting the cap surfaces the attempt for
            // adjudication; post-cap changed observations land in the explicitly
            // non-authoritative `last_observation` projection column, never here, so the fold's
            // input stays finite whatever the provider does.
            if state.reconcile_count >= limits.reconcile_lifetime_cap {
                return Err(GrammarRefusal::ReconcileLifetimeCapReached {
                    cap: limits.reconcile_lifetime_cap,
                });
            }
            // Appends only when the observation changed from the attempt's last recorded one.
            // The verdict kind is part of the observation: matches to differs is a change even
            // when the token is identical.
            if state.last_reconcile.as_ref() == Some(&(fact.kind, observation.clone())) {
                return Err(GrammarRefusal::ReconcileObservationUnchanged);
            }
            // The cadence bound, the third and last bound and the only one that bounds the
            // rate. Changed-only bounds repetition and the cap bounds the total; a provider
            // flapping between two observations satisfies both and still appends as fast as a
            // caller polls, burning the lifetime cap in seconds rather than describing a real
            // divergence.
            //
            // The comparison is lexicographic over two canonical instants, and the arithmetic is
            // confined to deriving the threshold. Both operands clear the shape authority first:
            // a stored instant that cannot be ordered fails closed here rather than reaching a
            // compare where a malformed value would read as "long enough ago". `fold` already
            // refuses a non-canonical `created_at`, so this covers a caller that reaches
            // `append_legal` directly.
            if let Some(last_at) = state.last_reconcile_at.as_deref() {
                let earliest = crate::prestate::unix_secs_from_rfc3339_utc(last_at)
                    .and_then(|secs| secs.checked_add(limits.reconcile_min_interval_seconds))
                    .map(crate::prestate::rfc3339_utc)
                    .filter(|threshold| is_canonical_rfc3339_utc(threshold));
                match earliest {
                    Some(threshold)
                        if is_canonical_rfc3339_utc(&fact.created_at)
                            && fact.created_at.as_str() >= threshold.as_str() => {}
                    // Too soon, or an instant this check cannot order: both refuse, and the
                    // refusal names the earliest legal instant it could derive.
                    other => {
                        return Err(GrammarRefusal::ReconcileTooSoon {
                            earliest: other.unwrap_or_default(),
                        })
                    }
                }
            }
            Ok(())
        }
        FactKind::AdjudicatedUnresolved => {
            // Adjudication operates only on a send-authorized unresolved attempt. Unresolved is
            // already guaranteed by (4): a terminal attribution would have refused above.
            if state.send_authorized {
                Ok(())
            } else {
                Err(GrammarRefusal::AdjudicationWithoutSendAuthorization)
            }
        }
        FactKind::LateAckApplied | FactKind::LateAckRefusedNoEffect => {
            Err(GrammarRefusal::LateAckWithoutAdjudication { kind: fact.kind })
        }
        FactKind::SupersededBy => Err(GrammarRefusal::SupersededByWithoutAdjudication),
    }
}

/// The cross-attempt half of the ordinal/retry rule: everything about a retry `Claim` that can
/// only be judged against the predecessor's own folded chain.
///
/// `predecessor_already_has_successor` is a store-derived fact (does any other CLAIM in this
/// operation cite the same predecessor?), passed in because a pure core cannot query.
///
/// Deliberately not checked here: transient-ness under `FailureKind`, the durable `RETRY_CAP`
/// budget, and claim-epoch equality with the current `control_epoch`. Those are retry
/// eligibility, enforced at the store, not grammar, and checking them here would put a second
/// copy of the budget rule in a module that cannot see the budget. The caller resolves
/// `predecessor` by the id the CLAIM payload names; this function judges that state and
/// cannot fetch it.
pub fn retry_lineage_legal(
    claim: &Fact,
    predecessor: &DerivedState,
    predecessor_already_has_successor: bool,
) -> Result<(), GrammarRefusal> {
    let FactPayload::Claim {
        ordinal,
        predecessor: link,
    } = &claim.payload
    else {
        return Err(GrammarRefusal::PayloadKindMismatch { kind: claim.kind });
    };
    let Some(link) = link else {
        return Err(GrammarRefusal::RetryOrdinalMissingPredecessor { ordinal: *ordinal });
    };
    let Some(predecessor_claim) = predecessor.claim.as_ref() else {
        return Err(GrammarRefusal::PredecessorUnclaimed);
    };
    // Acyclic, the base case: an attempt cannot be its own predecessor. Longer cycles are
    // unrepresentable given the ordinal rule below: a successor's ordinal strictly exceeds its
    // predecessor's, so a cycle would need a strictly increasing sequence to return to its
    // start.
    if link.attempt_id == claim.attempt_id {
        return Err(GrammarRefusal::PredecessorIsSelf);
    }
    // Same operation: retry lineage is internal to one operation's ordinal sequence, which
    // `UNIQUE (operation_id, attempt_ordinal)` arbitrates.
    if predecessor_claim.operation_id != claim.operation_id {
        return Err(GrammarRefusal::PredecessorOtherOperation);
    }
    // No retry from `ACK_AMBIGUOUS`/`ISSUANCE_UNKNOWN`, ever (adjudication is the only path). A
    // recorded ambiguous verdict gets its own refusal as the named case; an attempt that is
    // merely still in flight falls to the terminal check just below. Both are refused; only the
    // name differs.
    if predecessor.ambiguous_recorded {
        return Err(GrammarRefusal::RetryFromAmbiguity);
    }
    if predecessor.terminal_attribution.is_none() {
        return Err(GrammarRefusal::PredecessorNotTerminal);
    }
    // The declared reason is not a label: it must be what the predecessor's own chain folds
    // to. The `RetryReason` type cannot spell APPLIED or SEVERED, so those predecessors land
    // here as a mismatch rather than needing a rule of their own.
    if predecessor.historical != link.reason.required_attribution() {
        return Err(GrammarRefusal::PredecessorAttributionMismatch {
            declared: link.reason,
            actual: predecessor.historical,
        });
    }
    // Successor ordinal = predecessor ordinal + 1: the skipped-ordinal arm.
    if *ordinal != predecessor_claim.ordinal + 1 {
        return Err(GrammarRefusal::OrdinalNotPredecessorPlusOne {
            predecessor_ordinal: predecessor_claim.ordinal,
            offered: *ordinal,
        });
    }
    // Single successor: the predecessor has no other retry successor. Store-derived, so it
    // arrives as an argument.
    if predecessor_already_has_successor {
        return Err(GrammarRefusal::PredecessorAlreadyHasSuccessor);
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------
// The clamped-monotonic `created_at`
// ---------------------------------------------------------------------------------------

/// The result of the [`clamped_now`] clamp: the value to persist, plus the aging-review
/// signal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClampedNow {
    /// `max(now_utc, max_persisted)` — what goes in `attempt_fact.created_at`.
    pub value: String,
    /// True when `now_utc < max_persisted`: the wall clock stepped backward. The clamp alone
    /// freezes aging for the full rollback interval, so rollback means review now, never
    /// silently later. The flag is surfaced (a report field); no aging policy exists yet to
    /// freeze, so there is nothing to trigger and nothing to invent.
    pub backward_step_detected: bool,
}

/// Why a clamp input was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClockDefect {
    /// `now_utc` is not what `rfc3339_utc` emits.
    NonCanonicalNow,
    /// The persisted high-water mark is not what `rfc3339_utc` emits.
    NonCanonicalMaxPersisted,
}

impl fmt::Display for ClockDefect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// The `created_at` clamp: `created_at = max(now_utc, max persisted)`, with a backward step
/// surfaced rather than silently absorbed.
///
/// `max_persisted` is the empty string when no fact exists yet, the same "absent latch"
/// convention `time_high_water` uses (the empty latch sorts below every RFC 3339 instant, so
/// the first evaluation takes `now`).
///
/// Both inputs clear [`is_canonical_rfc3339_utc`] first, because the clamp is a lexicographic
/// comparison and a malformed value must fail explicitly there, never flow onward. That is why
/// this returns a `Result` around the `(value, backward_step_detected)` pair.
pub fn clamped_now(now_utc: &str, max_persisted: &str) -> Result<ClampedNow, ClockDefect> {
    if !is_canonical_rfc3339_utc(now_utc) {
        return Err(ClockDefect::NonCanonicalNow);
    }
    // The empty latch is absent, not corrupt (the first fact of the first attempt has no
    // predecessor to clamp against). Everything else must clear the shape authority in both
    // directions, because a malformed latch that sorts low is the one a max-only check silently
    // overwrites.
    if !max_persisted.is_empty() && !is_canonical_rfc3339_utc(max_persisted) {
        return Err(ClockDefect::NonCanonicalMaxPersisted);
    }
    // Both operands are now fixed-width canonical instants, so lexicographic order is time
    // order and the comparison is total.
    let backward_step_detected = now_utc < max_persisted;
    Ok(ClampedNow {
        value: if backward_step_detected {
            max_persisted.to_string()
        } else {
            now_utc.to_string()
        },
        backward_step_detected,
    })
}

// ---------------------------------------------------------------------------------------
// The canonical sever-witness encoding
// ---------------------------------------------------------------------------------------

/// The ASCII domain tag, no terminator (its own length is fixed). A new class byte requires a
/// new tag version, never a reused byte.
pub const SEVER_WITNESS_DOMAIN_TAG: &[u8] = b"photon.sever-witness.v1";

/// The complete versioned class-to-byte mapping. This is a frozen wire mapping, not an
/// internal enum: the byte values are the standard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WitnessClass {
    /// `0x01`: operation grain, an ACTIVE operation with no non-terminal attempt at the sever
    /// (never-claimed work and the retry gap).
    NoActiveAttempt,
    /// `0x02`: lifecycle-terminal before the sever. Absent from the witness, but present in the
    /// mapping: the mapping is versioned and complete, not need-based.
    Completed,
    /// `0x03` — claimed, never authorized.
    SeveredBeforeIssuance,
    /// `0x04`: authorized without terminal attribution. We cannot prove non-issuance, so we do
    /// not claim it.
    IssuedOrUnknown,
}

impl WitnessClass {
    /// Every class, for the mapping guard test.
    pub const ALL: [WitnessClass; 4] = [
        WitnessClass::NoActiveAttempt,
        WitnessClass::Completed,
        WitnessClass::SeveredBeforeIssuance,
        WitnessClass::IssuedOrUnknown,
    ];

    /// The byte. Frozen by the domain tag version.
    pub fn as_byte(&self) -> u8 {
        match self {
            WitnessClass::NoActiveAttempt => 0x01,
            WitnessClass::Completed => 0x02,
            WitnessClass::SeveredBeforeIssuance => 0x03,
            WitnessClass::IssuedOrUnknown => 0x04,
        }
    }
}

/// The tagged-union membership: an attempt-only tuple could not represent admitted-unclaimed
/// work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessMember {
    /// Tag byte `0x01`. Class is fixed at `NO_ACTIVE_ATTEMPT` (there is no other
    /// operation-grain member class), so it is not a field and an unrepresentable state cannot
    /// be encoded. There is no `operation_revision`.
    Operation {
        /// The opaque operation id bytes, as stored.
        operation_id: Vec<u8>,
    },
    /// Tag byte `0x02`.
    Attempt {
        /// The opaque attempt id bytes, as stored.
        attempt_id: Vec<u8>,
        /// The attempt's revision at the sever.
        attempt_revision: u64,
        /// The sever's class for the attempt.
        class_at_sever: WitnessClass,
    },
}

impl WitnessMember {
    /// The member's fully encoded byte string, the unit the sort orders over:
    /// `tag byte` ‖ `u32-BE length` ‖ raw id bytes ‖ (`Attempt` only) `u64-BE revision` ‖
    /// `class byte`.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            WitnessMember::Operation { operation_id } => {
                let mut out = Vec::with_capacity(1 + 4 + operation_id.len() + 1);
                out.push(0x01);
                out.extend_from_slice(&id_len_be(operation_id));
                out.extend_from_slice(operation_id);
                out.push(WitnessClass::NoActiveAttempt.as_byte());
                out
            }
            WitnessMember::Attempt {
                attempt_id,
                attempt_revision,
                class_at_sever,
            } => {
                let mut out = Vec::with_capacity(1 + 4 + attempt_id.len() + 8 + 1);
                out.push(0x02);
                out.extend_from_slice(&id_len_be(attempt_id));
                out.extend_from_slice(attempt_id);
                out.extend_from_slice(&attempt_revision.to_be_bytes());
                out.push(class_at_sever.as_byte());
                out
            }
        }
    }
}

/// The u32-BE length prefix. An id longer than 4 GiB is a broken caller, not a runtime
/// condition, and the panic is the loudest honest answer.
fn id_len_be(id: &[u8]) -> [u8; 4] {
    u32::try_from(id.len())
        .expect("a provider id longer than u32::MAX bytes is not a representable member")
        .to_be_bytes()
}

/// The canonical encoding, every byte specified: `"photon.sever-witness.v1"` ‖ `member_count`
/// (u32-BE) ‖ the members, each fully encoded, sorted bytewise ascending over their
/// fully-encoded byte strings (tag byte included).
///
/// Independent recomputation is a mechanical procedure, and ambiguous concatenation and
/// divergent implementations are unrepresentable. The length prefixes buy that: without them
/// `{"ab","c"}` and `{"a","bc"}` would concatenate identically (see the mutant test).
///
/// The function is total over the slice it is given and does not de-duplicate. Membership
/// totality (every active operation appears exactly once) is a property of the sever's
/// partition, derived over the store, not of the encoder, which must encode faithfully
/// whatever it is handed.
pub fn encode_sever_witness(members: &[WitnessMember]) -> Vec<u8> {
    // Sort order is bytewise ascending over each member's fully encoded byte string (tag byte
    // included). `Vec<u8>`'s own `Ord` is exactly that comparison, so the canonical order is
    // not a second rule to get wrong.
    let mut encoded: Vec<Vec<u8>> = members.iter().map(WitnessMember::encode).collect();
    encoded.sort();
    let count = u32::try_from(members.len())
        .expect("a sever with more than u32::MAX members is not a representable witness");
    let mut out = Vec::with_capacity(
        SEVER_WITNESS_DOMAIN_TAG.len() + 4 + encoded.iter().map(Vec::len).sum::<usize>(),
    );
    out.extend_from_slice(SEVER_WITNESS_DOMAIN_TAG);
    out.extend_from_slice(&count.to_be_bytes());
    for member in encoded {
        out.extend_from_slice(&member);
    }
    out
}

/// The witness digest: SHA-384 over [`encode_sever_witness`]'s bytes. One hash site,
/// provenance/attestation-binding bucket.
pub fn sever_witness_digest(members: &[WitnessMember]) -> [u8; 48] {
    let mut hasher = Sha384::new();
    hasher.update(encode_sever_witness(members));
    let out = hasher.finalize();
    let mut digest = [0u8; 48];
    digest.copy_from_slice(&out);
    digest
}

/// The digest as lowercase hex, the spelling the witness row persists.
pub fn sever_witness_digest_hex(members: &[WitnessMember]) -> String {
    sever_witness_digest(members)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- fixtures -------------------------------------------------------------------

    const T0: &str = "2026-08-08T00:00:00Z";

    fn fact(revision: u64, kind: FactKind, payload: FactPayload) -> Fact {
        Fact {
            operation_id: "op-1".into(),
            attempt_id: "att-1".into(),
            revision,
            kind,
            basis_epoch: 1,
            created_at: T0.into(),
            payload,
            prior_revision: if revision == 1 { None } else { Some(revision - 1) },
        }
    }

    fn claim(revision: u64, ordinal: u64, predecessor: Option<RetryPredecessor>) -> Fact {
        fact(
            revision,
            FactKind::Claim,
            FactPayload::Claim {
                ordinal,
                predecessor,
            },
        )
    }

    /// A one-atom exposure key, for the grammar tests that only need SOME key present.
    fn exposure(atom: &str) -> ExposureKey {
        ExposureKey {
            provider_scope: "res-1".into(),
            atoms: vec![ExposureAtom {
                atom_key: exposure_atom_key("res-1", atom),
                direction: ExposureDirection::Clear,
            }],
        }
    }

    fn send_auth(revision: u64) -> Fact {
        fact(
            revision,
            FactKind::SendAuthorized,
            FactPayload::SendAuthorized {
                exposure_key: exposure("membership:INBOX"),
            },
        )
    }

    fn plain(revision: u64, kind: FactKind) -> Fact {
        fact(revision, kind, FactPayload::None)
    }

    fn failed_pre_send(revision: u64, wire_evidence: WireEvidence) -> Fact {
        fact(
            revision,
            FactKind::FailedPreSend,
            FactPayload::FailedPreSend { wire_evidence, reason: PreSendReason::Failure, exposure_block: None, plan_refusal: None },
        )
    }

    fn reconcile(revision: u64, kind: FactKind, observation: &str) -> Fact {
        fact(
            revision,
            kind,
            FactPayload::Reconcile {
                observation: observation.into(),
            },
        )
    }

    fn adjudicated(revision: u64) -> Fact {
        fact(
            revision,
            FactKind::AdjudicatedUnresolved,
            FactPayload::Adjudicated {
                adjudication_id: "adj-1".into(),
            },
        )
    }

    fn superseded(revision: u64, successor: &str) -> Fact {
        fact(
            revision,
            FactKind::SupersededBy,
            FactPayload::SupersededBy {
                successor_operation_id: successor.into(),
            },
        )
    }

    /// Fold a chain that MUST be legal, or fail the test with the defect.
    fn folded(facts: &[Fact]) -> DerivedState {
        fold(facts).unwrap_or_else(|d| panic!("chain must fold: {d}"))
    }

    /// The refusal of appending `fact` to the state folded from `chain`.
    fn refusal(chain: &[Fact], next: &Fact) -> GrammarRefusal {
        let state = folded(chain);
        append_legal(&state, next).expect_err("this append must be refused")
    }

    /// Assert `next` is LEGAL after `chain`.
    fn assert_legal(chain: &[Fact], next: &Fact) {
        let state = folded(chain);
        append_legal(&state, next)
            .unwrap_or_else(|r| panic!("{:?} must be legal here, refused: {r}", next.kind));
    }

    // (D1): the two plan reasons + the typed plan_refusal record ------

    #[test]
    fn s1_pre_send_reason_vocabulary_has_four_members_and_round_trips() {
        use super::PreSendReason;
        assert_eq!(PreSendReason::ALL.len(), 4);
        for r in PreSendReason::ALL {
            assert_eq!(PreSendReason::from_token(r.as_token()), Some(r));
        }
        // Every variant, named here by an EXHAUSTIVE match (a new variant does not compile until
        // it takes a position), must be a member of `ALL` — `from_token` reads `ALL`, so a
        // variant missing from it would be a token this build writes and cannot read back.
        let every = |r: PreSendReason| match r {
            PreSendReason::Failure
            | PreSendReason::ExternallySatisfied
            | PreSendReason::StaleNotAttempted
            | PreSendReason::PlanRefused => r,
        };
        for r in [
            PreSendReason::Failure,
            PreSendReason::ExternallySatisfied,
            PreSendReason::StaleNotAttempted,
            PreSendReason::PlanRefused,
        ] {
            assert!(PreSendReason::ALL.contains(&every(r)), "{r:?} is missing from ALL");
            assert_eq!(PreSendReason::from_token(r.as_token()), Some(r), "{r:?} does not read back");
        }
        assert_eq!(PreSendReason::StaleNotAttempted.as_token(), "stale_not_attempted");
        assert_eq!(PreSendReason::PlanRefused.as_token(), "plan_refused");
        assert_eq!(PreSendReason::from_token("stale"), None, "the vocabulary is closed");
    }

    #[test]
    fn a_failed_pre_send_payload_carries_an_optional_plan_refusal_record() {
        use super::*;
        let rec = PlanRefusalRecord {
            reason: "state_diverged".into(),
            member_ref: "m1".into(),
            diff: vec![MemberDiff { atom: "label:TRASH".into(), expected: false, observed: Some(true) }],
            detail: None,
        };
        let p = FactPayload::FailedPreSend { wire_evidence: WireEvidence::ProvenNoWire, reason: PreSendReason::StaleNotAttempted, exposure_block: None, plan_refusal: Some(rec.clone()) };
        assert!(p.matches(FactKind::FailedPreSend));
        // The record is content-free by construction: an atom name from the engine's own
        // vocabulary, booleans, and a Photon message identity — never a subject or an address.
        // (`detail` too: its grant payload is the `String`-free `crate::plan::GrantDenial` —
        // `plan::tests::every_grant_denial_record_is_content_free_and_round_trips`.)
        assert!(!rec.atom_names().iter().any(|a| a.contains('@')));
        assert_eq!(rec.atom_names(), vec!["label:TRASH"]);
    }

    // ---- the CHECK-constraint guard (the 13-kind sync) --------------------------------

    #[test]
    fn fact_kind_vocabulary_matches_the_ddl_check_constraint() {
        // The guard that makes the enum and the SQL CHECK list ONE vocabulary rather than
        // two hand-written ones (the `NON_TERMINAL_STATUS_SQL` pattern). `include_str!` is
        // compile-time: the test reads the DDL's own source bytes, so a kind added to the
        // CHECK constraint without a variant here (or the reverse) fails HERE, once.
        let ddl = include_str!("store_open.rs");
        let anchor = "CHECK (fact_kind IN (";
        let start = ddl
            .find(anchor)
            .expect("store_open.rs must carry the attempt_fact fact_kind CHECK constraint");
        let rest = &ddl[start + anchor.len()..];
        let end = rest.find("))").expect("the CHECK list must terminate");
        let mut from_ddl: Vec<String> = rest[..end]
            .split(',')
            .map(|t| t.trim().trim_matches('\'').to_string())
            .filter(|t| !t.is_empty())
            .collect();
        let mut from_enum: Vec<String> = FactKind::ALL
            .iter()
            .map(|k| k.as_sql().to_string())
            .collect();
        assert_eq!(from_ddl.len(), 13, "the DDL must enumerate 13 kinds: {from_ddl:?}");
        assert_eq!(from_enum.len(), 13);
        from_ddl.sort();
        from_enum.sort();
        assert_eq!(from_enum, from_ddl, "FactKind and the CHECK constraint have drifted");
    }

    /// The three §5.2d CLOSED vocabularies against their own DDL CHECK lists — the same
    /// `include_str!` guard the 13 fact kinds get, because a durable vocabulary that lives in
    /// two hand-written places is two vocabularies.
    fn ddl_check_list(table: &str, anchor: &str) -> Vec<String> {
        let ddl = include_str!("store_open.rs");
        // Anchored on the TABLE first: `CHECK (kind IN (…)` also appears on `intents.kind`,
        // and a guard that reads the wrong table's vocabulary guards nothing.
        let table_at = ddl
            .find(table)
            .unwrap_or_else(|| panic!("store_open.rs must carry the table {table}"));
        let start = table_at
            + ddl[table_at..]
                .find(anchor)
                .unwrap_or_else(|| panic!("{table} must carry the CHECK constraint {anchor}"));
        let rest = &ddl[start + anchor.len()..];
        let end = rest.find("))").expect("the CHECK list must terminate");
        let mut tokens: Vec<String> = rest[..end]
            .split(',')
            .map(|t| t.trim().trim_matches('\'').to_string())
            .filter(|t| !t.is_empty())
            .collect();
        tokens.sort();
        tokens
    }

    #[test]
    fn the_adjudication_vocabularies_match_their_ddl_check_constraints() {
        let sorted = |mut v: Vec<String>| {
            v.sort();
            v
        };
        assert_eq!(
            sorted(AdjudicationReason::ALL.iter().map(|r| r.as_sql().to_string()).collect()),
            ddl_check_list("CREATE TABLE IF NOT EXISTS adjudication_record", "CHECK (reason IN ("),
            "AdjudicationReason and the adjudication_record CHECK have drifted"
        );
        assert_eq!(
            sorted(AcceptedRisk::ALL.iter().map(|r| r.as_sql().to_string()).collect()),
            ddl_check_list(
                "CREATE TABLE IF NOT EXISTS adjudication_record",
                "CHECK (accepted_risk IN ("
            ),
            "AcceptedRisk and the adjudication_record CHECK have drifted"
        );
        assert_eq!(
            sorted(AnomalyKind::ALL.iter().map(|k| k.as_sql().to_string()).collect()),
            ddl_check_list(
                "CREATE TABLE IF NOT EXISTS adjudication_annotation",
                "CHECK (kind IN ("
            ),
            "AnomalyKind and the adjudication_annotation CHECK have drifted"
        );
    }

    #[test]
    fn the_adjudication_vocabularies_round_trip_and_all_is_complete() {
        for r in AdjudicationReason::ALL {
            assert_eq!(AdjudicationReason::from_sql(r.as_sql()), Some(r));
        }
        assert_eq!(AdjudicationReason::from_sql("because-i-said-so"), None);
        for r in AcceptedRisk::ALL {
            assert_eq!(AcceptedRisk::from_sql(r.as_sql()), Some(r));
        }
        assert_eq!(AcceptedRisk::from_sql("everything-is-fine"), None);
        for k in AnomalyKind::ALL {
            assert_eq!(AnomalyKind::from_sql(k.as_sql()), Some(k));
        }
        assert_eq!(AnomalyKind::from_sql("weird"), None);
        // `ALL` is complete: each match is exhaustive, so a new variant is a COMPILE error
        // here until it is added.
        assert_eq!(
            AdjudicationReason::ALL.len(),
            AdjudicationReason::ALL
                .iter()
                .map(|r| match r {
                    AdjudicationReason::OperatorAbandonedUnresolved => 1,
                    AdjudicationReason::PresumedTransportLoss => 1,
                    AdjudicationReason::SupersedingUserInstruction => 1,
                    AdjudicationReason::CapacityRecovery => 1,
                })
                .sum::<usize>()
        );
        assert_eq!(
            AcceptedRisk::ALL.len(),
            AcceptedRisk::ALL
                .iter()
                .map(|r| match r {
                    AcceptedRisk::DuplicateEffectPossible => 1,
                    AcceptedRisk::ReversalPossible => 1,
                    AcceptedRisk::NoneClaimed => 1,
                })
                .sum::<usize>()
        );
        assert_eq!(
            AnomalyKind::ALL.len(),
            AnomalyKind::ALL
                .iter()
                .map(|k| match k {
                    AnomalyKind::ContradictoryLateAck => 1,
                    AnomalyKind::AppliedOverUnresolved => 1,
                    AnomalyKind::ExposureMaterialized => 1,
                    AnomalyKind::LateAmbiguousObservation => 1,
                })
                .sum::<usize>()
        );
        // The late-ack polarity maps onto the whitelist's two kinds and their attributions.
        assert_eq!(LateAck::Applied.fact_kind(), FactKind::LateAckApplied);
        assert_eq!(
            LateAck::RefusedNoEffect.fact_kind(),
            FactKind::LateAckRefusedNoEffect
        );
        assert_eq!(LateAck::Applied.attribution(), HistoricalAttribution::Applied);
        assert_eq!(
            LateAck::RefusedNoEffect.attribution(),
            HistoricalAttribution::RefusedNoEffect
        );
        assert_eq!(UNKNOWN_REVIEW_AFTER_SECONDS, 604_800);
    }

    #[test]
    fn fact_kind_round_trips_and_all_is_complete() {
        for k in FactKind::ALL {
            assert_eq!(FactKind::from_sql(k.as_sql()), Some(k));
        }
        assert_eq!(FactKind::from_sql("not_a_kind"), None);
        // `ALL` is itself complete: this match is exhaustive, so a new variant is a COMPILE
        // error here until it is added to `ALL`.
        assert_eq!(
            FactKind::ALL.len(),
            FactKind::ALL
                .iter()
                .map(|k| match k {
                    FactKind::Claim => 1,
                    FactKind::SendAuthorized => 1,
                    FactKind::AckApplied => 1,
                    FactKind::AckRefusedNoEffect => 1,
                    FactKind::FailedPreSend => 1,
                    FactKind::AckAmbiguous => 1,
                    FactKind::ReconcileStateMatches => 1,
                    FactKind::ReconcileStateDiffers => 1,
                    FactKind::SeveredBeforeIssuance => 1,
                    FactKind::AdjudicatedUnresolved => 1,
                    FactKind::LateAckApplied => 1,
                    FactKind::LateAckRefusedNoEffect => 1,
                    FactKind::SupersededBy => 1,
                })
                .sum::<usize>()
        );
    }

    #[test]
    fn attempt_class_round_trips() {
        for c in AttemptClass::ALL {
            assert_eq!(AttemptClass::from_sql(c.as_sql()), Some(c));
        }
        assert_eq!(AttemptClass::from_sql("no_active_attempt"), None,
            "NO_ACTIVE_ATTEMPT is OPERATION grain — it is not an attempt class");
    }

    // ---- W-ATTEMPT-GRAMMAR: one CLAIM -------------------------------------------------

    #[test]
    fn a_chain_must_begin_with_claim() {
        let state = DerivedState::empty();
        for kind in FactKind::ALL.iter().filter(|k| **k != FactKind::Claim) {
            let payload = match kind {
                FactKind::SendAuthorized => FactPayload::SendAuthorized {
                        exposure_key: exposure("k"),
                            },
                FactKind::FailedPreSend => FactPayload::FailedPreSend { wire_evidence: WireEvidence::Indeterminate, reason: PreSendReason::Failure, exposure_block: None, plan_refusal: None },
                FactKind::ReconcileStateMatches | FactKind::ReconcileStateDiffers =>
                    FactPayload::Reconcile { observation: "o".into() },
                FactKind::AdjudicatedUnresolved => FactPayload::Adjudicated { adjudication_id: "a".into() },
                FactKind::SupersededBy => FactPayload::SupersededBy { successor_operation_id: "op-2".into() },
                _ => FactPayload::None,
            };
            assert_eq!(
                append_legal(&state, &fact(1, *kind, payload)),
                Err(GrammarRefusal::FactBeforeClaim { kind: *kind }),
                "{kind:?} must be refused before any CLAIM"
            );
        }
    }

    #[test]
    fn exactly_one_claim_per_attempt() {
        let chain = [claim(1, 1, None)];
        assert_eq!(
            refusal(&chain, &claim(2, 1, None)),
            GrammarRefusal::DuplicateClaim
        );
        // …and after ANY later fact, too — the rule is not "not immediately after".
        let chain = [claim(1, 1, None), send_auth(2)];
        assert_eq!(
            refusal(&chain, &claim(3, 2, None)),
            GrammarRefusal::DuplicateClaim
        );
    }

    #[test]
    fn claim_ordinal_totality_within_the_claim() {
        let empty = DerivedState::empty();
        // ordinal 0 is not a 1-based ordinal.
        assert_eq!(
            append_legal(&empty, &claim(1, 0, None)),
            Err(GrammarRefusal::ClaimOrdinalZero)
        );
        // ordinal 1 carries NO predecessor.
        assert_eq!(
            append_legal(
                &empty,
                &claim(1, 1, Some(RetryPredecessor { attempt_id: "att-0".into(), reason: RetryReason::FailedPreSend }))
            ),
            Err(GrammarRefusal::FirstOrdinalCarriesPredecessor)
        );
        // every ordinal > 1 carries exactly one.
        assert_eq!(
            append_legal(&empty, &claim(1, 2, None)),
            Err(GrammarRefusal::RetryOrdinalMissingPredecessor { ordinal: 2 })
        );
        // the legal shapes.
        assert!(append_legal(&empty, &claim(1, 1, None)).is_ok());
        assert!(append_legal(
            &empty,
            &claim(1, 2, Some(RetryPredecessor { attempt_id: "att-0".into(), reason: RetryReason::AckRefusedNoEffect }))
        )
        .is_ok());
    }

    // ---- W-RETRY-LINEAGE: the cross-attempt totality ----------------------------------

    /// A predecessor chain folding to the given terminal.
    fn predecessor_chain(kind: FactKind, ordinal: u64) -> Vec<Fact> {
        let mut c = vec![Fact {
            attempt_id: "att-0".into(),
            ..claim(1, ordinal, if ordinal == 1 { None } else {
                Some(RetryPredecessor { attempt_id: "att-x".into(), reason: RetryReason::FailedPreSend })
            })
        }];
        match kind {
            FactKind::FailedPreSend => c.push(Fact {
                attempt_id: "att-0".into(),
                ..failed_pre_send(2, WireEvidence::Indeterminate)
            }),
            FactKind::AckRefusedNoEffect => {
                c.push(Fact { attempt_id: "att-0".into(), ..send_auth(2) });
                c.push(Fact { attempt_id: "att-0".into(), ..plain(3, FactKind::AckRefusedNoEffect) });
            }
            FactKind::AckAmbiguous => {
                c.push(Fact { attempt_id: "att-0".into(), ..send_auth(2) });
                c.push(Fact { attempt_id: "att-0".into(), ..plain(3, FactKind::AckAmbiguous) });
            }
            FactKind::AckApplied => {
                c.push(Fact { attempt_id: "att-0".into(), ..send_auth(2) });
                c.push(Fact { attempt_id: "att-0".into(), ..plain(3, FactKind::AckApplied) });
            }
            _ => {}
        }
        c
    }

    #[test]
    fn retry_lineage_totality_five_arms() {
        let pred = folded(&predecessor_chain(FactKind::FailedPreSend, 1));
        let retry = claim(
            1,
            2,
            Some(RetryPredecessor { attempt_id: "att-0".into(), reason: RetryReason::FailedPreSend }),
        );

        // The legal shape first — a table that only ever refuses proves nothing.
        assert_eq!(retry_lineage_legal(&retry, &pred, false), Ok(()));

        // arm 1 — SINGLE SUCCESSOR: the predecessor already has one.
        assert_eq!(
            retry_lineage_legal(&retry, &pred, true),
            Err(GrammarRefusal::PredecessorAlreadyHasSuccessor)
        );

        // arm 2 — SAME OPERATION.
        let foreign = folded(
            &predecessor_chain(FactKind::FailedPreSend, 1)
                .into_iter()
                .map(|f| Fact { operation_id: "op-OTHER".into(), ..f })
                .collect::<Vec<_>>(),
        );
        assert_eq!(
            retry_lineage_legal(&retry, &foreign, false),
            Err(GrammarRefusal::PredecessorOtherOperation)
        );

        // arm 3 — ACYCLIC: an attempt cannot be its own predecessor.
        let self_ref = Fact {
            payload: FactPayload::Claim {
                ordinal: 2,
                predecessor: Some(RetryPredecessor { attempt_id: "att-1".into(), reason: RetryReason::FailedPreSend }),
            },
            ..claim(1, 2, None)
        };
        let self_pred = folded(
            &predecessor_chain(FactKind::FailedPreSend, 1)
                .into_iter()
                .map(|f| Fact { attempt_id: "att-1".into(), ..f })
                .collect::<Vec<_>>(),
        );
        assert_eq!(
            retry_lineage_legal(&self_ref, &self_pred, false),
            Err(GrammarRefusal::PredecessorIsSelf)
        );

        // arm 4 — the predecessor holds no terminal attribution at all (still in flight).
        let in_flight = folded(&[claim(1, 1, None), send_auth(2)]
            .into_iter()
            .map(|f| Fact { attempt_id: "att-0".into(), ..f })
            .collect::<Vec<_>>());
        assert_eq!(
            retry_lineage_legal(&retry, &in_flight, false),
            Err(GrammarRefusal::PredecessorNotTerminal)
        );

        // arm 5 — SUCCESSOR ORDINAL = PREDECESSOR + 1 (the skipped-ordinal arm).
        let skipped = claim(
            1,
            3,
            Some(RetryPredecessor { attempt_id: "att-0".into(), reason: RetryReason::FailedPreSend }),
        );
        assert_eq!(
            retry_lineage_legal(&skipped, &pred, false),
            Err(GrammarRefusal::OrdinalNotPredecessorPlusOne { predecessor_ordinal: 1, offered: 3 })
        );
    }

    #[test]
    fn no_retry_from_ambiguity_ever() {
        // ISSUANCE_UNKNOWN: send-authorized, ACK_AMBIGUOUS, no terminal attribution.
        let ambiguous = folded(&predecessor_chain(FactKind::AckAmbiguous, 1));
        let retry = claim(
            1,
            2,
            Some(RetryPredecessor { attempt_id: "att-0".into(), reason: RetryReason::FailedPreSend }),
        );
        assert_eq!(
            retry_lineage_legal(&retry, &ambiguous, false),
            Err(GrammarRefusal::RetryFromAmbiguity)
        );
    }

    #[test]
    fn retry_reason_must_match_the_predecessors_actual_attribution() {
        // Declared FAILED_PRE_SEND, predecessor actually ACK_REFUSED_NO_EFFECT.
        let pred = folded(&predecessor_chain(FactKind::AckRefusedNoEffect, 1));
        let retry = claim(
            1,
            2,
            Some(RetryPredecessor { attempt_id: "att-0".into(), reason: RetryReason::FailedPreSend }),
        );
        assert_eq!(
            retry_lineage_legal(&retry, &pred, false),
            Err(GrammarRefusal::PredecessorAttributionMismatch {
                declared: RetryReason::FailedPreSend,
                actual: HistoricalAttribution::RefusedNoEffect,
            })
        );
        // An APPLIED predecessor is not retryable under EITHER reason — the closed
        // `RetryReason` type cannot even spell it, so the mismatch arm is the refusal.
        let applied = folded(&predecessor_chain(FactKind::AckApplied, 1));
        assert_eq!(
            retry_lineage_legal(&retry, &applied, false),
            Err(GrammarRefusal::PredecessorAttributionMismatch {
                declared: RetryReason::FailedPreSend,
                actual: HistoricalAttribution::Applied,
            })
        );
    }

    // ---- W-ATTEMPT-GRAMMAR: SEND_AUTHORIZED -------------------------------------------

    #[test]
    fn at_most_one_send_authorized_and_only_after_claim() {
        assert_legal(&[claim(1, 1, None)], &send_auth(2));
        assert_eq!(
            refusal(&[claim(1, 1, None), send_auth(2)], &send_auth(3)),
            GrammarRefusal::DuplicateSendAuthorized
        );
    }

    // ---- W-ATTEMPT-GRAMMAR: the terminal-attribution legality table --------------------

    #[test]
    fn acks_are_legal_only_after_send_authorization() {
        // Without this, CLAIM → ACK_APPLIED classifies an UNSENT operation as
        // completed and hides it from the sever set.
        for kind in [FactKind::AckApplied, FactKind::AckRefusedNoEffect, FactKind::AckAmbiguous] {
            assert_eq!(
                refusal(&[claim(1, 1, None)], &plain(2, kind)),
                GrammarRefusal::AckWithoutSendAuthorization { kind }
            );
            assert_legal(&[claim(1, 1, None), send_auth(2)], &plain(3, kind));
        }
    }

    #[test]
    fn severed_before_issuance_is_legal_only_before_send_authorization() {
        assert_legal(&[claim(1, 1, None)], &plain(2, FactKind::SeveredBeforeIssuance));
        assert_eq!(
            refusal(
                &[claim(1, 1, None), send_auth(2)],
                &plain(3, FactKind::SeveredBeforeIssuance)
            ),
            GrammarRefusal::SeveredAfterSendAuthorization
        );
    }

    #[test]
    fn failed_pre_send_post_auth_requires_positive_proven_no_wire() {
        // Pre-auth: always legal, evidence irrelevant (nothing was authorized).
        assert_legal(&[claim(1, 1, None)], &failed_pre_send(2, WireEvidence::Indeterminate));
        // Post-auth WITHOUT proof: stays ISSUANCE_UNKNOWN — the refusal is the honesty.
        assert_eq!(
            refusal(
                &[claim(1, 1, None), send_auth(2)],
                &failed_pre_send(3, WireEvidence::Indeterminate)
            ),
            GrammarRefusal::FailedPreSendPostAuthWithoutProvenNoWire
        );
        // Post-auth WITH the connector's positive proof: legal, and retryable per taxonomy.
        assert_legal(
            &[claim(1, 1, None), send_auth(2)],
            &failed_pre_send(3, WireEvidence::ProvenNoWire),
        );
    }

    #[test]
    fn at_most_one_terminal_attribution_and_nothing_follows_it() {
        let terminals = [
            (vec![claim(1, 1, None)], plain(2, FactKind::SeveredBeforeIssuance), FactKind::SeveredBeforeIssuance),
            (vec![claim(1, 1, None)], failed_pre_send(2, WireEvidence::Indeterminate), FactKind::FailedPreSend),
            (vec![claim(1, 1, None), send_auth(2)], plain(3, FactKind::AckApplied), FactKind::AckApplied),
            (vec![claim(1, 1, None), send_auth(2)], plain(3, FactKind::AckRefusedNoEffect), FactKind::AckRefusedNoEffect),
        ];
        for (prefix, terminal, terminal_kind) in terminals {
            let mut chain = prefix.clone();
            chain.push(terminal.clone());
            let next_rev = terminal.revision + 1;
            // EVERY kind is refused after a terminal attribution — both axes are closed and
            // no whitelist exists on this path (only adjudication opens one).
            for kind in FactKind::ALL {
                let payload = match kind {
                    FactKind::Claim => FactPayload::Claim { ordinal: 1, predecessor: None },
                    FactKind::SendAuthorized => FactPayload::SendAuthorized {
                        exposure_key: exposure("k"),
                            },
                    FactKind::FailedPreSend => FactPayload::FailedPreSend { wire_evidence: WireEvidence::ProvenNoWire, reason: PreSendReason::Failure, exposure_block: None, plan_refusal: None },
                    FactKind::ReconcileStateMatches | FactKind::ReconcileStateDiffers =>
                        FactPayload::Reconcile { observation: "o".into() },
                    FactKind::AdjudicatedUnresolved => FactPayload::Adjudicated { adjudication_id: "a".into() },
                    FactKind::SupersededBy => FactPayload::SupersededBy { successor_operation_id: "op-2".into() },
                    _ => FactPayload::None,
                };
                let expected = if kind == FactKind::Claim {
                    GrammarRefusal::DuplicateClaim
                } else {
                    GrammarRefusal::PostTerminalAppend { kind, terminal: terminal_kind }
                };
                assert_eq!(
                    refusal(&chain, &fact(next_rev, kind, payload)),
                    expected,
                    "{kind:?} after {terminal_kind:?}"
                );
            }
        }
    }

    #[test]
    fn at_most_one_ack_ambiguous() {
        let chain = [claim(1, 1, None), send_auth(2), plain(3, FactKind::AckAmbiguous)];
        assert_eq!(
            refusal(&chain, &plain(4, FactKind::AckAmbiguous)),
            GrammarRefusal::DuplicateAckAmbiguous
        );
        // …and an ambiguous attempt is still terminalizable (a late definitive ack path is
        // adjudication's, but a sever's SEVERED_BEFORE_ISSUANCE is not legal post-auth).
        assert_legal(&chain, &plain(4, FactKind::AckApplied));
    }

    // ---- W-ATTEMPT-GRAMMAR: RECONCILE_* bounds ----------------------------------------

    #[test]
    fn reconcile_requires_send_authorization() {
        assert_eq!(
            refusal(&[claim(1, 1, None)], &reconcile(2, FactKind::ReconcileStateMatches, "o1")),
            GrammarRefusal::ReconcileWithoutSendAuthorization
        );
    }

    #[test]
    fn reconcile_appends_only_when_the_observation_changed() {
        let chain = [
            claim(1, 1, None),
            send_auth(2),
            reconcile(3, FactKind::ReconcileStateDiffers, "o1"),
        ];
        // Identical (kind, observation) → refused: the total bound, not just the rate bound.
        // (Refused on the CHANGED-ONLY rule, which is checked ahead of the cadence — a repeat
        // is not "too soon", it is not an observation at all.)
        assert_eq!(
            refusal(&chain, &reconcile(4, FactKind::ReconcileStateDiffers, "o1")),
            GrammarRefusal::ReconcileObservationUnchanged
        );
        // A changed observation is legal — ONE CADENCE INTERVAL LATER (the
        // two bounds are independent, and a fixture for one must satisfy the other)…
        let later = crate::prestate::rfc3339_utc(t0_secs() + 3600);
        assert_legal(
            &chain,
            &reconcile_at(4, FactKind::ReconcileStateDiffers, "o2", &later),
        );
        // …and so is the same observation under a CHANGED verdict kind.
        assert_legal(
            &chain,
            &reconcile_at(4, FactKind::ReconcileStateMatches, "o1", &later),
        );
    }

    #[test]
    fn reconcile_lifetime_cap_surfaces_the_attempt_instead_of_growing_the_chain() {
        let limits = GrammarLimits::new(3, 3600).expect("a legal cadence");
        let mut chain = vec![claim(1, 1, None), send_auth(2)];
        // SPACED BY THE CADENCE: the cap and the interval are independent
        // bounds, so a fixture for one must satisfy the other — three reconciles an hour apart.
        for i in 0..3u64 {
            chain.push(reconcile_at(
                3 + i,
                FactKind::ReconcileStateDiffers,
                &format!("o{i}"),
                &crate::prestate::rfc3339_utc(t0_secs() + 3600 * (i + 1)),
            ));
        }
        let state = fold_with_limits(&chain, &limits).expect("chain folds");
        assert_eq!(state.reconcile_count, 3);
        assert_eq!(
            append_legal_with_limits(
                &state,
                &reconcile_at(
                    6,
                    FactKind::ReconcileStateDiffers,
                    "o9",
                    &crate::prestate::rfc3339_utc(t0_secs() + 3600 * 9),
                ),
                &limits
            ),
            Err(GrammarRefusal::ReconcileLifetimeCapReached { cap: 3 }),
            "the LIFETIME cap is what refuses a fact that clears the cadence"
        );
        // A definitive verdict is NEVER capped — the cap bounds annotations, not truth.
        assert!(append_legal_with_limits(&state, &plain(6, FactKind::AckApplied), &limits).is_ok());
    }

    /// A `Reconcile*` fact AT a chosen instant — the cadence bound's input axis (the plain
    /// [`reconcile`] helper stamps every fact `T0`, which is exactly the back-to-back shape
    /// §5.2a's minimum interval refuses).
    fn reconcile_at(revision: u64, kind: FactKind, observation: &str, created_at: &str) -> Fact {
        Fact {
            created_at: created_at.into(),
            ..reconcile(revision, kind, observation)
        }
    }

    /// `T0` as Unix seconds — the anchor cadence-spaced fixtures count from, through the ONE
    /// conversion authority rather than a hand-spelled second value.
    fn t0_secs() -> u64 {
        crate::prestate::unix_secs_from_rfc3339_utc(T0).expect("T0 is canonical")
    }

    #[test]
    fn reconcile_refuses_a_second_fact_inside_the_cadence_interval() {
        // §5.2a bounds `RECONCILE_*` by BOTH a lifetime cap AND a
        // MINIMUM INTERVAL (config, default 1h): "appends only when the observation CHANGED …
        // and no more often than the configured cadence". The changed-only rule alone does not
        // bound RATE — a provider flapping between two observations produces an unbounded
        // stream of CHANGED facts, all legal, as fast as a caller can poll.
        let chain = [
            claim(1, 1, None),
            send_auth(2),
            reconcile(3, FactKind::ReconcileStateDiffers, "o1"),
        ];
        let state = folded(&chain);
        // ONE SECOND after the last reconcile, with a genuinely CHANGED observation.
        let too_soon = reconcile_at(
            4,
            FactKind::ReconcileStateMatches,
            "o2",
            "2026-08-08T00:00:01Z",
        );
        assert!(
            append_legal(&state, &too_soon).is_err(),
            "a RECONCILE_* one second behind its predecessor must be refused by the cadence \
             bound — the changed-only rule does not bound the RATE"
        );
        assert_eq!(
            append_legal(&state, &too_soon),
            Err(GrammarRefusal::ReconcileTooSoon {
                earliest: crate::prestate::rfc3339_utc(t0_secs() + 3600),
            }),
            "…and the refusal NAMES the earliest legal instant, never a bare 'no'"
        );
        // AT the threshold it is legal — the bound is `last + interval`, inclusive.
        assert_legal(
            &chain,
            &reconcile_at(
                4,
                FactKind::ReconcileStateMatches,
                "o2",
                &crate::prestate::rfc3339_utc(t0_secs() + 3600),
            ),
        );
        // The FIRST reconcile of an attempt has no predecessor to be too soon after.
        assert_legal(
            &[claim(1, 1, None), send_auth(2)],
            &reconcile(3, FactKind::ReconcileStateMatches, "o1"),
        );
        // A NON-DEFAULT cadence is honored…
        let ten_minutes = GrammarLimits::new(32, 600).expect("600s clears the floor");
        assert!(append_legal_with_limits(
            &state,
            &reconcile_at(
                4,
                FactKind::ReconcileStateMatches,
                "o2",
                &crate::prestate::rfc3339_utc(t0_secs() + 600),
            ),
            &ten_minutes
        )
        .is_ok());
        // …and one BELOW the floor is refused at CONSTRUCTION — never clamped, never reaching
        // the grammar at all (§5.2a: validated ≥ 60s).
        assert_eq!(
            GrammarLimits::new(32, 59),
            Err(GrammarLimitsRefusal::ReconcileIntervalBelowFloor {
                seconds: 59,
                floor: 60
            })
        );
        assert!(GrammarLimits::new(32, 60).is_ok(), "the floor itself is legal");
        assert_eq!(
            GrammarLimits::DEFAULT.reconcile_min_interval_seconds, 3600,
            "the design's declared default is 1h"
        );
    }

    #[test]
    fn reconcile_is_refused_after_a_terminal_attribution() {
        let chain = [claim(1, 1, None), send_auth(2), plain(3, FactKind::AckApplied)];
        assert_eq!(
            refusal(&chain, &reconcile(4, FactKind::ReconcileStateMatches, "o1")),
            GrammarRefusal::PostTerminalAppend {
                kind: FactKind::ReconcileStateMatches,
                terminal: FactKind::AckApplied
            }
        );
    }

    // ---- W-ATTEMPT-GRAMMAR: adjudication + the post-adjudication whitelist -------------

    #[test]
    fn adjudication_operates_only_on_a_send_authorized_unresolved_attempt() {
        assert_eq!(
            refusal(&[claim(1, 1, None)], &adjudicated(2)),
            GrammarRefusal::AdjudicationWithoutSendAuthorization
        );
        assert_legal(&[claim(1, 1, None), send_auth(2)], &adjudicated(3));
    }

    #[test]
    fn adjudication_closes_the_operational_axis_only() {
        let state = folded(&[claim(1, 1, None), send_auth(2), adjudicated(3)]);
        assert_eq!(state.operational, OperationalAxis::Closed);
        assert_eq!(state.historical, HistoricalAttribution::Unknown);
        assert_eq!(state.class(), Some(AttemptClass::AdjudicatedHistoricalOpen));
        assert_eq!(state.terminal_attribution, None);
    }

    #[test]
    fn the_post_adjudication_whitelist_refuses_every_other_kind() {
        let chain = [claim(1, 1, None), send_auth(2), adjudicated(3)];
        for kind in FactKind::ALL {
            let payload = match kind {
                FactKind::Claim => FactPayload::Claim { ordinal: 1, predecessor: None },
                FactKind::SendAuthorized => FactPayload::SendAuthorized {
                        exposure_key: exposure("k"),
                            },
                FactKind::FailedPreSend => FactPayload::FailedPreSend { wire_evidence: WireEvidence::ProvenNoWire, reason: PreSendReason::Failure, exposure_block: None, plan_refusal: None },
                FactKind::ReconcileStateMatches | FactKind::ReconcileStateDiffers =>
                    FactPayload::Reconcile { observation: "o".into() },
                FactKind::AdjudicatedUnresolved => FactPayload::Adjudicated { adjudication_id: "a".into() },
                FactKind::SupersededBy => FactPayload::SupersededBy { successor_operation_id: "op-2".into() },
                _ => FactPayload::None,
            };
            let next = fact(4, kind, payload);
            match kind {
                // THE WHITELIST — exactly these three kinds, and nothing else.
                FactKind::LateAckApplied | FactKind::LateAckRefusedNoEffect | FactKind::SupersededBy => {
                    assert_legal(&chain, &next);
                }
                FactKind::Claim => {
                    assert_eq!(refusal(&chain, &next), GrammarRefusal::DuplicateClaim);
                }
                _ => assert_eq!(
                    refusal(&chain, &next),
                    GrammarRefusal::PostAdjudicationWhitelistViolation { kind },
                    "{kind:?} must be refused by the post-adjudication whitelist"
                ),
            }
        }
    }

    #[test]
    fn late_acks_require_adjudication() {
        for kind in [FactKind::LateAckApplied, FactKind::LateAckRefusedNoEffect] {
            assert_eq!(
                refusal(&[claim(1, 1, None), send_auth(2)], &plain(3, kind)),
                GrammarRefusal::LateAckWithoutAdjudication { kind }
            );
        }
        assert_eq!(
            refusal(&[claim(1, 1, None), send_auth(2)], &superseded(3, "op-2")),
            GrammarRefusal::SupersededByWithoutAdjudication
        );
    }

    #[test]
    fn at_most_one_late_ack_and_a_contradictory_second_is_an_anomaly() {
        let chain = [
            claim(1, 1, None),
            send_auth(2),
            adjudicated(3),
            plain(4, FactKind::LateAckApplied),
        ];
        // Same polarity twice = duplicate.
        assert_eq!(
            refusal(&chain, &plain(5, FactKind::LateAckApplied)),
            GrammarRefusal::DuplicateLateAck { existing: FactKind::LateAckApplied }
        );
        // CONTRADICTORY second late ack: refused AND flagged as the anomaly the store must
        // durably annotate on the adjudication record.
        assert_eq!(
            refusal(&chain, &plain(5, FactKind::LateAckRefusedNoEffect)),
            GrammarRefusal::ContradictoryLateAckAnomaly {
                existing: FactKind::LateAckApplied,
                offered: FactKind::LateAckRefusedNoEffect,
            }
        );
    }

    #[test]
    fn a_late_ack_resolves_the_historical_axis_only() {
        let state = folded(&[
            claim(1, 1, None),
            send_auth(2),
            adjudicated(3),
            plain(4, FactKind::LateAckApplied),
        ]);
        assert_eq!(state.historical, HistoricalAttribution::Applied);
        // The OPERATIONAL axis, the class, and the (absent) terminal attribution are
        // untouched — "unknown at decision time" ≠ "unknown forever", and the decision
        // itself is never invalidated.
        assert_eq!(state.operational, OperationalAxis::Closed);
        assert_eq!(state.class(), Some(AttemptClass::AdjudicatedHistoricalOpen));
        assert_eq!(state.terminal_attribution, None);
    }

    #[test]
    fn no_fact_after_both_axes_closed_except_the_whitelist() {
        // Late ack has closed the historical axis; adjudication closed the operational one.
        let chain = [
            claim(1, 1, None),
            send_auth(2),
            adjudicated(3),
            plain(4, FactKind::LateAckApplied),
        ];
        // The whitelist SURVIVES the closure: the one successor link is still legal.
        assert_legal(&chain, &superseded(5, "op-2"));
        // Everything outside it is not.
        assert_eq!(
            refusal(&chain, &reconcile(5, FactKind::ReconcileStateMatches, "o")),
            GrammarRefusal::PostAdjudicationWhitelistViolation { kind: FactKind::ReconcileStateMatches }
        );
    }

    #[test]
    fn at_most_one_superseded_by_and_never_its_own_operation() {
        let chain = [claim(1, 1, None), send_auth(2), adjudicated(3), superseded(4, "op-2")];
        assert_eq!(
            refusal(&chain, &superseded(5, "op-3")),
            GrammarRefusal::DuplicateSupersededBy
        );
        assert_eq!(
            refusal(
                &[claim(1, 1, None), send_auth(2), adjudicated(3)],
                &superseded(4, "op-1")
            ),
            GrammarRefusal::SupersedesOwnOperation
        );
    }

    #[test]
    fn payload_shape_must_match_the_kind() {
        let state = folded(&[claim(1, 1, None)]);
        assert_eq!(
            append_legal(&state, &fact(2, FactKind::SendAuthorized, FactPayload::None)),
            Err(GrammarRefusal::PayloadKindMismatch { kind: FactKind::SendAuthorized })
        );
        assert_eq!(
            append_legal(
                &state,
                &fact(2, FactKind::AckApplied, FactPayload::Reconcile { observation: "o".into() })
            ),
            Err(GrammarRefusal::PayloadKindMismatch { kind: FactKind::AckApplied })
        );
    }

    // ---- the fold's own integrity (a persisted chain is not trusted) ------------------

    #[test]
    fn fold_derives_the_two_axis_state_over_every_shape() {
        let table: [(&str, Vec<Fact>, AttemptClass, HistoricalAttribution, OperationalAxis); 7] = [
            ("claimed only", vec![claim(1, 1, None)], AttemptClass::PreIssuance, HistoricalAttribution::Unknown, OperationalAxis::Active),
            ("authorized", vec![claim(1, 1, None), send_auth(2)], AttemptClass::IssuedOrUnknown, HistoricalAttribution::Unknown, OperationalAxis::Active),
            ("ambiguous", vec![claim(1, 1, None), send_auth(2), plain(3, FactKind::AckAmbiguous)], AttemptClass::IssuedOrUnknown, HistoricalAttribution::Unknown, OperationalAxis::Active),
            ("applied", vec![claim(1, 1, None), send_auth(2), plain(3, FactKind::AckApplied)], AttemptClass::TerminalApplied, HistoricalAttribution::Applied, OperationalAxis::Closed),
            ("refused", vec![claim(1, 1, None), send_auth(2), plain(3, FactKind::AckRefusedNoEffect)], AttemptClass::TerminalRefusedNoEffect, HistoricalAttribution::RefusedNoEffect, OperationalAxis::Closed),
            ("pre-send failure", vec![claim(1, 1, None), failed_pre_send(2, WireEvidence::Indeterminate)], AttemptClass::TerminalFailedPreSend, HistoricalAttribution::FailedPreSend, OperationalAxis::Closed),
            ("severed", vec![claim(1, 1, None), plain(2, FactKind::SeveredBeforeIssuance)], AttemptClass::TerminalSeveredBeforeIssuance, HistoricalAttribution::SeveredBeforeIssuance, OperationalAxis::Closed),
        ];
        for (name, chain, class, historical, operational) in table {
            let s = folded(&chain);
            assert_eq!(s.class(), Some(class), "{name}: class");
            assert_eq!(s.historical, historical, "{name}: historical axis");
            assert_eq!(s.operational, operational, "{name}: operational axis");
            assert_eq!(s.current_revision, chain.len() as u64, "{name}: head revision");
            assert_eq!(s.claim.as_ref().map(|c| c.operation_id.as_str()), Some("op-1"), "{name}: owner");
        }
    }

    #[test]
    fn fold_refuses_an_empty_chain() {
        assert_eq!(fold(&[]), Err(FoldDefect::EmptyChain));
    }

    #[test]
    fn fold_refuses_a_broken_revision_chain() {
        // duplicate revision (the append-only trigger's twin, checked in the fold too)
        assert_eq!(
            fold(&[claim(1, 1, None), Fact { revision: 1, prior_revision: None, ..send_auth(2) }]),
            Err(FoldDefect::RevisionNotContiguous { index: 1, expected: 2, found: 1 })
        );
        // skipped revision
        assert_eq!(
            fold(&[claim(1, 1, None), Fact { revision: 3, ..send_auth(2) }]),
            Err(FoldDefect::RevisionNotContiguous { index: 1, expected: 2, found: 3 })
        );
        // first revision must be 1
        assert_eq!(
            fold(&[Fact { revision: 2, ..claim(1, 1, None) }]),
            Err(FoldDefect::FirstRevisionNotOne { found: 2 })
        );
        // the first fact carries no compare-and-append link
        assert_eq!(
            fold(&[Fact { prior_revision: Some(0), ..claim(1, 1, None) }]),
            Err(FoldDefect::FirstFactHasPriorRevision { found: 0 })
        );
        // the compare-and-append link must point at the previous revision
        assert_eq!(
            fold(&[claim(1, 1, None), Fact { prior_revision: Some(7), ..send_auth(2) }]),
            Err(FoldDefect::PriorRevisionMismatch { index: 1, expected: 1, found: Some(7) })
        );
    }

    #[test]
    fn fold_refuses_an_owner_or_attempt_drift() {
        assert_eq!(
            fold(&[claim(1, 1, None), Fact { operation_id: "op-OTHER".into(), ..send_auth(2) }]),
            Err(FoldDefect::OwnerMismatch { index: 1 })
        );
        assert_eq!(
            fold(&[claim(1, 1, None), Fact { attempt_id: "att-OTHER".into(), ..send_auth(2) }]),
            Err(FoldDefect::AttemptIdMismatch { index: 1 })
        );
    }

    #[test]
    fn fold_refuses_a_non_canonical_or_backward_created_at() {
        assert_eq!(
            fold(&[Fact { created_at: "not-a-time".into(), ..claim(1, 1, None) }]),
            Err(FoldDefect::NonCanonicalCreatedAt { index: 0 })
        );
        // The clamp is a WRITE promise; this is its READ-side proof.
        assert_eq!(
            fold(&[
                claim(1, 1, None),
                Fact { created_at: "2026-08-07T23:59:59Z".into(), ..send_auth(2) }
            ]),
            Err(FoldDefect::CreatedAtWentBackward { index: 1 })
        );
    }

    #[test]
    fn fold_refuses_a_persisted_illegal_fact() {
        // A chain that the append door could never have produced — e.g. an ACK before any
        // authorization. The fold does not repair it; it names it.
        assert_eq!(
            fold(&[claim(1, 1, None), plain(2, FactKind::AckApplied)]),
            Err(FoldDefect::IllegalFact {
                index: 1,
                refusal: GrammarRefusal::AckWithoutSendAuthorization { kind: FactKind::AckApplied }
            })
        );
    }

    #[test]
    fn witness_class_at_sever_transcribes_the_5_2c_bullet() {
        assert_eq!(
            folded(&[claim(1, 1, None)]).witness_class_at_sever(),
            Some(WitnessClass::SeveredBeforeIssuance)
        );
        assert_eq!(
            folded(&[claim(1, 1, None), send_auth(2)]).witness_class_at_sever(),
            Some(WitnessClass::IssuedOrUnknown)
        );
        // A terminal or adjudicated attempt is not a live member: its OPERATION classifies.
        assert_eq!(
            folded(&[claim(1, 1, None), send_auth(2), plain(3, FactKind::AckApplied)]).witness_class_at_sever(),
            None
        );
        assert_eq!(
            folded(&[claim(1, 1, None), send_auth(2), adjudicated(3)]).witness_class_at_sever(),
            None
        );
        assert_eq!(DerivedState::empty().witness_class_at_sever(), None);
    }

    // ---- the clamped-monotonic created_at ---------------------------------------------

    #[test]
    fn clamped_now_takes_the_max_and_surfaces_a_backward_step() {
        // forward clock: `now` wins, no backward step.
        let c = clamped_now("2026-08-08T00:00:10Z", "2026-08-08T00:00:00Z").expect("canonical");
        assert_eq!(c.value, "2026-08-08T00:00:10Z");
        assert!(!c.backward_step_detected);
        // equal: not a backward step (the clamp is `max`, and equality moves nothing).
        let c = clamped_now("2026-08-08T00:00:00Z", "2026-08-08T00:00:00Z").expect("canonical");
        assert_eq!(c.value, "2026-08-08T00:00:00Z");
        assert!(!c.backward_step_detected);
        // ROLLBACK: the latch wins AND the step is surfaced — review-now, never
        // silently-later.
        let c = clamped_now("2026-08-07T00:00:00Z", "2026-08-08T00:00:00Z").expect("canonical");
        assert_eq!(c.value, "2026-08-08T00:00:00Z");
        assert!(c.backward_step_detected);
        // the absent latch (no fact yet) sorts below every RFC-3339 instant.
        let c = clamped_now("2026-08-08T00:00:00Z", "").expect("canonical");
        assert_eq!(c.value, "2026-08-08T00:00:00Z");
        assert!(!c.backward_step_detected);
    }

    #[test]
    fn clamped_now_fails_loud_on_a_non_canonical_input() {
        // prestate.rs's COMPLEMENT RULE, on the READ side of both inputs.
        assert_eq!(
            clamped_now("zzz", "2026-08-08T00:00:00Z"),
            Err(ClockDefect::NonCanonicalNow)
        );
        assert_eq!(
            clamped_now("2026-08-08T00:00:00Z", "zzz-not-a-time"),
            Err(ClockDefect::NonCanonicalMaxPersisted)
        );
        // …including a value that sorts LOW, the direction a MAX-only check misses.
        assert_eq!(
            clamped_now("2026-08-08T00:00:00Z", "!"),
            Err(ClockDefect::NonCanonicalMaxPersisted)
        );
    }

    // ---- §5.1 the canonical witness encoding ------------------------------------------

    #[test]
    fn witness_class_byte_mapping_is_the_versioned_table() {
        // The bytes ARE the standard (§5.1): a new class requires a new
        // domain-tag version, never a reused byte. Changing a value here is a wire break.
        assert_eq!(WitnessClass::NoActiveAttempt.as_byte(), 0x01);
        assert_eq!(WitnessClass::Completed.as_byte(), 0x02);
        assert_eq!(WitnessClass::SeveredBeforeIssuance.as_byte(), 0x03);
        assert_eq!(WitnessClass::IssuedOrUnknown.as_byte(), 0x04);
        assert_eq!(SEVER_WITNESS_DOMAIN_TAG, b"photon.sever-witness.v1");
        assert_eq!(SEVER_WITNESS_DOMAIN_TAG.len(), 23);
        // every class has a distinct byte
        let mut bytes: Vec<u8> = WitnessClass::ALL.iter().map(|c| c.as_byte()).collect();
        bytes.sort_unstable();
        bytes.dedup();
        assert_eq!(bytes.len(), WitnessClass::ALL.len());
    }

    #[test]
    fn sever_witness_golden_bytes_and_digest() {
        // A hand-computed two-member case, byte for byte, per §5.1's "EVERY byte specified".
        let members = vec![
            WitnessMember::Operation { operation_id: b"op-1".to_vec() },
            WitnessMember::Attempt {
                attempt_id: b"att-1".to_vec(),
                attempt_revision: 7,
                class_at_sever: WitnessClass::IssuedOrUnknown,
            },
        ];
        let mut expected: Vec<u8> = Vec::new();
        expected.extend_from_slice(b"photon.sever-witness.v1"); // domain tag, no terminator
        expected.extend_from_slice(&[0x00, 0x00, 0x00, 0x02]); // member_count u32-BE
        // OperationMember: tag 0x01 | len 4 | "op-1" | class 0x01 (NO_ACTIVE_ATTEMPT)
        expected.extend_from_slice(&[0x01, 0x00, 0x00, 0x00, 0x04]);
        expected.extend_from_slice(b"op-1");
        expected.push(0x01);
        // AttemptMember: tag 0x02 | len 5 | "att-1" | revision u64-BE | class 0x04
        expected.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x05]);
        expected.extend_from_slice(b"att-1");
        expected.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 7]);
        expected.push(0x04);
        assert_eq!(expected.len(), 56);
        assert_eq!(encode_sever_witness(&members), expected);
        // The digest hex was computed by an INDEPENDENT implementation (Windows CNG
        // SHA-384 over the same 56 bytes) — a golden that only agrees with itself proves
        // nothing about "two implementations following this paragraph cannot differ".
        assert_eq!(
            sever_witness_digest_hex(&members),
            "8feae3570c896862784060dce72c6dc405d8d56cfadcdbd693d2a195165331bcb67bba582538328404f72a32f6b35851"
        );
    }

    #[test]
    fn sever_witness_sorts_bytewise_over_fully_encoded_members() {
        // Sort order is over the FULLY ENCODED byte string, tag byte included — NOT over the
        // ids. An OperationMember with a high id therefore precedes an AttemptMember with a
        // low one, because 0x01 < 0x02.
        let op = WitnessMember::Operation { operation_id: b"zz".to_vec() };
        let att = WitnessMember::Attempt {
            attempt_id: b"aa".to_vec(),
            attempt_revision: 1,
            class_at_sever: WitnessClass::SeveredBeforeIssuance,
        };
        let encoded = encode_sever_witness(&[att.clone(), op.clone()]);
        let head = SEVER_WITNESS_DOMAIN_TAG.len() + 4;
        assert_eq!(&encoded[head..head + op.encode().len()], &op.encode()[..]);
        // Input order is irrelevant: the encoding is canonical.
        assert_eq!(encoded, encode_sever_witness(&[op.clone(), att.clone()]));
        assert_eq!(
            sever_witness_digest(&[att.clone(), op.clone()]),
            sever_witness_digest(&[op, att])
        );
    }

    #[test]
    fn length_prefixes_defeat_ambiguous_concatenation() {
        // The mutant: two DIFFERENT member sets whose naive id concatenation is IDENTICAL.
        let set_a = vec![
            WitnessMember::Operation { operation_id: b"ab".to_vec() },
            WitnessMember::Operation { operation_id: b"c".to_vec() },
        ];
        let set_b = vec![
            WitnessMember::Operation { operation_id: b"a".to_vec() },
            WitnessMember::Operation { operation_id: b"bc".to_vec() },
        ];
        // Naive concatenation (what an implementation WITHOUT length prefixes produces):
        let naive = |ms: &[WitnessMember]| -> Vec<u8> {
            let mut ids: Vec<Vec<u8>> = ms
                .iter()
                .map(|m| match m {
                    WitnessMember::Operation { operation_id } => operation_id.clone(),
                    WitnessMember::Attempt { attempt_id, .. } => attempt_id.clone(),
                })
                .collect();
            ids.sort();
            ids.concat()
        };
        assert_eq!(naive(&set_a), naive(&set_b), "the mutant must be ambiguous naively");
        // With the u32-BE length prefixes the two are distinguishable — the digests differ.
        assert_ne!(encode_sever_witness(&set_a), encode_sever_witness(&set_b));
        assert_ne!(sever_witness_digest(&set_a), sever_witness_digest(&set_b));
    }

    #[test]
    fn an_empty_member_set_still_encodes_a_count() {
        // A sever with nothing active is a real, witnessable event: the count is 0, and the
        // digest is over the tag + count, never an empty string.
        let mut expected: Vec<u8> = SEVER_WITNESS_DOMAIN_TAG.to_vec();
        expected.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(encode_sever_witness(&[]), expected);
    }

    // ── The touched-atom exposure key (§5.2d EXP-1) ────────────────────────────────────

    fn basis(
        native: &str,
        atoms: &[(&str, &str)],
        targets: &[(&str, bool)],
    ) -> crate::prestate::FrozenBasis {
        crate::prestate::FrozenBasis {
            native_resource_key: native.into(),
            touched_atoms: atoms
                .iter()
                .map(|(a, o)| (a.to_string(), o.to_string()))
                .collect(),
            atom_targets: targets.iter().map(|(a, v)| (a.to_string(), *v)).collect(),
            role_bindings: std::collections::BTreeMap::new(),
            freshness: crate::prestate::Freshness::ImmutableConstants,
        }
    }

    #[test]
    fn the_exposure_key_copies_the_frozen_atoms_with_their_directions() {
        // EXP-1: "keyed by account/provider scope + the provider-native PRIMITIVE touched atom
        // + effect direction … derived from the operation's immutable frozen basis". Direction
        // comes from `atom_targets` — the value the atom holds AFTER the action — and an atom
        // with NO target is honestly `Unknown`, never a defaulted `Clear`.
        let key = ExposureKey::from_basis(&basis(
            "res-1",
            &[("membership:INBOX", "INBOX"), ("keyword:$seen", "$seen")],
            &[("membership:INBOX", false)],
        ));
        // The scope is the PROVIDER's, taken from the basis — never a local account handle
        // (`from_basis` no longer HAS a channel for one).
        assert_eq!(key.provider_scope, "res-1");
        let directions: Vec<(String, ExposureDirection)> = key
            .atoms
            .iter()
            .map(|a| (a.atom_key.clone(), a.direction))
            .collect();
        assert_eq!(
            directions,
            vec![
                (
                    exposure_atom_key("res-1", "keyword:$seen"),
                    ExposureDirection::Unknown
                ),
                (
                    exposure_atom_key("res-1", "membership:INBOX"),
                    ExposureDirection::Clear
                ),
            ],
            "every frozen atom, sorted canonically, each with its own honest direction"
        );
        // Canonical: the same basis always derives the same key, so a fence and an adjudication
        // deriving it independently cannot disagree.
        assert_eq!(
            key,
            ExposureKey::from_basis(&basis(
                "res-1",
                &[("keyword:$seen", "$seen"), ("membership:INBOX", "INBOX")],
                &[("membership:INBOX", false)],
            ))
        );
        let set = ExposureKey::from_basis(&basis(
            "res-1",
            &[("membership:INBOX", "INBOX")],
            &[("membership:INBOX", true)],
        ));
        assert_eq!(set.atoms[0].direction, ExposureDirection::Set);
    }

    #[test]
    fn the_exposure_atom_key_is_injective_over_resource_and_atom() {
        // EXP-5 depends on this: an obligation over ONE message's `membership:INBOX` must not
        // gate a DIFFERENT message's, and two (resource, atom) pairs must never collide into
        // one key. Provider ids are opaque, so the pair is joined by the crate's ONE injective
        // encoding rather than by a separator that a component could forge.
        assert_ne!(
            exposure_atom_key("a", "b:c"),
            exposure_atom_key("a:b", "c"),
            "a naive join would spell these identically"
        );
        assert_ne!(
            exposure_atom_key("msg-1", "membership:INBOX"),
            exposure_atom_key("msg-2", "membership:INBOX"),
            "the same primitive atom on two resources is two identities"
        );
        assert_eq!(
            exposure_atom_key("msg-1", "membership:INBOX"),
            exposure_atom_key("msg-1", "membership:INBOX"),
            "…and it is a function"
        );
    }

    #[test]
    fn a_send_authorization_records_its_exposure_key_and_nothing_else() {
        // The `SEND_AUTHORIZED` payload's WHOLE cargo is the exposure key the adjudication
        // record derives from. The store door deleted the staging `dispatch_episode` alongside it —
        // see the payload's own doc: with a fresh attempt per retry, "at most one
        // SEND_AUTHORIZED" needs no counter to qualify it.
        let key = exposure("membership:INBOX");
        let state = fold(&[
            claim(1, 1, None),
            fact(
                2,
                FactKind::SendAuthorized,
                FactPayload::SendAuthorized {
                    exposure_key: key.clone(),
                },
            ),
        ])
        .expect("a legal chain");
        assert!(state.send_authorized);
        assert_eq!(state.exposure_key, Some(key));
        assert_eq!(state.class(), Some(AttemptClass::IssuedOrUnknown));
        // A SECOND authorization on the same attempt is refused by the grammar alone.
        assert_eq!(
            append_legal(
                &state,
                &fact(
                    3,
                    FactKind::SendAuthorized,
                    FactPayload::SendAuthorized {
                        exposure_key: exposure("membership:INBOX"),
                    },
                ),
            ),
            Err(GrammarRefusal::DuplicateSendAuthorized)
        );
    }
    // ---- §5.2a INCREMENTAL VERIFICATION (the boot-quarantine baseline) ----------------

    #[test]
    fn folding_a_delta_from_every_split_point_equals_folding_the_whole_chain() {
        // The property the O(delta) open-time verification rests on: a baseline plus its
        // delta is the SAME state as the chain. Checked at every split, so no split is a
        // special case — including the empty delta (a finalized chain's steady state) and
        // the pristine one (the full fold).
        let chain = vec![
            claim(1, 1, None),
            send_auth(2),
            reconcile(3, FactKind::ReconcileStateDiffers, "differs"),
            plain(4, FactKind::AckAmbiguous),
            adjudicated(5),
            plain(6, FactKind::LateAckApplied),
        ];
        let whole = fold(&chain).expect("the chain folds");
        for split in 0..=chain.len() {
            let baseline = fold(&chain[..split]).unwrap_or_else(|_| DerivedState::empty());
            let anchor = if split == 0 { "" } else { chain[split - 1].created_at.as_str() };
            let state = fold_delta(
                &FoldBaseline {
                    state: &baseline,
                    revision: split as u64,
                    created_at: anchor,
                },
                &chain[split..],
            )
            .unwrap_or_else(|d| panic!("the delta after {split} fact(s) must fold: {d}"));
            assert_eq!(state, whole, "split after {split} fact(s)");
        }
    }

    #[test]
    fn a_delta_that_does_not_continue_the_baseline_is_a_defect() {
        let chain = vec![claim(1, 1, None), send_auth(2)];
        let baseline = fold(&chain).expect("folds");
        // A GAP: the baseline is at revision 2, the delta opens at 4.
        let gapped = fold_delta(
            &FoldBaseline {
                state: &baseline,
                revision: 2,
                created_at: T0,
            },
            &[plain(4, FactKind::AckApplied)],
        );
        assert!(
            matches!(
                gapped,
                Err(FoldDefect::RevisionNotContiguous {
                    index: 0,
                    expected: 3,
                    found: 4
                })
            ),
            "a withheld row must not be foldable as a shorter history: {gapped:?}"
        );
        // A BROKEN LINK at the seam: the right revision, the wrong compare-and-append target.
        let mut unlinked = plain(3, FactKind::AckApplied);
        unlinked.prior_revision = Some(1);
        let answer = fold_delta(
            &FoldBaseline {
                state: &baseline,
                revision: 2,
                created_at: T0,
            },
            &[unlinked],
        );
        assert!(
            matches!(
                answer,
                Err(FoldDefect::PriorRevisionMismatch {
                    index: 0,
                    expected: 2,
                    found: Some(1)
                })
            ),
            "the seam is checked exactly as an intra-delta link is: {answer:?}"
        );
    }

    #[test]
    fn an_ill_formed_baseline_is_refused_rather_than_trusted() {
        // The baseline is TRUSTED, which is precisely why a baseline that no fold of this
        // grammar could have produced must not be readable as one.
        let unclaimed = DerivedState::empty();
        assert_eq!(
            fold_delta(
                &FoldBaseline {
                    state: &unclaimed,
                    revision: 3,
                    created_at: T0,
                },
                &[],
            ),
            Err(FoldDefect::BaselineUnclaimed { revision: 3 }),
            "revision 1 of every attempt IS its claim"
        );
        let claimed = fold(&[claim(1, 1, None)]).expect("folds");
        assert_eq!(
            fold_delta(
                &FoldBaseline {
                    state: &claimed,
                    revision: 1,
                    created_at: "8 Aug 2026",
                },
                &[],
            ),
            Err(FoldDefect::BaselineNonCanonicalCreatedAt),
            "the monotonicity anchor clears the shape authority before it is compared"
        );
    }

    #[test]
    fn a_delta_carrying_a_fact_the_grammar_refuses_never_folds() {
        // The head cannot launder a defect: an illegal fact appended behind the watermark is
        // caught by the DELTA fold, which is the only thing open-time verification runs.
        let chain = vec![claim(1, 1, None), send_auth(2)];
        let baseline = fold(&chain).expect("folds");
        let answer = fold_delta(
            &FoldBaseline {
                state: &baseline,
                revision: 2,
                created_at: T0,
            },
            &[send_auth(3)],
        );
        assert!(
            matches!(
                answer,
                Err(FoldDefect::IllegalFact {
                    index: 0,
                    refusal: GrammarRefusal::DuplicateSendAuthorized
                })
            ),
            "at most one SEND_AUTHORIZED, on the incremental path too: {answer:?}"
        );
    }
}
