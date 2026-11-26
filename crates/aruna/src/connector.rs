//! The connector seam: the `Connector` trait, its error and evidence types, and the effect witness.

use crate::{Command, LogError};

#[cfg(doc)]
use crate::{CommandBus, IntentLog};

/// Whether a connector failure is worth retrying. The policy (which provider errors map to
/// which kind, e.g. 404/permission = deterministic, 429/503/timeout = transient) belongs to
/// each real connector (ADR-P013); the engine only consumes the kind a connector declares. A
/// connector that does not classify is treated as `Transient`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    /// Retryable below the seam: timeout, rate limit, downstream unavailable. Leave the intent
    /// non-terminal for the next recovery sweep (retry with cap and backoff).
    Transient,
    /// Non-retryable: validation, permission, missing target. Dead-letter immediately to the
    /// terminal `Failed` state, since retrying a deterministic failure only loops (ADR-P013).
    Deterministic,
}

/// What a connector can positively prove about a failed mutation's effect. Orthogonal to
/// [`FailureKind`], which is the retry taxonomy and asks a different question ("is an identical
/// retry worth making?").
///
/// **Positive proof, not failure name.** Each ack verdict is defined by what the provider proved
/// (the requested effect, a rejection before effect, or nothing), and the default is
/// `Indeterminate`: absence of proof is never proof.
///
/// Why three values and not two: `FailureKind::Deterministic` cannot stand in for "the provider
/// definitively refused". The Gmail transport classifies an unprovable post-dispatch stall as
/// deterministic on purpose (fail closed), yet such a failure is `ISSUANCE_UNKNOWN`. Deriving
/// `ACK_REFUSED_NO_EFFECT` from the retry kind alone would record "no effect" for an outcome the
/// connector never claimed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EffectEvidence {
    /// The connector proved the mutation was never issued: no request that could have had an
    /// effect left the host (the DNS/connect/TLS stage, and every refusal decided from local
    /// values before a mutation request was built). `FAILED_PRE_SEND`: no effect exists, and the
    /// failure stays safely retryable.
    ///
    /// The claim is about the mutation, not "any byte": non-effectful traffic does not disturb
    /// it. [`ConnectorError::deterministic_basis_rebound`] claims it for a refusal raised after
    /// identity re-verification reads (`JmapConnector::reverify_role_basis` makes two cursor reads
    /// and two role lookups first). A connector may claim this exactly when it can prove no
    /// mutation request was dispatched, never for a mutation whose fate it does not know.
    ProvenNoWire,
    /// The provider answered and definitively refused before any effect (the 4xx-class
    /// validation / permission / missing-target response). `ACK_REFUSED_NO_EFFECT`.
    ProvenRefusedNoEffect,
    /// Anything else, including a 5xx (Gmail's own retry guidance is not proof of no effect)
    /// and any truncated or absent post-dispatch response. `ACK_AMBIGUOUS` / `ISSUANCE_UNKNOWN`.
    #[default]
    Indeterminate,
}

impl EffectEvidence {
    /// The grammar's two-valued projection ([`crate::attempt::WireEvidence`]), which is what a
    /// `FAILED_PRE_SEND` payload records. Only [`EffectEvidence::ProvenNoWire`] projects to
    /// `ProvenNoWire`: a proven refusal is proof about the provider's decision, not about the
    /// wire, and takes the `ACK_REFUSED_NO_EFFECT` path instead.
    pub fn wire_evidence(&self) -> crate::attempt::WireEvidence {
        match self {
            EffectEvidence::ProvenNoWire => crate::attempt::WireEvidence::ProvenNoWire,
            EffectEvidence::ProvenRefusedNoEffect | EffectEvidence::Indeterminate => {
                crate::attempt::WireEvidence::Indeterminate
            }
        }
    }
}

/// An error returned by a connector when a mutation could not be applied below the seam,
/// tagged with whether it is worth retrying (`FailureKind`) and with what the connector can
/// prove about the request's effect ([`EffectEvidence`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorError {
    pub message: String,
    pub kind: FailureKind,
    /// The positive proof, if any. Every constructor defaults it to
    /// [`EffectEvidence::Indeterminate`]: a connector that says nothing has proven nothing.
    pub effect_evidence: EffectEvidence,
    /// The provider refused the credential (an HTTP 401-class answer, such as an expired or
    /// revoked access token), not the request. A third axis beside the retry kind and the
    /// effect evidence: it says whose refusal this is, which neither of the other two can.
    /// Every constructor defaults it to `false`; only a connector that classified the answer
    /// as its auth family says otherwise ([`ConnectorError::credential_rejected`]; the Gmail
    /// connector's `GmailError::Unauthorized`). [`CommandBus::preflight_plan`] reads it: an
    /// auth-class observation failure says nothing about the member, so it is an error with
    /// nothing written, never that member's divergence.
    pub credential_rejected: bool,
    /// The connector's own published capability map does not carry this verb (ADR-P010: each
    /// write capability is enabled per provider and tier), so the refusal is decided from a
    /// local value before any request exists. A fourth axis, for the same reason as
    /// `credential_rejected`: the caller must be able to name this refusal
    /// (`unsupported_capability`) rather than read a transport sentence it never reached.
    /// Every constructor defaults it to `false`; only a connector's capability refusal sets it
    /// ([`ConnectorError::unsupported_capability`]).
    pub unsupported_capability: bool,
}

impl ConnectorError {
    /// A retryable failure (the M0 default for a connector that does not classify its errors).
    pub fn transient(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            kind: FailureKind::Transient,
            effect_evidence: EffectEvidence::Indeterminate,
            credential_rejected: false,
            unsupported_capability: false,
        }
    }

    /// A non-retryable failure: dead-letter immediately, no retry (ADR-P013 deterministic class).
    pub fn deterministic(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            kind: FailureKind::Deterministic,
            effect_evidence: EffectEvidence::Indeterminate,
            credential_rejected: false,
            unsupported_capability: false,
        }
    }

    /// Tag this failure as the provider refusing the credential, not the request (see the
    /// `credential_rejected` field). Only a connector that classified the answer as its auth
    /// family may say this.
    pub fn credential_rejected(mut self) -> Self {
        self.credential_rejected = true;
        self
    }

    /// Tag this failure as the connector's own capability map refusing the verb (see the
    /// `unsupported_capability` field).
    pub fn unsupported_capability(mut self) -> Self {
        self.unsupported_capability = true;
        self
    }

    /// Tag this failure with the connector's positive proof that no mutation request left the
    /// host. Only a connector that can prove the stage may say this.
    pub fn proven_no_wire(mut self) -> Self {
        self.effect_evidence = EffectEvidence::ProvenNoWire;
        self
    }

    /// Tag this failure as a definitive provider refusal before any effect
    /// (`ACK_REFUSED_NO_EFFECT`): the provider answered, and its answer was "no".
    pub fn proven_refused_no_effect(mut self) -> Self {
        self.effect_evidence = EffectEvidence::ProvenRefusedNoEffect;
        self
    }

    /// The provider answered for a native identity that is no longer the one admission froze
    /// (a rebind of the Photon-local ref), or it no longer covers every frozen atom.
    /// Deterministic: a frozen basis is immutable, so retrying the same admitted operation can
    /// only ask the same wrong question again.
    ///
    /// Proven no wire: every site that raises this refuses on a local comparison before any
    /// mutation request is built (the engine's capture pipeline, the undo drive's basis-match
    /// check, and the connectors' pre-mutation re-verification). Nothing was sent, so
    /// `FAILED_PRE_SEND` is the truthful attribution even when the refusal lands after the
    /// send-authorization boundary.
    pub fn deterministic_basis_rebound() -> Self {
        Self::deterministic(
            "basis rebound: provider identity no longer matches the admission-frozen basis",
        )
        .proven_no_wire()
    }
}

/// Resolution failure at the admission boundary: a missing or invalid resolver basis refuses
/// admission with a named, retryable error. Never a wire call in the transaction, never a
/// stale fallback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveBasisError(pub String);

/// What a connector observed at the moment of effect, beside the boolean atom projection the
/// journal already carries. A separate typed field: the vector holds provider label ids, not
/// atoms, and `JournalRow::validate`'s touched-atom key-set equality does not read it. `None`
/// means no vector was observed on this route (JMAP, and every connector on the trait's
/// default [`Connector::apply_witnessed`]); `Some(set)` is the route's answer, which may
/// legitimately be empty (a message with no labels). The bus persists a `Some` beside the
/// operation ([`IntentLog::record_effect_witness`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EffectWitness {
    pub provider_label_vector: Option<std::collections::BTreeSet<String>>,
}

/// The persisted effect witness, read back (`IntentLog::effect_witness`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectWitnessRow {
    /// `intents.effect_label_vector`. Both stores return a row only when a vector is persisted,
    /// so a row they hand out carries `Some`; the `Option` mirrors the nullable column.
    pub effect_label_vector: Option<std::collections::BTreeSet<String>>,
    /// `intents.ripple_verdict` (+ `ripple_unexpected`); `None` means no pre-effect vector was
    /// available to judge the delta against.
    pub ripple_verdict: Option<crate::prestate::RippleVerdict>,
}

/// The single computation of the row both stores persist, so the in-memory twin cannot judge
/// a ripple differently from the durable store. The closure is the frozen basis's resolved
/// operands (`touched_atoms` values, the label ids the verb declared it touches), never its
/// atom keys. The verdict needs both vectors; with both present and no frozen basis it
/// refuses rather than judge against a guessed closure.
pub(crate) fn effect_witness_row(
    idempotency_key: &str,
    witness: &EffectWitness,
    pre: Option<&std::collections::BTreeSet<String>>,
    basis: Option<&crate::prestate::FrozenBasis>,
) -> Result<EffectWitnessRow, LogError> {
    let ripple_verdict = match (pre, &witness.provider_label_vector) {
        (Some(pre), Some(post)) => {
            let basis = basis.ok_or_else(|| {
                LogError(format!(
                    "record_effect_witness refused: '{idempotency_key}' has no frozen basis to take \
                     the closure from"
                ))
            })?;
            let closure: std::collections::BTreeSet<String> =
                basis.touched_atoms.values().cloned().collect();
            Some(crate::prestate::ripple_verdict(pre, post, &closure))
        }
        _ => None,
    };
    Ok(EffectWitnessRow {
        effect_label_vector: witness.provider_label_vector.clone(),
        ripple_verdict,
    })
}

/// The refusal both stores raise for a second `record_effect_witness` on an operation that
/// already holds its witness.
pub(crate) fn effect_witness_already_recorded(idempotency_key: &str) -> LogError {
    LogError(format!(
        "record_effect_witness refused: '{idempotency_key}' already holds its effect witness — an \
         effect is observed once, and a re-record would overwrite evidence"
    ))
}

/// The below-the-seam actuator: applies one command against a provider (mock, IMAP, JMAP…).
/// Provider-native ids live entirely behind this trait.
pub trait Connector {
    /// Dispatch the forward mutation, made only after the engine's send-authorization boundary.
    /// The bus's forward dispatch paths (`execute` and the `recover` sweep) call
    /// [`Connector::apply_witnessed`], which is this effect plus what the route observed; `apply`
    /// is its projection with the witness dropped (the trait default of `apply_witnessed` is
    /// `apply` with no vector). An override of `apply_witnessed` owes the two the same effect.
    ///
    /// **The basis is an argument:** dispatch never re-resolves. A binding change between
    /// admission and dispatch must refuse, not retarget; the frozen basis is the identity the
    /// wire may touch. Re-resolving account/message/mailbox ids at dispatch time would let a
    /// rebind put the wire on ids the exposure check never examined and the `SEND_AUTHORIZED`
    /// payload never named.
    ///
    /// An implementation owes one of two behaviors for every identity it consumes:
    /// - identity it must re-resolve to route the write (the provider account and message
    ///   handles): re-resolve, then refuse with `deterministic_basis_rebound` if the result does
    ///   not equal [`crate::prestate::FrozenBasis::native_resource_key`];
    /// - identity that is an operand of the write (JMAP's role-to-mailbox pair): take it from the
    ///   frozen basis and never re-resolve it.
    ///
    /// Neither costs an extra provider read: both are decided on values `apply` already had.
    fn apply(
        &self,
        command: &Command,
        basis: &crate::prestate::FrozenBasis,
    ) -> Result<(), ConnectorError>;

    /// `apply`, returning what the route observed at effect. The default is plain `apply` with
    /// no vector, so connectors and fakes that do not observe keep working; Gmail overrides it
    /// (each of its routes hands the label set back).
    fn apply_witnessed(
        &self,
        command: &Command,
        basis: &crate::prestate::FrozenBasis,
    ) -> Result<EffectWitness, ConnectorError> {
        self.apply(command, basis).map(|()| EffectWitness::default())
    }

    /// Resolve the command's provider-native basis from local durable resolver state only.
    /// Any provider I/O needed to obtain or refresh resolution state runs elsewhere, since this
    /// is consumed inside the admission path. The returned basis carries provider-scoped
    /// identity and freshness provenance.
    fn resolve_basis(
        &self,
        command: &Command,
    ) -> Result<crate::prestate::FrozenBasis, ResolveBasisError>;

    /// Read the current value of the command's touched atoms from the provider (network I/O;
    /// the caller guarantees no write transaction is open). The implementation must answer for
    /// the native identity it read (the input to basis verification) and may not consult or
    /// mutate engine state.
    fn observe(
        &self,
        command: &Command,
        basis: &crate::prestate::FrozenBasis,
    ) -> Result<crate::prestate::Observation, ConnectorError>;

    /// Restore dispatch: write the captured pre-state values `p` back onto the touched atoms,
    /// in the connector's native delta form (Gmail add/remove label arrays; JMAP path-scoped
    /// PatchObject entries such as `"mailboxIds/<id>": true|null` and
    /// `"keywords/<kw>": true|null`, RFC 8620 §5.3). Never a whole-object write, which the
    /// restore path prohibits, and never derived from the action direction: a fixed pattern
    /// would re-apply the forward result on an Unarchive undo and corrupt noncanonical
    /// pre-states such as membership in both. Every value comes from `p`.
    fn restore(
        &self,
        command: &Command,
        basis: &crate::prestate::FrozenBasis,
        p: &std::collections::BTreeMap<String, bool>,
    ) -> Result<(), ConnectorError>;
}
