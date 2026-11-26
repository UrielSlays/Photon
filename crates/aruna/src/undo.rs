//! The undo presentation and restoration verdict a caller reads.

use crate::EffectWitnessRow;

#[cfg(doc)]
use crate::{CommandBus, IntentLog};

/// What a user is shown about an undo, derived at read time from the parent's stored
/// lifecycle plus its undo child's. It is never stored and never consumed by ordering,
/// capacity, head-gating or recovery: those read the stored lifecycle, which stays the last
/// verified truth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UndoPresentation {
    /// No undo child, or nothing worth surfacing: mirror the lifecycle.
    None,
    /// Parent `Applied` + a non-terminal child: "undoing", scheduled but not yet verified.
    Undoing,
    /// Parent `Undone`: the restore (or the no-op) was verified.
    Undone,
    /// Parent `Applied` + a terminally `Failed` child: the undo did not happen and the
    /// refusal is surfaced (a conflict or deterministic refusal), not hidden behind a
    /// lifecycle that still reads "applied" with no explanation.
    AppliedUndoFailed,
    /// The operation's objective was produced by another actor while it sat in its retry gap,
    /// so it completed `EXTERNALLY_SATISFIED`: terminal, and permanently undo-ineligible
    /// because a stale captured `P` must never reverse that actor's change.
    ///
    /// Surfaced as its own value rather than falling through to [`UndoPresentation::None`]:
    /// "nothing to say" and "a reason no undo is offered" are different claims.
    ExternallySatisfied,
    /// The undo child's attempt was issuance-unknown and an operator adjudicated it, so the
    /// child is terminal and the parent's presentation returns to `Applied` **with the
    /// unresolved state surfaced**.
    ///
    /// It is not [`UndoPresentation::AppliedUndoFailed`]: that value claims the undo did not
    /// happen, and here nobody knows. It is not [`UndoPresentation::Undone`] either. The
    /// display is "your message is as it was, and one restore may or may not have landed".
    AppliedUndoUnresolved,
    /// The undo child's own operation was closed by a control-plane sever:
    /// `SEVERED_BEFORE_ISSUANCE` (never claimed the wire), or a send-authorized attempt the
    /// sever could not prove non-issuance for (`ISSUED_OR_UNKNOWN`, closed by later
    /// adjudication, a distinct arm). The parent stays truthfully `Applied`: the forward
    /// action was never touched.
    ///
    /// Surfaced as its own value for the same reason as
    /// [`UndoPresentation::ExternallySatisfied`]: "no undo was attempted" and "an undo was
    /// attempted and a kill switch closed it" are different claims. It is not
    /// [`UndoPresentation::AppliedUndoFailed`]: a sever is a seizure, not a proven-no-effect
    /// provider refusal, and conflating the two would blame the connector for an operator
    /// action.
    AppliedUndoSevered,
}

/// What the persisted effect witness lets an undo offer claim about restoration, for an
/// operation whose forward effect landed (`Applied`, or `Undone`: the undo restores the
/// declared closure, and whether the message is as it was is what the witness qualifies).
/// Derived at read time from [`IntentLog::effect_witness`] by
/// [`CommandBus::undo_presentation`] (and [`CommandBus::restoration`]): a NULL witness on an
/// `Applied` operation reads as undetermined, never as within-closure. Presentation only,
/// like [`UndoPresentation`]: nothing that orders, admits or recovers reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestorationVerdict {
    /// The witness judged every label that changed between the observe read and the route's
    /// answer to be inside the declared closure: the ordinary offer, unchanged.
    WithinClosure,
    /// Labels outside the declared closure changed, from the route's own ripple or another
    /// writer ([`crate::prestate::RippleVerdict`]): restoring the closure may not restore the
    /// message.
    OutsideClosure { unexpected: std::collections::BTreeSet<String> },
    /// A witness row with no verdict: no pre-effect vector was journaled to judge the delta
    /// against.
    NoPreEffectVector,
    /// No witness is persisted for the operation: its route observed no vector (a connector on
    /// the trait default), or the witness write failed after the settlement.
    NoEffectWitness,
}

impl RestorationVerdict {
    /// The mapping from the persisted witness: a row with `WithinClosure` is the ordinary
    /// offer; `OutsideClosure { unexpected }` is undetermined and names them; a row with no
    /// verdict is undetermined (no pre-effect vector); no row is undetermined (no effect
    /// witness).
    pub fn of(witness: Option<&EffectWitnessRow>) -> Self {
        match witness.map(|row| &row.ripple_verdict) {
            None => RestorationVerdict::NoEffectWitness,
            Some(None) => RestorationVerdict::NoPreEffectVector,
            Some(Some(crate::prestate::RippleVerdict::WithinClosure)) => RestorationVerdict::WithinClosure,
            Some(Some(crate::prestate::RippleVerdict::OutsideClosure { unexpected })) => {
                RestorationVerdict::OutsideClosure { unexpected: unexpected.clone() }
            }
        }
    }

    /// The "undetermined" sentence, or `None` for [`RestorationVerdict::WithinClosure`] (the
    /// ordinary offer carries no line). Labels follow
    /// [`crate::prestate::banked_label_split`]: system labels named, user labels counted but
    /// never named. The renderer composes the same three sentences from the wire (`src/state.ts`
    /// `restorationLine`).
    pub fn undetermined_line(&self) -> Option<String> {
        let cause = match self {
            RestorationVerdict::WithinClosure => return None,
            RestorationVerdict::OutsideClosure { unexpected } => {
                let (mut parts, user) = crate::prestate::banked_label_split(unexpected);
                if user > 0 {
                    parts.push(format!("{user} user label{}", if user == 1 { "" } else { "s" }));
                }
                format!("labels outside the declared closure changed: {}", parts.join(", "))
            }
            RestorationVerdict::NoPreEffectVector => "no pre-effect vector".to_string(),
            RestorationVerdict::NoEffectWitness => "no effect witness".to_string(),
        };
        Some(format!("restoration UNDETERMINED ({cause})"))
    }
}

/// What [`CommandBus::undo_presentation`] answers: the presentation and, for an operation
/// whose forward effect landed, its [`RestorationVerdict`] (`None` otherwise: there is no
/// restoration to qualify).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UndoPresentationRead {
    pub presentation: UndoPresentation,
    pub restoration: Option<RestorationVerdict>,
}
