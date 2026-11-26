//! The inbox, refresh, verb and undo shapes that cross the IPC boundary.

use serde::{Deserialize, Serialize};

use aruna::read_coordinator::{Freshness, ProjectionWrite};
use aruna::{LogError, RestorationVerdict, UndoPresentation, UndoPresentationRead};

/// One inbox row as the renderer sees it. `from_addr` is sent beside `from_name` because the UI
/// renders both and never presents a display name as authenticated identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboxRow {
    pub message_ref: String,
    pub received_at: i64,
    pub from_addr: String,
    pub from_name: String,
    pub subject: String,
    pub seen: bool,
    pub flagged: bool,
}

/// The keyset cursor, round-tripped opaquely by the UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PageCursor {
    pub received_at: i64,
    pub message_ref: String,
}

/// What a refresh re-checked: the freshness marker's data, not a summary of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FreshnessView {
    pub checked_through: Option<PageCursor>,
    pub stale_below: usize,
}

impl From<&Freshness> for FreshnessView {
    fn from(f: &Freshness) -> Self {
        Self {
            checked_through: f.checked_through.as_ref().map(|(ts, r)| PageCursor {
                received_at: *ts,
                message_ref: r.clone(),
            }),
            stale_below: f.stale_below,
        }
    }
}

/// The freshness a session that has never reconciled a page-1 window can claim: none.
/// `checked_through: None` means "nothing was re-checked", which is true before the first
/// refresh; the zero beside it counts rows this session decided, and it decided none.
pub(crate) const NO_COVERAGE_YET: FreshnessView = FreshnessView {
    checked_through: None,
    stale_below: 0,
};

/// What a refresh (page 1) or a refresh continuation (page N) answers: the freshness the last
/// page-1 window produced, how many rows this page ingested, and whether a provider continuation
/// is now held.
///
/// The freshness fields are `#[serde(flatten)]`ed, so the wire object is the old
/// `FreshnessView` shape with fields added (`{checked_through, stale_below, ingested,
/// has_more}`). That keeps the change to `refresh_inbox`'s return additive for anything already
/// reading its freshness, with one definition of the freshness fields that cannot drift from
/// [`FreshnessView`].
///
/// The freshness half is page 1's claim on both commands. Removal inference is
/// page-1-window-scoped, so a continuation makes no coverage claim of its own:
/// `checked_through`/`stale_below` come back from `refresh_more_inbox` as the last page-1
/// refresh left them, since advancing them would claim rows nothing re-checked. What a
/// continuation does report is [`RefreshOutcome::ingested`].
///
/// `has_more` is a fact about the session's held cursor: true exactly when a continuation token
/// is parked for this account, i.e. when `refresh_more_inbox` can do something. A "load more"
/// button driven by it is never one the shell refuses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefreshOutcome {
    #[serde(flatten)]
    pub freshness: FreshnessView,
    /// How many rows this page carried into the store, the one thing a purely additive
    /// continuation can report about itself. Not a count of new rows: a row the store already
    /// held is upserted (its headers may have changed), and that is work this page did.
    pub ingested: usize,
    pub has_more: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboxPage {
    pub rows: Vec<InboxRow>,
    /// The cursor for the next page, absent when this page reached the end.
    pub next_cursor: Option<PageCursor>,
    /// `None` until a refresh has run in this session: "never refreshed", stated rather than
    /// implied by a zero.
    pub freshness: Option<FreshnessView>,
}

/// The projection half of a verb outcome. The stale arm is a value the UI must render, never a
/// silence, and it may not be swallowed anywhere.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ProjectionState {
    Current,
    Stale { reason: String },
}

/// A skip is never `Current`. `Current` means exactly `Written`. A
/// `SupersededByNewerObservation` or `NotApplicable` means the placement/header write did not
/// happen, so the row the UI renders is whatever it already was, not what this operation's effect
/// implies; mapping both `ProjectionWrite::Ok` arms to `Current` would be a false `Current`.
/// `SupersededByNewerObservation` carries no reason of its own (the row simply was not proven
/// fresh enough to write), so its fixed sentence lives here. `NotApplicable` already carries the
/// real reason from the projection path (which of its three preconditions failed), and that
/// passes through. An `Err` is the one case whose reason is a real store error rather than an
/// honest skip.
impl From<Result<ProjectionWrite, LogError>> for ProjectionState {
    fn from(result: Result<ProjectionWrite, LogError>) -> Self {
        match result {
            Ok(ProjectionWrite::Written) => ProjectionState::Current,
            Ok(ProjectionWrite::SupersededByNewerObservation) => ProjectionState::Stale {
                reason: "a newer observation exists; refresh to confirm".to_string(),
            },
            Ok(ProjectionWrite::NotApplicable { reason }) => ProjectionState::Stale { reason },
            Err(e) => ProjectionState::Stale { reason: e.0 },
        }
    }
}

/// A verb's result: it applied, here is the key that undoes it, here is whether your row now
/// renders the truth, and here is what the effect witness lets the undo offer claim about
/// restoration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerbOutcome {
    pub applied: bool,
    pub undo_key: String,
    pub projection: ProjectionState,
    /// `None` only if the operation's forward effect has not landed, which is never the case for
    /// a verb that answered `applied: true`; a verb outcome always carries a verdict.
    pub restoration: Option<RestorationView>,
}

/// The engine's [`RestorationVerdict`] as the renderer sees it, tagged `verdict`.
/// `outside_closure` carries the rippled labels in their recorded form
/// (`aruna::prestate::banked_label_split`): system labels named, user labels counted, so a
/// provider-native user label id never crosses the wire. The renderer composes the sentence
/// (`src/state.ts` `restorationLine`); `within_closure` is the ordinary offer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum RestorationView {
    WithinClosure,
    OutsideClosure {
        system_labels: Vec<String>,
        user_label_count: u32,
    },
    NoPreEffectVector,
    NoEffectWitness,
    /// The verb applied and the witness read right after it failed: restoration is undetermined,
    /// and a verb that happened is never refused (the projection's rule in `run_verb`). The verb
    /// commands answer it, and so does `undo` when the undo committed and the read-back failed,
    /// beside [`UndoPresentationView::UnreadableAfterUndo`]. The read-only `undo_presentation`
    /// committed nothing and surfaces a failed read as its own error.
    Unreadable,
    /// The verb applied and settled, and the effect-witness write that follows failed
    /// (`aruna::WitnessRecord::WriteFailed`): the witness was not recorded, so restoration is
    /// undetermined. Same class as `Unreadable`, named for what failed. Answered by the commands
    /// whose own dispatch applied the operation (the verb commands and a plan run's applied
    /// members), beside the undo offer that stays.
    WitnessWriteFailed,
}

impl From<&RestorationVerdict> for RestorationView {
    fn from(v: &RestorationVerdict) -> Self {
        match v {
            RestorationVerdict::WithinClosure => RestorationView::WithinClosure,
            RestorationVerdict::OutsideClosure { unexpected } => {
                let (system_labels, users) = aruna::prestate::banked_label_split(unexpected);
                RestorationView::OutsideClosure {
                    system_labels,
                    user_label_count: u32::try_from(users).unwrap_or(u32::MAX),
                }
            }
            RestorationVerdict::NoPreEffectVector => RestorationView::NoPreEffectVector,
            RestorationVerdict::NoEffectWitness => RestorationView::NoEffectWitness,
        }
    }
}

/// The engine's [`UndoPresentation`] as the renderer sees it. It is mapped rather than
/// re-exported because the engine type is not `Serialize`, and the exhaustive mapping makes a new
/// engine variant a compile error here instead of a silently dropped state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UndoPresentationView {
    None,
    Undoing,
    Undone,
    AppliedUndoFailed,
    ExternallySatisfied,
    AppliedUndoUnresolved,
    AppliedUndoSevered,
    /// No intent exists under this key at all.
    Unknown,
    /// The `undo` command's undo committed and the presentation read-back after it failed. The
    /// presentation is unreadable after the undo, not "no such intent"
    /// ([`UndoPresentationView::Unknown`]) and not a bare error that would discard the undo's
    /// outcome. Answered only by `undo`; the read-only `undo_presentation` committed nothing and
    /// surfaces a failed read as its own error.
    UnreadableAfterUndo,
}

impl From<Option<UndoPresentation>> for UndoPresentationView {
    fn from(p: Option<UndoPresentation>) -> Self {
        match p {
            None => UndoPresentationView::Unknown,
            Some(UndoPresentation::None) => UndoPresentationView::None,
            Some(UndoPresentation::Undoing) => UndoPresentationView::Undoing,
            Some(UndoPresentation::Undone) => UndoPresentationView::Undone,
            Some(UndoPresentation::AppliedUndoFailed) => UndoPresentationView::AppliedUndoFailed,
            Some(UndoPresentation::ExternallySatisfied) => UndoPresentationView::ExternallySatisfied,
            Some(UndoPresentation::AppliedUndoUnresolved) => {
                UndoPresentationView::AppliedUndoUnresolved
            }
            Some(UndoPresentation::AppliedUndoSevered) => UndoPresentationView::AppliedUndoSevered,
        }
    }
}

/// What an undo did, plus the state of the local projection afterwards and the restoration
/// verdict the operation's effect witness allows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UndoOutcome {
    pub undone: bool,
    pub presentation: UndoPresentationView,
    pub projection: ProjectionState,
    /// `None` when the operation's forward effect has not landed (no restoration to qualify).
    pub restoration: Option<RestorationView>,
}

/// What `undo_presentation` answers: the presentation (still the bare-string
/// [`UndoPresentationView`], `src/ipc.ts` trap 2) beside the restoration verdict. A struct,
/// because a unit-variant enum cannot carry the verdict without changing trap 2's shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UndoPresentationReadView {
    pub presentation: UndoPresentationView,
    /// `None` = no such operation, or its forward effect has not landed.
    pub restoration: Option<RestorationView>,
}

impl From<Option<UndoPresentationRead>> for UndoPresentationReadView {
    fn from(read: Option<UndoPresentationRead>) -> Self {
        UndoPresentationReadView {
            presentation: UndoPresentationView::from(read.as_ref().map(|r| r.presentation)),
            restoration: read
                .as_ref()
                .and_then(|r| r.restoration.as_ref())
                .map(RestorationView::from),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn the_refresh_outcome_is_the_freshness_shape_plus_flat_ingested_and_has_more_fields() {
        let wire = serde_json::to_value(RefreshOutcome {
            freshness: FreshnessView {
                checked_through: Some(PageCursor {
                    received_at: 90,
                    message_ref: "msg-090".to_string(),
                }),
                stale_below: 3,
            },
            ingested: 2,
            has_more: true,
        })
        .expect("serializes");
        assert_eq!(
            wire,
            serde_json::json!({
                "checked_through": {"received_at": 90, "message_ref": "msg-090"},
                "stale_below": 3,
                "ingested": 2,
                "has_more": true
            }),
            "the freshness fields are FLATTENED: the wire shape is the old FreshnessView object \
             with exactly one field added, so the change is additive for anything already reading \
             a refresh result"
        );
        let empty = serde_json::to_value(RefreshOutcome {
            freshness: FreshnessView {
                checked_through: None,
                stale_below: 0,
            },
            ingested: 0,
            has_more: false,
        })
        .expect("serializes");
        assert_eq!(
            empty,
            serde_json::json!({
                "checked_through": null, "stale_below": 0, "ingested": 0, "has_more": false
            })
        );
    }

    // ===========================================================================================
    // The restoration verdict on the wire
    // ===========================================================================================

    #[test]
    fn e7_the_restoration_verdict_crosses_the_wire_tagged_with_user_labels_counted_never_named() {
        use aruna::RestorationVerdict as V;
        let set = |labels: &[&str]| labels.iter().map(|l| l.to_string()).collect::<BTreeSet<String>>();
        let wire = |v: &V| serde_json::to_value(RestorationView::from(v)).unwrap();
        assert_eq!(wire(&V::WithinClosure), serde_json::json!({ "verdict": "within_closure" }));
        let outside = wire(&V::OutsideClosure { unexpected: set(&["IMPORTANT", "Label_7", "Label_9"]) });
        assert_eq!(
            outside,
            serde_json::json!({ "verdict": "outside_closure", "system_labels": ["IMPORTANT"], "user_label_count": 2 })
        );
        assert!(!outside.to_string().contains("Label_"), "a user label id never crosses: {outside}");
        assert_eq!(wire(&V::NoPreEffectVector), serde_json::json!({ "verdict": "no_pre_effect_vector" }));
        assert_eq!(wire(&V::NoEffectWitness), serde_json::json!({ "verdict": "no_effect_witness" }));
        assert_eq!(
            serde_json::to_value(RestorationView::Unreadable).unwrap(),
            serde_json::json!({ "verdict": "unreadable" })
        );
    }
}
