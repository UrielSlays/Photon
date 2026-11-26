//! The command and action model: facets, mail flags, actions, risk tiers, the envelope, and the command itself.

use crate::{derive_idempotency_key, LogError};

#[cfg(doc)]
use crate::{CommandBus, Connector};

/// A surface facet within an account. Mail only for now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Facet {
    Mail,
}

/// A neutral mail state flag. A closed enum restricted to reversible metadata flags: every
/// new flag needs its own per-flag risk tier and capability row before it is added here, so
/// payload-level risk never inherits `Seen`'s tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailFlag {
    /// "Message has been read", the neutral positive. Gmail stores the negative (`UNREAD`),
    /// JMAP the positive (`$seen`); the connector seam absorbs the polarity.
    Seen,
    /// "Message is starred/flagged", user-authored curation. Positive on both providers
    /// (JMAP `$flagged`, Gmail `STARRED`), so there is no polarity inversion unlike
    /// `Seen`/`UNREAD`.
    Flagged,
}

/// A typed, facet-specific mutation: archive/unarchive, `SetFlag` (`Seen`, `Flagged`), and the
/// four triage verbs (Trash/Untrash on Gmail's dedicated endpoints, MarkSpam/UnmarkSpam on the
/// SPAM label; ADR-P005 as amended).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Archive { message_ref: String },
    Unarchive { message_ref: String },
    SetFlag { message_ref: String, flag: MailFlag, value: bool },
    /// Red tier: move to trash. The provider's ~30-day destruction clock starts (ADR-P005).
    Trash { message_ref: String },
    /// Yellow tier: remove from trash, a clean provider-supported toggle-back within the
    /// window (ADR-P005 as amended).
    Untrash { message_ref: String },
    /// Red tier: add the SPAM label via `users.messages.modify` (ADR-P005 as amended).
    MarkSpam { message_ref: String },
    /// Yellow tier: remove the SPAM label, the amended ADR's grounded toggle-back.
    UnmarkSpam { message_ref: String },
}

impl Action {
    /// The descriptor inverse of this mutation: the action an undo child stores in its own
    /// row, used for ordering, projection, and `recover()`'s defense-in-depth link check.
    /// **Dispatch never derives from it.** Undo restores the captured pre-state through
    /// [`Connector::restore`], decided by the requalification table, so an archive that
    /// changed nothing is undone by changing nothing rather than by this descriptor's
    /// counter-action. Reversibility is a data-model property (ADR-P007).
    pub fn inverse(&self) -> Action {
        match self {
            Action::Archive { message_ref } => Action::Unarchive {
                message_ref: message_ref.clone(),
            },
            Action::Unarchive { message_ref } => Action::Archive {
                message_ref: message_ref.clone(),
            },
            Action::SetFlag { message_ref, flag, value } => Action::SetFlag {
                message_ref: message_ref.clone(),
                flag: *flag,
                value: !*value,
            },
            Action::Trash { message_ref } => Action::Untrash { message_ref: message_ref.clone() },
            Action::Untrash { message_ref } => Action::Trash { message_ref: message_ref.clone() },
            Action::MarkSpam { message_ref } => Action::UnmarkSpam { message_ref: message_ref.clone() },
            Action::UnmarkSpam { message_ref } => Action::MarkSpam { message_ref: message_ref.clone() },
        }
    }
}

/// The ADR-P005 color risk tier: static verb metadata. Deliberately not named bare `Tier`:
/// the reserved `ActionEnvelope.tier` (ADR-P006) is the isolation/authority axis, a different
/// dimension. This classification never populates, validates, authorizes from, or gates on
/// that reserved field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskTier {
    Green,
    Yellow,
    Red,
    Black,
}

impl RiskTier {
    /// Whether a command of this tier must be a plan child. A red (or black) command meets
    /// [`CommandBus::execute`]'s first check: without a plan link it is refused
    /// `ExecuteError::PlanRequired`, and a plan link on a green/yellow command is refused
    /// `NotARedVerb`. `record()`'s plan-child arm asks it too, for that second half only
    /// (`PlanChildRefusal::NotARedVerb`). The plan child's `record()` arm and the send check
    /// then require the approved plan and its live, ready episode. `ActionEnvelope.tier`
    /// stays unused.
    pub fn requires_plan(self) -> bool {
        matches!(self, RiskTier::Red | RiskTier::Black)
    }
}

impl Action {
    /// Static per-verb, per-flag risk classification (ADR-P005). There is no wholesale
    /// `SetFlag { .. }` arm: a future flag must add its own row here (and in every connector
    /// capability map) or compilation fails.
    pub fn risk_tier(&self) -> RiskTier {
        match self {
            Action::Archive { .. } | Action::Unarchive { .. } => RiskTier::Yellow,
            Action::SetFlag { flag: MailFlag::Seen, .. } => RiskTier::Yellow,
            // Same tier as Seen, different grounding: Flagged is user-authored curation that a
            // blind compensating inverse would destroy, which is why undo captures the
            // pre-state and restores by delta.
            Action::SetFlag { flag: MailFlag::Flagged, .. } => RiskTier::Yellow,
            // ADR-P005: trash is red; recovery is real but bounded and degraded.
            Action::Trash { .. } => RiskTier::Red,
            // ADR-P005 amendment: mark-spam joins the red row for the Gmail arm.
            Action::MarkSpam { .. } => RiskTier::Red,
            // The two restore arms: clean, provider-supported toggle-backs within the window,
            // with none of the red tier's bounded-recovery character.
            Action::Untrash { .. } | Action::UnmarkSpam { .. } => RiskTier::Yellow,
        }
    }
}

/// The governance envelope every mutation reserves from the start.
///
/// Reserved, not active: all fields stay `None` until governance is built. They are modeled
/// now so the evidence/identity/authority layer can attach to the durable record without a
/// retrofit (which the ADR forbids), and in the SQLite schema when it lands.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ActionEnvelope {
    /// Who acted (identity). Reserved.
    pub principal: Option<String>,
    /// Control epoch under which the action was authorized. Reserved.
    pub epoch: Option<u64>,
    /// Pointer to the evidence record for this action. Reserved.
    pub evidence_ref: Option<String>,
    /// Pointer to the pre-state snapshot captured before provider submit, the durable home for
    /// the reserved `EvidenceSnapshotWritten` state. Reserved: `None` for now, modeled so the
    /// state can attach without a schema or struct migration.
    pub snapshot_ref: Option<String>,
    /// Isolation / authority tier. Reserved.
    pub tier: Option<String>,
}

/// A mutation command: the single mutation boundary, carrying the reserved `ActionEnvelope`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    pub idempotency_key: String,
    pub account: String,
    pub facet: Facet,
    pub action: Action,
    /// Reserved governance envelope (all `None` until the moat pass). See [`ActionEnvelope`].
    pub envelope: ActionEnvelope,
    /// Explicit compensation link: `Some(parent_key)` iff this command is an undo child minted
    /// by [`CommandBus::admit_undo_child`], the durable "this undoes `parent_key`" that the
    /// undo drive uses to heal the parent. `None` for every normal command; it is also the
    /// forward/undo discriminator the admission statement derives `kind` from.
    /// **Crate-private** so an external caller cannot inject a link pointing at an unrelated
    /// intent; only `new()` (which sets `None`), the child admission, and the row parser set it.
    ///
    /// Defense in depth: the link alone is not trusted to authorize a heal.
    /// [`CommandBus::drive_undo_child`], which both the synchronous undo and `recover()` go
    /// through, validates at entry, ahead of every arm that can flip a parent, that the row is
    /// the child [`mint_undo_child_command`] would mint for the parent it names (account,
    /// facet, the inverse action, the envelope, the link); anything else is a deterministic
    /// refusal (see `a_mislinked_compensation_never_heals_an_unrelated_parent`).
    pub(crate) compensates: Option<String>,
    /// `Some(link)` iff this command is a child of a `TriagePlan`. Crate-private like
    /// `compensates`: outside this crate only [`Command::plan_child`] sets it; inside it, that
    /// constructor and the row parser (`intent_from_raw`) do. Both `record()`s run the
    /// plan-child admission arm on a command that carries it (`Claim::PlanChildRefused` names
    /// each refusal); read it through [`Command::plan_child_link`].
    pub(crate) plan_child: Option<crate::plan::PlanChildLink>,
}

impl Command {
    pub fn new(
        idempotency_key: impl Into<String>,
        account: impl Into<String>,
        facet: Facet,
        action: Action,
    ) -> Self {
        Self {
            idempotency_key: idempotency_key.into(),
            account: account.into(),
            facet,
            action,
            envelope: ActionEnvelope::default(),
            compensates: None,
            plan_child: None,
        }
    }

    /// The plan-child constructor: the account is the plan's, the action is the plan's verb
    /// over `member_ref`, and the key is the crate-private `plan_child_key` over
    /// `(plan_id, member_ref)`; the caller supplies none of the three. It does not check that
    /// `member_ref` is a member: `record()`'s admission arm refuses a non-member by name.
    pub fn plan_child(plan: &crate::plan::TriagePlan, member_ref: &str) -> Self {
        let link = crate::plan::PlanChildLink { plan_id: plan.plan_id.clone(), member_ref: member_ref.to_string() };
        let mut c = Command::new(plan_child_key(&plan.account, &link), plan.account.clone(), Facet::Mail, plan.verb.action(member_ref));
        c.plan_child = Some(link);
        c
    }

    /// The plan link this command carries: `None` for every command not built by
    /// [`Command::plan_child`] (or read back from such a command's row). Named `_link` because
    /// `plan_child` is the constructor and an inherent fn and a method cannot share one name.
    pub fn plan_child_link(&self) -> Option<&crate::plan::PlanChildLink> {
        self.plan_child.as_ref()
    }
}

/// The key derivation for a plan child: [`derive_idempotency_key`] over the plan's account,
/// `Facet::Mail` and [`crate::plan::plan_child_logical_id`]. [`Command::plan_child`] keys with
/// it and `record()`'s admission arm compares against it, so the two cannot spell the key
/// differently.
pub(crate) fn plan_child_key(account: &str, link: &crate::plan::PlanChildLink) -> String {
    derive_idempotency_key(account, &Facet::Mail, &crate::plan::plan_child_logical_id(&link.plan_id, &link.member_ref))
}

pub(crate) fn facet_to_str(facet: &Facet) -> &'static str {
    match facet {
        Facet::Mail => "mail",
    }
}

pub(crate) fn facet_from_str(s: &str) -> Result<Facet, LogError> {
    match s {
        "mail" => Ok(Facet::Mail),
        other => Err(LogError(format!("unknown facet in intent log: {other}"))),
    }
}

pub(crate) fn action_to_parts(action: &Action) -> (&'static str, String) {
    match action {
        Action::Archive { message_ref } => ("archive", message_ref.clone()),
        Action::Unarchive { message_ref } => ("unarchive", message_ref.clone()),
        Action::SetFlag { message_ref, flag: MailFlag::Seen, value } => (
            if *value { "set_flag:seen:true" } else { "set_flag:seen:false" },
            message_ref.clone(),
        ),
        Action::SetFlag { message_ref, flag: MailFlag::Flagged, value } => (
            if *value { "set_flag:flagged:true" } else { "set_flag:flagged:false" },
            message_ref.clone(),
        ),
        Action::Trash { message_ref } => ("trash", message_ref.clone()),
        Action::Untrash { message_ref } => ("untrash", message_ref.clone()),
        Action::MarkSpam { message_ref } => ("mark_spam", message_ref.clone()),
        Action::UnmarkSpam { message_ref } => ("unmark_spam", message_ref.clone()),
    }
}

/// The `message_ref` an action targets, regardless of action kind.
pub(crate) fn action_message_ref(action: &Action) -> &str {
    match action {
        Action::Archive { message_ref }
        | Action::Unarchive { message_ref }
        | Action::SetFlag { message_ref, .. }
        | Action::Trash { message_ref }
        | Action::Untrash { message_ref }
        | Action::MarkSpam { message_ref }
        | Action::UnmarkSpam { message_ref } => message_ref,
    }
}

pub(crate) fn action_from_parts(kind: &str, message_ref: String) -> Result<Action, LogError> {
    match kind {
        "archive" => Ok(Action::Archive { message_ref }),
        "unarchive" => Ok(Action::Unarchive { message_ref }),
        "set_flag:seen:true" => Ok(Action::SetFlag {
            message_ref,
            flag: MailFlag::Seen,
            value: true,
        }),
        "set_flag:seen:false" => Ok(Action::SetFlag {
            message_ref,
            flag: MailFlag::Seen,
            value: false,
        }),
        "set_flag:flagged:true" => Ok(Action::SetFlag {
            message_ref,
            flag: MailFlag::Flagged,
            value: true,
        }),
        "set_flag:flagged:false" => Ok(Action::SetFlag {
            message_ref,
            flag: MailFlag::Flagged,
            value: false,
        }),
        "trash" => Ok(Action::Trash { message_ref }),
        "untrash" => Ok(Action::Untrash { message_ref }),
        "mark_spam" => Ok(Action::MarkSpam { message_ref }),
        "unmark_spam" => Ok(Action::UnmarkSpam { message_ref }),
        other => Err(LogError(format!("unknown action kind in intent log: {other}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- SetFlag (M1 §2): inverse symmetry + the durable set_flag:seen:* token family ----

    #[test]
    fn set_flag_inverse_flips_only_the_value() {
        let a = Action::SetFlag {
            message_ref: "m1".into(),
            flag: MailFlag::Seen,
            value: true,
        };
        assert_eq!(
            a.inverse(),
            Action::SetFlag {
                message_ref: "m1".into(),
                flag: MailFlag::Seen,
                value: false,
            }
        );
        assert_eq!(a.inverse().inverse(), a);

        // The same symmetry for EVERY flag (the §5.3 inverse witness generalized over the roster).
        for flag in all_mail_flags() {
            for value in [true, false] {
                let a = Action::SetFlag { message_ref: "m1".into(), flag, value };
                assert_eq!(
                    a.inverse(),
                    Action::SetFlag { message_ref: "m1".into(), flag, value: !value }
                );
                assert_eq!(a.inverse().inverse(), a);
            }
        }
    }

    #[test]
    fn set_flag_durable_token_round_trips_both_values() {
        for value in [true, false] {
            let a = Action::SetFlag {
                message_ref: "m9".into(),
                flag: MailFlag::Seen,
                value,
            };
            let (kind, message_ref) = action_to_parts(&a);
            assert_eq!(kind, if value { "set_flag:seen:true" } else { "set_flag:seen:false" });
            let back = action_from_parts(kind, message_ref).expect("round-trip");
            assert_eq!(back, a);
        }
    }

    #[test]
    fn unknown_or_inexact_set_flag_tokens_fail_closed() {
        // Exact-match only: impostor casings/prefixes are corrupt rows, never a silent default.
        // The unknown-flag sentinel names a flag that is STILL unknown (`answered`) — a token an
        // implemented flag owns must never sit here (star/unstar design 2026-07-26 §3: the old
        // `set_flag:flagged:true` entry would go red on the faithful build).
        for bad in [
            "set_flag:seen:TRUE",
            "set_flag:seen:",
            "set_flag:seen",
            "set_flag:answered:true",
            "set_flag:seen:true:extra",
        ] {
            assert!(
                action_from_parts(bad, "m1".into()).is_err(),
                "token {bad:?} must fail closed"
            );
        }
    }

    /// Every `MailFlag`, generated by walking successor links under an EXHAUSTIVE match: the
    /// compiler forces a new variant into `next`, so the §5.0 generative sentinel grows with the
    /// enum — no external derive crate (star/unstar design 2026-07-26 §5.0).
    fn all_mail_flags() -> Vec<MailFlag> {
        fn next(flag: MailFlag) -> Option<MailFlag> {
            match flag {
                MailFlag::Seen => Some(MailFlag::Flagged),
                MailFlag::Flagged => None,
            }
        }
        let mut all = vec![MailFlag::Seen];
        while let Some(flag) = next(*all.last().expect("roster is seeded non-empty")) {
            all.push(flag);
        }
        all
    }

    #[test]
    fn every_mail_flag_round_trips_the_durable_token_both_ways() {
        // The §5.0 generative round-trip sentinel: for EVERY flag and both values,
        // action_to_parts ⇄ action_from_parts is the identity. This is the positive witness
        // that closes the write/read token-asymmetry class — a to_parts arm without its
        // from_parts twin goes red HERE, not at a hand-pinned future token.
        for flag in all_mail_flags() {
            for value in [true, false] {
                let a = Action::SetFlag { message_ref: "m-gen".into(), flag, value };
                let (kind, message_ref) = action_to_parts(&a);
                let back = action_from_parts(kind, message_ref)
                    .unwrap_or_else(|e| panic!("token {kind:?} must parse back: {e:?}"));
                assert_eq!(back, a, "round-trip must be the identity for {kind:?}");
            }
        }
    }

    #[test]
    fn perturbed_valid_set_flag_tokens_fail_closed() {
        // The §5.0 perturbation negatives, DERIVED from each valid token (casing, truncation,
        // suffix) instead of hand-pinned future flags — so the negative battery also grows with
        // the enum and can never pin a token a later flag legitimately claims.
        for flag in all_mail_flags() {
            for value in [true, false] {
                let (kind, _) =
                    action_to_parts(&Action::SetFlag { message_ref: "m".into(), flag, value });
                let upper = kind.to_uppercase();
                let truncated = &kind[..kind.len() - 1];
                let suffixed = format!("{kind}:extra");
                for bad in [upper.as_str(), truncated, suffixed.as_str()] {
                    assert!(
                        action_from_parts(bad, "m".into()).is_err(),
                        "perturbed token {bad:?} (from {kind:?}) must fail closed"
                    );
                }
            }
        }
    }

    #[test]
    fn set_flag_carries_its_message_ref() {
        let a = Action::SetFlag {
            message_ref: "mr".into(),
            flag: MailFlag::Seen,
            value: true,
        };
        assert_eq!(action_message_ref(&a), "mr");
    }

    // ---- RiskTier (M1 §2): static per-verb classification + the no-flow guard ----

    #[test]
    fn every_action_variant_has_a_risk_tier() {
        // Exhaustive by construction: this match is the guard — adding an Action variant or a
        // MailFlag without extending risk_tier breaks compilation, and this test pins the values.
        assert_eq!(
            Action::Archive { message_ref: "m".into() }.risk_tier(),
            RiskTier::Yellow
        );
        assert_eq!(
            Action::Unarchive { message_ref: "m".into() }.risk_tier(),
            RiskTier::Yellow
        );
        assert_eq!(
            Action::SetFlag { message_ref: "m".into(), flag: MailFlag::Seen, value: true }
                .risk_tier(),
            RiskTier::Yellow
        );
        // Flagged: YELLOW on its OWN grounding — user-authored curation, not read-state
        // (star/unstar design 2026-07-26 §2).
        assert_eq!(
            Action::SetFlag { message_ref: "m".into(), flag: MailFlag::Flagged, value: true }
                .risk_tier(),
            RiskTier::Yellow
        );
    }

    // ---- the four triage verbs ----

    /// Every Action variant, constructed once, so token round-trips and tier
    /// rows are GENERATED from this list rather than hand-picked (attempt.rs:83-104's pattern).
    /// A new variant does not compile until `every_action_variant_is_enumerated_here`'s match
    /// names it; nothing forces its row HERE — this list is kept by hand.
    fn every_action() -> Vec<Action> {
        let m = || "msg-1".to_string();
        vec![
            Action::Archive { message_ref: m() },
            Action::Unarchive { message_ref: m() },
            Action::SetFlag { message_ref: m(), flag: MailFlag::Seen, value: true },
            Action::SetFlag { message_ref: m(), flag: MailFlag::Seen, value: false },
            Action::SetFlag { message_ref: m(), flag: MailFlag::Flagged, value: true },
            Action::SetFlag { message_ref: m(), flag: MailFlag::Flagged, value: false },
            Action::Trash { message_ref: m() },
            Action::Untrash { message_ref: m() },
            Action::MarkSpam { message_ref: m() },
            Action::UnmarkSpam { message_ref: m() },
        ]
    }

    #[test]
    fn every_action_variant_is_enumerated_here() {
        // The compiler cannot count variants for us; this match is the tripwire — the match
        // forces a new variant's arm; nothing forces a row in `every_action()` — keep the list
        // by hand.
        for a in every_action() {
            let _named: &str = match a {
                Action::Archive { .. } => "archive",
                Action::Unarchive { .. } => "unarchive",
                Action::SetFlag { .. } => "set_flag",
                Action::Trash { .. } => "trash",
                Action::Untrash { .. } => "untrash",
                Action::MarkSpam { .. } => "mark_spam",
                Action::UnmarkSpam { .. } => "unmark_spam",
            };
        }
        assert_eq!(every_action().len(), 10);
    }

    #[test]
    fn s1_durable_tokens_round_trip_for_every_variant_and_unknown_fails() {
        for a in every_action() {
            let (kind, message_ref) = action_to_parts(&a);
            assert_eq!(action_from_parts(kind, message_ref).unwrap(), a, "round trip of {kind}");
        }
        assert_eq!(action_to_parts(&Action::Trash { message_ref: "m".into() }).0, "trash");
        assert_eq!(action_to_parts(&Action::Untrash { message_ref: "m".into() }).0, "untrash");
        assert_eq!(action_to_parts(&Action::MarkSpam { message_ref: "m".into() }).0, "mark_spam");
        assert_eq!(action_to_parts(&Action::UnmarkSpam { message_ref: "m".into() }).0, "unmark_spam");
        assert!(action_from_parts("delete", "m".into()).is_err());
        assert!(action_from_parts("empty_trash", "m".into()).is_err());
    }

    #[test]
    fn s1_inverses_are_the_descriptor_pairs_and_involutions() {
        let m = || "m".to_string();
        assert_eq!(Action::Trash { message_ref: m() }.inverse(), Action::Untrash { message_ref: m() });
        assert_eq!(Action::Untrash { message_ref: m() }.inverse(), Action::Trash { message_ref: m() });
        assert_eq!(Action::MarkSpam { message_ref: m() }.inverse(), Action::UnmarkSpam { message_ref: m() });
        assert_eq!(Action::UnmarkSpam { message_ref: m() }.inverse(), Action::MarkSpam { message_ref: m() });
        for a in every_action() {
            assert_eq!(a.inverse().inverse(), a);
        }
    }

    #[test]
    fn s1_tiers_are_the_adr_p005_rows_and_only_red_requires_a_plan() {
        let m = || "m".to_string();
        assert_eq!(Action::Trash { message_ref: m() }.risk_tier(), RiskTier::Red);
        assert_eq!(Action::MarkSpam { message_ref: m() }.risk_tier(), RiskTier::Red);
        assert_eq!(Action::Untrash { message_ref: m() }.risk_tier(), RiskTier::Yellow);
        assert_eq!(Action::UnmarkSpam { message_ref: m() }.risk_tier(), RiskTier::Yellow);
        assert!(RiskTier::Red.requires_plan());
        assert!(!RiskTier::Yellow.requires_plan());
        assert!(!RiskTier::Green.requires_plan());
        assert!(RiskTier::Black.requires_plan(), "BLACK is never reachable through a plan either, but a plan is the LEAST it would need");
        for a in every_action() {
            match a.risk_tier() {
                RiskTier::Red => assert!(a.risk_tier().requires_plan()),
                RiskTier::Yellow => assert!(!a.risk_tier().requires_plan()),
                other => panic!("no S1 verb is {other:?}"),
            }
        }
    }

    #[test]
    fn s1_action_message_ref_is_total() {
        for a in every_action() {
            assert_eq!(action_message_ref(&a), "msg-1");
        }
    }
}
