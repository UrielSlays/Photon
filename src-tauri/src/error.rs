//! The typed refusals that cross IPC, and the closed table of the shell's plan-refusal tokens.

use serde::{Deserialize, Serialize};

use aruna::{ExecuteError, LogError};

use crate::single_flight::OperationKind;
use crate::token_refresh::Cure;

/// Every way a command can say no. Serialized as a tagged object so the renderer branches on
/// `kind` rather than parsing prose.
///
/// No variant carries a provider-native identifier or message content: the engine's connectors
/// confine those below their seams, and the strings that reach here are the engine's own refusal
/// phrases.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SurfaceError {
    /// Single-flight: an operation of this kind is already in flight. The caller retries when it
    /// finishes; nothing is queued on its behalf.
    Busy { operation: String },
    /// The cadence floor: this refresh arrived less than [`MIN_REFRESH_INTERVAL_MS`] after the
    /// last one completed. Distinct from [`SurfaceError::Busy`], which means "wait for the one
    /// that is running"; this means "the one you want just finished". `retry_after_ms` is how
    /// long is left.
    TooSoon {
        operation: String,
        retry_after_ms: u64,
    },
    /// The provider asked us to back off (a 429-class `GmailError::RateLimit`) and that answer is
    /// remembered until the recorded instant passes. Both provider-reading operations refuse
    /// while it holds, and the refusal names the provider rather than the local floor.
    ProviderBackoff {
        operation: String,
        retry_after_ms: u64,
    },
    /// The session has no usable store and/or credential, so no command can do its job. The
    /// reason is operator-facing (a path, a missing file), never a credential value.
    ///
    /// `cure` is the same discriminant [`SessionStatus::credential_cure`] renders for this state,
    /// so a command's toast and the status bar cannot disagree about one boot. `None` for arms
    /// that owe no credential cure (an unopenable store, an unresolved path, the JMAP
    /// placeholder); the frontend keeps the bare reason there.
    SessionUnconfigured {
        reason: String,
        cure: Option<Cure>,
    },
    /// The parked Gmail credential's `expires_at` has passed and the app could not renew it on
    /// this command. Its own kind rather than [`SurfaceError::Refused`] because cause and cure
    /// are specific: `cure` names which of the five remedies applies (a re-mint is only one; a
    /// refused client config, an administrator policy, a paced retry and an undetermined
    /// provider refusal each have a different cause and are never rendered as a re-mint demand).
    /// `reason` carries the outcome's own sentence; `expires_at` the stamp the UI renders.
    CredentialExpired {
        expires_at: i64,
        cure: Cure,
        reason: String,
    },
    /// The engine refused: a connector error, a dead-letter replay, an epoch fence, a conflicting
    /// idempotency key. The engine's own phrase rides along.
    ///
    /// `terminal` is the terminal/transient axis [`crate::isTerminalRefusal`]'s TS twin answers
    /// for every other kind. It is set in [`SurfaceError::execute`], the one classifier, from the
    /// `ExecuteError` variant that produced the refusal, never guessed renderer-side. `true`
    /// means retrying the same command cannot succeed without an out-of-band change; `false`
    /// means it may succeed later, unchanged.
    Refused { reason: String, terminal: bool },
    /// The local store could not answer (locked, corrupt, missing row).
    Store { reason: String },
    /// A shell-internal failure: a poisoned lock or a blocking-pool join failure. Distinct from
    /// [`SurfaceError::Store`] so an operator can tell "the DB said no" from "we broke".
    Internal { reason: String },
    /// A RED verb reached the engine without a plan (`ExecuteError::PlanRequired`). The RED
    /// commands here mint a plan and never dispatch, so none is expected to produce this; it has
    /// its own kind so a future command cannot hide it in `Refused`.
    PlanRequired,
    /// The send fence's plan arm refused a plan child (`ExecuteError::PlanRefused`), or the
    /// approve command refused the approval's evidence. `reason` is the engine's token
    /// (`aruna::plan::PlanSendRefusal::token`; `evidence_invalid` from the approve command);
    /// `member_ref` is the member's Photon logical id (`None` for a whole-plan refusal); `diff`
    /// is non-empty only for `state_diverged` (atom names and booleans). Nothing else crosses: a
    /// `grant_retired` payload can name two provider principals, and neither has a field here.
    PlanRefused {
        reason: String,
        member_ref: Option<String>,
        diff: Vec<MemberDiffView>,
    },
    /// A plan child's admission, or a plan command's precondition, refused by name. `reason` is a
    /// snake_case token (`plan_child_refusal_token`, and the plan-store / episode refusals the
    /// plan commands map), never the refusal's payload.
    PlanChildRefused { reason: String },
    /// The connector's capability map does not carry this verb
    /// (`aruna::ConnectorError::unsupported_capability`). The shell's connector is
    /// `GmailConnector::new`, which publishes `m1_verbs()`, so every triage verb answers this at
    /// the connector, behind admission. Turning the verbs on is a deliberate enablement step
    /// (ADR-P010), not a cure this build can offer. It answers before the mutation fence's
    /// sentence: the transport's write gate the fence names is never reached.
    UnsupportedCapability,
    /// The connector's credential was rejected during a plan member's dispatch
    /// (`aruna::ConnectorError::credential_rejected`, an HTTP 401-class answer, e.g. an access
    /// token that aged out mid-run). Its own kind, not a prefix inside [`SurfaceError::Refused`]'s
    /// free-text `reason`: the operator sentence is fixed (rendered by kind, `src/state.ts`) and
    /// the connector's own message never crosses this boundary.
    ///
    /// Latent: every triage verb answers [`SurfaceError::UnsupportedCapability`] at the
    /// connector's capability check before any `apply` runs, so this cannot reach a caller in
    /// this build. It goes live when a verb's capability is enabled (ADR-P010).
    CredentialRejected,
}

/// One diverged closure atom as the renderer sees it (`aruna::attempt::MemberDiff`): the
/// engine's atom name (`membership:INBOX`, `label:TRASH`, …) and two booleans; content-free.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberDiffView {
    pub atom: String,
    pub expected: bool,
    /// The captured value; `None` = the capture did not cover this atom.
    pub observed: Option<bool>,
}

impl From<aruna::attempt::MemberDiff> for MemberDiffView {
    fn from(d: aruna::attempt::MemberDiff) -> Self {
        Self {
            atom: d.atom,
            expected: d.expected,
            observed: d.observed,
        }
    }
}

impl SurfaceError {
    pub(crate) fn busy(kind: &OperationKind) -> Self {
        SurfaceError::Busy {
            operation: kind.label(),
        }
    }

    pub(crate) fn store(e: LogError) -> Self {
        SurfaceError::Store { reason: e.0 }
    }

    /// Like [`SurfaceError::execute`], plus the one piece of context the engine cannot carry: this
    /// session's mutation fence (see [`MUTATIONS_FENCED_REASON`]).
    ///
    /// A verb refused by the fence arrives as `ExecuteError::Connector` carrying the connector's
    /// fixed, id-free phrase ("gmail: provider rejected the mutation") and
    /// [`aruna::EffectEvidence::ProvenNoWire`], the evidence only a refusal decided before a
    /// socket existed may claim (`aruna::gmail::gmail_effect_evidence`, whose `PreWireRefused`
    /// arm is the default-closed [`aruna_gmail::transport::DestructiveWriteGate`]). That phrase
    /// says nothing about why every write on this arm refuses, so when the arm is fenced and the
    /// refusal proved no wire, the named fence is added beside the engine's phrase. It is not an
    /// unconditional rewrite: a transient pre-dispatch transport failure is not the fence, and an
    /// unfenced arm keeps the engine's phrase untouched.
    ///
    /// Run-ending connector dispositions ([`run_ending_connector_disposition`]) are decided
    /// first and answer by their own kind: [`SurfaceError::UnsupportedCapability`] is decided
    /// from the connector's published map, before the write gate the fence names is reached, and
    /// [`SurfaceError::CredentialRejected`] keeps its name even if a future connector proves
    /// `ProvenNoWire` on a rejected credential. The connector's own message is dropped, never
    /// carried onto the wire. The run stops, so unattempted members stay retryable once the
    /// credential is current again.
    pub(crate) fn execute_fenced(e: ExecuteError, fence_reason: Option<&str>) -> Self {
        if let (Some(fence), ExecuteError::Connector(c)) = (fence_reason, &e) {
            if c.effect_evidence == aruna::EffectEvidence::ProvenNoWire
                && c.kind == aruna::FailureKind::Deterministic
                && run_ending_connector_disposition(c).is_none()
            {
                // Terminal: the fence lifts only by an operator's own act (a knob flip, e.g.
                // backups on/off), never by time or by retrying the identical command.
                return SurfaceError::Refused {
                    reason: format!("{fence} (the engine refused pre-wire: {})", c.message),
                    terminal: true,
                };
            }
        }
        SurfaceError::execute(e)
    }

    /// The engine's mutation-boundary error, projected onto one refusal. `Connector` carries the
    /// connector's own already-confined message; every other arm is a fixed phrase, because those
    /// variants' meaning is structural and invented prose would drift from the engine's.
    ///
    /// The three plan errors each have their own arm and typed kind, never the `{other:?}`
    /// fallback, whose Debug text of a `PlanRefused` would carry the refusal's payload (two
    /// provider principals, for a `grant_retired` mismatch).
    ///
    /// Run-ending connector dispositions ([`run_ending_connector_disposition`], today
    /// `unsupported_capability` and `credential_rejected`) are decided here, the one place every
    /// caller reaching a connector error through `execute()`/`execute_fenced()` funnels through.
    ///
    /// Each arm names its own `terminal`, following the classification `ExecuteError`'s doc
    /// comments state:
    /// - `AdmissionRefused`: pre-durable, retryable ⇒ transient.
    /// - `CapacityRefused`: retry once occupancy drains or config changes ⇒ transient.
    /// - `Connector` (the ordinary case): classified by [`aruna::FailureKind`]. `Deterministic`
    ///   fails the same way again ⇒ terminal; `Transient` may not ⇒ transient.
    /// - `Conflict`: the durable command is immutable, so this idempotency key can never take a
    ///   different command ⇒ terminal.
    /// - `InProgress`: the 409-while-processing analog ⇒ transient.
    /// - `Failed`: an identical retry is replayed as an error (a dead letter) ⇒ terminal.
    /// - the catch-all (`ExposureBlocked`, `UndoUnavailable`, `UndoConflict`, `Severed`,
    ///   `ExternallySatisfied`, `AdjudicatedUnresolved`, `AdjudicatedLate`): each is a replay
    ///   answer against an already-closed operation ⇒ terminal.
    pub(crate) fn execute(e: ExecuteError) -> Self {
        let (reason, terminal) = match e {
            ExecuteError::PlanRequired => return SurfaceError::PlanRequired,
            ExecuteError::PlanRefused { reason, member_ref } => {
                return SurfaceError::plan_refused(reason, member_ref)
            }
            ExecuteError::PlanChildRefused(r) => {
                return SurfaceError::plan_child(plan_child_refusal_token(&r))
            }
            ExecuteError::Connector(c) => match run_ending_connector_disposition(&c) {
                Some(surface) => return surface,
                None => {
                    let terminal = c.kind == aruna::FailureKind::Deterministic;
                    (c.message, terminal)
                }
            },
            ExecuteError::Log(l) => return SurfaceError::Store { reason: l.0 },
            ExecuteError::AdmissionRefused(r) => (r, false),
            // Same pre-durable contract as `AdmissionRefused`. The payload is the refusal's typed
            // display text; the debug fallthrough would hand clients `CapacityRefused("…")`.
            ExecuteError::CapacityRefused(r) => (r, false),
            ExecuteError::Conflict => (
                "a different command already exists under this idempotency key".to_string(),
                true,
            ),
            ExecuteError::InProgress => (
                "this operation is still in flight — recovery owns it; retry later".to_string(),
                false,
            ),
            ExecuteError::Failed => (
                "this operation terminally failed; the stored failure is replayed, never a silent \
                 success"
                    .to_string(),
                true,
            ),
            other => (format!("{other:?}"), true),
        };
        SurfaceError::Refused { reason, terminal }
    }

    /// Provider-native identifiers never cross the caller boundary here. What leaves is the
    /// refusal's token, the member's Photon logical id and (for `state_diverged` only) the atom
    /// diff. The rest of the payload (epochs, timestamps, a knob generation, the two grant
    /// generations a `GrantDenial::Retired` carries) stays in the durable `FAILED_PRE_SEND`
    /// record the engine wrote.
    ///
    /// A plan command's refusal by name: a token of the closed table ([`PlanWireToken`]), never a
    /// string spelled at the call site.
    pub(crate) fn plan_child(token: PlanWireToken) -> Self {
        SurfaceError::PlanChildRefused {
            reason: token.as_token().to_string(),
        }
    }

    /// A whole-plan refusal of the approval's evidence (`member_ref: None`, no diff), by a token
    /// of the closed table ([`PlanWireToken`]).
    pub(crate) fn plan_whole(token: PlanWireToken) -> Self {
        SurfaceError::PlanRefused {
            reason: token.as_token().to_string(),
            member_ref: None,
            diff: Vec::new(),
        }
    }

    fn plan_refused(reason: aruna::plan::PlanSendRefusal, member_ref: String) -> Self {
        let token = reason.token().to_string();
        let diff = match reason {
            aruna::plan::PlanSendRefusal::StateDiverged { diff } => {
                diff.into_iter().map(MemberDiffView::from).collect()
            }
            _ => Vec::new(),
        };
        SurfaceError::PlanRefused {
            reason: token,
            member_ref: Some(member_ref),
            diff,
        }
    }
}

/// Declares a closed table of the shell's own wire tokens, after the engine's `closed_tokens!`:
/// each variant is spelled once, and the literal lives in the table, never at a call site.
macro_rules! closed_wire_tokens {
    ($(#[$meta:meta])* enum $name:ident { $($(#[$vmeta:meta])* $variant:ident => $token:literal),+ $(,)? }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub(crate) enum $name {
            $($(#[$vmeta])* $variant),+
        }
        impl $name {
            /// Every variant, in declaration order.
            #[cfg(test)]
            const ALL: &'static [$name] = &[$($name::$variant),+];
            /// The wire token.
            pub(crate) fn as_token(self) -> &'static str {
                match self {
                    $($name::$variant => $token),+
                }
            }
        }
    };
}

closed_wire_tokens! {
    /// The closed table of every token the shell puts in a plan refusal's `reason`
    /// (`SurfaceError::PlanChildRefused`, and the whole-plan `SurfaceError::PlanRefused` of an
    /// approval's evidence). The engine's send-fence tokens are its own table,
    /// `aruna::plan::PlanSendRefusal::TOKENS`. No plan refusal in this file is built from a
    /// string literal (`no_plan_refusal_in_production_is_built_from_an_inline_token`), and the
    /// renderer's copy map reads this table and the engine's (`src/__tests__/state.test.ts`), so
    /// a token with no sentence fails there.
    enum PlanWireToken {
        // A plan child's admission (`aruna::plan::PlanChildRefusal`), one per variant.
        NoPlan => "no_plan",
        NotApproved => "not_approved",
        NoEpisode => "no_episode",
        EpisodeNotActive => "episode_not_active",
        NotReady => "not_ready",
        NotAMember => "not_a_member",
        VerbMismatch => "verb_mismatch",
        AccountMismatch => "account_mismatch",
        KeyMismatch => "key_mismatch",
        EpochMismatch => "epoch_mismatch",
        Expired => "expired",
        NotARedVerb => "not_a_red_verb",
        // The pure plan core (`aruna::plan::PlanRefusal`), one per variant.
        EmptyMembers => "empty_members",
        ConflictingDuplicate => "conflicting_duplicate",
        HeaderCountMismatch => "header_count_mismatch",
        WarningShape => "warning_shape",
        HeaderDiverges => "header_diverges",
        PresentationRowCount => "presentation_row_count",
        PresentationRowDiverges => "presentation_row_diverges",
        ConfiguredKZero => "configured_k_zero",
        Commitment => "commitment",
        LaneMismatch => "lane_mismatch",
        PlanIdMismatch => "plan_id_mismatch",
        ApproverMissing => "approver_missing",
        ViewMismatch => "view_mismatch",
        SampleMismatch => "sample_mismatch",
        SampleKMismatch => "sample_k_mismatch",
        BypassGenerationMismatch => "bypass_generation_mismatch",
        UnknownVerb => "unknown_verb",
        PlanShape => "plan_shape",
        // The plan store's and the episode start's own (the tokens above they share are reused).
        UnknownMember => "unknown_member",
        AlreadyApproved => "already_approved",
        EpisodeClosed => "episode_closed",
        EpisodeHeld => "episode_held",
        DispatchBegan => "dispatch_began",
        // The approve command's evidence refusal: the send fence's own token for the same fact.
        EvidenceInvalid => "evidence_invalid",
        // The wire approve command and a plan frozen on the bypass lane.
        BypassLaneNoScreen => "bypass_lane_no_screen",
    }
}

/// Classifies a connector error that must end the run wherever it is met: a plan member's
/// dispatch, a preflight read, a single verb, `undo`, or the recovery sweep's reconciliation
/// loop. `None` means it is not one of these and the caller keeps its own handling (a recorded
/// refusal, a retry, a barrier). Consulted from `SurfaceError::execute`,
/// `SurfaceError::execute_fenced`, `drive_members`'s `NotMinted` dispatch arm and its `InFlight`
/// recovery-sweep arm, so the closed set lives in one function.
pub(crate) fn run_ending_connector_disposition(c: &aruna::ConnectorError) -> Option<SurfaceError> {
    if c.unsupported_capability {
        Some(SurfaceError::UnsupportedCapability)
    } else if c.credential_rejected {
        Some(SurfaceError::CredentialRejected)
    } else {
        None
    }
}

/// A plan child's admission refusal as its token, one per variant; the payloads (a member id,
/// epochs, timestamps, a status token) never cross.
fn plan_child_refusal_token(r: &aruna::plan::PlanChildRefusal) -> PlanWireToken {
    use aruna::plan::PlanChildRefusal as R;
    use PlanWireToken as T;
    match r {
        R::NoPlan => T::NoPlan,
        R::NotApproved => T::NotApproved,
        R::NoEpisode => T::NoEpisode,
        R::EpisodeNotActive(_) => T::EpisodeNotActive,
        R::NotReady => T::NotReady,
        R::NotAMember(_) => T::NotAMember,
        R::VerbMismatch => T::VerbMismatch,
        R::AccountMismatch => T::AccountMismatch,
        R::KeyMismatch => T::KeyMismatch,
        R::EpochMismatch { .. } => T::EpochMismatch,
        R::Expired { .. } => T::Expired,
        R::NotARedVerb => T::NotARedVerb,
    }
}

/// A [`SurfaceError`]'s reason as plain text. `session_status`'s epoch read never lets the whole
/// command error (a down store still reports `configured: false`), so this unwraps its error into
/// the text `epoch_reason` carries.
pub(crate) fn surface_error_reason(e: &SurfaceError) -> String {
    match e {
        SurfaceError::Busy { operation } => format!("busy: {operation}"),
        SurfaceError::TooSoon {
            operation,
            retry_after_ms,
        } => format!("too soon: {operation} (retry in {retry_after_ms}ms)"),
        SurfaceError::ProviderBackoff {
            operation,
            retry_after_ms,
        } => format!("provider backoff: {operation} (retry in {retry_after_ms}ms)"),
        SurfaceError::SessionUnconfigured { reason, .. }
        | SurfaceError::CredentialExpired { reason, .. }
        | SurfaceError::Refused { reason, .. }
        | SurfaceError::Store { reason }
        | SurfaceError::Internal { reason }
        | SurfaceError::PlanRefused { reason, .. }
        | SurfaceError::PlanChildRefused { reason } => reason.clone(),
        SurfaceError::PlanRequired => "plan_required".to_string(),
        SurfaceError::UnsupportedCapability => "unsupported_capability".to_string(),
        SurfaceError::CredentialRejected => "credential_rejected".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    use aruna::read_coordinator::VerbDelta;
    use aruna::{Action, MailFlag};

    use crate::provider::MUTATIONS_FENCED_REASON;
    use crate::verbs::YellowDoor;

    #[test]
    fn plan_refusals_project_typed_never_prose_and_carry_no_content() {
        let e = SurfaceError::execute(ExecuteError::PlanRequired);
        assert_eq!(e, SurfaceError::PlanRequired);
        let e = SurfaceError::execute(ExecuteError::PlanRefused {
            reason: aruna::plan::PlanSendRefusal::SnapshotAbsent,
            member_ref: "m1".into(),
        });
        assert_eq!(
            e,
            SurfaceError::PlanRefused {
                reason: "snapshot_absent".into(),
                member_ref: Some("m1".into()),
                diff: vec![]
            }
        );
        let e = SurfaceError::execute(ExecuteError::PlanChildRefused(
            aruna::plan::PlanChildRefusal::NotReady,
        ));
        assert_eq!(
            e,
            SurfaceError::PlanChildRefused {
                reason: "not_ready".into()
            }
        );
        // The state_diverged diff crosses as atom names and booleans.
        let e = SurfaceError::execute(ExecuteError::PlanRefused {
            reason: aruna::plan::PlanSendRefusal::StateDiverged {
                diff: vec![aruna::attempt::MemberDiff {
                    atom: "membership:INBOX".into(),
                    expected: true,
                    observed: Some(false),
                }],
            },
            member_ref: "m1".into(),
        });
        assert_eq!(
            e,
            SurfaceError::PlanRefused {
                reason: "state_diverged".into(),
                member_ref: Some("m1".into()),
                diff: vec![MemberDiffView {
                    atom: "membership:INBOX".into(),
                    expected: true,
                    observed: Some(false)
                }]
            }
        );
        // The route witness (route-CORRECT): each YELLOW door builds ITS action
        // and writes ITS projection delta.
        assert_eq!(
            YellowDoor::Untrash.action("m"),
            Action::Untrash {
                message_ref: "m".into()
            }
        );
        assert_eq!(YellowDoor::Untrash.delta(), VerbDelta::Untrashed);
        assert_eq!(
            YellowDoor::UnmarkSpam.action("m"),
            Action::UnmarkSpam {
                message_ref: "m".into()
            }
        );
        assert_eq!(YellowDoor::UnmarkSpam.delta(), VerbDelta::SpamSet(false));
        for value in [true, false] {
            assert_eq!(
                YellowDoor::SetSeen(value).action("m"),
                Action::SetFlag {
                    message_ref: "m".into(),
                    flag: MailFlag::Seen,
                    value
                }
            );
            assert_eq!(YellowDoor::SetSeen(value).delta(), VerbDelta::SeenSet(value));
        }
        assert_eq!(
            [
                YellowDoor::Untrash.verb(),
                YellowDoor::UnmarkSpam.verb(),
                YellowDoor::SetSeen(true).verb()
            ],
            ["untrash", "unmark_spam", "set_seen"]
        );
    }

    /// THE PRINCIPAL RULE: provider-native identifiers never cross
    /// the caller boundary. A `grant_retired` refusal's payload names two provider principals;
    /// the projection carries the TOKEN, the Photon member id and the diff — nothing else. And
    /// no plan kind reaches `execute`'s `{other:?}` fallback.
    #[test]
    fn a_plan_refusal_projection_carries_no_provider_identifier_and_every_plan_kind_has_its_own_arm(
    ) {
        use aruna::episode::EpisodeStatusToken;
        use aruna::plan::{PlanChildRefusal, PlanRefusal, PlanSendRefusal};
        let e = SurfaceError::execute(ExecuteError::PlanRefused {
            reason: PlanSendRefusal::GrantRetired(aruna::plan::GrantDenial::PrincipalMismatch),
            member_ref: "m1".into(),
        });
        assert_eq!(
            e,
            SurfaceError::PlanRefused {
                reason: "grant_retired".into(),
                member_ref: Some("m1".into()),
                diff: vec![]
            }
        );
        let wire = serde_json::to_string(&e).unwrap();
        assert!(!wire.contains('@'), "no provider principal crosses: {wire}");

        let every_send_refusal = [
            PlanSendRefusal::EpisodeHeld(EpisodeStatusToken::Paused),
            PlanSendRefusal::EpisodeClosed(EpisodeStatusToken::Completed),
            PlanSendRefusal::NotReady,
            PlanSendRefusal::NoEpisode,
            PlanSendRefusal::PlanEpochMismatch { plan: 1, current: 2 },
            PlanSendRefusal::Expired {
                expires_at: "2026-09-24T00:00:00Z".into(),
                effective_now: "2026-09-25T00:00:00Z".into(),
            },
            PlanSendRefusal::NotAMember,
            PlanSendRefusal::EvidenceAbsent,
            PlanSendRefusal::EvidenceInvalid(PlanRefusal::ViewMismatch),
            PlanSendRefusal::GrantRetired(aruna::plan::GrantDenial::Unavailable),
            PlanSendRefusal::CoverageDiverged { plan: 1, current: 2 },
            PlanSendRefusal::SnapshotAbsent,
            PlanSendRefusal::BypassNoticeAbsent,
            PlanSendRefusal::CaptureRequired,
            PlanSendRefusal::StateDiverged { diff: vec![] },
        ];
        assert_eq!(every_send_refusal.len(), PlanSendRefusal::TOKENS.len());
        for refusal in every_send_refusal {
            let token = refusal.token();
            let projected = SurfaceError::execute(ExecuteError::PlanRefused {
                reason: refusal,
                member_ref: "m1".into(),
            });
            let wire = serde_json::to_string(&projected).unwrap();
            assert!(!wire.contains('@'), "{token}: {wire}");
            match projected {
                SurfaceError::PlanRefused {
                    reason,
                    member_ref,
                    ..
                } => {
                    assert_eq!(reason, token);
                    assert_eq!(member_ref.as_deref(), Some("m1"));
                }
                other => panic!("{token} must project as plan_refused: {other:?}"),
            }
        }

        let every_child_refusal = [
            PlanChildRefusal::NoPlan,
            PlanChildRefusal::NotApproved,
            PlanChildRefusal::NoEpisode,
            PlanChildRefusal::EpisodeNotActive(EpisodeStatusToken::Paused),
            PlanChildRefusal::NotReady,
            PlanChildRefusal::NotAMember("m9".into()),
            PlanChildRefusal::VerbMismatch,
            PlanChildRefusal::AccountMismatch,
            PlanChildRefusal::KeyMismatch,
            PlanChildRefusal::EpochMismatch { plan: 1, current: 2 },
            PlanChildRefusal::Expired {
                expires_at: "2026-09-24T00:00:00Z".into(),
                effective_now: "2026-09-25T00:00:00Z".into(),
            },
            PlanChildRefusal::NotARedVerb,
        ];
        let mut tokens = BTreeSet::new();
        for refusal in every_child_refusal {
            match SurfaceError::execute(ExecuteError::PlanChildRefused(refusal)) {
                SurfaceError::PlanChildRefused { reason } => {
                    assert!(
                        !reason.is_empty()
                            && reason.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
                        "a snake_case token, never a payload: {reason:?}"
                    );
                    tokens.insert(reason);
                }
                other => panic!("a child refusal must project as plan_child_refused: {other:?}"),
            }
        }
        assert_eq!(tokens.len(), 12, "one token per variant: {tokens:?}");
    }

    #[test]
    fn the_expiry_refusal_serializes_under_its_own_kind_with_its_cure() {
        let wire = serde_json::to_value(SurfaceError::CredentialExpired {
            expires_at: 42,
            cure: Cure::ReMint,
            reason: "the Gmail credential expired at 42".to_string(),
        })
        .expect("serializes");
        assert_eq!(
            wire,
            serde_json::json!({
                "kind": "credential_expired",
                "expires_at": 42,
                "cure": "re_mint",
                "reason": "the Gmail credential expired at 42"
            })
        );
    }

    /// The other half: the SAME named reason reaches the verb path's typed refusal. The gate
    /// refuses below the seam and the engine hands up its fixed, id-free phrase plus
    /// `ProvenNoWire` — the evidence only a pre-socket refusal may claim — and this mapping is
    /// what turns that into something a user can act on.
    #[test]
    fn a_fence_refused_verb_surfaces_the_same_named_reason() {
        let fenced = SurfaceError::execute_fenced(
            ExecuteError::Connector(
                aruna::ConnectorError::deterministic("gmail: provider rejected the mutation")
                    .proven_no_wire(),
            ),
            Some(MUTATIONS_FENCED_REASON),
        );
        match &fenced {
            SurfaceError::Refused { reason, .. } => {
                assert!(
                    reason.contains(MUTATIONS_FENCED_REASON),
                    "the fence's own sentence must ride out: {reason}"
                );
                assert!(
                    reason.contains("gmail: provider rejected the mutation"),
                    "the engine's own phrase is kept beside it, never replaced: {reason}"
                );
            }
            other => panic!("a fence-refused verb must be a typed Refused: {other:?}"),
        }

        // NOT an unconditional rewrite. A TRANSIENT pre-dispatch failure is not the fence, and an
        // unfenced arm keeps the engine's phrase untouched.
        let transient = SurfaceError::execute_fenced(
            ExecuteError::Connector(
                aruna::ConnectorError::transient("gmail: provider rejected the mutation")
                    .proven_no_wire(),
            ),
            Some(MUTATIONS_FENCED_REASON),
        );
        assert_eq!(
            transient,
            SurfaceError::Refused {
                reason: "gmail: provider rejected the mutation".to_string(),
                // A Transient connector kind classifies transient.
                terminal: false,
            },
            "a retryable pre-dispatch failure is not the fence"
        );
        let unfenced = SurfaceError::execute_fenced(
            ExecuteError::Connector(
                aruna::ConnectorError::deterministic("gmail: provider rejected the mutation")
                    .proven_no_wire(),
            ),
            None,
        );
        assert_eq!(
            unfenced,
            SurfaceError::Refused {
                reason: "gmail: provider rejected the mutation".to_string(),
                // A Deterministic connector kind classifies terminal.
                terminal: true,
            },
            "an arm with no fence must not grow a fence reason"
        );
    }

    /// A capacity refusal reaches the surface as its OWN typed display
    /// text, never `format!("{:?}")`'s debug form. The variant mirrors `AdmissionRefused`'s
    /// pre-durable contract and carries the refusal's display sentence (which inequality
    /// refused, and the observed numbers); the earlier fallthrough handed clients
    /// `CapacityRefused("…")` with debug quoting and escaping instead of the sentence itself.
    #[test]
    fn a_capacity_refusal_surfaces_its_display_text_not_debug_quoting() {
        let refusal = "the active pool is full: 64 active operations at max_active_ops 64; \
                       retry once occupancy drains"
            .to_string();
        let surfaced = SurfaceError::execute(ExecuteError::CapacityRefused(refusal.clone()));
        assert_eq!(
            surfaced,
            // CapacityRefused classifies transient (mirrors
            // AdmissionRefused's pre-durable, documented-retryable contract).
            SurfaceError::Refused { reason: refusal, terminal: false },
            "the typed display text rides out verbatim — no CapacityRefused(..) debug wrapper, \
             no escaping"
        );
    }

    #[test]
    fn the_two_new_refusals_serialize_as_tagged_values_carrying_their_retry_after() {
        let too_soon = serde_json::to_value(SurfaceError::TooSoon {
            operation: "refresh_inbox".to_string(),
            retry_after_ms: 14_999,
        })
        .expect("serializes");
        assert_eq!(
            too_soon,
            serde_json::json!({
                "kind": "too_soon",
                "operation": "refresh_inbox",
                "retry_after_ms": 14_999
            })
        );

        let backoff = serde_json::to_value(SurfaceError::ProviderBackoff {
            operation: "message_body:m1".to_string(),
            retry_after_ms: 59_999,
        })
        .expect("serializes");
        assert_eq!(
            backoff,
            serde_json::json!({
                "kind": "provider_backoff",
                "operation": "message_body:m1",
                "retry_after_ms": 59_999
            })
        );
    }

    /// Every `PlanChildRefusal` projects to ITS token (the existing witness counted twelve
    /// distinct tokens; a swap of two rows kept the count).
    #[test]
    fn every_plan_child_refusal_projects_to_its_own_token() {
        use aruna::episode::EpisodeStatusToken;
        use aruna::plan::PlanChildRefusal as R;
        let table: Vec<(R, &str)> = vec![
            (R::NoPlan, "no_plan"),
            (R::NotApproved, "not_approved"),
            (R::NoEpisode, "no_episode"),
            (R::EpisodeNotActive(EpisodeStatusToken::Paused), "episode_not_active"),
            (R::NotReady, "not_ready"),
            (R::NotAMember("m".into()), "not_a_member"),
            (R::VerbMismatch, "verb_mismatch"),
            (R::AccountMismatch, "account_mismatch"),
            (R::KeyMismatch, "key_mismatch"),
            (R::EpochMismatch { plan: 1, current: 2 }, "epoch_mismatch"),
            (R::Expired { expires_at: "a".into(), effective_now: "b".into() }, "expired"),
            (R::NotARedVerb, "not_a_red_verb"),
        ];
        for (refusal, token) in table {
            assert_eq!(
                SurfaceError::execute(ExecuteError::PlanChildRefused(refusal.clone())),
                SurfaceError::PlanChildRefused { reason: token.to_string() },
                "{refusal:?}"
            );
        }
    }

    /// No plan refusal in the shell's PRODUCTION source is built from an inline string
    /// literal — every token comes from the one closed table (`PlanWireToken`), which the renderer's
    /// copy-coverage test reads (`src/__tests__/state.test.ts`).
    #[test]
    fn no_plan_refusal_in_production_is_built_from_an_inline_token() {
        // Every production module split out of the old single-file lib.rs.
        let sources = [
            include_str!("lib.rs"),
            include_str!("error.rs"),
            include_str!("single_flight.rs"),
            include_str!("credential.rs"),
            include_str!("session.rs"),
            include_str!("provider.rs"),
            include_str!("state.rs"),
            include_str!("status.rs"),
            include_str!("ipc.rs"),
            include_str!("plumbing.rs"),
            include_str!("verbs.rs"),
            include_str!("plan.rs"),
        ];
        let mut offenders = Vec::new();
        for source in sources {
            let source = source.replace("\r\n", "\n");
            let production = match source.find(&["#[cfg(test)]\nmod ", "tests {"].concat()) {
                Some(tests_at) => &source[..tests_at],
                None => &source[..],
            };
            for head in ["PlanChildRefused {", "PlanRefused {"] {
                for (at, _) in production.match_indices(head) {
                    let construction = &production[at..at + production[at..].find('}').expect("closes")];
                    let literal = construction
                        .split("reason:")
                        .skip(1)
                        .any(|after| after.trim_start().starts_with('"'));
                    if literal {
                        offenders.push(construction.split_whitespace().collect::<Vec<_>>().join(" "));
                    }
                }
            }
        }
        assert!(offenders.is_empty(), "inline plan-refusal tokens: {offenders:#?}");
        let tokens: BTreeSet<&str> = PlanWireToken::ALL.iter().map(|t| t.as_token()).collect();
        assert_eq!(tokens.len(), PlanWireToken::ALL.len(), "each token is spelled once");
        assert!(
            tokens.iter().all(|t| !t.is_empty() && t.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')),
            "snake_case tokens: {tokens:?}"
        );
    }
}
