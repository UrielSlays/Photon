//! The `TriagePlan` core, pure: types, canonical encoding, the keyed digests, the sample, and
//! every legality predicate. No I/O, no store, no clock; the store half calls through this
//! module. Every content-derived durable value here is an `mw.commitment.v1` tag under the
//! account key with its randomizer stored beside it (`crate::commitment`), never a bare digest.
//! This module reaches no digest or MAC primitive of its own (see `docs/crypto-inventory.md`).
//!
//! Encoding discipline, as in `attempt.rs`'s `encode_sever_witness`: a fixed-length ASCII
//! domain tag, a u32-BE count, then the members in canonical order, with every variable-length
//! field length-prefixed through `crate::commitment::frame_prefix`, the single framing point.

use std::collections::{BTreeMap, BTreeSet};

use crate::commitment::{
    commit_over, compute_tag, frame_prefix, mint_randomizer, CommitmentDisposition, CommitmentDomain, CommitmentError,
    CommitmentKey, CommitmentKeyRef, CommitmentProfile, CommitmentTag, Randomizer,
};

/// Every refusal this core can answer. Named, never a bare "no".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanRefusal {
    EmptyMembers,
    ConflictingDuplicate(String),
    HeaderCountMismatch { header: u32, members: usize },
    /// The uncovered-backup warning is present exactly when `backup_coverage == false`, and
    /// never empty. The encoding frames an absent warning as the empty string, so `Some("")`
    /// would collide with `None` and a covered header with an uncovered one.
    WarningShape(WarningShapeRule),
    /// The presentation header names another account or verb than the set digest binds: the
    /// human would read one red effect while the plan commits another. Carries the field.
    HeaderDiverges(HeaderField),
    PresentationRowCount { rows: usize, members: usize },
    PresentationRowDiverges(String),
    ConfiguredKZero,
    Commitment(CommitmentError),
    /// Evidence arrived for a lane the plan did not freeze.
    LaneMismatch { plan: AdmissionLane, evidence: Comprehension },
    /// Evidence minted against another plan instance: plan A's approval never admits plan B.
    PlanIdMismatch { plan: PlanId, evidence: PlanId },
    /// A screen lane's evidence names no approver.
    ApproverMissing,
    /// The rendered view's commitment does not equal the plan's (display substitution).
    ViewMismatch,
    /// Aggregate evidence carries a sample that is not the derived one.
    SampleMismatch(String),
    /// Aggregate evidence's k is not the plan's effective k.
    SampleKMismatch { plan: u32, evidence: u32 },
    /// The bypass lane's bound config generation is not the one in force.
    BypassGenerationMismatch { plan: u64, current: u64 },
    UnknownVerb(String),
    /// The plan disagrees with itself: a field against its own header, key reference, lane or
    /// recomputed `effective_k` ([`TriagePlan::validate_shape`]). Names the rule that broke.
    PlanShape(PlanShapeRule),
}

// The rule vocabularies a `PlanRefusal` names are closed enums rather than `&'static str`
// sentences, because a terminal send refusal's record carries them (`PlanSendRefusal::record`'s
// `detail`) and `PlanSendRefusal::from_record` reads them back. Each goes through one
// `closed_tokens!` declaration, so a rule's durable token has one spelling.
closed_tokens! {
    /// Which of [`TriagePlan::validate_shape`]'s rules a [`PlanRefusal::PlanShape`] names.
    pub enum PlanShapeRule {
        MemberCountIsNotHeaderCount => "member_count_is_not_header_count",
        VerbIsNotHeaderVerb => "verb_is_not_header_verb",
        AccountIsNotHeaderAccount => "account_is_not_header_account",
        HeaderTierIsNotRed => "header_tier_is_not_red",
        KeyRefIsNotDigestsKeyRef => "key_ref_is_not_digests_key_ref",
        BackupsOnIsNotHeaderCoverage => "backups_on_is_not_header_coverage",
        PerMemberLaneRequiresFullList => "per_member_lane_requires_full_list",
        AggregateLaneRequiresSummarySample => "aggregate_lane_requires_summary_sample",
        EffectiveKIsNotMin => "effective_k_is_not_min",
        /// A bypass notice on a plan that is not a bypass-lane plan minted under `backups: off`.
        BypassNoticeOutsideAnUncoveredBypassPlan => "bypass_notice_outside_an_uncovered_bypass_plan",
        /// A bypass notice whose text is not the plan verb's uncovered warning.
        BypassNoticeIsNotTheVerbWarning => "bypass_notice_is_not_the_verb_warning",
    }
}

closed_tokens! {
    /// Which of the warning rules (`check_warning_shape`) a [`PlanRefusal::WarningShape`] names.
    pub enum WarningShapeRule {
        CoverageOnCarriesNoWarning => "coverage_on_carries_no_warning",
        CoverageOffRequiresTheVerbWarning => "coverage_off_requires_the_verb_warning",
        TheWarningIsNeverEmpty => "the_warning_is_never_empty",
    }
}

closed_tokens! {
    /// Which presentation-header field a [`PlanRefusal::HeaderDiverges`] names.
    pub enum HeaderField {
        Account => "account",
        Verb => "verb",
        Tier => "tier",
    }
}

impl From<CommitmentError> for PlanRefusal {
    fn from(e: CommitmentError) -> Self {
        PlanRefusal::Commitment(e)
    }
}

/// The red-tier verbs a plan may carry (yellow verbs never need a plan; `RiskTier::requires_plan`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanVerb {
    Trash,
    MarkSpam,
}

impl PlanVerb {
    pub const ALL: [PlanVerb; 2] = [PlanVerb::Trash, PlanVerb::MarkSpam];
    pub fn as_token(self) -> &'static str {
        match self {
            PlanVerb::Trash => "trash",
            PlanVerb::MarkSpam => "mark_spam",
        }
    }
    pub fn from_token(s: &str) -> Result<Self, PlanRefusal> {
        PlanVerb::ALL.iter().copied().find(|v| v.as_token() == s).ok_or_else(|| PlanRefusal::UnknownVerb(s.to_string()))
    }
    /// The engine action for one member.
    pub fn action(self, message_ref: &str) -> crate::Action {
        match self {
            PlanVerb::Trash => crate::Action::Trash { message_ref: message_ref.to_string() },
            PlanVerb::MarkSpam => crate::Action::MarkSpam { message_ref: message_ref.to_string() },
        }
    }
    /// The verb-specific warning a plan's header carries when backups are off; see
    /// [`TRASH_UNCOVERED_WARNING`] and [`MARK_SPAM_UNCOVERED_WARNING`].
    pub fn uncovered_warning(self) -> &'static str {
        match self {
            PlanVerb::Trash => TRASH_UNCOVERED_WARNING,
            PlanVerb::MarkSpam => MARK_SPAM_UNCOVERED_WARNING,
        }
    }
}

/// The Trash warning, verbatim from the design.
pub const TRASH_UNCOVERED_WARNING: &str = "snapshot recovery is OFF: Photon's undo (Untrash, the 7-day offer, `UNDO_OFFER_SECONDS` at `prestate.rs:8`) still stands, because snapshots never served undo; what is lost is S-SNAP content recovery/export, leaving only the provider's own Trash retention (~30 days, provider-managed and policy-qualified); past it, gone for good";

/// The MarkSpam warning has no verbatim design sentence; it is the Trash sentence with the SPAM
/// destination's facts substituted (undo is UnmarkSpam; the remaining provider surface is the
/// SPAM folder's own provider-managed retention policy, never Trash wording).
pub const MARK_SPAM_UNCOVERED_WARNING: &str = "snapshot recovery is OFF: Photon's undo (UnmarkSpam, the 7-day offer, `UNDO_OFFER_SECONDS` at `prestate.rs:8`) still stands, because snapshots never served undo; what is lost is S-SNAP content recovery/export, leaving only the SPAM folder's own retention/deletion policy (provider-managed and policy-qualified); past it, gone for good";

/// The human-visible display fields frozen at mint: the row a human reads is the row the digest
/// covers, built from the header row at mint and never re-read at render. Subject, name half and
/// the display copy of the address are normalized text (`header_normalize::normalize_display`);
/// the header row's `from_addr` identity column stays raw and outside the plan. `size` is `None`
/// because the header store carries no size (unavailable, never blank).
///
/// `sender` (the name half) and `sender_address` are two separate fields, not one composed
/// `"{name} <{addr}>"` string. The plan row renders them as two `<bdi>` isolates, like the inbox
/// row, so a bidi-hostile display name cannot reorder a fake address into the position the real
/// one renders last (a quoted display name carrying its own fake `<addr>` pushed the real
/// address out of the trailing position). Both are in the digest preimage (`encode_row`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrozenDisplay {
    /// The display-name half only (empty when the header carried none), never the address.
    pub sender: String,
    /// The address half's display copy (normalized, through the same function as `sender`):
    /// `<{from_addr}>` when a display name is present, or the bare address when there is none,
    /// matching the inbox row's bare `from_addr` for a nameless sender.
    pub sender_address: String,
    /// The structured sender, frozen beside the display text: the summary's sender domains are
    /// derived from it, never from `sender`.
    pub sender_parse: FrozenSender,
    pub subject: String,
    /// RFC 3339 UTC of `received_at`.
    pub date: String,
    pub size: Option<u64>,
}

/// A frozen member's structured sender, from the header row's RFC 5322 §3.4 parse
/// (`crate::mailbox`): the addr-spec and its domain when the From header was exactly one
/// mailbox, and otherwise why there is none. An enum, so an address without its domain, or a
/// domain on an unparsed sender, cannot be represented. The four `plan_member` columns
/// (`sender_status`, `sender_local`, `sender_addr`, `sender_domain`) are its storage
/// ([`FrozenSender::from_columns`] reads them back), and their CHECKs mirror the same rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrozenSender {
    /// Exactly one mailbox: the canonical addr-spec, its local part (taken from the same
    /// grammar tokens as `addr`, never by splitting `addr` on its `@`, since a domain-literal
    /// may carry its own `@`), and its ASCII-lowercased domain.
    Parsed { addr: String, local: String, domain: String },
    /// No From value: there is no sender to name.
    Unavailable,
    /// A From value that does not parse under the grammar at all; its raw text is the display.
    Malformed,
    /// A From value that parses but is not exactly one mailbox (a group, or a list of more than
    /// one): its raw text is the display, with valid syntax and no single sender attributed.
    Unsupported,
}

impl FrozenSender {
    pub fn status(&self) -> crate::mailbox::SenderStatus {
        use crate::mailbox::SenderStatus;
        match self {
            FrozenSender::Parsed { .. } => SenderStatus::Ok,
            FrozenSender::Unavailable => SenderStatus::Unavailable,
            FrozenSender::Malformed => SenderStatus::Malformed,
            FrozenSender::Unsupported => SenderStatus::Unsupported,
        }
    }

    pub fn addr(&self) -> Option<&str> {
        match self {
            FrozenSender::Parsed { addr, .. } => Some(addr),
            FrozenSender::Unavailable | FrozenSender::Malformed | FrozenSender::Unsupported => None,
        }
    }

    /// The local-part half alone; `Some` exactly when [`Self::addr`] is.
    pub fn local(&self) -> Option<&str> {
        match self {
            FrozenSender::Parsed { local, .. } => Some(local),
            FrozenSender::Unavailable | FrozenSender::Malformed | FrozenSender::Unsupported => None,
        }
    }

    pub fn domain(&self) -> Option<&str> {
        match self {
            FrozenSender::Parsed { domain, .. } => Some(domain),
            FrozenSender::Unavailable | FrozenSender::Malformed | FrozenSender::Unsupported => None,
        }
    }

    /// Rebuild from the four stored columns; `None` when they disagree (a row the columns'
    /// CHECKs refuse to hold).
    pub fn from_columns(
        status: crate::mailbox::SenderStatus,
        local: Option<String>,
        addr: Option<String>,
        domain: Option<String>,
    ) -> Option<Self> {
        use crate::mailbox::SenderStatus;
        match (status, local, addr, domain) {
            (SenderStatus::Ok, Some(local), Some(addr), Some(domain)) => Some(FrozenSender::Parsed { addr, local, domain }),
            (SenderStatus::Unavailable, None, None, None) => Some(FrozenSender::Unavailable),
            (SenderStatus::Malformed, None, None, None) => Some(FrozenSender::Malformed),
            (SenderStatus::Unsupported, None, None, None) => Some(FrozenSender::Unsupported),
            _ => None,
        }
    }
}

/// One canonical member: the Photon logical identity (ADR-P004, never a provider handle), its
/// frozen display, the approval-time observed closure-atom state (the local belief at mint;
/// preflight and per-child admission re-observe against it), and the forward target per atom.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanMember {
    pub message_ref: String,
    pub display: FrozenDisplay,
    pub observed_state: BTreeMap<String, bool>,
    pub forward_target: BTreeMap<String, bool>,
}

/// Dedupe and sort by `message_ref` bytes. Two entries for one ref must be identical, or the
/// mint refuses: the engine never picks which of two frozen rows survives.
pub fn canonical_members(input: Vec<PlanMember>) -> Result<Vec<PlanMember>, PlanRefusal> {
    if input.is_empty() {
        return Err(PlanRefusal::EmptyMembers);
    }
    let mut by_ref: BTreeMap<String, PlanMember> = BTreeMap::new();
    for m in input {
        match by_ref.get(&m.message_ref) {
            Some(existing) if *existing != m => return Err(PlanRefusal::ConflictingDuplicate(m.message_ref)),
            Some(_) => {}
            None => {
                by_ref.insert(m.message_ref.clone(), m);
            }
        }
    }
    Ok(by_ref.into_values().collect())
}

/// The frozen admission lane: decided at mint by the screen-mode knob and the bypass knob in
/// force. Evidence of another lane is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionLane {
    PerMember,
    Aggregate,
    Bypassed { bypass_config_generation: u64 },
}

impl AdmissionLane {
    pub const TOKENS: [&'static str; 3] = ["per_member", "aggregate", "bypassed"];
    pub fn as_token(self) -> &'static str {
        match self {
            AdmissionLane::PerMember => "per_member",
            AdmissionLane::Aggregate => "aggregate",
            AdmissionLane::Bypassed { .. } => "bypassed",
        }
    }
}

/// The approval-screen mode the plan froze at mint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalMode {
    FullList,
    SummarySample { configured_k: u32, effective_k: u32 },
}

impl ApprovalMode {
    /// The durable `triage_plan.approval_mode` tokens, guarded against the DDL CHECK.
    pub const TOKENS: [&'static str; 2] = ["full_list", "summary_sample"];
    pub fn as_token(self) -> &'static str {
        match self {
            ApprovalMode::FullList => "full_list",
            ApprovalMode::SummarySample { .. } => "summary_sample",
        }
    }
}

/// The lane a plan freezes, from the knobs in force at mint (the red bypass lane).
pub fn admission_lane_for(
    mode: crate::config_knobs::ApprovalModeKnob,
    bypass: crate::config_knobs::InForce<crate::config_knobs::RedBypassKnob>,
) -> AdmissionLane {
    use crate::config_knobs::{ApprovalModeKnob, RedBypassKnob};
    match (bypass.value, mode) {
        (RedBypassKnob::On, _) => AdmissionLane::Bypassed { bypass_config_generation: bypass.generation },
        (RedBypassKnob::Off, ApprovalModeKnob::FullList) => AdmissionLane::PerMember,
        (RedBypassKnob::Off, ApprovalModeKnob::SummarySample { .. }) => AdmissionLane::Aggregate,
    }
}

/// `effective_k = min(configured_k, member_count)`; `configured_k` must be at least 1 so a
/// nonempty plan always samples at least one row.
pub fn effective_k(configured_k: u32, member_count: usize) -> Result<u32, PlanRefusal> {
    if configured_k == 0 {
        return Err(PlanRefusal::ConfiguredKZero);
    }
    Ok(configured_k.min(u32::try_from(member_count).unwrap_or(u32::MAX)))
}

/// The one tier a plan's presentation header may carry: every plan verb is red
/// ([`TriagePlan::tier`]; `PlanVerb::action`'s `risk_tier`). [`PlanDigests::mint`] refuses a
/// header naming any other (`HeaderDiverges(HeaderField::Tier)`), the store mints with it, and
/// the `triage_plan.tier` CHECK spells it (guarded in this module's tests).
pub const PLAN_TIER: &str = "red";

/// The leading fields of the rendered payload (verb, tier, count, coverage, and the
/// verb-specific warning), inside the commitment in both modes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentationHeader {
    pub account: String,
    pub verb: PlanVerb,
    pub tier: String,
    pub count: u32,
    pub backup_coverage: bool,
    /// The verb-specific warning, present exactly when `backup_coverage == false`, and never
    /// empty (`derive_presentation` refuses any other shape: `PlanRefusal::WarningShape`).
    pub warning: Option<String>,
}

/// The aggregate shape, computed from the same canonical members as the rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentationSummary {
    pub count: u32,
    /// `(domain, count)`, sorted by count descending then domain bytes. Parsed domains only
    /// ([`FrozenSender::Parsed`]): a member whose sender could not be parsed is never a domain
    /// entry; it is counted below.
    pub sender_domains: Vec<(String, u32)>,
    /// Members whose From header was absent or empty ([`FrozenSender::Unavailable`]); the review
    /// says "sender domain unavailable for N members".
    pub sender_domain_unavailable: u32,
    /// Members whose From header does not parse under the grammar at all
    /// ([`FrozenSender::Malformed`]); the review says "malformed sender header for N members,
    /// normalized text shown".
    pub sender_header_malformed: u32,
    /// Members whose From header parses but is not exactly one mailbox, a group or a list of
    /// more than one ([`FrozenSender::Unsupported`]); the review says "valid sender syntax Photon
    /// does not attribute for N members (group or multiple mailboxes), no sender address".
    pub sender_header_unsupported: u32,
    pub date_min: String,
    pub date_max: String,
    pub total_size: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentationRow {
    pub message_ref: String,
    pub sender: String,
    /// The address half, frozen and carried separately from `sender` (see
    /// `FrozenDisplay::sender_address`); the row renders both as their own isolate.
    pub sender_address: String,
    /// The frozen member's sender status token (`FrozenSender::status().as_token()`: "ok",
    /// "unavailable", "malformed" or "unsupported"), so a non-`ok` row's status renders outside
    /// the address isolate as its own status atom, never as a synthesized sentence inside it
    /// (where it would be indistinguishable from a real address).
    pub sender_status: String,
    /// The addr-spec's local-part half alone, from the parser's own tokens
    /// (`FrozenSender::local()`); empty unless `sender_status == "ok"`. The renderer places this
    /// in the local `<bdi>` and [`Self::sender_domain`] in the domain `<bdi>`, so it never
    /// derives that boundary by searching `sender_address` for an `@` (a domain-literal may
    /// carry its own `@`, which `lastIndexOf`/`split` cannot tell from the real boundary).
    pub sender_local: String,
    /// The addr-spec's domain half alone (`FrozenSender::domain()`); empty unless
    /// `sender_status == "ok"`. See [`Self::sender_local`].
    pub sender_domain: String,
    pub subject: String,
    pub date: String,
    pub size: Option<u64>,
}

/// The immutable, versioned canonical presentation, derived from the members and never
/// supplied beside them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanPresentation {
    pub header: PresentationHeader,
    pub summary: PresentationSummary,
    pub rows: Vec<PresentationRow>,
}

/// The warning rule: present exactly when coverage is off, and never the empty string (which
/// the encoding reserves for "absent").
fn check_warning_shape(header: &PresentationHeader) -> Result<(), PlanRefusal> {
    match (header.backup_coverage, header.warning.as_deref()) {
        (true, None) => Ok(()),
        (true, Some(_)) => Err(PlanRefusal::WarningShape(WarningShapeRule::CoverageOnCarriesNoWarning)),
        (false, None) => Err(PlanRefusal::WarningShape(WarningShapeRule::CoverageOffRequiresTheVerbWarning)),
        (false, Some("")) => Err(PlanRefusal::WarningShape(WarningShapeRule::TheWarningIsNeverEmpty)),
        (false, Some(_)) => Ok(()),
    }
}

pub fn derive_presentation(header: &PresentationHeader, members: &[PlanMember]) -> Result<PlanPresentation, PlanRefusal> {
    if header.count as usize != members.len() {
        return Err(PlanRefusal::HeaderCountMismatch { header: header.count, members: members.len() });
    }
    check_warning_shape(header)?;
    let rows: Vec<PresentationRow> = members
        .iter()
        .map(|m| PresentationRow {
            message_ref: m.message_ref.clone(),
            sender: m.display.sender.clone(),
            sender_address: m.display.sender_address.clone(),
            sender_status: m.display.sender_parse.status().as_token().to_string(),
            sender_local: m.display.sender_parse.local().unwrap_or("").to_string(),
            sender_domain: m.display.sender_parse.domain().unwrap_or("").to_string(),
            subject: m.display.subject.clone(),
            date: m.display.date.clone(),
            size: m.display.size,
        })
        .collect();
    // The domains are the parsed senders' (the header row's RFC 5322 §3.4 parse, frozen at
    // mint), never a search of the display text, whose last `<...>` a sender controls. What
    // cannot be parsed is counted, by reason.
    let mut domains: BTreeMap<String, u32> = BTreeMap::new();
    let (mut sender_domain_unavailable, mut sender_header_malformed, mut sender_header_unsupported) = (0u32, 0u32, 0u32);
    for m in members {
        match &m.display.sender_parse {
            FrozenSender::Parsed { domain, .. } => *domains.entry(domain.clone()).or_insert(0) += 1,
            FrozenSender::Unavailable => sender_domain_unavailable += 1,
            FrozenSender::Malformed => sender_header_malformed += 1,
            FrozenSender::Unsupported => sender_header_unsupported += 1,
        }
    }
    let mut sender_domains: Vec<(String, u32)> = domains.into_iter().collect();
    sender_domains.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.as_bytes().cmp(b.0.as_bytes())));
    let date_min = members.iter().map(|m| m.display.date.as_str()).min().unwrap_or_default().to_string();
    let date_max = members.iter().map(|m| m.display.date.as_str()).max().unwrap_or_default().to_string();
    let total_size = members.iter().try_fold(0u64, |acc, m| m.display.size.map(|s| acc.saturating_add(s)));
    Ok(PlanPresentation {
        header: header.clone(),
        summary: PresentationSummary {
            count: header.count,
            sender_domains,
            sender_domain_unavailable,
            sender_header_malformed,
            sender_header_unsupported,
            date_min,
            date_max,
            total_size,
        },
        rows,
    })
}

/// Row count equals member count, each row keyed by its member identity in canonical order,
/// each row's text equal to the member's frozen display (so a benign presentation cannot be
/// paired with a different sensitive member set and still validate).
pub fn validate_presentation(p: &PlanPresentation, members: &[PlanMember]) -> Result<(), PlanRefusal> {
    if p.rows.len() != members.len() {
        return Err(PlanRefusal::PresentationRowCount { rows: p.rows.len(), members: members.len() });
    }
    for (row, m) in p.rows.iter().zip(members) {
        if row.message_ref != m.message_ref
            || row.sender != m.display.sender
            || row.sender_address != m.display.sender_address
            // The structured sender the fold froze on the row and bound into the digest is
            // checked here too, or a forged row could carry a different status/local/domain than
            // the member's own `FrozenSender` and still validate.
            || row.sender_status != m.display.sender_parse.status().as_token()
            || row.sender_local != m.display.sender_parse.local().unwrap_or("")
            || row.sender_domain != m.display.sender_parse.domain().unwrap_or("")
            || row.subject != m.display.subject
            || row.date != m.display.date
            || row.size != m.display.size
        {
            return Err(PlanRefusal::PresentationRowDiverges(m.message_ref.clone()));
        }
    }
    Ok(())
}

// `PRESENTATION_DOMAIN_TAG` and `AGGREGATE_VIEW_DOMAIN_TAG` are at v2 because both preimages
// embed [`encode_row`], which gained three frames (`sender_status`, `sender_local`,
// `sender_domain`). A plan minted before that change and re-encoded under the new `encode_row`
// produces different bytes even under the old tag, so the bump makes that a visible domain
// change rather than a silent reinterpretation: a plan still open across the upgrade re-mints,
// and its evidence does not silently verify wrong. `SET_DOMAIN_TAG`, `STATE_DOMAIN_TAG`,
// `SHAPE_DOMAIN_TAG` and `SAMPLE_SEED_DOMAIN_TAG` encode no `PresentationRow` field and stay v1.
pub const PRESENTATION_DOMAIN_TAG: &[u8] = b"photon.triage.presentation.v2";
pub const SET_DOMAIN_TAG: &[u8] = b"photon.triage.set.v1";
pub const STATE_DOMAIN_TAG: &[u8] = b"photon.triage.state.v1";
pub const SHAPE_DOMAIN_TAG: &[u8] = b"photon.triage.shape.v1";
pub const AGGREGATE_VIEW_DOMAIN_TAG: &[u8] = b"photon.triage.aggregate-view.v2";
pub const SAMPLE_SEED_DOMAIN_TAG: &[u8] = b"photon.triage.sample-seed.v1";

fn push_frame(out: &mut Vec<u8>, field: &[u8]) -> Result<(), CommitmentError> {
    out.extend_from_slice(&frame_prefix(field.len())?);
    out.extend_from_slice(field);
    Ok(())
}

fn size_text(size: Option<u64>) -> String {
    match size {
        Some(n) => n.to_string(),
        None => "unavailable".to_string(),
    }
}

/// The header and summary bytes, shared by the full presentation and the aggregate view.
fn encode_header_and_summary(out: &mut Vec<u8>, p: &PlanPresentation) -> Result<(), CommitmentError> {
    let h = &p.header;
    push_frame(out, h.account.as_bytes())?;
    push_frame(out, h.verb.as_token().as_bytes())?;
    push_frame(out, h.tier.as_bytes())?;
    push_frame(out, h.count.to_string().as_bytes())?;
    push_frame(out, if h.backup_coverage { b"coverage:on" } else { b"coverage:off" })?;
    push_frame(out, h.warning.as_deref().unwrap_or("").as_bytes())?;
    let s = &p.summary;
    push_frame(out, s.count.to_string().as_bytes())?;
    push_frame(out, s.sender_domains.len().to_string().as_bytes())?;
    for (domain, n) in &s.sender_domains {
        push_frame(out, domain.as_bytes())?;
        push_frame(out, n.to_string().as_bytes())?;
    }
    // The counts the review says out loud are in the committed bytes, like every other summary
    // field: a changed domain, or a sender moved between parsed, unavailable, malformed and
    // unsupported, changes the presentation (and the shape and aggregate views).
    push_frame(out, s.sender_domain_unavailable.to_string().as_bytes())?;
    push_frame(out, s.sender_header_malformed.to_string().as_bytes())?;
    push_frame(out, s.sender_header_unsupported.to_string().as_bytes())?;
    push_frame(out, s.date_min.as_bytes())?;
    push_frame(out, s.date_max.as_bytes())?;
    push_frame(out, size_text(s.total_size).as_bytes())?;
    Ok(())
}

fn encode_row(out: &mut Vec<u8>, r: &PresentationRow) -> Result<(), CommitmentError> {
    push_frame(out, r.message_ref.as_bytes())?;
    push_frame(out, r.sender.as_bytes())?;
    // The address half gets its own frame: the digest binds it as it binds every other
    // displayed field, never as a substring of `sender`.
    push_frame(out, r.sender_address.as_bytes())?;
    // `sender_status`, `sender_local` and `sender_domain` are framed like every other displayed
    // field. Leaving them out of the digest would let a plan minted with one status/local/domain
    // be rendered with a forged one (of the same `sender_address` text) and still verify.
    push_frame(out, r.sender_status.as_bytes())?;
    push_frame(out, r.sender_local.as_bytes())?;
    push_frame(out, r.sender_domain.as_bytes())?;
    push_frame(out, r.subject.as_bytes())?;
    push_frame(out, r.date.as_bytes())?;
    push_frame(out, size_text(r.size).as_bytes())
}

/// The canonical presentation bytes, following `attempt.rs`'s encoding discipline: domain tag,
/// u32be row count, header and summary frames, rows in canonical order (each row's fields
/// framed), then the set and state digests. Text-only, deterministic, injective by framing.
pub fn encode_presentation(p: &PlanPresentation, set_digest_hex: &str, state_digest_hex: &str) -> Result<Vec<u8>, CommitmentError> {
    let mut out = Vec::new();
    out.extend_from_slice(PRESENTATION_DOMAIN_TAG);
    out.extend_from_slice(&frame_prefix(p.rows.len())?);
    encode_header_and_summary(&mut out, p)?;
    for r in &p.rows {
        encode_row(&mut out, r)?;
    }
    push_frame(&mut out, set_digest_hex.as_bytes())?;
    push_frame(&mut out, state_digest_hex.as_bytes())?;
    Ok(out)
}

fn domain(source_kind: &str, key_ref: &CommitmentKeyRef) -> Result<CommitmentDomain, CommitmentError> {
    CommitmentDomain::new(source_kind, CommitmentDisposition::EnvelopeCommitmentOnly, key_ref.clone())
}
pub fn presentation_domain(key_ref: &CommitmentKeyRef) -> Result<CommitmentDomain, CommitmentError> {
    domain("photon.triage.presentation", key_ref)
}
fn set_domain(key_ref: &CommitmentKeyRef) -> Result<CommitmentDomain, CommitmentError> {
    domain("photon.triage.set", key_ref)
}
fn state_domain(key_ref: &CommitmentKeyRef) -> Result<CommitmentDomain, CommitmentError> {
    domain("photon.triage.state", key_ref)
}
fn shape_domain(key_ref: &CommitmentKeyRef) -> Result<CommitmentDomain, CommitmentError> {
    domain("photon.triage.shape", key_ref)
}
fn aggregate_view_domain(key_ref: &CommitmentKeyRef) -> Result<CommitmentDomain, CommitmentError> {
    domain("photon.triage.aggregate_view", key_ref)
}
fn sample_seed_domain(key_ref: &CommitmentKeyRef) -> Result<CommitmentDomain, CommitmentError> {
    domain("photon.triage.sample_seed", key_ref)
}

/// `set_digest` content: domain-bound over account, principal, verb and the sorted member refs.
pub fn encode_set(account: &str, principal: &str, verb: PlanVerb, members: &[PlanMember]) -> Result<Vec<u8>, CommitmentError> {
    let mut out = Vec::new();
    out.extend_from_slice(SET_DOMAIN_TAG);
    push_frame(&mut out, account.as_bytes())?;
    push_frame(&mut out, principal.as_bytes())?;
    push_frame(&mut out, verb.as_token().as_bytes())?;
    out.extend_from_slice(&frame_prefix(members.len())?);
    for m in members {
        push_frame(&mut out, m.message_ref.as_bytes())?;
    }
    Ok(out)
}

fn atom_map_json(map: &BTreeMap<String, bool>) -> String {
    // `BTreeMap` serializes with sorted keys, so there is one spelling.
    serde_json::to_string(map).expect("BTreeMap<String,bool> serializes")
}

/// `state_digest` content: over each member's (ref, observed closure state, forward target) in
/// canonical order.
pub fn encode_state(members: &[PlanMember]) -> Result<Vec<u8>, CommitmentError> {
    let mut out = Vec::new();
    out.extend_from_slice(STATE_DOMAIN_TAG);
    out.extend_from_slice(&frame_prefix(members.len())?);
    for m in members {
        push_frame(&mut out, m.message_ref.as_bytes())?;
        push_frame(&mut out, atom_map_json(&m.observed_state).as_bytes())?;
        push_frame(&mut out, atom_map_json(&m.forward_target).as_bytes())?;
    }
    Ok(out)
}

/// `shape_digest` content: the header and summary only (the aggregate shape the summary mode shows).
pub fn encode_shape(p: &PlanPresentation) -> Result<Vec<u8>, CommitmentError> {
    let mut out = Vec::new();
    out.extend_from_slice(SHAPE_DOMAIN_TAG);
    encode_header_and_summary(&mut out, p)?;
    Ok(out)
}

/// The keyed digests a plan carries, with the profiles (randomizers) stored beside them.
///
/// There is one randomizer per durable commitment (see the `crate::commitment` docs). The
/// aggregate-view commitment is a durable member of the family (`ApprovalEvidence.view_digest`
/// in Aggregate mode), so it carries its own randomizer, minted here and stored as
/// `aggregate_view_profile`, never the presentation's reused under a second domain. The
/// PerMember `view_digest` is not a new commitment: it is the presentation commitment
/// re-derived over the rendered bytes, so it uses the presentation's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanDigests {
    pub set: CommitmentTag,
    pub set_profile: CommitmentProfile,
    pub state: CommitmentTag,
    pub state_profile: CommitmentProfile,
    pub presentation: CommitmentTag,
    pub presentation_profile: CommitmentProfile,
    pub shape: CommitmentTag,
    pub shape_profile: CommitmentProfile,
    /// The sample seed: a commitment over `{tag, presentation_digest}`; its randomizer is stored
    /// so re-derivation is exact.
    pub sample_seed: CommitmentTag,
    pub sample_seed_profile: CommitmentProfile,
    /// The aggregate-view commitment's profile, minted at plan freeze. Its tag is not computed
    /// here: it is what Aggregate evidence's `view_digest` must equal, re-derived at validation
    /// over the canonical summary and the derived sample under this stored randomizer.
    pub aggregate_view_profile: CommitmentProfile,
    /// The key reference every digest above was minted under (stored on the plan row).
    pub key_ref: CommitmentKeyRef,
    /// The presentation the digests were computed over: the canonical view.
    pub presentation_view: PlanPresentation,
}

impl PlanDigests {
    /// Mint every digest for a plan, in dependency order: set and state, then the presentation
    /// (which binds both), then shape, then the sample seed (which binds the presentation), then
    /// the aggregate-view randomizer. One call, so no caller can mint a presentation over foreign
    /// set/state digests. The header must name the same account and verb the set digest binds
    /// (otherwise the human would read one red effect while the set commits another), and the
    /// tier [`PLAN_TIER`] (`PlanRefusal::HeaderDiverges`).
    pub fn mint(
        key: &CommitmentKey,
        key_ref: &CommitmentKeyRef,
        account: &str,
        principal: &str,
        verb: PlanVerb,
        members: &[PlanMember],
        header: &PresentationHeader,
    ) -> Result<Self, PlanRefusal> {
        if header.account != account {
            return Err(PlanRefusal::HeaderDiverges(HeaderField::Account));
        }
        if header.verb != verb {
            return Err(PlanRefusal::HeaderDiverges(HeaderField::Verb));
        }
        if header.tier != PLAN_TIER {
            return Err(PlanRefusal::HeaderDiverges(HeaderField::Tier));
        }
        let (set, set_profile) = commit_over(key, &set_domain(key_ref)?, &encode_set(account, principal, verb, members)?)?;
        let (state, state_profile) = commit_over(key, &state_domain(key_ref)?, &encode_state(members)?)?;
        let presentation_view = derive_presentation(header, members)?;
        validate_presentation(&presentation_view, members)?;
        let (presentation, presentation_profile) = commit_over(key, &presentation_domain(key_ref)?, &encode_presentation(&presentation_view, &set.hex(), &state.hex())?)?;
        let (shape, shape_profile) = commit_over(key, &shape_domain(key_ref)?, &encode_shape(&presentation_view)?)?;
        let mut seed_content = Vec::new();
        seed_content.extend_from_slice(SAMPLE_SEED_DOMAIN_TAG);
        push_frame(&mut seed_content, presentation.hex().as_bytes())?;
        let (sample_seed, sample_seed_profile) = commit_over(key, &sample_seed_domain(key_ref)?, &seed_content)?;
        let aggregate_view_profile = CommitmentProfile::for_commitment(&aggregate_view_domain(key_ref)?, &mint_randomizer()?);
        Ok(Self {
            set,
            set_profile,
            state,
            state_profile,
            presentation,
            presentation_profile,
            shape,
            shape_profile,
            sample_seed,
            sample_seed_profile,
            aggregate_view_profile,
            key_ref: key_ref.clone(),
            presentation_view,
        })
    }

    /// Re-derive the presentation commitment over given bytes with the stored randomizer, the
    /// primitive for mode-scoped view equality: equal tags mean equal bytes under one key,
    /// domain and randomizer.
    fn presentation_tag_over(&self, key: &CommitmentKey, key_ref: &CommitmentKeyRef, bytes: &[u8]) -> Result<CommitmentTag, PlanRefusal> {
        let r = Randomizer::from_hex(&self.presentation_profile.randomizer)?;
        Ok(compute_tag(key, &presentation_domain(key_ref)?, &r, bytes)?)
    }
}

/// What the renderer says it showed, handed back at approval. The engine re-encodes it and
/// commits it under the plan's own stored randomizer, so `view_digest == presentation_digest`
/// exactly when the rendered text equals the canonical rows (a display-substitution check).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenderedView {
    FullList(PlanPresentation),
    Aggregate(AggregateRender),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregateRender {
    pub header: PresentationHeader,
    pub summary: PresentationSummary,
    pub sample_k: u32,
    pub sample_rows: Vec<PresentationRow>,
}

/// The aggregate-view commitment bytes: `{mode tag, header + summary, shape_digest, sample_k,
/// the sampled rows by identity, presentation_digest}`.
pub fn encode_aggregate_view(d: &PlanDigests, agg: &AggregateRender) -> Result<Vec<u8>, CommitmentError> {
    let mut out = Vec::new();
    out.extend_from_slice(AGGREGATE_VIEW_DOMAIN_TAG);
    push_frame(&mut out, b"mode:aggregate")?;
    let as_presentation = PlanPresentation { header: agg.header.clone(), summary: agg.summary.clone(), rows: Vec::new() };
    encode_header_and_summary(&mut out, &as_presentation)?;
    push_frame(&mut out, d.shape.hex().as_bytes())?;
    push_frame(&mut out, agg.sample_k.to_string().as_bytes())?;
    out.extend_from_slice(&frame_prefix(agg.sample_rows.len())?);
    for r in &agg.sample_rows {
        encode_row(&mut out, r)?;
    }
    push_frame(&mut out, d.presentation.hex().as_bytes())?;
    Ok(out)
}

/// The aggregate-view commitment under the plan's stored aggregate-view randomizer (see
/// [`PlanDigests`]), through the aggregate-view domain: re-derivable by the key holder, and
/// distinct from the presentation commitment by domain, randomizer and content tag.
pub fn aggregate_view_commitment(key: &CommitmentKey, key_ref: &CommitmentKeyRef, d: &PlanDigests, agg: &AggregateRender) -> Result<CommitmentTag, PlanRefusal> {
    let r = Randomizer::from_hex(&d.aggregate_view_profile.randomizer)?;
    Ok(compute_tag(key, &aggregate_view_domain(key_ref)?, &r, &encode_aggregate_view(d, agg)?)?)
}

/// The mode-scoped view commitment, which `ApprovalEvidence.view_digest` must equal: for
/// PerMember, the presentation commitment over the rendered rows; for Aggregate, the
/// aggregate-view commitment over the rendered summary and sample.
pub fn view_commitment(key: &CommitmentKey, key_ref: &CommitmentKeyRef, d: &PlanDigests, rendered: &RenderedView) -> Result<CommitmentTag, PlanRefusal> {
    match rendered {
        RenderedView::FullList(p) => d.presentation_tag_over(key, key_ref, &encode_presentation(p, &d.set.hex(), &d.state.hex())?),
        RenderedView::Aggregate(agg) => aggregate_view_commitment(key, key_ref, d, agg),
    }
}

fn sample_score_domain(key_ref: &CommitmentKeyRef) -> Result<CommitmentDomain, CommitmentError> {
    domain("photon.triage.sample_score", key_ref)
}

/// Per-member score: the leading 8 bytes (big-endian u64) of the commitment primitive
/// (`compute_tag`, through `crate::commitment`; this module hand-rolls no MAC) over
/// `frame(seed tag hex) ‖ frame(message_ref)`, through the `photon.triage.sample_score` domain,
/// with the sample seed's stored randomizer. It is a keyed, uniform, deterministic score with
/// no RNG state, following the reference implementation's `routineScoreFraction`, and
/// re-derivable only by the key holder. A score is never persisted, so it is not a durable
/// commitment and mints no randomizer of its own. This adds a domain under the existing
/// `compute_tag` site, not a new digest site (see `docs/crypto-inventory.md`).
fn member_score(key: &CommitmentKey, d: &PlanDigests, message_ref: &str) -> Result<u64, PlanRefusal> {
    let r = Randomizer::from_hex(&d.sample_seed_profile.randomizer)?;
    let mut content = Vec::new();
    push_frame(&mut content, d.sample_seed.hex().as_bytes())?;
    push_frame(&mut content, message_ref.as_bytes())?;
    let tag = compute_tag(key, &sample_score_domain(&d.key_ref)?, &r, &content)?;
    let mut lead = [0u8; 8];
    lead.copy_from_slice(&tag.0[..8]);
    Ok(u64::from_be_bytes(lead))
}

/// The derived sample: the `k` members with the lowest keyed scores, ties broken by ref bytes,
/// returned in ascending-score order (the reference implementation's score-then-take-lowest).
/// Uniform over the canonical list, deterministic, independent of input order, with no free
/// inputs. `k == 0` is refused, never an empty sample. `k >= member_count` degenerates to every
/// member, in canonical order.
pub fn derive_sample(key: &CommitmentKey, d: &PlanDigests, members: &[PlanMember], k: u32) -> Result<Vec<String>, PlanRefusal> {
    if k == 0 {
        return Err(PlanRefusal::ConfiguredKZero);
    }
    let k = (k as usize).min(members.len());
    if k == members.len() {
        // Degenerate to the full member list in canonical order.
        return Ok(members.iter().map(|m| m.message_ref.clone()).collect());
    }
    let mut scored: Vec<(u64, &str)> = members
        .iter()
        .map(|m| member_score(key, d, &m.message_ref).map(|s| (s, m.message_ref.as_str())))
        .collect::<Result<_, _>>()?;
    scored.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.as_bytes().cmp(b.1.as_bytes())));
    Ok(scored.into_iter().take(k).map(|(_, r)| r.to_string()).collect())
}

/// Admission re-derives and refuses on count mismatch, duplicate, non-member, or journaled
/// differing from derived. This is a correctness check (the journal must be mechanically
/// honest), not a security wall.
pub fn verify_sample(key: &CommitmentKey, d: &PlanDigests, members: &[PlanMember], k: u32, journaled: &[String]) -> Result<(), PlanRefusal> {
    if k == 0 {
        return Err(PlanRefusal::ConfiguredKZero);
    }
    if journaled.len() != k as usize && !(k as usize >= members.len() && journaled.len() == members.len()) {
        return Err(PlanRefusal::SampleMismatch(format!("count {} != k {k}", journaled.len())));
    }
    let distinct: BTreeSet<&String> = journaled.iter().collect();
    if distinct.len() != journaled.len() {
        return Err(PlanRefusal::SampleMismatch("duplicate member in sample".into()));
    }
    for r in journaled {
        if !members.iter().any(|m| &m.message_ref == r) {
            return Err(PlanRefusal::SampleMismatch(format!("'{r}' is not a plan member")));
        }
    }
    let derived = derive_sample(key, d, members, k)?;
    if derived != journaled {
        return Err(PlanRefusal::SampleMismatch("journaled sample differs from the derived one".into()));
    }
    Ok(())
}

/// An opaque plan identity: 32 lowercase hex, minted from OS entropy at mint, never
/// content-derived. Plan identity is what makes plan A's approval never admit plan B's child.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PlanId(pub String);

impl PlanId {
    /// Through `crate::commitment::mint_randomizer`, the crate's one OS-entropy source (no
    /// fallback: `EntropyUnavailable` refuses).
    pub fn mint() -> Result<Self, CommitmentError> {
        Ok(PlanId(mint_randomizer()?.hex()))
    }
}

/// The immutable plan. Every field the approval-binding contract lists as bound is a column;
/// the digests bind the members and their frozen display; the lane, mode and coverage
/// generation are frozen at mint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TriagePlan {
    pub plan_id: PlanId,
    pub account: String,
    pub provider_principal: String,
    pub grant_generation: u64,
    pub control_epoch: i64,
    pub verb: PlanVerb,
    pub rationale: Option<String>,
    pub minted_at: String,
    pub expires_at: String,
    pub members: Vec<PlanMember>,
    pub admission_lane: AdmissionLane,
    pub approval_mode: ApprovalMode,
    pub coverage_generation: u64,
    pub backups_on: bool,
    /// The bypass-lane notice: the verb's uncovered warning ([`PlanVerb::uncovered_warning`]),
    /// frozen at mint exactly when the plan froze the `Bypassed` lane under `backups: off`. It is
    /// the durable record, written before any child can reach the send check, of the warning
    /// that lane shows no screen for (the bypass waives the screen, never the notice). Showing
    /// it on the operator-visible surface is the shell's job ([`MintedPlan::bypass_notice`]
    /// carries it); this field does not show anything. `None` on every other plan. A bypass-lane
    /// plan under `backups: off` that carries `None` (a row minted before the column existed) is
    /// refused at the send check by name ([`PlanSendRefusal::BypassNoticeAbsent`]). Outside
    /// every digest: the notice is a bypass-lane admission check, not an approval-bound input.
    pub bypass_notice: Option<String>,
    pub digests: PlanDigests,
    pub key_ref: CommitmentKeyRef,
}

impl TriagePlan {
    pub fn count(&self) -> u32 {
        self.members.len() as u32
    }
    /// Every plan verb is red-tier (`PlanVerb::action`'s `risk_tier`; asserted per verb in tests).
    pub fn tier(&self) -> crate::RiskTier {
        crate::RiskTier::Red
    }
    pub fn member(&self, message_ref: &str) -> Option<&PlanMember> {
        self.members.iter().find(|m| m.message_ref == message_ref)
    }

    /// The plan against itself: every field the plan carries twice must agree with its other
    /// copy, and the frozen lane with the frozen mode. No key is needed (it compares the plan's
    /// own fields, never a tag against content). Called first by [`validate_evidence`] and by the
    /// store half's read-back, where a failing stored row is a store error, never a plan. The
    /// rules, each named in the refusal:
    /// - the member list matches the header's `count`, and the presentation rows are the members'
    ///   own frozen display ([`validate_presentation`]);
    /// - `verb`, `account`, `key_ref` and `backups_on` equal the header's verb, account, the
    ///   digests' key reference and `backup_coverage`; the header's tier is [`PLAN_TIER`];
    /// - lane and mode: `PerMember` requires `FullList`, `Aggregate` requires `SummarySample`,
    ///   `Bypassed` allows either (it has no screen, so its frozen mode is inert);
    /// - `SummarySample`'s `effective_k` is [`effective_k`] recomputed over `configured_k` and the
    ///   member count (`configured_k` of 0 refuses as `ConfiguredKZero`);
    /// - `bypass_notice`, when present, is on a `Bypassed` plan with `backups_on == false` and is
    ///   the verb's [`PlanVerb::uncovered_warning`]. Its absence on such a plan is the send check's
    ///   refusal ([`PlanSendRefusal::BypassNoticeAbsent`]), not a shape error, since a row minted
    ///   by an earlier build reads back without it.
    ///
    /// `coverage_generation` and `grant_generation` have no second copy to agree with: the send
    /// check (`IntentLog::authorize_send`'s plan arm) compares `coverage_generation` with the
    /// backups knob's head generation and takes the grant verdict from its caller
    /// ([`PlanBinding`]).
    pub fn validate_shape(&self) -> Result<(), PlanRefusal> {
        let header = &self.digests.presentation_view.header;
        if self.members.len() != header.count as usize {
            return Err(PlanRefusal::PlanShape(PlanShapeRule::MemberCountIsNotHeaderCount));
        }
        validate_presentation(&self.digests.presentation_view, &self.members)?;
        if self.verb != header.verb {
            return Err(PlanRefusal::PlanShape(PlanShapeRule::VerbIsNotHeaderVerb));
        }
        if self.account != header.account {
            return Err(PlanRefusal::PlanShape(PlanShapeRule::AccountIsNotHeaderAccount));
        }
        if header.tier != PLAN_TIER {
            return Err(PlanRefusal::PlanShape(PlanShapeRule::HeaderTierIsNotRed));
        }
        if self.key_ref != self.digests.key_ref {
            return Err(PlanRefusal::PlanShape(PlanShapeRule::KeyRefIsNotDigestsKeyRef));
        }
        if self.backups_on != header.backup_coverage {
            return Err(PlanRefusal::PlanShape(PlanShapeRule::BackupsOnIsNotHeaderCoverage));
        }
        match (self.admission_lane, self.approval_mode) {
            (AdmissionLane::PerMember, ApprovalMode::SummarySample { .. }) => {
                return Err(PlanRefusal::PlanShape(PlanShapeRule::PerMemberLaneRequiresFullList));
            }
            (AdmissionLane::Aggregate, ApprovalMode::FullList) => {
                return Err(PlanRefusal::PlanShape(PlanShapeRule::AggregateLaneRequiresSummarySample));
            }
            _ => {}
        }
        if let ApprovalMode::SummarySample { configured_k, effective_k: frozen } = self.approval_mode {
            if frozen != effective_k(configured_k, self.members.len())? {
                return Err(PlanRefusal::PlanShape(PlanShapeRule::EffectiveKIsNotMin));
            }
        }
        if let Some(notice) = &self.bypass_notice {
            if !matches!(self.admission_lane, AdmissionLane::Bypassed { .. }) || self.backups_on {
                return Err(PlanRefusal::PlanShape(PlanShapeRule::BypassNoticeOutsideAnUncoveredBypassPlan));
            }
            if notice != self.verb.uncovered_warning() {
                return Err(PlanRefusal::PlanShape(PlanShapeRule::BypassNoticeIsNotTheVerbWarning));
            }
        }
        Ok(())
    }

    /// The notice a plan with this lane and coverage freezes at mint: the verb's uncovered
    /// warning exactly when the lane is `Bypassed` and backups are off, `None` otherwise. The
    /// store's single assembler (`assemble_plan`) calls it.
    pub fn bypass_notice_for(verb: PlanVerb, lane: AdmissionLane, backups_on: bool) -> Option<String> {
        (matches!(lane, AdmissionLane::Bypassed { .. }) && !backups_on).then(|| verb.uncovered_warning().to_string())
    }
}

/// How the approver comprehended the plan: the journal says "approved by summary + sample of
/// k", never "N approvals"; `Bypassed` says "executed under red-bypass configuration, no
/// approval screen".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Comprehension {
    PerMember,
    Aggregate { shape_digest: CommitmentTag, sample_k: u32, sample_members: Vec<String> },
    Bypassed { bypass_config_generation: u64 },
}

impl Comprehension {
    pub const TOKENS: [&'static str; 3] = ["per_member", "aggregate", "bypassed"];
    pub fn as_token(&self) -> &'static str {
        match self {
            Comprehension::PerMember => "per_member",
            Comprehension::Aggregate { .. } => "aggregate",
            Comprehension::Bypassed { .. } => "bypassed",
        }
    }
}

/// The only decision an evidence row can carry. A refusal is not evidence; it is its absence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Approved,
}

impl Decision {
    /// The durable `approval_evidence.decision` token, guarded against the DDL CHECK.
    pub fn as_token(self) -> &'static str {
        match self {
            Decision::Approved => "approved",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalEvidence {
    pub plan_id: PlanId,
    pub approver: String,
    pub approved_at: String,
    pub view_digest: CommitmentTag,
    pub comprehension: Comprehension,
    pub decision: Decision,
}

/// The bound half of the approval-binding contract: evidence is minted against one plan
/// instance; the frozen lane must match; screen lanes require an approver identity and the
/// mode-scoped view equality; Aggregate additionally checks k and shape and re-derives the
/// sample; Bypassed requires the bound bypass generation to equal the plan's and the current one
/// (`current_bypass_generation`). The re-verified half (expiry, grant, epoch, membership,
/// coverage, snapshot, state) belongs to the send-authorization transaction, never here.
///
/// The plan's own shape is checked first ([`TriagePlan::validate_shape`]). Tag comparisons here
/// are plain equality: only in-process code reaches this function, and code already running on
/// the user's machine with the user's privileges is not defended against, so constant-time
/// comparison is not claimed as a control (`verify_tag` stays the constant-time primitive for
/// provider-facing checks).
pub fn validate_evidence(key: &CommitmentKey, plan: &TriagePlan, evidence: &ApprovalEvidence, current_bypass_generation: u64) -> Result<(), PlanRefusal> {
    plan.validate_shape()?;
    if evidence.plan_id != plan.plan_id {
        return Err(PlanRefusal::PlanIdMismatch { plan: plan.plan_id.clone(), evidence: evidence.plan_id.clone() });
    }
    // The decision is positive by type: `Decision` has one variant, and this exhaustive match
    // makes a future non-approving variant a compile error here rather than a silent admit.
    match evidence.decision {
        Decision::Approved => {}
    }
    let screen_lane = matches!(plan.admission_lane, AdmissionLane::PerMember | AdmissionLane::Aggregate);
    if screen_lane && evidence.approver.trim().is_empty() {
        return Err(PlanRefusal::ApproverMissing);
    }
    match (&plan.admission_lane, &evidence.comprehension) {
        (AdmissionLane::PerMember, Comprehension::PerMember) => {
            // PerMember: `view_digest == presentation_digest`.
            if evidence.view_digest != plan.digests.presentation {
                return Err(PlanRefusal::ViewMismatch);
            }
            Ok(())
        }
        (AdmissionLane::Aggregate, Comprehension::Aggregate { shape_digest, sample_k, sample_members }) => {
            let ApprovalMode::SummarySample { effective_k, .. } = plan.approval_mode else {
                return Err(PlanRefusal::LaneMismatch { plan: plan.admission_lane, evidence: evidence.comprehension.clone() });
            };
            if *sample_k != effective_k {
                return Err(PlanRefusal::SampleKMismatch { plan: effective_k, evidence: *sample_k });
            }
            if *shape_digest != plan.digests.shape {
                return Err(PlanRefusal::ViewMismatch);
            }
            verify_sample(key, &plan.digests, &plan.members, effective_k, sample_members)?;
            // The aggregate-view commitment over the canonical summary and the derived sample
            // rows (every sampled ref is a member: `verify_sample` refused any other).
            let sample_rows: Vec<PresentationRow> = sample_members
                .iter()
                .filter_map(|r| plan.digests.presentation_view.rows.iter().find(|row| &row.message_ref == r).cloned())
                .collect();
            let agg = AggregateRender { header: plan.digests.presentation_view.header.clone(), summary: plan.digests.presentation_view.summary.clone(), sample_k: *sample_k, sample_rows };
            let expected = aggregate_view_commitment(key, &plan.key_ref, &plan.digests, &agg)?;
            if evidence.view_digest != expected {
                return Err(PlanRefusal::ViewMismatch);
            }
            Ok(())
        }
        (AdmissionLane::Bypassed { bypass_config_generation }, Comprehension::Bypassed { bypass_config_generation: bound }) => {
            if bound != bypass_config_generation {
                return Err(PlanRefusal::LaneMismatch { plan: plan.admission_lane, evidence: evidence.comprehension.clone() });
            }
            if *bound != current_bypass_generation {
                return Err(PlanRefusal::BypassGenerationMismatch { plan: *bound, current: current_bypass_generation });
            }
            // No screen, so no rendered view: the evidence binds the plan's own presentation
            // digest (the store half sets it so); any other value is a view this plan never had.
            if evidence.view_digest != plan.digests.presentation {
                return Err(PlanRefusal::ViewMismatch);
            }
            Ok(())
        }
        (lane, comprehension) => Err(PlanRefusal::LaneMismatch { plan: *lane, evidence: comprehension.clone() }),
    }
}

// The store half's vocabulary. `IntentLog::mint_plan` / `plan` / `record_approval` / `approval`
// persist and read through these; everything here is still pure.

/// What a caller hands the store to mint a plan: member identities only. The store freezes
/// display and state from its own rows, never from the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanSpec {
    pub account: String,
    pub provider_principal: String,
    pub grant_generation: u64,
    pub verb: PlanVerb,
    pub member_refs: Vec<String>,
    pub rationale: Option<String>,
    /// Seconds from `minted_at` (the sticky clock) to `expires_at`. Zero refuses
    /// ([`PlanStoreError::TtlZero`]): a plan born expired is not a plan. A TTL whose expiry the
    /// canonical clock cannot spell refuses ([`PlanStoreError::TtlOutOfRange`]).
    pub ttl_seconds: u64,
}

impl PlanSpec {
    #[doc(hidden)]
    pub fn for_test(account: &str) -> Self {
        Self { account: account.into(), provider_principal: "me@e".into(), grant_generation: 1, verb: PlanVerb::Trash, member_refs: vec![], rationale: None, ttl_seconds: 3600 }
    }
}

/// What mint returns: the identity, the canonical presentation to render, and its digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintedPlan {
    pub plan_id: PlanId,
    pub presentation: PlanPresentation,
    pub presentation_digest: CommitmentTag,
    pub admission_lane: AdmissionLane,
    /// `Some(k)` exactly when the plan froze the summary-and-sample mode.
    pub effective_k: Option<u32>,
    /// The plan's frozen bypass-lane notice ([`TriagePlan::bypass_notice`]), for the surface to
    /// show as a non-blocking line; `None` unless the plan froze `Bypassed` under `backups: off`.
    pub bypass_notice: Option<String>,
}

impl MintedPlan {
    /// The caller's view of a freshly minted plan: one derivation, shared by both stores.
    pub fn of(plan: &TriagePlan) -> Self {
        MintedPlan {
            plan_id: plan.plan_id.clone(),
            presentation: plan.digests.presentation_view.clone(),
            presentation_digest: plan.digests.presentation,
            admission_lane: plan.admission_lane,
            effective_k: match plan.approval_mode {
                ApprovalMode::FullList => None,
                ApprovalMode::SummarySample { effective_k, .. } => Some(effective_k),
            },
            bypass_notice: plan.bypass_notice.clone(),
        }
    }
}

/// Every refusal the plan store answers. Named, never a bare "no".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanStoreError {
    /// The pure core refused (a [`PlanRefusal`], including a commitment failure).
    Refused(PlanRefusal),
    /// A requested member has no header row or no placement row for the account in this store;
    /// the store freezes only what it holds. Nothing is written.
    UnknownMember(String),
    PlanNotFound(PlanId),
    /// The plan already carries its approval — evidence is write-once per plan.
    AlreadyApproved,
    /// A knob act in force cannot be read (its strict reader refused). Nothing is minted.
    Knob(String),
    /// `ttl_seconds == 0`.
    TtlZero,
    /// `minted_at + ttl_seconds` is past what the RFC-3339 clock can spell canonically.
    TtlOutOfRange,
    /// The approval path's epoch check (as in `start_episode`): the store's `control_epoch` has
    /// moved since the plan was minted. Nothing is written.
    EpochMismatch { plan: i64, current: i64 },
    /// The approval path's expiry check (as in `start_episode`): `expires_at <= effective_now`
    /// on the sticky clock. The latch advance commits; nothing else is written.
    Expired { expires_at: String, effective_now: String },
    /// The store itself failed (I/O, a row that does not read back).
    Store(String),
}

impl From<PlanRefusal> for PlanStoreError {
    fn from(r: PlanRefusal) -> Self {
        PlanStoreError::Refused(r)
    }
}
impl From<CommitmentError> for PlanStoreError {
    fn from(e: CommitmentError) -> Self {
        PlanStoreError::Refused(PlanRefusal::Commitment(e))
    }
}

impl std::fmt::Display for PlanStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PlanStoreError::Refused(r) => write!(f, "plan refused: {r:?}"),
            PlanStoreError::UnknownMember(r) => write!(f, "plan refused: member '{r}' has no header and placement row in this store"),
            PlanStoreError::PlanNotFound(id) => write!(f, "no plan '{}'", id.0),
            PlanStoreError::AlreadyApproved => write!(f, "the plan already carries its approval (write-once)"),
            PlanStoreError::Knob(why) => write!(f, "plan refused: a knob in force is unreadable: {why}"),
            PlanStoreError::TtlZero => write!(f, "plan refused: ttl_seconds must be >= 1"),
            PlanStoreError::TtlOutOfRange => write!(f, "plan refused: minted_at + ttl_seconds is not a canonical RFC-3339 instant"),
            PlanStoreError::EpochMismatch { plan, current } => write!(f, "plan refused: minted under control epoch {plan}, the store is at {current}"),
            PlanStoreError::Expired { expires_at, effective_now } => write!(f, "plan refused: it expired at {expires_at} (effective now {effective_now})"),
            PlanStoreError::Store(why) => write!(f, "plan store: {why}"),
        }
    }
}
impl std::error::Error for PlanStoreError {}

/// The digest family as a store row holds it: each tag's lowercase hex beside its randomizer's
/// hex, plus the aggregate view's randomizer (that view's tag is committed at approval; see
/// [`PlanDigests`]). The profiles are not stored: [`PlanDigests::from_stored`] re-derives each
/// from its domain, the key reference and the randomizer, the fields the profile is made of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredDigests {
    pub set: String,
    pub set_randomizer: String,
    pub state: String,
    pub state_randomizer: String,
    pub presentation: String,
    pub presentation_randomizer: String,
    pub shape: String,
    pub shape_randomizer: String,
    pub sample_seed: String,
    pub sample_seed_randomizer: String,
    pub aggregate_view_randomizer: String,
}

impl PlanDigests {
    /// The row form, the one spelling [`PlanDigests::from_stored`] reads back.
    pub fn to_stored(&self) -> StoredDigests {
        StoredDigests {
            set: self.set.hex(),
            set_randomizer: self.set_profile.randomizer.clone(),
            state: self.state.hex(),
            state_randomizer: self.state_profile.randomizer.clone(),
            presentation: self.presentation.hex(),
            presentation_randomizer: self.presentation_profile.randomizer.clone(),
            shape: self.shape.hex(),
            shape_randomizer: self.shape_profile.randomizer.clone(),
            sample_seed: self.sample_seed.hex(),
            sample_seed_randomizer: self.sample_seed_profile.randomizer.clone(),
            aggregate_view_randomizer: self.aggregate_view_profile.randomizer.clone(),
        }
    }

    /// Rebuild the family from a stored row: every tag and randomizer parsed strictly (lowercase
    /// hex, exact length, via `CommitmentTag::from_hex` / `Randomizer::from_hex`), every profile
    /// re-derived through its own domain under `key_ref`, and the presentation re-derived from
    /// the stored header fields and members ([`derive_presentation`], deterministic, so the same
    /// members give the bytes the digest was minted over). Nothing is re-MACed: that needs the
    /// key, and the key-holding paths re-derive at approval and send.
    pub fn from_stored(key_ref: &CommitmentKeyRef, s: &StoredDigests, header: &PresentationHeader, members: &[PlanMember]) -> Result<Self, PlanRefusal> {
        let profile = |domain: CommitmentDomain, randomizer: &str| -> Result<CommitmentProfile, PlanRefusal> { Ok(CommitmentProfile::for_commitment(&domain, &Randomizer::from_hex(randomizer)?)) };
        let presentation_view = derive_presentation(header, members)?;
        validate_presentation(&presentation_view, members)?;
        Ok(Self {
            set: CommitmentTag::from_hex(&s.set)?,
            set_profile: profile(set_domain(key_ref)?, &s.set_randomizer)?,
            state: CommitmentTag::from_hex(&s.state)?,
            state_profile: profile(state_domain(key_ref)?, &s.state_randomizer)?,
            presentation: CommitmentTag::from_hex(&s.presentation)?,
            presentation_profile: profile(presentation_domain(key_ref)?, &s.presentation_randomizer)?,
            shape: CommitmentTag::from_hex(&s.shape)?,
            shape_profile: profile(shape_domain(key_ref)?, &s.shape_randomizer)?,
            sample_seed: CommitmentTag::from_hex(&s.sample_seed)?,
            sample_seed_profile: profile(sample_seed_domain(key_ref)?, &s.sample_seed_randomizer)?,
            aggregate_view_profile: profile(aggregate_view_domain(key_ref)?, &s.aggregate_view_randomizer)?,
            key_ref: key_ref.clone(),
            presentation_view,
        })
    }
}

/// A member's atom map as the store holds it: the canonical JSON the state digest encodes
/// (`BTreeMap` order, compact).
pub fn encode_atom_map(map: &BTreeMap<String, bool>) -> String {
    atom_map_json(map)
}

/// The strict inverse of [`encode_atom_map`]: `None` unless the text is exactly the canonical
/// spelling of the map it parses to (a duplicate key, whitespace, or a reordered key is not the
/// row the mint wrote).
pub fn decode_atom_map(s: &str) -> Option<BTreeMap<String, bool>> {
    let map: BTreeMap<String, bool> = serde_json::from_str(s).ok()?;
    (atom_map_json(&map) == s).then_some(map)
}

/// A journaled sample as the store holds it: a compact JSON array of member refs, in the
/// derived (ascending-score) order.
pub fn encode_sample(members: &[String]) -> String {
    serde_json::to_string(members).expect("a Vec<String> serializes")
}

/// The strict inverse of [`encode_sample`], like [`decode_atom_map`].
pub fn decode_sample(s: &str) -> Option<Vec<String>> {
    let members: Vec<String> = serde_json::from_str(s).ok()?;
    (encode_sample(&members) == s).then_some(members)
}

// The plan child. A child is an ordinary operation whose `intents` row carries this link
// (`plan_id`, `plan_member`); `Command::plan_child` is its only constructor and both `record()`s
// run the admission arm that answers `PlanChildRefusal`.

/// The durable link from a child operation to its plan: child identity is mechanical,
/// `UNIQUE(plan_id, member)` via the partial index `idx_intents_plan_child`. On a
/// `crate::Command` it sits in a crate-private field; outside this crate, `Command::plan_child`
/// is the only way to put one on a command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanChildLink {
    pub plan_id: PlanId,
    pub member_ref: String,
}

/// The child's `logical_id` for `crate::derive_idempotency_key`: a function of
/// `(plan_id, member_ref)` alone, so one member of one plan has one key. It is not the shell's
/// session-scoped key scheme (`src-tauri` `mint_key`).
pub fn plan_child_logical_id(plan_id: &PlanId, member_ref: &str) -> String {
    format!("plan:{}|member:{member_ref}", plan_id.0)
}

/// Why `record()` refused to admit a plan child. Like `Claim::CapacityRefused`, it is an `Ok`
/// answer with no `intents` row written. These are the cheap checks the admission transaction
/// can make from durable rows; the send-admission rules (`IntentLog::authorize_send`'s plan
/// arm, [`PlanSendRefusal`]) re-verify at the send check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanChildRefusal {
    /// No `triage_plan` row has the link's `plan_id`.
    NoPlan,
    /// The plan has no `approval_evidence` row.
    NotApproved,
    /// The plan has no `execution_episode` row (`IntentLog::start_episode` was never called).
    NoEpisode,
    /// The plan's episode is not `active` (the token, as the column holds it).
    EpisodeNotActive(crate::episode::EpisodeStatusToken),
    /// The episode is active but its preflight `ready_at` marker is not set
    /// (`IntentLog::mark_ready`).
    NotReady,
    /// The link's member is not one of the plan's `plan_member` rows.
    NotAMember(String),
    /// The command's action is not the plan's verb over the linked member.
    VerbMismatch,
    /// The command's account is not the plan's account.
    AccountMismatch,
    /// The command's idempotency key is not the one [`plan_child_logical_id`] derives for
    /// `(plan, member)`: a hand-built child under another key would be a second identity for one
    /// member.
    KeyMismatch,
    /// The store's `control_epoch` has moved since the plan was minted.
    EpochMismatch { plan: i64, current: i64 },
    /// The plan's `expires_at` is at or before the sticky clock's effective now.
    Expired { expires_at: String, effective_now: String },
    /// A `plan_child` link on a verb whose tier needs no plan (`RiskTier::requires_plan` is
    /// false): refused, never silently ignored.
    NotARedVerb,
}

// The send-admission vocabulary (the approval-binding contract's re-verified half).
// `IntentLog::authorize_send` takes a `PlanBinding` beside its `CaptureBinding` and answers
// `SendAuthOutcome::PlanRefused` with a `PlanSendRefusal`; a terminal one is carried in the
// `FAILED_PRE_SEND` payload as a `crate::attempt::PlanRefusalRecord` (`PlanSendRefusal::record`)
// and rebuilt from it (`PlanSendRefusal::from_record`).

/// The bus's answer from its grant ratchet (`crate::GrantRatchet`), handed into the
/// send-authorization transaction: the one input the store does not read from its own rows
/// (the high-water lives with the credential in the shell). The store's plan arm reads it for
/// the grant row and nothing else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantVerdict {
    Admitted,
    Refused(GrantDenial),
}

/// Why the grant row refused. Content-free by type: no `String` field, so no provider principal
/// and no ratchet sentence can reach the caller or the `FAILED_PRE_SEND` record.
/// `crate::CommandBus::plan_binding` is the only place that turns the ratchet's in-process
/// [`crate::GrantRefusal`] (which carries the two principals and the ratchet's reason) into this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantDenial {
    /// The plan's grant generation is below the ratchet's high-water: a retired grant. Terminal.
    Retired { generation: u64, high_water: u64 },
    /// The plan was minted under another provider principal than the credential's. Terminal.
    PrincipalMismatch,
    /// The ratchet could not be consulted (none wired, or its high-water unreadable). That is
    /// not a verdict about the grant, so the refusal is held.
    Unavailable,
}

impl GrantDenial {
    /// The `detail.kind` token.
    pub fn token(&self) -> &'static str {
        match self {
            GrantDenial::Retired { .. } => "retired",
            GrantDenial::PrincipalMismatch => "principal_mismatch",
            GrantDenial::Unavailable => "unavailable",
        }
    }
}

/// What an `authorize_send` caller states about the operation it is authorizing, total like
/// `crate::CaptureBinding`: `Plain` for an operation whose `intents` row carries no plan link,
/// `Child` for one whose row does. The store compares the binding with the row's link columns;
/// a plan child under `Plain`, or an ordinary operation under `Child`, is a `crate::LogError`
/// returned before the plan arm writes anything.
#[derive(Debug, Clone)]
pub enum PlanBinding {
    Plain,
    /// `account_key` is the key `validate_evidence` takes: the plan account's commitment key
    /// (`crate::commitment::derive_account_key` over the bus's root key).
    Child { grant: GrantVerdict, account_key: CommitmentKey },
}

/// Every refusal the plan arm of `authorize_send` answers, one per row of the checklist
/// `plan_send_admission` runs (the first row that fails is the answer).
/// [`PlanSendRefusal::is_terminal`] splits them: a terminal refusal of a never-authorized
/// attempt writes `FAILED_PRE_SEND` (with [`PlanSendRefusal::record`]) and the operation's
/// `Failed` in the refusing transaction; a held one writes no fact and no status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanSendRefusal {
    /// The episode is `paused`: held. Nothing writes `paused` yet.
    EpisodeHeld(crate::episode::EpisodeStatusToken),
    /// The episode is `cancelled`, `completed` or `invalidated`: terminal.
    EpisodeClosed(crate::episode::EpisodeStatusToken),
    /// The episode is active and its `ready_at` marker is not set: held. `record()` refuses a
    /// child of an unready plan (`PlanChildRefusal::NotReady`), so a child meets this only if the
    /// marker was cleared after its admission, which nothing does.
    NotReady,
    /// The plan has no `execution_episode` row.
    NoEpisode,
    /// The store's `control_epoch` is not the plan's.
    PlanEpochMismatch { plan: i64, current: i64 },
    /// `expires_at <= effective_now` on the sticky clock.
    Expired { expires_at: String, effective_now: String },
    /// The child's member is not one of the plan's members.
    NotAMember,
    /// The plan has no `approval_evidence` row.
    EvidenceAbsent,
    /// `validate_evidence` refused the plan's evidence under the account key and the red-bypass
    /// generation in force.
    EvidenceInvalid(PlanRefusal),
    /// The bus's grant verdict was a refusal ([`GrantDenial`], content-free). `Retired` and
    /// `PrincipalMismatch` are terminal; `Unavailable` is held and is checked with the other
    /// held rows, before the clock is read.
    GrantRetired(GrantDenial),
    /// The backups knob's head generation is not the one the plan froze (`coverage_generation`).
    CoverageDiverged { plan: u64, current: u64 },
    /// The plan froze `backups: on` and this build has no snapshot row to check (snapshots are
    /// not built): refused by name.
    SnapshotAbsent,
    /// A `Bypassed` plan minted under `backups: off` carries no frozen bypass notice
    /// ([`TriagePlan::bypass_notice`]): the journaled notice is itself a bypass-lane admission
    /// check, since the bypass waives the screen, never the notice. Terminal.
    BypassNoticeAbsent,
    /// The child asserted `CaptureBinding::NoJournalRow`: there is no durable capture to compare.
    CaptureRequired,
    /// The member's durable capture disagrees with its approval-time observed state over the
    /// plan's atoms: the `STALE_NOT_ATTEMPTED` terminal, with the diff recorded.
    StateDiverged { diff: Vec<crate::attempt::MemberDiff> },
}

impl PlanSendRefusal {
    /// Every `plan_refusal.reason` token, one per variant, in declaration order.
    pub const TOKENS: [&'static str; 15] = [
        "episode_held",
        "episode_closed",
        "not_ready",
        "no_episode",
        "plan_epoch_mismatch",
        "expired",
        "not_a_member",
        "evidence_absent",
        "evidence_invalid",
        "grant_retired",
        "coverage_diverged",
        "snapshot_absent",
        "bypass_notice_absent",
        "capture_required",
        "state_diverged",
    ];

    /// Terminal means every refusal except the held ones: `EpisodeHeld`, `NotReady` and
    /// `GrantRetired(Unavailable)`.
    pub fn is_terminal(&self) -> bool {
        !matches!(self, PlanSendRefusal::EpisodeHeld(_) | PlanSendRefusal::NotReady | PlanSendRefusal::GrantRetired(GrantDenial::Unavailable))
    }

    /// The `plan_refusal.reason` token: closed ([`PlanSendRefusal::TOKENS`]), one per variant.
    pub fn token(&self) -> &'static str {
        match self {
            PlanSendRefusal::EpisodeHeld(_) => "episode_held",
            PlanSendRefusal::EpisodeClosed(_) => "episode_closed",
            PlanSendRefusal::NotReady => "not_ready",
            PlanSendRefusal::NoEpisode => "no_episode",
            PlanSendRefusal::PlanEpochMismatch { .. } => "plan_epoch_mismatch",
            PlanSendRefusal::Expired { .. } => "expired",
            PlanSendRefusal::NotAMember => "not_a_member",
            PlanSendRefusal::EvidenceAbsent => "evidence_absent",
            PlanSendRefusal::EvidenceInvalid(_) => "evidence_invalid",
            PlanSendRefusal::GrantRetired(_) => "grant_retired",
            PlanSendRefusal::CoverageDiverged { .. } => "coverage_diverged",
            PlanSendRefusal::SnapshotAbsent => "snapshot_absent",
            PlanSendRefusal::BypassNoticeAbsent => "bypass_notice_absent",
            PlanSendRefusal::CaptureRequired => "capture_required",
            PlanSendRefusal::StateDiverged { .. } => "state_diverged",
        }
    }

    /// The pre-send reason the terminal fact carries: `StaleNotAttempted` for a diverged state,
    /// `PlanRefused` for every other refusal.
    pub fn pre_send_reason(&self) -> crate::attempt::PreSendReason {
        match self {
            PlanSendRefusal::StateDiverged { .. } => crate::attempt::PreSendReason::StaleNotAttempted,
            _ => crate::attempt::PreSendReason::PlanRefused,
        }
    }

    /// The typed record the terminal fact carries: the token, the member, the diff (non-empty
    /// only for `StateDiverged`) and `detail`, the variant's payload as JSON (`None` for a
    /// variant with no payload beyond the diff), which [`PlanSendRefusal::from_record`] reads back.
    pub fn record(&self, member_ref: &str) -> crate::attempt::PlanRefusalRecord {
        crate::attempt::PlanRefusalRecord {
            reason: self.token().to_string(),
            member_ref: member_ref.to_string(),
            diff: match self {
                PlanSendRefusal::StateDiverged { diff } => diff.clone(),
                _ => Vec::new(),
            },
            detail: self.detail().map(|v| v.to_string()),
        }
    }

    fn detail(&self) -> Option<serde_json::Value> {
        use serde_json::json;
        match self {
            PlanSendRefusal::EpisodeHeld(t) | PlanSendRefusal::EpisodeClosed(t) => Some(json!({ "status": t.as_token() })),
            PlanSendRefusal::PlanEpochMismatch { plan, current } => Some(json!({ "plan": plan, "current": current })),
            PlanSendRefusal::Expired { expires_at, effective_now } => Some(json!({ "expires_at": expires_at, "effective_now": effective_now })),
            PlanSendRefusal::EvidenceInvalid(r) => Some(plan_refusal_json(r)),
            PlanSendRefusal::GrantRetired(g) => Some(grant_denial_json(g)),
            PlanSendRefusal::CoverageDiverged { plan, current } => Some(json!({ "plan": plan, "current": current })),
            PlanSendRefusal::NotReady
            | PlanSendRefusal::NoEpisode
            | PlanSendRefusal::NotAMember
            | PlanSendRefusal::EvidenceAbsent
            | PlanSendRefusal::SnapshotAbsent
            | PlanSendRefusal::BypassNoticeAbsent
            | PlanSendRefusal::CaptureRequired
            | PlanSendRefusal::StateDiverged { .. } => None,
        }
    }

    /// Rebuild the refusal a record names, for the replay. Strict: every closed token inside
    /// `detail` is read back through its own vocabulary, and one this build does not write is an
    /// `Err` naming that token. The rebuilt refusal's own [`PlanSendRefusal::record`] must then
    /// equal `rec` field for field (the `detail` bytes and the diff included), so a record this
    /// build's writer cannot have produced (a missing or extra payload field, a payload on a
    /// payload-free token) is an `Err` naming the reason token, never a guessed refusal.
    pub fn from_record(rec: &crate::attempt::PlanRefusalRecord) -> Result<PlanSendRefusal, String> {
        let bad = |why: String| format!("plan_refusal '{}' does not read back: {why}", rec.reason);
        let detail: Option<serde_json::Value> = rec
            .detail
            .as_deref()
            .map(serde_json::from_str)
            .transpose()
            .map_err(|e| bad(format!("detail is not JSON: {e}")))?;
        let payload = || detail.as_ref().ok_or_else(|| "no detail".to_string());
        let status = || -> Decoded<crate::episode::EpisodeStatusToken> {
            let token = str_at(payload()?, "status")?;
            crate::episode::EpisodeStatusToken::from_token(token).ok_or_else(|| format!("unknown episode status token '{token}'"))
        };
        let rebuilt: Decoded<PlanSendRefusal> = match rec.reason.as_str() {
            "episode_held" => status().map(PlanSendRefusal::EpisodeHeld),
            "episode_closed" => status().map(PlanSendRefusal::EpisodeClosed),
            "not_ready" => Ok(PlanSendRefusal::NotReady),
            "no_episode" => Ok(PlanSendRefusal::NoEpisode),
            "plan_epoch_mismatch" => payload().and_then(|v| Ok(PlanSendRefusal::PlanEpochMismatch { plan: i64_at(v, "plan")?, current: i64_at(v, "current")? })),
            "expired" => payload().and_then(|v| Ok(PlanSendRefusal::Expired { expires_at: str_at(v, "expires_at")?.to_string(), effective_now: str_at(v, "effective_now")?.to_string() })),
            "not_a_member" => Ok(PlanSendRefusal::NotAMember),
            "evidence_absent" => Ok(PlanSendRefusal::EvidenceAbsent),
            "evidence_invalid" => payload().and_then(plan_refusal_from_json).map(PlanSendRefusal::EvidenceInvalid),
            "grant_retired" => payload().and_then(grant_denial_from_json).map(PlanSendRefusal::GrantRetired),
            "coverage_diverged" => payload().and_then(|v| Ok(PlanSendRefusal::CoverageDiverged { plan: u64_at(v, "plan")?, current: u64_at(v, "current")? })),
            "snapshot_absent" => Ok(PlanSendRefusal::SnapshotAbsent),
            "bypass_notice_absent" => Ok(PlanSendRefusal::BypassNoticeAbsent),
            "capture_required" => Ok(PlanSendRefusal::CaptureRequired),
            "state_diverged" => Ok(PlanSendRefusal::StateDiverged { diff: rec.diff.clone() }),
            other => Err(format!("unknown reason token '{other}'")),
        };
        let rebuilt = rebuilt.map_err(bad)?;
        if rebuilt.record(&rec.member_ref) != *rec {
            return Err(bad("the record is not the one this build writes for it".into()));
        }
        Ok(rebuilt)
    }
}

/// The durable comparison, over the same durable capture whose `capture_generation` the
/// send-authorization CAS spends. Pure: the member's approval-time observed state against the
/// captured `P`, over the atoms the observed state names. An atom the capture does not hold is a
/// divergence (`observed: None`). Empty means no divergence. Preflight (the bus) calls it over a
/// fresh observation's atoms.
pub fn member_state_diff(observed_state: &BTreeMap<String, bool>, captured: &BTreeMap<String, bool>) -> Vec<crate::attempt::MemberDiff> {
    observed_state
        .iter()
        .filter_map(|(atom, expected)| {
            let observed = captured.get(atom).copied();
            (observed != Some(*expected)).then(|| crate::attempt::MemberDiff { atom: atom.clone(), expected: *expected, observed })
        })
        .collect()
}

/// What `CommandBus::preflight_plan` decided (phase one of staleness checking).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreflightOutcome {
    /// Every member re-observed equal to its approval-time state: the durable `ready` marker is
    /// set (or already was).
    Ready,
    /// These members diverged, each with its diff: the episode is now
    /// `invalidated{stale_preflight}` naming them.
    Refused { diverged: Vec<(String, Vec<crate::attempt::MemberDiff>)> },
    /// The store's serialized barrier refused this writer's write because a child of the plan
    /// already holds a `send_authorized` fact (`EpisodeRefusal::DispatchBegan`); the per-child
    /// recheck at the send check owns staleness from here. `diverged` is what this preflight
    /// observed: empty when the members agreed and the ready write was the one refused, the named
    /// members and their diffs when the invalidation was.
    Raced { diverged: Vec<(String, Vec<crate::attempt::MemberDiff>)> },
}

/// One member's state as `CommandBus::plan_member_states` derives it from durable rows, a
/// minimal read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemberState {
    /// No child row exists for the member.
    NotMinted,
    /// The child row is not terminal.
    InFlight,
    /// The child row is `Applied`.
    Applied,
    /// The child row is `Failed` and its `FAILED_PRE_SEND` carries a plan-admission record.
    Refused { reason: String, diff: Vec<crate::attempt::MemberDiff> },
    /// Any other terminal status (a `Failed` child without a plan record included).
    Terminal(crate::IntentStatus),
}

// The refusal-payload codec (the `detail` JSON). Hand-written and total over each enum, so a
// variant added to one of them is a compile error here. Every closed vocabulary inside it (the
// rule and field enums `PlanShapeRule`, `WarningShapeRule`, `HeaderField` and
// `crate::commitment::IdShapeField`, the lane, the comprehension, the grant denial and the
// episode status) is written as its token and read back through its own vocabulary, and a token
// this build does not write is refused naming it.

/// A decoder's answer: the value, or why the `detail` does not read back (naming the field or
/// the unknown token).
type Decoded<T> = Result<T, String>;

fn field_at<'a>(v: &'a serde_json::Value, key: &str) -> Decoded<&'a serde_json::Value> {
    v.get(key).ok_or_else(|| format!("missing field '{key}'"))
}
fn str_at<'a>(v: &'a serde_json::Value, key: &str) -> Decoded<&'a str> {
    field_at(v, key)?.as_str().ok_or_else(|| format!("field '{key}' is not a string"))
}
fn u64_at(v: &serde_json::Value, key: &str) -> Decoded<u64> {
    field_at(v, key)?.as_u64().ok_or_else(|| format!("field '{key}' is not an unsigned integer"))
}
fn i64_at(v: &serde_json::Value, key: &str) -> Decoded<i64> {
    field_at(v, key)?.as_i64().ok_or_else(|| format!("field '{key}' is not an integer"))
}
fn u32_at(v: &serde_json::Value, key: &str) -> Decoded<u32> {
    u32::try_from(u64_at(v, key)?).map_err(|_| format!("field '{key}' is not a u32"))
}
fn usize_at(v: &serde_json::Value, key: &str) -> Decoded<usize> {
    usize::try_from(u64_at(v, key)?).map_err(|_| format!("field '{key}' is not a usize"))
}
/// A closed token at `key`, read back through `from_token`; an unknown one is refused by name.
fn token_at<T>(v: &serde_json::Value, key: &str, vocabulary: &str, from_token: fn(&str) -> Option<T>) -> Decoded<T> {
    let token = str_at(v, key)?;
    from_token(token).ok_or_else(|| format!("unknown {vocabulary} token '{token}'"))
}

fn plan_refusal_json(r: &PlanRefusal) -> serde_json::Value {
    use serde_json::json;
    match r {
        PlanRefusal::EmptyMembers => json!({ "kind": "empty_members" }),
        PlanRefusal::ConflictingDuplicate(m) => json!({ "kind": "conflicting_duplicate", "member": m }),
        PlanRefusal::HeaderCountMismatch { header, members } => json!({ "kind": "header_count_mismatch", "header": header, "members": members }),
        PlanRefusal::WarningShape(rule) => json!({ "kind": "warning_shape", "rule": rule.as_token() }),
        PlanRefusal::HeaderDiverges(field) => json!({ "kind": "header_diverges", "field": field.as_token() }),
        PlanRefusal::PresentationRowCount { rows, members } => json!({ "kind": "presentation_row_count", "rows": rows, "members": members }),
        PlanRefusal::PresentationRowDiverges(m) => json!({ "kind": "presentation_row_diverges", "member": m }),
        PlanRefusal::ConfiguredKZero => json!({ "kind": "configured_k_zero" }),
        PlanRefusal::Commitment(e) => json!({ "kind": "commitment", "error": commitment_error_json(e) }),
        PlanRefusal::LaneMismatch { plan, evidence } => json!({ "kind": "lane_mismatch", "plan": lane_json(plan), "evidence": comprehension_json(evidence) }),
        PlanRefusal::PlanIdMismatch { plan, evidence } => json!({ "kind": "plan_id_mismatch", "plan": plan.0, "evidence": evidence.0 }),
        PlanRefusal::ApproverMissing => json!({ "kind": "approver_missing" }),
        PlanRefusal::ViewMismatch => json!({ "kind": "view_mismatch" }),
        PlanRefusal::SampleMismatch(why) => json!({ "kind": "sample_mismatch", "why": why }),
        PlanRefusal::SampleKMismatch { plan, evidence } => json!({ "kind": "sample_k_mismatch", "plan": plan, "evidence": evidence }),
        PlanRefusal::BypassGenerationMismatch { plan, current } => json!({ "kind": "bypass_generation_mismatch", "plan": plan, "current": current }),
        PlanRefusal::UnknownVerb(v) => json!({ "kind": "unknown_verb", "verb": v }),
        PlanRefusal::PlanShape(rule) => json!({ "kind": "plan_shape", "rule": rule.as_token() }),
    }
}

fn plan_refusal_from_json(v: &serde_json::Value) -> Decoded<PlanRefusal> {
    let text = |k: &str| str_at(v, k).map(str::to_string);
    Ok(match str_at(v, "kind")? {
        "empty_members" => PlanRefusal::EmptyMembers,
        "conflicting_duplicate" => PlanRefusal::ConflictingDuplicate(text("member")?),
        "header_count_mismatch" => PlanRefusal::HeaderCountMismatch { header: u32_at(v, "header")?, members: usize_at(v, "members")? },
        "warning_shape" => PlanRefusal::WarningShape(token_at(v, "rule", "warning_shape rule", WarningShapeRule::from_token)?),
        "header_diverges" => PlanRefusal::HeaderDiverges(token_at(v, "field", "header_diverges field", HeaderField::from_token)?),
        "presentation_row_count" => PlanRefusal::PresentationRowCount { rows: usize_at(v, "rows")?, members: usize_at(v, "members")? },
        "presentation_row_diverges" => PlanRefusal::PresentationRowDiverges(text("member")?),
        "configured_k_zero" => PlanRefusal::ConfiguredKZero,
        "commitment" => PlanRefusal::Commitment(commitment_error_from_json(field_at(v, "error")?)?),
        "lane_mismatch" => PlanRefusal::LaneMismatch { plan: lane_from_json(field_at(v, "plan")?)?, evidence: comprehension_from_json(field_at(v, "evidence")?)? },
        "plan_id_mismatch" => PlanRefusal::PlanIdMismatch { plan: PlanId(text("plan")?), evidence: PlanId(text("evidence")?) },
        "approver_missing" => PlanRefusal::ApproverMissing,
        "view_mismatch" => PlanRefusal::ViewMismatch,
        "sample_mismatch" => PlanRefusal::SampleMismatch(text("why")?),
        "sample_k_mismatch" => PlanRefusal::SampleKMismatch { plan: u32_at(v, "plan")?, evidence: u32_at(v, "evidence")? },
        "bypass_generation_mismatch" => PlanRefusal::BypassGenerationMismatch { plan: u64_at(v, "plan")?, current: u64_at(v, "current")? },
        "unknown_verb" => PlanRefusal::UnknownVerb(text("verb")?),
        "plan_shape" => PlanRefusal::PlanShape(token_at(v, "rule", "plan_shape rule", PlanShapeRule::from_token)?),
        other => return Err(format!("unknown plan refusal kind token '{other}'")),
    })
}

fn commitment_error_json(e: &CommitmentError) -> serde_json::Value {
    use serde_json::json;
    match e {
        CommitmentError::KeyLength(n) => json!({ "kind": "key_length", "n": n }),
        CommitmentError::RandomizerLength(n) => json!({ "kind": "randomizer_length", "n": n }),
        CommitmentError::RandomizerHex => json!({ "kind": "randomizer_hex" }),
        CommitmentError::TagHex => json!({ "kind": "tag_hex" }),
        CommitmentError::KeyHex => json!({ "kind": "key_hex" }),
        CommitmentError::IdShape(field) => json!({ "kind": "id_shape", "field": field.as_token() }),
        CommitmentError::KeyEpochZero => json!({ "kind": "key_epoch_zero" }),
        CommitmentError::KeyEpochTooLarge(n) => json!({ "kind": "key_epoch_too_large", "n": n }),
        CommitmentError::FrameTooLong(n) => json!({ "kind": "frame_too_long", "n": n }),
        CommitmentError::EntropyUnavailable => json!({ "kind": "entropy_unavailable" }),
    }
}

fn commitment_error_from_json(v: &serde_json::Value) -> Decoded<CommitmentError> {
    Ok(match str_at(v, "kind")? {
        "key_length" => CommitmentError::KeyLength(usize_at(v, "n")?),
        "randomizer_length" => CommitmentError::RandomizerLength(usize_at(v, "n")?),
        "randomizer_hex" => CommitmentError::RandomizerHex,
        "tag_hex" => CommitmentError::TagHex,
        "key_hex" => CommitmentError::KeyHex,
        "id_shape" => CommitmentError::IdShape(token_at(v, "field", "id_shape field", crate::commitment::IdShapeField::from_token)?),
        "key_epoch_zero" => CommitmentError::KeyEpochZero,
        "key_epoch_too_large" => CommitmentError::KeyEpochTooLarge(u64_at(v, "n")?),
        "frame_too_long" => CommitmentError::FrameTooLong(usize_at(v, "n")?),
        "entropy_unavailable" => CommitmentError::EntropyUnavailable,
        other => return Err(format!("unknown commitment error kind token '{other}'")),
    })
}

fn lane_json(lane: &AdmissionLane) -> serde_json::Value {
    use serde_json::json;
    match lane {
        AdmissionLane::PerMember | AdmissionLane::Aggregate => json!({ "lane": lane.as_token() }),
        AdmissionLane::Bypassed { bypass_config_generation } => json!({ "lane": lane.as_token(), "bypass_config_generation": bypass_config_generation }),
    }
}

fn lane_from_json(v: &serde_json::Value) -> Decoded<AdmissionLane> {
    Ok(match str_at(v, "lane")? {
        "per_member" => AdmissionLane::PerMember,
        "aggregate" => AdmissionLane::Aggregate,
        "bypassed" => AdmissionLane::Bypassed { bypass_config_generation: u64_at(v, "bypass_config_generation")? },
        other => return Err(format!("unknown admission lane token '{other}'")),
    })
}

fn comprehension_json(c: &Comprehension) -> serde_json::Value {
    use serde_json::json;
    match c {
        Comprehension::PerMember => json!({ "comprehension": c.as_token() }),
        Comprehension::Aggregate { shape_digest, sample_k, sample_members } => {
            json!({ "comprehension": c.as_token(), "shape_digest": shape_digest.hex(), "sample_k": sample_k, "sample_members": sample_members })
        }
        Comprehension::Bypassed { bypass_config_generation } => json!({ "comprehension": c.as_token(), "bypass_config_generation": bypass_config_generation }),
    }
}

fn comprehension_from_json(v: &serde_json::Value) -> Decoded<Comprehension> {
    Ok(match str_at(v, "comprehension")? {
        "per_member" => Comprehension::PerMember,
        "aggregate" => Comprehension::Aggregate {
            shape_digest: CommitmentTag::from_hex(str_at(v, "shape_digest")?).map_err(|e| format!("field 'shape_digest': {e}"))?,
            sample_k: u32_at(v, "sample_k")?,
            sample_members: field_at(v, "sample_members")?
                .as_array()
                .ok_or_else(|| "field 'sample_members' is not an array".to_string())?
                .iter()
                .map(|m| m.as_str().map(str::to_string).ok_or_else(|| "a sample member is not a string".to_string()))
                .collect::<Decoded<Vec<_>>>()?,
        },
        "bypassed" => Comprehension::Bypassed { bypass_config_generation: u64_at(v, "bypass_config_generation")? },
        other => return Err(format!("unknown comprehension token '{other}'")),
    })
}

/// A grant denial's `detail`: the token, and for `retired` the two generations; the type has
/// nothing else to write.
fn grant_denial_json(g: &GrantDenial) -> serde_json::Value {
    use serde_json::json;
    match g {
        GrantDenial::Retired { generation, high_water } => json!({ "kind": g.token(), "generation": generation, "high_water": high_water }),
        GrantDenial::PrincipalMismatch | GrantDenial::Unavailable => json!({ "kind": g.token() }),
    }
}

fn grant_denial_from_json(v: &serde_json::Value) -> Decoded<GrantDenial> {
    Ok(match str_at(v, "kind")? {
        "retired" => GrantDenial::Retired { generation: u64_at(v, "generation")?, high_water: u64_at(v, "high_water")? },
        "principal_mismatch" => GrantDenial::PrincipalMismatch,
        "unavailable" => GrantDenial::Unavailable,
        other => return Err(format!("unknown grant denial token '{other}'")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The structured sender a header row carrying `sender` as its From text would freeze, via
    /// the store's own derivation (`mailbox::parse_mailbox`), so a test member's domain is the
    /// one the mint would freeze for that text.
    fn parsed_sender(sender: &str) -> FrozenSender {
        let parsed = crate::mailbox::parse_mailbox(sender);
        let local = (parsed.status == crate::mailbox::SenderStatus::Ok).then(|| parsed.local_part.clone());
        FrozenSender::from_columns(parsed.status, local, parsed.addr().map(String::from), parsed.domain).expect("a parse is one of the four shapes")
    }

    fn member(r: &str, sender: &str, inbox: bool) -> PlanMember {
        PlanMember {
            message_ref: r.to_string(),
            display: FrozenDisplay {
                sender: sender.to_string(),
                sender_address: String::new(),
                sender_parse: parsed_sender(sender),
                subject: format!("subj {r}"),
                date: "2026-09-24T00:00:00Z".to_string(),
                size: None,
            },
            observed_state: [("label:TRASH".to_string(), false), ("membership:INBOX".to_string(), inbox)].into_iter().collect(),
            forward_target: [("label:TRASH".to_string(), true), ("membership:INBOX".to_string(), false)].into_iter().collect(),
        }
    }

    #[test]
    fn canonical_members_are_deduplicated_and_sorted_by_ref_bytes_and_empty_is_refused() {
        let m = canonical_members(vec![member("b", "x@e", true), member("a", "y@e", true), member("b", "x@e", true)]).unwrap();
        assert_eq!(m.iter().map(|x| x.message_ref.as_str()).collect::<Vec<_>>(), vec!["a", "b"]);
        assert_eq!(canonical_members(vec![]).unwrap_err(), PlanRefusal::EmptyMembers);
        // Two members with the same ref but DIFFERENT frozen fields are a refusal, not a pick.
        let mut other = member("a", "x@e", true);
        other.display.subject = "different".into();
        assert_eq!(canonical_members(vec![member("a", "x@e", true), other]).unwrap_err(), PlanRefusal::ConflictingDuplicate("a".into()));
    }

    #[test]
    fn the_presentation_is_derived_one_to_one_from_the_members_and_validated() {
        let members = canonical_members(vec![member("a", "news@x.com", true), member("b", "news@x.com", true), member("c", "bob@y.org", false)]).unwrap();
        let header = PresentationHeader { account: "me@e".into(), verb: PlanVerb::Trash, tier: "red".into(), count: 3, backup_coverage: true, warning: None };
        let p = derive_presentation(&header, &members).unwrap();
        assert_eq!(p.rows.len(), 3);
        assert_eq!(p.rows.iter().map(|r| r.message_ref.as_str()).collect::<Vec<_>>(), vec!["a", "b", "c"]);
        assert_eq!(p.summary.sender_domains, vec![("x.com".to_string(), 2), ("y.org".to_string(), 1)]);
        assert_eq!(p.summary.date_min, "2026-09-24T00:00:00Z");
        assert_eq!(p.summary.count, 3);
        // A header whose count disagrees with the member list is refused at derivation.
        let bad = PresentationHeader { count: 2, ..header.clone() };
        assert_eq!(derive_presentation(&bad, &members).unwrap_err(), PlanRefusal::HeaderCountMismatch { header: 2, members: 3 });
        // validate: row count == member count, each row keyed by a member identity, same order.
        assert!(validate_presentation(&p, &members).is_ok());
        let mut forged = p.clone();
        forged.rows[1].subject = "changed".into();
        assert_eq!(validate_presentation(&forged, &members).unwrap_err(), PlanRefusal::PresentationRowDiverges("b".into()));
        let mut short = p.clone();
        short.rows.pop();
        assert_eq!(validate_presentation(&short, &members).unwrap_err(), PlanRefusal::PresentationRowCount { rows: 2, members: 3 });
    }

    /// (the gap the fold left, found out of that fold's literal
    /// spec): `validate_presentation` compared every OTHER frozen field to the member but not the
    /// three [`FrozenSender`] fields the fold put on the row and in the digest — a forged
    /// `sender_status`/`sender_local`/`sender_domain` (a different structured sender than the
    /// member's frozen one, the digest's OWN preimage) verified anyway. One member, one row each,
    /// mutate exactly one of the three fields, assert the SAME per-row refusal the other frozen
    /// fields already return.
    #[test]
    fn a_row_whose_sender_domain_differs_from_the_frozen_member_is_refused() {
        let members = canonical_members(vec![member("a", "real@trusted.example", true)]).unwrap();
        let header = PresentationHeader { account: "me@e".into(), verb: PlanVerb::Trash, tier: PLAN_TIER.into(), count: 1, backup_coverage: true, warning: None };
        let p = derive_presentation(&header, &members).unwrap();
        assert!(validate_presentation(&p, &members).is_ok());
        assert_eq!(p.rows[0].sender_domain, "trusted.example");
        let mut forged = p.clone();
        forged.rows[0].sender_domain = "evil.example".to_string();
        assert_eq!(validate_presentation(&forged, &members).unwrap_err(), PlanRefusal::PresentationRowDiverges("a".into()));
    }

    #[test]
    fn a_row_whose_sender_local_differs_from_the_frozen_member_is_refused() {
        let members = canonical_members(vec![member("a", "real@trusted.example", true)]).unwrap();
        let header = PresentationHeader { account: "me@e".into(), verb: PlanVerb::Trash, tier: PLAN_TIER.into(), count: 1, backup_coverage: true, warning: None };
        let p = derive_presentation(&header, &members).unwrap();
        assert_eq!(p.rows[0].sender_local, "real");
        let mut forged = p.clone();
        forged.rows[0].sender_local = "other".to_string();
        assert_eq!(validate_presentation(&forged, &members).unwrap_err(), PlanRefusal::PresentationRowDiverges("a".into()));
    }

    #[test]
    fn a_row_whose_sender_status_differs_from_the_frozen_member_is_refused() {
        let members = canonical_members(vec![member("a", "real@trusted.example", true)]).unwrap();
        let header = PresentationHeader { account: "me@e".into(), verb: PlanVerb::Trash, tier: PLAN_TIER.into(), count: 1, backup_coverage: true, warning: None };
        let p = derive_presentation(&header, &members).unwrap();
        assert_eq!(p.rows[0].sender_status, "ok");
        // The status changes, the components (local/domain/address text) are left in place — the
        // status alone is the forged field.
        let mut forged = p.clone();
        forged.rows[0].sender_status = "malformed".to_string();
        assert_eq!(validate_presentation(&forged, &members).unwrap_err(), PlanRefusal::PresentationRowDiverges("a".into()));
    }

    #[test]
    fn canonical_presentation_bytes_are_deterministic_domain_tagged_length_framed_and_order_independent_of_input() {
        let members = canonical_members(vec![member("b", "n@x.com", true), member("a", "n@x.com", true)]).unwrap();
        let header = PresentationHeader { account: "me@e".into(), verb: PlanVerb::MarkSpam, tier: "red".into(), count: 2, backup_coverage: false, warning: Some("snapshot recovery is OFF".into()) };
        let p = derive_presentation(&header, &members).unwrap();
        let bytes = encode_presentation(&p, "setdigest", "statedigest").unwrap();
        assert!(bytes.starts_with(PRESENTATION_DOMAIN_TAG));
        let again = encode_presentation(&p, "setdigest", "statedigest").unwrap();
        assert_eq!(bytes, again);
        // The header's verb, coverage and warning are INSIDE the bytes (/).
        let other_verb = PresentationHeader { verb: PlanVerb::Trash, ..header.clone() };
        let p2 = derive_presentation(&other_verb, &members).unwrap();
        assert_ne!(encode_presentation(&p2, "setdigest", "statedigest").unwrap(), bytes);
        let covered = PresentationHeader { backup_coverage: true, warning: None, ..header.clone() };
        let p3 = derive_presentation(&covered, &members).unwrap();
        assert_ne!(encode_presentation(&p3, "setdigest", "statedigest").unwrap(), bytes);
        // The set/state digests are bound into the presentation bytes — EACH of them.
        assert_ne!(encode_presentation(&p, "OTHER", "statedigest").unwrap(), bytes);
        assert_ne!(encode_presentation(&p, "setdigest", "OTHER").unwrap(), bytes);
        // Length framing: moving a byte across the set/state boundary changes the bytes.
        assert_ne!(encode_presentation(&p, "ab", "c").unwrap(), encode_presentation(&p, "a", "bc").unwrap());
        // Order-independent of input: the same members handed in the other order encode identically.
        let ab = canonical_members(vec![member("a", "n@x.com", true), member("b", "n@x.com", true)]).unwrap();
        assert_eq!(encode_presentation(&derive_presentation(&header, &ab).unwrap(), "setdigest", "statedigest").unwrap(), bytes);
    }

    #[test]
    fn the_warning_is_present_exactly_when_coverage_is_off_and_never_empty() {
        let members = canonical_members(vec![member("a", "n@x.com", true)]).unwrap();
        let base = PresentationHeader { account: "me@e".into(), verb: PlanVerb::Trash, tier: "red".into(), count: 1, backup_coverage: false, warning: Some("snapshot recovery is OFF".into()) };
        assert!(derive_presentation(&base, &members).is_ok());
        let on_with = PresentationHeader { backup_coverage: true, ..base.clone() };
        assert_eq!(derive_presentation(&on_with, &members).unwrap_err(), PlanRefusal::WarningShape(WarningShapeRule::CoverageOnCarriesNoWarning));
        let off_without = PresentationHeader { warning: None, ..base.clone() };
        assert_eq!(derive_presentation(&off_without, &members).unwrap_err(), PlanRefusal::WarningShape(WarningShapeRule::CoverageOffRequiresTheVerbWarning));
        // `Some("")` would frame identically to `None` — refused, so the encoding stays injective.
        let off_empty = PresentationHeader { warning: Some(String::new()), ..base.clone() };
        assert_eq!(derive_presentation(&off_empty, &members).unwrap_err(), PlanRefusal::WarningShape(WarningShapeRule::TheWarningIsNeverEmpty));
    }

    #[test]
    fn the_frozen_lane_follows_the_knobs_in_force_and_k_is_clamped_and_never_zero() {
        use crate::config_knobs::{ApprovalModeKnob, InForce, RedBypassKnob};
        let off = InForce { value: RedBypassKnob::Off, generation: 4 };
        let on = InForce { value: RedBypassKnob::On, generation: 9 };
        assert_eq!(admission_lane_for(ApprovalModeKnob::FullList, off), AdmissionLane::PerMember);
        assert_eq!(admission_lane_for(ApprovalModeKnob::SummarySample { configured_k: 3 }, off), AdmissionLane::Aggregate);
        // Bypass ON wins over either screen mode and freezes the generation of the act in force.
        assert_eq!(admission_lane_for(ApprovalModeKnob::FullList, on), AdmissionLane::Bypassed { bypass_config_generation: 9 });
        assert_eq!(admission_lane_for(ApprovalModeKnob::SummarySample { configured_k: 3 }, on), AdmissionLane::Bypassed { bypass_config_generation: 9 });
        assert_eq!(effective_k(5, 3).unwrap(), 3, "k above the member count degenerates to the count");
        assert_eq!(effective_k(2, 3).unwrap(), 2);
        assert_eq!(effective_k(0, 3).unwrap_err(), PlanRefusal::ConfiguredKZero);
        assert_eq!(AdmissionLane::TOKENS, [AdmissionLane::PerMember.as_token(), AdmissionLane::Aggregate.as_token(), AdmissionLane::Bypassed { bypass_config_generation: 0 }.as_token()]);
        for v in PlanVerb::ALL {
            assert_eq!(PlanVerb::from_token(v.as_token()).unwrap(), v);
        }
        assert_eq!(PlanVerb::from_token("delete").unwrap_err(), PlanRefusal::UnknownVerb("delete".into()));
        assert_eq!(PlanVerb::Trash.action("m1").risk_tier(), crate::RiskTier::Red);
        assert_eq!(PlanVerb::MarkSpam.action("m1").risk_tier(), crate::RiskTier::Red);
    }

    fn test_key() -> CommitmentKey {
        CommitmentKey::from_bytes(&[0x42u8; 48]).unwrap()
    }
    fn test_key_ref() -> CommitmentKeyRef {
        CommitmentKeyRef::new("photon.account.me@e", 1).unwrap()
    }

    #[test]
    fn the_digest_family_is_keyed_randomized_and_the_presentation_binds_set_and_state() {
        let members = canonical_members(vec![member("a", "n@x.com", true), member("b", "n@x.com", true)]).unwrap();
        let header = PresentationHeader { account: "me@e".into(), verb: PlanVerb::Trash, tier: "red".into(), count: 2, backup_coverage: true, warning: None };
        let d = PlanDigests::mint(&test_key(), &test_key_ref(), "me@e", "principal@e", PlanVerb::Trash, &members, &header).unwrap();
        // Every digest is a 96-hex tag with a stored randomizer profile — never a bare digest.
        for (tag, profile) in [(&d.set, &d.set_profile), (&d.state, &d.state_profile), (&d.presentation, &d.presentation_profile)] {
            assert_eq!(tag.hex().len(), 96);
            assert_eq!(profile.randomizer.len(), 32);
            assert_eq!(profile.commitment_scheme, "mw.commitment.v1");
        }
        assert_eq!(d.set_profile.key_ref, test_key_ref());
        // Same members, different verb ⇒ different set digest AND different presentation.
        let spam_header = PresentationHeader { verb: PlanVerb::MarkSpam, ..header.clone() };
        let d2 = PlanDigests::mint(&test_key(), &test_key_ref(), "me@e", "principal@e", PlanVerb::MarkSpam, &members, &spam_header).unwrap();
        assert_ne!(d.set, d2.set);
        assert_ne!(d.presentation, d2.presentation);
        // Two mints over IDENTICAL inputs differ (fresh randomizers) — no keyless correlation.
        let d3 = PlanDigests::mint(&test_key(), &test_key_ref(), "me@e", "principal@e", PlanVerb::Trash, &members, &header).unwrap();
        assert_ne!(d.presentation, d3.presentation);
        // …but re-derivation with the STORED randomizer is exact (key-holder verifiability).
        let r = Randomizer::from_hex(&d.presentation_profile.randomizer).unwrap();
        let bytes = encode_presentation(&d.presentation_view, &d.set.hex(), &d.state.hex()).unwrap();
        assert_eq!(compute_tag(&test_key(), &presentation_domain(&test_key_ref()).unwrap(), &r, &bytes).unwrap(), d.presentation);

        // The two cross-mint `assert_ne!`s above hold on fresh randomizers ALONE, so the CONTENT
        // binding is pinned here with each STORED randomizer held fixed.
        let set_r = Randomizer::from_hex(&d.set_profile.randomizer).unwrap();
        let set_tag = |verb: PlanVerb| compute_tag(&test_key(), &set_domain(&test_key_ref()).unwrap(), &set_r, &encode_set("me@e", "principal@e", verb, &members).unwrap()).unwrap();
        assert_eq!(set_tag(PlanVerb::Trash), d.set, "the set digest re-derives from its stored randomizer");
        assert_ne!(set_tag(PlanVerb::MarkSpam), d.set, "the verb is inside the set digest");
        let spam_view = encode_presentation(&d2.presentation_view, &d.set.hex(), &d.state.hex()).unwrap();
        assert_ne!(compute_tag(&test_key(), &presentation_domain(&test_key_ref()).unwrap(), &r, &spam_view).unwrap(), d.presentation, "the header verb is inside the presentation");
        let state_r = Randomizer::from_hex(&d.state_profile.randomizer).unwrap();
        let state_tag = |ms: &[PlanMember]| compute_tag(&test_key(), &state_domain(&test_key_ref()).unwrap(), &state_r, &encode_state(ms).unwrap()).unwrap();
        assert_eq!(state_tag(&members), d.state);
        let mut moved = members.clone();
        moved[0].observed_state.insert("membership:INBOX".into(), false);
        assert_ne!(state_tag(&moved), d.state, "the observed closure state is inside the state digest");
        // The presentation binds BOTH set and state: the same rows over a foreign set or state ⇒ another tag.
        let foreign_set = encode_presentation(&d.presentation_view, &d3.set.hex(), &d.state.hex()).unwrap();
        assert_ne!(compute_tag(&test_key(), &presentation_domain(&test_key_ref()).unwrap(), &r, &foreign_set).unwrap(), d.presentation);
        let foreign_state = encode_presentation(&d.presentation_view, &d.set.hex(), &d3.state.hex()).unwrap();
        assert_ne!(compute_tag(&test_key(), &presentation_domain(&test_key_ref()).unwrap(), &r, &foreign_state).unwrap(), d.presentation);
        // ONE fresh randomizer per durable commitment (commitment.rs module doc): six distinct.
        let randomizers: BTreeSet<&str> = [&d.set_profile, &d.state_profile, &d.presentation_profile, &d.shape_profile, &d.sample_seed_profile, &d.aggregate_view_profile]
            .iter()
            .map(|p| p.randomizer.as_str())
            .collect();
        assert_eq!(randomizers.len(), 6, "no randomizer is shared across two commitments");
        // A header naming another verb or account than the set binds is refused at mint.
        assert_eq!(PlanDigests::mint(&test_key(), &test_key_ref(), "me@e", "principal@e", PlanVerb::MarkSpam, &members, &header).unwrap_err(), PlanRefusal::HeaderDiverges(HeaderField::Verb));
        assert_eq!(PlanDigests::mint(&test_key(), &test_key_ref(), "other@e", "principal@e", PlanVerb::Trash, &members, &header).unwrap_err(), PlanRefusal::HeaderDiverges(HeaderField::Account));
    }

    #[test]
    fn full_list_view_equality_holds_iff_the_rendered_rows_equal_the_canonical_ones() {
        let members = canonical_members(vec![member("a", "n@x.com", true), member("b", "n@x.com", true)]).unwrap();
        let header = PresentationHeader { account: "me@e".into(), verb: PlanVerb::Trash, tier: "red".into(), count: 2, backup_coverage: true, warning: None };
        let d = PlanDigests::mint(&test_key(), &test_key_ref(), "me@e", "principal@e", PlanVerb::Trash, &members, &header).unwrap();
        let rendered = RenderedView::FullList(d.presentation_view.clone());
        assert_eq!(view_commitment(&test_key(), &test_key_ref(), &d, &rendered).unwrap(), d.presentation, "PerMember: view_digest == presentation_digest");
        // Display substitution: one visible row changed ⇒ a different view commitment ⇒ refuse.
        let mut forged = d.presentation_view.clone();
        forged.rows[0].subject = "not what the plan says".into();
        assert_ne!(view_commitment(&test_key(), &test_key_ref(), &d, &RenderedView::FullList(forged)).unwrap(), d.presentation);
        // Cross-object substitution: a presentation derived from ANOTHER member set, rendered
        // against this plan ⇒ a different view commitment ⇒ refuse.
        let other_members = canonical_members(vec![member("a", "n@x.com", true), member("z", "n@x.com", true)]).unwrap();
        let other_view = derive_presentation(&header, &other_members).unwrap();
        assert_ne!(view_commitment(&test_key(), &test_key_ref(), &d, &RenderedView::FullList(other_view)).unwrap(), d.presentation);
    }

    #[test]
    fn aggregate_view_commitment_is_its_own_domain_under_its_own_stored_randomizer_and_binds_what_was_shown() {
        let members = canonical_members((0..5).map(|i| member(&format!("m{i}"), "n@x.com", true)).collect()).unwrap();
        let header = PresentationHeader { account: "me@e".into(), verb: PlanVerb::Trash, tier: "red".into(), count: 5, backup_coverage: false, warning: Some("snapshot recovery is OFF".into()) };
        let d = PlanDigests::mint(&test_key(), &test_key_ref(), "me@e", "principal@e", PlanVerb::Trash, &members, &header).unwrap();
        let agg = AggregateRender { header: d.presentation_view.header.clone(), summary: d.presentation_view.summary.clone(), sample_k: 2, sample_rows: d.presentation_view.rows[..2].to_vec() };
        let c = aggregate_view_commitment(&test_key(), &test_key_ref(), &d, &agg).unwrap();
        assert_eq!(view_commitment(&test_key(), &test_key_ref(), &d, &RenderedView::Aggregate(agg.clone())).unwrap(), c);
        // Key-holder re-derivation from the STORED aggregate-view profile, through ITS domain.
        let dom = CommitmentDomain::new("photon.triage.aggregate_view", CommitmentDisposition::EnvelopeCommitmentOnly, test_key_ref()).unwrap();
        assert_eq!(d.aggregate_view_profile.domain_separator, crate::commitment::canonical_domain_separator(&dom));
        let r = Randomizer::from_hex(&d.aggregate_view_profile.randomizer).unwrap();
        assert_eq!(compute_tag(&test_key(), &dom, &r, &encode_aggregate_view(&d, &agg).unwrap()).unwrap(), c);
        // Everything the aggregate screen shows is inside: k, the summary, the coverage line, the rows.
        assert_ne!(aggregate_view_commitment(&test_key(), &test_key_ref(), &d, &AggregateRender { sample_k: 3, ..agg.clone() }).unwrap(), c);
        let mut other_summary = agg.clone();
        other_summary.summary.date_max = "2099-01-01T00:00:00Z".into();
        assert_ne!(aggregate_view_commitment(&test_key(), &test_key_ref(), &d, &other_summary).unwrap(), c);
        let mut other_coverage = agg.clone();
        other_coverage.header.backup_coverage = true;
        other_coverage.header.warning = None;
        assert_ne!(aggregate_view_commitment(&test_key(), &test_key_ref(), &d, &other_coverage).unwrap(), c);
        let mut other_rows = agg.clone();
        other_rows.sample_rows[0] = d.presentation_view.rows[4].clone();
        assert_ne!(aggregate_view_commitment(&test_key(), &test_key_ref(), &d, &other_rows).unwrap(), c);
        // It binds the underlying plan: the shape and presentation digests are inside its bytes.
        let bytes = encode_aggregate_view(&d, &agg).unwrap();
        assert!(bytes.windows(96).any(|w| w == d.presentation.hex().as_bytes()));
        assert!(bytes.windows(96).any(|w| w == d.shape.hex().as_bytes()));
        // Never the presentation digest (the PerMember lane's value).
        assert_ne!(c, d.presentation);
    }

    #[test]
    fn the_sample_is_the_k_lowest_keyed_scores_deterministic_order_independent_and_re_derivable() {
        let members = canonical_members((0..50).map(|i| member(&format!("m{i:02}"), "n@x.com", true)).collect()).unwrap();
        let header = PresentationHeader { account: "me@e".into(), verb: PlanVerb::Trash, tier: "red".into(), count: 50, backup_coverage: true, warning: None };
        let d = PlanDigests::mint(&test_key(), &test_key_ref(), "me@e", "principal@e", PlanVerb::Trash, &members, &header).unwrap();
        let s1 = derive_sample(&test_key(), &d, &members, 5).unwrap();
        let s2 = derive_sample(&test_key(), &d, &members, 5).unwrap();
        assert_eq!(s1, s2, "re-derivation from the stored seed is exact");
        assert_eq!(s1.len(), 5);
        assert!(s1.iter().collect::<BTreeSet<_>>().len() == 5, "distinct");
        assert!(s1.iter().all(|r| members.iter().any(|m| &m.message_ref == r)));
        // effective_k == member_count degenerates honestly to the full member list.
        let all = derive_sample(&test_key(), &d, &members, 50).unwrap();
        assert_eq!(all.len(), 50);
        assert_eq!(all, members.iter().map(|m| m.message_ref.clone()).collect::<Vec<_>>(), "k == count ⇒ every member, in canonical order");
        // A different plan (different presentation ⇒ different seed) samples differently.
        let other_header = PresentationHeader { verb: PlanVerb::MarkSpam, ..header.clone() };
        let d2 = PlanDigests::mint(&test_key(), &test_key_ref(), "me@e", "principal@e", PlanVerb::MarkSpam, &members, &other_header).unwrap();
        assert_ne!(derive_sample(&test_key(), &d2, &members, 5).unwrap(), s1);

        // THE LOWEST k, in ascending-score order: an oracle over every member's score.
        let mut scores: Vec<(u64, String)> = members.iter().map(|m| (member_score(&test_key(), &d, &m.message_ref).unwrap(), m.message_ref.clone())).collect();
        scores.sort();
        assert_eq!(s1, scores[..5].iter().map(|(_, r)| r.clone()).collect::<Vec<_>>(), "the k LOWEST scores, ascending");
        // Order-independent of input: the members handed in reverse canonicalize to the same sample.
        let reversed = canonical_members(members.iter().rev().cloned().collect()).unwrap();
        assert_eq!(derive_sample(&test_key(), &d, &reversed, 5).unwrap(), s1);
        // Every input of the score is live: the stored seed randomizer, the seed tag, the key.
        let mut other_r = d.clone();
        other_r.sample_seed_profile.randomizer = Randomizer::from_bytes(&[7u8; 16]).unwrap().hex();
        assert_ne!(derive_sample(&test_key(), &other_r, &members, 5).unwrap(), s1, "the seed's STORED randomizer is an input");
        let mut other_seed = d.clone();
        other_seed.sample_seed = d2.sample_seed;
        assert_ne!(derive_sample(&test_key(), &other_seed, &members, 5).unwrap(), s1, "the seed tag is an input");
        let other_key = CommitmentKey::from_bytes(&[0x43u8; 48]).unwrap();
        assert_ne!(derive_sample(&other_key, &d, &members, 5).unwrap(), s1, "the score is keyed");
        // k == 0 REFUSES — never an empty sample.
        assert_eq!(derive_sample(&test_key(), &d, &members, 0).unwrap_err(), PlanRefusal::ConfiguredKZero);
        assert_eq!(verify_sample(&test_key(), &d, &members, 0, &[]).unwrap_err(), PlanRefusal::ConfiguredKZero);
    }

    #[test]
    fn the_sample_is_uniform_enough_that_every_member_is_drawn_across_plans() {
        // A smoke check for position bias, not a statistics test: 200 plans over the same 10
        // members, k = 1 — each member is expected ~20 times; P(some member never drawn) is
        // ~10 · 0.9^200 ≈ 7e-9.
        let members = canonical_members((0..10).map(|i| member(&format!("m{i}"), "n@x.com", true)).collect()).unwrap();
        let header = PresentationHeader { account: "me@e".into(), verb: PlanVerb::Trash, tier: "red".into(), count: 10, backup_coverage: true, warning: None };
        let mut drawn: BTreeMap<String, u32> = BTreeMap::new();
        for _ in 0..200 {
            let d = PlanDigests::mint(&test_key(), &test_key_ref(), "me@e", "principal@e", PlanVerb::Trash, &members, &header).unwrap();
            for r in derive_sample(&test_key(), &d, &members, 1).unwrap() {
                *drawn.entry(r).or_insert(0) += 1;
            }
        }
        assert_eq!(drawn.len(), 10, "every member drawn at least once: {drawn:?}");
    }

    #[test]
    fn sample_verification_refuses_count_duplicate_non_member_and_journaled_ne_derived() {
        let members = canonical_members((0..10).map(|i| member(&format!("m{i}"), "n@x.com", true)).collect()).unwrap();
        let header = PresentationHeader { account: "me@e".into(), verb: PlanVerb::Trash, tier: "red".into(), count: 10, backup_coverage: true, warning: None };
        let d = PlanDigests::mint(&test_key(), &test_key_ref(), "me@e", "principal@e", PlanVerb::Trash, &members, &header).unwrap();
        let derived = derive_sample(&test_key(), &d, &members, 3).unwrap();
        assert!(verify_sample(&test_key(), &d, &members, 3, &derived).is_ok());
        assert_eq!(verify_sample(&test_key(), &d, &members, 3, &derived[..2]).unwrap_err(), PlanRefusal::SampleMismatch("count 2 != k 3".into()));
        let dup = vec![derived[0].clone(), derived[0].clone(), derived[1].clone()];
        assert!(matches!(verify_sample(&test_key(), &d, &members, 3, &dup).unwrap_err(), PlanRefusal::SampleMismatch(_)));
        let foreign = vec!["not-a-member".to_string(), derived[1].clone(), derived[2].clone()];
        assert!(matches!(verify_sample(&test_key(), &d, &members, 3, &foreign).unwrap_err(), PlanRefusal::SampleMismatch(_)));
        let mut shuffled = derived.clone();
        shuffled.swap(0, 2);
        assert!(matches!(verify_sample(&test_key(), &d, &members, 3, &shuffled).unwrap_err(), PlanRefusal::SampleMismatch(_)), "order is part of the derived value");
        // A VALID-looking k-subset of members that is simply not the derived one ⇒ refuse.
        let not_derived: Vec<String> = members.iter().map(|m| m.message_ref.clone()).filter(|r| !derived.contains(r)).take(3).collect();
        assert_eq!(verify_sample(&test_key(), &d, &members, 3, &not_derived).unwrap_err(), PlanRefusal::SampleMismatch("journaled sample differs from the derived one".into()));
        // k above the member count: the journaled sample is every member, in canonical order.
        let every: Vec<String> = members.iter().map(|m| m.message_ref.clone()).collect();
        assert!(verify_sample(&test_key(), &d, &members, 25, &every).is_ok());
    }

    #[test]
    fn aggregate_view_commitment_binds_mode_header_shape_sample_and_the_presentation() {
        let members = canonical_members((0..10).map(|i| member(&format!("m{i:02}"), "n@x.com", true)).collect()).unwrap();
        let header = PresentationHeader { account: "me@e".into(), verb: PlanVerb::Trash, tier: "red".into(), count: 10, backup_coverage: false, warning: Some("snapshot recovery is OFF".into()) };
        let d = PlanDigests::mint(&test_key(), &test_key_ref(), "me@e", "principal@e", PlanVerb::Trash, &members, &header).unwrap();
        let sample = derive_sample(&test_key(), &d, &members, 3).unwrap();
        assert_eq!(sample.len(), 3);
        let agg = AggregateRender { header: d.presentation_view.header.clone(), summary: d.presentation_view.summary.clone(), sample_k: 3, sample_rows: sample.iter().map(|r| d.presentation_view.rows.iter().find(|row| &row.message_ref == r).unwrap().clone()).collect() };
        let c1 = view_commitment(&test_key(), &test_key_ref(), &d, &RenderedView::Aggregate(agg.clone())).unwrap();
        assert_eq!(c1, aggregate_view_commitment(&test_key(), &test_key_ref(), &d, &agg).unwrap(), "the aggregate-view commitment is what Aggregate evidence must equal");
        // Evidence claiming a different sample ⇒ a different commitment ⇒ refuse (witness pair).
        let mut other = agg.clone();
        other.sample_rows.swap(0, 1);
        assert_ne!(view_commitment(&test_key(), &test_key_ref(), &d, &RenderedView::Aggregate(other)).unwrap(), c1);
        // PerMember evidence presented against an Aggregate render ⇒ different commitments.
        assert_ne!(c1, d.presentation);
    }

    fn plan_under(lane: AdmissionLane, mode: ApprovalMode, count: usize) -> (TriagePlan, PlanDigests) {
        let members = canonical_members((0..count).map(|i| member(&format!("m{i:02}"), "n@x.com", true)).collect()).unwrap();
        let header = PresentationHeader { account: "me@e".into(), verb: PlanVerb::Trash, tier: "red".into(), count: count as u32, backup_coverage: true, warning: None };
        let d = PlanDigests::mint(&test_key(), &test_key_ref(), "me@e", "principal@e", PlanVerb::Trash, &members, &header).unwrap();
        let plan = TriagePlan {
            plan_id: PlanId("plan-1".into()),
            account: "me@e".into(),
            provider_principal: "principal@e".into(),
            grant_generation: 3,
            control_epoch: 7,
            verb: PlanVerb::Trash,
            rationale: None,
            minted_at: "2026-09-24T00:00:00Z".into(),
            expires_at: "2026-09-25T00:00:00Z".into(),
            members,
            admission_lane: lane,
            approval_mode: mode,
            coverage_generation: 0,
            backups_on: true,
            bypass_notice: None,
            digests: d.clone(),
            key_ref: test_key_ref(),
        };
        (plan, d)
    }

    #[test]
    fn per_member_evidence_admits_only_with_a_positive_decision_and_an_equal_view() {
        let (plan, d) = plan_under(AdmissionLane::PerMember, ApprovalMode::FullList, 3);
        let view = view_commitment(&test_key(), &test_key_ref(), &d, &RenderedView::FullList(d.presentation_view.clone())).unwrap();
        let ok = ApprovalEvidence { plan_id: plan.plan_id.clone(), approver: "clinton".into(), approved_at: "2026-09-24T00:01:00Z".into(), view_digest: view, comprehension: Comprehension::PerMember, decision: Decision::Approved };
        assert!(validate_evidence(&test_key(), &plan, &ok, 0).is_ok());
        let wrong_view = ApprovalEvidence { view_digest: CommitmentTag([0u8; 48]), ..ok.clone() };
        assert_eq!(validate_evidence(&test_key(), &plan, &wrong_view, 0).unwrap_err(), PlanRefusal::ViewMismatch);
        let aggregate_on_per_member = ApprovalEvidence { comprehension: Comprehension::Aggregate { shape_digest: d.shape, sample_k: 1, sample_members: vec!["m00".into()] }, ..ok.clone() };
        assert!(matches!(validate_evidence(&test_key(), &plan, &aggregate_on_per_member, 0).unwrap_err(), PlanRefusal::LaneMismatch { .. }));
        let bypassed_on_per_member = ApprovalEvidence { comprehension: Comprehension::Bypassed { bypass_config_generation: 0 }, ..ok.clone() };
        assert!(matches!(validate_evidence(&test_key(), &plan, &bypassed_on_per_member, 0).unwrap_err(), PlanRefusal::LaneMismatch { .. }));

        // Evidence is minted against ONE plan instance: another plan_id refuses by name.
        let other_plan = ApprovalEvidence { plan_id: PlanId("plan-2".into()), ..ok.clone() };
        assert_eq!(validate_evidence(&test_key(), &plan, &other_plan, 0).unwrap_err(), PlanRefusal::PlanIdMismatch { plan: PlanId("plan-1".into()), evidence: PlanId("plan-2".into()) });
        // A screen lane requires an approver identity (v7 §3: "approver identity").
        let anonymous = ApprovalEvidence { approver: "  ".into(), ..ok.clone() };
        assert_eq!(validate_evidence(&test_key(), &plan, &anonymous, 0).unwrap_err(), PlanRefusal::ApproverMissing);
        // The shape digest is not the presentation digest: PerMember evidence carrying it refuses.
        let shape_as_view = ApprovalEvidence { view_digest: d.shape, ..ok.clone() };
        assert_eq!(validate_evidence(&test_key(), &plan, &shape_as_view, 0).unwrap_err(), PlanRefusal::ViewMismatch);
        // Bypass toggled ON after a screen-lane mint never waives that plan's screen: a bypass
        // generation in force changes nothing for the PerMember lane.
        assert!(validate_evidence(&test_key(), &plan, &ok, 42).is_ok());
    }

    #[test]
    fn aggregate_evidence_admits_only_with_the_derived_sample_and_the_aggregate_view_commitment() {
        let (plan, d) = plan_under(AdmissionLane::Aggregate, ApprovalMode::SummarySample { configured_k: 2, effective_k: 2 }, 6);
        let sample = derive_sample(&test_key(), &d, &plan.members, 2).unwrap();
        let agg = AggregateRender { header: d.presentation_view.header.clone(), summary: d.presentation_view.summary.clone(), sample_k: 2, sample_rows: sample.iter().map(|r| d.presentation_view.rows.iter().find(|x| &x.message_ref == r).unwrap().clone()).collect() };
        let view = aggregate_view_commitment(&test_key(), &test_key_ref(), &d, &agg).unwrap();
        let ok = ApprovalEvidence { plan_id: plan.plan_id.clone(), approver: "clinton".into(), approved_at: "t".into(), view_digest: view, comprehension: Comprehension::Aggregate { shape_digest: d.shape, sample_k: 2, sample_members: sample.clone() }, decision: Decision::Approved };
        assert!(validate_evidence(&test_key(), &plan, &ok, 0).is_ok());
        let wrong_k = ApprovalEvidence { comprehension: Comprehension::Aggregate { shape_digest: d.shape, sample_k: 3, sample_members: sample.clone() }, ..ok.clone() };
        assert_eq!(validate_evidence(&test_key(), &plan, &wrong_k, 0).unwrap_err(), PlanRefusal::SampleKMismatch { plan: 2, evidence: 3 });
        let per_member_on_aggregate = ApprovalEvidence { comprehension: Comprehension::PerMember, view_digest: d.presentation, ..ok.clone() };
        assert!(matches!(validate_evidence(&test_key(), &plan, &per_member_on_aggregate, 0).unwrap_err(), PlanRefusal::LaneMismatch { .. }));

        // A sample that is NOT the derived one — with a view digest honestly computed over THAT
        // render — still refuses: the journal's "sample of k" line is re-derived, never trusted.
        let not_derived: Vec<String> = plan.members.iter().map(|m| m.message_ref.clone()).filter(|r| !sample.contains(r)).take(2).collect();
        let other_agg = AggregateRender { sample_rows: not_derived.iter().map(|r| d.presentation_view.rows.iter().find(|x| &x.message_ref == r).unwrap().clone()).collect(), ..agg.clone() };
        let other_view = aggregate_view_commitment(&test_key(), &test_key_ref(), &d, &other_agg).unwrap();
        let shopped = ApprovalEvidence { view_digest: other_view, comprehension: Comprehension::Aggregate { shape_digest: d.shape, sample_k: 2, sample_members: not_derived }, ..ok.clone() };
        assert_eq!(validate_evidence(&test_key(), &plan, &shopped, 0).unwrap_err(), PlanRefusal::SampleMismatch("journaled sample differs from the derived one".into()));
        // The derived sample, but a view digest over another render (evidence sample X over a
        // render of sample Y — the design's witness pair) ⇒ refuse.
        let x_over_y = ApprovalEvidence { view_digest: other_view, ..ok.clone() };
        assert_eq!(validate_evidence(&test_key(), &plan, &x_over_y, 0).unwrap_err(), PlanRefusal::ViewMismatch);
        // A shape digest that is not the plan's ⇒ refuse.
        let wrong_shape = ApprovalEvidence { comprehension: Comprehension::Aggregate { shape_digest: d.presentation, sample_k: 2, sample_members: sample.clone() }, ..ok.clone() };
        assert_eq!(validate_evidence(&test_key(), &plan, &wrong_shape, 0).unwrap_err(), PlanRefusal::ViewMismatch);
        // An Aggregate LANE whose frozen mode is not summary+sample is itself inconsistent ⇒
        // refuse — by the plan's own shape check, which runs before any evidence is read.
        let (full_mode_plan, _) = plan_under(AdmissionLane::Aggregate, ApprovalMode::FullList, 6);
        let for_full_mode = ApprovalEvidence { plan_id: full_mode_plan.plan_id.clone(), ..ok.clone() };
        assert_eq!(validate_evidence(&test_key(), &full_mode_plan, &for_full_mode, 0).unwrap_err(), PlanRefusal::PlanShape(PlanShapeRule::AggregateLaneRequiresSummarySample));
    }

    #[test]
    fn bypassed_evidence_binds_the_bypass_generation_and_refuses_screen_evidence() {
        let (plan, d) = plan_under(AdmissionLane::Bypassed { bypass_config_generation: 5 }, ApprovalMode::FullList, 2);
        let ok = ApprovalEvidence { plan_id: plan.plan_id.clone(), approver: "mechanical".into(), approved_at: "t".into(), view_digest: d.presentation, comprehension: Comprehension::Bypassed { bypass_config_generation: 5 }, decision: Decision::Approved };
        assert!(validate_evidence(&test_key(), &plan, &ok, 5).is_ok());
        assert_eq!(validate_evidence(&test_key(), &plan, &ok, 6).unwrap_err(), PlanRefusal::BypassGenerationMismatch { plan: 5, current: 6 }, "the bypass config changed since mint ⇒ refuse");
        let screen = ApprovalEvidence { comprehension: Comprehension::PerMember, ..ok.clone() };
        assert!(matches!(validate_evidence(&test_key(), &plan, &screen, 5).unwrap_err(), PlanRefusal::LaneMismatch { .. }));

        // Evidence bound to ANOTHER bypass generation than the plan froze ⇒ lane mismatch, even
        // when that other generation is the one in force now.
        let rebound = ApprovalEvidence { comprehension: Comprehension::Bypassed { bypass_config_generation: 6 }, ..ok.clone() };
        assert!(matches!(validate_evidence(&test_key(), &plan, &rebound, 6).unwrap_err(), PlanRefusal::LaneMismatch { .. }));
        // Aggregate evidence against a bypass lane ⇒ lane mismatch.
        let aggregate = ApprovalEvidence { comprehension: Comprehension::Aggregate { shape_digest: d.shape, sample_k: 1, sample_members: vec!["m00".into()] }, ..ok.clone() };
        assert!(matches!(validate_evidence(&test_key(), &plan, &aggregate, 5).unwrap_err(), PlanRefusal::LaneMismatch { .. }));
        // The bypass lane records that no approver screen existed — no approver is demanded.
        let no_approver = ApprovalEvidence { approver: String::new(), ..ok.clone() };
        assert!(validate_evidence(&test_key(), &plan, &no_approver, 5).is_ok());
    }

    #[test]
    fn the_plan_identity_and_vocabularies_are_closed_and_agree() {
        let a = PlanId::mint().unwrap();
        let b = PlanId::mint().unwrap();
        assert_ne!(a, b, "plan identity is minted from OS entropy, never content-derived");
        assert_eq!(a.0.len(), 32);
        assert!(a.0.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')));
        // The evidence vocabulary spells the lane vocabulary: one token per lane, same order.
        assert_eq!(Comprehension::TOKENS, AdmissionLane::TOKENS);
        let shape = CommitmentTag([1u8; 48]);
        assert_eq!(
            [Comprehension::PerMember.as_token(), Comprehension::Aggregate { shape_digest: shape, sample_k: 1, sample_members: vec![] }.as_token(), Comprehension::Bypassed { bypass_config_generation: 0 }.as_token()],
            Comprehension::TOKENS
        );
        let (plan, _) = plan_under(AdmissionLane::PerMember, ApprovalMode::FullList, 3);
        assert_eq!(plan.count(), 3);
        assert_eq!(plan.tier(), crate::RiskTier::Red);
        assert_eq!(plan.tier(), plan.verb.action("m00").risk_tier(), "the plan's tier IS its verb's tier");
        assert!(plan.member("m01").is_some());
        assert!(plan.member("zz").is_none());
    }

    /// The `attempt.rs` closed-vocabulary guard (`ddl_check_list`), copied: the CHECK list is
    /// read out of the DDL the store actually executes (`store_open::schema_ddl()`), anchored on
    /// the TABLE first and bounded to that table's own statement, so a guard can never read
    /// another table's vocabulary.
    fn ddl_table_section(table: &str) -> String {
        let ddl = crate::store_open::schema_ddl();
        let anchor = format!("CREATE TABLE IF NOT EXISTS {table} (");
        let start = ddl.find(&anchor).unwrap_or_else(|| panic!("schema_ddl() must carry the table {table}"));
        let rest = &ddl[start..];
        let end = rest.find(");").expect("the CREATE TABLE statement terminates");
        rest[..end].to_string()
    }
    fn ddl_check_list(table: &str, anchor: &str) -> Vec<String> {
        let section = ddl_table_section(table);
        let start = section.find(anchor).unwrap_or_else(|| panic!("{table} must carry the CHECK constraint {anchor}"));
        let rest = &section[start + anchor.len()..];
        let end = rest.find("))").expect("the CHECK list must terminate");
        let mut tokens: Vec<String> = rest[..end].split(',').map(|t| t.trim().trim_matches('\'').to_string()).filter(|t| !t.is_empty()).collect();
        tokens.sort();
        tokens
    }

    #[test]
    fn the_plan_vocabularies_match_their_ddl_check_constraints() {
        let sorted = |mut v: Vec<String>| {
            v.sort();
            v
        };
        assert_eq!(sorted(PlanVerb::ALL.iter().map(|v| v.as_token().to_string()).collect()), ddl_check_list("triage_plan", "CHECK (verb IN ("), "PlanVerb and the triage_plan verb CHECK have drifted");
        assert_eq!(sorted(AdmissionLane::TOKENS.iter().map(|t| t.to_string()).collect()), ddl_check_list("triage_plan", "CHECK (admission_lane IN ("), "AdmissionLane and the triage_plan CHECK have drifted");
        assert_eq!(sorted(Comprehension::TOKENS.iter().map(|t| t.to_string()).collect()), ddl_check_list("approval_evidence", "CHECK (comprehension IN ("), "Comprehension and the approval_evidence CHECK have drifted");
        assert_eq!(sorted(ApprovalMode::TOKENS.iter().map(|t| t.to_string()).collect()), ddl_check_list("triage_plan", "CHECK (approval_mode IN ("), "ApprovalMode and the triage_plan CHECK have drifted");
        assert_eq!(
            ApprovalMode::TOKENS,
            [ApprovalMode::FullList.as_token(), ApprovalMode::SummarySample { configured_k: 1, effective_k: 1 }.as_token()]
        );
        // The two single-value CHECKs spell the core's own constants.
        assert!(ddl_table_section("triage_plan").contains(&format!("CHECK (tier = '{PLAN_TIER}')")), "the tier CHECK spells PLAN_TIER");
        assert!(ddl_table_section("approval_evidence").contains(&format!("CHECK (decision = '{}')", Decision::Approved.as_token())), "the decision CHECK spells Decision::Approved");
    }

    #[test]
    fn a_header_naming_another_tier_than_red_is_refused_at_mint() {
        // Every plan verb is RED (`TriagePlan::tier`); a presentation header reading any other
        // tier would show the human a tier the plan does not carry.
        let members = canonical_members(vec![member("a", "n@x.com", true)]).unwrap();
        let red = PresentationHeader { account: "me@e".into(), verb: PlanVerb::Trash, tier: PLAN_TIER.into(), count: 1, backup_coverage: true, warning: None };
        assert_eq!(PLAN_TIER, "red");
        assert!(PlanDigests::mint(&test_key(), &test_key_ref(), "me@e", "principal@e", PlanVerb::Trash, &members, &red).is_ok());
        for other in ["yellow", "RED", ""] {
            let header = PresentationHeader { tier: other.into(), ..red.clone() };
            assert_eq!(PlanDigests::mint(&test_key(), &test_key_ref(), "me@e", "principal@e", PlanVerb::Trash, &members, &header).unwrap_err(), PlanRefusal::HeaderDiverges(HeaderField::Tier), "tier '{other}'");
        }
    }

    #[test]
    fn validate_shape_refuses_every_self_disagreement_by_name_and_validate_evidence_runs_it_first() {
        let shape = |p: &TriagePlan| p.validate_shape();
        let (good, _) = plan_under(AdmissionLane::PerMember, ApprovalMode::FullList, 3);
        assert_eq!(shape(&good), Ok(()));
        // One mutation per rule.
        let mut p = good.clone();
        p.members.pop();
        assert_eq!(shape(&p), Err(PlanRefusal::PlanShape(PlanShapeRule::MemberCountIsNotHeaderCount)));
        let mut p = good.clone();
        p.members[1].display.subject = "not what the header's rows show".into();
        assert_eq!(shape(&p), Err(PlanRefusal::PresentationRowDiverges("m01".into())), "the presentation rows are the members' own");
        let mut p = good.clone();
        p.verb = PlanVerb::MarkSpam;
        assert_eq!(shape(&p), Err(PlanRefusal::PlanShape(PlanShapeRule::VerbIsNotHeaderVerb)));
        let mut p = good.clone();
        p.account = "other@e".into();
        assert_eq!(shape(&p), Err(PlanRefusal::PlanShape(PlanShapeRule::AccountIsNotHeaderAccount)));
        let mut p = good.clone();
        p.digests.presentation_view.header.tier = "yellow".into();
        assert_eq!(shape(&p), Err(PlanRefusal::PlanShape(PlanShapeRule::HeaderTierIsNotRed)));
        let mut p = good.clone();
        p.key_ref = CommitmentKeyRef::new("photon.account.other@e", 1).unwrap();
        assert_eq!(shape(&p), Err(PlanRefusal::PlanShape(PlanShapeRule::KeyRefIsNotDigestsKeyRef)));
        let mut p = good.clone();
        p.backups_on = false;
        assert_eq!(shape(&p), Err(PlanRefusal::PlanShape(PlanShapeRule::BackupsOnIsNotHeaderCoverage)));
        // lane ↔ mode.
        let (p, _) = plan_under(AdmissionLane::PerMember, ApprovalMode::SummarySample { configured_k: 2, effective_k: 2 }, 3);
        assert_eq!(shape(&p), Err(PlanRefusal::PlanShape(PlanShapeRule::PerMemberLaneRequiresFullList)));
        let (p, _) = plan_under(AdmissionLane::Aggregate, ApprovalMode::FullList, 3);
        assert_eq!(shape(&p), Err(PlanRefusal::PlanShape(PlanShapeRule::AggregateLaneRequiresSummarySample)));
        for mode in [ApprovalMode::FullList, ApprovalMode::SummarySample { configured_k: 2, effective_k: 2 }] {
            let (p, _) = plan_under(AdmissionLane::Bypassed { bypass_config_generation: 4 }, mode, 3);
            assert_eq!(shape(&p), Ok(()), "the bypass lane admits either frozen mode: {mode:?}");
        }
        // effective_k recomputed: min(configured_k, member count), never a stored free value.
        let (p, _) = plan_under(AdmissionLane::Aggregate, ApprovalMode::SummarySample { configured_k: 5, effective_k: 3 }, 3);
        assert_eq!(shape(&p), Ok(()), "min(5, 3) = 3");
        let (p, _) = plan_under(AdmissionLane::Aggregate, ApprovalMode::SummarySample { configured_k: 5, effective_k: 2 }, 3);
        assert_eq!(shape(&p), Err(PlanRefusal::PlanShape(PlanShapeRule::EffectiveKIsNotMin)));
        let (p, _) = plan_under(AdmissionLane::Aggregate, ApprovalMode::SummarySample { configured_k: 2, effective_k: 3 }, 3);
        assert_eq!(shape(&p), Err(PlanRefusal::PlanShape(PlanShapeRule::EffectiveKIsNotMin)));
        let (p, _) = plan_under(AdmissionLane::Aggregate, ApprovalMode::SummarySample { configured_k: 0, effective_k: 0 }, 3);
        assert_eq!(shape(&p), Err(PlanRefusal::ConfiguredKZero));
        // validate_evidence runs the shape check FIRST: evidence that would otherwise admit
        // (PerMember, the right view) refuses on a malformed plan.
        let (plan, d) = plan_under(AdmissionLane::PerMember, ApprovalMode::FullList, 3);
        let ok = ApprovalEvidence { plan_id: plan.plan_id.clone(), approver: "clinton".into(), approved_at: "t".into(), view_digest: d.presentation, comprehension: Comprehension::PerMember, decision: Decision::Approved };
        assert!(validate_evidence(&test_key(), &plan, &ok, 0).is_ok());
        let mut malformed = plan.clone();
        malformed.backups_on = false;
        assert_eq!(validate_evidence(&test_key(), &malformed, &ok, 0).unwrap_err(), PlanRefusal::PlanShape(PlanShapeRule::BackupsOnIsNotHeaderCoverage));
    }

    #[test]
    fn the_bypass_notice_is_frozen_only_on_an_uncovered_bypass_plan_and_is_the_verb_warning() {
        // The notice a mint freezes (`TriagePlan::bypass_notice_for`), and the plan's
        // own shape rule over a stored one.
        let bypassed = AdmissionLane::Bypassed { bypass_config_generation: 4 };
        for verb in PlanVerb::ALL {
            assert_eq!(TriagePlan::bypass_notice_for(verb, bypassed, false).as_deref(), Some(verb.uncovered_warning()), "{verb:?}");
            assert_eq!(TriagePlan::bypass_notice_for(verb, bypassed, true), None, "{verb:?}: covered, no notice");
            for lane in [AdmissionLane::PerMember, AdmissionLane::Aggregate] {
                for backups_on in [false, true] {
                    assert_eq!(TriagePlan::bypass_notice_for(verb, lane, backups_on), None, "{verb:?} {lane:?}: a screen lane never gets one");
                }
            }
        }
        // An uncovered bypass plan: the notice, or its absence (a row an earlier build minted), reads
        // back; a notice that is not the verb's warning does not.
        let (mut uncovered, _) = plan_under(bypassed, ApprovalMode::FullList, 2);
        uncovered.backups_on = false;
        uncovered.digests.presentation_view.header.backup_coverage = false;
        assert_eq!(uncovered.validate_shape(), Ok(()), "absent: the fence's refusal, not a shape error");
        uncovered.bypass_notice = Some(PlanVerb::Trash.uncovered_warning().to_string());
        assert_eq!(uncovered.validate_shape(), Ok(()));
        uncovered.bypass_notice = Some(PlanVerb::MarkSpam.uncovered_warning().to_string());
        assert_eq!(uncovered.validate_shape(), Err(PlanRefusal::PlanShape(PlanShapeRule::BypassNoticeIsNotTheVerbWarning)));
        // A notice on a covered bypass plan, or on a screen-lane plan, is a plan that disagrees with itself.
        let (mut covered, _) = plan_under(bypassed, ApprovalMode::FullList, 2);
        covered.bypass_notice = Some(PlanVerb::Trash.uncovered_warning().to_string());
        assert_eq!(covered.validate_shape(), Err(PlanRefusal::PlanShape(PlanShapeRule::BypassNoticeOutsideAnUncoveredBypassPlan)));
        let (mut screen, _) = plan_under(AdmissionLane::PerMember, ApprovalMode::FullList, 2);
        screen.backups_on = false;
        screen.digests.presentation_view.header.backup_coverage = false;
        screen.bypass_notice = Some(PlanVerb::Trash.uncovered_warning().to_string());
        assert_eq!(screen.validate_shape(), Err(PlanRefusal::PlanShape(PlanShapeRule::BypassNoticeOutsideAnUncoveredBypassPlan)));
    }

    #[test]
    fn a_named_sender_counts_under_its_address_domain() {
        // The store half freezes `sender` as `Name <addr>` when the header carries a display
        // name, and (-1) the summary's domain is the PARSED sender's — the
        // header row's RFC 5322 parse, frozen beside the display — never a search of the display
        // text: not `amazon.com>`, and not whatever a `<…>` or an `@` in a display name spells.
        let with = |r: &str, display: &str, addr: &str| {
            let mut m = member(r, addr, true);
            m.display.sender = display.to_string();
            m
        };
        let named = with("a", "Amazon <Deals@Amazon.com>", "Deals@Amazon.com");
        let bare = with("b", "news@amazon.com", "news@amazon.com");
        let tricky = with("c", "a@evil.test <bob@y.org>", "bob@y.org");
        let comment = with("d", "Notice <real@evil.example> (routing note <billing@trusted.example>)", "real@evil.example");
        let members = canonical_members(vec![named, bare, tricky, comment]).unwrap();
        let header = PresentationHeader { account: "me@e".into(), verb: PlanVerb::Trash, tier: "red".into(), count: 4, backup_coverage: true, warning: None };
        let p = derive_presentation(&header, &members).unwrap();
        assert_eq!(
            p.summary.sender_domains,
            vec![("amazon.com".to_string(), 2), ("evil.example".to_string(), 1), ("y.org".to_string(), 1)]
        );
        assert_eq!((p.summary.sender_domain_unavailable, p.summary.sender_header_malformed), (0, 0));
    }

    /// (-1): an unparsed sender is never a domain entry — it is counted, by
    /// why, in its own summary field.
    #[test]
    fn an_unavailable_or_malformed_sender_is_counted_never_a_domain_entry() {
        let mut empty = member("b", "", true);
        empty.display.sender_parse = FrozenSender::Unavailable;
        let bad = member("c", "<a@x.example> <b@y.example>", true);
        assert_eq!(bad.display.sender_parse, FrozenSender::Malformed);
        let members = canonical_members(vec![member("a", "real@evil.example", true), empty, bad]).unwrap();
        let header = PresentationHeader { account: "me@e".into(), verb: PlanVerb::Trash, tier: "red".into(), count: 3, backup_coverage: true, warning: None };
        let p = derive_presentation(&header, &members).unwrap();
        assert_eq!(p.summary.sender_domains, vec![("evil.example".to_string(), 1)]);
        assert_eq!(p.summary.sender_domain_unavailable, 1);
        assert_eq!(p.summary.sender_header_malformed, 1);
    }

    /// (-1): the new fields are members of the canonical presentation, so the
    /// presentation DIGEST covers them by construction — a member whose parsed domain moved (its
    /// display text and every row held), or whose sender moved between parsed, unavailable and
    /// malformed, re-derives a different digest under the plan's own key and randomizer, while the
    /// unchanged presentation re-derives the same one.
    #[test]
    fn a_changed_domain_changes_the_presentation_digest_with_every_row_held() {
        let a = member("a", "real@evil.example", true);
        let header = PresentationHeader { account: "me@e".into(), verb: PlanVerb::Trash, tier: PLAN_TIER.into(), count: 1, backup_coverage: true, warning: None };
        let d = PlanDigests::mint(&test_key(), &test_key_ref(), "me@e", "principal@e", PlanVerb::Trash, std::slice::from_ref(&a), &header).unwrap();
        let tag_of = |p: &PlanPresentation| {
            let bytes = encode_presentation(p, &d.set.hex(), &d.state.hex()).unwrap();
            d.presentation_tag_over(&test_key(), &test_key_ref(), &bytes).unwrap()
        };
        assert_eq!(tag_of(&d.presentation_view), d.presentation, "the unchanged presentation re-derives the minted digest");
        let mut tags = Vec::new();
        for moved in [
            FrozenSender::Parsed { addr: "real@evil.example".into(), local: "real".into(), domain: "trusted.example".into() },
            FrozenSender::Unavailable,
            FrozenSender::Malformed,
        ] {
            let mut b = a.clone();
            b.display.sender_parse = moved.clone();
            let p = derive_presentation(&header, &[b]).unwrap();
            // CHANGED expectation — `sender_status` is NOW part of the
            // row (the renderer shows it outside the address isolate), so it moves
            // WITH the sender_parse change; every OTHER row field still holds.
            assert_eq!(
                p.rows[0].sender_status,
                moved.status().as_token(),
                "{moved:?}: the row's own status moves with the frozen sender"
            );
            let held = |r: &PresentationRow| {
                (r.message_ref.clone(), r.sender.clone(), r.sender_address.clone(), r.subject.clone(), r.date.clone(), r.size)
            };
            assert_eq!(held(&p.rows[0]), held(&d.presentation_view.rows[0]), "{moved:?}: every OTHER row field held");
            assert_ne!(tag_of(&p), d.presentation, "{moved:?}: a different presentation digest");
            tags.push(tag_of(&p));
        }
        // Unavailable and malformed have the SAME (empty) domain list: only the two counts tell them
        // apart, so their digests differ only because the counts are committed.
        assert_ne!(tags[1], tags[2], "an unavailable sender and a malformed one are different presentations");
    }

    /// (/P-D): the address half is its OWN frozen field, IN THE
    /// DIGEST — changing it changes the digest with the name half held. The isolate split this
    /// class closes is a render-time fix over data that must already be split at mint; this pins
    /// the data half with the own construction: a quoted display NAME carrying a fake
    /// bracketed address of its own, frozen beside the REAL address.
    #[test]
    fn a_changed_sender_address_changes_the_digest_with_the_name_held() {
        let mut a = member("a", "real@evil.example", true);
        a.display.sender = "א <billing@paypal.example> ב".to_string();
        a.display.sender_address = "<real@evil.example>".to_string();
        let header = PresentationHeader { account: "me@e".into(), verb: PlanVerb::Trash, tier: PLAN_TIER.into(), count: 1, backup_coverage: true, warning: None };
        let d = PlanDigests::mint(&test_key(), &test_key_ref(), "me@e", "principal@e", PlanVerb::Trash, std::slice::from_ref(&a), &header).unwrap();
        let tag_of = |p: &PlanPresentation| {
            let bytes = encode_presentation(p, &d.set.hex(), &d.state.hex()).unwrap();
            d.presentation_tag_over(&test_key(), &test_key_ref(), &bytes).unwrap()
        };
        assert_eq!(d.presentation_view.rows[0].sender, "א <billing@paypal.example> ב");
        assert_eq!(
            d.presentation_view.rows[0].sender_address, "<real@evil.example>",
            "the ADDRESS isolate's text is the real address, bracketed — never the name's fake one"
        );
        assert!(
            !d.presentation_view.rows[0].sender_address.contains("billing@paypal.example"),
            "the address isolate never contains the name's fake address"
        );
        let mut b = a.clone();
        b.display.sender_address = "<other@evil.example>".to_string();
        let p = derive_presentation(&header, &[b]).unwrap();
        assert_eq!(p.rows[0].sender, a.display.sender, "the name half is held");
        assert_ne!(tag_of(&p), d.presentation, "a changed address changes the digest with the name held");
    }

    /// `sender_local` and `sender_domain` are IN THE DIGEST —
    /// `encode_row` used to frame `sender`/`sender_address`/`subject`/`date`/`size` and NOTHING
    /// else, so a forged row could carry a different structured local-part or domain (of the same
    /// `sender_address` display text) and still verify. Changing either, alone, changes the tag.
    #[test]
    fn the_digest_binds_sender_local_and_sender_domain() {
        let a = member("a", "real@evil.example", true);
        let header = PresentationHeader { account: "me@e".into(), verb: PlanVerb::Trash, tier: PLAN_TIER.into(), count: 1, backup_coverage: true, warning: None };
        let d = PlanDigests::mint(&test_key(), &test_key_ref(), "me@e", "principal@e", PlanVerb::Trash, std::slice::from_ref(&a), &header).unwrap();
        let tag_of = |p: &PlanPresentation| {
            let bytes = encode_presentation(p, &d.set.hex(), &d.state.hex()).unwrap();
            d.presentation_tag_over(&test_key(), &test_key_ref(), &bytes).unwrap()
        };
        assert_eq!(d.presentation_view.rows[0].sender_local, "real");
        assert_eq!(d.presentation_view.rows[0].sender_domain, "evil.example");

        let mut local_changed = d.presentation_view.clone();
        local_changed.rows[0].sender_local = "other".to_string();
        assert_ne!(tag_of(&local_changed), d.presentation, "a changed sender_local (address/domain held) changes the digest");

        let mut domain_changed = d.presentation_view.clone();
        domain_changed.rows[0].sender_domain = "other.example".to_string();
        assert_ne!(tag_of(&domain_changed), d.presentation, "a changed sender_domain (address/local held) changes the digest");
    }

    /// A presentation carrying a value in EVERY header and summary frame
    /// (coverage off with its warning, two sender domains), its digests, and one mutation per
    /// approval-bound frame — each changing exactly that field, every other frame and every row
    /// held — so each frame is witnessed ALONE.
    fn every_frame_presentation() -> (PlanPresentation, PlanDigests) {
        let members = canonical_members(vec![member("a", "n@x.com", true), member("b", "bob@y.org", true)]).unwrap();
        let header = PresentationHeader { account: "me@e".into(), verb: PlanVerb::Trash, tier: PLAN_TIER.into(), count: 2, backup_coverage: false, warning: Some("snapshot recovery is OFF".into()) };
        let d = PlanDigests::mint(&test_key(), &test_key_ref(), "me@e", "principal@e", PlanVerb::Trash, &members, &header).unwrap();
        (d.presentation_view.clone(), d)
    }
    type FrameVariant = (&'static str, fn(&mut PresentationHeader, &mut PresentationSummary));
    fn bound_frame_variants() -> [FrameVariant; 15] {
        [
            ("header.account", |h, _| h.account = "other@e".into()),
            ("header.verb", |h, _| h.verb = PlanVerb::MarkSpam),
            ("header.tier", |h, _| h.tier = "yellow".into()),
            ("header.count", |h, _| h.count = 3),
            ("header.backup_coverage", |h, _| h.backup_coverage = true),
            ("header.warning", |h, _| h.warning = Some("a softer warning".into())),
            ("summary.count", |_, s| s.count = 3),
            ("summary.sender_domains (a domain)", |_, s| s.sender_domains[0].0 = "z.example".into()),
            ("summary.sender_domains (a domain's count)", |_, s| s.sender_domains[0].1 += 1),
            // (-1): the two counts the review says out loud.
            ("summary.sender_domain_unavailable", |_, s| s.sender_domain_unavailable += 1),
            ("summary.sender_header_malformed", |_, s| s.sender_header_malformed += 1),
            ("summary.sender_header_unsupported", |_, s| s.sender_header_unsupported += 1),
            ("summary.date_min", |_, s| s.date_min = "2026-09-23T00:00:00Z".into()),
            ("summary.date_max", |_, s| s.date_max = "2026-09-25T00:00:00Z".into()),
            ("summary.total_size", |_, s| s.total_size = Some(1024)),
        ]
    }

    #[test]
    fn every_approval_bound_header_and_summary_field_is_inside_the_presentation_and_shape_bytes_each_varied_alone() {
        let (p, _) = every_frame_presentation();
        let base = encode_presentation(&p, "setdigest", "statedigest").unwrap();
        let base_shape = encode_shape(&p).unwrap();
        for (field, vary) in bound_frame_variants() {
            let mut q = p.clone();
            vary(&mut q.header, &mut q.summary);
            assert_ne!((&q.header, &q.summary), (&p.header, &p.summary), "{field}: the variant changes its field");
            assert_eq!(q.rows, p.rows, "{field}: every row held");
            assert_ne!(encode_presentation(&q, "setdigest", "statedigest").unwrap(), base, "{field} is inside the presentation bytes");
            assert_ne!(encode_shape(&q).unwrap(), base_shape, "{field} is inside the shape bytes");
        }
    }

    #[test]
    fn every_approval_bound_header_and_summary_field_is_inside_the_aggregate_view_bytes_each_varied_alone() {
        let (p, d) = every_frame_presentation();
        let agg = AggregateRender { header: p.header.clone(), summary: p.summary.clone(), sample_k: 1, sample_rows: vec![p.rows[0].clone()] };
        let base = encode_aggregate_view(&d, &agg).unwrap();
        for (field, vary) in bound_frame_variants() {
            let mut q = agg.clone();
            vary(&mut q.header, &mut q.summary);
            assert_ne!(encode_aggregate_view(&d, &q).unwrap(), base, "{field} is inside the aggregate-view bytes");
        }
        // The aggregate's own frames, each varied alone too: k, the sampled rows, the shape tag and
        // the presentation tag; the mode frame is a constant inside the bytes.
        assert_ne!(encode_aggregate_view(&d, &AggregateRender { sample_k: 2, ..agg.clone() }).unwrap(), base, "sample_k");
        assert_ne!(encode_aggregate_view(&d, &AggregateRender { sample_rows: vec![p.rows[1].clone()], ..agg.clone() }).unwrap(), base, "the sampled rows");
        let mut other_shape = d.clone();
        other_shape.shape = CommitmentTag([0u8; 48]);
        assert_ne!(encode_aggregate_view(&other_shape, &agg).unwrap(), base, "the shape tag");
        let mut other_presentation = d.clone();
        other_presentation.presentation = CommitmentTag([0u8; 48]);
        assert_ne!(encode_aggregate_view(&other_presentation, &agg).unwrap(), base, "the presentation tag");
        assert!(base.windows(b"mode:aggregate".len()).any(|w| w == b"mode:aggregate"), "the mode frame");
    }

    #[test]
    fn bypassed_evidence_binds_the_presentation_as_its_view() {
        // The bypass lane has no screen, so its `view_digest` is the plan's own presentation
        // digest (the store half sets it so) — a foreign value is refused, never ignored.
        let (plan, d) = plan_under(AdmissionLane::Bypassed { bypass_config_generation: 5 }, ApprovalMode::FullList, 2);
        let ok = ApprovalEvidence { plan_id: plan.plan_id.clone(), approver: String::new(), approved_at: "t".into(), view_digest: d.presentation, comprehension: Comprehension::Bypassed { bypass_config_generation: 5 }, decision: Decision::Approved };
        assert!(validate_evidence(&test_key(), &plan, &ok, 5).is_ok());
        for foreign in [d.shape, d.set, CommitmentTag([0u8; 48])] {
            let evidence = ApprovalEvidence { view_digest: foreign, ..ok.clone() };
            assert_eq!(validate_evidence(&test_key(), &plan, &evidence, 5).unwrap_err(), PlanRefusal::ViewMismatch);
        }
    }

    // ── (D4): the send-admission vocabulary and the refusal-payload codec ──────

    /// One value of EVERY `PlanRefusal` variant — each static rule and field once — and of every
    /// `CommitmentError`, lane and comprehension shape through them.
    fn every_plan_refusal() -> Vec<PlanRefusal> {
        let mut all = vec![
            PlanRefusal::EmptyMembers,
            PlanRefusal::ConflictingDuplicate("m1".into()),
            PlanRefusal::HeaderCountMismatch { header: 2, members: 3 },
            PlanRefusal::PresentationRowCount { rows: 1, members: 2 },
            PlanRefusal::PresentationRowDiverges("m2".into()),
            PlanRefusal::ConfiguredKZero,
            PlanRefusal::PlanIdMismatch { plan: PlanId("a".repeat(32)), evidence: PlanId("b".repeat(32)) },
            PlanRefusal::ApproverMissing,
            PlanRefusal::ViewMismatch,
            PlanRefusal::SampleMismatch("duplicate member in sample".into()),
            PlanRefusal::SampleKMismatch { plan: 3, evidence: 2 },
            PlanRefusal::BypassGenerationMismatch { plan: 4, current: 9 },
            PlanRefusal::UnknownVerb("delete".into()),
        ];
        all.extend(PlanShapeRule::ALL.iter().copied().map(PlanRefusal::PlanShape));
        all.extend(WarningShapeRule::ALL.iter().copied().map(PlanRefusal::WarningShape));
        all.extend(HeaderField::ALL.iter().copied().map(PlanRefusal::HeaderDiverges));
        let mut errors = vec![
            CommitmentError::KeyLength(47),
            CommitmentError::RandomizerLength(15),
            CommitmentError::RandomizerHex,
            CommitmentError::TagHex,
            CommitmentError::KeyHex,
            CommitmentError::KeyEpochZero,
            CommitmentError::KeyEpochTooLarge(u64::MAX),
            CommitmentError::FrameTooLong(usize::MAX),
            CommitmentError::EntropyUnavailable,
        ];
        errors.extend(crate::commitment::IdShapeField::ALL.iter().copied().map(CommitmentError::IdShape));
        all.extend(errors.into_iter().map(PlanRefusal::Commitment));
        let tag = CommitmentTag([7u8; 48]);
        for plan in [AdmissionLane::PerMember, AdmissionLane::Aggregate, AdmissionLane::Bypassed { bypass_config_generation: 5 }] {
            for evidence in [
                Comprehension::PerMember,
                Comprehension::Aggregate { shape_digest: tag, sample_k: 2, sample_members: vec!["m1".into(), "m2".into()] },
                Comprehension::Bypassed { bypass_config_generation: 6 },
            ] {
                all.push(PlanRefusal::LaneMismatch { plan, evidence });
            }
        }
        all
    }

    fn every_plan_send_refusal() -> Vec<PlanSendRefusal> {
        use crate::episode::EpisodeStatusToken as T;
        let mut all = vec![
            PlanSendRefusal::EpisodeHeld(T::Paused),
            PlanSendRefusal::NotReady,
            PlanSendRefusal::NoEpisode,
            PlanSendRefusal::PlanEpochMismatch { plan: 1, current: -2 },
            PlanSendRefusal::Expired { expires_at: "2026-09-24T01:00:00Z".into(), effective_now: "2099-01-01T00:00:00Z".into() },
            PlanSendRefusal::NotAMember,
            PlanSendRefusal::EvidenceAbsent,
            PlanSendRefusal::GrantRetired(GrantDenial::Retired { generation: 1, high_water: 2 }),
            PlanSendRefusal::GrantRetired(GrantDenial::PrincipalMismatch),
            PlanSendRefusal::GrantRetired(GrantDenial::Unavailable),
            PlanSendRefusal::CoverageDiverged { plan: 3, current: 5 },
            PlanSendRefusal::SnapshotAbsent,
            PlanSendRefusal::BypassNoticeAbsent,
            PlanSendRefusal::CaptureRequired,
            PlanSendRefusal::StateDiverged { diff: vec![crate::attempt::MemberDiff { atom: "membership:INBOX".into(), expected: true, observed: None }] },
        ];
        all.extend([T::Cancelled, T::Completed, T::Invalidated].into_iter().map(PlanSendRefusal::EpisodeClosed));
        all.extend(every_plan_refusal().into_iter().map(PlanSendRefusal::EvidenceInvalid));
        all
    }

    #[test]
    fn every_plan_send_refusal_has_one_closed_token_its_terminality_and_its_pre_send_reason() {
        use crate::attempt::PreSendReason;
        let all = every_plan_send_refusal();
        let tokens: BTreeSet<&str> = all.iter().map(PlanSendRefusal::token).collect();
        assert_eq!(tokens, PlanSendRefusal::TOKENS.iter().copied().collect::<BTreeSet<_>>(), "every variant's token, and only those");
        assert_eq!(PlanSendRefusal::TOKENS.len(), PlanSendRefusal::TOKENS.iter().collect::<BTreeSet<_>>().len(), "no token twice");
        for r in &all {
            let held = matches!(r, PlanSendRefusal::EpisodeHeld(_) | PlanSendRefusal::NotReady | PlanSendRefusal::GrantRetired(GrantDenial::Unavailable));
            assert_eq!(r.is_terminal(), !held, "{r:?}");
            let stale = matches!(r, PlanSendRefusal::StateDiverged { .. });
            assert_eq!(r.pre_send_reason(), if stale { PreSendReason::StaleNotAttempted } else { PreSendReason::PlanRefused }, "{r:?}");
        }
    }

    #[test]
    fn every_plan_send_refusal_rebuilds_from_its_record_and_a_record_the_writer_cannot_produce_is_refused() {
        for r in every_plan_send_refusal() {
            let rec = r.record("m1");
            assert_eq!(rec.reason, r.token());
            assert_eq!(rec.member_ref, "m1");
            assert_eq!(!rec.diff.is_empty(), matches!(r, PlanSendRefusal::StateDiverged { .. }), "{r:?}");
            assert_eq!(PlanSendRefusal::from_record(&rec).as_ref(), Ok(&r), "{rec:?}");
        }
        let good = PlanSendRefusal::CoverageDiverged { plan: 3, current: 5 }.record("m1");
        let refused = |rec: crate::attempt::PlanRefusalRecord| PlanSendRefusal::from_record(&rec).unwrap_err();
        // An unknown token, a missing payload, an extra key, a payload on a payload-free token, a
        // diff on a non-state refusal, a rule token this build does not write.
        assert!(refused(crate::attempt::PlanRefusalRecord { reason: "no_such".into(), ..good.clone() }).contains("no_such"));
        refused(crate::attempt::PlanRefusalRecord { detail: None, ..good.clone() });
        refused(crate::attempt::PlanRefusalRecord { detail: Some(serde_json::json!({ "plan": 3, "current": 5, "extra": 1 }).to_string()), ..good.clone() });
        refused(crate::attempt::PlanRefusalRecord { detail: Some(serde_json::json!({ "plan": 3 }).to_string()), ..PlanSendRefusal::SnapshotAbsent.record("m1") });
        refused(crate::attempt::PlanRefusalRecord { diff: vec![crate::attempt::MemberDiff { atom: "a".into(), expected: true, observed: None }], ..good.clone() });
        refused(crate::attempt::PlanRefusalRecord {
            detail: Some(serde_json::json!({ "kind": "plan_shape", "rule": "a rule no writer spells" }).to_string()),
            ..PlanSendRefusal::EvidenceInvalid(PlanRefusal::ViewMismatch).record("m1")
        });
        refused(crate::attempt::PlanRefusalRecord { detail: Some("not json".into()), ..good });
    }

    #[test]
    fn every_closed_detail_vocabulary_round_trips_and_its_durable_spellings_are_pinned() {
        // The rule and field payloads a refusal record carries are closed
        // enums (`closed_tokens!`), so a variant is written as its token and read back through
        // `from_token`. The spellings are a STORED format — pinned here, literally, so re-spelling
        // one fails this test instead of silently making every record that carries it unreadable.
        fn pinned<T: Copy + PartialEq + std::fmt::Debug>(all: &[T], as_token: fn(T) -> &'static str, from_token: fn(&str) -> Option<T>, spellings: &[&str]) {
            assert_eq!(all.iter().map(|t| as_token(*t)).collect::<Vec<_>>(), spellings, "the durable spellings");
            for t in all {
                assert_eq!(from_token(as_token(*t)), Some(*t), "{t:?} round-trips");
            }
            assert_eq!(from_token("not_a_token_this_build_writes"), None);
        }
        pinned(
            PlanShapeRule::ALL,
            PlanShapeRule::as_token,
            PlanShapeRule::from_token,
            &[
                "member_count_is_not_header_count",
                "verb_is_not_header_verb",
                "account_is_not_header_account",
                "header_tier_is_not_red",
                "key_ref_is_not_digests_key_ref",
                "backups_on_is_not_header_coverage",
                "per_member_lane_requires_full_list",
                "aggregate_lane_requires_summary_sample",
                "effective_k_is_not_min",
                "bypass_notice_outside_an_uncovered_bypass_plan",
                "bypass_notice_is_not_the_verb_warning",
            ],
        );
        pinned(
            WarningShapeRule::ALL,
            WarningShapeRule::as_token,
            WarningShapeRule::from_token,
            &["coverage_on_carries_no_warning", "coverage_off_requires_the_verb_warning", "the_warning_is_never_empty"],
        );
        pinned(HeaderField::ALL, HeaderField::as_token, HeaderField::from_token, &["account", "verb", "tier"]);
        pinned(
            crate::commitment::IdShapeField::ALL,
            crate::commitment::IdShapeField::as_token,
            crate::commitment::IdShapeField::from_token,
            &["namespace_key_id", "source_kind", "account"],
        );
    }

    #[test]
    fn every_grant_denial_record_is_content_free_and_round_trips() {
        // The grant row's refusal is `GrantDenial`, which has no
        // `String` field — so for EVERY variant the serialized record carries no `@` (no provider
        // principal can ride it), the detail is exactly the token (plus the two generations for
        // `retired`), and `from_record` returns the same refusal.
        use serde_json::json;
        let every = [
            (GrantDenial::Retired { generation: 3, high_water: 7 }, json!({ "kind": "retired", "generation": 3, "high_water": 7 })),
            (GrantDenial::PrincipalMismatch, json!({ "kind": "principal_mismatch" })),
            (GrantDenial::Unavailable, json!({ "kind": "unavailable" })),
        ];
        for (denial, detail) in every {
            let refusal = PlanSendRefusal::GrantRetired(denial);
            let rec = refusal.record("msg-1");
            let serialized = serde_json::to_string(&rec).unwrap();
            assert!(!serialized.contains('@'), "{denial:?}: {serialized}");
            assert_eq!(serde_json::from_str::<serde_json::Value>(rec.detail.as_deref().unwrap()).unwrap(), detail, "{denial:?}");
            assert_eq!(PlanSendRefusal::from_record(&rec), Ok(refusal), "{denial:?}");
        }
    }

    #[test]
    fn from_record_refuses_an_unknown_detail_token_by_name() {
        // Every closed token inside `detail` is read back through its enum's
        // `from_token`, and a token this build does not write is refused NAMING that token —
        // never a guessed refusal, never a bare "does not read back".
        use serde_json::json;
        let rec = |reason: &str, detail: serde_json::Value| crate::attempt::PlanRefusalRecord { reason: reason.into(), member_ref: "m1".into(), diff: vec![], detail: Some(detail.to_string()) };
        let cases = [
            (rec("evidence_invalid", json!({ "kind": "plan_shape", "rule": "a_rule_no_writer_spells" })), "a_rule_no_writer_spells"),
            (rec("evidence_invalid", json!({ "kind": "warning_shape", "rule": "no_such_warning_rule" })), "no_such_warning_rule"),
            (rec("evidence_invalid", json!({ "kind": "header_diverges", "field": "no_such_header_field" })), "no_such_header_field"),
            (rec("evidence_invalid", json!({ "kind": "commitment", "error": { "kind": "id_shape", "field": "no_such_id_field" } })), "no_such_id_field"),
            (rec("evidence_invalid", json!({ "kind": "commitment", "error": { "kind": "no_such_commitment_error" } })), "no_such_commitment_error"),
            (rec("evidence_invalid", json!({ "kind": "no_such_plan_refusal" })), "no_such_plan_refusal"),
            (rec("evidence_invalid", json!({ "kind": "lane_mismatch", "plan": { "lane": "no_such_lane" }, "evidence": { "comprehension": "per_member" } })), "no_such_lane"),
            (rec("evidence_invalid", json!({ "kind": "lane_mismatch", "plan": { "lane": "per_member" }, "evidence": { "comprehension": "no_such_comprehension" } })), "no_such_comprehension"),
            (rec("grant_retired", json!({ "kind": "no_such_grant_denial" })), "no_such_grant_denial"),
            (rec("episode_closed", json!({ "status": "no_such_status" })), "no_such_status"),
        ];
        for (record, token) in cases {
            let err = PlanSendRefusal::from_record(&record).unwrap_err();
            assert!(err.contains(token), "the refusal names the unknown token {token:?}: {err}");
        }
    }

    #[test]
    fn member_state_diff_names_each_diverged_atom_and_an_atom_the_capture_lacks() {
        let observed: BTreeMap<String, bool> = [("label:TRASH".to_string(), false), ("membership:INBOX".to_string(), true)].into_iter().collect();
        assert!(member_state_diff(&observed, &observed).is_empty(), "agreement is no divergence");
        let archived: BTreeMap<String, bool> = [("label:TRASH".to_string(), false), ("membership:INBOX".to_string(), false)].into_iter().collect();
        assert_eq!(
            member_state_diff(&observed, &archived),
            vec![crate::attempt::MemberDiff { atom: "membership:INBOX".into(), expected: true, observed: Some(false) }]
        );
        let partial: BTreeMap<String, bool> = [("membership:INBOX".to_string(), true)].into_iter().collect();
        assert_eq!(
            member_state_diff(&observed, &partial),
            vec![crate::attempt::MemberDiff { atom: "label:TRASH".into(), expected: false, observed: None }],
            "an atom the capture does not hold is a divergence, never an agreement"
        );
        let extra: BTreeMap<String, bool> = [("label:TRASH".to_string(), false), ("membership:INBOX".to_string(), true), ("label:STARRED".to_string(), true)].into_iter().collect();
        assert!(member_state_diff(&observed, &extra).is_empty(), "only the observed state's atoms are compared");
    }
}
