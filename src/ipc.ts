// Typed IPC wrappers over the Tauri commands: the v1 ten, and the triage ten.
//
// Every type below mirrors `src-tauri/src/lib.rs`'s serde shapes BYTE FOR BYTE — field names,
// tag discriminants, and enum wire representations are copied from the Rust source, not
// invented here. Five shapes are worth naming explicitly because they are easy to get wrong:
//
// 1. `SurfaceError` is `#[serde(tag = "kind", rename_all = "snake_case")]` — every refusal is a
//    TAGGED OBJECT `{ kind: "busy" | "too_soon" | "provider_backoff" | "session_unconfigured" |
//    "refused" | "store" | "internal",...fields }` (`src-tauri/src/lib.rs:96-128`, witnessed by
//    `src-tauri/tests/surface_contract.rs`'s `every_refusal_serializes_as_a_tagged_value_...`).
//    `TooSoon`/`ProviderBackoff` are the two PACING refusals: both
//    carry `{ operation, retry_after_ms }` — `TooSoon` is the local cadence floor,
//    `ProviderBackoff` is a remembered provider 429. The triage verbs add four more
//    kinds, `plan_required` / `plan_refused` / `plan_child_refused` (point 5) and,
//    `unsupported_capability` (the connector's capability refusal, by name)
//    adds `credential_rejected` (same class as `unsupported_capability` — no fields, fixed copy
//    by kind — LATENT, see its own doc comment below).
//
// 2. `UndoPresentationView` carries NO `#[serde(tag =...)]` — it is a plain unit-variant enum
//    with only `#[serde(rename_all = "snake_case")]`. Serde's default
//    representation for an all-unit-variant enum is a BARE JSON STRING equal to the renamed
//    variant name — so `UndoOutcome.presentation` (and, the `presentation`
//    field of what `undo_presentation` answers, `UndoPresentationReadView`) carries a STRING,
//    not a tagged object. The severed wire value is the literal string `"applied_undo_severed"`
//    (see `SEVERED_UNDO_PRESENTATION` below). The restoration verdict rides BESIDE it as its
//    own tagged value (`RestorationView`, tagged `verdict`), never inside it.
//
// 3. `BodyAvailability` also carries no serde attributes
//    — Rust's default EXTERNALLY-TAGGED enum representation applies: the tuple variant
//    `Text(BodyView)` serializes as `{ "Text": <BodyView> }`. `NoTextualBody` is no longer a
//    bare unit variant: it now carries `{ attachments:
//    AttachmentPresence }` so attachment-only mail (no textual part at all) still reports its
//    attachment count — it serializes as `{ "NoTextualBody": { "attachments": {...} } }`, a
//    single-key tagged object on BOTH arms now, never a bare string.
//
// 4. `RefreshOutcome` is what BOTH refresh doors answer:
//    `refresh_inbox` (page 1) and the new `refresh_more_inbox` (the provider continuation). Rust's
//    `#[serde(flatten)]` on the `freshness: FreshnessView` field means the wire object is the OLD
//    `FreshnessView` shape with fields added — `{checked_through, stale_below, ingested,
//    has_more}` — never a nested `{freshness: {...}, has_more}`. `has_more` is a fact about the
//    SESSION's held provider cursor: true exactly when `refresh_more_inbox` has a continuation to
//    spend. `refresh_more_inbox` itself refuses `SurfaceError::Refused` (never a bespoke wire
//    variant) when no continuation is held for the account — see its own module doc in `lib.rs`.
//    The FRESHNESS half is the last PAGE-1 refresh's claim on both doors: removal inference is
//    page-1-window-scoped, so a continuation revises no coverage. What it reports
//    about itself is `ingested` — how many rows THIS page carried into the store.
//
// 5. The plan's digests and randomizers NEVER cross the wire. `plan_mint` / `plan_review`
//    answer the canonical presentation (rows, summary, header) and — for the aggregate lane — the
//    derived sample; the renderer shows those and hands them BACK on `plan_approve` as a
//    `RenderedViewWire`, and the ENGINE recomputes the view commitment over what came back
//    (`src-tauri/src/lib.rs`'s `plan_approve_on`). Nothing here computes, holds or compares a
//    commitment. `RenderedViewWire` is tagged `mode`, `MemberStateView` `state`, `PreflightView`
//    `outcome`, `KnobActWire` `kind`; `LaneView` is a bare string (the trap-2 shape). The
//    three plan refusals carry the engine's TOKEN as `reason` (never prose) — and no provider
//    identifier: `member_ref` is the Photon message id.
//
// Tauri v2's command macro camelCases Rust's snake_case argument names for the JS side by
// default (no `rename_all` override appears on any `#[tauri::command]` in `lib.rs`), so every
// `invoke` call below passes camelCase keys while every RETURNED payload keeps the Rust
// struct's own snake_case field names — those are not renamed by the macro, only argument
// names are.

import { invoke } from "@tauri-apps/api/core";

// ===============================================================================================
// Cure: the five remedies a `credential_expired` refusal (and its resident
// `SessionStatus.credential_cure`) can name. Only `re_mint` sends the operator off-app; the other
// four each name a DIFFERENT true cause, and the frontend must never render a re-mint demand for
// any of them.
// ===============================================================================================
export type Cure = "re_mint" | "client_config" | "admin_policy" | "retry_later" | "undetermined";

// ===============================================================================================
// SurfaceError — lib.rs:93-146
// ===============================================================================================

export type SurfaceError =
  | { kind: "busy"; operation: string }
  /// The local cadence floor — this refresh
  /// arrived less than the minimum refresh interval after the last one COMPLETED.
  | { kind: "too_soon"; operation: string; retry_after_ms: number }
  /// The PROVIDER asked us to back off (a remembered 429-class refusal) and that answer holds
  /// until the recorded instant passes.
  | { kind: "provider_backoff"; operation: string; retry_after_ms: number }
  /// `cure` is the SAME discriminant `credential_expired` carries and the same one
  /// `SessionStatus.credential_cure` renders — a boot-time credential refusal (a pre-grant credential
  /// with no grant record, a read-only or superseded grant, an unusable principal) knows its cure,
  /// and previously only the SENTENCE crossed the boundary, so this refusal's toast was the only
  /// one in the union with no cure to branch on. `null` for the arms that owe no CREDENTIAL cure
  /// (an unopenable store, an unresolved path, the JMAP placeholder): the toast keeps the bare
  /// reason there. Read through the single-sourced `UNCONFIGURED_CURE_COPY` map (`state.ts`),
  /// never a literal — THIS refusal is the local boot's (a denied read, a boot-lock timeout, an
  /// unusable ratchet), and the refresh-stage `CURE_COPY` sentences name a provider and a renewal
  /// that no boot failure has.
  | { kind: "session_unconfigured"; reason: string; cure: Cure | null }
  /// The parked Gmail
  /// credential's own `expires_at` has PASSED. Its own kind, never a `Refused` — the cause AND the
  /// cure are both specific. `cure` names WHICH of the five remedies applies (`re_mint` is only
  /// ONE of them — this build has no in-app OAuth, so re-minting off-app is that one's fix;
  /// `client_config` / `admin_policy` / `retry_later` / `undetermined` each name a different true
  /// cause and must NEVER be rendered as a re-mint demand). `expires_at` carries the stamp the UI
  /// renders; `reason` carries the engine's own sentence.
  | { kind: "credential_expired"; expires_at: number; cure: Cure; reason: string }
  /// `terminal` — set in the ONE classifier
  /// (`SurfaceError::execute`, from the `ExecuteError` variant that produced this refusal) — is
  /// the SAME terminal/transient axis every OTHER `SurfaceError` kind already carries by its own
  /// identity; `refused` alone conflates several causes under one tag, so it carries the axis
  /// explicitly. `isTerminalRefusal` (`state.ts`) reads this field for this one kind instead of
  /// defaulting the whole kind terminal.
  | { kind: "refused"; reason: string; terminal: boolean }
  | { kind: "store"; reason: string }
  | { kind: "internal"; reason: string }
  /// A RED verb reached the engine without a plan. The RED doors mint instead of
  /// dispatching, so no door is expected to answer it; it is its own kind all the same.
  | { kind: "plan_required" }
  /// The send fence's plan arm refused a member, or the approve door refused the evidence
  /// (`reason: "evidence_invalid"`, `member_ref: null`). `reason` is the engine's token; `diff` is
  /// non-empty only for `state_diverged` (atom names + booleans).
  | { kind: "plan_refused"; reason: string; member_ref: string | null; diff: MemberDiffView[] }
  /// A plan child's admission, or a plan door's precondition, refused by token.
  | { kind: "plan_child_refused"; reason: string }
  /// The connector's own capability map does not carry this verb.
  /// every triage verb answers this (the shell's connector publishes `m1_verbs()`); enabling them
  /// is a deliberate enablement step (ADR-P010), so the copy offers no cure.
  | { kind: "unsupported_capability" }
  /// Same class as `unsupported_capability` above: a connector's
  /// credential was rejected DURING a plan member's dispatch (an HTTP 401-class provider answer,
  /// an access token that aged out mid-run). Its own kind, carrying NOTHING of the connector's
  /// message — the operator sentence is fixed, rendered by kind (`src/state.ts`). LATENT:
  /// every triage verb answers `unsupported_capability` at the connector's capability gate before
  /// `apply` ever runs, so this cannot yet reach a caller in this build; it becomes live at the
  /// deliberate enablement step that turns a verb's capability on.
  | { kind: "credential_rejected" };

// ===============================================================================================
// The plan wire shapes (src-tauri/src/lib.rs, "the plan surfaces" section)
// ===============================================================================================

/// One diverged closure atom: the engine's atom name and two booleans (`observed: null` = the
/// capture did not cover the atom).
export interface MemberDiffView {
  atom: string;
  expected: boolean;
  observed: boolean | null;
}

export interface PlanHeaderView {
  /// The Photon account partition — never the provider principal.
  account: string;
  verb: string;
  tier: string;
  count: number;
  backup_coverage: boolean;
  /// The verb-specific warning, present exactly when `backup_coverage` is false.
  warning: string | null;
}

export interface PlanSummaryView {
  count: number;
  /// `[domain, count]` pairs (a Rust tuple is a JSON array), in the engine's order — PARSED
  /// senders' domains only.
  sender_domains: [string, number][];
  /// Members whose From header was absent or empty — rendered as its own line, never a domain.
  sender_domain_unavailable: number;
  /// Members whose From header does not parse under the grammar at all — its own line.
  sender_header_malformed: number;
  /// Members whose From header PARSES but is not exactly one mailbox (a group or
  /// a >1 mailbox-list) — valid syntax, no single sender attributed — its own line.
  sender_header_unsupported: number;
  date_min: string;
  date_max: string;
  total_size: number | null;
}

export interface PlanRowView {
  message_ref: string;
  sender: string;
  /// The address half, frozen and carried separately from `sender` —
  /// `render.ts` isolates both into their own `<bdi>`, exactly like the inbox row's
  /// `from_name`/`from_addr`.
  sender_address: string;
  /// The frozen member's sender status token
  /// ("ok"/"unavailable"/"malformed"/"unsupported") — `render.ts` shows a non-"ok" row's status
  /// OUTSIDE the address isolate, as its own atom, never synthesized text inside it.
  sender_status: string;
  /// STRUCTURED-SENDER / NO-REPARSE: the addr-spec's local-part half
  /// alone (empty unless `sender_status === "ok"`) — from the engine's own RFC 5322 grammar
  /// tokens, never derived here by searching `sender_address` for an `@` (a domain-literal may
  /// carry its own `@`, so a delimiter search cannot find the real boundary the engine already
  /// knows). `render.ts` places this in the local `<bdi>`.
  sender_local: string;
  /// The addr-spec's domain half alone (empty unless `sender_status
  /// === "ok"`). `render.ts` places this in the domain `<bdi>`. See `sender_local`.
  sender_domain: string;
  subject: string;
  date: string;
  size: number | null;
}

/// The canonical presentation, verbatim — what the renderer shows and hands back.
export interface PlanPresentationView {
  header: PlanHeaderView;
  summary: PlanSummaryView;
  rows: PlanRowView[];
}

/// The plan's frozen admission lane — a bare string (module doc trap 2's shape).
export type LaneView = "per_member" | "aggregate" | "bypassed";

export interface PlanReviewView {
  plan_id: string;
  lane: LaneView;
  presentation: PlanPresentationView;
  /// Aggregate lane only.
  sample_k: number | null;
  /// Aggregate lane only: the derived sample, in DERIVED order.
  sample_rows: PlanRowView[] | null;
  expires_at: string;
  approved: boolean;
  /// The plan's episode is TERMINAL (completed, cancelled or invalidated), so
  /// no apply can run it again. Approved and not terminal ⇒ the review offers Apply.
  terminal: boolean;
  /// The plan's FROZEN bypass-lane notice — the verb's uncovered warning, present
  /// exactly when the plan froze the `bypassed` lane under `backups: off`. A bypassed plan opens no
  /// screen; the renderer shows this as a non-blocking toast line before the apply.
  bypass_notice: string | null;
}

/// What the renderer says it showed — handed back on approve, exactly as rendered.
export type RenderedViewWire =
  | { mode: "full_list"; presentation: PlanPresentationView }
  | { mode: "aggregate"; header: PlanHeaderView; summary: PlanSummaryView; sample_k: number; sample_rows: PlanRowView[] };

export interface PlanApproveOutcome {
  plan_id: string;
  /// `per_member` | `aggregate` | `bypassed`.
  comprehension: string;
  approver: string;
}

export type MemberStateView =
  | { state: "not_minted" }
  | { state: "in_flight" }
  | { state: "applied" }
  | { state: "refused"; reason: string; diff: MemberDiffView[] }
  | { state: "terminal"; status: string };

export type PreflightView =
  | { outcome: "ready" }
  | { outcome: "refused"; diverged: [string, MemberDiffView[]][] }
  | { outcome: "raced" };

/// One APPLIED member's undo offer — the member, the key the `undo` door undoes
/// it by, and the restoration verdict its effect witness allows (read when the member applied).
export interface PlanUndoKeyView {
  member_ref: string;
  undo_key: string;
  restoration: RestorationView | null;
}

export interface PlanApplyOutcome {
  plan_id: string;
  /// `null` = the run stopped before the preflight decided (see `stopped`).
  preflight: PreflightView | null;
  /// `[message_ref, state]` pairs, in the plan's canonical order.
  /// When the run's post-run member read FAILED, these are the members'
  /// LAST KNOWN states (the pre-run read, with each member the run itself applied moved to
  /// `applied`), and `stopped` names the store failure.
  members: [string, MemberStateView][];
  /// The engine's completion token; `undetermined` = the post-run
  /// settle failed, so the run could not read what the episode became.
  completion: string;
  projection: ProjectionState;
  /// Members already SETTLED when this run reached them — skipped, never re-driven.
  skipped: string[];
  /// Members IN FLIGHT when this run reached them — re-driven through recovery; their
  /// resulting state is in `members`.
  held: string[];
  /// Every APPLIED member's undo offer, REVERSE canonical order — the order `u` walks
  /// them through the existing `undo` door; each carries its
  /// restoration verdict, so the offer shows it.
  undo_keys: PlanUndoKeyView[];
  /// The plan's frozen bypass-lane notice, repeated for the outcome toast.
  bypass_notice: string | null;
  /// The refusal that ENDED the run before every member was attempted, beside
  /// everything the run did do; `null` = the run went to its end. The episode is not closed by a
  /// stop — the approved plan can be applied again.
  stopped: SurfaceError | null;
}

/// The one typed knob act. `configured_k` only (and required) with `summary_sample`, at least 1 —
/// the engine's knob reader decides and refuses anything else by its own sentence.
export type KnobActWire =
  | { kind: "backups"; on: boolean }
  | { kind: "red_bypass"; on: boolean }
  | { kind: "approval_mode"; mode: "full_list" | "summary_sample"; configured_k: number | null };

export interface KnobOutcome {
  generation: number;
}

/// The engine's `ExecuteError::Severed` is an undocumented-prose
/// unit variant; `SurfaceError::execute`'s catch-all arm maps it through
/// `format!("{other:?}")`, i.e. Rust's `Debug` output for a unit variant — the bare variant
/// name, `"Severed"`. This is therefore the EXACT string a `SurfaceError::Refused.reason` carries
/// when a verb/undo call meets a severed operation. Matched by EQUALITY, never substring (a
/// provider or store reason could legitimately contain the word "severed" in prose).
export const SEVERED_REFUSED_REASON = "Severed";

// ===============================================================================================
// UndoPresentationView — lib.rs:692-721 (bare string, see module doc above)
// ===============================================================================================

export type UndoPresentationView =
  | "none"
  | "undoing"
  | "undone"
  | "applied_undo_failed"
  | "externally_satisfied"
  | "applied_undo_unresolved"
  | "applied_undo_severed"
  | "unknown"
  /// The `undo` door's undo COMMITTED and its read-back failed —
  /// unreadable AFTER the undo, never "no such intent" (`unknown`) and never a bare error.
  | "unreadable_after_undo";

/// The severed wire value of `UndoPresentationView` (see module doc above).
export const SEVERED_UNDO_PRESENTATION: UndoPresentationView = "applied_undo_severed";

// ===============================================================================================
// Provider + session status — lib.rs:229-234, 732-755
// ===============================================================================================

export type ProviderKind = "gmail" | "jmap";

export interface SessionStatus {
  provider_kind: ProviderKind;
  account: string;
  store_path: string;
  /// `configured` now means "the store AND the
  /// provider arm are CONSTRUCTIBLE" — it no longer implies the credential is currently LIVE.
  /// An expired-but-refreshable credential (no refresh attempted yet, or the last attempt was a
  /// paced/transient outcome) is `configured: true` + `credential_expired: true` +
  /// `credential_cure: "retry_later"` — the app renews it on the next command. A latched-dead
  /// credential is the SAME shape with `credential_cure: "re_mint"`. `configured: false` stays
  /// reserved for a store/arm that could not be built at all (a missing store file, a malformed
  /// client config that never reaches an arm) — it is never the generic fence reason and never
  /// used merely because a live credential happens to be expired right now.
  configured: boolean;
  store_reason: string | null;
  /// Non-null EXACTLY when the credential answer came from the LOCAL boot stage: the cell
  /// published no arm, or the grant ratchet retired/could not be read. `null` means the cell is
  /// armed, so any `credential_cure` beside it is the refresh stage's own stamp. That is why
  /// `cureCopyFor` (`state.ts`) reads the stage off THIS field.
  provider_reason: string | null;
  credential_expires_at: number | null;
  /// Has the `credential_expires_at` stamp PASSED?
  /// Its own axis beside `configured` (see the redefined `configured` doc above) — a dead
  /// credential no longer forces `configured: false`; a session whose credential dies (or starts
  /// life expired-but-refreshable) stays `configured: true` while every provider read refuses with
  /// `SurfaceError.kind === "credential_expired"`. The status bar renders its own notice for this,
  /// distinct from the `mutations_live` fenced-writes notice, and now branches on `credential_cure`
  /// (below) rather than a hard-coded re-mint prompt.
  credential_expired: boolean;
  /// The credential cell's CURRENT cure. `null`
  /// EXACTLY when `credential_expired` is `false` (the credential is live); when
  /// `credential_expired` is `true` this carries the cell's cure — including `"retry_later"` for a
  /// brand-new session whose parked credential is expired-but-refreshable and has not yet had a
  /// refresh attempted (the app renews it on the next command). The frontend must NOT render a
  /// re-mint demand for that state — it branches on this field via the single-sourced
  /// `cureCopyFor` selector (`state.ts`), never a hard-coded string; that selector reads the
  /// refresh-stage map when this cure came from the credential cell's own stamp and the
  /// boot-stage one when it came from a cell that published no arm or from the grant ratchet,
  /// which are the two stages this field is published from. The
  /// discriminant is `provider_reason`, not `configured`: `configured` is
  /// also false when the STORE would not open, and that says nothing about which stage answered
  /// for the credential.
  credential_cure: Cure | null;
  epoch: number | null;
  epoch_reason: string | null;
  /// Whether a VERB can actually reach the
  /// provider in this build — `false` on the fence-gated production Gmail arm even when
  /// `configured` is `true`. The verbs refuse with this exact same reason; the
  /// UI must not offer buttons the engine always refuses.
  mutations_live: boolean;
  /// Set exactly when `mutations_live` is `false` — never travels without its why.
  mutations_reason: string | null;
}

// ===============================================================================================
// Inbox paging — lib.rs:612-659
// ===============================================================================================

export interface InboxRow {
  message_ref: string;
  received_at: number;
  from_addr: string;
  from_name: string;
  subject: string;
  seen: boolean;
  flagged: boolean;
}

export interface PageCursor {
  received_at: number;
  message_ref: string;
}

export interface FreshnessView {
  checked_through: PageCursor | null;
  stale_below: number;
}

/// See module doc point 4: what BOTH refresh doors answer — `FreshnessView`'s own fields
/// (`#[serde(flatten)]`ed, so this is additive on the wire) plus `ingested` and `has_more`.
export type RefreshOutcome = FreshnessView & { ingested: number; has_more: boolean };

export interface InboxPage {
  rows: InboxRow[];
  next_cursor: PageCursor | null;
  freshness: FreshnessView | null;
}

// ===============================================================================================
// Verb + undo outcomes — lib.rs:664-729
// ===============================================================================================

export type ProjectionState = { state: "current" } | { state: "stale"; reason: string };

/// The engine's restoration verdict (`RestorationView`, tagged
/// `verdict`) — what the operation's persisted effect witness lets the undo offer claim.
/// `within_closure` is the ordinary offer; every other verdict is restoration UNDETERMINED, composed
/// into their sentence by `state.ts`'s `restorationLine`. `outside_closure` carries the rippled
/// labels in their recorded form: system labels NAMED, user labels only COUNTED (a provider-native
/// user label id never crosses). `unreadable` is the verb doors' own: the verb applied and the
/// witness read right after it failed.
export type RestorationView =
  | { verdict: "within_closure" }
  | { verdict: "outside_closure"; system_labels: string[]; user_label_count: number }
  | { verdict: "no_pre_effect_vector" }
  | { verdict: "no_effect_witness" }
  | { verdict: "unreadable" }
  /// The verb applied and settled, and the effect-witness WRITE
  /// that followed failed — the witness was not recorded.
  | { verdict: "witness_write_failed" };

export interface VerbOutcome {
  applied: boolean;
  undo_key: string;
  projection: ProjectionState;
  /// `null` only if the forward effect has not landed — never for an applied verb.
  restoration: RestorationView | null;
}

export interface UndoOutcome {
  undone: boolean;
  presentation: UndoPresentationView;
  projection: ProjectionState;
  /// `null` = the operation's forward effect has not landed (no restoration to qualify).
  restoration: RestorationView | null;
}

/// What `undo_presentation` answers: the bare-string presentation (trap 2, unchanged)
/// beside the restoration verdict.
export interface UndoPresentationReadView {
  presentation: UndoPresentationView;
  restoration: RestorationView | null;
}

// ===============================================================================================
// Body — crates/aruna/src/body_view.rs:30-48
// ===============================================================================================

export interface AttachmentPresence {
  has_attachments: boolean;
  count: number;
}

export interface BodyView {
  plain_text: string;
  truncated: boolean;
  attachments: AttachmentPresence;
}

/// See module doc point 3: both arms are tagged single-key objects now — `NoTextualBody` still
/// carries `attachments` even though it has no textual part (attachment-only mail).
export type BodyAvailability = { Text: BodyView } | { NoTextualBody: { attachments: AttachmentPresence } };

// ===============================================================================================
// The twenty typed doors (the exact `generate_handler!` list in `src-tauri/src/lib.rs`'s `run`):
// the v1 ten (`refresh_more_inbox`, the provider-continuation door, joins the
// original nine) and the triage ten, at the end of this file
// ===============================================================================================

export function sessionStatus(): Promise<SessionStatus> {
  return invoke("session_status");
}

export function inboxPage(
  account: string,
  pageSize: number,
  cursor: PageCursor | null,
): Promise<InboxPage> {
  return invoke("inbox_page", { account, pageSize, cursor });
}

export function refreshInbox(account: string, pageSize: number): Promise<RefreshOutcome> {
  return invoke("refresh_inbox", { account, pageSize });
}

/// Continues the provider walk `refresh_inbox` started — fetches the NEXT
/// provider page off the session's held continuation. Refuses `{ kind: "refused", reason }` (never
/// a bespoke wire variant — see module doc point 4) when no continuation is held for the account;
/// a caller decides whether to call this at all off `RefreshOutcome.has_more`.
export function refreshMoreInbox(account: string): Promise<RefreshOutcome> {
  return invoke("refresh_more_inbox", { account });
}

export function messageBody(account: string, messageRef: string): Promise<BodyAvailability> {
  return invoke("message_body", { account, messageRef });
}

export function archive(account: string, messageRef: string): Promise<VerbOutcome> {
  return invoke("archive", { account, messageRef });
}

export function unarchive(account: string, messageRef: string): Promise<VerbOutcome> {
  return invoke("unarchive", { account, messageRef });
}

export function setStar(
  account: string,
  messageRef: string,
  value: boolean,
): Promise<VerbOutcome> {
  return invoke("set_star", { account, messageRef, value });
}

export function undo(undoKey: string): Promise<UndoOutcome> {
  return invoke("undo", { undoKey });
}

export function undoPresentation(undoKey: string): Promise<UndoPresentationReadView> {
  return invoke("undo_presentation", { undoKey });
}

// ===============================================================================================
// The triage ten doors
// ===============================================================================================

/// RED: mints a one-member plan and answers its review — never a dispatch.
export function trash(account: string, messageRef: string): Promise<PlanReviewView> {
  return invoke("trash", { account, messageRef });
}

export function untrash(account: string, messageRef: string): Promise<VerbOutcome> {
  return invoke("untrash", { account, messageRef });
}

/// RED: mints a one-member plan and answers its review — never a dispatch.
export function markSpam(account: string, messageRef: string): Promise<PlanReviewView> {
  return invoke("mark_spam", { account, messageRef });
}

export function unmarkSpam(account: string, messageRef: string): Promise<VerbOutcome> {
  return invoke("unmark_spam", { account, messageRef });
}

/// Mark read (`true`) / unread (`false`).
export function setSeen(account: string, messageRef: string, value: boolean): Promise<VerbOutcome> {
  return invoke("set_seen", { account, messageRef, value });
}

export function planMint(
  account: string,
  verb: "trash" | "mark_spam",
  memberRefs: string[],
  rationale: string | null,
): Promise<PlanReviewView> {
  return invoke("plan_mint", { account, verb, memberRefs, rationale });
}

export function planReview(planId: string): Promise<PlanReviewView> {
  return invoke("plan_review", { planId });
}

/// `rendered` is EXACTLY what the renderer showed (module doc trap 5).
export function planApprove(planId: string, rendered: RenderedViewWire, approver: string): Promise<PlanApproveOutcome> {
  return invoke("plan_approve", { planId, rendered, approver });
}

export function planApply(planId: string): Promise<PlanApplyOutcome> {
  return invoke("plan_apply", { planId });
}

export function setKnob(act: KnobActWire): Promise<KnobOutcome> {
  return invoke("set_knob", { act });
}
