// The ONE reducer + store (one explicit reducer/state model).
//
// Every DOM-facing side effect lives in `render.ts`; every IPC call lives in `ipc.ts`; this
// module is pure transitions over plain data, which is what makes it unit-testable without a
// DOM (`src/__tests__/state.test.ts` runs it under vitest's `node` environment).

import type {
  BodyAvailability,
  Cure,
  FreshnessView,
  InboxRow,
  MemberDiffView,
  MemberStateView,
  PageCursor,
  PlanApplyOutcome,
  PlanReviewView,
  ProjectionState,
  RestorationView,
  SessionStatus,
  SurfaceError,
  UndoPresentationView,
} from "./ipc";
import { SEVERED_REFUSED_REASON, SEVERED_UNDO_PRESENTATION } from "./ipc";

// ===============================================================================================
// Row display state ("unread (seen=false) and starred render distinctly")
// ===============================================================================================

export interface RowVisualState {
  unread: boolean;
  starred: boolean;
}

export function rowVisualState(row: Pick<InboxRow, "seen" | "flagged">): RowVisualState {
  return { unread: !row.seen, starred: row.flagged };
}

// ===============================================================================================
// Date rendering — `received_at` is epoch MILLISECONDS on both providers: a prior
// `* 1000` treated it as epoch seconds, which does not throw or clamp — `Date` silently accepts
// the resulting far-future timestamp and every row rendered a five-digit year.
// ===============================================================================================

export function formatReceivedAt(receivedAtMs: number): string {
  return new Date(receivedAtMs).toLocaleString();
}

// ===============================================================================================
// Focus / selection — pure clamp + toggle helpers
// ===============================================================================================

/// `j/k` move the focused row; clamps at both ends (never wraps, never goes negative, never
/// exceeds the last row).
export function clampFocus(index: number, delta: number, length: number): number {
  if (length <= 0) {
    return 0;
  }
  return Math.max(0, Math.min(length - 1, index + delta));
}

export function toggleSelect(selected: ReadonlySet<string>, ref: string): Set<string> {
  const next = new Set(selected);
  if (next.has(ref)) {
    next.delete(ref);
  } else {
    next.add(ref);
  }
  return next;
}

// ===============================================================================================
// Batch archive — fail-stop sequential singles, tri-state report
// ===============================================================================================

export type PerMessageAttempt =
  | { message_ref: string; ok: true; undo_key: string; projection: ProjectionState; restoration?: RestorationView | null }
  | { message_ref: string; ok: false; reason: string };

export interface BatchOutcome {
  succeeded: { message_ref: string; undo_key: string; projection: ProjectionState; restoration?: RestorationView | null }[];
  failed: { message_ref: string; reason: string } | null;
  notAttempted: string[];
}

/// `refs` is the FULL ordered target list; `results` is the ordered attempts actually made
/// (fail-stop: the caller stops issuing calls at the first failure, so `results.length <=
/// refs.length`, and the final entry — if present — is the one failure). This function does not
/// run the batch; it only derives the tri-state report from what already happened, which is why
/// it is pure and testable without a fake network.
export function deriveBatchOutcome(refs: string[], results: PerMessageAttempt[]): BatchOutcome {
  const succeeded: BatchOutcome["succeeded"] = [];
  let failed: { message_ref: string; reason: string } | null = null;
  let attemptedCount = results.length;

  for (const result of results) {
    if (result.ok) {
      succeeded.push({
        message_ref: result.message_ref,
        undo_key: result.undo_key,
        projection: result.projection,
        // Carried only when the attempt carried one, so a pre-verdict attempt's bookkeeping
        // is unchanged.
        ...(result.restoration !== undefined ? { restoration: result.restoration } : {}),
      });
    } else {
      failed = { message_ref: result.message_ref, reason: result.reason };
      break;
    }
  }
  // Fail-stop: everything after the failure (if any) was never attempted, including anything
  // past a shorter `results` array than `refs` (a caller that stopped early without reporting a
  // failure — e.g. it was itself interrupted — still leaves the remainder "not attempted", never
  // silently "succeeded").
  if (failed) {
    attemptedCount = succeeded.length + 1;
  }
  const notAttempted = refs.slice(attemptedCount);

  return { succeeded, failed, notAttempted };
}

/// The undo toast carries the succeeded set's keys "in reverse order" — undoing a
/// batch walks the successes backwards, last-applied-first.
export function undoKeysForBatch(outcome: BatchOutcome): string[] {
  return outcome.succeeded.map((s) => s.undo_key).reverse();
}

/// The keys of a batch undo that have NOT been spent yet: everything after the
/// `consumedCount` the walk has already sent.
///
/// A batch undo walks `undoKeysForBatch`'s list one IPC call at a time, and each success dispatched
/// an `undo_toast` — which replaced the batch toast with one carrying NO keys. From the first
/// success onward the remaining keys were unreachable: a throw on key 2 of 5 left keys 2..5 with no
/// affordance at all, even though nothing had undone them. (That is the same class
/// closed for `refusal_toast`, re-opened by the undo path's own toast.) The walk therefore carries
/// its unconsumed SUFFIX onto every intermediate toast, so the toast always offers exactly the keys
/// still owed — and a refusal landing mid-walk preserves that suffix through the merge shape.
export function unconsumedUndoKeys(keys: readonly string[], consumedCount: number): string[] {
  return keys.slice(Math.max(0, consumedCount));
}

// ===============================================================================================
// Freshness footer — RECONCILE
// ===============================================================================================

/// `last_freshness: None` (e.g. persisted rows survive a restart, but this session
/// never ran a reconcile yet) used to render NO footer at all — old rows appeared unqualified,
/// indistinguishable from a freshly-reconciled inbox. `hasRows` defaults to `false` so every
/// existing call site that never refreshed AND has nothing to show keeps rendering nothing.
const NEVER_REFRESHED_THIS_SESSION_LINE = "not yet refreshed this session — press r";

/// A fresh store's page-1 reconcile can land `stale_below: 0` (nothing BELOW the
/// window is stale — there's no window yet) while the provider still holds more messages
/// (`has_more: true`). The old two-fact footer (never-refreshed / stale_below) had no input for
/// this third fact at all, so a page-1-only inbox of >50 provider messages showed no indication
/// further pages existed. This line renders whenever `hasMore` is true, independent of
/// `stale_below` — the provider continuation and the stale-window count are orthogonal facts and
/// both can be true at once (both lines then render, joined).
// `r` REFETCHES page 1 — it does not continue past what is already
// loaded, only `j` at the bottom does that. The old line offered "(or r)" as an equivalent way to
// load more, which was never true: pressing `r` here restarts the reconcile from the top, it does
// not advance the window.
const MORE_ON_PROVIDER_LINE =
  "more messages on the provider — press j at the bottom to load more";

export function freshnessFooterText(
  freshness: FreshnessView | null | undefined,
  hasRows = false,
  hasMore = false,
): string | null {
  const lines: string[] = [];
  if (!freshness) {
    if (hasRows) {
      lines.push(NEVER_REFRESHED_THIS_SESSION_LINE);
    }
  } else if (freshness.stale_below > 0) {
    lines.push(`${freshness.stale_below} older messages not re-checked`);
  }
  if (hasMore) {
    lines.push(MORE_ON_PROVIDER_LINE);
  }
  return lines.length > 0 ? lines.join(" · ") : null;
}

// ===============================================================================================
// Severed detection — the BLACK banner's typed-tag match
// ===============================================================================================

/// Matches the engine's severed signal EXACTLY on the typed tag/value — never substring — per
/// the dispatch note's instruction to "match on the typed tag, not substring, if the enum tag
/// crosses IPC". The two wire shapes that carry it (see `ipc.ts`'s module doc):
///   - `SurfaceError::Refused { reason: "Severed" }` — the exact Debug string of the engine's
///     unit-variant `ExecuteError::Severed` (`lib.rs:142`, the `SurfaceError::execute` catch-all).
///   - `UndoPresentationView` === `"applied_undo_severed"` — the bare-string wire value of
///     `UndoPresentation::AppliedUndoSevered`.
export function isSeveredSignal(
  input: SurfaceError | UndoPresentationView | null | undefined,
): boolean {
  if (input == null) {
    return false;
  }
  if (typeof input === "string") {
    return input === SEVERED_UNDO_PRESENTATION;
  }
  return input.kind === "refused" && input.reason === SEVERED_REFUSED_REASON;
}

// ===============================================================================================
// Toast — every verb outcome renders one
// ===============================================================================================

export interface Toast {
  message: string;
  /// Undo affordance: keys in the order they should be undone (already reversed for a batch).
  undoKeys: string[];
  /// `ProjectionState::Stale` ⇒ the toast carries the explicit "not re-checked" line.
  staleReason: string | null;
  /// Set when this toast IS a refusal, carrying which typed tag produced it.
  refusalKind: SurfaceError["kind"] | null;
  /// Extra lines a toast carries, one per line through the one textContent sink
  /// (`render.ts` `renderToast`) — a plan toast's refused member and each diverged atom, verbatim
  /// from the engine's payload, and the restoration UNDETERMINED line beside an undo
  /// offer (`restorationLine`). ABSENT when there is none, so a toast with nothing to add is the
  /// toast it always was.
  detail?: string[];
  /// For a plan's APPLIED children — which member each undo key undoes (key → member
  /// ref). Present exactly when `undoKeys` holds plan-child keys; carried with those keys wherever
  /// they are carried, so the undo walk can name each member's verdict. Absent on every other
  /// toast.
  undoLabels?: Record<string, string>;
  /// The RESTORATION line of each undo key this toast offers (key →
  /// the line exactly as its own toast showed it in `detail`), present exactly when one of the
  /// offered keys has an UNDETERMINED verdict. Carried with those keys wherever they are carried —
  /// beside `undoLabels` — so an undo offer is never shown without its qualification.
  undoRestoration?: Record<string, string>;
}

// ===============================================================================================
// The restoration verdict beside the undo offer
// ===============================================================================================

/// The restoration line for a verdict, or `null` for the ordinary offer (`within_closure`) and for
/// no verdict at all. The three engine sentences are `RestorationVerdict::undetermined_line`'s
/// bytes (`crates/aruna/src/lib.rs`; `state.test.ts` pins the agreement): system labels named,
/// user labels counted, never named. `unreadable` is the verb doors' own fourth case, and
/// `witness_write_failed` the fifth: the verb applied and settled,
/// and the witness WRITE after it failed — named for what failed, beside the offer that stays.
export const WITNESS_NOT_RECORDED_LINE = "effect witness not recorded — restoration UNDETERMINED (no effect witness)";

export function restorationLine(restoration: RestorationView | null | undefined): string | null {
  if (restoration == null) {
    return null;
  }
  let cause: string;
  switch (restoration.verdict) {
    case "within_closure":
      return null;
    case "witness_write_failed":
      return WITNESS_NOT_RECORDED_LINE;
    case "outside_closure": {
      const parts = [...restoration.system_labels];
      const users = restoration.user_label_count;
      if (users > 0) {
        parts.push(`${users} user label${users === 1 ? "" : "s"}`);
      }
      cause = `labels outside the declared closure changed: ${parts.join(", ")}`;
      break;
    }
    case "no_pre_effect_vector":
      cause = "no pre-effect vector";
      break;
    case "no_effect_witness":
      cause = "no effect witness";
      break;
    case "unreadable":
      cause = "the effect witness could not be read";
      break;
  }
  return `restoration UNDETERMINED (${cause})`;
}

/// The toast with `lines` appended to its detail — or the toast UNCHANGED when there are none
/// (the byte-identity rule: a within-closure outcome renders exactly today's toast).
function withDetail(toast: Toast, lines: string[]): Toast {
  if (lines.length === 0) {
    return toast;
  }
  return { ...toast, detail: [...(toast.detail ?? []), ...lines] };
}

/// The restoration lines `keys` still owe, in key order, and the map of just those
/// keys (`undefined` when none owes a line).
function owedRestoration(
  restoration: Readonly<Record<string, string>> | undefined,
  keys: readonly string[],
): { lines: string[]; owed: Record<string, string> | undefined } {
  const kept = restoration === undefined ? [] : keys.filter((k) => Object.prototype.hasOwnProperty.call(restoration, k));
  if (restoration === undefined || kept.length === 0) {
    return { lines: [], owed: undefined };
  }
  return { lines: kept.map((k) => restoration[k]), owed: Object.fromEntries(kept.map((k) => [k, restoration[k]])) };
}

/// The toast with the restoration lines `keys` owe appended to its detail and their map attached —
/// or the toast unchanged when they owe none (the byte-identity rule).
function withOwedRestoration(
  toast: Toast,
  restoration: Readonly<Record<string, string>> | undefined,
  keys: readonly string[],
): Toast {
  const { lines, owed } = owedRestoration(restoration, keys);
  if (owed === undefined) {
    return toast;
  }
  return { ...withDetail(toast, lines), undoRestoration: owed };
}

export function projectionStaleReason(projection: ProjectionState): string | null {
  return projection.state === "stale" ? projection.reason : null;
}

/// THE COMPLEMENT over every predicting sentence in this file: it
/// said "row not re-checked — refresh to confirm", which promises that a refresh WILL confirm the
/// row. It may not: the same `refresh_inbox` guards that make a credential re-check unpromisable
/// (an unopenable store above all) refuse this door too, and the provider may simply answer
/// differently. The line now says only what is observed — the write landed, the read side did not
/// re-check, so the row on screen is the pre-write one.
const STALE_ROW_LINE = "row not re-checked — the row shown is from before the write";

/// The star toggle's toast used to hardcode `verbLabel: "star"` regardless of
/// which way the toggle went: an UNSTAR (the star REMOVED) rendered "star applied" — through
/// `toastForVerb`'s `${verbLabel} applied` idiom — which reads as the row having just been
/// starred, the opposite of what happened. `target` is the value the caller is about to send
/// (`true` ⇒ starring, `false` ⇒ unstarring); the label is derived from it so the toast always
/// names the actual direction, in the SAME `${verbLabel} applied` shape every other verb toast
/// already uses.
export function starVerbLabel(target: boolean): string {
  return target ? "star" : "unstar";
}

/// `restoration` is the verb outcome's verdict; its UNDETERMINED line rides beside the
/// offer (`restorationLine`), and a within-closure verdict (or none) leaves the toast as it was.
export function toastForVerb(
  verbLabel: string,
  undoKey: string,
  projection: ProjectionState,
  restoration: RestorationView | null = null,
): Toast {
  const staleReason = projectionStaleReason(projection);
  const message = staleReason
    ? `${verbLabel} applied — ${STALE_ROW_LINE}`
    : `${verbLabel} applied`;
  const line = restorationLine(restoration);
  const toast = withDetail({ message, undoKeys: [undoKey], staleReason, refusalKind: null }, line === null ? [] : [line]);
  // The line rides with ITS key wherever the offer is carried.
  return line === null ? toast : { ...toast, undoRestoration: { [undoKey]: line } };
}

/// A succeeded `PerMessageAttempt`'s `projection` used to be dropped entirely —
/// `toastForBatch` hardcoded `staleReason: null`, so a batch where every write succeeded but the
/// read side never re-checked one of the rows (`ProjectionState::Stale`) rendered as unqualified
/// success. This aggregates across ALL succeeded attempts: any one Stale ⇒ the batch toast
/// carries the stale marker, naming which refs.
function batchStaleReason(succeeded: BatchOutcome["succeeded"]): string | null {
  const staleRefs = succeeded
    .filter((s): s is typeof s & { projection: { state: "stale"; reason: string } } => s.projection.state === "stale")
    .map((s) => s.message_ref);
  if (staleRefs.length === 0) {
    return null;
  }
  return `${staleRefs.length} of ${succeeded.length} succeeded rows not re-checked (${staleRefs.join(", ")})`;
}

export function toastForBatch(verbLabel: string, outcome: BatchOutcome): Toast {
  const staleReason = batchStaleReason(outcome.succeeded);
  const parts = [
    `${verbLabel}: ${outcome.succeeded.length} succeeded`,
    outcome.failed ? `1 failed (${outcome.failed.message_ref})` : "0 failed",
    `${outcome.notAttempted.length} not attempted`,
  ];
  if (staleReason) {
    parts.push(STALE_ROW_LINE);
  }
  // Each succeeded message whose restoration is UNDETERMINED is named on its own line.
  const owed = outcome.succeeded.flatMap((s): [string, string][] => {
    const line = restorationLine(s.restoration);
    return line === null ? [] : [[s.undo_key, `${s.message_ref}: ${line}`]];
  });
  const toast = withDetail(
    {
      message: parts.join(", "),
      undoKeys: undoKeysForBatch(outcome),
      staleReason,
      refusalKind: null,
    },
    owed.map(([, line]) => line),
  );
  // Each line rides with ITS key wherever the offer is carried.
  return owed.length === 0 ? toast : { ...toast, undoRestoration: Object.fromEntries(owed) };
}

/// Rounds a `retry_after_ms` duration UP to whole seconds — a caller should never see "try again
/// in 0s" for a refusal that is still, technically, in effect for another 400ms.
function retryAfterSeconds(retryAfterMs: number): number {
  return Math.ceil(retryAfterMs / 1000);
}

// ===============================================================================================
// CURE_COPY: the ONE sentence-per-cure map, single-sourced. Both
// `toastForRefusal`'s `credential_expired` branch below AND `render.ts`'s status-bar cure notice
// read this SAME map, so the toast and the status bar can never drift apart on what a given cure
// says. A transient/non-remint cure (`retry_later`, `undetermined`) must NEVER contain the word
// "re-mint" — only the `re_mint` entry names a re-mint.
// ===============================================================================================
export const CURE_COPY: Record<Cure, string> = {
  re_mint: "the Gmail credential needs a re-mint (see the runbook)",
  // Covers BOTH members of the cure class: a refused client_secret.json AND an
  // invalid_scope refusal, whose fix lives in the console, not that file — so the sentence names
  // the review, never one file as THE cure.
  client_config: "the OAuth client or its scope configuration was refused — developer review of the OAuth client (client_secret.json / console) is required",
  // CURE-ACTOR-HONESTY: actor-neutral — this cure fronts every ProviderPolicy
  // refusal, and org_internal's documented remedy is account/organization scoped (switching to an
  // in-organization account), not necessarily an administrator's act; the per-code refusal reason
  // that follows the prefix names the specific policy, so the prefix asserts only the class.
  admin_policy: "an account or organization policy refused the credential",
  // NEUTRAL about pacing: this cure also covers states that retry
  // IMMEDIATELY (the boot-expired no-attempt-yet state, pre-wire local failures), so the
  // copy asserts only what EVERY carrier guarantees. The genuinely PACED refusals carry
  // their own "renewal is paced" sentence in the refusal reason itself.
  //
  // It said "renewal will be retried on your next command". A
  // `configured: false` session whose `store_unavailable` is set reads THIS map (the cure came
  // from a real refresh answer), and in that shape NOTHING retries: every
  // provider-read stops at `state.session()?` before `admit_provider`, and `self.session` is
  // written once at construction with no `&mut self` anywhere to reopen it. The row now names
  // the FACT (not renewed) and the CLASS of the reason (transient) and stops there.
  //
  // "the reason RECORDED is a transient one" asserted a record that
  // does not exist at boot inside the expiry grace window (`status_cure` yields `retry_later`
  // before any refresh has run; `last_result` is `None` and is not on the wire). A cure sentence
  // names what the CURE means for the credential, never a fact about the refresh history the
  // cure does not carry. The row now says the class of the condition and nothing about a record.
  //
  // Rationale:
  // "has not been renewed — a transient condition, not a refused one" was FALSE on its
  // most ordinary carrier (`RememberedOutcome::Renewed` ⇒ RetryLater: the credential WAS renewed,
  // then expired again) and contradicted the reason beside it on the grace-refused toast
  // ("... not a refused one:... Photon refused this admission...") and on a
  // GrantHighWaterUnusable refusal ("Photon refuses rather than treat an unreadable record as an
  // empty one"). The row now says only what the CURE means — retryable as it stands, no re-mint
  // or configuration change indicated — and defers the CONDITION to the reason it fronts.
  //
  // "— the reason
  // beside it names the condition" was FALSE on the status bar for an armed cell — both
  // `store_reason` and `provider_reason` are null there, so no parenthetical renders and the
  // cure copy stands alone; only the toast composes `copy: reason`. The row is now the bare
  // state-only fact, true wherever it renders; the CONDITION lives with the reason on the one
  // surface that carries one.
  retry_later: "the credential is retryable as it stands",
  // Same edit, same reason — the ACTOR (the provider) and the FACT (not renewed)
  // are both observed; "Photon will retry on your next command" was the prediction, and it is
  // gone. What DOES retry, and when, is the door contract's business, not a label's.
  undetermined: "the provider refused for an unrecognized reason — the credential has not been renewed",
};

// ===============================================================================================
// UNCONFIGURED_CURE_COPY: the SAME five cures, said for
// the OTHER stage.
//
// `CURE_COPY` above is refresh-stage copy: an arm exists, it was carried to the provider, and the
// provider answered. The UNCONFIGURED surface is the stage BEFORE that — no arm was built, and its
// refusals are the local filesystem's (a `PermissionDenied` on the credential file ⇒
// `undetermined`; a boot-lock timeout or an unusable grant ratchet ⇒ `retry_later`). Rendered
// through `CURE_COPY`, those prefixed the operator's own file-access failure with "the provider
// refused" and promised a "renewal" where the next step is a RECONCILE — the prefix contradicting
// the reason printed two words after it.
//
// A SECOND MAP, not a second set of literals: the two rows whose act is genuinely stage-neutral
// (`re_mint` — one consent, written to one file, whichever stage found the demand) and the two
// whose actor is the provider by definition (`client_config`, `admin_policy` — a console entry and
// an account/organization policy exist independently of any boot) are the SAME strings by
// reference, so they cannot drift. Only the two rows the finding names are re-written, and neither
// names the provider, a renewal, or a re-mint.
// ===============================================================================================
export const UNCONFIGURED_CURE_COPY: Record<Cure, string> = {
  re_mint: CURE_COPY.re_mint,
  client_config: CURE_COPY.client_config,
  admin_policy: CURE_COPY.admin_policy,
  // Nothing has been renewed and nothing can be: there is no arm.
  //
  // It said "Photon will re-check the credential on your next
  // command". FALSE at the ACTING doors — `run_verb`, `undo` and `undo_presentation` reach the
  // arm through `PhotonState::gmail`, which never calls `CredentialCoordinator::admit` (their
  // admission is separate), so "your next command" re-checks nothing at all. The row names the
  // observed fact and the class of the local refusal; it predicts no door.
  //
  // "a transient local refusal (... an unusable
  // grant ratchet)" called a DURABLE malformed `grant_high_water.json` transient — it stays
  // refused until someone repairs the file. The row now names the fact and defers WHAT refused
  // to the reason beside it.
  //
  // Carrier reason (at token_refresh.rs — "this
  // credential's grant could not be RECORDED"): "Photon refused to READ its local state" was
  // false for `GrantHighWaterWriteFailed`, whose failed operation is the WRITE. The sentence is
  // now verb-neutral ("a local state operation was refused"); this map renders only where a
  // reason rides beside it (the toast appends it; the status bar's unconfigured line prints
  // `provider_reason`, the very discriminant that selects this map), so the deferral is honest.
  retry_later: "the credential could not be checked — a local state operation was refused; the reason names what refused",
  // The ACTOR is deliberately unnamed: this cure fronts every boot refusal we do not map, and the
  // sentence that rides beside it on both surfaces (the toast appends it, the status bar prints it
  // in the "not configured (…)" line) is the one that names what refused.
  undetermined: "the credential state could not be established — the refusal reason names what refused",
};

/// The ONE place a `SessionStatus` is turned into cure copy — the status bar's only
/// job here is to append what this returns.
///
/// The map is chosen by the STAGE THE CURE CAME FROM, and `provider_reason` is that discriminant
/// Read `session_status_view` (lib.rs) at the byte: every
/// BOOT-stage cure source sets `provider_reason` in the same breath as the cure — the cell that
/// published no arm (`unconfigured_verdict` returns the pair) and the grant ratchet's own verdict
/// (`LiveGrantVerdict::Retired`/`Undetermined`, whose reason and cure travel together). When it is
/// `null` the cell IS armed and the only remaining source is `CredentialCell::status_cure` — the
/// refresh stage's stamp, an answer a provider actually gave.
///
/// It was `status.configured`, which is `store_unavailable.is_none() && provider_reason.is_none()`
/// TWO facts under one flag. A store that would not open makes it `false` over an ARMED,
/// expired credential whose cure came from a refresh attempt, and the boot-stage map then told the
/// operator Photon would "re-check the credential on your next command" about a renewal the
/// provider had already refused. `configured` is a session-level fact; the cure's stage is the
/// credential's, and only `provider_reason` answers that one.
///
/// Both hedges the toast carries live here too, against the SELECTED map: `?? "undetermined"` for
/// a null discriminant (a contract violation while `credential_expired` is true — named, never
/// papered over with a false re-mint demand) and a trailing `?? …undetermined` for a NON-null
/// discriminant this build's map has no row for, so neither surface can ever paint the literal
/// word "undefined".
export function cureCopyFor(status: SessionStatus): string {
  const copy = status.provider_reason === null ? CURE_COPY : UNCONFIGURED_CURE_COPY;
  return copy[status.credential_cure ?? "undetermined"] ?? copy.undetermined;
}

export function toastForRefusal(error: SurfaceError): Toast {
  let message: string;
  switch (error.kind) {
    case "busy":
      message = "operation already running";
      break;
    // The two PACING refusals — distinct prose so a
    // caller can tell "you asked too soon" (local floor) from "the provider itself pushed back".
    case "too_soon":
      message = `refreshed moments ago — try again in ${retryAfterSeconds(error.retry_after_ms)}s`;
      break;
    case "provider_backoff":
      message = `the provider asked us to back off — retrying is blocked for ${retryAfterSeconds(error.retry_after_ms)}s`;
      break;
    // A boot-time CREDENTIAL refusal now carries the same
    // `cure` discriminant the `credential_expired` arm does, read from the SAME single-sourced
    // `CURE_COPY` map so the two refusals and the status bar cannot say three different things
    // about one credential. `null` — an unopenable store, an unresolved path, the JMAP arm — owes
    // no credential cure and keeps the bare reason, exactly as this arm always rendered it.
    //
    // The `?? "undetermined"` hedge is the one `render.ts`'s
    // status bar already carries on the same discriminant. The wire union is CLOSED today, so
    // the two agree today — but they are two renderings of ONE value and only one of them
    // survived a cure the map has no row for: an unmapped index is `undefined`, and the template
    // literal paints it, so the operator reads a toast opening with the word "undefined". The
    // fallback is for an UNKNOWN cure only; `null` is ABSENT and keeps its own bare-reason arm.
    //
    // The map is `UNCONFIGURED_CURE_COPY`, not `CURE_COPY`.
    // THIS REFUSAL IS THE BOOT'S, and its refusals are the local filesystem's — a read that was
    // denied, a lock that timed out, a ratchet that would not parse. The refresh-stage copy
    // opened those with "the provider refused" and promised a renewal for a session with nothing
    // to renew, contradicting the reason appended two words later. The status bar reads the same
    // selection through `cureCopyFor`, so the two surfaces still cannot drift.
    case "session_unconfigured":
      message =
        error.cure !== null
          ? `${UNCONFIGURED_CURE_COPY[error.cure] ?? UNCONFIGURED_CURE_COPY.undetermined}: ${error.reason}`
          : error.reason;
      break;
    // The credential's own
    // `expires_at` has passed — the TRUE cure depends on `error.cure` (five distinct causes, only
    // one of which is a re-mint), read from the single-sourced `CURE_COPY` map so this toast and
    // the status bar's own notice (`render.ts`) never drift apart. The engine's own sentence
    // (`reason`) still rides along beside the cure sentence.
    case "credential_expired":
      message = `${CURE_COPY[error.cure]}: ${error.reason}`;
      break;
    case "refused":
      message = error.reason;
      break;
    case "store":
      message = error.reason;
      break;
    case "internal":
      message = error.reason;
      break;
    // The three plan refusals carry the engine's TOKEN, never prose — rendered through
    // the ONE copy map, `PLAN_REFUSAL_COPY` (`toastForPlanRefusal` reads the same one).
    case "plan_required":
    case "plan_refused":
    case "plan_child_refused":
      message = planRefusalMessage(error);
      break;
    // The connector's capability refusal, by its own name. No cure is
    // offered: turning a verb on is a deliberate enablement step (ADR-P010), not something to retry.
    case "unsupported_capability":
      message = UNSUPPORTED_CAPABILITY_MESSAGE;
      break;
    // Same class as `unsupported_capability` just above: the
    // connector's credential was rejected mid-run, by its own fixed sentence — never a connector
    // message riding a `credential_rejected: ` string prefix a caller had to parse out of
    // `refused` (the earlier shape). LATENT (see the kind's own doc comment in `ipc.ts`).
    case "credential_rejected":
      message = CREDENTIAL_REJECTED_MESSAGE;
      break;
  }
  return { message, undoKeys: [], staleReason: null, refusalKind: error.kind };
}

/// The `unsupported_capability` refusal's sentence — what the build does not do,
/// and nothing it cannot back (no cure, no promise of a later build).
export const UNSUPPORTED_CAPABILITY_MESSAGE = "this verb is not enabled on this build";

/// The `credential_rejected` refusal's sentence — the credential itself was
/// rejected mid-run; the actionable fact (check/refresh the credential) named plainly, never a
/// connector message.
export const CREDENTIAL_REJECTED_MESSAGE = "the credential was rejected — check the app's credential and try again";

// ===============================================================================================
// The plan review: the review state, the refusal copy keyed by the
// ENGINE's token, and the apply report in the BatchOutcome vocabulary.
// ===============================================================================================

/// THE BYPASS LANE ("the bypass waives the SCREEN, never the machine's
/// own safety or honesty"): a plan frozen `bypassed` opens NO review screen. Every other lane
/// does. The frozen lane decides — never the knob in force.
export function opensReviewScreen(review: PlanReviewView): boolean {
  return review.lane !== "bypassed";
}

/// The NON-BLOCKING toast a bypassed plan shows instead of its screen, before the apply: what is
/// about to run with no screen, and the plan's frozen notice when it carries one
/// ("the bypass waives the screen, never the notice").
export function toastForPlanBypass(review: PlanReviewView): Toast {
  const { verb, count } = review.presentation.header;
  const toast: Toast = {
    message: `RED bypass is on — ${verb} of ${count} messages runs with no approval screen`,
    undoKeys: [],
    staleReason: null,
    refusalKind: null,
  };
  return review.bypass_notice === null ? toast : { ...toast, detail: [review.bypass_notice] };
}

/// The open plan review: the canonical payload the engine answered, and whether an
/// approve → apply round trip is in flight (the approve control is disabled while it is).
export interface PlanReviewState {
  review: PlanReviewView;
  busy: boolean;
}

/// The three refusal kinds the plan doors answer.
export type PlanRefusal = Extract<SurfaceError, { kind: "plan_refused" | "plan_required" | "plan_child_refused" }>;

export function isPlanRefusal(error: SurfaceError): error is PlanRefusal {
  return error.kind === "plan_refused" || error.kind === "plan_required" || error.kind === "plan_child_refused";
}

/// One plain sentence per token the plan doors can answer (`src-tauri/src/lib.rs`'s ONE closed
/// token table, `PlanWireToken`, + the engine's `PlanSendRefusal::TOKENS`; `state.test.ts` reads
/// both and requires a row here for each). Each
/// sentence says what did NOT happen and, where one exists, the one act that cures it — never a
/// cure the refusal does not establish. An unknown token renders AS the token (`planRefusalMessage`).
export const PLAN_REFUSAL_COPY: Record<string, string> = {
  // The send fence's plan arm (PlanSendRefusal) and the plan doors' shared tokens.
  plan_required: "this RED verb runs only as part of an approved plan — it was not run",
  snapshot_absent: "this build has no content snapshots yet — turn backups off to run RED verbs, or wait for the snapshot slice",
  state_diverged: "the message changed since you approved it — it was not touched; re-plan from the current state",
  evidence_invalid: "the approval does not match what the plan froze — nothing was run under it",
  expired: "the plan's approval window passed — re-plan",
  grant_retired: "the grant this plan was made under is no longer confirmed in force — nothing was sent under it; re-plan once the credential is current",
  coverage_diverged: "the backups setting changed since approval — re-plan",
  episode_closed: "this plan already finished, or was cancelled or invalidated — re-plan to run it again",
  episode_held: "this plan is paused",
  not_ready: "the plan's pre-flight check has not completed — nothing was sent",
  no_episode: "this plan's run was never started — nothing was sent",
  plan_epoch_mismatch: "the control epoch moved since this plan was made — nothing was sent; re-plan",
  not_a_member: "that message is not part of this plan — it was not touched",
  evidence_absent: "this plan carries no recorded approval — nothing was sent",
  capture_required: "the message's state before the change was not captured — it was not touched",
  bypass_notice_absent: "this plan skips the approval screen with backups off, and it was made before its backups-off warning was recorded — nothing was sent; re-plan",
  // A plan child's admission (PlanChildRefusal).
  no_plan: "there is no such plan in this store",
  not_approved: "this plan has not been approved — nothing was sent",
  episode_not_active: "this plan's run is not active — nothing was sent",
  verb_mismatch: "the command does not match the plan's verb — it was not run",
  account_mismatch: "the command does not match the plan's account — it was not run",
  key_mismatch: "the command's identity does not match the plan's — it was not run",
  epoch_mismatch: "the control epoch moved since this plan was made — nothing was sent; re-plan",
  not_a_red_verb: "a plan carries only trash or spam — this verb was not run under it",
  // The plan doors' own preconditions (the plan store and the episode start).
  already_approved: "this plan is already approved",
  unknown_member: "a selected message is not in the local store — refresh, then plan again",
  dispatch_began: "another run of this plan already started sending — this run did nothing",
  // The plan core's refusals (PlanRefusal) — a plan that cannot be made or read as asked.
  empty_members: "nothing is selected to plan",
  conflicting_duplicate: "a message appears twice with different content — plan again",
  header_count_mismatch: "the plan's header does not match its members — no plan was made",
  warning_shape: "the plan's backups warning is malformed — no plan was made",
  header_diverges: "the plan's header names another account, verb or tier — no plan was made",
  presentation_row_count: "the plan's rows do not match its members — no plan was made",
  presentation_row_diverges: "a plan row does not match its member — no plan was made",
  configured_k_zero: "the spot-check size must be at least 1",
  commitment: "the plan's commitment could not be computed — no plan was made",
  lane_mismatch: "the approval is for another screen than the plan froze — nothing was run under it",
  plan_id_mismatch: "the approval names another plan — nothing was run under it",
  approver_missing: "the approval names no approver — nothing was run under it",
  view_mismatch: "what was approved is not what the plan froze — nothing was run under it",
  sample_mismatch: "the spot-check sample is not the one the engine derived — nothing was run under it",
  sample_k_mismatch: "the spot-check size is not the plan's — nothing was run under it",
  bypass_generation_mismatch: "the RED-bypass setting changed since the plan was made — re-plan",
  // The wire approve door and a bypass-lane plan.
  bypass_lane_no_screen: "this plan runs on the RED-bypass lane, which has no approval screen — nothing was approved here; applying it records its approval mechanically",
  unknown_verb: "that verb cannot be planned",
  plan_shape: "the stored plan disagrees with itself — it cannot be shown or run",
};

/// The refusal's token: its `reason`, or — for `plan_required`, which carries none — its kind.
export function planRefusalToken(refusal: PlanRefusal): string {
  return refusal.kind === "plan_required" ? refusal.kind : refusal.reason;
}

/// The sentence for a plan refusal; an unknown token renders AS the token (never a blank, and
/// never a property the map inherits).
export function planRefusalMessage(refusal: PlanRefusal): string {
  const token = planRefusalToken(refusal);
  return Object.prototype.hasOwnProperty.call(PLAN_REFUSAL_COPY, token) ? PLAN_REFUSAL_COPY[token] : token;
}

function diffLine(diff: MemberDiffView): string {
  return `${diff.atom}: expected ${diff.expected}, observed ${diff.observed === null ? "not captured" : diff.observed}`;
}

export function toastForPlanRefusal(refusal: PlanRefusal): Toast {
  const detail: string[] = [];
  if (refusal.kind === "plan_refused") {
    if (refusal.member_ref !== null) {
      detail.push(`member ${refusal.member_ref}`);
    }
    detail.push(...refusal.diff.map(diffLine));
  }
  return { message: planRefusalMessage(refusal), undoKeys: [], staleReason: null, refusalKind: refusal.kind, detail };
}

/// What a plan run did, per member — applied / refused / not attempted (the BatchOutcome
/// vocabulary's succeeded / failed / not attempted), then any member still in flight or ended in
/// another terminal status, by name; the members this run SKIPPED (already settled) and the ones it
/// found HELD and re-drove; the stale line when the local projection could not be
/// written; the plan's frozen bypass notice, repeated. A refused PREFLIGHT ran no member at all,
/// and says so. The toast offers the APPLIED children's undo keys in the engine's order (last
/// first), each labelled with its member — and each applied member whose restoration is
/// UNDETERMINED gets its restoration line BESIDE that offer
/// (never only after the undo). A run that STOPPED before every member was attempted says so first,
/// and why — what it did do is reported exactly as a finished run's.
export function toastForPlanApply(outcome: PlanApplyOutcome): Toast {
  const notice = outcome.bypass_notice === null ? [] : [outcome.bypass_notice];
  if (outcome.preflight?.outcome === "refused") {
    const diverged = outcome.preflight.diverged;
    return {
      message: `plan not run: ${diverged.length} of ${outcome.members.length} members changed since approval — nothing was touched; re-plan from the current state`,
      undoKeys: [],
      staleReason: null,
      refusalKind: null,
      detail: [...diverged.flatMap(([member, diffs]) => diffs.map((d) => `${member} — ${diffLine(d)}`)), ...notice],
    };
  }
  const restorationOf = new Map(outcome.undo_keys.map((offer) => [offer.member_ref, offer.restoration]));
  let applied = 0;
  let refused = 0;
  let notAttempted = 0;
  let inFlight = 0;
  const otherTerminal = new Map<string, number>();
  const detail: string[] = [];
  if (outcome.stopped !== null) {
    detail.push(`why it stopped: ${toastForRefusal(outcome.stopped).message}`);
  }
  for (const [member, state] of outcome.members) {
    switch (state.state) {
      case "applied": {
        applied += 1;
        const line = restorationLine(restorationOf.get(member) ?? null);
        if (line !== null) {
          detail.push(`${member}: ${line}`);
        }
        break;
      }
      case "refused":
        refused += 1;
        detail.push(`${member}: ${planRefusalMessage({ kind: "plan_refused", reason: state.reason, member_ref: member, diff: state.diff })}`);
        break;
      case "not_minted":
        notAttempted += 1;
        break;
      case "in_flight":
        inFlight += 1;
        break;
      case "terminal":
        otherTerminal.set(state.status, (otherTerminal.get(state.status) ?? 0) + 1);
        break;
    }
  }
  const parts = [`${applied} applied`, `${refused} refused`, `${notAttempted} not attempted`];
  if (inFlight > 0) {
    parts.push(`${inFlight} in flight`);
  }
  for (const [status, count] of otherTerminal) {
    parts.push(`${count} ${status}`);
  }
  if (outcome.skipped.length > 0) {
    parts.push(`${outcome.skipped.length} skipped (already settled)`);
  }
  if (outcome.held.length > 0) {
    parts.push(`${outcome.held.length} held (re-driven through recovery)`);
  }
  detail.push(...outcome.skipped.map((member) => `${member}: skipped — already settled`));
  detail.push(...outcome.held.map((member) => `${member}: held — re-driven through recovery`));
  detail.push(...notice);
  const staleReason = projectionStaleReason(outcome.projection);
  if (staleReason) {
    parts.push(STALE_ROW_LINE);
  }
  const toast: Toast = {
    message: outcome.stopped === null ? parts.join(", ") : `run stopped — ${parts.join(", ")}`,
    undoKeys: outcome.undo_keys.map((offer) => offer.undo_key),
    staleReason,
    refusalKind: null,
    detail,
  };
  if (outcome.undo_keys.length > 0) {
    toast.undoLabels = Object.fromEntries(outcome.undo_keys.map((offer) => [offer.undo_key, offer.member_ref]));
  }
  // Each applied member's restoration line, keyed by ITS undo key — the same line
  // the detail shows beside the offer, carried with the key wherever the offer is carried.
  const owed = outcome.undo_keys.flatMap((offer): [string, string][] => {
    const line = restorationLine(offer.restoration);
    return line === null ? [] : [[offer.undo_key, `${offer.member_ref}: ${line}`]];
  });
  if (owed.length > 0) {
    toast.undoRestoration = Object.fromEntries(owed);
  }
  return toast;
}

/// The one completion token of a plan whose episode is still ACTIVE with work outstanding
/// (`src-tauri/src/lib.rs` `completion_token`: `Completion::Incomplete`). Every other token names an
/// episode that ended (`completed`, `invalidated:*`, a terminal status) or never began.
const INCOMPLETE_COMPLETION = "incomplete";

/// The completion token of a run whose post-run settle FAILED
/// (`src-tauri/src/lib.rs` `COMPLETION_UNDETERMINED`) — the run could not read what the episode
/// became. It names NO ended episode, so it never proves the plan done on its own.
const UNDETERMINED_COMPLETION = "undetermined";

/// Every member's `state` that counts as
/// SETTLED — `applied`, `refused` and `terminal` all mean the driver reached a final answer for
/// that member; `not_minted` (never touched) and `in_flight` (held, re-drivable) do not.
function isMemberTerminal(view: MemberStateView): boolean {
  return view.state !== "not_minted" && view.state !== "in_flight";
}

/// Whether a
/// run's review re-opens is a COMPLETION question, never a `stopped` question. `stopped` says WHY
/// the run does not have more to do this round, not WHETHER the plan is done — a credential
/// rejection on the LAST member can leave every child terminal (the plan IS complete) while still
/// setting `stopped`, and the OLD rule (`stopped !== null || …`) called that incomplete anyway,
/// installing a Retry handle that could never succeed. COMPLETE iff
/// the engine's own `completion` token names an ended episode (anything but the one
/// `INCOMPLETE_COMPLETION` token — `completed`, `invalidated:*`, an `EpisodeStatusToken`,
/// `no_episode`), OR every member already reads back settled regardless of what `completion` says
/// (the engine's own completion computation and the member read are two independent doors; either
/// one proving DONE is enough) — `stopped` never overrides either.
///
/// `UNDETERMINED_COMPLETION` names no ended episode either (the settle
/// failed), and an EMPTY member list proves nothing (the run could not read any member) — so a run
/// answering both re-opens its review, where Retry re-reads the store.
export function reopensReviewAfterRun(outcome: PlanApplyOutcome): boolean {
  const endedEpisode = outcome.completion !== INCOMPLETE_COMPLETION && outcome.completion !== UNDETERMINED_COMPLETION;
  const everyMemberSettled = outcome.members.length > 0 && outcome.members.every(([, view]) => isMemberTerminal(view));
  return !(endedEpisode || everyMemberSettled);
}

/// Terminal vs transient for
/// EVERY `SurfaceError` kind EXCEPT `refused` — a `Record` over the closed kind union MINUS
/// `"refused"`, so `tsc` itself is the DERIVED witness: adding a new kind to
/// `SurfaceError` (`src/ipc.ts`) without adding it here is a COMPILE ERROR, never a silently
/// missing arm. `refused` is handled separately in `isTerminalRefusal` below, from its OWN wire
/// field — it is no longer a kind this table can answer for at all (the CONFLATED-kind residual
/// `refused` now carries `terminal` explicitly, set in the ONE
/// classifier, `SurfaceError::execute`, from the `ExecuteError` variant that produced it).
///
/// The five kinds reachable as `PlanApplyOutcome.stopped` that audit A3 classifies TRANSIENT
/// (`busy`, `too_soon`, `provider_backoff`, `credential_rejected`, `store`) and the four it
/// classifies TERMINAL (`plan_child_refused` — every token; `unsupported_capability`;
/// `plan_refused`; `plan_required`) are A3's table, verbatim. The remaining kinds are NEVER
/// reachable as `stopped` (A3 does not classify them) but ARE throwable bare from `plan_apply`
/// (the `main.ts` catch path) — this fold's own conservative judgment call, stated here:
/// `session_unconfigured`, `credential_expired` and `internal` default TERMINAL. A stuck retry
/// handle nobody can ever successfully spend is the exact defect this class closes, so an
/// unclassifiable kind favors CLEARING the handle over leaving it stuck forever.
const TERMINAL_REFUSAL_KIND: Record<Exclude<SurfaceError["kind"], "refused">, boolean> = {
  busy: false,
  too_soon: false,
  provider_backoff: false,
  session_unconfigured: true,
  credential_expired: true,
  store: false,
  internal: true,
  plan_required: true,
  plan_refused: true,
  plan_child_refused: true,
  unsupported_capability: true,
  credential_rejected: false,
};

/// ONE predicate, everywhere a caller must
/// decide whether a refusal ends the story (clear a retry handle, stop offering Retry) or leaves
/// it open (keep the handle; the same act may succeed once the transient condition clears). Takes
/// the WHOLE `SurfaceError` (not just its `kind`) because `refused` alone needs a second field —
/// every other kind answers from `TERMINAL_REFUSAL_KIND` alone, ignoring the rest of the value.
export function isTerminalRefusal(error: SurfaceError): boolean {
  if (error.kind === "refused") {
    return error.terminal;
  }
  return TERMINAL_REFUSAL_KIND[error.kind];
}

/// The rows a selection-driven verb acts on: the selected set (in row order), else the focused
/// row, else nothing — the rule `archiveSelection` has always used, in one place.
export function selectionTargets(state: Pick<AppState, "rows" | "selected" | "focusIndex">): string[] {
  if (state.selected.size > 0) {
    return state.rows.filter((r) => state.selected.has(r.message_ref)).map((r) => r.message_ref);
  }
  const focused = state.rows[state.focusIndex];
  return focused ? [focused.message_ref] : [];
}

/// `remainingKeys` is the batch walk's UNCONSUMED SUFFIX — the keys this undo has
/// not spent. It defaults to empty, which is the single-verb path's honest answer (one key, now
/// consumed) and keeps every existing call site unchanged.
///
/// `restoration` is the undone operation's verdict; its UNDETERMINED line rides on the
/// toast, and a within-closure verdict (or none) leaves the toast as it was.
///
/// The walk carries the unspent suffix too: `carried` is the
/// restoration map of the offer the walk started from; the keys still on offer keep their lines.
export function toastForUndo(
  presentation: UndoPresentationView,
  projection: ProjectionState,
  remainingKeys: readonly string[] = [],
  restoration: RestorationView | null = null,
  carried: Readonly<Record<string, string>> | undefined = undefined,
): Toast {
  const staleReason = projectionStaleReason(projection);
  const message = staleReason ? `undo: ${presentation} — ${STALE_ROW_LINE}` : `undo: ${presentation}`;
  const line = restorationLine(restoration);
  // The undo committed and its read-back failed — say so in words.
  const unreadable = presentation === "unreadable_after_undo" ? [UNREADABLE_AFTER_UNDO_LINE] : [];
  const toast = withDetail({ message, undoKeys: [...remainingKeys], staleReason, refusalKind: null }, [
    ...unreadable,
    ...(line === null ? [] : [line]),
  ]);
  return withOwedRestoration(toast, carried, remainingKeys);
}

/// The toast line for `unreadable_after_undo`.
const UNREADABLE_AFTER_UNDO_LINE = "the undo ran, but its result could not be read back — refresh to confirm";

// ===============================================================================================
// The undo route for a plan's APPLIED children
// ===============================================================================================

/// One child of a plan, undone through the existing `undo` door: which member, and what the door
/// answered.
export interface PlanUndoStep {
  member: string;
  presentation: UndoPresentationView;
  projection: ProjectionState;
  restoration: RestorationView | null;
}

/// The labels of `keys` only — what an offer still owes.
function labelsFor(labels: Readonly<Record<string, string>>, keys: readonly string[]): Record<string, string> | undefined {
  const kept = keys.filter((k) => Object.prototype.hasOwnProperty.call(labels, k));
  return kept.length > 0 ? Object.fromEntries(kept.map((k) => [k, labels[k]])) : undefined;
}

/// The plan undo walk's toast: every member undone so far, one line each with its verdict (and its
/// restoration line), and the keys the walk has not spent — still labelled.
export function toastForPlanUndo(
  steps: readonly PlanUndoStep[],
  remainingKeys: readonly string[],
  labels: Readonly<Record<string, string>>,
  carried: Readonly<Record<string, string>> | undefined = undefined,
): Toast {
  const undone = steps.filter((s) => s.presentation === "undone").length;
  const staleReason = steps.map((s) => projectionStaleReason(s.projection)).find((r) => r !== null) ?? null;
  const summary = `plan undo: ${undone} of ${steps.length} members undone`;
  const detail = steps.flatMap((s) => {
    const line = restorationLine(s.restoration);
    return [`${s.member}: ${s.presentation}`, ...(line === null ? [] : [`${s.member}: ${line}`])];
  });
  const toast: Toast = {
    message: staleReason ? `${summary} — ${STALE_ROW_LINE}` : summary,
    undoKeys: [...remainingKeys],
    staleReason,
    refusalKind: null,
    detail,
  };
  const owed = labelsFor(labels, remainingKeys);
  if (owed !== undefined) {
    toast.undoLabels = owed;
  }
  // The keys still on offer keep their restoration lines.
  return withOwedRestoration(toast, carried, remainingKeys);
}

// ===============================================================================================
// Mutation fence: `session_status`'s `mutations_live: false` (the fence-gated
// production Gmail arm) means every write verb is guaranteed-fail engine work. `verbsAllowed` is
// the guard a write-verb handler consults BEFORE issuing any IPC call — never after; `fenceToast`
// is what it renders instead, carrying the same `mutations_reason` the status bar's own fenced
// notice already shows (`render.ts`'s `status-mutations-fenced` span).
// ===============================================================================================

const MUTATIONS_FENCED_DEFAULT_REASON = "writes are not available in this build";

/// `status: null` (session_status has not landed yet — boot is still in flight) never blocks: there
/// is nothing to fence on yet, and boot's own sequencing already runs `sessionStatus()` before the
/// first paint that could accept a keystroke. Only an EXPLICIT `mutations_live: false` fences.
export function verbsAllowed(status: SessionStatus | null): boolean {
  return status?.mutations_live ?? true;
}

export function fenceToast(reason: string | null): Toast {
  return { message: reason ?? MUTATIONS_FENCED_DEFAULT_REASON, undoKeys: [], staleReason: null, refusalKind: null };
}

// ===============================================================================================
// Clipboard failure: `navigator.clipboard` may not exist (no secure context) or
// `writeText` may reject; the copy affordance must not fail invisibly.
// ===============================================================================================

export const COPY_FAILED_MESSAGE = "copy failed — clipboard unavailable";

export function copyFailedToast(): Toast {
  return { message: COPY_FAILED_MESSAGE, undoKeys: [], staleReason: null, refusalKind: null };
}

// ===============================================================================================
// Superseded pacing toasts: a busy/too_soon/provider_backoff refusal describes an
// in-flight refresh; once a refresh COMPLETES that description is stale and reads as a wedged
// operation. Cleared on `refresh_completed` — preserving any carried undo keys (the
// rule: a keyed toast is an outstanding offer and is never destroyed wholesale).
// ===============================================================================================

const PACING_REFUSAL_KINDS: ReadonlyArray<Toast["refusalKind"]> = ["busy", "too_soon", "provider_backoff"];

export const UNDO_STILL_AVAILABLE_MESSAGE = "undo still available";

export function clearSupersededPacingToast(toast: Toast | null): Toast | null {
  if (toast === null || !PACING_REFUSAL_KINDS.includes(toast.refusalKind)) {
    return toast;
  }
  if (toast.undoKeys.length > 0) {
    const kept: Toast = { message: UNDO_STILL_AVAILABLE_MESSAGE, undoKeys: [...toast.undoKeys], staleReason: null, refusalKind: null };
    // Plan-child keys keep their member labels wherever they are carried.
    if (toast.undoLabels !== undefined) {
      kept.undoLabels = toast.undoLabels;
    }
    // And their restoration lines — an undo offer is never kept without them.
    return withOwedRestoration(kept, toast.undoRestoration, toast.undoKeys);
  }
  return null;
}

// ===============================================================================================
// The UNDO-KEY MERGE — one helper, every toast that can land ON TOP of a keyed one
// ===============================================================================================

/// Carry a live toast's UNCONSUMED undo keys onto the toast that is about to replace it
/// (widened).
///
/// A toast that carries keys is an outstanding offer: the verb happened, and the only handle on
/// reversing it is sitting in `undoKeys`. Any toast that replaces it wholesale destroys that
/// handle — which was an earlier defect for `refusal_toast` and, unchanged, the same defect for
/// `copy_failed_toast`: a clipboard failure has NOTHING to do with the archive you just ran, yet it
/// threw the archive's undo key away. Both events are now the same shape — the replacing toast
/// keeps the keys and names that they are still there — so a third such toast has one rule to reuse
/// rather than a second one to invent.
///
/// A previous toast with NO keys (consumed by an undo, or dismissed — `toast_dismissed` clears
/// `state.toast` outright) has nothing to preserve, and the replacing toast renders unqualified.
function carryUnconsumedUndoKeys(next: Toast, previous: Toast | null): Toast {
  const preservedKeys = previous?.undoKeys ?? [];
  if (preservedKeys.length === 0) {
    return next;
  }
  const carried: Toast = {
    ...next,
    undoKeys: [...preservedKeys],
    message: `${next.message} — undo still available`,
  };
  // The carried keys keep THEIR labels (a plan's children), never the next toast's.
  delete carried.undoLabels;
  if (previous?.undoLabels !== undefined) {
    carried.undoLabels = previous.undoLabels;
  }
  // And THEIR restoration lines, read from the key map (never re-copied from the
  // previous toast's detail, so a line is carried once however many toasts carry it).
  delete carried.undoRestoration;
  return withOwedRestoration(carried, previous?.undoRestoration, preservedKeys);
}

// ===============================================================================================
// Status re-read after a refusal: boot's `session_status` read is otherwise the
// ONLY read for the whole session — an expiry-class refusal toasts but the status bar stays stale
// (still shows a credential that has since died, or a session that was never configured). This
// names exactly which refusal kinds are worth spending a re-read on: the ones whose STATUS itself
// just changed, never a pacing/busy refusal (nothing about the status changed there).
// ===============================================================================================

export function shouldRefreshStatus(errorKind: SurfaceError["kind"]): boolean {
  return errorKind === "credential_expired" || errorKind === "session_unconfigured";
}

// ===============================================================================================
// Reading pane text — body rendering
// ===============================================================================================

export interface ReadingPaneText {
  bodyText: string | null;
  attachmentLine: string | null;
  noBodyLine: string | null;
  truncatedMarker: boolean;
}

// ===============================================================================================
// Reading pane STATE: opening B must never keep rendering A's stale content while
// B's fetch is in flight (or after it fails). The pane content is now KEYED to the ref it belongs
// to — every non-empty variant carries its own `ref`, so "loading" / "error" / "loaded" can never
// be silently paired with the wrong message's data. `reading_pane_requested` moves straight to
// `loading` (clearing whatever was there before); a response only ever moves the pane to `loaded`
// or `error` for the ref it was issued for (guarded by the existing generation token below).
// ===============================================================================================

export type ReadingPaneState =
  | { status: "empty" }
  | { status: "loading"; ref: string }
  | { status: "error"; ref: string; reason: string }
  | { status: "loaded"; ref: string; text: ReadingPaneText };

export const EMPTY_READING_PANE: ReadingPaneState = { status: "empty" };

const ATTACHMENT_UNAVAILABLE_SUFFIX = "attachment opening is not available in v1";
const NO_TEXTUAL_BODY_LINE = "This message has no textual body.";

// JMAP's `count` is unknowable when the provider only reports presence — the wire
// carries `{has_attachments: true, count: 0}` for that case (the transport doc names it), and a
// literal "0 attachments" line contradicted the "attachments present" fact right next to it. A
// zero count paired with `has_attachments: true` therefore renders a count-FREE presence line
// instead of pretending the 0 is a real count.
const ATTACHMENTS_PRESENT_COUNT_UNKNOWN_LINE = `attachments present — ${ATTACHMENT_UNAVAILABLE_SUFFIX}`;

function attachmentLineFor(attachments: { has_attachments: boolean; count: number }): string | null {
  if (!attachments.has_attachments) {
    return null;
  }
  if (attachments.count === 0) {
    return ATTACHMENTS_PRESENT_COUNT_UNKNOWN_LINE;
  }
  return `${attachments.count} attachments — ${ATTACHMENT_UNAVAILABLE_SUFFIX}`;
}

/// `NoTextualBody` is no longer a bare
/// string — it is now `{ NoTextualBody: { attachments } }`, carrying attachment presence, because
/// attachment-only mail (no textual part at all) still has something true to say about it. The
/// attachment line renders on BOTH arms now, from the same `attachmentLineFor` helper.
export function readingPaneTextFor(body: BodyAvailability): ReadingPaneText {
  if ("NoTextualBody" in body) {
    return {
      bodyText: null,
      attachmentLine: attachmentLineFor(body.NoTextualBody.attachments),
      noBodyLine: NO_TEXTUAL_BODY_LINE,
      truncatedMarker: false,
    };
  }
  const view = body.Text;
  return {
    bodyText: view.plain_text,
    attachmentLine: attachmentLineFor(view.attachments),
    noBodyLine: null,
    truncatedMarker: view.truncated,
  };
}

// ===============================================================================================
// The application state + the ONE reducer
// ===============================================================================================

export interface AppState {
  status: SessionStatus | null;
  rows: InboxRow[];
  nextCursor: PageCursor | null;
  selected: Set<string>;
  focusIndex: number;
  freshness: FreshnessView | null;
  toast: Toast | null;
  /// Latches true — the BLACK banner never un-lights itself within a session (BLACK
  /// is a seizure state, not a flicker); a fresh session (page reload) starts clean.
  severed: boolean;
  readingPane: ReadingPaneState;
  readingPaneRef: string | null;
  /// A monotonic request-generation counter that guards body-fetch races. Bumped by
  /// `bodyRequestFor` every time a body fetch is issued; a response only lands (`acceptBody`) if
  /// its token still equals this field at the time it arrives.
  bodyRequestGeneration: number;
  /// Whether the LAST refresh (`refresh_inbox` or `refresh_more_inbox`)
  /// reported a provider continuation is still held — i.e. whether `refresh_more_inbox` has
  /// something to spend. Set only by `refresh_completed`; a later refusal (e.g. `too_soon`) never
  /// resets it — the fact it reports is about the provider's mailbox walk, not about whether the
  /// most recent call happened to succeed.
  hasMore: boolean;
  /// A monotonic REPLACE-generation counter, same shape as `bodyRequestGeneration`
  /// but for the loaded LIST rather than the reading pane. Bumped ONLY by `page_loaded` — the
  /// action that REPLACES the whole window (boot, `r`-refresh, and the post-continuation re-read
  /// in `reloadLoadedWindow`) — never by `page_appended`, which merely grows it. A `j`-triggered
  /// local-page fetch (`loadNextPage`'s `inboxPage` branch in `main.ts`) can still be in flight
  /// when an `r` reload lands and replaces `rows` out from under it; without this guard the late
  /// `page_appended` response then appends a PRE-RELOAD page onto the POST-RELOAD list — rows the
  /// reload legitimately dropped reappear, and the cursor it lands is stale. `loadNextPage`
  /// captures this counter before issuing the fetch and stamps it onto the `page_appended` it
  /// dispatches; the reducer drops an append whose stamp no longer matches.
  listGeneration: number;
  /// A monotonic request-generation counter for STATUS re-reads, same
  /// shape as `bodyRequestGeneration`: overlapping commands each fire `refreshStatus()` in their
  /// `finally`, and those independent `session_status` reads can complete out of order — an older
  /// expired-cell snapshot must not repaint over the newer live one. `status_read_requested`
  /// bumps it at issue time; `status_updated` presents the token its read captured, and the
  /// reducer drops a response whose token a newer read has superseded.
  statusRequestGeneration: number;
  /// The open plan review, or `null` when none is open.
  planReview: PlanReviewState | null;
  /// The plan-review REQUEST GENERATION — bumped by every FRESH mint
  /// (`plan_minted` with no `generation`), never by a reopen. A run captures it when it begins
  /// (`runPlan`, `main.ts`) and stamps it on its `plan_applied` and on its reopen's `plan_minted`,
  /// so a late result can tell whether a newer review was minted while it was in flight. It lives
  /// INDEPENDENTLY of `planReview`: `runPlan` dispatches `plan_applied(A)` — which clears A — and
  /// THEN re-opens A, so a gate on "the active review" would starve that legitimate reopen. The
  /// reading pane's `bodyRequestGeneration` is the same pattern.
  planGeneration: number;
  /// The bypass-lane plan whose last run left it INCOMPLETE, or
  /// `null`. While it is pending, `#` / `!` on the SAME selection (same verb, same member set)
  /// re-applies THIS plan — no new mint — and the toast says so; a run that ends it clears it.
  pendingBypassPlan: PendingBypassPlan | null;
}

/// What a pending bypass-lane plan is, as the renderer matches a key press against it.
export interface PendingBypassPlan {
  planId: string;
  verb: string;
  members: string[];
}

export function initialState(): AppState {
  return {
    status: null,
    rows: [],
    nextCursor: null,
    selected: new Set(),
    focusIndex: 0,
    freshness: null,
    toast: null,
    severed: false,
    readingPane: EMPTY_READING_PANE,
    readingPaneRef: null,
    bodyRequestGeneration: 0,
    hasMore: false,
    listGeneration: 0,
    statusRequestGeneration: 0,
    planReview: null,
    planGeneration: 0,
    pendingBypassPlan: null,
  };
}

/// The pending bypass plan a `#` / `!` on `targets` re-applies — the same verb over the SAME
/// member set (order-free) — or `null` when the press is a new plan.
export function pendingBypassPlanFor(
  pending: PendingBypassPlan | null,
  verb: string,
  targets: readonly string[],
): PendingBypassPlan | null {
  if (pending === null || pending.verb !== verb || pending.members.length !== targets.length) {
    return null;
  }
  const members = new Set(pending.members);
  return targets.every((t) => members.has(t)) && new Set(targets).size === members.size ? pending : null;
}

// ===============================================================================================
// Body-fetch request generations
// ===============================================================================================

/// Message A's slow `message_body` fetch can still be in flight when the user opens message B; if
/// A's response lands after B was opened, it must not overwrite B's now-focused reading pane. This
/// is a request-generation counter: `bodyRequestFor` bumps the counter and returns the token this
/// specific request must present at `acceptBody` time to be allowed to land — a caller issues it
/// right after dispatching, holds the token across the `await`, and passes it back with the
/// response.
export function bodyRequestFor(state: AppState, ref: string): { state: AppState; token: number } {
  // Opening the SAME ref a second time while its fetch is already in flight used to
  // bump the generation again — the backend refused the duplicate call as Busy, and the FIRST
  // (successful) response then got discarded as stale by the generation guard below, leaving the
  // pane empty. A reopen of the same ref while it is already loading is a no-op: hand back the
  // CURRENT token, untouched state, and issue no new fetch.
  if (state.readingPane.status === "loading" && state.readingPane.ref === ref) {
    return { state, token: state.bodyRequestGeneration };
  }
  const token = state.bodyRequestGeneration + 1;
  return {
    // Clears any prior message's content immediately — the pane must show B's own
    // loading state the instant B is opened, never A's leftover text (successful or not).
    state: { ...state, bodyRequestGeneration: token, readingPaneRef: ref, readingPane: { status: "loading", ref } },
    token,
  };
}

/// Applies a body response ONLY if `token` still matches the CURRENT generation; a stale token
/// (a newer request has since been issued for a different — or even the same — ref) is silently
/// dropped, leaving whatever is already on screen untouched.
export function acceptBody(
  state: AppState,
  token: number,
  ref: string,
  body: BodyAvailability,
): AppState {
  if (token !== state.bodyRequestGeneration) {
    return state;
  }
  return { ...state, readingPaneRef: ref, readingPane: { status: "loaded", ref, text: readingPaneTextFor(body) } };
}

/// The failure counterpart of `acceptBody` — a fetch that throws (network refusal,
/// severed session, etc.) must not leave the pane silently showing whatever was already on
/// screen (e.g. a PRIOR message's text). Same stale-token guard as `acceptBody`: dropped if a
/// newer request has since superseded this one.
export function rejectBody(state: AppState, token: number, ref: string, reason: string): AppState {
  if (token !== state.bodyRequestGeneration) {
    return state;
  }
  return { ...state, readingPaneRef: ref, readingPane: { status: "error", ref, reason } };
}

// ===============================================================================================
// Cursor-driven incremental loading: `next_cursor` was stored but nothing ever
// consumed it, so rows beyond page 1 were unreachable. `page_appended` fetches and appends the
// next local page (deduped by ref, sort order preserved); `isAtPageBoundary` is the pure
// predicate a caller uses to decide WHEN to fetch it.
// ===============================================================================================

/// True exactly when the focused row is the LAST currently-loaded row and a `nextCursor` is
/// present — i.e. moving `j` any further would run off the end of what has been fetched, and
/// there is more to fetch. `rowsLength === 0` is always false (nothing to be "at the bottom" of).
export function isAtPageBoundary(
  focusIndex: number,
  rowsLength: number,
  nextCursor: PageCursor | null,
): boolean {
  if (rowsLength <= 0 || nextCursor === null) {
    return false;
  }
  return focusIndex === rowsLength - 1;
}

/// The pure decision behind `loadNextPage` — which of three things a
/// "load more" moment should do. `nextCursor` (the LOCAL SQLite window) always wins when present:
/// paging locally spends no provider round trip. Only once it is exhausted does `hasMore` (the
/// SESSION's held provider continuation, per the last refresh) matter at all.
export type LoadMoreDecision = "local-page" | "provider-fetch" | "none";

export function loadMoreAction(state: AppState): LoadMoreDecision {
  if (state.nextCursor !== null) {
    return "local-page";
  }
  if (state.hasMore) {
    return "provider-fetch";
  }
  return "none";
}

/// THE FULL `j`-KEY LOAD-MORE CONTRACT, empty list included. `loadMoreAction` alone
/// never looked at `rows.length`, but its only caller (`main.ts`'s `move_down` handler) gated the
/// call behind "focus is at the last loaded row" — a condition an EMPTY list can never satisfy
/// (there is no row to be "at"). That left an empty list with `hasMore: true` (or a held local
/// `nextCursor`) with NO way to ever advance: `j` moved focus nowhere (`clampFocus` on zero rows is
/// a no-op) and the boundary check required `rows.length > 0`.
///
/// The fix folds both cases into one pure predicate: an empty list with something to load fires
/// immediately (there is no "last row" gate to apply), and a non-empty list keeps the exact
/// prior behavior — fire only when focus has reached the last loaded row.
export function shouldLoadMoreOnMoveDown(state: AppState): boolean {
  if (loadMoreAction(state) === "none") {
    return false;
  }
  if (state.rows.length === 0) {
    return true;
  }
  return state.focusIndex === state.rows.length - 1;
}

/// How deep the local re-page after a PROVIDER CONTINUATION has to go (UI half).
///
/// `refresh_more_inbox` is purely additive on the store side — it never removes a row — but it
/// DOES upsert: a message the continuation returned that the window already showed comes back with
/// whatever headers the provider says now (read/unread, starred, a corrected subject). Appending
/// the tail cannot land those, because `page_appended` dedupes by ref and keeps the copy already on
/// screen. So the loaded window is re-read from the top instead, and it must cover everything that
/// was loaded PLUS the page the continuation just made reachable.
export function windowReloadDepth(loadedRows: number, pageSize: number): number {
  return loadedRows + pageSize;
}

export type Action =
  | { type: "status_loaded"; status: SessionStatus }
  /// Bumps `statusRequestGeneration` the moment a status re-read is ISSUED
  /// `refreshStatus` dispatches this, reads the fresh generation back as its token, and stamps
  /// that token onto the `status_updated` it later lands.
  | { type: "status_read_requested" }
  /// Lands a status re-read issued AFTER an expiry-class refusal (`shouldRefreshStatus`)
  /// A distinct action from `status_loaded` (boot's one-shot read) so the two call sites stay
  /// readable at their own dispatch site, even though today they apply identically.
  /// `token` is the generation the re-read captured at issue time; the
  /// reducer drops a response a newer read has since superseded.
  | { type: "status_updated"; token: number; status: SessionStatus }
  | { type: "page_loaded"; rows: InboxRow[]; nextCursor: PageCursor | null; freshness: FreshnessView | null }
  /// `generation` is the `listGeneration` the caller read BEFORE issuing the fetch
  /// this append landed from — the reducer drops the append if a `page_loaded` has since bumped
  /// past it (see [`AppState.listGeneration`]).
  | { type: "page_appended"; rows: InboxRow[]; nextCursor: PageCursor | null; generation: number }
  | { type: "move_focus"; delta: number }
  | { type: "toggle_select" }
  | { type: "reading_pane_requested"; messageRef: string }
  | { type: "reading_pane_response"; token: number; messageRef: string; body: BodyAvailability }
  | { type: "reading_pane_failed"; token: number; messageRef: string; reason: string }
  /// `restoration` is the verb outcome's verdict (absent ⇒ none to show).
  | { type: "verb_toast"; verbLabel: string; undoKey: string; projection: ProjectionState; restoration?: RestorationView | null }
  | { type: "batch_toast"; verbLabel: string; refs: string[]; results: PerMessageAttempt[] }
  /// `remainingKeys` carries the batch walk's UNCONSUMED SUFFIX — the keys this undo
  /// did not spend. Optional: the single-verb undo path owes nothing after its one call, and every
  /// dispatch site that omits it keeps the previous "everything is consumed" meaning.
  | {
      type: "undo_toast";
      presentation: UndoPresentationView;
      projection: ProjectionState;
      remainingKeys?: readonly string[];
      /// The undone operation's restoration verdict (absent ⇒ none to show).
      restoration?: RestorationView | null;
      /// The restoration map of the offer the walk started from.
      undoRestoration?: Readonly<Record<string, string>>;
    }
  | { type: "refusal_toast"; error: SurfaceError }
  /// A fenced write-verb short-circuit's toast — never reaches `refusal_toast` because
  /// no IPC call was ever issued, so there is no `SurfaceError` to carry.
  | { type: "fence_toast"; reason: string | null }
  /// Lands a `RefreshOutcome` from EITHER refresh door (`refresh_inbox`
  /// page 1, or `refresh_more_inbox`'s continuation) — the freshness half and `has_more` together,
  /// since both doors answer the identical flattened shape.
  | { type: "refresh_completed"; freshness: FreshnessView; hasMore: boolean }
  /// `navigator.clipboard` may be absent (no secure context) or its `writeText` may
  /// reject — a silently-swallowed promise left the copy affordance failing invisibly. `render.ts`
  /// feature-detects/catches around the clipboard call and routes the failure through this action,
  /// the same toast path every other verb outcome renders through.
  | { type: "copy_failed_toast" }
  | { type: "toast_dismissed" }
  /// The plan review — opened with the payload a mint or a review answered, closed, marked
  /// busy for an approve → apply round trip, and closed by the apply's per-member report.
  /// `generation` ABSENT = a FRESH mint (bumps `planGeneration`, always
  /// replaces); PRESENT = a run's REOPEN, installed only while no fresh mint has happened since
  /// that run began (`generation === planGeneration`).
  | { type: "plan_minted"; review: PlanReviewView; generation?: number }
  | { type: "plan_review_closed" }
  /// `planId` names the review the flag is for; it never lands on another.
  | { type: "plan_busy"; planId: string; busy: boolean }
  /// `bypass` is present exactly when the run was a BYPASS-lane plan's (no
  /// screen): its verb, and whether this run was a RETRY of a pending plan rather than a new one.
  /// `generation` is the `planGeneration` the run captured when it began.
  | { type: "plan_applied"; outcome: PlanApplyOutcome; bypass?: { verb: string; retried: boolean }; generation: number }
  /// A BARE refusal (an exception, never a
  /// `plan_applied` action at all) thrown by `plan_apply` on a BYPASS-lane Retry — an expired
  /// plan's `start_episode` refusing `expired` is the named red. `pendingBypassPlan` is set/cleared
  /// ONLY inside the `plan_applied` case (see its own doc), so a bare refusal could never reach it
  /// before this action; `error` is the thrown `SurfaceError` WHOLE
  /// (`isTerminalRefusal` needs `refused`'s own `terminal` field, not just its `kind`), and
  /// `isTerminalRefusal` alone decides — never a second, ad hoc check at the `main.ts` call site.
  | { type: "plan_apply_bare_refusal"; planId: string; error: SurfaceError }
  | { type: "plan_refusal_toast"; refusal: PlanRefusal }
  /// A step of the undo walk over a plan's APPLIED children — every member undone so
  /// far, the keys not yet spent, and the key → member labels the walk started from.
  | {
      type: "plan_undo_toast";
      steps: readonly PlanUndoStep[];
      remainingKeys: readonly string[];
      labels: Readonly<Record<string, string>>;
      /// The restoration map of the offer the walk started from.
      undoRestoration?: Readonly<Record<string, string>>;
    };

/// The ONE reducer. Every state transition in the app goes through this
/// function; `render.ts` never mutates `AppState` directly.
export function reduce(state: AppState, action: Action): AppState {
  switch (action.type) {
    case "status_loaded":
      return {
        ...state,
        status: action.status,
        severed: state.severed, // status alone never latches BLACK — epoch/undo paths do.
      };

    // Overlapping re-reads present the generation they captured at issue
    // time; only the LIVE request's response may paint.
    case "status_read_requested":
      return { ...state, statusRequestGeneration: state.statusRequestGeneration + 1 };

    // Same shape as `status_loaded` (status alone never latches/un-latches BLACK) —
    // a distinct action name so a re-read issued off `shouldRefreshStatus` reads as its own event
    // at the dispatch site, not a second boot.
    // A stale token means a newer read superseded this response — drop it,
    // leaving the newer status painted.
    case "status_updated":
      return action.token === state.statusRequestGeneration ? { ...state, status: action.status } : state;

    case "page_loaded": {
      // A selected ref that no longer exists in the replaced page (e.g. it left the
      // window, or was archived elsewhere) must not linger in `selected` — `e` on it would be a
      // silent no-op against a ref the engine can no longer resolve. Intersect with what's here.
      const incomingRefs = new Set(action.rows.map((row) => row.message_ref));
      const selected = new Set([...state.selected].filter((ref) => incomingRefs.has(ref)));
      // Focus follows MESSAGE IDENTITY, not the numeric index. A bare
      // `clampFocus(state.focusIndex,...)` re-lands on whatever row now sits at the OLD index,
      // which is the wrong row the instant a reload inserts/removes anything above it (e.g. new
      // mail landed above the focused row while the window re-read). Resolve the ref that was
      // focused BEFORE this dispatch in the incoming rows first; only fall back to the clamped
      // numeric index when that ref is genuinely gone (archived/removed elsewhere).
      const previouslyFocusedRef = state.rows[state.focusIndex]?.message_ref;
      const resolvedIndex = previouslyFocusedRef
        ? action.rows.findIndex((row) => row.message_ref === previouslyFocusedRef)
        : -1;
      const focusIndex =
        resolvedIndex >= 0 ? resolvedIndex : clampFocus(state.focusIndex, 0, action.rows.length);
      return {
        ...state,
        rows: action.rows,
        nextCursor: action.nextCursor,
        freshness: action.freshness ?? state.freshness,
        focusIndex,
        selected,
        // This action REPLACES the window — bump the list generation so an append
        // whose `generation` was captured before this dispatch is now provably stale.
        listGeneration: state.listGeneration + 1,
      };
    }

    // Appends the next local page onto the end of what's already loaded — deduped by
    // ref (a row the current window already carries is never appended a second time) and in the
    // ORDER the new page arrived in, which keeps overall sort order since the new page's cursor is
    // strictly "older than everything currently loaded". Selection and focus are untouched: the
    // existing rows never move, so their indices (and any refs already selected among them) stay
    // exactly where they were.
    //
    // An append STAMPED with a `listGeneration` older than the current one is
    // dropped outright — a `page_loaded` replaced the window after this fetch was issued (an
    // `r`-reload racing a `j`-triggered local-page fetch), so `action.rows` is a pre-reload page
    // and `existingRefs` below would otherwise be computed against the CURRENT (post-reload) rows
    // while `action.nextCursor` is the PRE-reload cursor — landing it would both reintroduce rows
    // the reload legitimately dropped and clobber the reload's own cursor with a stale one.
    case "page_appended": {
      if (action.generation !== state.listGeneration) {
        return state;
      }
      const existingRefs = new Set(state.rows.map((row) => row.message_ref));
      const appended = action.rows.filter((row) => !existingRefs.has(row.message_ref));
      return { ...state, rows: [...state.rows, ...appended], nextCursor: action.nextCursor };
    }

    case "move_focus":
      return { ...state, focusIndex: clampFocus(state.focusIndex, action.delta, state.rows.length) };

    case "toggle_select": {
      const row = state.rows[state.focusIndex];
      if (!row) {
        return state;
      }
      return { ...state, selected: toggleSelect(state.selected, row.message_ref) };
    }

    case "reading_pane_requested":
      return bodyRequestFor(state, action.messageRef).state;

    case "reading_pane_response":
      return acceptBody(state, action.token, action.messageRef, action.body);

    case "reading_pane_failed":
      return rejectBody(state, action.token, action.messageRef, action.reason);

    case "verb_toast":
      return { ...state, toast: toastForVerb(action.verbLabel, action.undoKey, action.projection, action.restoration ?? null) };

    case "batch_toast": {
      const outcome = deriveBatchOutcome(action.refs, action.results);
      const severed = state.severed || (outcome.failed?.reason ? isSeveredReason(outcome.failed.reason) : false);
      // A batch that changed NOTHING (zero successes — first message refused) must not
      // destroy the previous toast's live undo offer. A batch WITH successes replaces the offer
      // deliberately (its own keys are the new outstanding set).
      const batchToast =
        outcome.succeeded.length === 0
          ? carryUnconsumedUndoKeys(toastForBatch(action.verbLabel, outcome), state.toast)
          : toastForBatch(action.verbLabel, outcome);
      return { ...state, toast: batchToast, severed };
    }

    // `remainingKeys` is the batch walk's unconsumed suffix (absent ⇒ nothing is
    // owed, the single-verb path). The toast therefore always offers exactly the keys still
    // outstanding, instead of dropping the whole remainder on the first success.
    case "undo_toast":
      return {
        ...state,
        toast: toastForUndo(action.presentation, action.projection, action.remainingKeys, action.restoration ?? null, action.undoRestoration),
        severed: state.severed || isSeveredSignal(action.presentation),
      };

    // A typed refusal arriving while an applied-verb (or undo-batch) toast still
    // holds UNCONSUMED undo keys used to REPLACE that toast wholesale — the keys became
    // irretrievable the instant the refusal rendered, even though the action they'd undo is still
    // live. Merge shape (not a queue — the simpler reducer-only fix): a refusal toast PRESERVES
    // the previous toast's unconsumed `undoKeys`, carried onto the refusal toast itself and
    // rendered through the toast's ordinary "Undo" affordance, with a line naming that the keys
    // are still there. A toast with no keys (already consumed via undo, or dismissed — see
    // `toast_dismissed`, which clears `state.toast` to `null`) has nothing to preserve, so an
    // ordinary refusal toast (no `— undo still available` suffix) is unchanged from before.
    case "refusal_toast":
      return {
        ...state,
        toast: carryUnconsumedUndoKeys(toastForRefusal(action.error), state.toast),
        severed: state.severed || isSeveredSignal(action.error),
      };

    // A fenced write-verb never issued an IPC call, so there is no `SurfaceError` and
    // no `severed` question to ask here — just the fence's own toast.
    case "fence_toast":
      return { ...state, toast: fenceToast(action.reason) };

    // Lands EITHER refresh door's `RefreshOutcome` — the freshness half
    // exactly as `freshness_updated` used to, PLUS `has_more`, which nothing before this fold ever
    // stored. A refusal (e.g. `too_soon`) rides through `refusal_toast` instead and never touches
    // `hasMore` — see that action's own doc.
    case "refresh_completed":
      return {
        ...state,
        freshness: action.freshness,
        hasMore: action.hasMore,
        // A PACING refusal toast (busy / too_soon / provider_backoff) describes a
        // refresh that is no longer in flight the moment one completes — leaving it up reads as
        // a stuck operation. Clear it, but never destroy a carried undo offer.
        toast: clearSupersededPacingToast(state.toast),
      };

    // Not a refusal (no IPC call, no `SurfaceError`) — same non-severed shape as
    // `fence_toast`.
    //
    // …but the SAME keyed-toast hazard as `refusal_toast`. A clipboard failure is
    // unrelated to the verb that just ran, and replacing its toast wholesale made that verb's undo
    // key irretrievable. One merge helper, both sites.
    case "copy_failed_toast":
      return { ...state, toast: carryUnconsumedUndoKeys(copyFailedToast(), state.toast) };

    case "toast_dismissed":
      return { ...state, toast: null };

    // The review holds the payload object the engine answered — the screen renders it and
    // the approve control echoes it back, so nothing here copies or reshapes it.
    // THE BYPASS LANE: a plan frozen `bypassed` opens no screen; its non-blocking
    // toast (what runs, and the frozen notice) is shown instead, before the apply (`main.ts`).
    //
    // A FRESH mint (no `generation`) bumps `planGeneration` and always
    // replaces; a run's REOPEN (`generation` present) is dropped when a fresh mint has happened
    // since that run began — a late reopen of A never replaces a newer review B.
    case "plan_minted": {
      if (action.generation !== undefined && action.generation !== state.planGeneration) {
        return state;
      }
      const planGeneration = action.generation === undefined ? state.planGeneration + 1 : state.planGeneration;
      if (!opensReviewScreen(action.review)) {
        return { ...state, planGeneration, planReview: null, toast: carryUnconsumedUndoKeys(toastForPlanBypass(action.review), state.toast) };
      }
      return { ...state, planGeneration, planReview: { review: action.review, busy: false } };
    }

    case "plan_review_closed":
      return { ...state, planReview: null };

    // The flag lands only on the review it names.
    case "plan_busy":
      return state.planReview?.review.plan_id === action.planId
        ? { ...state, planReview: { ...state.planReview, busy: action.busy } }
        : state;

    // The same rule holds for both plan toasts: a keyed toast is an outstanding undo offer, so
    // a plan toast landing on it carries its unconsumed keys.
    // A plan toast that carries its OWN undo keys (applied children) is the new outstanding offer
    // and replaces the previous one — the batch rule; one without keys keeps the previous offer.
    case "plan_applied": {
      const toast = toastForPlanApply(action.outcome);
      // WIDENED:
      // a bypass-lane plan has no
      // screen, so a run that left it INCOMPLETE keeps a retry handle — the plan id and a Retry
      // that runs `plan_apply` on the same plan. That handle is `pendingBypassPlan` ALONE now,
      // never a field on the toast (`render.ts` reads it off STATE — `state.pendingBypassPlan` —
      // on every paint, whatever toast happens to be showing; a `plan_refusal_toast` from a
      // FAILED Retry attempt replaces the toast wholesale, same as any other refusal, and no
      // longer drops the control with it). It is remembered as pending, so
      // `#` / `!` on the same selection re-applies it rather than minting a second plan over the
      // same members. A run that ends the plan (completed, invalidated, terminal) clears it — the
      // ONE place this state changes.
      let pendingBypassPlan = state.pendingBypassPlan;
      if (action.bypass !== undefined) {
        const id = action.outcome.plan_id;
        const lines: string[] = [];
        if (action.bypass.retried) {
          lines.push(`re-applied the incomplete plan ${id} — no new plan was minted`);
        }
        // Incomplete ALONE is not enough — a
        // TERMINAL `stopped` (`unsupported_capability`, `plan_child_refused`,
        // `refused{terminal:true}`, …) on an otherwise-incomplete run would install a Retry that
        // can only meet the identical wall again (a gap left
        // standing). The screen lane's reopen (`reopensReviewAfterRun`, used ONLY at the
        // `main.ts` call site above the bypass/screen split) deliberately keeps following
        // completion alone — a re-read of the review screen is harmless there — so this extra
        // check lives HERE, in the bypass-only handle, never in `reopensReviewAfterRun` itself.
        const retryable =
          action.outcome.stopped === null || !isTerminalRefusal(action.outcome.stopped);
        if (reopensReviewAfterRun(action.outcome) && retryable) {
          lines.push(`plan ${id} is incomplete — Retry re-applies this same plan; no new plan is minted`);
          pendingBypassPlan = { planId: id, verb: action.bypass.verb, members: action.outcome.members.map(([member]) => member) };
        } else if (pendingBypassPlan?.planId === id) {
          pendingBypassPlan = null;
        }
        toast.detail = [...lines, ...(toast.detail ?? [])];
      }
      // ONLY the review clear is gated — the toast and the
      // `pendingBypassPlan` halves above stay ungated (the bypass lane runs with no review open).
      // The run's own review is cleared only while no fresh mint has happened since the run
      // began AND the review showing is this run's plan; a late outcome never closes a newer one.
      const ownsTheReview =
        action.generation === state.planGeneration && state.planReview?.review.plan_id === action.outcome.plan_id;
      return {
        ...state,
        planReview: ownsTheReview ? null : state.planReview,
        pendingBypassPlan,
        toast: toast.undoKeys.length > 0 ? toast : carryUnconsumedUndoKeys(toast, state.toast),
      };
    }

    case "plan_undo_toast":
      return {
        ...state,
        toast: toastForPlanUndo(action.steps, action.remainingKeys, action.labels, action.undoRestoration),
        severed: state.severed || action.steps.some((s) => isSeveredSignal(s.presentation)),
      };

    // The bare-refusal catch path's own clear —
    // ONLY when this is still the SAME pending plan (a newer mint since could have replaced it)
    // AND the refusal is TERMINAL (`isTerminalRefusal`, the one predicate); a transient one keeps
    // the handle exactly as the `plan_applied` case already does for an in-band stop.
    case "plan_apply_bare_refusal":
      return state.pendingBypassPlan?.planId === action.planId && isTerminalRefusal(action.error)
        ? { ...state, pendingBypassPlan: null }
        : state;

    case "plan_refusal_toast":
      return { ...state, toast: carryUnconsumedUndoKeys(toastForPlanRefusal(action.refusal), state.toast) };

    default:
      return state;
  }
}

/// A batch failure's `reason` string is engine prose, not a typed `SurfaceError`; it still needs
/// the same EXACT-match discipline as `isSeveredSignal` (never substring), so it is compared
/// against the same named constant.
function isSeveredReason(reason: string): boolean {
  return reason === SEVERED_REFUSED_REASON;
}

// ===============================================================================================
// A tiny store — subscribe/dispatch/getState, nothing more
// ===============================================================================================

export type Listener = (state: AppState) => void;

export class Store {
  private state: AppState;
  private listeners: Set<Listener> = new Set();

  constructor(initial: AppState = initialState()) {
    this.state = initial;
  }

  getState(): AppState {
    return this.state;
  }

  dispatch(action: Action): void {
    this.state = reduce(this.state, action);
    for (const listener of this.listeners) {
      listener(this.state);
    }
  }

  subscribe(listener: Listener): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }
}
