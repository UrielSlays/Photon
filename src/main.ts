// The triage UI entry point. Wires `ipc.ts` (typed commands) to `state.ts` (the one
// reducer) to `render.ts` (the only DOM-writing module). This file itself never touches the DOM
// directly beyond handing elements to `render.ts` and never assigns `.textContent`/creates
// elements — see `src/__tests__/sinkfence.test.ts`.

import {
  archive,
  inboxPage,
  markSpam,
  messageBody,
  planApply,
  planApprove,
  planMint,
  planReview,
  refreshInbox,
  refreshMoreInbox,
  sessionStatus,
  setSeen,
  setStar,
  trash,
  undo as undoIpc,
} from "./ipc";
import type { FreshnessView, InboxRow, PageCursor, PlanReviewView, RenderedViewWire, SurfaceError, VerbOutcome } from "./ipc";
import {
  CREDENTIAL_REJECTED_MESSAGE,
  initialState,
  isPlanRefusal,
  loadMoreAction,
  pendingBypassPlanFor,
  selectionTargets,
  opensReviewScreen,
  reopensReviewAfterRun,
  shouldLoadMoreOnMoveDown,
  shouldRefreshStatus,
  starVerbLabel,
  Store,
  toastForRefusal,
  unconsumedUndoKeys,
  UNSUPPORTED_CAPABILITY_MESSAGE,
  verbsAllowed,
  windowReloadDepth,
} from "./state";
import type { PerMessageAttempt, PlanUndoStep } from "./state";
import { createVirtualizer, queryRoots, renderAll } from "./render";
import { assertNever, isInteractiveTarget, verbForKey } from "./keys";

const PAGE_SIZE = 50;

function isSurfaceError(e: unknown): e is SurfaceError {
  return typeof e === "object" && e !== null && "kind" in e;
}

async function main(): Promise<void> {
  const roots = queryRoots(document);
  const store = new Store(initialState());

  const virtualizer = createVirtualizer(0, roots.listScroll, paint);

  function paint(): void {
    renderAll(roots, virtualizer, store.getState(), handleUndoBatch, handleCopyFailed, handlePlanApprove, handlePlanCancel, handlePlanApply, handlePlanRetry);
  }

  store.subscribe(() => paint());
  paint();

  function currentAccount(): string | null {
    return store.getState().status?.account ?? null;
  }

  /// The status re-read, fired from BOTH halves: after an
  /// expiry-class refusal (`shouldRefreshStatus`, via `reportRefusal`), AND after every
  /// successful provider-READ command — `admit_provider` renews transparently, so the success
  /// path is exactly where `credential_expired`/`credential_cure`/`credential_expires_at` go
  /// stale (a session that boots expired would otherwise wear the dead-credential banner
  /// forever while every command succeeds). Failure is silent, same as boot's own read
  /// (`session_status` is designed to never itself refuse — there is nothing to branch on).
  async function refreshStatus(): Promise<void> {
    // Overlapping commands' independent re-reads can complete out of
    // order — capture the request generation at issue time; the reducer drops this response if a
    // newer read supersedes it before it lands.
    store.dispatch({ type: "status_read_requested" });
    const token = store.getState().statusRequestGeneration;
    try {
      const status = await sessionStatus();
      store.dispatch({ type: "status_updated", token, status });
    } catch {
      // Nothing to branch on — see doc above.
    }
  }

  /// Every catch site that renders a typed refusal toast routes through here so the
  /// status re-read (`shouldRefreshStatus`) is never a call site somebody forgot to add.
  async function reportRefusal(e: SurfaceError): Promise<void> {
    // The three plan refusals take their own toast (the engine's token through
    // PLAN_REFUSAL_COPY, the refused member and diff atoms on their own lines).
    if (isPlanRefusal(e)) {
      store.dispatch({ type: "plan_refusal_toast", refusal: e });
      return;
    }
    store.dispatch({ type: "refusal_toast", error: e });
    if (shouldRefreshStatus(e.kind)) {
      await refreshStatus();
    }
  }

  /// RE-READ the whole loaded window from SQLite, top down, and replace
  /// it in one dispatch.
  ///
  /// A provider continuation is purely additive in the store (it removes nothing), but ingest
  /// UPSERTS: a message the continuation returned that is already on screen comes back carrying the
  /// provider's CURRENT headers — read/unread, starred, a corrected subject. Appending the tail
  /// cannot land those, because `page_appended` dedupes by ref and keeps the copy already
  /// displayed, so the window silently rots the longer the walk runs. Re-reading is the simplest
  /// correct shape available: `page_loaded` already REPLACES the rows while preserving the focus
  /// index and intersecting the selection with what still exists, so no new reducer arm is needed.
  ///
  /// The walk is bounded by `windowReloadDepth` (everything already loaded, plus the page the
  /// continuation just made reachable) and by the store running out of rows — a page that reports
  /// no `next_cursor` ends it. One dispatch at the end, so the list paints once.
  async function reloadLoadedWindow(account: string, depth: number): Promise<void> {
    const rows: InboxRow[] = [];
    let cursor: PageCursor | null = null;
    let nextCursor: PageCursor | null = null;
    let freshness: FreshnessView | null = null;
    do {
      const page = await inboxPage(account, PAGE_SIZE, cursor);
      rows.push(...page.rows);
      nextCursor = page.next_cursor;
      freshness = page.freshness;
      // A page that carried nothing ENDS the walk regardless of what cursor it reported: the loop's
      // only other exit is `rows.length` growing, so an empty page with a cursor would spin here.
      cursor = page.rows.length > 0 ? page.next_cursor : null;
    } while (cursor !== null && rows.length < depth);

    // Same synchronous-paint constraint as `loadFirstPage`: the virtualizer's count
    // must be current BEFORE `dispatch` runs the subscribed `paint()`.
    virtualizer.setOptions({ ...virtualizer.options, count: rows.length });
    store.dispatch({ type: "page_loaded", rows, nextCursor, freshness });
  }

  async function loadFirstPage(): Promise<void> {
    const account = currentAccount();
    if (!account) {
      return;
    }
    try {
      const page = await inboxPage(account, PAGE_SIZE, null);
      // The virtualizer's `count` must be current BEFORE the reducer's `dispatch` triggers
      // `paint()` — `dispatch` runs the subscribed `paint()` synchronously, so a
      // `setOptions` call issued after it is one paint too late: the row count `renderList` reads
      // off `virtualizer.getVirtualItems()` would still reflect the PRIOR page.
      virtualizer.setOptions({ ...virtualizer.options, count: page.rows.length });
      store.dispatch({
        type: "page_loaded",
        rows: page.rows,
        nextCursor: page.next_cursor,
        freshness: page.freshness,
      });
    } catch (e) {
      if (isSurfaceError(e)) {
        await reportRefusal(e);
      }
    }
  }

  /// `next_cursor` used to just sit in state, unconsumed: rows beyond page 1 were
  /// unreachable. Fetches the next LOCAL page off the stored cursor and appends it (`page_appended`
  /// dedupes by ref and preserves sort order/selection/focus). Same synchronous-paint constraint as
  /// `loadFirstPage`: the virtualizer's `count` must be current BEFORE `dispatch`
  /// triggers `paint()`, so the post-append total is computed here (mirroring the reducer's own
  /// dedupe) rather than read back off state after the fact.
  ///
  /// The LOCAL cursor is not the only source of "more": once it is exhausted
  /// (`nextCursor: null`), `loadMoreAction` may still say `"provider-fetch"` (the last refresh
  /// reported `has_more`). That branch spends `refresh_more_inbox` first — which shares the same
  /// 15s pacing floor as `refresh_inbox`, so a `TooSoon` refusal here is rendered by the SAME
  /// toast arm every other pacing refusal already uses, nothing new.
  ///
  /// And then it RE-READS the whole loaded window rather than appending a tail
  /// page (`reloadLoadedWindow`). The continuation removes nothing, but its ingest upserts headers
  /// for rows already on screen, and an append drops those updates on the floor (`page_appended`
  /// dedupes by ref). The two branches are now disjoint: the provider branch re-reads and returns,
  /// the local branch appends off a cursor that is non-null by construction.
  async function loadNextPage(): Promise<void> {
    const account = currentAccount();
    const decision = loadMoreAction(store.getState());
    if (!account || decision === "none") {
      return;
    }
    if (decision === "provider-fetch") {
      const depth = windowReloadDepth(store.getState().rows.length, PAGE_SIZE);
      try {
        const outcome = await refreshMoreInbox(account);
        store.dispatch({
          type: "refresh_completed",
          freshness: { checked_through: outcome.checked_through, stale_below: outcome.stale_below },
          hasMore: outcome.has_more,
        });
        // RE-READ the window rather than appending its tail — the continuation's
        // ingest upserted headers for rows already on screen, and an append would keep the stale
        // copies. This is also why the provider branch does not fall through to the local-page
        // append below: the re-read already covers the rows that append would have added.
        await reloadLoadedWindow(account, depth);
      } catch (e) {
        if (isSurfaceError(e)) {
          await reportRefusal(e);
        }
      } finally {
        // The read may have renewed the credential transparently even
        // when the command then failed downstream — the re-read covers both arms.
        await refreshStatus();
      }
      return;
    }
    const current = store.getState();
    const cursor = current.nextCursor;
    if (!cursor) {
      return;
    }
    // Captured BEFORE the await, same shape as `bodyRequestFor`'s token — this local
    // fetch can still be in flight when an `r`-triggered reload (`page_loaded`) replaces the whole
    // window. Stamped onto the dispatch below so the reducer can tell a stale append from a current
    // one; also gates the `virtualizer.setOptions` call, which is computed off `current.rows` and
    // would otherwise clobber the reload's already-current count with pre-reload arithmetic.
    const generation = current.listGeneration;
    try {
      const page = await inboxPage(account, PAGE_SIZE, cursor);
      if (store.getState().listGeneration !== generation) {
        // A reload landed while this fetch was in flight — the reducer would drop this append
        // anyway (stale generation), so skip the virtualizer update too rather than set a count
        // computed off rows the reload already replaced.
        return;
      }
      const existingRefs = new Set(current.rows.map((row) => row.message_ref));
      const appendedCount = page.rows.filter((row) => !existingRefs.has(row.message_ref)).length;
      virtualizer.setOptions({ ...virtualizer.options, count: current.rows.length + appendedCount });
      store.dispatch({ type: "page_appended", rows: page.rows, nextCursor: page.next_cursor, generation });
    } catch (e) {
      if (isSurfaceError(e)) {
        await reportRefusal(e);
      }
    }
  }

  async function boot(): Promise<void> {
    try {
      const status = await sessionStatus();
      store.dispatch({ type: "status_loaded", status });
    } catch {
      // session_status is designed to never itself refuse — nothing to branch on.
    }
    await loadFirstPage();
  }

  async function doRefresh(): Promise<void> {
    const account = currentAccount();
    if (!account) {
      return;
    }
    try {
      const outcome = await refreshInbox(account, PAGE_SIZE);
      store.dispatch({
        type: "refresh_completed",
        freshness: { checked_through: outcome.checked_through, stale_below: outcome.stale_below },
        hasMore: outcome.has_more,
      });
      await loadFirstPage();
    } catch (e) {
      if (isSurfaceError(e)) {
        await reportRefusal(e);
      }
    } finally {
      // The read may have renewed the credential transparently EVEN
      // WHEN the command then failed downstream — the re-read covers both arms.
      await refreshStatus();
    }
  }

  /// Message A's slow fetch can still be in flight when B is opened. `dispatch` is
  /// synchronous, so the generation token minted by `reading_pane_requested` is readable off
  /// `store.getState()` immediately after — that token rides across the `await` and back with the
  /// response, so a stale (superseded) response is dropped by the reducer instead of overwriting
  /// whatever the user is now looking at.
  async function openReadingPane(row: InboxRow): Promise<void> {
    const account = currentAccount();
    if (!account) {
      return;
    }
    // Reopening the SAME ref while its fetch is already in flight used to bump the
    // generation a second time — the backend refused the duplicate as Busy, and the successful
    // FIRST response then got discarded as stale by the generation guard, leaving the pane empty.
    // A reopen of the same ref while it is already loading is a no-op: no new dispatch, no refetch.
    const current = store.getState();
    if (current.readingPane.status === "loading" && current.readingPane.ref === row.message_ref) {
      return;
    }
    store.dispatch({ type: "reading_pane_requested", messageRef: row.message_ref });
    const token = store.getState().bodyRequestGeneration;
    try {
      const body = await messageBody(account, row.message_ref);
      store.dispatch({ type: "reading_pane_response", token, messageRef: row.message_ref, body });
    } catch (e) {
      if (isSurfaceError(e)) {
        await reportRefusal(e);
        // A failed body fetch must not leave the pane silently showing whatever was
        // on screen before (the prior message's text) — it moves to an explicit, ref-keyed error
        // state naming the typed refusal, same reason prose as the toast.
        store.dispatch({
          type: "reading_pane_failed",
          token,
          messageRef: row.message_ref,
          reason: toastForRefusal(e).message,
        });
      }
    } finally {
      // The read may have renewed the credential transparently even
      // when the fetch then failed — the re-read covers both arms.
      await refreshStatus();
    }
  }

  /// `s` never reaches the provider at all when the LAST-known status says
  /// `mutations_live: false` (the fence-gated production Gmail arm always refuses this write): the
  /// guard fires BEFORE `setStar` is called, not after, so no round trip is spent on work that is
  /// guaranteed to fail engine-side.
  async function toggleStar(row: InboxRow): Promise<void> {
    const account = currentAccount();
    if (!account) {
      return;
    }
    const status = store.getState().status;
    if (!verbsAllowed(status)) {
      store.dispatch({ type: "fence_toast", reason: status?.mutations_reason ?? null });
      return;
    }
    try {
      // `target` is the value about to be sent; the toast's verb label is
      // derived FROM it (`starVerbLabel`), never hardcoded, so an unstar (`target === false`)
      // never renders as "star applied".
      const target = !row.flagged;
      const outcome: VerbOutcome = await setStar(account, row.message_ref, target);
      store.dispatch({
        type: "verb_toast",
        verbLabel: starVerbLabel(target),
        undoKey: outcome.undo_key,
        projection: outcome.projection,
        restoration: outcome.restoration,
      });
      await loadFirstPage();
    } catch (e) {
      if (isSurfaceError(e)) {
        await reportRefusal(e);
      }
    }
  }

  /// `e` — archive the selection, or the focused row if nothing is selected. Sequential,
  /// fail-stop: sequential singles engine-side, with a per-message
  /// succeeded/failed/not-attempted report.
  ///
  /// Same fence guard as `toggleStar`, before any target is even computed: a fenced
  /// build refuses every `archive` call identically, so there is nothing a per-message loop could
  /// learn by spending the round trips anyway.
  async function archiveSelection(): Promise<void> {
    const account = currentAccount();
    if (!account) {
      return;
    }
    const state = store.getState();
    if (!verbsAllowed(state.status)) {
      store.dispatch({ type: "fence_toast", reason: state.status?.mutations_reason ?? null });
      return;
    }
    const targets = selectionTargets(state);
    if (targets.length === 0) {
      return;
    }

    const results: PerMessageAttempt[] = [];
    for (const messageRef of targets) {
      try {
        const outcome = await archive(account, messageRef);
        results.push({
          message_ref: messageRef,
          ok: true,
          undo_key: outcome.undo_key,
          projection: outcome.projection,
          restoration: outcome.restoration,
        });
      } catch (e) {
        const reason = isSurfaceError(e) ? refusalReason(e) : "unknown failure";
        results.push({ message_ref: messageRef, ok: false, reason });
        if (isSurfaceError(e) && shouldRefreshStatus(e.kind)) {
          await refreshStatus();
        }
        break; // FAIL-STOP: stop issuing calls at the first failure.
      }
    }

    store.dispatch({ type: "batch_toast", verbLabel: "archive", refs: targets, results });
    await loadFirstPage();
  }

  function refusalReason(e: SurfaceError): string {
    switch (e.kind) {
      case "busy":
        return `busy: ${e.operation}`;
      // The pacing refusals carry `operation`/`retry_after_ms`, not
      // `reason` — a batch failure report names the operation and the wait, same as `busy` does.
      case "too_soon":
      case "provider_backoff":
        return `${e.kind}: ${e.operation} — retry in ${Math.ceil(e.retry_after_ms / 1000)}s`;
      // The one refusal kind with no `reason` — its kind is its token.
      case "plan_required":
        return e.kind;
      // No `reason` either — its sentence is the toast's own copy.
      case "unsupported_capability":
        return UNSUPPORTED_CAPABILITY_MESSAGE;
      // Same class as `unsupported_capability` just above: no
      // `reason` either — its sentence is the toast's own fixed copy, never a connector message.
      case "credential_rejected":
        return CREDENTIAL_REJECTED_MESSAGE;
      default:
        return e.reason;
    }
  }

  /// `u`/`z` — walk the last toast's succeeded undo keys (already reverse order per
  /// `undoKeysForBatch`), sequential, fail-stop.
  ///
  /// THE TOAST KEEPS WHAT THE WALK HAS NOT SPENT. Each success dispatched an
  /// `undo_toast` carrying no keys at all, so the batch toast — the only holder of the remaining
  /// keys — was replaced on the FIRST success and keys 2..N became irretrievable: a throw partway
  /// through then left the untouched remainder with no affordance, even though nothing had undone
  /// it. Every intermediate toast now carries the UNCONSUMED SUFFIX (`unconsumedUndoKeys`), so the
  /// "Undo" affordance always offers exactly what is still owed, and the refusal that stops the
  /// walk preserves that suffix through `refusal_toast`'s own merge.
  ///
  /// THE UNDO ROUTE FOR PLAN MEMBERS: a plan's APPLIED children arrive as keys the
  /// engine ordered last first, labelled with their members (`undoLabels`). The walk is the same —
  /// one existing `undo` door call per child, fail-stop — and each step's toast lists every member
  /// undone so far with its verdict.
  ///
  /// The offer's restoration lines (`undoRestoration`) are read
  /// with its labels, so each intermediate toast — and the refusal that stops the walk — keeps the
  /// line of every key still on offer.
  async function handleUndoBatch(keys: string[]): Promise<void> {
    const labels = store.getState().toast?.undoLabels ?? null;
    const undoRestoration = store.getState().toast?.undoRestoration;
    const steps: PlanUndoStep[] = [];
    for (let i = 0; i < keys.length; i += 1) {
      try {
        const outcome = await undoIpc(keys[i]);
        if (labels !== null) {
          steps.push({ member: labels[keys[i]] ?? keys[i], presentation: outcome.presentation, projection: outcome.projection, restoration: outcome.restoration });
          store.dispatch({ type: "plan_undo_toast", steps: [...steps], remainingKeys: unconsumedUndoKeys(keys, i + 1), labels, undoRestoration });
          continue;
        }
        store.dispatch({
          type: "undo_toast",
          presentation: outcome.presentation,
          projection: outcome.projection,
          restoration: outcome.restoration,
          // `i + 1` keys are spent; the failed/unattempted tail is what stays on offer. The key
          // that THREW is not consumed either — it is still in the suffix the catch below leaves
          // standing.
          remainingKeys: unconsumedUndoKeys(keys, i + 1),
          undoRestoration,
        });
      } catch (e) {
        if (isSurfaceError(e)) {
          await reportRefusal(e);
        }
        break; // FAIL-STOP.
      }
    }
    await loadFirstPage();
  }

  /// `render.ts`'s copy-body button routes a feature-detect/catch failure here
  /// rather than swallowing it — the one dispatch site this action has.
  function handleCopyFailed(): void {
    store.dispatch({ type: "copy_failed_toast" });
  }

  /// A SINGLE message goes through its own RED door,
  /// `trash` / `mark_spam` (each mints a one-member plan through the mint door and answers its
  /// Never a dispatch); a multi-message selection goes through `plan_mint`.
  function mintRedPlan(account: string, verb: "trash" | "mark_spam", targets: string[]): Promise<PlanReviewView> {
    if (targets.length === 1) {
      return verb === "trash" ? trash(account, targets[0]) : markSpam(account, targets[0]);
    }
    return planMint(account, verb, targets, null);
  }

  /// `#` / `!`: MINT a plan over the selection (the `archiveSelection` target rule —
  /// `selectionTargets`) and open its review. Minting reads and writes the local store only; no
  /// provider effect happens until the review is approved and applied.
  async function mintPlanForSelection(verb: "trash" | "mark_spam"): Promise<void> {
    const account = currentAccount();
    if (!account) {
      return;
    }
    const targets = selectionTargets(store.getState());
    if (targets.length === 0) {
      return;
    }
    // An INCOMPLETE bypass-lane plan over this SAME selection (same verb, same
    // members) is re-applied — never a second plan minted over members the first still holds — and
    // the outcome toast says so.
    const pending = pendingBypassPlanFor(store.getState().pendingBypassPlan, verb, targets);
    if (pending !== null) {
      await applyBypassedPlan(pending.planId, verb, true);
      return;
    }
    try {
      const review = await mintRedPlan(account, verb, targets);
      store.dispatch({ type: "plan_minted", review });
      // THE BYPASS LANE: a plan frozen `bypassed` opened no screen
      // (the reducer showed its non-blocking notice instead) and goes straight to the apply door,
      // which records the mechanical approval itself.
      if (!opensReviewScreen(review)) { await applyBypassedPlan(review.plan_id, verb, false); }
    } catch (e) {
      if (isSurfaceError(e)) {
        await reportRefusal(e);
      }
    }
  }

  /// ONE run of a plan: `plan_apply`, then its outcome toast. A run that
  /// STOPPED before every member was attempted answers its outcome too (what applied, their undo
  /// offers, why it stopped), and — when the plan has a screen (`reopen`) — the review is re-read,
  /// so an approved, non-terminal plan offers Apply. A bare refusal re-reads it the same way: an
  /// approval, once recorded, stands. A run that did not stop but left the plan
  /// INCOMPLETE (a member still in flight) re-reads it too — `reopensReviewAfterRun` decides on the
  /// completion, not only on the stop. A BYPASS-lane run (`bypass`, no screen to
  /// re-read) hands the reducer its verb, so an incomplete one keeps its retry handle on the toast.
  ///
  /// The run captures `planGeneration` BEFORE it awaits anything and
  /// stamps it on its `plan_applied` and on its reopen — a review freshly minted while this run was
  /// in flight is never closed or replaced by this run's late result (the reading pane's
  /// `bodyRequestGeneration` pattern).
  async function runPlan(planId: string, reopen: boolean, bypass?: { verb: string; retried: boolean }): Promise<void> {
    const generation = store.getState().planGeneration;
    try {
      const outcome = await planApply(planId);
      store.dispatch({ type: "plan_applied", outcome, bypass, generation });
      if (outcome.stopped !== null && shouldRefreshStatus(outcome.stopped.kind)) {
        await refreshStatus();
      }
      if (reopen && reopensReviewAfterRun(outcome)) {
        await reopenReview(planId, generation);
      }
    } catch (e) {
      if (isSurfaceError(e)) {
        await reportRefusal(e);
        // A BARE refusal never reaches the
        // `plan_applied` reducer case — the only OTHER place `pendingBypassPlan` is cleared — so a
        // bypass-lane Retry against an expired plan (`start_episode` refusing `expired`) left the
        // handle installed forever, re-applying the same dead plan on every subsequent `#`/`!`.
        // Routed through the reducer with the refusal WHOLE
        // (`refused` needs its own `terminal` field, not just its `kind`) so `isTerminalRefusal`
        // (the one predicate) decides, never a second ad hoc check here.
        if (bypass) {
          store.dispatch({ type: "plan_apply_bare_refusal", planId, error: e });
        }
      }
      if (reopen) {
        await reopenReview(planId, generation);
      }
    }
    await loadFirstPage();
  }

  /// Re-read a plan's review so the screen says what the store holds (approved, terminal).
  /// Stamped with the run's `generation` — the reducer drops it when a
  /// fresh mint has happened since the run began — and a failed re-read un-busies ONLY this plan's
  /// review (`plan_busy` names its plan).
  async function reopenReview(planId: string, generation: number): Promise<void> {
    try {
      store.dispatch({ type: "plan_minted", review: await planReview(planId), generation });
    } catch {
      store.dispatch({ type: "plan_busy", planId, busy: false });
    }
  }

  /// A bypass-lane plan's run: the fence guard first, as every write verb's; then
  /// `plan_apply` (the shell records the lane's mechanical approval before it drives — no approval
  /// is ever sent from here); the outcome toast repeats the plan's notice. The lane has no screen,
  /// so nothing is re-opened after the run — an INCOMPLETE run keeps its retry handle on the toast
  /// instead; `retried` says this run re-applied a pending plan.
  async function applyBypassedPlan(planId: string, verb: string, retried: boolean): Promise<void> {
    const status = store.getState().status;
    if (!verbsAllowed(status)) {
      store.dispatch({ type: "fence_toast", reason: status?.mutations_reason ?? null });
      return;
    }
    await runPlan(planId, false, { verb, retried });
  }

  /// The toast's Retry on an incomplete bypass-lane plan — `plan_apply` on the
  /// SAME plan: no mint, no screen, no approval (the shell's mechanical bypass approval is recorded
  /// once, at the first run).
  function handlePlanRetry(planId: string): void {
    const pending = store.getState().pendingBypassPlan;
    void applyBypassedPlan(planId, pending !== null && pending.planId === planId ? pending.verb : "", true);
  }

  /// Shift+I: mark the selection read, as sequential fail-stop singles with the same
  /// tri-state report and the same fence guard `archiveSelection` uses.
  async function markReadSelection(): Promise<void> {
    const account = currentAccount();
    if (!account) {
      return;
    }
    const state = store.getState();
    if (!verbsAllowed(state.status)) {
      store.dispatch({ type: "fence_toast", reason: state.status?.mutations_reason ?? null });
      return;
    }
    const targets = selectionTargets(state);
    if (targets.length === 0) {
      return;
    }
    const results: PerMessageAttempt[] = [];
    for (const messageRef of targets) {
      try {
        const outcome = await setSeen(account, messageRef, true);
        results.push({ message_ref: messageRef, ok: true, undo_key: outcome.undo_key, projection: outcome.projection, restoration: outcome.restoration });
      } catch (e) {
        const reason = isSurfaceError(e) ? refusalReason(e) : "unknown failure";
        results.push({ message_ref: messageRef, ok: false, reason });
        if (isSurfaceError(e) && shouldRefreshStatus(e.kind)) {
          await refreshStatus();
        }
        break; // FAIL-STOP.
      }
    }
    store.dispatch({ type: "batch_toast", verbLabel: "mark read", refs: targets, results });
    await loadFirstPage();
  }

  /// The approve control. `rendered` is EXACTLY what `render.ts` showed (built from the
  /// same payload objects, never re-read from the DOM); the engine commits the approval against
  /// it, then the plan is applied. The fence guard runs first, as every write verb's does: on a
  /// build whose writes are fenced no approval is recorded and no round trip is spent.
  async function handlePlanApprove(rendered: RenderedViewWire): Promise<void> {
    const current = store.getState().planReview;
    if (!current || current.busy || current.review.approved) {
      return;
    }
    const status = store.getState().status;
    if (!verbsAllowed(status)) {
      store.dispatch({ type: "fence_toast", reason: status?.mutations_reason ?? null });
      return;
    }
    const planId = current.review.plan_id;
    store.dispatch({ type: "plan_busy", planId, busy: true });
    try {
      await planApprove(planId, rendered, "operator");
    } catch (e) {
      if (isSurfaceError(e)) {
        await reportRefusal(e);
      }
      store.dispatch({ type: "plan_busy", planId, busy: false });
      return;
    }
    // The approval IS recorded: whatever the run answers, the review re-read after a stop or a
    // refusal says so (the approve control gives way to Apply — the approval is write-once).
    await runPlan(planId, true);
  }

  /// The Apply control: an APPROVED, non-terminal plan runs again (a run that
  /// stopped, or an approval whose apply never happened). No approval is sent — the recorded one
  /// stands. The fence guard runs first, as every write verb's does.
  async function handlePlanApply(): Promise<void> {
    const current = store.getState().planReview;
    if (!current || current.busy || !current.review.approved || current.review.terminal) {
      return;
    }
    const status = store.getState().status;
    if (!verbsAllowed(status)) {
      store.dispatch({ type: "fence_toast", reason: status?.mutations_reason ?? null });
      return;
    }
    store.dispatch({ type: "plan_busy", planId: current.review.plan_id, busy: true });
    await runPlan(current.review.plan_id, true);
  }

  function handlePlanCancel(): void {
    store.dispatch({ type: "plan_review_closed" });
  }

  document.addEventListener("keydown", (event) => {
    // While a plan review is open it owns the keyboard — Escape closes it, and no list
    // shortcut acts behind it. This arm runs BEFORE the interactive-target
    // guard below, so Escape closes the review even while one of the review's own buttons has
    // focus; every other key is left to that control (a focused button's Enter/Space still
    // activates it natively — nothing here prevents it).
    if (store.getState().planReview !== null) {
      if (event.key === "Escape") {
        event.preventDefault();
        handlePlanCancel();
      }
      return;
    }
    // A global shortcut (e.g. Enter) firing from a FOCUSED interactive/editable
    // control (the "Copy body"/"Undo" button) must not ALSO trigger the app's own handler for that
    // key — this returns before the keymap is even consulted.
    if (isInteractiveTarget(event.target as HTMLElement | null)) {
      return;
    }
    const verb = verbForKey(event);
    if (!verb) {
      return;
    }
    // Every shortcut this handler DOES claim owns the key — never let the browser additionally
    // act on it (e.g. Enter submitting a form, space scrolling the page).
    event.preventDefault();
    const state = store.getState();
    switch (verb) {
      case "move_down": {
        store.dispatch({ type: "move_focus", delta: 1 });
        const next = store.getState();
        virtualizer.scrollToIndex(next.focusIndex);
        // Focus reached the last loaded row and there
        // is more to fetch — either the next LOCAL page, or (once that is exhausted) another
        // provider page — OR the list is empty outright, which has no "last row" to be at but
        // still needs `j` to be the signal that kicks off the fetch. `shouldLoadMoreOnMoveDown`
        // is the full decision, empty list included.
        if (shouldLoadMoreOnMoveDown(next)) {
          void loadNextPage();
        }
        break;
      }
      case "move_up":
        store.dispatch({ type: "move_focus", delta: -1 });
        virtualizer.scrollToIndex(store.getState().focusIndex);
        break;
      case "open": {
        const row = state.rows[state.focusIndex];
        if (row) {
          void openReadingPane(row);
        }
        break;
      }
      case "toggle_select":
        store.dispatch({ type: "toggle_select" });
        break;
      case "toggle_star": {
        const row = state.rows[state.focusIndex];
        if (row) {
          void toggleStar(row);
        }
        break;
      }
      case "archive":
        void archiveSelection();
        break;
      case "undo": {
        const toast = state.toast;
        if (toast && toast.undoKeys.length > 0) {
          void handleUndoBatch(toast.undoKeys);
        }
        break;
      }
      case "refresh":
        void doRefresh();
        break;
      case "trash":
        void mintPlanForSelection("trash");
        break;
      case "spam":
        void mintPlanForSelection("mark_spam");
        break;
      case "mark_read":
        void markReadSelection();
        break;
      // Exhaustive — a KeyVerb with no case above fails `tsc` here.
      default:
        assertNever(verb);
    }
  });

  await boot();
}

void main();
