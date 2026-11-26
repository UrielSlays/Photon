# ADR-P007: Snapshot-before-mutation; recovery over prevention theater

**Status:** Accepted


> **Implementation status — normative, built in part.** The `aruna` engine captures pre-state before a
> journal-required YELLOW+ mutation and undoes by RESTORING it: the undo decides from the captured
> pre-state `P` and the admission-frozen forward target `A` (a forward that changed nothing is undone by
> changing nothing), requalifies the observed state, and dispatches a native DELTA restore through
> `Connector::restore`. **No undo path dispatches `Action::inverse()`** — the descriptor inverse survives
> only as the undo child's stored action (ordering, projection, and `recover()`'s link check). An intent
> with no usable capture gets a NAMED, mechanical refusal (capture disabled / predates the substrate /
> offer expired / unexplained journal gap), never a fallback counter-action. `Undone` means, on BOTH
> paths, "restore verified applied, or no-op verified"; a deferred undo leaves the parent truthfully
> `Applied` until that verification.
>
> **Exit criterion, still governing:** this ADR's snapshot/pre-state restoration lands before any
> real-provider YELLOW+ write is un-gated and before any code or doc claims undo restores prior state.
> **Residual:** the restore path is proven against hermetic fake transports only (live-provider proofs are
> separate), and this ADR's wider snapshot scope (full RFC-822 source for anything leaving the mailbox's
> normal reach, rule/filter definitions, the retention schedule, `ActionId` indexing) is NOT built.

> **Backup knobs.** The full-RFC-822 CONTENT snapshot this Decision mandates for anything leaving the
> mailbox's normal reach (trash, spam) is governed by a configuration knob — `backups: on|off` (default ON)
> plus a retention-duration knob. With backups=ON, everything below stands as written. With backups=OFF, a
> RED (trash/spam) effect proceeds WITHOUT the content snapshot: the gone-for-good consequence is surfaced
> at the knob AND at each use (verb-specific wording), the effect's journal records that it ran uncovered,
> and the backup-coverage state is bound into the approval itself and re-verified at send (the bulk-triage
> design's approval-binding contract). The engine's metadata pre-state capture — the undo spine in the
> implementation-status block above — is UNAFFECTED by the knob: content snapshots never served undo. Knob
> changes are journaled config acts; OFF never deletes existing snapshots; automatic purge arrives only
> through a sealed retention gate. **Anomaly signals under backups=OFF:** the Decision's anomaly rule
> splits — the HOLD still fires exactly as written (holding a batch at the next phase boundary persists no
> content and is not knob-governed), while the snapshot-scope ESCALATION is knob-bounded: it never
> overrides the operator's explicit no-content-capture choice, and the journal records that an anomaly hold
> occurred with coverage OFF. The hold's mechanism is a machine-initiated pause: the episode transitions to
> `paused` with its journaled trigger reason (`operator` | `anomaly{signal}`), durable before the next
> child, and the design's pause fence at send authorization — mint/snapshot early-stops included — IS the
> hold; clearance is the operator's explicit resume. ADR-P006's PRE-COMMIT sequencing reads THROUGH the
> backup knob: with backups=ON the content snapshot occupies PRE-COMMIT as written; with OFF that phase
> carries the metadata pre-state capture and the journaled notice only. The exit criterion above is
> unchanged for the default path; this is a configured exception to it, not a weakening of the gate.

**Decision.** Before any YELLOW+ action commits, Photon captures a `Snapshot` sufficient to reconstruct the affected state: message metadata + flags + folder membership for moves/archives; full RFC-822 source for anything leaving the mailbox's normal reach (trash, and as a precondition for any future permanent-delete capability); rule/filter definitions before rule mutations. Snapshots are local, retained on a configurable schedule, restorable through a first-class **undo** verb in both UI and agent API, and indexed by `ActionId` so every audited action points at its recovery object.

On anomaly signals (unusual action volume, novel action class for a given principal, executor errors mid-batch), Photon automatically escalates snapshot scope and holds the batch at the next phase boundary pending outcome.

**Why.** Prevention on a borrowed surface is provably incomplete — off-plane access can only be detected, not stopped, and mail has that property (nothing stops a user handing raw IMAP credentials to anything). The honest posture is to make mistakes *recoverable* and *measurable* rather than pretend they're impossible. The smartest model will almost never make the catastrophic mistake; Photon exists for the day it does.

**Rejected.** Undo as a UI nicety bolted on later (it shapes the executor's data model — brutal to retrofit); cloud-stored snapshots (violates local-first posture and creates a second breach surface).
