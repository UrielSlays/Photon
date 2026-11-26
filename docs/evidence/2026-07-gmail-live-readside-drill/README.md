# Evidence — read-side live drill, attended CLOSURE run (2026-09-03)

The human-readable summary of the run. Everything here is the **sanitized,
ID-free** output of one attended run against real Gmail; the raw wire bytes never entered the
repo, by design. *(The directory name keeps the lane's 2026-07 birth date. The committed run
below is the 2026-09-03 re-discharge under the `{gmail.modify}` product credential —
it supersedes the 2026-08-05 run wholesale, which had itself superseded the
2026-07-26 run when a digest change altered every digest. Committed evidence is never rewritten in
place; it is superseded by a fresh attended run, and git holds every earlier set.)*

| | |
|---|---|
| **Mode** | `closure` |
| **Implementation commit** | `ca857c12c806eee5a9ce66c80f0b8e0649b577d7` (detached HEAD — a separate clean worktree of `main` at the credential-migration merge; the worktree itself is operator-attested, since the manifest's `invocation` names the main checkout's shared target dir — see the confinement note) |
| **Clean tree** | yes — the drill's own cwd: `git status --porcelain --untracked-files=all` empty, probe exit-verified (`clean_tree_proof_porcelain` is the empty string). This proves the SOURCE tree, never the linked binary (see "Build provenance" below) |
| **Route form** | **`users/me/…`** — the drill constructs its production reader with the `me` alias: `GmailProviderPlacement::new(&transport, GmailUserId("me"…))` inside `live_readside_drills()` for the main reader and again for the denial reader (`crates/aruna-gmail/tests/live_readside.rs` lines 6228 and 6280 AT THE RUN COMMIT `ca857c12…`; cite the symbol, the line numbers drift). The `userId=<email>` principal-pinned form the S0 build record owes (R-S0-4, #87 item 2) is **NOT exercised by this run** — a drill change (pass the attested `provider_principal` into the reader) and a fresh attended run are required before that can be claimed |
| **Design of record** | The drill's read-side proof design — ⚠ **superseded in part by the credential migration:** it was written for a READ-ONLY main credential (`{gmail.readonly}` — its safety model, preflight scope clause and scope table); the lane has since moved to exactly `{gmail.modify}` and the code enforces that (`live_readside.rs:605-623`). Its read-only-credential control claims are owed a reconciliation and must not be read as describing this run. The proofs (R1/R2/R3), the evidence contract, and the sanitizer are unchanged and are what this record binds |
| **Toolchain** | `rustc 1.96.0 (ac68faa20 2026-05-25)` |
| **Account** | one sacrificial drill mailbox (its identity is withheld from every COMMITTED byte — manifest + captures — by construction; the runbook names the account deliberately, for the operator) |
| **Credential** | main slot **`https://www.googleapis.com/auth/gmail.modify`** (exactly that set — the lane contract), denial slot `openid` + `userinfo.email` (zero Gmail scope); preflight bound the attestation bundle's `grant_generation` to the ratchet high-water (`1`) before any request |
| **Source run dir** | `run-1788413993-36108` (parked outside every repo) |
| **Digests** | SHA-384 throughout (issue #51); the capture digest covers **(status, body)** (issue #48) |
| **Producer** | the attestation's `helper_source_sha384` (`766bcd11a701d3ca10a129fa7cce5af08309a4bd593f25f70b3cc485c14a8ba783bd99fb126eae0cd5b133f0dbd06f44`) was runtime-verified against this tree's committed `scripts/gmail_drill_mint.py` (the `verify_helper_provenance` gate) |

## Verdict — the gate is CLOSED (again, under the new grant)

| ProofId | outcome | capture |
|---|---|---|
| `R1_INBOX` | **Proved** | `r1_r1_inbox_capture.json` |
| `R1_ARCHIVE` | **Proved** | `r1_r1_archive_capture.json` |
| `R1_TRASH` | **Proved** | `r1_r1_trash_capture.json` |
| `R1_SPAM` | **Proved** | `r1_r1_spam_capture.json` |
| `R1_DRAFT` | **Proved** | `r1_r1_draft_capture.json` |
| `R3_SCOPE_403` | **Proved** | `r3_denial_envelope.json` |
| `R3_ERRORINFO_CASING` | **Proved** (conditional — the wire state existed) | `r3_denial_envelope.json` |
| `A2_ENCODING_OBSERVED` | **Unavailable** — `search bound reached before exhaustion; no zero-label candidate in the first N results` (conditional; see below) |

All **six** mandatory obligations PROVED; both conditional obligations resolved honestly.
Every PROVED row links a committed capture digest, and the suite binds each **proof_matrix row
individually** to the committed bytes (`committed_evidence_binds_fixture_file_and_manifest`).

**What this run adds over 2026-08-05:** the same eight-obligation matrix, re-derived on the
real host under the product's write-capable scope (`gmail.modify`, the credential the credential migration
introduced) with the credential's grant generation bound at preflight. It does NOT add the
`userId=<email>` route form — the drill's reader still uses the `me` alias (see the Route form
row above). Five of the six
captures came back **byte-identical** to the 2026-08-05 set (archive, trash, spam, draft, and
the R3 denial envelope — same digests); only the inbox capture differs, because the discovery
step picked a different inbox candidate this time (`UNREAD` + `CATEGORY_UPDATES` + `INBOX`
instead of `IMPORTANT` + `CATEGORY_UPDATES` + `INBOX` — both derive `Placement::Inbox`).

## Files

- **`manifest.json`** — the provenance-bound manifest: per-obligation outcomes with capture
  digests, per-arm probe-vs-SUT observations with `historyId` brackets (validated
  decimal-uint64), the W3 request census (48 requests, zero violations, one host), the
  attestation bundle's non-secret claims, the sanitizer identity + source digest, the
  RED-control result, and the clean-tree proof.
- **`r1_*_capture.json`** — the five R1 read-oracle arms' ID-free minimal-message projections
  (label-set evidence only: well-known system labels verbatim, user labels counted, message id
  dropped entirely).
- **`r3_denial_envelope.json`** — the live scope-denial 403 envelope, sanitized to the
  verdict-bearing fields only, value and casing preserved byte-for-byte, **with the transport
  status embedded in the canonical bytes** (issue #48).

All of these are replayed hermetically by `crates/aruna-gmail/tests/live_readside.rs`
(`r4_live_capture_corpus_replays_with_matching_digests`,
`r4_live_minimal_captures_replay_the_read_oracle_table`,
`r4_live_error_info_channels_are_disjoint_in_vocabulary`,
`committed_evidence_binds_fixture_file_and_manifest`), so a change to any committed byte breaks
the suite.

## The `error.rs:892` answer — RE-OBSERVED a third time, under `gmail.modify`

One real Gmail scope-denial 403 again carried BOTH channels simultaneously, with the same
vocabulary as the 2026-07-26 and 2026-08-05 observations. The canonical committed envelope
reproduced **byte-identically against the 2026-08-05 capture** (same sha384 — the same wire
shape, independently re-captured; the denial credential is the zero-Gmail-scope slot, so the
main slot's scope change does not touch it). Against 2026-07-26 the comparison is wire-shape
only: that run was recorded in the earlier form (sha256, status outside the digested bytes), so
its digest is not comparable at the byte.

| channel | field | observed value | shape |
|---|---|---|---|
| legacy | `error.errors[].reason` | `insufficientPermissions` | lowerCamel |
| legacy | `error.errors[].domain` | `global` | |
| current | `error.details[].ErrorInfo.reason` | `ACCESS_TOKEN_SCOPE_INSUFFICIENT` | UPPER_SNAKE |
| current | `error.details[].ErrorInfo.domain` | `googleapis.com` | |
| current | `error.status` | `PERMISSION_DENIED` | |

> ⚠ **This is an OBSERVATION, not a licence to map it.** The design's standing non-goal — *"NO
> ErrorInfo-vocabulary enumeration"* — HOLDS. `ACCESS_TOKEN_SCOPE_INSUFFICIENT` is **not**
> added to the classifier. Today it grades Unrecognized and therefore dominates, so the whole
> envelope fails closed to `GmailError::Unknown` / `Deterministic` — visible, safe, and
> exactly what the drill design requires. Any future mapping is a separately reviewed decision;
> `r4_live_error_info_channels_are_disjoint_in_vocabulary` asserts the current fail-closed
> behavior, so adding the reason without that review breaks a test.

## A2 — why it is `UNAVAILABLE`, and why the reason is the WEAK one

`A2_ENCODING_OBSERVED` is a **conditional** obligation (per the drill design).
This run's bounded search ended **`BoundReached`** — the mailbox is past the scan's
25-candidate cap, so the drill reports *"search bound reached before exhaustion"* and
deliberately does **NOT** emit the strong "no zero-label message reachable" claim (that
claim requires the provider to end the listing with every shown id kept — the claim-strength
honesty hardened in review). The 2026-07-26 independent
scan (174 messages, 6 pages, zero empty-label; the `CATEGORY_PERSONAL` floor construction)
remains the historical context for unreachability, at exactly its original strength and
date. Either way, **#36's A2 flip stays unlicensed** — the same practical outcome as the
design's accepted `InconclusiveNoFlipLicensed` inference.

## Fence evidence (W3)

48 requests, **zero violations**: every one a `GET` to the compiled host
`gmail.googleapis.com` on exactly three allowlisted route shapes — `users/me/profile`,
`users/me/messages`, `users/me/messages/{id}`. No mutating verb, no other host. The census
carries method + host + path shape + query KEYS only; no query values, no ids. The census
records the `users/me/…` path shape because the drill's reader is built with the `me` alias —
the product app's `userId=<email>` principal pinning is NOT on this run's wire (Route
form row above; this stays open).

## Confinement note

The manifest contains no message ids, thread ids, email addresses, or tokens; both token
digests are `null` because both credentials were still live at recording time (a token digest
is recorded only once that token has expired). The one piece of provider-derived state present is
the account's `historyId` in the per-arm brackets (validated as a decimal uint64 before
acceptance), recorded deliberately as the race-detector evidence.

**Known gap, stated (identifier minimization):** the manifest's `invocation` member records
the path of the test binary under the shared target directory (`<repo>\target\…`). This is the drill's pre-existing
manifest shape. For publication, the manifest's local invocation path was redacted to `<repo>`; that is the one edit made to the committed evidence. Minimizing that member at the source is a drill change
tracked alongside the `grant_generation` gap below.

**Known gap, stated:** the manifest's `attestation` block does not carry the bundle's
`grant_generation` — preflight binds it to the ratchet (a mismatch refuses the run before any
request), but the manifest emitter predates the field and does not re-emit it. The generation
this run bound to (`1`) is recorded here; adding the member to the manifest
is a drill change, not a re-record.

## Verifying these bytes yourself

```bash
cd docs/evidence/2026-07-gmail-live-readside-drill
sha384sum *.json          # (macOS: shasum -a 384 *.json · Windows: certutil -hashfile <f> SHA384)
```

Each capture's digest must equal the one recorded for it in `manifest.json`
(`capture_digests`, and per-row in `proof_matrix`), and the same digests are embedded in the
corpus fixtures in `crates/aruna-gmail/tests/live_readside.rs`:

| file | sha384 |
|---|---|
| `r1_r1_inbox_capture.json` | `d94837d01e375238ba8b3dec67779c221b25c39310173a95eab96f12df1c5fdaa0eda5178bb5dc46958597dae32c99b4` |
| `r1_r1_archive_capture.json` | `2500e1a12836a356dc980ae8412e4ed1235edf67c17c8aeee5cb8f610334d454269f5496cd23b2104dd0073daa00e764` |
| `r1_r1_trash_capture.json` | `e2b828eac924bf753f1aad8de6fb9fdd34b4675bbdb131787d72d0d2a989dcda005e1c69eba3ec6b4fd18a3ca673b15f` |
| `r1_r1_spam_capture.json` | `076fc247adb32fb22165cbb228595aacde35dd7b0a7dee5b354cf4f4aeddf0c7fc2a9bf13ec74ac1be78964e216e9875` |
| `r1_r1_draft_capture.json` | `6bff73851db7fd912261011a66fd63314f3285927dfa23d0daa4934374184862a67c0fffd159b7394730d2952bcc725a` |
| `r3_denial_envelope.json` | `6f942068de5e6e8d39731d7330fbb5d5670d2d3a1ba215cb2ac0370bce0271f16052183cb524c324fd4bff5e8c393636` |

> The `.gitattributes` in this directory sets `* -text`, disabling git's end-of-line
> normalization here. Without it, a checkout on Windows (`core.autocrlf=true`) would rewrite LF
> to CRLF and silently change every digest above, making the committed evidence unverifiable.
> **Do not remove it.**

### Recovering the sanitizer source the manifest binds

The manifest's `sanitizer.source_sha384`
(`a247875e4107af1c331357dd84fa46ce34669a26e971cdb5b3c0eb8799e39cdf351ff0a4f58df87956fbe4857dd7bb4f`)
identifies `crates/aruna-gmail/tests/live_readside.rs` **as it existed at the run commit**
(`ca857c12…`) — run-time PROVENANCE. The file in the final tree necessarily differs: recording
the run's own corpus rows EDITS that same file after the run, so the run-commit bytes can never
equal the merged tree's (a structural circularity of the single-file layout). The run commit
is on `main` (the credential-migration merge), so recovery needs no PR ref:

```bash
git show ca857c12c806eee5a9ce66c80f0b8e0649b577d7:crates/aruna-gmail/tests/live_readside.rs \
  | sha384sum   # must print the manifest's sanitizer.source_sha384
```

*(Named improvement: split the sanitizer into its own module so its file is
stable across the corpus update and its digest can match the merged tree directly — the same
stability the mint helper already has.)*

### What the capture digests cover

The canonical committed bytes for the error envelope embed the **transport status beside the
body** (a root-level `"status"` member — issue #48, closed 2026-08-05), so two responses with
identical JSON under different statuses can never share a capture digest; the
`r4_mutant_changed_status_family_moves_the_capture_digest` witness demonstrates it. The five
R1 minimal captures are ID-free label projections from 2xx-gated reads; their digests cover
the projection bytes.

## Build provenance (read before trusting a green)

The replay tests locate the committed files through `env!("CARGO_MANIFEST_DIR")`, a
COMPILE-TIME path. A test binary compiled in one checkout and reused from a target directory
shared with another checkout reads the files of the tree it was COMPILED in, and Cargo may
report it fresh. During this re-record exactly that produced a false green (a binary built in a
throwaway worktree was reused in the main checkout); the fix was a rebuild. Note that
`cargo clean -p aruna-gmail` rebuilds only that package — a dependency crate built elsewhere
(the `aruna` engine rlib) survives it. Before citing a green as evidence: build in an isolated
target directory (`CARGO_TARGET_DIR=<fresh dir>`) or run a full `cargo clean`, and read the
`Running …/deps/live_readside-<hash>.exe` line. The manifest's `clean_tree` proves the source
tree the drill ran in, never which binaries it linked.

## Reproducing

The captures are replayed by the hermetic suite on every `cargo test` that compiles the
drill from this tree (see "Build provenance" above). The live drill itself
is opt-in and operator-attended — see `docs/runbooks/gmail-live-drill-oauth-runbook.md`. The
arranged mailbox states this run needed: one message each in inbox, archive, trash, spam, and
drafts (the trash message had to be re-arranged — Gmail purges Trash after 30 days, and an
empty Trash reads as a `204` empty listing that the current drill mislabels FAILED).
