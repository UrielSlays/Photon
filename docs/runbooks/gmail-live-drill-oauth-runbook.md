# Runbook — Gmail OAuth setup for the live-drill lane

**What this mints:** OAuth credentials for the throwaway drill account, consumed by the
env-gated live drills. **Operator-run end to end** — every password and consent click is the
operator's; agents never see or handle the secrets, only the parked file paths.

> **CORRECTED for the read-side lane.** The original revision of
> this runbook assumed one `gmail.modify` credential minted and exchanged in-repo. Three
> corrections, all binding:
>
> **(a) The exchange happens OUTSIDE the repo, and drills consume ACCESS tokens via env only.**
> `scripts/gmail_drill_mint.py` performs the consent and the refresh→access exchange against the
> parked client secret and writes its outputs into the parked dir. Refresh tokens NEVER reach a
> drill process: the drills read short-lived ACCESS tokens from `PHOTON_GMAIL_ACCESS_TOKEN` /
> `PHOTON_GMAIL_403_TOKEN` and the bundle path from `PHOTON_GMAIL_ATTESTATION`. Only the
> helper's non-secret SOURCE lives in-repo; every credential artifact stays parked.
>
> **(b) Mint-time attestation — the content-bound bundle.** The helper emits, atomically, one
> JSON bundle beside the token files carrying: `grant_generation` (the grant these digests belong to; preflight binds it to the ratchet high-water), `main_token_sha384`, `denial_token_sha384`, the
> granted-scope strings `effective_main_scopes` / `effective_denial_scopes` with their
> provenance `scope_source_main` / `scope_source_denial` (`token_response` or
> `rfc6749_identical_request_fallback`), the `same_principal` boolean derived in-process from
> the two minted identities, `minted_at`, **per-token `expires_at_main` and
> `expires_at_denial`**, and `helper_source_sha384` (sha384 of the helper's own source bytes —
> the producer is digest-identified, never a self-reported version; SHA-384 throughout per the
> repo's hash posture). The drill recomputes the token digests at preflight
> and REFUSES on any mismatch. No identity value is ever written to the bundle, a file, the
> env, or any output. The denial slot's identity is the OIDC userinfo `email` claim — the
> denial scope set must carry an email-bearing scope (`email` or userinfo.email; refused
> pre-consent otherwise), and a userinfo response without the claim refuses rather than
> falling back to the non-comparable opaque `sub`.
>
> **(c) Per-lane scope table — one lane, one credential:**
>
> | lane | scope | note |
> |---|---|---|
> | **main (the product credential — amended for the triage verbs)** | `https://www.googleapis.com/auth/gmail.modify` | exactly this set (the triage verbs need it; `gmail.modify` cannot permanently delete — Google's scope reference); broader OR narrower refuses at mint AND at app admission; the token file now carries the `grant` provenance object (`grant_generation`, `provider_principal`, `effective_scopes`) and `grant_high_water.json` ratchets the generation |
> | **denial (R3)** | **ZERO Gmail scope** (e.g. `openid email`) | any `.../auth/gmail*` or `https://mail.google.com/` is REJECTED — **`gmail.labels` explicitly included in the rejection: it authorizes POST label create/edit, i.e. mutation** |
> | **full mailbox** | `https://mail.google.com/` | NEVER requested — refused by prefix at mint and by the exact-set law at admission (permanent delete lives only under this scope) |
>
> Mint BOTH the read and denial tokens in ONE sitting so `same_principal` is derived from two
> actually-minted identities. The helper accepts only a **Desktop-app** (`installed`) client —
> a `web` client's registered redirect URIs cannot match the loopback flow's random port.

**Standing artifacts (state as of 2026-07-26):**
- Drill account: `<your-test-account>@gmail.com` (a throwaway test mailbox — sacrificial by design).
  **This read lane performs NO mutation**; the account is sacrificial because a future write
  lane will. Its old MailOps credential is an IMAP app password (OS keyring, service "Agent
  MailOps IMAP") — **useless for the REST API**, which is why this runbook exists.
- Google Cloud project: `<your-gcp-project-id>`, **Desktop-type** OAuth client (the only type this
  flow accepts — a `web` client's registered redirect URIs cannot match the loopback flow's
  random port, and the helper refuses one), app in **Testing** mode.
- Parked secrets (gitignored territory, OUTSIDE every repo): `~/.photon/gmail/` (Windows: `%USERPROFILE%\.photon\gmail\`)
  — `client_secret.json` (the downloaded client) plus, after the mint below,
  `gmail_readside_main_token.json`, `gmail_readside_denial_token.json` and
  `gmail_readside_attestation.json`. The mint helper itself is now the reviewed in-repo
  `scripts/gmail_drill_mint.py` — its SOURCE is in the repo, every output stays parked.
  *(The old parked `mint_refresh_token.py` / `token.json` pair belongs to the superseded
  single-token flow — see "HISTORICAL — DO NOT RUN" at the end.)*

## The console steps (one-time per client; ~10 min)

1. **Project:** [console.cloud.google.com](https://console.cloud.google.com/) → sign in as the
   drill account → project dropdown (top-left) → **New Project** → name it → Create.
2. **Enable the API:** ☰ menu → *APIs & Services* → *Library* → search **Gmail API** → Enable
   (with the new project selected).
3. **Consent screen:** *APIs & Services* → *Credentials* → **Configure Consent Screen** → User
   Type **External** → Create → fill app name + support email + developer contact → Save and
   Continue through Scopes (leave default — the scope is requested at runtime, not registered
   here) and Test Users.
4. **⚠ THE 403 HOOP (the one that actually bit, 2026-07-26):** an app in **Testing** mode
   **blocks every login that is not an explicitly whitelisted test user** — the consent screen
   errors with 403 `access_denied` and it looks like you did something wrong. You didn't. Fix:
   *APIs & Services* → *OAuth consent screen* → **Test users** → **+ ADD USERS** → add the drill
   account (`<your-test-account>@gmail.com`) → Save. Testing mode + test users is DELIBERATE — it is what
   lets a restricted scope (`gmail.readonly`, like `gmail.modify`, is Google-RESTRICTED) run
   with zero verification
   paperwork, up to 100 test users. Do not "publish" the app; that path leads to the
   verification/security-assessment machine (see the design's compliance posture — obligations
   stay inherited-and-open, Testing mode is the fence).
5. **Desktop client:** *Credentials* → **+ Create Credentials** → **OAuth client ID** →
   Application type **Desktop app** → name it → Create → **Download JSON**.
6. **Park it:** move the download to `~/.photon/gmail/client_secret.json` (Windows: `%USERPROFILE%\.photon\gmail\client_secret.json`) (out of
   Downloads, outside every repo).

## Minting for the read-side lane — THE PROCEDURE (step 1 of 4)

```bash
# Run FROM THE PHOTON CHECKOUT ROOT (the helper's relative path resolves there; only
# --secrets-dir must live outside every repo — the helper refuses a repo-contained one, so
# tokens never land in a committable tree).
cd ~/source/Photon   # or wherever your checkout lives
# python3 explicitly: on hosts where bare `python` is Python 2, the helper's
# f-strings fail immediately. (On Windows, `python` IS Python 3 — use it there.)
python3 scripts/gmail_drill_mint.py --secrets-dir "$HOME/.photon/gmail"
```

**One sitting, two consents.** The helper mints the main token (`gmail.modify` since the triage-verb credential migration; `gmail.readonly` before it) FIRST, then
the denial token (`openid email` — zero Gmail scope), fetching each identity in-process so
`same_principal` is derived from the two ACTUALLY MINTED identities. It then writes the token
files and the content-bound attestation bundle atomically into the parked dir:

- `gmail_readside_main_token.json` · `gmail_readside_denial_token.json` (access + refresh)
- `gmail_readside_attestation.json` (the bundle the drill's preflight binds against)

Two expected speed bumps per consent: the account chooser (pick the test account) and the *"Google
hasn't verified this app"* interstitial (Testing mode — Continue). The loopback redirect uses
an ephemeral port, so a stale consent URL from a previous run is DEAD — always use the current
run's. Consent is bounded: a denial (`access_denied`) or a 5-minute timeout ends the run
cleanly. `--main-only` skips the denial slot (its bundle fields stay null and R3 reports
`UNAVAILABLE`, which cannot close).

**Re-mint cadence:** refresh tokens for Testing-mode apps expire after ~7 days (Google policy),
and access tokens after ~1 hour. Treat an expired credential as a NORMAL state — re-run this
mint, don't debug the transport. The bundle's `expires_at_main` / `expires_at_denial` are
checked at preflight and an expired one REFUSES the run.

## Step 2 of 4 — Evidence directory: PRE-CREATE IT (the drill refuses to)

**Create the parked evidence directory yourself before the run.** The drill never creates it
and REFUSES a path that does not already exist, cannot be canonicalized, is rootless
(relative), resolves inside the repository worktree, or sits under **Cargo's effective target
directory** — which the drill asks Cargo for (`cargo metadata … target_directory`), so a
`[build] target-dir` set in `.cargo/config.toml` or `$CARGO_HOME/config.toml` is caught too,
not just `CARGO_TARGET_DIR` or a literal `target` component:

```bash
mkdir -p "$HOME/.photon/photon-readside-evidence"
```

If `cargo metadata` cannot answer, a **closure** run refuses rather than guessing (smoke warns
loudly and proceeds — smoke results are never citable).

This is a construction, not a normalization heuristic: requiring an existing, canonicalizable
directory makes the containment comparison canonical-to-canonical, so no path spelling
(extended-path, UNC, 8.3, junction, case) can smuggle evidence into the worktree. Each run
banks into its own `run-<timestamp>-<pid>` subdirectory; a prior run's captures are never
overwritten. `PHOTON_GMAIL_EVIDENCE_DIR` is REQUIRED in `closure` mode; in `smoke` mode its
absence sends captures to a temp dir explicitly labelled NON-EVIDENCE (never citable).

**Closure additionally requires a CLEAN, DETACHED worktree at the recorded SHA** — `git status
--porcelain` must be empty, HEAD must be detached, and the SHA must be a full object name.

## Step 3 of 4 — Export the env (ACCESS tokens only, never the refresh tokens)

```bash
export PHOTON_GMAIL_IT=1
# ⚠ NEVER paste a token literal into the shell — an interactive shell writes the command
# line to its history file (~/.bash_history), duplicating a live bearer outside the parked
# dir. Read the values out of the token files by command substitution instead; only file
# PATHS ever appear in history:
export PHOTON_GMAIL_ACCESS_TOKEN="$(python -c "import json,os;print(json.load(open(os.path.expanduser('~/.photon/gmail/gmail_readside_main_token.json')))['access_token'])")"
export PHOTON_GMAIL_403_TOKEN="$(python -c "import json,os;print(json.load(open(os.path.expanduser('~/.photon/gmail/gmail_readside_denial_token.json')))['access_token'])")"
# Those two lines are an EXTRACTOR, not a validator: they pull one `access_token` string out
# of a file and judge nothing about the credential around it. `parse_gmail_credential` in the
# app is the ONLY judge of a credential (the `grant` object, its generation, its principal),
# so a green drill does NOT imply the app will admit the same file. Do not grow a credential
# check here — a runbook-local validator would be a fourth reader of the same bytes, the exact
# defect class as the tolerant ratchet parse this step used to carry (below).
export PHOTON_GMAIL_ATTESTATION="$HOME/.photon/gmail/gmail_readside_attestation.json"
# The ratchet's CURRENT grant generation — a small counter, not a secret (the mint prints the
# same number). Read it through the MINT'S OWN STRICT READER, never a hand-rolled json.load:
# a plain parse admits ratchet shapes that both strict readers REFUSE (a repeated member, an
# unknown member, a string-typed generation, a `-0`-then-2 last-wins pair, a nested extra
# object), each of which prints as a plain integer the drill's parse::<u64> then accepts — so
# the drill would bank a green closure under a ratchet file the mint refuses to read and the
# app refuses to admit. `--print-high-water` opens no network and needs no client_secret.json;
# it prints the bare integer and nothing else. An unusable ratchet exits NON-ZERO with the
# reason on stderr, so nothing empty is ever exported; an ABSENT ratchet prints `0` — the
# reader's own "nothing minted yet" semantics — which the drill then refuses against any real
# bundle.
export PHOTON_GMAIL_GRANT_HIGH_WATER="$(python3 scripts/gmail_drill_mint.py --print-high-water --secrets-dir "$HOME/.photon/gmail")"
export PHOTON_GMAIL_MODE=smoke   # or closure
export PHOTON_GMAIL_EVIDENCE_DIR="$HOME/.photon/photon-readside-evidence"
# optional, and NOT expected to be set on this account: a pinned zero-label candidate for the
# A2 probe. See "You do NOT need to manufacture a zero-label message" below.
# export PHOTON_GMAIL_A2_MSG="<message id>"
```

`PHOTON_GMAIL_IT=1` with a missing/empty required variable or an unreadable bundle **PANICS** —
a half-configured live run must never look like a skip.

`PHOTON_GMAIL_GRANT_HIGH_WATER` is what binds the bundle to the ratchet: the drill refuses
unless the bundle's own `grant_generation` equals it, so an older access token restored beside
the bundle it was minted with — a pair that agrees on SHA-384 forever — can no longer run the
drill under a grant the re-consent already retired. A bundle from an older mint carries no
`grant_generation` at all and refuses with "re-mint".

## Step 4 of 4 — Run the drill

Arrange the five R1 mailbox states first — one message each: inbox · archived · trashed ·
spam · draft — then:

```bash
cargo test -p aruna-gmail --test live_readside live_readside_drills -- --nocapture
```

Smoke reports skips (never citable). Closure requires every mandatory ProofId PROVED or the
run exits INCOMPLETE with the matrix printed. The manifest and the sanitized captures land in
`$PHOTON_GMAIL_EVIDENCE_DIR/run-<timestamp>-<pid>/`.

### You do NOT need to manufacture a zero-label message (A2)

**Do not try to create a message with an empty `labelIds` set, and do not treat
`A2_ENCODING_OBSERVED = UNAVAILABLE(no zero-label message reachable)` as a failed run.** It is
a CONDITIONAL obligation (design §4.0/§4.2) and does not block closure.

Measured on this account during the attended run: 172 archived messages scanned read-only,
**zero** with an empty label set (56 `CATEGORY_PROMOTIONS`-only, 27 `CATEGORY_UPDATES`-only, 1
`DRAFT`, remainder multi-label). A deliberate construction attempt — ALL category tabs disabled
in Settings → Inbox → Categories, a fresh message sent to the account, archived and marked
read — still came back carrying exactly `CATEGORY_PERSONAL`: **disabling category tabs is
display-only**, Gmail classifies every received message and falls back to `CATEGORY_PERSONAL`.

So an empty label set is not reachable for received mail through normal delivery or any UI
operation available to you. The only remaining paths (`messages.insert`, IMAP `APPEND`,
migration APIs) are WRITES this read-only lane forbids — **do not use them**. With no candidate
on the wire, the A2 flip simply stays unlicensed, which is the same outcome the design
already accepts for the "present" observation. If a future account state ever does contain a
zero-label message, the drill proves A2 automatically, no operator action required.

## After the attended run — sequencing step: DONE (gate CLOSED — current committed run 2026-09-03)

The CURRENT committed attended CLOSURE run executed 2026-09-03 (the re-discharge: the first closure under the `{gmail.modify}` product credential with `grant_generation`
bound at preflight) — detached HEAD at `ca857c12c806eee5a9ce66c80f0b8e0649b577d7` (a separate
clean worktree of `main` at the credential-migration merge), clean tree, run dir `run-1788413993-36108` — and
all six mandatory obligations PROVED (`R1_INBOX` · `R1_ARCHIVE` · `R1_TRASH` · `R1_SPAM` ·
`R1_DRAFT` · `R3_SCOPE_403`), plus conditional `R3_ERRORINFO_CASING` PROVED and conditional
`A2_ENCODING_OBSERVED` honestly `UNAVAILABLE(search bound reached before exhaustion; no
zero-label candidate in the first N results)` — the WEAK reason, correctly: the mailbox has
grown past the scan's candidate cap, so the strong unreachability claim is deliberately not
emitted (the §"You do NOT need to manufacture a zero-label message" analysis above is the
2026-07-26 independent-scan context, at its original strength and date). *(Supersession
chain: the 2026-07-26 run @ `787d5eed…` was superseded wholesale by the 2026-08-05 run @
`e091b32a…` when a digest change altered every committed digest; that run was superseded by this
one. Committed evidence is never rewritten in place — git holds every earlier set; see the
evidence README's supersession note.)*

**Arrange the Trash state fresh before every closure run.** Gmail purges Trash after 30 days,
so the message trashed for the previous run is gone by the next one — and today an EMPTY Trash
makes the `R1_TRASH` arm report FAILED rather than UNAVAILABLE (Gmail answers an empty listing
under the drill's `fields` mask with `HTTP 204` and no body). One message in Trash
is enough.

`LIVE_CAPTURE_CORPUS` (and the R1 table beside it) in
`crates/aruna-gmail/tests/live_readside.rs` is **populated from that run's committed captures**,
every row digest-verified against the manifest, and
`r4_live_capture_corpus_replays_with_matching_digests` is **un-ignored — it runs on every
`cargo test` that compiles the drill from this tree** (a binary built in another checkout and
reused via a shared target directory reads THAT tree's files — the evidence README's "Build
provenance" section owns the rule). Sanitized copies of the manifest and all six captures live in
`docs/evidence/2026-07-gmail-live-readside-drill/` with a summary README.

**If you re-run the drill:** rows carry the CANONICAL committed bytes and are never fabricated or
hand-edited. To refresh the corpus, replace the rows from a new run's committed files and re-verify
each digest against that run's manifest — if a digest disagrees, STOP and investigate; never
adjust a digest to fit.

## Consumption contract (the live drill lane builds against this)

- The drills consume short-lived ACCESS tokens from the env (above); the refresh→access
  exchange is the parked helper's job and happens outside the repo. The transport's
  `connect(token)` takes the access token as an opaque bearer.
- Env-gated like the Stalwart drills: no env ⇒ tests skip loudly, never fail. **But
  `PHOTON_GMAIL_IT=1` with a missing/empty required variable or an unreadable bundle PANICS —
  a half-configured live run must never look like a skip.**
- The write-side drills' Part-III gate posture is decided in the live drill's own design — this
  runbook only supplies the credential.
- Secrets never enter the repo, the chat, logs, or the audit trail; the credential deny-baseline
  covers the `.photon` dir the same as every key store.

---

## HISTORICAL — DO NOT RUN (superseded)

The original revision of this runbook minted ONE `gmail.modify` refresh token with a parked
`mint_refresh_token.py` (`python -u mint_refresh_token.py` → `token.json`). **Do not run it.**
It produces a credential with NO attestation bundle and NO `grant` provenance object, so the
preflight binding has nothing to check and the app refuses it at admission with
the re-mint cure. (The read lane's preflight formerly required exactly `{gmail.readonly}`; the main slot is now exactly `{gmail.modify}`.) The
denial slot still requires ZERO Gmail scope.

Use the four-step procedure above (mint `gmail.modify` main + zero-scope denial → bundle
emitted → pre-create the parked evidence dir → export env → run). LIVE RED effects stay
Part-III-gated: the credential carries write authority; the app's verbs earn it
slice by slice.
