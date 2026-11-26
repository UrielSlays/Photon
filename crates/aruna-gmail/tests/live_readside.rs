//! Env-gated LIVE read-side drills against the real Gmail API (read-side proofs;
//! see the design notes in `docs/design/`).
//! OPT-IN: the live tests run only when `PHOTON_GMAIL_IT=1`; otherwise the live tests skip and
//! everything else in this binary is hermetic, so the default `cargo test` stays offline-green.
//! The RIPPLE drill is a WRITE drill and takes a SECOND opt-in on top of that
//! whole contract: `PHOTON_GMAIL_RIPPLE_IT=1`, plus `PHOTON_GMAIL_RIPPLE_MESSAGES` — a comma list
//! of message ids the operator seeded in the drill account (never real mail). `PHOTON_GMAIL_IT=1`
//! alone never runs it. Opted in at this tree it FAILS LOUD at its gate line: ADR-P010's
//! `DestructiveWriteGate::allow_test_host` opens only for a loopback host, so no live write is
//! constructible until live writes are explicitly enabled.
//! Mirror of `aruna-jmap/tests/live_recovery.rs` (env-gated opt-in, independent probe, ID-redaction
//! discipline), adapted per the design where the two diverge.
//!
//! Structure:
//! - `DrillEnv` — the SOLE parser of the entire env contract (design §3: one struct
//!   so contract drift becomes a compile error). No `env::var` call exists outside
//!   [`drill_env_from_process`] and its sibling [`ripple_env_from_process`], which hands
//!   the read contract to the same [`parse_drill_env`] and adds only its own two variables.
//! - The attestation-bundle preflight binding (design §3): sha384 recomputed over the
//!   ACTUAL token strings; any mismatch REFUSES the run. This detects
//!   post-mint token/bundle ASSOCIATION and mixed-generation errors — it is mistake-proofing,
//!   never an anti-adversary control (a same-host forger owns the box).
//! - `GmailProbe` — the independent oracle: GET-only API surface (no generic request/POST method
//!   exists on the type), compiled host, three-route allowlist, request ledger, typed
//!   redacting error wrapper on every failure path, bounded pagination with a quad-state outcome.
//! - ProofId accounting (design §4.0): EIGHT ProofIds, the mandatory set a compiled const the
//!   manifest can report but never redefine.
//! - The three live drills R1/R2/R3 (§4.1–§4.3), the R4 hermetic corpus + mutants + the A2
//!   characterization pin (§4.4), and the provenance-bound manifest (§4.5).
//! - The RIPPLE drill matrix — [`drive_ripple_row`] over the transport seam,
//!   witnessed hermetically against the loopback fixture, and its live case
//!   `ripple_drill_trash_untrash_spam_unspam_delta_within_declared_closure` (OWED: see the
//!   OPT-IN paragraph above for why it cannot run at this tree).
//!
//! All output and evidence is ID-free including failure paths:
//! provider message ids, thread ids, tokens, and identities never reach a panic message, a log
//! line, or the manifest. [`DrillError`] enforces that by construction — it cannot carry dynamic
//! content at all.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use aruna::gmail::{
    classify_gmail_error, GmailAccountResolver, GmailConnector, GmailError, GmailMessageId,
    GmailMessageRefResolver, GmailModifyRequest, GmailTransport, GmailUserId, LabelId,
};
use aruna::prestate::{banked_label_split, is_system_label, ripple_verdict, FrozenBasis, RippleVerdict};
use aruna::read_model::{Placement, ProviderMessageId, ProviderPlacement};
use aruna::{Action, Command, Connector, Facet, FailureKind, LogError};
use aruna_gmail::{
    map_error_response, DestructiveWriteGate, GateError, GmailProviderPlacement,
    HttpGmailTransport, GMAIL_ENDPOINT,
};
use sha2::{Digest, Sha384};

// ===============================================================================================
// Shared small helpers
// ===============================================================================================

/// The one scope the main drill token may hold.
///
/// **This moved from `gmail.readonly` to `gmail.modify`.** The product's exact set is now `{gmail.modify}` because the triage verbs are
/// WRITES, and the mint no longer issues a readonly-only main token — so a drill pinned to
/// `gmail.readonly` would refuse every credential this build can produce, i.e. it would stop
/// being runnable at all. The LAW is unchanged: unordered EXACT SET, broader refuses closure.
///
/// This test's live re-run is still owed. The
/// SCOPE half is discharged: the 2026-09-03 attended CLOSURE run executed against a real
/// token under exactly `{gmail.modify}` with the bundle's `grant_generation` bound at
/// preflight (see [`LIVE_RUN_COMMIT_SHA`] / [`LIVE_RUN_DIR`] and the evidence README). The
/// PRINCIPAL half is NOT: this drill still builds its production reader with the `me` alias
/// (`GmailUserId("me")` in `live_readside_drills`), so the `userId=<email>` route form
/// remains undischarged — named here, not papered over.
const MODIFY_SCOPE: &str = "https://www.googleapis.com/auth/gmail.modify";

/// Gmail Discovery document revision every wire claim in this file is pinned against (design §1).
const DISCOVERY_REVISION: &str = "20260719";

/// Sha384 hex digest of arbitrary bytes — the binding primitive for the attestation preflight and
/// the manifest's capture digests.
fn sha384_hex(bytes: &[u8]) -> String {
    let digest = Sha384::digest(bytes);
    let mut out = String::with_capacity(64);
    for b in digest {
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_secs() as i64
}

// ===============================================================================================
// DrillEnv — the SOLE parser of the env contract (design §3). Fail-closed, never a skip.
// ===============================================================================================

/// `smoke` (default) | `closure` — §4.0's two accounting modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DrillMode {
    Smoke,
    Closure,
}

/// The parsed env contract. ONE struct is the sole parser of the entire contract (design §3) so a dropped/renamed variable is a compile-visible change here, never
/// silent drift across call sites.
#[derive(Debug, Clone)]
struct DrillEnv {
    access_token: String,
    denial_token: Option<String>,
    attestation_path: PathBuf,
    /// The ratchet's CURRENT grant generation, exported by the ceremony from
    /// `grant_high_water.json`'s `grant_generation` member the same way the access token is
    /// exported from the token file. REQUIRED whenever the live run is opted in — the drill's
    /// contract is env-only (it never opens the secrets dir), so this is how the bundle's
    /// generation gets something to be bound against.
    grant_high_water: u64,
    a2_msg: Option<String>,
    mode: DrillMode,
    /// Where captures + the manifest land: REQUIRED in closure mode, and it
    /// must ALREADY EXIST and sit outside the repo worktree and any cargo `target` dir
    /// ([`resolve_evidence_dir`]); optional in smoke, which otherwise falls back to a temp
    /// dir labelled NON-EVIDENCE.
    evidence_dir: Option<PathBuf>,
}

/// Parse the env contract from an injected lookup (hermetic + parallel-safe: the env tests never
/// touch process env). `Ok(None)` = the live run is not opted in. `Err` = opted in but the contract
/// is violated — the caller MUST panic, never skip (design §3 fail-closed env discipline).
fn parse_drill_env<F: Fn(&str) -> Option<String>>(get: F) -> Result<Option<DrillEnv>, String> {
    // Empty-string values are MISSING: an empty token exported by a broken shell line must not
    // count as present.
    let var = |key: &str| get(key).filter(|v| !v.trim().is_empty());

    if var("PHOTON_GMAIL_IT").as_deref() != Some("1") {
        return Ok(None);
    }
    // Fail-closed from here on: opted in, every required var must be present and non-empty
    // — a missing one is an ERROR the caller panics on, NEVER a skip. A silent skip here is
    // a claimed-closed obligation going green with its drill never
    // executing.
    let Some(access_token) = var("PHOTON_GMAIL_ACCESS_TOKEN") else {
        return Err("PHOTON_GMAIL_ACCESS_TOKEN is missing or empty".to_string());
    };
    let Some(attestation) = var("PHOTON_GMAIL_ATTESTATION") else {
        return Err("PHOTON_GMAIL_ATTESTATION is missing or empty".to_string());
    };
    // Same shape as the ATTESTATION requirement — missing REFUSES, it never
    // defaults to 0 and never becomes a skip. A non-numeric value refuses too rather than
    // coercing: a broken export line must not silently become "generation 0", which no mint
    // can ever produce and which would refuse every bundle for the wrong reason.
    let Some(high_water_raw) = var("PHOTON_GMAIL_GRANT_HIGH_WATER") else {
        return Err("PHOTON_GMAIL_GRANT_HIGH_WATER is missing or empty".to_string());
    };
    let Ok(grant_high_water) = high_water_raw.trim().parse::<u64>() else {
        return Err(
            "PHOTON_GMAIL_GRANT_HIGH_WATER is not a u64 grant generation (value redacted)"
                .to_string(),
        );
    };
    let mode = match var("PHOTON_GMAIL_MODE").as_deref() {
        None | Some("smoke") => DrillMode::Smoke,
        Some("closure") => DrillMode::Closure,
        Some(_) => {
            return Err(
                "PHOTON_GMAIL_MODE must be `smoke` or `closure` (value redacted)".to_string()
            )
        }
    };
    let evidence_dir = var("PHOTON_GMAIL_EVIDENCE_DIR").map(PathBuf::from);
    // Closure evidence is citable and must never land inside target/ or the worktree — so in
    // closure mode the dir is REQUIRED, refused at parse.
    if mode == DrillMode::Closure && evidence_dir.is_none() {
        return Err(
            "PHOTON_GMAIL_EVIDENCE_DIR is required in closure mode (evidence must land \
             outside the repo worktree and target/)"
                .to_string(),
        );
    }
    Ok(Some(DrillEnv {
        access_token,
        denial_token: var("PHOTON_GMAIL_403_TOKEN"),
        attestation_path: PathBuf::from(attestation),
        grant_high_water,
        a2_msg: var("PHOTON_GMAIL_A2_MSG"),
        mode,
        evidence_dir,
    }))
}

/// Resolve and validate the evidence dir — closing the containment class wholesale.
///
/// **Why not another normalization edge.** One failure shape was a relative path; another was
/// Windows' extended-path (`\\?\`) vs plain-form asymmetry. Windows path normalization
/// (extended-path / UNC / 8.3 short names / junctions / case) is an UNBOUNDED space and
/// per-edge patching cannot terminate. So the class is closed BY CONSTRUCTION instead: the
/// evidence dir must **already exist and be canonicalizable**, and the repo root must
/// canonicalize too — then the containment test is canonical-to-canonical, and **no prefix
/// comparison against an un-normalized path exists anywhere in this file**. The operator
/// pre-creates the parked evidence dir (runbook + design §4.5); a nonexistent,
/// uncanonicalizable, rootless, or repo-contained path REFUSES with that instruction.
///
/// Returns the CANONICAL dir on success — the only path the run may record into.
/// Extract `target_directory` from `cargo metadata --format-version 1 --no-deps` output.
///
/// **This is the single authority for the effective target directory** (an earlier
/// inference reproduced real data loss). Cargo already accounts for `CARGO_TARGET_DIR`, `[build] target-dir` in
/// `.cargo/config.toml`, the same key in `$CARGO_HOME/config.toml`, and the default — so
/// asking Cargo ends the class. The previous env-var-else-`<repo>/target` INFERENCE missed the
/// config-file forms, and that reproduced real data loss with one: a config pointing at
/// `build-cache`, then `cargo clean` DELETED a proof file beneath it.
fn parse_cargo_metadata_target_dir(metadata_json: &str) -> Result<PathBuf, String> {
    let value: serde_json::Value = serde_json::from_str(metadata_json)
        .map_err(|_| "cargo metadata output is not JSON".to_string())?;
    match value.get("target_directory").and_then(|d| d.as_str()) {
        Some(dir) if !dir.trim().is_empty() => Ok(PathBuf::from(dir)),
        _ => Err("cargo metadata carried no usable `target_directory`".to_string()),
    }
}

/// Resolve the EFFECTIVE target directory from injected inputs — pure, so the witness can
/// drive a config-file-configured dir without mutating real Cargo config.
///
/// Precedence: Cargo's own answer ALWAYS wins. `CARGO_TARGET_DIR` is a legitimate fallback
/// when `cargo metadata` is unavailable — Cargo's env var overrides config files by Cargo's
/// own precedence, so when set it IS the effective dir, not a guess. With neither, there is
/// NO answer: a repo root is location knowledge, not target-dir knowledge, and the old
/// `<repo>/target` last resort was a guess presented as success — under a configured
/// `[build] target-dir` it let closure accept an evidence dir inside Cargo's real build
/// directory (the closure fail-open class). A caller in CLOSURE mode routes
/// the `Err` through [`establish_or_refuse`] and refuses.
fn effective_target_dir_from(
    cargo_metadata_json: Option<&str>,
    env_target_dir: Option<PathBuf>,
) -> Result<PathBuf, String> {
    // A RELATIVE override is AMBIGUOUS BY CONSTRUCTION — Cargo resolves it
    // against the cwd of each invocation, and this integration test's nested `cargo metadata`
    // runs from the package dir while the outer `cargo test` ran from the workspace root, so
    // the two resolve `..\build-cache`-style values to DIFFERENT directories. The durability
    // check would then guard the wrong one and `cargo clean` could delete recorded evidence.
    // Refuse the relative override BEFORE consulting metadata (whose answer is poisoned by
    // the same mis-resolution), and require every answer that leaves this ladder be absolute.
    // The ambiguity class is CWD-RELATIVE resolution, so the predicate is `has_root()` —
    // not `is_absolute()`, which on Windows also rejects rooted-but-driveless paths
    // (`/env/target`) whose resolution does not depend on the invocation cwd.
    if let Some(dir) = &env_target_dir {
        if !dir.has_root() {
            return Err(format!(
                "CARGO_TARGET_DIR is CWD-RELATIVE ({}) — its resolution base differs across \
                 Cargo's nested invocations, so the durability check could guard the wrong \
                 directory; set a rooted path",
                dir.display()
            ));
        }
    }
    let answer = if let Some(json) = cargo_metadata_json {
        // Cargo answered: that answer is authoritative, config files included.
        parse_cargo_metadata_target_dir(json)?
    } else if let Some(dir) = env_target_dir {
        dir
    } else {
        return Err(
            "cargo metadata unavailable and CARGO_TARGET_DIR unset — the effective target \
             directory cannot be established (a <repo>/target guess would fail open under a \
             configured [build] target-dir)"
                .to_string(),
        );
    };
    if !answer.has_root() {
        return Err(format!(
            "the effective target directory resolved CWD-RELATIVE ({}) — ambiguous across \
             invocation cwds; refusing (codex r14 P1)",
            answer.display()
        ));
    }
    Ok(answer)
}

/// The target-directory CANDIDATES this binary runs under, derived from its own executable
/// path. Cargo's layout is
/// `<target-root>[/<target-kind>]/<profile>/deps/<exe>` — the optional middle component
/// appears under `cargo test --target <triple-or-custom.json>`, and its NAME IS ARBITRARY
/// (a custom target JSON names it anything — a hyphen-count heuristic was evaded by
/// `--target local.json` later). So NO
/// name discrimination at all: BOTH the third ancestor (root-or-kind) AND the fourth (the
/// root whenever a kind component exists) are candidates UNCONDITIONALLY, and every
/// candidate gates containment. Complement-shaped: nothing about the component's spelling
/// is assumed, so nothing can evade it. In the standard triple-less layout the extra
/// ancestor is the worktree (already refused by the worktree containment check — redundant,
/// harmless); in override layouts it over-refuses sibling evidence fail-closed. The ONE
/// carve-out: a fourth ancestor that is a filesystem ROOT is skipped — gating `/` would
/// refuse every path on the machine, which is not a containment check but a shutdown.
/// This covers EVERY override mechanism (env var, config file, `--target-dir` CLI flag) by
/// construction, because the binary physically lives where Cargo built it. An unexpected
/// layout fails CLOSED (closure refuses via `establish_or_refuse`).
fn target_dir_candidates_from_exe(exe: &Path) -> Result<Vec<PathBuf>, String> {
    let deps = exe
        .parent()
        .ok_or_else(|| "test executable has no parent directory".to_string())?;
    if deps.file_name().and_then(|n| n.to_str()) != Some("deps") {
        return Err(format!(
            "unexpected test-binary layout ({}) — expected \
             <target-root>[/<target-kind>]/<profile>/deps/<exe>; refusing to derive a \
             target directory from it",
            exe.display()
        ));
    }
    let profile = deps
        .parent()
        .ok_or_else(|| "deps directory has no parent".to_string())?;
    let root_or_kind = profile
        .parent()
        .ok_or_else(|| "profile directory has no parent".to_string())?;
    let mut candidates = vec![root_or_kind.to_path_buf()];
    if let Some(above) = root_or_kind.parent() {
        // Skip only a filesystem root (a parentless path): gating `/` or `C:\` would refuse
        // everything, not contain anything.
        if above.parent().is_some() {
            candidates.push(above.to_path_buf());
        }
    }
    Ok(candidates)
}

/// Ask Cargo for the effective target directory. Runs ONCE per drill run and is threaded from
/// there — never cached across runs, never re-shelled per call.
fn probe_effective_target_dir() -> Result<PathBuf, String> {
    let metadata = std::process::Command::new(
        std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()),
    )
    .args(["metadata", "--format-version", "1", "--no-deps"])
    .output();
    let json = match &metadata {
        Ok(o) if o.status.success() => Some(String::from_utf8_lossy(&o.stdout).to_string()),
        _ => None,
    };
    effective_target_dir_from(
        json.as_deref(),
        // Cargo's own variable, not part of the drill's `PHOTON_GMAIL_*` env contract.
        std::env::var_os("CARGO_TARGET_DIR").map(PathBuf::from),
    )
}

/// What the run KNOWS about the repository root — the shape that makes the closure fail-open
/// unreachable. `Option<&Path>` permitted `None` to mean "skip the worktree
/// containment check ENTIRELY", which is a fail-OPEN on the exact check that keeps evidence out
/// of the repo. Closure constructs [`RepoRootKnowledge::Known`] or refuses; only smoke can
/// build the unknown variant, and its name says so.
#[derive(Debug, Clone, Copy)]
enum RepoRootKnowledge<'a> {
    Known(&'a Path),
    /// SMOKE ONLY — worktree containment is not checked. Never constructible on a closure path.
    UnknownSmokeOnly,
}

fn resolve_evidence_dir(
    dir: &Path,
    repo_root: RepoRootKnowledge<'_>,
    // Cargo's ACTUALLY CONFIGURED target directory: `CARGO_TARGET_DIR` when
    // set, else the workspace `target`. `None` = not established (smoke only).
    cargo_target_dir: Option<&Path>,
) -> Result<PathBuf, String> {
    let repo_root: Option<&Path> = match repo_root {
        RepoRootKnowledge::Known(root) => Some(root),
        RepoRootKnowledge::UnknownSmokeOnly => None,
    };
    // Rootless first, for a precise message: a CWD-resolving dir lands inside the worktree.
    // (`has_root()` rather than `is_absolute()`: it is CWD-resolution being refused, and
    // `is_absolute()` on Windows additionally demands a drive prefix.)
    if !dir.has_root() {
        return Err(
            "REFUSE: evidence dir must be a rooted (absolute) path — a relative path \
             resolves against the CWD, inside the worktree"
                .to_string(),
        );
    }
    // MUST ALREADY EXIST. This is the load-bearing construction: canonicalize only succeeds
    // on a real path, so from here both sides of the comparison are canonical.
    let canonical_dir = std::fs::canonicalize(dir).map_err(|_| {
        "REFUSE: evidence dir does not exist or cannot be canonicalized — create the parked \
         evidence directory first, then re-run (the drill never creates it, so a path that \
         is not there yet can never be compared honestly against the worktree)"
            .to_string()
    })?;
    // The cheap BELT: any literal `target` component. Kept — it costs nothing and catches the
    // ordinary layout even when the real target dir cannot be established.
    if canonical_dir
        .components()
        .any(|c| c.as_os_str().eq_ignore_ascii_case("target"))
    {
        return Err(
            "REFUSE: evidence dir is inside a cargo target directory — `cargo clean` must \
             never erase banked evidence"
                .to_string(),
        );
    }
    // The BRACES: the component test alone passes a custom
    // `CARGO_TARGET_DIR` such as `D:\build-cache`, under which `cargo clean` would still erase
    // recorded evidence. Compare against Cargo's ACTUAL configured target directory,
    // canonicalized on both sides so the comparison is spelling-independent (the same
    // canonical-to-canonical discipline as the worktree check).
    if let Some(target_dir) = cargo_target_dir {
        let canonical_target = std::fs::canonicalize(target_dir).map_err(|_| {
            "REFUSE: cargo's configured target directory could not be canonicalized, so \
             evidence durability cannot be established"
                .to_string()
        })?;
        if canonical_dir.starts_with(&canonical_target) {
            return Err(
                "REFUSE: evidence dir is inside cargo's CONFIGURED target directory \
                 (CARGO_TARGET_DIR or the workspace target) — `cargo clean` must never erase \
                 banked evidence"
                    .to_string(),
            );
        }
    }
    if let Some(root) = repo_root {
        let canonical_root = std::fs::canonicalize(root).map_err(|_| {
            "REFUSE: the repository root could not be canonicalized — containment cannot be \
             established, so the run refuses rather than guessing"
                .to_string()
        })?;
        // Canonical-to-canonical, the ONLY containment comparison in this file.
        if canonical_dir.starts_with(&canonical_root) {
            return Err(
                "REFUSE: evidence dir is inside the repo worktree — evidence must survive \
                 checkouts and stay out of the clean-tree gate"
                    .to_string(),
            );
        }
    }
    Ok(canonical_dir)
}

/// The panic shell around [`parse_drill_env`]: opted-in-but-broken PANICS, never skips.
fn drill_env_or_panic<F: Fn(&str) -> Option<String>>(get: F) -> Option<DrillEnv> {
    match parse_drill_env(get) {
        Ok(env) => env,
        Err(reason) => panic!("PHOTON_GMAIL_IT=1 but the env contract is violated: {reason}"),
    }
}

/// The read contract's process-env read (design §3). Its one sibling is the ripple
/// drill's [`ripple_env_from_process`], which hands this same contract to [`parse_drill_env`];
/// the two are the only `PHOTON_GMAIL_*` reads in this binary.
fn drill_env_from_process() -> Option<DrillEnv> {
    drill_env_or_panic(|key| std::env::var(key).ok())
}

/// The RIPPLE drill's env contract: the read drill's WHOLE [`DrillEnv`],
/// parsed by [`parse_drill_env`] unchanged, PLUS the ripple drill's own two variables. One
/// struct again, so a dropped or renamed ripple variable is a compile-visible change here.
#[derive(Debug, Clone, PartialEq)]
struct RippleEnv {
    /// The read contract, every rule included (attestation, high-water, mode, evidence dir).
    drill: DrillEnv,
    /// `PHOTON_GMAIL_RIPPLE_MESSAGES` — the message ids the operator seeded in the drill account for
    /// the matrix (design §1-§2: an Inbox message carrying UNREAD + STARRED + IMPORTANT + a
    /// `CATEGORY_*` label + one user label, and an archived message with orthogonal labels). The
    /// drill seeds nothing itself and never picks a message of its own.
    messages: Vec<String>,
}

/// Parse the ripple contract from an injected lookup. `Ok(None)` = the ripple drill is not opted
/// in (`PHOTON_GMAIL_RIPPLE_IT != 1`) — whatever `PHOTON_GMAIL_IT` says, so the read drill's own
/// opt-in never starts a WRITE drill. `Err` = opted in and the contract is violated: the caller
/// PANICS, never skips (the same discipline). Values are never formatted into a reason.
fn parse_ripple_env<F: Fn(&str) -> Option<String>>(get: F) -> Result<Option<RippleEnv>, String> {
    // Empty-string values are MISSING, exactly as in `parse_drill_env`.
    let var = |key: &str| get(key).filter(|v| !v.trim().is_empty());
    if var("PHOTON_GMAIL_RIPPLE_IT").as_deref() != Some("1") {
        return Ok(None);
    }
    // Opted in: fail-closed from here on. The read contract rides WHOLE, through its own parser —
    // and its own opt-in is REQUIRED, so the write drill can never run outside the attested,
    // preflighted read contract (a missing `PHOTON_GMAIL_IT=1` is an error, never a skip).
    let Some(drill) = parse_drill_env(&get)? else {
        return Err(
            "PHOTON_GMAIL_RIPPLE_IT=1 requires the read drill's whole contract, \
             PHOTON_GMAIL_IT=1 included"
                .to_string(),
        );
    };
    let Some(raw) = var("PHOTON_GMAIL_RIPPLE_MESSAGES") else {
        return Err("PHOTON_GMAIL_RIPPLE_MESSAGES is missing or empty".to_string());
    };
    let messages: Vec<String> = raw.split(',').map(|m| m.trim().to_string()).collect();
    if messages.iter().any(String::is_empty) {
        return Err(
            "PHOTON_GMAIL_RIPPLE_MESSAGES carries an empty entry (value redacted)".to_string()
        );
    }
    // A repeated id would drive one message's round trips twice and record it under two
    // ordinals — refuse rather than guess which entry the operator meant.
    if messages.iter().collect::<BTreeSet<_>>().len() != messages.len() {
        return Err("PHOTON_GMAIL_RIPPLE_MESSAGES repeats an id (value redacted)".to_string());
    }
    Ok(Some(RippleEnv { drill, messages }))
}

/// The panic shell around [`parse_ripple_env`]: opted-in-but-broken PANICS, never skips.
fn ripple_env_or_panic<F: Fn(&str) -> Option<String>>(get: F) -> Option<RippleEnv> {
    match parse_ripple_env(get) {
        Ok(env) => env,
        Err(reason) => {
            panic!("PHOTON_GMAIL_RIPPLE_IT=1 but the ripple env contract is violated: {reason}")
        }
    }
}

/// The ripple drill's process-env read — the sibling of [`drill_env_from_process`].
fn ripple_env_from_process() -> Option<RippleEnv> {
    ripple_env_or_panic(|key| std::env::var(key).ok())
}

// ===============================================================================================
// The attestation bundle + the preflight binding (design §3)
// ===============================================================================================

/// The mint-emitted content-bound bundle, exactly the member set `scripts/gmail_drill_mint.py`
/// writes (design §3). Denial fields are null for a main-only mint sitting.
#[derive(Debug, Clone, serde::Deserialize)]
struct AttestationBundle {
    /// WHICH grant these digests belong to. The mint has written this
    /// member; the drill ignored it, so an older token and ITS OWN bundle — restored
    /// together after a re-consent — still agreed on sha384 and the run proceeded under a
    /// LOCALLY RETIRED grant. [`preflight`] now binds it to the ratchet high-water.
    ///
    /// Typed as a presence-preserving double-`Option` and not a bare `u64` on purpose: a
    /// older bundle omits the member entirely, and that case must reach the operator as the
    /// REFUSAL "re-mint this bundle", not as `load_bundle`'s generic "unparseable" — the two
    /// have different cures. The member is nonetheless REQUIRED: every non-value refuses, it
    /// never defaults.
    ///
    /// A plain `Option<u64>` collapsed a PRESENT
    /// `"grant_generation": null` into the absent case, and the refusal claimed "older
    /// mint" — false twice. The double-`Option` shape
    /// (`crates/aruna/src/capacity.rs:deserialize_present`) keeps the two facts apart:
    /// outer `None` = the key never appeared; `Some(None)` = present but null.
    #[serde(default, deserialize_with = "generation_member_present")]
    grant_generation: Option<Option<u64>>,
    main_token_sha384: String,
    denial_token_sha384: Option<String>,
    effective_main_scopes: Vec<String>,
    effective_denial_scopes: Option<Vec<String>>,
    scope_source_main: String,
    scope_source_denial: Option<String>,
    same_principal: Option<bool>,
    minted_at: i64,
    /// Per-token expiries: each slot carries its own, so preflight and the
    /// manifest's record-a-digest-only-when-expired rule are honest PER TOKEN — one merged
    /// expiry would let a still-live denial token's digest ride an expired main's timestamp.
    expires_at_main: i64,
    expires_at_denial: Option<i64>,
    helper_source_sha384: String,
}

/// Runs ONLY when the `grant_generation` key is present (a missing key is `#[serde(default)]`'s
/// outer `None`) — wrapping in `Some(..)` is itself the "present" signal (the
/// pattern at `crates/aruna/src/capacity.rs`). `null` decodes to the inner `None`.
fn generation_member_present<'de, D>(deserializer: D) -> Result<Option<Option<u64>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    <Option<u64> as serde::Deserialize>::deserialize(deserializer).map(Some)
}

/// An unreadable/unparseable bundle is an ERROR the live path panics on —
/// never a skip. The path is operator config, not a secret, so it may appear in the reason.
fn load_bundle(path: &Path) -> Result<(AttestationBundle, String), String> {
    let bytes = std::fs::read(path)
        .map_err(|e| format!("attestation bundle unreadable at {}: {e}", path.display()))?;
    let bundle: AttestationBundle = serde_json::from_slice(&bytes)
        .map_err(|_| format!("attestation bundle unparseable at {}", path.display()))?;
    Ok((bundle, sha384_hex(&bytes)))
}

/// The two provenance strings the helper may record for a scope set (RFC 6749 §5.1 handling).
const SCOPE_SOURCES: [&str; 2] = ["token_response", "rfc6749_identical_request_fallback"];

/// Preflight binding — env + file only, NO wire call (design §3). Recomputes sha384 over the
/// ACTUAL token strings and refuses on any mismatch with the bundle: the stale/mixed-env and
/// cross-mint-pairing class. The digest proves post-mint token/bundle
/// ASSOCIATION, not semantic truth (the helper's derivations are tested separately) and binds nothing against
/// a same-host adversary, which is out of scope (code already running on the user's machine with the user's privileges).
///
/// Error strings are static descriptions — no token byte, digest, or identity is formatted in.
/// The ONE exception is the pair of grant generations below: they are small monotone counters,
/// not identities or secrets (the mint prints the same number to the operator's terminal), and
/// a refusal that cannot say WHICH generation is stale cannot be acted on.
fn preflight(
    bundle: &AttestationBundle,
    main_token: &str,
    denial_token: Option<&str>,
    now: i64,
    mode: DrillMode,
    grant_high_water: u64,
) -> Result<(), String> {
    // The bundle↔ratchet binding — checked FIRST, because it is the
    // one refusal the digest binding below can never reach. An older access token and the
    // bundle minted WITH it agree on sha384 forever; restored together after a re-consent they
    // sail through the binding and the drill spends a grant the ratchet has already retired. The
    // generation the mint stamped into the bundle must equal the CURRENT high-water, which the
    // ceremony exports into the env contract exactly the way it exports the access token.
    //
    // This is mistake-proofing over the operator's own restore/backup tooling,
    // never an anti-adversary control — anyone who can rewrite the bundle can rewrite the
    // high-water file the export reads.
    match bundle.grant_generation {
        None => {
            return Err(
                "REFUSE: bundle carries no grant_generation (pre-#75 mint — re-mint)".to_string(),
            )
        }
        // PRESENT but null — an unusable value, never evidence of an older mint.
        Some(None) => {
            return Err(
                "REFUSE: bundle's grant_generation is JSON null — a present member with no \
                 readable generation (re-mint)"
                    .to_string(),
            )
        }
        Some(Some(generation)) if generation != grant_high_water => {
            return Err(format!(
                "REFUSE: bundle grant_generation {generation} is not the current high-water \
                 {grant_high_water} (a restored older token+bundle pair, or a stale ratchet \
                 — re-mint)"
            ))
        }
        Some(Some(_)) => {}
    }

    // The binding itself: recompute sha384 over the ACTUAL token strings in env and refuse
    // on any mismatch — both slots, and therefore any cross-session (mixed-generation) pairing.
    if sha384_hex(main_token.as_bytes()) != bundle.main_token_sha384 {
        return Err(
            "REFUSE: main token sha384 does not match the bundle (stale or mixed mint generation)"
                .to_string(),
        );
    }
    if let Some(denial) = denial_token {
        match bundle.denial_token_sha384.as_deref() {
            Some(attested) if sha384_hex(denial.as_bytes()) == attested => {}
            Some(_) => {
                return Err(
                    "REFUSE: denial token sha384 does not match the bundle (stale or mixed \
                     mint generation)"
                        .to_string(),
                )
            }
            None => {
                return Err(
                    "REFUSE: a denial token is present but the bundle attests none".to_string()
                )
            }
        }
    }

    // Scope provenance must be one of the two recorded sources the helper can emit.
    if !SCOPE_SOURCES.contains(&bundle.scope_source_main.as_str()) {
        return Err("REFUSE: bundle scope_source_main is not a recognized provenance".to_string());
    }
    if let Some(source) = bundle.scope_source_denial.as_deref() {
        if !SCOPE_SOURCES.contains(&source) {
            return Err(
                "REFUSE: bundle scope_source_denial is not a recognized provenance".to_string()
            );
        }
    }
    // A USED slot requires a RECORDED provenance: a denial token whose bundle
    // cannot say where its scope claim came from is unattested authority — refuse.
    if denial_token.is_some() && bundle.scope_source_denial.is_none() {
        return Err(
            "REFUSE: denial token present but the bundle records no denial scope provenance"
                .to_string(),
        );
    }

    // Main effective scopes: unordered exact set equality against {gmail.modify} —
    // never substrings. Broader REFUSES closure, warns in smoke (design §3).
    let main_scopes: BTreeSet<&str> = bundle
        .effective_main_scopes
        .iter()
        .map(String::as_str)
        .collect();
    let expected: BTreeSet<&str> = [MODIFY_SCOPE].into_iter().collect();
    if main_scopes != expected {
        match mode {
            DrillMode::Closure => {
                return Err(
                    "REFUSE (closure): main effective scopes are not exactly {gmail.modify}"
                        .to_string(),
                )
            }
            DrillMode::Smoke => eprintln!(
                "preflight WARNING (smoke): main effective scopes are not exactly \
                 {{gmail.modify}} — a closure run would refuse this bundle"
            ),
        }
    }

    if denial_token.is_some() {
        // Denial scopes must contain NO Gmail authority: nothing under the Gmail scope family and
        // not the full-access mail.google.com scope (design §3 — `gmail.labels` is explicitly a
        // POST-capable authority and is caught by the family prefix).
        let Some(denial_scopes) = bundle.effective_denial_scopes.as_ref() else {
            return Err(
                "REFUSE: denial token present but the bundle records no denial scopes".to_string(),
            );
        };
        if denial_scopes.iter().any(|s| {
            s.starts_with("https://www.googleapis.com/auth/gmail")
                || s.starts_with("https://mail.google.com/")
        }) {
            return Err(
                "REFUSE: denial token's effective scopes contain a Gmail scope".to_string()
            );
        }
        // R3's inference is about SCOPE, so both tokens must be the same principal — attested by
        // the helper from the two minted identities (design §3/§4.3).
        if bundle.same_principal != Some(true) {
            return Err(
                "REFUSE: denial token present but same_principal is not attested true".to_string(),
            );
        }
    }

    if now >= bundle.expires_at_main {
        return Err("REFUSE: the main token's expires_at_main is in the past".to_string());
    }
    if denial_token.is_some() {
        match bundle.expires_at_denial {
            None => {
                return Err(
                    "REFUSE: denial token present but the bundle records no denial expiry"
                        .to_string(),
                )
            }
            Some(expiry) if now >= expiry => {
                return Err(
                    "REFUSE: the denial token's expires_at_denial is in the past".to_string()
                )
            }
            Some(_) => {}
        }
    }
    Ok(())
}

/// Bind the attestation to the helper THIS TREE reviewed: the bundle's
/// producer digest must equal the digest of `scripts/gmail_drill_mint.py` as it exists in the
/// tree the drill runs from. The helper's derivations are tested separately; an attestation minted
/// by DIFFERENT bytes (a stale checkout, a locally-modified helper — earlier sha384-era
/// helpers on this very branch carry known scope/expiry bugs) is provenance the run must
/// refuse, in EVERY mode. The closure repo gates already guarantee tree == committed, so in
/// closure this binds the bundle to the committed, reviewed helper — turning a
/// mismatch class from a manual review check into an enforced runtime gate.
fn verify_helper_provenance(
    bundle: &AttestationBundle,
    helper_source: &[u8],
) -> Result<(), String> {
    if sha384_hex(helper_source) != bundle.helper_source_sha384 {
        return Err(
            "REFUSE: the attestation's helper_source_sha384 does not match this tree's \
             scripts/gmail_drill_mint.py — the bundle was minted by helper bytes this tree \
             did not review (re-mint with the current committed helper)"
                .to_string(),
        );
    }
    Ok(())
}

// ===============================================================================================
// DrillError — the typed redacting wrapper (design §2/§3). Every reqwest failure, non-2xx,
// JSON failure, assertion mismatch, and TOCTOU output crosses this ONE type before any
// Display/Debug can render — and the type cannot carry dynamic content AT ALL, so a provider id
// or token cannot leak through a failure path by construction.
// ===============================================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DrillStage {
    UrlBuild,
    Send,
    NonSuccess(u16),
    Json,
    Assertion,
    Toctou,
}

/// The wrapper CANNOT carry dynamic content: both fields are a `Copy` stage tag and a `'static`
/// description, so no constructor argument — a reqwest error embedding the request URL, a
/// provider body, an observed label set, a bracket value — can survive into Display/Debug even
/// by later refactor. Redaction by construction, not by discipline.
#[derive(Clone, Copy)]
struct DrillError {
    stage: DrillStage,
    what: &'static str,
}

impl DrillError {
    /// A URL that could not be constructed. The cause (which may embed the input, and therefore a
    /// message id) is discarded, not carried.
    fn url_build(_redacted_cause: &dyn std::fmt::Display) -> Self {
        Self {
            stage: DrillStage::UrlBuild,
            what: "probe URL construction failed (cause redacted)",
        }
    }

    /// A send-stage reqwest failure. reqwest's Display embeds the full request URL — which for
    /// `messages.get` contains the message id — so the cause is discarded, not carried.
    fn send(_redacted_cause: &reqwest::Error) -> Self {
        Self {
            stage: DrillStage::Send,
            what: "probe HTTP send failed (cause redacted)",
        }
    }

    /// A completed non-2xx exchange on a path that required success. The body (provider prose,
    /// ids, echoes) is discarded; only the integer status survives, inside the stage tag.
    fn non_success(status: u16, _redacted_body: &str) -> Self {
        Self {
            stage: DrillStage::NonSuccess(status),
            what: "non-2xx probe response (body redacted)",
        }
    }

    /// A body that could not be read as the expected JSON shape. Content discarded.
    fn json(_redacted_cause: &dyn std::fmt::Display) -> Self {
        Self {
            stage: DrillStage::Json,
            what: "probe response JSON unreadable (content redacted)",
        }
    }

    /// A drill assertion that did not hold. `context` is a static description BY TYPE; the
    /// observed value (which may be an id or a label set) is discarded.
    fn assertion_mismatch(context: &'static str, _redacted_observed: &str) -> Self {
        Self {
            stage: DrillStage::Assertion,
            what: context,
        }
    }

    /// The §4.1 history bracket advanced across an arm. Both bracket values are discarded from
    /// the error; the (non-secret) bracket pair is recorded in the manifest observation instead.
    fn toctou(_redacted_before: &str, _redacted_after: &str) -> Self {
        Self {
            stage: DrillStage::Toctou,
            what: "history bracket advanced across the arm (values redacted)",
        }
    }
}

impl std::fmt::Display for DrillError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "live-drill failure [{:?}]: {}", self.stage, self.what)
    }
}

impl std::fmt::Debug for DrillError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self}")
    }
}

// ===============================================================================================
// GmailProbe — the independent oracle (design §3). GET-only BY API SHAPE: the type exposes three
// route-specific GET methods and nothing else — there is no generic request method and no POST
// method to misuse — and every dispatch is recorded in the request ledger, whose checker is the
// load-bearing fence reviewers and the manifest consume.
// ===============================================================================================

/// The probe's compiled host. Mirrors the SUT's compiled-endpoint discipline: there is no
/// parameter through which a drill could point credentialed probe traffic anywhere else.
const PROBE_HOST: &str = "https://gmail.googleapis.com";

/// The three route SHAPES the probe may ever dispatch (design §1: profile / list / get, nothing
/// else, no other host). Shapes are id-free by construction: the concrete message id never
/// enters the ledger.
const PROBE_ROUTE_ALLOWLIST: [&str; 3] = [
    "users/me/profile",
    "users/me/messages",
    "users/me/messages/{id}",
];

/// One ledger row: method + HOST + path SHAPE + query KEYS (never values — `q` values and ids
/// stay out). The host rides so the census shows where every request went: the compiled Gmail
/// host in the live run, a loopback host under the explicit test constructor.
#[derive(Debug, Clone, PartialEq, Eq)]
struct LedgerEntry {
    method: String,
    host: String,
    path_shape: String,
    query_keys: Vec<String>,
}

/// Is this host a loopback form the hermetic harness may use? (Mirrors
/// `connect_for_test_fixture`'s loopback-only rule.)
fn is_loopback_host(host: &str) -> bool {
    if host == "localhost" {
        return true;
    }
    if let Ok(v4) = host.parse::<std::net::Ipv4Addr>() {
        return v4.is_loopback();
    }
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<std::net::Ipv6Addr>()
        .is_ok_and(|v6| v6.is_loopback())
}

/// The ledger's checker: every recorded request must be a GET, on an allowlisted shape, against the
/// compiled Gmail host or a loopback fixture (the ONLY two hosts a probe can be constructed
/// for). Returns the violating `method host path_shape` strings (id-free) — empty means the
/// fence held. The live run additionally pins every host to the compiled Gmail host.
fn ledger_violations(entries: &[LedgerEntry]) -> Vec<String> {
    // EXACT method + EXACT shape: a prefix rule would admit `users/me/watch`, `users/me/stop`,
    // and `users/me/messages/{id}/modify` — the precise POST-under-readonly routes §1 names as
    // why the credential alone is not the fence.
    entries
        .iter()
        .filter(|e| {
            e.method != "GET"
                || !PROBE_ROUTE_ALLOWLIST.contains(&e.path_shape.as_str())
                || (e.host != "gmail.googleapis.com" && !is_loopback_host(&e.host))
        })
        .map(|e| format!("{} {} {}", e.method, e.host, e.path_shape))
        .collect()
}

/// The typed route surface — the ONLY way the probe can dispatch (a
/// url+shape-parameter dispatch was the generic escape hatch design §3 forbids, and it let the
/// ledger record a caller CLAIM while the socket did something else). The URL is CONSTRUCTED
/// here from the probe's base and the ledger row is DERIVED from that constructed URL — there
/// is no parameter through which the two can disagree.
enum ProbeRoute<'a> {
    Profile,
    MessagesList {
        query: &'a str,
        page_token: Option<&'a str>,
    },
    MessageGetMinimal {
        id: &'a str,
    },
}

impl ProbeRoute<'_> {
    fn build_url(&self, base: &reqwest::Url) -> Result<reqwest::Url, DrillError> {
        let mut url = base.clone();
        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| DrillError::url_build(&"cannot-be-a-base probe URL"))?;
            segments.clear().extend(["gmail", "v1", "users", "me"]);
            match self {
                ProbeRoute::Profile => {
                    segments.extend(["profile"]);
                }
                ProbeRoute::MessagesList { .. } => {
                    segments.extend(["messages"]);
                }
                ProbeRoute::MessageGetMinimal { id } => {
                    segments.extend(["messages", id]);
                }
            }
        }
        url.set_fragment(None);
        match self {
            ProbeRoute::Profile => url.set_query(Some("fields=historyId")),
            ProbeRoute::MessagesList { query, page_token } => {
                url.set_query(None);
                {
                    let mut pairs = url.query_pairs_mut();
                    pairs
                        .append_pair("q", query)
                        .append_pair("includeSpamTrash", "true")
                        .append_pair("maxResults", "25")
                        .append_pair("fields", "messages/id,nextPageToken");
                    if let Some(token) = page_token {
                        pairs.append_pair("pageToken", token);
                    }
                }
            }
            // The EXACT SUT query shape (design §4.2's named non-independent dimension).
            ProbeRoute::MessageGetMinimal { .. } => {
                url.set_query(Some("format=minimal&fields=id,labelIds"))
            }
        }
        Ok(url)
    }
}

/// Derive the ledger row from the URL ACTUALLY being dispatched — never from caller input. The
/// message-id segment is masked to `{id}` so the ledger stays id-free by construction.
fn ledger_entry_for(method: &str, url: &reqwest::Url) -> LedgerEntry {
    let segments: Vec<String> = url
        .path_segments()
        .map(|s| s.filter(|p| !p.is_empty()).map(String::from).collect())
        .unwrap_or_default();
    let api: &[String] = if segments.len() >= 2 && segments[0] == "gmail" && segments[1] == "v1" {
        &segments[2..]
    } else {
        &segments[..]
    };
    let path_shape = if api.len() == 4
        && api[0] == "users"
        && api[1] == "me"
        && api[2] == "messages"
    {
        "users/me/messages/{id}".to_string()
    } else {
        api.join("/")
    };
    LedgerEntry {
        method: method.to_string(),
        host: url.host_str().unwrap_or("<no-host>").to_string(),
        path_shape,
        query_keys: url.query_pairs().map(|(k, _)| k.into_owned()).collect(),
    }
}

/// A single search page: the ids Gmail listed and the continuation token, if any.
struct ListPage {
    ids: Vec<String>,
    next_page_token: Option<String>,
}

/// The independent probe client. Blocking reqwest (already the workspace transport family),
/// `.no_proxy()` for the same reason as the SUT: never route a credentialed request through an
/// ambient proxy. GET-only by API shape: the only dispatch takes a typed [`ProbeRoute`].
struct GmailProbe {
    http: reqwest::blocking::Client,
    token: String,
    /// The base every route is constructed against: the COMPILED Gmail host under
    /// [`GmailProbe::new`]; a validated loopback origin only under the explicit
    /// [`GmailProbe::loopback_for_test`] constructor.
    base: reqwest::Url,
    ledger: RefCell<Vec<LedgerEntry>>,
}

impl GmailProbe {
    fn client() -> reqwest::blocking::Client {
        reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .connect_timeout(std::time::Duration::from_secs(10))
            .no_proxy()
            // A probe GET follows NOTHING (same class as the mint helper's
            // urllib finding — closed wholesale): reqwest's default policy re-sends the
            // request, bearer included, to a provider-chosen Location. Mirror of the
            // production transport's `Policy::none()` rationale; any 3xx arrives here as a
            // completed TERMINAL response.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("build no-proxy probe client")
    }

    /// The production constructor: base = the COMPILED host. No parameter exists through which
    /// credentialed probe traffic could be pointed anywhere else.
    fn new(token: &str) -> Self {
        Self {
            http: Self::client(),
            token: token.to_string(),
            base: reqwest::Url::parse(PROBE_HOST).expect("compiled probe host parses"),
            ledger: RefCell::new(Vec::new()),
        }
    }

    /// The ONLY way to aim the probe off the compiled host — loopback-only, validated here,
    /// and visible in the ledger (every row records the host). Mirrors
    /// `connect_for_test_fixture`'s pattern: it exists for hermetic tests and can never name a
    /// real provider.
    fn loopback_for_test(origin: &str, token: &str) -> Self {
        let base = reqwest::Url::parse(origin).expect("loopback origin parses");
        assert!(
            base.host_str().is_some_and(is_loopback_host),
            "loopback_for_test refuses non-loopback origins"
        );
        Self {
            http: Self::client(),
            token: token.to_string(),
            base,
            ledger: RefCell::new(Vec::new()),
        }
    }

    fn ledger_snapshot(&self) -> Vec<LedgerEntry> {
        self.ledger.borrow().clone()
    }

    /// The ONE dispatch tail — takes a TYPED route, constructs the URL from the probe's base,
    /// and derives the ledger row from that constructed URL (the row can no
    /// longer be a caller claim). Records BEFORE sending (a refused/failed send still counts as
    /// an attempted request) and returns the completed exchange without judging the status —
    /// capture-first callers need the raw non-2xx body.
    fn dispatch(&self, route: &ProbeRoute<'_>) -> Result<(u16, String), DrillError> {
        let url = route.build_url(&self.base)?;
        self.ledger.borrow_mut().push(ledger_entry_for("GET", &url));
        let response = self
            .http
            .get(url.as_str())
            .bearer_auth(&self.token)
            .send()
            .map_err(|e| DrillError::send(&e))?;
        let status = response.status().as_u16();
        let body = response.text().map_err(|e| DrillError::send(&e))?;
        Ok((status, body))
    }

    /// `users.getProfile?fields=historyId` — the §4.1 bracket source. Returns the historyId.
    fn get_profile_history_id(&self) -> Result<String, DrillError> {
        let (status, body) = self.dispatch(&ProbeRoute::Profile)?;
        if !(200..300).contains(&status) {
            return Err(DrillError::non_success(status, &body));
        }
        parse_profile_history_id(&body)
    }

    /// `users.messages.list` — discovery ONLY (design §4.1). `includeSpamTrash=true` on EVERY
    /// list call (the route builder hard-codes it) so the trash/spam arms find their candidates.
    fn list_messages(&self, query: &str, page_token: Option<&str>) -> Result<ListPage, DrillError> {
        let (status, body) = self.dispatch(&ProbeRoute::MessagesList { query, page_token })?;
        if !(200..300).contains(&status) {
            return Err(DrillError::non_success(status, &body));
        }
        parse_list_page(&body)
    }

    /// The raw `users.messages.get?format=minimal&fields=id,labelIds` exchange — the EXACT SUT
    /// query shape (design §4.2's named non-independent dimension: R2's observation is about this
    /// shape's encoding, so the shape must match by construction). Capture-first: returns the
    /// status and raw body without judging them, so R3 can record a denial envelope.
    fn get_raw_minimal(&self, id: &str) -> Result<(u16, String), DrillError> {
        self.dispatch(&ProbeRoute::MessageGetMinimal { id })
    }

    /// A checked minimal read: 2xx + the probe's OWN parse (independent oracle — the SUT's
    /// deserializer is never consulted). `Ok(None)` = `labelIds` OMITTED on the wire;
    /// `Ok(Some(labels))` = present, possibly empty.
    fn get_message_labels(&self, id: &str) -> Result<Option<Vec<String>>, DrillError> {
        let (status, body) = self.get_raw_minimal(id)?;
        if !(200..300).contains(&status) {
            return Err(DrillError::non_success(status, &body));
        }
        probe_parse_minimal(&body, id)
    }
}

/// The profile's `historyId`, VALIDATED: the Discovery contract is a uint64
/// encoded as a decimal string, and the bracket evidence (§4.1 — equal before/after an arm)
/// is only evidence if the value is a real historyId: two identical MALFORMED values (empty,
/// non-decimal) would satisfy the equality and record as valid closure evidence. Parse-validate
/// as u64; keep the string form (the bracket compares strings byte-for-byte).
fn parse_profile_history_id(body: &str) -> Result<String, DrillError> {
    let v: serde_json::Value = serde_json::from_str(body).map_err(|e| DrillError::json(&e))?;
    v.get("historyId")
        .and_then(|h| h.as_str())
        .filter(|h| h.parse::<u64>().is_ok())
        .map(String::from)
        .ok_or_else(|| {
            DrillError::json(&"profile response carried no decimal-uint64 historyId")
        })
}

/// The probe's list-page parser — FAIL-CLOSED: a non-array `messages` member,
/// an entry with a missing/non-string id, or a mistyped `nextPageToken` is a typed FAILURE of
/// the oracle, never an empty page — an empty page upstream becomes SearchExhausted, and "the
/// mailbox has no such message" must never be manufactured out of bytes we could not read.
/// An ABSENT `messages` member remains a legitimate empty page (Gmail omits it when the
/// listing is empty).
fn parse_list_page(body: &str) -> Result<ListPage, DrillError> {
    let v: serde_json::Value = serde_json::from_str(body).map_err(|e| DrillError::json(&e))?;
    // A non-object body ([]/null/scalar) must fail closed too — `Value::get`
    // answers None for every key on those, which read as a legitimate empty page.
    if !v.is_object() {
        return Err(DrillError::json(&"list response is not a JSON object"));
    }
    let ids: Vec<String> = match v.get("messages") {
        None => Vec::new(),
        Some(serde_json::Value::Array(list)) => list
            .iter()
            .map(|m| {
                m.get("id")
                    .and_then(|i| i.as_str())
                    // Degenerate-value family: an EMPTY id is not an
                    // id — it would build a malformed message-get route downstream.
                    .filter(|i| !i.is_empty())
                    .map(String::from)
                    .ok_or_else(|| {
                        DrillError::json(&"list entry without a non-empty string id")
                    })
            })
            .collect::<Result<_, _>>()?,
        Some(_) => return Err(DrillError::json(&"messages member is not an array")),
    };
    let next_page_token = match v.get("nextPageToken") {
        None => None,
        // Degenerate-value family: a present-but-empty token is
        // malformed — feeding it back as a page cursor is not a real continuation.
        Some(serde_json::Value::String(token)) if !token.is_empty() => Some(token.clone()),
        Some(serde_json::Value::String(_)) => {
            return Err(DrillError::json(&"nextPageToken is present but empty"))
        }
        Some(_) => return Err(DrillError::json(&"nextPageToken is not a string")),
    };
    Ok(ListPage {
        ids,
        next_page_token,
    })
}

/// The probe's own minimal-message parser: id-echo checked (a response for a different message
/// must never classify an arm), `labelIds` kept as Omitted-vs-Present. Independent of the SUT's
/// serde types on purpose.
fn probe_parse_minimal(body: &str, expected_id: &str) -> Result<Option<Vec<String>>, DrillError> {
    let v: serde_json::Value = serde_json::from_str(body).map_err(|e| DrillError::json(&e))?;
    let id = v
        .get("id")
        .and_then(|i| i.as_str())
        .ok_or_else(|| DrillError::json(&"minimal message carried no id"))?;
    if id != expected_id {
        return Err(DrillError::assertion_mismatch(
            "probe id-echo mismatch: response is for a different message",
            id,
        ));
    }
    match v.get("labelIds") {
        None => Ok(None),
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .map(|l| {
                l.as_str()
                    .map(String::from)
                    .ok_or_else(|| DrillError::json(&"non-string labelIds member"))
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Some),
        Some(_) => Err(DrillError::json(&"labelIds is not an array")),
    }
}

/// The probe's independent classification of a label set — the §4.1 table, implemented from the
/// design's rows rather than from the SUT's code (the table itself is the named non-independent
/// dimension: both sides implement the same published contract).
///
/// **The table was widened.** TRASH and SPAM moved IN model (`Placement::{Trash,Spam}` widened
/// with writer and consumer; derivation maps TRASH⇒Trash, SPAM⇒Spam; TRASH/SPAM leave the
/// out-of-model list when Placement widens, DRAFT stays). So DRAFT is the ONE out-of-model label (with anything);
/// otherwise TRASH, then SPAM, then INBOX, else Archive. TRASH-over-SPAM, and either over INBOX,
/// is a NAMED DERIVATION CHOICE of ours (§4.4), not a provider claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeVerdict {
    Inbox,
    Archive,
    Trash,
    Spam,
    OutOfModel,
}

fn classify_probe_labels(labels: &[String]) -> ProbeVerdict {
    let has = |label: &str| labels.iter().any(|l| l == label);
    if has("DRAFT") {
        ProbeVerdict::OutOfModel
    } else if has("TRASH") {
        ProbeVerdict::Trash
    } else if has("SPAM") {
        ProbeVerdict::Spam
    } else if has("INBOX") {
        ProbeVerdict::Inbox
    } else {
        ProbeVerdict::Archive
    }
}

// ===============================================================================================
// Bounded pagination with the quad-state outcome (design §3)
// ===============================================================================================

/// How many pages a search may follow before giving up. Bounded so an unexpected mailbox shape
/// can never turn discovery into an unbounded crawl.
const SEARCH_PAGE_BOUND: usize = 8;

/// The quad-state search result. `SearchExhausted` is the ONLY state that may become
/// `UNAVAILABLE` for an arm (design §4.1); a bound hit or a failed request is a FAILURE, because
/// "we stopped looking" must never be reported as "the mailbox has no such message".
#[derive(Debug, PartialEq, Eq)]
enum SearchOutcome {
    Found(String),
    SearchExhausted,
    BoundReached,
    RequestFailed,
}

/// Follow `nextPageToken` through `fetch_page` until a first id is found, the listing is
/// exhausted, the bound trips, or a request fails.
fn bounded_search<F>(mut fetch_page: F) -> SearchOutcome
where
    F: FnMut(Option<&str>) -> Result<ListPage, DrillError>,
{
    let mut token: Option<String> = None;
    for _ in 0..SEARCH_PAGE_BOUND {
        let page = match fetch_page(token.as_deref()) {
            Ok(page) => page,
            Err(_) => return SearchOutcome::RequestFailed,
        };
        if let Some(id) = page.ids.into_iter().next() {
            return SearchOutcome::Found(id);
        }
        match page.next_page_token {
            Some(next) => token = Some(next),
            None => return SearchOutcome::SearchExhausted,
        }
    }
    SearchOutcome::BoundReached
}

// ===============================================================================================
// The sanitizer (design §4.4): value+casing fidelity for every verdict-bearing field,
// absence for everything sensitive. This is the projection the manifest records digests of.
// ===============================================================================================

#[derive(Debug, PartialEq, Eq, serde::Serialize)]
struct SanitizedLegacyItem {
    domain: Option<String>,
    reason: Option<String>,
}

#[derive(Debug, PartialEq, Eq, serde::Serialize)]
struct SanitizedDetail {
    type_url: Option<String>,
    /// Populated only for `google.rpc.ErrorInfo` members — the one detail type whose `reason`
    /// is verdict-bearing (§4.3's enumeration).
    reason: Option<String>,
    /// `ErrorInfo.domain` — a SERVICE namespace (AIP-193), non-secret and evidence-bearing
    /// alongside the reason: the recorded envelope must let an auditor see which
    /// service domain the denial arrived under, value and casing intact. ErrorInfo members
    /// only, like `reason`.
    domain: Option<String>,
}

/// The recorded projection of one error envelope: §4.3.1's enumeration and NOTHING else — status,
/// `error.code`, every `errors[].reason`/`domain`, `error.status`, every `details[]` `@type` and
/// `ErrorInfo.reason`. No `message`, no ids, no metadata, no prose.
#[derive(Debug, PartialEq, Eq, serde::Serialize)]
struct SanitizedEnvelope {
    status: u16,
    error_code: Option<i64>,
    legacy_errors: Vec<SanitizedLegacyItem>,
    error_status: Option<String>,
    details: Vec<SanitizedDetail>,
}

/// Project a raw error body into the sanitized envelope. Extraction is read-only over a
/// `serde_json::Value` — this is EVIDENCE recording, not classification; classification runs the
/// SUT's own strict parser (`map_error_response`), which is where duplicate-member rejection
/// lives.
fn sanitize_envelope(status: u16, body: &str) -> SanitizedEnvelope {
    // IDENTITY projection of every verdict-bearing value — byte-for-byte VALUE AND
    // CASING fidelity, because casing IS the R3_ERRORINFO_CASING evidence (error.rs:892) and a
    // normalizing sanitizer silently destroys the thing being recorded.
    let normalize = |s: &str| s.to_string();

    let v: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => {
            return SanitizedEnvelope {
                status,
                error_code: None,
                legacy_errors: Vec::new(),
                error_status: None,
                details: Vec::new(),
            }
        }
    };
    let error = &v["error"];
    let legacy_errors = error
        .get("errors")
        .and_then(|e| e.as_array())
        .map(|items| {
            items
                .iter()
                .map(|item| SanitizedLegacyItem {
                    domain: item.get("domain").and_then(|d| d.as_str()).map(normalize),
                    reason: item.get("reason").and_then(|r| r.as_str()).map(normalize),
                })
                .collect()
        })
        .unwrap_or_default();
    let details = error
        .get("details")
        .and_then(|d| d.as_array())
        .map(|items| {
            items
                .iter()
                .map(|item| {
                    let type_url = item.get("@type").and_then(|t| t.as_str()).map(normalize);
                    // EXACT case-sensitive suffix — the SAME predicate as production
                    // `ErrorDetail::is_error_info` (a case-insensitive match
                    // here recorded reason/domain from details the SUT treats as unknown,
                    // widening the sensitive-field projection; two readers, one predicate).
                    let is_error_info = type_url
                        .as_deref()
                        .is_some_and(|t| t.ends_with("google.rpc.ErrorInfo"));
                    SanitizedDetail {
                        reason: if is_error_info {
                            item.get("reason").and_then(|r| r.as_str()).map(normalize)
                        } else {
                            None
                        },
                        domain: if is_error_info {
                            item.get("domain").and_then(|d| d.as_str()).map(normalize)
                        } else {
                            None
                        },
                        type_url,
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    SanitizedEnvelope {
        status,
        error_code: error.get("code").and_then(|c| c.as_i64()),
        legacy_errors,
        error_status: error.get("status").and_then(|s| s.as_str()).map(normalize),
        details,
    }
}

/// The WIRE-SHAPED reconstruction of a sanitized envelope: the same `{"error":{...}}` grammar
/// `map_error_response` parses, carrying exactly the sanitized fields and nothing else — PLUS
/// the transport status as a root-level `"status"` member beside `"error"`: the digest must cover (status, body), because two identical JSON bodies under
/// a 403 and a 404 are DIFFERENT evidence. The added root member is inert to classification by
/// the parser's own contract (error.rs: unknown members are ignored on purpose; only
/// verdict-bearing members are typed, and those all live INSIDE `error`), so the recorded bytes
/// remain directly replayable through `map_error_response`. This is what makes the
/// recorded-taxonomy claim REPLAYABLE: the recorded verdict is computed over
/// these bytes, and anyone holding the recorded capture can recompute it.
fn banked_envelope_wire(sanitized: &SanitizedEnvelope) -> serde_json::Value {
    let mut error = serde_json::Map::new();
    if let Some(code) = sanitized.error_code {
        error.insert("code".to_string(), serde_json::json!(code));
    }
    if !sanitized.legacy_errors.is_empty() {
        let items: Vec<serde_json::Value> = sanitized
            .legacy_errors
            .iter()
            .map(|item| {
                let mut m = serde_json::Map::new();
                if let Some(domain) = &item.domain {
                    m.insert("domain".to_string(), serde_json::json!(domain));
                }
                if let Some(reason) = &item.reason {
                    m.insert("reason".to_string(), serde_json::json!(reason));
                }
                serde_json::Value::Object(m)
            })
            .collect();
        error.insert("errors".to_string(), serde_json::Value::Array(items));
    }
    if let Some(status) = &sanitized.error_status {
        error.insert("status".to_string(), serde_json::json!(status));
    }
    if !sanitized.details.is_empty() {
        let items: Vec<serde_json::Value> = sanitized
            .details
            .iter()
            .map(|detail| {
                let mut m = serde_json::Map::new();
                if let Some(type_url) = &detail.type_url {
                    m.insert("@type".to_string(), serde_json::json!(type_url));
                }
                if let Some(reason) = &detail.reason {
                    m.insert("reason".to_string(), serde_json::json!(reason));
                }
                if let Some(domain) = &detail.domain {
                    m.insert("domain".to_string(), serde_json::json!(domain));
                }
                serde_json::Value::Object(m)
            })
            .collect();
        error.insert("details".to_string(), serde_json::Value::Array(items));
    }
    // Root-level, NOT inside `error`: `error.status` is Google's canonical-code string (a
    // typed, verdict-bearing member); this is the TRANSPORT status integer, placed where the
    // classifier's parser ignores it and an auditor can read it back.
    serde_json::json!({ "error": error, "status": sanitized.status })
}

/// THE canonical recorded serialization — the ONE byte stream behind the recorded file, its sha384
/// digest, the recorded taxonomy, and every corpus replay recompute (pretty
/// recording vs compact replay produced two digests no auditor could reconcile). Compact
/// `serde_json` with its default sorted object keys: deterministic bytes.
fn canonical_banked_bytes(sanitized: &SanitizedEnvelope) -> String {
    serde_json::to_string(&banked_envelope_wire(sanitized)).expect("wire projection serializes")
}

// ===============================================================================================
// ProofId accounting (design §4.0) — decision-keyed, the mandatory set immutable at runtime
// because it lives in these reviewed bytes and compiled code.
// ===============================================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProofId {
    R1Inbox,
    R1Archive,
    R1Trash,
    R1Spam,
    R1Draft,
    A2EncodingObserved,
    R3Scope403,
    R3ErrorInfoCasing,
}

impl ProofId {
    fn name(self) -> &'static str {
        match self {
            ProofId::R1Inbox => "R1_INBOX",
            ProofId::R1Archive => "R1_ARCHIVE",
            ProofId::R1Trash => "R1_TRASH",
            ProofId::R1Spam => "R1_SPAM",
            ProofId::R1Draft => "R1_DRAFT",
            ProofId::A2EncodingObserved => "A2_ENCODING_OBSERVED",
            ProofId::R3Scope403 => "R3_SCOPE_403",
            ProofId::R3ErrorInfoCasing => "R3_ERRORINFO_CASING",
        }
    }
}

/// The IMMUTABLE mandatory set (design §4.0). The manifest reports this; it can never redefine
/// it. Changing it is a reviewed design amendment committed BEFORE the run.
///
/// TWO obligations are CONDITIONAL — provable only when the wire state they observe exists:
/// - `R3_ERRORINFO_CASING`: closes only if an `ErrorInfo`
///   entry is actually observed; a legacy-only body leaves it `UNAVAILABLE`.
/// - `A2_ENCODING_OBSERVED` (**added on live evidence** — the same
///   pattern applied to a second obligation, not a new mechanism; design §4.2 carries the
///   measurement and §4.0 the provenance): an empty `labelIds` set is not reachable for
///   RECEIVED mail in Gmail through normal delivery or any operator-available UI operation, so
///   with no zero-label candidate on the wire it reports `UNAVAILABLE(...)` and the flip
///   stays unlicensed — the same practical outcome as the already-accepted
///   `InconclusiveNoFlipLicensed` inference, reached by a different route.
///
/// Conditional ≠ optional: a conditional obligation that is REACHABLE and FAILS still blocks
/// closure ([`ProofMatrix::closure_verdict`]).
const MANDATORY_PROOFS: [ProofId; 6] = [
    ProofId::R1Inbox,
    ProofId::R1Archive,
    ProofId::R1Trash,
    ProofId::R1Spam,
    ProofId::R1Draft,
    ProofId::R3Scope403,
];

/// Per-obligation outcome. `Unavailable` reasons are static strings by type, so the matrix
/// rendering is redacted by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProofOutcome {
    Proved,
    Failed,
    Unavailable(&'static str),
}

/// A2's extra fields (design §4.2): both observations are closure-satisfying; the INFERENCE is
/// what differs, and `Present` licenses NO flip.
/// The STRONG `UNAVAILABLE` reason — earned ONLY when the provider itself ended the listing
/// (design §4.2).
const A2_NO_ZERO_LABEL_REASON: &str = "no zero-label message reachable";

/// The WEAK, honest `UNAVAILABLE` reason for a search stopped by OUR bound rather than by the
/// provider. It asserts nothing about unreachability.
const A2_BOUND_REACHED_REASON: &str =
    "search bound reached before exhaustion; no zero-label candidate in the first N results";

/// How many candidate ids the A2 scan collects before stopping — OUR bound, not the provider's.
const A2_CANDIDATE_CAP: usize = 25;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EncodingObservation {
    Omitted,
    Present,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Inference {
    ClosedNoChange,
    InconclusiveNoFlipLicensed,
}

#[derive(Debug, Default)]
struct ProofMatrix {
    outcomes: Vec<(ProofId, ProofOutcome)>,
    /// The capture link behind every PROVED entry (design §0):
    /// `(proof, capture name, sha384 of the recorded ID-free projection)`. PROVED
    /// without a row here is unmanifestable — [`build_manifest`] refuses it.
    proved_captures: Vec<(ProofId, String, String)>,
    a2_observation: Option<EncodingObservation>,
    a2_inference: Option<Inference>,
}

impl ProofMatrix {
    /// Record a NON-proved outcome. PROVED must go through [`ProofMatrix::record_proved`] with
    /// its recorded capture — recording it here panics, so the capture obligation cannot be
    /// bypassed by picking the other method.
    fn record(&mut self, id: ProofId, outcome: ProofOutcome) {
        assert!(
            outcome != ProofOutcome::Proved,
            "PROVED must be recorded via record_proved with its banked capture digest"
        );
        self.outcomes.push((id, outcome));
    }

    /// Record PROVED together with the recorded capture that proves it existed on the wire.
    fn record_proved(&mut self, id: ProofId, capture_name: &str, capture_sha384: &str) {
        self.outcomes.push((id, ProofOutcome::Proved));
        self.proved_captures
            .push((id, capture_name.to_string(), capture_sha384.to_string()));
    }

    fn capture_of(&self, id: ProofId) -> Option<(&str, &str)> {
        self.proved_captures
            .iter()
            .find(|(recorded, _, _)| *recorded == id)
            .map(|(_, name, digest)| (name.as_str(), digest.as_str()))
    }

    /// PROVED entries lacking a capture link — must be empty for a manifest to build.
    fn proved_capture_gaps(&self) -> Vec<&'static str> {
        self.outcomes
            .iter()
            .filter(|(id, outcome)| {
                *outcome == ProofOutcome::Proved && self.capture_of(*id).is_none()
            })
            .map(|(id, _)| id.name())
            .collect()
    }

    fn outcome_of(&self, id: ProofId) -> Option<ProofOutcome> {
        self.outcomes
            .iter()
            .find(|(recorded, _)| *recorded == id)
            .map(|(_, outcome)| *outcome)
    }

    /// Redacted-by-construction rendering: ProofId names + outcomes (+ the A2 fields), nothing
    /// else can appear because nothing else is stored.
    fn render(&self) -> String {
        let mut out = String::new();
        for id in [
            ProofId::R1Inbox,
            ProofId::R1Archive,
            ProofId::R1Trash,
            ProofId::R1Spam,
            ProofId::R1Draft,
            ProofId::A2EncodingObserved,
            ProofId::R3Scope403,
            ProofId::R3ErrorInfoCasing,
        ] {
            let outcome = self
                .outcome_of(id)
                .map_or_else(|| "NOT RUN".to_string(), |o| format!("{o:?}"));
            let _ = writeln!(out, "  {:<22} {}", id.name(), outcome);
        }
        let _ = writeln!(
            out,
            "  A2 observation={:?} inference={:?}",
            self.a2_observation, self.a2_inference
        );
        out
    }

    /// Closure gate (design §4.0), TWO rules:
    ///
    /// 1. Every MANDATORY ProofId must be `PROVED`. A missing entry is as fatal as a failed one
    ///    — "the drill never ran" must not close.
    /// 2. **No obligation may be `FAILED` — including a CONDITIONAL one.** Conditional ≠
    ///    optional: `UNAVAILABLE` says the wire state this obligation observes did not exist,
    ///    which is an honest non-observation; `FAILED` says it WAS reachable and the assertion
    ///    did not hold, which is a broken claim and must never close a run.
    fn closure_verdict(&self) -> Result<(), String> {
        let unproved: Vec<&str> = MANDATORY_PROOFS
            .iter()
            .filter(|id| self.outcome_of(**id) != Some(ProofOutcome::Proved))
            .map(|id| id.name())
            .collect();
        let failed: Vec<&str> = self
            .outcomes
            .iter()
            .filter(|(_, outcome)| *outcome == ProofOutcome::Failed)
            .map(|(id, _)| id.name())
            .collect();
        if unproved.is_empty() && failed.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "INCOMPLETE: mandatory obligations not PROVED: {unproved:?}; FAILED \
                 obligations (mandatory or conditional): {failed:?}\nProofId matrix:\n{}",
                self.render()
            ))
        }
    }
}

// ===============================================================================================
// Manifest (design §4.5) — provenance-bound, clean-tree-gated in closure mode
// ===============================================================================================

/// The clean-tree predicate over `git status --porcelain` OUTPUT (injected, so it is hermetically
/// testable without mutating the repo): any surviving line — tracked, staged, or untracked —
/// makes the tree dirty and refuses closure.
fn porcelain_is_clean(porcelain: &str) -> bool {
    porcelain.lines().all(|line| line.trim().is_empty())
}

/// The EXACT `git status` invocation the closure gate uses.
///
/// `--untracked-files=all` is load-bearing and must never be dropped: `git status --porcelain`
/// honors `status.showUntrackedFiles=no` from repo OR global config, so on a machine carrying
/// that setting a tree containing untracked files — including a whole untracked source file —
/// prints nothing, passes [`porcelain_is_clean`], and produces a closure manifest CLAIMING a
/// clean tree. The flag overrides the config. `porcelain_args_pin_untracked_files` holds it.
const PORCELAIN_ARGS: [&str; 3] = ["status", "--porcelain", "--untracked-files=all"];

/// What the live path observed about the repo, as INJECTED DATA (exit codes + outputs), so the
/// closure gate below stays hermetically testable (the porcelain OUTPUT alone was
/// trusted — a git invocation that FAILED produced an empty string indistinguishable from clean).
struct RepoState {
    /// `git status --porcelain` exited 0.
    porcelain_exit_ok: bool,
    porcelain: String,
    /// What `git symbolic-ref -q HEAD` ESTABLISHED about HEAD — `None` means the probe itself
    /// could not be trusted. Closure requires a DETACHED worktree at the
    /// recorded SHA (design §4.5).
    head_attachment: Option<HeadAttachment>,
    /// `git rev-parse HEAD` exited 0.
    sha_exit_ok: bool,
    head_sha: String,
    /// `git rev-parse --show-toplevel` exited 0 AND produced a path. A
    /// failure here previously became `None`, which made the evidence-dir worktree-containment
    /// check vanish — a fail-OPEN on the check that keeps evidence out of the repo.
    repo_root: Option<PathBuf>,
}

/// What the HEAD probe established. `git symbolic-ref -q HEAD` speaks in exit codes: 0 = HEAD
/// is a symbolic ref (ON A BRANCH), 1 = it is not (DETACHED). Anything else — a spawn failure,
/// another exit code, a signal — established NOTHING and must not be read as either.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeadAttachment {
    Attached,
    Detached,
}

/// Interpret the HEAD probe's outcome. Previously `is_ok_and(success)`
/// collapsed "the probe FAILED" and "HEAD is genuinely detached" into the same `false`, so a
/// probe failure read as detached and closure could pass without ever establishing detachment —
/// the same fail-open class. `None` here means UNESTABLISHED, and the caller
/// refuses.
fn interpret_head_probe(
    outcome: &std::io::Result<std::process::Output>,
) -> Option<HeadAttachment> {
    match outcome {
        // Exit 0: HEAD names a branch.
        Ok(o) if o.status.success() => Some(HeadAttachment::Attached),
        // Exit 1: `-q` says "not a symbolic ref" — genuinely detached.
        Ok(o) if o.status.code() == Some(1) => Some(HeadAttachment::Detached),
        // Any other exit code, a signal, or a spawn failure: nothing was established.
        _ => None,
    }
}

// ===============================================================================================
// THE CLOSURE FAIL-CLOSED PRINCIPLE (the
// closure gate can be bypassed": a relative evidence path, a Windows canonicalize asymmetry,
// two fail-OPEN paths).
//
// An earlier fix covered path NORMALIZATION but assumed the gate's INPUTS were always obtainable.
// The real class is broader and simpler:
//
//   **In closure mode, any failure to ESTABLISH a fact the gate depends on must REFUSE —
//   never degrade to a permissive value.**
//
// Every `unwrap_or`, `.ok()`, `unwrap_or_default`, `if let Ok`, `.unwrap_or(None)`, or
// **`is_ok_and` / `is_some_and`** that converts a FAILURE into a permissive value on a closure
// path is an instance of the defect. `is_ok_and` counts and a grep for it MISSED it: it
// silently maps BOTH "the command failed" and "the command said no" to the same `false`, which
// is exactly how the HEAD-attachment probe stayed fail-open until (see
// [`interpret_head_probe`]). Add it to any future grep.
// [`establish_or_refuse`] is the one place that decision is made, so the rule is stated once
// and every gate input routes through it.
// ===============================================================================================

/// Establish a fact the closure gate depends on. In CLOSURE a failure is fatal; in SMOKE it
/// degrades loudly to `None` (smoke results are never citable, so a missing fact there is
/// reported, not fatal). Returns `Some` only when the fact was actually established.
fn establish_or_refuse<T>(
    mode: DrillMode,
    what: &str,
    outcome: Result<T, String>,
) -> Option<T> {
    match (mode, outcome) {
        (_, Ok(value)) => Some(value),
        (DrillMode::Closure, Err(reason)) => panic!(
            "closure REFUSED: could not establish {what} — {reason}. A fact the closure gate \
             depends on must never degrade to a permissive value."
        ),
        (DrillMode::Smoke, Err(reason)) => {
            eprintln!(
                "smoke WARNING: could not establish {what} — {reason}. A closure run would \
                 REFUSE here; smoke results are never citable."
            );
            None
        }
    }
}

/// Is this a full 40-hex-lowercase object name?
fn is_full_sha(s: &str) -> bool {
    s.len() == 40 && s.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

/// The closure repo gate: git commands must have SUCCEEDED, the
/// tree must be clean, HEAD must be detached, and the recorded SHA must be a real object name.
fn closure_repo_verdict(state: &RepoState) -> Result<(), String> {
    if !state.porcelain_exit_ok {
        return Err(
            "closure REFUSED: `git status --porcelain` failed — an unverifiable tree is not a \
             clean tree"
                .to_string(),
        );
    }
    if !porcelain_is_clean(&state.porcelain) {
        return Err(
            "closure REFUSED: the worktree is not clean (run from a clean detached worktree at \
             the recorded SHA — design §4.5)"
                .to_string(),
        );
    }
    match state.head_attachment {
        Some(HeadAttachment::Attached) => {
            return Err(
                "closure REFUSED: HEAD is on a branch — closure runs from a DETACHED worktree \
                 at the recorded SHA"
                    .to_string(),
            )
        }
        // Close 1: an unusable probe establishes NOTHING and must never read as
        // "detached" — the fail-open `is_ok_and` shape did exactly that.
        None => {
            return Err(
                "closure REFUSED: HEAD attachment could not be established (the \
                 `git symbolic-ref -q HEAD` probe neither succeeded nor returned the \
                 documented exit code 1)"
                    .to_string(),
            )
        }
        Some(HeadAttachment::Detached) => {}
    }
    if !state.sha_exit_ok || !is_full_sha(&state.head_sha) {
        return Err(
            "closure REFUSED: the recorded SHA is unavailable or not a full object name"
                .to_string(),
        );
    }
    // Repo-root discovery is a GATE INPUT, not an optional nicety — without
    // it the evidence-dir worktree containment check cannot run at all.
    if state.repo_root.is_none() {
        return Err(
            "closure REFUSED: the repository root could not be established, so evidence-dir \
             worktree containment cannot be checked"
                .to_string(),
        );
    }
    Ok(())
}

/// Probe the repository, capturing exit codes AND outputs. Called TWICE per run: once before
/// the drills, once immediately before recording.
fn probe_repo_state() -> RepoState {
    let git = |args: &[&str]| std::process::Command::new("git").args(args).output();
    let porcelain_out = git(&PORCELAIN_ARGS);
    let symbolic_out = git(&["symbolic-ref", "-q", "HEAD"]);
    let sha_out = git(&["rev-parse", "HEAD"]);
    let root_out = git(&["rev-parse", "--show-toplevel"]);
    RepoState {
        porcelain_exit_ok: porcelain_out.as_ref().is_ok_and(|o| o.status.success()),
        porcelain: porcelain_out
            .as_ref()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_else(|_| "GIT-UNAVAILABLE".to_string()),
        // Tri-state, never a collapsing boolean.
        head_attachment: interpret_head_probe(&symbolic_out),
        sha_exit_ok: sha_out.as_ref().is_ok_and(|o| o.status.success()),
        head_sha: sha_out
            .as_ref()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_else(|_| "GIT-UNAVAILABLE".to_string()),
        // Established or NOT — never a permissive default.
        repo_root: root_out
            .ok()
            .filter(|o| o.status.success())
            .map(|o| PathBuf::from(String::from_utf8_lossy(&o.stdout).trim().to_string()))
            .filter(|p| !p.as_os_str().is_empty()),
    }
}

/// The FINAL repository gate, run immediately BEFORE recording. The manifest
/// was previously built from the PRE-RUN state, so a tracked/untracked change or a HEAD move
/// during the operator-attended network run stayed invisible and the manifest went on claiming the
/// old clean tree and SHA — the manifest lying about exactly the property it exists to certify.
///
/// Requires: the full gate passes AGAIN on the post-run state, AND the SHA is unchanged. A
/// mismatch is a hard failure reporting BOTH SHAs — never a silent overwrite of the recorded
/// SHA with the new one.
fn closure_final_repo_verdict(pre: &RepoState, post: &RepoState) -> Result<(), String> {
    closure_repo_verdict(post).map_err(|reason| {
        format!("{reason} (re-checked AFTER the run, immediately before banking)")
    })?;
    if pre.head_sha != post.head_sha {
        return Err(format!(
            "closure REFUSED: HEAD MOVED during the run — the manifest would certify a SHA the \
             run did not execute at. pre-run={} post-run={}",
            pre.head_sha, post.head_sha
        ));
    }
    Ok(())
}

/// Everything the §4.5 manifest binds, gathered by the live path. Grouped as a struct so the
/// emission is one reviewed shape rather than a parameter list.
struct ManifestInputs<'a> {
    mode: DrillMode,
    commit_sha: String,
    porcelain: String,
    /// Did `git status --porcelain` itself SUCCEED? An empty `porcelain` from
    /// a FAILED probe is unverifiable, not clean — closure refuses earlier, but the smoke
    /// manifest must not claim `clean_tree: true` off it.
    porcelain_established: bool,
    invocation: String,
    toolchain: String,
    matrix: &'a ProofMatrix,
    observations: serde_json::Value,
    ledger: &'a [LedgerEntry],
    bundle: &'a AttestationBundle,
    bundle_sha384: String,
    sanitizer_sha384: String,
    capture_digests: Vec<(String, String)>,
    red_controls: serde_json::Value,
    now: i64,
}

/// Build the §4.5 manifest — or REFUSE when a PROVED entry carries no recorded capture digest:
/// an unmanifestable claim is better than an unbacked one.
fn build_manifest(inputs: &ManifestInputs<'_>) -> Result<serde_json::Value, String> {
    let gaps = inputs.matrix.proved_capture_gaps();
    if !gaps.is_empty() {
        return Err(format!(
            "manifest REFUSED: PROVED obligations with no banked capture digest: {gaps:?}"
        ));
    }
    let matrix_json: Vec<serde_json::Value> = inputs
        .matrix
        .outcomes
        .iter()
        .map(|(id, outcome)| {
            let capture = inputs.matrix.capture_of(*id).map(|(name, digest)| {
                serde_json::json!({ "name": name, "sha384": digest })
            });
            serde_json::json!({
                "proof_id": id.name(),
                "outcome": format!("{outcome:?}"),
                "capture": capture,
            })
        })
        .collect();
    let census: Vec<serde_json::Value> = inputs
        .ledger
        .iter()
        .map(|e| {
            serde_json::json!({
                "method": e.method,
                // Host identity IS request-ledger evidence (compiled Gmail host vs
                // loopback) — the recorded census must show where every request went.
                "host": e.host,
                "path_shape": e.path_shape,
                "query_keys": e.query_keys,
            })
        })
        .collect();
    // A token's digest is recorded ONLY when THAT token is already expired at recording time
    // (design §4.5, per-token honesty); otherwise the bundle digest alone
    // carries the binding for that slot.
    let main_expired = inputs.now >= inputs.bundle.expires_at_main;
    let denial_expired = inputs
        .bundle
        .expires_at_denial
        .is_some_and(|expiry| inputs.now >= expiry);
    let attestation = serde_json::json!({
        "bundle_sha384": inputs.bundle_sha384,
        "effective_main_scopes": inputs.bundle.effective_main_scopes,
        "effective_denial_scopes": inputs.bundle.effective_denial_scopes,
        "scope_source_main": inputs.bundle.scope_source_main,
        "scope_source_denial": inputs.bundle.scope_source_denial,
        "same_principal": inputs.bundle.same_principal,
        "minted_at": inputs.bundle.minted_at,
        "expires_at_main": inputs.bundle.expires_at_main,
        "expires_at_denial": inputs.bundle.expires_at_denial,
        "helper_source_sha384": inputs.bundle.helper_source_sha384,
        "main_token_sha384_banked": main_expired,
        "denial_token_sha384_banked": denial_expired,
        "main_token_sha384": main_expired.then(|| inputs.bundle.main_token_sha384.clone()),
        "denial_token_sha384": denial_expired
            .then(|| inputs.bundle.denial_token_sha384.clone())
            .flatten(),
    });
    Ok(serde_json::json!({
        "slice": "issue-21 read-side live proofs",
        "design": "docs/superpowers/specs/2026-07-26-gmail-live-readside-proofs-design.md (v5)",
        "mode": match inputs.mode { DrillMode::Smoke => "smoke", DrillMode::Closure => "closure" },
        "commit_sha": inputs.commit_sha,
        // `clean_tree` requires BOTH a successful status probe AND empty porcelain: an empty string from a FAILED `git status` is unverifiable, never clean.
        "clean_tree": inputs.porcelain_established && porcelain_is_clean(&inputs.porcelain),
        // A CLEAN tree's proof is the verbatim (empty) porcelain — the closure case, where the
        // verdicts have already refused anything dirty. A DIRTY tree (smoke permits it) must
        // NEVER copy porcelain verbatim: worktree FILENAMES ride in it, and a
        // filename can carry a message id, an address, or a token-like value — violating the
        // ID-free guarantee. Count only, paths redacted, in every mode (belt-and-suspenders).
        "clean_tree_proof_porcelain": if !inputs.porcelain_established {
            "<git status UNVERIFIABLE — the porcelain probe failed (smoke; closure refuses \
             this earlier); clean_tree is false by construction (codex r16 P2)>"
                .to_string()
        } else if porcelain_is_clean(&inputs.porcelain) {
            inputs.porcelain.clone()
        } else {
            format!(
                "<dirty: {} entries; paths REDACTED — filenames can carry ids/addresses \
                 (ID-free guarantee, codex r13 P2-2)>",
                inputs.porcelain.lines().count()
            )
        },
        "invocation": inputs.invocation,
        "toolchain": inputs.toolchain,
        "discovery_revision": DISCOVERY_REVISION,
        "mandatory_proof_ids": MANDATORY_PROOFS.iter().map(|p| p.name()).collect::<Vec<_>>(),
        "proof_matrix": matrix_json,
        "a2_observation": inputs.matrix.a2_observation.map(|o| format!("{o:?}")),
        "a2_inference": inputs.matrix.a2_inference.map(|i| format!("{i:?}")),
        "observations": inputs.observations,
        "w3_request_census": census,
        "w3_violations": ledger_violations(inputs.ledger),
        "attestation": attestation,
        "sanitizer": {
            "identity": "sanitize_envelope (crates/aruna-gmail/tests/live_readside.rs)",
            "source_sha384": inputs.sanitizer_sha384,
        },
        "capture_digests": inputs.capture_digests.iter().map(|(name, digest)| {
            serde_json::json!({ "capture": name, "sha384": digest })
        }).collect::<Vec<_>>(),
        "red_controls": inputs.red_controls,
        "banked_at_unix": inputs.now,
    }))
}

// ===============================================================================================
// R1/A2 capture projection: the ID-free recorded form of one minimal-message
// observation, sanitized by the fidelity rules — the message id is dropped entirely, only well-known
// ALL-CAPS system labels are named, and user labels (provider-native `Label_*` ids) are counted,
// never carried.
// ===============================================================================================

#[derive(Debug, PartialEq, Eq, serde::Serialize)]
struct SanitizedMinimalCapture {
    /// `omitted` | `present` — the A2-relevant wire encoding of `labelIds`.
    encoding: &'static str,
    /// Well-known system labels only (exact bytes — they are reserved, locale-independent ids).
    system_labels: Vec<String>,
    /// How many labels were NOT well-known system ids (user labels) — counted, never named.
    other_label_count: usize,
}

// The Gmail SYSTEM-label rule (reserved ALL-CAPS ids named; `Label_<n>` user labels counted, never
// named) is the ENGINE's — `aruna::prestate::{is_system_label, banked_label_split}`, imported above
// (this file used to keep a test-local copy).

fn sanitize_minimal_capture(labels: Option<&[String]>) -> SanitizedMinimalCapture {
    match labels {
        None => SanitizedMinimalCapture {
            encoding: "omitted",
            system_labels: Vec::new(),
            other_label_count: 0,
        },
        Some(list) => SanitizedMinimalCapture {
            encoding: "present",
            system_labels: list
                .iter()
                .filter(|l| is_system_label(l))
                .cloned()
                .collect(),
            other_label_count: list.iter().filter(|l| !is_system_label(l)).count(),
        },
    }
}

// ===============================================================================================
// Hermetic loopback SUT harness — a real HTTP exchange against the PUBLIC read path
// (`connect_for_test_fixture` + `GmailProviderPlacement`), used by the R4 mutants and the A2
// characterization pin. Loopback-only, single canned response, no external network.
// ===============================================================================================

/// Serve exactly one canned HTTP response on a fresh loopback port; returns the origin.
fn serve_once(status: u16, body: String) -> (String, std::thread::JoinHandle<()>) {
    serve_once_with_headers(status, body, String::new())
}

/// [`serve_once`] with extra response headers (each `name: value\r\n`-terminated) — the 302
/// redirect witnesses need a `location` header.
fn serve_once_with_headers(
    status: u16,
    body: String,
    extra_headers: String,
) -> (String, std::thread::JoinHandle<()>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let origin = format!(
        "http://127.0.0.1:{}",
        listener.local_addr().expect("local addr").port()
    );
    let handle = std::thread::spawn(move || {
        use std::io::{Read, Write};
        let (mut stream, _) = listener.accept().expect("accept");
        let mut discard = [0u8; 4096];
        let _ = stream.read(&mut discard); // request head; a GET has no body to wait for
        let response = format!(
            "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\n{extra_headers}connection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).expect("write response");
    });
    (origin, handle)
}

/// A loopback server that FLAGS whether it was ever contacted (bounded ~1.5s poll) — the
/// negative witness for the redirect refusal: the provider-chosen Location target must never
/// see a connection, let alone the bearer.
fn serve_flagging(
    status: u16,
    body: String,
) -> (
    String,
    std::sync::Arc<std::sync::atomic::AtomicBool>,
    std::thread::JoinHandle<()>,
) {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    listener.set_nonblocking(true).expect("nonblocking");
    let origin = format!(
        "http://127.0.0.1:{}",
        listener.local_addr().expect("local addr").port()
    );
    let hit = Arc::new(AtomicBool::new(false));
    let hit_flag = Arc::clone(&hit);
    let handle = std::thread::spawn(move || {
        use std::io::{Read, Write};
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(1500);
        while std::time::Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    hit_flag.store(true, Ordering::SeqCst);
                    let mut discard = [0u8; 4096];
                    let _ = stream.set_nonblocking(false);
                    let _ = stream.read(&mut discard);
                    let response = format!(
                        "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes());
                    return;
                }
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(10)),
            }
        }
    });
    (origin, hit, handle)
}

/// Drive the PUBLIC SUT read path (`GmailProviderPlacement::fetch_placement`) against one canned
/// 200 body for message id `drill-msg`, over a real loopback socket.
fn sut_placement_for_body(body: &str) -> Result<Placement, aruna::ConnectorError> {
    let (origin, handle) = serve_once(200, body.to_string());
    let transport = HttpGmailTransport::connect_for_test_fixture(&origin, "hermetic-test-token")
        .expect("fixture transport");
    let sut = GmailProviderPlacement::new(&transport, GmailUserId("me".to_string()));
    let result = sut.fetch_placement("hermetic", &ProviderMessageId("drill-msg".to_string()));
    handle.join().expect("server thread");
    result
}

// ===============================================================================================
// THE RIPPLE DRILL MATRIX: the drill BODY over the transport seam. Witnessed
// hermetically below against the loopback fixture; driven live by
// `ripple_drill_trash_untrash_spam_unspam_delta_within_declared_closure` once ADR-P010's gate
// can be opened (it cannot at this tree — see that test's gate line).
// ===============================================================================================

/// One direction of THE RIPPLE DRILL MATRIX (bounded): per direction, read the
/// full pre vector, apply the verb through the transport's own route, take the post vector the
/// route answered, judge the delta against the direction's DECLARED closure, record both vectors
/// and the verdict. An unexpected atom FAILS the restores-prior-state claim LOUDLY (v7 §1-§2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    Trash,
    Untrash,
    MarkSpam,
    UnmarkSpam,
}

impl Direction {
    const ALL: [Direction; 4] = [
        Direction::Trash,
        Direction::Untrash,
        Direction::MarkSpam,
        Direction::UnmarkSpam,
    ];

    /// The recorded name — fixed literals, never data.
    fn name(self) -> &'static str {
        match self {
            Direction::Trash => "trash",
            Direction::Untrash => "untrash",
            Direction::MarkSpam => "mark_spam",
            Direction::UnmarkSpam => "unmark_spam",
        }
    }

    /// The neutral verb this direction IS — used only to ask the production connector for the
    /// verb's declared closure ([`ripple_closure`]); the drill itself drives the transport.
    fn action(self, message_ref: &str) -> Action {
        let message_ref = message_ref.to_string();
        match self {
            Direction::Trash => Action::Trash { message_ref },
            Direction::Untrash => Action::Untrash { message_ref },
            Direction::MarkSpam => Action::MarkSpam { message_ref },
            Direction::UnmarkSpam => Action::UnmarkSpam { message_ref },
        }
    }

    /// The direction that restores this one — what the live half drives right after it.
    fn inverse(self) -> Direction {
        match self {
            Direction::Trash => Direction::Untrash,
            Direction::Untrash => Direction::Trash,
            Direction::MarkSpam => Direction::UnmarkSpam,
            Direction::UnmarkSpam => Direction::MarkSpam,
        }
    }
}

/// One driven row of the matrix. `pre` and `post` are the FULL label vectors (v7: "full pre/post
/// `labelIds`"), never a projection; `verdict` is judged over their delta.
///
/// No `Debug` on purpose: `message` is a provider id, and this binary's output is ID-free by
/// construction (module doc) — a row can never be formatted into a panic or a log line whole.
struct RippleRow {
    message: GmailMessageId,
    direction: Direction,
    pre: BTreeSet<String>,
    post: BTreeSet<String>,
    verdict: RippleVerdict,
    /// The vector RE-READ through the read route after this row's verb. Only the live half sets
    /// it, on its restore rows; [`drive_ripple_row`] leaves it `None`.
    readback: Option<BTreeSet<String>>,
}

/// The fixed resolver pair [`ripple_closure`] freezes a basis through: a non-alias user (a
/// frozen basis refuses `me`) and an identity message map. No I/O, no state — it exists only so
/// the drill can ask the PRODUCTION connector for a verb's closure instead of restating it.
struct ClosureProbe;

impl GmailAccountResolver for ClosureProbe {
    fn resolve_user(&self, _photon_account: &str) -> Option<GmailUserId> {
        Some(GmailUserId("ripple-closure-probe@drill.invalid".to_string()))
    }
}

impl GmailMessageRefResolver for ClosureProbe {
    fn resolve_message(
        &self,
        _photon_account: &str,
        message_ref: &str,
    ) -> Result<Option<GmailMessageId>, LogError> {
        Ok(Some(GmailMessageId(message_ref.to_string())))
    }
}

/// The DECLARED closure of one direction, READ FROM PRODUCTION rather than restated: the label
/// ids `GmailConnector::resolve_basis` freezes as `FrozenBasis.touched_atoms` VALUES — the exact
/// set the bus judges a persisted ripple against (`aruna` `effect_witness_row`). Its one
/// authority is `aruna::gmail`'s `touched_atoms` beside `gmail_atom_targets`, which
/// today declare Trash/Untrash ⇒ {TRASH, INBOX} and MarkSpam/UnmarkSpam ⇒ {SPAM, INBOX}. The
/// INBOX half is the declared HYPOTHESIS (design §2). The drill asserts that the observed
/// change stays inside {TRASH|SPAM, INBOX} and (additionally) that the route's
/// INBOX membership equals the declared target ([`declared_inbox_target`], checked per row by
/// [`ripple_row_failures`]); both are unobserved at this pin — the live half has not run.
fn ripple_closure(direction: Direction) -> BTreeSet<String> {
    ripple_basis(direction).touched_atoms.into_values().collect()
}

/// The DECLARED `membership:INBOX` target of one direction, READ FROM PRODUCTION like
/// [`ripple_closure`]: the value `GmailConnector::resolve_basis` freezes as
/// `FrozenBasis.atom_targets["membership:INBOX"]` — the sibling map of `touched_atoms` on the
/// same basis, whose one authority is `aruna::gmail`'s `gmail_atom_targets` (today `false` on all
/// four directions).
fn declared_inbox_target(direction: Direction) -> bool {
    *ripple_basis(direction)
        .atom_targets
        .get("membership:INBOX")
        .expect("every triage verb declares its membership:INBOX target")
}

/// The basis the production connector freezes for one direction — the ONE place
/// [`ripple_closure`] and [`declared_inbox_target`] read it from.
fn ripple_basis(direction: Direction) -> FrozenBasis {
    // `connect` takes no base and makes no network contact, and `resolve_basis` performs no
    // provider I/O — this transport is never called; it is only the connector's type argument.
    let transport = HttpGmailTransport::connect("ripple-closure-probe-token-never-sent")
        .expect("a closed-gate production transport constructs without network");
    let connector = GmailConnector::new(transport, ClosureProbe, ClosureProbe);
    let command = Command::new(
        "ripple-closure-probe",
        "ripple-closure-probe",
        Facet::Mail,
        direction.action("ripple-closure-probe"),
    );
    connector
        .resolve_basis(&command)
        .expect("the production connector freezes a basis for every triage verb")
}

/// THE PER-ROW EVALUATION the live half runs on every driven row, extracted so the hermetic half
/// can feed it fixture rows (the live half cannot run at this tree). Returns the row's failure
/// lines, ID-free (the message ORDINAL, never its id); empty = the row passed. The live half
/// collects them and asserts them all at its end, after the restores and the record — the drill's
/// capture-first order.
///
/// - an atom outside the declared closure moved ⇒ one line naming it (v7 §1-§2);
/// - the route's post-vector INBOX membership differs from the direction's
///   DECLARED `membership:INBOX` target ([`declared_inbox_target`]) ⇒ one line. The closure
///   verdict alone cannot see this: INBOX is IN every triage closure, so an untrash that put
///   INBOX back judged `WithinClosure` while falsifying the declared target.
fn ripple_row_failures(ordinal: usize, row: &RippleRow) -> Vec<String> {
    let mut failures = Vec::new();
    if let RippleVerdict::OutsideClosure { unexpected } = &row.verdict {
        failures.push(format!(
            "message #{ordinal} {}: a delta outside the declared closure — {}",
            row.direction.name(),
            bank_label_set(unexpected)
        ));
    }
    let direction = row.direction;
    let declared_inbox = declared_inbox_target(direction);
    let observed_inbox = row.post.contains(&LabelId::inbox().0);
    if observed_inbox != declared_inbox {
        failures.push(format!(
            "message #{ordinal} {}: the declared INBOX direction for {direction:?} \
             (membership:INBOX → {declared_inbox}) is falsified by the live route — its answer \
             has INBOX {}",
            direction.name(),
            if observed_inbox { "present" } else { "absent" }
        ));
    }
    failures
}

/// Drive ONE row of the matrix over the transport seam: `pre` = the read route
/// (`message_labels`), then the verb through ITS route (`trash_message` / `untrash_message` /
/// `modify_labels_observed` adding or removing `SPAM` — the body the connector builds for
/// MarkSpam/UnmarkSpam), `post` = what that route ANSWERED (never a re-read), and the verdict
/// over the delta against [`ripple_closure`]. Any route refusal — an id echo for another
/// message included — is an `Err` and produces NO row; a refused pre-read sends no write.
fn drive_ripple_row<T: GmailTransport>(
    t: &T,
    user: &GmailUserId,
    message: &GmailMessageId,
    direction: Direction,
) -> Result<RippleRow, GmailError> {
    let pre = t.message_labels(user, message)?;
    let spam = LabelId::spam().0;
    let post = match direction {
        Direction::Trash => t.trash_message(user, message)?,
        Direction::Untrash => t.untrash_message(user, message)?,
        Direction::MarkSpam => t.modify_labels_observed(
            user,
            message,
            &GmailModifyRequest::for_test_add(&[spam.as_str()]),
        )?,
        Direction::UnmarkSpam => t.modify_labels_observed(
            user,
            message,
            &GmailModifyRequest::for_test_remove(&[spam.as_str()]),
        )?,
    };
    let verdict = ripple_verdict(&pre, &post, &ripple_closure(direction));
    Ok(RippleRow {
        message: message.clone(),
        direction,
        pre,
        post,
        verdict,
        readback: None,
    })
}

/// One label set in its recorded form — [`sanitize_minimal_capture`]'s rules, reused: well-known
/// system labels named, user labels COUNTED and never named. Its `encoding` member is not
/// recorded: the transport projects an omitted `labelIds` and an empty one to the same `∅`, so the
/// wire encoding is not knowable here and is not claimed.
fn bank_label_set(labels: &BTreeSet<String>) -> serde_json::Value {
    let (system_labels, other_label_count) = banked_label_split(labels);
    serde_json::json!({
        "system_labels": system_labels,
        "other_label_count": other_label_count,
    })
}

/// Bank the matrix's rows, ID-FREE: the provider message id is DROPPED and replaced by a
/// `message_ordinal` (first appearance in `rows`), and every label set — pre, post, readback,
/// the verdict's unexpected set — goes through [`bank_label_set`]. The closure is recorded beside
/// each row so a reader can re-judge the delta without this file.
fn bank_ripple_rows(rows: &[RippleRow]) -> serde_json::Value {
    let mut seen: Vec<&GmailMessageId> = Vec::new();
    let banked: Vec<serde_json::Value> = rows
        .iter()
        .enumerate()
        .map(|(index, row)| {
            let message_ordinal = match seen.iter().position(|m| *m == &row.message) {
                Some(ordinal) => ordinal,
                None => {
                    seen.push(&row.message);
                    seen.len() - 1
                }
            };
            let unexpected = match &row.verdict {
                RippleVerdict::WithinClosure => serde_json::Value::Null,
                RippleVerdict::OutsideClosure { unexpected } => bank_label_set(unexpected),
            };
            serde_json::json!({
                "row": index,
                "message_ordinal": message_ordinal,
                "direction": row.direction.name(),
                "closure": bank_label_set(&ripple_closure(row.direction)),
                "pre": bank_label_set(&row.pre),
                "post": bank_label_set(&row.post),
                "verdict": row.verdict.as_token(),
                "unexpected": unexpected,
                "readback": row.readback.as_ref().map(bank_label_set),
            })
        })
        .collect();
    serde_json::json!({
        "schema": "photon-s1-ripple-rows/1",
        "sanitizer": RIPPLE_ROWS_SANITIZER,
        "rows": banked,
    })
}

/// The recorded identity of the ripple rows' sanitizer (a fixed literal, never data).
const RIPPLE_ROWS_SANITIZER: &str = "sanitize_minimal_capture \
     (crates/aruna-gmail/tests/live_readside.rs): system labels named, user labels counted never \
     named, provider message ids dropped (rows carry a first-appearance message_ordinal)";

/// [`serve_once`]'s SEQUENCE sibling: ONE loopback origin answering `responses` in
/// order, one connection each. A ripple row is a read then a write on one transport — two
/// exchanges on one origin, which `serve_once` (one exchange) cannot give. Same framing as
/// `serve_once` (`connection: close`, so the client opens a fresh connection per request). Each
/// request is read through its declared `content-length` before the answer is written: a write
/// carries a body, and closing over unread request bytes can reset the connection under the
/// client. The handle yields each request line (`METHOD target HTTP/1.1`) in arrival order; an
/// exchange that never arrives ends the thread at a bounded deadline, so a row that stops early
/// can never hang the join.
fn serve_sequence(
    responses: Vec<(u16, String)>,
) -> (String, std::thread::JoinHandle<Vec<String>>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    listener.set_nonblocking(true).expect("nonblocking");
    let origin = format!(
        "http://127.0.0.1:{}",
        listener.local_addr().expect("local addr").port()
    );
    let handle = std::thread::spawn(move || {
        use std::io::{Read, Write};
        let mut request_lines = Vec::new();
        for (status, body) in responses {
            let deadline = std::time::Instant::now() + std::time::Duration::from_millis(1500);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(_) if std::time::Instant::now() < deadline => {
                        std::thread::sleep(std::time::Duration::from_millis(5))
                    }
                    Err(_) => return request_lines,
                }
            };
            stream.set_nonblocking(false).expect("blocking stream");
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .expect("read timeout");
            let mut raw = Vec::new();
            let mut chunk = [0u8; 1024];
            let head_end = loop {
                if let Some(at) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                    break Some(at + 4);
                }
                match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => break None,
                    Ok(n) => raw.extend_from_slice(&chunk[..n]),
                }
            };
            let Some(head_end) = head_end else {
                return request_lines;
            };
            let head = String::from_utf8_lossy(&raw[..head_end]).to_string();
            let declared = head
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())?
                })
                .unwrap_or(0);
            while raw.len() < head_end + declared {
                match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => raw.extend_from_slice(&chunk[..n]),
                }
            }
            request_lines.push(head.lines().next().unwrap_or_default().to_string());
            let response = format!(
                "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).expect("write response");
        }
        request_lines
    });
    (origin, handle)
}

// ===============================================================================================
// ===============================================================================================
//                                   HERMETIC WITNESSES
// ===============================================================================================
// ===============================================================================================

// ---- env/bundle gate — fail-closed, PANICS, never a skip -------------------------------

/// A map-backed env lookup for hermetic, parallel-safe env tests (process env is never touched).
fn env_of<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
    move |key: &str| {
        pairs
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.to_string())
    }
}

#[test]
fn not_opted_in_is_a_clean_skip() {
    assert_eq!(
        parse_drill_env(env_of(&[])).expect("no opt-in is never an error"),
        None
    );
    assert_eq!(
        parse_drill_env(env_of(&[("PHOTON_GMAIL_IT", "0")])).expect("IT=0 is not opted in"),
        None
    );
    // The new grant high-water is required only when the live run is OPTED IN — the default
    // hermetic suite must keep parsing to `None`, never to an error, with it absent.
    assert_eq!(
        parse_drill_env(env_of(&[
            ("PHOTON_GMAIL_IT", "0"),
            ("PHOTON_GMAIL_ACCESS_TOKEN", "tok-main"),
            ("PHOTON_GMAIL_ATTESTATION", "/parked/bundle.json"),
        ]))
        .expect("IT=0 never requires the grant high-water"),
        None
    );
}

// `DrillEnv` equality only matters for the skip case above; spot-check fields directly here.
impl PartialEq for DrillEnv {
    fn eq(&self, other: &Self) -> bool {
        self.access_token == other.access_token
            && self.denial_token == other.denial_token
            && self.attestation_path == other.attestation_path
            && self.grant_high_water == other.grant_high_water
            && self.a2_msg == other.a2_msg
            && self.mode == other.mode
            && self.evidence_dir == other.evidence_dir
    }
}

#[test]
fn opted_in_with_full_contract_parses() {
    let env = parse_drill_env(env_of(&[
        ("PHOTON_GMAIL_IT", "1"),
        ("PHOTON_GMAIL_ACCESS_TOKEN", "tok-main"),
        ("PHOTON_GMAIL_403_TOKEN", "tok-denial"),
        ("PHOTON_GMAIL_ATTESTATION", "/parked/bundle.json"),
        ("PHOTON_GMAIL_GRANT_HIGH_WATER", "4"),
        ("PHOTON_GMAIL_A2_MSG", "pinned"),
        ("PHOTON_GMAIL_MODE", "closure"),
        ("PHOTON_GMAIL_EVIDENCE_DIR", "/parked/evidence"),
    ]))
    .expect("full contract parses")
    .expect("opted in");
    assert_eq!(env.access_token, "tok-main");
    assert_eq!(env.denial_token.as_deref(), Some("tok-denial"));
    assert_eq!(env.attestation_path, PathBuf::from("/parked/bundle.json"));
    assert_eq!(env.grant_high_water, 4);
    assert_eq!(env.a2_msg.as_deref(), Some("pinned"));
    assert_eq!(env.mode, DrillMode::Closure);
    assert_eq!(env.evidence_dir, Some(PathBuf::from("/parked/evidence")));
}

#[test]
fn missing_or_empty_required_vars_are_errors_never_skips() {
    // Opted in with a missing/empty required var must be an ERROR (the live
    // shell panics on it) — a silent skip would let a claimed-closed obligation go green with
    // its drill never executing (design §0).
    let missing_token = parse_drill_env(env_of(&[
        ("PHOTON_GMAIL_IT", "1"),
        ("PHOTON_GMAIL_ATTESTATION", "/parked/bundle.json"),
    ]));
    assert!(
        missing_token.is_err(),
        "IT=1 with no access token must be an Err (never Ok(None) — that is a silent skip): \
         got {missing_token:?}"
    );
    let empty_token = parse_drill_env(env_of(&[
        ("PHOTON_GMAIL_IT", "1"),
        ("PHOTON_GMAIL_ACCESS_TOKEN", "   "),
        ("PHOTON_GMAIL_ATTESTATION", "/parked/bundle.json"),
    ]));
    assert!(
        empty_token.is_err(),
        "an empty/whitespace token is MISSING, not present: got {empty_token:?}"
    );
    let missing_attestation = parse_drill_env(env_of(&[
        ("PHOTON_GMAIL_IT", "1"),
        ("PHOTON_GMAIL_ACCESS_TOKEN", "tok-main"),
    ]));
    assert!(
        missing_attestation.is_err(),
        "IT=1 with no attestation path must be an Err: got {missing_attestation:?}"
    );
    let bad_mode = parse_drill_env(env_of(&[
        ("PHOTON_GMAIL_IT", "1"),
        ("PHOTON_GMAIL_ACCESS_TOKEN", "tok-main"),
        ("PHOTON_GMAIL_ATTESTATION", "/parked/bundle.json"),
        // Present so this test still fails on the MODE, not on the high-water requirement.
        ("PHOTON_GMAIL_GRANT_HIGH_WATER", "4"),
        ("PHOTON_GMAIL_MODE", "yolo"),
    ]));
    assert!(bad_mode.is_err(), "an unknown mode must refuse, not default");
    // A BLANK `PHOTON_GMAIL_MODE='   '` is the
    // DECLARED equivalence — blank ≡ absent ≡ smoke, per the env contract's own "empty-string
    // values are MISSING" rule and the design's `smoke (default) | closure`. This
    // pin preserves that contract deliberately; the named consequence (an accidental blank
    // export silently loses a requested closure run, selecting smoke) is a LEDGERED residual —
    // changing blank to a refusal is a contract decision, not a mechanical change.
    let blank_mode = parse_drill_env(env_of(&[
        ("PHOTON_GMAIL_IT", "1"),
        ("PHOTON_GMAIL_ACCESS_TOKEN", "tok-main"),
        ("PHOTON_GMAIL_ATTESTATION", "/parked/bundle.json"),
        ("PHOTON_GMAIL_GRANT_HIGH_WATER", "4"),
        ("PHOTON_GMAIL_MODE", "   "),
    ]))
    .expect("a blank mode is the declared absent-equivalence, never an error")
    .expect("still opted in");
    assert_eq!(
        blank_mode.mode,
        DrillMode::Smoke,
        "blank mode selects smoke — the declared default, pinned so a contract change here \
         goes RED instead of silent"
    );
    // The ratchet high-water is as REQUIRED as the attestation itself —
    // without it preflight cannot bind the bundle to the grant the run is about to spend, and
    // a defaulted-to-zero (or skipped) high-water would be exactly the silent-skip shape the env gate
    // exists to forbid.
    let missing_high_water = parse_drill_env(env_of(&[
        ("PHOTON_GMAIL_IT", "1"),
        ("PHOTON_GMAIL_ACCESS_TOKEN", "tok-main"),
        ("PHOTON_GMAIL_ATTESTATION", "/parked/bundle.json"),
    ]));
    assert!(
        missing_high_water.is_err(),
        "IT=1 with no PHOTON_GMAIL_GRANT_HIGH_WATER must be an Err: got {missing_high_water:?}"
    );
    let non_numeric_high_water = parse_drill_env(env_of(&[
        ("PHOTON_GMAIL_IT", "1"),
        ("PHOTON_GMAIL_ACCESS_TOKEN", "tok-main"),
        ("PHOTON_GMAIL_ATTESTATION", "/parked/bundle.json"),
        ("PHOTON_GMAIL_GRANT_HIGH_WATER", "two"),
    ]));
    assert!(
        non_numeric_high_water.is_err(),
        "a non-numeric PHOTON_GMAIL_GRANT_HIGH_WATER must refuse, never coerce: got \
         {non_numeric_high_water:?}"
    );
}

#[test]
fn panic_shell_panics_on_a_violated_contract() {
    // The panic itself, witnessed: the live entrypoint goes through this shell, so a violated
    // contract can never be observed as a skip.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        drill_env_or_panic(env_of(&[("PHOTON_GMAIL_IT", "1")]))
    }));
    assert!(result.is_err(), "drill_env_or_panic must panic, not skip");
}

#[test]
fn unreadable_bundle_is_an_error() {
    let missing = load_bundle(Path::new("Z:/definitely/not/here/bundle.json"));
    assert!(missing.is_err(), "a missing bundle file must be an error");
    let dir = aruna::test_temp::TempDir::new("photon-w1-bundle"); // guarded, unique
    let garbled = dir.join("garbled.json");
    std::fs::write(&garbled, b"{not json").expect("write garbled bundle");
    assert!(
        load_bundle(&garbled).is_err(),
        "an unparseable bundle must be an error"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ---- the preflight digest binding -------------------------------------------------------

/// The grant generation the preflight fixtures are minted under — and, therefore, the high-water the
/// preflight witnesses pass in. Not 1: a fixture pinned to the first generation
/// would agree with a defaulted-to-zero-then-incremented high-water by accident.
const TEST_GRANT_HIGH_WATER: u64 = 7;

/// A well-formed bundle whose digests match the given token strings — the GREEN baseline the
/// mismatch witnesses perturb.
fn bundle_for(main_token: &str, denial_token: Option<&str>, now: i64) -> AttestationBundle {
    AttestationBundle {
        grant_generation: Some(Some(TEST_GRANT_HIGH_WATER)),
        main_token_sha384: sha384_hex(main_token.as_bytes()),
        denial_token_sha384: denial_token.map(|t| sha384_hex(t.as_bytes())),
        effective_main_scopes: vec![MODIFY_SCOPE.to_string()],
        effective_denial_scopes: denial_token
            .map(|_| vec!["openid".to_string(), "email".to_string()]),
        scope_source_main: "token_response".to_string(),
        scope_source_denial: denial_token.map(|_| "token_response".to_string()),
        same_principal: denial_token.map(|_| true),
        minted_at: now - 60,
        expires_at_main: now + 3000,
        expires_at_denial: denial_token.map(|_| now + 3000),
        helper_source_sha384: "0".repeat(96),
    }
}

#[test]
fn matched_pair_passes_preflight() {
    let now = 1_800_000_000;
    let bundle = bundle_for("tok-main-A", Some("tok-denial-A"), now);
    preflight(&bundle, "tok-main-A", Some("tok-denial-A"), now, DrillMode::Closure, TEST_GRANT_HIGH_WATER)
        .expect("a matched pair must pass");
}

#[test]
fn mismatched_main_token_refuses() {
    // Main slot: the env token is not the token this bundle attests — a stale or
    // mixed-generation env. The run must REFUSE, never proceed on the bundle's claims.
    let now = 1_800_000_000;
    let bundle = bundle_for("tok-main-A", Some("tok-denial-A"), now);
    let verdict = preflight(&bundle, "tok-main-B", Some("tok-denial-A"), now, DrillMode::Smoke, TEST_GRANT_HIGH_WATER);
    assert!(
        verdict.is_err(),
        "a main-token digest mismatch must refuse the run: got {verdict:?}"
    );
}

#[test]
fn mismatched_denial_token_refuses() {
    // Denial slot (the battery instantiates mismatch for BOTH slots).
    let now = 1_800_000_000;
    let bundle = bundle_for("tok-main-A", Some("tok-denial-A"), now);
    let verdict = preflight(&bundle, "tok-main-A", Some("tok-denial-B"), now, DrillMode::Smoke, TEST_GRANT_HIGH_WATER);
    assert!(
        verdict.is_err(),
        "a denial-token digest mismatch must refuse the run: got {verdict:?}"
    );
}

#[test]
fn cross_session_pair_refuses_both_ways() {
    // Cross-session: two complete, individually self-consistent
    // mint generations, paired wrong — session B's tokens under session A's bundle and vice
    // versa. Exactly the mixed-generation class the binding exists to close.
    let now = 1_800_000_000;
    let session_a = bundle_for("tok-main-A", Some("tok-denial-A"), now);
    let session_b = bundle_for("tok-main-B", Some("tok-denial-B"), now);
    assert!(
        preflight(&session_a, "tok-main-B", Some("tok-denial-B"), now, DrillMode::Smoke, TEST_GRANT_HIGH_WATER).is_err(),
        "session B tokens under session A's bundle must refuse"
    );
    assert!(
        preflight(&session_b, "tok-main-A", Some("tok-denial-A"), now, DrillMode::Smoke, TEST_GRANT_HIGH_WATER).is_err(),
        "session A tokens under session B's bundle must refuse"
    );
}

#[test]
fn denial_token_without_bundle_slot_refuses() {
    let now = 1_800_000_000;
    let mut bundle = bundle_for("tok-main-A", Some("tok-denial-A"), now);
    bundle.denial_token_sha384 = None;
    assert!(
        preflight(&bundle, "tok-main-A", Some("tok-denial-A"), now, DrillMode::Smoke, TEST_GRANT_HIGH_WATER).is_err(),
        "a denial token the bundle never attested must refuse"
    );
}

#[test]
fn preflight_scope_rules_hold() {
    let now = 1_800_000_000;
    // Broader main scope: refuses closure, warns (passes) in smoke — design §3.
    //
    // The fixture, not the rule, changed: the exact set is now
    // `{gmail.modify}`, so pushing `gmail.modify` onto the baseline bundle is a DUPLICATE
    // (the same SET), and the witness would have asserted nothing. The full-mailbox scope is
    // the honest "broader" here — it is the one scope that adds permanent-delete authority.
    let mut broad = bundle_for("tok-main-A", None, now);
    broad
        .effective_main_scopes
        .push("https://mail.google.com/".to_string());
    assert!(
        preflight(&broad, "tok-main-A", None, now, DrillMode::Closure, TEST_GRANT_HIGH_WATER).is_err(),
        "closure must refuse a broader main scope set"
    );
    preflight(&broad, "tok-main-A", None, now, DrillMode::Smoke, TEST_GRANT_HIGH_WATER)
        .expect("smoke warns on a broader main scope set but proceeds");

    // Unordered exact set: order and duplicates must not matter (design §3: set comparison).
    let mut dup = bundle_for("tok-main-A", None, now);
    dup.effective_main_scopes.push(MODIFY_SCOPE.to_string());
    preflight(&dup, "tok-main-A", None, now, DrillMode::Closure, TEST_GRANT_HIGH_WATER)
        .expect("a duplicated identical scope entry is the same SET");

    // Denial scopes: ANY Gmail-family scope refuses in every mode — gmail.labels authorizes
    // POST label mutation (design §3), and mail.google.com is total.
    for poisoned_scope in [
        "https://www.googleapis.com/auth/gmail.labels",
        "https://www.googleapis.com/auth/gmail.readonly",
        "https://mail.google.com/",
    ] {
        let mut poisoned = bundle_for("tok-main-A", Some("tok-denial-A"), now);
        poisoned
            .effective_denial_scopes
            .as_mut()
            .expect("denial scopes present")
            .push(poisoned_scope.to_string());
        assert!(
            preflight(&poisoned, "tok-main-A", Some("tok-denial-A"), now, DrillMode::Smoke, TEST_GRANT_HIGH_WATER)
                .is_err(),
            "a Gmail-family denial scope must refuse: {poisoned_scope}"
        );
    }

    // Same_principal must be attested true when the denial token rides (R3's precondition).
    for wrong in [Some(false), None] {
        let mut unattested = bundle_for("tok-main-A", Some("tok-denial-A"), now);
        unattested.same_principal = wrong;
        assert!(
            preflight(&unattested, "tok-main-A", Some("tok-denial-A"), now, DrillMode::Smoke, TEST_GRANT_HIGH_WATER)
                .is_err(),
            "same_principal={wrong:?} with a denial token must refuse"
        );
    }

    // Expiry refuses — PER TOKEN.
    let expired = bundle_for("tok-main-A", None, now);
    assert!(
        preflight(&expired, "tok-main-A", None, now + 4000, DrillMode::Smoke, TEST_GRANT_HIGH_WATER).is_err(),
        "an expired main token must refuse"
    );
    let mut denial_expired = bundle_for("tok-main-A", Some("tok-denial-A"), now);
    denial_expired.expires_at_main = now + 9000; // main stays live
    denial_expired.expires_at_denial = Some(now - 10);
    assert!(
        preflight(&denial_expired, "tok-main-A", Some("tok-denial-A"), now, DrillMode::Smoke, TEST_GRANT_HIGH_WATER)
            .is_err(),
        "an expired denial token must refuse even while the main token is live"
    );
    let mut denial_no_expiry = bundle_for("tok-main-A", Some("tok-denial-A"), now);
    denial_no_expiry.expires_at_denial = None;
    assert!(
        preflight(&denial_no_expiry, "tok-main-A", Some("tok-denial-A"), now, DrillMode::Smoke, TEST_GRANT_HIGH_WATER)
            .is_err(),
        "a used denial slot with no recorded expiry must refuse"
    );

    // Unknown scope provenance refuses (only the two recorded sources exist).
    let mut bad_source = bundle_for("tok-main-A", None, now);
    bad_source.scope_source_main = "operator_said_so".to_string();
    assert!(
        preflight(&bad_source, "tok-main-A", None, now, DrillMode::Smoke, TEST_GRANT_HIGH_WATER).is_err(),
        "an unrecognized scope provenance must refuse"
    );
}

#[test]
fn preflight_used_denial_slot_requires_recorded_provenance() {
    // A USED slot needs a recognized provenance value — a null
    // scope_source_denial beside a present denial token means the bundle cannot say where its
    // denial scope claim came from, and the run must refuse rather than trust it.
    let now = 1_800_000_000;
    let mut bundle = bundle_for("tok-main-A", Some("tok-denial-A"), now);
    bundle.scope_source_denial = None;
    assert!(
        preflight(&bundle, "tok-main-A", Some("tok-denial-A"), now, DrillMode::Smoke, TEST_GRANT_HIGH_WATER).is_err(),
        "a used denial slot with no recorded scope provenance must refuse"
    );
}

// ---- the bundle↔ratchet binding -----------------------------------------

/// Write a bundle JSON to a per-test temp path. `generation` = `None` OMITS the member
/// entirely — that is the shape every older mint produced. The
/// directory's guard comes back FIRST (the ONE guard, `aruna::test_temp`; it was a pid-only
/// name) — bind it for as long as the bundle is read.
fn write_bundle_json(name: &str, generation: Option<u64>, main_token: &str, now: i64) -> (aruna::test_temp::TempDir, PathBuf) {
    let dir = aruna::test_temp::TempDir::new(&format!("photon-f13-{name}"));
    let mut bundle = serde_json::json!({
        "main_token_sha384": sha384_hex(main_token.as_bytes()),
        "denial_token_sha384": serde_json::Value::Null,
        "effective_main_scopes": [MODIFY_SCOPE],
        "effective_denial_scopes": serde_json::Value::Null,
        "scope_source_main": "token_response",
        "scope_source_denial": serde_json::Value::Null,
        "same_principal": serde_json::Value::Null,
        "minted_at": now - 60,
        "expires_at_main": now + 3000,
        "expires_at_denial": serde_json::Value::Null,
        "helper_source_sha384": "0".repeat(96),
    });
    if let Some(generation) = generation {
        bundle["grant_generation"] = serde_json::json!(generation);
    }
    let path = dir.join("bundle.json");
    std::fs::write(&path, serde_json::to_vec_pretty(&bundle).expect("serialize bundle"))
        .expect("write bundle");
    (dir, path)
}

#[test]
fn bundle_with_null_grant_generation_refuses_as_null_never_as_absent() {
    // A bundle carrying `"grant_generation": null` is a PRESENT member with an unusable value.
    // Pre-fix, serde's blanket `Option` collapsed it into the absent case and the refusal
    // claimed "older mint" — false twice: the bundle DOES carry the member, and a null
    // proves nothing about the bundle's age. Still a REFUSAL either way (the change is
    // diagnosis-only); the sentence must name the null, not invent a provenance story.
    let now = 1_800_000_000;
    let (_dir, path) = {
        let (dir, p) = write_bundle_json("null-generation", None, "tok-main-A", now);
        let mut doc: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&p).expect("read bundle")).expect("parse");
        doc["grant_generation"] = serde_json::Value::Null;
        std::fs::write(&p, serde_json::to_vec_pretty(&doc).expect("serialize")).expect("write");
        (dir, p)
    };
    let (bundle, _) = load_bundle(&path).expect("a null-generation bundle still parses");
    let verdict = preflight(&bundle, "tok-main-A", None, now, DrillMode::Smoke, 2);
    let reason = verdict.expect_err("a null grant_generation must refuse the run");
    assert!(
        reason.contains("null"),
        "the refusal names the PRESENT-null fact: {reason}"
    );
    assert!(
        !reason.contains("pre-#75"),
        "a present member must not be diagnosed as the pre-#75 ABSENT shape: {reason}"
    );
    let _ = std::fs::remove_dir_all(path.parent().expect("temp dir"));
}

#[test]
fn bundle_without_grant_generation_refuses() {
    // An OLDER bundle carries no `grant_generation` at all. Serde's
    // tolerance means it parses; the run must still REFUSE, because nothing in it can be
    // bound to the grant the drill is about to spend.
    let now = 1_800_000_000;
    let (_dir, path) = write_bundle_json("no-generation", None, "tok-main-A", now);
    let (bundle, _) = load_bundle(&path).expect("a pre-#75 bundle still parses");
    let verdict = preflight(&bundle, "tok-main-A", None, now, DrillMode::Smoke, 2);
    assert!(
        verdict.is_err(),
        "a bundle carrying no grant_generation must refuse the run (pre-#75 mint): got \
         {verdict:?}"
    );
    let _ = std::fs::remove_dir_all(path.parent().expect("temp dir"));
}

#[test]
fn a_bundle_repeating_grant_generation_is_refused_by_the_derive() {
    // `load_bundle` deserializes
    // the bundle TYPED, straight from the bytes — `serde_json::from_slice::<AttestationBundle>`,
    // with no `Value` detour in front of it — so serde's derived reader sees the member stream
    // the mint actually wrote and answers "duplicate field `grant_generation`" itself. That
    // matters here for exactly the reason it matters at the credential's grant door: a bundle
    // stating an old generation and then the current high-water would otherwise bind the drill
    // to the LAST occurrence, which is the restored-pair class the ratchet binding exists to refuse.
    //
    // This is a NON-REGRESSION PIN, not a red: it was already refused before this change. The pin
    // is what keeps a future `Value`-then-typed rewrite of `load_bundle` from re-opening it.
    let now = 1_800_000_000;
    let dir = aruna::test_temp::TempDir::new("photon-f19-a30"); // guarded, unique
    let path = dir.join("bundle.json");
    // Written as TEXT, deliberately: `serde_json::json!` builds a map, and a map has already
    // collapsed the repeat by the time it is serialized — it cannot express this document.
    std::fs::write(
        &path,
        format!(
            "{{\"grant_generation\": 1, \
             \"main_token_sha384\": \"{}\", \
             \"denial_token_sha384\": null, \
             \"effective_main_scopes\": [\"{MODIFY_SCOPE}\"], \
             \"effective_denial_scopes\": null, \
             \"scope_source_main\": \"token_response\", \
             \"scope_source_denial\": null, \
             \"same_principal\": null, \
             \"minted_at\": {}, \
             \"expires_at_main\": {}, \
             \"expires_at_denial\": null, \
             \"helper_source_sha384\": \"{}\", \
             \"grant_generation\": 2}}",
            sha384_hex(b"tok-main-A"),
            now - 60,
            now + 3000,
            "0".repeat(96),
        ),
    )
    .expect("write bundle");

    let loaded = load_bundle(&path);
    assert!(
        loaded.is_err(),
        "a bundle that states `grant_generation` twice says two different things about which \
         consent it attests — the typed derive must refuse it, never bind the drill to the last \
         occurrence: got {loaded:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bundle_generation_below_the_high_water_refuses() {
    // The restored-pair class. An older token and ITS OWN matching
    // bundle agree on sha384 forever, so the digest binding cannot see the problem — only
    // the ratchet high-water can. Bundle minted under grant 1, current high-water 2.
    let now = 1_800_000_000;
    let (_dir, path) = write_bundle_json("stale-generation", Some(1), "tok-main-A", now);
    let (bundle, _) = load_bundle(&path).expect("bundle parses");
    let env = parse_drill_env(env_of(&[
        ("PHOTON_GMAIL_IT", "1"),
        ("PHOTON_GMAIL_ACCESS_TOKEN", "tok-main-A"),
        ("PHOTON_GMAIL_ATTESTATION", "/parked/bundle.json"),
        ("PHOTON_GMAIL_GRANT_HIGH_WATER", "2"),
    ]))
    .expect("contract parses")
    .expect("opted in");
    assert_eq!(env.grant_high_water, 2, "the ceremony's exported high-water");
    let verdict = preflight(
        &bundle,
        "tok-main-A",
        None,
        now,
        DrillMode::Smoke,
        env.grant_high_water,
    );
    assert!(
        verdict.is_err(),
        "a bundle minted under grant 1 must refuse while the current high-water is 2 (a \
         restored older token+bundle pair): got {verdict:?}"
    );
    // The refusal must NAME both generations — an operator who cannot see which side is stale
    // cannot choose between "re-mint" and "the ratchet file is the stale one".
    let reason = verdict.expect_err("refused");
    assert!(
        reason.contains("grant_generation 1") && reason.contains("high-water 2"),
        "the refusal must name both generations: {reason}"
    );
    let _ = std::fs::remove_dir_all(path.parent().expect("temp dir"));
}

#[test]
fn bundle_generation_equal_to_the_high_water_passes() {
    // The non-regression half: the CURRENT grant's bundle runs. The binding refuses stale
    // pairs, never the pair the ceremony just minted.
    let now = 1_800_000_000;
    let (_dir, path) = write_bundle_json("current-generation", Some(2), "tok-main-A", now);
    let (bundle, _) = load_bundle(&path).expect("bundle parses");
    preflight(&bundle, "tok-main-A", None, now, DrillMode::Smoke, 2)
        .expect("the current grant's bundle must pass");
    let _ = std::fs::remove_dir_all(path.parent().expect("temp dir"));
}

#[test]
fn closure_mode_requires_an_evidence_dir() {
    // Closure evidence must land OUTSIDE the repo worktree and target/ — so
    // the env contract requires PHOTON_GMAIL_EVIDENCE_DIR in closure mode, refused at parse
    // when absent (never a silent fall-back into target/).
    let parsed = parse_drill_env(env_of(&[
        ("PHOTON_GMAIL_IT", "1"),
        ("PHOTON_GMAIL_ACCESS_TOKEN", "tok-main"),
        ("PHOTON_GMAIL_ATTESTATION", "/parked/bundle.json"),
        // Present so this test still fails on the EVIDENCE DIR, not on the high-water requirement.
        ("PHOTON_GMAIL_GRANT_HIGH_WATER", "4"),
        ("PHOTON_GMAIL_MODE", "closure"),
    ]));
    assert!(
        parsed.is_err(),
        "closure with no PHOTON_GMAIL_EVIDENCE_DIR must refuse at parse: got {parsed:?}"
    );
}

// ---- the redacting wrapper never leaks --------------------------------------------------

/// A sentinel standing in for a provider message id — if this ever appears in a formatted
/// failure, the confinement is broken.
const SENTINEL: &str = "SENTINEL-MSG-ID-3f9a1b2c4d5e6f70";

fn assert_no_sentinel(err: &DrillError, path_name: &str) {
    let display = format!("{err}");
    let debug = format!("{err:?}");
    assert!(
        !display.contains(SENTINEL) && !debug.contains(SENTINEL),
        "{path_name}: the sentinel leaked through the wrapper.\n display: {display}\n debug: {debug}"
    );
}

#[test]
fn url_construction_failure_is_redacted() {
    // A real reqwest builder error whose OWN Display embeds the offending URL (and therefore the
    // sentinel) — the raw error demonstrably leaks; the wrapper must not. No network: the scheme
    // is unsupported, so the failure happens at request build time.
    let raw = reqwest::blocking::get(format!("unsupported://gmail.example/{SENTINEL}"))
        .expect_err("unsupported scheme must fail at build time");
    assert!(
        format!("{raw}").contains(SENTINEL) || format!("{raw:?}").contains(SENTINEL),
        "precondition: the RAW error must carry the sentinel, or this witness is vacuous"
    );
    assert_no_sentinel(&DrillError::send(&raw), "url/builder failure");
    // And the pure URL-parse path through the same wrapper surface.
    let parse_err = reqwest::Url::parse("http://[:::1").expect_err("invalid URL");
    assert_no_sentinel(&DrillError::url_build(&parse_err), "url parse failure");
}

#[test]
fn non_2xx_body_is_redacted() {
    let body = format!(
        r#"{{"error":{{"code":404,"message":"message {SENTINEL} not found","status":"NOT_FOUND"}}}}"#
    );
    assert_no_sentinel(&DrillError::non_success(404, &body), "non-2xx body");
}

#[test]
fn json_failure_is_redacted() {
    let malformed = format!(r#"{{"id":"{SENTINEL}","labelIds":["#);
    let raw = serde_json::from_str::<serde_json::Value>(&malformed)
        .expect_err("malformed JSON must fail to parse");
    assert_no_sentinel(&DrillError::json(&raw), "json failure");
}

#[test]
fn assertion_mismatch_is_redacted() {
    let observed = format!("SUT saw message {SENTINEL} with labels [INBOX]");
    assert_no_sentinel(
        &DrillError::assertion_mismatch("R1 placement mismatch", &observed),
        "assertion mismatch",
    );
}

#[test]
fn toctou_mismatch_is_redacted() {
    // History-bracket values are provider state; the failure output carries neither side.
    let before = format!("history-{SENTINEL}-before");
    let after = format!("history-{SENTINEL}-after");
    assert_no_sentinel(&DrillError::toctou(&before, &after), "toctou mismatch");
}

#[test]
fn probe_id_echo_mismatch_is_redacted() {
    // The parser's own failure path: a response for a DIFFERENT message — the foreign id must
    // not surface in the error.
    let body = format!(r#"{{"id":"{SENTINEL}","labelIds":["INBOX"]}}"#);
    let err = probe_parse_minimal(&body, "expected-id").expect_err("id echo must mismatch");
    assert_no_sentinel(&err, "probe id-echo mismatch");
}

// ---- the request-ledger fence ------------------------------------------------------------

fn entry(method: &str, path_shape: &str) -> LedgerEntry {
    entry_with_host(method, "gmail.googleapis.com", path_shape)
}

fn entry_with_host(method: &str, host: &str, path_shape: &str) -> LedgerEntry {
    LedgerEntry {
        method: method.to_string(),
        host: host.to_string(),
        path_shape: path_shape.to_string(),
        query_keys: Vec::new(),
    }
}

#[test]
fn ledger_accepts_the_three_allowlisted_get_routes() {
    let entries = vec![
        entry("GET", "users/me/profile"),
        entry("GET", "users/me/messages"),
        entry("GET", "users/me/messages/{id}"),
    ];
    assert!(
        ledger_violations(&entries).is_empty(),
        "the three allowlisted GET routes are the whole legal surface"
    );
}

#[test]
fn ledger_flags_non_get_and_off_route_shapes() {
    // Deliberately off-route / non-GET entries constructed as test doubles
    // (never real calls). `/watch` and `/stop` are the design's named negatives — POST routes
    // Google authorizes UNDER `gmail.readonly`, which is exactly why the credential alone is not
    // the fence (design §1).
    let negatives = [
        entry("POST", "users/me/watch"),
        entry("POST", "users/me/stop"),
        entry("GET", "users/me/watch"),
        entry("GET", "users/me/stop"),
        entry("POST", "users/me/messages"),
        entry("POST", "users/me/messages/{id}/modify"),
        entry("GET", "users/me/settings/filters"),
        entry("PUT", "users/me/labels/{id}"),
    ];
    for negative in &negatives {
        let violations = ledger_violations(std::slice::from_ref(negative));
        assert_eq!(
            violations.len(),
            1,
            "the fence must flag `{} {}` as a violation (got: {violations:?})",
            negative.method,
            negative.path_shape
        );
    }
    // A single bad entry among good ones is still caught — and only it.
    let mixed = vec![
        entry("GET", "users/me/profile"),
        entry("POST", "users/me/watch"),
        entry("GET", "users/me/messages"),
    ];
    let violations = ledger_violations(&mixed);
    assert_eq!(
        violations,
        vec!["POST gmail.googleapis.com users/me/watch".to_string()]
    );
    // An allowlisted GET against a FOREIGN host is a violation — only the compiled Gmail host
    // and the test constructor's loopback are legal probe destinations.
    let foreign = entry_with_host("GET", "gmail.googleapis.com.evil.example", "users/me/profile");
    assert_eq!(ledger_violations(std::slice::from_ref(&foreign)).len(), 1);
    for loopback in ["127.0.0.1", "localhost", "::1"] {
        let local = entry_with_host("GET", loopback, "users/me/profile");
        assert!(
            ledger_violations(std::slice::from_ref(&local)).is_empty(),
            "the hermetic-harness loopback allowance: {loopback}"
        );
    }
}

#[test]
fn probe_records_every_dispatch_in_the_ledger() {
    // The recording side, hermetically: a probe pointed at a dead loopback port (no server —
    // the send fails, and the ledger row must exist ANYWAY, because a refused/failed send was
    // still an attempted request). 127.0.0.1:1 refuses connections on every platform we ship on.
    let probe = GmailProbe::loopback_for_test("http://127.0.0.1:1", "hermetic-token");
    let result = probe.get_profile_history_id();
    assert!(result.is_err(), "nothing listens on 127.0.0.1:1");
    let ledger = probe.ledger_snapshot();
    assert_eq!(ledger.len(), 1, "the attempted request must be ledgered");
    assert_eq!(ledger[0].method, "GET");
    assert_eq!(ledger[0].host, "127.0.0.1", "the ledger records WHERE the request went");
    assert_eq!(ledger[0].path_shape, "users/me/profile");
    assert_eq!(ledger[0].query_keys, vec!["fields".to_string()]);
    assert!(ledger_violations(&ledger).is_empty());
}

#[test]
fn probe_loopback_constructor_refuses_non_loopback_origins() {
    // The ONLY way off the compiled host is loopback-validated (mirror of
    // connect_for_test_fixture): a real-host origin must panic at construction.
    let result = std::panic::catch_unwind(|| {
        GmailProbe::loopback_for_test("https://gmail.googleapis.com", "t")
    });
    assert!(result.is_err(), "a non-loopback origin must be refused");
}

#[test]
fn ledger_records_the_dispatched_route_never_a_caller_claim() {
    // The old dispatch surface took an arbitrary URL plus an INDEPENDENTLY
    // supplied path shape — the generic escape hatch design §3 forbids, and it let the ledger
    // record a caller CLAIM while the socket did something else (the ledger
    // said `users/me/profile` while the wire carried `users/me/watch`). The lie is now
    // INEXPRESSIBLE: dispatch takes a typed route, the URL is constructed from the probe's
    // base, and the row is DERIVED from that URL. Witness the derivation — including the id
    // masking that keeps the ledger id-free.
    let probe = GmailProbe::loopback_for_test("http://127.0.0.1:1", "hermetic-token");
    let _ = probe.get_raw_minimal("secret-msg-id-1234");
    let _ = probe.list_messages("in:inbox", Some("page-2-token"));
    let ledger = probe.ledger_snapshot();
    assert_eq!(ledger.len(), 2);
    assert_eq!(
        ledger[0].path_shape, "users/me/messages/{id}",
        "derived from the constructed URL, message id masked"
    );
    assert_eq!(ledger[0].query_keys, vec!["format".to_string(), "fields".to_string()]);
    assert_eq!(ledger[1].path_shape, "users/me/messages");
    assert_eq!(
        ledger[1].query_keys,
        vec!["q", "includeSpamTrash", "maxResults", "fields", "pageToken"]
    );
    // Nothing provider-native leaks into the census: neither the message id nor any query VALUE.
    let rendered = format!("{ledger:?}");
    assert!(
        !rendered.contains("secret-msg-id-1234") && !rendered.contains("page-2-token"),
        "ledger rows must carry shapes and keys only"
    );
    assert!(ledger_violations(&ledger).is_empty());
}

#[test]
fn probe_refuses_redirects_and_never_contacts_the_location_target() {
    // Reqwest's default
    // policy FOLLOWS a 3xx, re-sending the bearer to a provider-chosen Location. The probe
    // mirrors the production transport: `Policy::none()`, any 3xx is terminal. (Before the fix status 200
    // arrived and the Location target WAS contacted.)
    use std::sync::atomic::Ordering;
    let (target_origin, target_hit, target_handle) =
        serve_flagging(200, r#"{"id":"m1","labelIds":["INBOX"]}"#.to_string());
    let location = format!(
        "{target_origin}/gmail/v1/users/me/messages/m1?format=minimal&fields=id,labelIds"
    );
    let (origin, handle) =
        serve_once_with_headers(302, String::new(), format!("location: {location}\r\n"));
    let probe = GmailProbe::loopback_for_test(&origin, "hermetic-token");
    // Capture-first surface: the 302 arrives as a completed terminal exchange…
    let (status, _body) = probe.get_raw_minimal("m1").expect("the exchange completes");
    handle.join().expect("redirect server");
    target_handle.join().expect("target server");
    assert_eq!(
        status, 302,
        "a 3xx must arrive as a completed TERMINAL response — never be followed"
    );
    assert!(
        !target_hit.load(Ordering::SeqCst),
        "the provider-chosen Location target must NEVER receive the bearer"
    );
    // …and the checked surface types it as a plain non-success, still without following.
    let (origin2, handle2) =
        serve_once_with_headers(302, String::new(), format!("location: {location}\r\n"));
    let probe2 = GmailProbe::loopback_for_test(&origin2, "hermetic-token");
    let err = probe2
        .get_message_labels("m1")
        .expect_err("a 3xx on the checked surface is a typed terminal error");
    assert!(matches!(err.stage, DrillStage::NonSuccess(302)));
    handle2.join().expect("second redirect server");
}

// ---- Probe parsing + classification ----------------------------------------------------------

#[test]
fn helper_provenance_binds_the_bundle_to_this_trees_helper() {
    // An attestation minted by DIFFERENT helper bytes than this tree's must
    // refuse — earlier helpers on this very branch carry known scope/expiry bugs
    // blessed.
    let helper_bytes = b"#!/usr/bin/env python3\n# the reviewed helper\n";
    let mut bundle = bundle_for("tok-main", None, 1_700_000_000);
    bundle.helper_source_sha384 = sha384_hex(helper_bytes);
    verify_helper_provenance(&bundle, helper_bytes).expect("matching producer bytes pass");
    verify_helper_provenance(&bundle, b"#!/usr/bin/env python3\n# a STALE helper\n")
        .expect_err("mismatched producer bytes must refuse");
}

#[test]
fn target_dir_from_exe_reads_the_cargo_layout_and_fails_closed() {
    // The running binary's own path covers EVERY
    // target-dir override mechanism by construction (env, config file, --target-dir CLI
    // flag), and the optional `--target` middle component is handled WITHOUT any name
    // discrimination — a hyphen heuristic was evaded by `--target local.json`;
    // so BOTH ancestors are candidates unconditionally (the sole carve-out: a
    // filesystem-root parent is skipped, since gating `/` refuses everything). Unexpected
    // layouts refuse rather than guess.
    let exe = Path::new("/custom-target/debug/deps/live_readside-abc123");
    assert_eq!(
        target_dir_candidates_from_exe(exe).expect("cargo layout derives"),
        vec![PathBuf::from("/custom-target")],
        "a root-adjacent target dir yields one candidate (the fs-root parent is skipped)"
    );
    let release = Path::new("/w/buildcache/release/deps/t-1");
    assert_eq!(
        target_dir_candidates_from_exe(release).expect("release profile derives"),
        vec![PathBuf::from("/w/buildcache"), PathBuf::from("/w")],
        "both ancestors gate — no spelling assumptions"
    );
    // Cross-compile layout: `--target x86_64-pc-windows-msvc` inserts the
    // triple between the root and the profile — BOTH the triple dir AND the true root are
    // candidates, so `cargo clean --target-dir <root>` can never delete evidence that passed.
    let cross = Path::new("/cache/x86_64-pc-windows-msvc/debug/deps/live_readside-abc");
    assert_eq!(
        target_dir_candidates_from_exe(cross).expect("triple layout derives"),
        vec![
            PathBuf::from("/cache/x86_64-pc-windows-msvc"),
            PathBuf::from("/cache")
        ]
    );
    // A custom target JSON names its component ANYTHING —
    // `--target local.json` lays out under <root>/local/<profile>/deps, no hyphens in
    // sight. Both ancestors gate regardless of spelling.
    let custom_json = Path::new("/root-target/local/debug/deps/live_readside-abc");
    assert_eq!(
        target_dir_candidates_from_exe(custom_json).expect("custom-target layout derives"),
        vec![
            PathBuf::from("/root-target/local"),
            PathBuf::from("/root-target")
        ],
        "a hyphen-less custom target component must still expose the true root"
    );
    for unexpected in [
        "/somewhere/bin/live_readside",    // no deps component
        "/deps",                           // deps with no profile/target ancestry
        "live_readside-abc123",            // bare name
    ] {
        assert!(
            target_dir_candidates_from_exe(Path::new(unexpected)).is_err(),
            "an unexpected layout must refuse, never guess: {unexpected}"
        );
    }
}

#[test]
fn probe_rejects_degenerate_provider_values() {
    // A
    // malformed historyId, an empty message id, and an empty page token are each REFUSED —
    // never silently accepted into evidence.
    assert_eq!(
        parse_profile_history_id(r#"{"historyId":"128118"}"#).expect("valid decimal uint64"),
        "128118"
    );
    for bad in [
        r#"{"historyId":""}"#,               // empty — two empties would satisfy the bracket
        r#"{"historyId":"not-a-number"}"#,   // non-decimal
        r#"{"historyId":"-1"}"#,             // signed — not a uint64
        r#"{"historyId":"99999999999999999999999999"}"#, // overflows u64
        r#"{"historyId":128118}"#,           // wrong JSON type (Discovery says string)
        r#"{}"#,                             // absent
    ] {
        assert!(
            parse_profile_history_id(bad).is_err(),
            "malformed historyId must refuse, never bank into a bracket: {bad}"
        );
    }
    assert!(
        parse_list_page(r#"{"messages":[{"id":""}]}"#).is_err(),
        "an empty message id is not an id"
    );
    assert!(
        parse_list_page(r#"{"messages":[{"id":"m1"}],"nextPageToken":""}"#).is_err(),
        "a present-but-empty page token is malformed, not a continuation"
    );
}

#[test]
fn probe_parser_distinguishes_omitted_empty_and_present() {
    assert_eq!(
        probe_parse_minimal(r#"{"id":"m1"}"#, "m1").expect("omitted parses"),
        None,
        "labelIds omitted on the wire is Omitted, not empty"
    );
    assert_eq!(
        probe_parse_minimal(r#"{"id":"m1","labelIds":[]}"#, "m1").expect("empty parses"),
        Some(Vec::new()),
        "labelIds present-but-empty is Present([])"
    );
    assert_eq!(
        probe_parse_minimal(r#"{"id":"m1","labelIds":["INBOX","UNREAD"]}"#, "m1")
            .expect("present parses"),
        Some(vec!["INBOX".to_string(), "UNREAD".to_string()])
    );
    assert!(
        probe_parse_minimal(r#"{"labelIds":["INBOX"]}"#, "m1").is_err(),
        "a response with no id cannot classify an arm"
    );
    assert!(
        probe_parse_minimal(r#"{"id":"other","labelIds":["INBOX"]}"#, "m1").is_err(),
        "a response for a different message must never classify an arm"
    );
    assert!(
        probe_parse_minimal(r#"{"id":"m1","labelIds":"INBOX"}"#, "m1").is_err(),
        "a non-array labelIds is unreadable, not empty"
    );
}

#[test]
fn probe_classification_follows_the_design_table() {
    let labels = |list: &[&str]| list.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    assert_eq!(
        classify_probe_labels(&labels(&["INBOX", "UNREAD"])),
        ProbeVerdict::Inbox
    );
    assert_eq!(classify_probe_labels(&labels(&[])), ProbeVerdict::Archive);
    assert_eq!(
        classify_probe_labels(&labels(&["UNREAD", "STARRED", "CATEGORY_PERSONAL"])),
        ProbeVerdict::Archive,
        "placement-orthogonal labels are Archive when INBOX is absent"
    );
    // (design §4.4): TRASH and SPAM are IN model, each over INBOX, TRASH
    // over SPAM — the named derivation choice.
    for (label, verdict) in [("TRASH", ProbeVerdict::Trash), ("SPAM", ProbeVerdict::Spam)] {
        assert_eq!(classify_probe_labels(&labels(&[label])), verdict);
        assert_eq!(
            classify_probe_labels(&labels(&["INBOX", label])),
            verdict,
            "{label} dominates INBOX"
        );
    }
    assert_eq!(
        classify_probe_labels(&labels(&["SPAM", "TRASH"])),
        ProbeVerdict::Trash,
        "TRASH over SPAM"
    );
    // DRAFT is the ONE label still out of model, and it dominates every placement label.
    for companion in [None, Some("INBOX"), Some("TRASH"), Some("SPAM")] {
        let set: Vec<&str> = companion.into_iter().chain(["DRAFT"]).collect();
        assert_eq!(
            classify_probe_labels(&labels(&set)),
            ProbeVerdict::OutOfModel,
            "DRAFT dominates {companion:?} (any combination with DRAFT is out-of-model)"
        );
    }
    // Case-sensitivity: a lowercase 'inbox' is NOT the system label (mirrors the SUT's exact
    // byte-equality rule).
    assert_eq!(classify_probe_labels(&labels(&["inbox"])), ProbeVerdict::Archive);
}

// ---- Pagination quad-state --------------------------------------------------------------------

fn page(ids: &[&str], next: Option<&str>) -> ListPage {
    ListPage {
        ids: ids.iter().map(|s| s.to_string()).collect(),
        next_page_token: next.map(String::from),
    }
}

#[test]
fn pagination_finds_on_first_and_later_pages() {
    assert_eq!(
        bounded_search(|_| Ok(page(&["m1", "m2"], None))),
        SearchOutcome::Found("m1".to_string())
    );
    let mut calls = 0;
    let outcome = bounded_search(|token| {
        calls += 1;
        Ok(match (calls, token) {
            (1, None) => page(&[], Some("t1")),
            (2, Some("t1")) => page(&[], Some("t2")),
            (3, Some("t2")) => page(&["m3"], None),
            other => panic!("unexpected fetch sequence: {other:?}"),
        })
    });
    assert_eq!(outcome, SearchOutcome::Found("m3".to_string()));
    assert_eq!(calls, 3);
}

#[test]
fn pagination_exhaustion_bound_and_failure_are_distinct() {
    assert_eq!(
        bounded_search(|_| Ok(page(&[], None))),
        SearchOutcome::SearchExhausted,
        "no ids + no continuation = the mailbox really has no such message"
    );
    let mut calls = 0;
    let outcome = bounded_search(|_| {
        calls += 1;
        Ok(page(&[], Some("more")))
    });
    assert_eq!(
        outcome,
        SearchOutcome::BoundReached,
        "an endless continuation trips the bound — never reported as exhausted"
    );
    assert_eq!(calls, SEARCH_PAGE_BOUND);
    assert_eq!(
        bounded_search(|_| Err(DrillError::assertion_mismatch("fetch failed", "x"))),
        SearchOutcome::RequestFailed,
        "a failed request is a failure, never exhaustion"
    );
}

// ---- sanitizer fidelity --------------------------------------------------------------------

#[test]
fn sanitizer_fidelity_value_and_casing_plus_sensitive_absence() {
    // Byte-for-byte VALUE AND CASING equality
    // of every verdict-bearing field between the parsed raw capture and the sanitized
    // projection, PLUS explicit absence of the sensitive set. A value-redacting or
    // case-normalizing sanitizer fails here — casing is literally the R3_ERRORINFO_CASING
    // evidence, so a normalizing projection destroys the thing being recorded.
    let message_id = "18f0aSENSITIVEmsgid";
    let account = "drill-account@example.test";
    let token_fragment = "ya29.SENSITIVE-TOKEN";
    let legacy_raw = format!(
        r#"{{"error":{{"code":403,"errors":[{{"domain":"usageLimits","reason":"dailyLimitExceeded","message":"Quota for {account} on {message_id} with {token_fragment}","locationType":"header","location":"Authorization"}}],"message":"Quota for {account}"}}}}"#
    );
    let current_raw = format!(
        r#"{{"error":{{"code":403,"message":"Request had insufficient scopes for {account} reading {message_id}","status":"PERMISSION_DENIED","details":[{{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"ACCESS_TOKEN_SCOPE_INSUFFICIENT","domain":"googleapis.com","metadata":{{"service":"gmail.googleapis.com","email":"{account}"}}}},{{"@type":"type.googleapis.com/google.rpc.LocalizedMessage","locale":"en-US","message":"prose about {message_id}"}}]}}}}"#
    );

    for (name, raw) in [("legacy", &legacy_raw), ("current", &current_raw)] {
        let sanitized = sanitize_envelope(403, raw);
        let parsed: serde_json::Value = serde_json::from_str(raw).expect("fixture parses");
        let error = &parsed["error"];

        // Status + error.code
        assert_eq!(sanitized.status, 403, "{name}: status");
        assert_eq!(
            sanitized.error_code,
            error.get("code").and_then(|c| c.as_i64()),
            "{name}: error.code must survive exactly"
        );
        // Errors[].domain / errors[].reason — value AND casing, byte-for-byte.
        let raw_items: Vec<&serde_json::Value> = error
            .get("errors")
            .and_then(|e| e.as_array())
            .map(|a| a.iter().collect())
            .unwrap_or_default();
        assert_eq!(sanitized.legacy_errors.len(), raw_items.len(), "{name}: errors[] arity");
        for (got, raw_item) in sanitized.legacy_errors.iter().zip(&raw_items) {
            assert_eq!(
                got.domain.as_deref(),
                raw_item.get("domain").and_then(|d| d.as_str()),
                "{name}: errors[].domain must match byte-for-byte (value AND casing)"
            );
            assert_eq!(
                got.reason.as_deref(),
                raw_item.get("reason").and_then(|r| r.as_str()),
                "{name}: errors[].reason must match byte-for-byte (value AND casing)"
            );
        }
        // Error.status
        assert_eq!(
            sanitized.error_status.as_deref(),
            error.get("status").and_then(|s| s.as_str()),
            "{name}: error.status must match byte-for-byte"
        );
        // Details[] @type + ErrorInfo.reason
        let raw_details: Vec<&serde_json::Value> = error
            .get("details")
            .and_then(|d| d.as_array())
            .map(|a| a.iter().collect())
            .unwrap_or_default();
        assert_eq!(sanitized.details.len(), raw_details.len(), "{name}: details[] arity");
        for (got, raw_detail) in sanitized.details.iter().zip(&raw_details) {
            assert_eq!(
                got.type_url.as_deref(),
                raw_detail.get("@type").and_then(|t| t.as_str()),
                "{name}: details[].@type must match byte-for-byte"
            );
            let is_error_info = raw_detail
                .get("@type")
                .and_then(|t| t.as_str())
                .is_some_and(|t| t.ends_with("google.rpc.ErrorInfo"));
            if is_error_info {
                assert_eq!(
                    got.reason.as_deref(),
                    raw_detail.get("reason").and_then(|r| r.as_str()),
                    "{name}: ErrorInfo.reason must match byte-for-byte (value AND casing)"
                );
                // The service domain is evidence-bearing beside the reason and
                // must survive with the same fidelity.
                assert_eq!(
                    got.domain.as_deref(),
                    raw_detail.get("domain").and_then(|d| d.as_str()),
                    "{name}: ErrorInfo.domain must match byte-for-byte (value AND casing)"
                );
            } else {
                assert_eq!(
                    got.reason, None,
                    "{name}: non-ErrorInfo details carry no reason in the projection"
                );
                assert_eq!(
                    got.domain, None,
                    "{name}: non-ErrorInfo details carry no domain in the projection"
                );
            }
        }

        // Sensitive-absence: BOTH serialized forms — the struct dump and the CANONICAL recorded
        // bytes (the file/digest/replay stream) — must carry none of the sensitive set.
        let struct_form = serde_json::to_string(&sanitized).expect("projection serializes");
        let banked_form = canonical_banked_bytes(&sanitized);
        for sensitive in [message_id, account, token_fragment, "Quota for", "prose about"] {
            for (which, rendered) in [("struct", &struct_form), ("banked", &banked_form)] {
                assert!(
                    !rendered.contains(sensitive),
                    "{name}: sensitive content leaked into the {which} projection: {sensitive}"
                );
            }
        }
    }
}

#[test]
fn r3_casing_obligation_requires_observable_vocabulary() {
    // (the degenerate-value family at a PROOF-condition site): an ErrorInfo
    // whose `reason` is empty/whitespace exhibits NO casing — it must never prove
    // R3_ERRORINFO_CASING.
    let proved = sanitize_envelope(
        403,
        r#"{"error":{"code":403,"details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"ACCESS_TOKEN_SCOPE_INSUFFICIENT","domain":"googleapis.com"}]}}"#,
    );
    assert_eq!(error_info_casing_outcome(&proved), ProofOutcome::Proved);
    for degenerate in [
        r#"{"error":{"code":403,"details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"","domain":"googleapis.com"}]}}"#,
        r#"{"error":{"code":403,"details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"   ","domain":"googleapis.com"}]}}"#,
        // Case-LESS non-empty values: digits/underscores have no case.
        r#"{"error":{"code":403,"details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"123","domain":"googleapis.com"}]}}"#,
        r#"{"error":{"code":403,"details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"___","domain":"googleapis.com"}]}}"#,
        r#"{"error":{"code":403,"details":[{"@type":"type.googleapis.com/google.rpc.LocalizedMessage"}]}}"#,
        r#"{"error":{"code":403}}"#,
    ] {
        let sanitized = sanitize_envelope(403, degenerate);
        assert!(
            matches!(
                error_info_casing_outcome(&sanitized),
                ProofOutcome::Unavailable(_)
            ),
            "no observable vocabulary must never prove the casing obligation: {degenerate}"
        );
    }
}

#[test]
fn manifest_redacts_dirty_porcelain_paths() {
    // A dirty worktree's porcelain carries FILENAMES, and a filename can carry
    // a message id / address / token-like value — verbatim copying into the (smoke) manifest
    // violates the ID-free guarantee. Dirty ⇒ count-only marker; clean ⇒ verbatim empty proof.
    let sentinel = "SENTINEL-msg-18c2a4f9@drill.example.rs";
    let matrix = fully_proved_matrix();
    let bundle = bundle_for("tok-main", Some("tok-denial"), 1_700_000_000);
    let inputs = ManifestInputs {
        mode: DrillMode::Smoke,
        commit_sha: "smoke-head".to_string(),
        porcelain: format!(" M {sentinel}\n?? another-{sentinel}.txt"),
        porcelain_established: true,
        invocation: "test".to_string(),
        toolchain: "rustc test".to_string(),
        matrix: &matrix,
        observations: serde_json::Value::Array(Vec::new()),
        ledger: &[],
        bundle: &bundle,
        bundle_sha384: "b".repeat(96),
        sanitizer_sha384: "c".repeat(96),
        capture_digests: Vec::new(),
        red_controls: serde_json::Value::Null,
        now: 1_700_000_500,
    };
    let manifest = build_manifest(&inputs).expect("smoke manifest builds");
    let rendered = serde_json::to_string(&manifest).expect("serializes");
    assert!(
        !rendered.contains(sentinel),
        "a dirty filename must never reach the manifest bytes"
    );
    assert_eq!(manifest["clean_tree"], false);
    assert!(
        manifest["clean_tree_proof_porcelain"]
            .as_str()
            .expect("marker is a string")
            .contains("2 entries"),
        "the redacted marker still carries the entry count"
    );

    // An EMPTY porcelain from a FAILED `git status` is unverifiable, never
    // clean — the smoke manifest must say so rather than claim clean_tree: true.
    let mut unverifiable = inputs;
    unverifiable.porcelain = String::new();
    unverifiable.porcelain_established = false;
    let manifest = build_manifest(&unverifiable).expect("smoke manifest builds");
    assert_eq!(
        manifest["clean_tree"], false,
        "a failed status probe must never read as a clean tree"
    );
    assert!(
        manifest["clean_tree_proof_porcelain"]
            .as_str()
            .expect("marker is a string")
            .contains("UNVERIFIABLE"),
        "the proof field names the unverifiable state"
    );
}

#[test]
fn sanitizer_banks_error_info_fields_only_for_exact_type_matches() {
    // (the dual-reader class, again): the sanitizer's predicate was
    // case-INSENSITIVE (`…google.rpc.errorinfo` matched) while production
    // `ErrorDetail::is_error_info` is an exact case-sensitive suffix match — so the sanitizer
    // recorded provider-controlled `reason`/`domain` from a detail the SUT treats as UNKNOWN,
    // widening the sensitive-field projection beyond §4.3.1's enumeration. Both readers now
    // apply the SAME predicate.
    let mixed_case = r#"{"error":{"code":403,"details":[{"@type":"type.googleapis.com/google.rpc.ERRORINFO","reason":"PROVIDER_CONTROLLED","domain":"provider.example"}]}}"#;
    let sanitized = sanitize_envelope(403, mixed_case);
    assert_eq!(sanitized.details.len(), 1, "the detail itself is still enumerated");
    assert_eq!(
        sanitized.details[0].reason, None,
        "a non-exact @type must never have its reason banked (production treats it unknown)"
    );
    assert_eq!(
        sanitized.details[0].domain, None,
        "a non-exact @type must never have its domain banked"
    );
    // The exact production casing still records both, value and casing intact.
    let exact = r#"{"error":{"code":403,"details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"ACCESS_TOKEN_SCOPE_INSUFFICIENT","domain":"googleapis.com"}]}}"#;
    let sanitized = sanitize_envelope(403, exact);
    assert_eq!(
        sanitized.details[0].reason.as_deref(),
        Some("ACCESS_TOKEN_SCOPE_INSUFFICIENT")
    );
    assert_eq!(sanitized.details[0].domain.as_deref(), Some("googleapis.com"));
}

#[test]
fn sanitizer_survives_a_malformed_body() {
    let sanitized = sanitize_envelope(502, "utterly not json");
    assert_eq!(sanitized.status, 502);
    assert_eq!(sanitized.error_code, None);
    assert!(sanitized.legacy_errors.is_empty() && sanitized.details.is_empty());
}

// ---- ProofId accounting + closure gate ---------------------------------------------------------

fn fully_proved_matrix() -> ProofMatrix {
    let mut matrix = ProofMatrix::default();
    for id in MANDATORY_PROOFS {
        // Every PROVED rides with its recorded capture digest.
        matrix.record_proved(
            id,
            &format!("cap_{}", id.name().to_ascii_lowercase()),
            &sha384_hex(id.name().as_bytes()),
        );
    }
    // The two CONDITIONAL obligations, both UNAVAILABLE — the state the attended run actually
    // produced (design §4.0): no ErrorInfo on the wire, and no zero-label message reachable.
    matrix.record(
        ProofId::R3ErrorInfoCasing,
        ProofOutcome::Unavailable("no ErrorInfo on wire"),
    );
    matrix.record(
        ProofId::A2EncodingObserved,
        ProofOutcome::Unavailable(A2_NO_ZERO_LABEL_REASON),
    );
    matrix
}

#[test]
fn closure_passes_with_both_conditional_obligations_unavailable() {
    // A2 joins R3_ERRORINFO_CASING as a
    // CONDITIONAL obligation, so a run where neither wire state exists still closes.
    fully_proved_matrix().closure_verdict().expect(
        "all-mandatory-PROVED closes; both conditional items may stay UNAVAILABLE",
    );
}

#[test]
fn a2_proved_still_closes_when_a_candidate_is_found() {
    // The conditional path must NOT weaken the observation when it IS available: a future run
    // that finds a zero-label candidate still records PROVED, with its capture, and closes.
    let mut matrix = fully_proved_matrix();
    matrix
        .outcomes
        .retain(|(id, _)| *id != ProofId::A2EncodingObserved);
    matrix.record_proved(
        ProofId::A2EncodingObserved,
        "a2_encoding_capture",
        &sha384_hex(b"a2"),
    );
    matrix.a2_observation = Some(EncodingObservation::Omitted);
    matrix.a2_inference = Some(Inference::ClosedNoChange);
    matrix
        .closure_verdict()
        .expect("A2 PROVED closes exactly as before the amendment");
    assert_eq!(
        matrix.capture_of(ProofId::A2EncodingObserved).map(|(n, _)| n),
        Some("a2_encoding_capture"),
        "a PROVED A2 still carries its banked capture"
    );
}

#[test]
fn closure_is_incomplete_on_a_failed_or_missing_mandatory_obligation() {
    // A FAILED mandatory obligation blocks closure…
    let mut failed = fully_proved_matrix();
    failed.outcomes.retain(|(id, _)| *id != ProofId::R3Scope403);
    failed
        .proved_captures
        .retain(|(id, _, _)| *id != ProofId::R3Scope403);
    failed.record(ProofId::R3Scope403, ProofOutcome::Failed);
    let verdict = failed.closure_verdict().expect_err("FAILED cannot close");
    assert!(
        verdict.contains("INCOMPLETE") && verdict.contains("R3_SCOPE_403"),
        "the INCOMPLETE verdict names the unproved obligation: {verdict}"
    );

    // …an UNAVAILABLE MANDATORY one blocks closure (smoke-only reporting is never citable)…
    let mut unavailable = fully_proved_matrix();
    unavailable.outcomes.retain(|(id, _)| *id != ProofId::R1Spam);
    unavailable.record(ProofId::R1Spam, ProofOutcome::Unavailable("SearchExhausted"));
    assert!(
        unavailable.closure_verdict().is_err(),
        "closure makes all five R1 arms mandatory — UNAVAILABLE cannot close"
    );

    // …and a mandatory obligation that never ran at all blocks closure identically.
    let mut missing = fully_proved_matrix();
    missing.outcomes.retain(|(id, _)| *id != ProofId::R3Scope403);
    let verdict = missing
        .closure_verdict()
        .expect_err("an un-run mandatory obligation cannot close");
    assert!(verdict.contains("R3_SCOPE_403"));
}

#[test]
fn a_failed_conditional_obligation_still_blocks_closure() {
    // CONDITIONAL ≠ OPTIONAL. UNAVAILABLE is an honest non-observation (the wire state did not
    // exist); FAILED means it WAS reachable and the assertion did not hold — a broken claim,
    // which must never close a run, for EITHER conditional obligation.
    for conditional in [ProofId::A2EncodingObserved, ProofId::R3ErrorInfoCasing] {
        let mut matrix = fully_proved_matrix();
        matrix.outcomes.retain(|(id, _)| *id != conditional);
        matrix.record(conditional, ProofOutcome::Failed);
        let verdict = matrix
            .closure_verdict()
            .unwrap_err_or_panic(conditional.name());
        assert!(
            verdict.contains(conditional.name()),
            "the INCOMPLETE verdict names the failed conditional: {verdict}"
        );
    }
}

/// Tiny helper so the loop above reads as a witness rather than as unwrap plumbing.
trait UnwrapErrOrPanic {
    fn unwrap_err_or_panic(self, context: &str) -> String;
}
impl UnwrapErrOrPanic for Result<(), String> {
    fn unwrap_err_or_panic(self, context: &str) -> String {
        match self {
            Ok(()) => panic!("a FAILED conditional obligation ({context}) must NOT close"),
            Err(verdict) => verdict,
        }
    }
}

#[test]
fn the_mandatory_set_is_the_designs_six() {
    // Pin the compiled constant against the design table (§4.0) — a drive-by edit to the
    // mandatory set must break a test, not just a doc. SIX, since
    // A2_ENCODING_OBSERVED joined R3_ERRORINFO_CASING as a
    // CONDITIONAL obligation.
    let names: Vec<&str> = MANDATORY_PROOFS.iter().map(|p| p.name()).collect();
    assert_eq!(
        names,
        vec![
            "R1_INBOX",
            "R1_ARCHIVE",
            "R1_TRASH",
            "R1_SPAM",
            "R1_DRAFT",
            "R3_SCOPE_403"
        ]
    );
    for conditional in [ProofId::R3ErrorInfoCasing, ProofId::A2EncodingObserved] {
        assert!(
            !MANDATORY_PROOFS.contains(&conditional),
            "{} is conditional (§4.2/§4.3), never mandatory",
            conditional.name()
        );
    }
}

#[test]
fn manifest_links_every_proved_obligation_to_a_recorded_capture_digest() {
    // Design §0: a PROVED entry with no recorded
    // capture digest behind it is exactly "the evidence manifest claims a wire behavior with
    // no recorded capture digest behind it". Every PROVED row must link its capture.
    let now = 1_800_000_000;
    let bundle = bundle_for("tok-main-A", None, now);
    let matrix = fully_proved_matrix();
    let inputs = ManifestInputs {
        mode: DrillMode::Smoke,
        commit_sha: "0".repeat(40),
        porcelain: String::new(),
        porcelain_established: true,
        invocation: "hermetic".to_string(),
        toolchain: "hermetic".to_string(),
        matrix: &matrix,
        observations: serde_json::json!([]),
        ledger: &[],
        bundle: &bundle,
        bundle_sha384: "b".repeat(96),
        sanitizer_sha384: "c".repeat(96),
        capture_digests: Vec::new(),
        red_controls: serde_json::Value::Null,
        now,
    };
    let manifest = build_manifest(&inputs).expect("a fully capture-linked matrix manifests");
    // Per-token digest recording: both tokens are LIVE at this `now`, so
    // neither digest may be recorded — the bundle digest alone carries the binding.
    assert!(
        manifest["attestation"]["main_token_sha384"].is_null()
            && manifest["attestation"]["denial_token_sha384"].is_null(),
        "a live token's digest must never be banked"
    );
    for row in manifest["proof_matrix"].as_array().expect("matrix rows") {
        if row["outcome"] == "Proved" {
            assert!(
                row["capture"]["sha384"].is_string(),
                "falsification sentinel (b): a PROVED obligation must link a banked capture \
                 digest: {row}"
            );
        }
    }

    // …and a PROVED smuggled in WITHOUT a capture makes the manifest REFUSE to build at all.
    // (record() itself panics on Proved — witnessed below — so the only way to even construct
    // this state is direct field access, and the manifest still refuses it.)
    let mut unbacked = fully_proved_matrix();
    unbacked
        .proved_captures
        .retain(|(id, _, _)| *id != ProofId::R1Trash);
    let refusing_inputs = ManifestInputs {
        matrix: &unbacked,
        capture_digests: Vec::new(),
        observations: serde_json::json!([]),
        red_controls: serde_json::Value::Null,
        mode: DrillMode::Smoke,
        commit_sha: "0".repeat(40),
        porcelain: String::new(),
        porcelain_established: true,
        invocation: "hermetic".to_string(),
        toolchain: "hermetic".to_string(),
        ledger: &[],
        bundle: &bundle,
        bundle_sha384: "b".repeat(96),
        sanitizer_sha384: "c".repeat(96),
        now,
    };
    let refusal = build_manifest(&refusing_inputs)
        .expect_err("a Proved-without-capture manifest must be constructible-refused");
    assert!(
        refusal.contains("R1_TRASH"),
        "the refusal names the unbacked obligation: {refusal}"
    );

    // Per-token recording, the other direction: denial expired while main is
    // live — ONLY the denial digest is recorded.
    let mut split_expiry = bundle_for("tok-main-A", Some("tok-denial-A"), now);
    split_expiry.expires_at_denial = Some(now - 10);
    let split_matrix = fully_proved_matrix();
    let split_inputs = ManifestInputs {
        matrix: &split_matrix,
        bundle: &split_expiry,
        capture_digests: Vec::new(),
        observations: serde_json::json!([]),
        red_controls: serde_json::Value::Null,
        mode: DrillMode::Smoke,
        commit_sha: "0".repeat(40),
        porcelain: String::new(),
        porcelain_established: true,
        invocation: "hermetic".to_string(),
        toolchain: "hermetic".to_string(),
        ledger: &[],
        bundle_sha384: "b".repeat(96),
        sanitizer_sha384: "c".repeat(96),
        now,
    };
    let split_manifest = build_manifest(&split_inputs).expect("manifests");
    assert!(
        split_manifest["attestation"]["main_token_sha384"].is_null(),
        "the still-live main token's digest must not ride the denial's expiry"
    );
    assert!(
        split_manifest["attestation"]["denial_token_sha384"].is_string(),
        "the EXPIRED denial token's digest banks"
    );

    // The census must PRESERVE each row's destination host — host identity is
    // part of the request-ledger evidence (compiled Gmail host vs loopback), and a census without it
    // cannot show where a request went.
    let census_ledger = [
        entry("GET", "users/me/profile"),
        entry_with_host("GET", "127.0.0.1", "users/me/messages"),
    ];
    let census_inputs = ManifestInputs {
        matrix: &matrix,
        ledger: &census_ledger,
        capture_digests: Vec::new(),
        observations: serde_json::json!([]),
        red_controls: serde_json::Value::Null,
        mode: DrillMode::Smoke,
        commit_sha: "0".repeat(40),
        porcelain: String::new(),
        porcelain_established: true,
        invocation: "hermetic".to_string(),
        toolchain: "hermetic".to_string(),
        bundle: &bundle,
        bundle_sha384: "b".repeat(96),
        sanitizer_sha384: "c".repeat(96),
        now,
    };
    let census_manifest = build_manifest(&census_inputs).expect("manifests");
    let census = census_manifest["w3_request_census"]
        .as_array()
        .expect("census rows");
    assert_eq!(census[0]["host"], "gmail.googleapis.com", "census rows carry the host");
    assert_eq!(census[1]["host"], "127.0.0.1");

    // The recording API itself refuses a bare PROVED.
    let bare = std::panic::catch_unwind(|| {
        let mut m = ProofMatrix::default();
        m.record(ProofId::R1Inbox, ProofOutcome::Proved);
    });
    assert!(bare.is_err(), "record() must panic on Proved — record_proved is the only door");
}

// ---- Manifest: clean-tree predicate ------------------------------------------------------------

fn clean_detached_state() -> RepoState {
    RepoState {
        porcelain_exit_ok: true,
        porcelain: String::new(),
        head_attachment: Some(HeadAttachment::Detached),
        sha_exit_ok: true,
        head_sha: "0123456789abcdef0123456789abcdef01234567".to_string(),
        repo_root: Some(PathBuf::from("/repo")),
    }
}

#[test]
fn closure_repo_gate_requires_success_cleanliness_detachment_and_a_real_sha() {
    // , hermetic by injection: exit codes + outputs are DATA here.
    closure_repo_verdict(&clean_detached_state()).expect("clean + detached + real SHA closes");

    // A FAILED porcelain command must never read as a clean tree.
    let mut failed_git = clean_detached_state();
    failed_git.porcelain_exit_ok = false;
    assert!(closure_repo_verdict(&failed_git).is_err());

    // A dirty tree refuses.
    let mut dirty = clean_detached_state();
    dirty.porcelain = "?? stray.txt\n".to_string();
    assert!(closure_repo_verdict(&dirty).is_err());

    // HEAD on a branch (symbolic-ref succeeded) refuses — closure runs DETACHED (design §4.5).
    let mut attached = clean_detached_state();
    attached.head_attachment = Some(HeadAttachment::Attached);
    assert!(closure_repo_verdict(&attached).is_err());

    // A failed or malformed recorded SHA refuses.
    let mut no_sha = clean_detached_state();
    no_sha.sha_exit_ok = false;
    assert!(closure_repo_verdict(&no_sha).is_err());
    for bad in ["", "abc123", "GIT-UNAVAILABLE", "0123456789ABCDEF0123456789ABCDEF01234567"] {
        let mut bad_sha = clean_detached_state();
        bad_sha.head_sha = bad.to_string();
        assert!(
            closure_repo_verdict(&bad_sha).is_err(),
            "not a full lowercase object name: {bad:?}"
        );
    }
}

#[test]
fn closure_refuses_every_unestablishable_gate_input() {
    // The battery:
    // in closure mode, any failure to ESTABLISH a fact the gate depends on must REFUSE. Each
    // input is driven to failure in turn; every one must refuse, and the fully-established
    // baseline must still pass (non-vacuity).
    closure_repo_verdict(&clean_detached_state()).expect("baseline: everything established");

    // 1. porcelain command failed (exit code, not just empty output)
    let mut s = clean_detached_state();
    s.porcelain_exit_ok = false;
    assert!(closure_repo_verdict(&s).is_err(), "unestablishable porcelain must refuse");

    // 2. the tree is dirty
    let mut s = clean_detached_state();
    s.porcelain = " M crates/aruna-gmail/src/transport.rs\n".to_string();
    assert!(closure_repo_verdict(&s).is_err(), "a dirty tree must refuse");

    // 3. HEAD/detached probe says ATTACHED
    let mut s = clean_detached_state();
    s.head_attachment = Some(HeadAttachment::Attached);
    assert!(closure_repo_verdict(&s).is_err(), "an attached HEAD must refuse");

    // 4. SHA read failed
    let mut s = clean_detached_state();
    s.sha_exit_ok = false;
    assert!(closure_repo_verdict(&s).is_err(), "an unreadable SHA must refuse");

    // 5. SHA is a sentinel rather than an object name
    let mut s = clean_detached_state();
    s.head_sha = "GIT-UNAVAILABLE".to_string();
    assert!(closure_repo_verdict(&s).is_err(), "a sentinel SHA must refuse");

    // 6. REPO ROOT could not be established (was a fail-OPEN: the evidence
    //    worktree-containment check vanished entirely).
    let mut s = clean_detached_state();
    s.repo_root = None;
    let reason = closure_repo_verdict(&s).expect_err("an unestablishable repo root must refuse");
    assert!(
        reason.contains("repository root") && reason.contains("containment"),
        "the refusal names what could not be established: {reason}"
    );

    // 7. evidence-dir resolution failure — its full battery lives in the evidence_dir_* tests;
    //    here we assert it is a REFUSAL, not a skip.
    assert!(
        resolve_evidence_dir(
            Path::new("relative/evidence"),
            RepoRootKnowledge::UnknownSmokeOnly,
            None
        )
        .is_err(),
        "an unresolvable evidence dir must refuse"
    );

    // 8. THE PRINCIPLE ITSELF: establish_or_refuse panics in closure, degrades in smoke.
    let closure_panics = std::panic::catch_unwind(|| {
        establish_or_refuse::<u8>(DrillMode::Closure, "a fact", Err("unavailable".to_string()))
    });
    assert!(
        closure_panics.is_err(),
        "closure must PANIC on an unestablishable fact, never return None"
    );
    assert_eq!(
        establish_or_refuse::<u8>(DrillMode::Smoke, "a fact", Err("unavailable".to_string())),
        None,
        "smoke degrades loudly (never citable), it does not abort"
    );
    assert_eq!(
        establish_or_refuse(DrillMode::Closure, "a fact", Ok(7u8)),
        Some(7),
        "an established fact passes through unchanged"
    );
}

#[test]
fn head_probe_failure_never_reads_as_detached() {
    // Close 1 — the same fail-open class, in a construct an earlier sweep's
    // grep missed: `is_ok_and(|o| o.status.success())` maps BOTH "the probe failed" and "HEAD
    // is genuinely detached" to `false`, so a probe failure read as detached and closure could
    // pass without ever establishing detachment.
    //
    // Real probe outcomes, produced by actually running processes (no hand-built statuses):
    let run = |args: &[&str]| std::process::Command::new(args[0]).args(&args[1..]).output();

    // Exit 0 ⇒ ATTACHED (closure refuses).
    let exit0 = run(&["git", "--version"]);
    assert_eq!(
        interpret_head_probe(&exit0),
        Some(HeadAttachment::Attached),
        "a successful symbolic-ref means HEAD names a branch"
    );

    // Exit 1 ⇒ DETACHED (the documented `-q` answer; closure proceeds).
    let exit1 = run(&["git", "symbolic-ref", "-q", "refs/heads/definitely-not-a-symref"]);
    if matches!(&exit1, Ok(o) if o.status.code() == Some(1)) {
        assert_eq!(
            interpret_head_probe(&exit1),
            Some(HeadAttachment::Detached),
            "exit 1 is the documented `not a symbolic ref` answer"
        );
    }

    // A SPAWN FAILURE establishes nothing — and must NOT read as detached.
    let spawn_failure = run(&["definitely-not-a-real-binary-photon-r9"]);
    assert!(spawn_failure.is_err(), "fixture precondition: the spawn fails");
    assert_eq!(
        interpret_head_probe(&spawn_failure),
        None,
        "a spawn failure establishes NOTHING about HEAD"
    );

    // Another non-1 exit code (git's usage error) also establishes nothing.
    let other_exit = run(&["git", "symbolic-ref", "--this-flag-does-not-exist"]);
    if matches!(&other_exit, Ok(o) if o.status.code().is_some_and(|c| c != 0 && c != 1)) {
        assert_eq!(
            interpret_head_probe(&other_exit),
            None,
            "a non-0/1 exit code establishes NOTHING about HEAD"
        );
    }

    // …and closure REFUSES on the unestablished state, distinctly from the attached refusal.
    let mut unestablished = clean_detached_state();
    unestablished.head_attachment = None;
    let reason = closure_repo_verdict(&unestablished)
        .expect_err("an unestablished HEAD attachment must refuse");
    assert!(
        reason.contains("could not be established"),
        "the refusal says the probe established nothing, not that HEAD is attached: {reason}"
    );
    // The baseline (genuinely detached) still closes — non-vacuity.
    closure_repo_verdict(&clean_detached_state()).expect("a genuinely detached HEAD closes");
}

#[test]
fn effective_target_dir_comes_from_cargo_not_inference() {
    // A DEMONSTRATED bypass (real data loss was reproduced:
    // a `.cargo/config.toml` pointing at `build-cache`, then `cargo clean` DELETED a proof
    // file beneath it). The earlier basis was `CARGO_TARGET_DIR` else `<repo>/target`, which
    // cannot see `[build] target-dir` in `.cargo/config.toml` or `$CARGO_HOME/config.toml`.
    //
    // Driven with an INJECTED effective-target-dir value — real Cargo config is never mutated.
    let config_configured = "{\"target_directory\":\"/repo/build-cache\",\"packages\":[]}";

    // (the closure fail-open class, one more surviving site): with cargo
    // metadata UNAVAILABLE and no env var, the ladder used to answer `<repo>/target` — a
    // GUESS presented as success, which closure then accepted (`establish_or_refuse` refuses
    // only on Err). Under a configured `[build] target-dir` the guess is wrong and evidence
    // beneath the real target dir passes containment. A repo root is location knowledge, not
    // target-dir knowledge: no answer ⇒ Err, closure refuses, smoke proceeds warned.
    // (Before the fix this exact call returned Ok("/repo/target").)
    assert!(
        effective_target_dir_from(None, None).is_err(),
        "metadata unavailable + env unset must ERROR, never guess <repo>/target"
    );

    // The FOLD: Cargo's own answer is authoritative and DOES see the config file.
    assert_eq!(
        effective_target_dir_from(Some(config_configured), None).expect("cargo answered"),
        PathBuf::from("/repo/build-cache"),
        "cargo metadata's target_directory is the single authority"
    );
    // …and it wins over the env var too — Cargo has already folded that in.
    assert_eq!(
        effective_target_dir_from(Some(config_configured), Some(PathBuf::from("/somewhere/else")))
            .expect("cargo answered"),
        PathBuf::from("/repo/build-cache"),
        "cargo's answer already accounts for CARGO_TARGET_DIR; it is not overridden"
    );

    // Fallback ladder, only when cargo metadata is UNAVAILABLE: the env var is Cargo's own
    // override (it beats config files by Cargo's precedence), so it is a real answer.
    assert_eq!(
        effective_target_dir_from(None, Some(PathBuf::from("/env/target")))
            .expect("env fallback"),
        PathBuf::from("/env/target")
    );
    // Unusable cargo output is an ERROR, not a silent slide down the ladder — closure routes
    // this through establish_or_refuse and REFUSES.
    for unusable in [
        "not json at all",
        "{\"packages\":[]}",
        "{\"target_directory\":\"\"}",
        "{\"target_directory\":\"   \"}",
        "{\"target_directory\":42}",
    ] {
        assert!(
            effective_target_dir_from(Some(unusable), Some(PathBuf::from("/env"))).is_err(),
            "unusable cargo output must ERROR rather than fall back to a guess: {unusable}"
        );
    }

    // A CWD-RELATIVE override is ambiguous by construction — the outer
    // `cargo test` and this test's nested `cargo metadata` run from DIFFERENT cwds, so
    // `../build-cache` resolves to two different directories and the durability check can
    // guard the wrong one while `cargo clean` deletes recorded evidence. Refused at the
    // ladder, whichever source it arrives from. (The predicate is has_root(), not
    // is_absolute(): the ambiguity is cwd-resolution, and rooted-but-driveless fixture
    // paths must keep passing on Windows.)
    for relative in ["../build-cache", "build-cache"] {
        assert!(
            effective_target_dir_from(None, Some(PathBuf::from(relative))).is_err(),
            "a cwd-relative CARGO_TARGET_DIR must refuse: {relative}"
        );
        let metadata = format!("{{\"target_directory\":\"{relative}\",\"packages\":[]}}");
        assert!(
            effective_target_dir_from(Some(&metadata), None).is_err(),
            "a cwd-relative metadata answer must refuse: {relative}"
        );
    }

    // The configured dir then bites in the predicate: evidence beneath it REFUSES even though
    // no path component is literally named `target`.
    let tree = TempTree::new("cargometa");
    let checkout = tree.child("checkout");
    let build_cache = tree.child("build-cache");
    let evidence = tree.child("build-cache/proof");
    let metadata = format!(
        "{{\"target_directory\":{},\"packages\":[]}}",
        serde_json::to_string(&build_cache.to_string_lossy()).expect("json")
    );
    let effective = effective_target_dir_from(Some(&metadata), None)
        .expect("cargo answered with the configured dir");
    let reason = resolve_evidence_dir(
        &evidence,
        RepoRootKnowledge::Known(&checkout),
        Some(&effective),
    )
    .expect_err("evidence under the CONFIG-configured target dir must refuse");
    assert!(reason.contains("CONFIGURED target directory"), "{reason}");

    // …and the retired `<repo>/target` guess would have let exactly this through — the bypass,
    // demonstrated with the guess constructed literally (the ladder itself can no longer
    // produce it). `<checkout>/target` must exist for the comparison to run at
    // all, so the demonstration is of the WRONG BASIS rather than of an unresolvable one.
    tree.child("checkout/target");
    let guessed = checkout.join("target");
    resolve_evidence_dir(
        &evidence,
        RepoRootKnowledge::Known(&checkout),
        Some(&guessed),
    )
    .expect("THE BYPASS: guessing <repo>/target lets config-configured evidence through");
}

#[test]
fn evidence_dir_refuses_a_custom_cargo_target_dir() {
    // Close 2: the literal-`target`-component test passes a custom CARGO_TARGET_DIR
    // such as `D:\build-cache`, under which `cargo clean` would still erase recorded evidence.
    let tree = TempTree::new("cargotarget");
    let repo = tree.child("checkout");
    // A custom target dir whose name contains no `target` component at all.
    let custom_target = tree.child("build-cache");
    let evidence_under_target = tree.child("build-cache/photon-evidence");
    let safe_evidence = tree.child("parked-evidence");

    // Regression test: with only the component check (cargo_target_dir = None) this passes.
    resolve_evidence_dir(
        &evidence_under_target,
        RepoRootKnowledge::Known(&repo),
        None,
    )
    .expect("the component check alone cannot see a custom target dir (this is the defect)");

    // With Cargo's ACTUAL configured target dir supplied, it REFUSES.
    let reason = resolve_evidence_dir(
        &evidence_under_target,
        RepoRootKnowledge::Known(&repo),
        Some(&custom_target),
    )
    .expect_err("evidence under a custom CARGO_TARGET_DIR must refuse");
    assert!(
        reason.contains("CONFIGURED target directory"),
        "the refusal names the configured target dir: {reason}"
    );

    // The belt still catches the ordinary layout even with no configured dir known.
    let ordinary = tree.child("checkout/target/ev");
    assert!(
        resolve_evidence_dir(&ordinary, RepoRootKnowledge::Known(&repo), None).is_err(),
        "the cheap component check is retained"
    );

    // A genuinely safe dir still passes with the configured target dir supplied — non-vacuity.
    resolve_evidence_dir(
        &safe_evidence,
        RepoRootKnowledge::Known(&repo),
        Some(&custom_target),
    )
    .expect("an evidence dir outside both the worktree and the target dir passes");

    // An unresolvable configured target dir refuses rather than skipping the check.
    let missing_target = tree.0.join("never-created-target");
    assert!(
        resolve_evidence_dir(
            &safe_evidence,
            RepoRootKnowledge::Known(&repo),
            Some(&missing_target)
        )
        .is_err(),
        "an uncanonicalizable target dir must refuse, not silently skip durability"
    );
}

#[test]
fn closure_refuses_a_repository_that_changed_during_the_run() {
    // The manifest was built from the PRE-RUN state, so a change during the
    // operator-attended network run was invisible and the manifest went on certifying the old
    // clean tree and SHA — the manifest lying about the very property it exists to certify.
    let pre = clean_detached_state();

    // Unchanged and still clean ⇒ record.
    closure_final_repo_verdict(&pre, &clean_detached_state())
        .expect("an unchanged clean detached tree banks");

    // The tree went DIRTY during the run.
    let mut dirtied = clean_detached_state();
    dirtied.porcelain = "?? scripts/scratch.py\n".to_string();
    let reason = closure_final_repo_verdict(&pre, &dirtied)
        .expect_err("a tree that went dirty mid-run must refuse");
    assert!(
        reason.contains("re-checked AFTER the run"),
        "the refusal says WHEN it was detected: {reason}"
    );

    // HEAD MOVED during the run — reported with BOTH SHAs, never a silent overwrite.
    let mut moved = clean_detached_state();
    moved.head_sha = "fedcba9876543210fedcba9876543210fedcba98".to_string();
    let reason = closure_final_repo_verdict(&pre, &moved)
        .expect_err("a HEAD move mid-run must refuse");
    assert!(
        reason.contains("HEAD MOVED")
            && reason.contains(&pre.head_sha)
            && reason.contains(&moved.head_sha),
        "the refusal reports BOTH SHAs: {reason}"
    );

    // HEAD became attached mid-run.
    let mut attached = clean_detached_state();
    attached.head_attachment = Some(HeadAttachment::Attached);
    assert!(
        closure_final_repo_verdict(&pre, &attached).is_err(),
        "a HEAD that re-attached mid-run must refuse"
    );

    // The post-run probe itself failed.
    let mut unprobeable = clean_detached_state();
    unprobeable.porcelain_exit_ok = false;
    assert!(
        closure_final_repo_verdict(&pre, &unprobeable).is_err(),
        "an unprobeable post-run repo must refuse"
    );
}

#[test]
fn a2_candidate_scan_never_exceeds_its_cap() {
    // A short page plus a nextPageToken appended the NEXT page in full before
    // the cap was checked, so a nominal 25-candidate scan could probe up to 49. The extension
    // is now limited to remaining capacity. Quad-state semantics are untouched: `scan_end` is
    // still decided purely by whether the PROVIDER ended the listing.
    let mut candidates: Vec<u32> = Vec::new();
    let mut pages = 0;
    // Pages of 24 with a continuation each time — the shape that overran.
    while candidates.len() < A2_CANDIDATE_CAP && pages < SEARCH_PAGE_BOUND {
        let room = A2_CANDIDATE_CAP.saturating_sub(candidates.len());
        candidates.extend((0..24u32).take(room));
        pages += 1;
    }
    assert_eq!(
        candidates.len(),
        A2_CANDIDATE_CAP,
        "the scan collects exactly the cap, never a page-sized overshoot"
    );
    assert!(
        candidates.len() <= A2_CANDIDATE_CAP,
        "the cap is a CAP, not a soft target"
    );
    // The two scan endings still mean what they were defined to mean.
    // the provider ending the listing is exhaustion ONLY when nothing was
    // dropped — a truncated final page (more ids than remaining room) keeps BoundReached, so
    // the strong claim can never ride a scan that skipped candidates.
    assert_eq!(
        a2_final_page_scan_end(true),
        A2ScanEnd::BoundReached,
        "a truncated final page is OUR bound, never provider exhaustion"
    );
    assert_eq!(a2_final_page_scan_end(false), A2ScanEnd::Exhausted);
    assert_eq!(
        a2_no_candidate_outcome(a2_final_page_scan_end(true)).outcome,
        a2_no_candidate_outcome(A2ScanEnd::BoundReached).outcome,
        "…and it maps to the weak bound-reached reason, not the strong one"
    );

    assert_eq!(
        a2_no_candidate_outcome(A2ScanEnd::Exhausted).outcome,
        ProofOutcome::Unavailable(A2_NO_ZERO_LABEL_REASON)
    );
    assert_eq!(
        a2_no_candidate_outcome(A2ScanEnd::BoundReached).outcome,
        ProofOutcome::Unavailable(A2_BOUND_REACHED_REASON)
    );
}

/// A throwaway real directory tree for the containment battery — the rules are enforced
/// against the FILESYSTEM now (existence + canonicalization are the construction), so the
/// witnesses use real paths rather than injected strings. Self-cleaning per test:
/// the root is the engine's ONE guard (`aruna::test_temp`), unique per call (it was
/// pid + wall-clock SECONDS), removed on `Drop` without following a link, a leak a loud failure.
struct TempTree(aruna::test_temp::TempDir);

impl TempTree {
    fn new(tag: &str) -> Self {
        Self(aruna::test_temp::TempDir::new(&format!("photon-evdir-{tag}")))
    }
    fn child(&self, rel: &str) -> PathBuf {
        let path = self.0.join(rel);
        std::fs::create_dir_all(&path).expect("create child");
        path
    }
}

#[test]
fn evidence_dir_refuses_worktree_target_and_rootless_paths() {
    // All enforced through the ONE constructed rule.
    let tree = TempTree::new("rules");
    let repo = tree.child("checkout");
    let outside = tree.child("parked-evidence");

    resolve_evidence_dir(&outside, RepoRootKnowledge::Known(&repo), None).expect("an existing dir outside the repo passes");

    let inside = tree.child("checkout/evidence");
    assert!(
        resolve_evidence_dir(&inside, RepoRootKnowledge::Known(&repo), None).is_err(),
        "inside the worktree refuses"
    );
    let inside_target = tree.child("checkout/target/ev");
    assert!(
        resolve_evidence_dir(&inside_target, RepoRootKnowledge::Known(&repo), None).is_err(),
        "inside the repo's target refuses"
    );
    let foreign_target = tree.child("elsewhere/target/ev");
    assert!(
        resolve_evidence_dir(&foreign_target, RepoRootKnowledge::Known(&repo), None).is_err(),
        "ANY cargo target dir refuses — `cargo clean` must never erase evidence"
    );
    // Rootless (CWD-resolving) refuses whether or not it happens to exist.
    assert!(
        resolve_evidence_dir(Path::new("relative/evidence"), RepoRootKnowledge::UnknownSmokeOnly, None).is_err(),
        "a relative evidence dir must refuse"
    );
    assert!(
        resolve_evidence_dir(Path::new("./evidence"), RepoRootKnowledge::Known(&repo), None).is_err(),
        "a dot-relative evidence dir must refuse"
    );
    // With no repo root known, only the existence + target rules apply.
    resolve_evidence_dir(&outside, RepoRootKnowledge::UnknownSmokeOnly, None).expect("no repo root known: the dir still resolves");
}

#[test]
fn evidence_dir_containment_is_canonical_to_canonical() {
    // The construction, witnessed: because the dir must EXIST, both sides of the comparison
    // are canonical, so no spelling difference (extended-path/UNC/8.3/junction/case) can
    // split them. A dir directly under the checkout is caught however it is spelled.
    let tree = TempTree::new("canon");
    let repo = tree.child("checkout");
    let inside = tree.child("checkout/nested/evidence");

    // Spelled canonically…
    assert!(resolve_evidence_dir(&inside, RepoRootKnowledge::Known(&repo), None).is_err());
    // …spelled with `.` and `..` traversal (a different string, the same directory)…
    let traversed = tree.0.join("checkout").join(".").join("nested/../nested/evidence");
    assert!(
        resolve_evidence_dir(&traversed, RepoRootKnowledge::Known(&repo), None).is_err(),
        "a traversal spelling of the same in-worktree dir must refuse identically"
    );
    // …and with the ROOT given in its already-canonical form while the dir is not.
    let canonical_repo = std::fs::canonicalize(&repo).expect("canonicalize repo");
    assert!(
        resolve_evidence_dir(&traversed, RepoRootKnowledge::Known(&canonical_repo), None).is_err(),
        "mixed canonical/plain spellings on the two sides must not split the comparison"
    );
    // The returned path is canonical, so the run records into a normalized location.
    let outside = tree.child("parked");
    let resolved = resolve_evidence_dir(&outside, RepoRootKnowledge::Known(&repo), None).expect("resolves");
    assert_eq!(
        resolved,
        std::fs::canonicalize(&outside).expect("canonicalize outside"),
        "resolve_evidence_dir returns the CANONICAL dir"
    );
}

#[test]
fn r4_one_canonical_serialization_backs_digest_and_replay() {
    // (Before the fix the live record serialized with to_string_pretty while the
    // corpus replay recomputed with to_string — two byte streams, two irreconcilable digests).
    // Now ONE canonical serialization backs the recorded file, its digest, the recorded
    // taxonomy, and the replay recompute.
    let raw = r#"{"error":{"code":403,"errors":[{"domain":"global","reason":"forbidden"}],"status":"PERMISSION_DENIED"}}"#;
    let sanitized = sanitize_envelope(403, raw);
    let banked = canonical_banked_bytes(&sanitized);
    // Deterministic: the same projection always yields the same bytes and digest.
    assert_eq!(
        sha384_hex(banked.as_bytes()),
        sha384_hex(canonical_banked_bytes(&sanitized).as_bytes())
    );
    // Fixed point: sanitizing the recorded bytes re-records IDENTICAL bytes, so a replay's
    // recompute can never diverge from the recorded digest.
    let reparsed = sanitize_envelope(403, &banked);
    assert_eq!(
        canonical_banked_bytes(&reparsed),
        banked,
        "the canonical banked bytes must be a fixed point of sanitize→bank"
    );
    // Replayable taxonomy: the recorded bytes classify to a definite verdict —
    // the same one an auditor recomputes from the capture. (This fixture restates 403 as
    // PERMISSION_DENIED beside a legacy `forbidden`, so the whole envelope refines Forbidden.)
    assert_eq!(map_error_response(403, &banked), GmailError::Forbidden);
}

#[test]
fn red_control_requires_a_healthy_inbox_repeat_read() {
    // The control's whole job is a DEMONSTRATED discrimination — only a
    // healthy repeat read that derives Inbox proves the wrong claim (Archive) false. An
    // errored read proves nothing and must never count as went-red.
    assert!(
        red_control_went_red(&Ok(Placement::Inbox)),
        "a healthy Inbox read demonstrates the wrong claim false"
    );
    assert!(
        !red_control_went_red(&Ok(Placement::Archive)),
        "the wrong claim HELD: control failure"
    );
    assert!(
        !red_control_went_red(&Err(aruna::ConnectorError::deterministic("read failed"))),
        "an ERRORED repeat read proves nothing — never went-red"
    );
    assert!(
        !red_control_went_red(&Err(aruna::ConnectorError::transient("read failed"))),
        "a transient failure proves nothing either"
    );
}

#[test]
fn probe_list_parser_fails_closed_on_malformed_entries() {
    // A malformed listing is a FAILURE of the oracle, never an empty page —
    // an empty page upstream becomes SearchExhausted, and in closure "the mailbox has no such
    // message" must never be manufactured out of bytes we could not read.
    assert!(
        parse_list_page(r#"{"messages":"not-an-array"}"#).is_err(),
        "a non-array messages member must fail closed"
    );
    assert!(
        parse_list_page(r#"{"messages":[{"id":42}]}"#).is_err(),
        "a non-string id must fail closed"
    );
    assert!(
        parse_list_page(r#"{"messages":[{"threadId":"t-only"}]}"#).is_err(),
        "an entry with no id must fail closed"
    );
    assert!(
        parse_list_page(r#"{"messages":[{"id":"m1"}],"nextPageToken":7}"#).is_err(),
        "a non-string nextPageToken must fail closed"
    );
    // A NON-OBJECT 2xx body must be a typed failure too — `Value::get` on an
    // array/null/string returns None for every key, which read as a legitimate empty page
    // (and, upstream, SearchExhausted out of bytes that were never a listing at all).
    for non_object in ["[]", "null", "\"a string\"", "3", "true"] {
        assert!(
            parse_list_page(non_object).is_err(),
            "a non-object list response must fail closed: {non_object}"
        );
    }
    // …while the legitimate shapes stay readable.
    let empty = parse_list_page("{}").expect("an ABSENT messages member is a real empty page");
    assert!(empty.ids.is_empty() && empty.next_page_token.is_none());
    let page = parse_list_page(r#"{"messages":[{"id":"m1"},{"id":"m2"}],"nextPageToken":"t"}"#)
        .expect("a well-formed page parses");
    assert_eq!(page.ids, vec!["m1".to_string(), "m2".to_string()]);
    assert_eq!(page.next_page_token.as_deref(), Some("t"));
}

#[test]
fn evidence_dir_must_already_exist_and_be_canonicalizable() {
    // STOP
    // patching path-normalization edges — Windows normalization (extended-path/UNC/8.3/
    // junction/case) is an unbounded space and per-edge patching cannot terminate. The class
    // is closed BY CONSTRUCTION instead: the evidence dir must ALREADY EXIST and be
    // canonicalizable, so both sides of the containment comparison are canonical by
    // construction and no un-normalized prefix comparison exists anywhere.
    // A guarded, never-created name — absent by construction, owned all the same.
    let nonexistent = aruna::test_temp::TempDir::uncreated("photon-r3-never-created");
    assert!(!nonexistent.exists(), "fixture precondition");
    assert!(
        resolve_evidence_dir(&nonexistent, RepoRootKnowledge::UnknownSmokeOnly, None).is_err(),
        "a NONEXISTENT evidence dir must REFUSE (the operator pre-creates the parked dir) — \
         accepting it is the bypass: the dir is created after the clean-tree gate has passed"
    );
    // …including one directly under the repo checkout, which is the exact shape the earlier
    // finding named (created post-gate, recording in-worktree evidence under a clean claim).
    let tree = TempTree::new("nonexistent");
    let repo = tree.child("checkout");
    let never_made = repo.join("evidence");
    assert!(!never_made.exists(), "fixture precondition");
    assert!(
        resolve_evidence_dir(&never_made, RepoRootKnowledge::Known(&repo), None).is_err(),
        "a nonexistent dir under the checkout must refuse — never be created after the gate"
    );
    // The refusal TELLS the operator what to do (the runbook + design §4.5 instruction).
    let reason = resolve_evidence_dir(&nonexistent, RepoRootKnowledge::UnknownSmokeOnly, None).expect_err("refuses");
    assert!(
        reason.contains("create the parked evidence directory first"),
        "the refusal must instruct the operator: {reason}"
    );
}

/// This file's two recorded label forms — the capture
/// projection (list order kept) and the ripple rows' set form — are the ENGINE's rule
/// (`aruna::prestate::banked_label_split`), not a copy that could drift from it: over label sets
/// that probe the rule's edges, both agree with the engine's split.
#[test]
fn the_recorded_label_forms_are_the_engines_rule() {
    let sets: [&[&str]; 6] = [
        &["INBOX", "CATEGORY_PERSONAL", "Label_2384950192"],
        &["UNREAD", "IMPORTANT", "Label_1", "Label_22"],
        &["lowercase", "Mixed_Case", "SPAM"],
        &["CATEGORY_UPDATES", "STARRED", "TRASH", "DRAFT", "SENT"],
        &["A-B", "A B", "Ä", "X1_2"],
        &[],
    ];
    for labels in sets {
        let set: BTreeSet<String> = labels.iter().map(|l| l.to_string()).collect();
        let (named, counted) = banked_label_split(&set);
        let list: Vec<String> = set.iter().cloned().collect();
        let capture = sanitize_minimal_capture(Some(&list));
        assert_eq!(capture.system_labels, named, "{labels:?}");
        assert_eq!(capture.other_label_count, counted, "{labels:?}");
        assert_eq!(
            bank_label_set(&set),
            serde_json::json!({ "system_labels": named, "other_label_count": counted }),
            "{labels:?}"
        );
    }
}

#[test]
fn minimal_capture_projection_is_id_free_and_encoding_faithful() {
    // The R1/A2 capture form: encoding distinguished, system labels exact,
    // user labels counted never named.
    let omitted = sanitize_minimal_capture(None);
    assert_eq!(omitted.encoding, "omitted");
    assert!(omitted.system_labels.is_empty() && omitted.other_label_count == 0);

    let labels = vec![
        "INBOX".to_string(),
        "CATEGORY_PERSONAL".to_string(),
        "Label_2384950192".to_string(), // provider-native user-label id — must never be named
    ];
    let present = sanitize_minimal_capture(Some(&labels));
    assert_eq!(present.encoding, "present");
    assert_eq!(
        present.system_labels,
        vec!["INBOX".to_string(), "CATEGORY_PERSONAL".to_string()]
    );
    assert_eq!(present.other_label_count, 1);
    let banked = serde_json::to_string(&present).expect("serializes");
    assert!(
        !banked.contains("Label_2384950192"),
        "a provider-native user-label id leaked into the capture"
    );

    let empty = sanitize_minimal_capture(Some(&[]));
    assert_eq!(empty.encoding, "present", "Present([]) is not Omitted — A2's whole point");
}

#[test]
fn porcelain_args_pin_untracked_files() {
    // `status.showUntrackedFiles=no` (repo or global) makes a bare
    // `--porcelain` print NOTHING for a tree whose only changes are untracked — the clean-tree
    // gate would pass and the manifest would claim a clean tree over untracked source. The
    // explicit flag overrides the config, and this pins it so it cannot be dropped later.
    assert!(
        PORCELAIN_ARGS.contains(&"--untracked-files=all"),
        "the closure gate's git invocation MUST pass --untracked-files=all: {PORCELAIN_ARGS:?}"
    );
    assert!(PORCELAIN_ARGS.contains(&"--porcelain") && PORCELAIN_ARGS[0] == "status");

    // Executable proof that the flag actually overrides the config: ask git itself, with the
    // hostile setting injected via -c, whether it still reports an untracked file.
    let tree = TempTree::new("untracked");
    let repo = tree.0.to_path_buf();
    let git = |args: &[&str]| {
        std::process::Command::new("git")
            .current_dir(&repo)
            .args(args)
            .output()
    };
    let Ok(init) = git(&["init"]) else {
        eprintln!("porcelain flag witness SKIPPED LOUDLY: git not runnable here");
        return;
    };
    if !init.status.success() {
        eprintln!("porcelain flag witness SKIPPED LOUDLY: `git init` failed");
        return;
    }
    std::fs::write(repo.join("untracked-source.rs"), b"fn main() {}").expect("write untracked");

    // The hostile config alone hides it…
    let mut hidden_args = vec!["-c", "status.showUntrackedFiles=no", "status", "--porcelain"];
    let hidden = git(&hidden_args).expect("git status");
    let hidden_out = String::from_utf8_lossy(&hidden.stdout).to_string();
    assert!(
        porcelain_is_clean(&hidden_out),
        "precondition: showUntrackedFiles=no hides the untracked file (else this is vacuous)"
    );

    // …and OUR invocation still sees it.
    hidden_args.push("--untracked-files=all");
    let seen = git(&hidden_args).expect("git status");
    let seen_out = String::from_utf8_lossy(&seen.stdout).to_string();
    assert!(
        !porcelain_is_clean(&seen_out),
        "with --untracked-files=all the untracked file must still make the tree DIRTY, even \
         under status.showUntrackedFiles=no: {seen_out:?}"
    );
}

#[test]
fn r3_scope_403_requires_the_bracket_to_hold_on_both_sides() {
    // Regression test: probe-403 + SUT-401. The SUT's own status is invisible
    // (fetch_placement collapses to one id-free ConnectorError), so the expiry is caught by
    // the POST-SUT probe capture: a credential that died across the window reads 401 there.
    assert_eq!(
        r3_scope_403_verdict(403, Some(401), FailureKind::Deterministic, true),
        ProofOutcome::Failed,
        "probe-403 then SUT then probe-401 (credential expired across the window) must FAIL — \
         the design's own 401 ⇒ FAILED rule (§4.3.3)"
    );
    assert_eq!(
        r3_scope_403_verdict(403, Some(404), FailureKind::Deterministic, true),
        ProofOutcome::Failed,
        "404 on the bracket's far side must FAIL"
    );
    assert_eq!(
        r3_scope_403_verdict(403, Some(200), FailureKind::Deterministic, true),
        ProofOutcome::Failed,
        "a SUCCESS on the far side means the denial credential is not denying — FAILED"
    );
    assert_eq!(
        r3_scope_403_verdict(403, None, FailureKind::Deterministic, true),
        ProofOutcome::Failed,
        "an unobtainable far-side capture cannot close the bracket — FAILED, never Proved"
    );
    assert_eq!(
        r3_scope_403_verdict(401, Some(403), FailureKind::Deterministic, true),
        ProofOutcome::Failed,
        "the NEAR side must be 403 too"
    );
    // The standing conjuncts still bite.
    assert_eq!(
        r3_scope_403_verdict(403, Some(403), FailureKind::Transient, true),
        ProofOutcome::Failed,
        "a Transient classification must NEVER prove the scope-denial arm"
    );
    assert_eq!(
        r3_scope_403_verdict(403, Some(403), FailureKind::Deterministic, false),
        ProofOutcome::Failed,
        "the SUT must have refused deterministically with no placement"
    );
    // Only a bracket that holds on BOTH sides, with a deterministic SUT refusal, proves.
    assert_eq!(
        r3_scope_403_verdict(403, Some(403), FailureKind::Deterministic, true),
        ProofOutcome::Proved
    );
}

#[test]
fn clean_tree_predicate_over_injected_porcelain() {
    // Hermetic by injection (never by mutating the repo): closure refuses on ANY surviving
    // porcelain line — tracked, staged, or untracked (design §4.5).
    assert!(porcelain_is_clean(""));
    assert!(porcelain_is_clean("\n  \n"));
    assert!(!porcelain_is_clean("?? scripts/new_file.py\n"));
    assert!(!porcelain_is_clean(" M crates/aruna-gmail/src/transport.rs\n"));
    assert!(!porcelain_is_clean("A  staged_file.rs\n?? other.txt\n"));
}

// ---- R4: characterization pin, corpus table, semantic mutants ---------------------------------

#[test]
fn r4_a2_characterization_absent_and_present_empty_derive_the_same_placement() {
    // CHARACTERIZATION, not endorsement (design §4.4 — Feathers/golden-master
    // pattern, exempt from the differential rule): TODAY, `labelIds` OMITTED and `labelIds: []`
    // derive the SAME placement (Archive) through the public read path. The design keeps the
    // distinction TYPED so a future flip of `Absent` to an error costs one match arm — gated on
    // a live A2 observation. This pin exists so that flip must break a test DELIBERATELY,
    // never silently. Exercised over a real loopback exchange through the PUBLIC SUT surface
    // (`GmailProviderPlacement`), because the derivation internals are rightly private.
    let absent = sut_placement_for_body(r#"{"id":"drill-msg"}"#)
        .expect("omitted labelIds derives a placement today");
    let present_empty = sut_placement_for_body(r#"{"id":"drill-msg","labelIds":[]}"#)
        .expect("empty labelIds derives a placement today");
    assert_eq!(absent, Placement::Archive);
    assert_eq!(present_empty, Placement::Archive);
    assert_eq!(
        absent, present_empty,
        "the A2 equivalence this slice leaves open: breaking it must be a deliberate act"
    );
}

/// One digest-keyed live-capture fixture (design §4.4): the sanitized envelope's sha384 keys the
/// row; only DISTINCT verdict-bearing shapes enter the corpus.
struct CorpusFixture {
    /// Sha384 of the sanitized-envelope JSON recorded by the attended run.
    sanitized_sha384: &'static str,
    status: u16,
    /// The SANITIZED body replayed through the classifier (raw captures never enter the repo).
    body: &'static str,
    expected: GmailError,
    /// Which ProofId(s) this capture backed in the run that produced it.
    proof_ids: &'static str,
    /// The recorded capture's file name inside [`LIVE_RUN_DIR`].
    capture_name: &'static str,
}

// ===============================================================================================
// PROVENANCE of every row below — the attended CLOSURE run that produced them.
// ===============================================================================================

/// The implementation commit the closure run executed at (detached HEAD, clean tree) — the
/// merge, so the run exercised the `{gmail.modify}` product credential with its
/// `grant_generation` bound to the ratchet at preflight.
const LIVE_RUN_COMMIT_SHA: &str = "ca857c12c806eee5a9ce66c80f0b8e0649b577d7";
/// The run's evidence subdirectory name; the sanitized copies are committed under
/// `docs/evidence/2026-07-gmail-live-readside-drill/` (the directory name keeps the drill's
/// 2026-07 birth date; the CURRENT recorded run is this 2026-09-03 one, the credential-migration
/// re-discharge — it superseded the 2026-08-05 run, which had superseded 2026-07-26).
const LIVE_RUN_DIR: &str = "run-1788413993-36108";

/// POPULATED from the attended CLOSURE run (design §4.4 sequencing: drill run → fixtures →
/// PR-ready, all in this PR). `body` holds the CANONICAL recorded bytes
/// ([`canonical_banked_bytes`]) — the same bytes the digest and the recorded taxonomy bind to,
/// copied from the recorded file, never retyped.
///
/// RE-RECORDED 2026-09-03 from the attended closure run at [`LIVE_RUN_COMMIT_SHA`] — the
/// re-discharge: the same matrix re-derived on the real host under the product's
/// `gmail.modify` credential. The R3 denial envelope came back BYTE-IDENTICAL to the
/// 2026-08-05 capture (same sha384; the denial slot carries zero Gmail scope, so the main
/// slot's scope change cannot touch it) and carries the same wire vocabulary the 2026-07-26
/// run observed (that run recorded in an earlier form, so its digest is not comparable at
/// the byte); the row below is therefore unchanged in bytes.
///
/// (History: the 2026-08-05 re-record moved the corpus to the sha384 status-bound canonical
/// form — the live run reproduced the derived R3 bytes byte-identically, and
/// `committed_evidence_binds_fixture_file_and_manifest` re-opened with the proof-matrix
/// binding. That run is superseded by this one; git holds its evidence set.)
///
/// ONE row: the run recorded exactly one verdict-bearing ERROR-ENVELOPE shape (the R3 denial).
/// The five R1 captures are minimal-message projections, a different artifact type — they are
/// replayed by [`LIVE_MINIMAL_CAPTURES`] below, and copied into the evidence directory too.
const LIVE_CAPTURE_CORPUS: &[CorpusFixture] = &[CorpusFixture {
    // === THE `error.rs:892` ANSWER — first recorded 2026-07-26 on the drill account (run
    // `787d5eed…`); the bytes below are the CURRENT run's ([`LIVE_RUN_DIR`]), which reproduced
    // the 2026-08-05 capture byte-identically ===
    //
    // Error.rs:892 stated: "The attended drill must observe real ErrorInfo.reason casing on the
    // wire before the vocabulary is assumed disjoint by channel." OBSERVED, on a real Gmail
    // scope-denial 403 — this envelope carries BOTH channels at once:
    //
    //   legacy    `errors[].reason`            = "insufficientPermissions"        (lowerCamel)
    //   current   `details[].ErrorInfo.reason` = "ACCESS_TOKEN_SCOPE_INSUFFICIENT" (UPPER_SNAKE)
    //             `details[].ErrorInfo.domain` = "googleapis.com"
    //             `error.status`               = "PERMISSION_DENIED"
    //
    // So the two channels ARE disjoint in vocabulary on this wire, in one response.
    //
    // ⚠ NOT A LICENCE TO MAP IT. The standing non-goal (design §1, "NO ErrorInfo-vocabulary
    // enumeration") HOLDS: this is an OBSERVATION recorded for a future REVIEWED mapping
    // decision, never a reason to add ACCESS_TOKEN_SCOPE_INSUFFICIENT to the classifier here.
    // The replay below asserts the CURRENT behavior: the unsourced UPPER_SNAKE reason grades
    // Unrecognized and DOMINATES, so the whole envelope fails closed to `Unknown` —
    // Deterministic, visible, and exactly what §4.3 says must PASS ("never asserts
    // GmailError::Forbidden; an Unknown from modern vocabulary stays fail-closed and PASSES").
    sanitized_sha384: "6f942068de5e6e8d39731d7330fbb5d5670d2d3a1ba215cb2ac0370bce0271f16052183cb524c324fd4bff5e8c393636",
    status: 403,
    body: r#"{"error":{"code":403,"details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","domain":"googleapis.com","reason":"ACCESS_TOKEN_SCOPE_INSUFFICIENT"}],"errors":[{"domain":"global","reason":"insufficientPermissions"}],"status":"PERMISSION_DENIED"},"status":403}"#,
    expected: GmailError::Unknown,
    proof_ids: "R3_SCOPE_403 + R3_ERRORINFO_CASING",
    capture_name: "r3_denial_envelope.json",
}];

/// One recorded R1 read-oracle capture: the ID-free minimal-message projection
/// ([`sanitize_minimal_capture`]) the run keyed that arm's PROVED to.
struct MinimalCaptureFixture {
    sanitized_sha384: &'static str,
    /// The recorded projection bytes, copied from the file (pretty-printed by the run).
    body: &'static str,
    /// The placement the SUT must derive from this label set — `None` = typed rejection
    /// (the out-of-model partition).
    expected: Option<Placement>,
    proof_id: &'static str,
    capture_name: &'static str,
}

/// The five R1 arms, populated from the attended closure run. Each row replays: the digest
/// binds, the projection is a fixed point of its own sanitizer, and the witnessed label set
/// still derives the placement the table expects — a full re-derivation of the read-oracle
/// table from live evidence, hermetically. For R1_INBOX / R1_ARCHIVE / R1_DRAFT that
/// expectation is what the arm recorded live; for R1_TRASH / R1_SPAM it moved with the
/// model (see those rows) — the capture bytes did not.
const LIVE_MINIMAL_CAPTURES: &[MinimalCaptureFixture] = &[
    MinimalCaptureFixture {
        // 2026-09-03: discovery picked a different inbox candidate than the 2026-08-05 run
        // (`UNREAD` in place of `IMPORTANT`); both label sets derive `Placement::Inbox`. The
        // other four R1 captures came back byte-identical across the two runs.
        sanitized_sha384: "d94837d01e375238ba8b3dec67779c221b25c39310173a95eab96f12df1c5fdaa0eda5178bb5dc46958597dae32c99b4",
        body: "{\n  \"encoding\": \"present\",\n  \"system_labels\": [\n    \"UNREAD\",\n    \"CATEGORY_UPDATES\",\n    \"INBOX\"\n  ],\n  \"other_label_count\": 0\n}",
        expected: Some(Placement::Inbox),
        proof_id: "R1_INBOX",
        capture_name: "r1_r1_inbox_capture.json",
    },
    MinimalCaptureFixture {
        // The Archive arm's live evidence: SENT-only — the documented model-compression arm
        // (archived IS the absence of INBOX), not a positive "archive" label.
        sanitized_sha384: "2500e1a12836a356dc980ae8412e4ed1235edf67c17c8aeee5cb8f610334d454269f5496cd23b2104dd0073daa00e764",
        body: "{\n  \"encoding\": \"present\",\n  \"system_labels\": [\n    \"SENT\"\n  ],\n  \"other_label_count\": 0\n}",
        expected: Some(Placement::Archive),
        proof_id: "R1_ARCHIVE",
        capture_name: "r1_r1_archive_capture.json",
    },
    MinimalCaptureFixture {
        // The capture bytes are the 2026-09-03 closure run's, UNCHANGED (the ID-free projection
        // of the `labelIds` that run observed). The EXPECTATION changed 2026-09-24 with the
        // model ("derivation maps TRASH⇒Trash"): through M1 this
        // ProofId meant "refused as out-of-model", which is what that run recorded; it now means
        // "placed in Trash", which only the next attended run can prove live.
        sanitized_sha384: "e2b828eac924bf753f1aad8de6fb9fdd34b4675bbdb131787d72d0d2a989dcda005e1c69eba3ec6b4fd18a3ca673b15f",
        body: "{\n  \"encoding\": \"present\",\n  \"system_labels\": [\n    \"UNREAD\",\n    \"TRASH\",\n    \"CATEGORY_UPDATES\"\n  ],\n  \"other_label_count\": 0\n}",
        expected: Some(Placement::Trash),
        proof_id: "R1_TRASH",
        capture_name: "r1_r1_trash_capture.json",
    },
    MinimalCaptureFixture {
        // As R1_TRASH above: capture bytes UNCHANGED from the 2026-09-03 run; the EXPECTATION
        // changed 2026-09-24 with the new model ("SPAM⇒Spam") —
        // from "refused as out-of-model" (what that run recorded) to "placed in Spam".
        sanitized_sha384: "076fc247adb32fb22165cbb228595aacde35dd7b0a7dee5b354cf4f4aeddf0c7fc2a9bf13ec74ac1be78964e216e9875",
        body: "{\n  \"encoding\": \"present\",\n  \"system_labels\": [\n    \"UNREAD\",\n    \"CATEGORY_UPDATES\",\n    \"SPAM\"\n  ],\n  \"other_label_count\": 0\n}",
        expected: Some(Placement::Spam),
        proof_id: "R1_SPAM",
        capture_name: "r1_r1_spam_capture.json",
    },
    MinimalCaptureFixture {
        sanitized_sha384: "6bff73851db7fd912261011a66fd63314f3285927dfa23d0daa4934374184862a67c0fffd159b7394730d2952bcc725a",
        body: "{\n  \"encoding\": \"present\",\n  \"system_labels\": [\n    \"DRAFT\"\n  ],\n  \"other_label_count\": 0\n}",
        expected: None,
        proof_id: "R1_DRAFT",
        capture_name: "r1_r1_draft_capture.json",
    },
];

// GATE CLOSED 2026-07-26 by the FIRST attended CLOSURE run (`787d5eed…`); the corpus has since
// been re-recorded twice (2026-08-05 `e091b32a…`, then the CURRENT run at LIVE_RUN_COMMIT_SHA)
// and its recorded captures populate the corpus, so the `#[ignore]` is GONE and this runs by default.
// The non-vacuity guard STAYS: it still protects against a future edit that
// empties the corpus, which would otherwise make this a silent vacuous green again.
#[test]
fn r4_live_capture_corpus_replays_with_matching_digests() {
    assert!(
        !LIVE_CAPTURE_CORPUS.is_empty(),
        "the corpus is empty — a replay over zero cases proves nothing and must never \
         report green (codex r2 P1-3)"
    );
    for fixture in LIVE_CAPTURE_CORPUS {
        // Digest binding: the row's bytes ARE the recorded bytes (one canonical serialization —
        // ).
        assert_eq!(
            sha384_hex(fixture.body.as_bytes()),
            fixture.sanitized_sha384,
            "corpus row digest must match its banked capture bytes"
        );
        // Fixed point: the row really is a canonical sanitized projection — re-sanitizing and
        // re-recording it reproduces the identical bytes.
        let reparsed = sanitize_envelope(fixture.status, fixture.body);
        assert_eq!(
            canonical_banked_bytes(&reparsed),
            fixture.body,
            "corpus row must be a fixed point of the canonical banked serialization"
        );
        // Status binding: the digested bytes EMBED the transport status, and it must be
        // the same status the row replays with — a divergent hand-edit cannot survive both
        // this and the fixed point above.
        let embedded: serde_json::Value =
            serde_json::from_str(fixture.body).expect("banked bytes parse");
        assert_eq!(
            embedded["status"],
            serde_json::json!(fixture.status),
            "the banked bytes' embedded status must equal the row's replay status"
        );
        // Replay: the recorded taxonomy is the verdict OF THE RECORDED BYTES.
        assert_eq!(
            map_error_response(fixture.status, fixture.body),
            fixture.expected,
            "corpus replay verdict for {} ({})",
            fixture.capture_name,
            fixture.proof_ids
        );
        // …and the taxonomy the classifier hands the engine is Deterministic for every recorded
        // denial shape: a scope refusal must never enter a retry loop.
        assert_eq!(
            classify_gmail_error(&map_error_response(fixture.status, fixture.body)),
            FailureKind::Deterministic,
            "a banked denial envelope must classify Deterministic"
        );
    }
}

#[test]
fn r4_live_error_info_channels_are_disjoint_in_vocabulary() {
    // THE `error.rs:892` ANSWER, asserted rather than merely commented (first observed
    // 2026-07-26 on the drill account, run `787d5eed…`; re-observed byte-identically on the
    // CURRENT closure run at LIVE_RUN_COMMIT_SHA). One real Gmail scope-denial 403
    // carries BOTH channels, and their vocabularies do not overlap:
    //   legacy  errors[].reason            = insufficientPermissions        (lowerCamel)
    //   current ErrorInfo.reason           = ACCESS_TOKEN_SCOPE_INSUFFICIENT (UPPER_SNAKE)
    //
    // ⚠ NOT a licence to map the UPPER_SNAKE reason — design §1's "NO ErrorInfo-vocabulary
    // enumeration" stands. This pins the OBSERVATION so a future reviewed mapping decision
    // starts from evidence, and so a silent change to the recorded artifact breaks a test.
    let row = LIVE_CAPTURE_CORPUS
        .iter()
        .find(|f| f.capture_name == "r3_denial_envelope.json")
        .expect("the R3 denial envelope is banked");
    let sanitized = sanitize_envelope(row.status, row.body);

    let legacy_reasons: Vec<&str> = sanitized
        .legacy_errors
        .iter()
        .filter_map(|e| e.reason.as_deref())
        .collect();
    assert_eq!(legacy_reasons, vec!["insufficientPermissions"]);
    assert!(
        legacy_reasons[0].chars().next().is_some_and(char::is_lowercase),
        "the legacy channel's vocabulary is lowerCamel"
    );

    let error_info: Vec<(&str, &str)> = sanitized
        .details
        .iter()
        .filter(|d| {
            d.type_url
                .as_deref()
                .is_some_and(|t| t.ends_with("google.rpc.ErrorInfo"))
        })
        .filter_map(|d| Some((d.reason.as_deref()?, d.domain.as_deref()?)))
        .collect();
    assert_eq!(
        error_info,
        vec![("ACCESS_TOKEN_SCOPE_INSUFFICIENT", "googleapis.com")]
    );
    assert!(
        error_info[0].0.chars().all(|c| c.is_ascii_uppercase() || c == '_'),
        "the ErrorInfo channel's vocabulary is UPPER_SNAKE"
    );
    assert_eq!(sanitized.error_status.as_deref(), Some("PERMISSION_DENIED"));

    // Disjoint: neither channel's observed reason appears in the other's vocabulary…
    assert_ne!(legacy_reasons[0], error_info[0].0);
    // …and the UPPER_SNAKE reason remains UNSOURCED to the classifier, so the whole envelope
    // still fails closed. Asserting this is what keeps the non-goal honest: if someone adds
    // ACCESS_TOKEN_SCOPE_INSUFFICIENT to the vocabulary without a reviewed decision, THIS
    // breaks.
    assert_eq!(map_error_response(row.status, row.body), GmailError::Unknown);
}

#[test]
fn r4_live_minimal_captures_replay_the_read_oracle_table() {
    // The five R1 arms, re-derived from the run's recorded ID-free projections: the digest
    // binds, the projection is a fixed point of its own sanitizer, and the witnessed label
    // set derives the placement the table expects (R1_TRASH / R1_SPAM: the current model, not
    // the earlier outcome the run recorded) — through the PUBLIC SUT surface over a real loopback
    // exchange.
    assert_eq!(
        LIVE_MINIMAL_CAPTURES.len(),
        5,
        "all five R1 arms are banked (non-vacuity)"
    );
    for fixture in LIVE_MINIMAL_CAPTURES {
        assert_eq!(
            sha384_hex(fixture.body.as_bytes()),
            fixture.sanitized_sha384,
            "minimal-capture digest must match the banked file for {}",
            fixture.capture_name
        );
        let parsed: serde_json::Value =
            serde_json::from_str(fixture.body).expect("banked projection parses");
        // ID-free by construction, re-asserted on the committed bytes.
        assert_eq!(parsed["other_label_count"], 0);
        assert_eq!(parsed["encoding"], "present");
        let labels: Vec<String> = parsed["system_labels"]
            .as_array()
            .expect("system_labels")
            .iter()
            .map(|l| l.as_str().expect("label is a string").to_string())
            .collect();

        // Fixed point: re-sanitizing the reconstructed label set re-records identical bytes.
        // (Sound because `other_label_count == 0` — nothing was elided from the projection.)
        let rebuilt = sanitize_minimal_capture(Some(&labels));
        assert_eq!(
            serde_json::to_string_pretty(&rebuilt).expect("serializes"),
            fixture.body,
            "{} must be a fixed point of sanitize_minimal_capture",
            fixture.capture_name
        );

        // …and the live label set still derives the arm's recorded outcome through the SUT.
        let body = serde_json::json!({ "id": "drill-msg", "labelIds": labels }).to_string();
        match fixture.expected {
            Some(placement) => assert_eq!(
                sut_placement_for_body(&body).expect("the arm derived a placement live"),
                placement,
                "{} ({}) must derive the table's expected placement",
                fixture.capture_name,
                fixture.proof_id
            ),
            None => {
                let err = sut_placement_for_body(&body)
                    .expect_err("an out-of-model arm derives no placement");
                assert_eq!(
                    err.kind,
                    FailureKind::Deterministic,
                    "{} ({}) must re-derive a DETERMINISTIC typed rejection",
                    fixture.capture_name,
                    fixture.proof_id
                );
            }
        }
    }
}

#[test]
fn the_probe_table_the_arm_table_and_the_sut_agree_on_every_placement_row() {
    // Moved TRASH/SPAM in model on THREE surfaces that must move together: the probe's
    // independent table (`classify_probe_labels`), the live drill's arm table (`R1_ARMS`), and
    // the SUT's derivation (read through the public surface). The attended drill only compares
    // them LIVE, so a drift between any two would first show up as a failed attended run; this
    // pins the agreement hermetically. The arm row match (`sut_outcome_for_arm`) has its own
    // witness, next.
    fn as_placement(verdict: ProbeVerdict) -> Option<Placement> {
        match verdict {
            ProbeVerdict::Inbox => Some(Placement::Inbox),
            ProbeVerdict::Archive => Some(Placement::Archive),
            ProbeVerdict::Trash => Some(Placement::Trash),
            ProbeVerdict::Spam => Some(Placement::Spam),
            ProbeVerdict::OutOfModel => None,
        }
    }
    let owned = |list: &[&str]| list.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    let partition_identity = canonical_out_of_model_error();

    // (1) Probe ↔ SUT, over every row the table keys on and each precedence pair.
    for set in [
        &["INBOX"][..],
        &[],
        &["SENT"],
        &["TRASH"],
        &["SPAM"],
        &["INBOX", "TRASH"],
        &["INBOX", "SPAM"],
        &["SPAM", "TRASH"],
        &["DRAFT"],
        &["INBOX", "DRAFT"],
        &["TRASH", "DRAFT"],
        &["SPAM", "DRAFT"],
    ] {
        let labels = owned(set);
        let body = serde_json::json!({ "id": "drill-msg", "labelIds": labels }).to_string();
        let sut = match sut_placement_for_body(&body) {
            Ok(placement) => Some(placement),
            Err(e) => {
                assert_eq!(
                    e, partition_identity,
                    "{set:?}: a SUT refusal here must be the out-of-model partition's identity"
                );
                None
            }
        };
        assert_eq!(
            as_placement(classify_probe_labels(&labels)),
            sut,
            "the probe's table and the SUT's derivation disagree on {set:?}"
        );
    }

    // (2) Arm table ↔ oracle table ↔ probe, per R1 arm, over the recorded live captures.
    for arm in R1_ARMS {
        let name = arm.proof.name();
        let fixture = LIVE_MINIMAL_CAPTURES
            .iter()
            .find(|f| f.proof_id == name)
            .unwrap_or_else(|| panic!("{name} has a banked read-oracle capture"));
        assert_eq!(
            as_placement(arm.expectation),
            fixture.expected,
            "{name}: the live arm's expectation and the read-oracle row disagree"
        );
        let parsed: serde_json::Value =
            serde_json::from_str(fixture.body).expect("banked projection parses");
        let labels: Vec<String> = parsed["system_labels"]
            .as_array()
            .expect("system_labels")
            .iter()
            .map(|l| l.as_str().expect("label is a string").to_string())
            .collect();
        assert_eq!(
            classify_probe_labels(&labels),
            arm.expectation,
            "{name}: the probe must classify the banked live capture to the arm's row"
        );
    }
}

#[test]
fn the_arm_row_match_places_trash_and_spam_and_refuses_every_mismatch() {
    // The live drill's row match (`sut_outcome_for_arm`), driven hermetically. Previously the
    // TRASH/SPAM arms demanded a typed refusal; they now demand the placement, and a refusal
    // there — the M1 outcome — must FAIL the arm, as must any cross-row placement.
    let partition = canonical_out_of_model_error();
    let owned = |list: &[&str]| list.iter().map(|s| s.to_string()).collect::<Vec<String>>();
    let rows: [(ProbeVerdict, &[&str], Placement, &str); 4] = [
        (ProbeVerdict::Trash, &["UNREAD", "TRASH"], Placement::Trash, "Placement::Trash"),
        (ProbeVerdict::Spam, &["SPAM"], Placement::Spam, "Placement::Spam"),
        (ProbeVerdict::Inbox, &["INBOX"], Placement::Inbox, "Placement::Inbox"),
        (ProbeVerdict::Archive, &["SENT"], Placement::Archive, "Placement::Archive"),
    ];
    for (expectation, labels, placement, outcome) in rows {
        let slice = owned(labels);
        let probe: Result<Option<Vec<String>>, DrillError> = Ok(Some(slice.clone()));
        assert_eq!(
            sut_outcome_for_arm(expectation, &probe, &slice, &Ok(placement))
                .unwrap_or_else(|_| panic!("{expectation:?}: the SUT's {placement:?} is the row")),
            outcome
        );
        assert!(
            sut_outcome_for_arm(expectation, &probe, &slice, &Err(partition.clone())).is_err(),
            "{expectation:?}: a refusal where the row expects a placement must fail the arm"
        );
        for wrong in [
            Placement::Inbox,
            Placement::Archive,
            Placement::Trash,
            Placement::Spam,
        ] {
            if wrong != placement {
                assert!(
                    sut_outcome_for_arm(expectation, &probe, &slice, &Ok(wrong)).is_err(),
                    "{expectation:?}: a {wrong:?} placement is another row's and must fail the arm"
                );
            }
        }
    }
    // The Archive arm's label-set assertion still holds for the labels moved in model.
    for present in ["TRASH", "SPAM"] {
        let slice = owned(&[present]);
        let probe: Result<Option<Vec<String>>, DrillError> = Ok(Some(slice.clone()));
        let archive = Ok(Placement::Archive);
        assert!(
            sut_outcome_for_arm(ProbeVerdict::Archive, &probe, &slice, &archive).is_err(),
            "an Archive placement beside a probe-witnessed {present} must fail the archive arm"
        );
    }
    // The out-of-model arm is DRAFT's alone: the partition's refusal proves it, any placement
    // fails it.
    let slice = owned(&["DRAFT"]);
    let probe: Result<Option<Vec<String>>, DrillError> = Ok(Some(slice.clone()));
    let refused = Err(partition.clone());
    sut_outcome_for_arm(ProbeVerdict::OutOfModel, &probe, &slice, &refused)
        .unwrap_or_else(|_| panic!("a probe-witnessed DRAFT refused with the partition identity"));
    for placement in [
        Placement::Inbox,
        Placement::Archive,
        Placement::Trash,
        Placement::Spam,
    ] {
        assert!(
            sut_outcome_for_arm(ProbeVerdict::OutOfModel, &probe, &slice, &Ok(placement)).is_err(),
            "a {placement:?} placement cannot prove the out-of-model arm"
        );
    }
}

#[test]
fn a2_bound_reached_never_asserts_unreachability() {
    // An HONESTY defect: a capped search (page full, `nextPageToken` still
    // present) discarded the quad-state and recorded the STRONG claim "no zero-label message
    // reachable", which is stronger than what the drill observed ("none in the first N
    // results"). The design's A2 amendment partly rests on the drill's own reporting, so the
    // claim must match the measurement exactly.
    let exhausted = a2_no_candidate_outcome(A2ScanEnd::Exhausted);
    let capped = a2_no_candidate_outcome(A2ScanEnd::BoundReached);

    // The provider ended the listing ⇒ the strong claim is earned.
    assert_eq!(
        exhausted.outcome,
        ProofOutcome::Unavailable(A2_NO_ZERO_LABEL_REASON)
    );
    // OUR bound stopped it ⇒ a DISTINCT outcome that asserts nothing about unreachability.
    assert_eq!(
        capped.outcome,
        ProofOutcome::Unavailable(A2_BOUND_REACHED_REASON)
    );
    assert_ne!(
        exhausted.outcome, capped.outcome,
        "the two scan endings must NOT collapse to one claim"
    );

    // The strong string must be UNREACHABLE from a capped scan — structurally, not by
    // convention. (Before the fix `let _ = exhausted;` discarded the state and both paths
    // produced A2_NO_ZERO_LABEL_REASON.)
    let ProofOutcome::Unavailable(capped_reason) = capped.outcome else {
        panic!("a capped scan reports UNAVAILABLE, never Proved/Failed");
    };
    assert_ne!(capped_reason, A2_NO_ZERO_LABEL_REASON);
    assert!(
        !capped_reason.contains("reachable"),
        "the capped claim must not assert reachability in any form: {capped_reason}"
    );
    assert!(
        capped_reason.contains("bound reached before exhaustion"),
        "the capped claim names its own limitation: {capped_reason}"
    );
    // Neither ending is a failure, and neither licenses the flip.
    for run in [&exhausted, &capped] {
        assert!(run.inference.is_none() && run.observation.is_none());
        assert!(run.capture_json.is_none(), "no observation ⇒ no capture");
    }
}

/// `CARGO_MANIFEST_DIR` read at RUNTIME (`std::env::var`, which Cargo
/// sets fresh for every test-binary run), never `env!` (a COMPILE-TIME bake a test binary reused
/// unrecompiled from another tree — a shared `CARGO_TARGET_DIR` — would carry from the tree it was
/// actually compiled in).
fn manifest_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR for every test binary it runs"),
    )
}

/// Read a committed evidence file (the bytes a reader would verify).
fn read_committed_evidence(name: &str) -> Vec<u8> {
    let path = manifest_dir()
        .join("../../docs/evidence/2026-07-gmail-live-readside-drill")
        .join(name);
    std::fs::read(&path)
        .unwrap_or_else(|e| panic!("committed evidence {name} must be readable: {e}"))
}

/// The committed manifest's recorded digest for one capture name (as the run recorded it).
fn manifest_digest_for(capture_stem: &str) -> String {
    let manifest: serde_json::Value =
        serde_json::from_slice(&read_committed_evidence("manifest.json"))
            .expect("the committed manifest parses");
    manifest["capture_digests"]
        .as_array()
        .expect("capture_digests")
        .iter()
        .find(|row| row["capture"] == capture_stem)
        .and_then(|row| row["sha384"].as_str())
        .unwrap_or_else(|| panic!("the manifest records a digest for {capture_stem}"))
        .to_string()
}

// RE-OPENED 2026-08-05: the attended closure re-run re-recorded the evidence directory in the
// sha384 status-bound form (that run: `run-1785950080-52544` @ `e091b32a…`; the CURRENT run
// is [`LIVE_RUN_DIR`] @ [`LIVE_RUN_COMMIT_SHA`], re-recorded 2026-09-03 for the credential-migration
// re-discharge — this bind failed across that swap until the corpus rows were repointed,
// which is the demonstration it can fail), so the
// transitional `#[ignore]` gate is GONE — and per the gate's own recorded obligation, the binding now ALSO covers every `proof_matrix` row: a row's capture name,
// digest, or outcome drifting while the top-level `capture_digests` list stays intact breaks
// this test.
#[test]
fn committed_evidence_binds_fixture_file_and_manifest() {
    // The replay tests hashed only the INLINE fixture bytes and never opened
    // the committed files, so a recorded artifact — or its manifest digest — could drift while
    // the suite stayed green, defeating the very byte-immutability the `-text` pin protects.
    // THREE-WAY BIND, for every recorded capture: inline fixture ↔ committed file ↔ manifest.
    let mut checked = 0usize;

    for f in LIVE_CAPTURE_CORPUS {
        let stem = f.capture_name.trim_end_matches(".json");
        let file_bytes = read_committed_evidence(f.capture_name);
        let file_digest = sha384_hex(&file_bytes);
        assert_eq!(
            file_digest,
            manifest_digest_for(stem),
            "{}: committed file ↔ manifest digest",
            f.capture_name
        );
        assert_eq!(
            file_digest, f.sanitized_sha384,
            "{}: committed file ↔ inline fixture digest",
            f.capture_name
        );
        assert_eq!(
            file_bytes,
            f.body.as_bytes(),
            "{}: the inline fixture must be the committed file's BYTES",
            f.capture_name
        );
        checked += 1;
    }
    for f in LIVE_MINIMAL_CAPTURES {
        let stem = f.capture_name.trim_end_matches(".json");
        let file_bytes = read_committed_evidence(f.capture_name);
        let file_digest = sha384_hex(&file_bytes);
        assert_eq!(
            file_digest,
            manifest_digest_for(stem),
            "{}: committed file ↔ manifest digest",
            f.capture_name
        );
        assert_eq!(
            file_digest, f.sanitized_sha384,
            "{}: committed file ↔ inline fixture digest",
            f.capture_name
        );
        assert_eq!(
            file_bytes,
            f.body.as_bytes(),
            "{}: the inline fixture must be the committed file's BYTES",
            f.capture_name
        );
        checked += 1;
    }
    assert_eq!(checked, 6, "all six banked captures are bound (non-vacuity)");

    // The manifest itself must still describe THIS run.
    let manifest: serde_json::Value =
        serde_json::from_slice(&read_committed_evidence("manifest.json"))
            .expect("manifest parses");
    assert_eq!(manifest["commit_sha"], LIVE_RUN_COMMIT_SHA);
    assert_eq!(manifest["mode"], "closure");
    assert_eq!(manifest["clean_tree"], true);

    // (the gate's recorded re-open obligation): every PROVED proof_matrix row
    // is bound to the committed evidence individually — its capture name must be one of the
    // committed files and its per-row digest must equal that FILE's bytes, so a matrix row
    // drifting while the top-level capture_digests list stays intact cannot survive.
    let rows = manifest["proof_matrix"].as_array().expect("proof_matrix rows");
    let mut proved_rows = 0usize;
    for row in rows {
        if row["outcome"] != "Proved" {
            continue;
        }
        proved_rows += 1;
        let name = row["capture"]["name"].as_str().unwrap_or_else(|| {
            panic!("PROVED row {} carries no capture name", row["proof_id"])
        });
        let row_digest = row["capture"]["sha384"].as_str().unwrap_or_else(|| {
            panic!("PROVED row {} carries no capture digest", row["proof_id"])
        });
        let file_bytes = read_committed_evidence(&format!("{name}.json"));
        assert_eq!(
            sha384_hex(&file_bytes),
            row_digest,
            "proof_matrix row {} must bind to the committed {name}.json bytes",
            row["proof_id"]
        );
    }
    assert_eq!(
        proved_rows, 7,
        "this run PROVED seven obligations (six mandatory + the conditional casing); \
         a different count means the matrix drifted (non-vacuity)"
    );

    // And the bind is LIVE: perturbing one byte of a COPY (never the committed evidence) must
    // break it — the demonstration that this test can fail at all.
    let mut perturbed = read_committed_evidence("r3_denial_envelope.json");
    let last = perturbed.len() - 1;
    perturbed[last] ^= 0x20;
    assert_ne!(
        sha384_hex(&perturbed),
        manifest_digest_for("r3_denial_envelope"),
        "a single flipped byte must break the digest bind (the test is not vacuous)"
    );
}

#[test]
fn live_run_provenance_is_pinned() {
    // A reader must be able to trace any fixture to the run that produced it (and the
    // committed evidence copies under docs/evidence/…).
    assert!(
        is_full_sha(LIVE_RUN_COMMIT_SHA),
        "the run's commit SHA is a full object name: {LIVE_RUN_COMMIT_SHA}"
    );
    assert!(LIVE_RUN_DIR.starts_with("run-"));
    for name in LIVE_CAPTURE_CORPUS.iter().map(|f| f.capture_name) {
        assert!(name.ends_with(".json"));
    }
    for f in LIVE_MINIMAL_CAPTURES {
        assert!(f.capture_name.ends_with(".json") && !f.proof_id.is_empty());
    }
}

#[test]
fn r4_mutant_malformed_json_differs_from_baseline() {
    // Named semantic mutant with an ASSERTED DIFFERENTIAL (design §4.4): the baseline is a
    // hermetic exemplar shape already pinned in error.rs's suite; the mutation flips its verdict.
    let baseline = r#"{"error":{"code":403,"errors":[{"domain":"global","reason":"forbidden"}],"message":"prose"}}"#;
    assert_eq!(map_error_response(403, baseline), GmailError::Forbidden);
    let truncated = &baseline[..baseline.len() / 2];
    assert_eq!(
        map_error_response(403, truncated),
        GmailError::Unknown,
        "malformed JSON falls to the fail-closed default"
    );
    assert_ne!(
        map_error_response(403, baseline),
        map_error_response(403, truncated),
        "the mutant must DIFFER from its baseline or it discriminates nothing"
    );
}

#[test]
fn r4_mutant_duplicate_verdict_bearing_member_differs_from_baseline() {
    let baseline = r#"{"error":{"code":403,"errors":[{"domain":"global","reason":"forbidden"}]}}"#;
    let duplicated = r#"{"error":{"code":403,"errors":[{"domain":"global","reason":"forbidden","reason":"forbidden"}]}}"#;
    assert_eq!(map_error_response(403, baseline), GmailError::Forbidden);
    assert_eq!(
        map_error_response(403, duplicated),
        GmailError::Unknown,
        "a duplicated verdict-bearing member is a non-conforming envelope: fail closed"
    );
}

#[test]
fn r4_mutant_changed_status_family_differs_from_baseline() {
    // The same forbidden body under a different transport status: the status selects the
    // family, so the verdict moves — a fixture suite that keyed on the body alone would miss it.
    let body = r#"{"error":{"code":403,"errors":[{"domain":"global","reason":"forbidden"}]}}"#;
    assert_eq!(map_error_response(403, body), GmailError::Forbidden);
    assert_eq!(map_error_response(404, body), GmailError::NotFound);
    assert_eq!(map_error_response(401, body), GmailError::Unauthorized);
    assert_ne!(map_error_response(403, body), map_error_response(404, body));
}

#[test]
fn r4_mutant_changed_status_family_moves_the_capture_digest() {
    // The canonical recorded bytes must cover
    // (status, body), not the body alone — two responses with identical JSON under different
    // transport statuses are DIFFERENT evidence (`map_error_response` classifies them
    // differently) and must never share a capture digest. Before this close, the named
    // "changed 403 status/family" mutant above could demonstrate only the CLASSIFIER moving;
    // now the digest moves with it. (Before the fix identical canonical bytes appeared under 403 and 404.)
    let body = r#"{"error":{"code":403,"errors":[{"domain":"global","reason":"forbidden"}]}}"#;
    let banked_403 = canonical_banked_bytes(&sanitize_envelope(403, body));
    let banked_404 = canonical_banked_bytes(&sanitize_envelope(404, body));
    assert_ne!(
        banked_403, banked_404,
        "identical bodies under different statuses must bank different canonical bytes"
    );
    assert_ne!(
        sha384_hex(banked_403.as_bytes()),
        sha384_hex(banked_404.as_bytes()),
        "…and therefore different capture digests"
    );
    // The embedded status is the sanitizer's status argument, byte-recoverable by an auditor.
    let parsed: serde_json::Value = serde_json::from_str(&banked_403).expect("banked bytes parse");
    assert_eq!(parsed["status"], 403);
}

#[test]
fn r4_mutant_wrong_message_id_differs_from_baseline() {
    // Read-path mutant through the PUBLIC SUT surface: a correlated response derives; a
    // mis-routed one (id echo for a DIFFERENT message) fails closed.
    let baseline = sut_placement_for_body(r#"{"id":"drill-msg","labelIds":["INBOX"]}"#)
        .expect("correlated response derives");
    assert_eq!(baseline, Placement::Inbox);
    let mutant = sut_placement_for_body(r#"{"id":"other-msg","labelIds":["INBOX"]}"#);
    let err = mutant.expect_err("a response for a different message must never derive");
    assert_eq!(
        err.kind,
        FailureKind::Deterministic,
        "mis-routing is deterministic, never a retry"
    );
}

#[test]
fn r4_mutant_label_ids_null_differs_from_baseline() {
    // `labelIds: null` is REFUSED by the shared LabelIds type's deliberate construction (the
    // documented fail-closed deviation from ProtoJSON null-as-unset) — differential against the
    // omitted-key baseline, which derives Archive.
    let baseline = sut_placement_for_body(r#"{"id":"drill-msg"}"#).expect("omitted derives");
    assert_eq!(baseline, Placement::Archive);
    let mutant = sut_placement_for_body(r#"{"id":"drill-msg","labelIds":null}"#);
    let err = mutant.expect_err("labelIds:null must be refused, never read as unset");
    assert_eq!(err.kind, FailureKind::Deterministic);
}

#[test]
fn out_of_model_arm_rejects_an_unrelated_deterministic_error() {
    // (Before the fix ANY deterministic ConnectorError satisfied the TRASH/SPAM/
    // DRAFT branch, so an unrelated HTTP/JSON/id-validation regression could record the arm
    // PROVED without `__out_of_model_placement__` ever running).
    let canonical = canonical_out_of_model_error();
    assert_eq!(
        canonical.kind,
        FailureKind::Deterministic,
        "the partition's rejection is deterministic"
    );
    // A healthy probe fetch that witnessed DRAFT — the arm's first conjunct. (TRASH was this
    // witness's label through M1; TRASH is now in model, so DRAFT is the one left.)
    let good_probe: Result<Option<Vec<String>>, DrillError> =
        Ok(Some(vec!["DRAFT".to_string()]));

    // Both conjuncts hold ⇒ the arm proves.
    out_of_model_arm_verdict(&good_probe, &Err(canonical))
        .expect("probe-witnessed out-of-model + the pinned identity proves the arm");
    // …an unrelated deterministic error does NOT (the discrimination).
    let unrelated = aruna::ConnectorError::deterministic("some unrelated deterministic failure");
    assert!(
        out_of_model_arm_verdict(&good_probe, &Err(unrelated)).is_err(),
        "an unrelated deterministic error must FAIL the arm, never prove it"
    );
    // …nor does a transient failure, nor a success.
    assert!(out_of_model_arm_verdict(
        &good_probe,
        &Err(aruna::ConnectorError::transient(
            "provider rejected the placement read"
        ))
    )
    .is_err());
    assert!(out_of_model_arm_verdict(&good_probe, &Ok(Placement::Archive)).is_err());
    assert!(out_of_model_arm_verdict(&good_probe, &Ok(Placement::Inbox)).is_err());
}

#[test]
fn out_of_model_arm_requires_the_probes_own_successful_out_of_model_fetch() {
    // The identity
    // equality did not close it: `gmail_to_connector` collapses 404 / 403 / malformed-body to
    // the SAME kind AND message as the partition's refusal, so those siblings still satisfied
    // the arm. Closed WHOLESALE with the discriminator already in the harness — the
    // independent probe's own successful fetch of that id, witnessing an out-of-model label
    // (TRASH/SPAM/DRAFT through M1; DRAFT alone now).
    // A probe that FAILED cannot support the arm: the same 404 / transport failure /
    // malformed body / authorization refusal would have broken the probe too.
    let partition_identity = canonical_out_of_model_error();

    // Regression test for this change: with the identity-only shape (SUT identity alone) this combination PASSED.
    let failed_probe: Result<Option<Vec<String>>, DrillError> =
        Err(DrillError::non_success(404, "not found"));
    assert!(
        out_of_model_arm_verdict(&failed_probe, &Err(partition_identity.clone())).is_err(),
        "a FAILED probe fetch must FAIL the arm — the SUT's collapsed identity cannot be \
         attributed to the placement partition without the probe's independent witness"
    );
    for probe_error in [
        DrillError::send(&reqwest::blocking::get("unsupported://x").expect_err("build error")),
        DrillError::json(&"unreadable body"),
        DrillError::non_success(403, "forbidden"),
    ] {
        assert!(
            out_of_model_arm_verdict(&Err(probe_error), &Err(partition_identity.clone()))
                .is_err(),
            "every probe-side failure mode must fail the arm"
        );
    }

    // A probe that SUCCEEDED but witnessed a non-out-of-model label set also fails the arm —
    // the witness must be positive, not merely present. That now includes TRASH and
    // SPAM: they derive placements now (design §4.4), so a probe that saw them
    // has witnessed an IN-model message.
    for benign in [
        Some(vec!["INBOX".to_string()]),
        Some(vec!["UNREAD".to_string()]),
        Some(vec!["TRASH".to_string()]),
        Some(vec!["SPAM".to_string()]),
        Some(vec!["INBOX".to_string(), "TRASH".to_string()]),
        Some(Vec::new()),
        None, // labelIds omitted on the wire
    ] {
        assert!(
            out_of_model_arm_verdict(&Ok(benign), &Err(partition_identity.clone())).is_err(),
            "a probe witness without DRAFT cannot prove the out-of-model arm"
        );
    }

    // DRAFT — the one out-of-model label — witnessed positively, alone or beside any placement
    // label, does support the arm.
    for companion in [None, Some("INBOX"), Some("TRASH"), Some("SPAM")] {
        let witnessed: Vec<String> = companion
            .into_iter()
            .chain(["DRAFT"])
            .map(String::from)
            .collect();
        out_of_model_arm_verdict(&Ok(Some(witnessed)), &Err(partition_identity.clone()))
            .unwrap_or_else(|_| panic!("DRAFT beside {companion:?} supports the arm"));
    }
}

#[test]
fn r4_mutant_contradictory_label_set_differs_from_baseline() {
    // INBOX+DRAFT is out-of-model (any combination containing DRAFT) — the typed rejection,
    // differential against the plain INBOX baseline. DRAFT is the ONE label left out of
    // model: the SUT's `OUT_OF_MODEL_LABELS` is `["DRAFT"]` (private to
    // `aruna_gmail::transport`, so stated here rather than read; pinned in place by
    // `placement_derives_trash_over_spam_over_inbox_and_only_draft_is_out_of_model`).
    // Through M1 this mutant was INBOX+TRASH.
    let baseline = sut_placement_for_body(r#"{"id":"drill-msg","labelIds":["INBOX"]}"#)
        .expect("plain INBOX derives");
    assert_eq!(baseline, Placement::Inbox);
    let mutant = sut_placement_for_body(r#"{"id":"drill-msg","labelIds":["INBOX","DRAFT"]}"#);
    let err = mutant.expect_err("a contradictory label set is out-of-model: typed rejection");
    assert_eq!(
        err.kind,
        FailureKind::Deterministic,
        "out-of-model placement is deterministic, never Transient"
    );
    // …and the M1 body is IN model now: INBOX+TRASH derives Trash (design §4.4).
    assert_eq!(
        sut_placement_for_body(r#"{"id":"drill-msg","labelIds":["INBOX","TRASH"]}"#)
            .expect("since #75 S1, INBOX+TRASH derives a placement"),
        Placement::Trash
    );
}

// ---- the helper's semantic-witness matrix (via its --self-test) ----------------------------

#[test]
fn helper_semantic_witness_matrix_via_self_test() {
    // GATING DECISION (design §7): the helper is stdlib-only Python and its pure
    // logic self-tests via `--self-test` (scope precedence, RFC 6749 omission provenance,
    // same-principal derivation, hash-what-you-emit association, atomic emission, no-secret
    // error paths). Python is a MINT-MACHINE tool, not a CI guarantee — so this test runs the
    // matrix whenever an interpreter exists and SKIPS LOUDLY (with a printed reason, never a
    // failure) when none does. A broken helper on a python-equipped machine fails the suite;
    // a python-less CI job stays green and says why. The witness is NOT #[ignore]d: presence
    // of python is the only gate.
    let script = manifest_dir()
        .join("..")
        .join("..")
        .join("scripts")
        .join("gmail_drill_mint.py");
    assert!(
        script.exists(),
        "the reviewed helper source must live in-repo at scripts/gmail_drill_mint.py (design §5)"
    );
    // Python3 FIRST: on hosts where bare `python` is Python 2, the helper's
    // f-strings are a SyntaxError — a false matrix failure that would panic before the valid
    // interpreter was ever tried. `python3` is unambiguous; the others are fallbacks.
    let candidates = ["python3", "python", "py"];
    for candidate in candidates {
        let Ok(output) = std::process::Command::new(candidate)
            .arg(&script)
            .arg("--self-test")
            .output()
        else {
            continue; // interpreter not on PATH under this name
        };
        if output.status.success() {
            return; // helper matrix ran green
        }
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        // Windows app-execution aliases spawn successfully and then print "Python was not
        // found" (exit 9009) — that is interpreter ABSENCE, not a failing matrix.
        if output.status.code() == Some(9009) || text.contains("was not found") {
            continue;
        }
        panic!("gmail_drill_mint.py --self-test FAILED via `{candidate}`:\n{text}");
    }
    eprintln!(
        "W6 SKIPPED LOUDLY: no python interpreter found (tried {candidates:?}). The helper's \
         semantic-witness matrix runs as `python scripts/gmail_drill_mint.py --self-test` on \
         the mint machine; interpreter absence must never fail CI (recorded gating decision)."
    );
}

// ===============================================================================================
// ===============================================================================================
//                                     THE LIVE DRILLS
// ===============================================================================================
// ===============================================================================================

/// The five R1 arms (design §4.1): search query + the row of the table the arm exercises. Since
/// the TRASH and SPAM arms expect PLACEMENTS (design §4.4); DRAFT is the
/// one out-of-model arm left.
#[derive(Clone, Copy)]
struct ArmSpec {
    proof: ProofId,
    query: &'static str,
    expectation: ProbeVerdict,
}

const R1_ARMS: [ArmSpec; 5] = [
    ArmSpec {
        proof: ProofId::R1Inbox,
        query: "in:inbox",
        expectation: ProbeVerdict::Inbox,
    },
    ArmSpec {
        proof: ProofId::R1Archive,
        query: "-in:inbox -in:trash -in:spam -in:draft",
        expectation: ProbeVerdict::Archive,
    },
    ArmSpec {
        proof: ProofId::R1Trash,
        query: "in:trash",
        expectation: ProbeVerdict::Trash,
    },
    ArmSpec {
        proof: ProofId::R1Spam,
        query: "in:spam",
        expectation: ProbeVerdict::Spam,
    },
    ArmSpec {
        proof: ProofId::R1Draft,
        query: "in:draft",
        expectation: ProbeVerdict::OutOfModel,
    },
];

/// The manifest-facing record of one arm attempt. ID-FREE: label evidence is booleans + counts,
/// never the provider-native strings of user labels; brackets are the historyId pair §4.5 records.
struct ArmObservation {
    arm: &'static str,
    probe_label_summary: serde_json::Value,
    sut_outcome: String,
    bracket_before: String,
    bracket_after: String,
    retried: bool,
}

impl ArmObservation {
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "arm": self.arm,
            "probe_labels": self.probe_label_summary,
            "sut_outcome": self.sut_outcome,
            "bracket_before": self.bracket_before,
            "bracket_after": self.bracket_after,
            "retried": self.retried,
        })
    }
}

fn label_summary(labels: Option<&[String]>) -> serde_json::Value {
    match labels {
        None => serde_json::json!({ "encoding": "omitted", "count": 0 }),
        Some(list) => serde_json::json!({
            "encoding": "present",
            "count": list.len(),
            "contains_inbox": list.iter().any(|l| l == "INBOX"),
            "contains_trash": list.iter().any(|l| l == "TRASH"),
            "contains_spam": list.iter().any(|l| l == "SPAM"),
            "contains_draft": list.iter().any(|l| l == "DRAFT"),
        }),
    }
}

enum ArmFailure {
    Unavailable(&'static str),
    /// The history bracket advanced: retry the WHOLE arm once (design §4.1), then fail.
    /// Boxed so the error variant stays small (clippy `result_large_err`).
    Toctou {
        observation: Box<ArmObservation>,
    },
    Other(DrillError),
}

/// The CANONICAL out-of-model rejection, derived at run time from a hermetic loopback
/// exchange (no network): the exact `ConnectorError` the production placement partition emits
/// when it sees a rejected label set. Used as the identity the R1 DRAFT arm must match — the TRASH/SPAM arms left the out-of-model set.
///
/// **Residual, named honestly:** `gmail_to_connector` collapses every `GmailError` on this
/// route to one id-free message, so this identity is shared with other deterministic refusals
/// from the SAME route (e.g. a 403, a malformed body). Equality therefore proves the arm hit a
/// DETERMINISTIC PLACEMENT-ROUTE refusal identical to the one the out-of-model partition
/// emits — it excludes transient failures, non-refusal outcomes, and any future divergence in
/// the partition's error identity, but it cannot by itself isolate out-of-model from the other
/// refusals sharing that message. Narrowing further would require a production-source change
/// (a distinguishable error), which this change may not make; the R4 hermetic mutants
/// (`r4_mutant_contradictory_label_set_differs_from_baseline`) carry the isolation claim.
fn canonical_out_of_model_error() -> aruna::ConnectorError {
    // INBOX+DRAFT: DRAFT is the one label left out of model (through M1 this body was
    // INBOX+TRASH, which now derives `Placement::Trash`).
    sut_placement_for_body(r#"{"id":"drill-msg","labelIds":["INBOX","DRAFT"]}"#)
        .expect_err("the out-of-model partition must reject this label set")
}

/// The R1 out-of-model arm's verdict — a CONJUNCTION, both halves load-bearing (no third
/// identity variant, no production error-shape change):
///
/// 1. **The independent probe SUCCESSFULLY fetched that message and witnessed a label set
///    containing DRAFT** (TRASH/SPAM too through M1; they are now in model, so a probe
///    witness of either now belongs to a PLACEMENT arm). This is the load-bearing
///    discriminator, and it is what
///    the identity check alone could never be: a 404, a transport failure, a malformed body,
///    or an authorization refusal would have failed the PROBE's own fetch of the same id on
///    the same route moments earlier — so a passing probe fetch excludes exactly the sibling
///    causes that share the SUT's collapsed error identity.
/// 2. **The SUT deterministically refused with the pinned partition identity.**
///
/// **The arm's claim, at exactly this strength:** *the probe fetched an out-of-model message
/// that the SUT deterministically refused on the read route.* NOT "the partition's
/// out-of-model arm was the specific cause". **Residual, plainly:** production collapses every
/// read-route refusal to one id-free `ConnectorError`; full causal isolation would need a
/// distinguishable production error, which this test/evidence change must not introduce. The
/// hermetic `r4_mutant_contradictory_label_set_differs_from_baseline` carries that claim.
fn out_of_model_arm_verdict(
    probe_fetch: &Result<Option<Vec<String>>, DrillError>,
    sut_result: &Result<Placement, aruna::ConnectorError>,
) -> Result<String, DrillError> {
    // (1) The probe's own successful, out-of-model-witnessing fetch — checked FIRST, because
    // it is what excludes the sibling causes.
    match probe_fetch {
        Err(_) => {
            return Err(DrillError::assertion_mismatch(
                "out-of-model arm: the independent probe did not successfully fetch the \
                 message — a SUT refusal here cannot be attributed to the placement partition \
                 (404 / transport / malformed body / authorization all look identical)",
                "probe fetch failed",
            ))
        }
        Ok(labels) => {
            let witnessed = labels.as_deref().unwrap_or(&[]);
            if classify_probe_labels(witnessed) != ProbeVerdict::OutOfModel {
                return Err(DrillError::assertion_mismatch(
                    "out-of-model arm: the probe did not witness a DRAFT-bearing label set",
                    "probe label set is not out-of-model",
                ));
            }
        }
    }
    // (2) …and the SUT's deterministic refusal carries the pinned partition identity.
    let expected = canonical_out_of_model_error();
    match sut_result {
        Ok(placement) => Err(DrillError::assertion_mismatch(
            "out-of-model arm yielded a PLACEMENT where a typed rejection was required",
            &format!("{placement:?}"),
        )),
        Err(e) if e.kind != FailureKind::Deterministic => Err(DrillError::assertion_mismatch(
            "out-of-model arm produced a non-deterministic rejection",
            &e.message,
        )),
        Err(e) if *e != expected => Err(DrillError::assertion_mismatch(
            "out-of-model arm's rejection is NOT the placement partition's identity — an \
             unrelated deterministic failure cannot prove this arm",
            &e.message,
        )),
        Err(_) => Ok(
            "probe-witnessed out-of-model message, deterministically refused on the read \
             route with the pinned partition identity"
                .to_string(),
        ),
    }
}

/// A passed arm attempt: the observation, the candidate id (in-process only — R3 reuses the
/// inbox arm's known-good id; it never enters any output), and the ID-free capture projection
/// that must be RECORDED before the arm's ProofId may record PROVED.
struct ArmSuccess {
    observation: ArmObservation,
    id: String,
    capture_json: String,
}

/// The SUT half of one R1 arm: the SUT's outcome checked against the arm's row, given the
/// probe's witness. Moved VERBATIM out of [`attempt_arm`] so the row match is
/// hermetically testable — the new TRASH/SPAM placement arms included; every failure it
/// returns is one `attempt_arm` already mapped to `ArmFailure::Other`.
fn sut_outcome_for_arm(
    expectation: ProbeVerdict,
    probe_fetch: &Result<Option<Vec<String>>, DrillError>,
    label_slice: &[String],
    sut_result: &Result<Placement, aruna::ConnectorError>,
) -> Result<String, DrillError> {
    Ok(match (&expectation, sut_result) {
        (ProbeVerdict::Inbox, Ok(Placement::Inbox)) => "Placement::Inbox".to_string(),
        // The TRASH and SPAM arms are placement checks now (design §4.4),
        // never out-of-model refusals.
        (ProbeVerdict::Trash, Ok(Placement::Trash)) => "Placement::Trash".to_string(),
        (ProbeVerdict::Spam, Ok(Placement::Spam)) => "Placement::Spam".to_string(),
        (ProbeVerdict::Archive, Ok(Placement::Archive)) => {
            // The discriminating Archive arm additionally asserts the probe-witnessed label SET
            // alongside the placement (design §4.1): none of the four labels the table keys on
            // (INBOX/TRASH/SPAM, which derive placements, and DRAFT, which is out of model) is
            // present.
            if label_slice
                .iter()
                .any(|l| l == "INBOX" || l == "TRASH" || l == "SPAM" || l == "DRAFT")
            {
                return Err(DrillError::assertion_mismatch(
                    "archive arm label-set assertion failed: a placement label is present",
                    &label_slice.join(","),
                ));
            }
            "Placement::Archive".to_string()
        }
        (ProbeVerdict::OutOfModel, Err(_)) => {
            // The rejection must be the one the PLACEMENT PARTITION emits for a rejected
            // label set — not merely "some deterministic error" (any
            // deterministic ConnectorError satisfied this branch, so an unrelated HTTP /
            // JSON / id-validation regression could "prove" the arm without
            // `__out_of_model_placement__` ever being exercised).
            out_of_model_arm_verdict(probe_fetch, sut_result)?
        }
        (_, other) => {
            return Err(DrillError::assertion_mismatch(
                "SUT outcome does not match the probe-witnessed row",
                &format!("{other:?}"),
            ))
        }
    })
}

/// One attempt at one arm: bracket → discover → probe-classify → SUT → bracket.
fn attempt_arm(
    probe: &GmailProbe,
    sut: &GmailProviderPlacement<'_>,
    spec: &ArmSpec,
    retried: bool,
) -> Result<ArmSuccess, ArmFailure> {
    let bracket_before = probe
        .get_profile_history_id()
        .map_err(ArmFailure::Other)?;
    let id = match bounded_search(|token| probe.list_messages(spec.query, token)) {
        SearchOutcome::Found(id) => id,
        SearchOutcome::SearchExhausted => return Err(ArmFailure::Unavailable("SearchExhausted")),
        SearchOutcome::BoundReached => {
            return Err(ArmFailure::Other(DrillError::assertion_mismatch(
                "discovery page bound reached before a candidate appeared",
                spec.query,
            )))
        }
        SearchOutcome::RequestFailed => {
            return Err(ArmFailure::Other(DrillError::assertion_mismatch(
                "discovery request failed",
                spec.query,
            )))
        }
    };
    // The probe's fetch RESULT is kept (not `?`-ed away) because the out-of-model arm's
    // verdict is a CONJUNCTION over it and the SUT outcome.
    let probe_fetch = probe.get_message_labels(&id);
    let labels = match &probe_fetch {
        Ok(labels) => labels.clone(),
        Err(e) => return Err(ArmFailure::Other(*e)),
    };
    let label_slice = labels.clone().unwrap_or_default();
    let probe_verdict = classify_probe_labels(&label_slice);
    if probe_verdict != spec.expectation {
        return Err(ArmFailure::Other(DrillError::assertion_mismatch(
            "probe-witnessed label state does not match the arm's arranged state",
            &format!("{probe_verdict:?}"),
        )));
    }

    // The SUT reads the SAME id, only after the probe has classified (design §4.1 ordering).
    let sut_result = sut.fetch_placement("live-drill", &ProviderMessageId(id.clone()));
    let sut_outcome =
        sut_outcome_for_arm(spec.expectation, &probe_fetch, &label_slice, &sut_result)
            .map_err(ArmFailure::Other)?;

    let bracket_after = probe
        .get_profile_history_id()
        .map_err(ArmFailure::Other)?;
    let observation = ArmObservation {
        arm: spec.proof.name(),
        probe_label_summary: label_summary(labels.as_deref()),
        sut_outcome,
        bracket_before: bracket_before.clone(),
        bracket_after: bracket_after.clone(),
        retried,
    };
    if bracket_before != bracket_after {
        return Err(ArmFailure::Toctou {
            observation: Box::new(observation),
        });
    }
    // The ID-free capture projection this PROVED will be keyed to: the
    // probe-witnessed minimal-message observation, sanitized by the fidelity rules.
    let capture_json = serde_json::to_string_pretty(&sanitize_minimal_capture(labels.as_deref()))
        .expect("capture projection serializes");
    Ok(ArmSuccess {
        observation,
        id,
        capture_json,
    })
}

/// The completed result of one R1 arm (single bounded TOCTOU retry, design §4.1).
/// `observations` retains EVERY attempt's brackets — on a double-TOCTOU failure BOTH attempts
/// are recorded (the design requires both observations + brackets, not the last).
struct ArmRun {
    outcome: ProofOutcome,
    observations: Vec<ArmObservation>,
    id: Option<String>,
    capture_json: Option<String>,
}

fn run_r1_arm(probe: &GmailProbe, sut: &GmailProviderPlacement<'_>, spec: &ArmSpec) -> ArmRun {
    match attempt_arm(probe, sut, spec, false) {
        Ok(success) => ArmRun {
            outcome: ProofOutcome::Proved,
            observations: vec![success.observation],
            id: Some(success.id),
            capture_json: Some(success.capture_json),
        },
        Err(ArmFailure::Unavailable(reason)) => ArmRun {
            outcome: ProofOutcome::Unavailable(reason),
            observations: Vec::new(),
            id: None,
            capture_json: None,
        },
        Err(ArmFailure::Toctou {
            observation: first_attempt,
        }) => match attempt_arm(probe, sut, spec, true) {
            Ok(success) => ArmRun {
                // The toctou'd first attempt stays recorded beside the pass — evidence, not noise.
                outcome: ProofOutcome::Proved,
                observations: vec![*first_attempt, success.observation],
                id: Some(success.id),
                capture_json: Some(success.capture_json),
            },
            Err(ArmFailure::Unavailable(reason)) => ArmRun {
                outcome: ProofOutcome::Unavailable(reason),
                observations: vec![*first_attempt],
                id: None,
                capture_json: None,
            },
            Err(ArmFailure::Toctou {
                observation: second_attempt,
            }) => {
                // Second advancement: FAIL with BOTH attempts' observations + brackets recorded; the error text itself stays value-free.
                eprintln!(
                    "R1 arm {}: history bracket advanced twice — racing mailbox fails honestly",
                    spec.proof.name()
                );
                ArmRun {
                    outcome: ProofOutcome::Failed,
                    observations: vec![*first_attempt, *second_attempt],
                    id: None,
                    capture_json: None,
                }
            }
            Err(ArmFailure::Other(e)) => {
                eprintln!("R1 arm {} failed on retry: {e}", spec.proof.name());
                ArmRun {
                    outcome: ProofOutcome::Failed,
                    observations: vec![*first_attempt],
                    id: None,
                    capture_json: None,
                }
            }
        },
        Err(ArmFailure::Other(e)) => {
            eprintln!("R1 arm {} failed: {e}", spec.proof.name());
            ArmRun {
                outcome: ProofOutcome::Failed,
                observations: Vec::new(),
                id: None,
                capture_json: None,
            }
        }
    }
}

/// The completed R2 result: the outcome, the one-sided encoding observation + inference, the
/// recorded note, and the ID-free capture projection a PROVED must be keyed to.
struct R2Run {
    outcome: ProofOutcome,
    observation: Option<EncodingObservation>,
    inference: Option<Inference>,
    banked: serde_json::Value,
    capture_json: Option<String>,
}

impl R2Run {
    fn failed(observation: Option<EncodingObservation>, inference: Option<Inference>) -> Self {
        Self {
            outcome: ProofOutcome::Failed,
            observation,
            inference,
            banked: serde_json::Value::Null,
            capture_json: None,
        }
    }

    /// The STRONG claim — reachable ONLY from a search the provider itself ended
    /// (`SearchExhausted`). The caller cannot pick this string: it exists in
    /// exactly one constructor, gated on the exhausted quad-state, so a capped search can never
    /// produce it.
    fn unavailable_search_exhausted() -> Self {
        Self {
            outcome: ProofOutcome::Unavailable(A2_NO_ZERO_LABEL_REASON),
            observation: None,
            inference: None,
            banked: serde_json::Value::Null,
            capture_json: None,
        }
    }

    /// The WEAK, honest claim for a search that hit our own bound before the provider
    /// exhausted the listing. It asserts nothing about unreachability — only that the scanned
    /// prefix contained no candidate.
    fn unavailable_bound_reached() -> Self {
        Self {
            outcome: ProofOutcome::Unavailable(A2_BOUND_REACHED_REASON),
            observation: None,
            inference: None,
            banked: serde_json::Value::Null,
            capture_json: None,
        }
    }
}

/// How the A2 candidate search ended — the quad-state, preserved all the way to the CLAIM. Before this, a capped page discarded `exhausted` and the run recorded the
/// STRONG "no zero-label message reachable" claim from a search that had only seen the first N
/// results — a claim stronger than the drill's own observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum A2ScanEnd {
    /// The provider ended the listing (no `nextPageToken`) AND no id was dropped along the
    /// way — only then is the strong claim earned ([`a2_final_page_scan_end`]:
    /// a truncated final page stays [`A2ScanEnd::BoundReached`]).
    Exhausted,
    /// OUR bound stopped the scan while the provider still had more pages.
    BoundReached,
}

/// Map the scan's end-state to the outcome. Total and separate-by-construction: there is no
/// path from [`A2ScanEnd::BoundReached`] to the strong reason string.
///
/// The FINAL-page decision, pure: the provider ending the listing earns
/// `Exhausted` ONLY if every id the provider showed was actually kept. A final page that
/// overflowed the candidate cap DROPPED ids — unprobed messages exist, so the end-state is
/// OUR bound, never the provider's exhaustion, and the strong "no zero-label message
/// reachable" claim stays unavailable to it. (Pre-fix, the `None` next-token arm set
/// `Exhausted` unconditionally.)
fn a2_final_page_scan_end(final_page_truncated: bool) -> A2ScanEnd {
    if final_page_truncated {
        A2ScanEnd::BoundReached
    } else {
        A2ScanEnd::Exhausted
    }
}

fn a2_no_candidate_outcome(scan_end: A2ScanEnd) -> R2Run {
    match scan_end {
        A2ScanEnd::Exhausted => R2Run::unavailable_search_exhausted(),
        A2ScanEnd::BoundReached => R2Run::unavailable_bound_reached(),
    }
}

/// R2 (design §4.2): find a zero-label candidate, capture the RAW body of the exact SUT query
/// shape, record the encoding one-sidedly.
fn run_r2(
    probe: &GmailProbe,
    sut: &GmailProviderPlacement<'_>,
    pinned: Option<&str>,
) -> R2Run {
    const A2_QUERY: &str =
        "has:nouserlabels -in:inbox -in:trash -in:spam -in:draft -in:sent is:read -is:starred";
    // Candidate scan: first listing page(s), verify zero-label via the probe's raw get. The
    // pinned fallback is tried last (design §3: operator-pinned A2 candidate).
    let mut candidates: Vec<String> = Vec::new();
    // The quad-state must SURVIVE to the claim. `BoundReached` is the
    // default: the scan only earns `Exhausted` by seeing the provider end the listing.
    let mut scan_end = A2ScanEnd::BoundReached;
    let mut token: Option<String> = None;
    for _ in 0..SEARCH_PAGE_BOUND {
        match probe.list_messages(A2_QUERY, token.as_deref()) {
            Ok(page) => {
                // Take only what still FITS under the cap: appending a full
                // page before checking meant a nominal 25-candidate scan could probe up to 49.
                // This bounds the candidate PROBES; it does not touch the quad-state semantics
                // — `scan_end` is still decided purely by whether the PROVIDER
                // ended the listing.
                let room = A2_CANDIDATE_CAP.saturating_sub(candidates.len());
                let page_truncated = page.ids.len() > room;
                candidates.extend(page.ids.into_iter().take(room));
                match page.next_page_token {
                    // More pages AND room left under the candidate cap: keep going.
                    Some(next) if candidates.len() < A2_CANDIDATE_CAP => token = Some(next),
                    // More pages but the cap stopped us — OUR bound, not the provider's end.
                    Some(_) => break,
                    // Provider ended the listing — but a truncated final page dropped ids, and dropped ids are OUR bound: stays BoundReached.
                    None => {
                        scan_end = a2_final_page_scan_end(page_truncated);
                        break;
                    }
                }
            }
            Err(e) => {
                eprintln!("R2 discovery failed: {e}");
                return R2Run::failed(None, None);
            }
        }
    }
    candidates.extend(pinned.map(String::from));

    for id in &candidates {
        // Candidate read/parse failures are FAILED, fail-closed: a broken
        // oracle exchange must never be silently skipped into "no candidate found" — that
        // path ends in SearchExhausted/UNAVAILABLE, which closure treats as an honest state
        // of the MAILBOX, not of the drill.
        let (status, raw) = match probe.get_raw_minimal(id) {
            Ok(exchange) => exchange,
            Err(e) => {
                eprintln!("R2 candidate read failed: {e}");
                return R2Run::failed(None, None);
            }
        };
        if !(200..300).contains(&status) {
            eprintln!("R2 candidate read returned HTTP {status} (body redacted)");
            return R2Run::failed(None, None);
        }
        let labels = match probe_parse_minimal(&raw, id) {
            Ok(labels) => labels,
            Err(e) => {
                eprintln!("R2 candidate parse failed: {e}");
                return R2Run::failed(None, None);
            }
        };
        if labels.as_deref().is_some_and(|l| !l.is_empty()) {
            continue; // a LABELED candidate is a legitimate skip, not a failure
        }
        // Zero-label candidate found. The encoding observation is about THIS raw body — the
        // exact SUT query shape by construction (get_raw_minimal).
        let observation = if labels.is_none() {
            EncodingObservation::Omitted
        } else {
            EncodingObservation::Present
        };
        let inference = match observation {
            // Omitted observed ⇒ conclusive: the decision stands.
            EncodingObservation::Omitted => Inference::ClosedNoChange,
            // Present observed ⇒ inconclusive AND closure-valid; the flip stays unlicensed;
            // re-sampling refused (finite positives never prove universal presence).
            EncodingObservation::Present => Inference::InconclusiveNoFlipLicensed,
        };
        // SUT companion: the same id must derive Archive under either encoding.
        match sut.fetch_placement("live-drill", &ProviderMessageId(id.clone())) {
            Ok(Placement::Archive) => {}
            other => {
                eprintln!("R2 SUT companion did not derive Archive (outcome redacted at value level): ok={:?}", other.is_ok());
                return R2Run::failed(Some(observation), Some(inference));
            }
        }
        let banked = serde_json::json!({
            "observation": format!("{observation:?}"),
            "inference": format!("{inference:?}"),
            "n": 1,
            "date_unix": now_unix(),
            "scope": "gmail.modify",
            "account": "drill account (identity withheld)",
            "query_shape": "format=minimal&fields=id,labelIds",
        });
        // The ID-free capture this PROVED is keyed to: the A2 wire observation
        // itself, sanitized by the fidelity rules.
        let capture_json =
            serde_json::to_string_pretty(&sanitize_minimal_capture(labels.as_deref()))
                .expect("capture projection serializes");
        return R2Run {
            outcome: ProofOutcome::Proved,
            observation: Some(observation),
            inference: Some(inference),
            banked,
            capture_json: Some(capture_json),
        };
    }

    // No zero-label candidate in the scanned pages (and none pinned that verified):
    // `A2_ENCODING_OBSERVED` is CONDITIONAL and reports UNAVAILABLE (design §4.0/§4.2). The
    // flip stays unlicensed either way — the same practical outcome as the already-accepted
    // `InconclusiveNoFlipLicensed` inference, reached by a different route; this is NOT a
    // drill failure.
    //
    // WHICH reason depends on how the search ENDED — the drill may only
    // assert what the drill measured:
    //   Exhausted    → the provider ended the listing ⇒ the strong "not reachable" claim.
    //   BoundReached → our own cap stopped the scan ⇒ a claim about the scanned prefix ONLY.
    // The separate constructors make the strong string unreachable from BoundReached.
    //
    // NOTE ON ATTRIBUTION: the design §4.2 finding that an empty label set is not reachable
    // for received Gmail mail rests on an independent scan (174 messages across 6
    // paginated pages, plus a deliberately-constructed candidate), recorded there — NOT on
    // this capped drill search.
    eprintln!(
        "R2: no zero-label candidate found (scan ended: {scan_end:?}) — A2_ENCODING_OBSERVED \
         is UNAVAILABLE (conditional obligation; the #36 flip stays unlicensed)"
    );
    a2_no_candidate_outcome(scan_end)
}

/// `R3_SCOPE_403`'s verdict — **claim DOWNGRADED, and why**.
///
/// The finding: the arm bound its 403 assertion to the PROBE's saved status, so if the denial
/// token expired between the probe capture and the SUT call, the probe's 403 stood while the
/// SUT got a 401 — and because `GmailProviderPlacement` collapses every deterministic failure
/// to one id-free `ConnectorError`, the arm recorded PROVED in exactly the case design §4.3.3
/// says must be FAILED.
///
/// **The instructed primary fix is NOT AVAILABLE here.** The SUT request's own status
/// cannot be observed through the production surface: `fetch_placement` returns
/// `Result<Placement, ConnectorError>` and `gmail_to_connector` discards the status (and the
/// `GmailError`) behind one fixed message; `connect_for_test_fixture` is loopback-only, so the
/// SUT cannot be routed to Gmail through any drill-observable seam. Surfacing it would require
/// a production change, which this test/evidence change must not make.
///
/// **So the claim is downgraded to exactly what is provable, and bracketed.** Both probe
/// captures — immediately BEFORE and immediately AFTER the SUT's own request — must be 403.
/// That closes the named failure mode (a credential that expires or is revoked across the
/// window shows 401/404 on the second capture and the arm FAILS with both statuses recorded),
/// and it is the same bracket discipline §4.1 already uses for R1.
///
/// **What `R3_SCOPE_403 = PROVED` now claims:** *the denial credential was observed producing
/// a deterministic 403 on this route immediately before and after the SUT's own request, its
/// envelope recorded, and the SUT refused deterministically yielding no placement.*
/// **What it does NOT claim:** that the SUT's own request received 403. **Residual, named:** a
/// status divergence confined strictly to the SUT request between two 403 observations remains
/// undetectable here; closing it needs a production surface that exposes the normalized status,
/// which is a separate reviewed change.
fn r3_scope_403_verdict(
    pre_status: u16,
    post_status: Option<u16>,
    kind: FailureKind,
    sut_denied_deterministically: bool,
) -> ProofOutcome {
    let bracket_holds = pre_status == 403 && post_status == Some(403);
    if bracket_holds && kind == FailureKind::Deterministic && sut_denied_deterministically {
        ProofOutcome::Proved
    } else {
        ProofOutcome::Failed
    }
}

/// R3 (design §4.3): capture FIRST, normalize second, assert third. Returns the two outcomes,
/// the observation json, and the recorded capture (name, digest, serialized projection).
fn run_r3(
    denial_probe: &GmailProbe,
    denial_sut: &GmailProviderPlacement<'_>,
    known_good_id: &str,
) -> (
    ProofOutcome,
    ProofOutcome,
    serde_json::Value,
    Option<(String, String, String)>,
) {
    // 1. Capture first: the raw denial-token GET, recorded sanitized EVEN IF every later
    //    assertion fails.
    let (status, raw) = match denial_probe.get_raw_minimal(known_good_id) {
        Ok(exchange) => exchange,
        Err(e) => {
            eprintln!("R3 capture failed at send stage: {e}");
            return (
                ProofOutcome::Failed,
                ProofOutcome::Unavailable("capture never completed"),
                serde_json::Value::Null,
                None,
            );
        }
    };
    let sanitized = sanitize_envelope(status, &raw);
    let banked_projection = canonical_banked_bytes(&sanitized);
    let capture = (
        "r3_denial_envelope".to_string(),
        sha384_hex(banked_projection.as_bytes()),
        banked_projection.clone(),
    );

    // 2. Normalize second — over EXACTLY the recorded bytes, so the recorded
    //    taxonomy is replayable by anyone holding the capture: verdict OF THE RECORDED BYTES.
    //    Structure the sanitizer drops (duplicate members, unknown fields, provider prose) is
    //    INTENTIONALLY outside the recorded-taxonomy claim — the raw wire bytes never enter the
    //    repo (design §4.5), and the LIVE claim about the raw exchange is carried separately
    //    by the SUT's own outcome assertion below, whose transport parsed the raw bytes
    //    itself.
    let normalized = map_error_response(status, &banked_projection);
    let kind = classify_gmail_error(&normalized);

    // 3. Assert third — ALL of (design §4.3): raw 403 · Deterministic · SUT yields NO placement
    //    and NEVER Transient. 401/404/success ⇒ FAILED. `GmailError::Forbidden` is deliberately
    //    NOT asserted: an `Unknown` from modern vocabulary stays fail-closed and PASSES.
    let sut_result = denial_sut.fetch_placement("live-drill", &ProviderMessageId(known_good_id.to_string()));
    let sut_denied_deterministically =
        matches!(&sut_result, Err(e) if e.kind == FailureKind::Deterministic);
    // …and a SECOND probe capture immediately AFTER the SUT's request: the
    // status bracket. See `r3_scope_403_verdict` for why this exists and what it can and
    // cannot establish.
    let post_status = match denial_probe.get_raw_minimal(known_good_id) {
        Ok((post_status, _post_raw)) => Some(post_status),
        Err(e) => {
            eprintln!("R3 post-bracket capture failed: {e}");
            None
        }
    };
    let observation = serde_json::json!({
        "raw_status": status,
        "post_sut_probe_status": post_status,
        "normalized": format!("{normalized:?}"),
        "failure_kind": format!("{kind:?}"),
        "sut_yielded_placement": sut_result.is_ok(),
        "sut_denied_deterministically": sut_denied_deterministically,
        "envelope_capture_sha384": capture.1,
        "claim_scope": "the denial credential was observed 403 on this route immediately \
                        BEFORE and AFTER the SUT's own request, and the SUT refused \
                        deterministically with no placement; the SUT REQUEST'S OWN status is \
                        not observable through the production surface (residual, design §4.3)",
    });
    let scope_403 = r3_scope_403_verdict(status, post_status, kind, sut_denied_deterministically);
    if scope_403 != ProofOutcome::Proved {
        eprintln!(
            "R3 FAILED: pre_status={status}, post_status={post_status:?}, kind={kind:?}, \
             sut_ok={}, envelope banked regardless",
            sut_result.is_ok()
        );
    }

    // 4. Casing closes only if an ErrorInfo was OBSERVED on the wire (design §4.3.4).
    let casing = error_info_casing_outcome(&sanitized);
    (scope_403, casing, observation, Some(capture))
}

/// The R3_ERRORINFO_CASING conditional's decision, pure (the
/// class CLOSED complement-shaped): the casing obligation is proved only by an ErrorInfo
/// whose `reason` contains at least one ASCII ALPHABETIC character — the only characters
/// that HAVE case. Empty, whitespace, and case-less values (`"123"`, `"___"`) exhibit no
/// casing and report the obligation unavailable. This ends the per-shape refinement: "no
/// letter ⇒ no casing evidence" is total; WHICH casing was observed is the downstream
/// disjointness test's job, with its own assertions.
fn error_info_casing_outcome(sanitized: &SanitizedEnvelope) -> ProofOutcome {
    let observed = sanitized.details.iter().any(|d| {
        d.type_url
            .as_deref()
            .is_some_and(|t| t.ends_with("google.rpc.ErrorInfo"))
            && d.reason
                .as_deref()
                .is_some_and(|r| r.chars().any(|c| c.is_ascii_alphabetic()))
    });
    if observed {
        ProofOutcome::Proved
    } else {
        ProofOutcome::Unavailable("no ErrorInfo on wire")
    }
}

/// The §7 live red-control: a deliberately WRONG expectation demonstrated to fail — proving the
/// drill can discriminate at all. Uses the inbox arm's known-good id: asserting it derives
/// Archive must be false.
/// Did the red-control's repeat read demonstrate the wrong claim false? Only a HEALTHY read
/// deriving `Placement::Inbox` does: the control asserts the inbox candidate
/// as Archive, and disproving that claim requires a successful read showing Inbox — an
/// errored read (or any other placement) proves nothing and is a CONTROL FAILURE, never
/// went-red. (Before the fix `!matches!(Ok(Archive))` counted errors as red.)
fn red_control_went_red(repeat_read: &Result<Placement, aruna::ConnectorError>) -> bool {
    matches!(repeat_read, Ok(Placement::Inbox))
}

fn red_control(sut: &GmailProviderPlacement<'_>, inbox_id: &str) -> serde_json::Value {
    let repeat_read =
        sut.fetch_placement("live-drill", &ProviderMessageId(inbox_id.to_string()));
    let outcome_label = match &repeat_read {
        Ok(placement) => format!("Ok({placement:?})"),
        Err(_) => "Err (read failed — details redacted)".to_string(),
    };
    serde_json::json!({
        "identity": "deliberate wrong-expectation control: the R1_INBOX candidate asserted as Archive",
        "repeat_read": outcome_label,
        "went_red_as_required": red_control_went_red(&repeat_read),
    })
}

/// The attested preflight every live drill in this binary runs FIRST — moved VERBATIM out of
/// [`live_readside_drills`] so the ripple drill runs the SAME gates, never a copy:
/// the unreadable-bundle panic, the design §3 preflight binding, and the
/// helper-provenance binding. Env + file only, no wire call. Returns the bundle and its sha384
/// for the manifest.
fn attested_preflight(env: &DrillEnv) -> (AttestationBundle, String) {
    // An unreadable bundle PANICS, never skips.
    let (bundle, bundle_sha384) = load_bundle(&env.attestation_path)
        .unwrap_or_else(|reason| panic!("attestation bundle REFUSED: {reason}"));

    // Preflight binding (design §3): env + file only, no wire call. Any refusal is fatal.
    preflight(
        &bundle,
        &env.access_token,
        env.denial_token.as_deref(),
        now_unix(),
        env.mode,
        env.grant_high_water,
    )
    .unwrap_or_else(|reason| panic!("preflight REFUSED the run: {reason}"));
    // Helper provenance: the attestation must have been minted by the helper
    // bytes THIS TREE carries — the ones the helper test exercised. Unreadable helper source
    // refuses in closure / warns in smoke (establish_or_refuse); a DIGEST MISMATCH refuses in
    // every mode.
    let helper_source = establish_or_refuse(
        env.mode,
        "the mint-helper source (scripts/gmail_drill_mint.py)",
        std::fs::read(manifest_dir().join("../../scripts/gmail_drill_mint.py"))
            .map_err(|e| e.to_string()),
    );
    if let Some(bytes) = &helper_source {
        verify_helper_provenance(&bundle, bytes)
            .unwrap_or_else(|reason| panic!("{reason}"));
    }
    (bundle, bundle_sha384)
}

/// Where a live run's evidence lands — moved VERBATIM out of [`live_readside_drills`] (
/// so every live drill in this binary resolves its evidence dir through the SAME
/// containment gates. `repo_state` is the run's pre-dispatch probe.
fn establish_evidence_dir(env: &DrillEnv, repo_state: &RepoState) -> PathBuf {
    // Where evidence lands: NEVER inside target/ or the worktree. Closure
    // requires the explicit dir (parse enforced); smoke without one gets a temp dir loudly
    // labelled NON-EVIDENCE.
    match &env.evidence_dir {
        Some(dir) => {
            // The repo root is a FACT THE GATE DEPENDS ON: closure refuses without it rather
            // than skipping worktree containment. The typed
            // `RepoRootKnowledge` makes the permissive branch unreachable from closure.
            let established = establish_or_refuse(
                env.mode,
                "the repository root (git rev-parse --show-toplevel)",
                repo_state
                    .repo_root
                    .clone()
                    .ok_or_else(|| "git could not report the worktree root".to_string()),
            );
            let knowledge = match &established {
                Some(root) => RepoRootKnowledge::Known(root.as_path()),
                None => RepoRootKnowledge::UnknownSmokeOnly,
            };
            // Cargo's EFFECTIVE target directory, asked of Cargo itself (
            // `cargo metadata` already folds in CARGO_TARGET_DIR, `.cargo/config.toml`
            // `[build] target-dir`, `$CARGO_HOME/config.toml`, and the default — so there is no
            // other place the answer can come from. Resolved ONCE here and threaded; in closure
            // an unestablishable answer REFUSES rather than falling back to a guess.
            let cargo_target_dir = establish_or_refuse(
                env.mode,
                "cargo's effective target directory (cargo metadata target_directory)",
                probe_effective_target_dir(),
            );
            // …AND the target dir derived from THIS BINARY's own path:
            // `cargo test --target-dir <custom>` is exported to NEITHER the env NOR the
            // nested `cargo metadata`, so the ladder above cannot see it — but the running
            // test executable sits under whatever target dir Cargo ACTUALLY used, covering
            // env/config/CLI overrides BY CONSTRUCTION. Both answers gate containment;
            // redundancy is cheap, a hole is a defect.
            let exe_target_dirs = establish_or_refuse(
                env.mode,
                "the running binary's own target directory (current_exe layout)",
                std::env::current_exe()
                    .map_err(|e| e.to_string())
                    .and_then(|exe| target_dir_candidates_from_exe(&exe)),
            );
            let resolved = resolve_evidence_dir(dir, knowledge, cargo_target_dir.as_deref())
                .unwrap_or_else(|reason| panic!("{reason}"));
            for exe_td in exe_target_dirs.iter().flatten() {
                resolve_evidence_dir(dir, knowledge, Some(exe_td))
                    .unwrap_or_else(|reason| panic!("{reason}"));
            }
            resolved
        }
        None => {
            // Smoke only, and never citable: the temp dir is created HERE (it is not
            // evidence), and its name says so.
            let fallback = std::env::temp_dir().join(format!(
                "photon-readside-SMOKE-NON-EVIDENCE-{}",
                std::process::id()
            ));
            std::fs::create_dir_all(&fallback).expect("create smoke scratch dir");
            eprintln!(
                "smoke mode: no PHOTON_GMAIL_EVIDENCE_DIR — captures land in a temp dir \
                 labelled NON-EVIDENCE (never citable): {}",
                fallback.display()
            );
            fallback
        }
    }
}

/// A fresh run directory under `evidence_dir` — moved VERBATIM out of [`live_readside_drills`]
/// so every live drill in this binary records under the same never-overwrite rule.
fn create_run_dir(evidence_dir: &Path) -> PathBuf {
    // Run-specific subdirectory: a prior run's recorded captures are EVIDENCE
    // and must never be truncated by a later run — each run gets a fresh timestamp+pid dir,
    // and an (astronomically unlikely) collision refuses rather than overwrites.
    let run_dir = evidence_dir.join(format!("run-{}-{}", now_unix(), std::process::id()));
    assert!(
        !run_dir.exists(),
        "evidence run dir already exists — refusing to touch a prior run's captures"
    );
    std::fs::create_dir_all(&run_dir).expect("create evidence run dir");
    run_dir
}

/// Bank one capture into `run_dir` and return its sha384 — the read drill's `bank_capture`
/// closure body, moved VERBATIM: a recorded capture is never overwritten.
fn bank_capture_in(run_dir: &Path, name: &str, projection: &str) -> String {
    let path = run_dir.join(format!("{name}.json"));
    assert!(
        !path.exists(),
        "capture path already exists — a banked capture is never overwritten"
    );
    std::fs::write(&path, projection).expect("bank capture");
    sha384_hex(projection.as_bytes())
}

#[test]
fn live_readside_drills() {
    // Opt-in gate: parse the read contract (its process-env read). Not opted in → hermetic
    // skip; opted in but violated → drill_env_or_panic already panicked.
    let Some(env) = drill_env_from_process() else {
        eprintln!("live test: PHOTON_GMAIL_IT != 1 — skipping (default suite stays hermetic)");
        return;
    };

    let (bundle, bundle_sha384) = attested_preflight(&env);

    // The repo state the closure gate + manifest bind to — EXIT CODES checked, not just output
    // (a failed git invocation must never read as a clean tree), and repo-root
    // discovery included as a first-class gate input.
    let repo_state = probe_repo_state();
    // Closure runs only from a clean DETACHED worktree at a recorded SHA (design §4.5) —
    // checked BEFORE any drill dispatches.
    if env.mode == DrillMode::Closure {
        closure_repo_verdict(&repo_state).unwrap_or_else(|reason| panic!("{reason}"));
    }

    let evidence_dir = establish_evidence_dir(&env, &repo_state);
    let run_dir = create_run_dir(&evidence_dir);
    let bank_capture =
        |name: &str, projection: &str| -> String { bank_capture_in(&run_dir, name, projection) };

    // The probe (independent oracle) and the SUT (production read path, untouched).
    let probe = GmailProbe::new(&env.access_token);
    let transport =
        HttpGmailTransport::connect(&env.access_token).expect("connect SUT transport");
    let sut = GmailProviderPlacement::new(&transport, GmailUserId("me".to_string()));

    let mut matrix = ProofMatrix::default();
    let mut observations: Vec<serde_json::Value> = Vec::new();
    let mut capture_digests: Vec<(String, String)> = Vec::new();
    let mut inbox_candidate: Option<String> = None;

    // ---- R1: the five read-oracle arms (§4.1) ----
    for spec in &R1_ARMS {
        let run = run_r1_arm(&probe, &sut, spec);
        for obs in &run.observations {
            observations.push(obs.to_json());
        }
        match (&run.outcome, &run.capture_json) {
            // PROVED is keyed to its RECORDED capture: record first, record second.
            (ProofOutcome::Proved, Some(projection)) => {
                let name = format!("r1_{}_capture", spec.proof.name().to_ascii_lowercase());
                let digest = bank_capture(&name, projection);
                capture_digests.push((name.clone(), digest.clone()));
                matrix.record_proved(spec.proof, &name, &digest);
            }
            (outcome, _) => matrix.record(spec.proof, *outcome),
        }
        if spec.proof == ProofId::R1Inbox {
            inbox_candidate = run.id;
        }
    }

    // ---- R2: the A2 encoding probe (§4.2) ----
    let r2 = run_r2(&probe, &sut, env.a2_msg.as_deref());
    matrix.a2_observation = r2.observation;
    matrix.a2_inference = r2.inference;
    match (&r2.outcome, &r2.capture_json) {
        (ProofOutcome::Proved, Some(projection)) => {
            let digest = bank_capture("a2_encoding_capture", projection);
            capture_digests.push(("a2_encoding_capture".to_string(), digest.clone()));
            matrix.record_proved(ProofId::A2EncodingObserved, "a2_encoding_capture", &digest);
        }
        (outcome, _) => matrix.record(ProofId::A2EncodingObserved, *outcome),
    }
    if !r2.banked.is_null() {
        observations.push(serde_json::json!({ "arm": "A2", "banked": r2.banked }));
    }

    // ---- R3: the scope-denial drill (§4.3) — only with the denial token + attested bundle ----
    let mut denial_ledger_rows: Vec<LedgerEntry> = Vec::new();
    match (&env.denial_token, &inbox_candidate) {
        (Some(denial_token), Some(known_good_id)) => {
            let denial_probe = GmailProbe::new(denial_token);
            let denial_transport =
                HttpGmailTransport::connect(denial_token).expect("connect denial transport");
            let denial_sut =
                GmailProviderPlacement::new(&denial_transport, GmailUserId("me".to_string()));
            let (scope_403, casing, observation, capture) =
                run_r3(&denial_probe, &denial_sut, known_good_id);
            observations.push(serde_json::json!({ "arm": "R3", "observation": observation }));
            // Bank the sanitized envelope FIRST (capture-first, even when assertions failed),
            // then record the outcomes keyed to it.
            let envelope_digest = capture.map(|(name, digest, projection)| {
                let banked_digest = bank_capture(&name, &projection);
                debug_assert_eq!(banked_digest, digest, "banked digest must match computed");
                capture_digests.push((name.clone(), digest.clone()));
                (name, digest)
            });
            match (&scope_403, &envelope_digest) {
                (ProofOutcome::Proved, Some((name, digest))) => {
                    matrix.record_proved(ProofId::R3Scope403, name, digest)
                }
                (outcome, _) => matrix.record(ProofId::R3Scope403, *outcome),
            }
            match (&casing, &envelope_digest) {
                // The casing observation lives inside the same recorded envelope.
                (ProofOutcome::Proved, Some((name, digest))) => {
                    matrix.record_proved(ProofId::R3ErrorInfoCasing, name, digest)
                }
                (outcome, _) => matrix.record(ProofId::R3ErrorInfoCasing, *outcome),
            }
            // The denial probe's requests join the request census.
            denial_ledger_rows = denial_probe.ledger_snapshot();
            assert!(
                ledger_violations(&denial_ledger_rows).is_empty(),
                "W3: the denial probe dispatched off-fence requests"
            );
        }
        _ => {
            matrix.record(
                ProofId::R3Scope403,
                ProofOutcome::Unavailable("denial token absent or no known-good id"),
            );
            matrix.record(
                ProofId::R3ErrorInfoCasing,
                ProofOutcome::Unavailable("denial token absent or no known-good id"),
            );
        }
    }

    // ---- The live red-control (§7): a wrong expectation must go red ----
    let red = match &inbox_candidate {
        Some(id) => red_control(&sut, id),
        None => serde_json::json!({
            "identity": "deliberate wrong-expectation control",
            "went_red_as_required": serde_json::Value::Null,
            "reason": "no inbox candidate available",
        }),
    };
    // With a candidate available, ONLY an explicit true closes the control —
    // an errored repeat read or the wrong claim holding both void the run.
    if inbox_candidate.is_some() && red["went_red_as_required"] != serde_json::Value::Bool(true)
    {
        panic!(
            "the deliberate red-control did not demonstrate discrimination (repeat read \
             unhealthy or the wrong claim held) — run void"
        );
    }

    // ---- the request ledger over the REAL run — BOTH probes' rows ----
    let mut ledger = probe.ledger_snapshot();
    ledger.extend(denial_ledger_rows);
    assert!(
        ledger_violations(&ledger).is_empty(),
        "W3: the live run dispatched a non-GET or off-route request"
    );
    // The live run is pinned to the COMPILED host outright — loopback is a hermetic-harness
    // allowance only and must never appear in a live census.
    assert!(
        ledger.iter().all(|e| e.host == "gmail.googleapis.com"),
        "W3: live probe traffic left the compiled Gmail host"
    );

    // ---- Manifest (§4.5) ----
    // The toolchain string and the sanitizer source digest are
    // §4.5-REQUIRED provenance. Both previously degraded to sentinel strings
    // ("RUSTC-UNAVAILABLE" / "SOURCE-UNAVAILABLE"), which in closure would have recorded a
    // manifest whose provenance fields silently said "we could not tell" — the same
    // fail-open class. Both now route through the principle.
    let toolchain = establish_or_refuse(
        env.mode,
        "the toolchain identity (rustc --version)",
        // Honor Cargo's RUSTC override — the same env-first pattern as the
        // CARGO probe in `probe_effective_target_dir`: an unqualified PATH `rustc` can be a
        // DIFFERENT compiler than the one that built this test binary. Named residual, honest:
        // a `build.rustc` set only in Cargo config files has no stable runtime query and is
        // not detected here — the manifest attests the resolved-env/PATH compiler identity.
        std::process::Command::new(
            std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()),
        )
            .arg("--version")
            .output()
            .map_err(|e| e.to_string())
            .and_then(|o| {
                if o.status.success() {
                    // Empty output is NOT an identity: a zero-exit probe
                    // with no stdout would record empty provenance as "established".
                    let identity = String::from_utf8_lossy(&o.stdout).trim().to_string();
                    if identity.is_empty() {
                        Err("rustc --version exited 0 but emitted no identity".to_string())
                    } else {
                        Ok(identity)
                    }
                } else {
                    Err(format!("rustc exited {}", o.status))
                }
            }),
    )
    .unwrap_or_else(|| "RUSTC-UNAVAILABLE (smoke)".to_string());
    let sanitizer_sha384 = establish_or_refuse(
        env.mode,
        "the sanitizer source digest (tests/live_readside.rs)",
        std::fs::read(manifest_dir().join("tests/live_readside.rs"))
            .map(|bytes| sha384_hex(&bytes))
            .map_err(|e| e.to_string()),
    )
    .unwrap_or_else(|| "SOURCE-UNAVAILABLE (smoke)".to_string());

    // ---- The FINAL repository gate — AFTER every provenance read, immediately before the
    // manifest is built and written : the
    // toolchain probe and the sanitizer-source read above are themselves windows in which the
    // tree can move (an editor or formatter mid-attended-run) — a gate that ran BEFORE them
    // could pass, and the manifest would still record the old clean SHA beside a digest taken
    // from dirty bytes. Nothing but manifest construction sits between this probe and the
    // write.
    let post_repo_state = probe_repo_state();
    if env.mode == DrillMode::Closure {
        closure_final_repo_verdict(&repo_state, &post_repo_state)
            .unwrap_or_else(|reason| panic!("{reason}"));
    } else if post_repo_state.head_sha != repo_state.head_sha {
        eprintln!(
            "smoke WARNING: HEAD moved during the run (pre={} post={}); a closure run would \
             REFUSE here.",
            repo_state.head_sha, post_repo_state.head_sha
        );
    }

    let inputs = ManifestInputs {
        mode: env.mode,
        // The POST-run state is what the manifest certifies — identical to the pre-run SHA in
        // closure (enforced above), and honestly current in smoke.
        commit_sha: post_repo_state.head_sha.clone(),
        porcelain: post_repo_state.porcelain.clone(),
        porcelain_established: post_repo_state.porcelain_exit_ok,
        invocation: std::env::args().collect::<Vec<_>>().join(" "),
        toolchain,
        matrix: &matrix,
        observations: serde_json::Value::Array(observations),
        ledger: &ledger,
        bundle: &bundle,
        bundle_sha384,
        sanitizer_sha384,
        capture_digests,
        red_controls: red,
        now: now_unix(),
    };
    let manifest = build_manifest(&inputs)
        .unwrap_or_else(|reason| panic!("manifest construction REFUSED: {reason}"));
    let manifest_path = run_dir.join(format!(
        "photon-gmail-readside-manifest-{}-{}.json",
        std::process::id(),
        inputs.now
    ));
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).expect("manifest serializes"),
    )
    .expect("write manifest");
    eprintln!("manifest banked at {}", manifest_path.display());
    eprintln!("ProofId matrix:\n{}", matrix.render());

    // ---- Mode gate (§4.0): closure = all mandatory PROVED or INCOMPLETE; smoke reports ----
    match env.mode {
        DrillMode::Closure => {
            if let Err(verdict) = matrix.closure_verdict() {
                panic!("{verdict}");
            }
        }
        DrillMode::Smoke => {
            eprintln!("smoke mode: skips permitted, reported above, never citable (§4.0)");
        }
    }
}

// ===============================================================================================
// THE RIPPLE DRILL: hermetic witnesses of the drill body and its env contract,
// then the live case (OWED behind ADR-P010's gate enablement).
// ===============================================================================================

/// The message id every hermetic ripple row drives — a fixture value, never a provider id.
const RIPPLE_FIXTURE_MSG: &str = "ripple-fixture-msg";

/// A fixture label list, as the ripple case tables spell them.
type LabelList = &'static [&'static str];

fn label_set(list: &[&str]) -> BTreeSet<String> {
    list.iter().map(|l| l.to_string()).collect()
}

/// A minimal-message 200 body `{"id": .., "labelIds": [..]}`, built by serde so no escape
/// sequence rides in this file's source.
fn ripple_message_body(id: &str, labels: &[&str]) -> String {
    serde_json::json!({ "id": id, "labelIds": labels }).to_string()
}

/// Drive ONE hermetic ripple row over real loopback exchanges: one fixture origin answers
/// `responses` in order (the read route's, then the verb route's) through the PUBLIC transport —
/// `connect_for_test_fixture` opens the ADR-P010 gate for the loopback origin, which is the only
/// host it can ever be opened for. Returns the row and the request lines the fixture saw.
fn hermetic_ripple_row(
    direction: Direction,
    responses: Vec<String>,
) -> (Result<RippleRow, GmailError>, Vec<String>) {
    let (origin, handle) =
        serve_sequence(responses.into_iter().map(|body| (200, body)).collect());
    let transport = HttpGmailTransport::connect_for_test_fixture(&origin, "hermetic-test-token")
        .expect("fixture transport");
    let row = drive_ripple_row(
        &transport,
        &GmailUserId("me".to_string()),
        &GmailMessageId(RIPPLE_FIXTURE_MSG.to_string()),
        direction,
    );
    (row, handle.join().expect("fixture server thread"))
}

#[test]
fn ripple_drill_judges_within_the_declared_closure_on_every_direction() {
    // Every row carries atoms OUTSIDE the closure that the verb leaves UNCHANGED (UNREAD,
    // STARRED, IMPORTANT, a CATEGORY_* label, a user label): only the DELTA is judged, so they
    // must not read as a ripple. Each row's two routes are pinned from the fixture's request log.
    let cases: [(Direction, LabelList, LabelList, &str); 4] = [
        (
            Direction::Trash,
            &["INBOX", "UNREAD", "STARRED", "IMPORTANT", "CATEGORY_PROMOTIONS", "Label_7"],
            &["TRASH", "UNREAD", "STARRED", "IMPORTANT", "CATEGORY_PROMOTIONS", "Label_7"],
            "/trash?",
        ),
        // An untrash that puts INBOX back: INBOX is IN the declared closure, so its return is no
        // ripple (whether Gmail does this is what the live half observes).
        (
            Direction::Untrash,
            &["TRASH", "UNREAD", "Label_7"],
            &["INBOX", "UNREAD", "Label_7"],
            "/untrash?",
        ),
        (
            Direction::MarkSpam,
            &["INBOX", "UNREAD", "IMPORTANT", "Label_7"],
            &["SPAM", "UNREAD", "IMPORTANT", "Label_7"],
            "/modify?",
        ),
        (
            Direction::UnmarkSpam,
            &["SPAM", "UNREAD", "Label_7"],
            &["UNREAD", "Label_7"],
            "/modify?",
        ),
    ];
    for (direction, pre, post, route) in cases {
        let (row, requests) = hermetic_ripple_row(
            direction,
            vec![
                ripple_message_body(RIPPLE_FIXTURE_MSG, pre),
                ripple_message_body(RIPPLE_FIXTURE_MSG, post),
            ],
        );
        let row = row.unwrap_or_else(|e| panic!("{direction:?}: the row must drive, got {e:?}"));
        assert_eq!(row.direction, direction);
        assert_eq!(row.message, GmailMessageId(RIPPLE_FIXTURE_MSG.to_string()));
        assert_eq!(row.pre, label_set(pre), "{direction:?}: the FULL pre vector the read route answered");
        assert_eq!(row.post, label_set(post), "{direction:?}: the FULL post vector the VERB route answered");
        assert_eq!(row.verdict, RippleVerdict::WithinClosure, "{direction:?}");
        assert!(row.readback.is_none(), "{direction:?}: the body never re-reads");
        assert_eq!(requests.len(), 2, "{direction:?}: one read, then one write — {requests:?}");
        assert!(
            requests[0].starts_with("GET ")
                && requests[0].contains(&format!("/messages/{RIPPLE_FIXTURE_MSG}?")),
            "{direction:?}: the pre vector comes from the read route: {requests:?}"
        );
        assert!(
            requests[1].starts_with("POST ")
                && requests[1].contains(&format!("/messages/{RIPPLE_FIXTURE_MSG}{route}")),
            "{direction:?}: the verb rides its own route: {requests:?}"
        );
    }
}

#[test]
fn ripple_drill_an_atom_outside_the_closure_fails_the_row_loudly() {
    let cases: [(Direction, LabelList, LabelList, LabelList); 3] = [
        // The ripple the design names: a trash that ALSO drops IMPORTANT.
        (Direction::Trash, &["INBOX", "IMPORTANT", "UNREAD"], &["TRASH", "UNREAD"], &["IMPORTANT"]),
        // A spam mark that drops a USER label.
        (Direction::MarkSpam, &["INBOX", "Label_7"], &["SPAM"], &["Label_7"]),
        // …and the APPEARING direction: an untrash that brings a label outside the closure along.
        (Direction::Untrash, &["TRASH"], &["INBOX", "STARRED"], &["STARRED"]),
    ];
    for (direction, pre, post, unexpected) in cases {
        let (row, _) = hermetic_ripple_row(
            direction,
            vec![
                ripple_message_body(RIPPLE_FIXTURE_MSG, pre),
                ripple_message_body(RIPPLE_FIXTURE_MSG, post),
            ],
        );
        let row = row.unwrap_or_else(|e| panic!("{direction:?}: the row must drive, got {e:?}"));
        assert_eq!(
            row.verdict,
            RippleVerdict::OutsideClosure { unexpected: label_set(unexpected) },
            "{direction:?}: an atom outside the declared closure moved — the row must say so, \
             naming exactly that atom"
        );
    }
}

#[test]
fn ripple_drill_a_mismatched_id_echo_is_refused_and_produces_no_row() {
    // The VERB route answers for ANOTHER message: the route's own witness refuses, so the drill
    // yields an `Err` and NO row — never a row judged over a vector that is not this message's.
    for direction in Direction::ALL {
        let post: &[&str] = match direction {
            Direction::Trash => &["TRASH"],
            Direction::Untrash => &["INBOX"],
            Direction::MarkSpam => &["SPAM"],
            Direction::UnmarkSpam => &[],
        };
        let (row, requests) = hermetic_ripple_row(
            direction,
            vec![
                ripple_message_body(RIPPLE_FIXTURE_MSG, &["INBOX"]),
                ripple_message_body("another-message", post),
            ],
        );
        match row {
            Ok(_) => panic!("{direction:?}: an id echo for another message produced a row"),
            Err(e) => assert_eq!(e, GmailError::Unknown, "{direction:?}: the witness's refusal"),
        }
        assert_eq!(requests.len(), 2, "{direction:?}: {requests:?}");
    }
    // The READ route answering for another message refuses too — and then NO write is sent.
    let (row, requests) = hermetic_ripple_row(
        Direction::Trash,
        vec![
            ripple_message_body("another-message", &["INBOX"]),
            ripple_message_body(RIPPLE_FIXTURE_MSG, &["TRASH"]),
        ],
    );
    assert!(row.is_err(), "a pre read for another message must refuse the row");
    assert_eq!(requests.len(), 1, "a refused pre read sends no write: {requests:?}");
}

#[test]
fn ripple_closure_is_exactly_the_declared_set_per_direction() {
    let trash_pair = label_set(&["TRASH", "INBOX"]);
    let spam_pair = label_set(&["SPAM", "INBOX"]);
    assert_eq!(ripple_closure(Direction::Trash), trash_pair);
    assert_eq!(
        ripple_closure(Direction::Untrash),
        trash_pair,
        "Untrash declares INBOX too (it returns the message to All Mail; whether Gmail puts INBOX \
         back is the hypothesis the drill judges)"
    );
    assert_eq!(ripple_closure(Direction::MarkSpam), spam_pair);
    assert_eq!(ripple_closure(Direction::UnmarkSpam), spam_pair);
    // A round trip is judged against ONE set: each direction shares its inverse's closure.
    for direction in Direction::ALL {
        assert_eq!(direction.inverse().inverse(), direction);
        assert_eq!(ripple_closure(direction.inverse()), ripple_closure(direction));
    }
}

#[test]
fn ripple_row_evaluation_fails_loudly_when_the_route_contradicts_the_declared_inbox_target() {
    // The per-row evaluation the LIVE half runs, fed fixture rows. The
    // live half cannot run at this tree, so this is the only execution that code gets today.
    let row = |direction: Direction, pre: &BTreeSet<String>, post: &BTreeSet<String>| RippleRow {
        message: GmailMessageId(RIPPLE_FIXTURE_MSG.to_string()),
        direction,
        pre: pre.clone(),
        post: post.clone(),
        verdict: ripple_verdict(pre, post, &ripple_closure(direction)),
        readback: None,
    };

    // THE CASE THE CLOSURE VERDICT CANNOT SEE: an untrash that puts INBOX back. INBOX is IN the
    // closure, so the verdict is `WithinClosure` — while the declared target is falsified.
    assert!(
        !declared_inbox_target(Direction::Untrash),
        "precondition: production declares untrash → membership:INBOX false"
    );
    let untrash_back_to_inbox = row(
        Direction::Untrash,
        &label_set(&["TRASH", "UNREAD"]),
        &label_set(&["INBOX", "UNREAD"]),
    );
    assert_eq!(untrash_back_to_inbox.verdict, RippleVerdict::WithinClosure, "precondition");
    let failures = ripple_row_failures(3, &untrash_back_to_inbox);
    assert_eq!(failures.len(), 1, "exactly the INBOX-direction failure: {failures:?}");
    assert!(
        failures[0].starts_with("message #3 untrash: the declared INBOX direction for Untrash"),
        "the failure names the ordinal, the direction and the falsified declaration: {failures:?}"
    );
    assert!(!failures[0].contains(RIPPLE_FIXTURE_MSG), "ID-free: {failures:?}");

    // Every direction, both polarities, the target taken from production (never restated): a
    // route whose INBOX membership differs from the declared target fails the row with exactly
    // one line; one that matches it adds none. Every delta here stays inside the closure, so the
    // INBOX check is the only thing that can speak.
    for direction in Direction::ALL {
        let declared = declared_inbox_target(direction);
        let (verb_label, forward) = match direction {
            Direction::Trash => ("TRASH", true),
            Direction::Untrash => ("TRASH", false),
            Direction::MarkSpam => ("SPAM", true),
            Direction::UnmarkSpam => ("SPAM", false),
        };
        let pre = if forward {
            label_set(&["INBOX", "UNREAD"])
        } else {
            label_set(&[verb_label, "UNREAD"])
        };
        for inbox_in_post in [false, true] {
            let mut post = if forward {
                label_set(&[verb_label, "UNREAD"])
            } else {
                label_set(&["UNREAD"])
            };
            if inbox_in_post {
                post.insert("INBOX".to_string());
            }
            let driven = row(direction, &pre, &post);
            assert_eq!(driven.verdict, RippleVerdict::WithinClosure, "{direction:?} precondition");
            let failures = ripple_row_failures(0, &driven);
            if inbox_in_post == declared {
                assert!(failures.is_empty(), "{direction:?}: matches the declaration: {failures:?}");
            } else {
                assert_eq!(failures.len(), 1, "{direction:?}: {failures:?}");
                assert!(
                    failures[0].contains("the declared INBOX direction")
                        && failures[0].contains("is falsified by the live route"),
                    "{direction:?}: {failures:?}"
                );
            }
        }
    }

    // …and the closure check still speaks beside it: an outside-closure delta is its own line.
    let both = row(
        Direction::Untrash,
        &label_set(&["TRASH"]),
        &label_set(&["INBOX", "STARRED"]),
    );
    assert_eq!(ripple_row_failures(1, &both).len(), 2, "two independent failures, two lines");
}

#[test]
fn ripple_rows_record_id_free_with_system_labels_named_and_user_labels_counted() {
    let first = GmailMessageId(SENTINEL.to_string());
    let second = GmailMessageId("SENTINEL-SECOND-MSG-ID-77aa".to_string());
    let row = |message: &GmailMessageId,
               direction: Direction,
               pre: &[&str],
               post: &[&str],
               readback: Option<&[&str]>| {
        let (pre, post) = (label_set(pre), label_set(post));
        RippleRow {
            message: message.clone(),
            direction,
            verdict: ripple_verdict(&pre, &post, &ripple_closure(direction)),
            pre,
            post,
            readback: readback.map(label_set),
        }
    };
    let rows = vec![
        row(&first, Direction::Trash, &["INBOX", "UNREAD", "Label_7"], &["TRASH", "UNREAD", "Label_7"], None),
        row(
            &first,
            Direction::Untrash,
            &["TRASH", "UNREAD", "Label_7"],
            &["UNREAD", "Label_7"],
            Some(&["UNREAD", "Label_7"]),
        ),
        row(&second, Direction::MarkSpam, &["INBOX", "Label_7", "Label_99"], &["SPAM", "Label_99"], None),
    ];
    let banked = bank_ripple_rows(&rows);
    let set = |system: &[&str], others: usize| {
        serde_json::json!({ "system_labels": system, "other_label_count": others })
    };
    assert_eq!(
        banked,
        serde_json::json!({
            "schema": "photon-s1-ripple-rows/1",
            "sanitizer": RIPPLE_ROWS_SANITIZER,
            "rows": [
                {
                    "row": 0, "message_ordinal": 0, "direction": "trash",
                    "closure": set(&["INBOX", "TRASH"], 0),
                    "pre": set(&["INBOX", "UNREAD"], 1), "post": set(&["TRASH", "UNREAD"], 1),
                    "verdict": "within_closure", "unexpected": null, "readback": null,
                },
                {
                    "row": 1, "message_ordinal": 0, "direction": "untrash",
                    "closure": set(&["INBOX", "TRASH"], 0),
                    "pre": set(&["TRASH", "UNREAD"], 1), "post": set(&["UNREAD"], 1),
                    "verdict": "within_closure", "unexpected": null,
                    "readback": set(&["UNREAD"], 1),
                },
                {
                    "row": 2, "message_ordinal": 1, "direction": "mark_spam",
                    "closure": set(&["INBOX", "SPAM"], 0),
                    "pre": set(&["INBOX"], 2), "post": set(&["SPAM"], 1),
                    "verdict": "outside_closure", "unexpected": set(&[], 1),
                    "readback": null,
                },
            ],
        })
    );
    // ID-free, by the text: no provider message id and no user label ever reaches the record.
    let text = banked.to_string();
    for leak in [SENTINEL, "SENTINEL-SECOND", "Label_"] {
        assert!(!text.contains(leak), "the banked rows leaked {leak:?}: {text}");
    }
}

/// The read drill's minimal VALID contract, reused by the ripple env witnesses.
const RIPPLE_READ_CONTRACT: [(&str, &str); 4] = [
    ("PHOTON_GMAIL_IT", "1"),
    ("PHOTON_GMAIL_ACCESS_TOKEN", "tok-main"),
    ("PHOTON_GMAIL_ATTESTATION", "/parked/bundle.json"),
    ("PHOTON_GMAIL_GRANT_HIGH_WATER", "4"),
];

fn with_read_contract(extra: &[(&'static str, &'static str)]) -> Vec<(&'static str, &'static str)> {
    RIPPLE_READ_CONTRACT.iter().chain(extra).copied().collect()
}

#[test]
fn ripple_env_not_opted_in_is_a_clean_skip_even_when_the_read_drill_is() {
    assert_eq!(parse_ripple_env(env_of(&[])).expect("no opt-in is never an error"), None);
    // The read drill's own opt-in, whole and valid, never starts the WRITE drill.
    let read_only = with_read_contract(&[("PHOTON_GMAIL_RIPPLE_MESSAGES", "m1")]);
    assert_eq!(parse_ripple_env(env_of(&read_only)).expect("not opted in"), None);
    let ripple_zero =
        with_read_contract(&[("PHOTON_GMAIL_RIPPLE_IT", "0"), ("PHOTON_GMAIL_RIPPLE_MESSAGES", "m1")]);
    assert_eq!(parse_ripple_env(env_of(&ripple_zero)).expect("RIPPLE_IT=0 is not opted in"), None);
    // …and the read contract parses exactly as before with the ripple variables beside it.
    let both = with_read_contract(&[("PHOTON_GMAIL_RIPPLE_IT", "1")]);
    assert!(parse_drill_env(env_of(&both)).expect("the read contract is unchanged").is_some());
}

#[test]
fn ripple_env_opted_in_violations_are_errors_never_skips() {
    // Opted into the ripple drill WITHOUT the read drill's opt-in: an ERROR — the write drill
    // never runs outside the read contract, and a silent skip here would be a hidden failure.
    let no_read_opt_in =
        [("PHOTON_GMAIL_RIPPLE_IT", "1"), ("PHOTON_GMAIL_RIPPLE_MESSAGES", "m1")];
    let parsed = parse_ripple_env(env_of(&no_read_opt_in));
    assert!(parsed.is_err(), "RIPPLE_IT=1 without PHOTON_GMAIL_IT=1 must be an Err: {parsed:?}");
    // The read opt-in present but its contract broken: the read parser's refusal, propagated.
    let broken_read = [
        ("PHOTON_GMAIL_RIPPLE_IT", "1"),
        ("PHOTON_GMAIL_IT", "1"),
        ("PHOTON_GMAIL_RIPPLE_MESSAGES", "m1"),
    ];
    let parsed = parse_ripple_env(env_of(&broken_read));
    assert!(parsed.is_err(), "a broken read contract must refuse the ripple run: {parsed:?}");
    // The message list: missing, blank, an empty entry, or a repeated id all refuse.
    let opted = with_read_contract(&[("PHOTON_GMAIL_RIPPLE_IT", "1")]);
    let parsed = parse_ripple_env(env_of(&opted));
    assert!(parsed.is_err(), "no PHOTON_GMAIL_RIPPLE_MESSAGES must be an Err: {parsed:?}");
    for messages in ["   ", "m1,,m2", "m1, ", "m1,m2,m1"] {
        let env = with_read_contract(&[
            ("PHOTON_GMAIL_RIPPLE_IT", "1"),
            ("PHOTON_GMAIL_RIPPLE_MESSAGES", messages),
        ]);
        let parsed = parse_ripple_env(env_of(&env));
        assert!(parsed.is_err(), "messages {messages:?} must refuse: {parsed:?}");
    }
}

#[test]
fn ripple_env_full_contract_carries_the_read_contract_whole_plus_the_message_list() {
    let full = with_read_contract(&[
        ("PHOTON_GMAIL_RIPPLE_IT", "1"),
        ("PHOTON_GMAIL_RIPPLE_MESSAGES", " m-inbox , m-archived "),
    ]);
    let env = parse_ripple_env(env_of(&full))
        .expect("the full contract parses")
        .expect("opted in");
    assert_eq!(env.messages, vec!["m-inbox".to_string(), "m-archived".to_string()]);
    assert_eq!(
        Some(env.drill),
        parse_drill_env(env_of(&with_read_contract(&[]))).expect("the read contract parses"),
        "the read contract rides WHOLE, parsed by the read drill's own parser"
    );
}

#[test]
fn ripple_env_panic_shell_panics_on_a_violated_contract() {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        ripple_env_or_panic(env_of(&[("PHOTON_GMAIL_RIPPLE_IT", "1")]))
    }));
    assert!(result.is_err(), "ripple_env_or_panic must panic, not skip");
}

/// The host the live ripple drill's gate line asks ADR-P010 to open — derived from the COMPILED
/// endpoint, never configured.
fn ripple_live_host() -> &'static str {
    GMAIL_ENDPOINT
        .trim_start_matches("https://")
        .trim_end_matches('/')
}

#[test]
fn ripple_drill_gate_line_is_refused_at_this_tree() {
    // The live drill's precondition, witnessed hermetically: the gate line asks for the
    // compiled Gmail host, and at this tree ADR-P010's gate refuses it. OWED-state pin — the
    // day live writes are enabled this fails on purpose: update the live drill's
    // gate line and this pin together.
    assert_eq!(ripple_live_host(), "gmail.googleapis.com");
    assert_eq!(
        DestructiveWriteGate::allow_test_host(ripple_live_host()).err(),
        Some(GateError::NonLocalHostRefused),
        "no live write is constructible at this tree — the ripple drill's live half is OWED"
    );
}

/// THE RIPPLE DRILL MATRIX, LIVE. Per operator-seeded message
/// (`PHOTON_GMAIL_RIPPLE_MESSAGES` — the drill seeds nothing and never touches a message it was
/// not handed), Trash→Untrash then MarkSpam→UnmarkSpam through [`drive_ripple_row`]: the full
/// pre/post vectors per row, the verdict against the declared closure, and every forward verb
/// RESTORED by its inverse with the post-restore vector re-read and recorded — all BEFORE any
/// verdict is asserted, so a failing row still leaves the account restored and the evidence
/// written. Then: every row `WithinClosure`, every row's INBOX membership equal to its
/// direction's declared target ([`ripple_row_failures`]), every round trip
/// within the closure, and every re-read equal to the restore route's own answer.
///
/// **OWED — it cannot run at this tree.** Opted in, it runs the attested preflight and then
/// FAILS LOUD at its gate line: ADR-P010's `DestructiveWriteGate::allow_test_host` refuses the
/// compiled Gmail host by design, and this drill never routes a write around the gate. The live
/// run is the operator's attended drill once writes are enabled; nothing below the gate line
/// changes then.
#[test]
fn ripple_drill_trash_untrash_spam_unspam_delta_within_declared_closure() {
    // Opt-in gate: the ripple contract, which carries the read contract whole. Not opted in →
    // the ONE permitted non-run; opted in but violated → ripple_env_or_panic already panicked.
    let Some(ripple) = ripple_env_from_process() else {
        eprintln!(
            "live ripple drill: PHOTON_GMAIL_RIPPLE_IT != 1 — skipping (default suite stays hermetic)"
        );
        return;
    };
    let env = &ripple.drill;

    // The SAME attested preflight the read drill runs — env + file only, no wire call.
    let (bundle, bundle_sha384) = attested_preflight(env);

    // ---- THE GATE LINE (ADR-P010) ----
    // A live write needs the destructive-write gate opened for the COMPILED Gmail host. At this
    // tree `allow_test_host` refuses every non-loopback host BY DESIGN
    // (`crates/aruna-gmail/src/transport.rs`, `DestructiveWriteGate`), and this drill never goes
    // around it: no hand-rolled write path, no fixture origin, no raw probe client. The day
    // ADR-P010's gate is explicitly enabled, THIS statement is what changes (with its hermetic
    // pin, `ripple_drill_gate_line_is_refused_at_this_tree`) — nothing below it.
    let gate = DestructiveWriteGate::allow_test_host(ripple_live_host()).unwrap_or_else(|refusal| {
        panic!(
            "live ripple drill REFUSED at its gate line ({refusal:?}): live writes need \
             ADR-P010's gate enablement; not constructible at this tree (written over d675c68, \
             where DestructiveWriteGate::allow_test_host refuses every non-loopback host). This \
             is a FAILURE, never a skip."
        )
    });
    let transport = HttpGmailTransport::connect(&env.access_token)
        .expect("connect SUT transport")
        .with_destructive_writes(gate);
    // The `me` alias on the wire, exactly as the read drill (the principal half stays owed).
    let user = GmailUserId("me".to_string());

    // Repo + evidence gates, through the read drill's own helpers.
    let repo_state = probe_repo_state();
    if env.mode == DrillMode::Closure {
        closure_repo_verdict(&repo_state).unwrap_or_else(|reason| panic!("{reason}"));
    }
    let evidence_dir = establish_evidence_dir(env, &repo_state);
    let run_dir = create_run_dir(&evidence_dir);

    // ---- The matrix. Panics name the message ORDINAL, never its id (ID-free output). ----
    let mut rows: Vec<RippleRow> = Vec::new();
    let mut round_trips: Vec<serde_json::Value> = Vec::new();
    let mut failures: Vec<String> = Vec::new();
    for (ordinal, raw_id) in ripple.messages.iter().enumerate() {
        let message = GmailMessageId(raw_id.clone());
        for forward in [Direction::Trash, Direction::MarkSpam] {
            let inverse = forward.inverse();
            let forward_row = drive_ripple_row(&transport, &user, &message, forward)
                .unwrap_or_else(|e| {
                    panic!("message #{ordinal}: the {} row was refused: {e:?}", forward.name())
                });
            let inverse_row = drive_ripple_row(&transport, &user, &message, inverse)
                .unwrap_or_else(|e| {
                    panic!(
                        "message #{ordinal}: the {} RESTORE was refused ({e:?}) — the message \
                         may be left in its post-{} state",
                        inverse.name(),
                        forward.name()
                    )
                });
            let readback = transport.message_labels(&user, &message).unwrap_or_else(|e| {
                panic!("message #{ordinal}: the post-restore read was refused: {e:?}")
            });
            let round_trip = ripple_verdict(&forward_row.pre, &readback, &ripple_closure(forward));
            for row in [&forward_row, &inverse_row] {
                failures.extend(ripple_row_failures(ordinal, row));
            }
            if let RippleVerdict::OutsideClosure { unexpected } = &round_trip {
                failures.push(format!(
                    "message #{ordinal} {}→{}: the round trip moved labels outside the declared \
                     closure — {}",
                    forward.name(),
                    inverse.name(),
                    bank_label_set(unexpected)
                ));
            }
            if readback != inverse_row.post {
                failures.push(format!(
                    "message #{ordinal} {}: the re-read disagrees with the route's own answer",
                    inverse.name()
                ));
            }
            round_trips.push(serde_json::json!({
                "message_ordinal": ordinal,
                "forward": forward.name(),
                "inverse": inverse.name(),
                "round_trip_verdict": round_trip.as_token(),
                "restored_exactly": readback == forward_row.pre,
                "readback_matches_the_restore_answer": readback == inverse_row.post,
            }));
            rows.push(forward_row);
            rows.push(RippleRow {
                readback: Some(readback),
                ..inverse_row
            });
        }
    }

    // ---- Bank FIRST (capture-first, even when a verdict failed) ----
    // `message_ordinal` in both arrays is the env list's order: rows are pushed in that order,
    // so `bank_ripple_rows`' first-appearance ordinal and the loop's `ordinal` agree.
    let projection = serde_json::to_string_pretty(&serde_json::json!({
        "rows": bank_ripple_rows(&rows),
        "round_trips": round_trips,
    }))
    .expect("ripple rows serialize");
    let rows_digest = bank_capture_in(&run_dir, "s1_ripple_rows", &projection);

    // The FINAL repository gate immediately before the manifest (the read drill's order).
    let post_repo_state = probe_repo_state();
    if env.mode == DrillMode::Closure {
        closure_final_repo_verdict(&repo_state, &post_repo_state)
            .unwrap_or_else(|reason| panic!("{reason}"));
    }
    // BESIDE `build_manifest`, not through it: that schema is the read drill's (ProofMatrix +
    // the probe's request census), and the ripple drill has neither — it makes no probe call.
    let now = now_unix();
    let manifest = serde_json::json!({
        "slice": "issue-75 S1 ripple drill matrix (Task B9)",
        "design": "docs/superpowers/specs/2026-08-26-75-bulk-triage-verbs-design.md (v7 §1-§2)",
        "mode": match env.mode { DrillMode::Smoke => "smoke", DrillMode::Closure => "closure" },
        "commit_sha": post_repo_state.head_sha,
        "clean_tree": post_repo_state.porcelain_exit_ok
            && porcelain_is_clean(&post_repo_state.porcelain),
        "discovery_revision": DISCOVERY_REVISION,
        "attestation": {
            "bundle_sha384": bundle_sha384,
            "helper_source_sha384": bundle.helper_source_sha384,
            "effective_main_scopes": bundle.effective_main_scopes,
        },
        "captures": [{ "capture": "s1_ripple_rows", "sha384": rows_digest }],
        "rows_sanitizer": RIPPLE_ROWS_SANITIZER,
        "banked_at_unix": now,
    });
    let manifest_path = run_dir.join(format!(
        "photon-gmail-ripple-manifest-{}-{now}.json",
        std::process::id()
    ));
    assert!(
        !manifest_path.exists(),
        "ripple manifest path already exists — a banked manifest is never overwritten"
    );
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).expect("manifest serializes"),
    )
    .expect("write ripple manifest");
    eprintln!("ripple manifest banked at {}", manifest_path.display());

    // ---- Only NOW the verdicts (v7 §1-§2: an unexpected atom FAILS the claim LOUDLY) ----
    assert!(
        failures.is_empty(),
        "the ripple drill FAILED the restores-prior-state claim (v7 §1-§2):\n{}",
        failures.join("\n")
    );
}
