//! **the four-byte IPC-surface witness**: the surface is manifest + plugins + config, not
//! `generate_handler!` alone. The "no BLACK verb reachable" witness reads the capability
//! manifest + plugin registration + CSP string + command registration — all four bytes.
//!
//! Why a FILE-READING test and not a runtime assertion: three of the four bytes are consumed by
//! Tauri's build/codegen machinery, not by code we can call — the capability manifest is compiled
//! by `tauri-build`, the CSP is injected into the built asset, and a plugin registration is a
//! dependency plus a builder line. The only place all four are simultaneously observable is their
//! source bytes, read at test time from `CARGO_MANIFEST_DIR`. A test that read anything else would
//! be witnessing a copy.
//!
//! What each byte defends (adversary: a hostile script in the renderer, reached
//! via in-process code in an API-invited sandboxed context; these are DEFENSE IN DEPTH, labelled
//! as such, never claimed as a wall against a box-owning actor):
//! - the capability manifest bounds what the webview may ASK Tauri for;
//! - the CSP bounds what the webview may LOAD and where it may CONNECT;
//! - the absent opener plugin means no OS-handoff command exists to reach at all;
//! - the command registration is the whole list of engine doors — and it must carry no BLACK verb
//!   (send/compose) and no sever actuator (the kill switch is a status in v1, not a control).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// The v1 command set. Set-equality is asserted in BOTH directions:
/// a missing command is a broken product, an EXTRA one is a widened IPC surface.
/// **The witness is EDITED DELIBERATELY when a door is added**. This list is the
/// contract, so a new command has to appear here before it can be registered — that edit is the
/// review, not a bypass of it. `refresh_more_inbox` is the provider-continuation door: without it a
/// mailbox larger than one provider page could never ingest past its newest page, because
/// `refresh_inbox` fetched page 1 and DISCARDED the continuation token. It is a refresh
/// continuation, not a new capability: same single-flight family, same cadence gate, same
/// credential gate, read-only, and it carries no BLACK verb and no actuator.
const V1_COMMANDS: &[&str] = &[
    "inbox_page",
    "refresh_inbox",
    "refresh_more_inbox",
    "message_body",
    "archive",
    "unarchive",
    "set_star",
    "undo",
    "undo_presentation",
    "session_status",
    // The four verb doors + mark-read, and the plan
    // doors mint/review/approve/apply (pause/cancel are not yet exposed), plus the ONE typed knob door.
    // `trash`/`mark_spam` MINT a one-member plan — they never dispatch a RED effect themselves.
    "trash",
    "untrash",
    "mark_spam",
    "unmark_spam",
    "set_seen",
    "plan_mint",
    "plan_review",
    "plan_approve",
    "plan_apply",
    "set_knob",
];

/// Names that must not exist as a command under any registration state — the non-claims made
/// executable. `sever` is the kill-switch actuator ruled out ("BLACK in v1 is a status, not
/// a control"); `send`/`compose`/`reply`/`forward` are the BLACK verbs that do not exist
/// engine-side and must not appear to exist here either.
const FORBIDDEN_COMMAND_FRAGMENTS: &[&str] =
    &["sever", "send", "compose", "reply", "forward", "greet"];

/// `CARGO_MANIFEST_DIR` read at RUNTIME (`std::env::var`, which Cargo
/// sets fresh for every test-binary run), never `env!` (a COMPILE-TIME bake a test binary reused
/// unrecompiled from another tree — a shared `CARGO_TARGET_DIR` — would carry from the tree it was
/// actually compiled in).
fn manifest_dir() -> PathBuf {
    PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR for every test binary it runs"))
}

fn read(rel: &str) -> String {
    let path: PathBuf = manifest_dir().join(rel);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("the witness must be able to read {}: {e}", path.display()))
}

fn json(rel: &str) -> serde_json::Value {
    serde_json::from_str(&read(rel))
        .unwrap_or_else(|e| panic!("{rel} must be valid JSON for the witness to read it: {e}"))
}

// ===============================================================================================
// BYTE 1 — the capability manifest
// ===============================================================================================

#[test]
fn byte1_the_capability_manifest_grants_core_default_and_nothing_else() {
    let manifest = json("capabilities/default.json");
    let permissions = manifest
        .get("permissions")
        .and_then(|p| p.as_array())
        .expect("the capability manifest must carry a permissions array");

    let granted: Vec<&str> = permissions
        .iter()
        .map(|p| {
            p.as_str()
                .expect("every permission entry must be a plain string identifier")
        })
        .collect();

    assert_eq!(
        granted,
        vec!["core:default"],
        "§2 S3 CAPABILITY fold: the main window gets the minimum core permissions and NOTHING \
         else — `opener:default` is dropped, and any future grant is a reviewed widening of the \
         IPC surface, not an edit"
    );
    assert!(
        !granted.iter().any(|p| p.starts_with("opener:")),
        "no opener-class permission may be granted (§5: no attachment/link OS handoff in v1)"
    );
}

// ===============================================================================================
// BYTE 2 — the CSP + `withGlobalTauri`
// ===============================================================================================

#[test]
fn byte2_with_global_tauri_is_off() {
    let conf = json("tauri.conf.json");
    assert_eq!(
        conf.pointer("/app/withGlobalTauri"),
        Some(&serde_json::Value::Bool(false)),
        "§2 S3: `withGlobalTauri: false` — the invoke surface must not be hung on `window` for \
         any script on the page to find"
    );
}

#[test]
fn byte2_the_csp_is_a_real_policy_naming_the_ipc_sources_and_no_remote_origin() {
    let conf = json("tauri.conf.json");
    let csp = conf
        .pointer("/app/security/csp")
        .expect("app.security.csp must be present");
    let csp = csp.as_str().unwrap_or_else(|| {
        panic!("§2 S3: the CSP must be a non-null policy STRING; found {csp}")
    });

    // The IPC allowance, without which the command channel simply does not work (Tauri v2 CSP
    // doc — a bare `'self'` breaks invoke). Its presence is a REQUIREMENT, not a leak.
    assert!(
        csp.contains("ipc:"),
        "the policy must allow the `ipc:` scheme or the command channel is dead: {csp}"
    );
    assert!(
        csp.contains("http://ipc.localhost"),
        "the policy must allow Tauri's `http://ipc.localhost` IPC source: {csp}"
    );

    // Every directive, tokenized. The property: local assets + the narrow IPC sources
    // only — no remote origin anywhere in the policy.
    for directive in csp.split(';') {
        let directive = directive.trim();
        if directive.is_empty() {
            continue;
        }
        let mut tokens = directive.split_whitespace();
        let name = tokens.next().expect("a non-empty directive names itself");

        for source in tokens {
            if source.contains("://") || source.starts_with("//") {
                assert_eq!(
                    source, "http://ipc.localhost",
                    "the ONLY absolute origin the policy may name is Tauri's IPC source; \
                     `{name}` names `{source}`"
                );
            }
            assert!(
                !source.eq_ignore_ascii_case("*"),
                "`{name}` must not name the `*` wildcard"
            );
            assert!(
                !source.eq_ignore_ascii_case("'unsafe-eval'"),
                "`{name}` must not permit eval (§4 R3: no eval in the IPC posture)"
            );
        }

        if name == "script-src" {
            assert!(
                !directive.contains("unsafe-inline"),
                "script-src must not permit inline script — Tauri injects nonces/hashes for its \
                 own scripts at build; we never hand-wave the whole class open: {directive}"
            );
        }
    }

    // The named non-negotiables, asserted by directive rather than by substring so a reordering
    // edit cannot pass while a weakening one fails.
    for required in [
        "default-src 'self'",
        "object-src 'none'",
        "frame-src 'none'",
        "base-uri 'self'",
        "form-action 'none'",
    ] {
        assert!(
            csp.split(';').any(|d| d.trim() == required),
            "the policy must carry `{required}` verbatim: {csp}"
        );
    }
}

// ===============================================================================================
// BYTE 3 — plugin registration (the manifest half and the builder half)
// ===============================================================================================

/// Dependency KEYS declared in `Cargo.toml` — the left-hand side of a manifest entry, ignoring
/// comments. Keys and not raw text: the manifest is allowed to EXPLAIN in prose why a crate is
/// absent (that comment is what stops it being re-added), and a substring scan would read the
/// explanation as the thing it forbids.
fn declared_dependencies(cargo: &str) -> BTreeSet<String> {
    cargo
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#') && line.contains('='))
        .filter_map(|line| line.split('=').next())
        .map(|key| key.trim().trim_matches('"').to_string())
        .collect()
}

#[test]
fn byte3_the_opener_plugin_is_absent_from_the_manifest_and_the_builder() {
    let cargo = read("Cargo.toml");
    assert!(
        !declared_dependencies(&cargo).contains("tauri-plugin-opener"),
        "§2 S3: the opener plugin is REMOVED, not merely un-permissioned — a dependency that is \
         still compiled in is a door one builder line away from being open"
    );
    // The engine and both transports ARE here ("src-tauri path-depends on `aruna` + both
    // transport crates"): the shell that cannot reach the engine is not the shell.
    for required in ["aruna", "aruna-gmail", "aruna-jmap"] {
        assert!(
            declared_dependencies(&cargo).contains(required),
            "the shell must depend on `{required}`"
        );
    }

    let lib = read("src/lib.rs");
    assert!(
        !lib.contains("tauri_plugin_opener"),
        "no opener plugin may be registered on the builder"
    );
    // The general form: v1 registers NO plugin at all. Every plugin is a capability surface, and
    // adding one is a reviewed decision — this line is what makes that review happen.
    assert!(
        !lib.contains(".plugin("),
        "v1 registers no Tauri plugin; adding one widens the IPC surface and needs its own review"
    );
}

// ===============================================================================================
// BYTE 4 — command registration
// ===============================================================================================

/// Pull the comma-separated identifier list out of `tauri::generate_handler![... ]`, keeping the
/// LAST path segment of each entry (`commands::archive` → `archive`).
fn registered_commands(source: &str) -> BTreeSet<String> {
    let start = source
        .find("generate_handler![")
        .expect("the builder must register commands through generate_handler!");
    let open = start + "generate_handler![".len();
    let len = source[open..]
        .find(']')
        .expect("the generate_handler! list must be closed");
    source[open..open + len]
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(|entry| entry.rsplit("::").next().unwrap().to_string())
        .collect()
}

/// Every `#[tauri::command]`-annotated function name in the source — the set of doors that EXIST,
/// which must equal the set of doors that are REGISTERED.
fn declared_commands(source: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for (idx, _) in source.match_indices("#[tauri::command]") {
        let tail = &source[idx..];
        let fn_at = tail.find("fn ").expect("a command attribute precedes a fn");
        let after = &tail[fn_at + 3..];
        let end = after
            .find(|c: char| !(c.is_alphanumeric() || c == '_'))
            .unwrap_or(after.len());
        names.insert(after[..end].to_string());
    }
    names
}

#[test]
fn byte4_the_registered_command_list_is_exactly_the_v1_set() {
    let lib = read("src/lib.rs");
    let registered = registered_commands(&lib);
    let expected: BTreeSet<String> = V1_COMMANDS.iter().map(|s| s.to_string()).collect();

    assert_eq!(
        registered, expected,
        "the IPC door list must be EXACTLY the design's v1 set — a missing name is a broken \
         product, an extra one is a widened surface"
    );
}

#[test]
fn byte4_every_declared_command_is_registered_and_vice_versa() {
    let lib = read("src/lib.rs");
    assert_eq!(
        declared_commands(&lib),
        registered_commands(&lib),
        "a `#[tauri::command]` function that is not in `generate_handler!` is a door waiting for \
         one line, and a registered name with no function does not compile — the two sets are \
         one contract"
    );
}

#[test]
fn byte4_no_black_verb_and_no_sever_actuator_is_reachable() {
    let lib = read("src/lib.rs");
    let mut all: BTreeSet<String> = registered_commands(&lib);
    all.extend(declared_commands(&lib));

    for name in &all {
        for fragment in FORBIDDEN_COMMAND_FRAGMENTS {
            assert!(
                !name.contains(fragment),
                "command `{name}` carries the forbidden fragment `{fragment}` — §5 non-claims: \
                 no send/compose (no BLACK verb exists engine-side) and no sever actuator (BLACK \
                 is a STATUS in v1, never a renderer-callable control)"
            );
        }
    }
    assert!(
        !all.contains("greet"),
        "the scaffold `greet` command must be gone"
    );
}

// ===============================================================================================
// BYTE 4b — the setup path resolution
// ===============================================================================================

/// A path the resolver could not answer must not become the PROCESS WORKING DIRECTORY.
///
/// `setup` resolved the platform app-data dir and the home dir with
/// `unwrap_or_else(|_| PathBuf::from("."))`, so an unresolvable directory silently redirected the
/// SQLite store — and the credential read — into whatever directory the process happened to be
/// launched from. That is a real store and a real credential path, in a location nobody chose,
/// with no reason surfaced anywhere: `session_status` reported a configured session pointing at
/// `./photon.sqlite`. This is a source-byte witness because `setup`'s closure needs a running
/// Tauri app to call; the seam it now delegates to (`SessionConfig::try_resolve`) is unit-tested
/// beside it in `src/lib.rs`.
/// The source with its comment lines removed — the same discipline [`declared_dependencies`]
/// applies to `Cargo.toml`: a file is allowed to EXPLAIN in prose why a construct is absent (that
/// explanation is what stops it being re-added), and a raw substring scan would read the
/// explanation as the thing it forbids.
fn code_only(source: &str) -> String {
    source
        .lines()
        .filter(|line| {
            let t = line.trim_start();
            !(t.starts_with("//") || t.starts_with("/*") || t.starts_with('*'))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn byte4b_the_setup_path_resolution_never_falls_back_to_the_process_cwd() {
    let lib = code_only(&read("src/lib.rs"));
    assert!(
        !lib.contains("PathBuf::from(\".\")"),
        "an unresolvable app-data/home directory must carry its REASON into an unconfigured \
         session, never redirect the store or the credential into the process CWD"
    );
    assert!(
        lib.contains("fn try_resolve("),
        "the resolution must live in a seam that takes the resolvers' own Results, so the failure \
         path is testable without a running app"
    );
}

// ===============================================================================================
// The single-flight guard (provider-read bounds) — the guard type, tested directly.
// ===============================================================================================

#[test]
fn a_second_concurrent_operation_of_the_same_kind_is_refused_busy() {
    use photon_app_lib::{InFlight, OperationKind};

    let guard = InFlight::default();
    let first = guard
        .claim(OperationKind::RefreshInbox)
        .expect("the first refresh claims the slot");
    assert!(
        guard.claim(OperationKind::RefreshInbox).is_none(),
        "a second concurrent refresh must be REFUSED (typed Busy), never queued behind the first \
         — §2 S3: 'a refresh in flight coalesces/rejects duplicates'"
    );

    // A DIFFERENT kind is unaffected: single-flight is per operation kind, not a global valve.
    let other = guard
        .claim(OperationKind::Verb("msg-a".to_string()))
        .expect("a different operation kind claims its own slot");
    drop(other);

    drop(first);
    assert!(
        guard.claim(OperationKind::RefreshInbox).is_some(),
        "the slot must be released when the claim is dropped — including on an early return or a \
         panic, which is why the claim is a guard and not a flag the caller must remember to clear"
    );
}

#[test]
fn a_body_fetch_is_single_flight_per_message_not_per_kind() {
    use photon_app_lib::{InFlight, OperationKind};

    let guard = InFlight::default();
    let first = guard
        .claim(OperationKind::MessageBody("msg-a".to_string()))
        .expect("the first body fetch claims its message slot");
    assert!(
        guard
            .claim(OperationKind::MessageBody("msg-a".to_string()))
            .is_none(),
        "a second in-flight fetch for the SAME message is refused (per-message coalescing)"
    );
    let other = guard
        .claim(OperationKind::MessageBody("msg-b".to_string()))
        .expect("a different message is a different slot");

    drop(first);
    drop(other);
    assert!(guard
        .claim(OperationKind::MessageBody("msg-a".to_string()))
        .is_some());
}

// ===============================================================================================
// A refusal must be a VALUE the renderer can branch on — never a panic across IPC.
// ===============================================================================================

/// Forces the `cases` list below to
/// name EVERY `SurfaceError` variant — an EXHAUSTIVE match with NO wildcard arm (the house pattern,
/// `crates/aruna/src/attempt.rs`'s `s1_pre_send_reason_vocabulary_has_four_members_and_round_trips`),
/// so a variant added to the enum without a matching entry in `cases` is a COMPILE ERROR, never a
/// silently missing case. The hand-curated list this replaces omitted `UnsupportedCapability` and
/// `CredentialRejected` for a long time, and the belt still passed.
fn every_surface_error_variant(e: photon_app_lib::SurfaceError) -> photon_app_lib::SurfaceError {
    use photon_app_lib::SurfaceError as S;
    match &e {
        S::Busy { .. }
        | S::TooSoon { .. }
        | S::ProviderBackoff { .. }
        | S::SessionUnconfigured { .. }
        | S::CredentialExpired { .. }
        | S::Refused { .. }
        | S::Store { .. }
        | S::Internal { .. }
        | S::PlanRequired
        | S::PlanRefused { .. }
        | S::PlanChildRefused { .. }
        | S::UnsupportedCapability
        | S::CredentialRejected => {}
    }
    e
}

#[test]
fn every_refusal_serializes_as_a_tagged_value_the_renderer_can_branch_on() {
    use photon_app_lib::SurfaceError;

    // The call itself is a no-op (`every_surface_error_variant` returns its argument unchanged);
    // its BODY's exhaustive match is what matters, and that is checked at DEFINITION time — so
    // merely defining it already refuses to compile the day a new `SurfaceError` variant is added
    // without a matching arm here. This call only keeps it from being flagged unused.
    let _ = every_surface_error_variant(SurfaceError::PlanRequired);

    let cases = [
        SurfaceError::Busy {
            operation: "refresh_inbox".to_string(),
        },
        // The cadence floor and the retained provider backoff. Both carry a
        // `retry_after_ms` so the renderer never has to guess a wait or poll for one.
        SurfaceError::TooSoon {
            operation: "refresh_inbox".to_string(),
            retry_after_ms: 14_999,
        },
        SurfaceError::ProviderBackoff {
            operation: "message_body:m1".to_string(),
            retry_after_ms: 59_999,
        },
        // The unconfigured refusal carries the same `cure` discriminant the expiry refusal
        // does — `Some` for a CREDENTIAL refusal that knows its remedy, `None` for the arms that
        // owe none (an unopenable store, an unresolved path, the JMAP placeholder). Both are
        // exercised, because both cross the boundary.
        SurfaceError::SessionUnconfigured {
            reason: "no credential".to_string(),
            cure: Some(photon_app_lib::Cure::ReMint),
        },
        SurfaceError::SessionUnconfigured {
            reason: "no store".to_string(),
            cure: None,
        },
        // The credential's own `expires_at` passed. Its own kind: the
        // `cure` names WHICH remedy applies (a re-mint is only one of five), and the renderer
        // needs the stamp to say WHICH credential died.
        SurfaceError::CredentialExpired {
            expires_at: 1_700_000_000,
            cure: photon_app_lib::Cure::ReMint,
            reason: "the Gmail credential expired at 1700000000".to_string(),
        },
        SurfaceError::Refused {
            reason: "provider refused".to_string(),
            terminal: true,
        },
        SurfaceError::Store {
            reason: "locked".to_string(),
        },
        SurfaceError::Internal {
            reason: "poisoned".to_string(),
        },
    ];

    for case in cases {
        let value = serde_json::to_value(&case).expect("every refusal serializes");
        let obj = value
            .as_object()
            .expect("a refusal is a tagged object, not a bare string the UI must parse");
        assert!(
            obj.contains_key("kind"),
            "a refusal must carry its discriminant: {value}"
        );
    }

    // The three plan kinds, pinned to the exact wire bytes `src/ipc.ts` mirrors:
    // a snake_case tag, the engine's TOKEN as `reason`, the Photon member id, and a diff of atom
    // names + booleans. No provider identifier and no message content has a field to ride in.
    let plan_cases = [
        (
            SurfaceError::PlanRequired,
            serde_json::json!({ "kind": "plan_required" }),
        ),
        (
            SurfaceError::PlanRefused {
                reason: "state_diverged".to_string(),
                member_ref: Some("m1".to_string()),
                diff: vec![photon_app_lib::MemberDiffView {
                    atom: "membership:INBOX".to_string(),
                    expected: true,
                    observed: Some(false),
                }],
            },
            serde_json::json!({
                "kind": "plan_refused",
                "reason": "state_diverged",
                "member_ref": "m1",
                "diff": [{ "atom": "membership:INBOX", "expected": true, "observed": false }]
            }),
        ),
        (
            SurfaceError::PlanChildRefused {
                reason: "not_ready".to_string(),
            },
            serde_json::json!({ "kind": "plan_child_refused", "reason": "not_ready" }),
        ),
        // The two RUN-ENDING kinds,
        // pinned to their EXACT wire bytes — a `contains_key("kind")` smoke test (the loop above)
        // cannot catch a mutant that renames the TAG VALUE itself (the discriminating mutant:
        // `credential_rejected` → `credential_rejected_broken` left the OLD hand-curated `cases`
        // list, which never constructed this variant at all, green). Both carry NOTHING beside the
        // tag: the operator sentence is fixed BY KIND, never
        // from a connector message that could carry a provider-native detail across the boundary.
        (
            SurfaceError::UnsupportedCapability,
            serde_json::json!({ "kind": "unsupported_capability" }),
        ),
        (
            SurfaceError::CredentialRejected,
            serde_json::json!({ "kind": "credential_rejected" }),
        ),
        // `terminal` pinned onto `Refused`'s EXACT
        // wire bytes — a `contains_key("kind")` smoke test cannot catch a mutant that drops or
        // renames this field, and `isTerminalRefusal`'s TS twin now READS it for this one kind
        // instead of defaulting the whole kind terminal.
        (
            SurfaceError::Refused { reason: "a transient connector answer".to_string(), terminal: false },
            serde_json::json!({ "kind": "refused", "reason": "a transient connector answer", "terminal": false }),
        ),
        (
            SurfaceError::Refused { reason: "a terminal connector answer".to_string(), terminal: true },
            serde_json::json!({ "kind": "refused", "reason": "a terminal connector answer", "terminal": true }),
        ),
    ];
    for (case, expected) in plan_cases {
        assert_eq!(
            serde_json::to_value(&case).expect("every refusal serializes"),
            expected,
            "the plan refusal's wire bytes are the mirror's contract"
        );
    }
}

// ===============================================================================================
// Housekeeping: the witness reads the real bytes, from the real place.
// ===============================================================================================

#[test]
fn the_witness_reads_the_shipped_files_not_a_copy() {
    for rel in [
        "capabilities/default.json",
        "tauri.conf.json",
        "Cargo.toml",
        "src/lib.rs",
    ] {
        let path: &Path = &manifest_dir().join(rel);
        assert!(path.is_file(), "{} must exist to be witnessed", path.display());
    }
}
