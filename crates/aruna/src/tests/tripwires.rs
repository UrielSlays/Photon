//! Source-text tripwires over the status writes and the write-transaction spellings.

const CORE_SOURCES: &[(&str, &str)] = &[
    ("lib.rs", include_str!("../lib.rs")),
    ("adjudication.rs", include_str!("../adjudication.rs")),
    ("boot.rs", include_str!("../boot.rs")),
    ("bus.rs", include_str!("../bus.rs")),
    ("command.rs", include_str!("../command.rs")),
    ("connector.rs", include_str!("../connector.rs")),
    ("decision.rs", include_str!("../decision.rs")),
    ("fact_store.rs", include_str!("../fact_store.rs")),
    ("fixtures.rs", include_str!("../fixtures.rs")),
    ("grant.rs", include_str!("../grant.rs")),
    ("intent.rs", include_str!("../intent.rs")),
    ("intent_log.rs", include_str!("../intent_log.rs")),
    ("keys.rs", include_str!("../keys.rs")),
    ("memory_log.rs", include_str!("../memory_log.rs")),
    ("outcome.rs", include_str!("../outcome.rs")),
    ("plan_store.rs", include_str!("../plan_store.rs")),
    ("settle.rs", include_str!("../settle.rs")),
    ("sever.rs", include_str!("../sever.rs")),
    ("sqlite_log.rs", include_str!("../sqlite_log.rs")),
    ("undo.rs", include_str!("../undo.rs")),
    ("tests/mod.rs", include_str!("mod.rs")),
    ("tests/adjudication.rs", include_str!("adjudication.rs")),
    ("tests/boot.rs", include_str!("boot.rs")),
    ("tests/capacity.rs", include_str!("capacity.rs")),
    ("tests/config.rs", include_str!("config.rs")),
    ("tests/execute.rs", include_str!("execute.rs")),
    ("tests/parity.rs", include_str!("parity.rs")),
    ("tests/plan.rs", include_str!("plan.rs")),
    ("tests/prepare.rs", include_str!("prepare.rs")),
    ("tests/regressions.rs", include_str!("regressions.rs")),
    ("tests/retry.rs", include_str!("retry.rs")),
    ("tests/send_epoch.rs", include_str!("send_epoch.rs")),
    ("tests/settlement.rs", include_str!("settlement.rs")),
    ("tests/sever.rs", include_str!("sever.rs")),
    ("tests/store.rs", include_str!("store.rs")),
    ("tests/tripwires.rs", include_str!("tripwires.rs")),
    ("tests/undo.rs", include_str!("undo.rs")),
    ("tests/verdict.rs", include_str!("verdict.rs")),
    ("tests/witness.rs", include_str!("witness.rs")),
];

// ── The TRIPWIRE (explicitly NOT a closure claim) ──

/// Strip `//` line comments (outside string literals — a `"` toggles string state, `\"`
/// escapes) from Rust source, for `no_status_write_escapes_the_chokepoint` below. This
/// file carries no `/* */` block comments (verified once, at the scan site — `grep -c
/// '/\*' crates/aruna/src/lib.rs` == 0).
fn strip_line_comments(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    for line in src.lines() {
        let mut in_string = false;
        let mut escaped = false;
        let mut cut = line.len();
        for (i, c) in line.char_indices() {
            if in_string {
                if escaped {
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == '"' {
                    in_string = false;
                }
            } else if c == '"' {
                in_string = true;
            } else if c == '/' && line[i..].starts_with("//") {
                cut = i;
                break;
            }
        }
        out.push_str(&line[..cut]);
        out.push('\n');
    }
    out
}

#[test]
fn no_status_write_escapes_the_chokepoint() {
    // CHANGE-DETECTION, explicitly NOT a closure claim: the CLOSURE
    // lives in the `intents_status_activation` SQL trigger (it rides the `status`
    // COLUMN, not a Rust call site, so it fires correctly no matter which function
    // issues the write — `any_status_write_fires_activation` proves that directly) plus
    // `both_authorities_agree_at_the_edges`'s equivalence witness. This scan is honest
    // about its OWN blind spots: a REORDERED `SET` column list, a NEWLINE-SPLIT
    // spelling that still matches `find` but a smarter refactor could dodge, a WRAPPER
    // indirection one level removed from the literal, or a brand-NEW file this
    // `include_str!` never reads would all evade a literal-text scan like this one.
    //
    // KNOWN, NAMED, PRE-EXISTING WRITERS — NOT converted by the capacity-config work (its explicit
    // scope was `set_status_if`/`set_status_forced`/`terminalize_operation`'s 8
    // callers; these predate this change and each has a shape `settle_status` does not:
    // a combined attempts+status `CASE` write, an `intent_id`-keyed guard, or a plain
    // attempts-only write with no status column at all). Migrating them onto
    // `settle_status(tx, …)` directly is future work, not this change's — named here so
    // it cannot be forgotten.
    let allowlist: &[(&str, &str)] = &[
        ("dead_letter_if_quiescent", "dead_letter_if_quiescent write"),
        ("verify_undo_pair (parent flip)", "verify_undo_pair parent flip"),
        ("verify_undo_pair (child terminalize)", "verify_undo_pair child terminal"),
        (
            "charge_and_dead_letter_if_quiescent (the charge; no status column at all)",
            "charge_and_dead_letter charge",
        ),
        (
            "charge_and_dead_letter_if_quiescent (the dead-letter)",
            "charge_and_dead_letter write",
        ),
        ("settle_attempt (combined attempts+status CASE)", "settle_attempt charge"),
        ("record_late_ack (parent flip, intent_id-keyed)", "late-ack parent flip"),
        ("settle_status — THE CHOKEPOINT ITSELF", "settle_status '"),
        (
            "record_effect_witness (#75 S1 B8: the witness columns only; no status column at all)",
            "record_effect_witness write",
        ),
        // `mark_projected`'s entry is GONE — the function (and its
        // `UPDATE intents SET projected = 1 ...` statement) moved to
        // `read_coordinator.rs::project_applied_intent`, a file THIS scan does not read
        // (`include_str!("lib.rs")` only — a named, pre-existing blind spot this test's own
        // doc already states: "a brand-NEW file this `include_str!` never reads would...evade
        // a literal-text scan like this one"). The `projected` UPDATE there is still guarded
        // on `status = 'applied'` in its WHERE clause, never its SET list, exactly as this
        // allowlist required here.
    ];
    let mut stripped = String::new();
    for (name, source) in CORE_SOURCES {
        if name.starts_with("tests/") {
            continue;
        }
        // The file carries CRLF line endings on this checkout — match either spelling so the
        // boundary search is not itself a footgun the next `git config core.autocrlf` flip
        // silently breaks.
        let test_mod_at = source
            .find("#[cfg(test)]\r\nmod tests {")
            .or_else(|| source.find("#[cfg(test)]\nmod tests {"))
            .unwrap_or(source.len());
        let production = &source[..test_mod_at];
        stripped.push_str(&strip_line_comments(production));
    }
    let mut remaining: Vec<(&str, &str)> = allowlist.to_vec();
    let mut cursor = 0usize;
    let mut found = 0usize;
    while let Some(rel) = stripped[cursor..].find("UPDATE intents") {
        let at = cursor + rel;
        let window_end = (at + 1000).min(stripped.len());
        let window = &stripped[at..window_end];
        match remaining.iter().position(|(_, marker)| window.contains(marker)) {
            Some(i) => {
                remaining.remove(i);
                found += 1;
            }
            None => panic!(
                "an `UPDATE intents` site at byte {at} matched NO allowlist marker — a \
                 NEW status-write site needs a pinned entry here, or it should route \
                 through `settle_status`. Context:\n{window}"
            ),
        }
        cursor = at + "UPDATE intents".len();
    }
    assert_eq!(
        found,
        allowlist.len(),
        "expected exactly {} pinned `UPDATE intents` sites, found {found}; the allowlist \
         and the source have drifted — entries never matched: {remaining:?}",
        allowlist.len()
    );
}

// ── THE HONEST TRIPWIRE (explicitly NOT a closure claim) ──

/// One `(pattern, marker)` scan over ONE comment-stripped source, sharing
/// `strip_line_comments` with `no_status_write_escapes_the_chokepoint` (the house pattern).
/// Every occurrence of `pattern` must fall within a WINDOW around a still-unconsumed
/// allowlist marker, or the scan panics with the byte offset and surrounding context — a
/// new site needs a pinned entry (proving it is inside a blessed constructor or a
/// `#[cfg(test)]` region) or it should route through `with_immediate_tx`/
/// `with_enrolled_write` instead. Consumes matched entries so a SECOND real occurrence
/// cannot hide behind one allowlist line, and returns the number matched so the caller can
/// assert the whole (file × pattern) matrix, not just one scan.
fn scan_unenrolled_spelling(
    label: &str,
    source: &str,
    pattern: &str,
    allowlist: &mut Vec<(&'static str, &'static str)>,
) -> usize {
    let stripped = strip_line_comments(source);
    let mut cursor = 0usize;
    let mut found = 0usize;
    while let Some(rel) = stripped[cursor..].find(pattern) {
        let at = cursor + rel;
        let window_start = at.saturating_sub(800);
        let window_end = (at + 800).min(stripped.len());
        let window = &stripped[window_start..window_end];
        match allowlist.iter().position(|(_, marker)| window.contains(marker)) {
            Some(i) => {
                allowlist.remove(i);
                found += 1;
            }
            None => panic!(
                "{label}: an unenrolled write-transaction spelling (`{pattern}`) at byte \
                 {at} matched NO allowlist marker — a NEW site needs a pinned entry (naming \
                 which blessed constructor or `#[cfg(test)]` region covers it), or it \
                 should route through `with_immediate_tx`/`with_enrolled_write` instead. \
                 Context:\n{window}"
            ),
        }
        cursor = at + pattern.len();
    }
    found
}

#[test]
fn no_unenrolled_write_txn_spelling() {
    // CHANGE-DETECTION, explicitly NOT a closure claim (the same posture
    // `no_status_write_escapes_the_chokepoint` carries): the closure lives in the
    // ENROLLED-CLOSURE API (`GatedConnection::with_immediate_tx`/`with_enrolled_write`)
    // — every PRODUCTION writer is converted there, by construction, not
    // by this scan. This test is honest about its OWN blind spots, named here VERBATIM per
    // the plan: **new files · wrapper indirection · alternate spellings · future autocommit
    // mutations — this is change-detection; the closure lives in the enrolled-closure API
    // and the capacity activation trigger.**
    //
    // Three literal spellings, scanned comment-stripped (`strip_line_comments`, shared with
    // the sibling tripwire above — same CRLF-safety, same block-comment-free precondition,
    // verified for all four files below) across the four writer files (`store_open.rs` —
    // home of the blessed constructors themselves — is deliberately NOT one of them):
    //   - `TransactionBehavior::Immediate` — the raw enum spelling `run_immediate` uses;
    //     ⚠ `read_coordinator.rs` carries this literal in a DOC COMMENT (module-doc prose
    //     about the lock the enrolled door takes) — comment-stripping must remove it before
    //     this scan ever sees it, and does (verified: zero hits below).
    //   - `execute_batch("BEGIN` — a hand-rolled `BEGIN`/`BEGIN IMMEDIATE` outside the
    //     enrolled doors.
    //   - `"INSERT INTO message_header_fts` — a direct FTS5 write outside
    //     `with_enrolled_write` (`fts_integrity_ok` moved BEHIND
    //     `#[cfg(test)]` for exactly this reason — the same disposition the raw
    //     `begin()`/`commit()` pair got).
    //
    // Every current hit is `#[cfg(test)]`-gated witness/probe code, never production: this
    // scan intentionally does NOT try to detect `#[cfg(test)]` boundaries structurally
    // (message_header.rs's `fts_integrity_ok` is function-attribute-gated, not inside a
    // nested `mod tests` block — the same "before `mod tests`" cut the sibling tripwire
    // uses would MISS it). Instead every occurrence is named by a PINNED marker, exactly
    // the sibling tripwire's shape — the allowlist itself is the record of why each site is
    // safe, and any drift (new hit, or a stale entry nothing matches any more) fails loud.
    // `strip_line_comments` only strips `//` line comments — an actual block comment would
    // silently hide a write-transaction spelling from this scan, so the precondition is
    // asserted here rather than trusted forever (`assert_block_comment_count`'s own doc
    // names why `lib.rs`'s pinned count is not zero).
    for (name, source) in CORE_SOURCES {
        let expected = if *name == "tests/tripwires.rs" { 1 } else { 0 };
        assert_block_comment_count(name, source, expected);
    }
    assert_block_comment_count("read_coordinator.rs", include_str!("../read_coordinator.rs"), 0);
    assert_block_comment_count("message_store.rs", include_str!("../message_store.rs"), 0);
    assert_block_comment_count("message_header.rs", include_str!("../message_header.rs"), 0);

    let files: &[(&str, &str)] = &[
        CORE_SOURCES,
        &[
            ("read_coordinator.rs", include_str!("../read_coordinator.rs")),
            ("message_store.rs", include_str!("../message_store.rs")),
            ("message_header.rs", include_str!("../message_header.rs")),
        ],
    ]
    .concat();

    // Every pattern below is assembled from TWO literal fragments (`.concat()`) rather than
    // written as one contiguous string — the same self-reference this test's OWN source
    // would otherwise trip on `assert_block_comment_count` handles above: written as one
    // literal, this scan's own `scan_unenrolled_spelling(..., "TransactionBehavior::\
    // Immediate", ...)` call would BE a hit on itself the instant `include_str!("lib.rs")`
    // reads this very file. Splitting the literal breaks the contiguous substring in the
    // RAW SOURCE TEXT (the two fragments are separated by a closing quote, a comma, a
    // space and an opening quote) while still producing the intended pattern at runtime.

    // `TransactionBehavior::Immediate` — zero production or test hits expected: every
    // caller of the real enum goes through `store_open.rs::run_immediate`, which this scan
    // deliberately excludes (it is the blessed constructor's OWN internals, not a writer
    // file). An EMPTY allowlist is the honest population here — the scan still runs and
    // still protects against a future hit, it simply has nothing to name today.
    let immediate_pattern = ["TransactionBehavior::", "Immediate"].concat();
    let mut immediate_allowlist: Vec<(&'static str, &'static str)> = Vec::new();
    let mut immediate_found = 0usize;
    for (name, source) in files {
        immediate_found +=
            scan_unenrolled_spelling(name, source, &immediate_pattern, &mut immediate_allowlist);
    }
    assert_eq!(
        immediate_found, 0,
        "a bare `TransactionBehavior` `::Immediate` literal appeared OUTSIDE \
         store_open.rs's blessed constructor — every writer file must go through \
         `with_immediate_tx`/`with_enrolled_write` instead"
    );

    // `execute_batch("BEGIN` — five known witnesses, all `#[cfg(test)]`-gated probes of
    // SQLite's OWN locking behaviour (never a production write door). Three of them are
    // the sever-coalescing witnesses: they hold the store's write lock to widen
    // the SERVICE window deterministically instead of sleeping.
    let begin_pattern = ["execute_batch(", "\"BEGIN"].concat();
    let mut begin_allowlist: Vec<(&'static str, &'static str)> = vec![
        (
            "lib.rs: the_belt_refuses_a_send_authorized_after_a_sever_tickets's blocker \
             connection — TEST MACHINERY that widens the enroll-then-BEGIN window, never a \
             production write",
            "the blocker holds the write lock",
        ),
        (
            "read_coordinator.rs: ingest_and_projection_writes_take_the_reserved_lock_at_\
             begin_not_at_first_statement's contending probe connection, proving SQLite's \
             OWN `BEGIN IMMEDIATE` lock timing — never a production write",
            "a second writer must be refused the instant the first write tx begins",
        ),
        (
            "lib.rs: coalesced_severs_share_one_epoch_bump's blocker (#24-1b Task 7) — \
             TEST MACHINERY that widens the sever SERVICE window so the joiners arrive \
             before the leader's witness snapshot closes; never a production write",
            "the coalescing blocker holds the write lock",
        ),
        (
            "lib.rs: a_new_service_begins_only_after_the_prior_completes's blocker \
             (#24-1b Task 7) — the same machinery, holding ONE service open while the \
             second request proves it JOINS rather than ticketing",
            "the one-service blocker holds the write lock",
        ),
        (
            "lib.rs: w_seize_admit_unacknowledged_overflow_joiner_crash's blocker \
             (#24-1b Task 7) — the same machinery, making the leader / in-snapshot / \
             overflow role assignment deterministic before the crash seam fires",
            "the unacknowledged-crash blocker holds the write lock",
        ),
        (
            "lib.rs: w_seize_bound_barrier_schedule's blocker (#24-1b Task 9) — TEST \
             MACHINERY that forces whichever of the four production write doors wins the \
             gate-level enroll() race to park at its own `BEGIN IMMEDIATE`, deterministically \
             widening the window instead of racing a clock; never a production write",
            "the barrier-schedule blocker holds the write lock",
        ),
        (
            "read_coordinator.rs: a_sever_raised_mid_reconcile_waits_at_most_one_chunk's \
             FIXTURE seed (#24-1b codex-r3 F1) — one raw transaction that plants the local \
             Inbox rows the witness reconciles away; test-only construction, and going \
             through the enrolled per-row doors would cost 2 x 384 separate commits",
            "the reconcile-chunk fixture seeds in one raw transaction",
        ),
        (
            "read_coordinator.rs: a_sever_raised_mid_reconcile_waits_at_most_one_chunk's \
             blocker (#24-1b codex-r3 F1) — the same TEST MACHINERY the Task 7/9 witnesses \
             use: it holds SQLite's write lock so the first chunk parks at SQL with the \
             gate already taken, making the sever's mid-reconcile arrival deterministic \
             instead of raced against a clock; never a production write",
            "the reconcile-chunk sever probe takes SQLite's write lock",
        ),
    ];
    let mut begin_found = 0usize;
    for (name, source) in files {
        begin_found +=
            scan_unenrolled_spelling(name, source, &begin_pattern, &mut begin_allowlist);
    }
    assert_eq!(
        begin_found, 8,
        "expected exactly 8 pinned `execute_batch(` `\"BEGIN` sites (all test-only lock \
         probes and fixture seeds), found {begin_found}; the allowlist and the source have \
         drifted — entries never matched: {begin_allowlist:?}"
    );

    // `"INSERT INTO message_header_fts` — the one write `fts_integrity_ok` still performs,
    // `#[cfg(test)]`-gated precisely because it is a writer-class
    // statement with no production caller left.
    let fts_pattern = ["\"INSERT INTO ", "message_header_fts"].concat();
    let mut fts_allowlist: Vec<(&'static str, &'static str)> = vec![(
        "message_header.rs: fts_integrity_ok — #[cfg(test)]-gated (Task 6b), the same \
         disposition the raw begin()/commit() pair got; no production caller",
        "fts_integrity_ok",
    )];
    let mut fts_found = 0usize;
    for (name, source) in files {
        fts_found += scan_unenrolled_spelling(name, source, &fts_pattern, &mut fts_allowlist);
    }
    assert_eq!(
        fts_found, 1,
        "expected exactly 1 pinned `\"INSERT INTO` `message_header_fts` site, found \
         {fts_found}; the allowlist and the source have drifted — entries never matched: \
         {fts_allowlist:?}"
    );
}

/// The block-comment-free precondition `strip_line_comments`-based scans rest on, checked
/// against a PINNED expected count rather than "zero or one and hope": `strip_line_comments`
/// only strips `//` line comments, so an actual block comment would silently hide a
/// write-transaction spelling from `no_unenrolled_write_txn_spelling`'s scan. The
/// non-zero counts are self-referential, not a hidden real block comment: `lib.rs` names
/// its own opening delimiter twice in this very sentence's neighbourhood (the pre-existing
/// doc sentence at `no_status_write_escapes_the_chokepoint`'s precondition, and the literal
/// this function searches FOR, right below) — every OTHER file pins zero.
fn assert_block_comment_count(name: &str, source: &str, expected: usize) {
    let opening_delimiter = ['/', '*'].iter().collect::<String>();
    let count = source.matches(&opening_delimiter).count();
    assert_eq!(
        count, expected,
        "{name}: expected exactly {expected} block-comment-opening occurrence(s) (this \
         file's own self-referential mentions of the delimiter, never a real block \
         comment), found {count} — an actual block comment would silently hide a \
         write-transaction spelling from `no_unenrolled_write_txn_spelling`'s scan"
    );
}
