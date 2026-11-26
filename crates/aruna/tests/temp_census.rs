//! THE TEMP CENSUS (Lesson 10: the set is finite and
//! derivable, so it is a gate). The class: test helpers minted paths under the OS temp directory
//! and leaked them — 41,125 entries on the dev box in ~36 hours. The close: no path is minted
//! there except through the ONE guard, `aruna::test_temp` (`crates/aruna/src/test_temp.rs`).
//!
//! THE NET: every Rust source under `crates/` and `src-tauri/` — product and test code alike,
//! `target/`, `node_modules/` and dot-directories skipped — is read, and every NON-COMMENT line
//! carrying a temp-directory spelling ([`NEEDLES`]) outside the guard module fails the census,
//! named `file:line`. A line may stand only in [`EXEMPT`], with its reason; an exemption that
//! matches no line fails too, so the list cannot rot.
//!
//! A GREEN means "no such spelling on a non-comment line outside the guard module and the named
//! exemptions" — never "no test leaks". It is LEXICAL: a spelling outside `NEEDLES` (a path read
//! from an environment variable under another name, a name built by a macro, a crate added later)
//! is not seen. It says nothing about ORDER — a guard dropped under an open store is the guard's
//! own loud `Drop` failure, witnessed in `test_temp`'s tests.

use std::path::{Path, PathBuf};

/// `CARGO_MANIFEST_DIR` read at RUNTIME (the class-H rule, `crypto_census.rs`): a test
/// binary reused from another tree resolves THIS run's manifest dir, never a compile-time bake.
fn repo_root() -> PathBuf {
    PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR for every test binary it runs"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

/// The directories the census walks, relative to the repo root.
const ROOTS: &[&str] = &["crates", "src-tauri"];

/// The ONE guard module — the only file that may name the temp directory.
const GUARD_MODULE: &str = "crates/aruna/src/test_temp.rs";

/// This file names the needles to find them.
const THIS_FILE: &str = "crates/aruna/tests/temp_census.rs";

/// The temp-directory spellings. `temp_dir` as a WHOLE WORD covers `std::env::temp_dir()`,
/// `env::temp_dir()` and a `use std::env::temp_dir;` import; the quoted names are the environment
/// variables the OS temp directory is read from.
const NEEDLES: &[&str] = &["temp_dir", "\"TEMP\"", "\"TMP\"", "\"TMPDIR\""];

/// `(repo-relative path, the trimmed line, why it stands)`. Matched by CONTENT, not line number.
const EXEMPT: &[(&str, &str, &str)] = &[(
    "crates/aruna-gmail/tests/live_readside.rs",
    "let fallback = std::env::temp_dir().join(format!(",
    "the live drill's SMOKE capture directory (reached only with PHOTON_GMAIL_IT=1): the operator \
     is told to read the captures there after the run, so it must outlive the process — a guard \
     would delete the output it exists to leave. Not a test store.",
)];

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let p = entry.unwrap().path();
        if p.is_dir() {
            let name = p.file_name().unwrap().to_string_lossy();
            if name == "target" || name == "node_modules" || name.starts_with('.') {
                continue;
            }
            rust_sources(&p, out);
        } else if p.extension().is_some_and(|e| e == "rs") {
            out.push(p);
        }
    }
}

fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// `needle` occurs in `line`; an identifier-shaped needle only as a WHOLE WORD
/// (`temp_dir` matches `std::env::temp_dir()`, never `sqlite3_temp_directory`).
fn has_needle(line: &str, needle: &str) -> bool {
    if !needle.chars().all(is_ident) {
        return line.contains(needle);
    }
    line.match_indices(needle).any(|(at, _)| {
        let before = line[..at].chars().next_back();
        let after = line[at + needle.len()..].chars().next();
        !before.is_some_and(is_ident) && !after.is_some_and(is_ident)
    })
}

/// Every `(relative path, 1-based line, trimmed line)` a needle hits on a non-comment line.
fn hits_in(rel: &str, text: &str) -> Vec<(String, usize, String)> {
    text.lines()
        .enumerate()
        .filter(|(_, line)| !line.trim_start().starts_with("//"))
        .filter(|(_, line)| NEEDLES.iter().any(|n| has_needle(line, n)))
        .map(|(i, line)| (rel.to_string(), i + 1, line.trim().to_string()))
        .collect()
}

/// The census over the whole tree against `exempt`: the violations (hits neither in the guard
/// module nor exempt) and the exemptions that matched nothing.
fn census(root: &Path, exempt: &[(&str, &str, &str)]) -> (Vec<String>, Vec<String>) {
    let mut files = Vec::new();
    for r in ROOTS {
        rust_sources(&root.join(r), &mut files);
    }
    let mut violations = Vec::new();
    let mut exempt_used = vec![false; exempt.len()];
    for file in &files {
        let rel = file.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/");
        if rel == GUARD_MODULE || rel == THIS_FILE {
            continue;
        }
        let text = std::fs::read_to_string(file).unwrap();
        for (path, line_no, line) in hits_in(&rel, &text) {
            match exempt.iter().position(|(p, l, _)| *p == path && *l == line) {
                Some(i) => exempt_used[i] = true,
                None => violations.push(format!("{path}:{line_no}: {line}")),
            }
        }
    }
    let stale = exempt
        .iter()
        .zip(&exempt_used)
        .filter(|(_, used)| !**used)
        .map(|((p, l, _), _)| format!("{p}: {l}"))
        .collect();
    (violations, stale)
}

#[test]
fn the_needle_matcher_reads_whole_words_and_skips_comments() {
    assert!(has_needle("let p = std::env::temp_dir().join(\"x\");", "temp_dir"));
    assert!(has_needle("    env::temp_dir()", "temp_dir"));
    assert!(has_needle("use std::env::temp_dir;", "temp_dir"));
    assert!(!has_needle("pub static mut sqlite3_temp_directory: *mut c_char;", "temp_dir"));
    assert!(!has_needle("fn my_temp_dir_helper() {}", "temp_dir"));
    assert!(has_needle("std::env::var_os(\"TMPDIR\")", "\"TMPDIR\""));
    assert!(hits_in("x.rs", "    // std::env::temp_dir() in a comment\n    /// and a doc line: temp_dir()\n").is_empty());
    assert_eq!(hits_in("x.rs", "fn a() {}\n    let d = std::env::temp_dir();\n").len(), 1);
}

/// The exemption list is load-bearing both ways: without it, the exempt line IS a violation; with
/// an entry the tree no longer has, that entry is reported stale.
#[test]
fn an_exemption_is_what_keeps_its_line_green_and_a_dead_one_is_reported() {
    let root = repo_root();
    let (violations, _) = census(&root, &[]);
    assert!(
        violations.iter().any(|v| v.starts_with(EXEMPT[0].0) && v.ends_with(EXEMPT[0].1)),
        "with no exemptions the exempt line is a violation: {violations:?}"
    );
    let dead = ("crates/aruna/src/lib.rs", "let gone = std::env::temp_dir();", "a line the tree does not have");
    let (_, stale) = census(&root, &[EXEMPT[0], dead]);
    assert_eq!(stale, vec![format!("{}: {}", dead.0, dead.1)], "the dead entry, and only it, is stale");
}

/// THE GATE: no temp-directory spelling outside the one guard module (and the named exemptions).
#[test]
fn no_temp_path_is_minted_outside_the_one_guard() {
    let root = repo_root();
    let (violations, stale) = census(&root, EXEMPT);
    assert!(
        violations.is_empty(),
        "{} temp-directory spelling(s) outside `aruna::test_temp` ({GUARD_MODULE}) — mint the path \
         through `TempFile`/`TempDir` (bound BEFORE anything that opens it), or name the line in \
         EXEMPT with its reason:\n{}",
        violations.len(),
        violations.join("\n")
    );
    assert!(stale.is_empty(), "EXEMPT names line(s) the tree no longer has — drop them:\n{}", stale.join("\n"));
}
