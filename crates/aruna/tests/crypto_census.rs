//! THE PARTITION RULE, executable (ADR-P008 gate (f)): every digest/MAC call site in the repo's Rust source
//! MUST have a row in `docs/crypto-inventory.md`, and a site the doc does not name is a defect of
//! the DOC, not a silent pass. Lexical snapshot: it matches the spellings below, not the APIs
//! — the doc says so too.
//!
//! PER SITE: for each matching line the net takes the site's ENCLOSING ITEM — the nearest item
//! declaration at or above the site line (`fn NAME`, `type NAME`, `const NAME`, `static NAME`,
//! `impl … for NAME`, `impl NAME`; `//` lines are never declarations) — and requires ONE doc line
//! holding both the site's repo-relative path and that NAME as a whole word. A GREEN means
//! "every covered call site has a doc line naming its path and its enclosing item" — never "no
//! such site exists". It does not see: a second site inside an already-named item; a site in a
//! different item sharing an already-named item's bare name; a doc line naming the path and the
//! item in passing, in the wrong bucket or in two (bucket choice and exactly-one are the doc's
//! discipline); a nested item declared earlier in the same body (taken as the encloser); a
//! spelling outside `NEEDLES`.
//!
//! THE COUNT PIN: the net also pins how many LINES it sees. A new line matching a needle — the
//! first two blind spots above included — fails the pin until its row is added and the count
//! bumped. It counts lines, not sites: a site swapped for another keeps the count, and a second
//! spelling on an already-matching line does not move it.

use std::path::{Path, PathBuf};

/// `CARGO_MANIFEST_DIR` read at RUNTIME (`std::env::var`, which Cargo
/// sets fresh for every `cargo test`/`cargo nextest` PROCESS), never `env!` (a COMPILE-TIME bake)
/// — a test binary reused unrecompiled from another tree (a shared `CARGO_TARGET_DIR`) now
/// resolves THAT run's own manifest dir, never the one baked in when it was compiled.
fn repo_root() -> PathBuf {
    PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR for every test binary it runs"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

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

/// The spellings the census covers. A NEW digest API in the tree obliges a new alternation here
/// AND a doc row (the reference implementation's rule, verbatim). Past the five SHA-384/HMAC call spellings, the
/// type-name needles (`Sha1` · `sha1::` · `Sha224` · `Sha256` · `Sha512` · `Md5` · `HmacSha` ·
/// `KeyInit`) widen the net to other algorithms and widths They also match
/// lines that hash nothing (a type alias, a signature); the doc names those under Non-sites.
const NEEDLES: &[&str] = &["Sha384::new()", "Sha384::digest(", "Hmac::<", "HmacSha384::new_from_slice", "sha2::Sha384::new()", "Sha1", "sha1::", "Sha224", "Sha256", "Sha512", "Md5", "HmacSha", "KeyInit"];

fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// The identifier tokens of a line: split on everything that is not an identifier character.
fn tokens(line: &str) -> Vec<&str> {
    line.split(|c: char| !is_ident(c)).filter(|t| !t.is_empty()).collect()
}

/// `name` occurs in `line` bounded on both sides by a non-identifier character (or the line's
/// edge): `key_fingerprint` is present in "`key_fingerprint` (" but not in
/// "`key_fingerprint_is_sha384_…`".
fn word_present(line: &str, name: &str) -> bool {
    line.match_indices(name).any(|(at, _)| {
        let before = line[..at].chars().next_back();
        let after = line[at + name.len()..].chars().next();
        !before.is_some_and(is_ident) && !after.is_some_and(is_ident)
    })
}

/// Tokens that may LEAD an item declaration before its keyword (`pub(crate) unsafe fn …`).
const QUALIFIERS: &[&str] = &["pub", "crate", "super", "self", "in", "async", "unsafe", "extern", "default"];

/// The name of the item this line declares, if it declares one. The keyword must be reached
/// through leading qualifiers only, so a `let`/call/string line mentioning `fn x` declares
/// nothing. `const fn` is a function; `type X = …` names `X`; `static mut X` names `X`; an `impl`
/// names the type after its `for`, else the first type after `impl` (generic lists dropped).
fn declared_item(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    if trimmed.starts_with("//") {
        return None;
    }
    let toks = tokens(trimmed);
    let mut i = 0;
    while let Some(&tok) = toks.get(i) {
        match tok {
            "fn" | "type" => return toks.get(i + 1).map(|s| s.to_string()),
            "const" | "static" => match toks.get(i + 1).copied() {
                Some("fn" | "unsafe" | "async" | "extern") => i += 1,
                Some("mut") => return toks.get(i + 2).map(|s| s.to_string()),
                other => return other.map(str::to_string),
            },
            "impl" => return impl_target(trimmed),
            q if QUALIFIERS.contains(&q) => i += 1,
            _ => return None,
        }
    }
    None
}

/// `impl<T> Trait for Name<T>` → `Name`; `impl Name` → `Name`.
fn impl_target(trimmed: &str) -> Option<String> {
    let after_impl = &trimmed[trimmed.find("impl")? + "impl".len()..];
    let mut depth = 0usize;
    let flat: String = after_impl
        .chars()
        .filter(|&c| match c {
            '<' => {
                depth += 1;
                false
            }
            '>' => {
                depth = depth.saturating_sub(1);
                false
            }
            _ => depth == 0,
        })
        .collect();
    let toks = tokens(&flat);
    match toks.iter().rposition(|&t| t == "for") {
        Some(f) => toks.get(f + 1).map(|s| s.to_string()),
        None => toks.first().map(|s| s.to_string()),
    }
}

#[test]
fn the_item_scanner_reads_declarations_and_nothing_else() {
    assert_eq!(declared_item("pub fn key_fingerprint(key: &CommitmentKey) -> String {").as_deref(), Some("key_fingerprint"));
    assert_eq!(declared_item("    pub(crate) fn of_bytes(bytes: &[u8]) -> Self {").as_deref(), Some("of_bytes"));
    assert_eq!(declared_item("    fn tag_is_hmac() {").as_deref(), Some("tag_is_hmac"));
    assert_eq!(declared_item("const NEEDLES: &[&str] = &[\"a spelling\"];").as_deref(), Some("NEEDLES"));
    assert_eq!(declared_item("pub const fn frame_len() -> usize {").as_deref(), Some("frame_len"));
    assert_eq!(declared_item("static mut COUNTER: u8 = 0;").as_deref(), Some("COUNTER"));
    assert_eq!(declared_item("pub(crate) type TagMac = Hmac<Sha384>;").as_deref(), Some("TagMac"));
    assert_eq!(declared_item("unsafe impl<T: Send> Send for Holder<T> {}").as_deref(), Some("Holder"));
    assert_eq!(declared_item("impl FileGen {").as_deref(), Some("FileGen"));
    // Not declarations: a string holding `fn NAME`, a doc comment, a plain comment, a call.
    assert_eq!(declared_item("        let body = &src[src.find(\"pub fn verify_tag\").unwrap()..];"), None);
    assert_eq!(declared_item("/// fn looks_like_an_item() — prose"), None);
    assert_eq!(declared_item("    //   node -e 'const SK=String.fromCharCode()'"), None);
    assert_eq!(declared_item("    let mut hasher = Hasher::new();"), None);
}

#[test]
fn a_name_counts_only_as_a_whole_word() {
    assert!(word_present("| `crates/aruna/src/commitment.rs` `key_fingerprint` (`the call`) |", "key_fingerprint"));
    assert!(word_present("key_fingerprint", "key_fingerprint"));
    assert!(word_present("`FileGen::of_bytes` (", "of_bytes"));
    assert!(!word_present("test `key_fingerprint_is_sha384_over_the_bridges_prefix_and_the_material`", "key_fingerprint"));
    assert!(!word_present("`derive_account_key_v2`", "derive_account_key"));
    assert!(!word_present("`my_store_user`", "store_user"));
}

#[test]
fn every_digest_or_mac_site_in_rust_source_is_named_in_the_census() {
    let root = repo_root();
    let doc = std::fs::read_to_string(root.join("docs/crypto-inventory.md")).expect("docs/crypto-inventory.md must exist");
    let mut sources = Vec::new();
    for dir in ["crates", "src-tauri/src"] {
        rust_sources(&root.join(dir), &mut sources);
    }
    let mut unnamed = Vec::new();
    let mut seen = 0usize;
    for path in &sources {
        let text = std::fs::read_to_string(path).unwrap();
        let rel = path.strip_prefix(&root).unwrap().to_string_lossy().replace('\\', "/");
        let lines: Vec<&str> = text.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if line.trim_start().starts_with("//") {
                continue; // a comment naming the API is not a site
            }
            if !NEEDLES.iter().any(|n| line.contains(n)) {
                continue;
            }
            seen += 1;
            // The enclosing item: the nearest declaration AT OR ABOVE the site (at: a `const`
            // whose initializer holds the site encloses it — `NEEDLES` is the witness).
            let item = lines[..=i].iter().rev().find_map(|l| declared_item(l));
            let named = item
                .as_deref()
                .is_some_and(|name| doc.lines().any(|l| l.contains(&rel) && word_present(l, name)));
            if !named {
                unnamed.push(format!("{rel}:{} in `{}`", i + 1, item.as_deref().unwrap_or("<no enclosing item>")));
            }
        }
    }
    assert!(unnamed.is_empty(), "digest/MAC sites with no docs/crypto-inventory.md row naming their path AND enclosing item: {unnamed:#?}");
    // THE COUNT PIN (docs/crypto-inventory.md census log, closing review): twelve sites,
    // the NEEDLES line, and two lines that hash nothing (the MAC type alias and the signature of
    // the tag primitive that returns it).
    assert_eq!(seen, 15, "a new digest/MAC site is a census event — add its row, then bump this count");
}
