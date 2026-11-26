// The ratchet-reader parity differential (executed, hermetic).
//
// `grant_high_water.json` is a shared file with two readers: the mint writes and reads it in
// Python (`scripts/gmail_drill_mint.py`), the app reads it in Rust
// (`token_refresh::read_grant_high_water`). The ratchet's value rests on the two agreeing about
// which bytes are a legal ratchet: a shape one reader admits and the other refuses means the
// admitting side keeps running against a record the refusing side never raised. Earlier fixes
// closed three such shapes (lexical spellings, then repeated/unknown members) by reading the same
// bytes twice with two hand-written arguments. This test replaces the argument with one corpus of
// exact file bytes, the Python verdict recorded beside each case by the mint-side worker, and the
// Rust verdict computed here.
//
// It is a lib-internal module and not under `tests/` because `read_grant_high_water` is
// `pub(crate)`; an integration test would have to widen the reader's visibility. The fixture
// lives under `tests/fixtures/` because it is a test asset shared with the mint-side worker who
// authors it.
//
// Two tiers are asserted, because they are different claims:
//
//   1. The verdict (hard, no exceptions): accept-vs-refuse parity, and on accept the exact u64.
//      This is the safety property. Neither reader may admit bytes the other refuses, and they
//      may not disagree about which generation a file records.
//
//   2. The class (mapped, with an enumerated divergence table). The two readers' diagnostic
//      vocabularies are not isomorphic. Rust's is coarser on two axes (repeated vs unknown
//      member, both `DuplicateOrUnknownMember`; not-text vs not-JSON, both `NotJson` because
//      `from_slice` decodes and parses in one step), and the two JSON parsers disagree about
//      which stage some non-JSON literals fail at. Every known divergence is listed by case name
//      with its reason in `KNOWN_LABEL_DIVERGENCES`, and an unlisted divergence fails. The table
//      records two vocabularies and is not a licence: every case in it still refuses on both
//      sides, which tier 1 proves independently.
//
// No bytes are ever printed. A failure names the case and the two verdicts, since the corpus
// carries deliberately hostile file content and a test log is not a place to echo it.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::token_refresh::{read_grant_high_water, GrantHighWaterShape};

/// The corpus, authored on the mint side (the Python verdicts are that reader's own, recorded by
/// running it). It is committed rather than generated here: a differential whose two sides come
/// from the same worker in the same session proves nothing about two readers.
///
/// `CARGO_MANIFEST_DIR` is read at runtime (`std::env::var`, which Cargo sets fresh for every
/// test-binary run), never `env!`, whose compile-time bake would carry the tree a reused binary
/// was compiled in (e.g. under a shared `CARGO_TARGET_DIR`).
fn corpus_path() -> PathBuf {
    PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR for every test binary it runs"))
        .join("tests/fixtures/ratchet-parity-corpus.json")
}

const CORPUS_SCHEMA: &str = "photon.ratchet-parity-corpus.v1";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Corpus {
    schema: String,
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    name: String,
    /// The exact file bytes, base64, so a BOM, a lone CR, a missing trailing newline and an empty
    /// file all survive the trip through a JSON fixture unaltered.
    bytes_b64: String,
    /// `accept:<u64 decimal>` or `refuse:<label>`.
    python: String,
}

/// The PYTHON reader's verdict for one case.
#[derive(Debug, PartialEq, Eq)]
enum PythonVerdict {
    Accept(u64),
    Refuse(String),
}

/// The refusal labels the corpus schema defines. Enumerated so a typo in the fixture fails the
/// test instead of silently mapping to nothing.
const LABELS: [&str; 7] = [
    "not-json",
    // The file's bytes are not UTF-8, so there is no text to parse. The mint can say this and this
    // reader cannot: `serde_json::from_slice` decodes and parses in one step, so an invalid byte
    // and an invalid token are the same `NotJson` here (see `rust_label`).
    "not-utf8",
    "not-an-object",
    "repeated-member",
    "unknown-member",
    "absent-member",
    "not-u64",
];

impl PythonVerdict {
    fn parse(raw: &str, case: &str) -> Self {
        if let Some(n) = raw.strip_prefix("accept:") {
            return Self::Accept(n.parse::<u64>().unwrap_or_else(|_| {
                panic!("case {case}: an accept verdict carries a u64 decimal, got {raw:?}")
            }));
        }
        let label = raw.strip_prefix("refuse:").unwrap_or_else(|| {
            panic!("case {case}: a verdict is accept:<u64> or refuse:<label>, got {raw:?}")
        });
        assert!(
            LABELS.contains(&label),
            "case {case}: unknown refusal label {label:?} — the schema names exactly {LABELS:?}"
        );
        Self::Refuse(label.to_string())
    }
}

/// The Python label(s) a Rust shape corresponds to. Rust is coarser on two axes:
///
/// * it does not distinguish a repeated member name from a member outside the schema; both are
///   `DuplicateOrUnknownMember`, since both mean the wire form is not the one object with the
///   one member this file is defined to be;
/// * it does not distinguish bytes that are not text from text that is not JSON; both are
///   `NotJson`, because `serde_json::from_slice` decodes UTF-8 and parses in one step. The mint
///   reads bytes and decodes explicitly, so it can say `not-utf8` (a typed branch it needs, since
///   its decoder's exception would otherwise escape a `main()` that catches only `MintError`).
///   Both readers refuse the same bytes (tier 1 proves that), so this is a vocabulary difference.
fn rust_label(shape: GrantHighWaterShape) -> &'static str {
    match shape {
        // The coarse arm: EITHER `not-json` OR `not-utf8` on the Python side.
        GrantHighWaterShape::NotJson => "not-json|not-utf8",
        GrantHighWaterShape::NotAnObject => "not-an-object",
        // The coarse arm: EITHER `repeated-member` OR `unknown-member` on the Python side.
        GrantHighWaterShape::DuplicateOrUnknownMember => "repeated-member|unknown-member",
        GrantHighWaterShape::GenerationAbsent => "absent-member",
        GrantHighWaterShape::GenerationNotAnUnsignedInteger => "not-u64",
        // Not producible by this differential: every case writes a readable file first.
        GrantHighWaterShape::Unreadable(kind) => {
            panic!("the corpus writes a readable file for every case; got Unreadable({kind:?})")
        }
    }
}

/// Does the Rust shape ANSWER the Python label?
fn labels_agree(python: &str, shape: GrantHighWaterShape) -> bool {
    rust_label(shape).split('|').any(|l| l == python)
}

fn corpus() -> Corpus {
    corpus_at(&corpus_path())
}

/// [`corpus`] with the path as a parameter, the seam the two failure tests below reach through,
/// so "a missing or empty corpus fails, never skips" is tested directly.
fn corpus_at(path: &Path) -> Corpus {
    // Failure is explicit, never a skip (a differential's absence must be visible): a corpus that
    // is missing, unreadable, of the wrong schema or empty fails the suite.
    let raw = std::fs::read(path).unwrap_or_else(|e| {
        panic!(
            "the ratchet parity corpus is missing or unreadable at {} ({}). It is a COMMITTED \
             fixture authored on the mint side; this differential does not generate it and does \
             not skip without it.",
            path.display(),
            e.kind()
        )
    });
    let corpus: Corpus = serde_json::from_slice(&raw)
        .unwrap_or_else(|e| panic!("the corpus at {} is not {CORPUS_SCHEMA}: {e}", path.display()));
    assert_eq!(
        corpus.schema, CORPUS_SCHEMA,
        "the corpus declares a schema this differential does not read"
    );
    assert!(
        !corpus.cases.is_empty(),
        "a corpus with zero cases proves nothing — it must fail, not pass vacuously"
    );
    let mut seen = BTreeSet::new();
    for case in &corpus.cases {
        assert!(
            seen.insert(case.name.as_str()),
            "duplicate case name {:?} — a differential's cases are addressed by NAME",
            case.name
        );
    }
    corpus
}

// The differential's own honesty: an absent or empty corpus must fail, not quietly pass. A
// differential that skips when its fixture goes missing is a green light with nothing behind it,
// and since a different worker authors the corpus, "it did not land" is a real state.
#[test]
#[should_panic(expected = "missing or unreadable")]
fn a_missing_corpus_fails_loud_rather_than_skipping() {
    let dir = scratch_dir("absent");
    let _ = corpus_at(&dir.join("no-such-corpus.json"));
}

#[test]
#[should_panic(expected = "zero cases")]
fn an_empty_corpus_fails_loud_rather_than_passing_vacuously() {
    let dir = scratch_dir("empty");
    let path = dir.join("corpus.json");
    std::fs::write(
        &path,
        format!("{{\"schema\":\"{CORPUS_SCHEMA}\",\"cases\":[]}}"),
    )
    .expect("the scratch corpus is writable");
    let _ = corpus_at(&path);
}

/// Strict standard-alphabet base64 (RFC 4648 §4), hand-decoded rather than pulled in as a direct
/// dependency for one test asset. It is strict on purpose (no whitespace tolerance, no missing
/// padding): a corpus entry that does not decode exactly is corrupt, and the differential's value
/// is that the bytes it feeds the reader are the bytes the mint-side worker fed its own.
fn decode_base64(encoded: &str, case: &str) -> Vec<u8> {
    fn sextet(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes = encoded.as_bytes();
    assert!(
        bytes.len().is_multiple_of(4),
        "case {case}: base64 is padded to a multiple of four"
    );
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let pad = chunk.iter().filter(|c| **c == b'=').count();
        assert!(pad <= 2, "case {case}: malformed base64 padding");
        assert!(
            chunk[..4 - pad].iter().all(|c| *c != b'='),
            "case {case}: base64 padding is trailing-only"
        );
        let mut acc: u32 = 0;
        for c in &chunk[..4 - pad] {
            let v = sextet(*c)
                .unwrap_or_else(|| panic!("case {case}: byte outside the base64 alphabet"));
            acc = (acc << 6) | u32::from(v);
        }
        acc <<= 6 * pad;
        let full = acc.to_be_bytes();
        out.extend_from_slice(&full[1..4 - pad]);
    }
    out
}

/// Minted by the engine's guard (`aruna::test_temp`): unique per call, and the tree is removed
/// when the guard drops.
fn scratch_dir(tag: &str) -> aruna::test_temp::TempDir {
    aruna::test_temp::TempDir::new(&format!("photon-ratchet-parity-{tag}"))
}

// The known divergences between the two readers' label vocabularies.
//
// Every entry refuses on both sides (tier 1 proves that independently). What differs is only
// which word each reader uses, and each row says why. A divergence not listed here fails the
// differential.
struct Divergence {
    case: &'static str,
    python: &'static str,
    rust: &'static str,
    #[allow(dead_code)]
    why: &'static str,
}

const KNOWN_LABEL_DIVERGENCES: &[Divergence] = &[
    // Family A, the JSON extensions. CPython's `json` accepts `NaN` / `Infinity` / `-Infinity` by
    // default (its `parse_constant` hook), so the mint's reader parses these documents and refuses
    // one step later, at the value: `not-u64`. `serde_json` implements RFC 8259, which has no such
    // tokens, so the app refuses at the parse itself: `not-json`. The app is the stricter reader
    // and both refuse; the divergence is which stage each names, not whether the bytes are
    // admitted.
    Divergence {
        case: "m9-json-extension-nan",
        python: "not-u64",
        rust: "not-json",
        why: "CPython json accepts the NaN token; serde_json (RFC 8259) does not",
    },
    Divergence {
        case: "m9-json-extension-infinity",
        python: "not-u64",
        rust: "not-json",
        why: "CPython json accepts the Infinity token; serde_json (RFC 8259) does not",
    },
    Divergence {
        case: "m9-json-extension-minus-infinity",
        python: "not-u64",
        rust: "not-json",
        why: "CPython json accepts the -Infinity token; serde_json (RFC 8259) does not",
    },
    Divergence {
        case: "boundary-tight-nan",
        python: "not-u64",
        rust: "not-json",
        why: "same as m9-json-extension-nan, in the whitespace-free spelling",
    },
    Divergence {
        case: "boundary-tight-infinity",
        python: "not-u64",
        rust: "not-json",
        why: "same as m9-json-extension-infinity, in the whitespace-free spelling",
    },
    // Family B, two illegalities in one file. These bytes repeat `grant_generation` and spell one
    // of the two values `-0`, so each reader reports the one its own pipeline reaches first: the
    // mint names the illegal spelling (`not-u64`, its lexical integer check), the app names the
    // repeat (`repeated-member`, its wire-order name scan after the typed parse refused). Neither
    // admits the file, and the single-fault cases on both axes agree exactly
    // (`m10-repeat-seven-then-two` and `m9-lexical-negative-zero` are both in the corpus), so this
    // is a labelling artefact of a doubly illegal input.
    Divergence {
        case: "m10-repeat-negative-zero-then-two",
        python: "not-u64",
        rust: "repeated-member",
        why: "repeated member AND an illegal -0 spelling; each reader names the one it reaches first",
    },
    Divergence {
        case: "m10-repeat-two-then-negative-zero",
        python: "not-u64",
        rust: "repeated-member",
        why: "repeated member AND an illegal -0 spelling; each reader names the one it reaches first",
    },
    Divergence {
        case: "boundary-tight-repeat-negative-zero-then-two",
        python: "not-u64",
        rust: "repeated-member",
        why: "same as m10-repeat-negative-zero-then-two, in the whitespace-free spelling",
    },
    Divergence {
        case: "boundary-tight-repeat-two-then-negative-zero",
        python: "not-u64",
        rust: "repeated-member",
        why: "same as m10-repeat-two-then-negative-zero, in the whitespace-free spelling",
    },
];

fn known_divergence(case: &str, python: &str, shape: GrantHighWaterShape) -> bool {
    KNOWN_LABEL_DIVERGENCES.iter().any(|d| {
        d.case == case && d.python == python && rust_label(shape).split('|').any(|l| l == d.rust)
    })
}

// Tier 1, the verdict. The safety property, with no exceptions: the two readers admit the same
// bytes and refuse the same bytes, and where they admit, they read the same integer.
#[test]
fn the_two_ratchet_readers_admit_and_refuse_the_same_bytes() {
    let corpus = corpus();
    let dir = scratch_dir("verdict");
    let path = dir.join(crate::token_refresh::GRANT_HIGH_WATER_FILE_NAME);

    let mut accepted = 0usize;
    let mut refused = 0usize;
    let mut disagreements: Vec<String> = Vec::new();

    for case in &corpus.cases {
        let python = PythonVerdict::parse(&case.python, &case.name);
        std::fs::write(&path, decode_base64(&case.bytes_b64, &case.name))
            .expect("the scratch ratchet is writable");
        let rust = read_grant_high_water(&path);

        match (&python, &rust) {
            (PythonVerdict::Accept(n), Ok(Some(m))) => {
                if n == m {
                    accepted += 1;
                } else {
                    disagreements.push(format!(
                        "{}: both admit, but they read DIFFERENT generations (mint {n}, app {m})",
                        case.name
                    ));
                }
            }
            (PythonVerdict::Refuse(_), Err(_)) => refused += 1,
            // The two cases that must not exist, named separately because they are different
            // failures: one leaves the mint raising a ratchet the app will not read, the other
            // leaves the app admitting a record the mint refused to write.
            (PythonVerdict::Accept(n), _) => disagreements.push(format!(
                "{}: the MINT admits generation {n}; the app REFUSES the same bytes",
                case.name
            )),
            (PythonVerdict::Refuse(label), _) => disagreements.push(format!(
                "{}: the MINT refuses ({label}); the app ADMITS the same bytes",
                case.name
            )),
        }
    }

    assert!(
        disagreements.is_empty(),
        "the two ratchet readers disagree about {} of {} cases:\n  {}",
        disagreements.len(),
        corpus.cases.len(),
        disagreements.join("\n  ")
    );
    // The corpus must exercise both verdicts: an all-refuse corpus would pass a reader that
    // refuses everything, which is not the property.
    assert!(
        accepted > 0 && refused > 0,
        "the corpus must carry both admitted and refused shapes (accepted {accepted}, refused {refused})"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// Tier 2, the class. Same corpus and bytes: each refusal's label, mapped, with the enumerated
// divergence table above. Tier 1 already proved every one of these refuses on both sides; this
// pins why each says it refuses, so a reader that starts refusing the right bytes for the wrong
// reason still gets looked at.
#[test]
fn the_two_ratchet_readers_refuse_for_the_same_stated_reason() {
    let corpus = corpus();
    let dir = scratch_dir("class");
    let path = dir.join(crate::token_refresh::GRANT_HIGH_WATER_FILE_NAME);

    let mut unlisted: Vec<String> = Vec::new();
    let mut listed = 0usize;

    for case in &corpus.cases {
        let PythonVerdict::Refuse(label) = PythonVerdict::parse(&case.python, &case.name) else {
            continue;
        };
        std::fs::write(&path, decode_base64(&case.bytes_b64, &case.name))
            .expect("the scratch ratchet is writable");
        let Err(shape) = read_grant_high_water(&path) else {
            // Tier 1 owns this failure; here it would only be noise.
            continue;
        };
        if labels_agree(&label, shape) {
            continue;
        }
        if known_divergence(&case.name, &label, shape) {
            listed += 1;
            continue;
        }
        unlisted.push(format!(
            "{}: the mint says {label}, the app says {}",
            case.name,
            rust_label(shape)
        ));
    }

    assert!(
        unlisted.is_empty(),
        "{} refusal(s) diverge in CLASS without being recorded in KNOWN_LABEL_DIVERGENCES:\n  {}",
        unlisted.len(),
        unlisted.join("\n  ")
    );
    // Every recorded divergence must still be one: a row that has been fixed on either side
    // should be deleted, and leaving it would let a future regression hide behind it.
    assert_eq!(
        listed,
        KNOWN_LABEL_DIVERGENCES.len(),
        "KNOWN_LABEL_DIVERGENCES lists {} case(s); {listed} still diverge — delete the rows that \
         no longer do",
        KNOWN_LABEL_DIVERGENCES.len()
    );

    let _ = std::fs::remove_dir_all(&dir);
}
