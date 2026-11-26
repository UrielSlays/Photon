//! The DIFFERENTIAL
//! ORACLE. Stalwart's `mail-parser` (dev-dependency of THIS crate ONLY, never shipped —
//! `Cargo.toml`'s `[dev-dependencies]`) is a second, independently-written RFC 5322/6854/6532
//! parser, fuzzed and Miri-tested (its own README). This is not adoption — see `mailbox.rs`'s
//! module doc, "Prior art, and why this is not it": a lenient parser cannot say `Malformed`, and
//! this crate's whole contract is failing CLOSED (the build record). It is MEASURED against, on
//! two axes:
//!
//! 1. [`VALID_CORPUS`] — a fixed corpus of STANDARDS-VALID `From`/`Sender` lines (RFC 5322
//!    Appendix A.1.1-A.1.3, A.5, A.6.1-A.6.3, copied verbatim from rfc-editor.org; RFC 6854 §4's
//!    examples; the module's own valid inputs). ASSERTED, in [`the_oracle_never_calls_a_standards_
//!    valid_line_malformed`]: our parser never answers `Malformed` for any of these, and where our
//!    answer is `Ok`, our canonical addr-spec equals `mail-parser`'s extracted address. This test
//!    fails on the earlier parser (on the obs-route and group/mailbox-list lines, which the
//!    earlier grammar refused as `Malformed`).
//! 2. [`FAIL_CLOSED_SET`] — this crate's OWN fail-closed witnesses (a two-`@` address, a comment
//!    closed at its first `)`, a bare CR/LF in a quoted-string, the eight invisible codepoints
//!    the parser refuses). NOT asserted against `mail-parser` (it is lenient by design, and is not
//!    held to our fail-closed contract) — only RECORDED, in
//!    [`the_oracle_evaluated_on_our_fail_closed_set_recorded_not_asserted`], to `eprintln!` (run
//!    with `cargo test -p aruna --test mailparser_oracle -- --nocapture` to see it) — "the
//!    evaluated parser strategy" asked for.

use mail_parser::MessageParser;

/// One `From`/`Sender` header VALUE (the field name and colon are not part of what either parser
/// reads) — every line is STANDARDS-VALID: it MUST NOT be read as `Malformed` by a conformant
/// receiver, per RFC 5322 §4 ("obsolete syntax... MUST be accepted... and parsed") and RFC 6854 §2
/// (groups legalized in `From`/`Sender`).
const VALID_CORPUS: &[(&str, &str)] = &[
    ("RFC 5322 Appendix A.1.1 (From)", "John Doe <jdoe@machine.example>"),
    ("RFC 5322 Appendix A.1.1 (Sender)", "Michael Jones <mjones@machine.example>"),
    ("RFC 5322 Appendix A.1.2 (From)", "\"Joe Q. Public\" <john.q.public@example.com>"),
    ("RFC 5322 Appendix A.1.3 (From)", "Pete <pete@silly.example>"),
    ("RFC 5322 Appendix A.5 (From, nested comments)", "Pete(A nice \\) chap) <pete(his account)@silly.test(his host)>"),
    ("RFC 5322 Appendix A.6.1 (From, obs-phrase dot)", "Joe Q. Public <john.q.public@example.com>"),
    ("RFC 5322 Appendix A.6.2 (From)", "John Doe <jdoe@machine.example>"),
    ("RFC 5322 Appendix A.6.3 (From, obs-domain CFWS)", "John Doe <jdoe@machine(comment).  example>"),
    ("RFC 6854 §4 (From, empty group)", "Automated System:;"),
    ("RFC 6854 §4 (From, empty group)", "Nightly Monitor Robot:;"),
    ("RFC 6854 §4 (From, mailbox-list of 2)", "ben@example.com,carol@example.com"),
    ("RFC 6854 §4 (Sender, bare mailbox)", "dave@example.com"),
    ("RFC 6854 §4 (From, group with 2 mailboxes)", "Managing Partners:ben@example.com,carol@example.com;"),
    ("the round's valid inputs (seat 1/2, obs-route with 2 at-domains)", "<@route1.example,@route2.example:user@target.example>"),
    ("the round's valid inputs (seat 1/2, obs-route with 1 at-domain)", "Name <@route:a@b.example>"),
    ("the round's valid inputs (seat 2 #1, named group with 1 mailbox)", "Authors:user@target.example;"),
    ("the round's valid inputs (seat 1/2, empty group, hyphenated)", "undisclosed-recipients:;"),
    ("the round's valid inputs (seat 2 #1, mailbox-list of 2)", "a@x.example, b@y.example"),
    ("seat 3 P2 (quoted HTAB is content, not a fold)", "\"a\tb\"@x.example"),
    // (/): §4.4's null list members —
    // RFC 5322 Appendix A.6.1's own To line is the ONE Appendix A line the pre-fold corpus
    // skipped: it exercises a null member the earlier valid-corpus additions never did.
    ("RFC 5322 Appendix A.6.1 (To, null member + obs-route + obs-domain CFWS)", "Mary Smith <@node.test:mary@example.net>, , jdoe@test  . example"),
    ("the round's valid inputs (seat 1 R4-F2, trailing null member, one mailbox)", "a@x.example,"),
    ("the round's valid inputs (seat 1 R4-F2, leading null member, one mailbox)", ", a@x.example"),
    ("the round's valid inputs (seat 2/seat 3 P2, consecutive null member, two mailboxes)", "a@x.example,,b@y.example"),
    ("the round's valid inputs (seat 1 R4-F2, empty group with null members)", "G:,,;"),
    ("the round's valid inputs (seat 1 R4-F2, group with one member + trailing null)", "G: a@x.example,;"),
    ("the round's valid inputs (seat 1 R4-F2, domain-literal inside an obs-route)", "N <@[192.0.2.1]:u@t.example>"),
];

/// This crate's OWN fail-closed witnesses (`mailbox.rs`'s test module) — recorded against
/// `mail-parser`, never asserted. Class D's fold appends the eight invisible
/// Default_Ignorable codepoints predicate widening refuses.
const FAIL_CLOSED_SET: &[(&str, &str)] = &[
    ("r2 fail-closed: two `@` in the addr-spec", "Name <a@b@c>"),
    ("r2 fail-closed: a comment closed at its FIRST `)`, not its nesting-aware close", "(a (b) <c@d.example>"),
    ("seat 3 P2: a bare CR/LF in a quoted-string is not FWS", "\"a\r\nb\"@evil.example"),
    ("class D: U+FE0F (variation selector) in the domain", "PayPal <service@pay\u{FE0F}pal.example>"),
    ("class D: U+034F (combining grapheme joiner) in the domain", "PayPal <service@pay\u{034F}pal.example>"),
    ("class D: U+180B (Mongolian free variation selector) in the domain", "PayPal <service@pay\u{180B}pal.example>"),
    ("class D: U+E0100 (variation selector supplement) in the domain", "PayPal <service@pay\u{E0100}pal.example>"),
    ("class D: U+17B4 (Khmer inherent vowel) in the domain", "PayPal <service@pay\u{17B4}pal.example>"),
    ("class D: U+115F (Hangul choseong filler) in the domain", "PayPal <service@pay\u{115F}pal.example>"),
    ("class D: U+3164 (Hangul filler) in the domain", "PayPal <service@pay\u{3164}pal.example>"),
    ("class D: U+FFA0 (halfwidth Hangul filler) in the domain", "PayPal <service@pay\u{FFA0}pal.example>"),
    // a bare CR/LF anywhere in the field — not just
    // inside a quoted-string — is never FWS; `unfold` refuses it before the grammar ever runs.
    ("seat 2 (bare CRLF at the very start, not followed by WSP)", "\r\nreal@evil.example"),
    ("seat 3 P2 (a lone LF inside a dot-atom run)", "alice@one.\nexample"),
    ("seat 3 P2 (a lone CR inside a dot-atom run)", "alice\r@one.example"),
    ("the round's own witness (a trailing CRLF with nothing to fold onto)", "a@x.example\r\n"),
    // the invalid half of the group display-name rule —
    // `phrase = 1*word` REQUIRES at least one word; an empty name is `Malformed`, never a group
    // this parser used to accept vacuously.
    ("seat 1 R4-F2 (empty group display-name, empty member list)", ":;"),
    ("seat 1 R4-F2 (empty group display-name, one member)", ": a@x.example;"),
];

/// Wrap one `From` VALUE as a minimal RFC 5322 message and ask `mail-parser` for the addr-spec of
/// its first extracted mailbox (`None` if it parsed to no mailbox at all, e.g. an empty group).
fn oracle_addr(value: &str) -> Option<String> {
    let msg = format!("From: {value}\r\nDate: Fri, 21 Nov 1997 09:55:06 -0600\r\n\r\nbody\r\n");
    let message = MessageParser::default().parse(&msg)?;
    let addr = message.from()?.first()?;
    addr.address.as_ref().map(|c| c.to_string())
}

/// Corpus entries where an addr-spec MISMATCH against `mail-parser` is a KNOWN, RECORDED
/// divergence, not a defect in either parser — still asserted not-`Malformed`; the address
/// equality is recorded (`eprintln!`), not required:
///  - the two obs-route lines: `mail-parser` does not implement §4.4's route STRIPPING — it keeps
///    the route text as part of the address instead of discarding it;
///  - the quoted-HTAB line: `mail-parser` drops the quoted local-part entirely for a quoted-string
///    containing a raw tab (`.address` comes back domain-only) — evidence for the build record's
///    ("a lenient parser cannot say malformed"), not evidence this parser is wrong to admit HTAB.
const KNOWN_ADDRESS_DIVERGENCES: &[&str] = &[
    "the round's valid inputs (seat 1/2, obs-route with 2 at-domains)",
    "the round's valid inputs (seat 1/2, obs-route with 1 at-domain)",
    "seat 3 P2 (quoted HTAB is content, not a fold)",
    // the SAME route-stripping divergence as the two obs-route lines
    // above, on a domain-literal route.
    "the round's valid inputs (seat 1 R4-F2, domain-literal inside an obs-route)",
];

/// Axis 1 (ASSERTED): the standards-valid corpus. RED on the pre-fold parser — every obs-route and
/// group/mailbox-list line here was `Malformed` under the earlier rules.
#[test]
fn the_oracle_never_calls_a_standards_valid_line_malformed() {
    use aruna::mailbox::{parse_mailbox, SenderStatus};
    let mut compared_ok = 0usize;
    for (citation, raw) in VALID_CORPUS {
        let ours = parse_mailbox(raw);
        assert_ne!(ours.status, SenderStatus::Malformed, "{citation}: {raw:?} is standards-valid, never Malformed");
        if ours.status == SenderStatus::Ok {
            let theirs = oracle_addr(raw);
            // Whitespace-insensitive: RFC 5322 §4.4's obs-domain CFWS (A.6.3's
            // `machine(comment).  example`) folds to nothing addressable either way, but
            // `mail-parser` keeps the folding whitespace verbatim inside the atom run where this
            // parser normalizes it away — the same DOMAIN, a different byte-for-byte spelling.
            let squash = |s: &str| s.chars().filter(|c| !c.is_whitespace()).collect::<String>();
            let theirs_matches = theirs.as_deref().is_some_and(|a| squash(a).eq_ignore_ascii_case(&squash(&ours.from_addr)));
            if KNOWN_ADDRESS_DIVERGENCES.contains(citation) {
                eprintln!("KNOWN DIVERGENCE — {citation}: {raw:?} — ours = {:?}, mail-parser = {theirs:?}", ours.from_addr);
            } else {
                assert!(
                    theirs_matches,
                    "{citation}: {raw:?} — ours = {:?}, mail-parser = {theirs:?}",
                    ours.from_addr
                );
            }
            compared_ok += 1;
        }
    }
    assert_eq!(VALID_CORPUS.len(), 26, "the corpus size is pinned so this count is a deliberate edit");
    assert!(compared_ok >= 13, "at least the thirteen single-mailbox lines were address-compared, got {compared_ok}");
}

/// Axis 2 (RECORDED, not asserted): what `mail-parser` returns for OUR fail-closed set — "the
/// evaluated parser strategy". Run with `--nocapture` to read the table.
#[test]
fn the_oracle_evaluated_on_our_fail_closed_set_recorded_not_asserted() {
    use aruna::mailbox::parse_mailbox;
    eprintln!("mail-parser oracle — fail-closed set (ours is always Malformed by construction):");
    for (citation, raw) in FAIL_CLOSED_SET {
        let ours = parse_mailbox(raw);
        assert_eq!(ours.status, aruna::mailbox::SenderStatus::Malformed, "{citation}: {raw:?} is this crate's own fail-closed witness");
        let theirs = oracle_addr(raw);
        eprintln!("  {citation}\n    input: {raw:?}\n    mail-parser addr: {theirs:?}");
    }
}
