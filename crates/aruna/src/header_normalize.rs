//! Ingest normalization for header display strings.
//!
//! `normalize_display` is the one place header display strings (`from_name`, `subject`) pass
//! through before the ingest path writes them. It strips Unicode format-category (Cf) and
//! bidi-override codepoints and collapses newlines, including the Zl/Zp separators
//! U+2028/U+2029 (which are neither), to single spaces, so a hostile provider payload cannot
//! smuggle an invisible override character or fake newline-injected UI chrome into what the
//! client later renders.
//!
//! ## `from_addr` is not routed through this function
//!
//! Callers must not pass `from_addr` (or any other identity/address byte string) through
//! `normalize_display` as identity. A display copy of it may be normalized, and the plan's frozen
//! sender is (see "The wired callers"). The function is total over `&str` and does not recognize
//! an address shape, so nothing enforces that boundary at runtime; it is a caller contract.
//! Addresses are identity bytes and must round-trip exactly as the provider sent them. Only
//! display strings, the ones a human reads in a list or reading pane, go through here. The
//! address-beside-name and bidi-isolation controls (a display name is never presented as
//! authenticated identity) live in the UI layer.
//!
//! ## The Cf/bidi range table
//!
//! `std::char` has no general-category API, so the stripped ranges are an explicit,
//! hand-maintained list from the Unicode Character Database's Cf (Format) category plus the
//! bidi-control codepoints (`UnicodeData.txt` / `DerivedGeneralCategory.txt`;
//! <https://www.unicode.org/reports/tr44/#General_Category_Values>). It is a snapshot, not a live
//! derivation: later Unicode versions can add Cf codepoints, and the list errs toward the union
//! of known ranges but is not kept in sync automatically.
//!
//! The table was re-swept against the Cf list and gained one range, U+0890..U+0891 (ARABIC POUND
//! MARK ABOVE / ARABIC PIASTRE MARK ABOVE, Cf since Unicode 14.0), the siblings of the
//! U+0600..U+0605 Arabic number signs already listed. Checked and deliberately not added:
//! U+061D (ARABIC END OF TEXT MARK) is Po, not Cf; U+180B..U+180D and U+180F (Mongolian free
//! variation selectors) are Mn; U+2065 is unassigned (Cn), which is why the U+2060..U+2064 and
//! U+2066..U+206F ranges are split; U+13439..U+1343F (Unicode 15.0's Egyptian format controls)
//! were already inside U+13430..U+1343F.
//!
//! ## The wired callers
//!
//! [`crate::read_coordinator::ReadCoordinator::ingest_page`] routes `from_name` and `subject`
//! through [`normalize_display`] on their way into the durable header row, and routes `from_addr`
//! around it.
//!
//! `frozen_plan_member` in `lib.rs` normalizes the plan's frozen display copy of `Name <addr>`
//! (or of the bare address), the text a human reads on the approval screen. The identity column
//! stays outside: the header row's `from_addr` is read, never rewritten, and a plan member's
//! identity is its `message_ref`. The summary's sender domains come from the RFC 5322 parse
//! (`crate::mailbox`), not from this text, and that parser reads the Cf/bidi table below
//! (`is_cf_or_bidi`) to refuse an address carrying one: an address that would render as another
//! is `malformed`, never normalized into a domain.

/// Ranges (inclusive) covering the Unicode Cf (Format) general category and the explicit
/// bidi-override control points, as of the Unicode version available when this module was
/// written. See the module doc for sourcing and the snapshot caveat.
const CF_AND_BIDI_RANGES: &[(u32, u32)] = &[
    (0x00AD, 0x00AD),   // SOFT HYPHEN
    (0x0600, 0x0605),   // Arabic number signs
    (0x061C, 0x061C),   // ARABIC LETTER MARK
    (0x06DD, 0x06DD),   // ARABIC END OF AYAH
    (0x070F, 0x070F),   // SYRIAC ABBREVIATION MARK
    (0x0890, 0x0891),   // ARABIC POUND/PIASTRE MARK ABOVE (Cf, added Unicode 14.0)
    (0x08E2, 0x08E2),   // ARABIC DISPUTED END OF AYAH
    (0x180E, 0x180E),   // MONGOLIAN VOWEL SEPARATOR
    (0x200B, 0x200F),   // ZERO WIDTH SPACE..RIGHT-TO-LEFT MARK (incl. ZWJ/ZWNJ)
    (0x202A, 0x202E),   // LRE, RLE, PDF, LRO, RLO
    (0x2060, 0x2064),   // WORD JOINER..INVISIBLE PLUS
    (0x2066, 0x206F),   // LRI, RLI, FSI, PDI + deprecated format chars
    (0xFEFF, 0xFEFF),   // ZERO WIDTH NO-BREAK SPACE / BOM
    (0xFFF9, 0xFFFB),   // INTERLINEAR ANNOTATION ANCHOR/SEPARATOR/TERMINATOR
    (0x110BD, 0x110BD), // KAITHI NUMBER SIGN
    (0x110CD, 0x110CD), // KAITHI NUMBER SIGN ABOVE
    (0x13430, 0x1343F), // Egyptian hieroglyph format controls
    (0x1BCA0, 0x1BCA3), // Shorthand format controls
    (0x1D173, 0x1D17A), // Musical symbol format controls
    (0xE0001, 0xE0001), // LANGUAGE TAG
    (0xE0020, 0xE007F), // Tag characters
];

/// Is this codepoint a Unicode Cf-category / bidi-override control point (see
/// [`CF_AND_BIDI_RANGES`])?
pub(crate) fn is_cf_or_bidi(c: char) -> bool {
    let cp = c as u32;
    CF_AND_BIDI_RANGES
        .iter()
        .any(|&(lo, hi)| cp >= lo && cp <= hi)
}

/// Is this codepoint a control character (C0 or C1) that is NOT one of the whitespace
/// controls we map to a space (`\n`, `\r`, `\t`)?
fn is_stripped_control(c: char) -> bool {
    c.is_control() && c != '\n' && c != '\r' && c != '\t'
}

/// Normalize a header display string (`from_name`, `subject`) before the ingest path writes it.
/// See the module doc for the contract, the `from_addr` caveat and the range sourcing.
///
/// - Unicode Cf-category and bidi-override codepoints are dropped.
/// - Other control characters (C0 other than `\n`/`\r`/`\t`, and C1) are dropped.
/// - `\n`, `\r`, `\t`, U+2028 and U+2029 each map to a single space.
/// - Runs of spaces produced by that mapping (or already present) collapse to one.
/// - Leading and trailing whitespace is trimmed.
/// - All other codepoints, including non-ASCII text, pass through unchanged.
pub(crate) fn normalize_display(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut pending_space = false;

    for c in s.chars() {
        if is_cf_or_bidi(c) || is_stripped_control(c) {
            continue;
        }
        let mapped = match c {
            // U+2028 LINE SEPARATOR and U+2029 PARAGRAPH SEPARATOR join the CR/LF/tab arm. They are
            // general category Zl/Zp, neither Cf nor `char::is_control()`, so both strip
            // predicates above pass them through, while every renderer downstream treats them as
            // a hard line break: the same newline-injected fake-chrome surface `\n`/`\r` are
            // collapsed for. They map to a space for the same reason (a display string is one
            // line, and a dropped separator would weld two words together).
            '\n' | '\r' | '\t' | '\u{2028}' | '\u{2029}' => ' ',
            other => other,
        };
        if mapped == ' ' {
            pending_space = true;
            continue;
        }
        if pending_space {
            if !out.is_empty() {
                out.push(' ');
            }
            pending_space = false;
        }
        out.push(mapped);
    }

    out
}

#[cfg(test)]
mod tests {
    use super::normalize_display;

    #[test]
    fn strips_rtl_override() {
        assert_eq!(
            normalize_display("invoice\u{202E}fdp.exe"),
            "invoicefdp.exe"
        );
    }

    #[test]
    fn collapses_newline_injected_fake_chrome_to_single_line_no_double_spaces() {
        let hostile = "Payroll\n-- Photon: sender verified --\nOpen attachment";
        let normalized = normalize_display(hostile);
        assert_eq!(
            normalized,
            "Payroll -- Photon: sender verified -- Open attachment"
        );
        assert!(!normalized.contains("  "), "no double spaces from the collapse");
        assert!(!normalized.contains('\n'));
        assert!(!normalized.contains('\r'));
    }

    #[test]
    fn strips_zwj() {
        assert_eq!(normalize_display("acc\u{200D}ounts"), "accounts");
    }

    #[test]
    fn strips_lri() {
        assert_eq!(
            normalize_display("\u{2066}admin@photon.local"),
            "admin@photon.local"
        );
    }

    #[test]
    fn strips_every_cf_category_codepoint_in_the_representative_sweep() {
        let sweep = [
            '\u{00AD}', // soft hyphen
            '\u{200B}', '\u{200C}', '\u{200D}', '\u{200E}', '\u{200F}',
            '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}',
            '\u{2060}', '\u{2061}', '\u{2062}', '\u{2063}', '\u{2064}',
            '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
            '\u{FEFF}',
        ];
        for c in sweep {
            let s = format!("a{c}b");
            let normalized = normalize_display(&s);
            assert_eq!(
                normalized, "ab",
                "codepoint U+{:04X} survived normalization",
                c as u32
            );
            assert!(
                !normalized.chars().any(|nc| nc == c),
                "codepoint U+{:04X} present in output",
                c as u32
            );
        }
    }

    /// the Cf table's missing range. U+0890 ARABIC POUND MARK ABOVE and
    /// U+0891 ARABIC PIASTRE MARK ABOVE were added in Unicode 14.0 in the **Cf** category, beside
    /// the U+0600..U+0605 Arabic number signs this table already carries. They were absent, so an
    /// invisible format control survived the chokepoint into a durable display row.
    #[test]
    fn strips_the_unicode_14_arabic_cf_marks() {
        for c in ['\u{0890}', '\u{0891}'] {
            let s = format!("a{c}b");
            let normalized = normalize_display(&s);
            assert_eq!(
                normalized, "ab",
                "codepoint U+{:04X} (Cf since Unicode 14) survived normalization",
                c as u32
            );
        }
    }

    /// Regression test: U+2028 LINE SEPARATOR and U+2029 PARAGRAPH SEPARATOR.
    ///
    /// They are general category **Zl/Zp**, not Cf and not `char::is_control()`, so neither of this
    /// module's two strip predicates saw them and they passed through VERBATIM into a durable
    /// display row. Every layer that renders a header treats them as a line break (JS/ECMAScript
    /// terminators, CSS `white-space: pre-*`, most text shapers), which is exactly the
    /// newline-injected fake-chrome surface `\n`/`\r` are collapsed for — smuggled past the
    /// chokepoint through a codepoint the CR/LF arm never named.
    #[test]
    fn collapses_the_line_and_paragraph_separators_to_a_space() {
        assert_eq!(normalize_display("a\u{2028}b"), "a b");
        assert_eq!(normalize_display("a\u{2029}b"), "a b");
        // …and they join the SAME collapse rule the CR/LF/tab arm rides: a run around them is one
        // space, and the fake-chrome shape is single-line like its `\n` twin above.
        assert_eq!(
            normalize_display("Payroll\u{2028}-- Photon: sender verified --"),
            "Payroll -- Photon: sender verified --"
        );
        assert_eq!(normalize_display("a \u{2028} \u{2029} b"), "a b");
    }

    #[test]
    fn non_hostile_international_text_passes_through_untouched() {
        assert_eq!(normalize_display("Grüße aus München"), "Grüße aus München");
        assert_eq!(normalize_display("日本語の件名"), "日本語の件名");
        assert_eq!(normalize_display("Здравствуйте"), "Здравствуйте");
    }

    #[test]
    fn strips_control_chars_and_maps_tab_to_space() {
        // C0 controls other than \n \r \t are stripped entirely.
        let with_bell_and_vtab = "a\u{0007}b\u{000B}c";
        assert_eq!(normalize_display(with_bell_and_vtab), "abc");

        // \t maps to a single space.
        assert_eq!(normalize_display("a\tb"), "a b");

        // C1 controls are stripped entirely.
        let with_c1 = "a\u{0080}b\u{009F}c";
        assert_eq!(normalize_display(with_c1), "abc");
    }

    /// `from_addr` is NEVER routed through `normalize_display` by callers — see the module
    /// doc's "`from_addr` is NOT routed through this function" section. `normalize_display`
    /// is total over `&str` and does not special-case `@` or any address shape, so nothing
    /// at runtime enforces this; it is a caller contract, named here and in the module doc,
    /// not a behavior this test can assert against the function itself.
    #[test]
    fn from_addr_identity_is_a_caller_contract_not_a_function_behavior() {
        // Documented, not asserted: normalize_display has no address-aware special case,
        // so an address routed through it by mistake would be display-normalized like any
        // other string. Callers (the ingest path) must not do that. No assertion follows;
        // this test exists to anchor the contract in the test file per the design clause.
    }
}
