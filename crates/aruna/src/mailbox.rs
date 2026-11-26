//! The sender boundary: a `From` header is parsed by RFC 5322 §3.4's grammar, never by a
//! delimiter search.
//!
//! ```text
//! mailbox    = name-addr / addr-spec
//! name-addr  = [display-name] angle-addr
//! angle-addr = [CFWS] "<" addr-spec ">" [CFWS]
//! addr-spec  = local-part "@" domain
//! ```
//!
//! A comment is CFWS (§3.2.2): it is not part of the address, and it may hold angle brackets
//! of its own. A rule of "the last `<…>` pair wins" reads
//! `Notice <real@evil.example> (routing note <billing@trusted.example>)` as the mailbox
//! `billing@trusted.example`, and the approval summary would then name the comment's domain to
//! the human approving the plan. Here a comment is skipped whole (nesting and quoted-pairs
//! included) and a quoted-string is one word whatever it spells.
//!
//! **The complement rule.** A `From` value is
//! [`SenderStatus::Malformed`](crate::mailbox::SenderStatus::Malformed) only when it fails to
//! parse under the grammar this module implements (see "The strictness list"): an unterminated
//! comment/quoted-string/domain-literal, a stray bracket, two angle-addrs, text after an
//! angle-addr, or an address carrying a codepoint that cannot be shown. Parsed and exactly one
//! mailbox (obs-route inside the angle-addr parsed and ignored) is `Ok`. Parsed but not exactly
//! one mailbox (a group per RFC 6854 §2, any member count including the empty group
//! `undisclosed-recipients:;`, or a mailbox-list of more than one) is
//! [`SenderStatus::Unsupported`](crate::mailbox::SenderStatus::Unsupported): valid syntax, no
//! single sender to attribute; the raw text is kept and no domain is named, as with `Malformed`.
//! More than one `From` field in the message (RFC 5322 §3.6: `from` occurs at most once) is
//! `Malformed`; the transport counts them ([`RawFrom`](crate::mailbox::RawFrom)) before this
//! parser sees a value.
//!
//! **The strictness list.** This is where "the grammar this module implements" is defined. The
//! productions are those of RFC 5322 §3.2.1–§3.2.4, §3.4, §3.4.1, §4.1, §4.4 and RFC 6854 §2
//! enumerated by this module's directed and generated tests (each cites its section), minus
//! this list: (1) a bare CR or LF outside a CRLF+WSP fold, anywhere in the field (including as
//! the escaped half of an obs-qp quoted-pair, §4.1), refuses as `Malformed`: `unfold` refuses
//! any bare CR/LF over the whole raw field before `quoted_string` or `skip_comment` run, so
//! obs-qp CR/LF is simply not implemented; (2) a codepoint that cannot be shown in an address
//! (`is_shown_in_an_address`: Default_Ignorable, control, whitespace) refuses as `Malformed`
//! (UTS, beyond the RFC). Totality of the grammar is not claimed.
//!
//! **Prior art.** `mailparse` 0.17.0 (0BSD) closes a comment at its first `)`, but RFC 5322
//! §3.2.2 nests them (`ccontent = ctext / quoted-pair / comment`), so `(a (b) c) N <r@e.example>`
//! gives the display name `c) N`; it also accepts `Name <a@b@c>` and `Notice real@evil.example`
//! as addresses. Python's `email.headerregistry` parses leniently and reports defects; this
//! module treats any defect as `Malformed`. What remains is a small tokenizer over §3.2's lexical
//! tokens plus §3.4's two productions, with RFC 6532's UTF-8 admitted in atoms, and the obsolete
//! forms §4 obliges a receiver to accept where they cannot move the address (`obs-phrase`'s `.`,
//! `obs-local-part`'s CFWS between words, `obs-route` inside an angle-addr). Stalwart's
//! `mail-parser` (MIT/Apache-2.0) is the differential oracle for the standards-valid corpus
//! (`crates/aruna/tests/mailparser_oracle.rs`, a dev-dependency only). It is not adopted as the
//! parser, since a lenient parser cannot say `Malformed` and this module's contract is failing
//! closed.
//!
//! **What an address may contain.** An atom of the addr-spec (and a quoted local-part, and a
//! domain-literal) carries no control, Unicode format/bidi (Cf) or non-space whitespace
//! codepoint, and no Unicode `Default_Ignorable_Code_Point` (UTS §4 skeleton step 2: variation
//! selectors, combining grapheme joiners, Hangul/Khmer fillers and their kin). RFC 6532 admits
//! any UTF-8 there, but such a codepoint cannot be shown: `pay\u{200B}pal.example` (or
//! `pay\u{FE0F}pal.example`) renders exactly as `paypal.example`, and display normalization
//! would merge the two. Such an address is `Malformed`, never a domain the summary names. The
//! domain key used for grouping is also NFC-normalized (`café.example` in NFC and NFD key
//! identically); the addr-spec text itself is untouched.
//!
//! **One parser, two callers.** The Gmail transport splits the raw header with
//! [`parse_mailbox`](crate::mailbox::parse_mailbox) and stores
//! [`ParsedMailbox::from_addr`](crate::mailbox::ParsedMailbox::from_addr) as the header row's
//! `from_addr`; the header row's single write path (`message_header::upsert_header_row`) derives
//! the row's `from_status` and `from_domain` from that stored text through
//! [`sender_facts`](crate::mailbox::sender_facts), this same parser. The stored text re-parses to
//! the same answer: an `Ok` row stores the canonical addr-spec, which is an addr-spec; a
//! `Malformed` row stores the raw header with only its FWS trimmed, which is the input the
//! parser itself starts from; an `Unavailable` row stores nothing (tested by
//! `the_stored_from_addr_re_parses_to_the_transports_answer`).

closed_tokens! {
    /// What a `From` header named: the closed set a header row (`message_header.from_status`) and
    /// a frozen plan member (`plan_member.sender_status`) carry.
    ///
    /// By the complement rule, a `From` is `Malformed` only when it fails to parse under the
    /// grammar this module implements (module doc, "The strictness list"). Parsed, but not
    /// exactly one mailbox (a group of any member count, or a mailbox-list of more than one), is
    /// `Unsupported`, never `Malformed`.
    pub enum SenderStatus {
        /// Exactly one RFC 5322 mailbox: its addr-spec and its domain are known.
        Ok => "ok",
        /// No `From` value at all (absent, or empty after its folding whitespace): there is no
        /// sender to name.
        Unavailable => "unavailable",
        /// A value that does not parse under the grammar at all. Its raw text is kept as the
        /// display; no address and no domain are derived from it.
        Malformed => "malformed",
        /// A value that parses under the full address-list grammar but is not exactly one
        /// mailbox: a group (RFC 6854, any member count) or a mailbox-list of more than one. Its
        /// raw text is kept as the display and no address or domain is derived: the syntax is
        /// valid, Photon just does not attribute a single sender to it.
        Unsupported => "unsupported",
    }
}

/// One `From` header, parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedMailbox {
    pub status: SenderStatus,
    /// The display-name phrase (`Ok` only; empty otherwise): comments dropped, quoted-strings
    /// unquoted, a run of CFWS between two words one space (§3.2.2). RFC 2047-decoded here, per
    /// word, with each word's lexical provenance (see `phrase()`): an atom that is exactly one
    /// LWSP-separated encoded-word decodes, a quoted-string never does. The transports publish
    /// it as-is and must not decode it again (a second pass would double-decode). The address
    /// half is never decoded.
    pub display_name: String,
    /// The addr-spec's local-part, canonically spelled (`Ok` only; empty otherwise), taken from
    /// the same tokens `addr_spec` builds `from_addr` from, never by splitting `from_addr` on its
    /// `@`: an addr-spec's domain half may itself be a domain-literal carrying its own `@`
    /// (`obs-dtext`/dtext do not exclude it), so a delimiter search over the composed text
    /// cannot recover the boundary the grammar already knows.
    pub local_part: String,
    /// What the header row stores as `from_addr`: the canonical addr-spec (`Ok`); the raw value
    /// with its folding whitespace trimmed (`Malformed`); the empty string (`Unavailable`).
    pub from_addr: String,
    /// The addr-spec's domain, ASCII-lowercased (`Ok` only).
    pub domain: Option<String>,
}

impl ParsedMailbox {
    /// The addr-spec: `Some` exactly when the header is one well-formed mailbox.
    pub fn addr(&self) -> Option<&str> {
        (self.status == SenderStatus::Ok).then_some(self.from_addr.as_str())
    }
}

/// Parse one `From` header value by RFC 5322 §3.4. Total: every input answers.
///
/// `unfold` (private, hence a plain code span rather than an intra-doc link) runs first, over
/// the whole raw field: a bare CR, a bare LF, or a CRLF not immediately followed by WSP is not
/// FWS anywhere in the field (§2.2.3), and is `Malformed`, never silently dropped or treated as
/// ordinary whitespace.
pub fn parse_mailbox(raw: &str) -> ParsedMailbox {
    let Some(unfolded) = unfold(raw) else {
        return ParsedMailbox {
            status: SenderStatus::Malformed,
            display_name: String::new(),
            local_part: String::new(),
            from_addr: trim_fws(raw).to_string(),
            domain: None,
        };
    };
    let trimmed = trim_fws(&unfolded);
    if trimmed.is_empty() {
        return ParsedMailbox {
            status: SenderStatus::Unavailable,
            display_name: String::new(),
            local_part: String::new(),
            from_addr: String::new(),
            domain: None,
        };
    }
    match lex(trimmed).and_then(|tokens| classify(&tokens)) {
        Some(Classified::One(display_name, local_part, addr, domain)) => ParsedMailbox {
            status: SenderStatus::Ok,
            display_name,
            local_part,
            from_addr: addr,
            domain: Some(domain),
        },
        Some(Classified::Unsupported) => ParsedMailbox {
            status: SenderStatus::Unsupported,
            display_name: String::new(),
            local_part: String::new(),
            from_addr: trimmed.to_string(),
            domain: None,
        },
        None => ParsedMailbox {
            status: SenderStatus::Malformed,
            display_name: String::new(),
            local_part: String::new(),
            from_addr: trimmed.to_string(),
            domain: None,
        },
    }
}

/// What the tokens classify as, under the grammar this module implements (module doc, "The
/// strictness list").
enum Classified {
    /// Exactly one mailbox: `(display name, local-part, canonical addr-spec, lowercased domain)`.
    One(String, String, String, String),
    /// Parsed, but not exactly one mailbox (a group or a >1 mailbox-list).
    Unsupported,
}

/// Try the value as one mailbox first (§3.4 `mailbox`, obs-route included); a value that is not
/// one mailbox is tried next as an `address-list` (§3.4, RFC 6854): comma-separated addresses,
/// each a mailbox or a group. `None` means neither shape parses, so the value is `Malformed`.
fn classify(tokens: &[Token]) -> Option<Classified> {
    if let Some((display, local, addr, domain)) = mailbox(tokens) {
        return Some(Classified::One(display, local, addr, domain));
    }
    address_list(tokens)
}

/// The sender facts the header row's write path derives from the `from_addr` it stores:
/// [`parse_mailbox`] over that text (see the module doc, "One parser, two callers").
pub fn sender_facts(from_addr: &str) -> (SenderStatus, Option<String>) {
    let parsed = parse_mailbox(from_addr);
    (parsed.status, parsed.domain)
}

/// What a transport found under the header name `From`, before any grammar runs (RFC 5322 §3.6:
/// `from` occurs at most once). A typed signal, not a magic string: the Gmail transport reads a
/// raw header list and counts occurrences case-insensitively. The JMAP transport does the same.
/// JMAP's wire shape does not by itself guarantee at most one `From`: RFC 8621 §4.1.3's
/// convenience property (no `:all`) silently returns only the last header instance, discarding
/// any earlier one, and §4.1.2.3's `asAddresses` form discards group/comment information before
/// this module sees it. So the JMAP arm requests `header:From:asRaw:all` (every raw instance,
/// unparsed) and builds this type from the occurrence count, as Gmail does with its raw header
/// list: both transports run one parser over one cardinality rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RawFrom {
    /// No `From` header at all.
    Absent,
    /// Exactly one `From` header, unparsed.
    Single(String),
    /// More than one `From` header — the count, for the record; never used to pick one.
    Multiple(usize),
}

/// [`parse_mailbox`], preceded by the §3.6 cardinality check: `Multiple` is `Malformed` before
/// the §3.4 grammar runs, so a sender cannot pick which of two `From` fields the review trusts
/// by supplying one well-formed and one hostile.
pub fn parse_from(raw: RawFrom) -> ParsedMailbox {
    match raw {
        RawFrom::Absent => ParsedMailbox {
            status: SenderStatus::Unavailable,
            display_name: String::new(),
            local_part: String::new(),
            from_addr: String::new(),
            domain: None,
        },
        RawFrom::Single(value) => parse_mailbox(&value),
        RawFrom::Multiple(n) => ParsedMailbox {
            status: SenderStatus::Malformed,
            display_name: String::new(),
            local_part: String::new(),
            from_addr: format!("{n} From header fields"),
            domain: None,
        },
    }
}

/// RFC 5322's folding whitespace at the top level (SP and HTAB) trimmed at both ends, and nothing
/// else: a non-ASCII space is not FWS and stays, so the trimmed text lexes exactly as the
/// untrimmed one. CR/LF are not trimmed here: [`unfold`] (run first, over the whole field, by
/// every caller) is the only place a CR/LF is consumed, so a bare CR/LF can never be silently
/// stripped.
fn trim_fws(raw: &str) -> &str {
    raw.trim_matches(|c: char| matches!(c, ' ' | '\t'))
}

/// RFC 5322 §2.2.3 unfolding, run once over the whole raw field before anything else touches it
/// (CR/LF is legal only as CRLF immediately followed by WSP, anywhere in the field). A CRLF
/// immediately followed by at least one WSP is a fold: the CRLF is removed and the WSP run after
/// it is kept as ordinary content, the same whether the fold sits at the top level, inside a
/// dot-atom run, or inside a quoted-string. This is the only place CR/LF is consumed; `lex`,
/// `quoted_string` and `domain_literal` never see one after this runs. `None` (the whole value is
/// `Malformed`) for a lone CR (not immediately followed by LF), a lone LF (not immediately
/// preceded by a CR this function just consumed), or a CRLF with no WSP immediately after it
/// (nothing to fold onto, including a CRLF at the very end of the field).
fn unfold(raw: &str) -> Option<String> {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\r' => {
                if chars.next() != Some('\n') {
                    return None;
                }
                if !matches!(chars.peek(), Some(' ') | Some('\t')) {
                    return None;
                }
                // The CRLF folds away; the WSP run after it is ordinary content, pushed by the
                // loop's own default arm on its next iterations.
            }
            '\n' => return None,
            _ => out.push(c),
        }
    }
    Some(out)
}

/// One lexical token outside every comment (§3.2). CFWS is not a token: a run of it before a
/// token is recorded as `space_before`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Lexeme {
    /// A run of atext (§3.2.3), RFC 6532's UTF-8 non-ASCII admitted.
    Atom(String),
    /// A quoted-string's content, quoted-pairs resolved (§3.2.4).
    Quoted(String),
    /// A domain-literal's dtext, FWS removed (§3.4.1).
    DomainLiteral(String),
    /// One of the specials the mailbox grammar reads.
    Special(char),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Token {
    lexeme: Lexeme,
    space_before: bool,
}

/// atext (§3.2.3), with RFC 6532's `UTF8-non-ascii`.
fn is_atext(c: char) -> bool {
    c.is_ascii_alphanumeric() || "!#$%&'*+-/=?^_`{|}~".contains(c) || !c.is_ascii()
}

/// A codepoint an address may carry: no control character, no Unicode format/bidi codepoint
/// (`Cf`/bidi, `header_normalize::is_cf_or_bidi`), no whitespace, and no Unicode
/// `Default_Ignorable_Code_Point` (UTS v18.0.0 §4 skeleton step 2, Table 1: RESTRICTED). A
/// variation selector, combining grapheme joiner, Hangul/Khmer filler and their kin all render
/// as nothing, so `pay<invisible>pal.example` renders exactly as `paypal.example`. This
/// predicate is only about codepoints that render as nothing; it is not a confusable/homoglyph
/// defense (whole-script and mixed-script look-alikes remain the declared UTS residual).
fn is_shown_in_an_address(c: char) -> bool {
    !(c.is_control()
        || c.is_whitespace()
        || crate::header_normalize::is_cf_or_bidi(c)
        || icu_properties::CodePointSetData::new::<icu_properties::props::DefaultIgnorableCodePoint>().contains(c))
}

/// §3.2's lexical tokens, CFWS dropped. `None` means the value does not lex: an unterminated
/// comment, quoted-string or domain-literal, a stray `)` / `]` / `\`, or an ASCII character no
/// production admits here. CR and LF are not whitespace here: [`unfold`] has already run over the
/// whole field and refused any outside a legal fold, so neither can be present; if one somehow
/// were, it falls to the `_ => return None` arm rather than being treated as FWS.
fn lex(raw: &str) -> Option<Vec<Token>> {
    let mut tokens = Vec::new();
    let mut chars = raw.chars().peekable();
    let mut space = false;
    while let Some(&c) = chars.peek() {
        let lexeme = match c {
            ' ' | '\t' => {
                chars.next();
                space = true;
                continue;
            }
            '(' => {
                chars.next();
                skip_comment(&mut chars)?;
                space = true;
                continue;
            }
            '"' => {
                chars.next();
                Lexeme::Quoted(quoted_string(&mut chars)?)
            }
            '[' => {
                chars.next();
                Lexeme::DomainLiteral(domain_literal(&mut chars)?)
            }
            '<' | '>' | '@' | '.' | ',' | ';' | ':' => {
                chars.next();
                Lexeme::Special(c)
            }
            _ if is_atext(c) => {
                let mut atom = String::new();
                while let Some(&c) = chars.peek() {
                    if !is_atext(c) {
                        break;
                    }
                    atom.push(c);
                    chars.next();
                }
                Lexeme::Atom(atom)
            }
            _ => return None,
        };
        tokens.push(Token { lexeme, space_before: space });
        space = false;
    }
    Some(tokens)
}

/// A comment, after its `(`: nested comments (§3.2.2 `ccontent`) and quoted-pairs are skipped
/// with it. `None` means unterminated.
fn skip_comment(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> Option<()> {
    let mut depth = 1usize;
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                chars.next()?;
            }
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(());
                }
            }
            _ => {}
        }
    }
    None
}

/// A quoted-string's content, after its opening `"`: quoted-pairs resolved, a WSP run kept as
/// content (§2.2.3 FWS's mandatory `1*WSP`, admitted with no preceding CRLF: a quoted HTAB is
/// content, not a fold), and a CRLF unfolded away only when immediately followed by at least one
/// WSP (§2.2.3 FWS: `([*WSP CRLF] 1*WSP)`; the CRLF is never a token on its own). `None` means
/// unterminated, or a bare CR/LF that is not FWS (a lone CR, a lone LF, or a CRLF not followed
/// by WSP). Dropping every CR/LF unconditionally would turn `"a\r\nb"` into `"ab"`, an `Ok`
/// sender the review would call well-formed.
fn quoted_string(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> Option<String> {
    let mut content = String::new();
    while let Some(c) = chars.next() {
        match c {
            '\\' => content.push(chars.next()?),
            '"' => return Some(content),
            '\r' => {
                if chars.next() != Some('\n') {
                    return None;
                }
                if !matches!(chars.peek(), Some(' ') | Some('\t')) {
                    return None;
                }
                while matches!(chars.peek(), Some(' ') | Some('\t')) {
                    content.push(chars.next().expect("peeked Some"));
                }
            }
            '\n' => return None,
            _ => content.push(c),
        }
    }
    None
}

/// A domain-literal's dtext, after its `[`: FWS removed; `[` and anything an address cannot show
/// refuse; a `\` opens an `obs-dtext` quoted-pair (§4.4 `obs-dtext = obs-NO-WS-CTL /
/// quoted-pair`) whose escaped char is content (the backslash is discarded), still subject to
/// the same "can this be shown" check, so `a@[\192.0.2.1]` is `Ok` with domain `[192.0.2.1]` but
/// `\` followed by a NUL/control/whitespace codepoint still refuses (the strictness list, module
/// doc). `None` means unterminated, empty, refused, or a `\` with nothing after it.
fn domain_literal(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> Option<String> {
    let mut dtext = String::new();
    while let Some(c) = chars.next() {
        match c {
            ']' => return (!dtext.is_empty()).then_some(dtext),
            ' ' | '\t' | '\r' | '\n' => {}
            '[' => return None,
            '\\' => {
                let escaped = chars.next()?;
                if is_shown_in_an_address(escaped) {
                    dtext.push(escaped);
                } else {
                    return None;
                }
            }
            _ if is_shown_in_an_address(c) => dtext.push(c),
            _ => return None,
        }
    }
    None
}

fn special(t: &Token, s: char) -> bool {
    t.lexeme == Lexeme::Special(s)
}

/// For each token, whether it sits at angle-depth 0 (outside any `<...>` span), computed before
/// that token's own effect on the depth, so the opening `<` itself counts as depth 0 (it is the
/// delimiter) and everything strictly between an open and its close does not.
fn angle_top_level(tokens: &[Token]) -> Vec<bool> {
    let mut depth = 0i32;
    tokens
        .iter()
        .map(|t| {
            let top = depth == 0;
            if special(t, '<') {
                depth += 1;
            } else if special(t, '>') {
                depth -= 1;
            }
            top
        })
        .collect()
}

/// §3.4 `mailbox` over the tokens: `(display name, local-part, canonical addr-spec, lowercased
/// domain)`, or `None` when the value is not exactly one mailbox. A list (`,`) or group (`:` …
/// `;`) outside any angle-addr is not one mailbox; those are only tried as an `address-list`
/// ([`classify`]). A `:` inside an angle-addr is `obs-route` (§4.4), parsed and ignored.
fn mailbox(tokens: &[Token]) -> Option<(String, String, String, String)> {
    let top_level = angle_top_level(tokens);
    if tokens
        .iter()
        .zip(&top_level)
        .any(|(t, &top)| top && (special(t, ',') || special(t, ';') || special(t, ':')))
    {
        return None;
    }
    let opens: Vec<usize> = (0..tokens.len()).filter(|&i| special(&tokens[i], '<')).collect();
    let closes: Vec<usize> = (0..tokens.len()).filter(|&i| special(&tokens[i], '>')).collect();
    match (opens.as_slice(), closes.as_slice()) {
        ([], []) => {
            let (local, addr, domain) = addr_spec(tokens)?;
            Some((String::new(), local, addr, domain))
        }
        // name-addr: the angle-addr is the last token (trailing CFWS was never a token), so
        // anything else after the `>` is not a mailbox.
        ([open], [close]) if open < close && *close == tokens.len() - 1 => {
            let display_name = phrase(&tokens[..*open])?;
            let (local, addr, domain) = addr_spec_allowing_obs_route(&tokens[open + 1..*close])?;
            Some((display_name, local, addr, domain))
        }
        _ => None,
    }
}

/// `addr-spec`, or (§4.4) `obs-route` `:` `addr-spec`. The route is validated (a comma-separated
/// `obs-domain-list`, at least one `@domain`) and then discarded: only the addr-spec after the
/// final top-level `:` is the mailbox's address.
fn addr_spec_allowing_obs_route(tokens: &[Token]) -> Option<(String, String, String)> {
    match tokens.iter().position(|t| special(t, ':')) {
        None => addr_spec(tokens),
        Some(colon) => {
            // §4.4: `obs-route = obs-domain-list ":"`, at most one route, so a second `:` here is
            // not a route at all.
            if tokens[colon + 1..].iter().any(|t| special(t, ':')) {
                return None;
            }
            validate_obs_route(&tokens[..colon])?;
            addr_spec(&tokens[colon + 1..])
        }
    }
}

/// `obs-domain-list = *(CFWS / ",") "@" domain *("," [CFWS] "@" domain)` (CFWS already dropped by
/// the lexer): one or more `@domain` entries, comma-separated. An empty entry (leading or
/// repeated filler commas) is allowed, but a non-empty entry that is not `@domain` refuses the
/// whole route, and so the whole mailbox: an invalid route is not silently ignored.
fn validate_obs_route(tokens: &[Token]) -> Option<()> {
    if tokens.is_empty() {
        return None;
    }
    let mut saw_at_domain = false;
    for segment in tokens.split(|t| special(t, ',')) {
        if segment.is_empty() {
            continue;
        }
        let [first, rest @ ..] = segment else { return None };
        if !special(first, '@') || rest.is_empty() {
            return None;
        }
        route_domain(rest)?;
        saw_at_domain = true;
    }
    saw_at_domain.then_some(())
}

/// §4.4 `obs-domain = atom *("." atom) / domain-literal`: the same two shapes `addr-spec`'s own
/// domain half admits ([`addr_spec`]). Trying only the dotted-atom shape here would refuse
/// `N <@[192.0.2.1]:u@t.example>` at the route before the addr-spec after it was reached.
fn route_domain(tokens: &[Token]) -> Option<()> {
    match tokens {
        [Token { lexeme: Lexeme::DomainLiteral(_), .. }] => Some(()),
        rest => dotted(rest, false).map(|_| ()),
    }
}

/// Split top-level tokens on `,`, never inside an angle-addr and never inside an open group
/// (`:` … `;`, tracked the same way; a group cannot nest, so one flag suffices). `None` means the
/// brackets or the group never close (an unterminated shape, never a split).
fn split_top_level_commas(tokens: &[Token]) -> Option<Vec<&[Token]>> {
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut angle_depth = 0i32;
    let mut in_group = false;
    for (i, t) in tokens.iter().enumerate() {
        if special(t, '<') {
            angle_depth += 1;
        } else if special(t, '>') {
            angle_depth -= 1;
        } else if angle_depth == 0 && !in_group && special(t, ':') {
            in_group = true;
        } else if angle_depth == 0 && in_group && special(t, ';') {
            in_group = false;
        } else if angle_depth == 0 && !in_group && special(t, ',') {
            parts.push(&tokens[start..i]);
            start = i + 1;
        }
    }
    if angle_depth != 0 || in_group {
        return None;
    }
    parts.push(&tokens[start..]);
    Some(parts)
}

/// §3.4 `address-list` (RFC 6854 §2: `mailbox-list / address-list` in `From`), with §4.4's
/// obsolete null members: top-level comma-separated elements, with every null one (a leading,
/// trailing or doubled comma) stripped before anything else is decided. `None` (the value is
/// `Malformed`) when the brackets/group never close, a non-null element is not a well-formed
/// [`mailbox`] or `group`, or every element was null (`obs-mbox-list`/`obs-addr-list` still
/// require at least one real mailbox; §4.4 admits filler commas around members, never a list of
/// nothing but commas). Otherwise a group present anywhere (any member count, including all-null
/// like `G:,,;`) makes the whole list [`Classified::Unsupported`], and so does more than one
/// non-null mailbox. Exactly one non-null mailbox and no group (`a@x.example,` /
/// `, a@x.example`) is [`Classified::One`]: standards-valid syntax naming one mailbox is still
/// `Ok`, whatever filler commas surrounded it.
fn address_list(tokens: &[Token]) -> Option<Classified> {
    let elements = split_top_level_commas(tokens)?;
    let mut saw_group = false;
    let mut mailboxes: Vec<(String, String, String, String)> = Vec::new();
    for element in elements.into_iter().filter(|e| !e.is_empty()) {
        match address_element(element)? {
            AddressElement::Group => saw_group = true,
            AddressElement::Mailbox(display, local, addr, domain) => mailboxes.push((display, local, addr, domain)),
        }
    }
    if saw_group || mailboxes.len() > 1 {
        Some(Classified::Unsupported)
    } else {
        mailboxes.pop().map(|(display, local, addr, domain)| Classified::One(display, local, addr, domain))
    }
}

/// One non-null `address-list` element, classified.
enum AddressElement {
    /// A `group` (RFC 6854). Any member count, including zero, is [`Classified::Unsupported`] at
    /// the caller; this function only validates the group's own shape.
    Group,
    /// A bare [`mailbox`]: `(display name, local-part, canonical addr-spec, lowercased domain)`.
    Mailbox(String, String, String, String),
}

/// One `address-list` element: a `group` (`display-name ":" [group-list] ";"`) or a bare
/// [`mailbox`]. A group's `display-name` is required (`phrase = 1*word`, §3.2.2), so an empty
/// name before the `:` (`:;`, `: a@x.example;`) is `Malformed`, never a group that
/// `phrase(&[])` would accept vacuously. A group's own member list also strips null members
/// (the same §4.4 shape as the outer list) before validating each remaining member's shape; the
/// caller alone decides the group's overall classification, so member count is never surfaced
/// past this function.
fn address_element(tokens: &[Token]) -> Option<AddressElement> {
    if tokens.is_empty() {
        return None;
    }
    let top_level = angle_top_level(tokens);
    let colon = tokens.iter().zip(&top_level).position(|(t, &top)| top && special(t, ':'));
    match colon {
        None => mailbox(tokens).map(|(display, local, addr, domain)| AddressElement::Mailbox(display, local, addr, domain)),
        Some(colon) => {
            if tokens[..colon].is_empty() {
                return None;
            }
            phrase(&tokens[..colon])?;
            if !special(tokens.last()?, ';') {
                return None;
            }
            let inner = &tokens[colon + 1..tokens.len() - 1];
            if !inner.is_empty() {
                for member in split_top_level_commas(inner)?.into_iter().filter(|m| !m.is_empty()) {
                    mailbox(member)?;
                }
            }
            Some(AddressElement::Group)
        }
    }
}

/// A display-name (`phrase`, with `obs-phrase`'s `.`), empty when absent. A run of CFWS between
/// two words is one space; a `.` keeps the spacing it had.
///
/// The name is RFC 2047-decoded here, per word, while the lexer still knows each word's
/// provenance. Running `decode_rfc2047` over the finished string, after `Atom` and `Quoted` have
/// been flattened, would decode `"=?UTF-8?Q?Legal_Hold?="` (quoted) like the atom form. The rules:
/// - an `Atom` decodes only through [`encoded_word_atom`]: it is exactly one encoded-word (§2,
///   the decoder consumes the whole token) and is LWSP-separated from both neighbours (§5(3));
/// - a `Quoted` word is literal and never enters the decoder (§5(3): an encoded-word must not
///   appear within a quoted-string);
/// - the whitespace between two words is dropped only when both are decoded encoded-words
///   (§6.2), so `Legal =?UTF-8?Q?Hold?=` is `Legal Hold`, never `LegalHold`;
/// - a word that does not decode is literal, never a `None` (this function is also the group
///   display-name check in [`address_element`], which must not start refusing on a decode).
///
/// Non-claims: a comment between two encoded-words is CFWS, so they join as if only LWSP
/// separated them (`=?…?= (c) =?…?=`); an encoded-word inside a comment is never displayed (the
/// comment is dropped whole).
fn phrase(tokens: &[Token]) -> Option<String> {
    let mut text = String::new();
    let mut previous_decoded = false;
    for (i, t) in tokens.iter().enumerate() {
        let decoded = encoded_word_atom(tokens, i);
        let word = match (&t.lexeme, &decoded) {
            (Lexeme::Atom(_), Some(decoded)) => decoded.as_str(),
            (Lexeme::Atom(s), None) | (Lexeme::Quoted(s), _) => s.as_str(),
            (Lexeme::Special('.'), _) if i > 0 => ".",
            _ => return None,
        };
        let this_decoded = decoded.is_some();
        if t.space_before && !text.is_empty() && !(previous_decoded && this_decoded) {
            text.push(' ');
        }
        text.push_str(word);
        previous_decoded = this_decoded;
    }
    Some(text)
}

/// The `Atom` at `tokens[i]` decoded as an RFC 2047 encoded-word, or `None` (literal) unless (1)
/// it is exactly one encoded-word ([`crate::encoded_word::decode_encoded_word_exactly`], §2), and
/// (2) it is separated from both neighbours by linear whitespace (§5(3)): it is first or carries
/// `space_before`, and it is last or the next token carries `space_before`. So
/// `=?UTF-8?Q?J?=.=?UTF-8?Q?S?=` and `"x"=?UTF-8?Q?y?=` stay literal. `None` for any non-`Atom`
/// token.
fn encoded_word_atom(tokens: &[Token], i: usize) -> Option<String> {
    let Lexeme::Atom(s) = &tokens[i].lexeme else {
        return None;
    };
    let separated_before = i == 0 || tokens[i].space_before;
    let separated_after = tokens.get(i + 1).is_none_or(|next| next.space_before);
    if !(separated_before && separated_after) {
        return None;
    }
    crate::encoded_word::decode_encoded_word_exactly(s)
}

/// §3.4.1 `addr-spec`: `(local-part, canonical addr-spec, ASCII-lowercased domain)`. `local` is
/// the same text [`ParsedMailbox::local_part`] surfaces. The boundary is the token stream's own
/// `Special('@')` (there is exactly one: a domain-literal's own `@`, if any, was already
/// consumed into one `Lexeme::DomainLiteral` token by [`lex`]/[`domain_literal`]), never a
/// delimiter search over the composed text.
fn addr_spec(tokens: &[Token]) -> Option<(String, String, String)> {
    let at: Vec<usize> = (0..tokens.len())
        .filter(|&i| tokens[i].lexeme == Lexeme::Special('@'))
        .collect();
    let [at] = at.as_slice() else {
        return None;
    };
    let local = dotted(&tokens[..*at], true)?;
    // A domain-literal has two spellings here: the resolved text (`[` + dtext + `]`, quoted-pairs
    // already resolved by `domain_literal`), from which the domain key is derived, and the
    // canonical spelling (`rebracket`), which re-escapes what `domain_literal` would otherwise
    // mis-lex so the stored `from_addr` reparses to the same literal. A dot-atom domain has one
    // spelling for both.
    let (domain_resolved, domain_canonical) = match &tokens[at + 1..] {
        [Token { lexeme: Lexeme::DomainLiteral(dtext), .. }] => (format!("[{dtext}]"), rebracket(dtext)),
        rest => {
            let domain = dotted(rest, false)?;
            (domain.clone(), domain)
        }
    };
    // The domain key is NFC-normalized before lowercasing: `café.example` in NFC (one
    // precomposed U+00E9) and in NFD (`e` + combining U+0301) are the same domain to a human and
    // must group under the same key, and lowercasing alone does not merge them. The addr-spec
    // text itself (`domain`, in `{local}@{domain}`) stays byte-identical to what the grammar
    // parsed; only the key used for display grouping (the summary's `sender_domains`,
    // `from_domain`) is normalized.
    let key = icu_normalizer::ComposingNormalizer::new_nfc().normalize(&domain_resolved).to_ascii_lowercase();
    Some((local.clone(), format!("{local}@{domain_canonical}"), key))
}

/// `word *("." word)`: a dot-atom (or `obs-local-part` / `obs-domain`, whose CFWS between words
/// is already gone). A local-part word may be a quoted-string (re-quoted canonically); a
/// domain's may not. Every atom must be one an address can show.
fn dotted(tokens: &[Token], local_part: bool) -> Option<String> {
    let mut text = String::new();
    let mut want_word = true;
    for t in tokens {
        match (&t.lexeme, want_word) {
            (Lexeme::Atom(s), true) if s.chars().all(is_shown_in_an_address) => {
                text.push_str(s);
                want_word = false;
            }
            // A quoted HTAB is content (§3.2.4's quoted-string grammar admits FWS between
            // qcontent, and HTAB is WSP), like the literal space already admitted here; it is
            // not something `is_shown_in_an_address` gets to refuse.
            (Lexeme::Quoted(s), true) if local_part && s.chars().all(|c| c == ' ' || c == '\t' || is_shown_in_an_address(c)) => {
                text.push_str(&requote(s));
                want_word = false;
            }
            (Lexeme::Special('.'), false) => {
                text.push('.');
                want_word = true;
            }
            _ => return None,
        }
    }
    (!want_word).then_some(text)
}

/// A domain-literal's canonical spelling, [`requote`]'s sibling: `[` + the resolved dtext with
/// `[`, `]` and `\` escaped as a quoted-pair + `]`. These are exactly the three characters
/// [`domain_literal`] would otherwise mis-lex (`[` refuses, `]` closes, `\` opens a
/// quoted-pair); FWS never survives into dtext, and every other shown character reads back as
/// itself. Spelling the literal as `[` + dtext + `]` over the resolved text would store `a@[\]x]`
/// as `a@[]x]` (which does not lex, making the header row's `from_status` `malformed` for a
/// valid sender) and `a@[\\x]` as `a@[\x]` (which reparses to a different literal, `[x]`).
///
/// The canonical form generates `obs-dtext` (a quoted-pair inside a domain-literal, RFC 5322
/// §4.4), which §4 says a generator must not produce. `from_addr` is a stored key/display string
/// that this module's own parser reads back (`sender_facts`), never a header Photon generates or
/// sends; the reparse identity is the property it needs, and only `obs-dtext` can spell these
/// literals at all.
fn rebracket(dtext: &str) -> String {
    let mut literal = String::with_capacity(dtext.len() + 2);
    literal.push('[');
    for c in dtext.chars() {
        if c == '[' || c == ']' || c == '\\' {
            literal.push('\\');
        }
        literal.push(c);
    }
    literal.push(']');
    literal
}

/// A quoted-string's canonical spelling: `"` + the content with `\` and `"` escaped + `"`.
fn requote(content: &str) -> String {
    let mut quoted = String::with_capacity(content.len() + 2);
    quoted.push('"');
    for c in content.chars() {
        if c == '\\' || c == '"' {
            quoted.push('\\');
        }
        quoted.push(c);
    }
    quoted.push('"');
    quoted
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(display: &str, local: &str, addr: &str, domain: &str) -> ParsedMailbox {
        ParsedMailbox {
            status: SenderStatus::Ok,
            display_name: display.to_string(),
            local_part: local.to_string(),
            from_addr: addr.to_string(),
            domain: Some(domain.to_string()),
        }
    }

    fn malformed(raw: &str) -> ParsedMailbox {
        ParsedMailbox {
            status: SenderStatus::Malformed,
            display_name: String::new(),
            local_part: String::new(),
            from_addr: raw.to_string(),
            domain: None,
        }
    }

    fn unsupported(raw: &str) -> ParsedMailbox {
        ParsedMailbox {
            status: SenderStatus::Unsupported,
            display_name: String::new(),
            local_part: String::new(),
            from_addr: raw.to_string(),
            domain: None,
        }
    }

    /// The five witnesses, at the parser.
    #[test]
    fn the_five_witnesses() {
        assert_eq!(
            parse_mailbox("Notice <real@evil.example> (routing note <billing@trusted.example>)"),
            ok("Notice", "real", "real@evil.example", "evil.example"),
            "(1) the comment's angle-addr is CFWS, never the address"
        );
        assert_eq!(
            parse_mailbox("\"<fake@x.example>\" <real@y.example>"),
            ok("<fake@x.example>", "real", "real@y.example", "y.example"),
            "(2) the quoted-string's fake address is display text"
        );
        let empty = parse_mailbox("");
        assert_eq!(empty.status, SenderStatus::Unavailable, "(3) an empty From");
        assert_eq!((empty.addr(), empty.domain.as_deref(), empty.from_addr.as_str()), (None, None, ""));
        assert_eq!(parse_mailbox("real@evil.example"), ok("", "real", "real@evil.example", "evil.example"), "(4) a bare address");
        for raw in ["<a@x.example> <b@y.example>", "Name <unterminated", "Name <a@x.example", "Name a@x.example>"] {
            assert_eq!(parse_mailbox(raw), malformed(raw), "(5) {raw}");
        }
    }

    #[test]
    fn comments_nest_and_carry_quoted_pairs() {
        let bs = char::from(92u8);
        assert_eq!(parse_mailbox("(a (b <x@y.example>) c) N <r@e.example>"), ok("N", "r", "r@e.example", "e.example"));
        assert_eq!(parse_mailbox("(a (b) <billing@trusted.example>) <real@evil.example>"), ok("", "real", "real@evil.example", "evil.example"));
        assert_eq!(parse_mailbox(&format!("(a {bs}) <x@y.example>) N <r@e.example>")), ok("N", "r", "r@e.example", "e.example"));
        assert_eq!(parse_mailbox("real@evil.example (note <billing@trusted.example>)"), ok("", "real", "real@evil.example", "evil.example"));
        assert_eq!(parse_mailbox("Notice (x) <real@evil.example>"), ok("Notice", "real", "real@evil.example", "evil.example"));
        for raw in ["(unterminated <a@x.example>", "(a (b) <c@d.example>", "N <r@e.example> )"] {
            assert_eq!(parse_mailbox(raw).status, SenderStatus::Malformed, "{raw}");
        }
    }

    #[test]
    fn quoted_strings_are_one_word_with_their_quoted_pairs_resolved() {
        let bs = char::from(92u8);
        let raw = format!("\"a{bs}\" <x@y.example>\" <r@e.example>");
        assert_eq!(parse_mailbox(&raw), ok("a\" <x@y.example>", "r", "r@e.example", "e.example"));
        assert_eq!(parse_mailbox("\"q (\" <real@evil.example>"), ok("q (", "real", "real@evil.example", "evil.example"));
        assert_eq!(parse_mailbox("\"unterminated <a@x.example>").status, SenderStatus::Malformed);
        assert_eq!(parse_mailbox("\"a@b\"@c.example"), ok("", "\"a@b\"", "\"a@b\"@c.example", "c.example"), "a quoted local-part");
    }

    #[test]
    fn a_value_that_is_not_exactly_one_mailbox_is_malformed_and_keeps_its_raw_text() {
        for raw in [
            "Smith, John <j@x.example>",
            "Name <a@b@c>",
            "Name <foo>",
            "Notice <>",
            "Notice real@evil.example",
            "Notice <real@evil.example> trailing",
            "<a@x.example>>",
            "noreply@github.com <noreply@github.com>",
            "(only a comment)",
            "=?UTF-8?Q?trusted=40example.com?=",
            "a@.example",
            "a.@x.example",
            "a@x..example",
        ] {
            assert_eq!(parse_mailbox(raw), malformed(raw), "{raw}");
        }
    }

    /// (the complement rule): parsed, but not exactly one mailbox —
    /// a group (RFC 6854 §2/§4, any member count) or a >1 mailbox-list — is `Unsupported`, never
    /// `Malformed`. Moved here from the malformed list above (CLASSIFICATION
    /// S3r3-1): the OLD rule called every one of these `Malformed`.
    #[test]
    fn an_address_list_that_is_not_exactly_one_mailbox_is_unsupported() {
        for raw in [
            "a@x.example, b@y.example",
            "Undisclosed:;",
            "G: a@x.example;",
            "Authors:user@target.example;",
            "undisclosed-recipients:;",
            // RFC 6854 §4 examples — groups legalized in `From`/`Sender`.
            "Automated System:;",
            "Nightly Monitor Robot:;",
            "Managing Partners:ben@example.com,carol@example.com;",
        ] {
            assert_eq!(parse_mailbox(raw), unsupported(raw), "{raw}");
        }
    }

    /// §4.4 `obs-route`: `*1obs-domain-list ":"` inside an angle-addr is parsed and IGNORED — the
    /// mailbox is the addr-spec after it (RFC 5322 §4 obliges a conformant receiver to
    /// accept obsolete syntax; §4.4 says the route is ignored). Moved here from the malformed list
    /// above: the OLD rule refused every `:` inside an angle-addr.
    #[test]
    fn obs_route_inside_an_angle_addr_is_parsed_and_ignored() {
        assert_eq!(parse_mailbox("Name <@route:a@b.example>"), ok("Name", "a", "a@b.example", "b.example"));
        assert_eq!(
            parse_mailbox("<@route1.example,@route2.example:user@target.example>"),
            ok("", "user", "user@target.example", "target.example")
        );
        assert_eq!(
            parse_mailbox("Mary Smith <@node.test:mary@example.net>"),
            ok("Mary Smith", "mary", "mary@example.net", "example.net"),
            "RFC 5322 Appendix A.6.1"
        );
        // The route is IGNORED, not skipped blindly: an entry that is not `@domain` is not a
        // route, and the whole mailbox refuses rather than guessing which `:` was the route's.
        for raw in ["Name <route:a@b.example>", "Name <@:a@b.example>"] {
            assert_eq!(parse_mailbox(raw).status, SenderStatus::Malformed, "{raw}");
        }
    }

    /// §2.2.3 FWS inside a quoted-string: `CRLF` folds away ONLY when a WSP run follows it — a
    /// bare CR/LF is never FWS, so it is never silently dropped (the OLD rule merged
    /// `"a\r\nb"` into `"ab"`, an `Ok` sender the review then called well-formed). A quoted HTAB
    /// is content, not a fold, and never disqualifies the address.
    #[test]
    fn quoted_string_folding_is_crlf_then_wsp_only() {
        assert_eq!(parse_mailbox("\"a\r\nb\"@evil.example").status, SenderStatus::Malformed, "a bare CR/LF not followed by WSP is not FWS");
        assert_eq!(parse_mailbox("\"a\r\"@evil.example").status, SenderStatus::Malformed, "a lone CR is not FWS");
        assert_eq!(parse_mailbox("\"a\n\"@evil.example").status, SenderStatus::Malformed, "a lone LF is not FWS");
        assert_eq!(parse_mailbox("\"a\tb\"@x.example"), ok("", "\"a\tb\"", "\"a\tb\"@x.example", "x.example"), "a quoted HTAB is content, not a fold");
        assert_eq!(parse_mailbox("\"a\r\n b\"@x.example"), ok("", "\"a b\"", "\"a b\"@x.example", "x.example"), "CRLF+WSP folds away; the WSP run is kept as content");
    }

    /// The transport's typed §3.6 cardinality signal, ahead of the §3.4 grammar (/ CLI
    /// R-none: two `From` fields, first-wins, was `Ok`). `Multiple` re-parses to the SAME answer
    /// (module doc's "One parser, two callers" invariant) through its stored marker text.
    #[test]
    fn raw_from_counts_from_fields_before_the_grammar_runs() {
        assert_eq!(parse_from(RawFrom::Absent).status, SenderStatus::Unavailable);
        assert_eq!(parse_from(RawFrom::Single("real@evil.example".to_string())), ok("", "real", "real@evil.example", "evil.example"));
        let two = parse_from(RawFrom::Multiple(2));
        assert_eq!((two.status, two.domain.as_ref()), (SenderStatus::Malformed, None));
        assert_eq!(sender_facts(&two.from_addr), (SenderStatus::Malformed, None), "the marker text re-parses to the same answer");
    }

    #[test]
    fn the_display_name_is_the_phrase_with_obs_phrase_dots_and_one_space_per_cfws_run() {
        assert_eq!(parse_mailbox("J. Smith <j@x.example>"), ok("J. Smith", "j", "j@x.example", "x.example"));
        assert_eq!(parse_mailbox("  Alice   (x)  Q  <alice@example.com>  "), ok("Alice Q", "alice", "alice@example.com", "example.com"));
        assert_eq!(parse_mailbox("\"Alice\" <alice@example.com>"), ok("Alice", "alice", "alice@example.com", "example.com"));
        // the contract this line pinned MOVED — an encoded-word atom
        // now decodes HERE, in `phrase()`, with its lexical provenance (the transports used to
        // decode the finished name and no longer do); the quoted form stays literal.
        assert_eq!(
            parse_mailbox("=?UTF-8?B?44GT44KT44Gr44Gh44Gv?= <sender@example.com>"),
            ok("こんにちは", "sender", "sender@example.com", "example.com"),
            "an encoded-word ATOM decodes in the parser, once"
        );
        assert_eq!(
            parse_mailbox("\"=?UTF-8?B?44GT44KT44Gr44Gh44Gv?=\" <sender@example.com>"),
            ok("=?UTF-8?B?44GT44KT44Gr44Gh44Gv?=", "sender", "sender@example.com", "example.com"),
            "a QUOTED encoded-word is literal (RFC 2047 §5(3))"
        );
        assert_eq!(parse_mailbox("こんにちは <sender@example.com>"), ok("こんにちは", "sender", "sender@example.com", "example.com"));
        assert_eq!(parse_mailbox("<only@angle.example>"), ok("", "only", "only@angle.example", "angle.example"));
    }

    #[test]
    fn the_domain_is_lowercased_and_a_domain_literal_is_kept() {
        assert_eq!(parse_mailbox("N <a@EVIL.Example>"), ok("N", "a", "a@EVIL.Example", "evil.example"));
        assert_eq!(parse_mailbox("x@[1.2.3.4]"), ok("", "x", "x@[1.2.3.4]", "[1.2.3.4]"));
        assert_eq!(parse_mailbox("x@[ 1.2.3.4 ]"), ok("", "x", "x@[1.2.3.4]", "[1.2.3.4]"));
        assert_eq!(parse_mailbox("a . b (c) @ x . example"), ok("", "a.b", "a.b@x.example", "x.example"), "obs-local-part / obs-domain CFWS");
    }

    /// An address a human cannot SEE faithfully is not an address: a zero-width space, a bidi
    /// override, a control or a non-ASCII space inside the addr-spec is `Malformed` — never a domain
    /// that renders as another one.
    #[test]
    fn an_address_carrying_an_invisible_codepoint_is_malformed() {
        for invisible in ['\u{200B}', '\u{202E}', '\u{00A0}', '\u{2028}', '\u{0007}', '\u{FEFF}'] {
            for raw in [format!("N <a@pay{invisible}pal.example>"), format!("N <a{invisible}b@x.example>"), format!("a@x.example{invisible}")] {
                assert_eq!(parse_mailbox(&raw).status, SenderStatus::Malformed, "{raw:?}");
            }
        }
        assert_eq!(
            parse_mailbox("A\u{200D}B <a@x.example>").status,
            SenderStatus::Ok,
            "the DISPLAY name may carry one (it is normalized as display text)"
        );
    }

    /// `is_shown_in_an_address` widened to Unicode
    /// `Default_Ignorable_Code_Point` — codepoints the OLD Cf/control/whitespace check let
    /// through, that still render as NOTHING (UTS v18.0.0 §4 skeleton step 2, Table 1:
    /// RESTRICTED), so `pay<invisible>pal.example` renders exactly as `paypal.example`.
    #[test]
    fn an_address_carrying_a_default_ignorable_codepoint_is_malformed() {
        for invisible in ['\u{FE0F}', '\u{034F}', '\u{180B}', '\u{E0100}', '\u{17B4}', '\u{115F}', '\u{3164}', '\u{FFA0}'] {
            let raw = format!("PayPal <service@pay{invisible}pal.example>");
            assert_eq!(parse_mailbox(&raw).status, SenderStatus::Malformed, "{raw:?}");
        }
    }

    /// the domain KEY is NFC-normalized — `café.example` in
    /// NFC (one precomposed U+00E9) and in NFD (`e` + a combining U+0301) are the SAME domain to a
    /// human and must key identically; a combining diacritic renders visibly, so it is not refused
    /// by `is_shown_in_an_address` — only the KEY merges, the addr-spec TEXT stays untouched.
    #[test]
    fn the_domain_key_is_nfc_normalized_so_nfc_and_nfd_spellings_key_identically() {
        let nfc = "caf\u{00E9}.example";
        let nfd = "cafe\u{0301}.example";
        let a = parse_mailbox(&format!("a@{nfc}"));
        let b = parse_mailbox(&format!("a@{nfd}"));
        assert_eq!(a.status, SenderStatus::Ok);
        assert_eq!(b.status, SenderStatus::Ok);
        assert_eq!(a.domain, b.domain, "NFC and NFD spellings key identically");
        assert_eq!(a.domain.as_deref(), Some(nfc), "the key is the NFC form");
        assert_ne!(a.from_addr, b.from_addr, "the addr-spec TEXT itself is untouched — only the key merges");
    }

    #[test]
    fn empty_and_fws_only_values_are_unavailable_and_nothing_else_is() {
        for raw in ["", " ", "\t", "\r\n "] {
            assert_eq!(parse_mailbox(raw).status, SenderStatus::Unavailable, "{raw:?}");
        }
        assert_eq!(parse_mailbox("\u{00A0}").status, SenderStatus::Malformed, "a non-ASCII space is not FWS");
    }

    /// The module doc's "One parser, two callers": the header row stores `from_addr`, its write door
    /// derives status + domain from it through [`sender_facts`], and the answer is the transport's.
    #[test]
    fn the_stored_from_addr_re_parses_to_the_transports_answer() {
        let bs = char::from(92u8);
        let corpus = [
            "Notice <real@evil.example> (routing note <billing@trusted.example>)".to_string(),
            "\"<fake@x.example>\" <real@y.example>".to_string(),
            String::new(),
            "   ".to_string(),
            "real@evil.example".to_string(),
            "<a@x.example> <b@y.example>".to_string(),
            "Name <unterminated".to_string(),
            "\"a@b\"@c.example".to_string(),
            format!("N <\"a{bs}\"b\"@x.example>"),
            "x@[ 1.2.3.4 ]".to_string(),
            "a . b (c) @ X . Example".to_string(),
            "\u{00A0}real@evil.example".to_string(),
            "  (only a comment)  ".to_string(),
            "a@x.example, b@y.example".to_string(),
        ];
        for raw in &corpus {
            let parsed = parse_mailbox(raw);
            assert_eq!(sender_facts(&parsed.from_addr), (parsed.status, parsed.domain.clone()), "{raw:?}");
        }
    }

    #[test]
    fn the_status_tokens_are_the_closed_set() {
        assert_eq!(SenderStatus::ALL.iter().map(|s| s.as_token()).collect::<Vec<_>>(), vec!["ok", "unavailable", "malformed", "unsupported"]);
        for s in SenderStatus::ALL {
            assert_eq!(SenderStatus::from_token(s.as_token()), Some(*s));
        }
        assert_eq!(SenderStatus::from_token("OK"), None);
    }

    // ===========================================================================================
    // (item 5 — the parser's FOURTH appearance, closed one level up): a
    // GRAMMAR-DERIVED witness. Every input below is BUILT from named shape parameters (a member
    // count, a null-member position, a route shape, a group/no-group choice) — never typed out as
    // a literal — and its expected classification is COMPUTED from the SAME rule `classify` and
    // `address_list` implement (§4.4 null members stripped first; any group ⇒ Unsupported; the
    // remaining non-null mailbox count decides Ok/Unsupported/Malformed) — never a second,
    // hand-curated table of expected answers sitting beside a hand-curated table of inputs (the
    // exact shape of the blind spot: a hand list cannot see its own gaps).
    //
    // SCOPE (stated honestly): this generator covers list arity × null-member position × route
    // shape × group-vs-mailbox-list, and a small CR/LF-placement generator for the invalid side.
    // It does NOT additionally cross those with the CRLF+WSP folding dimension (folding is
    // covered by directed cases above and in `mailparser_oracle.rs` instead) — a full cross would
    // multiply every cell below by two for a dimension the RED witnesses do not exercise.
    // ===========================================================================================
    mod generated {
        use super::*;

        /// One real (non-null) member's shape, numbered so every generated member is textually
        /// distinct.
        #[derive(Clone, Copy, Debug)]
        enum Member {
            Bare,
            ObsRouteDomain,
            ObsRouteDomainLiteral,
        }

        fn member_text(shape: Member, n: usize) -> String {
            match shape {
                Member::Bare => format!("m{n}@x{n}.example"),
                Member::ObsRouteDomain => format!("<@route{n}.example:m{n}@x{n}.example>"),
                Member::ObsRouteDomainLiteral => format!("<@[192.0.{n}.9]:m{n}@x{n}.example>"),
            }
        }

        #[derive(Clone, Copy, Debug, PartialEq)]
        enum NullPosition {
            None,
            Leading,
            Trailing,
            Consecutive,
            LeadingAndTrailing,
        }

        /// `count` real members (numbered, `Bare` unless `first_shape` names the first member's
        /// shape), joined by `,`, with a null member (empty text) spliced in at every position
        /// `nulls` names. `None` when the resulting text would be empty (nothing to parse).
        fn build_list(count: usize, nulls: NullPosition, first_shape: Option<Member>) -> Option<String> {
            let mut members: Vec<String> = (0..count)
                .map(|i| member_text(if i == 0 { first_shape.unwrap_or(Member::Bare) } else { Member::Bare }, i))
                .collect();
            match nulls {
                NullPosition::None => {}
                NullPosition::Leading => members.insert(0, String::new()),
                NullPosition::Trailing => members.push(String::new()),
                NullPosition::Consecutive => {
                    members.insert(0, String::new());
                    members.insert(1, String::new());
                }
                NullPosition::LeadingAndTrailing => {
                    members.insert(0, String::new());
                    members.push(String::new());
                }
            }
            let raw = members.join(",");
            (!raw.is_empty()).then_some(raw)
        }

        /// §4.4's rule for a bare (non-group) list, computed independently of `parse_mailbox`:
        /// zero real members is not a valid `obs-mbox-list`/`obs-addr-list` at all (they require
        /// at least one mailbox) ⇒ `Malformed`; exactly one ⇒ `Ok`; more than one ⇒ `Unsupported`.
        fn expected_mailbox_list_status(real_member_count: usize) -> SenderStatus {
            match real_member_count {
                0 => SenderStatus::Malformed,
                1 => SenderStatus::Ok,
                _ => SenderStatus::Unsupported,
            }
        }

        #[test]
        fn generated_mailbox_list_shapes_classify_by_count_of_real_members_after_stripping_nulls() {
            let mut generated = 0usize;
            for count in [0usize, 1, 2] {
                for nulls in [
                    NullPosition::None,
                    NullPosition::Leading,
                    NullPosition::Trailing,
                    NullPosition::Consecutive,
                    NullPosition::LeadingAndTrailing,
                ] {
                    for route in [None, Some(Member::ObsRouteDomain), Some(Member::ObsRouteDomainLiteral)] {
                        // A route wraps the FIRST real member in an angle-addr; with zero real
                        // members there is nothing to wrap.
                        if route.is_some() && count == 0 {
                            continue;
                        }
                        let Some(raw) = build_list(count, nulls, route) else { continue };
                        let expected = expected_mailbox_list_status(count);
                        let got = parse_mailbox(&raw).status;
                        assert_eq!(got, expected, "count={count} nulls={nulls:?} route={route:?} raw={raw:?}");
                        generated += 1;
                    }
                }
            }
            assert!(generated >= 30, "the generator produced at least 30 mailbox-list instances, got {generated}");
        }

        /// Any GROUP present, at any member count including all-null, is `Unsupported` — computed
        /// as a constant rule (never `Ok`, never `Malformed`, whatever is inside the group),
        /// crossed with the same member-count × null-position shapes.
        #[test]
        fn generated_group_shapes_are_always_unsupported_whatever_is_inside() {
            let mut generated = 0usize;
            for count in [0usize, 1, 2] {
                for nulls in [
                    NullPosition::None,
                    NullPosition::Leading,
                    NullPosition::Trailing,
                    NullPosition::Consecutive,
                ] {
                    let inner = build_list(count, nulls, None).unwrap_or_default();
                    let raw = format!("G:{inner};");
                    let got = parse_mailbox(&raw).status;
                    assert_eq!(got, SenderStatus::Unsupported, "count={count} nulls={nulls:?} raw={raw:?}");
                    generated += 1;
                }
            }
            assert!(generated >= 10, "the generator produced at least 10 group instances, got {generated}");
        }

        /// An empty group display-name (`phrase = 1*word` violated) is `Malformed` regardless of
        /// what the group's own member list holds.
        #[test]
        fn generated_empty_group_display_name_is_always_malformed() {
            for count in [0usize, 1, 2] {
                let inner = build_list(count, NullPosition::None, None).unwrap_or_default();
                let raw = format!(":{inner};");
                assert_eq!(parse_mailbox(&raw).status, SenderStatus::Malformed, "count={count} raw={raw:?}");
            }
        }

        /// A single mailbox's route shape never changes its classification: bare, an obs-route
        /// naming a dot-atom domain, and an obs-route naming a domain-literal are all exactly one
        /// mailbox, parsed and ignored the same way — always `Ok`.
        #[test]
        fn generated_route_shape_never_changes_a_single_mailboxs_classification() {
            for shape in [Member::Bare, Member::ObsRouteDomain, Member::ObsRouteDomainLiteral] {
                let raw = member_text(shape, 0);
                assert_eq!(parse_mailbox(&raw).status, SenderStatus::Ok, "shape={shape:?} raw={raw:?}");
            }
        }

        /// The invalid side (§2.2.3): a bare CR or LF — never part of a legal CRLF+WSP fold — is
        /// `Malformed` at every placement a header value can put one: the very start, inside a
        /// dot-atom run, inside a quoted-string, and the very end.
        #[test]
        fn generated_bare_cr_lf_placements_are_all_malformed() {
            let bare = ['\r', '\n'];
            let placements: [fn(char) -> String; 4] = [
                |c| format!("{c}real@evil.example"),
                |c| format!("alice{c}bob@one.example"),
                |c| format!("\"alice{c}bob\"@one.example"),
                |c| format!("alice@one.example{c}"),
            ];
            let mut generated = 0usize;
            for c in bare {
                for placement in placements {
                    let raw = placement(c);
                    assert_eq!(parse_mailbox(&raw).status, SenderStatus::Malformed, "raw={raw:?}");
                    generated += 1;
                }
            }
            assert_eq!(generated, 8);
        }

        /// (item (d)): the QUOTED-PAIR position × escaped-char cross —
        /// RFC 5322 §4.4 `obs-dtext`/§3.2.4 `quoted-pair` inside a domain-literal, a quoted local
        /// part, or a comment — with every expected status COMPUTED from the same predicate the
        /// parser itself gates on (`is_shown_in_an_address`, the strictness list's item 2 in the
        /// module doc), never hand-typed per row.
        #[derive(Clone, Copy, Debug)]
        enum QuotedPairPosition {
            /// `"a\Xb"@x.example` — a quoted-string LOCAL PART; `dotted`'s own local-part guard
            /// admits a quoted SPACE/HTAB in addition to `is_shown_in_an_address`.
            LocalPartQuotedString,
            /// `(a\Xb) N <r@e.example>` — a COMMENT; `skip_comment` consumes the escaped char
            /// unconditionally and the whole comment is dropped, so the escaped char can never
            /// disqualify the address.
            Comment,
            /// `a@[\X]` — a DOMAIN LITERAL; `domain_literal` gates the escaped char on
            /// `is_shown_in_an_address` with NO space/tab exception (
            /// build note (a) — read literally: unlike the local-part quoted-string, an escaped
            /// WSP here is NOT content, so it refuses same as a control character).
            DomainLiteral,
        }

        fn quoted_pair_raw(position: QuotedPairPosition, c: char) -> String {
            match position {
                QuotedPairPosition::LocalPartQuotedString => format!("\"a\\{c}b\"@x.example"),
                QuotedPairPosition::Comment => format!("(a\\{c}b) N <r@e.example>"),
                QuotedPairPosition::DomainLiteral => format!("a@[\\{c}]"),
            }
        }

        /// The strictness list's item 2 (module doc), applied per position — never a hand-typed
        /// Ok/Malformed table.
        fn expected_quoted_pair_status(position: QuotedPairPosition, c: char) -> SenderStatus {
            let shown = match position {
                QuotedPairPosition::LocalPartQuotedString => {
                    c == ' ' || c == '\t' || is_shown_in_an_address(c)
                }
                QuotedPairPosition::Comment => true,
                QuotedPairPosition::DomainLiteral => is_shown_in_an_address(c),
            };
            if shown {
                SenderStatus::Ok
            } else {
                SenderStatus::Malformed
            }
        }

        /// The escaped-char set the quoted-pair cross runs over: a VCHAR (`.`), a WSP (` `), NUL,
        /// and an obs-NO-WS-CTL (`\x01`) — the four shapes named in the own build note —
        /// plus the four characters a canonical spelling must RE-ESCAPE
        /// to reparse the same: `[`, `]` and `\` inside a domain-literal, `\` and `"` inside a
        /// quoted local part.
        const ESCAPED_CHARS: [char; 8] = ['.', ' ', '\u{0}', '\u{1}', '[', ']', '\\', '"'];

        const QUOTED_PAIR_POSITIONS: [QuotedPairPosition; 3] = [
            QuotedPairPosition::LocalPartQuotedString,
            QuotedPairPosition::Comment,
            QuotedPairPosition::DomainLiteral,
        ];

        #[test]
        fn generated_quoted_pair_position_and_escaped_char_classify_by_the_strictness_list() {
            let mut generated = 0usize;
            for position in QUOTED_PAIR_POSITIONS {
                for c in ESCAPED_CHARS {
                    let raw = quoted_pair_raw(position, c);
                    let expected = expected_quoted_pair_status(position, c);
                    let got = parse_mailbox(&raw).status;
                    assert_eq!(got, expected, "position={position:?} c={c:?} raw={raw:?}");
                    generated += 1;
                }
            }
            assert_eq!(generated, 24, "3 positions x 8 escaped chars");
        }

        /// every raw value this module's generated corpus produces
        /// (every generator in this module, the quoted-pair cross over [`ESCAPED_CHARS`]
        /// included).
        fn generated_corpus() -> Vec<String> {
            let mut raws: Vec<String> = Vec::new();
            for count in [0usize, 1, 2] {
                for nulls in [
                    NullPosition::None,
                    NullPosition::Leading,
                    NullPosition::Trailing,
                    NullPosition::Consecutive,
                    NullPosition::LeadingAndTrailing,
                ] {
                    for route in [None, Some(Member::ObsRouteDomain), Some(Member::ObsRouteDomainLiteral)] {
                        if route.is_some() && count == 0 {
                            continue;
                        }
                        if let Some(raw) = build_list(count, nulls, route) {
                            raws.push(format!("G:{raw};"));
                            raws.push(raw);
                        }
                    }
                }
            }
            for position in QUOTED_PAIR_POSITIONS {
                for c in ESCAPED_CHARS {
                    raws.push(quoted_pair_raw(position, c));
                }
            }
            let mut n = 0usize;
            for display in ["", "Name", "\"Quoted Name\"", "Name (comment)"] {
                for shape in [Member::Bare, Member::ObsRouteDomain, Member::ObsRouteDomainLiteral] {
                    raws.push(wrap_with_display(display, shape, n));
                    n += 1;
                }
            }
            raws
        }

        /// PARSE → CANONICAL → REPARSE is the identity for every `Ok`
        /// row of the generated corpus — the canonical `from_addr` the header row stores reparses
        /// (`sender_facts`, the row's one write door's derivation) to the SAME status, the SAME
        /// canonical address and the SAME domain key. Pre-fold, a domain-literal's canonical form
        /// was `[` + the RESOLVED dtext + `]`, so `a@[\]]` stored `a@[]]` (which does not lex — the
        /// row became `malformed` for a valid sender) and `a@[\\]` stored `a@[\]` (which reparses
        /// to a different literal).
        #[test]
        fn parse_canonical_reparse_is_the_identity_for_every_ok_row_of_the_generated_corpus() {
            let mut checked = 0usize;
            let mut literals = 0usize;
            for raw in generated_corpus() {
                let first = parse_mailbox(&raw);
                if first.status != SenderStatus::Ok {
                    continue;
                }
                let again = parse_mailbox(&first.from_addr);
                assert_eq!(again.status, SenderStatus::Ok, "raw={raw:?} canonical={:?}", first.from_addr);
                assert_eq!(again.from_addr, first.from_addr, "raw={raw:?}: the canonical address is a fixed point");
                assert_eq!(again.domain, first.domain, "raw={raw:?}: the domain key survives the round trip");
                assert_eq!(
                    sender_facts(&first.from_addr),
                    (first.status, first.domain.clone()),
                    "raw={raw:?}: the stored text derives the parsed facts"
                );
                checked += 1;
                if first.domain.as_deref().is_some_and(|d| d.starts_with('[')) {
                    literals += 1;
                }
            }
            assert!(checked >= 40, "expected at least 40 Ok rows, got {checked}");
            // `.`, `[`, `]`, `\` and `"` escaped in a domain-literal are the five shown ones.
            assert!(literals >= 5, "the domain-literal rows are in the corpus: {literals}");
        }

        /// (item (d)): DISPLAY-NAME shape crossed with the existing
        /// member (route) shapes — neither dimension changes a single mailbox's classification:
        /// always `Ok`.
        fn wrap_with_display(display: &str, shape: Member, n: usize) -> String {
            let body = member_text(shape, n);
            if display.is_empty() {
                return body;
            }
            let angled = if body.starts_with('<') { body } else { format!("<{body}>") };
            format!("{display} {angled}")
        }

        #[test]
        fn generated_display_name_shape_never_changes_a_single_mailboxs_classification() {
            let display_shapes = ["", "Name", "\"Quoted Name\"", "Name (comment)"];
            let member_shapes = [Member::Bare, Member::ObsRouteDomain, Member::ObsRouteDomainLiteral];
            let mut generated = 0usize;
            for display in display_shapes {
                for shape in member_shapes {
                    let raw = wrap_with_display(display, shape, generated);
                    assert_eq!(
                        parse_mailbox(&raw).status,
                        SenderStatus::Ok,
                        "display={display:?} shape={shape:?} raw={raw:?}"
                    );
                    generated += 1;
                }
            }
            assert_eq!(generated, 12, "4 display shapes x 3 member route shapes");
        }

        /// the INVERSE check — for every `Ok` row this module's own
        /// generated corpus (every generator above) produces, `local_part` + `"@"` + `domain`
        /// reconstructs `from_addr` exactly. Never derived by splitting `from_addr` (the property
        /// under test IS that no split is needed): `local_part` and `domain` both come straight
        /// off [`ParsedMailbox`], built at parse time from the SAME tokens [`addr_spec`] builds
        /// `from_addr` from.
        ///
        /// this runs over the escaped-char set, NOT the widened
        /// [`ESCAPED_CHARS`] — for a domain-literal whose resolved dtext holds `[`, `]` or `\`,
        /// `domain` is the RESOLVED key while `from_addr` spells the literal re-escaped
        /// ([`rebracket`]), so this reconstruction differs by construction there. The round trip
        /// that matters for those rows (the stored text reparses to the same facts) is
        /// `parse_canonical_reparse_is_the_identity_for_every_ok_row_of_the_generated_corpus`.
        #[test]
        fn local_part_plus_at_plus_domain_reconstructs_from_addr_for_every_ok_row_of_the_generated_corpus() {
            let mut raws: Vec<String> = Vec::new();
            for count in [0usize, 1, 2] {
                for nulls in [
                    NullPosition::None,
                    NullPosition::Leading,
                    NullPosition::Trailing,
                    NullPosition::Consecutive,
                    NullPosition::LeadingAndTrailing,
                ] {
                    for route in [None, Some(Member::ObsRouteDomain), Some(Member::ObsRouteDomainLiteral)] {
                        if route.is_some() && count == 0 {
                            continue;
                        }
                        if let Some(raw) = build_list(count, nulls, route) {
                            raws.push(raw);
                        }
                    }
                }
            }
            for position in [
                QuotedPairPosition::LocalPartQuotedString,
                QuotedPairPosition::Comment,
                QuotedPairPosition::DomainLiteral,
            ] {
                for c in ['.', ' ', '\u{0}', '\u{1}'] {
                    raws.push(quoted_pair_raw(position, c));
                }
            }
            let mut n = 0usize;
            for display in ["", "Name", "\"Quoted Name\"", "Name (comment)"] {
                for shape in [Member::Bare, Member::ObsRouteDomain, Member::ObsRouteDomainLiteral] {
                    raws.push(wrap_with_display(display, shape, n));
                    n += 1;
                }
            }

            let mut checked = 0usize;
            for raw in &raws {
                let p = parse_mailbox(raw);
                if p.status != SenderStatus::Ok {
                    continue;
                }
                let domain = p.domain.clone().expect("Ok carries a domain");
                let reconstructed = format!("{}@{}", p.local_part, domain);
                assert_eq!(
                    reconstructed, p.from_addr,
                    "raw={raw:?} local_part={:?} domain={domain:?}",
                    p.local_part
                );
                checked += 1;
            }
            assert!(checked >= 20, "expected to check at least 20 Ok rows from the generated corpus, got {checked}");
        }
    }
}
