//! RFC 2047 `=?charset?B|Q?payload?=` encoded-word decoding, shared by both transports.
//!
//! It was moved here from `aruna-gmail` so `aruna-jmap`, which depends only on `aruna`, can
//! decode a `From` header's display-name half too. Without it `header_summary_from_row`
//! published `=?UTF-8?Q?Legal_Hold?= <a@b.example>` undecoded.
//!
//! `decode_rfc2047`'s body is identical to the function this module was copied from
//! (`crates/aruna-gmail/src/transport.rs`'s `decode_rfc2047`), as are `base64_standard_decode`
//! and the header-variant quoted-printable decoder. The one adaptation is the
//! charset-bytes-to-`String` step: `aruna-gmail` calls `decode_part_bytes`, which returns that
//! crate's own `GmailError`, a type this crate must not depend on. `decode_charset_bytes` here
//! carries the same four-arm charset policy (utf-8/us-ascii strict, latin-1 and windows-1252
//! transcoded, anything else lossy `from_utf8_lossy`) but returns `Result<String, ()>`, like
//! every other private decoder in this module. `aruna-gmail`'s `decode_part_bytes` (message
//! body and attachment decoding, not header words) keeps its own copy of the policy.
//! `base64_decode_with_alphabet` and the windows-1252 high-byte table are likewise private
//! copies rather than a cross-crate reach into `aruna-gmail::transport`.
//!
//! There are two entry points, by what the text is.
//! [`crate::encoded_word::decode_rfc2047`] scans unstructured text (Gmail's `Subject`) for
//! encoded-words anywhere. A `From` display name is a `phrase`, which is structured, and is
//! decoded per word by [`crate::encoded_word::decode_encoded_word_exactly`], called from
//! `crate::mailbox`'s `phrase()` with each word's lexical provenance (RFC 2047 §5(3)). Neither
//! transport runs `decode_rfc2047` over a display name.

/// The 0x80-0x9F block of windows-1252, where it differs from ISO-8859-1 (which puts C1 controls
/// there). Copied from `aruna-gmail`'s own table (see the module doc).
const WINDOWS_1252_HIGH: [char; 32] = [
    '\u{20AC}', '\u{0081}', '\u{201A}', '\u{0192}', '\u{201E}', '\u{2026}', '\u{2020}', '\u{2021}',
    '\u{02C6}', '\u{2030}', '\u{0160}', '\u{2039}', '\u{0152}', '\u{008D}', '\u{017D}', '\u{008F}',
    '\u{0090}', '\u{2018}', '\u{2019}', '\u{201C}', '\u{201D}', '\u{2022}', '\u{2013}', '\u{2014}',
    '\u{02DC}', '\u{2122}', '\u{0161}', '\u{203A}', '\u{0153}', '\u{009D}', '\u{017E}', '\u{0178}',
];

/// Decode one encoded-word's already B/Q-decoded bytes against its declared charset, with the
/// same four-arm policy as `aruna-gmail`'s `decode_part_bytes` (see the module doc for why this
/// is a separate `Result<String, ()>` copy).
fn decode_charset_bytes(bytes: Vec<u8>, charset: Option<&str>) -> Result<String, ()> {
    match charset {
        None | Some("utf-8") | Some("utf8") | Some("us-ascii") | Some("ascii") => {
            String::from_utf8(bytes).map_err(|_| ())
        }
        Some("iso-8859-1") | Some("iso8859-1") | Some("latin1") | Some("latin-1")
        | Some("iso_8859-1") | Some("l1") => Ok(bytes.into_iter().map(char::from).collect()),
        Some("windows-1252") | Some("cp1252") | Some("cp-1252") | Some("windows1252") => Ok(bytes
            .into_iter()
            .map(|b| match b {
                0x80..=0x9F => WINDOWS_1252_HIGH[(b - 0x80) as usize],
                other => char::from(other),
            })
            .collect()),
        Some(_) => Ok(String::from_utf8_lossy(&bytes).into_owned()),
    }
}

/// The shared base64 core both alphabets use: a private copy of `aruna-gmail`'s
/// `base64_decode_with_alphabet` (see the module doc).
fn base64_decode_with_alphabet(input: &str, sextet: fn(u8) -> Result<u8, ()>) -> Result<Vec<u8>, ()> {
    let all = input.as_bytes();
    let mut end = all.len();
    let mut pad = 0usize;
    while end > 0 && all[end - 1] == b'=' && pad < 2 {
        end -= 1;
        pad += 1;
    }
    let bytes = &all[..end];
    if bytes.contains(&b'=') {
        return Err(());
    }
    if pad > 0 && !(bytes.len() + pad).is_multiple_of(4) {
        return Err(());
    }
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4 + 3);
    let mut group = [0u8; 4];
    let mut group_len = 0usize;
    for &b in bytes {
        group[group_len] = sextet(b)?;
        group_len += 1;
        if group_len == 4 {
            out.push((group[0] << 2) | (group[1] >> 4));
            out.push((group[1] << 4) | (group[2] >> 2));
            out.push((group[2] << 6) | group[3]);
            group_len = 0;
        }
    }
    match group_len {
        0 => {}
        1 => return Err(()),
        2 => out.push((group[0] << 2) | (group[1] >> 4)),
        3 => {
            out.push((group[0] << 2) | (group[1] >> 4));
            out.push((group[1] << 4) | (group[2] >> 2));
        }
        _ => unreachable!("group_len is bounded to 0..4 by the loop above"),
    }
    Ok(out)
}

/// Decode RFC 4648 §4 standard base64 (`+`/`/`), the alphabet an `=?charset?B?…?=` header token
/// uses. It is `pub` because `aruna-gmail`'s own unit tests call it by this name through
/// `use aruna::encoded_word::base64_standard_decode;`.
#[allow(clippy::result_unit_err)]
pub fn base64_standard_decode(input: &str) -> Result<Vec<u8>, ()> {
    fn sextet(b: u8) -> Result<u8, ()> {
        match b {
            b'A'..=b'Z' => Ok(b - b'A'),
            b'a'..=b'z' => Ok(b - b'a' + 26),
            b'0'..=b'9' => Ok(b - b'0' + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err(()),
        }
    }
    base64_decode_with_alphabet(input, sextet)
}

/// RFC 2047 §4.2 quoted-printable, the header variant (`_` decodes to a literal space). A private
/// copy of `aruna-gmail`'s `quoted_printable_header_decode`, called only from
/// [`decode_one_encoded_word`] in either crate.
fn quoted_printable_header_decode(payload: &str) -> Result<Vec<u8>, ()> {
    let bytes = payload.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'_' => {
                out.push(b' ');
                i += 1;
            }
            b'=' => {
                let hi = (*bytes.get(i + 1).ok_or(())? as char).to_digit(16).ok_or(())?;
                let lo = (*bytes.get(i + 2).ok_or(())? as char).to_digit(16).ok_or(())?;
                out.push(((hi << 4) | lo) as u8);
                i += 3;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    Ok(out)
}

/// Try to decode one RFC 2047 encoded-word starting at the very beginning of `s`. The body is
/// identical to `aruna-gmail`'s `decode_one_encoded_word`, except the final charset step calls
/// this module's [`decode_charset_bytes`] instead of the `GmailError`-typed `decode_part_bytes`.
fn decode_one_encoded_word(s: &str) -> Option<(String, usize)> {
    debug_assert!(s.starts_with("=?"));
    let rest = &s[2..];
    let q1 = rest.find('?')?;
    let charset = &rest[..q1];
    if charset.is_empty() {
        return None;
    }
    let rest2 = &rest[q1 + 1..];
    let q2 = rest2.find('?')?;
    let enc = &rest2[..q2];
    let mut enc_chars = enc.chars();
    let enc_char = enc_chars.next()?;
    if enc_chars.next().is_some() {
        return None; // the encoding token must be exactly one character
    }
    let rest3 = &rest2[q2 + 1..];
    let end = rest3.find("?=")?;
    let payload = &rest3[..end];
    let consumed = 2 + q1 + 1 + q2 + 1 + end + 2;
    let bytes = match enc_char {
        'b' | 'B' => base64_standard_decode(payload).ok()?,
        'q' | 'Q' => quoted_printable_header_decode(payload).ok()?,
        _ => return None,
    };
    let charset_lower = charset.to_ascii_lowercase();
    let decoded = decode_charset_bytes(bytes, Some(&charset_lower)).ok()?;
    Some((decoded, consumed))
}

/// Decode `token` iff it is exactly one RFC 2047 encoded-word. This is the per-word decoder
/// [`crate::mailbox`]'s `phrase()` calls with lexical context (a display name's `Atom` only; a
/// quoted-string never reaches here, RFC 2047 §5(3)). `None` means it is not an encoded-word, and
/// the caller keeps the token as literal text (fail-open, never an error).
///
/// Enforced (RFC 2047 §2): the decoder must consume the whole token, so `x=?UTF-8?Q?y?=` and
/// `=?UTF-8?Q?a?==?UTF-8?Q?b?=` (one atom each, since the lexer merges atext) are not
/// encoded-words; `charset` and `encoding` are `token`s (no SPACE, CTL or `especials`); the
/// encoding is `B` or `Q`; the `encoded-text` is `1*` printable ASCII other than `?` and SPACE.
///
/// Deliberate leniencies: (1) §2's 75-character limit on an encoded-word is not enforced, so a
/// longer word from a sloppy but legitimate sender still decodes; (2) §5(3)'s restricted `Q`
/// alphabet inside a phrase (letters, digits, `!*+-/=_`) is not enforced, so any `Q` text the
/// quoted-printable decoder reads decodes. Neither can move the boundary between the name half
/// and the address half, which the grammar fixes before any decode runs.
pub fn decode_encoded_word_exactly(token: &str) -> Option<String> {
    if !token.starts_with("=?") || !token.ends_with("?=") {
        return None;
    }
    let (decoded, consumed) = decode_one_encoded_word(token)?;
    if consumed != token.len() {
        return None;
    }
    let mut parts = token[2..token.len() - 2].splitn(3, '?');
    let (charset, encoding, text) = (parts.next()?, parts.next()?, parts.next()?);
    let is_token = |s: &str| {
        !s.is_empty() && s.bytes().all(|b| (0x21..0x7f).contains(&b) && !b"()<>@,;:\"/[]?.=".contains(&b))
    };
    let is_encoded_text = !text.is_empty() && text.bytes().all(|b| (0x21..0x7f).contains(&b) && b != b'?');
    (is_token(charset) && is_token(encoding) && is_encoded_text).then_some(decoded)
}

/// Decode every RFC 2047 encoded-word (`=?charset?B|Q?payload?=`) inside a raw header value. The
/// body is identical to `aruna-gmail`'s `decode_rfc2047`; the one adaptation is in
/// `decode_one_encoded_word`'s callee (see the module doc).
///
/// - `B`/`Q` are case-insensitive. `B` is [`base64_standard_decode`] (RFC 2047's own `+`/`/`
///   alphabet); `Q` is the header-variant quoted-printable decoder (`_` is a space).
/// - Adjacent encoded words separated only by linear whitespace concatenate without that
///   whitespace (RFC 2047 §6.2). Whitespace that is not between two successfully decoded words
///   is left where the sender put it.
/// - A malformed token fails open: the original substring is copied through verbatim, never an
///   error.
///
/// For unstructured text only: it cannot see quoting or word boundaries, so it must never run
/// over a display name (see [`decode_encoded_word_exactly`]).
pub fn decode_rfc2047(raw: &str) -> String {
    enum Piece<'a> {
        Word(String),
        Raw(&'a str),
    }
    let mut pieces: Vec<Piece> = Vec::new();
    let mut raw_start = 0usize;
    let mut pos = 0usize;
    while pos < raw.len() {
        if raw.as_bytes()[pos] == b'=' && raw[pos..].starts_with("=?") {
            if let Some((decoded, consumed)) = decode_one_encoded_word(&raw[pos..]) {
                if raw_start < pos {
                    pieces.push(Piece::Raw(&raw[raw_start..pos]));
                }
                pieces.push(Piece::Word(decoded));
                pos += consumed;
                raw_start = pos;
                continue;
            }
        }
        // No token recognized here: advance by exactly one char (never a raw byte index) so a
        // multi-byte UTF-8 sequence elsewhere in the header is never split mid-scan.
        let step = raw[pos..].chars().next().map_or(1, char::len_utf8);
        pos += step;
    }
    if raw_start < raw.len() {
        pieces.push(Piece::Raw(&raw[raw_start..]));
    }
    let mut out = String::with_capacity(raw.len());
    for i in 0..pieces.len() {
        match &pieces[i] {
            Piece::Word(s) => out.push_str(s),
            Piece::Raw(s) => {
                let is_whitespace_only = !s.is_empty() && s.chars().all(|c| c.is_ascii_whitespace());
                let flanked_by_words = i > 0
                    && matches!(pieces[i - 1], Piece::Word(_))
                    && matches!(pieces.get(i + 1), Some(Piece::Word(_)));
                if !(is_whitespace_only && flanked_by_words) {
                    out.push_str(s);
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_rfc2047_decodes_a_base64_encoded_utf8_word() {
        let raw = "=?UTF-8?B?44GT44KT44Gr44Gh44Gv?=";
        assert_eq!(decode_rfc2047(raw), "こんにちは");
    }

    #[test]
    fn decode_rfc2047_decodes_a_quoted_printable_latin1_word_with_underscores_as_spaces() {
        let raw = "=?ISO-8859-1?Q?Andr=E9_M=FCller?=";
        assert_eq!(decode_rfc2047(raw), "André Müller");
    }

    #[test]
    fn decode_rfc2047_is_a_no_op_on_plain_text() {
        assert_eq!(decode_rfc2047("Ordinary Subject Line"), "Ordinary Subject Line");
        assert_eq!(decode_rfc2047(""), "");
    }

    #[test]
    fn decode_rfc2047_leaves_a_malformed_token_verbatim() {
        let raw = "=?UTF-8?X?abc?=";
        assert_eq!(decode_rfc2047(raw), raw, "an unrecognized encoding letter is not decodable");
    }
}
