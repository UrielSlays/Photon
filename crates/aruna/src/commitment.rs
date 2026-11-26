//! `mw.commitment.v1`: a keyed commitment scheme ported byte-for-byte from the reference
//! implementation. Pure: no I/O, no store, no clock.
//!
//! tag = HMAC-SHA-384(K, frame(DS) ‖ DS ‖ frame(r) ‖ r ‖ frame(m) ‖ m)
//! frame(f) = u32be(len(f)), the real byte length, refused above u32::MAX (injective framing)
//! DS = compact JSON {scheme_id, source_kind, commitment_disposition, key_ref{namespace_key_id, key_epoch}}
//! K = exactly 48 bytes (an equality, not a floor) · r = exactly 16 bytes, fresh per durable
//! commitment, carried in the clear beside the tag · tag = 96 lowercase hex.
//!
//! Crypto census (`docs/crypto-inventory.md`): the MAC sites here are content commitments,
//! HMAC-SHA-384; `key_fingerprint` is a content-addressed hash.

pub const COMMITMENT_SCHEME: &str = "mw.commitment.v1";
pub const COMMITMENT_SCHEME_VERSION: u32 = 1;
pub const COMMITMENT_KEY_BYTES: usize = 48;
pub const COMMITMENT_RANDOMIZER_BYTES: usize = 16;
pub const COMMITMENT_TAG_BYTES: usize = 48;
pub const COMMITMENT_TAG_LENGTH_BITS: u32 = 384;
/// The largest field a 4-byte big-endian length prefix can express (reference `MAX_FRAME_BYTES`).
/// Documents the ceiling; `frame_prefix` enforces it with `u32::try_from`, which compiles at any
/// pointer width (a `len > MAX_FRAME_BYTES` comparison would be always-false on a 32-bit target,
/// where no `usize` exceeds it).
pub const MAX_FRAME_BYTES: usize = u32::MAX as usize;
/// Reference `MAX_ID_CHARS`: an id in the DS is at most this long.
pub const MAX_ID_CHARS: usize = 256;
/// JavaScript's `Number.MAX_SAFE_INTEGER`. The reference implementation refuses a `key_epoch`
/// above it, so a `key_ref` this module accepts is one the reference implementation accepts.
pub const MAX_KEY_EPOCH: u64 = (1 << 53) - 1;

use std::fmt;

/// Every way the scheme refuses. Fail-closed: a value that could not be built cannot be
/// committed over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitmentError {
    /// The key was not exactly 48 bytes (an equality, not a floor).
    KeyLength(usize),
    /// The randomizer was not exactly 16 bytes.
    RandomizerLength(usize),
    /// A randomizer hex string was not 32 lowercase hex chars.
    RandomizerHex,
    /// A tag hex string was not 96 lowercase hex chars.
    TagHex,
    /// A key hex string was not 96 lowercase hex chars.
    KeyHex,
    /// An id in the domain separator is empty, longer than `MAX_ID_CHARS`, or carries a byte
    /// outside printable ASCII, a `"` or a `\`. Printable ASCII without a quote or backslash
    /// is written by JSON with no escaping, so the id bytes appear verbatim in the domain
    /// separator under both `JSON.stringify` and `serde_json`. Names the field
    /// ([`IdShapeField`], a closed token, because a plan refusal record can carry it).
    IdShape(IdShapeField),
    /// `key_epoch` must be 1..=`MAX_KEY_EPOCH` (reference: positive int, `isSafeInteger`).
    KeyEpochZero,
    /// `key_epoch` exceeded `MAX_KEY_EPOCH` (the reference implementation's `isSafeInteger`
    /// ceiling).
    KeyEpochTooLarge(u64),
    /// A framed field exceeded `MAX_FRAME_BYTES`; the length prefix would wrap.
    FrameTooLong(usize),
    /// OS entropy was unavailable. Never a fallback: a randomizer that is not random is a
    /// keyless correlation oracle.
    EntropyUnavailable,
}

impl fmt::Display for CommitmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CommitmentError::KeyLength(n) => write!(f, "commitment key must be exactly 48 bytes (got {n})"),
            CommitmentError::RandomizerLength(n) => write!(f, "commitment randomizer must be exactly 16 bytes (got {n})"),
            CommitmentError::RandomizerHex => write!(f, "commitment randomizer must be 32 lowercase hex characters"),
            CommitmentError::TagHex => write!(f, "commitment tag must be 96 lowercase hex characters"),
            CommitmentError::KeyHex => write!(f, "commitment key must be 96 lowercase hex characters"),
            CommitmentError::IdShape(field) => write!(f, "commitment domain field `{}` must be 1..=256 printable ASCII chars with no quote or backslash", field.as_token()),
            CommitmentError::KeyEpochZero => write!(f, "commitment key_epoch must be >= 1"),
            CommitmentError::KeyEpochTooLarge(n) => write!(f, "commitment key_epoch {n} exceeds the JS safe-integer ceiling 2^53-1"),
            CommitmentError::FrameTooLong(n) => write!(f, "commitment frame field of {n} bytes exceeds the 4-byte length prefix"),
            CommitmentError::EntropyUnavailable => write!(f, "commitment randomizer: OS entropy unavailable"),
        }
    }
}

impl std::error::Error for CommitmentError {}

closed_tokens! {
    /// The domain-separator field a [`CommitmentError::IdShape`] names. A closed token rather
    /// than a `&'static str`, because a plan refusal record's `detail` carries it and
    /// `crate::plan::PlanSendRefusal::from_record` reads it back.
    pub enum IdShapeField {
        NamespaceKeyId => "namespace_key_id",
        SourceKind => "source_kind",
        Account => "account",
    }
}

/// The 48-byte HMAC key. Opaque: no `Debug` of the bytes, no `Display`, no `Serialize`.
#[derive(Clone, PartialEq, Eq)]
pub struct CommitmentKey([u8; COMMITMENT_KEY_BYTES]);

impl CommitmentKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CommitmentError> {
        let arr: [u8; COMMITMENT_KEY_BYTES] =
            bytes.try_into().map_err(|_| CommitmentError::KeyLength(bytes.len()))?;
        Ok(Self(arr))
    }
    pub fn as_bytes(&self) -> &[u8; COMMITMENT_KEY_BYTES] {
        &self.0
    }
    /// Lowercase 96-hex, the spelling a key custodian stores (the OS credential store holds a
    /// string). **This deliberately exports the secret**: the redacted `Debug` below still
    /// never prints the bytes, and this method exists for the key custodian
    /// (`src-tauri/src/key_custody_keyring.rs`), its only production caller.
    pub fn hex(&self) -> String {
        hex_lower(&self.0)
    }
    /// The inverse of `hex`: exactly 96 lowercase hex characters, else `KeyHex` (never
    /// `KeyLength`, because a string of the wrong length is a spelling defect, not a byte count).
    pub fn from_hex(s: &str) -> Result<Self, CommitmentError> {
        let bytes = hex_decode_lower(s, COMMITMENT_KEY_BYTES).ok_or(CommitmentError::KeyHex)?;
        Self::from_bytes(&bytes)
    }
}

impl fmt::Debug for CommitmentKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CommitmentKey(<48 bytes redacted>)")
    }
}

/// The 16-byte per-event randomizer, carried in the clear beside its tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Randomizer([u8; COMMITMENT_RANDOMIZER_BYTES]);

impl Randomizer {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CommitmentError> {
        let arr: [u8; COMMITMENT_RANDOMIZER_BYTES] =
            bytes.try_into().map_err(|_| CommitmentError::RandomizerLength(bytes.len()))?;
        Ok(Self(arr))
    }
    pub fn as_bytes(&self) -> &[u8; COMMITMENT_RANDOMIZER_BYTES] {
        &self.0
    }
    /// Lowercase 32-hex, the on-disk/wire spelling.
    pub fn hex(&self) -> String {
        hex_lower(&self.0)
    }
    pub fn from_hex(s: &str) -> Result<Self, CommitmentError> {
        let bytes = hex_decode_lower(s, COMMITMENT_RANDOMIZER_BYTES).ok_or(CommitmentError::RandomizerHex)?;
        Self::from_bytes(&bytes)
    }
}

/// Whether committed content may leave the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitmentDisposition {
    ContentEgressPermitted,
    EnvelopeCommitmentOnly,
}

impl CommitmentDisposition {
    pub fn as_str(self) -> &'static str {
        match self {
            CommitmentDisposition::ContentEgressPermitted => "content-egress-permitted",
            CommitmentDisposition::EnvelopeCommitmentOnly => "envelope-commitment-only",
        }
    }
}

fn valid_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_ID_CHARS
        && s.bytes().all(|b| (0x20..=0x7e).contains(&b) && b != b'"' && b != b'\\')
}

/// `key_ref = { namespace-key id, key_epoch }`, the domain-separation input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitmentKeyRef {
    namespace_key_id: String,
    key_epoch: u64,
}

impl CommitmentKeyRef {
    pub fn new(namespace_key_id: &str, key_epoch: u64) -> Result<Self, CommitmentError> {
        if !valid_id(namespace_key_id) {
            return Err(CommitmentError::IdShape(IdShapeField::NamespaceKeyId));
        }
        if key_epoch == 0 {
            return Err(CommitmentError::KeyEpochZero);
        }
        if key_epoch > MAX_KEY_EPOCH {
            return Err(CommitmentError::KeyEpochTooLarge(key_epoch));
        }
        Ok(Self { namespace_key_id: namespace_key_id.to_string(), key_epoch })
    }
    pub fn namespace_key_id(&self) -> &str {
        &self.namespace_key_id
    }
    pub fn key_epoch(&self) -> u64 {
        self.key_epoch
    }
}

/// The domain-separator axes plus the `key_ref` binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitmentDomain {
    source_kind: String,
    disposition: CommitmentDisposition,
    key_ref: CommitmentKeyRef,
}

impl CommitmentDomain {
    pub fn new(
        source_kind: &str,
        disposition: CommitmentDisposition,
        key_ref: CommitmentKeyRef,
    ) -> Result<Self, CommitmentError> {
        if !valid_id(source_kind) {
            return Err(CommitmentError::IdShape(IdShapeField::SourceKind));
        }
        Ok(Self { source_kind: source_kind.to_string(), disposition, key_ref })
    }
    pub fn source_kind(&self) -> &str {
        &self.source_kind
    }
    pub fn disposition(&self) -> CommitmentDisposition {
        self.disposition
    }
    pub fn key_ref(&self) -> &CommitmentKeyRef {
        &self.key_ref
    }
}

/// The 48-byte HMAC-SHA-384 tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitmentTag(pub [u8; COMMITMENT_TAG_BYTES]);

impl CommitmentTag {
    /// Lowercase 96-hex, the on-disk/wire spelling.
    pub fn hex(&self) -> String {
        hex_lower(&self.0)
    }
    pub fn from_hex(s: &str) -> Result<Self, CommitmentError> {
        let bytes = hex_decode_lower(s, COMMITMENT_TAG_BYTES).ok_or(CommitmentError::TagHex)?;
        let arr: [u8; COMMITMENT_TAG_BYTES] = bytes.try_into().map_err(|_| CommitmentError::TagHex)?;
        Ok(Self(arr))
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Decodes exactly `want` bytes of lowercase hex; anything else is `None`. Uppercase is
/// refused on purpose: one spelling in both directions, like every durable token in this crate.
fn hex_decode_lower(s: &str, want: usize) -> Option<Vec<u8>> {
    if s.len() != want * 2 || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    (0..want)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok())
        .collect()
}

/// The canonical domain separator: compact JSON with fixed key order and no `scheme_version`
/// (it lives in the profile, never in the authenticated bytes; including it would break
/// interop with every conforming producer). Built by string assembly, not by a serializer, so
/// the bytes cannot drift with a library's escaping rules. Byte identity with the reference
/// implementation's `JSON.stringify` rests on two constructor bounds: the ids are printable
/// ASCII without a quote or a backslash (`valid_id`), which JSON writes with no escaping, and
/// `key_epoch` is 1..=`MAX_KEY_EPOCH`, which `JSON.stringify` prints as the same plain decimal
/// digits as `u64`'s `Display`.
pub fn canonical_domain_separator(domain: &CommitmentDomain) -> String {
    format!(
        "{{\"scheme_id\":\"{}\",\"source_kind\":\"{}\",\"commitment_disposition\":\"{}\",\"key_ref\":{{\"namespace_key_id\":\"{}\",\"key_epoch\":{}}}}}",
        COMMITMENT_SCHEME,
        domain.source_kind,
        domain.disposition.as_str(),
        domain.key_ref.namespace_key_id,
        domain.key_ref.key_epoch,
    )
}

/// 4-byte big-endian length prefix for one frame (no raw concatenation). Every framed field
/// goes through here, so a length that does not fit a `u32` is refused, never truncated.
pub fn frame_prefix(len: usize) -> Result<[u8; 4], CommitmentError> {
    let len32 = u32::try_from(len).map_err(|_| CommitmentError::FrameTooLong(len))?;
    Ok(len32.to_be_bytes())
}

/// The full preimage `frame(DS) ‖ DS ‖ frame(r) ‖ r ‖ frame(m) ‖ m`, the known-answer-test
/// surface.
/// Production tagging streams the identical frames (`compute_tag`) and never copies `content`.
pub fn encode_preimage(
    domain: &CommitmentDomain,
    randomizer: &Randomizer,
    content: &[u8],
) -> Result<Vec<u8>, CommitmentError> {
    let ds = canonical_domain_separator(domain);
    // Every prefix is computed (and every refusal taken) before the output is allocated, as in
    // the reference implementation.
    let ds_prefix = frame_prefix(ds.len())?;
    let r_prefix = frame_prefix(COMMITMENT_RANDOMIZER_BYTES)?;
    let m_prefix = frame_prefix(content.len())?;
    let mut out = Vec::with_capacity(12 + ds.len() + COMMITMENT_RANDOMIZER_BYTES + content.len());
    out.extend_from_slice(&ds_prefix);
    out.extend_from_slice(ds.as_bytes());
    out.extend_from_slice(&r_prefix);
    out.extend_from_slice(randomizer.as_bytes());
    out.extend_from_slice(&m_prefix);
    out.extend_from_slice(content);
    Ok(out)
}

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha384};

type HmacSha384 = Hmac<Sha384>;

/// The tag primitive: keys HMAC-SHA-384 and feeds every field through `frame_prefix`.
/// `compute_tag` finalizes it and `verify_tag` compares it, so the framing loop exists once.
fn mac_over_frames(key: &CommitmentKey, frames: &[&[u8]]) -> Result<HmacSha384, CommitmentError> {
    let mut mac = HmacSha384::new_from_slice(key.as_bytes())
        .map_err(|_| CommitmentError::KeyLength(key.as_bytes().len()))?;
    for field in frames {
        mac.update(&frame_prefix(field.len())?);
        mac.update(field);
    }
    Ok(mac)
}

/// HMAC-SHA-384(K, DS ‖ r ‖ m) with every field length-prefixed. Streams the frames; never
/// materializes `content` twice.
pub fn compute_tag(
    key: &CommitmentKey,
    domain: &CommitmentDomain,
    randomizer: &Randomizer,
    content: &[u8],
) -> Result<CommitmentTag, CommitmentError> {
    let ds = canonical_domain_separator(domain);
    let mac = mac_over_frames(key, &[ds.as_bytes(), randomizer.as_bytes(), content])?;
    Ok(CommitmentTag(mac.finalize().into_bytes().into()))
}

/// Recompute and compare in constant time (the `hmac` crate's `verify_slice`). A `false`
/// carries no reason: a verifier that explains which byte differed is an oracle.
pub fn verify_tag(
    key: &CommitmentKey,
    domain: &CommitmentDomain,
    randomizer: &Randomizer,
    content: &[u8],
    expected: &CommitmentTag,
) -> bool {
    let ds = canonical_domain_separator(domain);
    match mac_over_frames(key, &[ds.as_bytes(), randomizer.as_bytes(), content]) {
        Ok(mac) => mac.verify_slice(&expected.0).is_ok(),
        Err(_) => false,
    }
}

/// Non-secret key fingerprint: the registry record a restored key is verified against.
/// Reference recipe verbatim: sha384("mw.key-fingerprint.v1 " ‖ material).
pub fn key_fingerprint(key: &CommitmentKey) -> String {
    let mut h = Sha384::new();
    h.update(b"mw.key-fingerprint.v1 ");
    h.update(key.as_bytes());
    format!("{:x}", h.finalize())
}

/// Per-account commitment key from the store's root key: HMAC-SHA-384(root, tag ‖ account).
/// Follows the shape of the reference implementation's `deriveDomainKey`, at SHA-384 width.
/// One key per account so a holder of one account's key cannot compute or verify another
/// account's tags (the profile beside a tag is stored in the clear by design).
pub fn derive_account_key(root: &CommitmentKey, account: &str) -> Result<CommitmentKey, CommitmentError> {
    if !valid_id(account) {
        return Err(CommitmentError::IdShape(IdShapeField::Account));
    }
    let mut mac = HmacSha384::new_from_slice(root.as_bytes())
        .map_err(|_| CommitmentError::KeyLength(root.as_bytes().len()))?;
    mac.update(b"photon.commitment.account-key.v1:");
    mac.update(account.as_bytes());
    let bytes: [u8; COMMITMENT_TAG_BYTES] = mac.finalize().into_bytes().into();
    CommitmentKey::from_bytes(&bytes)
}

/// The 128-bit per-event randomizer, minted once per durable commitment from OS entropy and
/// stored beside the tag. `compute_tag` takes the randomizer as an argument and does not check
/// where it came from; the production path (`commit_over`) passes a freshly minted one, and
/// the known-answer tests pass fixed bytes to pin the reference implementation's vectors.
pub fn mint_randomizer() -> Result<Randomizer, CommitmentError> {
    let mut buf = [0u8; COMMITMENT_RANDOMIZER_BYTES];
    getrandom::fill(&mut buf).map_err(|_| CommitmentError::EntropyUnavailable)?;
    Randomizer::from_bytes(&buf)
}

/// The profile every commitment-bearing row carries beside its tag (reference
/// `CommitmentProfile`): the scheme, its version, the `key_ref`, the exact DS string, the
/// disposition, the randomizer hex, the tag length. Stored so a key-holding verifier
/// re-derives from the row, never from a remembered convention.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitmentProfile {
    pub commitment_scheme: &'static str,
    pub scheme_version: u32,
    pub key_ref: CommitmentKeyRef,
    pub domain_separator: String,
    pub commitment_disposition: CommitmentDisposition,
    pub randomizer: String,
    pub tag_length: u32,
}

impl CommitmentProfile {
    pub fn for_commitment(domain: &CommitmentDomain, randomizer: &Randomizer) -> Self {
        Self {
            commitment_scheme: COMMITMENT_SCHEME,
            scheme_version: COMMITMENT_SCHEME_VERSION,
            key_ref: domain.key_ref.clone(),
            domain_separator: canonical_domain_separator(domain),
            commitment_disposition: domain.disposition,
            randomizer: randomizer.hex(),
            tag_length: COMMITMENT_TAG_LENGTH_BITS,
        }
    }
}

/// Mint a fresh randomizer, compute the tag, and hand back the tag with the profile the row
/// stores beside it. The production path to a new durable commitment. `compute_tag` stays
/// public for re-derivation from a stored randomizer and for the known-answer tests.
pub fn commit_over(
    key: &CommitmentKey,
    domain: &CommitmentDomain,
    content: &[u8],
) -> Result<(CommitmentTag, CommitmentProfile), CommitmentError> {
    let randomizer = mint_randomizer()?;
    let tag = compute_tag(key, domain, &randomizer, content)?;
    Ok((tag, CommitmentProfile::for_commitment(domain, &randomizer)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_is_exactly_48_bytes_an_equality_not_a_floor() {
        assert!(CommitmentKey::from_bytes(&[7u8; 48]).is_ok());
        assert_eq!(CommitmentKey::from_bytes(&[7u8; 47]).unwrap_err(), CommitmentError::KeyLength(47));
        assert_eq!(CommitmentKey::from_bytes(&[7u8; 64]).unwrap_err(), CommitmentError::KeyLength(64));
    }

    /// The custodian's spelling of a key (A7 review fold): 96 lowercase hex, both directions, one
    /// helper in the engine. A string of the wrong length is a SPELLING defect (`KeyHex`), never a
    /// byte count (`KeyLength`) — an odd length has no byte count at all.
    #[test]
    fn a_key_round_trips_through_96_lowercase_hex_and_refuses_every_other_spelling() {
        let key = CommitmentKey::from_hex(&"a5".repeat(48)).unwrap();
        assert_eq!(key, CommitmentKey::from_bytes(&[0xa5u8; 48]).unwrap());
        assert_eq!(key.hex(), "a5".repeat(48));
        // Byte ORDER is pinned too: 00 01 .. 2f spells in that order and reads back to it.
        let ordered: Vec<u8> = (0u8..48).collect();
        let ordered_hex: String = (0u8..48).map(|b| format!("{b:02x}")).collect();
        assert_eq!(CommitmentKey::from_bytes(&ordered).unwrap().hex(), ordered_hex);
        assert_eq!(CommitmentKey::from_hex(&ordered_hex).unwrap().as_bytes().as_slice(), ordered.as_slice());
        assert_eq!(CommitmentKey::from_hex(&"A5".repeat(48)).unwrap_err(), CommitmentError::KeyHex, "uppercase");
        assert_eq!(CommitmentKey::from_hex(&"a5".repeat(47)).unwrap_err(), CommitmentError::KeyHex, "94 chars");
        assert_eq!(CommitmentKey::from_hex(&format!("{}a", "a5".repeat(47))).unwrap_err(), CommitmentError::KeyHex, "95 chars");
        assert_eq!(CommitmentKey::from_hex(&"a5".repeat(49)).unwrap_err(), CommitmentError::KeyHex, "98 chars");
        assert_eq!(CommitmentKey::from_hex(&"g5".repeat(48)).unwrap_err(), CommitmentError::KeyHex, "not hex");
        assert_eq!(CommitmentError::KeyHex.to_string(), "commitment key must be 96 lowercase hex characters");
        // The redacted Debug is unchanged: `hex()` is a deliberate export beside `as_bytes()`, not
        // a Debug leak path.
        assert_eq!(format!("{key:?}"), "CommitmentKey(<48 bytes redacted>)");
    }

    #[test]
    fn a_randomizer_is_exactly_16_bytes() {
        assert!(Randomizer::from_bytes(&[3u8; 16]).is_ok());
        assert_eq!(Randomizer::from_bytes(&[3u8; 15]).unwrap_err(), CommitmentError::RandomizerLength(15));
        assert_eq!(Randomizer::from_hex("03030303030303030303030303030303").unwrap(), Randomizer::from_bytes(&[3u8; 16]).unwrap());
        assert_eq!(Randomizer::from_hex("0303").unwrap_err(), CommitmentError::RandomizerHex);
        assert_eq!(Randomizer::from_hex("ZZ030303030303030303030303030303").unwrap_err(), CommitmentError::RandomizerHex);
    }

    #[test]
    fn key_ref_and_source_kind_refuse_what_the_ds_cannot_carry_unambiguously() {
        // Printable ASCII, no quote, no backslash, ≤ 256 chars — every such character is one JSON
        // writes with NO escaping, so the id bytes appear verbatim in the canonical DS under both
        // JSON.stringify and serde_json.
        assert!(CommitmentKeyRef::new("tenant:a", 1).is_ok());
        assert!(CommitmentKeyRef::new("photon.account.someone@example.com", 1).is_ok());
        assert_eq!(CommitmentKeyRef::new("", 1).unwrap_err(), CommitmentError::IdShape(IdShapeField::NamespaceKeyId));
        assert_eq!(CommitmentKeyRef::new("has\"quote", 1).unwrap_err(), CommitmentError::IdShape(IdShapeField::NamespaceKeyId));
        assert_eq!(CommitmentKeyRef::new("has\\backslash", 1).unwrap_err(), CommitmentError::IdShape(IdShapeField::NamespaceKeyId));
        assert_eq!(CommitmentKeyRef::new("ünïcode", 1).unwrap_err(), CommitmentError::IdShape(IdShapeField::NamespaceKeyId));
        assert_eq!(CommitmentKeyRef::new(&"x".repeat(257), 1).unwrap_err(), CommitmentError::IdShape(IdShapeField::NamespaceKeyId));
        assert_eq!(CommitmentKeyRef::new("tenant:a", 0).unwrap_err(), CommitmentError::KeyEpochZero);
        assert_eq!(
            CommitmentDomain::new("", CommitmentDisposition::EnvelopeCommitmentOnly, CommitmentKeyRef::new("tenant:a", 1).unwrap()).unwrap_err(),
            CommitmentError::IdShape(IdShapeField::SourceKind)
        );
    }

    #[test]
    fn a_tag_renders_as_96_lowercase_hex() {
        let tag = CommitmentTag([0xabu8; 48]);
        let hex = tag.hex();
        assert_eq!(hex.len(), 96);
        assert!(hex.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')));
        assert_eq!(CommitmentTag::from_hex(&hex).unwrap(), tag);
        assert_eq!(CommitmentTag::from_hex("abc").unwrap_err(), CommitmentError::TagHex);
    }

    #[test]
    fn scheme_constants_are_the_bridges() {
        assert_eq!(super::COMMITMENT_SCHEME, "mw.commitment.v1");
        assert_eq!(super::COMMITMENT_KEY_BYTES, 48);
        assert_eq!(super::COMMITMENT_RANDOMIZER_BYTES, 16);
        assert_eq!(super::COMMITMENT_TAG_BYTES, 48);
    }

    #[test]
    fn key_epoch_is_bounded_by_the_js_safe_integer_ceiling_the_bridge_enforces() {
        assert!(CommitmentKeyRef::new("tenant:a", MAX_KEY_EPOCH).is_ok());
        assert_eq!(CommitmentKeyRef::new("tenant:a", MAX_KEY_EPOCH + 1).unwrap_err(), CommitmentError::KeyEpochTooLarge(MAX_KEY_EPOCH + 1));
        assert_eq!(CommitmentKeyRef::new("tenant:a", u64::MAX).unwrap_err(), CommitmentError::KeyEpochTooLarge(u64::MAX));
    }

    #[test]
    fn hex_is_lowercase_only_in_both_directions_and_the_boundaries_are_exact() {
        assert_eq!(Randomizer::from_hex(&"0A".repeat(16)).unwrap_err(), CommitmentError::RandomizerHex);
        assert_eq!(CommitmentTag::from_hex(&"AB".repeat(48)).unwrap_err(), CommitmentError::TagHex);
        assert_eq!(CommitmentTag::from_hex(&"zz".repeat(48)).unwrap_err(), CommitmentError::TagHex);
        // The id rule at its edges: 256 accepted, 0x7f (DEL) and a control byte refused, and
        // source_kind is checked by the same predicate (not only for emptiness).
        assert!(CommitmentKeyRef::new(&"x".repeat(256), 1).is_ok());
        assert_eq!(CommitmentKeyRef::new("del\u{7f}", 1).unwrap_err(), CommitmentError::IdShape(IdShapeField::NamespaceKeyId));
        assert_eq!(CommitmentKeyRef::new("tab\there", 1).unwrap_err(), CommitmentError::IdShape(IdShapeField::NamespaceKeyId));
        assert_eq!(
            CommitmentDomain::new("bad\"kind", CommitmentDisposition::EnvelopeCommitmentOnly, CommitmentKeyRef::new("tenant:a", 1).unwrap()).unwrap_err(),
            CommitmentError::IdShape(IdShapeField::SourceKind)
        );
        // The key never prints its bytes.
        let key = CommitmentKey::from_bytes(&[0x5au8; 48]).unwrap();
        assert_eq!(format!("{key:?}"), "CommitmentKey(<48 bytes redacted>)");
        // Every scheme constant, not four of eight.
        assert_eq!(COMMITMENT_SCHEME_VERSION, 1);
        assert_eq!(COMMITMENT_TAG_LENGTH_BITS, 384);
        assert_eq!(MAX_FRAME_BYTES, u32::MAX as usize);
        assert_eq!(MAX_ID_CHARS, 256);
    }

    fn golden_domain() -> CommitmentDomain {
        CommitmentDomain::new(
            "test-producer",
            CommitmentDisposition::EnvelopeCommitmentOnly,
            CommitmentKeyRef::new("tenant:a", 1).unwrap(),
        )
        .unwrap()
    }
    const GOLDEN_CONTENT: &[u8] = b"the exact content bytes the capture references";

    #[test]
    fn canonical_ds_is_the_bridges_compact_json_with_fixed_key_order_and_no_scheme_version() {
        assert_eq!(
            canonical_domain_separator(&golden_domain()),
            r#"{"scheme_id":"mw.commitment.v1","source_kind":"test-producer","commitment_disposition":"envelope-commitment-only","key_ref":{"namespace_key_id":"tenant:a","key_epoch":1}}"#
        );
    }

    #[test]
    fn max_key_epoch_is_the_js_safe_integer_and_the_id_range_edges_are_exact() {
        assert_eq!(MAX_KEY_EPOCH, 9_007_199_254_740_991);
        assert!(CommitmentKeyRef::new("tenant:a", 9_007_199_254_740_992).is_err());
        // 0x1f is a byte JSON.stringify escapes (`\u001f`) — it must be refused; 0x20 (space) and
        // 0x7e (`~`) are the inclusive edges of the allowed set — accepted.
        assert_eq!(CommitmentKeyRef::new("unit\u{1f}sep", 1).unwrap_err(), CommitmentError::IdShape(IdShapeField::NamespaceKeyId));
        assert!(CommitmentKeyRef::new(" ~ edges ~ ", 1).is_ok());
        assert_eq!(Randomizer::from_bytes(&[0xABu8; 16]).unwrap().hex(), "ab".repeat(16));
    }

    #[test]
    fn the_ds_is_byte_identical_to_json_stringify_at_the_far_edges_too() {
        // Every allowed id byte, the 256-char maximum, the epoch ceiling and the OTHER disposition
        // — one literal, whose SHA-384 below was computed ONCE by node's JSON.stringify (the
        // reference implementation's captured encoder). SK = the 93 printable-ASCII characters 0x20..=0x7e minus `"`
        // (0x22) and `\` (0x5c), in order. The exact command run (node v24.19.0, 2026-09-24):
        //   node -e 'const SK=String.fromCharCode(...Array.from({length:95},(_,i)=>0x20+i).filter(b=>b!==0x22&&b!==0x5c));const o={scheme_id:"mw.commitment.v1",source_kind:SK,commitment_disposition:"content-egress-permitted",key_ref:{namespace_key_id:"x".repeat(256),key_epoch:9007199254740991}};const s=JSON.stringify(o);console.log(SK.length, s.length);console.log(s);console.log(require("crypto").createHash("sha384").update(s).digest("hex"))'
        // It printed `93 513`, the JSON, then the hex pinned below. A mismatch means format! and
        // JSON.stringify diverged — never regenerate the literal to make a red row green.
        let source_kind: String = (0x20u8..=0x7e).filter(|b| *b != b'"' && *b != b'\\').map(|b| b as char).collect();
        assert_eq!(source_kind.len(), 93);
        let d = CommitmentDomain::new(&source_kind, CommitmentDisposition::ContentEgressPermitted, CommitmentKeyRef::new(&"x".repeat(256), MAX_KEY_EPOCH).unwrap()).unwrap();
        let expected = format!(
            "{{\"scheme_id\":\"mw.commitment.v1\",\"source_kind\":\"{source_kind}\",\"commitment_disposition\":\"content-egress-permitted\",\"key_ref\":{{\"namespace_key_id\":\"{}\",\"key_epoch\":9007199254740991}}}}",
            "x".repeat(256)
        );
        assert_eq!(expected.len(), 513);
        assert_eq!(canonical_domain_separator(&d), expected);
        use sha2::{Digest, Sha384};
        assert_eq!(format!("{:x}", Sha384::digest(expected.as_bytes())), "c1998df29d8ed000b169b584b02d572023574e249f4ffce90cc5fd1f45878c723c9bf3d7e964cebe6257cf77d5a8f864");
    }

    #[test]
    fn frame_prefix_is_the_real_byte_length_big_endian_and_refuses_a_wrap() {
        assert_eq!(frame_prefix(0).unwrap(), [0, 0, 0, 0]);
        assert_eq!(frame_prefix(1).unwrap(), [0, 0, 0, 1]);
        assert_eq!(frame_prefix(0x0102_0304).unwrap(), [1, 2, 3, 4]);
        assert_eq!(frame_prefix(u32::MAX as usize).unwrap(), [0xff, 0xff, 0xff, 0xff]);
        // 64-bit only: on a 32-bit target `u32::MAX as usize + 1` is a compile-time overflow
        // (deny-by-default `arithmetic_overflow`), and no `usize` there can exceed the ceiling.
        #[cfg(target_pointer_width = "64")]
        {
            assert_eq!(frame_prefix(u32::MAX as usize + 1).unwrap_err(), CommitmentError::FrameTooLong(u32::MAX as usize + 1));
        }
    }

    #[test]
    fn preimage_is_frame_ds_frame_r_frame_m_and_matches_the_bridges_golden_sha384() {
        use sha2::{Digest, Sha384};
        let r = Randomizer::from_bytes(&[3u8; 16]).unwrap();
        let preimage = encode_preimage(&golden_domain(), &r, GOLDEN_CONTENT).unwrap();
        let ds = canonical_domain_separator(&golden_domain());
        // Structural: the three frames, in order, each u32be-length-prefixed.
        let mut expect = Vec::new();
        expect.extend_from_slice(&(ds.len() as u32).to_be_bytes());
        expect.extend_from_slice(ds.as_bytes());
        expect.extend_from_slice(&16u32.to_be_bytes());
        expect.extend_from_slice(&[3u8; 16]);
        expect.extend_from_slice(&(GOLDEN_CONTENT.len() as u32).to_be_bytes());
        expect.extend_from_slice(GOLDEN_CONTENT);
        assert_eq!(preimage, expect);
        // THE GOLDEN VECTOR (the reference implementation's test vectors, pinned at scheme birth
        // 2026-07-18, recomputed against the reference implementation): a framing or DS drift FAILS here. Never
        // regenerate this literal to make a red row green — a mismatch IS the defect.
        let got = format!("{:x}", Sha384::digest(&preimage));
        assert_eq!(got, "95cf227cfea19b4308c901b6af0a20f682fdb4a5a9d3db87d375f9eb7b1fb235d00d7d94163bbdd4610331d5545e3039");
    }

    #[test]
    fn tag_is_hmac_sha384_over_the_framed_preimage_and_matches_the_bridges_golden_tag() {
        let key = CommitmentKey::from_bytes(&[7u8; 48]).unwrap();
        let r = Randomizer::from_bytes(&[3u8; 16]).unwrap();
        let tag = compute_tag(&key, &golden_domain(), &r, GOLDEN_CONTENT).unwrap();
        // reference-implementation GOLDEN_TAG — DO NOT regenerate.
        assert_eq!(tag.hex(), "478940d7a1405774e59e23f421aeb44b4edc83a5a11332babd36f777666578550548aadaebafd1445baf37e0810a5f4f");
        // Comparative (CT-20): an independent HMAC-SHA-384 over encode_preimage agrees.
        use hmac::{Hmac, Mac};
        let mut mac = Hmac::<sha2::Sha384>::new_from_slice(key.as_bytes()).unwrap();
        mac.update(&encode_preimage(&golden_domain(), &r, GOLDEN_CONTENT).unwrap());
        let independent: [u8; 48] = mac.finalize().into_bytes().into();
        assert_eq!(tag.0, independent);
    }

    #[test]
    fn verify_is_constant_time_equality_and_refuses_every_single_bit_flip() {
        let key = CommitmentKey::from_bytes(&[7u8; 48]).unwrap();
        let r = Randomizer::from_bytes(&[3u8; 16]).unwrap();
        let tag = compute_tag(&key, &golden_domain(), &r, GOLDEN_CONTENT).unwrap();
        assert!(verify_tag(&key, &golden_domain(), &r, GOLDEN_CONTENT, &tag));
        for byte in 0..48 {
            for bit in 0..8 {
                let mut flipped = tag;
                flipped.0[byte] ^= 1 << bit;
                assert!(!verify_tag(&key, &golden_domain(), &r, GOLDEN_CONTENT, &flipped), "byte {byte} bit {bit}");
            }
        }
        // The compare verify_tag makes IS hmac's constant-time verify_slice (source-text witness).
        // CRLF is normalized first: a Windows checkout under core.autocrlf=true hands include_str!
        // "\r\n" line ends, where the "\n}\n" anchor below would not be found.
        let src = include_str!("commitment.rs").replace("\r\n", "\n");
        let body = &src[src.find("pub fn verify_tag").unwrap()..];
        let body = &body[..body.find("\n}\n").unwrap()];
        assert!(body.contains("verify_slice("), "verify_tag must compare through hmac's constant-time verify_slice");
        assert!(!body.contains(" == "), "no == compare inside verify_tag");
        // Any other input changes the tag: content, randomizer, key, and EACH DS axis (CT-23b).
        assert!(!verify_tag(&key, &golden_domain(), &r, b"other content", &tag));
        assert!(!verify_tag(&key, &golden_domain(), &Randomizer::from_bytes(&[4u8; 16]).unwrap(), GOLDEN_CONTENT, &tag));
        assert!(!verify_tag(&CommitmentKey::from_bytes(&[8u8; 48]).unwrap(), &golden_domain(), &r, GOLDEN_CONTENT, &tag));
        let other_ref = CommitmentDomain::new("test-producer", CommitmentDisposition::EnvelopeCommitmentOnly, CommitmentKeyRef::new("tenant:b", 1).unwrap()).unwrap();
        assert!(!verify_tag(&key, &other_ref, &r, GOLDEN_CONTENT, &tag));
        let other_epoch = CommitmentDomain::new("test-producer", CommitmentDisposition::EnvelopeCommitmentOnly, CommitmentKeyRef::new("tenant:a", 2).unwrap()).unwrap();
        assert!(!verify_tag(&key, &other_epoch, &r, GOLDEN_CONTENT, &tag));
        let other_kind = CommitmentDomain::new("other-producer", CommitmentDisposition::EnvelopeCommitmentOnly, CommitmentKeyRef::new("tenant:a", 1).unwrap()).unwrap();
        assert!(!verify_tag(&key, &other_kind, &r, GOLDEN_CONTENT, &tag));
        let other_disp = CommitmentDomain::new("test-producer", CommitmentDisposition::ContentEgressPermitted, CommitmentKeyRef::new("tenant:a", 1).unwrap()).unwrap();
        assert!(!verify_tag(&key, &other_disp, &r, GOLDEN_CONTENT, &tag));
    }

    #[test]
    fn key_fingerprint_is_sha384_over_the_bridges_prefix_and_the_material() {
        use sha2::{Digest, Sha384};
        let key = CommitmentKey::from_bytes(&[7u8; 48]).unwrap();
        let mut h = Sha384::new();
        h.update(b"mw.key-fingerprint.v1 ");
        h.update(key.as_bytes());
        assert_eq!(key_fingerprint(&key), format!("{:x}", h.finalize()));
        // reference-implementation keyFingerprint(7×48) — DO NOT regenerate.
        assert_eq!(key_fingerprint(&key), "3500d34a4cef06b69af0720716c518c3f212b1a3ca6debc8cd05a518b6dfbd943428270956b34cce138350e39db2a54e");
        assert_eq!(key_fingerprint(&key).len(), 96);
        assert_ne!(key_fingerprint(&key), key_fingerprint(&CommitmentKey::from_bytes(&[8u8; 48]).unwrap()));
    }

    #[test]
    fn account_key_derivation_is_hmac_sha384_of_the_domain_tag_and_account_and_never_the_root() {
        let root = CommitmentKey::from_bytes(&[9u8; 48]).unwrap();
        let a = derive_account_key(&root, "someone@example.com").unwrap();
        let b = derive_account_key(&root, "other@example.com").unwrap();
        assert_ne!(a, b);
        assert_ne!(a, root);
        assert_eq!(a, derive_account_key(&root, "someone@example.com").unwrap());
        use hmac::{Hmac, Mac};
        let mut mac = Hmac::<sha2::Sha384>::new_from_slice(root.as_bytes()).unwrap();
        mac.update(b"photon.commitment.account-key.v1:");
        mac.update(b"someone@example.com");
        let expect: [u8; 48] = mac.finalize().into_bytes().into();
        assert_eq!(a.as_bytes(), &expect);
        assert_eq!(derive_account_key(&root, "").unwrap_err(), CommitmentError::IdShape(IdShapeField::Account));
    }

    #[test]
    fn the_profile_carries_every_field_a_verifier_rederives_from() {
        let r = Randomizer::from_bytes(&[0xabu8; 16]).unwrap();
        assert_eq!(CommitmentProfile::for_commitment(&golden_domain(), &r), CommitmentProfile {
            commitment_scheme: "mw.commitment.v1",
            scheme_version: 1,
            key_ref: CommitmentKeyRef::new("tenant:a", 1).unwrap(),
            domain_separator: r#"{"scheme_id":"mw.commitment.v1","source_kind":"test-producer","commitment_disposition":"envelope-commitment-only","key_ref":{"namespace_key_id":"tenant:a","key_epoch":1}}"#.to_string(),
            commitment_disposition: CommitmentDisposition::EnvelopeCommitmentOnly,
            randomizer: "ab".repeat(16),
            tag_length: 384,
        });
    }

    #[test]
    fn minted_randomizers_are_16_bytes_and_do_not_repeat() {
        let a = mint_randomizer().unwrap();
        let b = mint_randomizer().unwrap();
        assert_ne!(a, b, "two mints in a row must not collide (128 bits of OS entropy)");
        assert_eq!(a.hex().len(), 32);
    }

    #[test]
    fn this_modules_own_source_carries_no_control_bytes() {
        // Adopted from a sibling implementation's tests: two invisible NUL bytes once
        // hid inside a domain separator and grep-based guards silently skipped the "binary" file.
        // The source of the scheme must be printable, so every guard that greps it can see it.
        let source = include_str!("commitment.rs");
        for (i, line) in source.lines().enumerate() {
            for ch in line.chars() {
                assert!(
                    !ch.is_control(),
                    "commitment.rs line {} carries a control byte U+{:04X}",
                    i + 1,
                    ch as u32
                );
            }
        }
    }
}
