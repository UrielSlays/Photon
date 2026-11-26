//! The parked Gmail credential file and the loader that reads it.

use std::collections::BTreeSet;
use std::path::Path;

use serde::Deserialize;

use crate::token_refresh::{self, Cure, FileGen, GrantProvenance};

/// The mint-emitted Gmail token file (`scripts/gmail_drill_mint.py` writes
/// `{access_token, refresh_token, expires_at}` atomically into `--secrets-dir`, default
/// `~/.photon/gmail/`). This crate reads it and never writes it.
pub const GMAIL_TOKEN_FILE: &str = "gmail_readside_main_token.json";

/// The credential as read from the token file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GmailCredential {
    pub(crate) access_token: String,
    /// The mint's parked refresh token, which the app spends to renew the access token. `None`
    /// when the file carries none (or a blank one): the file still loads and the refusal names
    /// the absence; it is not a load error.
    pub(crate) refresh_token: Option<String>,
    /// The mint's own expiry stamp (unix seconds), when the file carries one. Surfaced as status
    /// so the UI can say "your credential expired" instead of showing an unexplained refusal.
    pub(crate) expires_at: Option<i64>,
    /// What authorized this credential: which consent (`grant_generation`), which mailbox
    /// (`provider_principal`) and which scopes. Not an `Option`: a credential whose authority
    /// cannot be named is refused by the loader, so no consumer has an "unknown authority" case.
    pub(crate) grant: GrantProvenance,
}

#[derive(Debug, Deserialize)]
struct GmailTokenFile<'a> {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_at: Option<i64>,
    /// Read as raw JSON rather than `Option<GrantProvenance>` so "absent" and "present but not a
    /// usable grant record" stay two facts with two sentences.
    ///
    /// It is a `RawValue`, not a `serde_json::Value`: building a `Value` collapses a repeated
    /// member to its last occurrence before any typed reader can object, so a grant with an old
    /// `grant_generation` followed by the current high-water would be admitted under the last
    /// one. `RawValue` keeps the member stream as written, so `GrantProvenance`'s derived reader
    /// sees it and rejects "duplicate field `grant_generation`" itself. This matches the
    /// ratchet's reader (`token_refresh::read_grant_high_water`).
    ///
    /// Serde's blanket `Option<T>` maps JSON `null` to `None` just like a missing key, which
    /// would send a present `"grant": null` down the absent branch. The double `Option` (as in
    /// `crates/aruna/src/capacity.rs:deserialize_present`) keeps them apart: `#[serde(default)]`
    /// supplies the outer `None` only when the key never appears, and the field deserializer runs
    /// only when the key is present (`null` gives an inner `None`: present but unusable).
    ///
    /// The neighbouring `refresh_token`/`expires_at` stay plain `Option`s: a `null` there reads
    /// as absent, and every spelling of "no usable value" converges on one downstream state and
    /// one cure. `expires_at`'s null-as-absence also matters for admission (no stamp means no
    /// expiry evidence), so changing it is a design decision.
    #[serde(default, borrow, deserialize_with = "grant_member_present")]
    grant: Option<Option<&'a serde_json::value::RawValue>>,
}

/// Runs only when the `grant` key is present in the file (a missing key is
/// `#[serde(default)]`'s outer `None`), so wrapping the result in `Some(..)` is the "key was
/// present" signal. The value decodes through `Option<&RawValue>`: JSON `null` gives the inner
/// `None` (present but unusable); anything else is the raw member stream that
/// `GrantProvenance`'s strict reader then judges.
fn grant_member_present<'de, D>(
    deserializer: D,
) -> Result<Option<Option<&'de serde_json::value::RawValue>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<&'de serde_json::value::RawValue>::deserialize(deserializer).map(Some)
}

/// How much life a parked credential must have left to be treated as usable.
///
/// A token expiring within the next minute may not survive the round trip it is about to be
/// spent on, and the resulting raw provider 401 would surface as an unexplained refusal. The
/// margin is fixed and small, not a refresh schedule. A credential inside it is renewed on the
/// command that needs it; mid-flight expiry of a single request still falls back to the
/// transport's 401.
pub const CREDENTIAL_EXPIRY_GRACE_SECS: i64 = 60;

/// Has this credential's stamp passed (with [`CREDENTIAL_EXPIRY_GRACE_SECS`] of margin)? `Some`
/// is the stamp that passed, which the reason and the refusal both name. `None` when the
/// credential is live and also when it has no stamp: an absent `expires_at` is not evidence of
/// death, and inventing one would refuse a working session.
pub(crate) fn credential_expired_at(expires_at: Option<i64>, now_unix_secs: i64) -> Option<i64> {
    expires_at.filter(|exp| *exp <= now_unix_secs.saturating_add(CREDENTIAL_EXPIRY_GRACE_SECS))
}

/// The wall clock in unix seconds, the unit `scripts/gmail_drill_mint.py` writes into
/// `expires_at`.
///
/// A clock that cannot be read answers `0`, which makes every stamp look live: a broken clock
/// must not brick a session whose credential is fine, and the provider's own 401 remains the
/// backstop.
pub(crate) fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// A credential-load refusal: the class the cure derives from, and the class-only sentence the
/// operator reads. They travel together as two renderings of one fact, so the status bar and the
/// command refusal never disagree about a boot. The `reason` never carries the file's contents,
/// only which clause refused.
#[derive(Clone, Debug)]
pub(crate) struct CredentialLoadFailure {
    pub(crate) class: CredentialLoadRefusal,
    pub(crate) reason: String,
}

impl std::fmt::Display for CredentialLoadFailure {
    /// The class-only sentence. The cure is a discriminant the wire carries beside it, not a word
    /// this rendering has to be trusted to contain.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason)
    }
}

impl CredentialLoadFailure {
    fn new(class: CredentialLoadRefusal, reason: String) -> Self {
        Self { class, reason }
    }

    /// The cure this refusal prescribes: the variant's, never a caller's guess. Every consumer
    /// (boot's fresh-install arm, boot's locked arm, `reconcile_locked`, and the wave's load arm)
    /// reads it from here, so one refusal cannot take different cures on different surfaces.
    pub(crate) fn cure(&self) -> Cure {
        self.class.cure()
    }
}

/// Why the credential loader refused: one variant per distinct refusal site in
/// [`load_gmail_credential`] and [`parse_gmail_credential`], because the cure depends on which
/// clause refused, not on the fact that a load failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CredentialLoadRefusal {
    /// No file at the documented path: `read_to_string` answered `NotFound`.
    NotFound,
    /// The file is there and the read itself failed: a local file-access fault, not a statement
    /// about any credential. The `ErrorKind` is kept because it alone decides whether waiting is
    /// a cure.
    ///
    /// A decode failure is not one of these: [`load_gmail_credential`] reads bytes and decodes
    /// them separately, so "these bytes are not UTF-8" refuses as [`Self::NotTokenJson`].
    Unreadable(std::io::ErrorKind),
    /// The bytes are not the token JSON — they do not decode as UTF-8 text at all, or they decode
    /// and are not that object.
    NotTokenJson,
    /// `access_token` present but blank.
    AccessTokenBlank,
    /// `access_token` broke the credential shape contract.
    AccessTokenShape(token_refresh::ContractViolation),
    /// No `grant` member at all — every pre-grant credential file.
    GrantProvenanceAbsent,
    /// A `grant` member Photon cannot read. `grant_generation: 0` lands here too: that rule is
    /// enforced inside [`token_refresh::GrantProvenance`]'s own deserialization, and this one
    /// `Err` site cannot see through it without matching on a serde message.
    GrantProvenanceUnreadable,
    /// The grant's `provider_principal` is not a usable account identity.
    PrincipalUnusable(token_refresh::PrincipalShape),
    /// The grant's scope set is not exactly this product's.
    ScopeSetNotTheProductSet,
}

impl CredentialLoadRefusal {
    /// The cure for this class. The match is exhaustive with no wildcard arm so that a new
    /// refusal site cannot be added without deciding what cures it.
    ///
    /// Eight of the nine classes are cured by a re-mint. [`Self::Unreadable`] is not: the
    /// credential's bytes were never in question, and a re-consent spends a refresh-token slot
    /// against the provider's per-client ceiling to fix a file-permission problem it cannot
    /// touch.
    pub(crate) fn cure(self) -> Cure {
        match self {
            // A fresh install, a corrupt file, a missing or unreadable grant, an unusable
            // principal, a wrong scope set: in each the file is the problem, and the mint is what
            // writes the file.
            Self::NotFound
            | Self::NotTokenJson
            | Self::AccessTokenBlank
            | Self::AccessTokenShape(_)
            | Self::GrantProvenanceAbsent
            | Self::GrantProvenanceUnreadable
            | Self::PrincipalUnusable(_)
            | Self::ScopeSetNotTheProductSet => Cure::ReMint,
            // A failed read says nothing about the credential. Only the kinds documented to clear
            // on their own get the promise of a retry; everything else is undetermined rather than
            // dressed as a wait or a re-consent. The wildcard is `ErrorKind`'s (it is
            // `#[non_exhaustive]`), not ours.
            Self::Unreadable(kind) => match kind {
                std::io::ErrorKind::Interrupted
                | std::io::ErrorKind::WouldBlock
                | std::io::ErrorKind::TimedOut => Cure::RetryLater,
                _ => Cure::Undetermined,
            },
        }
    }
}

/// The fresh-install diagnosis, shared by both loaders.
///
/// When there is no credential file, the answer is the loader's own refusal and no lock. A lock
/// over a credential that does not exist protects nothing, and in a directory that does not exist
/// it cannot even be created, so reaching for one would turn the ordinary never-minted state into
/// a lock fault. The call sites are [`build_gmail_provider`] and `credential_cell`'s
/// `reconcile_locked` (the wave cannot reach an absent file: a changed digest always reconciles
/// first, and a reconcile that publishes `Unconfigured` leaves no expiry for the wave to be
/// entered on).
///
/// `observed` is the caller's own lock-free observation of the credential file and `load` its own
/// loader, because the two read different disks: boot reads the real one, the coordinator reads
/// the one its [`credential_cell::AdmitIo`] injects. An absent directory and an absent file are
/// the same observation ([`FileGen::Absent`]) and so the same diagnosis.
///
/// `None` means "not the fresh-install case, carry on to the lock", including when the file
/// appeared between the probe and the read (a mint that raced us). The probe is a fast path, not
/// a decision; only the locked path may build an arm.
pub(crate) fn credential_absent_diagnosis(
    observed: &FileGen,
    load: impl FnOnce() -> Result<GmailCredential, CredentialLoadFailure>,
) -> Option<CredentialLoadFailure> {
    if !matches!(observed, FileGen::Absent) {
        return None;
    }
    load().err()
}

/// Read the mint-emitted token file.
///
/// `aruna-gmail` exports no credential loader: the live read-side drill takes its token from
/// `PHOTON_GMAIL_ACCESS_TOKEN` inside the test binary, and the `~/.photon/gmail/` layout is
/// produced by a Python mint script. There is nothing to reuse, so this reads the documented file
/// directly.
///
/// Every failure reason names the path and the shape, never the file's contents: a reason
/// carrying a token fragment would put the credential in a log. The failure is typed
/// ([`CredentialLoadFailure`]) so every caller derives the wire cure from the class that actually
/// refused.
pub(crate) fn load_gmail_credential(secrets_dir: &Path) -> Result<GmailCredential, CredentialLoadFailure> {
    let path = secrets_dir.join(GMAIL_TOKEN_FILE);
    // Two classes, not one: "there is no credential" and "the credential could not be read" are
    // different facts with different cures, and both arrive as a `read_to_string` error. They are
    // split at the `ErrorKind`; no message is inspected.
    //
    // The read and the decode are two questions. `read_to_string` asks both and reports a
    // non-UTF-8 byte as `io::ErrorKind::InvalidData`, which would land in the `Unreadable` arm
    // below and say "a local file-access failure" when the OS read the file perfectly and bytes
    // that are not text cannot be the token JSON. So the bytes are read here and decoded one step
    // lower, where a decode failure takes the same cure `serde_json` gives on the next line
    // (`NotTokenJson` already means exactly this).
    let bytes = std::fs::read(&path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => CredentialLoadFailure::new(
            CredentialLoadRefusal::NotFound,
            format!(
                "no Gmail credential at {} ({}). Mint one with scripts/gmail_drill_mint.py per \
                 docs/runbooks/gmail-live-drill-oauth-runbook.md.",
                path.display(),
                e.kind()
            ),
        ),
        kind => CredentialLoadFailure::new(
            CredentialLoadRefusal::Unreadable(kind),
            format!(
                "the Gmail credential at {} could not be READ ({kind}) — the file is there; this \
                 is a local file-access failure, not a statement about the credential",
                path.display()
            ),
        ),
    })?;
    let raw = String::from_utf8(bytes).map_err(|_| {
        CredentialLoadFailure::new(
            CredentialLoadRefusal::NotTokenJson,
            format!(
                "{} is not the expected token JSON: its bytes are not UTF-8 text",
                path.display()
            ),
        )
    })?;
    parse_gmail_credential(&raw, &path)
}

/// The parse-and-validate half of [`load_gmail_credential`], split out so a caller holding the
/// bytes can derive the credential and the generation from the same read (the status
/// suppression's digest-then-reload pair could otherwise straddle a concurrent write).
pub(crate) fn parse_gmail_credential(
    raw: &str,
    path: &Path,
) -> Result<GmailCredential, CredentialLoadFailure> {
    let parsed: GmailTokenFile<'_> = serde_json::from_str(raw).map_err(|_| {
        CredentialLoadFailure::new(
            CredentialLoadRefusal::NotTokenJson,
            format!(
                "{} is not the expected token JSON ({{access_token, refresh_token, expires_at, grant}} — each member at most once)",
                path.display()
            ),
        )
    })?;
    if parsed.access_token.trim().is_empty() {
        return Err(CredentialLoadFailure::new(
            CredentialLoadRefusal::AccessTokenBlank,
            format!("{} carries an empty access_token", path.display()),
        ));
    }
    // The ingress boundary the app owns. The file is written by the mint today and by any writer
    // tomorrow, so the loader enforces the same token-shape contract as the refresh path (a bad
    // token such as `ya29:BAD` once reached a durable credential the refresh path refuses). A
    // non-credential on disk never reaches `Authorization: Bearer`. The reason names the clause,
    // never the bytes.
    if let Some(what) = token_refresh::access_token_shape_violation(&parsed.access_token) {
        return Err(CredentialLoadFailure::new(
            CredentialLoadRefusal::AccessTokenShape(what),
            format!(
                "{} carries an access_token that broke the credential shape contract ({}); \
                 re-mint with scripts/gmail_drill_mint.py",
                path.display(),
                token_refresh::contract_violation_label(what)
            ),
        ));
    }
    // The grant. Every clause is admitted here, before any transport, connector or URL exists,
    // and every refusal names the class and carries the re-mint cure in words. A load failure
    // publishes `Provider::Unconfigured` and the wave's load arm answers `Cure::ReMint`
    // (`credential_cell::run_wave_inner`), so nothing new crosses the boundary.
    //
    // Every pre-grant credential file is refused at the first boot of this build because none
    // carries a grant. That is an operator-attended re-mint, not a defect, and the sentence below
    // says so.
    let re_mint = "re-mint with scripts/gmail_drill_mint.py";
    let raw_grant = match parsed.grant {
        // The key never appears in the file: the pre-grant legacy shape.
        None => {
            return Err(CredentialLoadFailure::new(
                CredentialLoadRefusal::GrantProvenanceAbsent,
                format!(
                    "{} carries no grant provenance (the {{grant_generation, \
                     provider_principal, effective_scopes}} record that says which consent \
                     authorized it); {re_mint}",
                    path.display()
                ),
            ));
        }
        // Present but `null`: an unusable record, not an absent one. It takes the malformed-grant
        // class and sentence.
        Some(None) => {
            return Err(CredentialLoadFailure::new(
                CredentialLoadRefusal::GrantProvenanceUnreadable,
                format!(
                    "{} carries a grant provenance record Photon cannot read: it is JSON \
                     null, not {{grant_generation (1 or greater), provider_principal, \
                     effective_scopes}}; {re_mint}",
                    path.display()
                ),
            ));
        }
        Some(Some(raw)) => raw,
    };
    // `from_str` on the raw member stream, never `from_value` on a collapsed map, so a repeated
    // member inside the grant is refused rather than resolved last-one-wins. It maps to the same
    // malformed-grant class as every other unreadable grant.
    let grant: GrantProvenance = serde_json::from_str(raw_grant.get()).map_err(|_| {
        CredentialLoadFailure::new(
            CredentialLoadRefusal::GrantProvenanceUnreadable,
            format!(
                "{} carries a grant provenance record Photon cannot read: it is not \
                 {{grant_generation (1 or greater), provider_principal, effective_scopes}}; \
                 {re_mint}",
                path.display()
            ),
        )
    })?;

    // The principal is provider-supplied data that becomes a URL path segment on every wire call
    // (OWASP ASVS V5 / CWE-20), so validate before constructing: this refusal happens before any
    // URL exists. `aruna-gmail`'s `validate_path_id` stays as a second check.
    if let Some(shape) = token_refresh::principal_shape_violation(&grant.provider_principal) {
        return Err(CredentialLoadFailure::new(
            CredentialLoadRefusal::PrincipalUnusable(shape),
            format!(
                "{} carries a grant whose provider_principal is not a usable account identity \
                 ({}); {re_mint}",
                path.display(),
                token_refresh::principal_shape_label(shape)
            ),
        ));
    }

    // Exact set against the compiled product set: missing or unexpected refuses. Rendered by
    // local label only, since a scope string in this sentence would put a remote value in a UI
    // string; the required set is named by what it grants, not by its URI.
    let required: BTreeSet<String> = token_refresh::REQUIRED_SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    if grant.effective_scopes != required {
        return Err(CredentialLoadFailure::new(
            CredentialLoadRefusal::ScopeSetNotTheProductSet,
            format!(
                "{} carries a credential grant that is not exactly {} — it holds {}; {re_mint}",
                path.display(),
                token_refresh::render_scope_set(&required),
                token_refresh::render_scope_set(&grant.effective_scopes)
            ),
        ));
    }

    Ok(GmailCredential {
        access_token: parsed.access_token,
        refresh_token: parsed
            .refresh_token
            .filter(|t| !t.trim().is_empty()),
        expires_at: parsed.expires_at,
        grant,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::SurfaceError;
    use crate::state::PhotonState;
    use crate::status::session_status_view;
    use crate::tests::fixtures::{
        s0_dir, s0_grant, s0_grant_with, s0_token_file, S0_FULL_MAILBOX, S0_MODIFY, S0_PRINCIPAL,
        S0_READONLY,
    };
    use crate::{ProviderKind, SessionConfig};

    #[test]
    fn a_missing_credential_file_is_a_reason_not_a_panic() {
        let dir = aruna::test_temp::TempDir::uncreated("photon-no-cred"); // guarded, never created
        let err = load_gmail_credential(&dir).expect_err("no file, no credential");
        assert!(err.reason.contains(GMAIL_TOKEN_FILE), "the reason names the path: {err}");
        assert!(
            err.reason.contains("gmail_drill_mint.py"),
            "the reason says how to fix it: {err}"
        );
    }

    #[test]
    fn a_credential_reason_never_carries_the_token_bytes() {
        let dir = aruna::test_temp::TempDir::new("photon-bad-cred"); // the ONE guard (`aruna::test_temp`)
        let secret = "ya29.SENTINEL-SECRET-TOKEN-BYTES";
        std::fs::write(dir.join(GMAIL_TOKEN_FILE), format!("{{\"access_token\": \"{secret}\",")).unwrap();

        let err = load_gmail_credential(&dir).expect_err("truncated JSON is not a credential");
        assert!(
            !err.reason.contains(secret),
            "a refusal reason must never carry credential bytes: {err}"
        );

        std::fs::write(dir.join(GMAIL_TOKEN_FILE), "{\"access_token\": \"   \"}").unwrap();
        let err = load_gmail_credential(&dir).expect_err("an empty token is not a credential");
        assert!(err.reason.contains("empty access_token"), "{err}");

        // The mint's own v2 shape: the grant record rides beside the tokens.
        std::fs::write(
            dir.join(GMAIL_TOKEN_FILE),
            s0_token_file(42, Some(&s0_grant())),
        )
        .unwrap();
        let cred = load_gmail_credential(&dir).expect("the mint's own shape parses");
        assert_eq!(cred.access_token, "tok");
        assert_eq!(cred.expires_at, Some(42));
        assert_eq!(cred.grant.provider_principal, S0_PRINCIPAL);
        assert_eq!(cred.grant.grant_generation, 1);

        std::fs::remove_dir_all(&dir).ok();
    }

    // The loader is the INGRESS BOUNDARY THE APP OWNS (a bad token written as `ya29:BAD` once reached a durable credential):
    // it enforces the same token-shape contract as the refresh door, so a non-credential on
    // disk — whatever wrote it — never rides into `Authorization: Bearer`. The reason names
    // the CLAUSE, never the bytes.
    #[test]
    fn the_loader_refuses_a_token_outside_the_shared_shape_contract() {
        let dir = aruna::test_temp::TempDir::new("photon-shape-cred"); // the ONE guard (`aruna::test_temp`)
        for bad in ["ya29:BAD", "ya29!outside", "caf\\u00e9tok"] {
            std::fs::write(
                dir.join(GMAIL_TOKEN_FILE),
                format!(
                    "{{\"access_token\": \"{bad}\", \"refresh_token\": \"rt\", \
                     \"expires_at\": 42, \"grant\": {}}}",
                    s0_grant()
                ),
            )
            .unwrap();
            let err = load_gmail_credential(&dir)
                .expect_err("a token outside the shape contract is not a credential");
            assert!(
                !err.reason.contains("BAD") && !err.reason.contains("outside-"),
                "the reason must name the clause, never the bytes: {err}"
            );
            assert!(err.reason.contains("gmail_drill_mint.py"), "the reason says how to fix it: {err}");
        }
        // A real Google-shaped token still loads.
        std::fs::write(
            dir.join(GMAIL_TOKEN_FILE),
            format!(
                "{{\"access_token\": \"ya29.a0AfH6-_~+/ok==\", \"refresh_token\": \"rt\", \
                 \"expires_at\": 42, \"grant\": {}}}",
                s0_grant()
            ),
        )
        .unwrap();
        load_gmail_credential(&dir).expect("a conforming token loads");
        std::fs::remove_dir_all(&dir).ok();
    }

    // ===========================================================================================
    // THE GRANT PROVENANCE WITNESSES.
    //
    // The credential file is v2: it carries the grant that authorizes the arm — its generation,
    // the mailbox principal the mint observed, and the scope set Google actually granted. Every
    // clause of that record is admitted at the LOADER, before any transport exists, and every
    // refusal names the CLASS (never the value) and carries the `re_mint` cure through the
    // existing `Provider::Unconfigured` machinery.
    // ===========================================================================================

    // -------------------------------------------------------------------------------------------
    // A credential with NO grant provenance is refused, with the re-mint cure.
    //
    // Before the fix: `GmailTokenFile` has no `grant` member at all, so serde ignores its absence
    // and every pre-grant file — the one every operator has parked today — loads and builds an arm
    // whose authority nothing ever established.
    // -------------------------------------------------------------------------------------------
    #[test]
    fn a_credential_without_grant_provenance_is_refused_with_the_re_mint_cure() {
        let dir = s0_dir("g1");
        std::fs::write(dir.join(GMAIL_TOKEN_FILE), s0_token_file(42, None)).unwrap();

        let err = load_gmail_credential(&dir)
            .expect_err("a credential that cannot say what authority it holds is not a credential");
        assert!(
            err.reason.contains("grant provenance"),
            "the refusal names the ABSENCE of grant provenance, not a generic parse failure: {err}"
        );
        assert!(
            err.reason.contains("gmail_drill_mint.py"),
            "the sentence carries the re-mint cure the frontend's `re_mint` copy fires on: {err}"
        );

        // A grant record that is PRESENT but not a usable one is its own fact with its own
        // sentence — including generation 0, which is the ratchet's "nothing minted yet"
        // reading and therefore a generation that can never be latched or superseded.
        let unusable: &[String] = &[
            s0_grant_with(0, S0_PRINCIPAL, &[S0_MODIFY]),
            "{\"provider_principal\": \"owner@example.com\", \"effective_scopes\": []}".to_string(),
            "{\"grant_generation\": 1, \"effective_scopes\": []}".to_string(),
            "\"not-an-object\"".to_string(),
            "null".to_string(),
        ];
        for grant in unusable {
            std::fs::write(dir.join(GMAIL_TOKEN_FILE), s0_token_file(42, Some(grant))).unwrap();
            let err = load_gmail_credential(&dir).expect_err(
                "a grant record Photon cannot read is not a grant, and not a credential either",
            );
            assert!(
                err.reason.contains("grant provenance"),
                "an unusable grant record refuses by NAME, never as a generic parse failure \
                 ({grant}): {err}"
            );
            assert!(err.reason.contains("gmail_drill_mint.py"), "the cure is named: {err}");
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    // -------------------------------------------------------------------------------------------
    // A SURPLUS grant refuses too, and the full-mailbox scope (`https://mail.google.com/` —
    // the only scope that can permanently delete, Google's scope reference) is refused BY NAME at
    // the second door (the mint refuses it at the first).
    //
    // Before the fix: same as the scope-set case — the set was never compared, so an over-broad grant admitted.
    // -------------------------------------------------------------------------------------------
    #[test]
    fn a_surplus_or_full_mailbox_grant_is_refused_at_admission() {
        let dir = s0_dir("g3");
        for scopes in [
            vec![S0_MODIFY, S0_FULL_MAILBOX],
            vec![S0_FULL_MAILBOX],
            vec![S0_MODIFY, S0_READONLY],
        ] {
            std::fs::write(
                dir.join(GMAIL_TOKEN_FILE),
                s0_token_file(42, Some(&s0_grant_with(1, S0_PRINCIPAL, &scopes))),
            )
            .unwrap();
            let err = load_gmail_credential(&dir)
                .expect_err("EXACT SET: a surplus scope is this contract failing, not passing");
            assert!(
                err.reason.contains("read + triage authority"),
                "the refusal names the contract set by label: {err}"
            );
            assert!(
                !err.reason.contains("mail.google.com") && !err.reason.contains("googleapis.com"),
                "no raw scope URI may reach a rendered string: {err}"
            );
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    // -------------------------------------------------------------------------------------------
    // The principal is PROVIDER-SUPPLIED DATA that becomes a URL PATH SEGMENT on every wire
    // call (OWASP ASVS V5 / CWE-20). It is validated at load, before any
    // URL exists. This witness pins that the LOAD DOOR applies the law and that every refusal
    // names the class, carries the cure, and never echoes the value; the law's own clause table
    // (including the corrected 254-byte bound) is
    // `token_refresh`'s `a_provider_principal_must_be_a_mailbox_…`.
    //
    // Before the fix: there is no principal at all — the resolver hardcodes `me`, so this class of
    // input had nowhere to arrive and nothing refusing it.
    // -------------------------------------------------------------------------------------------
    #[test]
    fn every_unusable_provider_principal_shape_is_refused_by_class() {
        let dir = s0_dir("g7");
        // 255 ASCII bytes — one past the honest bound (RFC 5321 §4.5.3.1.3's 256-octet path
        // minus the two angle brackets = 254). The old comment here said 320, which no RFC
        // states.
        let over_bound = format!("SENTINEL{}@example.com", "a".repeat(255 - 20));
        // Every hostile shape carries the SENTINEL marker, so "the reason never echoes the
        // provider-supplied value" is checkable without tripping over degenerate inputs
        // (`.` and `me` are substrings of any English sentence about them).
        let cases: &[(&str, &str)] = &[
            ("", "empty"),
            ("me", "the credential-relative alias"),
            (".", "a dot segment"),
            ("..", "a dot segment"),
            ("SENTINEL er@example.com", "whitespace"),
            ("SENTINEL\\ter@example.com", "a tab is whitespace too"),
            ("SENTINEL/er@example.com", "a path separator"),
            ("SENTINEL?er@example.com", "a query delimiter"),
            ("SENTINEL#er@example.com", "a fragment delimiter"),
            ("SENTINEL%2Fer@example.com", "a percent-escape"),
            ("SENTINEL\\u00f6wner@example.com", "non-ASCII"),
            (over_bound.as_str(), "over the 254-byte mailbox bound"),
            ("SENTINEL-not-an-email", "not a mailbox at all (council r1 seat 3, EXECUTED)"),
            // DEL, not NUL: a raw NUL is not valid JSON at all, so it would be refused a
            // door earlier and prove nothing about the PRINCIPAL law. DEL is legal JSON
            // text and was one of two escapes past the old "ASCII" clause.
            ("SENTINEL\u{7f}@example.com", "a control byte (council r1 seat 1)"),
        ];
        for (principal, why) in cases {
            std::fs::write(
                dir.join(GMAIL_TOKEN_FILE),
                s0_token_file(42, Some(&s0_grant_with(1, principal, &[S0_MODIFY]))),
            )
            .unwrap();
            let err = load_gmail_credential(&dir).unwrap_err();
            assert!(
                err.reason.contains("provider_principal"),
                "the refusal names the FIELD ({why}): {err}"
            );
            assert!(
                !err.reason.contains("SENTINEL"),
                "the refusal names the CLASS, never the provider-supplied value ({why}): {err}"
            );
            assert!(
                err.reason.contains("gmail_drill_mint.py"),
                "the cure is named ({why}): {err}"
            );
        }

        // The conformant address loads — the rule must not refuse what the mint really writes.
        std::fs::write(
            dir.join(GMAIL_TOKEN_FILE),
            s0_token_file(42, Some(&s0_grant())),
        )
        .unwrap();
        load_gmail_credential(&dir).expect("a real mailbox address is a usable principal");
        std::fs::remove_dir_all(&dir).ok();
    }

    // -------------------------------------------------------------------------------------------
    // The grant is deserialized from its OWN RAW MEMBER STREAM, so a grant
    // that REPEATS a member is refused as malformed instead of collapsing to the last occurrence.
    //
    // `serde_json::Value` is a MAP: constructing one drops every earlier occurrence of a repeated
    // key before any typed deserialize can see it. A `grant` carrying an old `grant_generation`
    // followed by the current high-water was therefore ADMITTED under the LAST occurrence — a
    // pre-parse transform voiding the very discriminator the typed shape exists to be. The
    // ratchet's own reader (`token_refresh::read_grant_high_water`) already refuses a repeated
    // member; this door was its un-hardened neighbour. Holding the grant as a `RawValue` and
    // deserializing it with `from_str` puts serde's derived `GrantWire` back in front of the
    // member stream, where "duplicate field `grant_generation`" is its answer.
    //
    // The refusal is the SAME malformed-grant one that was already there — no new class, no new
    // sentence, the nine-variant set unchanged. And the distinction the `Option` exists for is
    // untouched: ABSENT still says "carries no grant provenance", MALFORMED still says
    // "cannot read".
    //
    // Before the fix (`grant: Option<serde_json::Value>` + `serde_json::from_value`): case (a) below
    // LOADED, and `credential.grant.grant_generation` read 7.
    // -------------------------------------------------------------------------------------------
    #[test]
    fn a_grant_that_repeats_a_member_is_refused_as_malformed_never_collapsed() {
        let dir = s0_dir("f19");
        let path = dir.join(GMAIL_TOKEN_FILE);
        let live = unix_now() + 3_600;

        // (a) an old generation followed by the current high-water; (b) the same shape for the
        // other two members. Each file's grant says two different things about ONE question.
        let repeated: &[(&str, String)] = &[
            (
                "grant_generation",
                format!(
                    "{{\"grant_generation\": 1, \"provider_principal\": \"{S0_PRINCIPAL}\", \
                     \"effective_scopes\": [\"{S0_MODIFY}\"], \"grant_generation\": 7}}"
                ),
            ),
            (
                "provider_principal",
                format!(
                    "{{\"grant_generation\": 1, \"provider_principal\": \"someone@example.com\", \
                     \"effective_scopes\": [\"{S0_MODIFY}\"], \
                     \"provider_principal\": \"{S0_PRINCIPAL}\"}}"
                ),
            ),
            (
                "effective_scopes",
                format!(
                    "{{\"grant_generation\": 1, \"provider_principal\": \"{S0_PRINCIPAL}\", \
                     \"effective_scopes\": [\"{S0_READONLY}\"], \
                     \"effective_scopes\": [\"{S0_MODIFY}\"]}}"
                ),
            ),
        ];
        for (member, grant) in repeated {
            std::fs::write(&path, s0_token_file(live, Some(grant))).unwrap();
            match load_gmail_credential(&dir) {
                Ok(admitted) => panic!(
                    "a grant repeating `{member}` was ADMITTED under its LAST occurrence \
                     (generation {}) — a member stated twice is a malformed record, not a value",
                    admitted.grant.grant_generation
                ),
                Err(err) => {
                    assert_eq!(
                        err.class,
                        CredentialLoadRefusal::GrantProvenanceUnreadable,
                        "a repeated `{member}` refuses as the EXISTING malformed-grant class — \
                         no tenth variant was minted for it: {err}"
                    );
                    assert!(
                        err.reason.contains("cannot read"),
                        "the malformed sentence, not the ABSENT one: {err}"
                    );
                    assert!(
                        err.reason.contains("gmail_drill_mint.py"),
                        "the cure is named: {err}"
                    );
                }
            }
        }

        // (c) TWO TOP-LEVEL `grant` members. serde's derived reader for `GmailTokenFile` already
        // refused this at da3f046 — the collapse was only ever the `Value` detour inside the
        // grant — so this is a NON-REGRESSION PIN, not a red: the outer object and the inner one
        // must now agree that a name stated twice is not a document.
        std::fs::write(
            &path,
            format!(
                "{{\"access_token\": \"tok\", \"refresh_token\": \"rt\", \"expires_at\": {live}, \
                 \"grant\": {}, \"grant\": {}}}",
                s0_grant_with(1, S0_PRINCIPAL, &[S0_READONLY]),
                s0_grant()
            ),
        )
        .unwrap();
        let err = match load_gmail_credential(&dir) {
            Ok(_) => panic!("a token file that declares `grant` twice is not the token JSON"),
            Err(err) => err,
        };
        assert_eq!(
            err.class,
            CredentialLoadRefusal::NotTokenJson,
            "a repeated TOP-LEVEL member is the file failing its own shape: {err}"
        );

        // (d) NON-REGRESSION, both sentences. The mint's own shape still loads...
        std::fs::write(&path, s0_token_file(live, Some(&s0_grant()))).unwrap();
        let ok = load_gmail_credential(&dir).expect("the canonical minted credential still loads");
        assert_eq!(ok.grant.grant_generation, 1);
        assert_eq!(ok.grant.provider_principal, S0_PRINCIPAL);

        // ...and an ABSENT grant is still its own fact with its own sentence, which is the whole
        // reason the member is an `Option` of raw JSON rather than an `Option<GrantProvenance>`.
        std::fs::write(&path, s0_token_file(live, None)).unwrap();
        let absent = load_gmail_credential(&dir).expect_err("no grant is still no credential");
        assert_eq!(absent.class, CredentialLoadRefusal::GrantProvenanceAbsent);
        assert!(
            absent.reason.contains("carries no grant provenance"),
            "ABSENT and MALFORMED stay two facts with two sentences: {absent}"
        );

        // (e) a
        // PRESENT `"grant": null` is a present-but-unusable record, and it must take the
        // UNREADABLE class and sentence — not the ABSENT ceremony sentence. Before the fix, serde's
        // blanket `Option<T>` mapped the JSON `null` to `None` exactly as a missing key, so
        // the operator holding a null-grant file was told the file "carries no grant
        // provenance" when the bytes carry the member. This case failed on the earlier shape.
        std::fs::write(&path, s0_token_file(live, Some("null"))).unwrap();
        let present_null =
            load_gmail_credential(&dir).expect_err("a null grant is still no credential");
        assert_eq!(
            present_null.class,
            CredentialLoadRefusal::GrantProvenanceUnreadable,
            "present-null is an UNUSABLE record, never an ABSENT one: {present_null}"
        );
        assert!(
            present_null.reason.contains("cannot read"),
            "the malformed-family sentence, not the ceremony one: {present_null}"
        );
        assert!(
            !present_null.reason.contains("carries no grant provenance"),
            "the ABSENT sentence must not fire on a present member: {present_null}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Boot a session on `dir` and answer what BOTH cure surfaces say about its credential:
    /// `(status.credential_cure, status.provider_reason, the refusal's serialized wire form)`.
    /// The two surfaces are asserted EQUAL here, once, so every row below inherits that check.
    fn cures(dir: &Path) -> (Option<Cure>, String, serde_json::Value) {
        let state = PhotonState::new(SessionConfig {
            account: "acct".to_string(),
            store_path: dir.join("store.sqlite"),
            provider_kind: ProviderKind::Gmail,
            gmail_secrets_dir: dir.to_path_buf(),
        });
        let status = session_status_view(&state, Some(1), None, 1_000_000);
        assert!(!status.configured, "every row here is a REFUSAL, by construction");
        let err = match state.admit_provider_sync(unix_now()) {
            Err(e) => e,
            Ok(_) => panic!("a refused credential admits nothing"),
        };
        assert!(
            matches!(err, SurfaceError::SessionUnconfigured { .. }),
            "a load-door refusal is a SessionUnconfigured refusal: {err:?}"
        );
        let wire = serde_json::to_value(&err).expect("SurfaceError serializes");
        assert_eq!(
            status.credential_cure.map(|c| serde_json::to_value(c).unwrap()),
            Some(wire["cure"].clone()),
            "the status bar and the refusal must never say two different things about one boot"
        );
        (
            status.credential_cure,
            status.provider_reason.unwrap_or_default(),
            wire,
        )
    }

    // ===========================================================================================
    // THE LOAD DOOR'S ERROR SET, ONE CURE PER VARIANT.
    //
    // The fix is not "add a branch", it is REVERT the
    // invention. `CREDENTIAL_LOAD_FAILURE_CURE = Cure::ReMint` was one constant standing for
    // every `Err` `load_gmail_credential`/`parse_gmail_credential` can produce, and it could
    // stand for them all only because the error was an untyped `String` — nothing in the type
    // system knew there was a SET. There is: nine distinct refusal sites, and exactly one of
    // them (a raw I/O READ failure on a file that IS there) is not cured by a re-consent. The
    // constant is deleted; the door's error is typed; the cure is an exhaustive match with no
    // wildcard arm, so a tenth refusal cannot be added without deciding its cure.
    //
    // These nine witnesses ARE the set, enumerated from the code (every `Err(` site in those two
    // functions), each judged on BOTH surfaces the operator meets — the status bar's
    // `credential_cure` and the `session_unconfigured` refusal's `cure`.
    // ===========================================================================================

    // -------------------------------------------------------------------------------------------
    // THE ROW THE BLANKET CONSTANT GOT WRONG: the credential file IS there and the READ failed.
    //
    // A re-consent cures nothing here — the bytes were never in question — and it is not free:
    // every re-mint spends a refresh-token slot against the provider's per-client ceiling.
    //
    // The fixture makes the credential PATH a DIRECTORY, the portable way to get a non-`NotFound`
    // `read_to_string` error (Windows: `PermissionDenied`; Unix: `IsADirectory`).
    //
    // Before the fix this test failed:
    //   panicked at 'assertion `left != right` failed: a READ failure is not cured by a
    //   re-consent: the file is there, Photon could not read it — and a re-mint spends a
    //   refresh-token slot against the provider ceiling for nothing
    //     left: Some(ReMint)
    //    right: Some(ReMint)'
    // -------------------------------------------------------------------------------------------
    #[test]
    fn unreadable_a_read_failure_is_never_cured_by_a_re_mint() {
        let dir = s0_dir("f4r4f2-unreadable");
        std::fs::create_dir_all(dir.join(GMAIL_TOKEN_FILE))
            .expect("the credential PATH is a directory: present, and unreadable as a file");

        let (cure, reason, wire) = cures(&dir);
        assert_ne!(
            cure,
            Some(Cure::ReMint),
            "a READ failure is not cured by a re-consent: the file is there, Photon could not \
             read it — and a re-mint spends a refresh-token slot against the provider ceiling \
             for nothing"
        );
        assert_eq!(
            cure,
            Some(Cure::Undetermined),
            "and a non-transient read failure is honestly UNDETERMINED, not a promised retry: \
             {reason}"
        );
        assert_eq!(wire["cure"], serde_json::json!("undetermined"));
        assert!(
            reason.contains("could not be READ"),
            "the sentence names the READ, not the credential's provenance: {reason}"
        );
        assert!(
            !reason.contains("grant provenance") && !reason.contains("gmail_drill_mint.py"),
            "and prescribes no re-mint anywhere in it: {reason}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The TRANSIENT half of the same variant, asserted at the discriminant: the kinds that take
    /// `RetryLater` (`Interrupted`, `WouldBlock`, `TimedOut`) cannot be provoked from a temp
    /// directory on every platform this product ships to, and inventing a fixture that fakes one
    /// would witness the fixture, not the rule.
    #[test]
    fn unreadable_transient_kinds_take_retry_later_and_the_rest_undetermined() {
        use std::io::ErrorKind::{
            Interrupted, InvalidData, Other, PermissionDenied, TimedOut, WouldBlock,
        };
        for kind in [Interrupted, WouldBlock, TimedOut] {
            assert_eq!(
                CredentialLoadRefusal::Unreadable(kind).cure(),
                Cure::RetryLater,
                "{kind:?} really does clear on its own — the next command IS the cure"
            );
        }
        // `InvalidData` is still an honest READ failure when the OS reports one — but
        // now it is no longer how a non-UTF-8 credential file arrives here: the door reads
        // bytes and decodes them separately, so that file refuses as `NotTokenJson`
        // (`non_utf8_bytes_are_a_malformed_credential_not_a_read_failure`).
        for kind in [PermissionDenied, InvalidData, Other] {
            assert_eq!(
                CredentialLoadRefusal::Unreadable(kind).cure(),
                Cure::Undetermined,
                "{kind:?} is not known to clear on its own, and is not a consent problem either"
            );
        }
    }

    /// NOT FOUND — the fresh install. A mint really is the cure; this row also pins that the
    /// split left the sentence the fresh-install witness reads exactly where it was.
    #[test]
    fn not_found_a_fresh_install_is_cured_by_a_mint() {
        let dir = s0_dir("f4r4f2-notfound");
        let (cure, reason, wire) = cures(&dir);
        assert_eq!(cure, Some(Cure::ReMint), "{reason}");
        assert_eq!(wire["cure"], serde_json::json!("re_mint"));
        assert!(reason.contains("no Gmail credential at"), "{reason}");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// NOT THE TOKEN JSON — corrupt bytes on disk; a re-mint rewrites the file.
    #[test]
    fn not_token_json_a_corrupt_file_is_cured_by_a_re_mint() {
        let dir = s0_dir("f4r4f2-notjson");
        std::fs::write(dir.join(GMAIL_TOKEN_FILE), "{\"access_token\": ").unwrap();
        let (cure, reason, wire) = cures(&dir);
        assert_eq!(cure, Some(Cure::ReMint), "{reason}");
        assert_eq!(wire["cure"], serde_json::json!("re_mint"));
        assert!(reason.contains("not the expected token JSON"), "{reason}");
        std::fs::remove_dir_all(&dir).ok();
    }

    // -------------------------------------------------------------------------------------------
    // NOT UTF-8 — the SAME fact as "not the token JSON", arriving one layer lower
    //
    // `read_to_string` folds the DECODE into the READ and reports a byte that cannot start a
    // UTF-8 sequence as `io::ErrorKind::InvalidData` — which this door classed `Unreadable`, whose
    // cure is `Undetermined` and whose sentence tells the operator "this is a local file-access
    // failure, not a statement about the credential". Both halves are false: nothing failed to be
    // read, and bytes that are not text cannot be the token JSON. The honest class is the
    // malformed-credential one, and its cure — the re-mint that rewrites the file — is the one
    // that actually works.
    //
    // Before the fix this test failed:
    //   assertion `left == right` failed: a file whose bytes are not UTF-8 is a MALFORMED
    //   CREDENTIAL, not a file-access failure — the read itself succeeded: the Gmail credential
    //   at …\gmail_readside_main_token.json could not be READ (invalid data) — the file is
    //   there; this is a local file-access failure, not a statement about the credential
    //     left: Unreadable(InvalidData)
    //    right: NotTokenJson
    // -------------------------------------------------------------------------------------------
    #[test]
    fn non_utf8_bytes_are_a_malformed_credential_not_a_read_failure() {
        let dir = s0_dir("f11r9-not-utf8");
        // A lone `0xFF`: no UTF-8 sequence may begin with it, so these bytes are not text at all
        // Let alone the token JSON. Everything around it is the mint's own shape, so the decode
        // is the ONLY clause of the door that can refuse this file.
        let mut bytes = format!(
            "{{\"access_token\": \"ya29.aaaa\", \"refresh_token\": \"rt\", \
             \"expires_at\": 42, \"grant\": {}}}",
            s0_grant()
        )
        .into_bytes();
        bytes.insert(20, 0xFF);
        std::fs::write(dir.join(GMAIL_TOKEN_FILE), &bytes).unwrap();

        let err =
            load_gmail_credential(&dir).expect_err("bytes that are not text are no credential");
        assert_eq!(
            err.class,
            CredentialLoadRefusal::NotTokenJson,
            "a file whose bytes are not UTF-8 is a MALFORMED CREDENTIAL, not a file-access \
             failure — the read itself succeeded: {}",
            err.reason
        );
        assert_eq!(
            err.cure(),
            Cure::ReMint,
            "and a re-mint is what rewrites the file: {}",
            err.reason
        );

        // BOTH surfaces, through the same helper every other row in this set uses.
        let (cure, reason, wire) = cures(&dir);
        assert_eq!(cure, Some(Cure::ReMint), "{reason}");
        assert_eq!(wire["cure"], serde_json::json!("re_mint"));
        assert!(reason.contains("not the expected token JSON"), "{reason}");
        assert!(
            !reason.contains("could not be READ"),
            "the sentence never calls a decode failure a file-access failure: {reason}"
        );
        assert!(
            !reason.contains("ya29"),
            "and it never carries the file's own bytes (§2 S2's sink rule): {reason}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A BLANK access token.
    #[test]
    fn access_token_blank_is_cured_by_a_re_mint() {
        let dir = s0_dir("f4r4f2-blank");
        std::fs::write(
            dir.join(GMAIL_TOKEN_FILE),
            format!(
                "{{\"access_token\": \"   \", \"refresh_token\": \"rt\", \
                 \"expires_at\": 42, \"grant\": {}}}",
                s0_grant()
            ),
        )
        .unwrap();
        let (cure, reason, wire) = cures(&dir);
        assert_eq!(cure, Some(Cure::ReMint), "{reason}");
        assert_eq!(wire["cure"], serde_json::json!("re_mint"));
        assert!(reason.contains("empty access_token"), "{reason}");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// An access token that broke the credential SHAPE contract.
    #[test]
    fn access_token_shape_is_cured_by_a_re_mint() {
        let dir = s0_dir("f4r4f2-shape");
        std::fs::write(
            dir.join(GMAIL_TOKEN_FILE),
            format!(
                "{{\"access_token\": \"ya29:BAD\", \"refresh_token\": \"rt\", \
                 \"expires_at\": 42, \"grant\": {}}}",
                s0_grant()
            ),
        )
        .unwrap();
        let (cure, reason, wire) = cures(&dir);
        assert_eq!(cure, Some(Cure::ReMint), "{reason}");
        assert_eq!(wire["cure"], serde_json::json!("re_mint"));
        assert!(reason.contains("credential shape contract"), "{reason}");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// NO grant provenance — the state every pre-grant file on every machine is in.
    #[test]
    fn grant_provenance_absent_is_cured_by_a_re_mint() {
        let dir = s0_dir("f4r4f2-nogrant");
        std::fs::write(dir.join(GMAIL_TOKEN_FILE), s0_token_file(42, None)).unwrap();
        let (cure, reason, wire) = cures(&dir);
        assert_eq!(cure, Some(Cure::ReMint), "{reason}");
        assert_eq!(wire["cure"], serde_json::json!("re_mint"));
        assert!(reason.contains("grant provenance"), "{reason}");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A grant record Photon cannot READ — and this is also where `grant_generation: 0` lands,
    /// because that rule is enforced INSIDE `GrantProvenance`'s own deserialization
    /// (`try_from = "GrantWire"`) and the single `Err(` site here cannot see through it. One
    /// site, one variant: splitting it would mean matching on a serde message, which is the
    /// string matching this change exists to end. Both readings take the same cure anyway.
    #[test]
    fn grant_provenance_unreadable_is_cured_by_a_re_mint() {
        let dir = s0_dir("f4r4f2-gen0");
        std::fs::write(
            dir.join(GMAIL_TOKEN_FILE),
            s0_token_file(42, Some(&s0_grant_with(0, S0_PRINCIPAL, &[S0_MODIFY]))),
        )
        .unwrap();
        let (cure, reason, wire) = cures(&dir);
        assert_eq!(cure, Some(Cure::ReMint), "{reason}");
        assert_eq!(wire["cure"], serde_json::json!("re_mint"));
        assert!(reason.contains("Photon cannot read"), "{reason}");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A `provider_principal` that is not a usable account identity.
    #[test]
    fn principal_unusable_is_cured_by_a_re_mint() {
        let dir = s0_dir("f4r4f2-principal");
        std::fs::write(
            dir.join(GMAIL_TOKEN_FILE),
            s0_token_file(42, Some(&s0_grant_with(1, "me", &[S0_MODIFY]))),
        )
        .unwrap();
        let (cure, reason, wire) = cures(&dir);
        assert_eq!(cure, Some(Cure::ReMint), "{reason}");
        assert_eq!(wire["cure"], serde_json::json!("re_mint"));
        assert!(reason.contains("provider_principal"), "{reason}");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A scope set that is not exactly this product's.
    #[test]
    fn scope_set_not_the_product_set_is_cured_by_a_re_mint() {
        let dir = s0_dir("f4r4f2-scopes");
        std::fs::write(
            dir.join(GMAIL_TOKEN_FILE),
            s0_token_file(
                42,
                Some(&s0_grant_with(
                    1,
                    S0_PRINCIPAL,
                    &["https://www.googleapis.com/auth/gmail.readonly"],
                )),
            ),
        )
        .unwrap();
        let (cure, reason, wire) = cures(&dir);
        assert_eq!(cure, Some(Cure::ReMint), "{reason}");
        assert_eq!(wire["cure"], serde_json::json!("re_mint"));
        assert!(reason.contains("not exactly"), "{reason}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_credential_with_no_expiry_stamp_is_never_treated_as_expired() {
        // The mint always writes one, but the loader tolerates its absence (`#[serde(default)]`).
        // An ABSENT stamp is not evidence of death — inventing one would refuse a working session.
        assert_eq!(credential_expired_at(None, i64::MAX / 2), None);
    }
}
