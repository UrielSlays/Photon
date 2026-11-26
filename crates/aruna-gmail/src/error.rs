//! Wire to [`GmailError`] normalization, including 403 `reason` disambiguation (the layer
//! `aruna::gmail`'s taxonomy defers to).
//!
//! # Status selects the family; reason refines only within a compatible family
//!
//! A recognizable body may not override the HTTP status: that would let a hostile body
//! downgrade a hard 401/403/400 into a retry (`HTTP 401` carrying `backendError`), and the
//! `reason` space is unbounded and vendor-controlled, so a reason-first allowlist would turn
//! every un-enumerated throttle into a permanent dead-letter. `429` already covers the
//! short-horizon throttle family, and the legacy-403 reason list is a small, bounded
//! refinement. Everything unrecognized at 403 fails closed.
//!
//! # Two envelopes, normalized separately
//!
//! Google is mid-rollout of a second error shape and both are accepted, but not unified under a
//! shared `domain` key: legacy Gmail's `domain: "usageLimits"` is a quota grouping, while
//! `google.rpc.ErrorInfo.domain` is a service domain (`googleapis.com`, AIP-193).
//!
//! - **Legacy:** `{"error":{"code":<int>,"errors":[{"domain","reason","message",…}],"message"}}`,
//!   with `reason` in lowerCamelCase.
//! - **Current:** `{"error":{"code","message","status","details":[{"@type":"…/google.rpc.ErrorInfo",
//!   "reason","domain",…}]}}`. The canonical code is the top-level `status`, and
//!   `RESOURCE_EXHAUSTED` is a top-level status rather than an `ErrorInfo.reason`.
//!
//! # Typed fields only
//!
//! Only `error.code` (as a self-consistency precondition at 403, never to select a family),
//! `error.errors[].domain|reason`, `error.status` and `error.details[ErrorInfo].reason` are
//! consulted. Provider `message` text, ids and metadata are never read or carried into the
//! surfaced error (ADR-P003/P004).

use aruna::gmail::GmailError;
use serde::Deserialize;

/// What a single typed entry contributes to the classification.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Entry {
    /// A recognized reason whose home status family matches this response's status.
    Refines(Refinement),
    /// A recognized reason that contradicts the status family (e.g. 401 carrying `backendError`,
    /// 400 carrying `rateLimitExceeded`, 403 carrying `RESOURCE_EXHAUSTED`).
    Incompatible,
    /// Nothing this normalizer recognizes, or a non-conforming envelope.
    Unrecognized,
}

/// The refinement a recognized, compatible reason names. Not [`GmailError`] itself:
/// `Backend` needs the status to build its variant, and this stays `Copy` for cheap aggregation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Refinement {
    /// Short-horizon throttle — back off and retry.
    RateLimit,
    /// Server-side, lifts on retry.
    Backend,
    /// Authorization refusal — will not self-heal.
    Forbidden,
    /// Credential refusal.
    Unauthorized,
    /// The id is gone.
    NotFound,
    /// Malformed request; an identical retry fails identically.
    InvalidArgument,
    /// Long-horizon quota (`dailyLimitExceeded`). Deterministic, not a throttle: Google's remedy
    /// for the daily quota is a console quota increase, not backoff, and the engine's
    /// `RETRY_CAP = 5` immediate sweeps (no eligibility clock) cannot wait out a daily quota;
    /// they only burn the budget and add provider pressure. This could become Transient only
    /// once a long-horizon deferred-retry state exists.
    LongHorizonQuota,
}

/// Which status family a recognized reason belongs to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Home {
    /// Exactly this status.
    Status(u16),
    /// Any 5xx.
    ServerError,
    /// The throttle family: Gmail documents the short-horizon rate-limit reasons at both 403 and
    /// 429, so either status is a compatible home for them.
    Throttle,
}

impl Home {
    fn admits(self, status: u16) -> bool {
        match self {
            Home::Status(expected) => status == expected,
            Home::ServerError => (500..600).contains(&status),
            Home::Throttle => status == 403 || status == 429,
        }
    }
}

/// The legacy envelope's `reason` vocabulary (Gmail's error guide). The rate-limit rows
/// additionally require `domain: "usageLimits"` (the guide's quota grouping), so a rate-limit
/// reason under any other domain is not taken as a throttle.
fn legacy_reason(domain: Option<&str>, reason: &str) -> Option<(Home, Refinement)> {
    let usage_limits = domain == Some("usageLimits");
    match reason {
        "backendError" => Some((Home::ServerError, Refinement::Backend)),
        "rateLimitExceeded" | "userRateLimitExceeded" if usage_limits => {
            Some((Home::Throttle, Refinement::RateLimit))
        }
        "dailyLimitExceeded" if usage_limits => {
            Some((Home::Status(403), Refinement::LongHorizonQuota))
        }
        "insufficientPermissions" | "forbidden" | "domainPolicy" | "accessNotConfigured" => {
            Some((Home::Status(403), Refinement::Forbidden))
        }
        "authError" => Some((Home::Status(401), Refinement::Unauthorized)),
        "notFound" => Some((Home::Status(404), Refinement::NotFound)),
        "invalidArgument" | "failedPrecondition" | "badRequest" => {
            Some((Home::Status(400), Refinement::InvalidArgument))
        }
        _ => None,
    }
}

/// The current envelope's canonical-code vocabulary (`google.rpc.Code` / AIP-193), read from the
/// top-level `status` and from `details[ErrorInfo].reason`. A reason outside this vocabulary is
/// `Unrecognized` (the space is vendor-controlled and unbounded); at 403 that fails closed.
fn canonical_code(code: &str) -> Option<(Home, Refinement)> {
    match code {
        "UNAVAILABLE" | "INTERNAL" => Some((Home::ServerError, Refinement::Backend)),
        // AIP-193 represents resource exhaustion with HTTP 429. At 403 this is an incompatible
        // pair and falls to the fail-closed default; treating it as long-horizon would be an
        // interpretation the published contract doesn't support.
        "RESOURCE_EXHAUSTED" => Some((Home::Status(429), Refinement::RateLimit)),
        "PERMISSION_DENIED" => Some((Home::Status(403), Refinement::Forbidden)),
        "UNAUTHENTICATED" => Some((Home::Status(401), Refinement::Unauthorized)),
        "NOT_FOUND" => Some((Home::Status(404), Refinement::NotFound)),
        "INVALID_ARGUMENT" | "FAILED_PRECONDITION" => {
            Some((Home::Status(400), Refinement::InvalidArgument))
        }
        _ => None,
    }
}

/// Grade one reason, recognized or not, against the response status.
fn grade(status: u16, mapped: Option<(Home, Refinement)>) -> Entry {
    match mapped {
        Some((home, refinement)) if home.admits(status) => Entry::Refines(refinement),
        Some(_) => Entry::Incompatible,
        None => Entry::Unrecognized,
    }
}

// The envelope shapes below are typed rather than probed out of a `serde_json::Value` tree.
//
// `Value` resolves a duplicate object member silently, last-key-wins. Probed:
// `{"domain":"global","reason":"forbidden","domain":"usageLimits","reason":"rateLimitExceeded"}`
// classified as `RateLimit`/Transient, and the same two members in the opposite order as
// `Forbidden`/Deterministic, so a hostile or malformed body could pick its own classification by
// key order. The same exploit across the entry array is covered by mixed-order test fixtures.
//
// A serde-derived struct rejects a repeated member of a field it knows (`duplicate field ...`),
// which closes the class without a hand-rolled scan. `deny_unknown_fields` does not do this (it
// is about unknown keys) and would also reject legitimate forward-compatible fields Google may
// add. Unknown members stay ignored; only members that can change a verdict are typed.
//
// A body that is not JSON, carries no `error` object, or carries a repeated or mistyped relevant
// member yields no entries, and at 403 (the only status that consults the body) no entries means
// the fail-closed default. Strict parsing therefore fails in the safe direction.

/// The outer wrapper. `error` is required; a repeated `error` member is itself rejected.
#[derive(Deserialize)]
struct ErrorEnvelope {
    error: ErrorBody,
}

/// Both envelope shapes at once: a response carries the legacy `errors[]`, or the current
/// `status`/`details[]`, and each is graded on its own contract (see the module doc).
#[derive(Deserialize)]
struct ErrorBody {
    /// The envelope's own statement of the HTTP status, present in both shapes. It is read only
    /// to check that the envelope agrees with itself (see [`entries`]); it never selects a
    /// family, the transport-level status does.
    #[serde(default)]
    code: Option<i64>,
    /// Legacy envelope.
    #[serde(default)]
    errors: Option<Vec<LegacyErrorItem>>,
    /// Current envelope: the canonical code, carried as the top-level `status`.
    #[serde(default)]
    status: Option<String>,
    /// Current envelope: typed detail payloads.
    #[serde(default)]
    details: Option<Vec<ErrorDetail>>,
}

/// One `error.errors[]` member. `message`, `location`, `locationType` and anything else are
/// untyped: provider prose is never read (ADR-P003/P004).
#[derive(Deserialize)]
struct LegacyErrorItem {
    #[serde(default)]
    domain: Option<String>,
    #[serde(default)]
    reason: Option<String>,
}

/// One `error.details[]` member. Only `google.rpc.ErrorInfo` members (selected by `@type`) carry
/// classification meaning.
#[derive(Deserialize)]
struct ErrorDetail {
    #[serde(rename = "@type", default)]
    type_url: Option<String>,
    #[serde(default)]
    reason: Option<String>,
    /// Typed only so that a repeated `domain` member fails the envelope closed via serde's
    /// duplicate-field rejection (untyped, a duplicate would be silently ignored). Never consulted
    /// for a verdict: `ErrorInfo.domain` is a service namespace (AIP-193), distinct from the
    /// legacy `usageLimits` grouping. The leading underscore means "reject duplicates, read
    /// nothing."
    #[serde(rename = "domain", default)]
    _domain: Option<String>,
}

impl ErrorDetail {
    /// Is this member a `google.rpc.ErrorInfo`? Other detail types (`RetryInfo`, `Help`,
    /// `LocalizedMessage`, …) are ignored.
    fn is_error_info(&self) -> bool {
        self.type_url
            .as_deref()
            .is_some_and(|t| t.ends_with("google.rpc.ErrorInfo"))
    }
}

/// Collect every typed entry both envelopes carry, graded against the status. Never just the
/// first: first-match is exploitable by ordering (a 403 whose `errors[0]` is a throttle and whose
/// `errors[1]` is `global/forbidden` would turn a deterministic refusal into a retry loop purely
/// by array order). A body that is not JSON, carries no `error` object, or repeats a relevant
/// member yields no entries, and the caller falls back to the status family.
///
/// # The envelope must agree with itself
///
/// Both Google envelopes restate the HTTP status as `error.code`. This is called only at 403, the
/// one row where a body can move the verdict (including into a retry), so a `code` that is
/// missing, mistyped, or different from the transport-level status makes the response internally
/// inconsistent, and a single dominating [`Entry::Incompatible`] fails the whole envelope closed.
/// (An outer HTTP 403 carrying `error.code: 401` plus `usageLimits/rateLimitExceeded` would
/// otherwise classify as a transient `RateLimit`.) The `code` never selects a family, so this is
/// a precondition on refinement, not a second body-first precedence rule.
fn entries(status: u16, body: &str) -> Vec<Entry> {
    let Ok(envelope) = serde_json::from_str::<ErrorEnvelope>(body) else {
        return Vec::new();
    };
    let error = envelope.error;
    if error.code != Some(i64::from(status)) {
        return vec![Entry::Incompatible];
    }
    let mut out = Vec::new();
    // Legacy envelope: every `errors[]` member.
    for item in error.errors.iter().flatten() {
        // A member with no readable `reason` is an entry we cannot grade, not silence.
        let entry = match item.reason.as_deref() {
            Some(reason) => grade(status, legacy_reason(item.domain.as_deref(), reason)),
            None => Entry::Unrecognized,
        };
        out.push(entry);
    }
    // Current envelope: the top-level canonical `status`.
    //
    // At 403, "PERMISSION_DENIED" (`google.rpc.Code`) merely restates the status line, and
    // Google's transitional envelope stamps it beside a legacy `errors[]` whose reason is the
    // actual refinement. Counting the restatement as a vote forced a documented hybrid throttle
    // (`usageLimits/rateLimitExceeded` + `status:"PERMISSION_DENIED"`) into the contradictory
    // bucket and dead-lettered a retryable refusal. The restatement therefore votes only when it
    // is the sole refinement source: alone, it refines the bare 403 to `Forbidden`; beside any
    // specific refinement (a legacy entry or an `ErrorInfo`) it is a self-consistency datum,
    // already checked via `error.code` above. A non-restating `status` is a real claim and
    // votes (or fails closed) as usual, so a hostile body gains nothing, and every dominance
    // rule (duplicates, order-independence, unrecognized, incompatible) is unchanged.
    let error_info_present = error
        .details
        .as_deref()
        .is_some_and(|list| list.iter().any(|d| d.is_error_info()));
    if let Some(code) = error.status.as_deref() {
        let restates_the_403 = status == 403 && code == "PERMISSION_DENIED";
        if !restates_the_403 || (out.is_empty() && !error_info_present) {
            out.push(grade(status, canonical_code(code)));
        }
    }
    // Current envelope: `details[]`, ErrorInfo members only.
    if let Some(list) = error.details.as_deref() {
        let infos: Vec<&ErrorDetail> = list.iter().filter(|d| d.is_error_info()).collect();
        match infos.len() {
            0 => {}
            1 => {
                let entry = match infos[0].reason.as_deref() {
                    Some(reason) => grade(status, canonical_code(reason)),
                    None => Entry::Unrecognized,
                };
                out.push(entry);
            }
            // AIP-193: each detail payload type appears at most once, so two `ErrorInfo` members
            // is a non-conforming envelope. Reject it rather than picking one.
            _ => out.push(Entry::Unrecognized),
        }
    }
    out
}

/// The family the HTTP status alone determines, used when no typed entry refines it. `pub(crate)`
/// so the transport's unreadable-body paths (over-cap, invalid UTF-8) fall back to the same
/// status-first rule.
pub(crate) fn status_family(status: u16) -> GmailError {
    match status {
        429 => GmailError::RateLimit,
        500..=599 => GmailError::Backend(status),
        401 => GmailError::Unauthorized,
        404 => GmailError::NotFound,
        400 => GmailError::InvalidArgument,
        // 403 with nothing to refine it, 3xx (redirects are refused, so terminal), and every
        // other status fail closed.
        _ => GmailError::Unknown,
    }
}

/// Build the [`GmailError`] a refinement names at this status.
fn refined(status: u16, refinement: Refinement) -> GmailError {
    match refinement {
        Refinement::RateLimit => GmailError::RateLimit,
        Refinement::Backend => GmailError::Backend(status),
        Refinement::Forbidden => GmailError::Forbidden,
        Refinement::Unauthorized => GmailError::Unauthorized,
        Refinement::NotFound => GmailError::NotFound,
        Refinement::InvalidArgument => GmailError::InvalidArgument,
        Refinement::LongHorizonQuota => GmailError::Unknown,
    }
}

/// Normalize a completed non-2xx HTTP exchange into the engine's [`GmailError`] taxonomy.
///
/// `body` must already have been checked against the caller's byte cap; this function is pure and
/// performs no I/O.
///
/// # Body dominance is confined to the 403 row
///
/// 1. **Where the status determines the family, it returns before any entry is inspected.**
///    Fail-closed dominance exists to stop a hostile body from upgrading a hard failure into a
///    retry. Applied at a status the HTTP code already decides, it could only downgrade: a
///    legitimately transient 5xx would become a permanent dead-letter on a stale, wrong or
///    hostile reason string (`HTTP 503` + `authError` must stay retryable; see
///    `an_incompatible_entry_never_downgrades_a_status_determined_family`). Unrecognized and
///    contradictory reasons are treated alike here, since there is nothing at a
///    status-determined row for either to contradict.
/// 2. **At 403, transient requires unanimity.** Every entry must refine to the same verdict; any
///    ungradeable, non-conforming or incompatible entry dominates and the whole envelope fails
///    closed. An incompatible pair disagrees with the status family, so neither half of the
///    response can be trusted. Unanimity is order-independent, so array ordering is not
///    exploitable.
pub fn map_error_response(status: u16, body: &str) -> GmailError {
    // (1) Status-determined families need no refinement and must not be downgraded by one; the
    // body is never parsed on this path.
    if status != 403 {
        return status_family(status);
    }
    // (2) The 403 row: unanimous refinement, or fail closed. `Entry::Incompatible` and
    // `Entry::Unrecognized` both fall to the dominating arm.
    let mut verdict: Option<Refinement> = None;
    for entry in &entries(status, body) {
        match entry {
            Entry::Refines(refinement) if verdict.is_none() || verdict == Some(*refinement) => {
                verdict = Some(*refinement);
            }
            _ => return GmailError::Unknown,
        }
    }
    verdict.map_or(GmailError::Unknown, |r| refined(status, r))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aruna::gmail::classify_gmail_error;
    use aruna::FailureKind;

    // ============================================================================================
    // FIXTURE PROVENANCE — the two kinds are split and labelled (design §4).
    //
    // CONFORMANCE fixtures reproduce the envelope SHAPES Google publishes: the legacy shape
    // `{"error":{"code","errors":[{"domain","reason","message"}],"message"}}` from the Gmail API
    // "resolve errors" guide, and the current shape
    // `{"error":{"code","message","status","details":[{"@type":".../google.rpc.ErrorInfo",…}]}}`
    // from google.rpc / AIP-193. Authoring a conformance fixture in the shape one's
    // own parser assumes is the fake-grading-its-own-homework failure — these carry the SHAPE
    // claims, so they follow the sources, not the parser.
    //
    // ADVERSARIAL fixtures (incompatible status/reason pairs, duplicate ErrorInfo, malformed and
    // truncated bodies, ordering permutations) are EXPLICITLY AUTHORED and labelled as such. That
    // is correct here: no well-behaved server emits them, so no official source can supply them.
    // ============================================================================================

    /// CONFORMANCE shape — legacy envelope (Gmail "resolve errors" guide).
    fn legacy(code: u16, entries: &[(&str, &str)]) -> String {
        let items: Vec<String> = entries
            .iter()
            .map(|(domain, reason)| {
                format!(
                    r#"{{"domain":"{domain}","reason":"{reason}","message":"Provider prose that must never be read","location":"Authorization","locationType":"header"}}"#
                )
            })
            .collect();
        format!(
            r#"{{"error":{{"code":{code},"errors":[{}],"message":"Provider prose that must never be read"}}}}"#,
            items.join(",")
        )
    }

    /// CONFORMANCE shape — current envelope with only the canonical top-level `status` (a real and
    /// common shape: `details` is optional).
    fn current(code: u16, status: &str) -> String {
        format!(
            r#"{{"error":{{"code":{code},"message":"Provider prose that must never be read","status":"{status}"}}}}"#
        )
    }

    /// CONFORMANCE shape — current envelope carrying `google.rpc.ErrorInfo` details.
    fn current_with_details(code: u16, status: &str, details: &str) -> String {
        format!(
            r#"{{"error":{{"code":{code},"message":"Provider prose that must never be read","status":"{status}","details":[{details}]}}}}"#
        )
    }

    fn error_info(reason: &str) -> String {
        format!(
            r#"{{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"{reason}","domain":"googleapis.com","metadata":{{"service":"gmail.googleapis.com"}}}}"#
        )
    }

    fn kind(status: u16, body: &str) -> FailureKind {
        classify_gmail_error(&map_error_response(status, body))
    }

    // ---- legacy envelope, status-determined families ----

    #[test]
    fn http_429_is_a_transient_rate_limit() {
        // The row that alone closes the real short-horizon throttle family — no reason consulted.
        let body = legacy(429, &[("usageLimits", "rateLimitExceeded")]);
        assert_eq!(map_error_response(429, &body), GmailError::RateLimit);
        assert_eq!(map_error_response(429, ""), GmailError::RateLimit);
        assert_eq!(kind(429, &body), FailureKind::Transient);
    }

    #[test]
    fn http_5xx_backend_error_is_transient_and_carries_the_status() {
        for status in [500u16, 502, 503] {
            let body = legacy(status, &[("global", "backendError")]);
            assert_eq!(
                map_error_response(status, &body),
                GmailError::Backend(status)
            );
            assert_eq!(kind(status, &body), FailureKind::Transient);
        }
    }

    #[test]
    fn http_401_is_unauthorized_and_http_404_is_not_found() {
        let unauth = legacy(401, &[("global", "authError")]);
        assert_eq!(map_error_response(401, &unauth), GmailError::Unauthorized);
        assert_eq!(map_error_response(401, ""), GmailError::Unauthorized);
        let missing = legacy(404, &[("global", "notFound")]);
        assert_eq!(map_error_response(404, &missing), GmailError::NotFound);
        assert_eq!(kind(404, &missing), FailureKind::Deterministic);
    }

    #[test]
    fn http_400_family_is_invalid_argument() {
        for reason in ["invalidArgument", "failedPrecondition", "badRequest"] {
            let body = legacy(400, &[("global", reason)]);
            assert_eq!(
                map_error_response(400, &body),
                GmailError::InvalidArgument,
                "400 reason {reason}"
            );
        }
        assert_eq!(map_error_response(400, ""), GmailError::InvalidArgument);
    }

    // ---- the 403 row: the ONLY place the body refines the family ----

    #[test]
    fn legacy_403_short_horizon_throttle_reasons_are_transient() {
        for reason in ["rateLimitExceeded", "userRateLimitExceeded"] {
            let body = legacy(403, &[("usageLimits", reason)]);
            assert_eq!(
                map_error_response(403, &body),
                GmailError::RateLimit,
                "403 usageLimits/{reason} is the documented back-off family"
            );
            assert_eq!(kind(403, &body), FailureKind::Transient);
        }
    }

    #[test]
    fn legacy_403_daily_limit_exceeded_is_deterministic_not_a_throttle() {
        // The short-vs-long-horizon split, asserted against its sibling: the SAME status and the
        // SAME domain, and the two must not classify alike. Google's remedy for the daily family is
        // a console quota increase, not backoff.
        let daily = legacy(403, &[("usageLimits", "dailyLimitExceeded")]);
        let short = legacy(403, &[("usageLimits", "rateLimitExceeded")]);
        assert_eq!(map_error_response(403, &daily), GmailError::Unknown);
        assert_eq!(kind(403, &daily), FailureKind::Deterministic);
        assert_ne!(
            map_error_response(403, &daily),
            map_error_response(403, &short),
            "the long- and short-horizon 403 quota families must not collapse together"
        );
    }

    #[test]
    fn legacy_403_authorization_reasons_are_forbidden() {
        for reason in [
            "insufficientPermissions",
            "forbidden",
            "domainPolicy",
            "accessNotConfigured",
        ] {
            let body = legacy(403, &[("global", reason)]);
            assert_eq!(
                map_error_response(403, &body),
                GmailError::Forbidden,
                "403 {reason}"
            );
            assert_eq!(kind(403, &body), FailureKind::Deterministic);
        }
    }

    #[test]
    fn http_403_unrecognized_or_absent_body_fails_closed() {
        // ADVERSARIAL: a reason nobody has sourced. The fail-closed default is upheld — a novel
        // short-horizon reason is deterministic and VISIBLE, never a silent transient guess.
        let novel = legacy(403, &[("usageLimits", "someNovelThrottleReason")]);
        assert_eq!(map_error_response(403, &novel), GmailError::Unknown);
        assert_eq!(map_error_response(403, ""), GmailError::Unknown);
        assert_eq!(kind(403, &novel), FailureKind::Deterministic);
    }

    // ---- current envelope, parsed on its OWN contract ----

    #[test]
    fn current_envelope_canonical_codes_map_on_their_own_contract() {
        assert_eq!(
            map_error_response(403, &current(403, "PERMISSION_DENIED")),
            GmailError::Forbidden
        );
        assert_eq!(
            map_error_response(401, &current(401, "UNAUTHENTICATED")),
            GmailError::Unauthorized
        );
        assert_eq!(
            map_error_response(404, &current(404, "NOT_FOUND")),
            GmailError::NotFound
        );
        assert_eq!(
            map_error_response(400, &current(400, "INVALID_ARGUMENT")),
            GmailError::InvalidArgument
        );
        let unavailable = current(503, "UNAVAILABLE");
        assert_eq!(
            map_error_response(503, &unavailable),
            GmailError::Backend(503)
        );
        assert_eq!(kind(503, &unavailable), FailureKind::Transient);
    }

    #[test]
    fn current_envelope_resource_exhausted_at_403_is_deterministic() {
        // AIP-193 represents resource exhaustion with 429, so 403 + RESOURCE_EXHAUSTED is an
        // incompatible/unproven pairing and falls to the fail-closed default. Same outcome as a
        // "long-horizon" special rule would give, with a reason that is actually defensible.
        let body = current(403, "RESOURCE_EXHAUSTED");
        assert_eq!(map_error_response(403, &body), GmailError::Unknown);
        assert_eq!(kind(403, &body), FailureKind::Deterministic);
        // At its documented status it IS the throttle family.
        assert_eq!(
            map_error_response(429, &current(429, "RESOURCE_EXHAUSTED")),
            GmailError::RateLimit
        );
    }

    #[test]
    fn current_envelope_error_info_reason_outside_the_sourced_vocabulary_fails_closed_at_403() {
        // CONFORMANCE shape, real-world reason: Google's live ErrorInfo reasons (e.g.
        // ACCESS_TOKEN_SCOPE_INSUFFICIENT) are a service-scoped vocabulary this design deliberately
        // does NOT enumerate. At 403 an unsourced reason dominates → deterministic and visible.
        let body = current_with_details(
            403,
            "PERMISSION_DENIED",
            &error_info("ACCESS_TOKEN_SCOPE_INSUFFICIENT"),
        );
        assert_eq!(kind(403, &body), FailureKind::Deterministic);
    }

    #[test]
    fn non_error_info_details_members_are_ignored() {
        // A RetryInfo detail carries no classification meaning here; the ErrorInfo beside it decides.
        let details = format!(
            r#"{{"@type":"type.googleapis.com/google.rpc.RetryInfo","retryDelay":"30s"}},{}"#,
            error_info("PERMISSION_DENIED")
        );
        let body = current_with_details(403, "PERMISSION_DENIED", &details);
        assert_eq!(map_error_response(403, &body), GmailError::Forbidden);
    }

    #[test]
    fn duplicate_error_info_details_fail_closed() {
        // ADVERSARIAL: AIP-193 says each detail payload type appears at most once, so two ErrorInfo
        // members is a non-conforming envelope — reject it rather than picking one.
        let details = format!(
            "{},{}",
            error_info("PERMISSION_DENIED"),
            error_info("PERMISSION_DENIED")
        );
        let body = current_with_details(403, "PERMISSION_DENIED", &details);
        assert_eq!(map_error_response(403, &body), GmailError::Unknown);
        assert_eq!(kind(403, &body), FailureKind::Deterministic);
    }

    #[test]
    fn a_duplicate_domain_member_inside_error_info_fails_closed() {
        // Regression test: `ErrorDetail` typed `@type` and `reason` but not
        // `domain`, so a repeated `domain` member was silently IGNORED (an unknown key passes
        // through) instead of failing the envelope closed — the one member of the typed
        // `ErrorInfo.reason|domain` contract the earlier version left untyped. With `domain` typed, serde's
        // duplicate-field rejection covers it like every other relevant key, and the otherwise
        // self-consistent PERMISSION_DENIED envelope may no longer refine to `Forbidden`.
        let body = r#"{"error":{"code":403,"status":"PERMISSION_DENIED","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"PERMISSION_DENIED","domain":"first.example","domain":"second.example"}]}}"#;
        assert_eq!(map_error_response(403, body), GmailError::Unknown);
        assert_eq!(kind(403, body), FailureKind::Deterministic);
    }

    // ---- entry-array aggregation ----

    /// The same object with its duplicate members in BOTH orders — the object-key analogue of the
    /// array-order fixtures below. ADVERSARIAL and explicitly authored: no well-behaved server
    /// emits a duplicate member.
    fn legacy_with_duplicate_reason(first: (&str, &str), second: (&str, &str)) -> String {
        format!(
            r#"{{"error":{{"code":403,"errors":[{{"domain":"{}","reason":"{}","domain":"{}","reason":"{}"}}],"message":"prose"}}}}"#,
            first.0, first.1, second.0, second.1
        )
    }

    #[test]
    fn duplicate_object_members_fail_closed_and_are_order_independent() {
        // Regression test. `serde_json::Value` takes the LAST
        // duplicate member silently, so reversing the two `reason` fields flipped a 403 between
        // `RateLimit` (Transient) and `Forbidden` (Deterministic) — the same order-exploitability
        // §4 already forbids across the entry ARRAY, one level down at the object key.
        let throttle_last = legacy_with_duplicate_reason(
            ("global", "forbidden"),
            ("usageLimits", "rateLimitExceeded"),
        );
        let throttle_first = legacy_with_duplicate_reason(
            ("usageLimits", "rateLimitExceeded"),
            ("global", "forbidden"),
        );
        assert_eq!(
            map_error_response(403, &throttle_last),
            map_error_response(403, &throttle_first),
            "duplicate object members must never change classification by order"
        );
        // …and the honest verdict for a member we cannot read unambiguously is fail-closed, not a
        // pick. A duplicate key is a non-conforming envelope.
        for body in [&throttle_last, &throttle_first] {
            assert_eq!(map_error_response(403, body), GmailError::Unknown);
            assert_eq!(kind(403, body), FailureKind::Deterministic);
        }
        // Every relevant key, in both envelopes — including the one that would otherwise let a
        // hostile body pick its own classification.
        for body in [
            r#"{"error":{"code":403,"status":"PERMISSION_DENIED","status":"PERMISSION_DENIED"}}"#,
            r#"{"error":{"code":403,"errors":[{"domain":"global","reason":"forbidden"}],"errors":[{"domain":"usageLimits","reason":"rateLimitExceeded"}]}}"#,
            r#"{"error":{"code":403,"status":"PERMISSION_DENIED","details":[],"details":[]}}"#,
            r#"{"error":{"code":403},"error":{"code":403,"status":"PERMISSION_DENIED"}}"#,
        ] {
            assert_eq!(
                map_error_response(403, body),
                GmailError::Unknown,
                "a duplicate member must fail closed: {body}"
            );
        }
    }

    #[test]
    fn a_403_whose_embedded_code_does_not_agree_with_the_status_fails_closed() {
        // Regression test for an embedded `error.code` that disagrees with the status. The 403 row is the ONE place a body is
        // allowed to move the verdict — including into a RETRY — so the envelope must at minimum
        // agree with itself about what happened. The probe: outer HTTP 403 carrying
        // `error.code: 401` plus `usageLimits/rateLimitExceeded` returned transient `RateLimit`
        // from a self-contradictory envelope. A response that cannot state its own status
        // consistently has not earned the one upgrade this normalizer grants.
        let mismatched = r#"{"error":{"code":401,"errors":[{"domain":"usageLimits","reason":"rateLimitExceeded"}]}}"#;
        assert_eq!(map_error_response(403, mismatched), GmailError::Unknown);
        assert_eq!(kind(403, mismatched), FailureKind::Deterministic);

        // Missing, mistyped, and every other disagreeing shape fail closed alike — the throttle
        // reason inside each of these is the documented back-off family, so a lenient reading
        // would make all of them retryable.
        for body in [
            // Absent
            r#"{"error":{"errors":[{"domain":"usageLimits","reason":"rateLimitExceeded"}]}}"#,
            // Mistyped: a string, a float, a bool, null
            r#"{"error":{"code":"403","errors":[{"domain":"usageLimits","reason":"rateLimitExceeded"}]}}"#,
            r#"{"error":{"code":403.0,"errors":[{"domain":"usageLimits","reason":"rateLimitExceeded"}]}}"#,
            r#"{"error":{"code":true,"errors":[{"domain":"usageLimits","reason":"rateLimitExceeded"}]}}"#,
            r#"{"error":{"code":null,"errors":[{"domain":"usageLimits","reason":"rateLimitExceeded"}]}}"#,
            // Mismatched, both directions
            r#"{"error":{"code":429,"errors":[{"domain":"usageLimits","reason":"rateLimitExceeded"}]}}"#,
            r#"{"error":{"code":200,"errors":[{"domain":"usageLimits","reason":"rateLimitExceeded"}]}}"#,
            // Duplicate — the last-key-wins class, on the member that now decides admissibility
            r#"{"error":{"code":403,"code":403,"errors":[{"domain":"usageLimits","reason":"rateLimitExceeded"}]}}"#,
            // …and the current envelope is held to the same rule.
            r#"{"error":{"code":401,"status":"PERMISSION_DENIED"}}"#,
        ] {
            assert_eq!(
                map_error_response(403, body),
                GmailError::Unknown,
                "a 403 whose embedded code does not agree must fail closed: {body}"
            );
            assert_eq!(kind(403, body), FailureKind::Deterministic, "{body}");
        }

        // The AGREEING envelope still refines, or the rule would have closed the 403 row entirely
        // and silently deleted the 403 disambiguation.
        let agreeing = legacy(403, &[("usageLimits", "rateLimitExceeded")]);
        assert_eq!(map_error_response(403, &agreeing), GmailError::RateLimit);
        assert_eq!(kind(403, &agreeing), FailureKind::Transient);
    }

    #[test]
    fn array_order_never_changes_the_classification() {
        // ADVERSARIAL (the discriminating one): the SAME two typed entries in BOTH orders. A
        // first-match implementation returns RateLimit for one order and a deterministic verdict for
        // the other — a hostile or merely malformed body would downgrade a deterministic refusal
        // into a retry loop purely by array ordering.
        let throttle_first = legacy(
            403,
            &[("usageLimits", "rateLimitExceeded"), ("global", "forbidden")],
        );
        let forbidden_first = legacy(
            403,
            &[("global", "forbidden"), ("usageLimits", "rateLimitExceeded")],
        );
        assert_eq!(
            map_error_response(403, &throttle_first),
            map_error_response(403, &forbidden_first),
            "array order must never change classification"
        );
        assert_eq!(
            kind(403, &throttle_first),
            FailureKind::Deterministic,
            "a deterministic entry dominates a transient one, whatever the order"
        );
        assert_eq!(kind(403, &forbidden_first), FailureKind::Deterministic);
    }

    #[test]
    fn one_unknown_entry_dominates_an_otherwise_unanimous_transient_set_at_403() {
        // ADVERSARIAL: transient unanimity is the ONLY route to a transient 403, so a single
        // ungradeable entry is enough to fail the whole envelope closed.
        let unanimous = legacy(
            403,
            &[
                ("usageLimits", "rateLimitExceeded"),
                ("usageLimits", "userRateLimitExceeded"),
            ],
        );
        assert_eq!(kind(403, &unanimous), FailureKind::Transient);
        let poisoned = legacy(
            403,
            &[
                ("usageLimits", "rateLimitExceeded"),
                ("usageLimits", "userRateLimitExceeded"),
                ("usageLimits", "someNovelThrottleReason"),
            ],
        );
        assert_eq!(map_error_response(403, &poisoned), GmailError::Unknown);
        assert_eq!(kind(403, &poisoned), FailureKind::Deterministic);
    }

    #[test]
    fn an_unrecognized_reason_never_downgrades_a_status_determined_family() {
        // THE DISCRIMINATING TEST for the dominance SCOPE. Aggregation's fail-closed dominance
        // exists to stop a body from UPGRADING a hard failure into a retry. Applied uniformly it
        // would also DOWNGRADE a legitimately-transient 5xx into a permanent dead-letter — the exact
        // worst-mode the taxonomy exists to prevent, arriving through the machinery meant to prevent
        // it. Where the status alone determines the family there is nothing for an unknown reason to
        // contradict, so it changes nothing. An implementation that dominates uniformly fails here.
        let novel_5xx = legacy(503, &[("global", "someUnheardOfServerReason")]);
        assert_eq!(
            map_error_response(503, &novel_5xx),
            GmailError::Backend(503)
        );
        assert_eq!(
            kind(503, &novel_5xx),
            FailureKind::Transient,
            "a 5xx must stay retryable regardless of an unrecognized reason string"
        );
        let novel_429 = legacy(429, &[("global", "someUnheardOfThrottleReason")]);
        assert_eq!(kind(429, &novel_429), FailureKind::Transient);
        // …and the other direction still holds: at 403 the body IS consulted, so it dominates.
        let novel_403 = legacy(403, &[("usageLimits", "someUnheardOfThrottleReason")]);
        assert_eq!(kind(403, &novel_403), FailureKind::Deterministic);
    }

    // Tests for the restatement rule.
    // ONE #[test] PER ASSERTION: five assertions in a single test meant a failing first
    // assertion masked whether the other four still passed. Split, each case is self-evident.

    #[test]
    fn a_hybrid_throttle_with_a_restating_status_is_transient() {
        // Regression test. `google.rpc.Code` maps HTTP 403 to
        // PERMISSION_DENIED, and Google's transitional envelope stamps that restatement beside
        // the legacy `errors[]` member that carries the real refinement. Requiring the
        // restatement to AGREE with the specific refinement dead-lettered a documented,
        // well-formed hybrid throttle.
        let hybrid_throttle = r#"{"error":{"code":403,"errors":[{"domain":"usageLimits","reason":"rateLimitExceeded"}],"message":"prose","status":"PERMISSION_DENIED"}}"#;
        assert_eq!(map_error_response(403, hybrid_throttle), GmailError::RateLimit);
        assert_eq!(kind(403, hybrid_throttle), FailureKind::Transient);
    }

    #[test]
    fn a_hybrid_whose_halves_agree_stays_forbidden() {
        let hybrid_forbidden = r#"{"error":{"code":403,"errors":[{"domain":"global","reason":"forbidden"}],"status":"PERMISSION_DENIED"}}"#;
        assert_eq!(map_error_response(403, hybrid_forbidden), GmailError::Forbidden);
    }

    #[test]
    fn a_restating_status_alone_still_refines_to_forbidden() {
        // Alone, the restatement is the only refinement there is and still refines — the
        // standing behavior, re-asserted so the amendment cannot silently widen.
        let pure_canonical = r#"{"error":{"code":403,"status":"PERMISSION_DENIED"}}"#;
        assert_eq!(map_error_response(403, pure_canonical), GmailError::Forbidden);
    }

    #[test]
    fn a_non_restating_status_still_votes_and_fails_closed() {
        // A NON-restating status is a real claim, not a restatement: it still votes, and a
        // contradictory one still fails the envelope closed.
        let hostile_status = r#"{"error":{"code":403,"errors":[{"domain":"usageLimits","reason":"rateLimitExceeded"}],"status":"NOT_FOUND"}}"#;
        assert_eq!(map_error_response(403, hostile_status), GmailError::Unknown);
        assert_eq!(kind(403, hostile_status), FailureKind::Deterministic);
    }

    #[test]
    fn a_specific_error_info_conflict_is_not_a_restatement() {
        // A specific canonical refinement (ErrorInfo) is NOT a restatement — two specific
        // sources that disagree remain contradictory.
        let specific_conflict = r#"{"error":{"code":403,"errors":[{"domain":"usageLimits","reason":"rateLimitExceeded"}],"status":"PERMISSION_DENIED","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"PERMISSION_DENIED"}]}}"#;
        assert_eq!(map_error_response(403, specific_conflict), GmailError::Unknown);
    }

    #[test]
    fn a_legacy_style_reason_inside_error_info_fails_closed() {
        // Provenance-pinned conformance fixture : Google's own IAM documentation publishes a real 403 whose ErrorInfo
        // carries a legacy-style lowerCamel reason — `"reason":"forbidden","domain":"global"` —
        // inside the CURRENT envelope. `canonical_code` knows only the UPPER_SNAKE vocabulary, so
        // this grades Unrecognized and fails closed: behaviorally inert for the forbidden family
        // (both channels are Deterministic), and the honest fail-closed answer for an unsourced
        // vocabulary. Deliberately NOT silenced and NOT mapped: a legacy reason has no published
        // contract binding it to the HTTP status the way AIP-193 binds `status` to the code, so
        // mapping it would be exactly the unsourced interpretation `RESOURCE_EXHAUSTED` at 403
        // already refuses. The attended drill must observe real ErrorInfo.reason casing on the
        // wire before the vocabulary is assumed disjoint by channel.
        let iam_documented = r#"{"error":{"code":403,"status":"PERMISSION_DENIED","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"forbidden","domain":"global"}]}}"#;
        assert_eq!(map_error_response(403, iam_documented), GmailError::Unknown);
        assert_eq!(kind(403, iam_documented), FailureKind::Deterministic);
    }

    #[test]
    fn incompatible_pairs_fail_closed_within_403_and_only_there() {
        // CORRECTED. This test previously codified a STALE rule — "an
        // incompatible pair fails closed at ANY status" — which contradicts the standing ruling
        // that ALL body dominance is confined to the 403 row. The direction is the whole point:
        // dominance exists to stop a body UPGRADING a hard failure into a retry; applied at a
        // status the HTTP code already decides, it only DOWNGRADES (see the 5xx case below and
        // `an_incompatible_entry_never_downgrades_a_status_determined_family`).
        //
        // At 403 — the one row where the body is consulted at all — an incompatible pair still
        // fails closed: it positively disagrees with the status family, so neither half is
        // trustworthy.
        let forbidden_with_5xx_reason = legacy(403, &[("global", "backendError")]);
        assert_eq!(
            map_error_response(403, &forbidden_with_5xx_reason),
            GmailError::Unknown
        );
        assert_eq!(kind(403, &forbidden_with_5xx_reason), FailureKind::Deterministic);

        // …and at a status-determined family the SAME kind of contradictory body changes nothing:
        // the status decides, exactly as it does for an unrecognized reason.
        let unauth_with_backend = legacy(401, &[("global", "backendError")]);
        assert_eq!(
            map_error_response(401, &unauth_with_backend),
            GmailError::Unauthorized,
            "401 is status-determined; a contradictory body may not touch it"
        );
        let bad_request_with_throttle = legacy(400, &[("usageLimits", "rateLimitExceeded")]);
        assert_eq!(
            map_error_response(400, &bad_request_with_throttle),
            GmailError::InvalidArgument
        );
        // The safety direction is untouched: neither becomes RETRYABLE.
        for (status, body) in [
            (401, &unauth_with_backend),
            (400, &bad_request_with_throttle),
        ] {
            assert_eq!(kind(status, body), FailureKind::Deterministic);
        }
    }

    #[test]
    fn an_incompatible_entry_never_downgrades_a_status_determined_family() {
        // Regression test: HTTP 503 carrying
        // `authError`. A 503 is a server-side failure that lifts on retry, and the body — hostile,
        // stale, or merely wrong — must not be able to convert it into a permanent dead-letter.
        // Under the pre-fix code the incompatible-entry sweep ran BEFORE the `status != 403` guard
        // and returned `Unknown`/Deterministic here.
        let backend_with_auth_reason = legacy(503, &[("global", "authError")]);
        assert_eq!(
            map_error_response(503, &backend_with_auth_reason),
            GmailError::Backend(503),
            "a 5xx must stay a 5xx whatever the body claims"
        );
        assert_eq!(
            kind(503, &backend_with_auth_reason),
            FailureKind::Transient,
            "an incompatible body must never dead-letter a retryable server error"
        );
        // Same law across the other status-determined rows, in both envelopes.
        assert_eq!(
            map_error_response(429, &legacy(429, &[("global", "notFound")])),
            GmailError::RateLimit
        );
        assert_eq!(
            map_error_response(500, &current(500, "PERMISSION_DENIED")),
            GmailError::Backend(500)
        );
        assert_eq!(
            map_error_response(404, &legacy(404, &[("global", "backendError")])),
            GmailError::NotFound
        );
    }

    #[test]
    fn a_hostile_body_can_never_upgrade_a_hard_failure_into_a_retry() {
        // The precedence law, stated as a test: v1's "reason first, status fallback" model let a
        // 401 carrying `backendError` become a retry. Status selects the family — always.
        for status in [400u16, 401, 403, 404] {
            let hostile = legacy(status, &[("usageLimits", "rateLimitExceeded")]);
            let verdict = kind(status, &hostile);
            if status == 403 {
                continue; // 403 IS the refinement row — covered by its own tests above.
            }
            assert_eq!(
                verdict,
                FailureKind::Deterministic,
                "status {status} must not be downgraded to a retry by a body"
            );
        }
    }

    // ---- 3xx, malformed, and the no-provider-text guarantee ----

    #[test]
    fn a_3xx_is_terminal_and_deterministic() {
        // Redirects are refused outright (design §3.1a), so a 3xx arrives as a completed response
        // and is a terminal failure — never followed, never retried.
        for status in [301u16, 302, 307, 308] {
            assert_eq!(map_error_response(status, ""), GmailError::Unknown);
            assert_eq!(kind(status, ""), FailureKind::Deterministic);
        }
    }

    #[test]
    fn malformed_empty_and_truncated_bodies_fall_back_to_the_status_family() {
        // ADVERSARIAL: never a guess. A body we cannot read tells us nothing, so the status decides.
        let truncated = r#"{"error":{"code":503,"errors":[{"domain":"global","reas"#;
        for body in ["", "not json at all", "null", "{}", r#"{"error":{}}"#, truncated] {
            assert_eq!(
                map_error_response(503, body),
                GmailError::Backend(503),
                "malformed body {body:?} must fall back to the 503 family"
            );
            assert_eq!(map_error_response(403, body), GmailError::Unknown);
        }
    }

    #[test]
    fn no_provider_text_is_ever_carried_into_the_normalized_error() {
        // Confinement by construction: only typed fields are read, so provider prose cannot ride
        // along even in Debug output.
        let leak = "Provider prose that must never be read";
        for (status, body) in [
            (403, legacy(403, &[("global", "insufficientPermissions")])),
            (500, legacy(500, &[("global", "backendError")])),
            (
                403,
                current_with_details(403, "PERMISSION_DENIED", &error_info("PERMISSION_DENIED")),
            ),
        ] {
            let rendered = format!("{:?}", map_error_response(status, &body));
            assert!(
                !rendered.contains(leak) && !rendered.contains("gmail.googleapis.com"),
                "provider text leaked into the normalized error: {rendered}"
            );
        }
    }
}
