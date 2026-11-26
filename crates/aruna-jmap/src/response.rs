//! Parsing JMAP response envelopes into success or a typed [`aruna::jmap::JmapError`]. An HTTP-200
//! whose `Email/set` puts our email in `notUpdated[id]` is a failure, and the per-record
//! `SetError.type` must reach the taxonomy. The `type` is deserialized as a string and routed
//! through [`crate::error`], so an unknown type maps to the deterministic `Unknown` bucket rather
//! than failing deserialization. Provider text (`description`) is never carried into the
//! `JmapError`.

use serde::Deserialize;

use aruna::jmap::JmapError;

use crate::error::{map_method_error, map_set_error};
use crate::transport::{correlate_account, wire_member_names_are_unique};

/// A JMAP response envelope (RFC 8620 §3.4): `methodResponses` is a list of `[name, args, callId]`.
#[derive(Debug, Deserialize)]
struct ResponseEnvelope {
    #[serde(rename = "methodResponses")]
    method_responses: Vec<(String, serde_json::Value, String)>,
}

/// Parse an `Email/set` response body and decide the outcome for `email_id`:
/// `Ok(())` if it was updated, `Err(JmapError)` if the method failed or the record is in
/// `notUpdated`. A malformed or empty envelope is a deterministic failure (fail closed).
///
/// Three correlations gate the outcome read, in order: the callId (does this tuple answer our
/// call?), the method name (is it an `Email/set` at all?), and the `accountId` (whose mailbox does
/// it describe? `transport::correlate_account`, RFC 8620 §5.1). Only past all three may `updated` /
/// `notUpdated` be read.
///
/// An account mismatch is observed post-dispatch: the provider processed the POST, so the
/// mutation may have applied. The verdict is "not proven applied", never "no provider effect"
/// and never a silent success. It lands in the same deterministic fail-closed family as
/// `__call_id_mismatch__` and `__record_not_in_response__`: visible, dead-lettered and not
/// retried, because re-dispatching a non-idempotent write with an unproven outcome risks a
/// duplicate (RFC 9110 §9.2.2; provider idempotency is not something we can assume).
pub fn parse_email_set_response(
    body: &str,
    email_id: &str,
    expected_call_id: &str,
    expected_account_id: &str,
) -> Result<(), JmapError> {
    // A body we can't parse is a deterministic failure, never a silent success.
    let envelope: ResponseEnvelope =
        serde_json::from_str(body).map_err(|_| map_method_error("__malformed_response__"))?;
    // Same raw-text uniqueness scan every method-response read uses. The deserialize above
    // already collapsed any duplicate member to the last copy, and the members this parse
    // decides on (`accountId`, `type`, `updated`, `notUpdated`) are the ones that turn an
    // unproven write into a confirmed one. Runs after the syntax parse so a non-JSON body keeps
    // its `__malformed_response__` verdict.
    wire_member_names_are_unique(body)?;
    let (name, args, call_id) = envelope
        .method_responses
        .first()
        .ok_or_else(|| map_method_error("__empty_response__"))?;

    // Correlate the response to our request before interpreting the tuple as an error or a
    // success. A tuple whose callId doesn't echo what we sent is misrouted or replayed and fails
    // closed; in particular a mismatched method-level `error` must not be accepted as our
    // (possibly transient) result and retried.
    if call_id.as_str() != expected_call_id {
        return Err(map_method_error("__call_id_mismatch__"));
    }
    // A method-level failure replaces the method response with `["error", {type}, callId]`.
    if name == "error" {
        let type_str = args.get("type").and_then(|v| v.as_str()).unwrap_or("");
        return Err(map_method_error(type_str));
    }
    // Only an actual `Email/set` result may confirm or refute the mutation; never trust a stray
    // `updated`.
    if name != "Email/set" {
        return Err(map_method_error("__unexpected_method_response__"));
    }
    // Then whose mailbox this outcome describes. An `updated[id]` scoped to another account is
    // not proof our account's message moved; fail closed (see the doc comment).
    correlate_account(args, expected_account_id)?;

    // The `Email/set` args carry per-record `updated` / `notUpdated`. Navigate the Value
    // directly (no struct deser) so extra fields never derail the outcome read.
    if let Some(entry) = args
        .get("notUpdated")
        .and_then(|v| v.as_object())
        .and_then(|m| m.get(email_id))
    {
        // `notUpdated` on an HTTP-200 is a failure: map the typed SetError, drop the description.
        let type_str = entry.get("type").and_then(|v| v.as_str()).unwrap_or("");
        return Err(map_set_error(type_str));
    }
    if args
        .get("updated")
        .and_then(|v| v.as_object())
        .is_some_and(|m| m.contains_key(email_id))
    {
        return Ok(());
    }
    // The record appears in neither map: not proven applied. Fail closed.
    Err(map_method_error("__record_not_in_response__"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aruna::jmap::{classify_jmap_error, SetError};
    use aruna::FailureKind;

    fn ok_updated(id: &str) -> String {
        format!(r#"{{"methodResponses":[["Email/set",{{"accountId":"a","updated":{{"{id}":null}}}},"c0"]]}}"#)
    }

    #[test]
    fn updated_record_is_success() {
        assert!(parse_email_set_response(&ok_updated("eml-1"), "eml-1", "c0", "a").is_ok());
    }

    #[test]
    fn not_updated_with_typed_set_error_is_a_deterministic_failure() {
        // The load-bearing case: HTTP-200 but our record is in notUpdated -> failure, typed.
        let body = r#"{"methodResponses":[["Email/set",{"accountId":"a","notUpdated":{"eml-1":{"type":"notFound","description":"SECRET-PROVIDER-ID-xyz"}}},"c0"]]}"#;
        let err = parse_email_set_response(body, "eml-1", "c0", "a").expect_err("notUpdated -> Err");
        assert_eq!(classify_jmap_error(&err), FailureKind::Deterministic);
        // Confinement by construction: JmapError is a pure typed enum with NO free-text field, so
        // the provider `description` cannot ride along — only the typed kind survives.
        assert_eq!(err, JmapError::Set(SetError::NotFound));
    }

    #[test]
    fn unknown_set_error_type_routes_to_deterministic_unknown() {
        let body = r#"{"methodResponses":[["Email/set",{"accountId":"a","notUpdated":{"eml-1":{"type":"someFutureError"}}},"c0"]]}"#;
        let err =
            parse_email_set_response(body, "eml-1", "c0", "a").expect_err("unknown -> Err");
        assert_eq!(classify_jmap_error(&err), FailureKind::Deterministic);
    }

    #[test]
    fn method_level_error_response_maps_via_method_taxonomy() {
        // A method-level failure replaces the method response with ["error", {type}, callId].
        let body = r#"{"methodResponses":[["error",{"type":"serverUnavailable"},"c0"]]}"#;
        let err = parse_email_set_response(body, "eml-1", "c0", "a").expect_err("method error -> Err");
        assert_eq!(classify_jmap_error(&err), FailureKind::Transient);

        let body = r#"{"methodResponses":[["error",{"type":"serverFail"},"c0"]]}"#;
        let err = parse_email_set_response(body, "eml-1", "c0", "a").expect_err("serverFail -> Err");
        assert_eq!(classify_jmap_error(&err), FailureKind::Deterministic);
    }

    #[test]
    fn method_level_error_under_a_mismatched_call_id_fails_closed_not_retried() {
        // A misrouted/replayed `["error", …]` whose callId is NOT ours must fail closed
        // (Deterministic) — never be accepted as our (transient) result and retried. The callId
        // correlation now runs BEFORE the `error` branch: `serverUnavailable`
        // would map to Transient on a MATCHED callId, but under the WRONG callId it is a misroute.
        let body = r#"{"methodResponses":[["error",{"type":"serverUnavailable"},"WRONG"]]}"#;
        let err = parse_email_set_response(body, "eml-1", "c0", "a").expect_err("misrouted error -> Err");
        assert_eq!(classify_jmap_error(&err), FailureKind::Deterministic);
    }

    #[test]
    fn malformed_envelope_fails_closed_deterministic() {
        let err = parse_email_set_response("not json", "eml-1", "c0", "a").expect_err("malformed -> Err");
        assert_eq!(classify_jmap_error(&err), FailureKind::Deterministic);
    }

    #[test]
    fn misrouted_method_response_name_fails_closed_even_with_an_updated_record() {
        // A misrouted/unexpected method name that happens to carry `updated[id]` must NOT be trusted
        // to confirm the mutation — only an actual `Email/set` result may.
        let body = r#"{"methodResponses":[["Foo/bar",{"updated":{"eml-1":null}},"c0"]]}"#;
        let err = parse_email_set_response(body, "eml-1", "c0", "a").expect_err("wrong method name -> Err");
        assert_eq!(classify_jmap_error(&err), FailureKind::Deterministic);
    }

    #[test]
    fn mismatched_call_id_fails_closed_even_with_an_updated_record() {
        // The response callId must correlate with the request's — a misrouted Email/set carrying
        // `updated[id]` under the WRONG callId must not falsely confirm the mutation.
        let body = r#"{"methodResponses":[["Email/set",{"updated":{"eml-1":null}},"WRONG"]]}"#;
        let err = parse_email_set_response(body, "eml-1", "c0", "a").expect_err("callId mismatch -> Err");
        assert_eq!(classify_jmap_error(&err), FailureKind::Deterministic);
    }

    #[test]
    fn a_foreign_account_id_never_confirms_the_write_and_is_not_proven_applied() {
        // The c47776d correlation class at the write path's parse. callId + method name prove the
        // tuple answers OUR CALL; neither proves WHOSE mailbox it describes. An `updated[id]` under
        // a foreign `accountId` is another account's record moving -- accepting it would report our
        // mutation as applied on evidence about someone else's mailbox.
        //
        // The response is POST-DISPATCH (the provider processed the request), so the honest verdict
        // is NOT PROVEN APPLIED: Deterministic, fail closed, never retried -- retrying an
        // ambiguously-applied non-idempotent write is the one outcome this family exists to prevent.
        let body = r#"{"methodResponses":[["Email/set",{"accountId":"ACCT-OTHER","updated":{"eml-1":null}},"c0"]]}"#;
        let err = parse_email_set_response(body, "eml-1", "c0", "a")
            .expect_err("foreign accountId -> Err");
        assert_eq!(classify_jmap_error(&err), FailureKind::Deterministic);
        // Absent is nonconforming too (RFC 8620 §5.1) -- same fail-closed answer.
        let absent = r#"{"methodResponses":[["Email/set",{"updated":{"eml-1":null}},"c0"]]}"#;
        let err = parse_email_set_response(absent, "eml-1", "c0", "a")
            .expect_err("absent accountId -> Err");
        assert_eq!(classify_jmap_error(&err), FailureKind::Deterministic);
    }

    #[test]
    fn a_duplicated_decision_member_never_confirms_the_write() {
        // The duplicate-member class at the write path. `serde_json::Value` keeps the LAST duplicate
        // member, so every member this parse BRANCHES on can have its decision flipped by a
        // duplicate the collapsed value never shows:
        //   * `notUpdated` repeated — the real per-record FAILURE in the first copy, an empty
        //     object in the last — collapses to empty, the parse falls through to `updated`, and a
        //     write the provider REFUSED is reported as applied;
        //   * `accountId` repeated — foreign first, ours last — correlates as ours;
        //   * `updated` repeated — a record absent from the first copy, present in the last.
        // A raw-text uniqueness scan on the decision members is what makes this a class closure
        // rather than two point fixes (RFC 8620 §1.1 / RFC 7493 §2.3: I-JSON names MUST be unique).
        for args in [
            r#"{"accountId":"a","notUpdated":{"eml-1":{"type":"forbidden"}},"updated":{"eml-1":null},"notUpdated":{}}"#,
            r#"{"accountId":"ACCT-OTHER","updated":{"eml-1":null},"accountId":"a"}"#,
            r#"{"accountId":"a","updated":{},"updated":{"eml-1":null}}"#,
        ] {
            let body = format!(r#"{{"methodResponses":[["Email/set",{args},"c0"]]}}"#);
            let err = parse_email_set_response(&body, "eml-1", "c0", "a")
                .expect_err("an ambiguous wire object must never confirm a non-idempotent write");
            assert_eq!(classify_jmap_error(&err), FailureKind::Deterministic);
        }
        // …and the conforming body still succeeds: the discipline must not refuse valid responses.
        assert!(parse_email_set_response(&ok_updated("eml-1"), "eml-1", "c0", "a").is_ok());
    }
}
