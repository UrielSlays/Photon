//! Wire to taxonomy error mapping. Each error layer's `type` string is mapped onto `aruna`'s
//! `JmapError`; an unrecognized type never fails deserialization but routes to the deterministic
//! `Unknown` bucket (RFC 8620: unknown must be treated as `serverFail`). The functions are pure.
//! Only the typed `type` (and, for a `limit`, the limit name) is consulted; provider
//! descriptions and details are never carried.

use aruna::jmap::{JmapError, MethodError, RequestError, RequestLimit, SetError, TransportError};

/// Map a JMAP request-level problem-details `type` (RFC 8620 §3.6.1, `urn:ietf:params:jmap:error:*`)
/// plus the optional `limit` property name onto a [`JmapError`].
pub fn map_request_problem(type_str: &str, limit: Option<&str>) -> JmapError {
    let kind = match type_str {
        "urn:ietf:params:jmap:error:limit" => RequestError::Limit(map_request_limit(limit)),
        "urn:ietf:params:jmap:error:unknownCapability" => RequestError::UnknownCapability,
        "urn:ietf:params:jmap:error:notJSON" => RequestError::NotJson,
        "urn:ietf:params:jmap:error:notRequest" => RequestError::NotRequest,
        _ => RequestError::Unknown,
    };
    JmapError::Request(kind)
}

fn map_request_limit(limit: Option<&str>) -> RequestLimit {
    match limit {
        Some("maxConcurrentRequests") => RequestLimit::MaxConcurrentRequests,
        Some("maxSizeRequest") => RequestLimit::MaxSizeRequest,
        Some("maxCallsInRequest") => RequestLimit::MaxCallsInRequest,
        _ => RequestLimit::Other,
    }
}

/// Map a JMAP method-level error `type` (RFC 8620 §3.6.2) onto a [`JmapError`]. Types
/// `aruna`'s taxonomy doesn't name (e.g. `requestTooLarge`, `cannotCalculateChanges`) fall through
/// to `MethodError::Unknown`, which is deterministic (fail closed).
pub fn map_method_error(type_str: &str) -> JmapError {
    let kind = match type_str {
        "serverUnavailable" => MethodError::ServerUnavailable,
        "rateLimit" => MethodError::RateLimit,
        "serverFail" => MethodError::ServerFail,
        "serverPartialFail" => MethodError::ServerPartialFail,
        "unknownMethod" => MethodError::UnknownMethod,
        "invalidArguments" => MethodError::InvalidArguments,
        "invalidResultReference" => MethodError::InvalidResultReference,
        "forbidden" => MethodError::Forbidden,
        "accountNotFound" => MethodError::AccountNotFound,
        "accountNotSupportedByMethod" => MethodError::AccountNotSupportedByMethod,
        "accountReadOnly" => MethodError::AccountReadOnly,
        "stateMismatch" => MethodError::StateMismatch,
        _ => MethodError::Unknown,
    };
    JmapError::Method(kind)
}

/// Map a per-record `SetError` `type` (RFC 8620 §5.3 + RFC 8621) onto a [`JmapError`]. Unrecognized
/// types fail closed to `SetError::Unknown` (deterministic).
pub fn map_set_error(type_str: &str) -> JmapError {
    let kind = match type_str {
        "rateLimit" => SetError::RateLimit,
        "notFound" => SetError::NotFound,
        "forbidden" => SetError::Forbidden,
        "invalidPatch" => SetError::InvalidPatch,
        "invalidProperties" => SetError::InvalidProperties,
        "tooLarge" => SetError::TooLarge,
        "singleton" => SetError::Singleton,
        "willDestroy" => SetError::WillDestroy,
        "overQuota" => SetError::OverQuota,
        "tooManyMailboxes" => SetError::TooManyMailboxes,
        "mailboxCounts" => SetError::MailboxCounts,
        _ => SetError::Unknown,
    };
    JmapError::Set(kind)
}

/// Map an HTTP status to a transport-layer [`JmapError`].
pub fn map_http_status(status: u16) -> JmapError {
    let kind = match status {
        408 => TransportError::Timeout,
        429 => TransportError::TooManyRequests,
        500..=599 => TransportError::ServerError(status),
        401 | 403 => TransportError::Unauthorized(status),
        _ => TransportError::ClientError(status),
    };
    JmapError::Transport(kind)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aruna::jmap::classify_jmap_error;
    use aruna::FailureKind;

    #[test]
    fn request_limit_subtypes_map_concurrency_transient_else_deterministic() {
        assert_eq!(
            map_request_problem("urn:ietf:params:jmap:error:limit", Some("maxConcurrentRequests")),
            JmapError::Request(RequestError::Limit(RequestLimit::MaxConcurrentRequests))
        );
        assert_eq!(
            map_request_problem("urn:ietf:params:jmap:error:limit", Some("maxSizeRequest")),
            JmapError::Request(RequestError::Limit(RequestLimit::MaxSizeRequest))
        );
        assert_eq!(
            map_request_problem("urn:ietf:params:jmap:error:limit", Some("somethingNew")),
            JmapError::Request(RequestError::Limit(RequestLimit::Other))
        );
    }

    #[test]
    fn known_request_problems_map_and_unknown_fails_closed() {
        assert_eq!(
            map_request_problem("urn:ietf:params:jmap:error:notJSON", None),
            JmapError::Request(RequestError::NotJson)
        );
        assert_eq!(
            map_request_problem("urn:ietf:params:jmap:error:unknownCapability", None),
            JmapError::Request(RequestError::UnknownCapability)
        );
        // An unrecognized urn → deterministic Unknown bucket.
        assert_eq!(
            map_request_problem("urn:ietf:params:jmap:error:somethingFuture", None),
            JmapError::Request(RequestError::Unknown)
        );
    }

    #[test]
    fn method_errors_map_with_unknown_routed_to_unknown_deterministic() {
        assert_eq!(
            map_method_error("serverFail"),
            JmapError::Method(MethodError::ServerFail)
        );
        assert_eq!(
            map_method_error("serverPartialFail"),
            JmapError::Method(MethodError::ServerPartialFail)
        );
        assert_eq!(
            map_method_error("serverUnavailable"),
            JmapError::Method(MethodError::ServerUnavailable)
        );
        assert_eq!(
            map_method_error("rateLimit"),
            JmapError::Method(MethodError::RateLimit)
        );
        // Jmap-client has no Other on MethodErrorType; we hand-roll, so an unknown method type goes
        // to the deterministic Unknown bucket instead of failing deserialization.
        let unknown = map_method_error("requestTooLarge");
        assert_eq!(unknown, JmapError::Method(MethodError::Unknown));
        assert_eq!(classify_jmap_error(&unknown), FailureKind::Deterministic);
    }

    #[test]
    fn set_errors_map_with_unknown_fail_closed() {
        assert_eq!(map_set_error("notFound"), JmapError::Set(SetError::NotFound));
        assert_eq!(map_set_error("rateLimit"), JmapError::Set(SetError::RateLimit));
        assert_eq!(map_set_error("overQuota"), JmapError::Set(SetError::OverQuota));
        assert_eq!(
            map_set_error("tooManyMailboxes"),
            JmapError::Set(SetError::TooManyMailboxes)
        );
        let unknown = map_set_error("mailboxHasChild");
        assert_eq!(unknown, JmapError::Set(SetError::Unknown));
        assert_eq!(classify_jmap_error(&unknown), FailureKind::Deterministic);
    }

    #[test]
    fn http_status_maps_to_transport_layer() {
        assert_eq!(
            classify_jmap_error(&map_http_status(429)),
            FailureKind::Transient
        );
        assert_eq!(
            classify_jmap_error(&map_http_status(503)),
            FailureKind::Transient
        );
        assert_eq!(
            classify_jmap_error(&map_http_status(401)),
            FailureKind::Deterministic
        );
        assert_eq!(
            classify_jmap_error(&map_http_status(404)),
            FailureKind::Deterministic
        );
        // Exact variants
        assert_eq!(
            map_http_status(429),
            JmapError::Transport(TransportError::TooManyRequests)
        );
        assert_eq!(
            map_http_status(502),
            JmapError::Transport(TransportError::ServerError(502))
        );
    }

    #[test]
    fn http_408_request_timeout_is_a_transient_timeout_not_a_deterministic_client_error() {
        // A bare HTTP 408 (server/intermediary request-timeout) is recoverable — it must retry, not
        // dead-letter as a deterministic 4xx.
        assert_eq!(
            classify_jmap_error(&map_http_status(408)),
            FailureKind::Transient
        );
        assert_eq!(
            map_http_status(408),
            JmapError::Transport(TransportError::Timeout)
        );
    }
}
