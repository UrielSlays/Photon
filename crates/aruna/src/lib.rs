//! Aruna — the Photon engine: command bus, intent log, store, connectors.
//!
//! Named for the Vedic charioteer of the Sun (the engine that *drives* the light-surface
//! Photon). Internal type names stay dry/descriptive (ADR-P012); the codename lives at the
//! crate/component layer only.
//!
//! Pure logic, no UI/Tauri dependency, so it is fast and independent to test.
//! M0 proving slice: mail facet, archive action, over an in-memory log/connector first.

/// Declares a closed, durable token vocabulary: the enum, its `ALL` list, `as_token` and
/// `from_token`, all generated from one `Variant => "token"` list so the two directions
/// cannot drift and both matches stay exhaustive. A token spelled twice becomes an
/// unreachable `from_token` arm, which `-D warnings` refuses. Tokens are stored formats (a
/// refusal record's `detail` carries one), so each vocabulary's spellings are pinned by its
/// own test: re-spelling one would make existing records unreadable. Used by `plan.rs` and
/// `commitment.rs`.
macro_rules! closed_tokens {
    ($(#[$meta:meta])* $vis:vis enum $name:ident { $($(#[$vmeta:meta])* $variant:ident => $token:literal),+ $(,)? }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        $vis enum $name {
            $($(#[$vmeta])* $variant),+
        }
        impl $name {
            /// Every variant, in declaration order.
            pub const ALL: &'static [$name] = &[$($name::$variant),+];
            /// The durable token.
            pub fn as_token(self) -> &'static str {
                match self {
                    $($name::$variant => $token),+
                }
            }
            /// The variant a durable token names; `None` for a token this build does not write.
            pub fn from_token(token: &str) -> Option<Self> {
                match token {
                    $($token => Some($name::$variant),)+
                    _ => None,
                }
            }
        }
    };
}

/// The pure attempt-fact grammar: the 13-kind closed vocabulary, the two-axis fold, the
/// legality predicate, and the canonical SHA-384 sever-witness encoding. No store, no
/// clock; the SQLite half calls through it.
pub mod attempt;
/// The engine-side body conversion boundary: `RawBody` (has `html`) in, `BodyView` (has no
/// `html`) out, with the size cap re-applied after conversion.
pub mod body_view;
/// The capacity domain core: `CapacityConfig`/`validate`/`from_engine_payload` and
/// `Occupancy`/`AdmissionKind`/`admission_check`, the pure admission check that
/// `SqliteIntentLog::record`/`InMemoryIntentLog::record` wire in.
///
/// **`pub`, not `pub(crate)`:** [`IntentLog::record_capacity_config`] is a `pub trait`
/// method taking `capacity::CapacityConfig` by value, so a private module would make that
/// parameter type unnameable and the method uncallable from external callers (`src-tauri`
/// and external integration tests included). Only the config type and its fail-closed
/// constructor [`capacity::CapacityConfig::from_engine_payload`] cross the boundary;
/// `validate`, `admission_check`, `Occupancy`, the refusal enums and `effective_bounds`
/// stay `pub(crate)`, as do the writer-gate and `settle_status` machinery.
pub mod capacity;
pub mod commitment;
pub mod config_knobs;
/// The RFC 2047 encoded-word decoder both HTTP transports use. It lives here so
/// `aruna-jmap` (which depends only on this crate) can decode a `From` display name too.
pub mod encoded_word;
pub mod episode;
pub mod gmail;
/// Ingest display normalization (the sender-spoofing defense).
/// Crate-internal: the read coordinator is its only consumer.
mod header_normalize;
pub mod jmap;
pub mod key_custody;
/// The sender boundary: a `From` header parsed by the RFC 5322 §3.4 grammar
/// (`parse_mailbox`), and the closed `SenderStatus` set a header row and a frozen plan
/// member carry.
pub mod mailbox;
pub mod mem;
pub mod message_header;
pub mod message_store;
pub mod plan;
pub mod prestate;
/// The read coordinator: ingest (atomic identity+header write, minting, normalization),
/// window-scoped refresh reconcile, and post-verb projection maintenance. A read-side
/// module, outside [`CommandBus`].
pub mod read_coordinator;
pub mod read_model;
/// The shared transport read-surface vocabulary: `HeaderSummary`, `ContinuationToken`,
/// `AttachmentPresence`, `RawBody`, and the page-size clamp both
/// `GmailTransport::list_inbox_page` and `JmapTransport::list_inbox_page` share.
pub mod read_surface;
pub mod reconcile;
/// The store-open contract (preflight, bootstrap, per-connection checks).
/// Crate-internal: opening a store is `SqliteIntentLog::open`'s job, not API surface.
mod store_open;
/// The open-time integrity evidence a caller reads off [`SqliteIntentLog::integrity_report`].
/// Re-exported because the module itself is crate-internal while its verdict is not.
pub use store_open::IntegrityEvidence;
// Test-only: the guard every test in this workspace and in the `src-tauri` shell mints its
// temp paths through. Compiled only under `cfg(test)` or the `test-support` feature, which
// only dev-dependencies enable. (A `//` comment, not `///`: an outer doc here would merge
// into the module's own `//!` docs and resolve their intra-doc links from the crate root.)
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod test_temp;
/// The sever-priority writer gate: the process-wide per-file-identity enrollment state
/// machine, its ticketed/coalescing sever service, and the stall surfaces. Crate-internal:
/// the store types enroll and the sever path drives the service.
pub(crate) mod writer_gate;

mod adjudication;
mod boot;
mod bus;
mod command;
mod connector;
mod decision;
mod fact_store;
mod fixtures;
mod grant;
mod intent;
mod intent_log;
mod keys;
mod memory_log;
mod outcome;
mod plan_store;
mod settle;
mod sever;
mod sqlite_log;
mod undo;

pub use bus::{backoff_delay, CommandBus, BACKOFF_BASE, BACKOFF_CAP, RETRY_CAP};
pub use command::{Action, ActionEnvelope, Command, Facet, MailFlag, RiskTier};
pub use connector::{
    Connector, ConnectorError, EffectEvidence, EffectWitness, EffectWitnessRow, FailureKind,
    ResolveBasisError,
};
pub use fixtures::{
    test_support, AlwaysFailConnector, AlwaysOkConnector, CountingConnector,
    DeterministicFailConnector, RecordingConnector,
};
pub use grant::{GrantRatchet, GrantRefusal, InMemoryGrantRatchet, NoGrantRatchet};
pub use intent::{
    status_to_str, DeadLetterWrite, Intent, IntentStatus, StatusPrecondition, StatusWrite,
    TransientCharge, UndoPairChild, UndoPairFlip,
};
pub use intent_log::{
    AdjudicatedHistory, AdjudicationOutcome, AttemptClaim, CaptureBinding, CapturedJournal,
    CapturedPreState, Claim, ClaimOutcome, ConnectorVerdict, ExposureObligation, IntentLog,
    JournalReplaceOutcome, LateAckOutcome, LiveAttempt, LogError, SendAuthOutcome, SettleOutcome,
    SettledLifecycle, SeverOutcome, SeverWitness, UndoContext, UnknownReviewReport,
    UnknownReviewRow,
};
pub use keys::derive_idempotency_key;
pub use memory_log::{InMemoryAnnotation, InMemoryIntentLog, InMemoryJournal, InMemoryObligation};
pub use outcome::{ExecuteError, Executed, RecoverReport, WitnessRecord, WitnessWriteFailure};
pub use sqlite_log::SqliteIntentLog;
pub use undo::{RestorationVerdict, UndoPresentation, UndoPresentationRead};

pub(crate) use command::action_message_ref;
pub(crate) use intent::NON_TERMINAL_STATUS_SQL;
pub(crate) use sqlite_log::{intent_from_raw, raw_intent_from_row, INTENT_COLUMNS, SCHEMA_VERSION};
#[cfg(test)]
pub(crate) use adjudication::{
    ADJUDICATION_ANNOTATION_HALF_TRACE_SQL, EXPOSURE_CONTRIBUTORS_SQL,
    EXPOSURE_GENERATION_HIGH_WATER_SQL, EXPOSURE_OVERLAP_SQL,
    EXPOSURE_RETIREMENT_BY_CONTRIBUTOR_SQL, FACT_CLOCK_HIGH_WATER_SQL, RETRY_SUCCESSOR_SQL,
};
#[cfg(test)]
pub(crate) use fixtures::FIXTURE_KEY_PROVIDER;
#[cfg(test)]
pub(crate) use intent::non_terminal_native_predecessor_sql;

#[cfg(test)]
mod tests;
