//! Live HTTP JMAP transport for the Photon engine (`aruna`).
//!
//! Implements `aruna::jmap::JmapTransport` against a real JMAP server (RFC 8620/8621) over a
//! hand-rolled `reqwest::blocking` + serde surface. Compile-isolated from the engine crate so
//! the HTTP/TLS dependency tree never reaches `aruna`. We hand-roll rather than adopt
//! `jmap-client` because its `SetResponse` hides the typed per-record `notUpdated[id]` map
//! (private field; every public accessor stringifies via `to_string_error()`), which would
//! destroy `aruna`'s `JmapError` fidelity (checked against `jmap-client` 0.4.2 `core/set.rs`).
//!
//! Each error layer's `type` string is deserialized here and mapped onto `aruna`'s `JmapError`;
//! an unrecognized type routes to the deterministic `Unknown` bucket rather than failing
//! deserialization. Provider ids, `description` and `detail` never cross back above the seam,
//! only typed `JmapError` variants do.

// Wire to taxonomy mapping (pure, hermetically tested).
pub mod error;
pub mod response;
// The live `HttpJmapTransport` (reqwest::blocking) and the pure wire-shape builders/parsers it uses.
pub mod transport;
