//! The capacity configuration domain core.
//!
//! This module is the pure inequality and config core. Occupancy is a view over `intents.status`
//! elsewhere: capacity is derived, never ledgered. An operation occupies a slot exactly while
//! `intents.status` is lifecycle-non-terminal (`NON_TERMINAL_STATUS_SQL`, the single authority).
//! Nothing here counts rows or touches SQLite; it validates and parses the configuration bounds
//! those counts are checked against.
//!
//! `CapacityConfig::validate` is the domain check: `1 ≤ undo_reserve < max_active_ops`,
//! `64 ≤ max_active_ops ≤ 8192`, and the other three fields positive. Violations refuse at config
//! load, so `max_active_ops − undo_reserve` can never underflow.
//!
//! `CapacityConfig::from_engine_payload` is a fail-closed, named-field parse, never
//! `serde_json::Value` (a `Value` map keeps the last of a duplicate key; named fields make a
//! duplicate a refusal). An absent `capacity` object refuses too: an act that says nothing about
//! capacity is not a capacity act. A first-run engine uses `DEFAULT`, answered by
//! `effective_bounds`' no-activation path. (`DEFAULT`, `Occupancy`, `admission_check` and
//! `CapacityError` are `pub(crate)`, so this `pub` doc names them in plain code font.)
//!
//! ## Occupancy and admission
//!
//! `Occupancy` is a view, never a ledger: `active_forward`/`active_undo` are the caller's own
//! counts over `intents.status`/`compensates`, taken inside the same `Immediate` transaction
//! `admission_check` gates, so count-then-insert is atomic. A forward claim must satisfy the
//! protected reserve (`active_forward + batch ≤ max_active_ops − undo_reserve`) **and** the total
//! cap (`occupancy.total() + batch ≤ max_active_ops`); an undo claim answers to the total cap
//! only, since the reserve exists to keep that domain free for it. `batch == 0` is a malformed
//! request (`CapacityError::Domain`); an at-cap refusal is `CapacityError::Refused`, carrying the
//! observed numbers.
//!
//! ## One strict parse for the capacity ledger
//!
//! **Every Rust read of a `kind='capacity'` or `kind='capacity_activated'` payload goes through
//! `CapacityConfig::from_engine_payload` or `parse_activation_pointer`**, and neither can answer
//! "absent" for bytes that were present. This closes fail-open parsing, which appeared three
//! times: `{"capacity":null}` parsed as a missing key; an unreadable ledger was swallowed into the
//! default at open; and a present-but-null `$.activates_generation` read as "no activation ever",
//! so a store configured down to 64 slots admitted against 1024. Each had one shape: SQL
//! `json_extract` returns NULL for malformed, missing, null and wrong-typed input alike, and
//! `Option<i64>` + `.flatten()` maps all of them onto the `None` that means "no row".
//!
//! **Rust readers reject.** A malformed activation row makes every capacity read refuse (the
//! `record` admission read, `record_capacity_config`'s fit-check, and the open-time read, which
//! retries once). Never fall back to the compiled default: a bound nobody can read is not a bound.
//!
//! **The SQL trigger keeps its own `json_valid` guards, which composes with the Rust parse.**
//! `intents_status_activation` (see `store_open::schema_ddl`) reads the same acts from a `WHEN`
//! clause, where a bare `json_extract` over malformed JSON raises and would abort the firing
//! statement; its guards keep it inert on an unreadable act. That is sound because this crate
//! writes the `capacity_activated` row, so only raw SQL or file corruption can plant a pointer
//! these parsers reject, and then the write side stays inert while the read side refuses by name.

use serde::Deserialize;
use std::fmt;

/// The capacity configuration bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapacityConfig {
    /// The total occupancy cap across forward and undo operations.
    pub(crate) max_active_ops: u32,
    /// The protected remedy domain: `active_total + batch ≤ max_active_ops` still gates undo,
    /// but the reserve keeps `max_active_ops − undo_reserve` free of forwards.
    pub(crate) undo_reserve: u32,
    /// The bounded-transaction work budget a bulk writer chunks into, in milliseconds.
    pub(crate) writer_chunk_budget_ms: u32,
    /// The sever-side stall watchdog threshold, in milliseconds.
    pub(crate) sever_watchdog_ms: u32,
    /// The bounded joiner set a sever's kill transaction carries.
    pub(crate) sever_joiner_cap: u32,
}

/// The bounds recorded at code level for a first-run engine or an absent `capacity` config
/// act: `max_active_ops` 1024 (domain 64..8192), `undo_reserve` 64.
pub(crate) const DEFAULT: CapacityConfig = CapacityConfig {
    max_active_ops: 1024,
    undo_reserve: 64,
    writer_chunk_budget_ms: 50,
    sever_watchdog_ms: 5000,
    sever_joiner_cap: 16,
};

/// The domain floor and ceiling for `max_active_ops`.
///
/// `pub(crate)`: `store_open::capacity_domain_guard_sql` interpolates these same two bounds
/// into the activation trigger's SQL, so the domain is written once and a future edit to
/// either number cannot leave the SQL guard and `validate()` disagreeing.
pub(crate) const MAX_ACTIVE_OPS_MIN: u32 = 64;
pub(crate) const MAX_ACTIVE_OPS_MAX: u32 = 8192;

/// A capacity configuration that fails the domain. Closed: every violation names the field and
/// the observed value, never a generic message.
///
/// `pub` because [`CapacityConfig::from_engine_payload`] is `pub` and returns this as its
/// `Err`; a private error type on a public fallible constructor trips rustc's
/// `private_interfaces` lint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapacityConfigError {
    /// `max_active_ops` fell outside `64..=8192`.
    MaxActiveOpsOutOfBounds { observed: u32 },
    /// `undo_reserve` was `0`, or `>= max_active_ops` — either way the protected remedy
    /// domain is not a positive fraction strictly below the total cap.
    UndoReserveOutOfBounds { observed: u32, max_active_ops: u32 },
    /// `writer_chunk_budget_ms`, `sever_watchdog_ms`, or `sever_joiner_cap` was `0`.
    FieldMustBePositive { field: &'static str, observed: u32 },
    /// The payload was not readable JSON, or a present `capacity` object was missing a field
    /// or carried a wrong-typed one. The parse error is carried along for diagnostics, since
    /// the missing field is not otherwise reconstructable from serde's message.
    Unreadable { detail: String },
}

impl fmt::Display for CapacityConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CapacityConfigError::MaxActiveOpsOutOfBounds { observed } => write!(
                f,
                "max_active_ops={observed} is outside the domain {MAX_ACTIVE_OPS_MIN}..={MAX_ACTIVE_OPS_MAX}"
            ),
            CapacityConfigError::UndoReserveOutOfBounds { observed, max_active_ops } => write!(
                f,
                "undo_reserve={observed} is not in 1..max_active_ops ({max_active_ops})"
            ),
            CapacityConfigError::FieldMustBePositive { field, observed } => {
                write!(f, "{field}={observed} must be at least 1")
            }
            CapacityConfigError::Unreadable { detail } => {
                write!(f, "capacity config is not a readable config act ({detail})")
            }
        }
    }
}

impl std::error::Error for CapacityConfigError {}

impl CapacityConfig {
    /// The domain check: every inequality evaluator in this crate assumes a `CapacityConfig`
    /// has already passed it, so an unsigned `max_active_ops − undo_reserve` subtraction
    /// cannot underflow downstream.
    pub(crate) fn validate(&self) -> Result<(), CapacityConfigError> {
        if self.max_active_ops < MAX_ACTIVE_OPS_MIN || self.max_active_ops > MAX_ACTIVE_OPS_MAX {
            return Err(CapacityConfigError::MaxActiveOpsOutOfBounds {
                observed: self.max_active_ops,
            });
        }
        if self.undo_reserve < 1 || self.undo_reserve >= self.max_active_ops {
            return Err(CapacityConfigError::UndoReserveOutOfBounds {
                observed: self.undo_reserve,
                max_active_ops: self.max_active_ops,
            });
        }
        if self.writer_chunk_budget_ms < 1 {
            return Err(CapacityConfigError::FieldMustBePositive {
                field: "writer_chunk_budget_ms",
                observed: self.writer_chunk_budget_ms,
            });
        }
        if self.sever_watchdog_ms < 1 {
            return Err(CapacityConfigError::FieldMustBePositive {
                field: "sever_watchdog_ms",
                observed: self.sever_watchdog_ms,
            });
        }
        if self.sever_joiner_cap < 1 {
            return Err(CapacityConfigError::FieldMustBePositive {
                field: "sever_joiner_cap",
                observed: self.sever_joiner_cap,
            });
        }
        Ok(())
    }

    /// Parse a `capacity` object out of an `engine_config` act payload with named-field serde,
    /// never `serde_json::Value`.
    ///
    /// An absent `capacity` object refuses: the compiled `DEFAULT` belongs only to a store with
    /// no activated act at all (`effective_bounds`' no-activation path; see the absent arm below
    /// for the dual-bound widening the alternative allowed). A present object with a missing or
    /// wrong-typed field, an explicit `null`, or unreadable JSON refuses too. `{"capacity":null}`
    /// must not parse as if the key were absent: serde's `Option<T>` maps JSON `null` to `None`
    /// exactly as it maps a missing key. The distinction is carried by the double-`Option` field
    /// below: `#[serde(default)]` gives the outer `None` only when the key is absent, and
    /// `deserialize_with` runs only when it is present, so "present but null" (`Some(None)`) and
    /// "absent" (`None`) are different values. A parsed object runs through `Self::validate`
    /// before it is returned, so a well-shaped object outside the domain (e.g. `undo_reserve: 0`)
    /// refuses. Unknown sibling keys are ignored, the `engine_config` convention.
    ///
    /// `pub`: the one fail-closed constructor an external caller can reach to build a value for
    /// [`crate::IntentLog::record_capacity_config`]; `CapacityConfig`'s fields are `pub(crate)`.
    pub fn from_engine_payload(payload: &str) -> Result<CapacityConfig, CapacityConfigError> {
        #[derive(Deserialize)]
        struct RawCapacity {
            max_active_ops: u32,
            undo_reserve: u32,
            writer_chunk_budget_ms: u32,
            sever_watchdog_ms: u32,
            sever_joiner_cap: u32,
        }

        /// Runs only when the `capacity` key is present in the payload (a missing key is
        /// `#[serde(default)]`'s job below), so wrapping the result in `Some(..)` is itself the
        /// "the key was present" signal, distinct from the outer `None` a missing key produces
        /// via `Default`. The value is decoded through `Option<RawCapacity>`'s own blanket impl:
        /// JSON `null` decodes to the inner `None` (still inside the outer `Some`: "present
        /// but null"), an object decodes to the inner `Some`, and anything else is the
        /// ordinary wrong-type refusal.
        fn deserialize_present<'de, D>(
            deserializer: D,
        ) -> Result<Option<Option<RawCapacity>>, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            Option::<RawCapacity>::deserialize(deserializer).map(Some)
        }

        #[derive(Deserialize)]
        struct CapacityPayload {
            #[serde(default, deserialize_with = "deserialize_present")]
            capacity: Option<Option<RawCapacity>>,
        }

        let parsed: CapacityPayload = serde_json::from_str(payload)
            .map_err(|e| CapacityConfigError::Unreadable { detail: e.to_string() })?;

        let config = match parsed.capacity {
            // The key never appeared in the payload at all: refuse. Defaulting absent to
            // `DEFAULT` would be harmless for a value builder, but every production read of
            // this parse is over a `kind='capacity'` act, and there it would be a live
            // widening: a raw act carrying no capacity object would parse as `DEFAULT`
            // (1024/64), sit as the newest pending act, and the dual-bound rule would then
            // answer forward admission from those wide pending bounds (64 forwards admitted
            // against a configured 64/1 whose own forward bound is 63). First-run and no-act
            // stores still get `DEFAULT`, through `effective_bounds` with no activation
            // (`current: None` gives `DEFAULT`). An act that says nothing about capacity is
            // not a capacity act; a bound nobody wrote is not a bound. The absent-versus-null
            // machinery above stays so the two shapes keep distinct diagnostics.
            None => {
                return Err(CapacityConfigError::Unreadable {
                    detail: "the payload carries no capacity object — a kind='capacity' act \
                             must spell its bounds; the compiled DEFAULT belongs only to a \
                             store with no activated act at all"
                        .to_string(),
                })
            }
            // The key was present and its value was JSON `null`: a malformed act, never a
            // silent default.
            Some(None) => {
                return Err(CapacityConfigError::Unreadable {
                    detail: "capacity is present but null — supply the full object (since \
                             r10 F2 an absent key refuses too; the compiled DEFAULT belongs \
                             only to a store with no activated capacity act at all)"
                        .to_string(),
                })
            }
            Some(Some(raw)) => CapacityConfig {
                max_active_ops: raw.max_active_ops,
                undo_reserve: raw.undo_reserve,
                writer_chunk_budget_ms: raw.writer_chunk_budget_ms,
                sever_watchdog_ms: raw.sever_watchdog_ms,
                sever_joiner_cap: raw.sever_joiner_cap,
            },
        };
        config.validate()?;
        Ok(config)
    }
}

/// The single strict parse for a `kind='capacity_activated'` act's payload (see the module docs
/// for why fail-open parsing is closed here, not per call site).
///
/// The payload must be JSON whose top-level `activates_generation` is a non-negative integer
/// naming an `engine_config.generation`. Everything else is refused by name:
///
/// - unreadable JSON, with `serde_json`'s error carried along;
/// - the key missing (serde's "missing field"), never a silent `None`: an activation act that
///   names no generation is corrupt;
/// - the key present and `null`: this is why the field is a plain `u64`, not `Option<u64>`
///   (serde maps `null` and absent onto the same `None`, the collapse this parse refuses);
/// - a non-integer or negative number: `u64` refuses both, so no `CAST(... AS INTEGER)` coerces
///   `"7"`, `7.9` or `-1`;
/// - a value past `i64::MAX`: `engine_config.generation` is an `i64` `INTEGER PRIMARY KEY`, so
///   such a pointer names no row that can exist.
///
/// Duplicate `activates_generation` members refuse too (serde's "duplicate field"), because a
/// `Value` map keeps the last duplicate and reversing the order would flip the answer.
///
/// Returns `u64`; callers handing it to `crate::capacity::effective_bounds` (which speaks the
/// column's `i64`) convert with the range already proven here.
pub(crate) fn parse_activation_pointer(payload: &str) -> Result<u64, CapacityConfigError> {
    #[derive(Deserialize)]
    struct ActivationPointer {
        activates_generation: u64,
    }

    let parsed: ActivationPointer = serde_json::from_str(payload).map_err(|e| {
        CapacityConfigError::Unreadable {
            detail: format!(
                "capacity_activated act does not carry a readable \
                 `activates_generation` integer ({e})"
            ),
        }
    })?;
    if parsed.activates_generation > i64::MAX as u64 {
        return Err(CapacityConfigError::Unreadable {
            detail: format!(
                "capacity_activated act names generation {} , which is outside the \
                 `engine_config.generation` domain (an INTEGER PRIMARY KEY, i.e. i64)",
                parsed.activates_generation
            ),
        });
    }
    Ok(parsed.activates_generation)
}

/// The derived occupancy view admission is checked against: counts of currently non-terminal
/// intents, split by whether each carries `compensates` (an undo/remedy) or not (a forward
/// operation). Nothing here counts rows itself: the caller's own `COUNT(*) FILTER (WHERE …)`
/// over `intents.status`/`compensates` (SQLite) or its `entries` map (in-memory) is the view;
/// this struct only carries the two numbers into the pure inequality check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Occupancy {
    /// Non-terminal intents with `compensates IS NULL`.
    pub(crate) active_forward: u32,
    /// Non-terminal intents with `compensates IS NOT NULL`.
    pub(crate) active_undo: u32,
}

impl Occupancy {
    /// The total-cap side of the inequality: `active_forward + active_undo`, over the same
    /// snapshot both counts were taken from.
    pub(crate) fn total(&self) -> u32 {
        self.active_forward + self.active_undo
    }
}

/// Which admission inequality a claim answers to: a forward claim clears both the protected
/// reserve and the total cap; an undo (remedy) claim clears the total cap only, since the
/// reserve exists to keep exactly that headroom free for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdmissionKind {
    Forward,
    Undo,
}

/// A capacity admission refused at the observed occupancy. Distinct from
/// [`CapacityConfigError`]: the request itself is well-formed, the pool is just at (or would be
/// driven past) its bound. Every field is an observed number, never a generic message, so the
/// caller's refusal string reports exactly what was seen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CapacityRefusal {
    /// A forward claim would push `active_forward` past the protected reserve bound
    /// (`max_active_ops − undo_reserve`). Refused even though the total cap has room, so the
    /// reserve stays free for remedies.
    ForwardReserveExceeded {
        active_forward: u32,
        batch: u32,
        forward_bound: u32,
    },
    /// Either polarity's claim would push `occupancy.total()` past `max_active_ops`: the pool
    /// itself is full.
    TotalExceeded {
        active_total: u32,
        batch: u32,
        max_active_ops: u32,
    },
}

impl fmt::Display for CapacityRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CapacityRefusal::ForwardReserveExceeded { active_forward, batch, forward_bound } => write!(
                f,
                "forward admission refused: active_forward={active_forward} + batch={batch} \
                 exceeds the protected forward reserve bound {forward_bound} (design §5.3 \
                 EXACT-CAPACITY-ACCOUNTING — the undo reserve stays free of forwards)"
            ),
            CapacityRefusal::TotalExceeded { active_total, batch, max_active_ops } => write!(
                f,
                "admission refused: active_total={active_total} + batch={batch} exceeds \
                 max_active_ops={max_active_ops} (design §5.3 EXACT-CAPACITY-ACCOUNTING) — \
                 in-place adjudication is always admissible to drain a slot, even at this \
                 bound (design §5.2d: a control transition, no admission door, net −1)"
            ),
        }
    }
}

impl std::error::Error for CapacityRefusal {}

/// The two ways [`admission_check`] can refuse: a malformed request (`batch == 0`, a domain
/// error over the same [`CapacityConfigError`] vocabulary, not a backpressure event) versus a
/// well-formed claim the observed occupancy cannot admit ([`CapacityRefusal`]). They are two
/// variants, not folded together, because a caller must route a domain error and a legitimate
/// at-cap refusal to different outcomes: the former is a caller bug, the latter is ordinary
/// backpressure that a retry later or a bigger pool can resolve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CapacityError {
    /// `batch == 0` (or any other config-domain violation caught at admission time): not a
    /// capacity refusal, because no larger pool would ever admit it.
    Domain(CapacityConfigError),
    /// The admission inequality was violated at the observed occupancy.
    Refused(CapacityRefusal),
}

impl fmt::Display for CapacityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CapacityError::Domain(e) => write!(f, "{e}"),
            CapacityError::Refused(r) => write!(f, "{r}"),
        }
    }
}

impl std::error::Error for CapacityError {}

/// The admission check: a forward claim requires both
/// `occ.active_forward + batch ≤ max_active_ops − undo_reserve` (the protected reserve) and
/// `occ.total() + batch ≤ max_active_ops` (the total cap); an undo claim requires only the
/// total cap. `batch == 0` is a domain error (there is no request to admit or refuse),
/// checked before either inequality so a `CapacityConfigError` never masquerades as an at-cap
/// [`CapacityRefusal`]. `cfg` is assumed already [`CapacityConfig::validate`]-d (every caller
/// reads it through [`CapacityConfig::from_engine_payload`], which validates), so
/// `max_active_ops − undo_reserve` never underflows here.
pub(crate) fn admission_check(
    kind: AdmissionKind,
    batch: u32,
    occ: Occupancy,
    cfg: &CapacityConfig,
) -> Result<(), CapacityError> {
    if batch == 0 {
        return Err(CapacityError::Domain(CapacityConfigError::FieldMustBePositive {
            field: "batch",
            observed: 0,
        }));
    }
    if matches!(kind, AdmissionKind::Forward) {
        let forward_bound = cfg.max_active_ops - cfg.undo_reserve;
        if occ.active_forward + batch > forward_bound {
            return Err(CapacityError::Refused(CapacityRefusal::ForwardReserveExceeded {
                active_forward: occ.active_forward,
                batch,
                forward_bound,
            }));
        }
    }
    if occ.total() + batch > cfg.max_active_ops {
        return Err(CapacityError::Refused(CapacityRefusal::TotalExceeded {
            active_total: occ.total(),
            batch,
            max_active_ops: cfg.max_active_ops,
        }));
    }
    Ok(())
}

/// Current-state activation fit: the question a pending capacity reduction's activation
/// answers over the current occupancy, which is a different question from
/// [`admission_check`]'s prospective claim. Forcing the two predicates equal makes one of them
/// wrong: at `active_forward == max_active_ops - undo_reserve` (960 at [`DEFAULT`]) activation
/// fits (`960 <= 960`) while admission of one more forward refuses (`961 > 960`).
/// `activation_fits` therefore never takes a `batch`: it asks whether the pool, as it stands,
/// already fits inside `cfg`. This is the pending-to-current condition, never an admission
/// check. `cfg` is assumed already [`CapacityConfig::validate`]-d (every caller reads it
/// through [`CapacityConfig::from_engine_payload`], which validates), so the subtraction never
/// underflows.
pub(crate) fn activation_fits(occ: Occupancy, cfg: &CapacityConfig) -> bool {
    occ.active_forward <= cfg.max_active_ops - cfg.undo_reserve && occ.total() <= cfg.max_active_ops
}

/// The current and pending capacity bounds, derived from the `engine_config` ledger's two
/// relevant act families: a `kind='capacity'` act carries a full bounds object; a
/// `kind='capacity_activated'` act names which capacity act's generation is now current
/// (`{"activates_generation": N}`). The latest activation wins, and an older unactivated
/// capacity act is superseded the moment a newer one lands: "pending" is always the newest
/// capacity act past the last-activated generation, never an accumulation of every act that
/// never fit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EffectiveBounds {
    /// The bounds every claim is currently admitted (and every releasing write activated)
    /// against.
    pub(crate) current: CapacityConfig,
    /// The newest not-yet-activated capacity act, if one exists past the last activation, as
    /// `(generation, bounds)`.
    pub(crate) pending: Option<(i64, CapacityConfig)>,
}

/// Derive [`EffectiveBounds`] from the ledger's two act families. Pure, so the SQL reader stays a
/// thin two-query fetch and every edge is testable without a store.
///
/// `capacity_acts` is every `kind='capacity'` act (`(generation, payload)`, any order).
/// `activation` is the latest `kind='capacity_activated'` act as
/// `(row_generation, activates_generation)`, or `None` before any activation.
///
/// **Two ordering refusals live here, so no reader carries a private copy.** A pointer at or past
/// its own row's generation is a planted-reservation shape (no honest writer mints a forward
/// pointer). A newest-pending act behind the activation row (`pointer < act < row`) is a shape no
/// honest writer produces and the trigger's integer prefilter can never activate, so honoring it
/// as pending would wedge the reduction forever. A later honest activation row supersedes either.
///
/// `current`: `None` gives [`DEFAULT`]; `Some(gen)` is the act with that exact generation (a
/// lookup, not "the latest", since a newer act may be pending). A `gen` naming no supplied act
/// refuses rather than falling back to [`DEFAULT`]. `pending`: the newest act with generation
/// strictly greater than the last-activated one (`two_pending_capacity_acts_latest_generation_wins`).
pub(crate) fn effective_bounds(
    capacity_acts: &[(i64, String)],
    activation: Option<(i64, i64)>,
) -> Result<EffectiveBounds, CapacityConfigError> {
    // Ordering refusal (1): a pointer must name its own past. Checked before any payload
    // parse, since the shape is refused regardless of what the acts say.
    if let Some((row_generation, pointer)) = activation {
        if pointer >= row_generation {
            return Err(CapacityConfigError::Unreadable {
                detail: format!(
                    "the newest activation row, at generation {row_generation}, names \
                     generation {pointer} — not in its own past; no honest writer mints a \
                     forward pointer, and honoring one would seat a never-fitted act as CURRENT"
                ),
            });
        }
    }
    let activated_generation = activation.map(|(_, pointer)| pointer);
    let current = match activated_generation {
        None => DEFAULT,
        Some(gen) => {
            let payload = capacity_acts
                .iter()
                .find(|(g, _)| *g == gen)
                .map(|(_, p)| p.as_str())
                .ok_or_else(|| CapacityConfigError::Unreadable {
                    detail: format!(
                        "activation names generation {gen} but no kind='capacity' act at that \
                         generation was supplied"
                    ),
                })?;
            CapacityConfig::from_engine_payload(payload)?
        }
    };
    let last_activated = activated_generation.unwrap_or(0);
    let newest_pending = capacity_acts.iter().filter(|(g, _)| *g > last_activated).max_by_key(|(g, _)| *g);
    // Ordering refusal (2): an act stranded between the pointer and its own activation row.
    // Checked before the pending payload parses, for the same reason as (1).
    if let (Some((gen, _)), Some((row_generation, _))) = (newest_pending, activation) {
        if *gen < row_generation {
            return Err(CapacityConfigError::Unreadable {
                detail: format!(
                    "the newest pending capacity act, at generation {gen}, is stranded behind \
                     the newest activation row at generation {row_generation} — no honest \
                     activation writer leaves an act between its pointer and its own row, and \
                     the status trigger's integer prefilter can never see it; honoring it as \
                     pending would wedge the reduction forever"
                ),
            });
        }
    }
    let pending = match newest_pending {
        None => None,
        Some((gen, payload)) => Some((*gen, CapacityConfig::from_engine_payload(payload)?)),
    };
    Ok(EffectiveBounds { current, pending })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> CapacityConfig {
        DEFAULT
    }

    #[test]
    fn config_refuses_zero_undo_reserve() {
        let cfg = CapacityConfig { undo_reserve: 0, ..valid() };
        assert_eq!(
            cfg.validate(),
            Err(CapacityConfigError::UndoReserveOutOfBounds {
                observed: 0,
                max_active_ops: cfg.max_active_ops,
            })
        );
    }

    #[test]
    fn config_refuses_reserve_not_below_max() {
        // == max_active_ops
        let cfg_eq = CapacityConfig { max_active_ops: 100, undo_reserve: 100, ..valid() };
        assert_eq!(
            cfg_eq.validate(),
            Err(CapacityConfigError::UndoReserveOutOfBounds { observed: 100, max_active_ops: 100 })
        );
        // > max_active_ops
        let cfg_gt = CapacityConfig { max_active_ops: 100, undo_reserve: 101, ..valid() };
        assert_eq!(
            cfg_gt.validate(),
            Err(CapacityConfigError::UndoReserveOutOfBounds { observed: 101, max_active_ops: 100 })
        );
    }

    #[test]
    fn config_refuses_max_out_of_bounds() {
        let below = CapacityConfig { max_active_ops: 63, undo_reserve: 1, ..valid() };
        assert_eq!(
            below.validate(),
            Err(CapacityConfigError::MaxActiveOpsOutOfBounds { observed: 63 })
        );

        let above = CapacityConfig { max_active_ops: 8193, undo_reserve: 1, ..valid() };
        assert_eq!(
            above.validate(),
            Err(CapacityConfigError::MaxActiveOpsOutOfBounds { observed: 8193 })
        );

        let floor = CapacityConfig { max_active_ops: 64, undo_reserve: 1, ..valid() };
        assert_eq!(floor.validate(), Ok(()));

        let ceiling = CapacityConfig { max_active_ops: 8192, undo_reserve: 1, ..valid() };
        assert_eq!(ceiling.validate(), Ok(()));
    }

    #[test]
    fn config_defaults_are_in_domain() {
        assert_eq!(DEFAULT.max_active_ops, 1024);
        assert_eq!(DEFAULT.undo_reserve, 64);
        assert_eq!(DEFAULT.writer_chunk_budget_ms, 50);
        assert_eq!(DEFAULT.sever_watchdog_ms, 5000);
        assert_eq!(DEFAULT.sever_joiner_cap, 16);
        assert_eq!(DEFAULT.validate(), Ok(()));
    }

    #[test]
    fn config_parses_named_fields_and_refuses_malformed() {
        // Absent `capacity` object -> REFUSE (was documented-DEFAULT earlier;
        // see the parse's own comment for the dual-bound widening that killed it).
        let absent = CapacityConfig::from_engine_payload(r#"{"other":"stuff"}"#);
        assert!(matches!(absent, Err(CapacityConfigError::Unreadable { .. })));

        // Wrong-typed field -> refuse.
        let wrong_typed = CapacityConfig::from_engine_payload(
            r#"{"capacity":{"max_active_ops":"not-a-number","undo_reserve":64,
                "writer_chunk_budget_ms":50,"sever_watchdog_ms":5000,"sever_joiner_cap":16}}"#,
        );
        assert!(matches!(wrong_typed, Err(CapacityConfigError::Unreadable { .. })));

        // Missing field -> refuse.
        let missing_field = CapacityConfig::from_engine_payload(
            r#"{"capacity":{"max_active_ops":1024,"undo_reserve":64,
                "writer_chunk_budget_ms":50,"sever_watchdog_ms":5000}}"#,
        );
        assert!(matches!(missing_field, Err(CapacityConfigError::Unreadable { .. })));

        // Unknown siblings (top-level and inside `capacity`) ignored; valid explicit object
        // round-trips.
        let explicit = CapacityConfig::from_engine_payload(
            r#"{"schema_version":9,"capacity":{"max_active_ops":2048,"undo_reserve":128,
                "writer_chunk_budget_ms":75,"sever_watchdog_ms":6000,"sever_joiner_cap":32,
                "unknown_sibling":"ignored"}}"#,
        )
        .unwrap();
        assert_eq!(
            explicit,
            CapacityConfig {
                max_active_ops: 2048,
                undo_reserve: 128,
                writer_chunk_budget_ms: 75,
                sever_watchdog_ms: 6000,
                sever_joiner_cap: 32,
            }
        );

        // A present-but-out-of-domain explicit object refuses via validate().
        let out_of_domain = CapacityConfig::from_engine_payload(
            r#"{"capacity":{"max_active_ops":1024,"undo_reserve":0,
                "writer_chunk_budget_ms":50,"sever_watchdog_ms":5000,"sever_joiner_cap":16}}"#,
        );
        assert!(matches!(
            out_of_domain,
            Err(CapacityConfigError::UndoReserveOutOfBounds { observed: 0, max_active_ops: 1024 })
        ));
    }

    #[test]
    fn config_refuses_explicit_null_capacity_object() {
        // updated: an ABSENT `capacity` key now refuses too —
        // the null arm below keeps its own DISTINCT diagnostic, which is what this test pins.
        let absent = CapacityConfig::from_engine_payload(r#"{"other":"stuff"}"#);
        assert!(
            matches!(absent, Err(CapacityConfigError::Unreadable { .. })),
            "an absent capacity key refuses since r10 F2: {absent:?}"
        );

        // A PRESENT `capacity` key carrying JSON `null` must REFUSE, never silently fall
        // back to DEFAULT — serde's blanket `Option<T>` impl maps `null` to `None` exactly
        // the way a missing key does, so pre-fix this returned `Ok(DEFAULT)` indistinguishably
        // from the absent-key case above.
        let explicit_null = CapacityConfig::from_engine_payload(r#"{"capacity":null}"#);
        assert!(
            matches!(explicit_null, Err(CapacityConfigError::Unreadable { .. })),
            "a PRESENT-but-null capacity object must refuse, not default: {explicit_null:?}"
        );

        // Sibling keys alongside an explicit null still refuse the same way — the null is
        // what disqualifies it, not the payload's overall shape.
        let explicit_null_with_siblings =
            CapacityConfig::from_engine_payload(r#"{"schema_version":9,"capacity":null}"#);
        assert!(matches!(
            explicit_null_with_siblings,
            Err(CapacityConfigError::Unreadable { .. })
        ));
    }

    // both admission inequalities, distinct backpressure (design §5.3, the §7c
    // edge table at DEFAULTS: max_active_ops=1024, undo_reserve=64, forward_bound=960) ──

    #[test]
    fn forward_admits_at_the_reserve_boundary() {
        let cfg = DEFAULT;
        // 959 + 1 = 960 == forward_bound (1024 - 64) -> ADMITS, exactly at the boundary.
        let at_boundary = Occupancy { active_forward: 959, active_undo: 0 };
        assert_eq!(admission_check(AdmissionKind::Forward, 1, at_boundary, &cfg), Ok(()));
        // 960 + 1 = 961 > 960 -> REFUSES ForwardReserveExceeded, one past the boundary.
        let one_past = Occupancy { active_forward: 960, active_undo: 0 };
        assert_eq!(
            admission_check(AdmissionKind::Forward, 1, one_past, &cfg),
            Err(CapacityError::Refused(CapacityRefusal::ForwardReserveExceeded {
                active_forward: 960,
                batch: 1,
                forward_bound: 960,
            }))
        );
    }

    #[test]
    fn forward_at_the_959_65_edge_refuses_total() {
        let cfg = DEFAULT;
        // forward=959 passes the reserve (959 + 1 = 960 <= 960) but total=959+65=1024, and
        // 1024 + 1 = 1025 > 1024 refuses on the TOTAL cap, not the reserve — the reserve
        // floors remedies, the total caps them.
        let occ = Occupancy { active_forward: 959, active_undo: 65 };
        assert_eq!(
            admission_check(AdmissionKind::Forward, 1, occ, &cfg),
            Err(CapacityError::Refused(CapacityRefusal::TotalExceeded {
                active_total: 1024,
                batch: 1,
                max_active_ops: 1024,
            }))
        );
    }

    #[test]
    fn undo_admits_the_65th_remedy() {
        let cfg = DEFAULT;
        // forward=959, undo=64 (total=1023); the 65th remedy: 1023 + 1 = 1024 <= 1024 ADMITS
        // — undo answers ONLY to the total cap, never the reserve.
        let occ = Occupancy { active_forward: 959, active_undo: 64 };
        assert_eq!(admission_check(AdmissionKind::Undo, 1, occ, &cfg), Ok(()));
    }

    #[test]
    fn undo_refuses_at_total_cap() {
        let cfg = DEFAULT;
        // total=1024 refuses: 1024 + 1 = 1025 > 1024.
        let full = Occupancy { active_forward: 960, active_undo: 64 };
        assert_eq!(
            admission_check(AdmissionKind::Undo, 1, full, &cfg),
            Err(CapacityError::Refused(CapacityRefusal::TotalExceeded {
                active_total: 1024,
                batch: 1,
                max_active_ops: 1024,
            }))
        );
        // total=1023 admits even with undo already at 64 — the reserve never binds undo.
        let edge = Occupancy { active_forward: 959, active_undo: 64 };
        assert_eq!(admission_check(AdmissionKind::Undo, 1, edge, &cfg), Ok(()));
    }

    #[test]
    fn oversized_batch_refuses_whole() {
        let cfg = DEFAULT;
        // An empty pool with a batch bigger than the WHOLE cap refuses outright — there is
        // no partial admission of an oversized batch.
        let empty = Occupancy { active_forward: 0, active_undo: 0 };
        assert_eq!(
            admission_check(AdmissionKind::Undo, 1025, empty, &cfg),
            Err(CapacityError::Refused(CapacityRefusal::TotalExceeded {
                active_total: 0,
                batch: 1025,
                max_active_ops: 1024,
            }))
        );
    }

    #[test]
    fn zero_batch_is_a_domain_error() {
        let cfg = DEFAULT;
        let empty = Occupancy { active_forward: 0, active_undo: 0 };
        // batch=0 is a REQUEST malformation, not an at-cap refusal — routed through the
        // SAME `CapacityConfigError::FieldMustBePositive` domain vocabulary `validate()`
        // uses for the other positive-fields, never a `CapacityRefusal`.
        assert_eq!(
            admission_check(AdmissionKind::Forward, 0, empty, &cfg),
            Err(CapacityError::Domain(CapacityConfigError::FieldMustBePositive {
                field: "batch",
                observed: 0,
            }))
        );
        assert_eq!(
            admission_check(AdmissionKind::Undo, 0, empty, &cfg),
            Err(CapacityError::Domain(CapacityConfigError::FieldMustBePositive {
                field: "batch",
                observed: 0,
            }))
        );
    }

    // `activation_fits` vs `admission_check` at the §7c edges (domain
    // correction — the two predicates are DIFFERENT questions and must disagree exactly
    // where the design says they do) ──

    #[test]
    fn activation_fits_at_the_forward_reserve_boundary_where_admission_refuses() {
        let cfg = DEFAULT; // max=1024, reserve=64, forward_bound=960
        // 960 == forward_bound: activation FITS (current-state, no batch).
        let at_bound = Occupancy { active_forward: 960, active_undo: 0 };
        assert!(activation_fits(at_bound, &cfg));
        // The SAME occupancy refuses ONE MORE forward admission — the two questions disagree
        // on purpose (EXECUTED).
        assert_eq!(
            admission_check(AdmissionKind::Forward, 1, at_bound, &cfg),
            Err(CapacityError::Refused(CapacityRefusal::ForwardReserveExceeded {
                active_forward: 960,
                batch: 1,
                forward_bound: 960,
            }))
        );
        // 961 > forward_bound: activation no longer fits.
        let one_past = Occupancy { active_forward: 961, active_undo: 0 };
        assert!(!activation_fits(one_past, &cfg));
    }

    #[test]
    fn activation_fits_at_the_total_cap_boundary() {
        let cfg = DEFAULT;
        // total = 1024 == max_active_ops: fits.
        let at_cap = Occupancy { active_forward: 960, active_undo: 64 };
        assert!(activation_fits(at_cap, &cfg));
        // total = 1025: does not fit (even though the forward-only bound alone would).
        let one_past = Occupancy { active_forward: 960, active_undo: 65 };
        assert!(!activation_fits(one_past, &cfg));
    }

    #[test]
    fn activation_fits_one_under_and_at_the_64_32_fixture_edges() {
        // The 64/32 fixture: max=64, reserve=32, forward_bound=32.
        let cfg = CapacityConfig {
            max_active_ops: 64,
            undo_reserve: 32,
            ..DEFAULT
        };
        // One under every bound: fits.
        assert!(activation_fits(Occupancy { active_forward: 31, active_undo: 30 }, &cfg));
        // Exactly at both bounds: fits.
        assert!(activation_fits(Occupancy { active_forward: 32, active_undo: 32 }, &cfg));
        // One past the forward bound only (total still under cap): does not fit.
        assert!(!activation_fits(Occupancy { active_forward: 33, active_undo: 0 }, &cfg));
        // One past the total cap only (forward under its bound): does not fit.
        assert!(!activation_fits(Occupancy { active_forward: 0, active_undo: 65 }, &cfg));
    }

    // `effective_bounds` ──

    #[test]
    fn effective_bounds_before_any_capacity_act_is_the_compiled_default() {
        let eb = effective_bounds(&[], None).unwrap();
        assert_eq!(eb.current, DEFAULT);
        assert_eq!(eb.pending, None);
    }

    #[test]
    fn effective_bounds_no_traffic_activation_makes_the_newest_act_current() {
        let cfg = CapacityConfig { max_active_ops: 128, undo_reserve: 16, ..DEFAULT };
        let payload = format!(
            r#"{{"capture":"on","capacity":{{"max_active_ops":{},"undo_reserve":{},
                "writer_chunk_budget_ms":{},"sever_watchdog_ms":{},"sever_joiner_cap":{}}}}}"#,
            cfg.max_active_ops,
            cfg.undo_reserve,
            cfg.writer_chunk_budget_ms,
            cfg.sever_watchdog_ms,
            cfg.sever_joiner_cap
        );
        let acts = vec![(2i64, payload)];
        // Activated: generation 2 is CURRENT (its activation row sits at 3), nothing pending.
        let eb = effective_bounds(&acts, Some((3, 2))).unwrap();
        assert_eq!(eb.current, cfg);
        assert_eq!(eb.pending, None);
    }

    #[test]
    fn effective_bounds_an_unactivated_act_is_pending_current_stays_default() {
        let cfg = CapacityConfig { max_active_ops: 128, undo_reserve: 16, ..DEFAULT };
        let payload = format!(
            r#"{{"capture":"on","capacity":{{"max_active_ops":{},"undo_reserve":{},
                "writer_chunk_budget_ms":{},"sever_watchdog_ms":{},"sever_joiner_cap":{}}}}}"#,
            cfg.max_active_ops,
            cfg.undo_reserve,
            cfg.writer_chunk_budget_ms,
            cfg.sever_watchdog_ms,
            cfg.sever_joiner_cap
        );
        let acts = vec![(2i64, payload)];
        let eb = effective_bounds(&acts, None).unwrap();
        assert_eq!(eb.current, DEFAULT, "never activated ⇒ current stays first-run default");
        assert_eq!(eb.pending, Some((2, cfg)));
    }

    #[test]
    fn effective_bounds_two_pending_acts_latest_generation_wins() {
        let older = CapacityConfig { max_active_ops: 200, undo_reserve: 10, ..DEFAULT };
        let newer = CapacityConfig { max_active_ops: 128, undo_reserve: 16, ..DEFAULT };
        let payload_of = |c: &CapacityConfig| {
            format!(
                r#"{{"capture":"on","capacity":{{"max_active_ops":{},"undo_reserve":{},
                    "writer_chunk_budget_ms":{},"sever_watchdog_ms":{},"sever_joiner_cap":{}}}}}"#,
                c.max_active_ops,
                c.undo_reserve,
                c.writer_chunk_budget_ms,
                c.sever_watchdog_ms,
                c.sever_joiner_cap
            )
        };
        // Two unactivated acts, generation 2 (older) and generation 3 (newer) — an
        // OUT-OF-ORDER slice on purpose (the caller passes ANY order).
        let acts = vec![(3i64, payload_of(&newer)), (2i64, payload_of(&older))];
        let eb = effective_bounds(&acts, None).unwrap();
        assert_eq!(eb.current, DEFAULT);
        assert_eq!(
            eb.pending,
            Some((3, newer)),
            "the OLDER unactivated act (generation 2) is superseded, never surfaced as pending"
        );
    }

    #[test]
    fn effective_bounds_current_is_a_generation_lookup_not_the_newest_act() {
        // A NEWER unactivated act sits pending while an OLDER one is still current — this is
        // exactly the state after one activation with a second reduction already appended.
        let activated = CapacityConfig { max_active_ops: 512, undo_reserve: 32, ..DEFAULT };
        let pending = CapacityConfig { max_active_ops: 128, undo_reserve: 16, ..DEFAULT };
        let payload_of = |c: &CapacityConfig| {
            format!(
                r#"{{"capture":"on","capacity":{{"max_active_ops":{},"undo_reserve":{},
                    "writer_chunk_budget_ms":{},"sever_watchdog_ms":{},"sever_joiner_cap":{}}}}}"#,
                c.max_active_ops,
                c.undo_reserve,
                c.writer_chunk_budget_ms,
                c.sever_watchdog_ms,
                c.sever_joiner_cap
            )
        };
        // The honest ledger shape: act 2 → activation row 3 (pointing 2) → reduction act 4.
        let acts = vec![(2i64, payload_of(&activated)), (4i64, payload_of(&pending))];
        let eb = effective_bounds(&acts, Some((3, 2))).unwrap();
        assert_eq!(eb.current, activated, "current is the NAMED generation, not the newest act");
        assert_eq!(eb.pending, Some((4, pending)));
    }

    #[test]
    fn effective_bounds_activation_naming_a_missing_generation_refuses() {
        let err = effective_bounds(&[], Some((8, 7))).unwrap_err();
        assert!(matches!(err, CapacityConfigError::Unreadable { .. }));
    }

    #[test]
    fn effective_bounds_a_forward_pointer_refuses_not_in_its_own_past() {
        // hoisted into the one authority: a pointer at or past
        // its own row's generation is the planted-reservation shape. The discriminating
        // door-level witnesses live at the two readers
        // (the future-activation-pointer test in `lib.rs`,
        // `a_forward_activation_pointer_refuses_the_open_capacity_read`); this
        // is the authority's own domain row.
        let err = effective_bounds(&[], Some((3, 4))).unwrap_err();
        assert!(
            format!("{err}").contains("not in its own past"),
            "a forward pointer refuses by name; got {err:?}"
        );
        // …and a row cannot activate ITSELF (pointer == row generation) either.
        let err_self = effective_bounds(&[], Some((3, 3))).unwrap_err();
        assert!(
            format!("{err_self}").contains("not in its own past"),
            "a self-pointing row refuses by name; got {err_self:?}"
        );
    }

    #[test]
    fn effective_bounds_an_act_stranded_behind_the_activation_row_refuses() {
        // `pointer < act < row` — a shape no honest activation writer produces
        // and the status trigger's integer prefilter can never activate. Door-level witness:
        // the stranded-act test in `lib.rs`.
        let current = CapacityConfig { max_active_ops: 512, undo_reserve: 32, ..DEFAULT };
        let stranded = CapacityConfig { max_active_ops: 128, undo_reserve: 16, ..DEFAULT };
        let payload_of = |c: &CapacityConfig| {
            format!(
                r#"{{"capture":"on","capacity":{{"max_active_ops":{},"undo_reserve":{},
                    "writer_chunk_budget_ms":{},"sever_watchdog_ms":{},"sever_joiner_cap":{}}}}}"#,
                c.max_active_ops,
                c.undo_reserve,
                c.writer_chunk_budget_ms,
                c.sever_watchdog_ms,
                c.sever_joiner_cap
            )
        };
        let acts = vec![(2i64, payload_of(&current)), (4i64, payload_of(&stranded))];
        // Activation row at 5 re-naming generation 2 leaves act 4 stranded: refuse.
        let err = effective_bounds(&acts, Some((5, 2))).unwrap_err();
        assert!(
            format!("{err}").contains("stranded behind"),
            "the gap shape refuses by name; got {err:?}"
        );
        // The honest neighbour still derives: the same acts with the activation row at 3
        // (so act 4 was appended AFTER it) is exactly the ordinary pending state.
        let eb = effective_bounds(&acts, Some((3, 2))).unwrap();
        assert_eq!(eb.current, current);
        assert_eq!(eb.pending, Some((4, stranded)));
    }

    // ── (WHOLESALE): the ONE strict activation-pointer parse ──
    //
    // The DISCRIMINATING witnesses for this close live at the two READERS (they are what the
    // pre-fix bytes actually got wrong): the null-pointer test in `lib.rs` and the one in `store_open.rs`:
    //
    // `a_null_activation_pointer_refuses_the_open_capacity_read`. These are the
    // authority's own domain table — one row per way a pointer can be un-readable, so a later
    // relaxation of any single one fails HERE, by name, instead of at whichever reader
    // happened to notice.

    #[test]
    fn activation_pointer_parses_a_plain_generation() {
        assert_eq!(parse_activation_pointer(r#"{"activates_generation":7}"#), Ok(7));
        // Unknown siblings are ignored — the `engine_config` payload convention.
        assert_eq!(
            parse_activation_pointer(r#"{"schema_version":9,"activates_generation":2}"#),
            Ok(2)
        );
    }

    #[test]
    fn activation_pointer_refuses_every_unreadable_shape() {
        // (label, payload) — each row is a distinct way SQL's
        // `json_extract` + `CAST(... AS INTEGER)` + `Option<i64>.flatten()` used to answer
        // "no activation act exists", which the compiled DEFAULT as CURRENT.
        let cases: &[(&str, &str)] = &[
            ("present but JSON null (the codex-r5 instance)", r#"{"activates_generation":null}"#),
            ("the key missing entirely", r#"{"capture":"on"}"#),
            ("an empty object", "{}"),
            ("unreadable JSON", r#"{"activates_generation":"#),
            ("a string that looks like a number", r#"{"activates_generation":"7"}"#),
            ("a float", r#"{"activates_generation":7.5}"#),
            ("a negative generation", r#"{"activates_generation":-1}"#),
            ("an object", r#"{"activates_generation":{"gen":7}}"#),
            ("a duplicate member", r#"{"activates_generation":2,"activates_generation":9}"#),
            (
                "past the i64 generation domain",
                r#"{"activates_generation":9223372036854775808}"#,
            ),
        ];
        for (label, payload) in cases.iter().copied() {
            let got = parse_activation_pointer(payload);
            assert!(
                matches!(got, Err(CapacityConfigError::Unreadable { .. })),
                "{label}: an unreadable activation pointer must REFUSE, never read as \
                 `no activation has ever landed`; got {got:?} for {payload}"
            );
        }
    }

    #[test]
    fn activation_pointer_generation_zero_is_readable_and_names_no_act() {
        // `0` is IN the parse domain (non-negative) but names no row: `engine_config.generation`
        // carries `CHECK (generation >= 1)`. `effective_bounds` is where that becomes a refusal,
        // and it refuses as a LOOKUP MISS — a different, better-named failure than "unreadable".
        assert_eq!(parse_activation_pointer(r#"{"activates_generation":0}"#), Ok(0));
        let err = effective_bounds(&[], Some((1, 0))).unwrap_err();
        assert!(
            matches!(err, CapacityConfigError::Unreadable { .. }),
            "a pointer naming no capacity act must still refuse, never default; got {err:?}"
        );
    }
}
