//! The user-facing knobs as journaled `engine_config` acts. Three kinds, each read through
//! one strict named-field parser (the same rule as `capacity.rs`: never `serde_json::Value`;
//! absent means the code-level default, only through the no-act path; present but malformed
//! is refused by name). A plan freezes the generation of the act in force at mint; a later
//! act is a new generation, so every change bumps it.
//!
//! **A knob act never restates the capture mode, and the capture-mode read never sees it.**
//! `record`'s admission read and `record_capacity_config`'s carry-forward read find the capture
//! mode off the latest act of a kind that carries `"capture"`: the positive list
//! `CAPTURE_KINDS` in `lib.rs` (`pub(crate)`). A knob payload carries only its own member (its
//! reader refuses any other, via `deny_unknown_fields`), so no knob kind is on that list. A
//! positive list, rather than excluding [`KNOB_KINDS`], means a kind added later, knob or not,
//! cannot shadow the capture mode either. It is one half of a partition with
//! `ENGINE_CONFIG_KINDS` in `lib.rs` (which lists these three kinds): a kind outside it at the
//! ledger head refuses the capture read by name rather than being skipped.

use serde::Deserialize;

/// `kind = 'triage_approval_mode'`: full list (default), or summary plus a spot-check of k.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalModeKnob {
    FullList,
    SummarySample { configured_k: u32 },
}

/// `kind = 'backups'`: content snapshots before a red-tier effect, on (default) or off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupsKnob {
    On,
    Off,
}

/// `kind = 'red_bypass'`: the ADR-P005 bypass of the red-tier approval screen (never of the
/// plan machinery itself).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedBypassKnob {
    Off,
    On,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KnobError {
    /// The payload was not the named-field shape this kind requires. Carries the kind and why.
    Malformed { kind: &'static str, why: String },
    /// `configured_k` must be at least 1 (k = 0 would let an empty sample satisfy admission).
    ConfiguredKZero,
}

impl std::fmt::Display for KnobError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KnobError::Malformed { kind, why } => write!(f, "config act '{kind}' is not readable: {why}"),
            KnobError::ConfiguredKZero => write!(f, "triage_approval_mode: configured_k must be >= 1"),
        }
    }
}
impl std::error::Error for KnobError {}

pub const KIND_APPROVAL_MODE: &str = "triage_approval_mode";
pub const KIND_BACKUPS: &str = "backups";
pub const KIND_RED_BYPASS: &str = "red_bypass";

/// Every knob kind, in one list. None of them carries the capture mode, so none is on the
/// capture-mode read's positive list (`CAPTURE_KINDS`, `lib.rs`); a test there checks the two
/// lists are disjoint.
pub const KNOB_KINDS: [&str; 3] = [KIND_APPROVAL_MODE, KIND_BACKUPS, KIND_RED_BYPASS];

impl ApprovalModeKnob {
    pub fn from_engine_payload(payload: &str) -> Result<Self, KnobError> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            mode: String,
            #[serde(default)]
            configured_k: Option<u32>,
        }
        let raw: Raw = serde_json::from_str(payload).map_err(|e| KnobError::Malformed { kind: KIND_APPROVAL_MODE, why: e.to_string() })?;
        match (raw.mode.as_str(), raw.configured_k) {
            ("full_list", None) => Ok(ApprovalModeKnob::FullList),
            ("summary_sample", Some(0)) => Err(KnobError::ConfiguredKZero),
            ("summary_sample", Some(k)) => Ok(ApprovalModeKnob::SummarySample { configured_k: k }),
            ("summary_sample", None) => Err(KnobError::Malformed { kind: KIND_APPROVAL_MODE, why: "summary_sample requires configured_k".into() }),
            ("full_list", Some(_)) => Err(KnobError::Malformed { kind: KIND_APPROVAL_MODE, why: "full_list carries no configured_k".into() }),
            (other, _) => Err(KnobError::Malformed { kind: KIND_APPROVAL_MODE, why: format!("unknown mode '{other}'") }),
        }
    }
    /// The act's own payload: one spelling in both directions.
    pub fn to_engine_payload(self) -> String {
        match self {
            ApprovalModeKnob::FullList => r#"{"mode":"full_list"}"#.to_string(),
            ApprovalModeKnob::SummarySample { configured_k } => format!(r#"{{"mode":"summary_sample","configured_k":{configured_k}}}"#),
        }
    }
}

impl BackupsKnob {
    pub fn from_engine_payload(payload: &str) -> Result<Self, KnobError> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            backups: String,
        }
        let raw: Raw = serde_json::from_str(payload).map_err(|e| KnobError::Malformed { kind: KIND_BACKUPS, why: e.to_string() })?;
        match raw.backups.as_str() {
            "on" => Ok(BackupsKnob::On),
            "off" => Ok(BackupsKnob::Off),
            other => Err(KnobError::Malformed { kind: KIND_BACKUPS, why: format!("backups must be \"on\" or \"off\", got \"{other}\"") }),
        }
    }
    pub fn to_engine_payload(self) -> String {
        match self {
            BackupsKnob::On => r#"{"backups":"on"}"#.to_string(),
            BackupsKnob::Off => r#"{"backups":"off"}"#.to_string(),
        }
    }
}

impl RedBypassKnob {
    pub fn from_engine_payload(payload: &str) -> Result<Self, KnobError> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            bypass: String,
        }
        let raw: Raw = serde_json::from_str(payload).map_err(|e| KnobError::Malformed { kind: KIND_RED_BYPASS, why: e.to_string() })?;
        match raw.bypass.as_str() {
            "on" => Ok(RedBypassKnob::On),
            "off" => Ok(RedBypassKnob::Off),
            other => Err(KnobError::Malformed { kind: KIND_RED_BYPASS, why: format!("bypass must be \"on\" or \"off\", got \"{other}\"") }),
        }
    }
    pub fn to_engine_payload(self) -> String {
        match self {
            RedBypassKnob::On => r#"{"bypass":"on"}"#.to_string(),
            RedBypassKnob::Off => r#"{"bypass":"off"}"#.to_string(),
        }
    }
}

/// One knob's state in force: the value and the generation of the act that set it. Generation
/// 0 means no act was ever recorded (the code-level default is in force, and a plan minted
/// under it freezes generation 0; the first act then diverges it, as any change would).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InForce<T: Copy> {
    pub value: T,
    pub generation: u64,
}

/// Every knob a plan freezes at mint, read in one store call so the three cannot be read at
/// different instants (a knob changing between three reads would freeze a state that never
/// existed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KnobState {
    pub approval_mode: InForce<ApprovalModeKnob>,
    pub backups: InForce<BackupsKnob>,
    pub red_bypass: InForce<RedBypassKnob>,
}

impl KnobState {
    /// The no-act defaults: full list, backups on, bypass off.
    pub fn defaults() -> Self {
        Self {
            approval_mode: InForce { value: ApprovalModeKnob::FullList, generation: 0 },
            backups: InForce { value: BackupsKnob::On, generation: 0 },
            red_bypass: InForce { value: RedBypassKnob::Off, generation: 0 },
        }
    }

    /// The derivation both stores' `IntentLog::knob_state` answer through: each argument is
    /// the head act of its kind as `(generation, payload)`, or `None` when no act of that kind
    /// was ever recorded. `None` gives that knob's default at generation 0 (the only path to a
    /// default); `Some` goes through the strict reader, and a refusal there is the whole answer
    /// (never a fallback to the default: a knob nobody can read is not a knob).
    pub(crate) fn from_head_acts(
        approval_mode: Option<(u64, &str)>,
        backups: Option<(u64, &str)>,
        red_bypass: Option<(u64, &str)>,
    ) -> Result<Self, KnobError> {
        let d = Self::defaults();
        Ok(Self {
            approval_mode: match approval_mode {
                None => d.approval_mode,
                Some((generation, payload)) => InForce { value: ApprovalModeKnob::from_engine_payload(payload)?, generation },
            },
            backups: match backups {
                None => d.backups,
                Some((generation, payload)) => InForce { value: BackupsKnob::from_engine_payload(payload)?, generation },
            },
            red_bypass: match red_bypass {
                None => d.red_bypass,
                Some((generation, payload)) => InForce { value: RedBypassKnob::from_engine_payload(payload)?, generation },
            },
        })
    }
}

/// The act a caller records, typed. Every act is re-read through its kind's reader before it
/// is stored ([`KnobAct::checked_payload`], called by `record_knob_act` on both stores), so a
/// knob act stored through `record_knob_act` is always readable. The type alone does not
/// guarantee it: `ApprovalMode(SummarySample { configured_k: 0 })` is constructible and its
/// reader refuses it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KnobAct {
    ApprovalMode(ApprovalModeKnob),
    Backups(BackupsKnob),
    RedBypass(RedBypassKnob),
}

impl KnobAct {
    pub fn kind(self) -> &'static str {
        match self {
            KnobAct::ApprovalMode(_) => KIND_APPROVAL_MODE,
            KnobAct::Backups(_) => KIND_BACKUPS,
            KnobAct::RedBypass(_) => KIND_RED_BYPASS,
        }
    }
    pub fn payload(self) -> String {
        match self {
            KnobAct::ApprovalMode(k) => k.to_engine_payload(),
            KnobAct::Backups(k) => k.to_engine_payload(),
            KnobAct::RedBypass(k) => k.to_engine_payload(),
        }
    }
    /// The act's payload, re-read through its kind's own strict reader (the one a later
    /// `knob_state` will use) and refused with that reader's error when it does not read; for
    /// example the approval-mode knob refuses a non-positive `configured_k` at set time. Both
    /// stores' `record_knob_act` store only what this returns.
    pub fn checked_payload(self) -> Result<String, KnobError> {
        let payload = self.payload();
        match self {
            KnobAct::ApprovalMode(_) => {
                ApprovalModeKnob::from_engine_payload(&payload)?;
            }
            KnobAct::Backups(_) => {
                BackupsKnob::from_engine_payload(&payload)?;
            }
            KnobAct::RedBypass(_) => {
                RedBypassKnob::from_engine_payload(&payload)?;
            }
        }
        Ok(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approval_mode_reads_both_modes_refuses_k_zero_and_refuses_unknown_or_duplicate_members() {
        assert_eq!(ApprovalModeKnob::from_engine_payload(r#"{"mode":"full_list"}"#).unwrap(), ApprovalModeKnob::FullList);
        assert_eq!(ApprovalModeKnob::from_engine_payload(r#"{"mode":"summary_sample","configured_k":25}"#).unwrap(), ApprovalModeKnob::SummarySample { configured_k: 25 });
        assert_eq!(ApprovalModeKnob::from_engine_payload(r#"{"mode":"summary_sample","configured_k":0}"#).unwrap_err(), KnobError::ConfiguredKZero);
        assert!(ApprovalModeKnob::from_engine_payload(r#"{"mode":"summary_sample"}"#).is_err());
        assert!(ApprovalModeKnob::from_engine_payload(r#"{"mode":"full_list","configured_k":3}"#).is_err());
        assert!(ApprovalModeKnob::from_engine_payload(r#"{"mode":"aggregate"}"#).is_err());
        assert!(ApprovalModeKnob::from_engine_payload(r#"{"mode":"full_list","mode":"summary_sample","configured_k":1}"#).is_err(), "a duplicate member is a refusal, never last-wins");
        // …and the refusal is serde's named-field duplicate check itself, not some other arm.
        assert!(
            matches!(
                ApprovalModeKnob::from_engine_payload(r#"{"mode":"summary_sample","configured_k":1,"mode":"summary_sample"}"#),
                Err(KnobError::Malformed { why, .. }) if why.contains("duplicate field `mode`")
            ),
            "an identical duplicate refuses too — by name"
        );
        assert!(ApprovalModeKnob::from_engine_payload(r#"{"mode":"full_list","extra":1}"#).is_err(), "unknown members refuse (deny_unknown_fields)");
        for k in [ApprovalModeKnob::FullList, ApprovalModeKnob::SummarySample { configured_k: 7 }] {
            assert_eq!(ApprovalModeKnob::from_engine_payload(&k.to_engine_payload()).unwrap(), k);
        }
    }

    #[test]
    fn backups_and_bypass_read_on_off_only_and_round_trip() {
        assert_eq!(BackupsKnob::from_engine_payload(r#"{"backups":"on"}"#).unwrap(), BackupsKnob::On);
        assert_eq!(BackupsKnob::from_engine_payload(r#"{"backups":"off"}"#).unwrap(), BackupsKnob::Off);
        assert!(BackupsKnob::from_engine_payload(r#"{"backups":"yes"}"#).is_err());
        assert!(BackupsKnob::from_engine_payload(r#"{"backups":true}"#).is_err(), "a non-string is refused");
        assert_eq!(RedBypassKnob::from_engine_payload(r#"{"bypass":"on"}"#).unwrap(), RedBypassKnob::On);
        assert!(RedBypassKnob::from_engine_payload(r#"{}"#).is_err(), "absent member refuses — an act that says nothing is not an act");
        for k in [BackupsKnob::On, BackupsKnob::Off] {
            assert_eq!(BackupsKnob::from_engine_payload(&k.to_engine_payload()).unwrap(), k);
        }
        for k in [RedBypassKnob::On, RedBypassKnob::Off] {
            assert_eq!(RedBypassKnob::from_engine_payload(&k.to_engine_payload()).unwrap(), k);
        }
        // Both readers are strict named-field parses too (mutants M2b/M2c survived without these).
        assert!(BackupsKnob::from_engine_payload(r#"{"backups":"on","extra":1}"#).is_err(), "unknown members refuse (deny_unknown_fields)");
        assert!(
            RedBypassKnob::from_engine_payload(r#"{"bypass":"off","capture":"on"}"#).is_err(),
            "…including a restated capture mode — a knob act carries only its own member"
        );
        assert!(BackupsKnob::from_engine_payload(r#"{"backups":"on","backups":"off"}"#).is_err(), "a duplicate member is a refusal, never last-wins");
        assert!(RedBypassKnob::from_engine_payload(r#"{"bypass":"off","bypass":"on"}"#).is_err(), "a duplicate member is a refusal, never last-wins");
    }

    #[test]
    fn defaults_are_full_list_backups_on_bypass_off_at_generation_zero() {
        let d = KnobState::defaults();
        assert_eq!(d.approval_mode, InForce { value: ApprovalModeKnob::FullList, generation: 0 });
        assert_eq!(d.backups, InForce { value: BackupsKnob::On, generation: 0 });
        assert_eq!(d.red_bypass, InForce { value: RedBypassKnob::Off, generation: 0 });
    }
}
