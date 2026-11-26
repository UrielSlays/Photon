//! The fixture connectors and fixture basis the tests and integration tests drive the engine with.

use crate::command::action_message_ref;
use crate::{prestate, Action, Command, Connector, ConnectorError, ResolveBasisError};

#[cfg(doc)]
use crate::EffectEvidence;

/// The provider tag every in-crate fixture basis carries. Handed to
/// [`prestate::native_resource_key`] exactly like a real connector's tag.
pub(crate) const FIXTURE_KEY_PROVIDER: &str = "test";

/// The deterministic basis every in-crate fixture connector freezes: keyed on the command's
/// `message_ref` under a `test` provider tag (so the native-keyed ordering domain is exercised
/// without a provider), one `membership:INBOX` atom, and `ImmutableConstants` freshness, since
/// a fixture has no provider-issued cursor to evidence.
///
/// Built through [`prestate::native_resource_key`], the single encoding authority, like every
/// real connector: a hand-rolled key shape would drift from the encoding under test.
///
/// The two plan verbs (`Trash`, `MarkSpam`) freeze the verb's two-atom closure instead: the
/// atoms and targets `gmail::gmail_atom_targets` names for it, each atom's operand the text
/// after its `:`. The send check compares a plan member's approval-time state over those
/// atoms, and a one-atom capture could never agree with it. Their undo verbs (`Untrash`,
/// `UnmarkSpam`) freeze the same set, because the undo identity check compares the parent's
/// atoms with the undo child's, so a one-atom undo basis would refuse every undo of a plan
/// child (`gmail.rs` gives each pair the same atom set).
pub(crate) fn fixture_basis(command: &Command) -> prestate::FrozenBasis {
    let plan_verb = matches!(
        command.action,
        Action::Trash { .. } | Action::Untrash { .. } | Action::MarkSpam { .. } | Action::UnmarkSpam { .. }
    );
    let atom_targets: std::collections::BTreeMap<String, bool> = if plan_verb {
        crate::gmail::gmail_atom_targets(&command.action)
    } else {
        // The fixture's forward target is "not in INBOX".
        [("membership:INBOX".to_string(), false)].into_iter().collect()
    };
    prestate::FrozenBasis {
        native_resource_key: prestate::native_resource_key(
            FIXTURE_KEY_PROVIDER,
            &[action_message_ref(&command.action)],
        ),
        // Keyed identically to `A` (the key-set equality `validate` enforces).
        touched_atoms: atom_targets
            .keys()
            .map(|atom| (atom.clone(), atom.split_once(':').map_or(atom.as_str(), |(_, operand)| operand).to_string()))
            .collect(),
        atom_targets,
        role_bindings: std::collections::BTreeMap::new(),
        freshness: prestate::Freshness::ImmutableConstants,
    }
}

/// Fixture helpers for this crate's integration tests. The `tests/` binaries compile against
/// the public API only, so the crate-private fixtures they need live here. Hidden from the
/// docs; nothing in the engine calls into this module.
#[doc(hidden)]
pub mod test_support {
    /// The crate's deterministic fixture basis (the crate-private `fixture_basis`) for `command`.
    pub fn fixture_basis(command: &crate::Command) -> crate::prestate::FrozenBasis {
        super::fixture_basis(command)
    }

    /// Set the durable store's sticky-clock latch (`time_high_water.max_seen`) to `instant`
    /// through a raw connection. It sets rather than raises (the engine's own writes only
    /// raise). Panics on a store error.
    pub fn latch_time_high_water(path: &std::path::Path, instant: &str) {
        let conn = rusqlite::Connection::open(path).expect("latch_time_high_water: open");
        crate::store_open::pin_durability_profile(&conn).expect("latch_time_high_water: profile");
        conn.execute(
            "INSERT INTO time_high_water (id, max_seen) VALUES (1, ?1) ON CONFLICT(id) DO UPDATE SET max_seen = excluded.max_seen;",
            [instant],
        )
        .expect("latch_time_high_water: write");
    }

    /// An observation for `basis`'s native identity whose atoms are exactly `atoms`: the
    /// crate-private `fixture_observation` with the values named. Panics unless `atoms` names
    /// exactly the basis's touched atoms (prepare refuses any other key set).
    pub fn fixture_observation_with(basis: &crate::prestate::FrozenBasis, atoms: &[(&str, bool)]) -> crate::prestate::Observation {
        let atoms: std::collections::BTreeMap<String, bool> = atoms.iter().map(|(atom, value)| (atom.to_string(), *value)).collect();
        assert!(
            atoms.keys().eq(basis.touched_atoms.keys()),
            "fixture_observation_with: name exactly the basis's touched atoms"
        );
        crate::prestate::Observation {
            native_resource_key: basis.native_resource_key.clone(),
            atoms,
            request_id: None,
            provider_label_vector: None,
        }
    }

    /// The claim every dispatch asks for: `CommandBus::claim_dispatch`'s shape at an
    /// operation's first dispatch (ordinal 1, no predecessor, zero observed attempts).
    pub fn first_claim() -> crate::AttemptClaim {
        crate::AttemptClaim { ordinal: 1, predecessor: None, observed_attempts: 0 }
    }

    /// The attempt id of a `Won` claim. Panics on any other outcome.
    pub fn won_attempt_id(outcome: crate::ClaimOutcome) -> String {
        match outcome {
            crate::ClaimOutcome::Won { attempt_id, .. } => attempt_id,
            other => panic!("won_attempt_id: the claim did not win: {other:?}"),
        }
    }

    /// Set an episode's `status` and `status_reason` columns through a raw connection. It
    /// bypasses the transition table on purpose, to reach states nothing writes yet
    /// (`paused`, `cancelled`). It writes no journal row and does not bump the generation.
    /// Panics on a store error.
    pub fn set_episode_status_for_test(path: &std::path::Path, plan_id: &crate::plan::PlanId, status: &str, reason_json: Option<&str>) {
        let conn = rusqlite::Connection::open(path).expect("set_episode_status_for_test: open");
        crate::store_open::pin_durability_profile(&conn).expect("set_episode_status_for_test: profile");
        let changed = conn
            .execute(
                "UPDATE execution_episode SET status = ?2, status_reason = ?3 WHERE plan_id = ?1;",
                rusqlite::params![plan_id.0, status, reason_json],
            )
            .expect("set_episode_status_for_test: write");
        assert_eq!(changed, 1, "set_episode_status_for_test: no episode for the plan");
    }
}

/// The observation a stateless fixture connector answers with: it answers for the frozen
/// native identity and reports every frozen atom as absent, an empty provider.
pub(crate) fn fixture_observation(basis: &prestate::FrozenBasis) -> prestate::Observation {
    prestate::Observation {
        native_resource_key: basis.native_resource_key.clone(),
        atoms: basis
            .touched_atoms
            .keys()
            .map(|atom| (atom.clone(), false))
            .collect(),
        request_id: None,
        // A fixture holds no provider label set.
        provider_label_vector: None,
    }
}

/// The restore a stateless fixture connector performs: it holds no provider state to write,
/// so it only enforces the delta-grain precondition the real connectors enforce. Every frozen
/// atom must carry a captured value, because a restore that filled a gap by guessing would be
/// a blind inverse. Fixtures that must prove a restore happened use a recording double
/// instead ([`CountingConnector::restore_count`], [`RecordingConnector::restored`]).
pub(crate) fn fixture_restore(
    basis: &prestate::FrozenBasis,
    p: &std::collections::BTreeMap<String, bool>,
) -> Result<(), ConnectorError> {
    if basis.touched_atoms.keys().any(|atom| !p.contains_key(atom)) {
        // Proven pre-wire, like the real connectors' identical refusal: `restore` runs
        // post-authorization, and this is decided from local values with nothing dispatched.
        // Answering `Indeterminate` here would make every bus-level test of this arm exercise
        // an adjudication park the shipped connectors do not take.
        return Err(ConnectorError::deterministic(
            "test: captured pre-state does not cover the frozen atoms",
        )
        .proven_no_wire());
    }
    Ok(())
}

/// A connector that always succeeds — for the earliest bus tests.
pub struct AlwaysOkConnector;

impl Connector for AlwaysOkConnector {
    fn apply(&self, _command: &Command, _basis: &prestate::FrozenBasis) -> Result<(), ConnectorError> {
        Ok(())
    }
    fn resolve_basis(&self, command: &Command) -> Result<prestate::FrozenBasis, ResolveBasisError> {
        Ok(fixture_basis(command))
    }
    fn observe(
        &self,
        _command: &Command,
        basis: &prestate::FrozenBasis,
    ) -> Result<prestate::Observation, ConnectorError> {
        Ok(fixture_observation(basis))
    }
    fn restore(
        &self,
        _command: &Command,
        basis: &prestate::FrozenBasis,
        p: &std::collections::BTreeMap<String, bool>,
    ) -> Result<(), ConnectorError> {
        fixture_restore(basis, p)
    }
}

/// A connector that counts how many times it was asked to apply — for idempotency tests.
pub struct CountingConnector {
    apply_count: std::cell::Cell<usize>,
    observe_count: std::cell::Cell<usize>,
    observed_before_applied: std::cell::Cell<bool>,
    restored: std::cell::RefCell<Vec<(String, std::collections::BTreeMap<String, bool>)>>,
    /// The atom values `observe` answers instead of `false` (`observing`).
    observed: std::collections::BTreeMap<String, bool>,
}

impl CountingConnector {
    pub fn new() -> Self {
        Self {
            apply_count: std::cell::Cell::new(0),
            observe_count: std::cell::Cell::new(0),
            observed_before_applied: std::cell::Cell::new(false),
            restored: std::cell::RefCell::new(Vec::new()),
            observed: std::collections::BTreeMap::new(),
        }
    }
    /// A counting connector whose `observe` answers these values for the named atoms. Each
    /// frozen atom it does not name still answers `false`, and a named atom the basis does not
    /// freeze is not reported (the observation covers exactly the frozen atoms).
    pub fn observing(atoms: &[(&str, bool)]) -> Self {
        Self { observed: atoms.iter().map(|(atom, value)| (atom.to_string(), *value)).collect(), ..Self::new() }
    }
    pub fn apply_count(&self) -> usize {
        self.apply_count.get()
    }
    /// Observations are counted separately from applies: a pre-state read is not a mutation,
    /// so an apply-count assertion must never be satisfied by an observe.
    pub fn observe_count(&self) -> usize {
        self.observe_count.get()
    }
    /// Did an observation happen before the very first apply? Capture is worthless if the
    /// effect landed first. Sampled at the first apply, so a later observation cannot backdate
    /// the answer.
    pub fn observed_before_applied(&self) -> bool {
        self.observed_before_applied.get()
    }
    /// How many restores were dispatched, counted separately from applies and observes, so a
    /// "undo restored nothing" assertion cannot be satisfied by either.
    pub fn restore_count(&self) -> usize {
        self.restored.borrow().len()
    }
    /// Every restore's `(native_resource_key, P)`: the values actually written back.
    pub fn restored(&self) -> Vec<(String, std::collections::BTreeMap<String, bool>)> {
        self.restored.borrow().clone()
    }
}

impl Default for CountingConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl Connector for CountingConnector {
    fn apply(&self, _command: &Command, _basis: &prestate::FrozenBasis) -> Result<(), ConnectorError> {
        if self.apply_count.get() == 0 {
            self.observed_before_applied
                .set(self.observe_count.get() > 0);
        }
        self.apply_count.set(self.apply_count.get() + 1);
        Ok(())
    }
    fn resolve_basis(&self, command: &Command) -> Result<prestate::FrozenBasis, ResolveBasisError> {
        Ok(fixture_basis(command))
    }
    fn observe(
        &self,
        _command: &Command,
        basis: &prestate::FrozenBasis,
    ) -> Result<prestate::Observation, ConnectorError> {
        self.observe_count.set(self.observe_count.get() + 1);
        let mut observation = fixture_observation(basis);
        for (atom, value) in observation.atoms.iter_mut() {
            if let Some(configured) = self.observed.get(atom) {
                *value = *configured;
            }
        }
        Ok(observation)
    }
    fn restore(
        &self,
        _command: &Command,
        basis: &prestate::FrozenBasis,
        p: &std::collections::BTreeMap<String, bool>,
    ) -> Result<(), ConnectorError> {
        fixture_restore(basis, p)?;
        self.restored
            .borrow_mut()
            .push((basis.native_resource_key.clone(), p.clone()));
        Ok(())
    }
}

/// A connector that always fails transiently, for retry and recovery failure-path tests.
pub struct AlwaysFailConnector;

impl Connector for AlwaysFailConnector {
    fn apply(&self, _command: &Command, _basis: &prestate::FrozenBasis) -> Result<(), ConnectorError> {
        // The connect-stage proof a retryable failure carries: an unproven post-authorization
        // failure is `ISSUANCE_UNKNOWN` and is never retried, so a fixture that models "the
        // network failed before the mutation went out" must say so.
        Err(ConnectorError::transient("connector failed").proven_no_wire())
    }
    fn resolve_basis(&self, command: &Command) -> Result<prestate::FrozenBasis, ResolveBasisError> {
        Ok(fixture_basis(command))
    }
    fn observe(
        &self,
        _command: &Command,
        basis: &prestate::FrozenBasis,
    ) -> Result<prestate::Observation, ConnectorError> {
        Ok(fixture_observation(basis))
    }
    /// A provider that rejects every mutation rejects the restore mutation too; a restore
    /// that silently succeeded would let a test pass against a provider that never accepted a
    /// write.
    fn restore(
        &self,
        _command: &Command,
        _basis: &prestate::FrozenBasis,
        _p: &std::collections::BTreeMap<String, bool>,
    ) -> Result<(), ConnectorError> {
        // Same connect-stage proof as `apply` above.
        Err(ConnectorError::transient("connector failed").proven_no_wire())
    }
}

/// A connector that always fails deterministically, for dead-letter tests. Stands in for the
/// real connector's "this will never succeed" verdict (validation, permission, missing
/// target); the actual error-policy taxonomy belongs to each connector (ADR-P013).
///
/// It models a provider that answered and refused, so it says so
/// ([`EffectEvidence::ProvenRefusedNoEffect`]): a dead-letter asserts "no effect", and that
/// assertion needs the proof, not merely the retry kind.
pub struct DeterministicFailConnector {
    message: String,
}

impl DeterministicFailConnector {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl Connector for DeterministicFailConnector {
    fn apply(&self, _command: &Command, _basis: &prestate::FrozenBasis) -> Result<(), ConnectorError> {
        Err(ConnectorError::deterministic(self.message.clone()).proven_refused_no_effect())
    }
    fn resolve_basis(&self, command: &Command) -> Result<prestate::FrozenBasis, ResolveBasisError> {
        Ok(fixture_basis(command))
    }
    fn observe(
        &self,
        _command: &Command,
        basis: &prestate::FrozenBasis,
    ) -> Result<prestate::Observation, ConnectorError> {
        Ok(fixture_observation(basis))
    }
    /// The same permanent verdict the apply path gives (see `AlwaysFailConnector::restore`).
    fn restore(
        &self,
        _command: &Command,
        _basis: &prestate::FrozenBasis,
        _p: &std::collections::BTreeMap<String, bool>,
    ) -> Result<(), ConnectorError> {
        Err(ConnectorError::deterministic(self.message.clone()).proven_refused_no_effect())
    }
}

/// A connector that records every action it applied, for inspecting dispatch (e.g. undo).
pub struct RecordingConnector {
    applied: std::cell::RefCell<Vec<Action>>,
    restored: std::cell::RefCell<Vec<(String, std::collections::BTreeMap<String, bool>)>>,
}

impl RecordingConnector {
    pub fn new() -> Self {
        Self {
            applied: std::cell::RefCell::new(Vec::new()),
            restored: std::cell::RefCell::new(Vec::new()),
        }
    }
    pub fn applied_actions(&self) -> Vec<Action> {
        self.applied.borrow().clone()
    }
    /// Every restore's `(native_resource_key, P)`, for inspecting the undo path. Kept separate
    /// from `applied_actions` because a restore is not an action replay.
    pub fn restored(&self) -> Vec<(String, std::collections::BTreeMap<String, bool>)> {
        self.restored.borrow().clone()
    }
}

impl Default for RecordingConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl Connector for RecordingConnector {
    fn apply(
        &self,
        command: &Command,
        _basis: &prestate::FrozenBasis,
    ) -> Result<(), ConnectorError> {
        self.applied.borrow_mut().push(command.action.clone());
        Ok(())
    }
    fn resolve_basis(&self, command: &Command) -> Result<prestate::FrozenBasis, ResolveBasisError> {
        Ok(fixture_basis(command))
    }
    fn observe(
        &self,
        _command: &Command,
        basis: &prestate::FrozenBasis,
    ) -> Result<prestate::Observation, ConnectorError> {
        Ok(fixture_observation(basis))
    }
    fn restore(
        &self,
        _command: &Command,
        basis: &prestate::FrozenBasis,
        p: &std::collections::BTreeMap<String, bool>,
    ) -> Result<(), ConnectorError> {
        fixture_restore(basis, p)?;
        self.restored
            .borrow_mut()
            .push((basis.native_resource_key.clone(), p.clone()));
        Ok(())
    }
}
