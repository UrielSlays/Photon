//! The reserved key namespace, the record-boundary refusals, and the idempotency-key derivation.

use crate::command::facet_to_str;
use crate::{Command, Facet, LogError};

/// Reserved key-namespace prefix for internally minted intents (deferred-undo compensations).
/// A leading U+0001 can never appear in a key from [`derive_idempotency_key`] (printable
/// length-prefixed text only), and [`IntentLog::record`] refuses a non-compensation command in
/// this namespace, so a minted compensation key cannot collide with a caller's key.
const RESERVED_KEY_PREFIX: char = '\u{1}';

/// The reserved, collision-free idempotency key for the undo child of a parent intent.
/// Deterministic (stable across undo retries, so idempotent) and outside the caller namespace.
///
/// The argument is the parent's opaque `intent_id`, never a user-visible key, so the child's
/// durable key is content-free (no user key text, no message handle) while staying
/// uncollidable (one parent row, one opaque id, one child key). The `\u{1}` namespace stays
/// engine-exclusive: a user-submitted key in it is rejected at both admission paths
/// ([`reject_reserved_user_key`]).
pub(crate) fn compensation_key(parent_intent_id: &str) -> String {
    format!("{RESERVED_KEY_PREFIX}undo:{parent_intent_id}")
}

/// The reserved key for a new undo child, minted over the parent's opaque `intent_id` in a
/// domain disjoint from the legacy [`compensation_key`] shape a pre-rework store may hold.
///
/// Why a separate domain: the legacy deferred-undo child was keyed
/// `compensation_key(parent user idempotency_key)` = `\u{1}undo:<user_key>`; the new child is
/// keyed on the opaque `intent_id`. In an upgraded store a user key value could equal another
/// parent's `intent_id`, and under one shared `compensation_key` the two child keys would be
/// the same string, so `undo()` would consume the wrong child's verdict. This form places the
/// reserved char `\u{1}` where the legacy format has a `:`; a legacy user key can never contain
/// `\u{1}` ([`reject_reserved_user_key`] guarantees it), so `\u{1}undo\u{1}<id>` can never equal
/// `\u{1}undo:<user_key>` for any inputs. [`compensation_key`] is unchanged for the legacy
/// lookup path ([`CommandBus::legacy_deferred_child`]) and stays the
/// [`reject_reserved_user_key`] contract.
pub(crate) fn undo_child_key(parent_intent_id: &str) -> String {
    format!("{RESERVED_KEY_PREFIX}undo{RESERVED_KEY_PREFIX}{parent_intent_id}")
}

/// Reject a non-compensation command that tries to claim the reserved internal namespace,
/// which is exclusive to engine-minted compensations (`compensates.is_some()` may use it).
pub(crate) fn reject_reserved_user_key(command: &Command) -> Result<(), LogError> {
    if command.compensates.is_none() && command.idempotency_key.starts_with(RESERVED_KEY_PREFIX) {
        return Err(LogError(format!(
            "idempotency key '{}' uses the reserved internal namespace",
            command.idempotency_key
        )));
    }
    Ok(())
}

/// Refuse a structurally invalid `FrozenBasis` at the durable boundary: `execute()` validates
/// the resolver's output, but `record()` is what a direct caller reaches, and a committed basis
/// that `FrozenBasis::from_json` would refuse to re-read poisons every later
/// `get()`/`unreconciled()` sweep. The log never persists a value it cannot re-read. Uses the
/// same check as `from_json` (`FrozenBasis::validate`).
pub(crate) fn reject_unreadable_basis(basis: &crate::prestate::FrozenBasis) -> Result<(), LogError> {
    basis
        .validate()
        .map_err(|e| LogError(format!("record refused: unreadable frozen basis — {e}")))
}

/// Refuse a basis that is not admissible, on the fresh-insert path of both `record` impls.
/// [`CommandBus::resolve_admission_basis`] runs the same check, but `record()` is the durable
/// boundary a direct caller reaches, and a row committed without the forward target vector `A`
/// can never answer the requalification table or the no-op check later; its undo degrades to
/// `PredatesSubstrate` forever. Both paths share
/// [`prestate::FrozenBasis::validate_for_admission`] and carry its message through.
///
/// Fresh-insert only: an `AlreadyExisted` replay of an existing row must not be re-validated,
/// or every legacy row with empty `atom_targets` (legal at the storage tier) would stop
/// replaying idempotently and start erroring. The durable command is immutable, and so is the
/// basis it already froze.
pub(crate) fn reject_inadmissible_basis(basis: &crate::prestate::FrozenBasis) -> Result<(), LogError> {
    basis
        .validate_for_admission()
        .map_err(|e| LogError(format!("record refused: inadmissible frozen basis — {e}")))
}

/// Derives the durable idempotency key for a logical intent: deterministic and namespaced by
/// `(account, facet)`. Components are **length-prefixed** (byte length) so the split is
/// unambiguous: no component value, even one containing a delimiter, can collide with a
/// different triple. Same inputs give the same key (safe to re-derive on retry); a different
/// account/facet/logical_id gives a different key.
///
/// Callers own two obligations not enforced here: `logical_id` must be stable per logical
/// intent across retries (never a per-attempt UUID/timestamp, else dedup breaks), and
/// `account` normalization (e.g. case) is the provider/connector's job.
pub fn derive_idempotency_key(account: &str, facet: &Facet, logical_id: &str) -> String {
    let facet_s = facet_to_str(facet);
    format!(
        "{}:{}|{}:{}|{}:{}",
        account.len(),
        account,
        facet_s.len(),
        facet_s,
        logical_id.len(),
        logical_id
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Facet;

    #[test]
    fn derived_idempotency_keys_are_namespaced_by_account_and_facet() {
        // Idempotency-key contract: deterministic per logical intent,
        // stable across retries, namespaced by (account, facet). The same logical id under
        // two accounts must NOT produce the same key (which would collapse them in the log).
        let a = derive_idempotency_key("acct-A", &Facet::Mail, "archive-msg-1");
        let b = derive_idempotency_key("acct-B", &Facet::Mail, "archive-msg-1");
        let a_again = derive_idempotency_key("acct-A", &Facet::Mail, "archive-msg-1");

        assert_ne!(a, b, "different accounts must yield different keys");
        assert_eq!(
            a, a_again,
            "derivation must be deterministic / stable across crash-retry"
        );
    }

    #[test]
    fn derive_idempotency_key_is_collision_free_under_delimiter_injection() {
        // / robust-identity: a component containing the delimiter must not let
        // two DISTINCT triples derive the same key. Raw concatenation collides here; a
        // length-prefixed encoding makes the split unambiguous.
        let a = derive_idempotency_key("acct", &Facet::Mail, "mail\u{1f}x");
        let b = derive_idempotency_key("acct\u{1f}mail", &Facet::Mail, "x");
        assert_ne!(a, b, "delimiter injection must not collapse distinct triples");
    }

    #[test]
    fn new_and_legacy_undo_child_key_domains_are_disjoint() {
        // A VALUE collision: one parent's OPAQUE intent_id equals another
        // parent's USER idempotency key (both a 32-hex string). The new undo child is minted
        // over the intent_id; the pre-rework legacy child was minted over the user key. If both
        // ride `compensation_key`, the two keys are the SAME string and undo consumes the
        // wrong child's verdict. The domains must be DISJOINT BY CONSTRUCTION.
        let shared = "0123456789abcdef0123456789abcdef".to_string();
        assert_ne!(
            undo_child_key(&shared),   // new domain: \u{1}undo\u{1}<intent_id>
            compensation_key(&shared), // legacy domain: \u{1}undo:<user_key>
            "new undo-child and legacy compensation key domains must be disjoint"
        );
        // The reserved char sits where the legacy `:` does, so the forms can NEVER coincide —
        // and the legacy lookup shape is unchanged (regression fence for map_legacy_deferred_child).
        assert_eq!(undo_child_key(&shared), format!("\u{1}undo\u{1}{shared}"));
        assert_eq!(compensation_key(&shared), format!("\u{1}undo:{shared}"));
    }
}
