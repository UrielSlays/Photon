//! Provider-neutral read-model vocabulary: the [`Placement`] belief, the opaque
//! [`ProviderMessageId`] key, and the [`ProviderPlacement`] provider-truth seam. They were moved
//! out of `crate::jmap` because they are read-model vocabulary, not JMAP vocabulary. The
//! JMAP-native types (`EmailId`, `MailboxId`, `MailboxRole`, transports) stay in `crate::jmap`,
//! and each provider crate converts [`ProviderMessageId`] to its own native id type at its own
//! boundary.
//!
//! Import ban: this module must never depend on `crate::jmap`; the dependency arrow points the
//! other way. A test below scans this file's own source for it.

use serde::{Deserialize, Serialize};

use crate::{ConnectorError, LogError};

/// An opaque provider-native message id (a JMAP `Email` id or a Gmail message id), the name for
/// what `message_placement.email_id` already stores. It stays below the seam and is never
/// inspected here: the store round-trips it as text, and each provider crate converts it to its
/// native id type at its own boundary.
///
/// It derives `Serialize`/`Deserialize` because [`crate::read_surface::HeaderSummary`] carries it
/// as its identity field and crosses IPC. The id stays opaque text on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderMessageId(pub String);

/// The read-side placement of a message. The original pair (`Action::Archive`/`Unarchive`) was a
/// closed two-variant enum on purpose, since widening it with no writer and no consumer would be
/// an inert axis. It now has the two RED-territory states the triage verbs write, each with its
/// producers: `ReadCoordinator::write_verb_delta` (the `Trashed`/`Untrashed`/`SpamSet` deltas,
/// which file the header row under [`Placement::mailbox`]) and the Gmail derivation
/// (`aruna-gmail` `placement_from_labels`, provider truth to belief). Provider states the model
/// rejects still fail closed in each provider's own derivation, and states that are
/// archive-semantics land in that derivation's documented model-compression arm, never a silent
/// collapse here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Placement {
    Inbox,
    Archive,
    Trash,
    Spam,
}

impl Placement {
    /// Every variant, so round-trip tests are generated from this list rather than hand-listed
    /// (`attempt.rs`'s `FactKind::ALL` pattern). [`Placement::from_token`] parses by searching it,
    /// so a variant left off it cannot be read back from the store. Today its type fixes four
    /// entries and the tests require four distinct tokens, which with four variants is every
    /// variant. A fifth variant is a compile error in [`Placement::as_str`]/[`Placement::mailbox`]
    /// (exhaustive `match`es) but not here: it must be added by hand, and only a test that
    /// constructs it would notice if it were not.
    pub const ALL: [Placement; 4] = [
        Placement::Inbox,
        Placement::Archive,
        Placement::Trash,
        Placement::Spam,
    ];

    /// String form for durable storage: a stable on-disk token.
    pub fn as_str(self) -> &'static str {
        match self {
            Placement::Inbox => "inbox",
            Placement::Archive => "archive",
            Placement::Trash => "trash",
            Placement::Spam => "spam",
        }
    }

    /// Parse the durable token; an unknown value is an error, never a silent default.
    pub fn from_token(s: &str) -> Result<Self, LogError> {
        Placement::ALL
            .iter()
            .copied()
            .find(|p| p.as_str() == s)
            .ok_or_else(|| LogError(format!("unknown placement in store: {s}")))
    }

    /// The `message_header.mailbox` display token for this placement. It is total (an exhaustive
    /// `match`, so a new variant does not compile until it names its folder). The constants live
    /// in `read_coordinator` (`MAILBOX_*`); this is the one mapping from a placement to them, and
    /// `write_verb_delta` derives its header folder from it, so that writer's two rows cannot
    /// name different placements. (The ingest path still writes its Inbox pair as two named
    /// constants in `read_coordinator`'s `ingest_row`.)
    pub fn mailbox(self) -> &'static str {
        match self {
            Placement::Inbox => crate::read_coordinator::MAILBOX_INBOX,
            Placement::Archive => crate::read_coordinator::MAILBOX_ARCHIVE,
            Placement::Trash => crate::read_coordinator::MAILBOX_TRASH,
            Placement::Spam => crate::read_coordinator::MAILBOX_SPAM,
        }
    }

    /// The placement a refresh-reconcile records for a row that vanished from the inbox listing
    /// (`read_coordinator` `refresh_reconcile`'s withdrawal UPDATE). Absent from INBOX means
    /// archived, which is Gmail's documented model-compression arm. A listing diff carries no
    /// label read, so that UPDATE cannot tell an archived message from an externally trashed or
    /// spammed one and records Archive for all three. Correcting such a row to Trash/Spam needs a
    /// placement read (`aruna-gmail` `placement_from_labels` derives both); this default does not
    /// claim that any caller performs it.
    pub fn withdrawal_default() -> Placement {
        Placement::Archive
    }
}

/// Reads the provider's current placement for a message, the truth source for divergence
/// correction. It is faked in `aruna` unit tests, and the real impls live per provider crate
/// (`aruna-jmap` via `Email/get`, `aruna-gmail` via `users.messages.get`), which keeps `aruna`
/// HTTP-free. It is keyed on the neutral [`ProviderMessageId`]. `Err` carries a normalized
/// [`ConnectorError`]: a fetch failure is surfaced, never swallowed into a false "converged".
pub trait ProviderPlacement {
    fn fetch_placement(
        &self,
        account: &str,
        id: &ProviderMessageId,
    ) -> Result<Placement, ConnectorError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placement_tokens_round_trip_and_unknown_fails() {
        assert_eq!(Placement::Inbox.as_str(), "inbox");
        assert_eq!(Placement::Archive.as_str(), "archive");
        assert_eq!(Placement::from_token("inbox").unwrap(), Placement::Inbox);
        assert_eq!(Placement::from_token("archive").unwrap(), Placement::Archive);
        // Was `"trash"` through M1; made trash a placement, so the unknown-token probe
        // is now a state the model still has no belief for.
        assert!(Placement::from_token("sent").is_err());
    }

    #[test]
    fn placement_tokens_round_trip_for_every_variant_generated_from_the_list() {
        // Generated from `Placement::ALL`, not hand-listed (attempt.rs `FactKind::ALL` pattern):
        // every listed variant round-trips or this fails. Four DISTINCT tokens over a four-entry
        // list is every variant of today's enum (see `ALL`'s doc for what this does not guard).
        for p in Placement::ALL {
            assert_eq!(Placement::from_token(p.as_str()).unwrap(), p);
        }
        assert_eq!(Placement::ALL.len(), 4);
        let distinct: std::collections::BTreeSet<&str> =
            Placement::ALL.iter().map(|p| p.as_str()).collect();
        assert_eq!(distinct.len(), Placement::ALL.len(), "no variant is listed twice");
        assert_eq!(Placement::from_token("trash").unwrap(), Placement::Trash);
        assert_eq!(Placement::from_token("spam").unwrap(), Placement::Spam);
        assert_eq!(Placement::Trash.as_str(), "trash");
        assert_eq!(Placement::Spam.as_str(), "spam");
        assert!(Placement::from_token("sent").is_err());
    }

    #[test]
    fn mailbox_is_total_and_the_withdrawal_default_is_named() {
        assert_eq!(Placement::Inbox.mailbox(), "Inbox");
        assert_eq!(Placement::Archive.mailbox(), "Archive");
        assert_eq!(Placement::Trash.mailbox(), "Trash");
        assert_eq!(Placement::Spam.mailbox(), "Spam");
        assert_eq!(Placement::withdrawal_default(), Placement::Archive);
    }

    #[test]
    fn read_model_module_never_imports_the_jmap_module() {
        // Design §2.1 closure witness, part (e): the ownership move is a DEPENDENCY claim, not a
        // name grep — `read_model` must not lean on `crate::jmap` in any form. Parts (a)/(d) are
        // witnessed by the workspace compiling with the old `jmap::Placement` /
        // `jmap::ProviderPlacement` exports deleted; part (c) by both provider crates carrying a
        // `ProviderPlacement` impl.
        // The needle is assembled at runtime so this test's own bytes cannot satisfy it, and
        // comment/doc lines are skipped so PROSE naming the ban does not trip the ban.
        let needle: String = ["crate", "::", "jmap"].concat();
        let source = include_str!("read_model.rs");
        let offending: Vec<&str> = source
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .filter(|line| line.contains(&needle))
            .collect();
        assert!(
            offending.is_empty(),
            "read_model.rs must not depend on the jmap module (design §2.1 import ban): {offending:?}"
        );
    }
}
