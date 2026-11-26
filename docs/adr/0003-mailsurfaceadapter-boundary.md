# ADR-P003: The MailSurfaceAdapter boundary (provider-protocol-is-scaffolding law)

**Status:** Accepted


**Decision.** All mailbox actuation goes through a generic **`MailSurfaceAdapter`** interface — a generic surface-adapter contract specialized for mail: `enumerateAccounts()`, `attach()`, `perceive()` (metadata/folder/message reads), `act(ActionEnvelope)`, `detach()`. IMAP, Gmail API, and Microsoft Graph are *implementations confined below the boundary*.

**No adapter-native handle leaks above the boundary.** No IMAP UID, no UIDVALIDITY pair, no Gmail message id, no Graph resource id, no folder path string ever becomes durable identity, authority, or audit vocabulary. Photon mints its own durable nouns (ADR-P004) and maintains the mapping privately inside each connector.

**Why.** Volatile, protocol-native handles masquerading as identity corrupt everything built on them. Mail is *worse* than the browser here — IMAP UIDs are explicitly unstable (UIDVALIDITY resets), Gmail ids don't survive account migration, and folder paths are a localization minefield. The existing MailOps connector registry already points this direction; this ADR makes it law.

**Rejected.** Building the contract on Gmail API semantics because it's the richest; letting the planner or review queue store provider ids as primary keys.
