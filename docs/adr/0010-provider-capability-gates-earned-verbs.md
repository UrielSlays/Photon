# ADR-P010: Provider capability gates, earned verbs

**Status:** Accepted


**Decision.** Each connector publishes an explicit capability map (scan, body fetch, archive, label, trash, unsubscribe, rules, send). Unsupported operations fail safe and visibly. Write capabilities are enabled per-provider, per-tier, in order of reversibility: YELLOW verbs first (archive on Gmail API is the canonical first write), then RED, then BLACK — each enablement gated by the validation gate (Part III), never by roadmap pressure. Real-provider destructive execution remains globally disabled until the gate passes. Manual IMAP/app-password setup remains the advanced/fallback path; OAuth onboarding (Google, Microsoft) is the mainstream path; secrets stay in OS-backed credential storage (keyring/DPAPI), never SQLite, never plaintext, never logs.

**Why.** Capability-gated, not guessed — already MailOps doctrine, now bound to the tier system. "Earn the next verb" converts the roadmap from a feature list into a trust ladder, which is also exactly the shape regulators are converging on.

**Rejected.** Symmetric capability claims across providers (IMAP cannot do what Graph does; pretending otherwise produces silent failure); enabling send because a demo needs it.
