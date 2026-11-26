# ADR-P012: Naming and namespace hygiene

**Status:** Accepted


**Decision.** "Photon" lives at the brand layer only. All sensitive internals — tool names, audit fields, schema names, paths — are dry and descriptive (`mail-surface-adapter`, `action-envelope`, `evidence-writer`, `snapshot-store`). The rename from "Agent MailOps" is executed as one atomic pass (repo name, package metadata, docs, UI strings) verified by zero old-name references on sensitive paths.

**Trademark caution, recorded:** "Photon" is also a collided name (the Photon real-time multiplayer engine in game development; VMware's Photon OS Linux distribution, among others). A clearance check happens before any public release; the brand-layer-only rule means a forced rename later costs a string table, not an architecture.

**Why.** Brands churn; contracts shouldn't.
