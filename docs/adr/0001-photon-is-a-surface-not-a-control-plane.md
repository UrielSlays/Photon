# ADR-P001: Photon is a surface, not a control plane

**Status:** Accepted


**Decision.** Photon is a governed *surface*. Identity, authority, audit custody, and orchestration belong to a separate control plane. Photon mints **no identity** and grants **no authority**. It enforces gates, records evidence, executes approved actions against mail providers, and nothing more.

Photon MUST be useful without a control plane, but governed by one when present — a two-tier model:

- **Bare (latch mode):** Photon runs standalone. Agents latch via the contract (MCP tools over the local API). Humans use the mail shell directly. Approval gates, tiers, evidence, and snapshots all function locally. This is the dogfood configuration and the configuration most early users will run.
- **Governed:** Control-plane identity, epoch, seizure, and evidence custody come online. Photon's local gates become the *enforcement point* for authority decisions made above it.

**Why.** The control plane must not be welded to any one surface, and no surface may grow its own competing authority model. The moment Photon mints trust, the two-layer defense collapses into one and the architecture is dead.

**Rejected.** Photon as a standalone hero product with its own accounts/identity system; Photon depending on a control plane to be usable at all (kills dogfooding and adoption); a built-in chat assistant (Photon is agent-operable, not agent-opinionated — this was already settled in the MailOps roadmap and survives the rename).
