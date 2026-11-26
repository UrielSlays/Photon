# Architecture decisions

Photon is a governed mail *surface*.

Photon implements an agent-latch contract: identity-bound, auditable, recoverable, and neutral. It exists to prove that this contract governs the mailbox without modification to its load-bearing ideas. That is the actual bet: not "a better mail client," but a surface-neutral contract for agentic action that any agent — Claude, ChatGPT, Gemini, a local model, a thin web wrapper given hands — can latch onto, under human authority, with evidence before effect.

Mail is a good surface for this contract for three reasons. It is the most universally deployed high-stakes workflow on earth. It is bounded enough to gate completely — the verb set is small and enumerable in a way "the web" never is. And it is the terrain where the cost of agent error is immediately legible to ordinary people: a deleted tax document, a sent email that cannot be unsent. If the contract holds here, the claim that it generalizes is no longer speculative.

These records capture the decisions the code is built against, and the gate Photon must pass before it may write to a real mailbox. Each decision is changed only by a pull request that amends its file with the rationale.

## Decisions

- [ADR-P001: Photon is a surface, not a control plane](0001-photon-is-a-surface-not-a-control-plane.md)
- [ADR-P002: Neutrality governs everything](0002-neutrality-governs-everything.md)
- [ADR-P003: The MailSurfaceAdapter boundary (provider-protocol-is-scaffolding law)](0003-mailsurfaceadapter-boundary.md)
- [ADR-P004: Durable nouns, shared vocabulary](0004-durable-nouns-shared-vocabulary.md)
- [ADR-P005: The color-tier action taxonomy](0005-the-color-tier-action-taxonomy.md)
- [ADR-P006: Action transaction boundary and the irreversible pivot](0006-action-transaction-boundary-and-the-irreversible-pivot.md)
- [ADR-P007: Snapshot-before-mutation; recovery over prevention theater](0007-snapshot-before-mutation-recovery-over-prevention-theater.md)
- [ADR-P008: Evidence-before-effect, aligned to the A–F record](0008-evidence-before-effect-aligned-to-the-a-f-record.md)
- [ADR-P009: The agent API is MCP-native and approval gates live in the surface](0009-mcp-native-agent-api.md)
- [ADR-P010: Provider capability gates, earned verbs](0010-provider-capability-gates-earned-verbs.md)
- [ADR-P011: Regulatory mapping is a build artifact, not marketing](0011-regulatory-mapping-is-a-build-artifact-not-marketing.md)
- [ADR-P012: Naming and namespace hygiene](0012-naming-and-namespace-hygiene.md)
- [ADR-P013: The idempotency-decision gate (one status-aware decision point)](0013-idempotency-decision-gate.md)

## Part III: Validation gate

Before Photon enables any RED verb on a real provider, before any BLACK verb exists anywhere outside the mock connector, and before any hosted/enterprise/multi-user conversation:

- **Adversarial suite green** (step 8) — every safety invariant has a test that tried to break it and failed.
- **Evidence completeness audit** — sample real actions end-to-end; every one traceable envelope → approval → evidence record → outcome, hash chain verified, no gaps.
- **Recovery drill** — restore from snapshot for every YELLOW/RED verb class against a live mailbox; undo produces byte-faithful state (metadata verbs) or full-source recovery (trash).
- **Kill-mid-batch drill** — executor terminated at each phase boundary under a real bulk operation; no half-applied, no double-applied on resume.
- **Injection drill** — adversarial mailbox seeded with hostile content (instruction-shaped subjects/bodies, protected-category mimicry); assert zero gate bypasses and zero agent-command origination from content.
- **Dogfood mileage** — the maintainer runs Photon on real accounts as the daily driver through at least one full review→approve→execute→undo cycle per verb class.

Until passed: local-only, attended, real-provider destructive execution disabled.
