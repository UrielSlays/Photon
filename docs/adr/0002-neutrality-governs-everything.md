# ADR-P002: Neutrality governs everything

**Status:** Accepted


**Decision.** Photon MUST NOT weld itself to one agent, one model provider, one mail provider, or one client experience. Any agentic entity may latch. Gmail, Outlook/Graph, generic IMAP, and future JMAP accounts are peers behind one connector contract. The agent API is provider-blind: the same tools, the same tiers, the same gates, regardless of who is calling or whose mailbox is underneath.

**Why.** Neutrality is the structural position. Every lab is building AI *into* its own products — the mailbox as a lock-in for their model. The structurally open position is the substrate none of them can own: a mail surface where every lab's agent gets the same hands under the same supervision. A single lab owning the substrate makes it non-neutral by definition; neutrality is only credible from a layer with nothing else to defend.

**Rejected.** Copilot-style captive integration; per-agent feature tiers; "premium" providers getting verbs that others don't (capability differences must come from provider API reality, never from commercial preference).
