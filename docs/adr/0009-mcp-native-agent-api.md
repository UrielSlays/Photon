# ADR-P009: The agent API is MCP-native and approval gates live in the surface

**Status:** Accepted


**Decision.** Photon's agent layer is a real MCP server (graduating the current `agent_api/` stub). Tools are published with tier labels (ADR-P005) and scope declarations in their schemas. Any MCP-speaking agent latches with zero Photon-specific training. The approval UI — the review queue that already exists — is Photon's, not the agent's: agents *propose*, Photon *gates*, humans *authorize*. Approval state, bypass events, and outcomes are first-class telemetry events (consent-architected, local-first, exportable only by explicit user action) — the actuary's raw feed.

Prompt-injection posture is inherited and hardened: email content is untrusted data, never instructions; no message body, subject, snippet, or header may originate an agent command; protected categories cannot be bypassed by message content. The current keyword-based guard is acknowledged as advisory only — the *structural* defense is that gates and tiers are enforced in Photon's process, outside any LLM context window, so a prompt-injected agent can at worst *propose* something a human still has to approve.

**Why.** MCP won the protocol war for tool exposure; fighting that is wasted motion. Gates living in the surface (not the agent) is what makes Photon agent-neutral *and* what makes it safe to give a thin model wrapper hands: the lab's agent doesn't have to be trusted, because the surface doesn't trust anyone.

**Rejected.** Per-agent SDKs; trusting agent self-reported identity for anything beyond labeling (authority is the control plane's or, in latch mode, the local human's); LLM-based injection detection as a primary control (fine as a signal, never as the gate).
