# ADR-P011: Regulatory mapping is a build artifact, not marketing

**Status:** Accepted


**Decision.** Photon maintains a compliance map as a living document (not yet written) mapping architecture properties to regulatory requirements as they solidify: EU AI Act human-oversight and logging articles, UK pro-innovation principles, Singapore PDPC/MAS guidance, China's interim generative-AI measures, and successors. Each row maps a *requirement* to an *architectural mechanism* (human gate, evidence chain, local-first residency, snapshot/recovery, consent-gated telemetry) — mappings, not claims. Where Photon does not yet satisfy a requirement, the row says so.

**Why.** The architecture *is* the compliance posture — human approval gates, tamper-evident audit (detection-capable at the standalone tier; stronger continuity claims only at the witnessed attached tier — the limit ADR-P008's honesty note states), no autonomous irreversible action, local data residency. That sentence is only credible if the mapping is maintained with the same adversarial honesty as the code (claims labeled as intent until tested). Enterprise procurement and regulator conversations then read a maintained engineering document instead of a pitch deck.

**Rejected.** Compliance-by-press-release; deferring the document until "we go enterprise" (retrofitting the mapping is how overclaims are born).
