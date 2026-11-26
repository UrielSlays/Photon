# ADR-P006: Action transaction boundary and the irreversible pivot

**Status:** Accepted


**Decision.** Every YELLOW+ action follows a four-phase transaction shape: INTENT → PRE-COMMIT → COMMIT → POST-COMMIT, keyed by `IdempotencyKey`, interruptible only at phase boundaries. Every action is classified technically-reversible / socially-reversible / compensatable / irreversible — and the classification drives the tier (ADR-P005), not vice versa. BLACK actions hard-pause at PRE-COMMIT for explicit positive human authorization.

For mail specifically: the PRE-COMMIT phase is where the pre-mutation snapshot (ADR-P007) is taken and where evidence is written (ADR-P008). A send action that fails its evidence write never reaches the SMTP/API call. No half-applied bulk archive; no double-applied trash sweep on retry; no "the agent sent it twice."

**Why.** The actuary needs the four-class outcome data in the same shape from every surface.

**Rejected.** Treating mail actions as fire-and-forget API calls with after-the-fact logging.
