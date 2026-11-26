# ADR-P004: Durable nouns, shared vocabulary

**Status:** Accepted


**Decision.** Photon speaks the shared governance noun vocabulary wherever a concept already exists — `PrincipalId`, `AuthorityGrantId`, `ActionEnvelope`, `IdempotencyKey`, `EvidenceChainHead` are *imported, not re-invented*. Photon adds mail-shaped durable nouns it owns: `PhotonAccountId`, `PhotonMessageId`, `PhotonThreadId`, `PhotonFolderId`, `PlanId`, `ActionId`, `SnapshotId`. All are logical and survive volatile provider handles.

**Why.** Two surfaces with one contract requires one vocabulary. If Photon's evidence records and another surface's evidence records use different words for "who" and "under what authority," the control plane has to translate — and translation layers are where audit integrity goes to die.

**Rejected.** A fresh noun set "because mail is different" (it isn't, at the contract layer); reusing provider message-ids with a prefix (still volatile underneath).
