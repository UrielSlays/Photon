# Photon crypto inventory — every digest / MAC site in exactly one bucket

> **HOME:** `docs/crypto-inventory.md` in the Photon repo — ADR-P008 gate (f): "a Photon-repo
> crypto-inventory census is created (mirroring a FIPS inventory's partition rule: every
> digest/MAC site lands in exactly one named bucket — CAS · sealed-row/event · content-commitment
> · checkpoint · signature-suite · provenance/attestation-binding · external-mandate;
> classification follows the SEMANTIC INPUT, never the field name, per CALL SITE never per file".
> The POSTURE is: strict SHA-384 everywhere we control the format; SHA-256/SHA-1 only under a
> documented external mandate — this file inventories Photon's sites against that posture and never
> restates a wider one.
>
> **PARTITION RULE (repo-wide, per CALL SITE):** every digest or MAC call site, of any algorithm
> or width, under `crates/**/*.rs` and `src-tauri/src/**/*.rs` MUST have a row in exactly one
> bucket below, naming the site's path AND its enclosing item (`fn` / `type` / `const` / `static` /
> `impl` name); the bucket is chosen by the site's SEMANTIC INPUT, never by the field or file it
> lives in. A site with no row is a defect of THIS DOCUMENT. Executable arm:
> `crates/aruna/tests/crypto_census.rs` — the net approximates this rule over the spellings in its
> `NEEDLES` (a digest API spelled outside them obliges a new needle there and a row here). For
> each matching line the net takes the nearest item declaration at or above it as its enclosing
> item and requires one line of this document to hold both the site's path and that item's name as
> a whole word; it also pins the COUNT of matching lines, so a new one fails the census until its
> row is added and the count bumped. A GREEN census means "every covered line has a row naming its
> path and its enclosing item, and the covered-line count is the pinned one" — never "no such site
> exists". **What the net does not see:** a second site inside an already-named item (the first
> site's row covers it by name — the count pin catches the new line, the name check does not); a
> site in a different item sharing an already-named item's bare name (likewise); a row that names
> the path and the item in passing, or sits in the wrong bucket, or in two (bucket choice and
> exactly-one are this document's discipline, not the net's); a nested item declared earlier in
> the same body (taken as the encloser); any spelling outside the net's `NEEDLES`; any non-Rust
> site. The count is of LINES, not sites: a site swapped for another keeps it, and a second
> spelling on an already-matching line does not move it.

## Buckets (ADR-P008 gate (f)'s seven, in its order)

### CAS
*The digest IS the identity of its input: the input is the thing identified, the output is its address.*

| Site | What is hashed (the semantic input) | Why this bucket |
|---|---|---|
| `crates/aruna/src/commitment.rs` `key_fingerprint` (`Sha384::new()`) | `"mw.key-fingerprint.v1 " ‖ key material` | the root key's NON-SECRET identity — the registry's write-once record of which key this store holds (restore ≠ import) |
| `crates/aruna/src/commitment.rs` test `key_fingerprint_is_sha384_over_the_bridges_prefix_and_the_material` (`Sha384::new()`, test-only) | the same prefix ‖ key material as the production fingerprint row above | independent recomputation of the fingerprint — the same semantic input, so the same bucket; test-only, not a production site |
| `src-tauri/src/token_refresh.rs` `FileGen::of_bytes` (`sha2::Sha384::new()`) | the credential file's raw bytes | the credential FILE's generation identity — the digest names which bytes are on disk |
| `src-tauri/src/key_custody_keyring.rs` `store_user` (`Sha384::digest(`), called by `KeyringCustody::for_store` | the canonical store path's Unicode string (a non-Unicode path is refused, never hashed) | the keyring entry name for one store — an identity digest over our own path, never the path itself in the OS store — a pseudonym for a path; CAS is the closest of the seven buckets |

### sealed-row/event
No site at this census. Photon seals no rows or events itself — the Black Hole seam that seals them is a later slice.

### content-commitment
*Keyed, randomized commitments over governed content (`mw.commitment.v1`), the key family that keys them, and the known-answer digests that pin their preimage bytes (test-only).*

| Site | What is committed (the semantic input) | Why this bucket |
|---|---|---|
| `crates/aruna/src/commitment.rs` `mac_over_frames` (`HmacSha384::new_from_slice`) — the ONE tag primitive behind `compute_tag` / `verify_tag` | `frame(DS) ‖ DS ‖ frame(r) ‖ r ‖ frame(m) ‖ m` under a per-account key | the commitment tag itself — `mw.commitment.v1` consumed as specified (the bulk-triage design's commitment family): presentation / aggregate-view / view / sample-seed commitments, keyed and randomized, never a bare digest |
| `crates/aruna/src/commitment.rs` `derive_account_key` (`HmacSha384::new_from_slice`) | `"photon.commitment.account-key.v1:" ‖ account` under the root key | the commitment family's per-account key (input = root key ‖ account; the reference implementation's `deriveDomainKey` shape at SHA-384) — it exists only to key the tags above |
| `crates/aruna/src/commitment.rs` test `the_ds_is_byte_identical_to_json_stringify_at_the_far_edges_too` (`Sha384::digest(`, test-only) | the far-edge domain-separator string | known-answer digest of the commitment's DS against the SHA-384 pinned from node's `JSON.stringify` — test-only |
| `crates/aruna/src/commitment.rs` test `preimage_is_frame_ds_frame_r_frame_m_and_matches_the_bridges_golden_sha384` (`Sha384::digest(`, test-only) | the framed commitment preimage | known-answer digest against the reference implementation's golden vector — test-only |
| `crates/aruna/src/commitment.rs` test `tag_is_hmac_sha384_over_the_framed_preimage_and_matches_the_bridges_golden_tag` (`Hmac::<sha2::Sha384>::new_from_slice`, test-only) | the same key and frames as the tag row above | CT-20 comparative HMAC — independent recomputation of the tag; test-only |
| `crates/aruna/src/commitment.rs` test `account_key_derivation_is_hmac_sha384_of_the_domain_tag_and_account_and_never_the_root` (`Hmac::<sha2::Sha384>::new_from_slice`, test-only) | the same root key, domain tag and account as the per-account key row above | CT-20 comparative HMAC — independent recomputation of the per-account key; test-only |

**Domains under the existing MAC sites (no new site) — triage plan (`crates/aruna/src/plan.rs`).** Every triage commitment is a `mw.commitment.v1` tag through `commit_over` / `compute_tag` — the `mac_over_frames` row above — under the per-account key (`derive_account_key`, row above; key reference `photon.account.<account>`, epoch 1). Each domain below is a `CommitmentDomain` `source_kind` (disposition `envelope-commitment-only`), not a call site; `plan.rs` reaches no digest or MAC primitive of its own. The content bytes each commits open with their own ASCII content tag where one is named (`photon.triage.*.v1`, framed by `commitment::frame_prefix`).

| Domain (`source_kind`) | What it commits | Where the randomizer is stored |
|---|---|---|
| `photon.triage.set` | `photon.triage.set.v1` ‖ account ‖ provider principal ‖ verb ‖ the canonical member refs (`encode_set`) | `triage_plan.set_randomizer` (tag: `set_digest`) |
| `photon.triage.state` | `photon.triage.state.v1` ‖ per member: ref ‖ observed closure state ‖ forward target (`encode_state`) | `triage_plan.state_randomizer` (tag: `state_digest`) |
| `photon.triage.presentation` | `photon.triage.presentation.v1` ‖ header + summary ‖ every row's frozen display ‖ the set and state digests (`encode_presentation`) | `triage_plan.presentation_randomizer` (tag: `presentation_digest`) |
| `photon.triage.presentation` — the FullList VIEW re-derivation (a reuse of the domain above, not a new commitment) | the same encoding over the rows the renderer says it showed (`view_commitment`, `RenderedView::FullList`) | the plan's `triage_plan.presentation_randomizer` (tag: `approval_evidence.view_digest`, PerMember — equal to `presentation_digest` iff the engine's re-encoding of the rendered struct equals the canonical encoding (a rendered warning of `Some("")` encodes as `None` — hygiene, ledgered in the build record's `### Part C — review r1`) |
| `photon.triage.shape` | `photon.triage.shape.v1` ‖ header + summary (`encode_shape`) | `triage_plan.shape_randomizer` (tag: `shape_digest`; also `approval_evidence.shape_digest`, Aggregate) |
| `photon.triage.sample_seed` | `photon.triage.sample-seed.v1` ‖ the presentation digest | `triage_plan.sample_seed_randomizer` (tag: `sample_seed`) |
| `photon.triage.sample_score` | frame(sample-seed tag) ‖ frame(member ref) — the per-member sampling score (`member_score`); never persisted, so not a durable commitment | none of its own: it computes under the stored `triage_plan.sample_seed_randomizer` |
| `photon.triage.aggregate_view` | `photon.triage.aggregate-view.v1` ‖ `mode:aggregate` ‖ header + summary ‖ shape digest ‖ sample k ‖ the sampled rows ‖ presentation digest (`encode_aggregate_view`) | `triage_plan.aggregate_view_randomizer`, minted at plan freeze (tag: `approval_evidence.view_digest`, Aggregate — committed at approval) |

### checkpoint
No site at this census.

### signature-suite
No site at this census.

### provenance/attestation-binding
*Digests that bind a produced artifact to the evidence or producer that attests it.*

| Site | What is hashed (the semantic input) | Why this bucket |
|---|---|---|
| `crates/aruna/src/attempt.rs` `sever_witness_digest` (`Sha384::new()`) | the canonical sever-witness bytes (`encode_sever_witness`: domain tag ‖ u32be count ‖ sorted members) | the sever witness: binds one sever to the member partition it attests |
| `crates/aruna-gmail/tests/live_readside.rs` `sha384_hex` (`Sha384::digest(`, test-only) — one call site, many callers | token strings, the attestation bundle bytes, the helper and sanitizer source, banked capture and fixture bytes | every caller binds a drill artifact to the evidence that attests it; ADR-P008 gate (f) places this file's drill-lane digests here by name — test-only |
| `scripts/gmail_drill_mint.py` `token_sha384` (`hashlib.sha384`) | the emitted token strings | the attestation bundle's token binding; named into this bucket by ADR-P008 gate (f) — not a Rust site, outside the net, listed for completeness |
| `scripts/gmail_drill_mint.py` `helper_source_sha384` (`hashlib.sha384`) | the helper's own source bytes | the producer digest (the drill design's producer digest); named into this bucket by ADR-P008 gate (f) — not a Rust site, outside the net |
| `scripts/gmail_drill_mint.py` `self_test` (`hashlib.sha384`, two calls, test-only) | the literal test tokens `tok-main` / `tok-denial` | the helper's self-test recomputation of the bundle's token binding — test-only; not a Rust site, outside the net |

### external-mandate
*The algorithm is fixed by an external standard, never chosen by us (the documented-exception shape).*

| Site | Mandate |
|---|---|
| `scripts/gmail_drill_mint.py` `consent_and_exchange` PKCE `S256` challenge (`hashlib.sha256` over the code verifier) | RFC 7636 §4.2 — the S256 code-challenge method is BASE64URL(SHA-256(verifier)) by the standard. ADR-P008 gate (f) points at this site as `scripts/gmail_drill_mint.py:1907-1911` (corrected 2026-09-24 at `ceba4c3`), inside `consent_and_exchange`. Not a Rust site, outside the net. |

### Non-sites (spelled like a site, not one — outside the seven buckets)
| Line | Why it is not a site |
|---|---|
| `crates/aruna/tests/crypto_census.rs` `NEEDLES` | the net's own list of the spellings it matches — string literals, nothing is hashed. The net sees it (it is not a `//` line; its enclosing item is the `const` itself) and it is named here rather than skipped. |
| `crates/aruna/src/commitment.rs` `HmacSha384` (`type HmacSha384 = Hmac<Sha384>;`) | a type alias naming the MAC type the two content-commitment sites construct — nothing is hashed on this line. Seen by the `HmacSha` needle; its enclosing item is the `type` itself. The `mac_over_frames` row above also holds this path and this name as a whole word, so the net passes with or without this row — it is named here on purpose. |
| `crates/aruna/src/commitment.rs` `mac_over_frames` signature line (`-> Result<HmacSha384, CommitmentError>`) | the tag primitive's return type — nothing is hashed on this line. Seen by the `HmacSha` needle; its enclosing item is `mac_over_frames`, whose call-site row (content-commitment) already names it. |

(The `crypto_census` test skips `//` comment lines, both as sites and as item declarations; a doc-comment naming an API is not a call.)

### Pinned references (not sites — Photon computes no digest)
Digests a TOOL verifies against a pin we carry. No Photon code hashes anything for them, so they sit outside the seven buckets and outside the net.

| Where | What is pinned | Who computes and checks it |
|---|---|---|
| `crates/aruna-jmap/tests/fixtures/stalwart/setup.sh` `CLI` (`ghcr.io/stalwartlabs/cli@sha256:…`, line 23) | the OCI image's content digest, SHA-256 as the registry publishes it | docker, against the pulled image (test fixture) |
| `Cargo.lock` and `src-tauri/Cargo.lock` `checksum = …` lines (211 and 540 at this census) | each registry crate's SHA-256, cargo's registry format | cargo, at fetch |
| `package-lock.json` `"integrity": "sha512-…"` lines (163 at this census) | each npm package's SHA-512, npm's Subresource Integrity (SRI) string | npm, at install |

## Census log
- 2026-09-24 (Part A): created. Net over `crates/**`, `src-tauri/src/**`: twelve sites, all bucketed, plus the net's own `NEEDLES` line (a non-site); zero unmapped. Production sites: SIX — the production HMAC site count is TWO (`mac_over_frames`, `derive_account_key`), and four SHA-384 (`sever_witness_digest`, `key_fingerprint`, `FileGen::of_bytes`, `store_user`). Test-only: six (five in `commitment.rs` tests, one `sha384_hex` in the drill test). No SHA-1 or SHA-256 call site exists in Photon's Rust source (the PKCE `S256` is Python, RFC-mandated). Outside the net's two roots, `src-tauri/build.rs` and `src-tauri/tests/**` carry no digest or MAC spelling at this census (grep, not the net).
- 2026-09-24 (Part A, recut): buckets recut to ADR-P008 gate (f)'s seven names in its order, each site classified per call site by its semantic input; three buckets (sealed-row/event, checkpoint, signature-suite) hold no site and say so. The net now checks path AND enclosing item name per site (it checked the path only). Rust sites unchanged: twelve plus `NEEDLES`, one row each. Production: six — CAS three (`key_fingerprint`, `FileGen::of_bytes`, `store_user`), content-commitment two (`mac_over_frames`, `derive_account_key` — the only production MAC sites), provenance/attestation-binding one (`sever_witness_digest`). Test-only Rust: six — CAS one (the fingerprint recomputation), content-commitment four, provenance/attestation-binding one (`sha384_hex`). Listed outside the net: `scripts/gmail_drill_mint.py` (provenance/attestation-binding: `token_sha384`, `helper_source_sha384`, and the `self_test` recomputation, which the first census missed; external-mandate: PKCE `S256`) and the stalwart CLI image pin in `crates/aruna-jmap/tests/fixtures/stalwart/setup.sh` (external-mandate, a reference docker verifies; the first census missed it).
- 2026-09-24 (Part A, closing review): (1) `NEEDLES` widened from the five SHA-384/HMAC call spellings to also match `Sha1` · `sha1::` · `Sha224` · `Sha256` · `Sha512` · `Md5` · `HmacSha` · `KeyInit`, and the item scanner now reads `type NAME` as a declaration. The widened net surfaced NO new site: two new lines, both non-sites (the `HmacSha384` type alias and `mac_over_frames`'s signature), now named under Non-sites. (2) The count of lines the net sees is pinned at FIFTEEN: the twelve sites, the `NEEDLES` line, and those two non-sites. (3) The stalwart image pin moved out of external-mandate into the new "Pinned references" note, beside the two `Cargo.lock` files' `checksum` lines and `package-lock.json`'s `integrity` lines (docker, cargo and npm verify them; Photon computes nothing). (4) `store_user`'s row now calls it a pseudonym for a path, with CAS as the closest bucket; the content-commitment bucket definition now names its test-only known-answer digests. SHA-1/SHA-256/other-width sites: none SEEN, by the widened net or by `git ls-files '*.rs' | xargs grep -nE 'Sha256|Sha1\b|sha1::|Sha512|Sha224|Md5'` (zero hits at `485ca41`). This does not mean none exist.
- 2026-09-24 (Part C): the `photon.triage.*` commitment domains recorded under the content-commitment bucket — seven `source_kind`s `crates/aruna/src/plan.rs` declares (`set` · `state` · `presentation` · `shape` · `sample_seed` · `sample_score` · `aggregate_view`) plus the presentation domain's reuse for the FullList view re-derivation, each with where its randomizer is stored. Domains under the existing `mac_over_frames` / `derive_account_key` sites, not sites: no new digest or MAC call site, the net's line count stays FIFTEEN.
- 2026-09-24 (Part F — the final tree): `cargo test -p aruna --test crypto_census` green (3 passed); the plan's grep (`Hmac::<` · `Sha384::new` · `Sha384::digest(` · `sha2::Sha384` over `crates/` and `src-tauri/src`, `*.rs`) returns 13 lines — the twelve sites and the `NEEDLES` line — each held by exactly one row above; no row added, the net's line count stays FIFTEEN. The external-mandate row's ADR-P008 pointer now reads `scripts/gmail_drill_mint.py:1907-1911`. The hit-by-hit table is the build record's `## Crypto census — final`.
