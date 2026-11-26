//! Source censuses over the production half of every shell module.

// -------------------------------------------------------------------------------------------
// THE RE-MINT PRODUCER CENSUS.
//
// WHAT THIS IS: a flashlight over a FINITE, TYPE-DERIVED set, used as a CHANGE DETECTOR — not
// a closure claim. Every `Cure` this app renders is
// produced by a `cure()` map on an error/outcome type, and there are four such maps that can
// answer `ReMint`. The suppression is written as "whatever produced this cure", which is
// only as total as that set is knowable — so the set is PINNED here, mechanically, and a
// FIFTH producer (a new refusal type, a new arm on an existing map in a new function) turns
// this test RED and forces the author to decide whether the suppression covers it.
//
// ITS OWN BLIND SPOTS, NAMED: a literal-text scan cannot see a `ReMint` produced through an
// alias, a `From` impl, a constant, or a file this scan does not read; it reads the PRODUCTION
// half of three files (the `#[cfg(test)] mod tests` tail of each is excluded, the way
// `render-contract.test.ts` excludes `__tests__`) with line comments stripped. It is a gate on
// the shape we have, not a proof about the shape we could have.
//
// The COMPARISON sites are censused too, and separately: they are the two places that ASK
// whether a cure is the re-mint class (the stamp suppression's predicate and the unconfigured boot's own), and
// a new one appearing is exactly as interesting as a new producer.
// -------------------------------------------------------------------------------------------
#[test]
fn the_re_mint_producers_are_exactly_the_four_cure_maps() {
    /// `file::impl::fn` for every `Cure::ReMint` in the production half, split into the sites
    /// that PRODUCE one and the sites that COMPARE against one.
    fn census(file: &str, source: &str) -> (Vec<String>, Vec<String>) {
        let cut = source
            .find("#[cfg(test)]\r\nmod tests {")
            .or_else(|| source.find("#[cfg(test)]\nmod tests {"))
            .expect("every scanned file carries its own `mod tests`");
        let mut current_impl = "(free)".to_string();
        let mut current_fn = "(none)".to_string();
        let (mut produced, mut compared) = (Vec::new(), Vec::new());
        for raw in source[..cut].lines() {
            // Line comments are DATA here, not code: `Cure::ReMint` is named in prose in
            // several docs, and a doc comment naming it is not a producer.
            let line = match raw.find("//") {
                Some(at) => &raw[..at],
                None => raw,
            };
            if let Some(rest) = line.strip_prefix("impl ") {
                current_impl = rest.trim().trim_end_matches('{').trim().to_string();
            } else if line.starts_with("fn ") {
                current_impl = "(free)".to_string();
            }
            if let Some(at) = line.find("fn ") {
                let name: String = line[at + 3..]
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                if !name.is_empty() {
                    current_fn = name;
                }
            }
            if let Some(at) = line.find("Cure::ReMint") {
                let site = format!("{file}::{current_impl}::{current_fn}");
                // `==`/`!=` anywhere to the LEFT is the whole difference between asking and
                // answering: `self.cure() == Cure::ReMint` asks, `_ => Cure::ReMint` answers.
                if line[..at].contains("==") || line[..at].contains("!=") {
                    compared.push(site);
                } else {
                    produced.push(site);
                }
            }
        }
        (produced, compared)
    }

    let sources: [(&str, &str); 14] = [
        ("lib.rs", include_str!("../lib.rs")),
        ("error.rs", include_str!("../error.rs")),
        ("single_flight.rs", include_str!("../single_flight.rs")),
        ("credential.rs", include_str!("../credential.rs")),
        ("session.rs", include_str!("../session.rs")),
        ("provider.rs", include_str!("../provider.rs")),
        ("state.rs", include_str!("../state.rs")),
        ("status.rs", include_str!("../status.rs")),
        ("ipc.rs", include_str!("../ipc.rs")),
        ("plumbing.rs", include_str!("../plumbing.rs")),
        ("verbs.rs", include_str!("../verbs.rs")),
        ("plan.rs", include_str!("../plan.rs")),
        ("credential_cell.rs", include_str!("../credential_cell.rs")),
        ("token_refresh.rs", include_str!("../token_refresh.rs")),
    ];
    let (mut produced, mut compared) = (Vec::new(), Vec::new());
    for (file, source) in sources {
        let (p, c) = census(file, source);
        produced.extend(p);
        compared.extend(c);
    }

    assert_eq!(
        produced,
        vec![
            // The BOOT door's map: nine load refusals, eight of which a re-consent cures
            "credential.rs::CredentialLoadRefusal::cure".to_string(),
            // The status surface's grant derivation: a retired generation.
            "status.rs::LiveGrantVerdict::cure".to_string(),
            // The wave's PROVIDER answers: authority mismatch, reauth required, a missing
            // refresh token.
            "token_refresh.rs::RefreshOutcome::cure".to_string(),
            // The wave's LOCAL failures: the pre-exchange ratchet refusal.
            "token_refresh.rs::RefreshLocalError::cure".to_string(),
        ],
        "a FIFTH producer of `Cure::ReMint` appeared. F10 suppresses a re-mint-class cure \
             for a cell whose replacement has landed, and it is written over the RENDERED cure \
             precisely so it does not have to enumerate producers — but the claim that the class \
             is finite and type-derived is THIS list. Decide whether the new producer's cure \
             reaches an unconfigured cell (`unconfigured_verdict`), a published generation \
             (`GrantOnDisk::verdict`) or a stamp (`CredentialCell::status_cure`), then add it here"
    );
    assert_eq!(
        compared,
        vec![
            // The same predicate: the unconfigured cell's cure, read off the cure map.
            "status.rs::(free)::unconfigured_verdict".to_string(),
            // The stamp suppression's predicate.
            "credential_cell.rs::RememberedOutcome::cured_by_a_landed_replacement".to_string(),
        ],
        "a THIRD place asks whether a cure is the re-mint class. The two that exist are the \
             two suppressions this fold family is made of; a third is either a fourth copy of \
             the same rule (ANTI-DRIFT 🧩: unify, do not patch) or a new question worth its own \
             name"
    );
}

// -------------------------------------------------------------------------------------------
// THE WIRE-CURE OUTPUT CENSUS: every production site that puts a cure ON THE
// WIRE, counted.
//
// The producer census above pins where a `Cure::ReMint` is MADE; this one pins where any cure
// is HANDED OUT — the two `SurfaceError` variants that carry one (`SessionUnconfigured`,
// `CredentialExpired`) and the status view's `credential_cure`. The derived reason makes an unconfigured
// cell's cure conditional on a reading of the disk, and a site that hands out that cure
// without the reading is the defect closed at `PhotonState::gmail` — so the set
// of such sites is enumerated mechanically rather than remembered.
//
// THE HONEST RESIDUAL, VERBATIM: enforced at the two unbound sites (status view, gmail()) by
// behavioural probes and at the eight bound sites by ordering (reconcile precedes each); a
// NEW site is caught by this census, not by construction.
//
// TEN before, TEN now: the change altered what `PhotonState::gmail` puts on the wire, not
// how many places put something there — the helper it now calls returns a pair, it does not
// construct a refusal of its own.
//
// Same shape and the same named blind spots as the producer census: a literal-text scan of
// the production half of three files, comment-stripped, blind to an alias, a `From` impl, a
// constructor helper one level removed, or a file it does not read. PATTERNS are excluded by
// their `..` rest-binding — a `match` arm that READS a cure off a refusal hands nothing out.
// -------------------------------------------------------------------------------------------
#[test]
fn the_wire_cure_output_sites_are_exactly_the_ten_the_audit_enumerated() {
    fn output_sites(file: &str, source: &str) -> Vec<String> {
        let cut = source
            .find("#[cfg(test)]\r\nmod tests {")
            .or_else(|| source.find("#[cfg(test)]\nmod tests {"))
            .expect("every scanned file carries its own `mod tests`");
        let mut current_impl = "(free)".to_string();
        let mut current_fn = "(none)".to_string();
        let mut sites = Vec::new();
        for raw in source[..cut].lines() {
            let line = match raw.find("//") {
                Some(at) => &raw[..at],
                None => raw,
            };
            if let Some(rest) = line.strip_prefix("impl ") {
                current_impl = rest.trim().trim_end_matches('{').trim().to_string();
            } else if line.starts_with("fn ") {
                current_impl = "(free)".to_string();
            }
            if let Some(at) = line.find("fn ") {
                let name: String = line[at + 3..]
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                if !name.is_empty() {
                    current_fn = name;
                }
            }
            let trimmed = line.trim_start();
            let hands_a_cure_out = !line.contains("..")
                && (line.contains("Err(SurfaceError::SessionUnconfigured {")
                    || line.contains("Err(SurfaceError::CredentialExpired {")
                    || trimmed.starts_with("SurfaceError::SessionUnconfigured {")
                    || trimmed.starts_with("SurfaceError::CredentialExpired {"))
                || trimmed.starts_with("let credential_cure");
            if hands_a_cure_out {
                sites.push(format!("{file}::{current_impl}::{current_fn}"));
            }
        }
        sites
    }

    let sources: [(&str, &str); 14] = [
        ("lib.rs", include_str!("../lib.rs")),
        ("error.rs", include_str!("../error.rs")),
        ("single_flight.rs", include_str!("../single_flight.rs")),
        ("credential.rs", include_str!("../credential.rs")),
        ("session.rs", include_str!("../session.rs")),
        ("provider.rs", include_str!("../provider.rs")),
        ("state.rs", include_str!("../state.rs")),
        ("status.rs", include_str!("../status.rs")),
        ("ipc.rs", include_str!("../ipc.rs")),
        ("plumbing.rs", include_str!("../plumbing.rs")),
        ("verbs.rs", include_str!("../verbs.rs")),
        ("plan.rs", include_str!("../plan.rs")),
        ("credential_cell.rs", include_str!("../credential_cell.rs")),
        ("token_refresh.rs", include_str!("../token_refresh.rs")),
    ];
    let sites: Vec<String> = sources
        .into_iter()
        .flat_map(|(file, source)| output_sites(file, source))
        .collect();

    assert_eq!(
        sites,
        vec![
            // UNBOUND — no reconcile precedes these two, so each is enforced by its own
            // behavioural witness in this file: they read the disk
            // through the one derivation before they label a refusal.
            "state.rs::PhotonState::session".to_string(),
            "state.rs::PhotonState::gmail".to_string(),
            "status.rs::(free)::session_status_view".to_string(),
            // BOUND BY ORDERING — every one of these is downstream of a reconcile inside the
            // coordinator's critical section, so the cell they read is the cell the disk just
            // produced.
            "credential_cell.rs::CredentialCoordinator::admit".to_string(),
            "credential_cell.rs::CredentialCoordinator::admit".to_string(),
            "credential_cell.rs::CredentialCoordinator::admit".to_string(),
            "credential_cell.rs::CredentialCoordinator::join".to_string(),
            "credential_cell.rs::CredentialCoordinator::run_wave".to_string(),
            "credential_cell.rs::(free)::gmail_arm".to_string(),
            "credential_cell.rs::(free)::refusal".to_string(),
        ],
        "the set of places a cure reaches the wire changed. If the new one speaks for a cell \
             that may be STALE — no reconcile between the read and the answer — it owes the same \
             derivation `session_status_view` and `PhotonState::gmail` take (the D-e defect); if \
             it is downstream of a reconcile, say so here and add it"
    );
}
