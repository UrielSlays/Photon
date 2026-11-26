//! (PERMANENT witness) — a reproduction probe
//! kept as a permanent regression test.
//! Original header, verbatim:
//!
//! Reproduction probe: RFC 5322
//! §4.4 `obs-dtext = obs-NO-WS-CTL / quoted-pair` admits a quoted-pair inside an obsolete domain
//! literal. `mailbox.rs`'s `domain_literal` (~line 416-424) refuses ANY backslash
//! (`'[' | '\\' => return None`), so `a@[\192.0.2.1]` — a valid obsolete domain literal whose text
//! after removing the quoted-pair is `192.0.2.1` — comes back `Malformed`.
use aruna::mailbox::{parse_mailbox, SenderStatus};

fn is_ok(s: &SenderStatus) -> bool {
    matches!(s, SenderStatus::Ok)
}

#[test]
fn obs_dtext_quoted_pair_in_a_domain_literal_is_ok() {
    let raw = "Sender <a@[\\192.0.2.1]>";
    let p = parse_mailbox(raw);
    // THE LOAD-BEARING ASSERTION: status must be Ok (RFC 5322 §4.4 obs-dtext admits a
    // quoted-pair). RED at 6c49b97: observed `Malformed` here.
    assert!(
        is_ok(&p.status),
        "obs-dtext quoted-pair in a domain literal must parse: status {:?}, addr {:?}",
        p.status,
        p.addr()
    );
    // Record the exact address string produced, whichever way the quoted-pair is resolved —
    // this is the secondary fact, not the load-bearing one.
    eprintln!("r5_p1: status={:?} addr={:?} domain={:?}", p.status, p.addr(), p.domain);
    assert_eq!(
        p.addr(),
        Some("a@[192.0.2.1]"),
        "the quoted-pair's escaped char (the literal `1`) is content — removing only the \
         backslash yields 192.0.2.1: addr was {:?}",
        p.addr()
    );
}
