//! Photon REQUIRES a bundled SQLite of at least 3.51.3 — the product floor. SQLite reports
//! the WAL-reset corruption bug as likely present from 3.7.0 through 3.51.2 and fixed in 3.51.3
//! and later, with fixed backports ALSO published for 3.44.6 and 3.50.7
//! (https://sqlite.org/wal.html#walresetbug). The floor is deliberately the simple `>= 3.51.3`
//! shipping requirement: a backported version below it is refused by THIS test as "below the
//! product floor", not asserted to be corrupt. Tracked
//! via the rusqlite/libsqlite3-sys bundled-version bumps. This is a RUNTIME check against a live
//! connection (`SELECT sqlite_version()`), the same authority `store_open::write_first_run_config_act`
//! records into the first-run `engine_config` act — not a compile-time/const assertion, so it
//! actually proves what the shipped binary links against.
//!
//! The version string is PRINTED (not just asserted) so the shipped SQLite is auditable straight
//! out of `cargo test -- --nocapture` output — the issue's discharge condition.

use rusqlite::Connection;

/// Parse a SQLite `"X.Y.Z"` version string into a comparable `(major, minor, patch)` tuple.
fn parse_version(v: &str) -> (u32, u32, u32) {
    let mut parts = v.split('.').map(|p| p.parse::<u32>().unwrap_or(0));
    let major = parts.next().unwrap_or(0);
    let minor = parts.next().unwrap_or(0);
    let patch = parts.next().unwrap_or(0);
    (major, minor, patch)
}

#[test]
fn bundled_sqlite_is_out_of_the_wal_reset_corruption_range() {
    let conn = Connection::open_in_memory().expect("open_in_memory: probe connection");
    let live_version: String = conn
        .query_row("SELECT sqlite_version();", [], |r| r.get(0))
        .expect("SELECT sqlite_version()");

    // Auditable: print the actual shipped version regardless of pass/fail.
    println!("live SELECT sqlite_version() = {live_version}");

    let floor = (3, 51, 3);
    let live = parse_version(&live_version);
    assert!(
        live >= floor,
        "bundled SQLite {live_version} is below Photon's product floor of 3.51.3 (#56: the \
         WAL-reset bug is fixed in 3.51.3+ and in the 3.44.6 / 3.50.7 backports, but the floor \
         is the simple >= 3.51.3 requirement) — the LIVE connection must report at least \
         3.51.3, got {live_version}"
    );
}
