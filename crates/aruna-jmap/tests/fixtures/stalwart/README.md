# Stalwart JMAP test fixture (Photon `aruna-jmap` live integration)

A reproducible, self-hosted **Stalwart** JMAP server (RFC 8620/8621) for proving the live
`HttpJmapTransport` over the wire — the M0 DoD "works end-to-end against a JMAP test account" proof.
This is a **disposable test server only**; it does not enable real-mailbox writes (ADR-P010 Part III
gate stays shut). Pinned image `stalwartlabs/stalwart:v0.16.10` (never `:latest`).

## Run it

```bash
cd crates/aruna-jmap/tests/fixtures/stalwart
./setup.sh        # clean-slate rebuild: bootstrap + seed; leaves the fixture running
```

Then run the env-gated live test (default suite stays hermetic when these are unset):

```bash
PHOTON_JMAP_IT=1 \
PHOTON_JMAP_URL=http://localhost:18080 \
PHOTON_JMAP_USER=testuser@example.test \
PHOTON_JMAP_PASS=photon-jmap-fixture-7x9k \
cargo test -p aruna-jmap --test live_jmap -- --nocapture
```

Teardown: `docker rm -f stalwart-jmap-fixture && docker volume rm photon-stalwart-config photon-stalwart-data`.

## Why a script and not just `docker compose up`

Stalwart v0.16.10 has **no non-interactive init flag**. With no `/etc/stalwart/config.json` it boots
into *bootstrap mode*: only a recovery HTTP listener on `:8080` is up, and every JMAP method returns
`forbidden: The server is in bootstrap mode`. The (scriptable) unlock is the CLI call
`stalwart-cli update Bootstrap`, after which Stalwart writes `config.json` and **the process exits** —
you then recreate the container against the now-populated named volumes to get a full-mode,
JMAP-ready server. `setup.sh` automates this whole dance and seeds the account/mailbox/message.
Docker preflight: verified on Docker 29.5.3 + Compose v5.1.4.

## Byte-verified facts (v0.16.10, 2026-06-25)

| Thing | Value |
|---|---|
| Base URL (reachable) | `http://localhost:18080` — JMAP at `/jmap/`, session at `/jmap/session` |
| Auth | HTTP **Basic** `testuser@example.test : photon-jmap-fixture-7x9k` |
| Account id (testuser) | `c` (stable on clean slate) |
| Inbox mailbox / seeded email | inbox `a` / email `eaaaaab` |
| Archive mailbox | created by `setup.sh` (Stalwart's defaults omit the archive role) |
| Admin (setup only) | `admin@example.test` — secret randomly generated at bootstrap, captured by the script |

## Gotchas (each cost real time — don't re-derive)

1. **The advertised `apiUrl` is NOT reachable in this fixture.** The JMAP Session JSON returns
   `"apiUrl":"https://localhost/jmap/"` (built from the configured `serverHostname`, defaulting to
   https/443) — but the test reaches the server at `http://localhost:18080/jmap/`. The transport's
   fixture path must resolve method calls against the **connection base** it was given, not the
   advertised `apiUrl`. (Production does NOT rebase; it REQUIRES the advertised `apiUrl` to be the
   same authority it connected to — a malicious Session must not retarget credentialed traffic,
   CWE-346. A genuine cross-authority provider would be an explicit reviewed allowlist.)
2. **Bootstrap exits the process** after `update Bootstrap` — normal; recreate the container.
3. **zxcvbn rejects common passwords** even at `passwordMinStrength=zero` (`Passw0rd!` etc. fail).
   The fixture password `photon-jmap-fixture-7x9k` passes at score 0; `setup.sh` also relaxes the
   policy before creating the account.
4. **The admin password is random at bootstrap** (printed once); `setup.sh` captures it from the CLI
   output and uses it within the run — it is never needed by the test (the test uses testuser).
5. **`/healthz/live` returns 200 in BOTH bootstrap and full mode** — it cannot tell you JMAP is
   ready. Gate on `GET /jmap/session` returning 200 with the test credentials instead.
6. **IDs are short opaque strings** (`a`,`b`,`c`,…) stable on a *fresh* install. The live test should
   DISCOVER them (session → `Mailbox/query`) rather than hardcode, in case the layout shifts.

## Credentials note

The credentials here are for a **disposable local fixture only** — never a real/production account.
`photon-jmap-fixture-7x9k` is **intentional public test scaffolding**: `setup.sh`
must set it on the seeded account, so it is committed by necessity and documented above as functional
run-instructions. It authenticates nothing but an ephemeral, loopback-bound Stalwart container that is
torn down on teardown.

The **"never-print-creds / id-free output" discipline** therefore binds the *runtime* paths — the
connector and the live test — and any **real** credential or provider id: the live test reports only
id-free booleans, the connector maps every provider error to a fixed id-free message, and `setup.sh`
no longer echoes the fixture password or fixture ids It does **not**
forbid documenting this disposable scaffolding value in these run-instructions.
