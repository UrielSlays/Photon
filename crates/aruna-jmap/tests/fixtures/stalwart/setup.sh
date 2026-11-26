#!/usr/bin/env bash
# Reproducible, headless Stalwart JMAP fixture for Photon's aruna-jmap live integration test.
#
# Stalwart v0.16.10 has NO non-interactive init flag: with no /etc/stalwart/config.json it boots a
# web setup wizard ("bootstrap mode"), where every JMAP method returns `forbidden: server is in
# bootstrap mode`. The unlock is the scriptable `update Bootstrap` CLI call, after which the server
# writes config.json and EXITS — you then recreate the container against the (now-populated) named
# volumes to get a full-mode, JMAP-ready server. This script automates that whole dance from a clean
# slate and seeds: domain example.test, account testuser@example.test, an Archive role mailbox, and
# one Inbox message. Every step below was byte-verified on 2026-06-25 against v0.16.10.
#
# Usage:  ./setup.sh         # tears down + rebuilds from clean state, leaves the fixture running
# Then the env-gated live test reads:
#   PHOTON_JMAP_IT=1
#   PHOTON_JMAP_URL=http://localhost:18080
#   PHOTON_JMAP_USER=testuser@example.test
#   PHOTON_JMAP_PASS=photon-jmap-fixture-7x9k
set -euo pipefail

IMAGE=stalwartlabs/stalwart:v0.16.10
# Pinned by digest (never :latest) so a moving CLI tag can't break reproducibility against the
# pinned v0.16.10 server.
CLI=ghcr.io/stalwartlabs/cli@sha256:6a750ac640e2f58fa188afa4f36e6055faaa42aa8a22538d37257351d57a7271
BASE=http://localhost:18080
DOMAIN=example.test
TEST_USER="testuser@${DOMAIN}"
TEST_PASS=photon-jmap-fixture-7x9k   # novel passphrase: Stalwart's zxcvbn rejects common ones even at minStrength=zero

cli()      { docker run --rm        --network host "$CLI" --url "$BASE" "$@"; }
cli_stdin(){ docker run --rm -i     --network host "$CLI" --url "$BASE" "$@"; }
jmap()     { curl -s -u "$TEST_USER:$TEST_PASS" -X POST "$BASE/jmap/" -H 'Content-Type: application/json' -d "$1"; }

echo "[1/9] clean slate"
docker rm -f stalwart-bootstrap stalwart-jmap-fixture >/dev/null 2>&1 || true
docker volume rm photon-stalwart-config photon-stalwart-data >/dev/null 2>&1 || true
docker volume create photon-stalwart-config >/dev/null
docker volume create photon-stalwart-data >/dev/null

echo "[2/9] boot bootstrap container (recovery listener on :8080)"
docker run -d --name stalwart-bootstrap -p 127.0.0.1:18080:8080 \
  -e STALWART_RECOVERY_ADMIN=admin:TestSecret1! \
  -v photon-stalwart-config:/etc/stalwart -v photon-stalwart-data:/var/lib/stalwart "$IMAGE" >/dev/null
until [ "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/healthz/live")" = "200" ]; do sleep 1; done

echo "[3/9] scripted bootstrap (writes config.json, then the server exits)"
ADMIN_SECRET=$(cli --user admin --password 'TestSecret1!' update Bootstrap \
  --field "defaultDomain=$DOMAIN" --field "serverHostname=localhost" \
  --field "requestTlsCertificate=false" --field "generateDkimKeys=false" \
  | grep -oE 'secret: "[^"]+"' | cut -d'"' -f2)
[ -n "$ADMIN_SECRET" ] || { echo "FAILED to capture admin secret"; exit 1; }
sleep 3
docker rm -f stalwart-bootstrap >/dev/null

echo "[4/9] start full-mode container (config now persisted in the volume)"
docker run -d --name stalwart-jmap-fixture -p 127.0.0.1:18080:8080 -p 127.0.0.1:18443:443 \
  -v photon-stalwart-config:/etc/stalwart -v photon-stalwart-data:/var/lib/stalwart "$IMAGE" >/dev/null
until [ "$(curl -s -u "admin@$DOMAIN:$ADMIN_SECRET" -o /dev/null -w '%{http_code}' "$BASE/jmap/session")" = "200" ]; do sleep 1; done

echo "[5/9] relax password policy (zxcvbn) so the fixture password is accepted"
cli --user "admin@$DOMAIN" --password "$ADMIN_SECRET" \
  update Authentication --field "passwordMinStrength=zero" --field "passwordMinLength=4" >/dev/null

echo "[6/9] create testuser + set known password"
echo '{"@type":"User","name":"testuser","domainId":"b"}' \
  | cli_stdin --user "admin@$DOMAIN" --password "$ADMIN_SECRET" create Account --stdin >/dev/null
ACCT=$(curl -s -u "$TEST_USER:$TEST_PASS" "$BASE/jmap/session" 2>/dev/null | grep -oE '"urn:ietf:params:jmap:mail":"[^"]+"' | cut -d'"' -f4 || true)
# password isn't set yet, so the session call above 401s; set the password first via the admin id.
printf '{"@type":"update","object":"Account","id":"c","value":{"credentials":{"0":{"@type":"Password","secret":"%s","expiresAt":null,"allowedIps":{}}}}}' "$TEST_PASS" \
  | cli_stdin --user "admin@$DOMAIN" --password "$ADMIN_SECRET" apply --stdin >/dev/null
ACCT=$(curl -s -u "$TEST_USER:$TEST_PASS" "$BASE/jmap/session" | grep -oE '"urn:ietf:params:jmap:mail":"[^"]+"' | cut -d'"' -f4)
echo "      account: ready"   # id-free output — never print provider ids, even the fixture's

echo "[7/9] create an Archive role mailbox (Stalwart's defaults omit it; the connector needs it)"
jmap '{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["Mailbox/set",{"accountId":"'"$ACCT"'","create":{"arch":{"name":"Archive","role":"archive"}}},"0"]]}' >/dev/null

echo "[8/9] seed one Inbox message"
INBOX=$(jmap '{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["Mailbox/query",{"accountId":"'"$ACCT"'","filter":{"role":"inbox"}},"0"]]}' | grep -oE '"ids":\["[^"]+"' | grep -oE '[a-z0-9]+"$' | tr -d '"')
BLOB=$(curl -s -u "$TEST_USER:$TEST_PASS" -X POST "$BASE/jmap/upload/$ACCT/" -H "Content-Type: message/rfc822" \
  --data-binary $'From: sender@example.com\r\nTo: testuser@example.test\r\nSubject: Photon JMAP Fixture\r\nDate: Wed, 25 Jun 2026 01:00:00 +0000\r\nMIME-Version: 1.0\r\nContent-Type: text/plain\r\n\r\nFixture message.\r\n' \
  | grep -oE '"blobId":"[^"]+"' | cut -d'"' -f4)
jmap '{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["Email/import",{"accountId":"'"$ACCT"'","emails":{"i1":{"blobId":"'"$BLOB"'","mailboxIds":{"'"$INBOX"'":true},"keywords":{},"receivedAt":"2026-06-25T01:00:00Z"}}},"0"]]}' >/dev/null

echo "[9/9] verify"
# Match only a NON-empty ids array ("ids":["..."]) so an Email/import that failed at the JMAP level
# (HTTP 200 but empty result) does not falsely report success.
COUNT=$(jmap '{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["Email/query",{"accountId":"'"$ACCT"'","filter":{"inMailbox":"'"$INBOX"'"}},"0"]]}' | grep -oE '"ids":\["[^"]+"' || true)
ARCH=$(jmap '{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["Mailbox/query",{"accountId":"'"$ACCT"'","filter":{"role":"archive"}},"0"]]}' | grep -oE '"ids":\["[^"]+"' || true)
[ -n "$COUNT" ] || { echo "FAILED: no message seeded in Inbox (Email/import likely failed despite HTTP 200)"; exit 1; }
[ -n "$ARCH" ]  || { echo "FAILED: Archive role mailbox was not created"; exit 1; }
# id-free output: presence, never the raw id-bearing grep match.
echo "      inbox: seeded message present"
echo "      archive mailbox: created"
echo ""
echo "Fixture ready. Run the live test with the env block in this directory's README.md"
echo "(disposable LOCAL fixture credentials — never printed here; see the README 'Run it' section)."
