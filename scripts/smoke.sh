#!/usr/bin/env sh
# End-to-end smoke test against a locally built binary in --dev-identity mode.
# Needs curl. Run inside the dev container:  ./scripts/dev.sh sh scripts/smoke.sh
set -eu
BIN="${BIN:-./target/debug/tsidp-server}"
ST="$(mktemp -d)"
"$BIN" --dev-identity alice@example.com --state-dir "$ST" \
  --listen 127.0.0.1:8443 --cluster-listen 127.0.0.1:8080 --admin-listen 127.0.0.1:9464 \
  --enable-sts --log warn > "$ST/server.log" 2>&1 &
PID=$!
trap 'kill $PID 2>/dev/null || true' EXIT
for i in 1 2 3 4 5 6 7 8 9 10; do
  if "$BIN" --check-ready --admin-listen 127.0.0.1:9464 >/dev/null 2>&1; then break; fi
  sleep 0.5
done
fail() { echo "FAIL: $*" >&2; cat "$ST/server.log" >&2; exit 1; }
TN='-H X-Forwarded-For:100.64.0.5'

echo "--- readyz"
curl -sf localhost:9464/readyz | grep -q '"ready":true' || fail readyz
echo "--- discovery on both listeners"
curl -sf $TN localhost:8443/.well-known/openid-configuration | grep -q '"registration_endpoint"' || fail "tailnet discovery"
curl -sf localhost:8080/.well-known/openid-configuration | grep -q '"registration_endpoint"' && fail "cluster discovery must hide registration"
echo "--- create client via API"
C=$(curl -sf -X POST $TN -H 'Sec-Fetch-Site: same-origin' -d 'name=demo&redirect_uri=https://app/cb' localhost:8443/clients/new)
ID=$(printf '%s' "$C" | sed 's/.*"client_id":"\([^"]*\)".*/\1/')
SEC=$(printf '%s' "$C" | sed 's/.*"client_secret":"\([^"]*\)".*/\1/')
[ -n "$ID" ] && [ -n "$SEC" ] || fail "client create: $C"
echo "--- authorize (tailnet)"
LOC=$(curl -s -o /dev/null -w '%{redirect_url}' $TN "localhost:8443/authorize?client_id=$ID&redirect_uri=https://app/cb&scope=openid%20email&state=s1")
CODE=$(printf '%s' "$LOC" | sed 's/.*code=\([^&]*\).*/\1/')
printf '%s' "$LOC" | grep -q 'state=s1' || fail "authorize redirect: $LOC"
echo "--- token (cluster listener)"
T=$(curl -sf -u "$ID:$SEC" -d "grant_type=authorization_code&code=$CODE&redirect_uri=https://app/cb" localhost:8080/token)
AT=$(printf '%s' "$T" | sed 's/.*"access_token":"\([^"]*\)".*/\1/')
printf '%s' "$T" | grep -q '"id_token"' || fail "token: $T"
echo "--- userinfo (cluster listener)"
curl -sf -H "Authorization: Bearer $AT" localhost:8080/userinfo | grep -q '"email":"alice@example.com"' || fail userinfo
echo "--- introspect"
curl -sf -u "$ID:$SEC" -d "token=$AT" localhost:8080/introspect | grep -q '"active":true' || fail introspect
echo "--- admin UI lists the client"
curl -sf $TN localhost:8443/ | grep -q demo || fail "ui list"
echo "--- cluster listener refuses identity endpoints"
[ "$(curl -s -o /dev/null -w '%{http_code}' "localhost:8080/authorize?client_id=$ID&redirect_uri=https://app/cb")" = "404" ] || fail "cluster /authorize"
echo "--- metrics"
curl -sf localhost:9464/metrics | grep -q '^tsidp_tokens_issued_total 1' || fail metrics
echo "--- state files written in Go-compatible layout"
[ -s "$ST/oidc-key.json" ] && [ -s "$ST/oidc-funnel-clients.json" ] || fail "state files"
grep -q '"redirect_uri"' "$ST/oidc-funnel-clients.json" || fail "legacy field"
echo "SMOKE OK"
