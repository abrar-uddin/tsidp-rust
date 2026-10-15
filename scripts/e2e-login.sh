#!/usr/bin/env bash
# Drive a full OIDC login against a running tsidp with curl, from a device on
# the tailnet (identity comes from your tailnet address):
#   scripts/e2e-login.sh https://idp.<tailnet>.ts.net <client_id> <redirect_uri> [--secret S] [--token-url URL] [--scope "openid email profile"]
# --token-url lets the code be redeemed on the cluster listener instead
# (run from a pod: http://tsidp.tsidp.svc.cluster.local:8080/token).
# Needs curl, openssl, base64.
set -euo pipefail
ISSUER="${1:?issuer url}"; CLIENT_ID="${2:?client id}"; REDIRECT="${3:?redirect uri}"; shift 3
SECRET=""; TOKEN_URL=""; SCOPE="openid email profile"
while [ $# -gt 0 ]; do
  case "$1" in
    --secret) SECRET="$2"; shift 2 ;;
    --token-url) TOKEN_URL="$2"; shift 2 ;;
    --scope) SCOPE="$2"; shift 2 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done
ISSUER="${ISSUER%/}"
TOKEN_URL="${TOKEN_URL:-$ISSUER/token}"

urlenc() { printf '%s' "$1" | od -An -tx1 -v | tr ' ' '\n' | grep -v '^$' | sed 's/^/%/' | tr -d '\n'; }
b64url() { base64 | tr '+/' '-_' | tr -d '=\n'; }
jwt_payload() { local p; p=$(printf '%s' "$1" | cut -d. -f2 | tr '_-' '/+'); while [ $(( ${#p} % 4 )) -ne 0 ]; do p="$p="; done; printf '%s' "$p" | base64 -d 2>/dev/null; }

VERIFIER=$(openssl rand -hex 32)                                   # 64 unreserved chars
CHALLENGE=$(printf '%s' "$VERIFIER" | openssl dgst -sha256 -binary | b64url)
STATE=$(openssl rand -hex 8)

echo "1. discovery  $ISSUER/.well-known/openid-configuration"
curl -fsS "$ISSUER/.well-known/openid-configuration" | tr -d '\n' | sed 's/,/,\n   /g' | grep -E '"(issuer|authorization_endpoint|token_endpoint|jwks_uri)"' || true

echo "2. authorize  (PKCE S256)"
LOC=$(curl -sS -o /dev/null -w '%{redirect_url}' \
  "$ISSUER/authorize?response_type=code&client_id=$(urlenc "$CLIENT_ID")&redirect_uri=$(urlenc "$REDIRECT")&scope=$(urlenc "$SCOPE")&state=$STATE&code_challenge=$CHALLENGE&code_challenge_method=S256")
[ -n "$LOC" ] || { echo "   no redirect from /authorize (is this device on the tailnet and allowed to reach tsidp?)" >&2; exit 1; }
case "$LOC" in
  *error=*) echo "   authorize error: $LOC" >&2; exit 1 ;;
esac
CODE=$(printf '%s' "$LOC" | sed -n 's/.*[?&]code=\([^&]*\).*/\1/p')
printf '%s' "$LOC" | grep -q "state=$STATE" || { echo "   state mismatch: $LOC" >&2; exit 1; }
echo "   code received, state ok"

echo "3. token      $TOKEN_URL"
AUTH=()
if [ -n "$SECRET" ]; then AUTH=(-u "$CLIENT_ID:$SECRET"); fi
TOK=$(curl -fsS "${AUTH[@]}" -X POST "$TOKEN_URL" \
  -d "grant_type=authorization_code&code=$CODE&redirect_uri=$(urlenc "$REDIRECT")&client_id=$(urlenc "$CLIENT_ID")&code_verifier=$VERIFIER")
ID_TOKEN=$(printf '%s' "$TOK" | sed -n 's/.*"id_token":"\([^"]*\)".*/\1/p')
ACCESS=$(printf '%s' "$TOK" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
[ -n "$ID_TOKEN" ] || { echo "   no id_token in: $TOK" >&2; exit 1; }
echo "   id_token claims:"; jwt_payload "$ID_TOKEN"; echo

echo "4. userinfo   ${TOKEN_URL%/token}/userinfo"
curl -fsS -H "Authorization: Bearer $ACCESS" "${TOKEN_URL%/token}/userinfo"; echo
echo "OK"
