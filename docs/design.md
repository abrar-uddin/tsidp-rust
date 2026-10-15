# Design notes

## Why a sidecar instead of tsnet

The Go tsidp embeds a userspace Tailscale node (tsnet). That is convenient on a
laptop and awkward in Kubernetes (upstream issue #169): the only way in or out
of the process is the tailnet, so a plain `Service` cannot front it, in-cluster
relying parties have to reach it through the operator's egress proxies, and the
"local port" escape hatch is hard-wired to localhost.

Rust has no tsnet, which forced a decision that turns out to be the better
Kubernetes shape anyway:

```
┌─ pod ──────────────────────────────────────────────────────────────────┐
│  tailscale (sidecar, userspace)         tsidp                          │
│  ───────────────────────────────        ───────────────────────────────│
│  https://idp.tn.ts.net:443  ──serve──►  127.0.0.1:8443  tailnet router │
│       (TLS, identity, funnel flag)         trusts X-Forwarded-For      │
│  /var/run/tailscale/tailscaled.sock ◄──  LocalAPI: whois, status,      │
│                                            serve-config                │
│                                         0.0.0.0:8080   cluster router  │
│                                            token, userinfo, jwks only  │
│                                         0.0.0.0:9464   admin router    │
│                                            /healthz /readyz /metrics   │
└────────────────────────────────────────────────────────────────────────┘
```

* `tailscale serve` terminates TLS with the node's MagicDNS certificate and
  proxies to tsidp on the pod's loopback. It sets `X-Forwarded-For` to the
  peer's tailnet IP and `Tailscale-Funnel-Request: ?1` for public traffic.
  tsidp resolves the peer with LocalAPI `whois`, which returns the node, its
  user, and the `tailscale.com/cap/tsidp` grants. This is exactly what the Go
  server's `-use-local-tailscaled` mode did, promoted to the only mode.
* The **cluster listener** serves only endpoints that authenticate with a
  bearer token or client credentials. It never looks at forwarded headers, so a
  workload that can reach the `Service` cannot impersonate a tailnet user. The
  browser half of OIDC (`/authorize`) still goes through the tailnet URL, which
  is where the identity comes from.
* Because both containers share the pod network namespace, nothing outside the
  pod can reach the loopback listener, which is what makes trusting
  `X-Forwarded-For` there sound. tsidp warns at startup if the tailnet
  listener is not bound to loopback.
* Both containers run as uid 65532 so tsidp has write access to LocalAPI and
  can install the serve config itself; a `TS_SERVE_CONFIG` ConfigMap does the
  same thing declaratively and covers the read-only case.

## State

Two keys, same names and formats as the Go server so directories migrate in
either direction:

| key | content |
|---|---|
| `oidc-key.json` | `{"kid": <u64>, "key": "<PKCS#1 PEM>"}` |
| `oidc-funnel-clients.json` | `{ "<client_id>": { client_id, client_secret, client_name, redirect_uris, token_endpoint_auth_method, ..., created_at, redirect_uri } }` |

Backends: `file` (atomic writes, 0600) and `kubernetes` (a Secret patched
through the in-cluster API with the pod's service account). With the sidecar's
`TS_KUBE_SECRET` the pod needs no volume at all.

Codes, access tokens and refresh tokens are in memory, as upstream. A restart
invalidates sessions; relying parties simply re-authorize. Multi-replica is out
of scope until a shared token store exists (see roadmap).

## Upstream issues addressed

| issue | what changed |
|---|---|
| #169 Kubernetes is hard | sidecar model, cluster listener, StatefulSet + Helm chart, kube state backend |
| field trial: `TSIDP_PORT` collided with Kubernetes service links | issuer port env renamed to `TSIDP_ISSUER_PORT`, non-numeric `TSIDP_PORT` ignored with a warning, `enableServiceLinks: false` in manifests |
| field trial: cluster discovery advertised tailnet URLs | cluster-listener discovery advertises `--cluster-public-url` (or the request Host) for token/userinfo/introspection/jwks; `--cluster-issuer-url` for strict RPs |
| #94 / #122 Helm chart | `charts/tsidp` |
| #113 / #114 / #96 permission denied on state | image runs as 65532 with `/data` pre-owned; `fsGroup` in manifests; startup write probe with an actionable message |
| #164 health check bypasses tailnet | `/readyz` reflects tailscaled's `BackendState`, readiness probe, `--check-ready` for Compose |
| #193 auth codes never expire / wiped by cleanup | codes carry a 5 min expiry; cleanup only drops expired entries |
| #195 POST /authorize ignores body | query and form body are merged |
| #174 / #182 public clients | `token_endpoint_auth_method: none` honoured; PKCE S256 enforced; UI checkbox |
| #183 / #177 opaque access tokens | `--jwt-access-tokens` issues RFC 9068 `at+jwt` tokens with scope and extra claims; `--extra-scopes` advertises custom scopes |
| #109 offline_access | accepted and advertised (refresh tokens were already issued) |
| #180 groups claim | `groups` from `UserProfile.Groups` plus `groups` in the capability grant |
| #120 tagged devices | `--allow-tagged-nodes`: `sub=node:<stable id>`, `tags` claim, no email |
| #58 / #63 pseudo-emails | `--email-domain` to control the suffix appended to `user@github` / `user@passkey` |
| #106 CSRF blocks cross-origin DCR | CSRF guards the UI, `/clients` and (by default) `/register`; `--allow-cross-origin-dcr` swaps the gate on `/register` for CORS when browser-based MCP clients need it |
| #161 secret in error messages | credentials are never logged; errors say "invalid client secret" only |
| #52 duplicate clients on refresh | form posts render the result page (no re-POST on refresh of the list), API returns 201 |
| #78 / #80 consolidate client management | `/clients` JSON API covers list, create (form or JSON), get, delete, rotate secret |
| #38 missing claims in userinfo | userinfo includes name, email, picture, username, preferred_username, groups |
| #92 Tailscale Services / HA | `--issuer-url` lets the issuer be the Service FQDN; token store sharing is on the roadmap |
| #84 bring your own domain | `--issuer-url` plus Funnel/`AllowFunnel`; a reverse proxy in front of the sidecar is now possible since TLS is the sidecar's job |
| #142 / #149 auth key confusion | node registration is the sidecar's job; `TS_AUTHKEY` is only consulted on first start and state lives in `TS_KUBE_SECRET` |
| #116 / #184 workload identity federation | the `tailscale/tailscale` image supports `TS_CLIENT_ID`/`TS_AUDIENCE`; set them on the sidecar |

Behavioural differences from the Go server worth knowing:

* Discovery advertises `response_types_supported: ["code"]` only; the Go
  server listed `id_token` but never implemented the implicit flow.
* A grant with an `extraClaims` key that collides with a protected claim is
  logged and skipped rather than failing the token request.
* Array `extraClaims` keep their JSON types (`[1,2,3]` stays numeric).
* Errors are always `application/json` with `error`/`error_description`.
* Redirects are `302 Found`; cache headers are `no-store` everywhere.

## Verified

The sidecar model, the Secret state backends, the restricted pod security
profile, the cluster listener and the Headlamp + kube-apiserver flow were
exercised on a single-node k3s cluster on 2026-10-14
([field report](field-report-2026-10-14-k3s-headlamp.md)).

## Roadmap

* Certificate status in `/readyz`: readiness tracks tailscaled's state, so the
  first HTTPS request can fail for up to a minute after the pod is Ready while
  the sidecar obtains the certificate.

* Shared token store (Kubernetes `Lease`/Secret or a Redis-compatible backend)
  so replicas behind a Tailscale Service can share codes and refresh tokens.
* Signing key rotation with a JWKS that publishes the previous key.
* `Tailscale-App-Capabilities` header support (`AcceptAppCaps` in the serve
  config) as an alternative to LocalAPI whois.
* Device-posture/check-mode style re-authentication (upstream #59).
