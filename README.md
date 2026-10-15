# tsidp (Rust)

A Tailscale-backed OpenID Connect identity provider, rewritten in Rust and
built for Kubernetes. Your tailnet identity is the login: any app that speaks
OIDC (Grafana, Proxmox, Headlamp, Portainer, MCP servers...) can authenticate
users by who they are on the tailnet, with no passwords and no extra IdP.

This is a port of [tailscale/tsidp](https://github.com/tailscale/tsidp) with a
different deployment model: instead of embedding a userspace Tailscale node,
tsidp runs next to a real `tailscaled` (a pod sidecar or a Compose service) and
talks to it over the LocalAPI socket. That is what makes it fit a cluster:

* **A normal workload.** `tailscale serve` in the sidecar terminates TLS for
  `https://idp.<tailnet>.ts.net` and proxies to tsidp on loopback.
* **A cluster listener.** A second port serves only the identity-free OAuth
  endpoints (token, userinfo, jwks, discovery) so in-cluster relying parties use
  a plain `Service`, never tailnet routing from inside the cluster.
* **No volumes required.** State lives in Kubernetes Secrets (or files, in the
  Go server's exact format for painless migration).
* **Probes and metrics.** `/readyz` tracks tailscaled's real state;
  `/metrics` is Prometheus text; logs can be JSON.
* **Non-root, distroless, multi-arch image**, running as uid 65532 like the
  Tailscale image so the two containers can share the LocalAPI socket.

It also fixes or implements a long list of upstream issues (public PKCE
clients, JWT access tokens, `offline_access`, `groups`, tagged nodes, expiring
auth codes, POST `/authorize`, cross-origin DCR...). See
[docs/design.md](docs/design.md) for the mapping.

> Status: experimental, like upstream. Verified end to end on a k3s cluster
> with Headlamp as the relying party and kube-apiserver accepting the tokens
> ([field report](docs/field-report-2026-10-14-k3s-headlamp.md)); the test
> suite covers about 93% of lines. Images are built by CI at
> `ghcr.io/abrar-uddin/tsidp-rust` for amd64 and arm64; the package is private
> while the repository is (pull secret or make it public).

## Quick start (Docker Compose)

```sh
echo "TS_AUTHKEY=tskey-auth-..." > .env
docker compose up -d
docker compose logs -f tailscale        # wait for "Running"
```

Then add the grant below to your tailnet policy and open
`https://idp.<your-tailnet>.ts.net`.

```jsonc
"grants": [{
  "src": ["autogroup:member"],
  "dst": ["autogroup:self"],           // or the tag / user owning the idp node
  "app": { "tailscale.com/cap/tsidp": [{ "allow_admin_ui": true, "allow_dcr": true }] }
}]
```

## Quick start (Kubernetes)

```sh
kubectl apply -k deploy/kubernetes/base       # image: ghcr.io/abrar-uddin/tsidp-rust (needs a pull secret while private)
kubectl -n tsidp create secret generic tsidp-authkey --from-literal=TS_AUTHKEY=tskey-auth-...
```

or `helm install tsidp oci://ghcr.io/abrar-uddin/charts/tsidp --version 0.1.0 --set tailscale.authKeySecret=tsidp-authkey`.
Node auth with an OAuth client, the tailnet policy, the admin JSON API, a
worked Headlamp + kube-apiserver example and troubleshooting:
[docs/kubernetes.md](docs/kubernetes.md).

## Releases

Every tag `vX.Y.Z` (cut with `scripts/release.sh X.Y.Z --push`) publishes:

| artifact | where |
|---|---|
| image | `ghcr.io/abrar-uddin/tsidp-rust:X.Y.Z`, `:X.Y`, `:latest` (amd64, arm64) |
| Helm chart | `helm install tsidp oci://ghcr.io/abrar-uddin/charts/tsidp --version X.Y.Z` |
| static binaries | `tsidp-server-vX.Y.Z-linux-{amd64,arm64}.tar.gz` with `SHA256SUMS` on the [GitHub Release](https://github.com/abrar-uddin/tsidp-rust/releases) |

Pushes to `main` only produce `:main` and `:sha-...` images. The release body
is the matching section of [CHANGELOG.md](CHANGELOG.md).

## Endpoints

| path | listener | notes |
|---|---|---|
| `/.well-known/openid-configuration`, `/.well-known/oauth-authorization-server`, `/.well-known/jwks.json` | tailnet + cluster | discovery; on the cluster listener the server-to-server endpoints point at the cluster URL, `authorization_endpoint` at the tailnet |
| `/authorize` | tailnet | GET or POST; identity comes from the caller's tailnet address; PKCE S256 required for public clients |
| `/token` | tailnet + cluster | `authorization_code`, `refresh_token`, `urn:ietf:params:oauth:grant-type:token-exchange` (with `--enable-sts`) |
| `/userinfo`, `/introspect` | tailnet + cluster | bearer token / client credentials |
| `/register` | tailnet | RFC 7591 dynamic client registration, needs `allow_dcr` |
| `/clients`, `/clients/new`, `/clients/{id}`, `/clients/{id}/secret` | tailnet | JSON API, needs `allow_admin_ui`; curl examples in [docs/kubernetes.md](docs/kubernetes.md#admin-api) |
| `/`, `/new`, `/edit/{id}` | tailnet | admin UI, needs `allow_admin_ui` |
| `/healthz`, `/readyz`, `/metrics`, `/version` | admin | probes and Prometheus |

## Configuration

Every flag is also an environment variable. `TS_STATE_DIR` and `TS_SOCKET` are
accepted as legacy aliases.

| flag | env | default | purpose |
|---|---|---|---|
| `--listen` | `TSIDP_LISTEN` | `127.0.0.1:8443` | tailnet listener behind `tailscale serve` |
| `--cluster-listen` | `TSIDP_CLUSTER_LISTEN` | off | identity-free endpoints for in-cluster clients |
| `--cluster-public-url` | `TSIDP_CLUSTER_PUBLIC_URL` | request Host | base URL the cluster listener's discovery advertises for token/userinfo/jwks |
| `--cluster-issuer-url` | `TSIDP_CLUSTER_ISSUER_URL` | off | make the cluster listener a second issuer (strict RPs only; not with kube-apiserver) |
| `--admin-listen` | `TSIDP_ADMIN_LISTEN` | `0.0.0.0:9464` | probes and metrics |
| `--tailscale-socket` | `TSIDP_TAILSCALE_SOCKET` | `/var/run/tailscale/tailscaled.sock` | LocalAPI socket |
| `--port` | `TSIDP_ISSUER_PORT` | `443` | public port in the issuer URL (`TSIDP_PORT` is a deprecated alias, ignored unless numeric) |
| `--issuer-url` | `TSIDP_ISSUER_URL` | derived from MagicDNS | override for Tailscale Services / custom domains |
| `--state-backend` | `TSIDP_STATE_BACKEND` | `file` | `file` or `kubernetes` |
| `--state-dir` | `TSIDP_STATE_DIR` | `.` | file backend directory |
| `--kube-secret`, `--kube-namespace` | `TSIDP_KUBE_SECRET`, `TSIDP_KUBE_NAMESPACE` | `tsidp-state`, pod ns | kubernetes backend |
| `--funnel` | `TSIDP_USE_FUNNEL` | false | allow Funnel in the serve config |
| `--enable-sts` | `TSIDP_ENABLE_STS` | false | RFC 8693 token exchange |
| `--configure-serve` | `TSIDP_CONFIGURE_SERVE` | true | write the serve config via LocalAPI |
| `--jwt-access-tokens` | `TSIDP_JWT_ACCESS_TOKENS` | false | RFC 9068 JWT access tokens |
| `--allow-tagged-nodes` | `TSIDP_ALLOW_TAGGED_NODES` | false | issue tokens to tagged nodes (`sub=node:<id>`) |
| `--allow-cross-origin-dcr` | `TSIDP_ALLOW_CROSS_ORIGIN_DCR` | false | let browser pages on other origins call `/register` (browser-based MCP clients); see Security |
| `--allow-http-redirect-uris` | `TSIDP_ALLOW_HTTP_REDIRECT_URIS` | false | accept `http://` redirect URIs for hosts other than localhost |
| `--extra-scopes` | `TSIDP_EXTRA_SCOPES` | | extra scopes to advertise/accept |
| `--email-domain` | `TSIDP_EMAIL_DOMAIN` | issuer host | suffix for `user@github` / `user@passkey` |
| `--access-token-ttl`, `--refresh-token-ttl`, `--code-ttl` | `TSIDP_*_TTL` | 300 / 30d / 300 | lifetimes in seconds |
| `--log`, `--log-format` | `TSIDP_LOG`, `TSIDP_LOG_FORMAT` | `info`, `text` | logging |
| `--dev-identity` | `TSIDP_DEV_IDENTITY` | | development only: fake identity, no tailscaled |
| `--check-ready` | | | exit 0 if `/readyz` is 200 (container health checks) |

## Capability grant

```jsonc
"tailscale.com/cap/tsidp": [{
  "allow_admin_ui": true,            // admin UI and /clients API
  "allow_dcr": true,                 // dynamic client registration
  "users": ["*"],                    // token exchange / resource indicators: who
  "resources": ["https://api.example.com"],   // ...may get tokens for which audiences
  "groups": ["platform"],            // added to the `groups` claim
  "extraClaims": { "email_verified": true, "roles": ["admin"] },
  "includeInUserInfo": true          // also return extraClaims from /userinfo
}]
```

## Security notes

tsidp has no login page: the caller's tailnet identity *is* the
authentication, and it travels with every request a user's machine makes,
including requests a web page they happen to visit makes from their browser.
The defaults are chosen with that in mind.

* **Browser-facing endpoints are CSRF-gated.** The admin UI, `/clients` and
  `/register` require `Sec-Fetch-Site: same-origin` (or a matching `Origin`)
  on mutating requests. Non-browser callers (curl, operators) send neither
  header and pass. Browser-based MCP clients that register themselves from
  another origin need `--allow-cross-origin-dcr`, which swaps the gate on
  `/register` for permissive CORS; understand that any page a DCR-permitted
  user visits can then register clients with that user's identity.
* **No consent screen.** `/authorize` answers a valid request from a
  registered client with an immediate redirect, as upstream does. Treat
  `allow_dcr` and `allow_admin_ui` grants as the ability to create relying
  parties that any tailnet user will silently log in to.
* **PKCE is S256 only** (OAuth 2.1); public clients must use it, confidential
  clients may.
* **Redirect URIs** must be `https://`, a custom scheme, or `http://` on
  localhost unless `--allow-http-redirect-uris` is set.
* **Refresh tokens rotate and detect replay.** Presenting a refresh token twice
  revokes every token derived from the same authorization. Each refresh also
  re-resolves the user through `whois`, so a user removed from the tailnet (or
  whose grant changed) loses access at the next refresh instead of at the
  refresh token's expiry.
* **Client credentials never degrade.** Wrong or unknown credentials on the
  token-exchange and introspection endpoints are refused; only a request that
  presents no credentials at all is attributed to the calling tailnet node.
* **Admin UI** output is attribute-escaped and served with a strict
  `Content-Security-Policy` (no inline script, no framing).
* **Admin listener** (`/healthz`, `/readyz`, `/metrics`) is unauthenticated;
  `/readyz` reports only readiness booleans and the issuer. Restrict it with
  the chart's `networkPolicy.adminIngressFrom`.
* **Dependencies** are checked with `cargo deny` in CI (`deny.toml`). The one
  accepted advisory is RUSTSEC-2023-0071 (`rsa`, no fix available), with the
  rationale recorded next to the ignore.
* **Image** is a statically linked musl binary on `distroless/static`: no
  libc, OpenSSL or libstdc++ packages to patch.

## Development

No local Rust toolchain is needed; everything runs in the dev container.

```sh
./scripts/dev.sh cargo test                 # or .\scripts\dev.ps1 cargo test on Windows
make clippy
make coverage                               # per-file line coverage (about 93%)
make dev                                    # fake identity on http://127.0.0.1:8443
make docker-image                           # tsidp:local
make image-tar                              # dist/tsidp-<version>.tar for sideloading
scripts/e2e-login.sh https://idp.<tailnet>.ts.net <client id> <redirect uri>   # verify a deployment
```

Open the folder in VS Code and "Reopen in Container" to get rust-analyzer,
kubectl and helm preinstalled (`.devcontainer/devcontainer.json`).

## Migrating from the Go tsidp

1. Deploy the sidecar pair with the file backend (`deploy/kubernetes/overlays/pvc`
   or Compose) and copy `oidc-key.json` and `oidc-funnel-clients.json` into
   the state directory. Client IDs, secrets and the signing key carry over, so
   relying parties and the JWKS stay valid.
2. The tailnet node is now the sidecar: use the same hostname so the issuer URL
   does not change. Remove the old node from the admin console first to avoid
   `idp-1`.
3. Replace `TS_STATE_DIR`/`TS_HOSTNAME`/`TS_AUTHKEY` with their sidecar
   equivalents (`TS_STATE_DIR` or `TS_KUBE_SECRET`, `TS_HOSTNAME`, `TS_AUTHKEY`
   on the `tailscale` container). `TSIDP_ENABLE_STS`, `TSIDP_USE_FUNNEL`,
   `TSIDP_LOG` keep their names. `TAILSCALE_USE_WIP_CODE` is not needed.

## License

BSD-3-Clause, same as upstream.
