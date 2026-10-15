# Running tsidp on Kubernetes

tsidp runs as a single-replica StatefulSet with a `tailscale/tailscale`
sidecar. The sidecar is the tailnet node (`idp.<tailnet>.ts.net`); tsidp is a
plain HTTP service next to it. See [design.md](design.md) for why.

This guide reflects a live deployment on k3s with Flux and Headlamp
([field report](field-report-2026-10-14-k3s-headlamp.md)): a pods-have-no-tailnet
cluster whose node runs `tailscaled`, which is the setup the cluster listener
exists for.

## Prerequisites

* A tailnet with MagicDNS and HTTPS certificates enabled.
* Node credentials for the sidecar: an auth key, or an OAuth client (see
  [Node authentication](#node-authentication)). Workload identity federation
  also works: set `TS_CLIENT_ID` and `TS_AUDIENCE` on the sidecar instead.
* The policy entries in [Tailnet policy](#tailnet-policy).
* The image: releases publish `ghcr.io/abrar-uddin/tsidp-rust:X.Y.Z` and
  `:latest`; pushes to `main` publish `:main` and `:sha-...`. The package inherits the
  repository's visibility; while that is private, give the cluster a pull
  secret (see [Image](#image)) or make the package public.

## Image

CI builds and pushes `ghcr.io/abrar-uddin/tsidp-rust` for amd64 and arm64. To pull
a private package, create a pull secret from a token with `read:packages` and
reference it from the pod:

```sh
kubectl -n tsidp create secret docker-registry ghcr   --docker-server=ghcr.io --docker-username=abrar-uddin --docker-password=<token>
kubectl -n tsidp patch serviceaccount tsidp -p '{"imagePullSecrets":[{"name":"ghcr"}]}'
```

Or build locally:

```sh
make docker-image                       # builds tsidp:local for the host arch
make image-tar                          # docker save -> dist/tsidp-<version>.tar
```

Sideloading without a registry:

| cluster | command |
|---|---|
| k3s | `sudo k3s ctr -n k8s.io images import dist/tsidp-<version>.tar` |
| kind | `kind load image-archive dist/tsidp-<version>.tar` |
| k0s | `sudo k0s ctr -n k8s.io images import dist/tsidp-<version>.tar` |

Then set `imagePullPolicy: Never` (or `IfNotPresent`) and the tag you imported.
`GET :9464/version` returns the `VERSION` build argument, which is the quickest
way to confirm which build a pod is running after a re-import.

## Node authentication

The sidecar registers the node once; afterwards the identity lives in the
`TS_KUBE_SECRET` Secret (or the state volume) and the key is not consulted.

**Auth key** (the quick-start path): create a reusable or single-use key and
put it in a Secret named `tsidp-authkey` with key `TS_AUTHKEY`.

**OAuth client** (no long-lived key in git): create an OAuth client with the
`auth_keys` write scope for `tag:tsidp`. Three details matter:

1. Nodes minted from an OAuth client default to `ephemeral=true` and
   `preauthorized=false`. An ephemeral `idp` node that stays offline long
   enough is deleted, the stored state goes stale, and the next start
   registers as `idp-1`. Append `?ephemeral=false&preauthorized=true`.
2. A `secretKeyRef` cannot carry a query string, but Kubernetes `$(VAR)`
   expansion can, as long as the referenced variable is defined earlier in
   the list:
   ```yaml
   - name: TS_OAUTH_CLIENT_SECRET
     valueFrom: { secretKeyRef: { name: tsidp-oauth, key: client_secret } }
   - name: TS_AUTHKEY
     value: "$(TS_OAUTH_CLIENT_SECRET)?ephemeral=false&preauthorized=true"
   - name: TS_EXTRA_ARGS
     value: "--advertise-tags=tag:tsidp"
   ```
   The kustomize base carries this block commented out; the chart renders it
   from `tailscale.oauth.*`.
3. The OAuth client can only mint keys for tags it owns: `tagOwners["tag:tsidp"]`
   must list the tag the OAuth client itself was created with (for example
   `tag:tailscale-operator` if you reuse the operator's client).

**Secrets from an operator.** Any secret operator works; the Secret just needs
the expected key. With the 1Password operator:

```yaml
apiVersion: onepassword.com/v1
kind: OnePasswordItem
metadata: { name: tsidp-oauth, namespace: tsidp }
spec: { itemPath: "vaults/homelab/items/tsidp-oauth-client" }   # field: client_secret
```

With External Secrets, an `ExternalSecret` whose `target.name` is `tsidp-oauth`
and whose data maps `client_secret` does the same.

## Tailnet policy

Two kinds of sources need to reach the node on port 443: people (through the
browser) and machines that fetch discovery or JWKS, such as the kube-apiserver
host if it runs `tailscaled`, or operator proxies if you use an egress Service.
Then a capability grant for the people who manage clients:

```jsonc
"grants": [
  // reachability: humans and tagged machines (apiserver host, operator proxies)
  { "src": ["autogroup:member", "autogroup:tagged"], "dst": ["tag:tsidp"], "ip": ["443"] },

  // who may administer tsidp, and extra claims for everyone matched
  { "src": ["autogroup:admin"], "dst": ["tag:tsidp"],
    "app": { "tailscale.com/cap/tsidp": [{
      "allow_admin_ui": true,
      "allow_dcr": true,
      "groups": ["admins"],                     // -> `groups` claim; bind RBAC to it
      "extraClaims": { "email_verified": true },
      "includeInUserInfo": true,
      "users": ["*"], "resources": ["*"]        // only needed for token exchange
    }] } }
]
```

Grants apply immediately; no restart needed. `groups` is the piece that makes
Kubernetes RBAC simple later, because the username claim is a long
pseudo-email for GitHub and passkey logins (see [kube-apiserver](#kube-apiserver)).

## Install with kustomize

```sh
kubectl apply -k deploy/kubernetes/base
kubectl -n tsidp create secret generic tsidp-authkey --from-literal=TS_AUTHKEY=tskey-auth-...
kubectl -n tsidp rollout status sts/tsidp
```

The default base keeps all state in two Secrets (`tsidp-tailscale-state` for
the node, `tsidp-state` for the signing key and clients); the Role in
`rbac.yaml` is sufficient for both. Use `deploy/kubernetes/overlays/pvc` for a
PersistentVolume instead, which is also how you migrate a Go tsidp data
directory: copy `oidc-key.json` and `oidc-funnel-clients.json` into the volume.

Verified on k3s with the base as shipped: the namespace's
`pod-security.kubernetes.io/enforce: restricted` label (both containers run
as 65532 with dropped capabilities and the runtime seccomp profile), the
`NetworkPolicy` under k3s's policy controller, the `TS_SERVE_CONFIG`
ConfigMap (the sidecar applies it before tsidp is up; tsidp then logs
`already configured`), and the startup probe's `failureThreshold: 120`, which
covers the certificate wait. Clients survived pod replacements and an image
swap with the Secret backend.

## Install with Helm

```sh
helm install tsidp oci://ghcr.io/abrar-uddin/charts/tsidp --version 0.1.0 \
  -n tsidp --create-namespace \
  --set tailscale.authKeySecret=tsidp-authkey \
  --set tailscale.hostname=idp
```

(`charts/tsidp` from a checkout works the same way.)

or with an OAuth client:

```sh
  --set tailscale.oauth.existingSecret=tsidp-oauth \
  --set tailscale.oauth.tags=tag:tsidp
```

Useful values: `tailscale.funnel`, `tsidp.clusterPublicUrl`,
`tsidp.clusterIssuerUrl`, `tsidp.jwtAccessTokens`, `tsidp.allowTaggedNodes`,
`tsidp.extraScopes`, `tsidp.issuerUrl`, `serviceMonitor.enabled`,
`persistence.*`. The chart renders the same objects as the kustomize base but
has not itself been through a live deployment yet.

## First start

Watch the sidecar until the node is Running, then `/readyz`:

```sh
kubectl -n tsidp logs sts/tsidp -c tailscale -f
kubectl -n tsidp port-forward sts/tsidp 9464 & curl -s localhost:9464/readyz
```

```json
{"ready":true,"issuer":"https://idp.<tailnet>.ts.net","clients":0,
 "state_backend":"kubernetes secret tsidp/tsidp-state",
 "tailscaled":{"running":true,"version":"1.96.5","serve_config":{"Ok":"already configured"},...}}
```

Readiness tracks tailscaled's state, not the TLS certificate. The first
HTTPS request to `https://idp.<tailnet>.ts.net` can fail for up to a minute
after readiness while the sidecar obtains the certificate from Let's Encrypt.
Retry; it is a one-time wait per node.

## Admin API

Everything the admin UI does is also a JSON API on the tailnet listener,
gated by the `allow_admin_ui` grant of the calling device. Run these from a
device whose user has the grant.

```sh
IDP=https://idp.<tailnet>.ts.net

# create (public client: PKCE, no secret)
curl -s -X POST $IDP/clients/new -H 'Content-Type: application/json' \
  -d '{"name":"headlamp","redirect_uris":["https://headlamp.<tailnet>.ts.net/oidc-callback"],"public":true}'
# create (confidential client; the secret is only ever shown in this response)
curl -s -X POST $IDP/clients/new -H 'Content-Type: application/json' \
  -d '{"name":"grafana","redirect_uris":["https://grafana.example/login/generic_oauth"]}'
# the same as a form: name=..., redirect_uri=<one per line>, public=1
curl -s $IDP/clients/                          # list (secrets redacted)
curl -s $IDP/clients/<client_id>               # get
curl -s -X POST $IDP/clients/<client_id>/secret   # rotate; makes a public client confidential
curl -s -X DELETE $IDP/clients/<client_id>     # delete and revoke its tokens
```

Fields accepted on create: `name`, `redirect_uris` (array) or `redirect_uri`
(newline separated), `public` (bool). Responses use the RFC 7591 field names
(`client_id`, `client_secret`, `client_name`, `redirect_uris`,
`token_endpoint_auth_method`). Browser-originated requests are checked for
`Sec-Fetch-Site: same-origin`; curl is not affected.

Applications can also register themselves with RFC 7591 dynamic client
registration at `POST /register` if their device has `allow_dcr`.

## Wiring up relying parties

There are two URLs for tsidp:

| URL | who uses it | what it serves |
|---|---|---|
| `https://idp.<tailnet>.ts.net` | browsers, anything on the tailnet | everything; identity comes from the caller's tailnet address |
| `http://tsidp.tsidp.svc.cluster.local:8080` (the cluster Service) | pods | discovery, token, userinfo, introspection, jwks; no identity, no `/authorize` |

Pods on a normal CNI network cannot resolve or route to the tailnet name, so
in-cluster relying parties point at the Service. Discovery served there is
built for that: `authorization_endpoint` is the tailnet URL (the browser can
reach it), while `token_endpoint`, `userinfo_endpoint`,
`introspection_endpoint` and `jwks_uri` are under the Service URL.

```sh
$ curl -s http://tsidp.tsidp.svc.cluster.local:8080/.well-known/openid-configuration
{
  "issuer": "https://idp.<tailnet>.ts.net",
  "authorization_endpoint": "https://idp.<tailnet>.ts.net/authorize",
  "token_endpoint": "http://tsidp.tsidp.svc.cluster.local:8080/token",
  "userinfo_endpoint": "http://tsidp.tsidp.svc.cluster.local:8080/userinfo",
  "introspection_endpoint": "http://tsidp.tsidp.svc.cluster.local:8080/introspect",
  "jwks_uri": "http://tsidp.tsidp.svc.cluster.local:8080/.well-known/jwks.json",
  ...
}
```

The Service URL comes from `TSIDP_CLUSTER_PUBLIC_URL`, which the manifests and
the chart set to the Service they create. If it is unset, tsidp echoes the
request's `Host` header. Either way the cluster listener ignores every
`X-Forwarded-*` header for identity.

### Which issuer does the relying party see?

**Default: `issuer` stays the tailnet URL.** ID tokens carry
`iss: https://idp.<tailnet>.ts.net` whichever listener minted them. Use this
whenever tokens are forwarded to something that validates against the tailnet
issuer, kube-apiserver above all. The relying party fetches discovery from the
Service URL, so it must accept that the document's `issuer` differs from the
URL it fetched it from. go-oidc based clients reject that by default and need
their "insecure issuer" setting; most expose it:

| relying party | setting |
|---|---|
| Headlamp | `config.oidc.issuerURL=http://tsidp.tsidp.svc.cluster.local:8080`, `config.oidc.validatorIssuerURL=https://idp.<tailnet>.ts.net` |
| oauth2-proxy | `--oidc-issuer-url=http://tsidp.tsidp.svc.cluster.local:8080 --insecure-oidc-skip-issuer-verification` |
| go-oidc | `oidc.InsecureIssuerURLContext(ctx, "https://idp.<tailnet>.ts.net")` |
| Grafana | no discovery needed: set `auth_url`, `token_url`, `api_url` individually (below) |

**Strict mode: `TSIDP_CLUSTER_ISSUER_URL=http://tsidp.tsidp.svc.cluster.local:8080`.**
The cluster listener becomes a second issuer. Discovery served there reports
the Service URL as `issuer`, and tokens minted through that listener carry it
as `iss`, so clients with no override (Argo CD, Dex connectors, Spring
Security) work unmodified. Tokens minted via the tailnet listener keep the
tailnet issuer. Do not enable this when the same tokens are forwarded to
kube-apiserver or to anything else configured with the tailnet issuer.

Duplicate scopes in a request (Headlamp sends `openid openid profile email`)
are accepted and collapsed.

### Headlamp (verified)

Register a public client with the admin API (above), redirect URI
`https://headlamp.<tailnet>.ts.net/oidc-callback`. Headlamp chart values:

```yaml
config:
  oidc:
    clientID: <client id>
    issuerURL: http://tsidp.tsidp.svc.cluster.local:8080   # discovery, token, jwks via the Service
    validatorIssuerURL: https://idp.<tailnet>.ts.net        # `iss` in the tokens
    callbackURL: https://headlamp.<tailnet>.ts.net/oidc-callback
    scopes: "openid profile email"
    usePKCE: true
    useAccessToken: false
```

`validatorIssuerURL` is mandatory (it is Headlamp's go-oidc insecure-issuer
switch). Set `callbackURL` explicitly rather than relying on
`X-Forwarded-Proto` from the ingress proxy.

The resulting ID token:

```json
{"iss":"https://idp.<tailnet>.ts.net","aud":["<client id>"],"sub":"userid:1652...",
 "email":"abrar@github.idp.<tailnet>.ts.net","preferred_username":"abrar",
 "groups":["admins"],"email_verified":true}
```

### kube-apiserver

kube-apiserver fetches discovery and JWKS from *its* configured issuer URL,
so the control plane itself must reach `https://idp.<tailnet>.ts.net`. In
order of simplicity:

1. **The control-plane host runs `tailscaled`** (k3s, kubeadm, Talos with the
   Tailscale extension). Nothing else is needed: the host resolves MagicDNS,
   the certificate is a public Let's Encrypt one, so no `--oidc-ca-file`
   (`OIDC: No x509 certificates provided, will use host's root CA set`). Give
   the host's tag access to `tag:tsidp:443` (the `autogroup:tagged` grant
   above).
2. **Operator egress Service**: an `ExternalName` Service with the
   `tailscale.com/tailnet-fqdn: idp.<tailnet>.ts.net` annotation plus a
   CoreDNS rewrite so the tailnet name resolves to it in-cluster, and a grant
   from the proxy tag to `tag:tsidp:443`.
3. **Structured authentication configuration** (Kubernetes 1.30+) has a
   separate `issuer.discoveryURL`; check whether your version accepts a
   plain-http URL before pointing it at the Service, otherwise terminate TLS in
   front of the Service.

k3s, `/etc/rancher/k3s/config.yaml`:

```yaml
kube-apiserver-arg:
  - oidc-issuer-url=https://idp.<tailnet>.ts.net
  - oidc-client-id=<headlamp client id>
  - oidc-username-claim=email
  - "oidc-username-prefix=tsidp:"
  - oidc-groups-claim=groups
  - "oidc-groups-prefix=tsidp:"
```

Quote the items that end in a colon: unquoted, YAML parses
`oidc-groups-prefix=tsidp:` as a map, the apiserver fails with `unknown flag`,
and the control plane stays down until the file is fixed.

Bind RBAC to the group from the capability grant rather than the username:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: { name: tsidp-admins }
roleRef: { apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: cluster-admin }
subjects: [{ kind: Group, name: "tsidp:admins" }]
```

With `oidc-username-claim=email` a GitHub or passkey user becomes
`tsidp:abrar@github.idp.<tailnet>.ts.net`, which is correct but long.
`preferred_username` (`abrar`) is friendlier but is only the local part of the
login and may collide across identity providers; prefer group bindings and
treat the username as informational.

Verified: `kubectl --token=<id_token> auth whoami` reports the user and
`[tsidp:admins system:authenticated]`; a tampered token is `Unauthorized`.

### Grafana

```ini
[auth.generic_oauth]
enabled = true
name = Tailscale
client_id = ...
client_secret = ...
scopes = openid email profile
auth_url = https://idp.<tailnet>.ts.net/authorize
token_url = http://tsidp.tsidp.svc.cluster.local:8080/token
api_url = http://tsidp.tsidp.svc.cluster.local:8080/userinfo
use_pkce = true
```

Enable `tsidp.jwtAccessTokens` if a client validates access tokens offline
(Incus, MCP Toolbox, zitadel/oidc based apps).

### Public / SPA / CLI clients

Create the client with `public: true` (UI checkbox, API field, or
`"token_endpoint_auth_method": "none"` via DCR). The client must use PKCE
with S256 and sends only `client_id` to `/token`.

## Verifying a deployment

`scripts/e2e-login.sh` drives the login flow with curl from a tailnet device:
authorize with PKCE, redeem the code, decode the ID token, call userinfo.

```sh
scripts/e2e-login.sh https://idp.<tailnet>.ts.net <client id> https://app/cb
# add --token-url http://tsidp.tsidp.svc.cluster.local:8080/token when run inside a pod
```

## Observability

* `GET :9464/healthz` liveness, `GET :9464/readyz` readiness with a JSON body
  explaining what is missing (tailscaled state, DNS name, serve config).
* `GET :9464/metrics` Prometheus counters: tokens, codes, exchanges, denied
  requests, whois failures, live token gauges.
* `GET :9464/version` the build's `VERSION`.
* `TSIDP_LOG_FORMAT=json` for structured logs; one `token issued` line per
  token with `for_user`, `sub`, `client_id`, `redirect_uri`.

## Troubleshooting

| symptom | cause / fix |
|---|---|
| `ErrImagePull` | the GHCR package is private: add a pull secret, make the package public, or sideload (see [Image](#image)) |
| StatefulSet change does not roll out while the pod is crash-looping | RollingUpdate waits for a Ready pod; `kubectl -n tsidp delete pod tsidp-0` |
| RP log: `Post "https://idp.<tailnet>.ts.net/token": dial tcp: lookup idp.<tailnet>.ts.net ... no such host` | the RP is using tailnet URLs; point its issuer at the cluster Service and check `TSIDP_CLUSTER_PUBLIC_URL` |
| RP log: `issuer did not match the issuer returned by provider` | expected in the default mode: set the RP's issuer-validation override to the tailnet URL (Headlamp `validatorIssuerURL`), or enable `TSIDP_CLUSTER_ISSUER_URL` |
| `invalid value 'tcp://...' for '--port'` (older builds) or a warning about `TSIDP_PORT` | Kubernetes service links for a Service named `tsidp`; the manifests set `enableServiceLinks: false`, current builds ignore a non-numeric `TSIDP_PORT` (use `TSIDP_ISSUER_PORT`) |
| `https://idp.<tailnet>.ts.net` returns nothing for the first minute | certificate issuance; `/readyz` does not wait for it |
| node registers as `idp-1` | stale node state after an ephemeral node was deleted; use `?ephemeral=false` on OAuth keys, delete the old node and the state Secret |
| sidecar: `tag:tsidp` not permitted | `tagOwners["tag:tsidp"]` must include the OAuth client's own tag |
| apiserver down after adding OIDC flags on k3s | unquoted `...prefix=tsidp:` in `config.yaml` parsed as YAML; quote it |
| `/readyz` says `running: false` | sidecar not logged in; check `kubectl logs -c tailscale` for the login URL or an expired key |
| `no DNS name` | MagicDNS/HTTPS not enabled for the tailnet |
| `LocalAPI refused to write the serve config` | tsidp is not running as tailscaled's uid; keep the `TS_SERVE_CONFIG` ConfigMap (default) or run both as 65532 |
| `state directory ... is not writable by uid 65532` | set `fsGroup: 65532` (default manifests do) or chown the volume |
| browser gets `access_denied: 100.x.y.z is not a tailnet peer` | request did not come via `tailscale serve`, or the policy blocks the user from reaching `tag:tsidp:443` |
| `application capability allow_admin_ui not granted` | add the grant above for your user |
| token endpoint says `invalid_client` | wrong secret, or a public client registered as confidential (rotate the secret or re-register with `public: true`) |

## Not yet exercised on a live cluster

Helm chart (the live run used the kustomize base), file backend / PVC overlay,
Funnel, token exchange, dynamic client registration, JWT access tokens,
tagged-node tokens, refresh-token rotation, Compose, arm64 image. All are
covered by the test suite; none has a field report.
