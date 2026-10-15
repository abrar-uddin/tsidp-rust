# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/). The section for a version becomes
the body of its GitHub Release.

## [Unreleased]

## [0.1.0] - 2026-10-14

First release of the Rust port of [tailscale/tsidp](https://github.com/tailscale/tsidp).

### Added
- OIDC identity provider backed by a `tailscaled` sidecar over LocalAPI:
  discovery, `/authorize` (identity from the caller's tailnet address),
  `/token` (authorization code with PKCE, refresh, RFC 8693 token exchange),
  `/userinfo`, `/introspect`, JWKS, RFC 7591 dynamic client registration,
  admin UI and JSON `/clients` API.
- Cluster listener serving the identity-free endpoints to in-cluster relying
  parties through a plain Service, with discovery that advertises the
  Service URL (`--cluster-public-url`) and an optional second issuer
  (`--cluster-issuer-url`).
- State backends: files (byte-compatible with the Go server's
  `oidc-key.json` / `oidc-funnel-clients.json`) and a Kubernetes Secret.
- Public (PKCE-only) clients, optional RFC 9068 JWT access tokens,
  `offline_access`, `groups` claim from the capability grant and user
  profile, opt-in tokens for tagged nodes, configurable pseudo-email domain.
- `/healthz`, `/readyz` (tracks tailscaled state and serve config),
  `/metrics` (Prometheus), `/version`, JSON logs, graceful shutdown.
- kustomize base, Helm chart, Compose example, dev container, CI with
  multi-arch distroless/static image, security hardening (CSP, CSRF,
  S256-only PKCE, loopback-only http redirect URIs, refresh-token family
  revocation).
- Verified on k3s with Headlamp and kube-apiserver
  (`docs/field-report-2026-10-14-k3s-headlamp.md`).

[Unreleased]: https://github.com/abrar-uddin/tsidp-rust/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/abrar-uddin/tsidp-rust/releases/tag/v0.1.0
