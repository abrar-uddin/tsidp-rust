.PHONY: build test coverage clippy fmt deny release docker-image image-tar binary dev helm-lint kustomize-check cut-release

# Everything runs inside the dev container (scripts/dev.sh); no local Rust needed.
DEV := ./scripts/dev.sh

build:
	$(DEV) cargo build

test:
	$(DEV) cargo test

# Per-file line coverage (cargo-llvm-cov); `make coverage HTML=1` also writes target/llvm-cov/html
coverage:
	$(DEV) sh scripts/coverage.sh $(if $(HTML),--html,)

clippy:
	$(DEV) sh -c "rustup component add clippy >/dev/null && cargo clippy --all-targets -- -D warnings"

fmt:
	$(DEV) sh -c "rustup component add rustfmt >/dev/null && cargo fmt"

# Advisories, licenses, duplicate crates and sources per deny.toml
deny:
	$(DEV) sh -c "cargo install cargo-deny --locked >/dev/null 2>&1; cargo deny check"

release:
	$(DEV) cargo build --release --locked

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || date +%Y%m%d)

docker-image:
	docker build --build-arg VERSION=$(VERSION) -t tsidp:local -t tsidp:$(VERSION) .

# Tarball for clusters without a registry:
#   k3s:  sudo k3s ctr -n k8s.io images import dist/tsidp-$(VERSION).tar
#   kind: kind load image-archive dist/tsidp-$(VERSION).tar
image-tar: docker-image
	@mkdir -p dist
	docker save tsidp:$(VERSION) -o dist/tsidp-$(VERSION).tar
	@echo "wrote dist/tsidp-$(VERSION).tar (image tsidp:$(VERSION))"

# Run locally with a fake identity (no tailscaled): http://127.0.0.1:8443 is the admin UI.
dev:
	$(DEV) cargo run -- --dev-identity you@example.com --state-dir /tmp/tsidp-dev --listen 0.0.0.0:8443 --admin-listen 0.0.0.0:9464

helm-lint:
	helm lint charts/tsidp
	helm template tsidp charts/tsidp >/dev/null

kustomize-check:
	kubectl kustomize deploy/kubernetes/base >/dev/null
	kubectl kustomize deploy/kubernetes/overlays/pvc >/dev/null

# Just the static binary for this host's arch (same builder stage as the image).
binary:
	docker buildx build --target binary --build-arg VERSION=$(VERSION) --output type=local,dest=dist/bin .
	@ls -l dist/bin/tsidp-server

# Bump versions, update CHANGELOG, commit and tag; pushes the tag with PUSH=1.
#   make cut-release V=0.2.0 PUSH=1
cut-release:
	scripts/release.sh $(V) $(if $(PUSH),--push,)
