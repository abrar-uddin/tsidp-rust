#!/usr/bin/env bash
# Run cargo (or any command) inside the project's dev container.
#   ./scripts/dev.sh cargo test
#   ./scripts/dev.sh cargo build --release
#   ./scripts/dev.sh bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
image="rust:1-bookworm"
if [ $# -eq 0 ]; then set -- cargo build; fi
docker volume create tsidp-rust-cargo-registry >/dev/null
docker volume create tsidp-rust-target >/dev/null
tty_flag="-i"; if [ -t 0 ] && [ -t 1 ]; then tty_flag="-it"; fi
exec docker run --rm $tty_flag \
  -v "$root:/workspace" \
  -v tsidp-rust-cargo-registry:/usr/local/cargo/registry \
  -v tsidp-rust-target:/workspace/target \
  -w /workspace \
  -e CARGO_TERM_COLOR=always \
  "$image" "$@"
