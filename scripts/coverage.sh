#!/usr/bin/env sh
# Line coverage per file with cargo-llvm-cov. Run inside the dev container:
#   ./scripts/dev.sh sh scripts/coverage.sh            # summary table
#   ./scripts/dev.sh sh scripts/coverage.sh --html     # also writes target/llvm-cov/html
set -eu
if ! command -v cargo-llvm-cov >/dev/null 2>&1; then
  rustup component add llvm-tools-preview >/dev/null 2>&1
  curl -LsSf https://github.com/taiki-e/cargo-llvm-cov/releases/latest/download/cargo-llvm-cov-x86_64-unknown-linux-gnu.tar.gz \
    | tar xzf - -C /usr/local/cargo/bin
fi
if [ "${1:-}" = "--html" ]; then
  cargo llvm-cov --all-targets --ignore-filename-regex 'main\.rs' --html
fi
cargo llvm-cov --all-targets --ignore-filename-regex 'main\.rs' 2>&1 \
  | grep -E '^(Filename|[a-z/_]+\.rs|TOTAL)' \
  | awk '{ printf "%-26s lines %6s / %-6s  %s\n", $1, $10, $9, $11 }'
