#!/usr/bin/env bash
# Local equivalent of the CI checks: formatting, lints, tests.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== cargo fmt =="
cargo fmt --all --check

echo "== cargo clippy =="
cargo clippy --all-targets -- -D warnings

echo "== cargo test =="
cargo test

echo "all checks passed"
