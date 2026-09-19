#!/usr/bin/env bash
#
# build.sh — iterative build entry point (mirrors initos scripts/build.sh).
#
# Usage: scripts/build.sh [check|build|test|deps|all]
#
# Expects either Nix (preferred; everything from the flake) or a host with
# the required tools already installed.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Refresh/export the environment (Nix profile under target/nix, cargo under
# target/cargo). Pass --no-nix to skip the profile refresh.
. "${ROOT}/env.sh" "${NCP_NO_NIX:+--no-nix}"

deps() {
    nix profile install --profile "${NCP_PROFILE}" \
        "${ROOT}/.#nix-composefs" "${ROOT}/.#deps"
    echo "Profile: ${NCP_PROFILE}"
}

check() {
    cargo check --manifest-path "${ROOT}/Cargo.toml" --all-targets
}

build() {
    cargo build --release --manifest-path "${ROOT}/Cargo.toml"
    echo "Binary: ${NCP_TARGET}/cargo/release/nix-composefs"
}

test() {
    cargo test --manifest-path "${ROOT}/Cargo.toml"
}

all() {
    check
    build
    test
}

if [[ $# -gt 0 ]]; then
    "$@"
else
    all
fi
