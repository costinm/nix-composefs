#!/usr/bin/env bash
#
# build.sh — iterative build entry point (mirrors initos scripts/build.sh).
#
# Usage: scripts/build.sh [check|build|test|deps|all]
#
# Expects either Nix (preferred; everything from the flake, including the
# musl cc) or a host with the required tools already installed.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
MUSL_TARGET="x86_64-unknown-linux-musl"

# Refresh/export the environment (Nix profile under target/nix, cargo under
# target/cargo). Pass --no-nix to skip the profile refresh.
. "${ROOT}/env.sh" "${NCP_NO_NIX:+--no-nix}"

deps() {
    # Full bundle: nix-composefs + upstream cfsctl + runtime tools.
    nix profile add --profile "${NCP_PROFILE}" "${ROOT}/#nix-composefs" 2>/dev/null \
        || nix profile install --profile "${NCP_PROFILE}" "${ROOT}/#nix-composefs"
    echo "Profile: ${NCP_PROFILE}"
}

check() {
    cargo check --manifest-path "${ROOT}/Cargo.toml" --all-targets \
        --target ${MUSL_TARGET}
}

build() {
    cargo build --release --manifest-path "${ROOT}/Cargo.toml" \
        --target ${MUSL_TARGET}
    echo "Binary: ${NCP_TARGET}/cargo/${MUSL_TARGET}/release/nix-composefs"
}

test() {
    cargo test --manifest-path "${ROOT}/Cargo.toml" --target ${MUSL_TARGET}
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
