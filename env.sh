#!/usr/bin/env bash
#
# env.sh — nix-composefs development environment.
#
# Source this from a shell (do not exec):
#
#   . ./env.sh            # refresh the Nix profile, export PATH
#   . ./env.sh --no-nix   # export only (no Nix profile refresh)
#
# Everything Nix-provided lands under target/nix so the host is never
# touched:
#
#   target/nix/profiles/profile   — nix profile (binary + runtime tools)
#   target/cargo                  — CARGO_TARGET_DIR (cargo build state)
#
# After sourcing, use:
#   ncp-build   — cargo build --release
#   ncp-test    — cargo test
#   ncp-run     — run the freshly built binary
#   ncp         — alias for the built binary path

NCP_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
NCP_TARGET="${NCP_TARGET:-${NCP_ROOT}/target}"
NCP_PROFILE="${NCP_PROFILE:-${NCP_TARGET}/nix/profiles/profile}"

export NCP_ROOT
export NCP_TARGET
export NCP_PROFILE
# Match initos naming so scripts can share conventions.
export NIX_PROFILE="${NCP_PROFILE}"
# Keep all cargo state under target/ as well.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${NCP_TARGET}/cargo}"

if [ "${1:-}" != "--no-nix" ] && command -v nix >/dev/null 2>&1; then
    # Refresh the profile with the built binary plus runtime tools. This
    # nix only accepts a single package per `nix profile install`, so install
    # each separately. Idempotent.
    mkdir -p "$(dirname "${NCP_PROFILE}")"
    for attr in nix-composefs deps; do
        nix profile install --profile "${NCP_PROFILE}" "${NCP_ROOT}/.#${attr}" \
            2>/dev/null || nix build "${NCP_ROOT}/.#${attr}" \
            --profile "${NCP_PROFILE}" --no-link
    done
fi

if [ -d "${NCP_PROFILE}/bin" ]; then
    case ":${PATH}:" in
        *":${NCP_PROFILE}/bin:"*) ;;
        *) export PATH="${NCP_PROFILE}/bin:${PATH}" ;;
    esac
fi

ncp-build() {
    cargo build --release --manifest-path "${NCP_ROOT}/Cargo.toml"
}

ncp-test() {
    cargo test --manifest-path "${NCP_ROOT}/Cargo.toml" "$@"
}

ncp() {
    "${NCP_TARGET}/cargo/release/nix-composefs" "$@"
}

ncp-run() {
    ncp "$@"
}
