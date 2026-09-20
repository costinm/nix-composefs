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
#   ncp-build   — cargo build --release (--target musl)
#   ncp-test    — cargo test (--target musl)
#   ncp-run     — run the freshly built binary
#   ncp         — alias for the built binary path

NCP_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
NCP_TARGET="${NCP_TARGET:-${NCP_ROOT}/target}"
NCP_PROFILE="${NCP_PROFILE:-${NCP_TARGET}/nix/profiles/profile}"
NCP_MUSL_TARGET="${NCP_MUSL_TARGET:-x86_64-unknown-linux-musl}"

export NCP_ROOT
export NCP_TARGET
export NCP_PROFILE
export NCP_MUSL_TARGET
# Match initos naming so scripts can share conventions.
export NIX_PROFILE="${NCP_PROFILE}"
# Keep all cargo state under target/ as well.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${NCP_TARGET}/cargo}"

if [ -d "${NCP_PROFILE}/bin" ]; then
    case ":${PATH}:" in
        *":${NCP_PROFILE}/bin:"*) ;;
        *) export PATH="${NCP_PROFILE}/bin:${PATH}" ;;
    esac
fi

# If the musl cc is available (inside `nix develop`, or already on PATH),
# point cargo/CC at it so vendored openssl builds for musl too.
if command -v x86_64-unknown-linux-musl-gcc >/dev/null 2>&1; then
    MUSL_CC="$(command -v x86_64-unknown-linux-musl-gcc)"
    export CC_x86_64_unknown_linux_musl="${MUSL_CC}"
    export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER="${MUSL_CC}"
fi

ncp-build() {
    cargo build --release --manifest-path "${NCP_ROOT}/Cargo.toml" \
        --target "${NCP_MUSL_TARGET}" "$@"
}

ncp-test() {
    cargo test --manifest-path "${NCP_ROOT}/Cargo.toml" \
        --target "${NCP_MUSL_TARGET}" "$@"
}

ncp() {
    "${NCP_TARGET}/cargo/${NCP_MUSL_TARGET}/release/nix-composefs" "$@"
}

ncp-run() {
    ncp "$@"
}
