#!/usr/bin/env bash
#
# nixc-sync.sh — push a signed composefs nix-store closure to a worker over SSH.
#
# Usage:
#   bin/nixc-sync.sh user@worker [options]
#
# Options:
#   --manifest FILE    completion manifest (build machine)
#   --image FILE       composefs metadata image (build machine)
#   --cas DIR          local CAS (build machine)
#   --remote-cas DIR   CAS directory on the worker (default: same as --cas)
#   --remote-store DIR store root on the worker (default: /nix/store)
#   --key B64          Ed25519 public key (image_key.pub.b64) to verify on the worker
#   --db-crt FILE      UEFI db certificate to verify on the worker
#   --secrets DIR      secrets dir; --key defaults to $DIR/image_key.pub.b64
#   --sign             sign the image locally first (needs --secrets)
#   --no-materialize   transfer only; do not materialize the remote store
#
# Steps:
#   1. nix-composefs missing  -> tar the missing CAS objects -> ssh/tar to the worker
#   2. scp image (+ .sig files) + manifest to the worker
#   3. remote: nix-composefs import, verify, materialize
#
# The binary is resolved from NCP_PROFILE/bin (see env.sh), PATH, or CARGO target.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

dst=""
manifest=""
image=""
cas=""
remote_cas=""
remote_store="/nix/store"
key=""
db_crt=""
secrets=""
sign=0
materialize=1

while [ $# -gt 0 ]; do
    case "$1" in
        --manifest) manifest="$2"; shift 2 ;;
        --image) image="$2"; shift 2 ;;
        --cas) cas="$2"; shift 2 ;;
        --remote-cas) remote_cas="$2"; shift 2 ;;
        --remote-store) remote_store="$2"; shift 2 ;;
        --key) key="$2"; shift 2 ;;
        --db-crt) db_crt="$2"; shift 2 ;;
        --secrets) secrets="$2"; shift 2 ;;
        --sign) sign=1; shift ;;
        --no-materialize) materialize=0; shift ;;
        -*) echo "unknown option: $1" >&2; exit 2 ;;
        *) if [ -z "$dst" ]; then dst="$1"; else echo "unexpected argument: $1" >&2; exit 2; fi; shift ;;
    esac
done

[ -n "$dst" ] && [ -n "$manifest" ] && [ -n "$image" ] && [ -n "$cas" ] || {
    echo "usage: $0 user@worker --manifest FILE --image FILE --cas DIR [--remote-cas DIR] [--remote-store DIR] [--key B64 | --db-crt FILE | --secrets DIR] [--sign] [--no-materialize]" >&2
    exit 2
}
[ -n "$remote_cas" ] || remote_cas="$cas"
[ -n "$secrets" ] && [ ! -n "$key" ] && [ -f "$secrets/image_key.pub.b64" ] && key="$(cat "$secrets/image_key.pub.b64")"

# Resolve the binary: Nix profile (env.sh) > PATH > cargo target.
NCP_BIN=""
if [ -n "${NCP_PROFILE:-}" ] && [ -x "${NCP_PROFILE}/bin/nix-composefs" ]; then
    NCP_BIN="${NCP_PROFILE}/bin/nix-composefs"
elif command -v nix-composefs >/dev/null 2>&1; then
    NCP_BIN="$(command -v nix-composefs)"
elif [ -x "${ROOT}/target/cargo/release/nix-composefs" ]; then
    NCP_BIN="${ROOT}/target/cargo/release/nix-composefs"
else
    echo "ERROR: nix-composefs binary not found; source ./env.sh first" >&2
    exit 1
fi

scp_opts=(-o BatchMode=yes)
ssh_opts=(-o BatchMode=yes)

# 1. Missing CAS objects over SSH+tar.
missing=$("$NCP_BIN" missing --manifest "$manifest" --cas "$cas")
if [ -n "$missing" ]; then
    n=$(printf '%s\n' "$missing" | wc -l)
    echo "-> transferring $n missing CAS objects to ${dst}:${remote_cas}"
    printf '%s\n' "$missing" | tar -cf - -C "$cas" -T - \
        | ssh "${ssh_opts[@]}" "$dst" "mkdir -p '${remote_cas}' && tar -C '${remote_cas}' -xf -"
else
    echo "-> all CAS objects already present on ${dst}"
fi

# 2. Sign locally if requested, then transfer image + signatures + manifest.
remote_dir="$(dirname "$image")"
remote_base="$(basename "$image")"
if [ "$sign" -eq 1 ]; then
    [ -n "$secrets" ] || { echo "ERROR: --sign needs --secrets" >&2; exit 2; }
    "$NCP_BIN" sign --image "$image" --secrets "$secrets"
fi

files=("$image")
for f in "$image".sig "$image"*.db.sig; do
    [ -f "$f" ] && files+=("$f")
done
echo "-> transferring image + signatures + manifest"
scp "${scp_opts[@]}" "${files[@]}" "$manifest" "$dst:$remote_dir/"
scp "${scp_opts[@]}" "$manifest" "$dst:${remote_cas}/" 2>/dev/null || true

# 3. Remote: import (verity), verify, materialize.
remote_verify=""
[ -n "$key" ] && remote_verify="$remote_verify --key '$key'"
[ -n "$db_crt" ] && {
    scp "${scp_opts[@]}" "$db_crt" "$dst:$remote_dir/"
    remote_verify="$remote_verify --db-crt '$remote_dir/$(basename "$db_crt")'"
}

echo "-> remote: import + verify + materialize"
ssh "${ssh_opts[@]}" "$dst" "set -e
    nix-composefs import --manifest '$remote_dir/$(basename "$manifest")' --cas '$remote_cas'
    if [ -n '$remote_verify' ]; then
        nix-composefs verify --image '$remote_dir/$remote_base' $remote_verify
    else
        echo 'WARNING: no --key/--db-crt given; skipping remote verification'
    fi
"
if [ "$materialize" -eq 1 ]; then
    ssh "${ssh_opts[@]}" "$dst" "set -e
        nix-composefs materialize --manifest '$remote_dir/$(basename "$manifest")' --cas '$remote_cas' --store '$remote_store'
    "
fi

echo "done: ${dst} store at ${remote_store} (image ${remote_dir}/${remote_base})"
