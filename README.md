# nix-composefs

`/nix/store` as a **signed, syncable composefs store**.

This is a rust CLI that turns a /nix/store subset into a 
syncable composefs store and fs-verity and public key signed 
Erofs metadata image. 

Trusted build machine: find all dependencies (NixOS closure), content-address every regular file into a fs-verity object store
(composefs CAS), emit a composefs **metadata EROFS image** plus a **manifest**, and
sign the image with the same conventions as initos erofs images.
The input is a list of packages (`nix-store -q --refclosure`).


Worker: pull the missing CAS objects and erofs, verify signature and re-create `/nix/store` by **hard-linking** store entries into the CAS. The same CAS serves any number of closures — identical content is stored once (dedup like `nix store optimise`, but keyed by fs-verity
digest instead of re-hashing).

The nix store files will have fs-verity enabled, so any change is detected at runtime. The directories are verified by the 
erofs fs-verity has which is signed by the builder private key.

Assuming secure EFI boot, signed kernel and init and full chain - after a reboot the file integrity should be verified. An attacker getting access can still break the system - but after reboot changes will be detected.

Built on [composefs-rs](https://github.com/containers/composefs-rs)
(`composefs` 0.9.x): the scanner, the V1 (C-compatible) EROFS writer, and
fs-verity support come from the library; this project adds the Nix-store
specifics (completion, manifest, store materialization, initos-compatible
signing).

## Layout

```
src/lib.rs         crate root (re-exports composefs fs-verity types)
src/store.rs       store path grammar + completion files
src/cas.rs         fs-verity CAS (flat xx/digest layout), ObjectStore impl
src/build.rs       completion -> merged tree -> V1 EROFS image + manifest
src/manifest.rs    completion manifest (JSON): paths, inventory, objects
src/sync.rs        missing / import / materialize / optimise
src/sign.rs        Ed25519 + UEFI db signing & verification (initos layout)
src/main.rs        CLI
tests/             end-to-end build->materialize->compare + sign roundtrip
```

## Build (everything from Nix)

```sh
nix build .#nix-composefs          # bundle: nix-composefs + upstream cfsctl + runtime tools (musl)
nix build .#cfsctl                 # upstream composefs-rs cfsctl alone
nix build .#deps                   # runtime tools only (erofs-utils, fsverity-utils, ...)
```

Iterative development (Nix profile under `target/`, host untouched):

```sh
. ./env.sh                        # refreshes target/nix/profiles/profile, exports PATH
ncp-build                         # cargo build --release --target x86_64-unknown-linux-musl (state in target/cargo)
ncp-test
ncp build --help                  # runs target/cargo/x86_64-unknown-linux-musl/release/nix-composefs
```

`nix-composefs` and `cfsctl` are statically linked with musl (initos
conventions); the deps/runtime tools stay glibc.

Local cargo runs need the musl cc and the vendored-openssl build tools; get them via `nix develop`, or install gnumake/perl directly:

```sh
nix shell nixpkgs#gnumake nixpkgs#perl --command cargo test
```

## Usage

Build machine (e.g. the initos SIGN_HOST):

```sh
# completion: one store path per line (e.g. from a NixOS system closure)
nix-composefs build \
  --store /nix/store \
  --cas /z/img/composefs/objects \
  --paths system-closure.txt \
  --image system.composefs \
  --manifest system.json \
  --name system-25.05

nix-composefs sign --image system.composefs --secrets /path/to/uefi-keys
# -> system.composefs.sig (Ed25519) and/or system.composefs.<keyid>.db.sig (UEFI db)
```

Worker:

```sh
nix-composefs missing   --manifest system.json --cas $CAS        # one rel. path per line
# tar those paths over SSH/rsync/OCI into the worker's $CAS
nix-composefs import    --manifest system.json --cas $CAS        # enable fs-verity
nix-composefs verify    --image system.composefs --key "$(cat image_key.pub.b64)"
nix-composefs materialize --manifest system.json --cas $CAS --store /nix/store
```

Mount the composed view (kernel composefs, verity enforced):

```sh
mount -t composefs -o "basedir=$CAS,verity,ro" system.composefs /mnt/nix
# or overlayfs style:
mount -t overlay -o "ro,lowerdir=/mnt/nix-meta::$CAS,verity=require" composefs /mnt/nix
```

Dedup an existing store into the CAS (like `nix store optimise`):

```sh
nix-composefs optimise --manifest system.json --cas $CAS --store /nix/store
```

## Design notes

- **Object identity is the fs-verity digest**, not the Nix sha256 path hash.
  The CAS layout is C-compatible flat `xx/<digest>` (same as the initos
  firmware CAS). The metadata image records each regular file's verity
  digest (overlay metacopy xattr) and redirect; the kernel verifies content
  at read time when mounted with `verity`.
- **Direct store objects**: the composefs-rs scanner walks the real
  `/nix/store` entries; the custom `ObjectStore` streams each file into the
  CAS (copy_file_range, reflink on CoW fs) instead of an intermediate
  staging tree. Nix store files are immutable (`chattr +i`), so the CAS
  holds copies of their inodes — dedup happens *into* the CAS from the
  store (`optimise`) and between closures (shared objects), and workers
  re-create the store as hard links to CAS objects.
- **Small files (<= 64 B)** are inlined in the EROFS image by composefs
  (format constant), and additionally stored in the CAS so materialization
  never needs to parse the image.
- **Signing** mirrors `initos verify`: Ed25519 over the raw fs-verity
  digest in `<image>.sig` (key `image_key.pem`, pubkey
  `image_key.pub.b64`), and PKCS#1 v1.5 SHA-256 in
  `<image>.<keyid>.db.sig` (`keyid` = first 16 hex of
  SHA-256(SPI DER of `db.crt`)). A signed composefs image therefore drops
  into the existing `initos verify` flow unchanged.
- **`--insecure`** enables userspace digests when the backing filesystem
  lacks fs-verity (tmpfs/overlayfs dev machines); production workers use
  verity enforcement.

## Limitations / open items

- The nix store's own `chattr +i` blocks hard-linking store files *from*
  the store; `optimise` unlinks + relinks and reports immutable files
  instead of forcing `chattr -i`.
- Materialization recreates paths/dirs/symlinks/hard links; it does not
  register paths with a nix daemon (no `validity.db` integration yet).
- GC of the CAS: keep an immutable generation per closure set and only
  collect objects no installed closure references (see initos firmware GC
  policy in `notes/ai/2026-09-08-composefs-git-firmware-rollout.md`).

# TODO

- use the previous version to compute the missing objects to be transmitted or packaged. The same idea used in initos for OCI, we can have a periodic large binary (monthly) and incremental deltas - the worker can be simpler and may not need to track
nix packages or run a daemon. So instead of rsync-like (find what worker has, send what is missing) keep track here of what 
the worker is supposed to have, send changed.