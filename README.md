# nix-composefs

The core idea: build and sign a Nix or NixOS app and all deps on a trusted machine.
Distribute efficiently to multiple worker machines - where it just runs as a
real read-only compose-fs image backed by a CAS.

It takes Nix closures and builds composefs EROFS metadata images using 
composefs-rs repositories. It is only for builder-to-worker deployment, not
a replacement for normal Nix store copy or daemon semantics which continues 
to be used on the build machines.

`nix-composefs` is deliberately build-side only. It uses composefs-rs for the
tree scanner, EROFS writer, and its `Repository` object store. The repository
root is `/z/composefs`; its objects retain the compatible
`/z/composefs/objects/xx/<digest>` layout while upstream manages repository
metadata, references, garbage collection, and OCI transport.

costinm/initos or another project owns image signing, verification, import, and runtime mounting.

Syncing the CAS is also out of scope - plenty of ways to do it.

## Trust model

The signed composefs image is the sole filesystem manifest. It contains the
authenticated directory tree, per-path metadata, backing-object redirects, and
expected fs-verity digests. OCI, SSH, rsync, or another transport may deliver
the image and objects, but cannot alter the mounted tree without failing
fs-verity or InitOS image-signature verification.

```text
InitOS image signature -> EROFS fs-verity digest -> composefs metadata
                                                    -> backing-object digest
```

Workers mount the verified image; they do not materialize a writable physical
`/nix/store`. This preserves the authenticated per-path permissions and avoids
requiring a Nix daemon or validity database on constrained workers.

## Build

```sh
nix-store -q --refclosure XXX | nix-composefs --image system.composefs
```

The completion defaults to standard input; `/nix/store` and
`/z/composefs` are the default store and repository paths. Use `--paths`,
`--store`, or `--cas` only when a build needs different locations. The build
populates the repository object store and creates a metadata-only EROFS image.
`--image` is the repository ref name, not an external output path: the image
is stored once as an object, linked from `images/<digest>`, and rooted at
`images/refs/system.composefs`.

The builder computes composefs-compatible fs-verity digests in userspace, so
its filesystem does not need fs-verity support.

Sign the resulting image through the existing InitOS release flow, ship it and
the referenced objects through the chosen transport, import objects with
fs-verity, then have InitOS verify and mount it with verity enforcement.

### Receiver import

The receiver does not need `cfsctl` or a composefs daemon to accept a
repository. For an initial administrative transfer, copy the repository root,
then enable fs-verity on every received object before mounting the image:

```sh
rsync -a builder:/z/composefs/ /z/composefs/

find /z/composefs/objects -type f -print0 |
  xargs -0 -r -P 8 -n 1 sh -c '
    fsverity enable "$1" 2>/dev/null || fsverity measure "$1" >/dev/null
  ' sh

composefs-info --basedir=/z/composefs/objects \
  missing-objects /z/composefs/images/refs/system.composefs
```

`fsverity enable` is the receiver-side operation that calls the kernel's
fs-verity ioctl. The fallback accepts only objects that were already verity
enabled; another failure makes the import fail. `missing-objects` must produce
no paths before the image is mounted with `verity=require`.

This full-tree `rsync` procedure is useful for bootstrapping or repair, not an
efficient recurring transport: it scans both repositories. Normal delivery
should derive the missing digest set from the signed image and stream only
those objects, enabling fs-verity before atomically publishing each one under
`objects/xx/<digest>`.

## Development

```sh
nix build .#nix-composefs
nix build .#deps

. ./env.sh
ncp-build
ncp-test
```

The bundle includes the generator plus standard composefs, EROFS, and
fs-verity runtime tools. It does not bundle a separate composefs-rs checkout
or duplicate upstream object-store implementation.

## Deliberate boundaries

- No JSON filesystem manifest: use the signed EROFS image as authority.
- No signing implementation: use InitOS’s existing signature chain.
- No transport implementation: OCI remains the current delivery mechanism.
- No hard-link materialization or Nix daemon registration.
- No local garbage-collection or transport implementation: use upstream
  composefs-rs `cfsctl` repository operations (including OCI and GC) when the
  deployment flow needs them. InitOS remains responsible for selecting only
  verified, signed images on workers.
