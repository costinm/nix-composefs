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

### Garbage collection

`nix-composefs gc` collects unreferenced objects in `objects/xx/<digest>` while
preserving:

- Objects reachable from EROFS images under `images/refs/**` (or `streams/refs/**`)
  and explicit `-r`/`--root` or positional anchor paths/names.
- Any EROFS image in `images/` whose backing file is hardlinked (`st_nlink > 1`)
  or currently mounted/locked (`flock`), keeping both the image and every
  object it references alive.
- Any individual object in `objects/xx/<digest>` with `st_nlink > 1` (e.g.
  hardlinked into an external directory or another CAS) or an active `flock`.

Sidecar signature files (`*.sig`, `*.db.sig`, `*.basedir`) placed under
`images/refs/` are tolerated and left untouched.

```sh
# Preview deletions without modifying /z/composefs:
nix-composefs gc --cas /z/composefs --dry-run

# Run GC, optionally supplying external EROFS anchors:
nix-composefs gc --cas /z/composefs -r /z/initos/101/firmware-light.composefs
```

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
- GC (`nix-composefs gc`) preserves EROFS image anchors (`images/refs/**`,
  `streams/refs/**`, explicit `-r`/positional anchors, hardlinked EROFS images)
  as well as externally hardlinked objects (`st_nlink > 1`). Use upstream
  `cfsctl` for OCI transport operations. InitOS remains responsible for
  selecting only verified, signed images on workers.
