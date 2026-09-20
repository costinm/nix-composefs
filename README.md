# nix-composefs

Build composefs V1 EROFS metadata images and composefs-rs repositories from
Nix closures. It is for builder-to-worker deployment of complete immutable
generations, not a replacement for normal Nix store copy or daemon semantics.

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
populates the repository object store and produces a metadata-only EROFS image.

The builder computes composefs-compatible fs-verity digests in userspace, so
its filesystem does not need fs-verity support.

Sign the resulting image through the existing InitOS release flow, ship it and
the referenced objects through the chosen transport, import objects with
fs-verity, then have InitOS verify and mount it with verity enforcement.

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
