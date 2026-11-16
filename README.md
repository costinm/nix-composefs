# nix-composefs

The core idea: build and sign a Nix or NixOS app and all deps on a trusted machine.
Distribute efficiently to multiple worker machines - where it just runs as a
real read-only composefs image backed by a CAS.

It takes Nix closures and builds composefs V1 EROFS metadata images backed by a
composefs digest store. It is only for builder-to-worker deployment, not a
replacement for normal Nix store copy or daemon semantics which continue to be
used on the build machines.

`nix-composefs` uses `composefs-rs` for the tree scanner, V1 EROFS writer,
reader, and `FlatDigestStore` (`<cas>/objects/xx/<62-hex>`). The default
repository root is `/z/composefs`. `meta.json` is **strictly optional**: without
`meta.json`, both `build` and `gc` use the exact same fixed defaults
(`fsverity-sha256-12` with 4 KiB blocks, EROFS V1 with 64-byte inline threshold,
and userspace fs-verity digest fallback on builders).

`costinm/initos` or another project owns image signing, verification, import,
and runtime mounting. Syncing the CAS is also out of scope — `rsync`, OCI, or
other transports can replicate `objects/` and `images/`.

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

Workers mount the verified image (or check out verified individual files by
hardlinking from `objects/xx/<62-hex>`); they do not materialize a writable
physical `/nix/store`. Because objects on workers carry kernel `fs-verity` and
`0444` permissions, hardlinked checkouts are immutable even to root.

## Build

```sh
nix-store -qR /nix/store/xxx-package | nix-composefs --image system.composefs
```

The completion defaults to standard input; `/nix/store` and `/z/composefs` are
the default store and repository paths. Use `--paths`, `--store`, or `--cas`
only when a build needs different locations. The build populates
`<cas>/objects/xx/<62-hex>` and writes a V1 metadata-only EROFS image:
`--image` is the repository ref name under `images/refs/` (not an external file
path) — the EROFS image itself is stored once in `objects/`, linked from
`images/<digest>`, and anchored at `images/refs/system.composefs`. No
`meta.json` is required or created (if `meta.json` is already present, its
algorithm must match `fsverity-sha256-12`).

The builder enables kernel fs-verity when supported and falls back to computing
composefs-compatible fs-verity digests in userspace (`FlatDigestStore` insecure
mode), so the builder filesystem does not need fs-verity support.

To import an arbitrary directory tree (not tied to `/nix/store`, e.g., firmware
trees, `/etc` overlays, or container rootfs bundles) into `<cas>/objects` and
create a composefs V1 EROFS image mountable back onto that directory:

```sh
# Imports /path/to/dir -> /z/composefs/images/refs/dir.composefs (or --image <NAME>):
nix-composefs import --cas /z/composefs /path/to/dir

# Mount back over /path/to/dir (requires root / CAP_SYS_ADMIN; remove -o verity if FS lacks fs-verity):
mount.composefs -o basedir=/z/composefs/objects /z/composefs/images/refs/dir.composefs /path/to/dir
# Or using kernel EROFS loop + overlayfs (the EROFS root includes 00..ff whiteouts hiding CAS shards):
mount -t erofs -o loop,ro /z/composefs/images/refs/dir.composefs /mnt/.meta
mount -t overlay composefs -o metacopy=on,redirect_dir=on,lowerdir=/mnt/.meta::/z/composefs/objects /path/to/dir
```

Sign the resulting image through the existing InitOS release flow, ship it and
the referenced objects through the chosen transport, import objects with
fs-verity, then have InitOS verify and mount it with verity enforcement.

## Checkout & Nix DB registration

`nix-composefs checkout` materializes a `.composefs` EROFS image (or a subpath
of one) into any destination directory by **hardlinking** external objects
(`> 64` bytes) from `<cas>/objects/xx/<62-hex>`, stripping write bits
(`0444`/`0555`), and verifying/enabling kernel `fs-verity` on each backing
object (`--require-verity` fails if the filesystem does not support `fs-verity`):

```sh
# Check out an arbitrary directory or subpath from the CAS via hardlinks:
nix-composefs checkout --cas /z/composefs --image app-bundle.composefs /srv/app
nix-composefs checkout --cas /z/composefs --image system.composefs --subpath etc/foo /tmp/foo

# Check out Nix store paths into /nix/store via hardlinks AND register them in
# Nix's SQLite DB (`nix-store --load-db`) without duplicating files:
nix-composefs checkout --cas /z/composefs --image system.composefs /nix/store --import
```

Unlike `nix-store --import` (which extracts raw bytes from a NAR stream and
creates duplicate unlinked copies on disk), `checkout --import` (alias
`--load-db`) computes each store path's canonical NAR SHA-256, `narSize`, and
topologically sorted `/nix/store/<nix32>-<name>` references directly from the
EROFS tree + `<cas>/objects` and pipes those records into `nix-store --load-db`
(`--print-db` emits the registration stream without calling `nix-store`).
Checked-out hardlinks (`st_nlink > 1`) preserve shared `fs-verity` inodes and
are retained automatically by `nix-composefs gc`.

Why use `.composefs` EROFS images as the checkout manifest rather than Nix
manifests (`closureInfo/registration`, `.narinfo`, or `.ls` JSON)?
`registration`/`.narinfo` only record whole-package NAR hashes (no per-file list),
and Nix `.ls`/NAR formats only store a monolithic stream offset (`narOffset`) and
a 1-bit `executable` flag — stripping `uid`/`gid`/`mtime`/full POSIX modes/`xattrs`
and carrying no per-file `fs-verity` digests for CAS hardlinking. The composefs
EROFS image already carries full POSIX metadata, inline data (`<= 64` bytes),
and exact `objects/xx/<62-hex>` digests for arbitrary directories.

### Receiver import

The receiver does not need `cfsctl` or a composefs daemon to accept a
repository. Copy `objects/` and `images/`, verify each object's fs-verity
digest against its `<xx>/<62-hex>` path name before enabling fs-verity, and
check image completeness before mounting:

```sh
rsync -a builder:/z/composefs/ /z/composefs/

find /z/composefs/objects -type f | while read -r o; do
  want=$(basename "$(dirname "$o")")$(basename "$o")
  fsverity measure "$o" >/dev/null 2>&1 || {
    actual=$(fsverity digest "$o" | awk '{print $1}' | sed 's/^sha256://')
    [ "$actual" = "$want" ] || { echo "BAD $o ($actual != $want)" >&2; exit 1; }
    fsverity enable "$o" && chmod 0444 "$o"
  }
done

composefs-info --basedir=/z/composefs/objects \
  missing-objects /z/composefs/images/refs/system.composefs
```

`fsverity digest` computes the Merkle digest in userspace before `fsverity enable`
turns on kernel verification, so corrupted or tampered objects are rejected
before entering the store. `missing-objects` must produce no paths before the
image is mounted with `verity=require`.

This full-tree `rsync` procedure is useful for bootstrapping or repair; normal
delivery can derive the missing digest set from the signed image and stream
only those objects, checking the digest and enabling fs-verity before atomically
publishing each one under `objects/xx/<62-hex>`.

## Garbage collection & hardlink checkouts

`nix-composefs gc` collects unreferenced objects in `<cas>/objects/xx/<62-hex>`
while remaining compatible with both bare C-style stores (no `meta.json`) and
`composefs-rs` repositories (with `meta.json`):

- **Anchors (`images/refs/**`, `streams/refs/**`, active `flock`):** Every EROFS
  image referenced under `images/refs/**` (plus any stream under `streams/refs/**`
  or any object/image holding an active `flock`, such as a mounted image) keeps
  its metadata blob and all referenced backing objects alive. Unreferenced EROFS
  images in `images/` are **not** anchors (even if hardlinked elsewhere), and
  unanchored `images/<digest>` symlinks are pruned.
- **Hardlink checkouts (`st_nlink > 1`):** Individual files in
  `objects/xx/<62-hex>` with `st_nlink > 1` are preserved even if no EROFS ref
  currently points to them. This mirrors OSTree `bare` hardlink checkouts:
  tools can check out verified files from `objects/xx/<62-hex>` via hardlinks
  into external directories, and `nix-composefs gc` will keep those objects in
  `objects/` until the external hardlinks are removed.
- **Sidecar tolerance:** Regular signature/metadata sidecar files (`*.sig`,
  `*.db.sig`, `*.basedir`) inside `images/` and `images/refs/` (created by
  `sign.sh image`) are ignored and preserved rather than aborting GC.

```sh
# Preview deletions without modifying /z/composefs:
nix-composefs gc --cas /z/composefs --dry-run

# Run GC:
nix-composefs gc --cas /z/composefs
```

## Development

```sh
nix build .#nix-composefs
nix build .#deps

. ./env.sh
ncp-build
ncp-test
```

The bundle includes `nix-composefs` plus standard composefs, EROFS, and
fs-verity runtime tools.

## Deliberate boundaries

- No JSON filesystem manifest or Nix `.ls`/NAR parser: use the EROFS image as authority.
- No signing implementation: use InitOS's existing signature chain.
- No transport implementation: OCI, SSH, or `rsync` remain external delivery mechanisms.
- `meta.json` is strictly optional: defaults without `meta.json` are
  `fsverity-sha256-12` and EROFS V1, matching bare C `composefs` stores and
  `composefs-rs` defaults.
