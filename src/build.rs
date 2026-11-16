//! Build a composefs metadata image from a Nix store completion.
//!
//! Pipeline:
//!   1. For each store path in the completion, run the composefs-rs scanner
//!      (`read_filesystem_with_opts`) with a composefs-rs [`FlatDigestStore`] as
//!      the object store (`<cas>/objects`). The scanner walks `/nix/store`
//!      entries and stores regular files larger than 64 bytes by fs-verity
//!      SHA-256 digest (enabling kernel fs-verity when supported, or falling back
//!      to userspace digest calculation).
//!   2. Small files (<= 64 bytes) are inlined in the EROFS image.
//!   3. The merged tree is validated and written as a V1 (C-compatible)
//!      EROFS image into `objects/xx/<digest>`, linked at `images/<digest>`
//!      and `images/refs/<image>`. No `meta.json` is required or created.

use std::collections::BTreeMap;
use std::ffi::{CStr, OsStr, OsString};
use std::io::{Read, Write};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use anyhow::{bail, ensure, Context, Result};
use composefs::erofs::format::FormatVersion;
use composefs::erofs::writer::{mkfs_erofs_versioned, ValidatedFileSystem};
use composefs::fs::{
    read_filesystem_with_opts, FlatDigestStore, HardlinkBehavior, ObjectStore, ReadFilesystemOpts,
};
use composefs::fsverity::{Algorithm, FsVerityHashValue, Sha256HashValue};
use composefs::generic_tree::{Directory, Inode, Leaf, LeafContent, LeafId, Stat};
use composefs::repository::read_repo_algorithm;
use composefs::tree::{FileSystem, RegularFile};
use rustix::fs::{
    fchmod, fstat, getxattr, listxattr, open, openat, readlinkat, renameat, symlinkat, unlinkat,
    AtFlags, FileType, Mode, OFlags,
};
use rustix::io::Errno;

use crate::store::StorePath;

/// Build options.
#[derive(Debug, Clone)]
pub struct BuildOptions {
    /// Root of the Nix store (e.g. /nix/store).
    pub store: PathBuf,
    /// Composefs repository root (created if missing; `meta.json` is optional).
    pub cas: PathBuf,
    /// Name of the image reference created in `<cas>/images/refs`.
    pub image: String,
    /// Number of scanner worker threads (0 = one per CPU).
    pub threads: usize,
}

/// Build result summary.
#[derive(Debug, Clone)]
pub struct BuildReport {
    pub entries: usize,
    pub symlinks: usize,
    pub image_size: u64,
}

/// Build a V1 EROFS composefs image and populate its `<cas>/objects` digest store
/// from a Nix store closure.
pub fn build(completion: &[StorePath], opts: &BuildOptions) -> Result<BuildReport> {
    let (cas_fd, cas, mut rt) = prepare_cas_and_runtime(&opts.cas, &opts.image, opts.threads)?;

    let store_fd = open(
        &opts.store,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("opening store root {:?}", opts.store))?;

    let (tree, n_symlink_entries) =
        scan_completion(completion, &opts.store, &store_fd, &cas, &mut rt)?;

    publish_tree(
        tree,
        completion.len(),
        n_symlink_entries,
        &opts.cas,
        &cas_fd,
        &cas,
        &opts.image,
    )
}

/// Build a V1 EROFS composefs image and populate its `<cas>/objects` digest store
/// from an arbitrary source directory (not tied to `/nix/store`).
pub fn build_source_dir(source: &Path, opts: &BuildOptions) -> Result<BuildReport> {
    let (cas_fd, cas, rt) = prepare_cas_and_runtime(&opts.cas, &opts.image, opts.threads)?;

    let source_fd = open(
        source,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("opening source directory {:?}", source))?;

    let tree: FileSystem<Sha256HashValue> = rt
        .block_on(read_filesystem_with_opts(
            source_fd,
            PathBuf::from("."),
            ReadFilesystemOpts {
                store: Some(Arc::clone(&cas) as Arc<dyn ObjectStore<Sha256HashValue>>),
                semaphore: None,
                hardlinks: HardlinkBehavior::Tracked,
            },
        ))
        .with_context(|| format!("scanning source directory {:?}", source))?;

    let (entries, symlinks) = count_tree_stats(&tree.root, &tree.leaves);
    publish_tree(tree, entries, symlinks, &opts.cas, &cas_fd, &cas, &opts.image)
}

fn prepare_cas_and_runtime(
    cas_path: &Path,
    image_name: &str,
    threads: usize,
) -> Result<(OwnedFd, Arc<FlatDigestStore>, tokio::runtime::Runtime)> {
    validate_ref_name(image_name)?;

    let objects_dir = cas_path.join("objects");
    let images_dir = cas_path.join("images");
    let refs_dir = images_dir.join("refs");
    std::fs::create_dir_all(&objects_dir)
        .with_context(|| format!("creating objects directory {:?}", objects_dir))?;
    std::fs::create_dir_all(&refs_dir)
        .with_context(|| format!("creating refs directory {:?}", refs_dir))?;

    let cas_fd = open(
        cas_path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("opening repository root {:?}", cas_path))?;

    if let Some(alg) = read_repo_algorithm(&cas_fd)? {
        if alg != Algorithm::SHA256 {
            bail!(
                "repository algorithm {alg} does not match expected {}",
                Algorithm::SHA256
            );
        }
    }

    // Builders compute fs-verity digests in userspace when kernel fs-verity is
    // unavailable (insecure = true). Receivers validate digests and enable
    // kernel fs-verity on import/checkout.
    let cas = Arc::new(
        FlatDigestStore::open(&objects_dir, threads.max(1), true)
            .with_context(|| format!("opening digest store {:?}", objects_dir))?,
    );

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(threads.max(1))
        .enable_all()
        .build()
        .context("building tokio runtime")?;

    Ok((cas_fd, cas, rt))
}

fn publish_tree(
    tree: FileSystem<Sha256HashValue>,
    entries: usize,
    symlinks: usize,
    cas_path: &Path,
    cas_fd: &OwnedFd,
    cas: &FlatDigestStore,
    image_name: &str,
) -> Result<BuildReport> {
    let external_modes: Vec<(Sha256HashValue, u32)> = tree
        .leaves
        .iter()
        .filter_map(|leaf| match &leaf.content {
            LeafContent::Regular(
                RegularFile::External(id, _) | RegularFile::ExternalNoVerity(id, _),
            ) => Some((id.clone(), (leaf.stat.st_mode & 0o7777) & !0o222)),
            _ => None,
        })
        .collect();

    let validated = ValidatedFileSystem::new(tree).context("validating merged tree")?;
    let image = mkfs_erofs_versioned(&validated, FormatVersion::V1);
    let image_id = write_image_to_cas(cas_path, cas_fd, cas, image_name, &image)
        .context("recording image in composefs repository")?;

    finalize_object_permissions(cas_fd, &external_modes, &image_id)?;

    Ok(BuildReport {
        entries,
        symlinks,
        image_size: image.len() as u64,
    })
}

fn finalize_object_permissions(
    cas_fd: &OwnedFd,
    external_modes: &[(Sha256HashValue, u32)],
    image_id: &Sha256HashValue,
) -> Result<()> {
    let objects_fd = openat(
        cas_fd,
        "objects",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .context("opening objects/ to finalize object permissions")?;

    for (id, target_mode) in external_modes {
        set_object_readonly_mode(&objects_fd, id, *target_mode)?;
    }
    set_object_readonly_mode(&objects_fd, image_id, 0o444)?;
    Ok(())
}

fn set_object_readonly_mode(
    objects_fd: &OwnedFd,
    id: &Sha256HashValue,
    target_mode: u32,
) -> Result<()> {
    let rel = id.to_object_pathname();
    let fd = openat(
        objects_fd,
        &rel,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("opening CAS object {} for chmod", rel))?;
    let st = fstat(&fd).with_context(|| format!("stat CAS object {}", rel))?;
    if (st.st_mode & 0o7777) != target_mode {
        if let Err(e) = fchmod(&fd, Mode::from_raw_mode(target_mode)) {
            if !matches!(e, Errno::PERM | Errno::ACCESS | Errno::ROFS) {
                return Err(e).with_context(|| format!("chmod CAS object {}", rel));
            }
        }
    }
    Ok(())
}

fn count_tree_stats(
    dir: &Directory<RegularFile<Sha256HashValue>>,
    leaves: &[Leaf<RegularFile<Sha256HashValue>>],
) -> (usize, usize) {
    let mut entries = 0usize;
    let mut symlinks = 0usize;
    for (_, inode) in dir.entries() {
        entries += 1;
        match inode {
            Inode::Directory(sub) => {
                let (sub_entries, sub_symlinks) = count_tree_stats(sub, leaves);
                entries += sub_entries;
                symlinks += sub_symlinks;
            }
            Inode::Leaf(id, _) => {
                if matches!(leaves[id.0].content, LeafContent::Symlink(_)) {
                    symlinks += 1;
                }
            }
        }
    }
    (entries, symlinks)
}

fn validate_ref_name(name: &str) -> Result<Vec<String>> {
    ensure!(!name.is_empty(), "image ref name cannot be empty");
    let mut parts = Vec::new();
    for component in Path::new(name).components() {
        match component {
            Component::Normal(p) => {
                let s = p
                    .to_str()
                    .with_context(|| format!("image ref name is not valid UTF-8: {name:?}"))?;
                parts.push(s.to_owned());
            }
            _ => bail!("invalid image ref name: {name:?}"),
        }
    }
    ensure!(!parts.is_empty(), "invalid image ref name: {name:?}");
    Ok(parts)
}

fn write_image_to_cas(
    cas_path: &Path,
    cas_fd: &OwnedFd,
    store: &FlatDigestStore,
    ref_name: &str,
    image: &[u8],
) -> Result<Sha256HashValue> {
    let objects_dir = cas_path.join("objects");
    let objects_fd = openat(
        cas_fd,
        "objects",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("opening {:?}/objects", cas_path))?;

    let ro_fd = match openat(
        &objects_fd,
        ".",
        OFlags::RDWR | OFlags::TMPFILE | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o644),
    ) {
        Ok(tmp) => {
            let mut file = std::fs::File::from(tmp);
            file.write_all(image)
                .context("writing EROFS image to tmpfile")?;
            let proc_path = format!("/proc/self/fd/{}", file.as_raw_fd());
            let ro = open(
                proc_path,
                OFlags::RDONLY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .context("re-opening EROFS image tmpfile read-only")?;
            drop(file);
            ro
        }
        Err(Errno::OPNOTSUPP | Errno::NOSYS) => {
            let tmp_name = format!(".image-tmp.{}", std::process::id());
            let _ = unlinkat(&objects_fd, &tmp_name, AtFlags::empty());
            let fd = openat(
                &objects_fd,
                &tmp_name,
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o644),
            )
            .with_context(|| format!("creating temporary image file {:?}", objects_dir.join(&tmp_name)))?;
            let mut file = std::fs::File::from(fd);
            let write_res = file.write_all(image);
            let ro = openat(
                &objects_fd,
                &tmp_name,
                OFlags::RDONLY | OFlags::CLOEXEC,
                Mode::empty(),
            );
            let _ = unlinkat(&objects_fd, &tmp_name, AtFlags::empty());
            drop(file);
            write_res.context("writing temporary EROFS image file")?;
            ro.context("re-opening temporary EROFS image read-only")?
        }
        Err(e) => return Err(e).context("creating tmpfile for EROFS image"),
    };

    let image_id: Sha256HashValue =
        ObjectStore::<Sha256HashValue>::ensure_object_from_fd(store, ro_fd, image.len() as u64)?;
    let hex = image_id.to_hex();

    let images_fd = openat(
        cas_fd,
        "images",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .context("opening images/ directory")?;
    let obj_target = format!("../objects/{}", image_id.to_object_pathname());
    replace_symlinkat(Path::new(&obj_target), &images_fd, Path::new(&hex))
        .with_context(|| format!("linking images/{hex}"))?;

    let parts = validate_ref_name(ref_name)?;
    let ref_parent = Path::new(ref_name).parent().filter(|p| !p.as_os_str().is_empty());
    if let Some(parent) = ref_parent {
        std::fs::create_dir_all(cas_path.join("images/refs").join(parent))
            .with_context(|| format!("creating images/refs/{}", parent.display()))?;
    }
    let refs_fd = openat(
        &images_fd,
        "refs",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .context("opening images/refs/ directory")?;
    let ref_target = format!("{}{hex}", "../".repeat(parts.len()));
    let (target_dirfd, link_name) = if let Some(parent) = ref_parent {
        let dirfd = openat(
            &refs_fd,
            parent,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .with_context(|| format!("opening images/refs/{}", parent.display()))?;
        let leaf = Path::new(ref_name)
            .file_name()
            .expect("validated ref has leaf name");
        (Some(dirfd), Path::new(leaf))
    } else {
        (None, Path::new(ref_name))
    };
    let parent_fd = target_dirfd.as_ref().unwrap_or(&refs_fd);
    replace_symlinkat(Path::new(&ref_target), parent_fd, link_name)
        .with_context(|| format!("linking images/refs/{ref_name}"))?;

    Ok(image_id)
}

pub(crate) fn replace_symlinkat(target: &Path, dirfd: impl AsFd, name: &Path) -> Result<()> {
    match symlinkat(target, &dirfd, name) {
        Ok(()) => return Ok(()),
        Err(Errno::EXIST) => {}
        Err(e) => return Err(e.into()),
    }

    if let Ok(current) = readlinkat(&dirfd, name, []) {
        if current.into_bytes() == target.as_os_str().as_bytes() {
            return Ok(());
        }
    }

    let tmp_name = format!(
        ".symlink-{}-{}",
        std::process::id(),
        name.file_name()
            .map(|n| n.to_string_lossy())
            .unwrap_or_default()
    );
    let _ = unlinkat(&dirfd, &tmp_name, AtFlags::empty());
    symlinkat(target, &dirfd, &tmp_name)?;
    if let Err(e) = renameat(&dirfd, &tmp_name, &dirfd, name) {
        let _ = unlinkat(&dirfd, &tmp_name, AtFlags::empty());
        return Err(e.into());
    }
    Ok(())
}

/// Scan every completion entry and merge the trees under a single root.
fn scan_completion(
    completion: &[StorePath],
    store: &Path,
    store_fd: &OwnedFd,
    cas: &Arc<FlatDigestStore>,
    rt: &mut tokio::runtime::Runtime,
) -> Result<(FileSystem<Sha256HashValue>, usize)> {
    let mut leaves: Vec<Leaf<RegularFile<Sha256HashValue>>> = Vec::new();
    let mut n_symlink_entries = 0usize;

    let root_stat = {
        let st = std::fs::metadata(store)?;
        Stat {
            st_mode: 0o755,
            st_uid: st.uid(),
            st_gid: st.gid(),
            st_mtim_sec: 0,
            st_mtim_nsec: 0,
            xattrs: Default::default(),
        }
    };
    let mut root = Directory::new(root_stat);

    for sp in completion {
        let entry = sp.entry();
        let entry_path = sp.path(store);
        let st = std::fs::symlink_metadata(&entry_path)
            .with_context(|| format!("store entry not found: {entry_path:?}"))?;

        if st.file_type().is_symlink() {
            // Store entry is a symlink (rare; CA derivations, ...).
            let target = std::fs::read_link(&entry_path)
                .with_context(|| format!("reading symlink {entry_path:?}"))?;
            let stat = Stat {
                st_mode: 0o777,
                st_uid: 0,
                st_gid: 0,
                st_mtim_sec: 0,
                st_mtim_nsec: 0,
                xattrs: Default::default(),
            };
            let leaf = Leaf {
                stat,
                content: LeafContent::Symlink(OsString::from(target).into()),
            };
            let id = leaves.len();
            leaves.push(leaf);
            root.insert(OsStr::new(entry.as_str()), Inode::leaf(LeafId(id)));
            n_symlink_entries += 1;
            continue;
        }

        if st.is_file() {
            let leaf = scan_regular_store_entry(store_fd, &entry, cas)?;
            let id = leaves.len();
            leaves.push(leaf);
            root.insert(OsStr::new(entry.as_str()), Inode::leaf(LeafId(id)));
            continue;
        }

        if !st.is_dir() {
            anyhow::bail!("unsupported store entry type: {entry_path:?}");
        }

        let fs: FileSystem<Sha256HashValue> = rt
            .block_on(read_filesystem_with_opts(
                store_fd.try_clone().context("cloning store fd")?,
                PathBuf::from(entry.clone()),
                ReadFilesystemOpts {
                    store: Some(Arc::clone(cas) as Arc<dyn ObjectStore<Sha256HashValue>>),
                    semaphore: None,
                    hardlinks: HardlinkBehavior::Tracked,
                },
            ))
            .with_context(|| format!("scanning store entry {entry}"))?;
        // Leaf ids inside a per-entry tree are local; offset them so they
        // index into the merged leaves table.
        let base = leaves.len();
        let mut entry_inode = Inode::Directory(Box::new(fs.root));
        remap_leaf_ids(&mut entry_inode, base);
        root.insert(OsStr::new(entry.as_str()), entry_inode);
        leaves.extend(fs.leaves);
    }

    Ok((FileSystem { root, leaves }, n_symlink_entries))
}

/// Scan a regular file that is itself a Nix store path.
///
/// `read_filesystem_with_opts` intentionally scans directory roots. Nix
/// closures also contain generated singleton files, so retain their
/// permissions and use the same inline/external split as composefs-rs.
fn scan_regular_store_entry(
    store_fd: &OwnedFd,
    entry: &str,
    cas: &Arc<FlatDigestStore>,
) -> Result<Leaf<RegularFile<Sha256HashValue>>> {
    let fd = openat(
        store_fd,
        entry,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("opening regular store entry {entry}"))?;
    let st = fstat(&fd)?;
    if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
        anyhow::bail!("store entry type changed while scanning: {entry}");
    }
    let size: u64 = st
        .st_size
        .try_into()
        .context("regular store entry has a negative size")?;
    let stat = Stat {
        st_mode: st.st_mode & 0o7777,
        st_uid: st.st_uid,
        st_gid: st.st_gid,
        st_mtim_sec: st.st_mtime,
        st_mtim_nsec: st.st_mtime_nsec as u32,
        xattrs: read_xattrs(&fd)?,
    };
    let content = if size <= composefs::INLINE_CONTENT_MAX_V0 as u64 {
        let mut data = Vec::with_capacity(size as usize);
        std::fs::File::from(fd)
            .read_to_end(&mut data)
            .context("reading inline regular store entry")?;
        RegularFile::Inline(data.into_boxed_slice())
    } else {
        RegularFile::External(cas.ensure_object_from_fd(fd, size)?, size)
    };
    Ok(Leaf {
        stat,
        content: LeafContent::Regular(content),
    })
}

/// Read xattrs from a descriptor without following an independently supplied
/// path. This is the small leaf-root counterpart to composefs-rs' directory
/// scanner, which uses the same `/proc/self/fd` pattern.
fn read_xattrs(fd: &OwnedFd) -> Result<BTreeMap<Box<OsStr>, Box<[u8]>>> {
    let proc_fd = PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd()));
    let mut xattrs = BTreeMap::new();
    let mut names = [MaybeUninit::new(0); 65536];
    let (names, _) = listxattr(&proc_fd, &mut names)?;

    for name in names.split_inclusive(|c| *c == 0) {
        let name = CStr::from_bytes_with_nul(name)?;
        let mut value = [MaybeUninit::new(0); 65536];
        let (value, _) = getxattr(&proc_fd, name, &mut value)?;
        xattrs.insert(
            Box::from(OsStr::from_bytes(name.to_bytes())),
            Box::from(value),
        );
    }
    Ok(xattrs)
}

/// Offset every leaf id in a subtree by `offset` (used when merging
/// independently-scanned trees into one leaves table).
fn remap_leaf_ids(inode: &mut Inode<RegularFile<Sha256HashValue>>, offset: usize) {
    match inode {
        Inode::Leaf(id, _) => *id = LeafId(id.0 + offset),
        Inode::Directory(d) => {
            let names: Vec<OsString> = d.entries().map(|(n, _)| n.to_os_string()).collect();
            for name in names {
                if let Some(mut child) = d.pop(&name) {
                    remap_leaf_ids(&mut child, offset);
                    d.insert(&name, child);
                }
            }
        }
    }
}
