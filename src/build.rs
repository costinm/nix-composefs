//! Build a composefs metadata image from a Nix store completion.
//!
//! Pipeline:
//!   1. For each store path in the completion, run the composefs-rs scanner
//!      (`read_filesystem_with_opts`) with a composefs-rs [`Repository`] as the object store. The
//!      scanner walks the real /nix/store objects and references every large
//!      regular file by its fs-verity digest — no staging copy of the tree.
//!   2. Small files may be inlined in the EROFS image by the scanner.
//!   3. The merged tree is validated and written as a V1 (C-compatible)
//!      EROFS image, which carries only metadata.

use std::collections::BTreeMap;
use std::ffi::{CStr, OsStr, OsString};
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use composefs::erofs::format::FormatVersion;
use composefs::erofs::writer::{mkfs_erofs_versioned, ValidatedFileSystem};
use composefs::fs::{read_filesystem_with_opts, HardlinkBehavior, ObjectStore, ReadFilesystemOpts};
use composefs::fsverity::Sha256HashValue;
use composefs::generic_tree::{Directory, Inode, Leaf, LeafContent, LeafId, Stat};
use composefs::repository::{Repository, RepositoryConfig};
use composefs::tree::{FileSystem, RegularFile};
use rustix::fs::{fstat, getxattr, listxattr, open, openat, FileType, Mode, OFlags};

use crate::store::StorePath;

/// Build options.
#[derive(Debug, Clone)]
pub struct BuildOptions {
    /// Root of the Nix store (e.g. /nix/store).
    pub store: PathBuf,
    /// composefs-rs repository root (created if missing).
    pub cas: PathBuf,
    /// Name of the image reference created in the repository.
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

/// Build an EROFS composefs image and populate its composefs-rs repository.
pub fn build(completion: &[StorePath], opts: &BuildOptions) -> Result<BuildReport> {
    // Builder repositories calculate compatible fs-verity digests in
    // userspace. Deployment tooling can import the result into a repository
    // with its required-verification policy on the worker.
    let (cas, _) = Repository::<Sha256HashValue>::init_path(
        rustix::fs::CWD,
        &opts.cas,
        RepositoryConfig::default().set_insecure(),
    )?;
    let cas = Arc::new(cas);

    let store_fd = open(
        &opts.store,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("opening store root {:?}", opts.store))?;

    let mut rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(opts.threads.max(1))
        .enable_all()
        .build()
        .context("building tokio runtime")?;

    let (tree, n_symlink_entries) =
        scan_completion(completion, &opts.store, &store_fd, &cas, &mut rt)?;

    let validated = ValidatedFileSystem::new(tree).context("validating merged tree")?;
    let image = mkfs_erofs_versioned(&validated, FormatVersion::V1);
    cas.write_image(Some(&opts.image), &image)
        .context("recording image in composefs repository")?;

    let image_size = image.len() as u64;

    Ok(BuildReport {
        entries: completion.len(),
        symlinks: n_symlink_entries,
        image_size,
    })
}

/// Scan every completion entry and merge the trees under a single root.
fn scan_completion(
    completion: &[StorePath],
    store: &Path,
    store_fd: &OwnedFd,
    cas: &Arc<Repository<Sha256HashValue>>,
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
    cas: &Arc<Repository<Sha256HashValue>>,
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
        use std::io::Read;

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
