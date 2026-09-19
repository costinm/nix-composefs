//! Build a composefs metadata image from a Nix store completion.
//!
//! Pipeline:
//!   1. For each store path in the completion, run the composefs-rs scanner
//!      (`read_filesystem_with_opts`) with a [`Cas`] as the object store. The
//!      scanner walks the real /nix/store objects and references every large
//!      regular file by its fs-verity digest — no staging copy of the tree.
//!   2. Small files (<= 64 bytes) are inlined in the EROFS image by the
//!      scanner; they are additionally stored in the CAS so that workers can
//!      re-create every store file by hard link.
//!   3. The merged tree is validated and written as a V1 (C-compatible)
//!      EROFS image, which carries only metadata.
//!   4. A manifest with the full inventory and object list is emitted.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::os::unix::fs::MetadataExt;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use composefs::erofs::format::FormatVersion;
use composefs::erofs::writer::{ValidatedFileSystem, mkfs_erofs_versioned};
use composefs::fs::{HardlinkBehavior, ObjectStore, ReadFilesystemOpts, read_filesystem_with_opts};
use composefs::fsverity::{FsVerityHashValue, Sha256HashValue};
use composefs::generic_tree::{Directory, Inode, Leaf, LeafContent, LeafId, Stat};
use composefs::tree::{FileSystem, RegularFile};
use rustix::fs::{Mode, OFlags, open};

use crate::cas::Cas;
use crate::manifest::{FileEntry, FileKind, ImageInfo, Manifest, MANIFEST_VERSION, ObjectEntry};
use crate::store::StorePath;

/// Build options.
#[derive(Debug, Clone)]
pub struct BuildOptions {
    /// Root of the Nix store (e.g. /nix/store).
    pub store: PathBuf,
    /// CAS directory (created if missing).
    pub cas: PathBuf,
    /// Output composefs metadata image path.
    pub image: PathBuf,
    /// Output manifest path (optional).
    pub manifest: Option<PathBuf>,
    /// Closure name recorded in the manifest.
    pub name: String,
    /// Number of scanner worker threads (0 = one per CPU).
    pub threads: usize,
    /// Userspace-digest fallback (no kernel fs-verity required).
    pub insecure: bool,
}

/// Build result summary.
#[derive(Debug, Clone)]
pub struct BuildReport {
    pub entries: usize,
    pub dirs: usize,
    pub files: usize,
    pub symlinks: usize,
    pub objects: usize,
    pub image_size: u64,
    /// fs-verity digest (hex) of the metadata image.
    pub image_verity: String,
}

/// Build the image and (optionally) the manifest.
pub fn build(completion: &[StorePath], opts: &BuildOptions) -> Result<(BuildReport, Manifest)> {
    let cas: Arc<Cas> = Arc::new(Cas::open(&opts.cas, opts.threads.max(1), opts.insecure)?);

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
    std::fs::write(&opts.image, &*image)
        .with_context(|| format!("writing image {:?}", opts.image))?;

    let image_verity = composefs::fsverity::compute_verity::<Sha256HashValue>(&image).to_hex();

    // Inventory from the validated tree (exactly what was written).
    let fs: &FileSystem<Sha256HashValue> = &validated;
    let (files, objects, dirs, nfiles, symlinks) =
        walk_inventory(&fs.root, &fs.leaves, &cas)?;

    let image_size = std::fs::metadata(&opts.image)?.len();
    let image_file = opts
        .image
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "image.composefs".into());

    let manifest = Manifest {
        version: MANIFEST_VERSION,
        name: opts.name.clone(),
        entries: completion.iter().map(|s| s.entry()).collect(),
        image: ImageInfo {
            file: image_file,
            size: image_size,
            verity: image_verity.clone(),
        },
        objects: objects
            .into_iter()
            .map(|(digest, (size, count))| ObjectEntry { digest, size, count })
            .collect(),
        files,
        meta: BTreeMap::from([
            ("tool".to_string(), env!("CARGO_PKG_VERSION").to_string()),
            ("format".to_string(), "composefs-v1-erofs".to_string()),
            ("cas-layout".to_string(), "flat-xx-digest".to_string()),
            ("insecure".to_string(), opts.insecure.to_string()),
            (
                "symlink-entries".to_string(),
                n_symlink_entries.to_string(),
            ),
        ]),
    };

    if let Some(path) = &opts.manifest {
        manifest.save(path)?;
    }

    let report = BuildReport {
        entries: completion.len(),
        dirs,
        files: nfiles,
        symlinks,
        objects: manifest.objects.len(),
        image_size,
        image_verity,
    };
    Ok((report, manifest))
}

/// Scan every completion entry and merge the trees under a single root.
fn scan_completion(
    completion: &[StorePath],
    store: &Path,
    store_fd: &OwnedFd,
    cas: &Arc<Cas>,
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

        if !st.is_dir() {
            anyhow::bail!("store entry is not a directory: {entry_path:?}");
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

    Ok((
        FileSystem { root, leaves },
        n_symlink_entries,
    ))
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

/// Walk the tree, ensuring CAS objects for inline files, collecting the
/// file inventory and the deduplicated object map.
fn walk_inventory(
    dir: &Directory<RegularFile<Sha256HashValue>>,
    leaves: &[Leaf<RegularFile<Sha256HashValue>>],
    cas: &Cas,
) -> Result<(Vec<FileEntry>, BTreeMap<String, (u64, usize)>, usize, usize, usize)> {
    let mut files = Vec::new();
    let mut objects: BTreeMap<String, (u64, usize)> = BTreeMap::new();
    let mut counters = (0usize, 0usize, 0usize);
    rec_inventory(dir, leaves, cas, "", &mut files, &mut objects, &mut counters)?;
    Ok((files, objects, counters.0, counters.1, counters.2))
}

fn rec_inventory(
    dir: &Directory<RegularFile<Sha256HashValue>>,
    leaves: &[Leaf<RegularFile<Sha256HashValue>>],
    cas: &Cas,
    prefix: &str,
    files: &mut Vec<FileEntry>,
    objects: &mut BTreeMap<String, (u64, usize)>,
    counters: &mut (usize, usize, usize),
) -> Result<()> {
    for (name, inode) in dir.sorted_entries() {
        let name = name.to_string_lossy().into_owned();
        let rel = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        match inode {
            Inode::Directory(d) => {
                files.push(FileEntry {
                    path: rel.clone(),
                    kind: FileKind::Dir,
                    size: 0,
                    mode: d.stat.st_mode,
                    digest: None,
                    target: None,
                });
                counters.0 += 1;
                rec_inventory(d, leaves, cas, &rel, files, objects, counters)?;
            }
            Inode::Leaf(id, _) => {
                let leaf = &leaves[id.0];
                match &leaf.content {
                    LeafContent::Regular(rf) => {
                        let (digest, size) = match rf {
                            RegularFile::Inline(data) => {
                                let id = cas
                                    .ensure_object_from_bytes(data)
                                    .with_context(|| format!("CAS object for {rel}"))?;
                                (id.to_hex(), data.len() as u64)
                            }
                            RegularFile::External(id, size)
                            | RegularFile::ExternalNoVerity(id, size) => (id.to_hex(), *size),
                            RegularFile::Sparse(size) => {
                                files.push(FileEntry {
                                    path: rel.clone(),
                                    kind: FileKind::File,
                                    size: *size,
                                    mode: leaf.stat.st_mode,
                                    digest: None,
                                    target: None,
                                });
                                counters.1 += 1;
                                continue;
                            }
                        };
                        objects.entry(digest.clone()).or_insert((size, 0)).1 += 1;
                        files.push(FileEntry {
                            path: rel,
                            kind: FileKind::File,
                            size,
                            mode: leaf.stat.st_mode,
                            digest: Some(digest),
                            target: None,
                        });
                        counters.1 += 1;
                    }
                    LeafContent::Symlink(target) => {
                        files.push(FileEntry {
                            path: rel,
                            kind: FileKind::Symlink,
                            size: 0,
                            mode: leaf.stat.st_mode,
                            digest: None,
                            target: Some(target.to_string_lossy().into_owned()),
                        });
                        counters.2 += 1;
                    }
                    other => {
                        anyhow::bail!("unsupported leaf type at {rel}: {other:?}");
                    }
                }
            }
        }
    }
    Ok(())
}
