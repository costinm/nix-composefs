//! Check out composefs EROFS images into directories using hardlinks and optional Nix DB registration.
//!
//! Because V1 composefs EROFS images preserve full POSIX metadata (mode, uid/gid,
//! mtime, xattrs), inline content (<= 64 bytes), and exact fs-verity digests
//! (`objects/xx/<62-hex>`) for external files, the `.composefs` EROFS image
//! itself serves as the checkout manifest for both arbitrary directories and Nix
//! store closures.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::ffi::OsStr;
use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{bail, ensure, Context, Result};
use composefs::digest::{Digest, Sha256};
use composefs::erofs::reader::erofs_to_filesystem;
use composefs::fsverity::{
    enable_verity_with_retry, measure_verity, measure_verity_with_fallback, Algorithm,
    EnableVerityError, FsVerityHashValue, MeasureVerityError, Sha256HashValue,
};
use composefs::generic_tree::{Directory, Inode, Leaf, LeafContent};
use composefs::repository::read_repo_algorithm;
use composefs::tree::{FileSystem, RegularFile};
use rustix::fs::{
    fchmod, fstat, linkat, mkdirat, open, openat, renameat, unlinkat, AtFlags, Mode, OFlags,
};
use rustix::io::Errno;

use crate::build::replace_symlinkat;
use crate::store::StorePath;

const IO_BUF_SIZE: usize = 64 * 1024;
const NIX32_HASH_LEN: usize = 32;

/// Options for [`checkout`].
#[derive(Debug, Clone)]
pub struct CheckoutOptions {
    /// Composefs repository root (`<cas>`).
    pub cas: PathBuf,
    /// Image ref name under `<cas>/images/refs/`, digest in `<cas>/images/`, or path to an image file.
    pub image: String,
    /// Destination directory (or target path when checking out a single-file `--subpath`).
    pub dest: PathBuf,
    /// Optional subpath within the EROFS image to check out (default: full root tree).
    pub subpath: Option<PathBuf>,
    /// Require kernel fs-verity to be enabled on every external object.
    pub require_verity: bool,
    /// Register checked-out top-level Nix store paths in the Nix DB via `nix-store --load-db`.
    pub register_nix_db: bool,
    /// Include the `nix-store --load-db` registration text in `CheckoutReport::registration` (and let CLI print it).
    pub print_nix_db: bool,
    /// Nix store prefix used for DB registration and reference scanning (default: `/nix/store`).
    pub nix_store_prefix: String,
}

/// Summary statistics returned by [`checkout`].
#[derive(Debug, Clone, Default)]
pub struct CheckoutReport {
    pub directories: usize,
    pub hardlinked_files: usize,
    pub inlined_files: usize,
    pub symlinks: usize,
    pub verity_enabled: usize,
    pub nix_registered_paths: usize,
    pub registration: String,
}

/// Materialize a composefs EROFS image (or a subpath of it) into `opts.dest`
/// by hardlinking external files from `<cas>/objects/xx/<62-hex>` and verifying
/// / enabling `fs-verity` on each backing object.
pub fn checkout(opts: &CheckoutOptions) -> Result<CheckoutReport> {
    let cas_fd = open(
        &opts.cas,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("opening repository root {:?}", opts.cas))?;

    if let Some(alg) = read_repo_algorithm(&cas_fd)? {
        if alg != Algorithm::SHA256 {
            bail!(
                "repository algorithm {alg} does not match expected {}",
                Algorithm::SHA256
            );
        }
    }

    let objects_fd = openat(
        &cas_fd,
        "objects",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("opening objects directory {:?}", opts.cas.join("objects")))?;

    let image_path = resolve_image_path(&opts.cas, &opts.image)?;
    let image_bytes = std::fs::read(&image_path)
        .with_context(|| format!("reading EROFS image {:?}", image_path))?;
    let fs: FileSystem<Sha256HashValue> = erofs_to_filesystem::<Sha256HashValue>(&image_bytes)
        .with_context(|| format!("parsing EROFS image {:?}", image_path))?;

    let mut report = CheckoutReport::default();

    let subpath_parts = match &opts.subpath {
        Some(sub) => parse_subpath(sub)?,
        None => Vec::new(),
    };

    if subpath_parts.is_empty() {
        materialize_directory_root(&fs.root, &fs.leaves, &objects_fd, &opts.dest, opts, &mut report)?;
    } else {
        let target = resolve_inode(&fs.root, &subpath_parts)?;
        match target {
            Inode::Directory(dir) => {
                materialize_directory_root(dir, &fs.leaves, &objects_fd, &opts.dest, opts, &mut report)?;
            }
            Inode::Leaf(leaf_id, _) => {
                let leaf = fs
                    .leaves
                    .get(leaf_id.0)
                    .with_context(|| format!("missing leaf {}", leaf_id.0))?;
                let (parent_path, file_name) = if opts.dest.is_dir() {
                    let name = subpath_parts
                        .last()
                        .expect("non-empty subpath has last component")
                        .as_os_str()
                        .to_owned();
                    (opts.dest.as_path(), name)
                } else {
                    let parent = opts
                        .dest
                        .parent()
                        .filter(|p| !p.as_os_str().is_empty())
                        .unwrap_or_else(|| Path::new("."));
                    let name = opts
                        .dest
                        .file_name()
                        .with_context(|| format!("destination path has no file name: {:?}", opts.dest))?
                        .to_owned();
                    (parent, name)
                };
                std::fs::create_dir_all(parent_path)
                    .with_context(|| format!("creating destination parent {:?}", parent_path))?;
                let parent_fd = open(
                    parent_path,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .with_context(|| format!("opening destination directory {:?}", parent_path))?;
                materialize_leaf(leaf, &objects_fd, &parent_fd, &file_name, opts, &mut report)?;
            }
        }
    }

    if opts.register_nix_db || opts.print_nix_db {
        let registration = build_nix_registration(
            &fs,
            &objects_fd,
            &subpath_parts,
            &opts.nix_store_prefix,
        )?;
        report.nix_registered_paths = registration.count;
        report.registration = registration.text;

        if opts.register_nix_db && report.nix_registered_paths > 0 {
            load_nix_db(&report.registration)?;
        }
    }

    Ok(report)
}

fn resolve_image_path(cas: &Path, image: &str) -> Result<PathBuf> {
    ensure!(!image.is_empty(), "image specifier cannot be empty");

    let has_parent_dir = Path::new(image)
        .components()
        .any(|c| matches!(c, Component::ParentDir));

    if !has_parent_dir && !image.starts_with('/') {
        let ref_candidate = cas.join("images/refs").join(image);
        if ref_candidate.exists() {
            return Ok(ref_candidate);
        }

        let digest_candidate = cas.join("images").join(image);
        if digest_candidate.exists() {
            return Ok(digest_candidate);
        }
    }

    let direct = PathBuf::from(image);
    if direct.exists() {
        return Ok(direct);
    }

    bail!(
        "image {:?} not found in {:?}/images/refs, {:?}/images, or filesystem path",
        image,
        cas,
        cas
    );
}

fn parse_subpath(sub: &Path) -> Result<Vec<std::ffi::OsString>> {
    let mut parts = Vec::new();
    for c in sub.components() {
        match c {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(p) => parts.push(p.to_os_string()),
            Component::ParentDir | Component::Prefix(_) => {
                bail!("invalid subpath component in {:?}", sub);
            }
        }
    }
    Ok(parts)
}

fn resolve_inode<'a>(
    root: &'a Directory<RegularFile<Sha256HashValue>>,
    parts: &[std::ffi::OsString],
) -> Result<&'a Inode<RegularFile<Sha256HashValue>>> {
    let mut cur_dir = root;
    for (idx, part) in parts.iter().enumerate() {
        let child = cur_dir
            .entries()
            .find(|(name, _)| *name == part.as_os_str())
            .map(|(_, inode)| inode)
            .with_context(|| format!("subpath entry not found: {:?}", part))?;
        if idx + 1 == parts.len() {
            return Ok(child);
        }
        match child {
            Inode::Directory(d) => cur_dir = d,
            Inode::Leaf(_, _) => {
                bail!("subpath component {:?} is not a directory", part);
            }
        }
    }
    unreachable!("parse_subpath yielded empty slice before resolve_inode")
}

fn materialize_directory_root(
    dir: &Directory<RegularFile<Sha256HashValue>>,
    leaves: &[Leaf<RegularFile<Sha256HashValue>>],
    objects_fd: &OwnedFd,
    dest: &Path,
    opts: &CheckoutOptions,
    report: &mut CheckoutReport,
) -> Result<()> {
    std::fs::create_dir_all(dest)
        .with_context(|| format!("creating destination directory {:?}", dest))?;
    let dest_fd = open(
        dest,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("opening destination directory {:?}", dest))?;
    report.directories += 1;
    materialize_dir_contents(dir, leaves, objects_fd, &dest_fd, opts, report)?;
    apply_dir_mode(&dest_fd, dir.stat.st_mode)?;
    Ok(())
}

fn materialize_dir_contents(
    dir: &Directory<RegularFile<Sha256HashValue>>,
    leaves: &[Leaf<RegularFile<Sha256HashValue>>],
    objects_fd: &OwnedFd,
    dir_fd: &OwnedFd,
    opts: &CheckoutOptions,
    report: &mut CheckoutReport,
) -> Result<()> {
    for (name, inode) in dir.sorted_entries() {
        match inode {
            Inode::Directory(sub) => {
                let initial_mode = Mode::from_raw_mode((sub.stat.st_mode & 0o7777) | 0o700);
                match mkdirat(dir_fd, name, initial_mode) {
                    Ok(()) => {}
                    Err(Errno::EXIST) => {}
                    Err(e) => {
                        return Err(e)
                            .with_context(|| format!("creating directory {:?}", name));
                    }
                }
                let sub_fd = openat(
                    dir_fd,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .with_context(|| format!("opening subdirectory {:?}", name))?;
                // Ensure owner write/exec bits while populating existing directories
                // (ignore EPERM/EROFS if owned by someone else and already traversable).
                let _ = fchmod(&sub_fd, initial_mode);
                report.directories += 1;
                materialize_dir_contents(sub, leaves, objects_fd, &sub_fd, opts, report)?;
                apply_dir_mode(&sub_fd, sub.stat.st_mode)?;
            }
            Inode::Leaf(leaf_id, _) => {
                let leaf = leaves
                    .get(leaf_id.0)
                    .with_context(|| format!("missing leaf {}", leaf_id.0))?;
                materialize_leaf(leaf, objects_fd, dir_fd, name, opts, report)?;
            }
        }
    }
    Ok(())
}

fn apply_dir_mode(dir_fd: &OwnedFd, st_mode: u32) -> Result<()> {
    // Preserve group/other read/exec bits while keeping owner u+rwx so
    // non-root checkouts/overwrites/cleanups never fail with EACCES.
    let target_mode = ((st_mode & 0o7777) | 0o700) & 0o7777;
    if let Err(e) = fchmod(dir_fd, Mode::from_raw_mode(target_mode)) {
        if !matches!(e, Errno::PERM | Errno::ACCESS | Errno::ROFS) {
            return Err(e).context("setting checked-out directory mode");
        }
    }
    Ok(())
}

fn materialize_leaf(
    leaf: &Leaf<RegularFile<Sha256HashValue>>,
    objects_fd: &OwnedFd,
    dir_fd: &OwnedFd,
    name: &OsStr,
    opts: &CheckoutOptions,
    report: &mut CheckoutReport,
) -> Result<()> {
    match &leaf.content {
        LeafContent::Symlink(target) => {
            replace_symlinkat(Path::new(&**target), dir_fd, Path::new(name))
                .with_context(|| format!("creating symlink {:?}", name))?;
            report.symlinks += 1;
        }
        LeafContent::Regular(RegularFile::Inline(data)) => {
            materialize_inline_file(dir_fd, name, leaf.stat.st_mode, data)?;
            report.inlined_files += 1;
        }
        LeafContent::Regular(
            RegularFile::External(id, expected_size)
            | RegularFile::ExternalNoVerity(id, expected_size),
        ) => {
            materialize_external_file(
                objects_fd,
                dir_fd,
                name,
                leaf.stat.st_mode,
                id,
                *expected_size,
                opts.require_verity,
                report,
            )?;
            report.hardlinked_files += 1;
        }
        LeafContent::Regular(RegularFile::Sparse(_)) => {
            bail!("unsupported sparse regular file entry in image: {:?}", name);
        }
        LeafContent::Fifo => bail!("unsupported FIFO entry in image: {:?}", name),
        LeafContent::Socket => bail!("unsupported socket entry in image: {:?}", name),
        LeafContent::CharacterDevice(_) => {
            bail!("unsupported character device entry in image: {:?}", name)
        }
        LeafContent::BlockDevice(_) => {
            bail!("unsupported block device entry in image: {:?}", name)
        }
    }
    Ok(())
}

fn materialize_inline_file(
    dir_fd: &OwnedFd,
    name: &OsStr,
    st_mode: u32,
    data: &[u8],
) -> Result<()> {
    let target_mode = (st_mode & 0o7777) & !0o222;
    let tmp_name = format!(
        ".nix-composefs-inline.{}.{}",
        std::process::id(),
        name.to_string_lossy()
    );
    let _ = unlinkat(dir_fd, &tmp_name, AtFlags::empty());

    let fd = openat(
        dir_fd,
        &tmp_name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o644),
    )
    .with_context(|| format!("creating temp file for inline entry {:?}", name))?;

    let write_res = {
        let mut file = File::from(fd);
        let res = file.write_all(data);
        if res.is_ok() {
            fchmod(&file, Mode::from_raw_mode(target_mode))
                .context("setting mode on inline file")?;
        }
        res
    };
    if let Err(e) = write_res {
        let _ = unlinkat(dir_fd, &tmp_name, AtFlags::empty());
        return Err(e).with_context(|| format!("writing inline file {:?}", name));
    }

    if let Err(e) = renameat(dir_fd, &tmp_name, dir_fd, name) {
        let _ = unlinkat(dir_fd, &tmp_name, AtFlags::empty());
        return Err(e).with_context(|| format!("renaming inline file {:?}", name));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn materialize_external_file(
    objects_fd: &OwnedFd,
    dir_fd: &OwnedFd,
    name: &OsStr,
    st_mode: u32,
    id: &Sha256HashValue,
    expected_size: u64,
    require_verity: bool,
    report: &mut CheckoutReport,
) -> Result<()> {
    let obj_rel = id.to_object_pathname();
    let obj_fd = openat(
        objects_fd,
        &obj_rel,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("opening CAS object {}", obj_rel))?;

    let st = fstat(&obj_fd).with_context(|| format!("stat CAS object {}", obj_rel))?;
    let actual_size = u64::try_from(st.st_size).context("negative object file size")?;
    ensure!(
        actual_size == expected_size,
        "CAS object {} size mismatch: expected {}, found {}",
        obj_rel,
        expected_size,
        actual_size
    );

    // Strip write bits (e.g., 0644 -> 0444, 0755 -> 0555) before enabling verity.
    let target_mode = (st_mode & 0o7777) & !0o222;
    if (st.st_mode & 0o7777) != target_mode {
        if let Err(e) = fchmod(&obj_fd, Mode::from_raw_mode(target_mode)) {
            // Allow read-only CAS or immutable existing objects if not writable and exec bit matches.
            let compatible = matches!(e, Errno::PERM | Errno::ACCESS | Errno::ROFS)
                && (st.st_mode & 0o222) == 0
                && (st.st_mode & 0o111) == (target_mode & 0o111);
            if !compatible {
                return Err(e).with_context(|| format!("chmod CAS object {}", obj_rel));
            }
        }
    }

    ensure_object_verity(&obj_fd, &obj_rel, id, require_verity, report)?;

    match unlinkat(dir_fd, name, AtFlags::empty()) {
        Ok(()) | Err(Errno::NOENT) => {}
        Err(e) => {
            return Err(e).with_context(|| format!("unlinking existing target {:?}", name));
        }
    }

    linkat(objects_fd, &obj_rel, dir_fd, name, AtFlags::empty()).with_context(|| {
        format!(
            "hardlinking CAS object {} -> {:?}",
            obj_rel, name
        )
    })?;

    Ok(())
}

fn ensure_object_verity(
    obj_fd: &OwnedFd,
    obj_rel: &str,
    expected_id: &Sha256HashValue,
    require_verity: bool,
    report: &mut CheckoutReport,
) -> Result<()> {
    match measure_verity::<Sha256HashValue>(obj_fd) {
        Ok(measured) => {
            ensure!(
                measured == *expected_id,
                "kernel fs-verity mismatch for {}: expected {}, got {}",
                obj_rel,
                expected_id.to_hex(),
                measured.to_hex()
            );
            report.verity_enabled += 1;
            Ok(())
        }
        Err(MeasureVerityError::VerityMissing) => {
            match enable_verity_with_retry::<Sha256HashValue>(obj_fd) {
                Ok(()) | Err(EnableVerityError::AlreadyEnabled) => {
                    let measured = measure_verity::<Sha256HashValue>(obj_fd)
                        .with_context(|| format!("measuring verity after enable on {}", obj_rel))?;
                    ensure!(
                        measured == *expected_id,
                        "kernel fs-verity mismatch after enable on {}: expected {}, got {}",
                        obj_rel,
                        expected_id.to_hex(),
                        measured.to_hex()
                    );
                    report.verity_enabled += 1;
                    Ok(())
                }
                Err(EnableVerityError::FilesystemNotSupported) => {
                    if require_verity {
                        bail!(
                            "filesystem does not support fs-verity for {} (--require-verity set)",
                            obj_rel
                        );
                    }
                    verify_userspace_verity(obj_fd, obj_rel, expected_id)
                }
                Err(e) => {
                    if require_verity {
                        return Err(anyhow::anyhow!(e))
                            .with_context(|| format!("enabling fs-verity on {}", obj_rel));
                    }
                    verify_userspace_verity(obj_fd, obj_rel, expected_id)
                }
            }
        }
        Err(MeasureVerityError::FilesystemNotSupported) => {
            if require_verity {
                bail!(
                    "filesystem does not support fs-verity for {} (--require-verity set)",
                    obj_rel
                );
            }
            verify_userspace_verity(obj_fd, obj_rel, expected_id)
        }
        Err(e) => Err(anyhow::anyhow!(e))
            .with_context(|| format!("measuring fs-verity on {}", obj_rel)),
    }
}

fn verify_userspace_verity(
    obj_fd: &OwnedFd,
    obj_rel: &str,
    expected_id: &Sha256HashValue,
) -> Result<()> {
    let cloned = obj_fd
        .try_clone()
        .context("cloning CAS object fd for verity verification")?;
    let mut file = File::from(cloned);
    let actual = measure_verity_with_fallback::<Sha256HashValue>(&mut file)
        .with_context(|| format!("computing userspace fs-verity digest for {}", obj_rel))?;
    ensure!(
        actual == *expected_id,
        "fs-verity digest mismatch for {}: expected {}, got {}",
        obj_rel,
        expected_id.to_hex(),
        actual.to_hex()
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Nix store DB registration (`nix-store --load-db`)
// ---------------------------------------------------------------------------

struct RegistrationBatch {
    count: usize,
    text: String,
}

#[derive(Clone)]
struct StoreRecord {
    path: String,
    nar_hash_hex: String,
    nar_size: u64,
    references: BTreeSet<String>,
}

fn build_nix_registration(
    fs: &FileSystem<Sha256HashValue>,
    objects_fd: &OwnedFd,
    subpath_parts: &[std::ffi::OsString],
    nix_store_prefix: &str,
) -> Result<RegistrationBatch> {
    let prefix = nix_store_prefix.trim_end_matches('/');
    ensure!(!prefix.is_empty(), "nix store prefix cannot be empty");

    // Map every Nix32 hash present at top-level of `fs.root` to its full store path.
    let mut known_hashes: HashMap<[u8; NIX32_HASH_LEN], String> = HashMap::new();
    let mut all_top_entries: BTreeMap<String, &Inode<RegularFile<Sha256HashValue>>> =
        BTreeMap::new();

    for (name_os, inode) in fs.root.entries() {
        let Some(name_str) = name_os.to_str() else {
            continue;
        };
        if let Ok(sp) = StorePath::parse(name_str) {
            let full_path = format!("{}/{}", prefix, sp.entry());
            let mut key = [0u8; NIX32_HASH_LEN];
            key.copy_from_slice(sp.hash.as_bytes());
            known_hashes.insert(key, full_path.clone());
            all_top_entries.insert(full_path, inode);
        }
    }

    let selected: Vec<(String, &Inode<RegularFile<Sha256HashValue>>)> =
        if let Some(first) = subpath_parts.first() {
            let Some(name_str) = first.to_str() else {
                return Ok(RegistrationBatch {
                    count: 0,
                    text: String::new(),
                });
            };
            if let Ok(sp) = StorePath::parse(name_str) {
                let full_path = format!("{}/{}", prefix, sp.entry());
                match all_top_entries.get(&full_path) {
                    Some(inode) => vec![(full_path, *inode)],
                    None => Vec::new(),
                }
            } else {
                Vec::new()
            }
        } else {
            all_top_entries.into_iter().collect()
        };

    if selected.is_empty() {
        return Ok(RegistrationBatch {
            count: 0,
            text: String::new(),
        });
    }

    let ref_prefix = format!("{prefix}/");
    let mut records = Vec::with_capacity(selected.len());
    for (full_path, inode) in selected {
        let mut nar = NarHasher::new(ref_prefix.as_bytes(), &known_hashes);
        nar.write_archive(inode, &fs.leaves, objects_fd)
            .with_context(|| format!("computing NAR hash for {}", full_path))?;
        let (nar_hash_hex, nar_size, references) = nar.finish();
        records.push(StoreRecord {
            path: full_path,
            nar_hash_hex,
            nar_size,
            references,
        });
    }

    let sorted = topo_sort_records(records)?;
    let count = sorted.len();
    let mut text = String::new();
    for rec in sorted {
        text.push_str(&rec.path);
        text.push('\n');
        text.push_str(&rec.nar_hash_hex);
        text.push('\n');
        text.push_str(&rec.nar_size.to_string());
        text.push('\n');
        // Empty deriver line.
        text.push('\n');
        text.push_str(&rec.references.len().to_string());
        text.push('\n');
        for r in &rec.references {
            text.push_str(r);
            text.push('\n');
        }
    }

    Ok(RegistrationBatch { count, text })
}

fn topo_sort_records(records: Vec<StoreRecord>) -> Result<Vec<StoreRecord>> {
    let n = records.len();
    let mut path_to_idx: HashMap<String, usize> = HashMap::with_capacity(n);
    for (i, rec) in records.iter().enumerate() {
        path_to_idx.insert(rec.path.clone(), i);
    }

    // Edge: dep_idx -> user_idx when `records[user_idx]` references `records[dep_idx]`.
    let mut dependents: Vec<Vec<usize>> = vec![Vec::new(); n];
    let mut indegree: Vec<usize> = vec![0; n];

    for (user_idx, rec) in records.iter().enumerate() {
        for r in &rec.references {
            if let Some(&dep_idx) = path_to_idx.get(r) {
                if dep_idx != user_idx {
                    dependents[dep_idx].push(user_idx);
                    indegree[user_idx] += 1;
                }
            }
        }
    }

    let mut ready = VecDeque::new();
    for (idx, &deg) in indegree.iter().enumerate() {
        if deg == 0 {
            ready.push_back(idx);
        }
    }

    let mut order = Vec::with_capacity(n);
    let mut seen = HashSet::with_capacity(n);
    while let Some(idx) = ready.pop_front() {
        order.push(idx);
        seen.insert(idx);
        for &user_idx in &dependents[idx] {
            indegree[user_idx] -= 1;
            if indegree[user_idx] == 0 {
                ready.push_back(user_idx);
            }
        }
    }

    // If there is a mutual reference cycle between two store paths, append
    // any remaining paths deterministically.
    if order.len() < n {
        for idx in 0..n {
            if !seen.contains(&idx) {
                order.push(idx);
            }
        }
    }

    let mut opt_records: Vec<Option<StoreRecord>> = records.into_iter().map(Some).collect();
    Ok(order
        .into_iter()
        .map(|idx| opt_records[idx].take().expect("unique index"))
        .collect())
}

fn load_nix_db(registration: &str) -> Result<()> {
    let mut child = Command::new("nix-store")
        .arg("--load-db")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawning `nix-store --load-db`")?;

    {
        let mut stdin = child
            .stdin
            .take()
            .context("opening stdin of `nix-store --load-db`")?;
        stdin
            .write_all(registration.as_bytes())
            .context("writing registration records to `nix-store --load-db`")?;
    }

    let output = child
        .wait_with_output()
        .context("waiting for `nix-store --load-db`")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "`nix-store --load-db` exited with {}: {}",
            output.status,
            stderr.trim()
        );
    }
    Ok(())
}

struct NarHasher<'a> {
    hasher: Sha256,
    nar_size: u64,
    ref_prefix: &'a [u8],
    known_hashes: &'a HashMap<[u8; NIX32_HASH_LEN], String>,
    references: BTreeSet<String>,
    tail: Vec<u8>,
}

impl<'a> NarHasher<'a> {
    fn new(
        ref_prefix: &'a [u8],
        known_hashes: &'a HashMap<[u8; NIX32_HASH_LEN], String>,
    ) -> Self {
        Self {
            hasher: Sha256::new(),
            nar_size: 0,
            ref_prefix,
            known_hashes,
            references: BTreeSet::new(),
            tail: Vec::new(),
        }
    }

    fn feed_raw(&mut self, bytes: &[u8]) {
        self.hasher.update(bytes);
        self.nar_size += bytes.len() as u64;
    }

    fn scan_payload_for_refs(&mut self, data: &[u8]) {
        if data.is_empty() || self.known_hashes.is_empty() {
            return;
        }
        let pat = self.ref_prefix;
        let plen = pat.len();
        let needle_len = plen + NIX32_HASH_LEN;

        let mut buf = Vec::with_capacity(self.tail.len() + data.len());
        buf.extend_from_slice(&self.tail);
        buf.extend_from_slice(data);

        if buf.len() >= needle_len {
            let limit = buf.len() - needle_len;
            let mut i = 0;
            while i <= limit {
                if &buf[i..i + plen] == pat {
                    let candidate = &buf[i + plen..i + needle_len];
                    if candidate.iter().all(|b| is_nix32_byte(*b)) {
                        let mut key = [0u8; NIX32_HASH_LEN];
                        key.copy_from_slice(candidate);
                        if let Some(full_path) = self.known_hashes.get(&key) {
                            self.references.insert(full_path.clone());
                        }
                    }
                    i += plen;
                } else {
                    i += 1;
                }
            }
        }

        let keep = (needle_len - 1).min(buf.len());
        self.tail.clear();
        self.tail.extend_from_slice(&buf[buf.len() - keep..]);
    }

    fn write_padding(&mut self, len: u64) {
        let rem = (len % 8) as usize;
        if rem != 0 {
            const ZEROS: [u8; 8] = [0u8; 8];
            self.feed_raw(&ZEROS[..8 - rem]);
        }
    }

    fn write_str(&mut self, bytes: &[u8]) {
        let len = bytes.len() as u64;
        self.feed_raw(&len.to_le_bytes());
        self.feed_raw(bytes);
        self.write_padding(len);
    }

    fn write_archive(
        &mut self,
        root: &Inode<RegularFile<Sha256HashValue>>,
        leaves: &[Leaf<RegularFile<Sha256HashValue>>],
        objects_fd: &OwnedFd,
    ) -> Result<()> {
        self.write_str(b"nix-archive-1");
        self.write_node(root, leaves, objects_fd)
    }

    fn write_node(
        &mut self,
        inode: &Inode<RegularFile<Sha256HashValue>>,
        leaves: &[Leaf<RegularFile<Sha256HashValue>>],
        objects_fd: &OwnedFd,
    ) -> Result<()> {
        self.write_str(b"(");
        match inode {
            Inode::Directory(dir) => {
                self.write_str(b"type");
                self.write_str(b"directory");
                for (name, child) in dir.sorted_entries() {
                    self.write_str(b"entry");
                    self.write_str(b"(");
                    self.write_str(b"name");
                    self.write_str(name.as_bytes());
                    self.write_str(b"node");
                    self.write_node(child, leaves, objects_fd)?;
                    self.write_str(b")");
                }
            }
            Inode::Leaf(leaf_id, _) => {
                let leaf = leaves
                    .get(leaf_id.0)
                    .with_context(|| format!("missing leaf {}", leaf_id.0))?;
                match &leaf.content {
                    LeafContent::Regular(reg) => {
                        self.write_str(b"type");
                        self.write_str(b"regular");
                        if (leaf.stat.st_mode & 0o111) != 0 {
                            self.write_str(b"executable");
                            self.write_str(b"");
                        }
                        self.write_str(b"contents");
                        match reg {
                            RegularFile::Inline(data) => {
                                self.tail.clear();
                                self.scan_payload_for_refs(data);
                                self.write_str(data);
                            }
                            RegularFile::External(id, size)
                            | RegularFile::ExternalNoVerity(id, size) => {
                                self.feed_raw(&size.to_le_bytes());
                                self.tail.clear();
                                let obj_rel = id.to_object_pathname();
                                let obj_fd = openat(
                                    objects_fd,
                                    &obj_rel,
                                    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                                    Mode::empty(),
                                )
                                .with_context(|| format!("opening CAS object {} for NAR hash", obj_rel))?;
                                let mut reader = BufReader::with_capacity(IO_BUF_SIZE, File::from(obj_fd));
                                let mut buf = [0u8; IO_BUF_SIZE];
                                let mut total_read = 0u64;
                                loop {
                                    let n = reader.read(&mut buf)?;
                                    if n == 0 {
                                        break;
                                    }
                                    total_read += n as u64;
                                    self.feed_raw(&buf[..n]);
                                    self.scan_payload_for_refs(&buf[..n]);
                                }
                                ensure!(
                                    total_read == *size,
                                    "CAS object {} size mismatch during NAR hash: expected {}, read {}",
                                    obj_rel,
                                    size,
                                    total_read
                                );
                                self.write_padding(*size);
                            }
                            RegularFile::Sparse(_) => {
                                bail!("unsupported sparse regular file in NAR hash");
                            }
                        }
                    }
                    LeafContent::Symlink(target) => {
                        let target_bytes = target.as_bytes();
                        self.tail.clear();
                        self.scan_payload_for_refs(target_bytes);
                        self.write_str(b"type");
                        self.write_str(b"symlink");
                        self.write_str(b"target");
                        self.write_str(target_bytes);
                    }
                    other => {
                        bail!("unsupported NAR leaf type: {:?}", other);
                    }
                }
            }
        }
        self.write_str(b")");
        Ok(())
    }

    fn finish(self) -> (String, u64, BTreeSet<String>) {
        let digest = self.hasher.finalize();
        let hex = encode_hex(&digest);
        (hex, self.nar_size, self.references)
    }
}

fn is_nix32_byte(b: u8) -> bool {
    matches!(
        b,
        b'0'..=b'9' | b'a'..=b'd' | b'f'..=b'n' | b'p'..=b's' | b'v'..=b'z'
    )
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}
