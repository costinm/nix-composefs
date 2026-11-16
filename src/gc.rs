//! Garbage collection for composefs repositories and object stores.
//!
//! Collects unreferenced objects in `objects/xx/<digest>` while preserving:
//! - Objects reachable from EROFS images anchored in `images/refs/**`,
//!   `streams/refs/**`, or actively mounted/locked images (`flock`).
//! - Any individual object in `objects/xx/<digest>` with `st_nlink > 1`
//!   (files checked out externally via hardlinks, consistent with OSTree
//!   bare hardlink checkouts) or an active `flock`.
//!
//! `meta.json` is strictly optional; defaults match `fsverity-sha256-12` and
//! V1 EROFS images.

use std::collections::{HashMap, HashSet};
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::File;
use std::io::Read;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use composefs::erofs::reader::collect_objects;
use composefs::fsverity::{Algorithm, FsVerityHashValue, Sha256HashValue};
use composefs::repository::read_repo_algorithm;
use composefs::splitstream::SplitStreamReader;
use rustix::fs::{
    accessat, flock, open, openat, readlinkat, statat, unlinkat, Access, AtFlags, Dir, FileType,
    FlockOperation, Mode, OFlags,
};
use rustix::io::Errno;

/// Garbage collection options.
#[derive(Debug, Clone)]
pub struct GcOptions {
    /// Repository root (e.g. `/z/composefs`) or bare `objects` directory.
    pub cas: PathBuf,
    /// If true, only report what would be removed without unlinking anything.
    pub dry_run: bool,
}

/// Garbage collection summary statistics.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GcReport {
    /// Objects reachable from EROFS image anchors or streams.
    pub objects_reachable: u64,
    /// Unreferenced objects kept solely because `st_nlink > 1` (checked out via hardlinks).
    pub objects_hardlinked_kept: u64,
    /// Total bytes of objects kept via `st_nlink > 1`.
    pub hardlinked_bytes: u64,
    /// Unreferenced objects kept because of an active flock.
    pub objects_locked_kept: u64,
    /// Objects removed (or that would be removed in `dry_run`).
    pub objects_removed: u64,
    /// Total bytes of removed objects.
    pub bytes_removed: u64,
    /// Broken or unanchored symlinks pruned from `images/` and `images/refs/`.
    pub images_pruned: u64,
    /// Broken or unanchored symlinks pruned from `streams/` and `streams/refs/`.
    pub streams_pruned: u64,
}

/// Run garbage collection against `opts.cas`.
pub fn gc(opts: &GcOptions) -> Result<GcReport> {
    let repo_fd = open(
        &opts.cas,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("opening repository directory {:?}", opts.cas))?;

    if let Some(alg) = read_repo_algorithm(&repo_fd)? {
        if alg != Algorithm::SHA256 {
            bail!(
                "repository algorithm {alg} does not match expected {}",
                Algorithm::SHA256
            );
        }
    }

    if !opts.dry_run {
        accessat(&repo_fd, ".", Access::WRITE_OK, AtFlags::empty())
            .with_context(|| format!("repository {:?} is not writable", opts.cas))?;
    }

    let lock_op = if opts.dry_run {
        FlockOperation::LockShared
    } else {
        FlockOperation::LockExclusive
    };
    flock(&repo_fd, lock_op).with_context(|| format!("locking repository {:?}", opts.cas))?;

    let has_objects_subdir = opts.cas.join("objects").is_dir();
    let has_repo_layout = has_objects_subdir
        || opts.cas.join("meta.json").exists()
        || opts.cas.join("images").is_dir()
        || opts.cas.join("streams").is_dir();

    let (has_repo_root, objects_fd) = if has_objects_subdir {
        let fd = openat(
            &repo_fd,
            "objects",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .with_context(|| format!("opening {:?}/objects", opts.cas))?;
        (true, Some(fd))
    } else if has_repo_layout {
        (true, None)
    } else {
        (
            false,
            Some(repo_fd.try_clone().context("cloning store directory fd")?),
        )
    };

    let mut report = GcReport::default();
    let mut live_objects = HashSet::new();
    let mut parsed_erofs_ids = HashSet::new();

    let mut all_images: HashMap<String, Sha256HashValue> = HashMap::new();
    let mut image_ids: HashSet<Sha256HashValue> = HashSet::new();
    let mut all_streams: HashMap<String, Sha256HashValue> = HashMap::new();
    let mut id_to_stream_name: HashMap<Sha256HashValue, String> = HashMap::new();

    if has_repo_root {
        // 1. Collect images/ and images/refs/
        if let Some(images_fd) = open_optional_dir(&repo_fd, "images")? {
            let mut root_image_names = HashSet::new();

            for item in Dir::read_from(&images_fd).context("reading images/ directory")? {
                let entry = item.context("reading images/ entry")?;
                let filename = entry.file_name();
                if filename == c"." || filename == c".." || filename == c"refs" {
                    continue;
                }
                let ftype = entry_file_type(&images_fd, filename, entry.file_type())?;
                match ftype {
                    FileType::Symlink => {
                        let target = readlinkat(&images_fd, filename, [])
                            .with_context(|| format!("reading symlink images/{filename:?}"))?;
                        let name = OsStr::from_bytes(filename.to_bytes())
                            .to_string_lossy()
                            .into_owned();
                        if let Ok(id) = Sha256HashValue::from_object_pathname(target.as_bytes())
                            .or_else(|_| Sha256HashValue::from_hex(filename.to_bytes()))
                        {
                            image_ids.insert(id.clone());
                            all_images.insert(name, id);
                        }
                    }
                    FileType::RegularFile => {
                        if !is_sidecar_bytes(filename.to_bytes()) {
                            let data = read_fd_bytes(
                                openat(
                                    &images_fd,
                                    filename,
                                    OFlags::RDONLY | OFlags::CLOEXEC,
                                    Mode::empty(),
                                )
                                .with_context(|| format!("opening images/{filename:?}"))?,
                            )?;
                            collect_erofs_bytes(&data, &mut live_objects).with_context(|| {
                                format!("reading EROFS image images/{filename:?}")
                            })?;
                        }
                    }
                    _ => {}
                }
            }

            if let Some(refs_fd) = open_optional_dir(&images_fd, "refs")? {
                walk_image_refs(
                    &refs_fd,
                    "",
                    &all_images,
                    &mut root_image_names,
                    &mut live_objects,
                    &mut parsed_erofs_ids,
                )?;
            }

            for (name, id) in &all_images {
                let is_locked = match objects_fd.as_ref() {
                    Some(obj_dir) => is_object_locked(obj_dir, id)?,
                    None => false,
                };

                if root_image_names.contains(name) || is_locked {
                    live_objects.insert(id.clone());
                    if !parsed_erofs_ids.contains(id) {
                        if let Some(obj_dir) = objects_fd.as_ref() {
                            if let Some(fd) = open_object_optional(obj_dir, id)? {
                                let data = read_fd_bytes(fd)?;
                                collect_erofs_bytes(&data, &mut live_objects).with_context(
                                    || format!("collecting objects for image {name}"),
                                )?;
                                parsed_erofs_ids.insert(id.clone());
                            }
                        }
                    }
                }
            }
        }

        // 2. Collect streams/ and streams/refs/
        if let Some(streams_fd) = open_optional_dir(&repo_fd, "streams")? {
            let mut root_stream_names = HashSet::new();

            for item in Dir::read_from(&streams_fd).context("reading streams/ directory")? {
                let entry = item.context("reading streams/ entry")?;
                let filename = entry.file_name();
                if filename == c"." || filename == c".." || filename == c"refs" {
                    continue;
                }
                let ftype = entry_file_type(&streams_fd, filename, entry.file_type())?;
                if ftype == FileType::Symlink {
                    let target = readlinkat(&streams_fd, filename, [])
                        .with_context(|| format!("reading symlink streams/{filename:?}"))?;
                    if let Ok(id) = Sha256HashValue::from_object_pathname(target.as_bytes()) {
                        let name = OsStr::from_bytes(filename.to_bytes())
                            .to_string_lossy()
                            .into_owned();
                        id_to_stream_name.insert(id.clone(), name.clone());
                        all_streams.insert(name, id);
                    }
                }
            }

            if let Some(refs_fd) = open_optional_dir(&streams_fd, "refs")? {
                walk_stream_refs(&refs_fd, "", &all_streams, &mut root_stream_names, &mut live_objects)?;
            }

            for (name, id) in &all_streams {
                let is_locked = match objects_fd.as_ref() {
                    Some(obj_dir) => is_object_locked(obj_dir, id)?,
                    None => false,
                };
                if is_locked {
                    root_stream_names.insert(name.clone());
                }
            }

            if let Some(obj_dir) = objects_fd.as_ref() {
                let mut walked_streams = HashSet::new();
                for stream_name in root_stream_names {
                    walk_stream(
                        obj_dir,
                        &all_streams,
                        &id_to_stream_name,
                        &image_ids,
                        &stream_name,
                        &mut walked_streams,
                        &mut live_objects,
                        &mut parsed_erofs_ids,
                    )?;
                }
            }
        }
    }

    // 3. Sweep objects/00..ff/<62-hex>
    let mut removed_objects = HashSet::new();
    if let Some(obj_dir) = objects_fd.as_ref() {
        for first_byte in 0x00..=0xffu8 {
            let subdir_name = format!("{first_byte:02x}");
            let Some(dirfd) = open_optional_dir(obj_dir, &subdir_name)? else {
                continue;
            };
            for item in Dir::read_from(&dirfd)
                .with_context(|| format!("reading objects/{subdir_name} directory"))?
            {
                let entry = item.context("reading object directory entry")?;
                let filename = entry.file_name();
                if filename == c"." || filename == c".." {
                    continue;
                }
                let Ok(id) =
                    Sha256HashValue::from_object_dir_and_basename(first_byte, filename.to_bytes())
                else {
                    // Ignore staging tmpfiles or unrelated entries.
                    continue;
                };
                let stat = statat(&dirfd, filename, AtFlags::SYMLINK_NOFOLLOW).with_context(|| {
                    format!("statting objects/{subdir_name}/{filename:?}")
                })?;
                if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
                    continue;
                }
                let size = stat.st_size.max(0) as u64;

                if live_objects.contains(&id) {
                    report.objects_reachable += 1;
                    continue;
                }

                // Preserve externally hardlinked objects (checked-out files).
                if stat.st_nlink > 1 {
                    report.objects_hardlinked_kept += 1;
                    report.hardlinked_bytes += size;
                    continue;
                }

                if is_file_locked(&dirfd, filename)? {
                    report.objects_locked_kept += 1;
                    continue;
                }

                report.objects_removed += 1;
                report.bytes_removed += size;
                removed_objects.insert(id);

                if !opts.dry_run {
                    unlinkat(&dirfd, filename, AtFlags::empty()).with_context(|| {
                        format!("unlinking objects/{subdir_name}/{filename:?}")
                    })?;
                }
            }
        }
    }

    // 4. Clean up broken or unanchored symlinks in images/ and streams/
    if has_repo_root {
        report.images_pruned =
            cleanup_category(&repo_fd, "images", &live_objects, &removed_objects, opts.dry_run)?;
        report.streams_pruned = cleanup_category(
            &repo_fd,
            "streams",
            &live_objects,
            &removed_objects,
            opts.dry_run,
        )?;
    }

    Ok(report)
}

fn collect_erofs_bytes(data: &[u8], live: &mut HashSet<Sha256HashValue>) -> Result<()> {
    let objs = collect_objects::<Sha256HashValue>(data).context("parsing EROFS image")?;
    live.extend(objs);
    Ok(())
}

fn is_sidecar_bytes(name: &[u8]) -> bool {
    name.ends_with(b".sig") || name.ends_with(b".basedir")
}

fn open_optional_dir(dirfd: &OwnedFd, name: &str) -> Result<Option<OwnedFd>> {
    match openat(
        dirfd,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => Ok(Some(fd)),
        Err(Errno::NOENT) => Ok(None),
        Err(e) => Err(e).with_context(|| format!("opening directory {name}")),
    }
}

fn open_object_optional(objects_fd: &OwnedFd, id: &Sha256HashValue) -> Result<Option<OwnedFd>> {
    let rel = id.to_object_pathname();
    match openat(objects_fd, &rel, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty()) {
        Ok(fd) => Ok(Some(fd)),
        Err(Errno::NOENT) => Ok(None),
        Err(e) => Err(e).with_context(|| format!("opening object {rel}")),
    }
}

fn read_fd_bytes(fd: OwnedFd) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    File::from(fd)
        .read_to_end(&mut data)
        .context("reading file data")?;
    Ok(data)
}

fn entry_file_type(dirfd: &OwnedFd, name: &CStr, d_type: FileType) -> Result<FileType> {
    if d_type != FileType::Unknown {
        return Ok(d_type);
    }
    let st = statat(dirfd, name, AtFlags::SYMLINK_NOFOLLOW)
        .with_context(|| format!("statting {name:?}"))?;
    Ok(FileType::from_raw_mode(st.st_mode))
}

fn is_object_locked(objects_fd: &OwnedFd, id: &Sha256HashValue) -> Result<bool> {
    let rel = id.to_object_pathname();
    let rel_c = CString::new(rel.as_bytes()).context("building object pathname")?;
    is_file_locked(objects_fd, &rel_c)
}

fn is_file_locked(dirfd: &OwnedFd, filename: &CStr) -> Result<bool> {
    let fd = match openat(
        dirfd,
        filename,
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(false),
        Err(e) => return Err(e).with_context(|| format!("opening {filename:?} for lock check")),
    };
    match flock(&fd, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(false),
        Err(Errno::WOULDBLOCK) => Ok(true),
        Err(e) => Err(e).with_context(|| format!("probing flock on {filename:?}")),
    }
}

fn walk_image_refs(
    dirfd: &OwnedFd,
    rel_prefix: &str,
    all_images: &HashMap<String, Sha256HashValue>,
    root_image_names: &mut HashSet<String>,
    live_objects: &mut HashSet<Sha256HashValue>,
    parsed_erofs_ids: &mut HashSet<Sha256HashValue>,
) -> Result<()> {
    for item in Dir::read_from(dirfd).context("reading images/refs directory")? {
        let entry = item.context("reading images/refs entry")?;
        let filename = entry.file_name();
        if filename == c"." || filename == c".." {
            continue;
        }
        let name_str = OsStr::from_bytes(filename.to_bytes())
            .to_string_lossy()
            .into_owned();
        let rel_path = if rel_prefix.is_empty() {
            name_str
        } else {
            format!("{rel_prefix}/{name_str}")
        };
        let ftype = entry_file_type(dirfd, filename, entry.file_type())?;
        match ftype {
            FileType::Directory => {
                let subfd = openat(
                    dirfd,
                    filename,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .with_context(|| format!("opening images/refs/{rel_path}"))?;
                walk_image_refs(
                    &subfd,
                    &rel_path,
                    all_images,
                    root_image_names,
                    live_objects,
                    parsed_erofs_ids,
                )?;
            }
            FileType::Symlink => {
                let target = readlinkat(dirfd, filename, [])
                    .with_context(|| format!("reading symlink images/refs/{rel_path}"))?;
                let target_path = Path::new(OsStr::from_bytes(target.as_bytes()));
                let mut resolved_id = Sha256HashValue::from_object_pathname(target.as_bytes()).ok();

                if let Some(base) = target_path.file_name() {
                    let base_str = base.to_string_lossy();
                    if let Some(id) = all_images.get(base_str.as_ref()) {
                        root_image_names.insert(base_str.into_owned());
                        resolved_id = Some(id.clone());
                    }
                }

                match openat(
                    dirfd,
                    filename,
                    OFlags::RDONLY | OFlags::CLOEXEC,
                    Mode::empty(),
                ) {
                    Ok(fd) => {
                        if let Some(id) = &resolved_id {
                            live_objects.insert(id.clone());
                            if parsed_erofs_ids.contains(id) {
                                continue;
                            }
                        }
                        let data = read_fd_bytes(fd)?;
                        collect_erofs_bytes(&data, live_objects)
                            .with_context(|| format!("parsing EROFS image images/refs/{rel_path}"))?;
                        if let Some(id) = resolved_id {
                            parsed_erofs_ids.insert(id);
                        }
                    }
                    Err(Errno::NOENT) => {
                        // Dangling ref symlink; left to cleanup_category.
                    }
                    Err(e) => {
                        return Err(e)
                            .with_context(|| format!("opening EROFS image images/refs/{rel_path}"));
                    }
                }
            }
            FileType::RegularFile => {
                if is_sidecar_bytes(filename.to_bytes()) {
                    continue;
                }
                let fd = openat(
                    dirfd,
                    filename,
                    OFlags::RDONLY | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .with_context(|| format!("opening images/refs/{rel_path}"))?;
                let data = read_fd_bytes(fd)?;
                collect_erofs_bytes(&data, live_objects)
                    .with_context(|| format!("parsing EROFS image images/refs/{rel_path}"))?;
            }
            _ => {}
        }
    }
    Ok(())
}

fn walk_stream_refs(
    dirfd: &OwnedFd,
    rel_prefix: &str,
    all_streams: &HashMap<String, Sha256HashValue>,
    root_stream_names: &mut HashSet<String>,
    live_objects: &mut HashSet<Sha256HashValue>,
) -> Result<()> {
    for item in Dir::read_from(dirfd).context("reading streams/refs directory")? {
        let entry = item.context("reading streams/refs entry")?;
        let filename = entry.file_name();
        if filename == c"." || filename == c".." {
            continue;
        }
        let name_str = OsStr::from_bytes(filename.to_bytes())
            .to_string_lossy()
            .into_owned();
        let rel_path = if rel_prefix.is_empty() {
            name_str
        } else {
            format!("{rel_prefix}/{name_str}")
        };
        let ftype = entry_file_type(dirfd, filename, entry.file_type())?;
        match ftype {
            FileType::Directory => {
                let subfd = openat(
                    dirfd,
                    filename,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .with_context(|| format!("opening streams/refs/{rel_path}"))?;
                walk_stream_refs(
                    &subfd,
                    &rel_path,
                    all_streams,
                    root_stream_names,
                    live_objects,
                )?;
            }
            FileType::Symlink => {
                let target = readlinkat(dirfd, filename, [])
                    .with_context(|| format!("reading symlink streams/refs/{rel_path}"))?;
                if let Ok(id) = Sha256HashValue::from_object_pathname(target.as_bytes()) {
                    live_objects.insert(id);
                }
                let target_path = Path::new(OsStr::from_bytes(target.as_bytes()));
                if let Some(base) = target_path.file_name() {
                    let base_str = base.to_string_lossy();
                    if all_streams.contains_key(base_str.as_ref()) {
                        root_stream_names.insert(base_str.into_owned());
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn walk_stream(
    objects_fd: &OwnedFd,
    all_streams: &HashMap<String, Sha256HashValue>,
    id_to_stream_name: &HashMap<Sha256HashValue, String>,
    image_ids: &HashSet<Sha256HashValue>,
    stream_name: &str,
    walked_streams: &mut HashSet<String>,
    live_objects: &mut HashSet<Sha256HashValue>,
    parsed_erofs_ids: &mut HashSet<Sha256HashValue>,
) -> Result<()> {
    if !walked_streams.insert(stream_name.to_owned()) {
        return Ok(());
    }
    let Some(stream_id) = all_streams.get(stream_name) else {
        return Ok(());
    };
    live_objects.insert(stream_id.clone());

    let Some(fd) = open_object_optional(objects_fd, stream_id)? else {
        return Ok(());
    };
    let mut reader = SplitStreamReader::<Sha256HashValue>::new(File::from(fd), None)
        .with_context(|| format!("reading splitstream {stream_name}"))?;
    reader
        .get_object_refs(|obj_id| {
            live_objects.insert(obj_id.clone());
        })
        .with_context(|| format!("collecting object refs from splitstream {stream_name}"))?;

    let named_refs: Vec<Sha256HashValue> = reader
        .iter_named_refs()
        .map(|(_, obj_id)| obj_id.clone())
        .collect();

    for ref_id in named_refs {
        live_objects.insert(ref_id.clone());
        if let Some(next_stream) = id_to_stream_name.get(&ref_id) {
            walk_stream(
                objects_fd,
                all_streams,
                id_to_stream_name,
                image_ids,
                next_stream,
                walked_streams,
                live_objects,
                parsed_erofs_ids,
            )?;
        } else if image_ids.contains(&ref_id) && !parsed_erofs_ids.contains(&ref_id) {
            if let Some(img_fd) = open_object_optional(objects_fd, &ref_id)? {
                let data = read_fd_bytes(img_fd)?;
                collect_erofs_bytes(&data, live_objects).with_context(|| {
                    format!("collecting objects for stream-linked image {ref_id:?}")
                })?;
                parsed_erofs_ids.insert(ref_id);
            }
        }
    }

    Ok(())
}

fn cleanup_category(
    repo_fd: &OwnedFd,
    category: &str,
    live_objects: &HashSet<Sha256HashValue>,
    removed_objects: &HashSet<Sha256HashValue>,
    dry_run: bool,
) -> Result<u64> {
    let Some(category_fd) = open_optional_dir(repo_fd, category)? else {
        return Ok(0);
    };

    let mut pruned_first_level_names = HashSet::new();
    let mut count = cleanup_dir_links(
        &category_fd,
        false,
        live_objects,
        removed_objects,
        &mut pruned_first_level_names,
        None,
        dry_run,
    )
    .with_context(|| format!("cleaning broken links in {category}/"))?;

    if let Some(refs_fd) = open_optional_dir(&category_fd, "refs")? {
        let mut dummy = HashSet::new();
        count += cleanup_dir_links(
            &refs_fd,
            true,
            live_objects,
            removed_objects,
            &mut dummy,
            Some(&pruned_first_level_names),
            dry_run,
        )
        .with_context(|| format!("cleaning broken links in {category}/refs"))?;
    }

    Ok(count)
}

fn cleanup_dir_links(
    dirfd: &OwnedFd,
    recursive: bool,
    live_objects: &HashSet<Sha256HashValue>,
    removed_objects: &HashSet<Sha256HashValue>,
    pruned_names: &mut HashSet<OsString>,
    first_level_pruned: Option<&HashSet<OsString>>,
    dry_run: bool,
) -> Result<u64> {
    let mut count = 0;
    for item in Dir::read_from(dirfd).context("reading directory for symlink cleanup")? {
        let entry = item.context("reading directory entry for symlink cleanup")?;
        let filename = entry.file_name();
        if filename == c"." || filename == c".." || (!recursive && filename == c"refs") {
            continue;
        }
        let ftype = entry_file_type(dirfd, filename, entry.file_type())?;
        match ftype {
            FileType::Directory => {
                if !recursive {
                    continue;
                }
                let subfd = openat(
                    dirfd,
                    filename,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .with_context(|| format!("opening subdirectory {filename:?}"))?;
                count += cleanup_dir_links(
                    &subfd,
                    recursive,
                    live_objects,
                    removed_objects,
                    pruned_names,
                    first_level_pruned,
                    dry_run,
                )?;
            }
            FileType::Symlink => {
                let is_broken = match statat(dirfd, filename, AtFlags::empty()) {
                    Ok(_) => false,
                    Err(Errno::NOENT) => true,
                    Err(e) => {
                        return Err(e).with_context(|| format!("statting symlink {filename:?}"));
                    }
                };

                let target = readlinkat(dirfd, filename, [])
                    .with_context(|| format!("reading symlink {filename:?}"))?;
                let target_id = Sha256HashValue::from_object_pathname(target.as_bytes()).ok();

                let unanchored_first_level = !recursive
                    && target_id
                        .as_ref()
                        .map(|id| !live_objects.contains(id))
                        .unwrap_or(false);

                let would_break = if is_broken || unanchored_first_level {
                    true
                } else if dry_run {
                    let points_to_removed_obj = target_id
                        .as_ref()
                        .map(|id| removed_objects.contains(id))
                        .unwrap_or(false);
                    let points_to_pruned_entry = first_level_pruned
                        .and_then(|set| {
                            Path::new(OsStr::from_bytes(target.as_bytes()))
                                .file_name()
                                .map(|base| set.contains(base))
                        })
                        .unwrap_or(false);
                    points_to_removed_obj || points_to_pruned_entry
                } else {
                    false
                };

                if is_broken || would_break {
                    count += 1;
                    pruned_names.insert(OsStr::from_bytes(filename.to_bytes()).to_os_string());
                    if !dry_run {
                        unlinkat(dirfd, filename, AtFlags::empty())
                            .with_context(|| format!("unlinking broken symlink {filename:?}"))?;
                    }
                }
            }
            _ => {
                // Leave regular sidecars (e.g. .sig, .db.sig, .basedir) intact.
            }
        }
    }
    Ok(count)
}
