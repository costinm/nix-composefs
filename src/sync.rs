//! Cross-machine sync and store materialization.
//!
//! Transport is deliberately not built in: `missing` prints the relative
//! CAS object paths that a worker needs, and any byte transport (SSH+tar,
//! rsync, OCI, ...) can move them. After objects arrive, `import` (re-)enables fs-verity, and
//! `materialize` re-creates /nix/store by hard-linking store entries into
//! the CAS.

use std::collections::HashSet;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use composefs::fsverity::{FsVerityHashValue, Sha256HashValue};
use rustix::fs::{AtFlags, Mode, OFlags, linkat, open, unlink};

use crate::cas::Cas;
use crate::manifest::{FileKind, Manifest};

/// Relative CAS object paths (e.g. `ab/cdef...`) missing from the CAS.
pub fn missing_objects(manifest: &Manifest, cas: &Cas) -> Result<Vec<PathBuf>> {
    let want: Vec<Sha256HashValue> = manifest
        .object_digests()
        .iter()
        .map(|d| Sha256HashValue::from_hex(d))
        .collect::<std::result::Result<_, _>>()
        .context("parsing manifest object digests")?;
    let missing = cas.missing_objects(&want)?;
    let mut out = Vec::with_capacity(missing.len());
    for id in missing {
        let p = cas.object_path(&id);
        out.push(p.strip_prefix(cas.root()).with_context(|| "object path prefix")?.to_path_buf());
    }
    Ok(out)
}

/// Enable fs-verity on all CAS objects referenced by the manifest (or on the
/// listed relative object paths when `paths` is given). Returns the number of
/// objects handled.
pub fn import(cas: &Cas, manifest: Option<&Manifest>, paths: Option<&[PathBuf]>) -> Result<usize> {
    let mut ids: Vec<Sha256HashValue> = if let Some(paths) = paths {
        paths
            .iter()
            .map(|p| {
                Sha256HashValue::from_object_pathname(p.as_os_str().as_bytes())
                    .with_context(|| format!("parsing object path {:?}", p))
            })
            .collect::<std::result::Result<_, _>>()?
    } else if let Some(m) = manifest {
        m.object_digests()
            .iter()
            .map(|d| Sha256HashValue::from_hex(d))
            .collect::<std::result::Result<_, _>>()
            .context("parsing manifest object digests")?
    } else {
        bail!("either a manifest or an object path list is required")
    };
    ids.sort_by(|a, b| a.to_hex().cmp(&b.to_hex()));
    ids.dedup();
    for id in &ids {
        cas.ensure_verity(id)?;
    }
    Ok(ids.len())
}

/// Materialize the store described by the manifest below `store_root`:
/// directories, symlinks, and hard links of CAS objects.
///
/// Existing store files are left untouched unless they are already hard
/// links to the CAS object; `replace` controls whether mismatched existing
/// files are replaced.
pub fn materialize(
    manifest: &Manifest,
    cas: &Cas,
    store_root: &Path,
    replace: bool,
) -> Result<MaterializeReport> {
    let mut report = MaterializeReport::default();

    for f in &manifest.files {
        let path = store_root.join(&f.path);
        match f.kind {
            FileKind::Dir => {
                std::fs::create_dir_all(&path)
                    .with_context(|| format!("mkdir {}", f.path))?;
                report.dirs += 1;
            }
            FileKind::Symlink => {
                let target = f.target.as_deref().unwrap_or("");
                match std::fs::symlink_metadata(&path) {
                    Ok(st) if st.file_type().is_symlink() => {
                        report.existing += 1;
                        continue;
                    }
                    Ok(_) => {
                        if replace {
                            std::fs::remove_file(&path)
                                .with_context(|| format!("remove {}", f.path))?;
                        } else {
                            report.existing += 1;
                            continue;
                        }
                    }
                    Err(_) => {}
                }
                std::os::unix::fs::symlink(target, &path)
                    .with_context(|| format!("symlink {}", f.path))?;
                report.symlinks += 1;
            }
            FileKind::File => {
                let digest = f
                    .digest
                    .as_deref()
                    .context("file entry without digest")?;
                let id = Sha256HashValue::from_hex(digest)
                    .with_context(|| format!("parsing digest for {}", f.path))?;
                if !cas.has_object(&id) {
                    bail!(
                        "missing CAS object {} for {} — run import first",
                        id.to_hex(),
                        f.path
                    );
                }
                match std::fs::symlink_metadata(&path) {
                    Ok(st) => {
                        if st.file_type().is_symlink() || st.file_type().is_dir() {
                            bail!("store path {} is not a regular file", f.path);
                        }
                        if same_inode(&path, &cas.object_path(&id))? {
                            report.hardlinks += 1;
                            continue;
                        }
                        if !replace {
                            report.existing += 1;
                            continue;
                        }
                        // Different inode: unlink and relink to the CAS object.
                        std::fs::remove_file(&path)
                            .with_context(|| format!("unlink {}", f.path))?;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e).with_context(|| format!("stat {}", f.path)),
                }
                hardlink_into_store(&cas.object_path(&id), &path)
                    .with_context(|| format!("hard link {} -> {}", f.path, id.to_hex()))?;
                report.hardlinks += 1;
            }
        }
    }
    Ok(report)
}

/// Dedup pass over an existing store: for each regular file in the manifest,
/// if the CAS already holds an object with the same verity digest and the
/// store file is a different inode, replace the store file with a hard link
/// to the CAS object. Files that cannot be unlinked (e.g. immutable) are
/// reported, not failed.
pub fn optimise(manifest: &Manifest, cas: &Cas, store_root: &Path) -> Result<OptimiseReport> {
    let mut report = OptimiseReport::default();
    let mut seen: HashSet<String> = HashSet::new();

    for f in &manifest.files {
        if f.kind != FileKind::File || f.digest.is_none() {
            continue;
        }
        let digest = f.digest.as_deref().unwrap();
        if !seen.insert(digest.to_owned()) {
            // Counted once per object, not per path.
            continue;
        }
        let id = Sha256HashValue::from_hex(digest).with_context(|| "parsing digest")?;
        if !cas.has_object(&id) {
            report.missing_objects += 1;
            continue;
        }
        let path = store_root.join(&f.path);
        let st = match std::fs::symlink_metadata(&path) {
            Ok(st) => st,
            Err(_) => continue,
        };
        if st.file_type().is_symlink() || st.file_type().is_dir() {
            continue;
        }
        if same_inode(&path, &cas.object_path(&id))? {
            report.already_linked += 1;
            continue;
        }
        // Verify the store file actually matches the object before relinking.
        let store_digest = Cas::digest_of_file(&path)
            .with_context(|| format!("digesting {}", f.path))?;
        if store_digest != id {
            report.mismatch += 1;
            continue;
        }
        if let Err(e) = replace_with_hardlink(&path, &cas.object_path(&id)) {
            report.skipped.push(format!("{}: {e}", f.path));
            continue;
        }
        report.deduped += 1;
        report.bytes_saved += f.size;
    }
    Ok(report)
}

#[derive(Debug, Clone, Default)]
pub struct MaterializeReport {
    pub dirs: usize,
    pub symlinks: usize,
    pub hardlinks: usize,
    pub existing: usize,
}

#[derive(Debug, Clone, Default)]
pub struct OptimiseReport {
    pub deduped: usize,
    pub already_linked: usize,
    pub mismatch: usize,
    pub missing_objects: usize,
    pub bytes_saved: u64,
    pub skipped: Vec<String>,
}

fn same_inode(a: &Path, b: &Path) -> Result<bool> {
    let sa = std::fs::symlink_metadata(a)?;
    let sb = std::fs::symlink_metadata(b)?;
    use std::os::unix::fs::MetadataExt;
    Ok(sa.ino() == sb.ino() && sa.dev() == sb.dev())
}

/// Unlink `store_file` and replace it with a hard link to `cas_object`.
fn replace_with_hardlink(store_file: &Path, cas_object: &Path) -> Result<()> {
    unlink(store_file).context("unlinking store file")?;
    hardlink_into_store(cas_object, store_file).context("linking CAS object into store")
}

/// Create a hard link `dest` pointing to the CAS object `cas_object`.
fn hardlink_into_store(cas_object: &Path, dest: &Path) -> Result<()> {
    let cas_dir = open(
        cas_object
            .parent()
            .context("CAS object without parent")?,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .context("opening CAS object dir")?;
    let dest_dir = open(
        dest.parent().context("dest without parent")?,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("opening dest dir {:?}", dest.parent().unwrap()))?;
    linkat(
        &cas_dir,
        cas_object.file_name().context("CAS object without name")?,
        &dest_dir,
        dest.file_name().context("dest without name")?,
        AtFlags::SYMLINK_FOLLOW,
    )
    .with_context(|| format!("linking {:?} -> {:?}", cas_object, dest))?;
    Ok(())
}


