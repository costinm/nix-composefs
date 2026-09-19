//! fs-verity content-addressed store (CAS).
//!
//! Objects live at `<root>/<first-byte-hex>/<full-hex-digest>` (the
//! C-compatible flat layout, identical to the firmware CAS layout used by
//! initos). Every object has fs-verity enabled when the backing filesystem
//! supports it; in `insecure` mode (dev machines, tmpfs/overlayfs) digests
//! are computed in userspace and no kernel verity is required.
//!
//! `Cas` implements composefs-rs [`ObjectStore`] so the standard
//! `read_filesystem_with_opts` scanner can walk /nix/store and reference
//! store files by verity digest without an intermediate staging copy.

use std::collections::HashSet;
use std::io::Read;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use composefs::fs::ObjectStore;
use composefs::fsverity::{
    EnableVerityError, FsVerityHasher, FsVerityHashValue, Sha256HashValue,
    enable_verity_maybe_copy, measure_verity, measure_verity_opt, measure_verity_with_fallback,
};
use rustix::fs::{AtFlags, Mode, OFlags, CWD, linkat, mkdirat, open, openat};
use rustix::io::Errno;
use tokio::sync::Semaphore;

const IO_BUF: usize = 64 * 1024;

/// A flat, content-addressed, fs-verity object store.
#[derive(Debug)]
pub struct Cas {
    root: PathBuf,
    /// Open directory fd for the store root.
    root_fd: OwnedFd,
    /// Userspace-digest fallback when the filesystem lacks fs-verity.
    insecure: bool,
    semaphore: Arc<Semaphore>,
}

impl Cas {
    /// Open or create the CAS at `path`.
    pub fn open(path: &Path, concurrency: usize, insecure: bool) -> Result<Self> {
        match mkdirat(CWD, path, Mode::from_raw_mode(0o755)) {
            Ok(()) | Err(Errno::EXIST) => {}
            Err(e) => return Err(e).with_context(|| format!("creating CAS root {path:?}")),
        }
        let root_fd = openat(
            CWD,
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .with_context(|| format!("opening CAS root {path:?}"))?;
        Ok(Self {
            root: path.to_path_buf(),
            root_fd,
            insecure,
            semaphore: Arc::new(Semaphore::new(concurrency.max(1))),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn insecure(&self) -> bool {
        self.insecure
    }

    /// Path of an object inside the CAS (`<root>/xx/rest`).
    pub fn object_path(&self, id: &Sha256HashValue) -> PathBuf {
        self.root.join(id.to_object_pathname())
    }

    pub fn has_object(&self, id: &Sha256HashValue) -> bool {
        self.object_path(id).is_file()
    }

    /// Ensure an object exists in the CAS for the content of `src` (a regular
    /// file). The source is streamed into an O_TMPFILE, verity is enabled (or
    /// computed in userspace), and the result is hard-linked into its
    /// content-addressed path. Existing objects are reused (dedup).
    pub fn ensure_object_from_file(&self, src: &Path) -> Result<Sha256HashValue> {
        let fd = open(
            src,
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .with_context(|| format!("opening {src:?}"))?;
        let size = std::fs::metadata(src)
            .with_context(|| format!("stat {src:?}"))?
            .len();
        self.ensure_object_from_fd(fd, size)
    }

    /// Ensure an object exists in the CAS for an in-memory content.
    pub fn ensure_object_from_bytes(&self, data: &[u8]) -> Result<Sha256HashValue> {
        let fd = create_tmpfile_in(&self.root_fd)?;
        {
            use std::io::Write;
            let mut f = std::fs::File::from(fd.try_clone().context("cloning tmpfile")?);
            f.write_all(data)
                .context("writing object content")?;
        }
        self.seal_and_link(fd)
    }

    fn seal_and_link(&self, tmp_fd: OwnedFd) -> Result<Sha256HashValue> {
        let ro_fd = reopen_ro(tmp_fd.as_raw_fd())
            .context("reopening object tmpfile read-only")?;
        let ro_fd = Arc::new(ro_fd);

        let (ro_fd, verity_enabled) = match enable_verity_maybe_copy::<Sha256HashValue>(
            &self.root_fd,
            ro_fd.as_fd(),
        ) {
            Ok(None) => (ro_fd.clone(), true),
            Ok(Some(new_fd)) => (Arc::new(new_fd), true),
            Err(EnableVerityError::AlreadyEnabled) => (ro_fd.clone(), true),
            Err(EnableVerityError::FilesystemNotSupported) if self.insecure => (ro_fd.clone(), false),
            Err(e) => return Err(anyhow!(e)).context("enabling fs-verity on object"),
        };

        let id: Sha256HashValue = if verity_enabled {
            measure_verity(&*ro_fd).context("measuring object digest")?
        } else {
            let mut f = std::fs::File::from(ro_fd.try_clone().context("cloning object fd")?);
            userspace_verity(&mut f)?
        };

        self.link_object(&ro_fd, &id)
            .with_context(|| format!("storing object {}", id.to_hex()))?;
        drop(ro_fd);
        Ok(id)
    }

    /// Link the (tmp) file behind `fd` into its content-addressed path.
    fn link_object(&self, fd: &OwnedFd, id: &Sha256HashValue) -> Result<()> {
        let obj_path = id.to_object_pathname();
        let slash = obj_path
            .find('/')
            .expect("object pathname always contains '/'");
        let dir_name = &obj_path[..slash];
        let file_name = &obj_path[slash + 1..];

        match mkdirat(&self.root_fd, dir_name, Mode::from_raw_mode(0o755)) {
            Ok(()) | Err(Errno::EXIST) => {}
            Err(e) => {
                return Err(e).with_context(|| format!("creating object dir {dir_name:?}"))
            }
        }
        let subdir = openat(
            &self.root_fd,
            dir_name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .with_context(|| format!("opening object dir {dir_name:?}"))?;

        match linkat(
            CWD,
            proc_self_fd(fd),
            &subdir,
            file_name,
            AtFlags::SYMLINK_FOLLOW,
        ) {
            Ok(()) | Err(Errno::EXIST) => Ok(()),
            Err(e) => Err(e).with_context(|| format!("linking object {obj_path:?}")),
        }
    }

    /// Enable fs-verity on the object (no-op when already enabled; skipped in
    /// insecure mode). Used after transferring objects to a worker.
    pub fn ensure_verity(&self, id: &Sha256HashValue) -> Result<()> {
        if self.insecure {
            return Ok(());
        }
        let fd = open(
            self.object_path(id),
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .with_context(|| format!("opening CAS object {}", id.to_hex()))?;
        match measure_verity_opt::<Sha256HashValue>(&fd)? {
            Some(d) => {
                if &d != id {
                    bail!(
                        "CAS object digest mismatch: expected {} found {}",
                        id.to_hex(),
                        d.to_hex()
                    );
                }
            }
            None => {
                enable_verity_maybe_copy::<Sha256HashValue>(
                    &self.root_fd,
                    fd.as_fd(),
                )
                .map(|_| ())
                .with_context(|| format!("enabling verity on {}", id.to_hex()))?;
            }
        }
        Ok(())
    }

    /// Verify the object exists and its measured verity digest matches.
    pub fn verify_object(&self, id: &Sha256HashValue) -> Result<()> {
        if !self.has_object(id) {
            bail!("missing CAS object {}", id.to_hex());
        }
        if self.insecure {
            return Ok(());
        }
        let fd = open(
            self.object_path(id),
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let found = measure_verity_with_fallback::<Sha256HashValue>(std::fs::File::from(fd))
            .context("measuring CAS object")?;
        if found != *id {
            bail!(
                "CAS object digest mismatch: expected {} found {}",
                id.to_hex(),
                found.to_hex()
            );
        }
        Ok(())
    }

    /// Compute the verity digest of a local file (kernel if available,
    /// userspace fallback).
    pub fn digest_of_file(path: &Path) -> Result<Sha256HashValue> {
        let fd = open(path, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())
            .with_context(|| format!("opening {path:?}"))?;
        measure_verity_with_fallback::<Sha256HashValue>(std::fs::File::from(fd))
            .with_context(|| format!("digesting {path:?}"))
    }

    /// List all object paths (relative to the CAS root) present in the store.
    pub fn list_objects(&self) -> Result<Vec<PathBuf>> {
        let mut out = Vec::new();
        let root_dir = openat(
            CWD,
            &self.root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .with_context(|| format!("opening CAS root {}", self.root.display()))?;
        for entry in rustix::fs::Dir::read_from(&root_dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.chars().all(|c| c.is_ascii_hexdigit()) || name.len() != 2 {
                continue;
            }
            let sub = openat(
                &root_dir,
                name.as_bytes(),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )?;
            for obj in rustix::fs::Dir::read_from(&sub)? {
                let obj = obj?;
                out.push(PathBuf::from(name.as_str()).join(obj.file_name().to_string_lossy().as_ref()));
            }
        }
        Ok(out)
    }

    /// Objects from `want` that are not yet present in the CAS.
    pub fn missing_objects(&self, want: &[Sha256HashValue]) -> Result<Vec<Sha256HashValue>> {
        let have: HashSet<Sha256HashValue> = self
            .list_objects()?
            .iter()
            .filter_map(|p| Sha256HashValue::from_object_pathname(p.as_os_str().as_bytes()).ok())
            .collect();
        Ok(want.iter().filter(|id| !have.contains(id)).cloned().collect())
    }
}

impl ObjectStore<Sha256HashValue> for Cas {
    fn ensure_object_from_fd(&self, fd: OwnedFd, size: u64) -> Result<Sha256HashValue> {
        let tmp = create_tmpfile_in(&self.root_fd).context("creating object tmpfile")?;
        let copied = copy_fd_to_fd(&fd, &tmp)?;
        if copied != size {
            bail!("object size mismatch: expected {size}, copied {copied}");
        }
        self.seal_and_link(tmp)
    }

    fn write_semaphore(&self) -> Arc<Semaphore> {
        self.semaphore.clone()
    }
}

/// Create an anonymous O_TMPFILE inside `dirfd`.
fn create_tmpfile_in(dirfd: &OwnedFd) -> Result<OwnedFd> {
    openat(
        dirfd,
        ".",
        OFlags::RDWR | OFlags::TMPFILE | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o644),
    )
    .context("creating O_TMPFILE")
}

/// Reopen the file behind `raw_fd` as a fresh read-only descriptor via
/// /proc/self/fd (the kernel requires no writable fds to enable verity).
fn reopen_ro(raw_fd: i32) -> Result<OwnedFd> {
    let p = format!("/proc/self/fd/{raw_fd}");
    open(&p, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())
        .with_context(|| format!("reopening {p}"))
}

fn proc_self_fd(fd: &impl std::os::fd::AsFd) -> String {
    format!("/proc/self/fd/{}", fd.as_fd().as_raw_fd())
}

/// Stream-copy `from` -> `to`, preferring copy_file_range (reflink on CoW
/// filesystems) with a read/write fallback.
fn copy_fd_to_fd(from: &OwnedFd, to: &OwnedFd) -> Result<u64> {
    let mut off = 0u64;
    loop {
        let mut off_from = off;
        let mut off_to = off;
        match rustix::fs::copy_file_range(from, Some(&mut off_from), to, Some(&mut off_to), IO_BUF) {
            Ok(0) => return Ok(off),
            Ok(_) => off = off_from,
            Err(e)
                if off == 0
                    && matches!(
                        e,
                        Errno::NOSYS | Errno::OPNOTSUPP | Errno::INVAL | Errno::IO | Errno::PERM
                    ) =>
            {
                // copy_file_range unavailable/unsupported: plain copy.
                let mut f = std::fs::File::from(from.try_clone().context("cloning source")?);
                let mut t = std::fs::File::from(to.try_clone().context("cloning target")?);
                return std::io::copy(&mut f, &mut t).context("copying object");
            }
            Err(e) => return Err(e).context("copy_file_range"),
        }
    }
}

/// Userspace fs-verity digest (Merkle tree, 4 KiB blocks, SHA-256).
/// Chunks must be fed block-aligned; the final chunk may be short.
pub fn userspace_verity(reader: &mut impl Read) -> Result<Sha256HashValue> {
    let mut hasher = FsVerityHasher::<Sha256HashValue>::new();
    let mut buf = vec![0u8; FsVerityHasher::<Sha256HashValue>::BLOCK_SIZE];
    loop {
        let n = reader.read(&mut buf).context("reading for verity digest")?;
        if n == 0 {
            break;
        }
        hasher.add_block(&buf[..n]);
    }
    Ok(hasher.digest())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_roundtrip_insecure() -> Result<()> {
        let td = tempfile::tempdir()?;
        let cas = Cas::open(td.path(), 1, true)?;
        let content = b"hello cas";
        let id = cas.ensure_object_from_bytes(content)?;
        assert!(cas.has_object(&id));
        let stored = std::fs::read(cas.object_path(&id))?;
        assert_eq!(stored, content);

        // Dedup: storing identical content again returns the same id.
        let id2 = cas.ensure_object_from_bytes(content)?;
        assert_eq!(id, id2);

        // Layout: xx/rest.
        let obj = cas.object_path(&id);
        let rel = obj.strip_prefix(td.path())?;
        assert_eq!(rel.components().count(), 2);

        // missing_objects
        let mut other = FsVerityHasher::<Sha256HashValue>::new();
        other.add_block(b"different");
        let want = vec![id.clone(), other.digest()];
        let missing = cas.missing_objects(&want)?;
        assert_eq!(missing.len(), 1);
        Ok(())
    }
}
