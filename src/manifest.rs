//! Completion manifest: the signed-description of one closure.
//!
//! The manifest records the completion (the NixOS-style set of store paths),
//! the full file inventory with fs-verity digests, the deduplicated object
//! list, and the metadata image digest. It drives cross-machine sync (which
//! objects are missing) and store materialization on workers.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Manifest format version.
pub const MANIFEST_VERSION: u32 = 1;

/// File kinds in the inventory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileKind {
    Dir,
    File,
    Symlink,
}

/// One entry of the file inventory, path relative to the store root
/// (e.g. `abc...-bin/bin/bash`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEntry {
    pub path: String,
    pub kind: FileKind,
    pub size: u64,
    pub mode: u32,
    /// fs-verity digest (hex) for regular files.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    /// Symlink target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
}

/// One content-addressed object (deduplicated).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectEntry {
    /// fs-verity digest, hex.
    pub digest: String,
    pub size: u64,
    /// Number of store files sharing this object.
    pub count: usize,
}

/// Metadata image description.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageInfo {
    /// Image file name (relative to the release directory).
    pub file: String,
    pub size: u64,
    /// fs-verity digest of the image, hex.
    pub verity: String,
}

/// A completion manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub version: u32,
    /// Human-readable closure name, e.g. a NixOS system id.
    pub name: String,
    /// Completion: the store paths that make up the closure.
    pub entries: Vec<String>,
    pub image: ImageInfo,
    pub objects: Vec<ObjectEntry>,
    pub files: Vec<FileEntry>,
    /// Build-time extras (tool version, source host, ...).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub meta: BTreeMap<String, String>,
}

impl Manifest {
    pub fn load(path: &Path) -> Result<Self> {
        let data = std::fs::read(path)
            .with_context(|| format!("reading manifest {path:?}"))?;
        let m: Manifest =
            serde_json::from_slice(&data).with_context(|| format!("parsing manifest {path:?}"))?;
        if m.version != MANIFEST_VERSION {
            anyhow::bail!("unsupported manifest version {}", m.version);
        }
        Ok(m)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let data = serde_json::to_string_pretty(self)?;
        std::fs::write(path, data)
            .with_context(|| format!("writing manifest {path:?}"))?;
        Ok(())
    }

    /// All object digests referenced by this manifest (hex strings).
    pub fn object_digests(&self) -> Vec<String> {
        self.objects.iter().map(|o| o.digest.clone()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() -> Result<()> {
        let td = tempfile::tempdir()?;
        let m = Manifest {
            version: MANIFEST_VERSION,
            name: "test".into(),
            entries: vec!["abc...-bin".into()],
            image: ImageInfo {
                file: "test.composefs".into(),
                size: 1,
                verity: "00".into(),
            },
            objects: vec![ObjectEntry {
                digest: "00".into(),
                size: 5,
                count: 2,
            }],
            files: vec![FileEntry {
                path: "abc...-bin/bin".into(),
                kind: FileKind::Dir,
                size: 0,
                mode: 0o755,
                digest: None,
                target: None,
            }],
            meta: BTreeMap::new(),
        };
        let p = td.path().join("manifest.json");
        m.save(&p)?;
        let m2 = Manifest::load(&p)?;
        assert_eq!(m, m2);
        Ok(())
    }
}
