//! Nix store path grammar and completion files.
//!
//! A store path is `/nix/store/<sha256-hex>-<name>` (the leading `/nix/store/`
//! or a bare `<sha256-hex>-<name>` is also accepted). A completion file is a
//! list of store paths, one per line, e.g. the output of
//! `nix-store -q --refclosure <path>` or a NixOS system closure.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use anyhow::{bail, ensure, Context, Result};

/// A parsed Nix store entry: `<hash>-<name>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StorePath {
    /// 32-char lowercase hex content hash.
    pub hash: String,
    /// Entry name without the `<hash>-` prefix.
    pub name: String,
}

impl StorePath {
    /// Parse a store path from any of the accepted forms.
    pub fn parse(input: &str) -> Result<Self> {
        let s = input.trim();
        let entry = s
            .strip_prefix("/nix/store/")
            .or_else(|| s.strip_prefix("store/"))
            .unwrap_or(s);
        if entry.starts_with('/') {
            bail!("not a store path: {input:?}");
        }
        let (hash, name) = entry
            .split_once('-')
            .ok_or_else(|| anyhow::anyhow!("not a store path: {input:?}"))?;
        if hash.len() != 32 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
            bail!("invalid store hash in {input:?}");
        }
        if name.is_empty() || name.starts_with('-') {
            bail!("invalid store name in {input:?}");
        }
        ensure!(!name.contains('/'), "store name contains '/': {input:?}");
        let hash = hash.to_ascii_lowercase();
        Ok(Self { hash, name: name.to_owned() })
    }

    /// The store entry name, e.g. `abc...123-bin`.
    pub fn entry(&self) -> String {
        format!("{}-{}", self.hash, self.name)
    }

    /// Absolute path of this entry below `store_root`.
    pub fn path(&self, store_root: &Path) -> PathBuf {
        store_root.join(self.entry())
    }
}

/// Read a completion file: one store path per line, `#` comments and blank
/// lines ignored.
pub fn read_completion(path: &Path) -> Result<Vec<StorePath>> {
    let file = File::open(path).with_context(|| format!("opening completion file {path:?}"))?;
    let mut out = Vec::new();
    for line in BufReader::new(file).lines() {
        let line = line.with_context(|| "reading completion file")?;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        out.push(StorePath::parse(line).with_context(|| format!("line: {line}"))?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_full_path() {
        let p = StorePath::parse("/nix/store/00000000000000000000000000000000-bash").unwrap();
        assert_eq!(p.entry(), "00000000000000000000000000000000-bash");
    }

    #[test]
    fn parse_bare_entry() {
        let p = StorePath::parse("abcdefabcdefabcdefabcdefabcdefab-coreutils").unwrap();
        assert_eq!(p.hash, "abcdefabcdefabcdefabcdefabcdefab");
        assert_eq!(p.name, "coreutils");
    }

    #[test]
    fn rejects_bad_hash() {
        assert!(StorePath::parse("/nix/store/short-name").is_err());
        assert!(StorePath::parse("/nix/store/ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ-name").is_err());
        assert!(StorePath::parse("/nix/store/00000000000000000000000000000000-").is_err());
    }
}
