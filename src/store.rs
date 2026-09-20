//! Nix store path grammar and completion files.
//!
//! A store path is `/nix/store/<sha256-hex>-<name>` (the leading `/nix/store/`
//! or a bare `<sha256-hex>-<name>` is also accepted). A completion file is a
//! list of store paths, one per line, e.g. the output of
//! `nix-store -q --refclosure <path>` or a NixOS system closure.

use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};

use anyhow::{bail, ensure, Context, Result};

/// A parsed Nix store entry: `<hash>-<name>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StorePath {
    /// 32-char Nix32 store hash.
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
        // Nix store hashes use its custom base32 alphabet, not hexadecimal.
        // See <https://nix.dev/manual/nix/stable/protocols/nix32.html>.
        if hash.len() != 32
            || !hash
                .chars()
                .all(|c| matches!(c, '0'..='9' | 'a'..='d' | 'f'..='n' | 'p'..='s' | 'v'..='z'))
        {
            bail!("invalid store hash in {input:?}");
        }
        if name.is_empty() || name.starts_with('-') {
            bail!("invalid store name in {input:?}");
        }
        ensure!(!name.contains('/'), "store name contains '/': {input:?}");
        Ok(Self {
            hash: hash.to_owned(),
            name: name.to_owned(),
        })
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
    if path == Path::new("-") {
        return read_completion_reader(std::io::stdin().lock());
    }
    let file = File::open(path).with_context(|| format!("opening completion file {path:?}"))?;
    read_completion_reader(file)
}

/// Parse completion paths from a stream. `-` on the CLI means standard input.
pub fn read_completion_reader(reader: impl Read) -> Result<Vec<StorePath>> {
    let mut out = Vec::new();
    for line in BufReader::new(reader).lines() {
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
        let p = StorePath::parse("abcdfabcdfabcdfabcdfabcdfabcdfab-coreutils").unwrap();
        assert_eq!(p.hash, "abcdfabcdfabcdfabcdfabcdfabcdfab");
        assert_eq!(p.name, "coreutils");
    }

    #[test]
    fn rejects_bad_hash() {
        assert!(StorePath::parse("/nix/store/short-name").is_err());
        assert!(StorePath::parse("/nix/store/ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ-name").is_err());
        assert!(StorePath::parse("/nix/store/00000000000000000000000000000000-").is_err());
    }

    #[test]
    fn accepts_nix32_hash() {
        let p = StorePath::parse("g1w7hy3qg1w7hy3qg1w7hy3qg1w7hy3q-foo").unwrap();
        assert_eq!(p.hash, "g1w7hy3qg1w7hy3qg1w7hy3qg1w7hy3q");
    }

    #[test]
    fn reads_completion_stream() {
        let entries = read_completion_reader(std::io::Cursor::new(
            b"# comment\ng1w7hy3qg1w7hy3qg1w7hy3qg1w7hy3q-foo\n",
        ))
        .unwrap();
        assert_eq!(entries.len(), 1);
    }
}
