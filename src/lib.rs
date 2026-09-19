//! nix-composefs — /nix/store as a signed, syncable composefs store.
//!
//! Build machine: walk a completion (a NixOS-style set of store paths),
//! content-address every regular file into a fs-verity object store (CAS),
//! and emit a composefs metadata EROFS image plus a manifest describing the
//! closure. The image is signed with the same conventions as initos erofs
//! images (Ed25519 over the fs-verity digest, optional UEFI db RSA).
//!
//! Worker: verify the image, import the missing CAS objects (over SSH or
//! any other transport), and re-create /nix/store by hard-linking store
//! entries into the CAS.

pub mod build;
pub mod cas;
pub mod manifest;
pub mod sign;
pub mod store;
pub mod sync;

pub use composefs::fsverity::{FsVerityHashValue, Sha256HashValue};
