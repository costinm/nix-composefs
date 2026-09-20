//! nix-composefs — composefs metadata images and digest stores for Nix closures.
//!
//! This crate is build-side only. It walks a Nix completion, inserts regular
//! file content into composefs-rs's flat fs-verity digest store, and emits a
//! V1 EROFS composefs image. InitOS owns image signing and verification; the
//! signed image is the sole filesystem manifest at runtime.

pub mod build;
pub mod store;

pub use composefs::fsverity::{FsVerityHashValue, Sha256HashValue};
