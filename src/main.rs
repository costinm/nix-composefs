//! nix-composefs CLI.
//!
//! Build machine:
//!   nix-composefs build   --store /nix/store --cas /z/img/composefs/objects \
//!       --paths completion.txt --image system.composefs --manifest system.json
//!   nix-composefs sign    --image system.composefs --secrets /path/to/uefi-keys
//!
//! Worker:
//!   nix-composefs missing   --manifest system.json --cas <cas>      # for tar/ssh
//!   nix-composefs import    --manifest system.json --cas <cas>
//!   nix-composefs verify    --image system.composefs --key <b64pub>
//!   nix-composefs materialize --manifest system.json --cas <cas> --store /nix/store

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use nix_composefs::build::{BuildOptions, build};
use nix_composefs::cas::Cas;
use nix_composefs::manifest::Manifest;
use nix_composefs::store::read_completion;
use nix_composefs::sync;

#[derive(Parser)]
#[command(name = "nix-composefs", version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Build a composefs metadata image from a store completion.
    Build {
        /// Nix store root.
        #[arg(long)]
        store: PathBuf,
        /// CAS directory (created if missing).
        #[arg(long)]
        cas: PathBuf,
        /// Completion file: one store path per line.
        #[arg(long)]
        paths: PathBuf,
        /// Output composefs metadata image.
        #[arg(long)]
        image: PathBuf,
        /// Output manifest (JSON).
        #[arg(long)]
        manifest: Option<PathBuf>,
        /// Closure name recorded in the manifest.
        #[arg(long, default_value = "closure")]
        name: String,
        /// Scanner worker threads (default: one per CPU).
        #[arg(long)]
        threads: Option<usize>,
        /// Userspace digests; no kernel fs-verity required.
        #[arg(long)]
        insecure: bool,
    },
    /// Show a manifest summary.
    Manifest {
        #[arg(long)]
        manifest: PathBuf,
    },
    /// Print relative CAS object paths missing from the CAS (one per line).
    Missing {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        cas: PathBuf,
    },
    /// Enable fs-verity on CAS objects (all manifest objects, or --objects).
    Import {
        #[arg(long)]
        cas: PathBuf,
        #[arg(long)]
        manifest: Option<PathBuf>,
        /// Object path list (one relative CAS path per line; `-` = stdin).
        #[arg(long)]
        objects: Option<PathBuf>,
        #[arg(long)]
        insecure: bool,
    },
    /// Re-create the store from the CAS (hard links), per the manifest.
    Materialize {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        cas: PathBuf,
        /// Target store root.
        #[arg(long)]
        store: PathBuf,
        /// Replace existing store files with CAS hard links.
        #[arg(long)]
        replace: bool,
        #[arg(long)]
        insecure: bool,
    },
    /// Dedup an existing store into the CAS (nix store optimise, verity-based).
    Optimise {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        cas: PathBuf,
        #[arg(long)]
        store: PathBuf,
        #[arg(long)]
        insecure: bool,
    },
    /// Sign an image (Ed25519 and/or UEFI db) like initos erofs images.
    Sign {
        #[arg(long)]
        image: PathBuf,
        /// Secrets directory (image_key.pem / db.key + db.crt).
        #[arg(long)]
        secrets: PathBuf,
    },
    /// Verify an image signature (fs-verity digest based).
    Verify {
        #[arg(long)]
        image: PathBuf,
        /// Base64 raw Ed25519 public key (image_key.pub.b64).
        #[arg(long)]
        key: Option<String>,
        /// UEFI db certificate (PEM); verifies the db signature.
        #[arg(long)]
        db_crt: Option<PathBuf>,
    },
    /// Generate an Ed25519 image-signing keypair into --secrets.
    Genkeys {
        #[arg(long)]
        secrets: PathBuf,
    },
}

fn main() -> ExitCode {
    if let Err(e) = run() {
        eprintln!("nix-composefs: {e:#}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Build {
            store,
            cas,
            paths,
            image,
            manifest,
            name,
            threads,
            insecure,
        } => {
            let completion = read_completion(&paths)?;
            if completion.is_empty() {
                anyhow::bail!("completion file is empty: {paths:?}");
            }
            let threads = threads
                .unwrap_or_else(|| std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4))
                .max(1)
                .min(64);
            let opts = BuildOptions {
                store,
                cas,
                image: image.clone(),
                manifest: manifest.clone(),
                name,
                threads,
                insecure,
            };
            let (report, m) = build(&completion, &opts)?;
            println!("image:        {image:?} ({} bytes, verity {})", report.image_size, report.image_verity);
            if let Some(p) = &manifest {
                println!("manifest:     {p:?}");
            }
            println!(
                "entries: {}  dirs: {}  files: {}  symlinks: {}  objects: {}",
                report.entries, report.dirs, report.files, report.symlinks, report.objects
            );
            println!("objects total: {} ({} bytes)", m.objects.len(), m.objects.iter().map(|o| o.size).sum::<u64>());
        }
        Cmd::Manifest { manifest } => {
            let m = Manifest::load(&manifest)?;
            println!("name:    {}", m.name);
            println!("entries: {}", m.entries.len());
            println!("files:   {}", m.files.len());
            println!("objects: {} ({} bytes)", m.objects.len(), m.objects.iter().map(|o| o.size).sum::<u64>());
            println!("image:   {} ({} bytes, verity {})", m.image.file, m.image.size, m.image.verity);
            for (k, v) in &m.meta {
                println!("  {k}: {v}");
            }
        }
        Cmd::Missing { manifest, cas } => {
            let m = Manifest::load(&manifest)?;
            let cas = Cas::open(&cas, 1, true)?;
            for p in sync::missing_objects(&m, &cas)? {
                println!("{}", p.display());
            }
        }
        Cmd::Import {
            cas,
            manifest,
            objects,
            insecure,
        } => {
            let cas = Cas::open(&cas, 1, insecure)?;
            let m = manifest.map(|p| Manifest::load(&p)).transpose()?;
            let paths = match objects {
                Some(p) => Some(read_object_list(&p)?),
                None => None,
            };
            let n = sync::import(&cas, m.as_ref(), paths.as_deref())?;
            println!("verified/registered {n} objects in {cas:?}", cas = cas.root());
        }
        Cmd::Materialize {
            manifest,
            cas,
            store,
            replace,
            insecure,
        } => {
            let m = Manifest::load(&manifest)?;
            let cas = Cas::open(&cas, 1, insecure)?;
            let r = sync::materialize(&m, &cas, &store, replace)?;
            println!(
                "materialized: {} dirs, {} symlinks, {} hard links ({} pre-existing)",
                r.dirs, r.symlinks, r.hardlinks, r.existing
            );
        }
        Cmd::Optimise {
            manifest,
            cas,
            store,
            insecure,
        } => {
            let m = Manifest::load(&manifest)?;
            let cas = Cas::open(&cas, 1, insecure)?;
            let r = sync::optimise(&m, &cas, &store)?;
            println!(
                "deduped: {} objects ({} bytes saved), already linked: {}, mismatch: {}, missing: {}",
                r.deduped, r.bytes_saved, r.already_linked, r.mismatch, r.missing_objects
            );
            for s in &r.skipped {
                println!("  skipped: {s}");
            }
        }
        Cmd::Sign { image, secrets } => {
            for p in nix_composefs::sign::sign_image(&image, &secrets)? {
                println!("signed: {p:?}");
            }
        }
        Cmd::Verify { image, key, db_crt } => {
            let mut ok = false;
            if let Some(k) = key {
                let r = nix_composefs::sign::verify_image(&image, &k)?;
                println!("ed25519 signature: {}", if r { "OK" } else { "MISMATCH" });
                ok |= r;
            }
            if let Some(c) = db_crt {
                let r = nix_composefs::sign::verify_image_db(&image, &c)?;
                println!("db signature:      {}", if r { "OK" } else { "MISMATCH/ABSENT" });
                ok |= r;
            }
            if !ok {
                anyhow::bail!("no --key or --db-crt given; nothing verified");
            }
            if !ok {
                anyhow::bail!("verification failed");
            }
        }
        Cmd::Genkeys { secrets } => {
            let (_, p) = nix_composefs::sign::genkeys(&secrets)?;
            println!("wrote {p:?} (+ image_key_pub.pem, image_key.pub.b64)");
        }
    }
    Ok(())
}

fn read_object_list(p: &std::path::Path) -> Result<Vec<PathBuf>> {
    let data = if p == PathBuf::from("-") {
        let mut s = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut s)
            .context("reading object list from stdin")?;
        s
    } else {
        std::fs::read_to_string(p).with_context(|| format!("reading {p:?}"))?
    };
    Ok(data
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .map(PathBuf::from)
        .collect())
}
