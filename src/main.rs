//! Build composefs images for Nix closures and manage repository GC.
//! Signing, transport, and runtime verification belong to InitOS and its
//! deployment tooling.

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{bail, Result};
use clap::{Args, CommandFactory, Parser, Subcommand};

use nix_composefs::build::{build, BuildOptions};
use nix_composefs::gc::{gc, GcOptions};
use nix_composefs::store::read_completion;

#[derive(Parser)]
#[command(name = "nix-composefs", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Run garbage collection instead of building an image.
    #[arg(long, conflicts_with = "image")]
    gc: bool,

    /// Name of the composefs image reference created in the repository.
    #[arg(long)]
    image: Option<String>,

    /// Nix store root.
    #[arg(long, default_value = "/nix/store")]
    store: PathBuf,

    /// composefs-rs repository root (or bare objects directory for gc).
    #[arg(
        long,
        visible_alias = "repo",
        default_value = "/z/composefs",
        global = true
    )]
    cas: PathBuf,

    /// Completion file, or - for standard input.
    #[arg(long, default_value = "-")]
    paths: PathBuf,

    /// Scanner worker threads (default: one per CPU).
    #[arg(long)]
    threads: Option<usize>,

    /// Preview GC deletions without modifying the repository (use with --gc).
    #[arg(short = 'n', long)]
    dry_run: bool,

    /// Delete unreferenced objects (default for GC; use with --gc).
    #[arg(long, conflicts_with = "dry_run")]
    delete: bool,

    /// Additional GC root image names or external EROFS anchor paths (use with --gc).
    #[arg(short = 'r', long = "root", value_name = "ROOT")]
    roots: Vec<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Build a composefs EROFS image from a Nix closure.
    Build(BuildArgs),
    /// Garbage-collect unreferenced objects while keeping EROFS anchors and hardlinked objects.
    Gc(GcArgs),
}

#[derive(Args)]
struct BuildArgs {
    /// Name of the composefs image reference created in the repository.
    #[arg(long)]
    image: String,

    /// Nix store root.
    #[arg(long, default_value = "/nix/store")]
    store: PathBuf,

    /// Completion file, or - for standard input.
    #[arg(long, default_value = "-")]
    paths: PathBuf,

    /// Scanner worker threads (default: one per CPU).
    #[arg(long)]
    threads: Option<usize>,
}

#[derive(Args)]
struct GcArgs {
    /// Preview what would be deleted without modifying the repository.
    #[arg(short = 'n', long)]
    dry_run: bool,

    /// Delete unreferenced objects (default behavior; accepted for compatibility).
    #[arg(long, conflicts_with = "dry_run")]
    delete: bool,

    /// Additional root image names, ref names, or external EROFS anchor paths to keep.
    #[arg(short = 'r', long = "root", value_name = "ROOT")]
    roots: Vec<String>,

    /// Additional anchor EROFS paths or image names to keep.
    #[arg(value_name = "ANCHOR")]
    anchors: Vec<String>,
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
    let cas = cli.cas;

    match cli.command {
        Some(Commands::Build(args)) => {
            if cli.gc || cli.image.is_some() || cli.dry_run || cli.delete || !cli.roots.is_empty() {
                bail!("top-level build/gc flags cannot be combined with the `build` subcommand");
            }
            run_build(args.image, args.store, cas, args.paths, args.threads)
        }
        Some(Commands::Gc(args)) => {
            if cli.gc || cli.image.is_some() || cli.dry_run || cli.delete || !cli.roots.is_empty() {
                bail!("top-level build/gc flags cannot be combined with the `gc` subcommand");
            }
            let mut roots = args.roots;
            roots.extend(args.anchors);
            run_gc(cas, roots, args.dry_run)
        }
        None => {
            if cli.gc {
                return run_gc(cas, cli.roots, cli.dry_run);
            }
            if cli.dry_run || cli.delete || !cli.roots.is_empty() {
                bail!("--dry-run, --delete, and --root require `gc` or `--gc`");
            }
            if let Some(image) = cli.image {
                return run_build(image, cli.store, cas, cli.paths, cli.threads);
            }
            Cli::command()
                .error(
                    clap::error::ErrorKind::MissingRequiredArgument,
                    "either `--image <IMAGE>` or a subcommand (`build`, `gc`) is required",
                )
                .exit();
        }
    }
}

fn run_build(
    image: String,
    store: PathBuf,
    cas: PathBuf,
    paths: PathBuf,
    threads: Option<usize>,
) -> Result<()> {
    let completion = read_completion(&paths)?;
    if completion.is_empty() {
        anyhow::bail!("completion is empty: {:?}", paths);
    }
    let threads = threads
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4)
        })
        .clamp(1, 64);
    let report = build(
        &completion,
        &BuildOptions {
            store,
            cas: cas.clone(),
            image: image.clone(),
            threads,
        },
    )?;
    println!(
        "image:   {:?} in {:?}/images/refs ({} bytes)",
        image, cas, report.image_size
    );
    println!(
        "entries: {}  symlink entries: {}",
        report.entries, report.symlinks
    );
    Ok(())
}

fn run_gc(cas: PathBuf, roots: Vec<String>, dry_run: bool) -> Result<()> {
    let report = gc(&GcOptions {
        cas,
        roots,
        dry_run,
    })?;
    println!(
        "gc: reachable={} hardlinked_kept={} ({} bytes) removed={} ({} bytes) images_pruned={} dry_run={}",
        report.objects_reachable,
        report.objects_hardlinked_kept,
        report.hardlinked_bytes,
        report.objects_removed,
        report.bytes_removed,
        report.images_pruned,
        dry_run
    );
    Ok(())
}
