//! Build composefs images for Nix closures and manage repository GC.
//! Signing, transport, and runtime verification belong to InitOS and its
//! deployment tooling.

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{bail, Result};
use clap::{Args, CommandFactory, Parser, Subcommand};

use nix_composefs::build::{build, build_source_dir, BuildOptions};
use nix_composefs::checkout::{checkout, CheckoutOptions};
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

    /// composefs repository root (or bare objects directory for gc).
    #[arg(
        long,
        visible_alias = "repo",
        default_value = "/z/composefs",
        global = true
    )]
    cas: PathBuf,

    /// Completion file, or - for standard input (default: -).
    #[arg(long, conflicts_with = "source")]
    paths: Option<PathBuf>,

    /// Pack an arbitrary source directory instead of a Nix closure completion.
    #[arg(long, conflicts_with = "paths")]
    source: Option<PathBuf>,

    /// Scanner worker threads (default: one per CPU).
    #[arg(long)]
    threads: Option<usize>,

    /// Preview GC deletions without modifying the repository (use with --gc).
    #[arg(short = 'n', long)]
    dry_run: bool,

    /// Delete unreferenced objects (default for GC; use with --gc).
    #[arg(long, conflicts_with = "dry_run")]
    delete: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Build a composefs EROFS image from a Nix closure or source directory.
    Build(BuildArgs),
    /// Import a directory tree into the CAS and create a mountable composefs image.
    Import(ImportArgs),
    /// Check out an image (or subpath) by hardlinking CAS objects into a destination directory.
    Checkout(CheckoutArgs),
    /// Garbage-collect unreferenced objects while keeping anchored images and hardlinked checkouts.
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

    /// Completion file, or - for standard input (default: -).
    #[arg(long, conflicts_with = "source")]
    paths: Option<PathBuf>,

    /// Pack an arbitrary source directory instead of a Nix closure completion.
    #[arg(long, conflicts_with = "paths")]
    source: Option<PathBuf>,

    /// Scanner worker threads (default: one per CPU).
    #[arg(long)]
    threads: Option<usize>,
}

#[derive(Args)]
struct CheckoutArgs {
    /// Image ref name under `<cas>/images/refs/`, digest under `<cas>/images/`, or path to an EROFS image.
    #[arg(long)]
    image: String,

    /// Destination directory (or target file path for a single-file `--subpath`). Defaults to `--store` when `--import` is used.
    #[arg(value_name = "DEST")]
    dest: Option<PathBuf>,

    /// Destination directory (alternative to positional DEST).
    #[arg(long = "dest", value_name = "DIR", conflicts_with = "dest")]
    dest_opt: Option<PathBuf>,

    /// Optional subpath within the EROFS image to check out.
    #[arg(long)]
    subpath: Option<PathBuf>,

    /// Require kernel fs-verity to be enabled on every checked-out external file.
    #[arg(long)]
    require_verity: bool,

    /// Register checked-out Nix store paths in the Nix DB via `nix-store --load-db`.
    #[arg(long, visible_alias = "load-db")]
    import: bool,

    /// Print the `nix-store --load-db` registration manifest to stdout.
    #[arg(long)]
    print_db: bool,

    /// Nix store prefix used for DB registration and reference scanning.
    #[arg(long, default_value = "/nix/store")]
    store: PathBuf,
}

#[derive(Args)]
struct ImportArgs {
    /// Directory tree to import into `<cas>/objects` and pack into an EROFS image.
    #[arg(value_name = "DIR")]
    source: Option<PathBuf>,

    /// Source directory tree (alternative to positional DIR).
    #[arg(long = "source", value_name = "DIR", conflicts_with = "source")]
    source_opt: Option<PathBuf>,

    /// Name of the composefs image reference created in `<cas>/images/refs` (default: `<DIR>.composefs`).
    #[arg(long)]
    image: Option<String>,

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
}

fn main() -> ExitCode {
    if let Err(e) = run() {
        eprintln!("nix-composefs: {e:#}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

fn ensure_no_top_level_flags(has_top_level: bool, subcommand: &str) -> Result<()> {
    if has_top_level {
        bail!("top-level build/gc flags cannot be combined with the `{subcommand}` subcommand");
    }
    Ok(())
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let has_top_level = cli.gc
        || cli.image.is_some()
        || cli.dry_run
        || cli.delete
        || cli.source.is_some()
        || cli.paths.is_some();
    let cas = cli.cas;

    match cli.command {
        Some(Commands::Build(args)) => {
            ensure_no_top_level_flags(has_top_level, "build")?;
            run_build(
                args.image,
                args.store,
                cas,
                args.paths,
                args.source,
                args.threads,
            )
        }
        Some(Commands::Import(args)) => {
            ensure_no_top_level_flags(has_top_level, "import")?;
            run_import(cas, args)
        }
        Some(Commands::Checkout(args)) => {
            ensure_no_top_level_flags(has_top_level, "checkout")?;
            run_checkout(cas, args)
        }
        Some(Commands::Gc(args)) => {
            ensure_no_top_level_flags(has_top_level, "gc")?;
            run_gc(cas, args.dry_run)
        }
        None => {
            if cli.gc {
                return run_gc(cas, cli.dry_run);
            }
            if cli.dry_run || cli.delete {
                bail!("--dry-run and --delete require `gc` or `--gc`");
            }
            if let Some(image) = cli.image {
                return run_build(image, cli.store, cas, cli.paths, cli.source, cli.threads);
            }
            Cli::command()
                .error(
                    clap::error::ErrorKind::MissingRequiredArgument,
                    "either `--image <IMAGE>` or a subcommand (`build`, `import`, `checkout`, `gc`) is required",
                )
                .exit();
        }
    }
}

fn run_import(cas: PathBuf, args: ImportArgs) -> Result<()> {
    let source = match (args.source, args.source_opt) {
        (Some(d), _) | (_, Some(d)) => d,
        (None, None) => bail!("source directory DIR (or `--source <DIR>`) is required"),
    };
    let image = match args.image {
        Some(img) => img,
        None => {
            let name = source
                .file_name()
                .and_then(|n| n.to_str())
                .map(str::to_owned)
                .or_else(|| {
                    std::fs::canonicalize(&source)
                        .ok()
                        .and_then(|p| p.file_name().and_then(|n| n.to_str()).map(str::to_owned))
                })
                .unwrap_or_else(|| "root".to_owned());
            if name.ends_with(".composefs") {
                name
            } else {
                format!("{name}.composefs")
            }
        }
    };
    run_build(
        image,
        PathBuf::from("/nix/store"),
        cas,
        None,
        Some(source),
        args.threads,
    )
}

fn run_build(
    image: String,
    store: PathBuf,
    cas: PathBuf,
    paths: Option<PathBuf>,
    source: Option<PathBuf>,
    threads: Option<usize>,
) -> Result<()> {
    let threads = threads
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4)
        })
        .clamp(1, 64);

    let opts = BuildOptions {
        store,
        cas: cas.clone(),
        image: image.clone(),
        threads,
    };

    let report = if let Some(source_dir) = source {
        build_source_dir(&source_dir, &opts)?
    } else {
        let paths = paths.unwrap_or_else(|| PathBuf::from("-"));
        let completion = read_completion(&paths)?;
        if completion.is_empty() {
            anyhow::bail!("completion is empty: {:?}", paths);
        }
        build(&completion, &opts)?
    };

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

fn run_checkout(cas: PathBuf, args: CheckoutArgs) -> Result<()> {
    let dest = match (args.dest, args.dest_opt) {
        (Some(d), _) | (_, Some(d)) => d,
        (None, None) => {
            if args.import {
                args.store.clone()
            } else {
                bail!("destination directory DEST (or `--dest <DIR>`) is required");
            }
        }
    };

    let nix_store_prefix = args.store.to_string_lossy().into_owned();
    let report = checkout(&CheckoutOptions {
        cas,
        image: args.image,
        dest: dest.clone(),
        subpath: args.subpath,
        require_verity: args.require_verity,
        register_nix_db: args.import,
        print_nix_db: args.print_db,
        nix_store_prefix,
    })?;

    if args.print_db && !report.registration.is_empty() {
        print!("{}", report.registration);
    } else {
        println!(
            "checkout: dest={:?} dirs={} hardlinked={} inline={} symlinks={} verity={} nix_db={}",
            dest,
            report.directories,
            report.hardlinked_files,
            report.inlined_files,
            report.symlinks,
            report.verity_enabled,
            report.nix_registered_paths
        );
    }
    Ok(())
}

fn run_gc(cas: PathBuf, dry_run: bool) -> Result<()> {
    let report = gc(&GcOptions { cas, dry_run })?;
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
