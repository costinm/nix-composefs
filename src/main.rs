//! Build composefs images for Nix closures. Signing, transport, and runtime
//! verification belong to InitOS and its deployment tooling.

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Result;
use clap::Parser;

use nix_composefs::build::{build, BuildOptions};
use nix_composefs::store::read_completion;

#[derive(Parser)]
#[command(name = "nix-composefs", version, about)]
struct Cli {
    /// Output composefs metadata image.
    #[arg(long)]
    image: PathBuf,
    /// Nix store root.
    #[arg(long, default_value = "/nix/store")]
    store: PathBuf,
    /// composefs-rs repository root.
    #[arg(long, default_value = "/z/composefs")]
    cas: PathBuf,
    /// Completion file, or - for standard input.
    #[arg(long, default_value = "-")]
    paths: PathBuf,
    /// Scanner worker threads (default: one per CPU).
    #[arg(long)]
    threads: Option<usize>,
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
    let completion = read_completion(&cli.paths)?;
    if completion.is_empty() {
        anyhow::bail!("completion is empty: {:?}", cli.paths);
    }
    let threads = cli
        .threads
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4)
        })
        .clamp(1, 64);
    let report = build(
        &completion,
        &BuildOptions {
            store: cli.store,
            cas: cli.cas,
            image: cli.image.clone(),
            threads,
        },
    )?;
    println!("image:   {:?} ({} bytes)", cli.image, report.image_size);
    println!(
        "entries: {}  symlink entries: {}",
        report.entries, report.symlinks
    );
    Ok(())
}
