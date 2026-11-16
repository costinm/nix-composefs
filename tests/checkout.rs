//! Integration tests for hardlink checkout, arbitrary source directory builds,
//! GC hardlink preservation, subpath extraction, and Nix DB registration.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::process::Command;

use nix_composefs::build::{build, build_source_dir, BuildOptions};
use nix_composefs::checkout::{checkout, CheckoutOptions};
use nix_composefs::gc::{gc, GcOptions};
use nix_composefs::store::StorePath;

fn write_file_mode(path: &Path, content: &[u8], mode: u32) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, content).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

#[test]
fn checkout_arbitrary_directory_hardlinks_and_gc_protects() {
    let td = tempfile::tempdir().unwrap();
    let root = td.path();
    let src = root.join("src");
    let cas = root.join("cas");
    let dest = root.join("dest");

    // Inline file (<= 64 B), external data file (> 64 B), executable (> 64 B), and symlink.
    let small_data = b"tiny config\n";
    let large_data = vec![0x41u8; 4096];
    let script_data = format!("#!/bin/sh\n# {}\necho ok\n", "x".repeat(128)).into_bytes();

    write_file_mode(&src.join("etc/small.conf"), small_data, 0o644);
    write_file_mode(&src.join("share/blob.bin"), &large_data, 0o644);
    write_file_mode(&src.join("bin/run"), &script_data, 0o755);
    std::os::unix::fs::symlink("../bin/run", src.join("etc/link-to-run")).unwrap();

    let build_report = build_source_dir(
        &src,
        &BuildOptions {
            store: Path::new("/unused").to_path_buf(),
            cas: cas.clone(),
            image: "rootfs.composefs".into(),
            threads: 1,
        },
    )
    .unwrap();
    assert!(build_report.image_size > 0);
    assert_eq!(build_report.symlinks, 1);

    let report = checkout(&CheckoutOptions {
        cas: cas.clone(),
        image: "rootfs.composefs".into(),
        dest: dest.clone(),
        subpath: None,
        require_verity: false,
        register_nix_db: false,
        print_nix_db: false,
        nix_store_prefix: "/nix/store".into(),
    })
    .unwrap();

    assert_eq!(report.hardlinked_files, 2);
    assert_eq!(report.inlined_files, 1);
    assert_eq!(report.symlinks, 1);

    assert_eq!(std::fs::read(dest.join("etc/small.conf")).unwrap(), small_data);
    assert_eq!(std::fs::read(dest.join("share/blob.bin")).unwrap(), large_data);
    assert_eq!(std::fs::read(dest.join("bin/run")).unwrap(), script_data);
    assert_eq!(
        std::fs::read_link(dest.join("etc/link-to-run")).unwrap(),
        Path::new("../bin/run")
    );

    // Permissions have write bits stripped (0444 / 0555).
    assert_eq!(
        std::fs::metadata(dest.join("share/blob.bin")).unwrap().mode() & 0o777,
        0o444
    );
    assert_eq!(
        std::fs::metadata(dest.join("bin/run")).unwrap().mode() & 0o777,
        0o555
    );
    assert_eq!(
        std::fs::metadata(dest.join("etc/small.conf")).unwrap().mode() & 0o777,
        0o444
    );

    // External checked-out files share an inode with `<cas>/objects/xx/<62-hex>` (st_nlink == 2).
    assert_eq!(std::fs::metadata(dest.join("share/blob.bin")).unwrap().nlink(), 2);
    assert_eq!(std::fs::metadata(dest.join("bin/run")).unwrap().nlink(), 2);

    // Remove the EROFS image ref; GC removes only the unreferenced EROFS image object
    // while keeping both hardlinked external objects alive via `st_nlink > 1`.
    std::fs::remove_file(cas.join("images/refs/rootfs.composefs")).unwrap();
    let gc_report = gc(&GcOptions {
        cas: cas.clone(),
        dry_run: false,
    })
    .unwrap();
    assert_eq!(gc_report.objects_reachable, 0);
    assert_eq!(gc_report.objects_hardlinked_kept, 2);
    assert_eq!(gc_report.objects_removed, 1);
}

#[test]
fn checkout_subpath_extracts_single_dir_or_leaf() {
    let td = tempfile::tempdir().unwrap();
    let root = td.path();
    let src = root.join("src");
    let cas = root.join("cas");

    write_file_mode(&src.join("pkg-a/lib/data.bin"), &[0x55; 2048], 0o644);
    write_file_mode(&src.join("pkg-a/meta.txt"), b"pkg-a inline", 0o644);
    write_file_mode(&src.join("pkg-b/other.bin"), &[0x66; 2048], 0o644);

    build_source_dir(
        &src,
        &BuildOptions {
            store: Path::new("/unused").to_path_buf(),
            cas: cas.clone(),
            image: "bundle.composefs".into(),
            threads: 1,
        },
    )
    .unwrap();

    // Directory subpath checkout.
    let sub_dest = root.join("pkg-a-out");
    let dir_rep = checkout(&CheckoutOptions {
        cas: cas.clone(),
        image: "bundle.composefs".into(),
        dest: sub_dest.clone(),
        subpath: Some("pkg-a".into()),
        require_verity: false,
        register_nix_db: false,
        print_nix_db: false,
        nix_store_prefix: "/nix/store".into(),
    })
    .unwrap();
    assert_eq!(dir_rep.hardlinked_files, 1);
    assert_eq!(dir_rep.inlined_files, 1);
    assert_eq!(
        std::fs::metadata(sub_dest.join("lib/data.bin")).unwrap().nlink(),
        2
    );
    assert!(!sub_dest.join("pkg-b").exists());

    // Single-file leaf subpath checkout into an existing directory.
    let file_dir = root.join("single-dir");
    std::fs::create_dir_all(&file_dir).unwrap();
    let leaf_rep = checkout(&CheckoutOptions {
        cas,
        image: "bundle.composefs".into(),
        dest: file_dir.clone(),
        subpath: Some("pkg-b/other.bin".into()),
        require_verity: false,
        register_nix_db: false,
        print_nix_db: false,
        nix_store_prefix: "/nix/store".into(),
    })
    .unwrap();
    assert_eq!(leaf_rep.hardlinked_files, 1);
    assert_eq!(
        std::fs::metadata(file_dir.join("other.bin")).unwrap().nlink(),
        2
    );
}

#[test]
fn checkout_nix_closure_generates_exact_nar_registration_and_loads_nix_db() {
    let td = tempfile::tempdir().unwrap();
    let root = td.path();
    let src_store = root.join("src-store");
    let cas = root.join("cas");

    // 1. Canonical Nix-verified NAR vector (`g1w7hy3qg1w7hy3qg1w7hy3qg1w7hy3q-demo` with `hi` = "hello\n").
    let demo = "g1w7hy3qg1w7hy3qg1w7hy3qg1w7hy3q-demo";
    write_file_mode(&src_store.join(demo).join("hi"), b"hello\n", 0o644);

    // 2. Dependent external package (`dep` and `app` referencing `dep` inside > 64B script & symlink).
    let dep = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-dep";
    let app = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-app";
    write_file_mode(
        &src_store.join(dep).join("bin/tool"),
        format!("#!/bin/sh\necho {}\n", "d".repeat(120)).as_bytes(),
        0o755,
    );
    write_file_mode(
        &src_store.join(app).join("bin/wrapper"),
        format!("#!/bin/sh\nexec /nix/store/{dep}/bin/tool {}\n", "w".repeat(100)).as_bytes(),
        0o755,
    );
    std::os::unix::fs::symlink(
        format!("/nix/store/{dep}/bin/tool"),
        src_store.join(app).join("bin/tool-link"),
    )
    .unwrap();

    let completion = [
        StorePath::parse(app).unwrap(),
        StorePath::parse(demo).unwrap(),
        StorePath::parse(dep).unwrap(),
    ];
    build(
        &completion,
        &BuildOptions {
            store: src_store,
            cas: cas.clone(),
            image: "nix-closure.composefs".into(),
            threads: 1,
        },
    )
    .unwrap();

    // Materialize into an isolated local Nix root (`<nix_root>/nix/store`).
    let nix_root = root.join("nix-root");
    let dest_store = nix_root.join("nix/store");
    let report = checkout(&CheckoutOptions {
        cas: cas.clone(),
        image: "nix-closure.composefs".into(),
        dest: dest_store.clone(),
        subpath: None,
        require_verity: false,
        register_nix_db: false,
        print_nix_db: true,
        nix_store_prefix: "/nix/store".into(),
    })
    .unwrap();

    assert_eq!(report.nix_registered_paths, 3);
    assert_eq!(report.hardlinked_files, 2);
    assert_eq!(report.inlined_files, 1);
    assert_eq!(report.symlinks, 1);

    // Check golden NAR hash/size for `demo` ("hello\n" in `hi` -> sha256 6a43da..., size 288).
    let expected_demo_block = format!(
        "/nix/store/{demo}\n6a43da6ae68d8ca36f9e4542772d6a48dc22f50a2b59dd53f2a18629122eff51\n288\n\n0\n"
    );
    assert!(
        report.registration.contains(&expected_demo_block),
        "expected exact NAR registration block for {demo}, got:\n{}",
        report.registration
    );

    // Verify topological order: `dep` must appear before `app`, and `app` must reference `dep`.
    let dep_pos = report
        .registration
        .find(&format!("/nix/store/{dep}\n"))
        .unwrap();
    let app_pos = report
        .registration
        .find(&format!("/nix/store/{app}\n"))
        .unwrap();
    assert!(
        dep_pos < app_pos,
        "dep must precede app in registration:\n{}",
        report.registration
    );
    let app_tail = &report.registration[app_pos..];
    assert!(
        app_tail.contains(&format!("1\n/nix/store/{dep}\n")),
        "app must list reference to dep:\n{}",
        app_tail
    );

    // External checked-out store binaries remain hardlinked to CAS.
    assert_eq!(
        std::fs::metadata(dest_store.join(app).join("bin/wrapper"))
            .unwrap()
            .nlink(),
        2
    );
    assert_eq!(
        std::fs::metadata(dest_store.join(dep).join("bin/tool"))
            .unwrap()
            .nlink(),
        2
    );

    // When `nix-store` is available on PATH (dev/host runs; skipped inside pure nix build sandbox),
    // test the full `nix-composefs checkout --import` CLI flow plus `nix-store --verify-path` and `-qR`.
    if Command::new("nix-store").arg("--version").output().is_ok() {
        let cli_root = root.join("cli-nix-root");
        let cli_store = cli_root.join("nix/store");
        let nix_cfg = format!("store = local?root={}", cli_root.display());

        let cli_out = Command::new(env!("CARGO_BIN_EXE_nix-composefs"))
            .args([
                "checkout",
                "--cas",
                cas.to_str().unwrap(),
                "--image",
                "nix-closure.composefs",
                cli_store.to_str().unwrap(),
                "--import",
            ])
            .env("NIX_CONFIG", &nix_cfg)
            .output()
            .unwrap();
        assert!(
            cli_out.status.success(),
            "nix-composefs checkout --import failed: {}",
            String::from_utf8_lossy(&cli_out.stderr)
        );
        let stdout = String::from_utf8_lossy(&cli_out.stdout);
        assert!(stdout.contains("nix_db=3"), "unexpected stdout: {stdout}");

        let verify_out = Command::new("nix-store")
            .args([
                "--verify-path",
                &format!("/nix/store/{demo}"),
                &format!("/nix/store/{dep}"),
                &format!("/nix/store/{app}"),
            ])
            .env("NIX_CONFIG", &nix_cfg)
            .output()
            .unwrap();
        assert!(
            verify_out.status.success(),
            "nix-store --verify-path failed: {}",
            String::from_utf8_lossy(&verify_out.stderr)
        );

        let qr_out = Command::new("nix-store")
            .args(["-qR", &format!("/nix/store/{app}")])
            .env("NIX_CONFIG", &nix_cfg)
            .output()
            .unwrap();
        assert!(
            qr_out.status.success(),
            "nix-store -qR failed: {}",
            String::from_utf8_lossy(&qr_out.stderr)
        );
        let qr_str = String::from_utf8_lossy(&qr_out.stdout);
        assert!(qr_str.contains(&format!("/nix/store/{dep}")));
        assert!(qr_str.contains(&format!("/nix/store/{app}")));

        // Verify nix-store --load-db did NOT break hardlinks on the store objects!
        // Note: both `dest_store` and `cli_store` are hardlinked to `cas/objects`, so nlink >= 3.
        assert_eq!(
            std::fs::metadata(cli_store.join(app).join("bin/wrapper"))
                .unwrap()
                .nlink(),
            3
        );
    }
}

#[test]
fn import_directory_tree_creates_mountable_composefs_and_verity_objects() {
    // Prefer `CARGO_TARGET_DIR` (btrfs on this host) when writable outside Nix's `/build`
    // sandbox so real kernel fs-verity is exercised; fall back to `tempfile::tempdir()`.
    let td = std::env::var_os("CARGO_TARGET_DIR")
        .map(std::path::PathBuf::from)
        .filter(|p| !p.starts_with("/build") && p.is_dir())
        .and_then(|p| tempfile::tempdir_in(p).ok())
        .unwrap_or_else(|| tempfile::tempdir().unwrap());

    let root = td.path();
    let src = root.join("my-tree");
    let cas = root.join("cas");

    let script = format!("#!/bin/sh\n# {}\necho hi\n", "a".repeat(120));
    write_file_mode(&src.join("etc/inline.txt"), b"inline cfg\n", 0o644);
    write_file_mode(&src.join("share/blob.dat"), &[0x7eu8; 4096], 0o644);
    write_file_mode(&src.join("bin/app1"), script.as_bytes(), 0o755);
    std::fs::hard_link(src.join("bin/app1"), src.join("bin/app2")).unwrap();
    std::fs::set_permissions(
        src.join("etc"),
        std::fs::Permissions::from_mode(0o750),
    )
    .unwrap();
    std::os::unix::fs::symlink("../bin/app1", src.join("etc/link")).unwrap();

    // Run `nix-composefs import --cas <cas> <dir>/my-tree` (default ref: `my-tree.composefs`).
    let out = Command::new(env!("CARGO_BIN_EXE_nix-composefs"))
        .args([
            "import",
            "--cas",
            cas.to_str().unwrap(),
            src.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "nix-composefs import failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let img_ref = cas.join("images/refs/my-tree.composefs");
    assert!(img_ref.is_symlink() && img_ref.exists());

    // Every object under `cas/objects/xx/<62-hex>` must already have write bits stripped.
    let mut obj_count = 0usize;
    let mut has_exec = false;
    let mut has_ro_data = false;
    let mut any_verity = false;
    for dir_entry in std::fs::read_dir(cas.join("objects")).unwrap() {
        let dir_entry = dir_entry.unwrap();
        if !dir_entry.file_type().unwrap().is_dir() {
            continue;
        }
        for file_entry in std::fs::read_dir(dir_entry.path()).unwrap() {
            let file_entry = file_entry.unwrap();
            let path = file_entry.path();
            let mode = std::fs::metadata(&path).unwrap().mode() & 0o777;
            assert_eq!(mode & 0o222, 0, "object {:?} remained writable: {:o}", path, mode);
            if mode == 0o555 {
                has_exec = true;
            } else if mode == 0o444 {
                has_ro_data = true;
            }
            if let Ok(Some(_)) = composefs::fsverity::measure_verity_opt::<
                nix_composefs::Sha256HashValue,
            >(std::fs::File::open(&path).unwrap())
            {
                any_verity = true;
            }
            obj_count += 1;
        }
    }
    // app1/app2 deduplicated + blob.dat + EROFS image object = 3 objects.
    assert_eq!(obj_count, 3);
    assert!(has_exec && has_ro_data);

    if Command::new("fsck.erofs").arg("--version").output().is_ok() {
        let fsck = Command::new("fsck.erofs")
            .arg(&img_ref)
            .output()
            .unwrap();
        assert!(
            fsck.status.success(),
            "fsck.erofs failed: {}",
            String::from_utf8_lossy(&fsck.stderr)
        );
    }

    if Command::new("composefs-info").arg("--help").output().is_ok() {
        let missing = Command::new("composefs-info")
            .args([
                &format!("--basedir={}", cas.join("objects").display()),
                "missing-objects",
                img_ref.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(
            missing.status.success(),
            "composefs-info missing-objects failed: {}",
            String::from_utf8_lossy(&missing.stderr)
        );
        assert!(
            missing.stdout.is_empty(),
            "unexpected missing objects: {}",
            String::from_utf8_lossy(&missing.stdout)
        );

        let dump = Command::new("composefs-info")
            .args(["dump", img_ref.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(dump.status.success());
        let dump_str = String::from_utf8_lossy(&dump.stdout);
        let script_len = script.len();
        assert!(
            dump_str.contains(&format!("/bin/app1 {script_len} 100755 ")),
            "{}",
            dump_str
        );
        assert!(
            dump_str.contains(&format!("/bin/app2 {script_len} @100755 "))
                && dump_str.contains(" /bin/app1 "),
            "{}",
            dump_str
        );
        assert!(dump_str.contains("/etc/inline.txt 11 100644 "), "{}", dump_str);
        assert!(dump_str.contains("/etc/link 11 120777 "), "{}", dump_str);
    }

    // Round-trip checkout back into a fresh directory (enforcing fs-verity if kernel enabled it).
    let roundtrip = root.join("roundtrip");
    let ck = checkout(&CheckoutOptions {
        cas: cas.clone(),
        image: "my-tree.composefs".into(),
        dest: roundtrip.clone(),
        subpath: None,
        require_verity: any_verity,
        register_nix_db: false,
        print_nix_db: false,
        nix_store_prefix: "/nix/store".into(),
    })
    .unwrap();
    assert_eq!(ck.hardlinked_files, 3);
    assert_eq!(ck.inlined_files, 1);
    assert_eq!(ck.symlinks, 1);
    if any_verity {
        assert_eq!(ck.verity_enabled, 3);
    }
    assert_eq!(std::fs::read(roundtrip.join("etc/inline.txt")).unwrap(), b"inline cfg\n");
    assert_eq!(std::fs::read(roundtrip.join("share/blob.dat")).unwrap(), &[0x7eu8; 4096]);
    assert_eq!(
        std::fs::read_link(roundtrip.join("etc/link")).unwrap(),
        Path::new("../bin/app1")
    );
}
