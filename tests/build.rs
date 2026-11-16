//! Build a Nix32-named closure into a composefs digest store and image ref tree.

use std::path::Path;

use nix_composefs::build::{build, BuildOptions};
use nix_composefs::store::{read_completion, StorePath};

fn write(path: &Path, content: &[u8]) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, content).unwrap();
}

#[test]
fn build_populates_repository_from_nix32_completion() {
    let td = tempfile::tempdir().unwrap();
    let root = td.path();
    let store = root.join("store");
    let entry = "g1w7hy3qg1w7hy3qg1w7hy3qg1w7hy3q-demo";
    write(&store.join(entry).join("bin/app"), &[0x7c; 4096]);
    std::os::unix::fs::symlink("app", store.join(entry).join("bin/link")).unwrap();
    let singleton = "h2w7hy3qh2w7hy3qh2w7hy3qh2w7hy3q-generated-file";
    write(&store.join(singleton), &[0x2a; 4096]);

    let completion = root.join("completion.txt");
    std::fs::write(
        &completion,
        format!("/nix/store/{entry}\n/nix/store/{singleton}\n"),
    )
    .unwrap();
    let paths = read_completion(&completion).unwrap();
    assert_eq!(
        paths,
        vec![
            StorePath::parse(entry).unwrap(),
            StorePath::parse(singleton).unwrap()
        ]
    );

    let cas = root.join("repository");
    let image = "system.composefs";
    let report = build(
        &paths,
        &BuildOptions {
            store: store.clone(),
            cas: cas.clone(),
            image: image.into(),
            threads: 1,
        },
    )
    .unwrap();

    assert_eq!(report.entries, 2);
    assert!(
        !cas.join("meta.json").exists(),
        "meta.json is strictly optional and not emitted by default"
    );
    assert!(cas.join("images/refs/system.composefs").is_symlink());
    assert!(cas.join("images/refs/system.composefs").exists());
    assert!(
        std::fs::read_dir(cas.join("objects"))
            .unwrap()
            .next()
            .is_some(),
        "repository object store is populated"
    );

    // Compatible optional meta.json works identically.
    std::fs::write(
        cas.join("meta.json"),
        r#"{"version":1,"algorithm":"fsverity-sha256-12"}"#,
    )
    .unwrap();
    let nested = build(
        &paths,
        &BuildOptions {
            store: store.clone(),
            cas: cas.clone(),
            image: "slots/101.composefs".into(),
            threads: 1,
        },
    )
    .unwrap();
    assert_eq!(nested.entries, 2);
    assert!(cas.join("images/refs/slots/101.composefs").exists());

    // Incompatible meta.json algorithm is rejected.
    std::fs::write(
        cas.join("meta.json"),
        r#"{"version":1,"algorithm":"fsverity-sha512-12"}"#,
    )
    .unwrap();
    assert!(build(
        &paths,
        &BuildOptions {
            store,
            cas,
            image: "bad.composefs".into(),
            threads: 1,
        },
    )
    .is_err());
}
