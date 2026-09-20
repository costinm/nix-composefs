//! Build a Nix32-named closure into an upstream composefs repository.

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
    let image = root.join("system.composefs");
    let report = build(
        &paths,
        &BuildOptions {
            store,
            cas: cas.clone(),
            image: image.clone(),
            threads: 1,
        },
    )
    .unwrap();

    assert_eq!(report.entries, 2);
    assert!(image.is_file());
    assert!(cas.join("meta.json").is_file());
    assert!(
        std::fs::read_dir(cas.join("objects"))
            .unwrap()
            .next()
            .is_some(),
        "repository object store is populated"
    );
}
