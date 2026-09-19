//! End-to-end: fake store -> build -> manifest -> materialize -> compare,
//! plus sign/verify roundtrip. Runs without kernel fs-verity (insecure mode).

use std::os::unix::fs::MetadataExt;
use std::path::Path;

use nix_composefs::build::{BuildOptions, build};
use nix_composefs::cas::Cas;
use nix_composefs::manifest::Manifest;
use nix_composefs::store::{StorePath, read_completion};
use nix_composefs::sync;
use nix_composefs::{FsVerityHashValue, Sha256HashValue};

fn write(path: &Path, content: &[u8]) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, content).unwrap();
}

#[test]
fn build_materialize_roundtrip() {
    let td = tempfile::tempdir().unwrap();
    let root = td.path();

    // --- Fake store -------------------------------------------------------
    let store = root.join("store");
    let big = vec![0x5au8; 4096 * 3 + 17];
    let small = b"tiny file\n";
    write(&store.join("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bash/bin/bash"), &big);
    write(&store.join("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bash/bin/small"), small);
    write(&store.join("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bash/lib/libfoo.so"), &big);
    std::fs::create_dir_all(store.join("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-bash/bin")).unwrap();
    // Same content as ...-bash/bin/bash -> must dedup to one CAS object.
    write(&store.join("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-bash/bin/bash2"), &big);
    std::os::unix::fs::symlink("bash", store.join("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bash/bin/link")).unwrap();

    let completion = root.join("completion.txt");
    std::fs::write(
        &completion,
        "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bash\n\
         # comment\n\
         bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-bash\n",
    )
    .unwrap();

    // --- Build ------------------------------------------------------------
    let cas = root.join("cas");
    let image = root.join("system.composefs");
    let manifest_path = root.join("system.json");
    let completion_paths = read_completion(&completion).unwrap();
    let opts = BuildOptions {
        store: store.clone(),
        cas: cas.clone(),
        image: image.clone(),
        manifest: Some(manifest_path.clone()),
        name: "test-closure".into(),
        threads: 2,
        insecure: true,
    };
    let (report, m) = build(&completion_paths, &opts).unwrap();

    assert!(image.is_file(), "image written");
    assert_eq!(report.entries, 2);
    assert!(report.files >= 4, "files counted: {}", report.files);
    assert_eq!(report.symlinks, 1);
    // big content shared by 3 paths -> 1 object; small file -> 1 object.
    assert_eq!(report.objects, 2, "objects: {:?}", m.objects);
    let big_obj = m
        .objects
        .iter()
        .find(|o| o.size == big.len() as u64)
        .unwrap();
    assert_eq!(big_obj.count, 3, "dedup across store entries");
    assert!(!m.image.verity.is_empty());

    // Missing on a fresh CAS: all objects; on our CAS: none.
    let fresh = Cas::open(&root.join("cas-fresh"), 1, true).unwrap();
    assert_eq!(sync::missing_objects(&m, &fresh).unwrap().len(), 2);
    let our_cas = Cas::open(&cas, 1, true).unwrap();
    assert!(sync::missing_objects(&m, &our_cas).unwrap().is_empty());

    // --- Materialize --------------------------------------------------------
    let new_store = root.join("store2");
    let r = sync::materialize(&m, &our_cas, &new_store, false).unwrap();
    assert!(r.hardlinks >= 4, "hardlinks: {r:?}");

    // Tree comparison.
    for (sub, content) in [
        ("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bash/bin/bash", big.as_slice()),
        ("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-bash/bin/bash2", big.as_slice()),
        ("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bash/lib/libfoo.so", big.as_slice()),
        ("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bash/bin/small", small),
    ] {
        let p = new_store.join(sub);
        let stored = std::fs::read(&p).unwrap_or_else(|e| panic!("{sub}: {e}"));
        assert_eq!(stored, content, "content mismatch in {sub}");
        // Hard-linked into the CAS.
        let digest = m
            .objects
            .iter()
            .find(|o| o.size == content.len() as u64)
            .unwrap()
            .digest
            .clone();
        let cas_obj = our_cas.object_path(&Sha256HashValue::from_hex(&digest).unwrap());
        let sa = std::fs::symlink_metadata(&p).unwrap();
        let sb = std::fs::symlink_metadata(&cas_obj).unwrap();
        assert_eq!(sa.ino(), sb.ino(), "{sub} not hard-linked to CAS");
    }

    let link = new_store.join("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bash/bin/link");
    let target = std::fs::read_link(&link).unwrap();
    assert_eq!(target.to_string_lossy().as_ref(), "bash");

    // Re-materializing is idempotent: files stay hard-linked, nothing new.
    let r2 = sync::materialize(&m, &our_cas, &new_store, false).unwrap();
    assert_eq!(r2.hardlinks, r.hardlinks, "{r2:?}");
    assert_eq!(r2.symlinks, 0, "{r2:?}");
    assert_eq!(r2.existing, 1, "the symlink is pre-existing: {r2:?}");
}

#[test]
fn sign_verify_roundtrip_on_image() {
    let td = tempfile::tempdir().unwrap();
    let root = td.path();

    let store = root.join("store");
    write(
        &store.join("cccccccccccccccccccccccccccccccc-demo/bin/app"),
        &[0x7cu8; 1000],
    );
    let completion = root.join("completion.txt");
    std::fs::write(&completion, "cccccccccccccccccccccccccccccccc-demo\n").unwrap();

    let cas = root.join("cas");
    let image = root.join("demo.composefs");
    let opts = BuildOptions {
        store,
        cas: cas.clone(),
        image: image.clone(),
        manifest: Some(root.join("demo.json")),
        name: "sign-test".into(),
        threads: 1,
        insecure: true,
    };
    build(&[StorePath::parse("cccccccccccccccccccccccccccccccc-demo").unwrap()], &opts).unwrap();

    let secrets = root.join("secrets");
    nix_composefs::sign::genkeys(&secrets).unwrap();
    let written = nix_composefs::sign::sign_image(&image, &secrets).unwrap();
    assert_eq!(written.len(), 1, "only ed25519 key present: {written:?}");

    let pub_b64 = std::fs::read_to_string(secrets.join("image_key.pub.b64")).unwrap();
    assert!(nix_composefs::sign::verify_image(&image, pub_b64.trim()).unwrap());

    let m = Manifest::load(&root.join("demo.json")).unwrap();
    assert_eq!(m.image.verity, nix_composefs::sign::digest_of(&image, false).unwrap().to_hex());
}
