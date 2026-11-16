//! Tests for hardlink- and EROFS-anchor-aware garbage collection.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use composefs::erofs::reader::collect_objects;
use composefs::fsverity::{FsVerityHashValue, Sha256HashValue};
use nix_composefs::build::{build, BuildOptions};
use nix_composefs::gc::{gc, GcOptions};
use nix_composefs::store::StorePath;

fn write(path: &Path, content: &[u8]) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, content).unwrap();
}

fn list_object_files(cas: &Path) -> HashSet<PathBuf> {
    let mut out = HashSet::new();
    let objects_dir = cas.join("objects");
    if !objects_dir.is_dir() {
        return out;
    }
    for subdir in std::fs::read_dir(&objects_dir).unwrap() {
        let subdir = subdir.unwrap();
        if !subdir.file_type().unwrap().is_dir() {
            continue;
        }
        for entry in std::fs::read_dir(subdir.path()).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_file() {
                out.insert(entry.path());
            }
        }
    }
    out
}

fn image_backing_objects(image_path: &Path) -> HashSet<Sha256HashValue> {
    let bytes = std::fs::read(image_path).unwrap();
    collect_objects::<Sha256HashValue>(&bytes).unwrap()
}

fn image_object_id(cas: &Path, image_ref: &str) -> Sha256HashValue {
    let link = std::fs::read_link(cas.join("images/refs").join(image_ref)).unwrap();
    let hex = link.file_name().unwrap().to_str().unwrap();
    Sha256HashValue::from_hex(hex).unwrap()
}

fn object_path(cas: &Path, id: &Sha256HashValue) -> PathBuf {
    cas.join("objects").join(id.to_object_pathname())
}

#[test]
fn gc_keeps_referenced_and_removes_unreferenced_single_link_objects() {
    let td = tempfile::tempdir().unwrap();
    let root = td.path();
    let store = root.join("store");
    let cas = root.join("cas");

    let entry_a = "g1w7hy3qg1w7hy3qg1w7hy3qg1w7hy3q-alpha";
    let entry_b = "h2w7hy3qh2w7hy3qh2w7hy3qh2w7hy3q-beta";
    write(&store.join(entry_a).join("bin/a"), &[0x11; 4096]);
    write(&store.join(entry_b).join("bin/b"), &[0x22; 4096]);

    build(
        &[StorePath::parse(entry_a).unwrap()],
        &BuildOptions {
            store: store.clone(),
            cas: cas.clone(),
            image: "image-a".into(),
            threads: 1,
        },
    )
    .unwrap();

    build(
        &[StorePath::parse(entry_b).unwrap()],
        &BuildOptions {
            store,
            cas: cas.clone(),
            image: "image-b".into(),
            threads: 1,
        },
    )
    .unwrap();

    let id_a = image_object_id(&cas, "image-a");
    let id_b = image_object_id(&cas, "image-b");
    let objs_a = image_backing_objects(&cas.join("images/refs/image-a"));
    let objs_b = image_backing_objects(&cas.join("images/refs/image-b"));
    assert_eq!(objs_a.len(), 1);
    assert_eq!(objs_b.len(), 1);
    let file_a = objs_a.into_iter().next().unwrap();
    let file_b = objs_b.into_iter().next().unwrap();

    // Unanchor image-b.
    std::fs::remove_file(cas.join("images/refs/image-b")).unwrap();

    let dry = gc(&GcOptions {
        cas: cas.clone(),
        roots: vec![],
        dry_run: true,
    })
    .unwrap();
    assert_eq!(dry.objects_reachable, 2);
    assert_eq!(dry.objects_removed, 2);
    assert_eq!(dry.images_pruned, 1);
    assert!(object_path(&cas, &id_b).exists());
    assert!(object_path(&cas, &file_b).exists());
    assert!(cas.join("images").join(id_b.to_hex()).is_symlink());

    let real = gc(&GcOptions {
        cas: cas.clone(),
        roots: vec![],
        dry_run: false,
    })
    .unwrap();
    assert_eq!(real, dry);
    assert!(object_path(&cas, &id_a).exists());
    assert!(object_path(&cas, &file_a).exists());
    assert!(!object_path(&cas, &id_b).exists());
    assert!(!object_path(&cas, &file_b).exists());
    assert!(!cas.join("images").join(id_b.to_hex()).exists());
}

#[test]
fn gc_preserves_hardlinked_objects_until_external_link_removed() {
    let td = tempfile::tempdir().unwrap();
    let root = td.path();
    let store = root.join("store");
    let cas = root.join("cas");

    let entry = "g1w7hy3qg1w7hy3qg1w7hy3qg1w7hy3q-bundle";
    write(&store.join(entry).join("bin/keep"), &[0x33; 4096]);
    write(&store.join(entry).join("bin/drop"), &[0x44; 4096]);

    build(
        &[StorePath::parse(entry).unwrap()],
        &BuildOptions {
            store,
            cas: cas.clone(),
            image: "system.composefs".into(),
            threads: 1,
        },
    )
    .unwrap();

    let image_id = image_object_id(&cas, "system.composefs");
    let mut backing: Vec<PathBuf> = image_backing_objects(&cas.join("images/refs/system.composefs"))
        .into_iter()
        .map(|id| object_path(&cas, &id))
        .collect();
    backing.sort();
    assert_eq!(backing.len(), 2);

    // Unanchor the EROFS image ref, and extract one backing object via hardlink.
    std::fs::remove_file(cas.join("images/refs/system.composefs")).unwrap();
    let extracted_dir = root.join("extracted");
    std::fs::create_dir_all(&extracted_dir).unwrap();
    let extracted_file = extracted_dir.join("app");
    std::fs::hard_link(&backing[0], &extracted_file).unwrap();

    let first = gc(&GcOptions {
        cas: cas.clone(),
        roots: vec![],
        dry_run: false,
    })
    .unwrap();
    assert_eq!(first.objects_hardlinked_kept, 1);
    assert_eq!(first.hardlinked_bytes, 4096);
    assert_eq!(first.objects_removed, 2);
    assert!(backing[0].exists(), "hardlinked object must survive GC");
    assert!(!backing[1].exists(), "unlinked object must be removed");
    assert!(!object_path(&cas, &image_id).exists());

    // Dropping the external hardlink lets GC collect the object.
    std::fs::remove_file(&extracted_file).unwrap();
    let second = gc(&GcOptions {
        cas: cas.clone(),
        roots: vec![],
        dry_run: false,
    })
    .unwrap();
    assert_eq!(second.objects_hardlinked_kept, 0);
    assert_eq!(second.objects_removed, 1);
    assert!(list_object_files(&cas).is_empty());
}

#[test]
fn gc_preserves_closure_of_hardlinked_erofs_image() {
    let td = tempfile::tempdir().unwrap();
    let root = td.path();
    let store = root.join("store");
    let cas = root.join("cas");

    let entry = "g1w7hy3qg1w7hy3qg1w7hy3qg1w7hy3q-slot";
    write(&store.join(entry).join("bin/one"), &[0x55; 4096]);
    write(&store.join(entry).join("bin/two"), &[0x66; 4096]);

    build(
        &[StorePath::parse(entry).unwrap()],
        &BuildOptions {
            store,
            cas: cas.clone(),
            image: "system.composefs".into(),
            threads: 1,
        },
    )
    .unwrap();

    let image_id = image_object_id(&cas, "system.composefs");
    let erofs_obj = object_path(&cas, &image_id);

    // Hardlink the EROFS image object itself into an active slot dir, then drop images/refs/.
    let slot_dir = root.join("slot-101");
    std::fs::create_dir_all(&slot_dir).unwrap();
    let slot_image = slot_dir.join("system.composefs");
    std::fs::hard_link(&erofs_obj, &slot_image).unwrap();
    std::fs::remove_file(cas.join("images/refs/system.composefs")).unwrap();

    // Backing file objects still have nlink == 1, yet must stay alive because
    // the hardlinked EROFS image in images/ acts as an anchor.
    let first = gc(&GcOptions {
        cas: cas.clone(),
        roots: vec![],
        dry_run: false,
    })
    .unwrap();
    assert_eq!(first.objects_reachable, 3);
    assert_eq!(first.objects_removed, 0);
    assert_eq!(list_object_files(&cas).len(), 3);

    // Removing the slot hardlink drops the anchor.
    std::fs::remove_file(&slot_image).unwrap();
    let second = gc(&GcOptions {
        cas: cas.clone(),
        roots: vec![],
        dry_run: false,
    })
    .unwrap();
    assert_eq!(second.objects_removed, 3);
    assert_eq!(second.images_pruned, 1);
    assert!(list_object_files(&cas).is_empty());
}

#[test]
fn gc_supports_external_erofs_anchor_and_tolerates_sig_sidecars() {
    let td = tempfile::tempdir().unwrap();
    let root = td.path();
    let store = root.join("store");
    let cas = root.join("cas");

    let entry_a = "g1w7hy3qg1w7hy3qg1w7hy3qg1w7hy3q-fw";
    let entry_b = "h2w7hy3qh2w7hy3qh2w7hy3qh2w7hy3q-old";
    write(&store.join(entry_a).join("lib/fw.bin"), &[0x77; 4096]);
    write(&store.join(entry_b).join("lib/old.bin"), &[0x88; 4096]);

    build(
        &[StorePath::parse(entry_a).unwrap()],
        &BuildOptions {
            store: store.clone(),
            cas: cas.clone(),
            image: "fw.composefs".into(),
            threads: 1,
        },
    )
    .unwrap();

    build(
        &[StorePath::parse(entry_b).unwrap()],
        &BuildOptions {
            store,
            cas: cas.clone(),
            image: "old.composefs".into(),
            threads: 1,
        },
    )
    .unwrap();

    let id_a = image_object_id(&cas, "fw.composefs");
    let id_b = image_object_id(&cas, "old.composefs");
    let backing_a = image_backing_objects(&cas.join("images/refs/fw.composefs"));
    assert_eq!(backing_a.len(), 1);
    let obj_a = backing_a.into_iter().next().unwrap();

    // Copy fw.composefs externally (no hardlink), remove in-repo image symlinks,
    // and leave sign.sh-style sidecars inside images/refs/.
    let external_dir = root.join("external");
    std::fs::create_dir_all(&external_dir).unwrap();
    let external_anchor = external_dir.join("fw.composefs");
    std::fs::copy(cas.join("images/refs/fw.composefs"), &external_anchor).unwrap();

    std::fs::remove_file(cas.join("images/refs/fw.composefs")).unwrap();
    std::fs::remove_file(cas.join("images/refs/old.composefs")).unwrap();
    std::fs::remove_file(cas.join("images").join(id_a.to_hex())).unwrap();
    std::fs::remove_file(cas.join("images").join(id_b.to_hex())).unwrap();

    let sig_file = cas.join("images/refs/fw.composefs.sig");
    let db_sig_file = cas.join("images/refs/fw.composefs.1234abcd.db.sig");
    std::fs::write(&sig_file, b"sig").unwrap();
    std::fs::write(&db_sig_file, b"dbsig").unwrap();

    let report = gc(&GcOptions {
        cas: cas.clone(),
        roots: vec![external_anchor.to_string_lossy().into_owned()],
        dry_run: false,
    })
    .unwrap();

    assert_eq!(report.objects_reachable, 1);
    assert_eq!(report.objects_removed, 3);
    assert!(object_path(&cas, &obj_a).exists());
    assert_eq!(list_object_files(&cas).len(), 1);
    assert!(sig_file.exists());
    assert!(db_sig_file.exists());
}
