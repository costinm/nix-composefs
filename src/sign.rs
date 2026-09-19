//! Signing and verification, compatible with the initos erofs conventions.
//!
//! - Ed25519: `<image>.sig` — 64-byte signature over the raw fs-verity
//!   digest, key `${SECRETS}/image_key.pem` (PKCS#8). Verified with the
//!   base64 raw public key (`image_key.pub.b64`), exactly what `initos
//!   verify` checks.
//! - UEFI db: `<image>.<key-id>.db.sig` — PKCS#1 v1.5 SHA-256 over the
//!   fs-verity digest, key `${SECRETS}/db.key`, key-id = first 16 hex of
//!   SHA-256(SPI DER of `${SECRETS}/db.crt`). Verified the way `initos
//!   verify` checks db certificates.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use composefs::fsverity::{Sha256HashValue, measure_verity_opt, enable_verity_raw};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::{Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};
use x509_cert::der::{Decode, Encode};
use x509_cert::Certificate;
use zerocopy::IntoBytes;

/// File-suffix convention shared with initos (`initos verify`).
fn signature_path(img: &Path, suffix: &str) -> PathBuf {
    img.with_extension(
        img.extension()
            .map(|e| format!("{}.{}", e.to_string_lossy(), suffix))
            .unwrap_or_else(|| suffix.to_string()),
    )
}

/// Measure the image fs-verity digest (kernel if enabled, enable-on-demand
/// like `initos verify`, userspace fallback otherwise).
pub fn digest_of(image: &Path, allow_enable: bool) -> Result<Sha256HashValue> {
    let fd = std::fs::File::open(image)
        .with_context(|| format!("opening image {:?}", image))?;
    if let Some(d) = measure_verity_opt::<Sha256HashValue>(&fd)? {
        return Ok(d);
    }
    if allow_enable {
        if let Ok(()) = enable_verity_raw::<Sha256HashValue>(&fd) {
            return measure_verity_opt::<Sha256HashValue>(&fd)?
                .context("measure after enable");
        }
    }
    // Userspace fallback (dev machines without kernel fs-verity).
    crate::cas::userspace_verity(&mut std::io::BufReader::new(
        std::fs::File::open(image)
            .with_context(|| format!("opening image {:?}", image))?,
    ))
}

/// Ed25519 seed from an OpenSSL-generated PKCS#8 PEM key: the last 32 bytes
/// of the DER encoding (mirrors `openssl pkey -outform DER | tail -c 32`).
pub fn ed25519_seed_from_pem(pem: &str) -> Result<[u8; 32]> {
    let b64: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .filter(|l| !l.trim().is_empty())
        .collect();
    let der = base64_decode(&b64).context("base64-decoding PEM")?;
    if der.len() < 32 {
        bail!("PKCS#8 DER too short: {} bytes", der.len());
    }
    Ok(der[der.len() - 32..].try_into().unwrap())
}

pub fn base64_decode(s: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| anyhow::anyhow!("bad base64: {e}"))
}

pub fn base64_encode(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(b)
}

/// Generate an Ed25519 image-signing keypair in initos layout:
/// `image_key.pem` (PKCS#8), `image_key_pub.pem` (SPKI),
/// `image_key.pub.b64` (raw 32-byte public key).
pub fn genkeys(secrets: &Path) -> Result<(SigningKey, PathBuf)> {
    use rand_core::OsRng;
    std::fs::create_dir_all(secrets)?;
    let signing = SigningKey::generate(&mut OsRng);
    let seed = signing.to_bytes();

    // Minimal PKCS#8 envelope for Ed25519 (same bytes OpenSSL emits).
    let pkcs8: Vec<u8> = vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x21, 0x00,
    ]
    .into_iter()
    .chain(seed.iter().copied())
    .collect();
    let pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        base64_encode(&pkcs8)
    );
    let key_path = secrets.join("image_key.pem");
    std::fs::write(&key_path, pem)?;

    let spki: Vec<u8> = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ]
    .into_iter()
    .chain(signing.verifying_key().to_bytes().iter().copied())
    .collect();
    std::fs::write(
        secrets.join("image_key_pub.pem"),
        format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            base64_encode(&spki)
        ),
    )?;
    std::fs::write(
        secrets.join("image_key.pub.b64"),
        base64_encode(signing.verifying_key().as_bytes()),
    )?;
    Ok((signing, key_path))
}

/// Sign an image with everything available under `secrets`. Returns the
/// signature file paths written.
pub fn sign_image(image: &Path, secrets: &Path) -> Result<Vec<PathBuf>> {
    let digest = digest_of(image, true)?;
    let mut written = Vec::new();

    let key_pem = secrets.join("image_key.pem");
    if key_pem.is_file() {
        let pem = std::fs::read_to_string(&key_pem)
            .with_context(|| format!("reading {key_pem:?}"))?;
        let seed = ed25519_seed_from_pem(&pem)?;
        let signing = SigningKey::from_bytes(&seed);
        let sig = signing.sign(digest.as_bytes());
        let sig_path = signature_path(image, "sig");
        std::fs::write(&sig_path, sig.to_bytes())
            .with_context(|| format!("writing {sig_path:?}"))?;
        written.push(sig_path);
    }

    let db_key = secrets.join("db.key");
    let db_crt = secrets.join("db.crt");
    if db_key.is_file() {
        if !db_crt.is_file() {
            bail!("{} present but {} missing", db_key.display(), db_crt.display());
        }
        let key_id = cert_key_id(&db_crt)?;
        let db_key_pem = std::fs::read_to_string(&db_key)
            .with_context(|| format!("reading {db_key:?}"))?;
        let db_key_der = pem_to_der(&db_key_pem).with_context(|| format!("parsing {db_key:?}"))?;
        let rsa_key = RsaPrivateKey::from_pkcs8_der(&db_key_der)
            .with_context(|| format!("parsing {db_key:?}"))?;
        let sig = rsa_key
            .sign(Pkcs1v15Sign::new::<Sha256>(), digest.as_bytes())
            .context("RSA signing")?;
        let sig_path = signature_path(image, &format!("{key_id}.db.sig"));
        std::fs::write(&sig_path, sig)
            .with_context(|| format!("writing {sig_path:?}"))?;
        written.push(sig_path);
    }

    if written.is_empty() {
        bail!(
            "no signing keys in {:?} (expected image_key.pem and/or db.key+db.crt)",
            secrets
        );
    }
    Ok(written)
}

/// Verify the Ed25519 signature of an image's fs-verity digest.
pub fn verify_image(image: &Path, pub_key_b64: &str) -> Result<bool> {
    let digest = digest_of(image, true)?;
    let sig_path = signature_path(image, "sig");
    let sig_bytes = std::fs::read(&sig_path)
        .with_context(|| format!("reading signature {sig_path:?}"))?;
    if sig_bytes.len() != 64 {
        bail!("signature must be 64 bytes, got {}", sig_bytes.len());
    }
    let pub_bytes = base64_decode(pub_key_b64).context("decoding public key")?;
    if pub_bytes.len() != 32 {
        bail!("public key must be 32 bytes, got {}", pub_bytes.len());
    }
    let vk = VerifyingKey::from_bytes(pub_bytes.as_slice().try_into().unwrap())
        .map_err(|e| anyhow::anyhow!("bad public key: {e}"))?;
    let sig = Signature::from_bytes(sig_bytes.as_slice().try_into().unwrap());
    Ok(vk.verify_strict(digest.as_bytes(), &sig).is_ok())
}

/// Verify the UEFI db (RSA) signature of an image against one certificate.
pub fn verify_image_db(image: &Path, db_crt: &Path) -> Result<bool> {
    let digest = digest_of(image, true)?;
    let key_id = cert_key_id(db_crt)?;
    let sig_path = signature_path(image, &format!("{key_id}.db.sig"));
    let sig_bytes = match std::fs::read(&sig_path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e).with_context(|| format!("reading {sig_path:?}")),
    };
    let cert_pem =
        std::fs::read_to_string(db_crt).with_context(|| format!("reading {db_crt:?}"))?;
    let cert_der = pem_to_der(&cert_pem)?;
    let cert = Certificate::from_der(&cert_der)
        .with_context(|| format!("parsing certificate {db_crt:?}"))?;
    let rsa_pub_der = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .context("certificate is not an RSA key")?;
    let rsa_pub =
        RsaPublicKey::from_pkcs1_der(rsa_pub_der).context("parsing RSA public key")?;
    let mut h = Sha256::new();
    h.update(digest.as_bytes());
    Ok(rsa_pub
        .verify(Pkcs1v15Sign::new::<Sha256>(), &h.finalize(), &sig_bytes)
        .is_ok())
}

/// First 16 hex chars of SHA-256(SPI DER) — the initos db key id.
pub fn cert_key_id(db_crt: &Path) -> Result<String> {
    let cert_pem =
        std::fs::read_to_string(db_crt).with_context(|| format!("reading {db_crt:?}"))?;
    let cert_der = pem_to_der(&cert_pem)?;
    let cert = Certificate::from_der(&cert_der)
        .with_context(|| format!("parsing certificate {db_crt:?}"))?;
    let spki_der = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .context("encoding SPKI")?;
    let digest = Sha256::digest(&spki_der);
    Ok(hex::encode(&digest[..8]))
}

fn pem_to_der(pem: &str) -> Result<Vec<u8>> {
    let b64: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .filter(|l| !l.trim().is_empty())
        .collect();
    base64_decode(&b64).context("PEM body")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_image(data: &[u8]) -> (tempfile::TempDir, PathBuf) {
        let td = tempfile::tempdir().unwrap();
        let p = td.path().join("img.composefs");
        std::fs::write(&p, data).unwrap();
        (td, p)
    }

    #[test]
    fn sign_verify_ed25519_roundtrip() {
        let (td, image) = tmp_image(b"fake composefs image content for signing");
        let secrets = td.path().join("secrets");
        genkeys(&secrets).unwrap();
        sign_image(&image, &secrets).unwrap();
        let pub_b64 = std::fs::read_to_string(secrets.join("image_key.pub.b64")).unwrap();
        assert!(verify_image(&image, pub_b64.trim()).unwrap());
        // Tampered image fails.
        let (_td2, image2) = tmp_image(b"tampered content");
        std::fs::write(signature_path(&image2, "sig"), std::fs::read(signature_path(&image, "sig")).unwrap()).unwrap();
        assert!(!verify_image(&image2, pub_b64.trim()).unwrap());
    }

    #[test]
    fn genkeys_layout() {
        let td = tempfile::tempdir().unwrap();
        let (signing, key_path) = genkeys(td.path()).unwrap();
        assert!(key_path.is_file());
        let pem = std::fs::read_to_string(&key_path).unwrap();
        let seed = ed25519_seed_from_pem(&pem).unwrap();
        assert_eq!(seed, signing.to_bytes());
        let pub_b64 = std::fs::read_to_string(td.path().join("image_key.pub.b64")).unwrap();
        assert_eq!(base64_decode(&pub_b64).unwrap(), signing.verifying_key().to_bytes());
    }

    #[test]
    fn digest_matches_userspace() {
        let (_td, image) = tmp_image(&[0xabu8; 10000]);
        let d = digest_of(&image, false).unwrap();
        let h = crate::cas::userspace_verity(&mut std::io::Cursor::new(&[0xabu8; 10000])).unwrap();
        assert_eq!(d, h);
    }
}
