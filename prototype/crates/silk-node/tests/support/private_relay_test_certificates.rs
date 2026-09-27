//! Ephemeral, standard-OpenSSL certificates for private transport tests only.
//! The caller's RAII temporary root owns every file, including all private keys.

use sha2::{Digest as _, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

#[allow(dead_code)] // Shared with the lib fixture, which already has its own RAII root.
pub struct TemporaryRoot(pub PathBuf);

impl TemporaryRoot {
    #[allow(dead_code)]
    pub fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "silknode-private-tls-test-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        silk_local_platform::protect_private_directory(&path).unwrap();
        Self(fs::canonicalize(path).unwrap())
    }
}

impl Drop for TemporaryRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn protect_key(path: &Path) {
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    silk_local_platform::protect_private_file(&file, path).unwrap();
}

fn openssl(root: &Path, args: &[&str]) {
    let status = Command::new("openssl")
        .current_dir(root)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("test certificate generation requires the system OpenSSL executable");
    assert!(
        status.success(),
        "OpenSSL test certificate generation failed"
    );
}

pub fn generate(root: &Path, identities: usize) {
    assert!(identities > 0 && identities <= 32);
    fs::create_dir(root).unwrap();
    silk_local_platform::protect_private_directory(root).unwrap();
    fs::write(root.join("ca.cnf"), "[req]\ndistinguished_name=dn\nx509_extensions=ca\nprompt=no\n[dn]\nCN=SilkNode temporary test CA\n[ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n").unwrap();
    fs::write(root.join("leaf.cnf"), "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=IP:127.0.0.1,IP:::1\nauthorityKeyIdentifier=keyid,issuer\nsubjectKeyIdentifier=hash\n").unwrap();
    openssl(
        root,
        &[
            "genpkey",
            "-algorithm",
            "EC",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-out",
            "ca-key.pem",
        ],
    );
    protect_key(&root.join("ca-key.pem"));
    openssl(
        root,
        &[
            "req",
            "-new",
            "-x509",
            "-key",
            "ca-key.pem",
            "-sha256",
            "-days",
            "2",
            "-config",
            "ca.cnf",
            "-out",
            "ca.pem",
        ],
    );
    openssl(
        root,
        &["x509", "-in", "ca.pem", "-outform", "DER", "-out", "ca.der"],
    );
    for index in 0..identities {
        let key = format!("leaf-{index}-key.pem");
        let request = format!("leaf-{index}.csr");
        let cert = format!("leaf-{index}.pem");
        let cert_der = format!("leaf-{index}.der");
        let key_der = format!("leaf-{index}-key.der");
        let subject = format!("/CN=silknode-private-test-{index}");
        let serial = (index + 1).to_string();
        openssl(
            root,
            &[
                "genpkey",
                "-algorithm",
                "EC",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-out",
                &key,
            ],
        );
        protect_key(&root.join(&key));
        openssl(
            root,
            &[
                "req", "-new", "-key", &key, "-subj", &subject, "-out", &request,
            ],
        );
        openssl(
            root,
            &[
                "x509",
                "-req",
                "-in",
                &request,
                "-CA",
                "ca.pem",
                "-CAkey",
                "ca-key.pem",
                "-set_serial",
                &serial,
                "-days",
                "2",
                "-sha256",
                "-extfile",
                "leaf.cnf",
                "-out",
                &cert,
            ],
        );
        openssl(
            root,
            &["x509", "-in", &cert, "-outform", "DER", "-out", &cert_der],
        );
        openssl(
            root,
            &[
                "pkcs8", "-topk8", "-nocrypt", "-in", &key, "-outform", "DER", "-out", &key_der,
            ],
        );
        protect_key(&root.join(&key_der));
    }
}

pub fn root_der(root: &Path) -> Vec<u8> {
    fs::read(root.join("ca.der")).unwrap()
}

pub fn leaf_der(root: &Path, index: usize) -> Vec<u8> {
    fs::read(root.join(format!("leaf-{index}.der"))).unwrap()
}

pub fn private_key_der(root: &Path, index: usize) -> Vec<u8> {
    fs::read(root.join(format!("leaf-{index}-key.der"))).unwrap()
}

pub fn leaf_pin(root: &Path, index: usize) -> [u8; 32] {
    Sha256::digest(leaf_der(root, index)).into()
}
