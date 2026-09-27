use crate::{Result, fail};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use silk_f04_node::{Digest, node::Node};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    net::SocketAddr,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub schema: String,
    pub accept_public_zero_value: bool,
    pub domain: String,
    pub store: PathBuf,
    pub retained_head: PathBuf,
    pub host_margin: PathBuf,
    pub spend_parameters: PathBuf,
    pub output_parameters: PathBuf,
    pub seed: SocketAddr,
    pub ca_der_hex: PathBuf,
    pub seed_certificate_sha256: String,
    pub reward_owner: String,
    pub listen: Option<SocketAddr>,
    pub server_certificate_der: Option<PathBuf>,
    pub server_key_pkcs8_der: Option<PathBuf>,
}
impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let c: Self = serde_json::from_slice(&read_file(path, 8192)?)?;
        if c.schema != "silknode-public-testnet-config-v1"
            || !c.accept_public_zero_value
            || c.domain != silk_f04_node::genesis::public_testnet_v1::DOMAIN_HEX
            || c.seed.port() == 0
            || c.seed.ip().is_unspecified()
        {
            return fail("explicit pinned public valueless configuration required");
        }
        digest(&c.reward_owner)?;
        digest(&c.seed_certificate_sha256)?;
        for p in [
            &c.store,
            &c.retained_head,
            &c.host_margin,
            &c.spend_parameters,
            &c.output_parameters,
            &c.ca_der_hex,
        ] {
            if !p.is_absolute() {
                return fail("configuration paths must be absolute");
            }
        }
        Ok(c)
    }
    // The retained local pin is never sourced from a peer or from store/HEAD.
    // Operator-owned parent is outside the importable store, on its capped volume.
    pub fn pin_parent(&self) -> Result<PathBuf> {
        let parent = self
            .retained_head
            .parent()
            .ok_or("retained head parent")?
            .canonicalize()?;
        let meta = fs::symlink_metadata(&parent)?;
        let store_parent = self.store.parent().ok_or("store parent")?.canonicalize()?;
        let store = store_parent.join(self.store.file_name().ok_or("store name")?);
        if !meta.is_dir()
            || meta.mode() & 0o077 != 0
            || parent.starts_with(&store)
            || meta.dev() != store_parent.metadata()?.dev()
            || meta.uid() != store_parent.metadata()?.uid()
        {
            return fail(
                "retained pin requires separate private local directory on capped store volume",
            );
        }
        Ok(parent)
    }
    pub fn load_pin(&self) -> Result<Digest> {
        let parent = self.pin_parent()?;
        let m = fs::symlink_metadata(&self.retained_head)?;
        if !m.is_file()
            || m.mode() & 0o077 != 0
            || m.nlink() != 1
            || m.uid() != parent.metadata()?.uid()
        {
            return fail("retained local pin ownership/type");
        }
        digest(std::str::from_utf8(&read_file(&self.retained_head, 64)?)?)
    }
    pub fn save_pin(&self, node: &Node) -> Result<()> {
        let parent = self.pin_parent()?;
        if self.retained_head.try_exists()? {
            self.load_pin()?;
        }
        let tmp = self.retained_head.with_extension("pending");
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)?;
        f.write_all(hex::encode(node.local_head()?).as_bytes())?;
        f.sync_all()?;
        fs::rename(tmp, &self.retained_head)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    }
}
pub fn digest(s: &str) -> Result<Digest> {
    if s.len() != 64
        || !s
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return fail("expected lowercase hex32");
    }
    Ok(hex::decode(s)?.try_into().map_err(|_| "digest length")?)
}
pub fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
pub fn read_file(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let m = f.metadata()?;
    if !m.is_file() || m.len() > limit as u64 {
        return fail("file type/length");
    }
    let mut out = Vec::with_capacity(m.len() as usize);
    f.take(limit as u64 + 1).read_to_end(&mut out)?;
    if out.len() as u64 != m.len() {
        return fail("file changed length");
    }
    Ok(out)
}
