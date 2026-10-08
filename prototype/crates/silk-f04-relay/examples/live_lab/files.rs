use super::Result;
use silk_f04_relay::{Digest, Error, owner::PinRetention};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

pub fn directory(path: &Path) -> Result<()> {
    fs::create_dir(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    File::open(path)?.sync_all()?;
    File::open(path.parent().ok_or("directory parent")?)?.sync_all()?;
    Ok(())
}
pub fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    File::open(path.parent().ok_or("file parent")?)?.sync_all()?;
    Ok(())
}
pub fn read(path: &Path, cap: usize) -> Result<Zeroizing<Vec<u8>>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits().cast_signed())
        .open(path)?;
    if !file.metadata()?.is_file() || file.metadata()?.len() > cap as u64 {
        return Err(Error::Unavailable("fixture input bound/type").into());
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(cap as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > cap {
        return Err(Error::Unavailable("fixture input grew").into());
    }
    Ok(bytes)
}
pub fn exact<const N: usize>(path: &Path) -> Result<Zeroizing<[u8; N]>> {
    let bytes = read(path, N)?;
    Ok(Zeroizing::new(bytes.as_slice().try_into()?))
}

/// Separate mounted rollback domain, still the same administrative fixture.
/// Two exact32-byte files at most; never journal adoption or hardware custody.
pub struct Pins {
    directory: PathBuf,
}
impl Pins {
    pub fn new(directory: &Path) -> Self {
        Self {
            directory: directory.to_owned(),
        }
    }
}
impl PinRetention for Pins {
    fn retain(&mut self, pin: Digest) -> silk_f04_relay::Result<()> {
        let stage = self.directory.join("STAGE");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&stage)?;
        file.write_all(&pin)?;
        file.sync_all()?;
        fs::rename(stage, self.directory.join("CURRENT"))?;
        File::open(&self.directory)?.sync_all()?;
        Ok(())
    }
}
