//! Owner-private filesystem primitives shared by the native local tools.

use std::{
    fs::{self, File},
    io,
    path::Path,
};

/// Stable identity of one already-opened filesystem object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpenedFileIdentity {
    volume: u64,
    object: [u8; 16],
}

impl OpenedFileIdentity {
    /// Versioned local filesystem identity bytes, not a transferable backup ID.
    /// The platform tag prevents interpreting another platform's object format.
    pub fn local_binding_bytes(self) -> [u8; 25] {
        let mut bytes = [0; 25];
        bytes[0] = if cfg!(unix) { 1 } else { 2 };
        bytes[1..9].copy_from_slice(&self.volume.to_le_bytes());
        bytes[9..].copy_from_slice(&self.object);
        bytes
    }
}

/// Applies the platform's exact owner-private policy to a directory.
pub fn configure_private_directory(path: &Path) -> io::Result<()> {
    platform::configure_directory(path)
}

/// Applies the platform's exact owner-private policy to an opened file.
pub fn configure_private_file(file: &File, path: &Path) -> io::Result<()> {
    platform::configure_file(file, path)
}

/// Reapplies and verifies the exact owner-private directory policy.
pub fn protect_private_directory(path: &Path) -> io::Result<()> {
    configure_private_directory(path)?;
    require(private_directory(path)?, "directory is not owner-private")
}

/// Reapplies and verifies the exact owner-private file policy.
pub fn protect_private_file(file: &File, path: &Path) -> io::Result<()> {
    configure_private_file(file, path)?;
    require(private_file(path)?, "file is not owner-private")
}

/// Returns whether `path` is a real, exact owner-private directory.
pub fn private_directory(path: &Path) -> io::Result<bool> {
    let metadata = fs::symlink_metadata(path)?;
    Ok(metadata.is_dir() && !link_like_metadata(&metadata) && platform::private(path, true)?)
}

/// Returns whether `path` is a real, exact owner-private regular file.
pub fn private_file(path: &Path) -> io::Result<bool> {
    let metadata = fs::symlink_metadata(path)?;
    Ok(metadata.is_file() && !link_like_metadata(&metadata) && platform::private(path, false)?)
}

/// Returns whether `path` is a symbolic link or Windows reparse point.
pub fn link_like(path: &Path) -> io::Result<bool> {
    Ok(link_like_metadata(&fs::symlink_metadata(path)?))
}

/// Returns whether an already-opened regular file is still the file at `path`.
pub fn opened_file_matches_path(file: &File, path: &Path) -> io::Result<bool> {
    platform::opened_file_matches_path(file, path)
}

/// Opens a file or directory without following a final-component link.
pub fn open_read_no_follow(path: &Path, directory: bool) -> io::Result<File> {
    platform::open_read_no_follow(path, directory)
}

/// Returns whether an opened file has exactly one hard link.
pub fn opened_file_has_single_link(file: &File) -> io::Result<bool> {
    platform::opened_file_has_single_link(file)
}

/// Returns the stable volume/object identity of an already-opened file.
pub fn opened_file_identity(file: &File) -> io::Result<OpenedFileIdentity> {
    platform::opened_file_identity(file)
}

/// Flushes directory metadata where the platform exposes a safe primitive.
pub fn sync_directory(path: &Path) -> io::Result<()> {
    platform::sync_directory(path)
}

/// Atomically replaces `destination` with `source` within one directory.
pub fn replace_file(source: &Path, destination: &Path) -> io::Result<()> {
    platform::replace_file(source, destination)
}

fn require(condition: bool, message: &'static str) -> io::Result<()> {
    if condition {
        Ok(())
    } else {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, message))
    }
}

#[cfg(unix)]
fn link_like_metadata(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

#[cfg(windows)]
fn link_like_metadata(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(any(unix, windows)))]
compile_error!("silk-local-platform supports only Unix and Windows targets");

#[cfg(unix)]
mod platform {
    use super::*;
    use std::os::unix::fs::OpenOptionsExt as _;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    pub(super) fn configure_directory(path: &Path) -> io::Result<()> {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
    }

    pub(super) fn configure_file(file: &File, _path: &Path) -> io::Result<()> {
        file.set_permissions(fs::Permissions::from_mode(0o600))
    }

    pub(super) fn private(path: &Path, directory: bool) -> io::Result<bool> {
        let metadata = fs::symlink_metadata(path)?;
        let expected = if directory { 0o700 } else { 0o600 };
        Ok(metadata.mode() & 0o777 == expected)
    }

    pub(super) fn opened_file_matches_path(file: &File, path: &Path) -> io::Result<bool> {
        let path_metadata = fs::symlink_metadata(path)?;
        if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
            return Ok(false);
        }
        let opened_metadata = file.metadata()?;
        Ok(path_metadata.dev() == opened_metadata.dev()
            && path_metadata.ino() == opened_metadata.ino())
    }

    pub(super) fn open_read_no_follow(path: &Path, directory: bool) -> io::Result<File> {
        let mut options = fs::OpenOptions::new();
        options.read(true);
        let directory_flag = if directory { libc::O_DIRECTORY } else { 0 };
        options
            .custom_flags(libc::O_NOFOLLOW | directory_flag)
            .open(path)
    }

    pub(super) fn opened_file_has_single_link(file: &File) -> io::Result<bool> {
        Ok(file.metadata()?.nlink() == 1)
    }

    pub(super) fn opened_file_identity(file: &File) -> io::Result<OpenedFileIdentity> {
        let metadata = file.metadata()?;
        let mut object = [0_u8; 16];
        object[..std::mem::size_of::<u64>()].copy_from_slice(&metadata.ino().to_le_bytes());
        Ok(OpenedFileIdentity {
            volume: metadata.dev(),
            object,
        })
    }

    pub(super) fn sync_directory(path: &Path) -> io::Result<()> {
        File::open(path)?.sync_all()
    }

    pub(super) fn replace_file(source: &Path, destination: &Path) -> io::Result<()> {
        fs::rename(source, destination)
    }
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::{
        ffi::{OsStr, c_void},
        mem::{MaybeUninit, size_of},
        os::windows::{ffi::OsStrExt as _, fs::OpenOptionsExt as _, io::AsRawHandle as _},
        ptr::null_mut,
    };
    use windows_sys::Win32::Security::Authorization::{
        GetNamedSecurityInfoW, SE_FILE_OBJECT, SetNamedSecurityInfoW,
    };
    use windows_sys::Win32::{
        Foundation::{CloseHandle, ERROR_SUCCESS, HANDLE, LocalFree},
        Security::{
            ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_REVISION, AddAccessAllowedAceEx,
            CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, EqualSid, GetAce,
            GetSecurityDescriptorControl, GetTokenInformation, InitializeAcl, OBJECT_INHERIT_ACE,
            OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED,
            TOKEN_INFORMATION_CLASS, TOKEN_OWNER, TOKEN_QUERY, TOKEN_USER, TokenOwner, TokenUser,
        },
        Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, FILE_ALL_ACCESS, FILE_ATTRIBUTE_REPARSE_POINT,
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_INFO, FileIdInfo,
            GetFileInformationByHandle, GetFileInformationByHandleEx, MOVEFILE_REPLACE_EXISTING,
            MOVEFILE_WRITE_THROUGH, MoveFileExW,
        },
        System::{
            SystemServices::ACCESS_ALLOWED_ACE_TYPE,
            Threading::{GetCurrentProcess, OpenProcessToken},
        },
    };

    pub(super) fn configure_directory(path: &Path) -> io::Result<()> {
        require(!super::link_like(path)?, "directory is a reparse point")?;
        let mut name = wide_path(path)?;
        with_current_security_sids(|user_sid, owner_sid| unsafe {
            // SAFETY: the path and ACL pointers remain live for the duration of
            // this synchronous Win32 call.
            require(
                owner_matches_current_token(name.as_ptr(), user_sid, owner_sid)?,
                "directory owner is not from the current security token",
            )?;
            set_private_acl(name.as_mut_ptr(), user_sid, true)
        })
    }

    pub(super) fn configure_file(file: &File, path: &Path) -> io::Result<()> {
        require(!super::link_like(path)?, "file is a reparse point")?;
        require(
            opened_file_matches_path(file, path)?,
            "opened file no longer matches its path",
        )?;
        let mut name = wide_path(path)?;
        with_current_security_sids(|user_sid, owner_sid| unsafe {
            // SAFETY: the path, generated ACL, and token SID remain live for
            // the duration of these synchronous Win32 calls.
            require(
                owner_matches_current_token(name.as_ptr(), user_sid, owner_sid)?,
                "file owner is not from the current security token",
            )?;
            set_private_acl(name.as_mut_ptr(), user_sid, false)
        })?;
        require(
            opened_file_matches_path(file, path)?,
            "opened file changed while applying its ACL",
        )
    }

    pub(super) fn private(path: &Path, directory: bool) -> io::Result<bool> {
        let mut name = wide_path(path)?;
        with_current_security_sids(|user_sid, _owner_sid| unsafe {
            // SAFETY: Windows allocates `descriptor`; all returned interior
            // pointers remain valid until the matching LocalFree below.
            inspect_private_acl(name.as_mut_ptr().cast_const(), user_sid, directory)
        })
    }

    pub(super) fn opened_file_matches_path(file: &File, path: &Path) -> io::Result<bool> {
        let path_file = open_read_no_follow(path, false)?;
        let metadata = path_file.metadata()?;
        use std::os::windows::fs::MetadataExt as _;
        if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Ok(false);
        }
        Ok(opened_file_identity(&path_file)? == opened_file_identity(file)?)
    }

    pub(super) fn open_read_no_follow(path: &Path, directory: bool) -> io::Result<File> {
        let flags = FILE_FLAG_OPEN_REPARSE_POINT
            | if directory {
                FILE_FLAG_BACKUP_SEMANTICS
            } else {
                0
            };
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(flags)
            .open(path)?;
        use std::os::windows::fs::MetadataExt as _;
        if file.metadata()?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "path is a reparse point",
            ));
        }
        Ok(file)
    }

    pub(super) fn opened_file_has_single_link(file: &File) -> io::Result<bool> {
        Ok(file_information(file)?.nNumberOfLinks == 1)
    }

    pub(super) fn opened_file_identity(file: &File) -> io::Result<OpenedFileIdentity> {
        let information = file_id_information(file)?;
        Ok(OpenedFileIdentity {
            volume: information.VolumeSerialNumber,
            object: information.FileId.Identifier,
        })
    }

    fn file_id_information(file: &File) -> io::Result<FILE_ID_INFO> {
        let mut information = MaybeUninit::<FILE_ID_INFO>::uninit();
        let buffer_size = u32::try_from(size_of::<FILE_ID_INFO>())
            .map_err(|_| io::Error::other("FILE_ID_INFO size does not fit u32"))?;
        let result = unsafe {
            // SAFETY: `file` owns a live handle and `information` is a valid
            // writable FILE_ID_INFO buffer for the duration of this call.
            GetFileInformationByHandleEx(
                file.as_raw_handle() as HANDLE,
                FileIdInfo,
                information.as_mut_ptr().cast(),
                buffer_size,
            )
        };
        if result == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(unsafe {
                // SAFETY: a successful FileIdInfo query fully initializes the
                // FILE_ID_INFO output buffer.
                information.assume_init()
            })
        }
    }

    fn file_information(file: &File) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
        let mut information = MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
        let result = unsafe {
            // SAFETY: `file` owns a live handle and `information` is a valid
            // writable out pointer for the duration of this call.
            GetFileInformationByHandle(file.as_raw_handle() as HANDLE, information.as_mut_ptr())
        };
        if result == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(unsafe {
                // SAFETY: a successful GetFileInformationByHandle fully
                // initializes BY_HANDLE_FILE_INFORMATION.
                information.assume_init()
            })
        }
    }

    pub(super) fn sync_directory(path: &Path) -> io::Result<()> {
        // Win32 does not expose a supported equivalent of fsync on a directory
        // handle. Validate that the directory remains real; file contents are
        // flushed before publication and replacement uses WRITE_THROUGH below.
        require(
            fs::symlink_metadata(path)?.is_dir() && !super::link_like(path)?,
            "directory is unsafe",
        )
    }

    pub(super) fn replace_file(source: &Path, destination: &Path) -> io::Result<()> {
        let source = wide_path(source)?;
        let destination = wide_path(destination)?;
        let result = unsafe {
            // SAFETY: both NUL-terminated path buffers remain live for this call.
            MoveFileExW(
                source.as_ptr(),
                destination.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        if result == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn wide_path(path: &Path) -> io::Result<Vec<u16>> {
        wide(path.as_os_str())
    }

    fn wide(value: &OsStr) -> io::Result<Vec<u16>> {
        let mut encoded: Vec<u16> = value.encode_wide().collect();
        if encoded.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "path contains NUL",
            ));
        }
        encoded.push(0);
        Ok(encoded)
    }

    fn with_current_security_sids<T>(
        operation: impl FnOnce(PSID, PSID) -> io::Result<T>,
    ) -> io::Result<T> {
        let mut token: HANDLE = null_mut();
        let opened = unsafe {
            // SAFETY: `token` is a valid out pointer and GetCurrentProcess
            // returns the current process pseudo-handle.
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
        };
        if opened == 0 {
            return Err(io::Error::last_os_error());
        }

        let result = (|| {
            let user_buffer = token_information(token, TokenUser, size_of::<TOKEN_USER>())?;
            let owner_buffer = token_information(token, TokenOwner, size_of::<TOKEN_OWNER>())?;
            let token_user = unsafe {
                // SAFETY: successful TokenUser output starts with TOKEN_USER.
                &*user_buffer.as_ptr().cast::<TOKEN_USER>()
            };
            let token_owner = unsafe {
                // SAFETY: successful TokenOwner output starts with TOKEN_OWNER.
                &*owner_buffer.as_ptr().cast::<TOKEN_OWNER>()
            };
            require(
                !token_user.User.Sid.is_null(),
                "current user SID is unavailable",
            )?;
            require(
                !token_owner.Owner.is_null(),
                "current default owner SID is unavailable",
            )?;
            operation(token_user.User.Sid, token_owner.Owner)
        })();

        unsafe {
            // SAFETY: `token` was returned by OpenProcessToken exactly once.
            CloseHandle(token);
        }
        result
    }

    fn token_information(
        token: HANDLE,
        information_class: TOKEN_INFORMATION_CLASS,
        minimum_length: usize,
    ) -> io::Result<Vec<usize>> {
        let mut length = 0_u32;
        unsafe {
            // SAFETY: this sizing query intentionally supplies no buffer and
            // obtains the exact byte length required for the selected class.
            GetTokenInformation(token, information_class, null_mut(), 0, &mut length);
        }
        if length < minimum_length as u32 {
            return Err(io::Error::last_os_error());
        }
        // Token information contains pointer-aligned structures. Keep the
        // backing allocation aligned instead of casting a `Vec<u8>`.
        let words = (length as usize).div_ceil(size_of::<usize>());
        let mut buffer = vec![0_usize; words];
        let queried = unsafe {
            // SAFETY: `buffer` has the requested capacity and the token remains
            // open through this synchronous query.
            GetTokenInformation(
                token,
                information_class,
                buffer.as_mut_ptr().cast(),
                length,
                &mut length,
            )
        };
        if queried == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(buffer)
        }
    }

    unsafe fn private_acl(sid: PSID, directory: bool) -> io::Result<Vec<u32>> {
        let sid_length = unsafe { windows_sys::Win32::Security::GetLengthSid(sid) } as usize;
        if sid_length == 0 {
            return Err(io::Error::last_os_error());
        }
        let ace_length = size_of::<ACCESS_ALLOWED_ACE>() - size_of::<u32>() + sid_length;
        let acl_length = size_of::<ACL>() + ace_length;
        // ACL storage must be DWORD-aligned for InitializeAcl/GetAce.
        let mut acl = vec![0_u32; acl_length.div_ceil(size_of::<u32>())];
        let acl_pointer = acl.as_mut_ptr().cast::<ACL>();
        if unsafe { InitializeAcl(acl_pointer, acl_length as u32, ACL_REVISION) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let flags = if directory {
            OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
        } else {
            0
        };
        if unsafe { AddAccessAllowedAceEx(acl_pointer, ACL_REVISION, flags, FILE_ALL_ACCESS, sid) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(acl)
    }

    unsafe fn set_private_acl(name: *mut u16, sid: PSID, directory: bool) -> io::Result<()> {
        let mut acl = unsafe { private_acl(sid, directory)? };
        let information = OWNER_SECURITY_INFORMATION
            | DACL_SECURITY_INFORMATION
            | windows_sys::Win32::Security::PROTECTED_DACL_SECURITY_INFORMATION;
        let error = unsafe {
            SetNamedSecurityInfoW(
                name,
                SE_FILE_OBJECT,
                information,
                sid,
                null_mut(),
                acl.as_mut_ptr().cast(),
                null_mut(),
            )
        };
        if error == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(error as i32))
        }
    }

    unsafe fn owner_matches_current_token(
        name: *const u16,
        user_sid: PSID,
        default_owner_sid: PSID,
    ) -> io::Result<bool> {
        let mut owner: PSID = null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
        let error = unsafe {
            GetNamedSecurityInfoW(
                name,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                null_mut(),
                null_mut(),
                &mut descriptor,
            )
        };
        if error != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(error as i32));
        }
        let matches = !owner.is_null()
            && !descriptor.is_null()
            && (unsafe { EqualSid(owner, user_sid) } != 0
                || unsafe { EqualSid(owner, default_owner_sid) } != 0);
        if !descriptor.is_null() {
            unsafe {
                LocalFree(descriptor.cast());
            }
        }
        Ok(matches)
    }

    unsafe fn inspect_private_acl(
        name: *const u16,
        user_sid: PSID,
        directory: bool,
    ) -> io::Result<bool> {
        let mut owner: PSID = null_mut();
        let mut dacl: *mut ACL = null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
        let error = unsafe {
            GetNamedSecurityInfoW(
                name,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut descriptor,
            )
        };
        if error != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(error as i32));
        }

        let result = (|| {
            if owner.is_null() || dacl.is_null() || descriptor.is_null() {
                return Ok(false);
            }
            if unsafe { EqualSid(owner, user_sid) } == 0 {
                return Ok(false);
            }

            let mut control = 0_u16;
            let mut revision = 0_u32;
            if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0
                || control & SE_DACL_PROTECTED == 0
            {
                return Ok(false);
            }
            if unsafe { (*dacl).AceCount } != 1 {
                return Ok(false);
            }

            let mut ace: *mut c_void = null_mut();
            if unsafe { GetAce(dacl, 0, &mut ace) } == 0 || ace.is_null() {
                return Ok(false);
            }
            let header = unsafe { &*ace.cast::<ACE_HEADER>() };
            let expected_flags = if directory {
                (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8
            } else {
                0
            };
            if u32::from(header.AceType) != ACCESS_ALLOWED_ACE_TYPE
                || header.AceFlags != expected_flags
            {
                return Ok(false);
            }
            let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
            if allowed.Mask != FILE_ALL_ACCESS {
                return Ok(false);
            }
            let ace_sid = std::ptr::addr_of!(allowed.SidStart).cast_mut().cast();
            Ok(unsafe { EqualSid(ace_sid, user_sid) } != 0)
        })();

        unsafe {
            // SAFETY: GetNamedSecurityInfoW allocated the descriptor with LocalAlloc.
            LocalFree(descriptor.cast());
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        env,
        fs::OpenOptions,
        process,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn private_directory_file_and_handle_round_trip() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock")
            .as_nanos();
        let root = env::temp_dir().join(format!("silk-local-platform-{}-{nonce}", process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).expect("test directory");
        protect_private_directory(&root).expect("private test directory");

        let path = root.join("owner.bin");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .expect("test file");
        protect_private_file(&file, &path).expect("private test file");
        assert!(private_directory(&root).expect("directory policy"));
        assert!(private_file(&path).expect("file policy"));
        assert!(opened_file_matches_path(&file, &path).expect("file identity"));
        let identity = opened_file_identity(&file).expect("opened identity");
        let binding = identity.local_binding_bytes();
        assert_eq!(binding[0], if cfg!(unix) { 1 } else { 2 });
        let reopened = open_read_no_follow(&path, false).expect("reopen same object");
        assert_eq!(
            binding,
            opened_file_identity(&reopened)
                .unwrap()
                .local_binding_bytes()
        );
        drop(reopened);

        let directory = open_read_no_follow(&root, true).expect("open actual owner directory");
        let directory_binding = opened_file_identity(&directory)
            .unwrap()
            .local_binding_bytes();
        let moved = root.join("other-directory");
        fs::create_dir(&moved).unwrap();
        protect_private_directory(&moved).unwrap();
        let other = open_read_no_follow(&moved, true).unwrap();
        assert_ne!(
            directory_binding,
            opened_file_identity(&other).unwrap().local_binding_bytes()
        );
        drop(other);
        drop(directory);

        let linked = root.join("linked.bin");
        fs::hard_link(&path, &linked).expect("create hard link");
        assert!(!opened_file_has_single_link(&file).expect("multiple links detected"));
        assert_eq!(
            identity,
            opened_file_identity(&file).expect("identity remains stable")
        );
        fs::remove_file(linked).expect("remove hard link");
        assert!(opened_file_has_single_link(&file).expect("single link restored"));

        drop(file);
        fs::remove_dir_all(root).expect("test cleanup");
    }
}
