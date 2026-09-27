//! Reviewed ownership and pointer boundary for the `RandomX` C API.

use std::ffi::{c_int, c_void};
use std::ptr::NonNull;
use thiserror::Error;

const RANDOMX_FLAG_DEFAULT: c_int = 0;
const RANDOMX_FLAG_V2: c_int = 128;

/// `RandomX` always produces exactly 32 output bytes.
pub const RANDOMX_HASH_BYTES: usize = 32;
/// Local cap for one consensus transcript accepted by the FFI wrapper.
pub const MAX_RANDOMX_INPUT_BYTES: usize = 4_096;

unsafe extern "C" {
    fn randomx_alloc_cache(flags: c_int) -> *mut c_void;
    fn randomx_init_cache(cache: *mut c_void, key: *const c_void, key_size: usize);
    fn randomx_release_cache(cache: *mut c_void);
    fn randomx_create_vm(flags: c_int, cache: *mut c_void, dataset: *mut c_void) -> *mut c_void;
    fn randomx_destroy_vm(machine: *mut c_void);
    fn randomx_calculate_hash(
        machine: *mut c_void,
        input: *const c_void,
        input_size: usize,
        output: *mut c_void,
    );
}

/// Failures exposed by the bounded safe wrapper.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RandomXError {
    /// Empty key material is not accepted by this wrapper.
    #[error("randomx.empty_key")]
    EmptyKey,
    /// Empty or oversized input is outside the local transcript boundary.
    #[error("randomx.input_bounds")]
    InputBounds,
    /// `RandomX` could not allocate its light-mode cache.
    #[error("randomx.cache_allocation")]
    CacheAllocation,
    /// `RandomX` could not create an interpreted v2 virtual machine.
    #[error("randomx.vm_allocation")]
    VmAllocation,
}

/// One owned `RandomX` v2 interpreted light-mode virtual machine.
///
/// The VM borrows the cache in the C API. This owner retains both and destroys
/// the VM before releasing its cache. It is intentionally neither `Clone` nor
/// `Send`; callers serialize use through their own safe local boundary.
pub struct RandomXV2Vm {
    machine: NonNull<c_void>,
    cache: NonNull<c_void>,
}

impl RandomXV2Vm {
    /// Initialize one interpreted v2 VM for exact public key material.
    ///
    /// # Errors
    ///
    /// Rejects an empty key or an allocation failure.
    pub fn new(key: &[u8]) -> Result<Self, RandomXError> {
        if key.is_empty() {
            return Err(RandomXError::EmptyKey);
        }
        // SAFETY: The flags are accepted by the pinned C API. Null is checked
        // before the pointer is used or placed under ownership.
        let cache = NonNull::new(unsafe { randomx_alloc_cache(RANDOMX_FLAG_DEFAULT) })
            .ok_or(RandomXError::CacheAllocation)?;
        // SAFETY: `cache` is live and owned here; `key` is nonempty and valid
        // for exactly `key.len()` bytes for the duration of the call.
        unsafe {
            randomx_init_cache(cache.as_ptr(), key.as_ptr().cast(), key.len());
        }
        // SAFETY: v2 interpreted light mode requires a live initialized cache
        // and a null dataset. Null is checked before ownership is constructed.
        let machine = NonNull::new(unsafe {
            randomx_create_vm(RANDOMX_FLAG_V2, cache.as_ptr(), std::ptr::null_mut())
        });
        let Some(machine) = machine else {
            // SAFETY: This is the sole live owner of `cache`; VM creation
            // failed, so no VM retains a cache borrow.
            unsafe { randomx_release_cache(cache.as_ptr()) };
            return Err(RandomXError::VmAllocation);
        };
        Ok(Self { machine, cache })
    }

    /// Calculate one genuine `RandomX` v2 hash over a bounded transcript.
    ///
    /// # Errors
    ///
    /// Rejects empty input or input above [`MAX_RANDOMX_INPUT_BYTES`].
    pub fn calculate_hash(
        &mut self,
        input: &[u8],
    ) -> Result<[u8; RANDOMX_HASH_BYTES], RandomXError> {
        if input.is_empty() || input.len() > MAX_RANDOMX_INPUT_BYTES {
            return Err(RandomXError::InputBounds);
        }
        let mut output = [0_u8; RANDOMX_HASH_BYTES];
        // SAFETY: `machine` is a live VM exclusively borrowed through
        // `&mut self`; both slices are valid for their declared lengths, and output
        // has the exact 32-byte capacity required by the pinned API.
        unsafe {
            randomx_calculate_hash(
                self.machine.as_ptr(),
                input.as_ptr().cast(),
                input.len(),
                output.as_mut_ptr().cast(),
            );
        }
        Ok(output)
    }
}

impl Drop for RandomXV2Vm {
    fn drop(&mut self) {
        // SAFETY: This owner is unique and destruction order is required by
        // the API: the VM releases its cache borrow before the cache is freed.
        unsafe {
            randomx_destroy_vm(self.machine.as_ptr());
            randomx_release_cache(self.cache.as_ptr());
        }
    }
}

impl std::fmt::Debug for RandomXV2Vm {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RandomXV2Vm")
            .field("mode", &"interpreted-light-v2")
            .finish_non_exhaustive()
    }
}
