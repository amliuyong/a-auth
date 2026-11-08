//! Kernel mount checks for operator-projected files.

use std::{fs::File, mem::MaybeUninit, os::fd::AsRawFd};

/// Kubernetes projection roots retain writable Unix directory mode bits even
/// when the volume is mounted read-only. Trust the descriptor's kernel flag,
/// never a configured path or an operator-supplied claim about immutability.
pub(crate) fn read_only_mount(file: &File) -> bool {
    let mut status = MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: file owns a live descriptor and status has sufficient writable
    // storage. The structure is read only after fstatvfs initializes it.
    if unsafe { libc::fstatvfs(file.as_raw_fd(), status.as_mut_ptr()) } != 0 {
        return false;
    }
    // SAFETY: the successful call above initialized the complete structure.
    let status = unsafe { status.assume_init() };
    status.f_flag & libc::ST_RDONLY != 0
}
