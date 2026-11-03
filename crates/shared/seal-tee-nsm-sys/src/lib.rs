//! The Nitro Secure Module driver's one ioctl, for `seal_tee::nitro`. Linux
//! `drivers/misc/nsm.c` (and AWS's `nsm.ko` in the Nitro boot blobs) takes one command,
//! `NSM_IOCTL_RAW = _IOWR(0x0A, 0, struct nsm_raw)`, whose argument is two `{u64 addr; u64 len}`
//! buffers: the request, and room for the response. The driver writes the response's length
//! back into the second `len`.
//!
//! This crate is the only `unsafe` code `seal-tee` links, kept apart so `seal-tee` can
//! `forbid(unsafe_code)`: one call, in `exchange`. What the bytes mean (CBOR) is `seal-tee`'s.

use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;

/// `struct nsm_iovec` (`include/uapi/linux/nsm.h`).
#[repr(C)]
struct Iovec {
    addr: u64,
    len: u64,
}

/// `struct nsm_raw`.
#[repr(C)]
struct Raw {
    request: Iovec,
    response: Iovec,
}

/// `_IOWR(type, nr, size)` as Linux encodes it on x86_64 and arm64: direction (read and write
/// = 3) in bits 30..32, the argument's size in bits 16..30, the type in 8..16, the number in
/// 0..8.
pub const fn iowr(ty: u8, nr: u8, size: usize) -> u64 {
    (3 << 30) | ((size as u64) << 16) | ((ty as u64) << 8) | nr as u64
}

/// `NSM_IOCTL_RAW`: `_IOWR(0x0A, 0, struct nsm_raw)` = `0xC0200A00`.
pub const NSM_IOCTL_RAW: u64 = iowr(0x0A, 0, std::mem::size_of::<Raw>());

/// Sends `request` to the NSM open as `device` and writes its response into `response`; the
/// response's length. Blocks until the NSM answers.
pub fn exchange(device: &File, request: &[u8], response: &mut [u8]) -> io::Result<usize> {
    let mut raw = Raw {
        request: Iovec { addr: request.as_ptr() as u64, len: request.len() as u64 },
        response: Iovec { addr: response.as_mut_ptr() as u64, len: response.len() as u64 },
    };
    // SAFETY: `device` is an open file for the call's duration. `raw` is a valid, exclusively
    // borrowed `struct nsm_raw` whose size is the one the command encodes. Its request buffer
    // is a live shared slice the driver only reads; its response buffer is a live exclusive
    // slice of exactly the length given, which the driver writes at most that much of. Both
    // borrows are held across the call and neither pointer is kept after it.
    let status = unsafe { libc::ioctl(device.as_raw_fd(), NSM_IOCTL_RAW as _, &mut raw as *mut Raw) };
    if status < 0 {
        return Err(io::Error::last_os_error());
    }
    let len = usize::try_from(raw.response.len).unwrap_or(usize::MAX);
    if len > response.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "response longer than its buffer"));
    }
    Ok(len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_command_is_nsm_ioctl_raw() {
        assert_eq!(std::mem::size_of::<Raw>(), 32);
        assert_eq!(NSM_IOCTL_RAW, 0xC020_0A00);
        assert_eq!(iowr(0x0A, 0, 32), 0xC020_0A00);
    }

    #[test]
    fn a_file_that_is_not_the_nsm_refuses_the_command() {
        let file = File::open("/dev/null").unwrap();
        let mut response = [0u8; 16];
        assert!(exchange(&file, b"x", &mut response).is_err());
    }
}
