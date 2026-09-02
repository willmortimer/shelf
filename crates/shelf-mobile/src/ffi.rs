//! C ABI matching `include/shelf_mobile.h`.
//!
//! Error codes (never secret key material):
//! - [`SHELF_OK`] (0): success
//! - [`SHELF_ERR_NULL`] (-1): required pointer was null
//! - [`SHELF_ERR_UTF8`] (-2): path or text was not valid UTF-8
//! - [`SHELF_ERR_OPEN`] (-3): vault open/create failed
//! - [`SHELF_ERR_SESSION`] (-4): session handle was null
//! - [`SHELF_ERR_PUT`] (-5): put_text failed
//! - [`SHELF_ERR_LATEST`] (-6): latest failed (empty vault or decrypt)
//! - [`SHELF_ERR_BUFFER`] (-7): caller buffer too small; `*out_len` is required size
//! - [`SHELF_ERR_SYNC`] (-8): opportunistic mailbox sync failed

use std::ffi::{CStr, c_char};
use std::ptr;

use crate::MobileSession;

/// Opaque session handle for the C ABI (`typedef struct ShelfMobileSession`).
pub struct ShelfMobileSession {
    inner: MobileSession,
}

/// Success.
pub const SHELF_OK: i32 = 0;
/// Required pointer was null.
pub const SHELF_ERR_NULL: i32 = -1;
/// Path or text was not valid UTF-8.
pub const SHELF_ERR_UTF8: i32 = -2;
/// Vault open/create failed.
pub const SHELF_ERR_OPEN: i32 = -3;
/// Session handle was null.
pub const SHELF_ERR_SESSION: i32 = -4;
/// `put_text` failed.
pub const SHELF_ERR_PUT: i32 = -5;
/// `latest` failed (empty vault or decrypt).
pub const SHELF_ERR_LATEST: i32 = -6;
/// Caller buffer too small; `*out_len` is the required size.
pub const SHELF_ERR_BUFFER: i32 = -7;
/// Opportunistic mailbox sync failed.
pub const SHELF_ERR_SYNC: i32 = -8;

/// Open or create the vault under `home_utf8`.
///
/// # Safety
/// `home_utf8` must be a valid C string. `out` must be a valid pointer.
/// On success `*out` is a heap session that must be passed to
/// [`shelf_mobile_close`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn shelf_mobile_open(
    home_utf8: *const c_char,
    out: *mut *mut ShelfMobileSession,
) -> i32 {
    if home_utf8.is_null() || out.is_null() {
        return SHELF_ERR_NULL;
    }
    // SAFETY: caller guarantees `out` is writable for one pointer.
    unsafe {
        ptr::write(out, ptr::null_mut());
    }
    let home = match unsafe { c_str(home_utf8) } {
        Ok(s) => s,
        Err(code) => return code,
    };
    match MobileSession::open(home) {
        Ok(inner) => {
            let boxed = Box::new(ShelfMobileSession { inner });
            // SAFETY: `out` is a valid pointer as checked above.
            unsafe {
                ptr::write(out, Box::into_raw(boxed));
            }
            SHELF_OK
        }
        Err(_) => SHELF_ERR_OPEN,
    }
}

/// Drop a session opened by [`shelf_mobile_open`]. Null is a no-op.
///
/// # Safety
/// `session` must be null or a pointer from [`shelf_mobile_open`] that has not
/// been closed already.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn shelf_mobile_close(session: *mut ShelfMobileSession) {
    if session.is_null() {
        return;
    }
    // SAFETY: unique pointer from `shelf_mobile_open`.
    drop(unsafe { Box::from_raw(session) });
}

/// Put UTF-8 text into the vault.
///
/// # Safety
/// `session` must be a live handle. `text_utf8` must be a valid C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn shelf_mobile_put_text(
    session: *mut ShelfMobileSession,
    text_utf8: *const c_char,
) -> i32 {
    let Some(session) = (unsafe { session.as_mut() }) else {
        return SHELF_ERR_SESSION;
    };
    if text_utf8.is_null() {
        return SHELF_ERR_NULL;
    }
    let text = match unsafe { c_str(text_utf8) } {
        Ok(s) => s,
        Err(code) => return code,
    };
    match session.inner.put_text(text) {
        Ok(_) => SHELF_OK,
        Err(_) => SHELF_ERR_PUT,
    }
}

/// Copy the newest plaintext into `buf`.
///
/// Always writes the required size to `*out_len` when `out_len` is non-null.
/// Returns [`SHELF_ERR_BUFFER`] when `buf` is null or `cap` is too small.
///
/// # Safety
/// `session` must be a live handle. `out_len`, if non-null, must be writable.
/// When `buf` is non-null it must be valid for `cap` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn shelf_mobile_latest(
    session: *mut ShelfMobileSession,
    buf: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    let Some(session) = (unsafe { session.as_mut() }) else {
        return SHELF_ERR_SESSION;
    };
    if out_len.is_null() {
        return SHELF_ERR_NULL;
    }
    let bytes = match session.inner.latest() {
        Ok(b) => b,
        Err(_) => {
            unsafe {
                ptr::write(out_len, 0);
            }
            return SHELF_ERR_LATEST;
        }
    };
    unsafe {
        ptr::write(out_len, bytes.len());
    }
    if buf.is_null() || cap < bytes.len() {
        return SHELF_ERR_BUFFER;
    }
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), buf, bytes.len());
    }
    SHELF_OK
}

/// Opportunistic mailbox GET/ACK/PUT when `config.toml` has `mailbox_url`.
///
/// # Safety
/// `session` must be a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn shelf_mobile_sync_once(session: *mut ShelfMobileSession) -> i32 {
    let Some(session) = (unsafe { session.as_mut() }) else {
        return SHELF_ERR_SESSION;
    };
    match session.inner.sync_once() {
        Ok(()) => SHELF_OK,
        Err(_) => SHELF_ERR_SYNC,
    }
}

unsafe fn c_str<'a>(ptr: *const c_char) -> Result<&'a str, i32> {
    // SAFETY: caller guarantees a valid C string.
    let cstr = unsafe { CStr::from_ptr(ptr) };
    cstr.to_str().map_err(|_| SHELF_ERR_UTF8)
}

impl ShelfMobileSession {
    /// Wrap an already-open session (host tests; not part of the C ABI).
    #[cfg(test)]
    pub(crate) fn from_session(inner: MobileSession) -> Box<Self> {
        Box::new(Self { inner })
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use std::ptr;

    use super::*;
    use crate::MobileSession;

    fn handle_for_temp() -> (*mut ShelfMobileSession, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let session = MobileSession::open_with(dir.path(), Some("test-pass")).unwrap();
        (
            Box::into_raw(ShelfMobileSession::from_session(session)),
            dir,
        )
    }

    #[test]
    fn ffi_put_then_latest() {
        let (handle, _dir) = handle_for_temp();
        let text = CString::new("from-share-sheet").unwrap();
        assert_eq!(
            unsafe { shelf_mobile_put_text(handle, text.as_ptr()) },
            SHELF_OK
        );

        let mut needed = 0usize;
        assert_eq!(
            unsafe { shelf_mobile_latest(handle, ptr::null_mut(), 0, &mut needed) },
            SHELF_ERR_BUFFER
        );
        assert_eq!(needed, b"from-share-sheet".len());

        let mut buf = vec![0u8; needed];
        let mut len = 0usize;
        assert_eq!(
            unsafe { shelf_mobile_latest(handle, buf.as_mut_ptr(), buf.len(), &mut len) },
            SHELF_OK
        );
        assert_eq!(&buf[..len], b"from-share-sheet");
        unsafe { shelf_mobile_close(handle) };
    }

    #[test]
    fn ffi_null_session_is_session_error() {
        let text = CString::new("x").unwrap();
        assert_eq!(
            unsafe { shelf_mobile_put_text(ptr::null_mut(), text.as_ptr()) },
            SHELF_ERR_SESSION
        );
        let mut len = 99usize;
        assert_eq!(
            unsafe { shelf_mobile_latest(ptr::null_mut(), ptr::null_mut(), 0, &mut len) },
            SHELF_ERR_SESSION
        );
        assert_eq!(
            unsafe { shelf_mobile_sync_once(ptr::null_mut()) },
            SHELF_ERR_SESSION
        );
        unsafe { shelf_mobile_close(ptr::null_mut()) };
    }
}
