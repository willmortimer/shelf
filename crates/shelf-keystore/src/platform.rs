//! Platform wrap-key custody: Keychain, Secret Service, DPAPI.
//!
//! Failures are non-fatal: the caller may fall back to `--allow-file-key`.

use std::path::Path;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::process::{Command, Stdio};

use crate::KeystoreError;

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) fn account_id(home: &Path) -> String {
    let h = blake3::hash(home.to_string_lossy().as_bytes());
    let hex: String = h.as_bytes()[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("shelf-wrap-{hex}")
}

/// Store `key` in the platform secret store. Returns true if it landed.
pub(crate) fn store_wrap_key(home: &Path, key: &[u8; 32]) -> Result<bool, KeystoreError> {
    #[cfg(target_os = "macos")]
    {
        macos_store(&account_id(home), &hex_key(key))
    }
    #[cfg(target_os = "linux")]
    {
        linux_store(&account_id(home), &hex_key(key))
    }
    #[cfg(windows)]
    {
        windows_store(home, key)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    {
        let _ = (home, key);
        Ok(false)
    }
}

/// Load a wrap key previously stored by [`store_wrap_key`].
pub(crate) fn load_wrap_key(home: &Path) -> Result<Option<[u8; 32]>, KeystoreError> {
    #[cfg(target_os = "macos")]
    {
        macos_load(&account_id(home))
    }
    #[cfg(target_os = "linux")]
    {
        linux_load(&account_id(home))
    }
    #[cfg(windows)]
    {
        windows_load(home)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    {
        let _ = home;
        Ok(None)
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn hex_key(key: &[u8; 32]) -> String {
    key.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn parse_hex_key(s: &str) -> Result<[u8; 32], KeystoreError> {
    let s = s.trim();
    if s.len() != 64 {
        return Err(KeystoreError::Identity(
            "platform wrap key must be 32 bytes".into(),
        ));
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|_| KeystoreError::Identity("invalid platform wrap hex".into()))?;
    }
    Ok(out)
}

#[cfg(target_os = "macos")]
fn macos_store(account: &str, hex: &str) -> Result<bool, KeystoreError> {
    let status = Command::new("security")
        .args([
            "add-generic-password",
            "-a",
            account,
            "-s",
            "shelf.wrap-key",
            "-w",
            hex,
            "-U",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    Ok(status.map(|s| s.success()).unwrap_or(false))
}

#[cfg(target_os = "macos")]
fn macos_load(account: &str) -> Result<Option<[u8; 32]>, KeystoreError> {
    let output = Command::new("security")
        .args([
            "find-generic-password",
            "-a",
            account,
            "-s",
            "shelf.wrap-key",
            "-w",
        ])
        .stdin(Stdio::null())
        .output();
    let Ok(output) = output else {
        return Ok(None);
    };
    if !output.status.success() {
        return Ok(None);
    }
    let s = String::from_utf8_lossy(&output.stdout);
    Ok(Some(parse_hex_key(&s)?))
}

#[cfg(target_os = "linux")]
fn linux_store(account: &str, hex: &str) -> Result<bool, KeystoreError> {
    let mut child = match Command::new("secret-tool")
        .args([
            "store",
            "--label=Shelf wrap key",
            "service",
            "shelf.wrap-key",
            "account",
            account,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return Ok(false),
    };
    if let Some(mut stdin) = child.stdin.take() {
        let _ = std::io::Write::write_all(&mut stdin, hex.as_bytes());
    }
    Ok(child.wait().map(|s| s.success()).unwrap_or(false))
}

#[cfg(target_os = "linux")]
fn linux_load(account: &str) -> Result<Option<[u8; 32]>, KeystoreError> {
    let output = Command::new("secret-tool")
        .args(["lookup", "service", "shelf.wrap-key", "account", account])
        .stdin(Stdio::null())
        .output();
    let Ok(output) = output else {
        return Ok(None);
    };
    if !output.status.success() {
        return Ok(None);
    }
    let s = String::from_utf8_lossy(&output.stdout);
    if s.trim().is_empty() {
        return Ok(None);
    }
    Ok(Some(parse_hex_key(&s)?))
}

#[cfg(windows)]
fn windows_store(home: &Path, key: &[u8; 32]) -> Result<bool, KeystoreError> {
    match dpapi_protect(key) {
        Ok(blob) => {
            std::fs::write(home.join("wrap.dpapi"), blob)?;
            Ok(true)
        }
        Err(_) => Ok(false),
    }
}

#[cfg(windows)]
fn windows_load(home: &Path) -> Result<Option<[u8; 32]>, KeystoreError> {
    let path = home.join("wrap.dpapi");
    if !path.exists() {
        return Ok(None);
    }
    let blob = std::fs::read(path)?;
    match dpapi_unprotect(&blob) {
        Ok(raw) => {
            let bytes: [u8; 32] = raw
                .as_slice()
                .try_into()
                .map_err(|_| KeystoreError::Identity("dpapi wrap key must be 32 bytes".into()))?;
            Ok(Some(bytes))
        }
        Err(_) => Ok(None),
    }
}

/// User-logon DPAPI (Windows). Not compiled on Unix CI.
#[cfg(windows)]
fn dpapi_protect(key: &[u8; 32]) -> Result<Vec<u8>, KeystoreError> {
    use std::ptr;
    use windows_sys::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData,
    };
    let input = CRYPT_INTEGER_BLOB {
        cbData: key.len() as u32,
        pbData: key.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };
    let ok = unsafe {
        CryptProtectData(
            &input,
            ptr::null(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 || output.pbData.is_null() {
        return Err(KeystoreError::Wrap);
    }
    let slice = unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) };
    let out = slice.to_vec();
    unsafe { windows_sys::Win32::Foundation::LocalFree(output.pbData as _) };
    Ok(out)
}

#[cfg(windows)]
fn dpapi_unprotect(blob: &[u8]) -> Result<Vec<u8>, KeystoreError> {
    use std::ptr;
    use windows_sys::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptUnprotectData,
    };
    let input = CRYPT_INTEGER_BLOB {
        cbData: blob.len() as u32,
        pbData: blob.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };
    let ok = unsafe {
        CryptUnprotectData(
            &input,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 || output.pbData.is_null() {
        return Err(KeystoreError::Wrap);
    }
    let slice = unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) };
    let out = slice.to_vec();
    unsafe { windows_sys::Win32::Foundation::LocalFree(output.pbData as _) };
    Ok(out)
}
