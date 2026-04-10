#[cfg(target_os = "windows")]
use windows::Win32::Security::Credentials::{
    CredWriteW, CredReadW, CredDeleteW, CredFree,
    CREDENTIALW, CRED_TYPE_GENERIC, CRED_PERSIST_LOCAL_MACHINE,
};

#[cfg(target_os = "windows")]
pub fn store_key(service: &str, account: &str, key: &[u8]) {
    store_key_checked(service, account, key)
        .expect("Failed to store key in Windows Credential Manager");
}

#[cfg(target_os = "windows")]
pub fn store_key_checked(service: &str, account: &str, key: &[u8]) -> Result<(), String> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    
    let target_name = format!("{}:{}", service, account);
    let target_name_wide: Vec<u16> = OsStr::new(&target_name)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    
    let mut credential = CREDENTIALW {
        Flags: 0,
        Type: CRED_TYPE_GENERIC,
        TargetName: target_name_wide.as_ptr() as *mut u16,
        Comment: std::ptr::null_mut(),
        LastWritten: Default::default(),
        CredentialBlobSize: key.len() as u32,
        CredentialBlob: key.as_ptr() as *mut u8,
        Persist: CRED_PERSIST_LOCAL_MACHINE,
        AttributeCount: 0,
        Attributes: std::ptr::null_mut(),
        TargetAlias: std::ptr::null_mut(),
        UserName: std::ptr::null_mut(),
    };
    
    unsafe {
        CredWriteW(&mut credential, 0)
            .map_err(|e| format!("Windows Credential Manager error: {:?}", e))?;
    }
    
    Ok(())
}

#[cfg(target_os = "windows")]
pub fn load_key(service: &str, account: &str) -> Option<Vec<u8>> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    
    let target_name = format!("{}:{}", service, account);
    let target_name_wide: Vec<u16> = OsStr::new(&target_name)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    
    unsafe {
        let mut credential_ptr = std::ptr::null_mut();
        
        match CredReadW(
            target_name_wide.as_ptr(),
            CRED_TYPE_GENERIC,
            0,
            &mut credential_ptr,
        ) {
            Ok(_) => {
                if credential_ptr.is_null() {
                    return None;
                }
                
                let credential = &*credential_ptr;
                let blob_size = credential.CredentialBlobSize as usize;
                let blob_ptr = credential.CredentialBlob;
                
                let key = std::slice::from_raw_parts(blob_ptr, blob_size).to_vec();
                
                CredFree(credential_ptr as *const _);
                
                Some(key)
            }
            Err(_) => None,
        }
    }
}

#[cfg(target_os = "windows")]
pub fn delete_key(service: &str, account: &str) {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    
    let target_name = format!("{}:{}", service, account);
    let target_name_wide: Vec<u16> = OsStr::new(&target_name)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    
    unsafe {
        CredDeleteW(target_name_wide.as_ptr(), CRED_TYPE_GENERIC, 0)
            .expect("Failed to delete key from Windows Credential Manager");
    }
}

// Заглушки для других платформ
#[cfg(not(target_os = "windows"))]
pub fn store_key(_service: &str, _account: &str, _key: &[u8]) {
    panic!("Windows Credential Manager is only available on Windows");
}

#[cfg(not(target_os = "windows"))]
pub fn store_key_checked(_service: &str, _account: &str, _key: &[u8]) -> Result<(), String> {
    Err("Windows Credential Manager is only available on Windows".to_string())
}

#[cfg(not(target_os = "windows"))]
pub fn load_key(_service: &str, _account: &str) -> Option<Vec<u8>> {
    None
}

#[cfg(not(target_os = "windows"))]
pub fn delete_key(_service: &str, _account: &str) {
    panic!("Windows Credential Manager is only available on Windows");
}
