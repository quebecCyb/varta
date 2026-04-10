use crate::os::mac::keychain as mac_keychain;
use crate::os::windows::keychain as win_keychain;
use crate::os::os::get_os;
use crate::os::os::Os;
use rand::RngCore;

pub fn store_key(service: &str, key: &Vec<u8>) {
    match get_os() {
        Os::Mac => mac_keychain::store_key(service, "varta", key),
        Os::Windows => win_keychain::store_key(service, "varta", key),
        _ => panic!("OS is not currently supported"),
    }
}

pub fn load_or_create_key(service: &str) -> Vec<u8> {
    let (load_fn, store_fn): (fn(&str, &str) -> Option<Vec<u8>>, fn(&str, &str, &[u8]) -> Result<(), String>) = match get_os() {
        Os::Mac => (mac_keychain::load_key, mac_keychain::store_key_checked),
        Os::Windows => (win_keychain::load_key, win_keychain::store_key_checked),
        _ => panic!("OS is not currently supported"),
    };
    
    match load_fn(service, "varta") {
        Some(key) => return key,
        None => {
            // Ключ не найден - создаем новый
            let mut new_key = vec![0u8; 32];
            rand::thread_rng().fill_bytes(&mut new_key);
            match store_fn(service, "varta", &new_key) {
                Ok(_) => new_key,
                Err(e) => panic!("Failed to store device key: {}. Please allow access to secure storage.", e)
            }
        }
    }
}

pub fn load_key(service: &str) -> Option<Vec<u8>> {
    match get_os() {
        Os::Mac => mac_keychain::load_key(service, "varta"),
        Os::Windows => win_keychain::load_key(service, "varta"),
        _ => None,
    }
}

pub fn delete_key(service: &str) {
    match get_os() {
        Os::Mac => mac_keychain::delete_key(service, "varta"),
        Os::Windows => win_keychain::delete_key(service, "varta"),
        _ => {},
    }
}


