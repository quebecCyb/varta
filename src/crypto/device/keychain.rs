use crate::os::mac::keychain;
use crate::os::os::get_os;
use crate::os::os::Os;
use rand::RngCore;

pub fn store_key(service: &str, key: &Vec<u8>) {
    if get_os() == Os::Mac {
        keychain::store_key(service, "varta", key);
    } else {
        panic!("OS is not currently supported")
    }
}

pub fn load_or_create_key(service: &str) -> Vec<u8> {
    if get_os() == Os::Mac {
        match keychain::load_key(service, "varta") {
            Some(key) => return key,
            None => {
                // Ключ не найден - создаем новый
                let mut new_key = vec![0u8; 32];
                rand::thread_rng().fill_bytes(&mut new_key);
                match keychain::store_key_checked(service, "varta", &new_key) {
                    Ok(_) => new_key,
                    Err(e) => panic!("Failed to store device key in Keychain: {}. Please allow access to Keychain.", e)
                }
            }
        }
    } else {
        panic!("OS is not currently supported")
    }
}

pub fn load_key(service: &str) -> Option<Vec<u8>> {
    if get_os() == Os::Mac {
        keychain::load_key(service, "varta")
    } else {
        None
    }
}

pub fn delete_key(service: &str) {
    if get_os() == Os::Mac {
        keychain::delete_key(service, "varta");
    }
}


