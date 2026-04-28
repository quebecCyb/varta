use security_framework::passwords::set_generic_password;
use security_framework::passwords::get_generic_password;
use security_framework::passwords::delete_generic_password;

pub fn store_key(service: &str, account: &str, key: &[u8]) {
    set_generic_password(service, account, key)
        .expect("Failed to store key in Keychain");
}

pub fn store_key_checked(service: &str, account: &str, key: &[u8]) -> Result<(), String> {
    set_generic_password(service, account, key)
        .map_err(|e| format!("Keychain error: {:?}", e))
}

pub fn load_key(service: &str, account: &str) -> Option<Vec<u8>> {
    match get_generic_password(service, account) {
        Ok(password) => Some(password),
        Err(_) => None, 
    }
}

pub fn delete_key(service: &str, account: &str) {
    delete_generic_password(service, account)
        .expect("Failed to delete key");
}
