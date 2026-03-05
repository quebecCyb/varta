

pub use rand::rngs::OsRng;
use rand::RngCore;

pub const VERSION: u8 = 1;

pub const ROOT_SECRETS_FOLDER: &str = "secrets";

pub fn generate_random_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}
