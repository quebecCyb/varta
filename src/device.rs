use sha2::{Sha256, Digest};
use std::sync::{Mutex, MutexGuard};
use crate::config::VERSION;
use crate::crypto::device::keychain;
use crate::crypto::sign::{ED25519_SIG_LEN, sign_ed25519};
use zeroize::Zeroize;
use once_cell::sync::OnceCell;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

const DEVICE_KEY_NAME: &str = "varta_device_key_v1";

static DEVICE_INSTANCE: OnceCell<Mutex<Device>> = OnceCell::new();

pub struct Device {
    version: u8,
    device_id: [u8; 32],
    private_key: [u8; 32],
}

impl Device {
    pub fn initialize() {
        DEVICE_INSTANCE.get_or_init(|| {
            let device_key = keychain::load_or_create_key(DEVICE_KEY_NAME);
            let device_id = Self::compute_id(&device_key);
            
            let device = Self {
                version: VERSION,
                device_id,
                private_key: device_key.try_into()
                    .expect("Keychain returned invalid key length (expected 32 bytes)"),
            };
            
            Mutex::new(device)
        });
    }

    pub fn instance() -> MutexGuard<'static, Device> {
        DEVICE_INSTANCE
            .get()
            .expect("Device not initialized. Call Device::initialize() first")
            .lock()
            .expect("Device mutex poisoned")
    }
    
    fn compute_id(device_key: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(device_key);
        hasher.finalize().into()
    }

    pub fn get_id(&self) -> [u8; 32] {
        self.device_id
    }

    pub fn sign(&self, plaintext: &[u8]) -> [u8; ED25519_SIG_LEN] {
        sign_ed25519(&self.private_key, plaintext)
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

