use borsh::{BorshSerialize, BorshDeserialize, to_vec, from_slice};
use sha2::{Sha256, Digest};
use std::sync::{Mutex, MutexGuard};
use crate::common::VERSION;
use crate::crypto::device::keychain;
use crate::crypto::sign::{ED25519_SIG_LEN, sign_ed25519};
use zeroize::Zeroize;
use once_cell::sync::OnceCell;

const DEVICE_KEY_NAME: &str = "varta_device_key_v1";

static DEVICE_INSTANCE: OnceCell<Mutex<Device>> = OnceCell::new();


#[derive(BorshSerialize, BorshDeserialize)]
pub struct Device {
    version: u8,
    
    #[borsh(skip)]
    device_id: Option<[u8; 32]>,

    #[borsh(skip)]
    private_key: Option<[u8; 32]>,
}

impl Device {
    /// Инициализировать глобальный Device singleton
    pub fn initialize() {
        DEVICE_INSTANCE.get_or_init(|| {
            let device = if let Some(device) = Device::load() {
                device
            } else {
                let device_key = keychain::load_or_create_key(DEVICE_KEY_NAME);
                let device_id = Self::compute_id(&device_key);

                Self {
                    version: VERSION,
                    device_id: Some(device_id),
                    private_key: Some(device_key.try_into().expect("Invalid key length")),
                }
            };
            Mutex::new(device)
        });
    }

    /// Получить ссылку на глобальный Device singleton
    pub fn instance() -> MutexGuard<'static, Device> {
        DEVICE_INSTANCE
            .get()
            .expect("Device not initialized. Call Device::initialize() first")
            .lock()
            .unwrap()
    }

    /// Проверить, инициализирован ли Device
    pub fn is_initialized() -> bool {
        DEVICE_INSTANCE.get().is_some()
    }

    /// Создать новый Device (для внутреннего использования)
    fn new() -> Self {
        if let Some(device) = Self::load() {
            return device;
        }

        let device_key = keychain::load_or_create_key(DEVICE_KEY_NAME);
        let device_id = Self::compute_id(&device_key);

        Self {
            version: VERSION,
            device_id: Some(device_id),
            private_key: Some(device_key.try_into().expect("Invalid key length")),
        }
    }

    /// Загрузить Device из хранилища (заглушка для будущей реализации)
    pub fn load() -> Option<Self> {
        // TODO: Implement device persistence if needed
        None
    }
    
    fn compute_id(device_key: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(device_key);
        hasher.finalize().into()
    }

    pub fn get_id(&self) -> [u8; 32] {
        self.device_id.expect("Device ID not initialized")
    }

    pub fn sign(&self, plaintext: &[u8]) -> [u8; ED25519_SIG_LEN] {
        let device_key = self.private_key.as_ref().expect("Device key not initialized");
        sign_ed25519(device_key, plaintext)
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        if let Some(ref mut key) = self.private_key {
            key.zeroize();
        }
        println!("🔒 Device private_key zeroized");
    }
}

