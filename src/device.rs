use crate::common::DEVICE_KEY_FILE;
use borsh::{BorshSerialize, BorshDeserialize, to_vec, from_slice};
use sha2::{Sha256, Digest};
use std::fs;
use rand::rngs::OsRng;
use crate::common::VERSION;
use rand::RngCore;
use std::io::Write;

#[derive(BorshSerialize, BorshDeserialize)]
pub struct Device {
    version: u8,
    pub device_id: [u8; 32],
    device_key: [u8; 32],
}

impl Device {
    pub fn new() -> Self {
        if let Some(device) = Device::load() {
            return device;
        }

        let mut device_key: [u8; 32] = [0u8; 32];
        OsRng.fill_bytes(&mut device_key);
        

        let mut device = Self {
            version: VERSION,
            device_id: [0u8; 32],
            device_key,
        };
        device.device_id = device.get_id();

        device.save();

        device
    }

    fn get_id(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        
        hasher.update(&self.device_key);
        
        hasher.finalize().into()
    }
 
    pub fn load() -> Option<Self> {
        if !fs::exists(DEVICE_KEY_FILE).unwrap() {
            return None;
        }
        
        let data = fs::read(DEVICE_KEY_FILE).unwrap();
        let obj: Device = from_slice(&data).unwrap();
        
        println!("Device loaded.");
        Some(obj)
    }

    fn save(&self) {
        let mut file = fs::File::create(DEVICE_KEY_FILE).unwrap();
        file.write_all(&to_vec(self).unwrap()).unwrap();
        println!("Device saved.");
    }

    pub fn get_device_key(&self) -> [u8; 32] {
        self.device_key
    }
}

