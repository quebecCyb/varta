
use std::time::{SystemTime, UNIX_EPOCH};

use borsh::{BorshSerialize, BorshDeserialize, to_vec, from_slice};
use sha2::{Sha256, Digest};

use crate::config::VERSION;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(BorshSerialize, BorshDeserialize, Clone)]
pub struct VaultObject {
    version: u8,
    
    key: String,
    value: Vec<u8>,

    status: u64,
    digest: [u8; 32],

    created_at: u64,
    updated_at: u64,
}


impl VaultObject {
    pub fn new(key: String, value: Vec<u8>) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut obj = Self {
            version: VERSION,
            key,
            value,
            status: 0,
            digest: [0u8; 32],
            created_at: timestamp,
            updated_at: timestamp,
        };
        
        obj.digest = obj.hash();
        obj
    }


    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(to_vec(self)?)
    }
    
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        Ok(from_slice(data)?)
    }

    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        
        hasher.update(&self.key.as_bytes());
        hasher.update(&self.value);
        hasher.update(&self.status.to_le_bytes());
        hasher.update(&self.created_at.to_le_bytes());
        hasher.update(&self.updated_at.to_le_bytes());
        
        hasher.finalize().into()
    }


    pub fn key(&self) -> &str {
        &self.key
    }

    pub fn value(&self) -> &[u8] {
        &self.value
    }
    
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
    
    pub fn created_at(&self) -> u64 {
        self.created_at
    }
    
    pub fn updated_at(&self) -> u64 {
        self.updated_at
    }
    
    pub fn status(&self) -> u64 {
        self.status
    }

    pub fn update(&mut self, new_value: Vec<u8>) {
        self.value = new_value;
        self.updated_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.digest = self.hash();
    }
    
    pub fn set_status(&mut self, status: u64) {
        self.status = status;
        self.digest = self.hash();
    }
}

