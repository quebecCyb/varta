use aes_gcm::{Aes256Gcm, Nonce, KeyInit};
use aes_gcm::aead::{Aead, OsRng};
use rand::RngCore;
use zeroize::Zeroize;

use super::block_header::{BlockHeader, BlockType, HEADER_SIZE};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

const NONCE_SIZE: usize = 12;
const AUTH_TAG_SIZE: usize = 16;
const MIN_BLOCK_SIZE: usize = HEADER_SIZE + NONCE_SIZE + AUTH_TAG_SIZE; // Minimal size
const BLOCK_SIZE: usize = 1024; // Block Size

pub struct Block {
    header: BlockHeader,
    nonce: [u8; 12], 
    ciphertext: Vec<u8>,
}


impl Block {
    pub fn encrypt(
        block_type: BlockType,
        key: &[u8; 32],
        plaintext: &[u8],
    ) -> Result<Self> {
        let header = BlockHeader::new(block_type, plaintext.len() as u32);
        
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let nonce_gcm = Nonce::from_slice(&nonce);
        
        let cipher = Aes256Gcm::new(key.into());
        let ciphertext = cipher.encrypt(nonce_gcm, plaintext)
            .map_err(|e| format!("Encryption failed: {}", e))?;
        
        Ok(Self {
            header,
            nonce,
            ciphertext,
        })
    }
    
    /// Encrypt with padding to fixed BLOCK_SIZE (1 KB)
    pub fn encrypt_padded(
        block_type: BlockType,
        key: &[u8; 32],
        plaintext: &[u8],
    ) -> Result<Self> {
        // plaintext max size 1 KB
        // BLOCK_SIZE = HEADER_SIZE + NONCE_SIZE + ciphertext_size
        // ciphertext_size = plaintext_size + AUTH_TAG_SIZE
        // plaintext_size = BLOCK_SIZE - HEADER_SIZE - NONCE_SIZE - AUTH_TAG_SIZE
        const MAX_PLAINTEXT_SIZE: usize = BLOCK_SIZE - HEADER_SIZE - NONCE_SIZE - AUTH_TAG_SIZE;
        
        if plaintext.len() > MAX_PLAINTEXT_SIZE {
            return Err(format!(
                "Plaintext too large for 1 KB block: {} > {} bytes",
                plaintext.len(),
                MAX_PLAINTEXT_SIZE
            ).into());
        }
        
        // padding to MAX_PLAINTEXT_SIZE
        let mut padded_plaintext = plaintext.to_vec();
        padded_plaintext.resize(MAX_PLAINTEXT_SIZE, 0);
        
        // encrypt padded data
        let header = BlockHeader::new(block_type, plaintext.len() as u32);
        
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let nonce_gcm = Nonce::from_slice(&nonce);
        
        let cipher = Aes256Gcm::new(key.into());
        let ciphertext = cipher.encrypt(nonce_gcm, padded_plaintext.as_ref())
            .map_err(|e| format!("Encryption failed: {}", e))?;
        
        Ok(Self {
            header,
            nonce,
            ciphertext,
        })
    }
    
    pub fn decrypt(&self, key: &[u8; 32]) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new(key.into());
        let nonce_gcm = Nonce::from_slice(&self.nonce);
        
        let padded_plaintext = cipher.decrypt(nonce_gcm, self.ciphertext.as_ref())
            .map_err(|e| format!("Decryption failed: {}", e))?;
        
        // remove padding using plaintext_size from header
        let real_size = self.header.plaintext_size() as usize;
        if real_size > padded_plaintext.len() {
            return Err(format!(
                "Invalid plaintext size in header: {} > {}",
                real_size,
                padded_plaintext.len()
            ).into());
        }
        
        Ok(padded_plaintext[..real_size].to_vec())
    }
    
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.size());
        
        bytes.extend_from_slice(&self.header.to_bytes());
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.ciphertext);
        
        bytes
    }
    
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < MIN_BLOCK_SIZE {
            return Err(format!("Data too short for block: {} < {}", data.len(), MIN_BLOCK_SIZE).into());
        }
        
        let mut offset = 0;
        
        let header = BlockHeader::from_bytes(&data[offset..offset + HEADER_SIZE])
            .map_err(|e| format!("Failed to parse block header: {}", e))?;
        offset += HEADER_SIZE;
        
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&data[offset..offset + 12]);
        offset += 12;
        
        let ciphertext = data[offset..].to_vec();
        
        Ok(Self {
            header,
            nonce,
            ciphertext,
        })
    }
    
    pub fn size(&self) -> usize {
        HEADER_SIZE + NONCE_SIZE + self.ciphertext.len()
    }
    
    pub const fn min_size() -> usize {
        MIN_BLOCK_SIZE
    }
    
    /// Fixed block size (1 KB)
    pub const fn block_size() -> usize {
        BLOCK_SIZE
    }
    
    /// Maximum plaintext size for 1 KB block
    pub const fn max_plaintext_size() -> usize {
        BLOCK_SIZE - HEADER_SIZE - NONCE_SIZE - AUTH_TAG_SIZE
    }
    
    /// Check if block is padded (size == BLOCK_SIZE)
    pub fn is_padded(&self) -> bool {
        self.size() == BLOCK_SIZE
    }
    
    pub fn header(&self) -> &BlockHeader {
        &self.header
    }
    
    pub fn header_mut(&mut self) -> &mut BlockHeader {
        &mut self.header
    }
    
    pub fn nonce(&self) -> &[u8; 12] {
        &self.nonce
    }
    
    pub fn ciphertext_size(&self) -> usize {
        self.ciphertext.len()
    }
}

impl Drop for Block {
    fn drop(&mut self) {
        self.ciphertext.zeroize();
    }
}
