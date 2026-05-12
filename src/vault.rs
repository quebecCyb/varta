
use std::fs;
use std::path::PathBuf;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

use hkdf::Hkdf;
use sha2::{Sha256, Digest};
use zeroize::Zeroize;

use crate::config::{
    VERSION, generate_random_key, VAULT_FILE_NAME,
    VAULT_AES_KEY_SALT, VAULT_META_KEY_SALT,
    OP_CREATE, OP_UPDATE, OP_DELETE,
};
use crate::operation::Operation;
use crate::vault_object::VaultObject;
use crate::crypto::symm_enc;
use crate::agent::Agent;
use crate::storage::obs::{ObjectStorage, ObjectPlainIter};
use crate::storage::ops::{OperationStorage};



pub struct Vault {
    version: u8,
    agent_id: [u8; 32],
    master_key: [u8; 32],
    vault_digest: [u8; 32],

    name: String,
    meta_key: [u8; 32],
    storage: ObjectStorage,
    audit: OperationStorage,
    last_op: Option<Operation>,
}

impl Vault {
    pub const SERIALIZED_SIZE: usize = 1 + 32 + 32 + 32; // 97 bytes
    
    pub fn to_bytes(&self) -> [u8; Self::SERIALIZED_SIZE] {
        let mut buffer = [0u8; Self::SERIALIZED_SIZE];
        let mut offset = 0;
        
        // version: u8 (1 byte)
        buffer[offset] = self.version;
        offset += 1;
        
        // agent_id: [u8; 32] (32 bytes)
        buffer[offset..offset + 32].copy_from_slice(&self.agent_id);
        offset += 32;
        
        // master_key: [u8; 32] (32 bytes)
        buffer[offset..offset + 32].copy_from_slice(&self.master_key);
        offset += 32;
        
        // vault_digest: [u8; 32] (32 bytes)
        buffer[offset..offset + 32].copy_from_slice(&self.vault_digest);
        
        buffer
    }
    
    /// Бинарная десериализация - возвращает кортеж из 4 полей
    pub fn from_bytes(data: &[u8]) -> Result<(u8, [u8; 32], [u8; 32], [u8; 32])> {
        if data.len() < Self::SERIALIZED_SIZE {
            return Err(format!(
                "Invalid data size: expected {}, got {}",
                Self::SERIALIZED_SIZE,
                data.len()
            ).into());
        }
        
        let mut offset = 0;
        
        // version: u8
        let version = data[offset];
        offset += 1;
        
        // agent_id: [u8; 32]
        let mut agent_id = [0u8; 32];
        agent_id.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;
        
        // master_key: [u8; 32]
        let mut master_key = [0u8; 32];
        master_key.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;
        
        // vault_digest: [u8; 32]
        let mut vault_digest = [0u8; 32];
        vault_digest.copy_from_slice(&data[offset..offset + 32]);
        
        Ok((version, agent_id, master_key, vault_digest))
    }
    
    /// Encrypt for Header Storage
    pub fn encrypt_for_header(&self) -> Result<([u8; 12], [u8; 97], [u8; 16])> {
        let plaintext = self.to_bytes();
        
        let (nonce, ciphertext) = symm_enc::encrypt(&self.meta_key, &plaintext);
        
        if ciphertext.len() < 16 {
            return Err("Invalid ciphertext length".into());
        }
        
        let tag_offset = ciphertext.len() - 16;
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&ciphertext[tag_offset..]);
        
        let mut ciphertext_array = [0u8; 97];
        let ciphertext_len = tag_offset.min(97);
        ciphertext_array[..ciphertext_len].copy_from_slice(&ciphertext[..ciphertext_len]);
        
        let mut nonce_array = [0u8; 12];
        if nonce.len() >= 12 {
            nonce_array.copy_from_slice(&nonce[..12]);
        }
        
        Ok((nonce_array, ciphertext_array, tag))
    }
    
    pub fn decrypt_from_header(
        nonce: &[u8; 12],
        ciphertext: &[u8],
        tag: &[u8; 16],
        meta_key: &[u8; 32],
    ) -> Result<(u8, [u8; 32], [u8; 32], [u8; 32])> {
        // ciphertext + tag
        let mut full_ciphertext = ciphertext.to_vec();
        full_ciphertext.extend_from_slice(tag);
        
        // Decrypt AES-256-GCM
        let plaintext = symm_enc::decrypt(meta_key, nonce, &full_ciphertext);
        
        // Binary deserialization
        Self::from_bytes(&plaintext)
    }

    pub fn new(
        name: String, agent_id: [u8; 32], derivation_key: &[u8; 32]
    ) -> Result<Self> {
        let master_key = generate_random_key();
        let meta_key = Vault::derive_meta_key(derivation_key, &name);
        let vault_dir = Vault::get_path(agent_id, &name);
        let vault_file_path = vault_dir.join(VAULT_FILE_NAME);
        let storage = ObjectStorage::new(&vault_file_path)?;
        let mut audit = OperationStorage::new(&vault_file_path)?;

        let op = Operation::initial(agent_id, &name);
        audit.append_operation(&op.to_bytes()?, &master_key)?;
        let last_op = Some(op);
        let mut vault = Self {
            version: VERSION,
            name: name,
            agent_id,
            master_key,
            storage,
            audit,
            vault_digest: [0u8; 32],
            meta_key: meta_key,
            last_op,
        };

        vault.vault_digest = vault.state_hash();
        vault.save()?;

        Ok(vault)
    }

    pub fn save(&mut self) -> Result<()> {
        let (nonce_array, ciphertext_only, tag) = self.encrypt_for_header()?;
        self.storage.set_vault_metadata(nonce_array, ciphertext_only, tag)?;
        self.audit.set_vault_metadata(nonce_array, ciphertext_only, tag)?;

        println!("Vault saved: {}", hex::encode(self.vault_digest));
        Ok(())
    }

    pub fn open(name: String, agent_id: [u8; 32], derivation_key: &[u8; 32]) -> Result<Vault> {
        let meta_key = Vault::derive_meta_key(derivation_key, &name);
        
        let vault_dir = Vault::get_path(agent_id, &name);
        
        if !vault_dir.exists() {
            return Err(format!("Vault not found: {}", name).into());
        }

        let vault_file_path = vault_dir.join(VAULT_FILE_NAME);
        
        let storage = ObjectStorage::open(&vault_file_path)?;
        let audit = OperationStorage::open(&vault_file_path)?;
        
        if !storage.has_vault_metadata() || !audit.has_vault_metadata() {
            return Err("Vault metadata not found in storage".into());
        }
        
        let (nonce, ciphertext, tag) = storage.get_vault_metadata();
        
        let (version, agent_id, master_key, vault_digest) = 
            Vault::decrypt_from_header(nonce, ciphertext, tag, &meta_key)?;
        
        let mut vault = Self {
            version,
            agent_id,
            master_key,
            vault_digest,
            audit,
            name,
            meta_key,
            storage,
            last_op: None,
        };

        println!("Vault loaded: {}", vault.name);
        vault.read_last_op()?;
        Ok(vault)
    }

    pub fn read_last_op(&mut self) -> Result<()> {
        let last_op_bytes = self.audit.read_last_operation(&self.master_key)?;
        if let Some(bytes) = last_op_bytes {
            let last_op = Operation::from_bytes(&bytes)?;
            self.last_op = Some(last_op);
        }
        Ok(())
    }
    
    /// =================
    /// Getters 
    /// =================

    pub fn get_name(&self) -> &str {
        &self.name
    }

    pub fn get_agent_id(&self) -> [u8; 32] {
        self.agent_id
    }


    // =================
    // OPERATIONS 
    // =================

    fn execute_operation<F>(&mut self, operation_name: &str, operation: F) -> Result<()>
    where
        F: FnOnce(&mut Self) -> Result<()>,
    {
        let old_digest = self.vault_digest;
        
        operation(self)?;
        
        let new_digest = self.state_hash();
        self.vault_digest = new_digest;
        
        if old_digest != new_digest {
            println!("⚠️  Vault state changed after '{}'", operation_name);
            println!("   Old hash: {}", hex::encode(old_digest));
            println!("   New hash: {}", hex::encode(new_digest));

            if let Some(op) = self.last_op.as_ref() {
                let bytes = op.to_bytes()?;
                self.audit.append_operation(&bytes, &self.master_key)?;
            }
        }
        
        self.save()?;
        Ok(())
    }

    pub fn exists_object(&self, key: &str) -> bool {
        self.storage.has_object(key)
    }

    pub fn create_object(&mut self, key: String, value: Vec<u8>) -> Result<()> {
        if self.exists_object(&key) {
            return Err(format!("Object already exists: {}", key).into());
        }
        
        self.execute_operation("create_object", |vault| {
            let obj = VaultObject::new(key.clone(), value);
            let data = obj.to_bytes()?;
            
            vault.storage.add_object(&key, &data, &vault.master_key)?;
            
            vault.last_op = Some(Operation::new(
                vault,
                &obj,
                OP_CREATE,
                vault.last_op.as_ref().ok_or("No last operation found")?,
            ));
            
            println!("Object created: {}", key);
            Ok(())
        })?;
        Ok(())
    }

    pub fn update_object(&mut self, key: &str, value: Vec<u8>) -> Result<()> {
        if !self.exists_object(key) {
            return Err(format!("Object not found: {}", key).into());
        }
        
        self.execute_operation("update_object", |vault| {
            let data = vault.storage.get_object(key, &vault.master_key)?;
            let mut obj = VaultObject::from_bytes(&data)?;
            
            obj.update(value);
            let updated_data = obj.to_bytes()?;
            
            vault.storage.upd_object(key, &updated_data, &vault.master_key)?;
            
            vault.last_op = Some(Operation::new(
                vault,
                &obj,
                OP_UPDATE,
                vault.last_op.as_ref().ok_or("No last operation found")?,
            ));


            println!("Object updated: {}", key);
            Ok(())
        })?;
        Ok(())
    }

    pub fn list_objects_iter(&self) -> ObjectPlainIter<'_> {
        self.storage.list_objects(&self.master_key)
    }

    pub fn read_object(&self, key: &str) -> Result<VaultObject> {
        if !self.exists_object(key) {
            return Err(format!("Object not found: {}", key).into());
        }
        
        let data = self.storage.get_object(key, &self.master_key)?;
        VaultObject::from_bytes(&data)
    }

    pub fn delete_object(&mut self, key: &str) -> Result<()> {
        if !self.exists_object(key) {
            return Err(format!("Object not found: {}", key).into());
        }
        
        self.execute_operation("secure_delete_object", |vault| {
            vault.storage.secure_del_object(key, &vault.master_key)?;

            vault.last_op = Some(Operation::new(
                vault,
                &VaultObject::new("deleted".to_string(), vec![]),
                OP_DELETE,
                vault.last_op.as_ref().ok_or("No last operation found")?,
            ));


            println!("Object securely deleted: {}", key);
            Ok(())
        })?;
        Ok(())
    }

    /// =====================
    /// CRYPTO 
    /// =====================

    pub fn derive_vault_key(&self) -> [u8; 32] {
        let salt = VAULT_AES_KEY_SALT;
        let hkdf = Hkdf::<Sha256>::new(Some(salt.as_bytes()), &self.master_key);
        let mut aes_key = [0u8; 32];
        let context: &[u8] = self.name.as_bytes();
        hkdf.expand(context, &mut aes_key)
            .expect("HKDF expansion failed for vault_key");

        aes_key
    }

    // Derive AES key for main object encryption
    pub fn derive_meta_key(
        derivation_key: &[u8; 32],
        name: &str,
    ) -> [u8; 32] {
        let salt = VAULT_META_KEY_SALT;
        let hkdf = Hkdf::<Sha256>::new(Some(salt.as_bytes()), derivation_key);
        let mut aes_key = [0u8; 32];
        let context: &[u8] = name.as_bytes();
        hkdf.expand(context, &mut aes_key)
            .expect("HKDF expansion failed for meta_key");

        aes_key
    }

    /// Fast state hash - uses cached vault_digest and last operation hash.
    pub fn state_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();

        hasher.update(&self.version.to_le_bytes());
        hasher.update(&self.agent_id);
        hasher.update(self.name.as_bytes());
        hasher.update(&self.master_key);
        hasher.update(&self.vault_digest);
        
        if let Some(ref op) = self.last_op {
            hasher.update(&op.op_hash);
        }

        hasher.finalize().into()
    }


    // Determined folder name
    pub fn hash_dir_name(agent_id: [u8; 32], name: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(&agent_id);
        hasher.update(name.as_bytes());
        let hash: [u8; 32] = hasher.finalize().into();
        hex::encode(&hash[0..16])
    }


    pub fn get_path(agent_id: [u8; 32], name: &str) -> PathBuf {
        let agent_path = Agent::get_path(agent_id);
        agent_path.join(Vault::hash_dir_name(agent_id, name))
    }
}

impl Drop for Vault {
    fn drop(&mut self) {
        self.master_key.zeroize();
        self.meta_key.zeroize();
    }
}
