
use std::fs::{self};
use std::time::{SystemTime, UNIX_EPOCH};

use borsh::{BorshSerialize, BorshDeserialize, to_vec, from_slice};
use sha2::{Sha256, Digest};
use hkdf::Hkdf;

use crate::crypto::symm_enc;
use crate::vault::Vault;
use crate::common::VERSION;

#[derive(BorshSerialize, BorshDeserialize)]
pub struct VaultObject {
    version: u8,
    
    pub key: String,
    pub value: Vec<u8>,

    status: u64,
    digest: [u8; 32],

    created_at: u64,
    updated_at: u64,

    vault_name: String,
    agent_id: [u8; 32],

    #[borsh(skip)]
    vault_aes_key: Option<[u8; 16]>,
}


impl VaultObject {
    pub fn new(key: String, value: Vec<u8>, vault_name: String, agent_id: [u8; 32], vault_aes_key: Option<[u8; 16]>) -> Self {
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
            vault_name,
            agent_id,
            vault_aes_key,
        };
        
        obj.digest = obj.hash();
        obj.save();
        obj
    }


    pub fn save(&self) {
        let vault_aes_key = self.vault_aes_key.expect("VaultObject: vault_aes_key not set");
        let path = VaultObject::get_path(&vault_aes_key, self.agent_id, &self.vault_name, &self.key);
        let vault_object_key = VaultObject::derive_vault_object_key(&vault_aes_key, &self.key);
        let (nonce, ciphertext) = symm_enc::encrypt(&vault_object_key, &to_vec(self).unwrap());
        fs::write(&path, to_vec(&(nonce, ciphertext)).unwrap());
        println!("Object saved: {}", path);
    }

    pub fn open(vault_name: &str, agent_id: [u8; 32], encrypted_filename: String, vault_aes_key: [u8; 16]) -> Self {
        let key: String = VaultObject::get_decrypted_filename(&vault_aes_key, &encrypted_filename);
        let path = VaultObject::get_path(&vault_aes_key, agent_id, vault_name, &key);
        
        if !fs::exists(&path).unwrap() {
            panic!("VaultObject not found: {}", key);
        }

        let aes_key = VaultObject::derive_vault_object_key(&vault_aes_key, &key);
        
        let data = fs::read(&path).unwrap();
        let (nonce, ciphertext): (Vec<u8>, Vec<u8>) = from_slice(&data).unwrap();
        let mut obj: VaultObject = from_slice(&symm_enc::decrypt(&aes_key, &nonce, &ciphertext)).unwrap();
        obj.vault_aes_key = Some(vault_aes_key);
        
        println!("Object loaded: {}", path);
        obj
    }
    ////////////////////////
    // CRYPTO //////////////
    ////////////////////////

    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        
        hasher.update(&self.key.as_bytes());
        hasher.update(&self.value);
        hasher.update(&self.status.to_le_bytes());
        hasher.update(&self.created_at.to_le_bytes());
        hasher.update(self.vault_name.as_bytes());
        hasher.update(&self.agent_id);
        
        hasher.finalize().into()
    }


    pub fn derive_vault_object_key(vault_aes_key: &[u8; 16], key: &str) -> [u8; 16] {
        let salt = "varta_vault_object_aes_encryption";
        let hkdf = Hkdf::<Sha256>::new(Some(salt.as_bytes()), vault_aes_key);
        let mut aes_key = [0u8; 16];
        let context: &[u8] = key.as_bytes();
        hkdf.expand(context, &mut aes_key)
            .expect("HKDF expansion failed");

        aes_key
    }


    ////////////////////////
    // OPERATIONS //////////
    ////////////////////////

    pub fn update(&mut self, new_value: Vec<u8>) {
        self.value = new_value;
        self.updated_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.digest = self.hash();
        self.save();
    }

    pub fn delete(&self) {
        let vault_aes_key = self.vault_aes_key.expect("VaultObject: vault_aes_key not set");
        let path = VaultObject::get_path(&vault_aes_key, self.agent_id, &self.vault_name, &self.key);
        
        if fs::exists(&path).unwrap() {
            fs::remove_file(&path).unwrap();
            println!("Object deleted: {}", path);
        }
    }

    ////////////////////////
    // STATIC //////////////
    ////////////////////////

    pub fn get_encrypted_filename(vault_aes_key: &[u8; 16], key: &str) -> String {
        format!("{}.ob", symm_enc::encrypt_filename(vault_aes_key, key))
    }

    pub fn get_decrypted_filename(vault_aes_key: &[u8; 16], hex_name: &str) -> String {
        symm_enc::decrypt_filename(vault_aes_key, hex_name.split(".").next().unwrap()) 
    }

    pub fn get_path(vault_aes_key: &[u8; 16], agent_id: [u8; 32], vault_name: &str, key: &str) -> String {
        let vault_path = Vault::get_path_objects(agent_id, vault_name);
        let encrypted_filename = VaultObject::get_encrypted_filename(vault_aes_key, key);
        format!("{}/{}", vault_path, encrypted_filename)
    }
}

