
use std::fs;
use std::collections::HashMap;

use hkdf::Hkdf;

use sha2::{Sha256, Digest};
use borsh::{BorshSerialize, BorshDeserialize, from_slice, to_vec};

use crate::common::{VERSION, generate_random_key};
use crate::operation::{Operation, OP_CREATE};
use crate::vault_object::VaultObject;
use crate::crypto::symm_enc;
use crate::agent::Agent;
use zeroize::Zeroize;


#[derive(BorshSerialize, BorshDeserialize)]
pub struct Vault {
    version: u8,

    agent_id: [u8; 32],

    pub name: String,
    
    master_key: [u8; 32],
    vault_digest: [u8; 32],

    #[borsh(skip)]
    meta_key: Option<[u8; 32]>,

    #[borsh(skip)]
    last_op: Option<Operation>,
}

impl Vault {
    pub fn new(
        name: String, agent_id: [u8; 32], derivation_key: &[u8; 32]
    ) -> Self {
        let master_key = generate_random_key();
        let meta_key = Vault::derive_meta_key(derivation_key, &name);
        let last_op = Some(Operation::initial(&master_key, agent_id, &name));

        let vault = Self {
            version: VERSION,
            name,
            agent_id,
            master_key,
            vault_digest: [0u8; 32],
            meta_key: Some(meta_key),
            last_op,
        };

        vault.save();

        vault
    }

    pub fn save(&self) {
        let meta_key = self.meta_key.expect("Meta key should be set");
        let vault_path = Vault::get_path(self.agent_id, &self.name);
        let objects_path = Vault::get_path_objects(self.agent_id, &self.name);
        let operations_path = Vault::get_path_operations(self.agent_id, &self.name);

        if !fs::exists(&vault_path).unwrap() {
            fs::create_dir_all(&vault_path).unwrap();
        }

        if !fs::exists(&objects_path).unwrap() {
            fs::create_dir_all(&objects_path).unwrap();
        }

        if !fs::exists(&operations_path).unwrap() {
            fs::create_dir_all(&operations_path).unwrap();
        }

        let plaintext = to_vec(self).unwrap();
        let (nonce, ciphertext) = symm_enc::encrypt(&meta_key, &plaintext);

        let encrypted_data = (nonce, ciphertext);
        fs::write(format!("{}/index", &vault_path), to_vec(&encrypted_data).unwrap()).unwrap();
        println!("Vault saved: {}", vault_path);
    }

    pub fn open(name: String, agent_id: [u8; 32], derivation_key: &[u8; 32]) -> Vault {
        let meta_key = Vault::derive_meta_key(derivation_key, &name);
        
        let path = Vault::get_path(agent_id, &name);
    
        if !fs::exists(&path).unwrap() {
            panic!("Vault not found: {}", name);
        }
        
        let data = fs::read(format!("{}/index", &path)).unwrap();
        let (nonce, ciphertext): (Vec<u8>, Vec<u8>) = from_slice(&data).unwrap();
        let decrypted = symm_enc::decrypt(&meta_key, &nonce, &ciphertext);
        let mut vault: Vault = from_slice(&decrypted).unwrap();
        
        vault.meta_key = Some(meta_key);

        println!("Vault loaded: {}", name);
        vault.read_last_op();
        vault
    }

    pub fn read_last_op(&mut self) {
        let op_path = Vault::get_path_operations(self.agent_id, &self.name);
        let last_file: Option<String> = fs::read_dir(&op_path)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .max();
        
        if let Some(last_file) = last_file {
            let op = Operation::read(
                &self.master_key, 
                self.agent_id, 
                &self.name, 
                &last_file
            );
            self.last_op = Some(op);
        }
    }
    
    /////////////
    // Getters //
    /////////////

    pub fn get_name(&self) -> &str {
        &self.name
    }

    pub fn get_agent_id(&self) -> [u8; 32] {
        self.agent_id
    }


    ////////////////////////
    // OPERATIONS //////////
    ////////////////////////

    fn execute_operation<F>(&mut self, operation_name: &str, operation: F)
    where
        F: FnOnce(&mut Self),
    {
        let old_digest = self.vault_digest;
        
        operation(self);
        
        let new_digest = self.hash();
        self.vault_digest = new_digest;
        
        if old_digest != new_digest {
            println!("⚠️  Vault state changed after '{}'", operation_name);
            println!("   Old hash: {}", hex::encode(old_digest));
            println!("   New hash: {}", hex::encode(new_digest));
        }
        
        self.save();
    }

    pub fn exists_object(&self, key: &str) -> bool {
        let path = VaultObject::get_path(&self.derive_vault_key(), self.agent_id, &self.name, key);
        fs::exists(&path).unwrap_or(false)
    }

    pub fn create_object(&mut self, key: String, value: Vec<u8>) {
        if self.exists_object(&key) {
            panic!("Object already exists: {}", key);
        }
        
        self.execute_operation("create_object", |vault| {
            let obj = VaultObject::new(
                key.clone(),
                value,
                vault.name.clone(),
                vault.agent_id,
                Some(vault.derive_vault_key())
            );

            vault.last_op = Some(Operation::new(
                &vault.master_key,
                vault,
                &obj,
                OP_CREATE,
                vault.last_op.as_ref().expect("No last operation found!"),
            ));
        });
    }

    pub fn update_object(&mut self, key: &str, value: Vec<u8>) {
        if !self.exists_object(key) {
            panic!("Object not found: {}", key);
        }
        
        self.execute_operation("update_object", |vault| {
            let encrypt_filename = VaultObject::get_encrypted_filename(&vault.derive_vault_key(), key);
            let mut obj = VaultObject::open(&vault.name, vault.agent_id, encrypt_filename, vault.derive_vault_key());
            obj.update(value);
        });
    }

    pub fn list_objects(&self) -> Vec<String> {
        let obs_path = Vault::get_path_objects(self.agent_id, &self.name);

        println!("Restoring objects from: {}", obs_path);
        
        if !fs::exists(&obs_path).unwrap() {
            panic!("Objects directory not found: {}", obs_path);
        }
    
        let mut objects: Vec<String> = Vec::new();

        for entry in fs::read_dir(&obs_path).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_file() {
                let filename: &str = path.file_name().unwrap().to_str().unwrap();
                objects.push(VaultObject::get_decrypted_filename(&self.derive_vault_key(), filename));
            }
        }
        
        objects
    }

    pub fn read_object(&self, key: &str) -> VaultObject {
        if !self.exists_object(key) {
            panic!("Object not found: {}", key);
        }
        
        let encrypt_filename = VaultObject::get_encrypted_filename(&self.derive_vault_key(), key);
        let obj = VaultObject::open(&self.name, self.agent_id, encrypt_filename, self.derive_vault_key());
        obj
    }

    pub fn delete_object(&mut self, key: &str) {
        if !self.exists_object(key) {
            panic!("Object not found: {}", key);
        }
        
        self.execute_operation("delete_object", |vault| {
            let encrypt_filename = VaultObject::get_encrypted_filename(&vault.derive_vault_key(), key);
            let obj = VaultObject::open(&vault.name, vault.agent_id, encrypt_filename, vault.derive_vault_key());
            obj.delete();
        });
    }

    pub fn restore_vault(&self) -> HashMap<String, Vec<u8>> {
        let obs_path = Vault::get_path_objects(self.agent_id, &self.name);

        println!("Restoring objects from: {}", obs_path);
        
        if !fs::exists(&obs_path).unwrap() {
            panic!("Objects directory not found: {}", obs_path);
        }
    
        let mut objects = HashMap::new();

        for entry in fs::read_dir(&obs_path).unwrap() {
            let entry = entry.unwrap();

            if entry.path().is_file() {
                let encrypted_filename = entry.file_name().into_string().unwrap();
                let binary_data = fs::read(&entry.path()).unwrap();
                
                objects.insert(encrypted_filename, binary_data);
            }
        }
        
        println!("Objects restored: {}", objects.len());
        
        objects
    }

    ////////////////////////
    // CRYPTO /////////////
    ////////////////////////

    pub fn derive_vault_key(&self) -> [u8; 32] {
        let salt = "varta_vault_aes_encryption";
        let hkdf = Hkdf::<Sha256>::new(Some(salt.as_bytes()), &self.master_key);
        let mut aes_key = [0u8; 32];
        let context: &[u8] = self.name.as_bytes();
        hkdf.expand(context, &mut aes_key)
            .expect("HKDF expansion failed");

        aes_key
    }

    // Derive AES key for main object encryption
    pub fn derive_meta_key(
        derivation_key: &[u8; 32],
        name: &str,
    ) -> [u8; 32] {
        let salt = format!("varta_meta_encryption");
        let hkdf = Hkdf::<Sha256>::new(Some(salt.as_bytes()), derivation_key);
        let mut aes_key = [0u8; 32];
        let context: &[u8] = name.as_bytes();
        hkdf.expand(context, &mut aes_key)
            .expect("HKDF expansion failed");

        aes_key
    }

    // Get full vault fingerprint
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();

        hasher.update(&self.version.to_le_bytes());
        hasher.update(&self.agent_id);
        hasher.update(self.name.as_bytes());
        hasher.update(&self.master_key);

        // Sort keys lexicographically for deterministic hashing
        let objects: HashMap<String, Vec<u8>> = self.restore_vault();
        let mut sorted_keys: Vec<&String> = objects.keys().collect();
        sorted_keys.sort();
        
        for key in sorted_keys {
            let value = objects.get(key).unwrap();
            hasher.update(key.as_bytes());
            hasher.update(value);
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


    pub fn get_path(agent_id: [u8; 32], name: &str) -> String {
        let agent_path = Agent::get_path(agent_id);
        format!("{}/{}", agent_path, Vault::hash_dir_name(agent_id, name))
    }

    pub fn get_path_objects(agent_id: [u8; 32], name: &str) -> String {
        let vault_path = Vault::get_path(agent_id, name);
        format!("{}/obs", vault_path)
    }

    pub fn get_path_operations(agent_id: [u8; 32], name: &str) -> String {
        let vault_path = Vault::get_path(agent_id, name);
        format!("{}/ops", vault_path)
    }
}

impl Drop for Vault {
    fn drop(&mut self) {
        self.master_key.zeroize();
        if let Some(ref mut key) = self.meta_key {
            key.zeroize();
        }
        println!("🔒 Vault master_key and meta_key zeroized");
    }
}
