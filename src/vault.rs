
use std::fs;
use std::collections::HashMap;

use hkdf::Hkdf;

use sha2::{Sha256, Digest};
use borsh::{BorshSerialize, BorshDeserialize, from_slice, to_vec};

use crate::common::{VERSION, generate_random_key};
use crate::agent::Agent;
use crate::operation::Operation;
use crate::vault_object::VaultObject;
use crate::crypto::symm_enc;

#[derive(BorshSerialize, BorshDeserialize)]
pub struct Vault {
    version: u8,

    agent_id: [u8; 32],

    pub name: String,
    
    master_key: [u8; 32],
    vault_digest: [u8; 32],

    #[borsh(skip)]
    aes_key: Option<[u8; 16]>,

    #[borsh(skip)]
    ops: Vec<Operation>,

    #[borsh(skip)]
    objects: HashMap<String, VaultObject>,
}

impl Vault {
    pub fn new(name: String, agent_id: [u8; 32], aes_key: Option<[u8; 16]>, master_key: [u8; 32]) -> Self {
        let vault = Self {
            name,
            agent_id,
            master_key,
            version: VERSION,
            vault_digest: [0u8; 32],
            ops: Vec::new(),
            objects: HashMap::new(),
            aes_key
        };

        vault
    }

    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();

        hasher.update(&self.version.to_le_bytes());
        hasher.update(&self.agent_id);
        hasher.update(self.name.as_bytes());
        hasher.update(&self.master_key);

        // Sort keys lexicographically for deterministic hashing
        let mut sorted_keys: Vec<&String> = self.objects.keys().collect();
        sorted_keys.sort();
        
        for key in sorted_keys {
            let obj = self.objects.get(key).unwrap();
            hasher.update(&obj.hash());
        }

        hasher.finalize().into()
    }

    pub fn get_path(&self) -> String {
        Vault::get_path_id(self.agent_id, &self.name)
    }

    pub fn save(&self) {
        let vault_path = self.get_path();

        if !fs::exists(&vault_path).unwrap() {
            fs::create_dir_all(&vault_path).unwrap();
        }

        if !fs::exists(format!("{}/obs", &vault_path)).unwrap() {
            fs::create_dir_all(format!("{}/obs", &vault_path)).unwrap();
        }

        if !fs::exists(format!("{}/ops", &vault_path)).unwrap() {
            fs::create_dir_all(format!("{}/ops", &vault_path)).unwrap();
        }
        let aes_key = self.aes_key.expect("No AES Key set up!");
        let plaintext = to_vec(self).unwrap();
        let (nonce, ciphertext) = symm_enc::encrypt(&aes_key, &plaintext);

        let encrypted_data = (nonce, ciphertext);
        fs::write(format!("{}/index", &vault_path), to_vec(&encrypted_data).unwrap()).unwrap();
        println!("Vault saved: {}", vault_path);
    }

    pub fn create_object(&mut self, key: String, value: Vec<u8>) -> bool {
        let obj = VaultObject::create(key, value, self.name.clone(), self.agent_id, Some(self.get_vault_key()));
        self.objects.insert(obj.key.clone(), obj);
        self.vault_digest = self.hash();
        self.save();
        true
    }

    pub fn update_object(&mut self, key: &str, value: Vec<u8>) -> bool {
        if !self.objects.contains_key(key) {
            return false;
        }
        
        let obj = self.objects.get_mut(key).unwrap();
        obj.update(value);

        self.vault_digest = self.hash();
        self.save();
        true
    }

    pub fn list_objects(&self) -> Vec<String> {
        self.objects.keys().cloned().collect()
    }

    pub fn read_object(&self, key: &str) -> Option<&VaultObject> {
        if !self.objects.contains_key(key) {
            return None;
        }
        
        Some(self.objects.get(key).unwrap())
    }

    pub fn delete_object(&mut self, key: &str) -> bool {
        if !self.objects.contains_key(key) {
            return false;
        }
        
        let obj = self.objects.remove(key).unwrap();
        obj.delete();

        self.vault_digest = self.hash();
        self.save();
        true
    }

    pub fn get_vault_key(&self) -> [u8; 16] {
        let salt = "varta_vault_aes_encryption";
        let hkdf = Hkdf::<Sha256>::new(Some(salt.as_bytes()), &self.master_key);
        let mut aes_key = [0u8; 16];
        let context: &[u8] = self.name.as_bytes();
        hkdf.expand(context, &mut aes_key)
            .expect("HKDF expansion failed");

        aes_key
    }

    pub fn restore_objects(&mut self) -> bool {
        let obs_path = format!("{}/obs", self.get_path());

        println!("Restoring objects from: {}", obs_path);
        
        if !fs::exists(&obs_path).unwrap() {
            return false;
        }

        for entry in fs::read_dir(&obs_path).unwrap() {
            let entry = entry.unwrap();

            if entry.path().is_file() {
                let encrypted_filename = entry.file_name().into_string().unwrap();
                let obj = VaultObject::open(&self.name, self.agent_id, encrypted_filename, self.get_vault_key());
                
                self.objects.insert(obj.key.clone(), obj);
            }
        }
        
        println!("Objects restored: {}", self.objects.len());

        self.vault_digest = self.hash();
        self.save();
        true
    }

    // Static


    pub fn hash_name(agent_id: [u8; 32], name: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(&agent_id);
        hasher.update(name.as_bytes());
        let hash: [u8; 32] = hasher.finalize().into();
        hex::encode(&hash[0..16])
    }

    pub fn get_aes_key(
        derivation_key: &[u8; 32],
        name: &str,
    ) -> [u8; 16] {
        let salt = format!("varta_aes_encryption");
        let hkdf = Hkdf::<Sha256>::new(Some(salt.as_bytes()), derivation_key);
        let mut aes_key = [0u8; 16];
        let context: &[u8] = name.as_bytes();
        hkdf.expand(context, &mut aes_key)
            .expect("HKDF expansion failed");

        aes_key
    }

    pub fn create(name: String, agent: &Agent, derivation_key: [u8; 32]) -> Vault {
        let aes_key = Vault::get_aes_key(&derivation_key, &name);
        let vault = Vault::new(name, agent.get_id(), Some(aes_key), generate_random_key());
        vault.save();
        vault
    }

    pub fn open(name: String, agent: &Agent, derivation_key: [u8; 32]) -> Vault {
        let aes_key = Vault::get_aes_key(&derivation_key, &name);
        
        let path = Vault::get_path_id(agent.get_id(), &name);
    
        if !Vault::exists(&name, agent) {
            panic!("Vault not found: {}", name);
        }
        
        let data = fs::read(format!("{}/index", &path)).unwrap();
        let (nonce, ciphertext): (Vec<u8>, Vec<u8>) = from_slice(&data).unwrap();
        let decrypted = symm_enc::decrypt(&aes_key, &nonce, &ciphertext);
        let mut vault: Vault = from_slice(&decrypted).unwrap();
        vault.aes_key = Some(aes_key);
        
        println!("Vault loaded: {}", name);
        vault.restore_objects();
        vault
    }

    pub fn exists(name: &str, agent: &Agent) -> bool {
        let path = Vault::get_path_id(agent.get_id(), name);
        fs::exists(&path).unwrap()
    }


    pub fn get_path_id(agent_id: [u8; 32], name: &str) -> String {
        let agent_path = Agent::get_path_id(agent_id);
        format!("{}/{}", agent_path, Vault::hash_name(agent_id, name))
    }
}
