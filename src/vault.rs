
use std::fs;
use std::collections::HashMap;

use hkdf::Hkdf;

use sha2::{Sha256, Digest};
use borsh::{BorshSerialize, BorshDeserialize, from_slice, to_vec};

use crate::common::{VERSION, generate_random_key};
use crate::agent::Agent;
use crate::operation::{Operation, OP_CREATE};
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
    aes_metadata_key: Option<[u8; 16]>,

    #[borsh(skip)]
    last_op: Option<Operation>,

    #[borsh(skip)]
    objects: HashMap<String, VaultObject>,
}

impl Vault {
    pub fn new(
        name: String, agent: &Agent //, derivation_key: [u8; 32]
    ) -> Self {
        let derivation_key = agent.get_vault_derivation_key();
        let aes_metadata_key = Vault::derive_meta_key(&derivation_key, &name);
        let master_key = generate_random_key();
        let agent_id = Agent::get_id(&agent.name);
        let vault = Self {
            name: name.clone(),
            agent_id,
            master_key,
            version: VERSION,
            vault_digest: [0u8; 32],
            // ops: Vec::new(),
            objects: HashMap::new(),
            aes_metadata_key: Some(aes_metadata_key),
            last_op: Some(Operation::initial(&master_key, agent_id, &name)),
        };
        vault.save();
        vault
    }

    pub fn save(&self) {
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

        let aes_metadata_key = self.aes_metadata_key.expect("No AES Metadata Key set up!");
        let plaintext = to_vec(self).unwrap();
        let (nonce, ciphertext) = symm_enc::encrypt(&aes_metadata_key, &plaintext);

        let encrypted_data = (nonce, ciphertext);
        fs::write(format!("{}/index", &vault_path), to_vec(&encrypted_data).unwrap()).unwrap();
        println!("Vault saved: {}", vault_path);
    }

    pub fn open(name: String, agent: &Agent) -> Vault {
        let derivation_key = agent.get_vault_derivation_key();
        let aes_metadata_key = Vault::derive_meta_key(&derivation_key, &name);
        
        let path = Vault::get_path(Agent::get_id(&agent.name), &name);
    
        if !fs::exists(&path).unwrap() {
            panic!("Vault not found: {}", name);
        }
        
        let data = fs::read(format!("{}/index", &path)).unwrap();
        let (nonce, ciphertext): (Vec<u8>, Vec<u8>) = from_slice(&data).unwrap();
        let decrypted = symm_enc::decrypt(&aes_metadata_key, &nonce, &ciphertext);
        let mut vault: Vault = from_slice(&decrypted).unwrap();
        vault.aes_metadata_key = Some(aes_metadata_key);
        
        println!("Vault loaded: {}", name);
        vault.restore_objects();
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

    pub fn get_agent_id(&self) -> [u8; 32] {
        self.agent_id
    }


    ////////////////////////
    // OPERATIONS //////////
    ////////////////////////

    pub fn create_object(&mut self, key: String, value: Vec<u8>) {
        let obj = VaultObject::new(key, value, self.name.clone(), self.agent_id, Some(self.derive_vault_key()));
        self.vault_digest = self.hash();

        self.last_op = Some(Operation::new(
            &self.master_key,
            &self,
            &obj,
            OP_CREATE,
            self.last_op.as_ref().expect("No last operation found!"),
        ));

        self.objects.insert(obj.key.clone(), obj);

        self.save();
    }

    pub fn update_object(&mut self, key: &str, value: Vec<u8>) {
        if !self.objects.contains_key(key) {
            panic!("Object not found: {}", key);
        }
        
        let obj = self.objects.get_mut(key).unwrap();
        obj.update(value);

        self.vault_digest = self.hash();
        self.save();
    }

    pub fn list_objects(&self) -> Vec<String> {
        self.objects.keys().cloned().collect()
    }

    pub fn read_object(&self, key: &str) -> &VaultObject {
        if !self.objects.contains_key(key) {
            panic!("Object not found: {}", key);
        }
        
        self.objects.get(key).unwrap()
    }

    pub fn delete_object(&mut self, key: &str) {
        if !self.objects.contains_key(key) {
            panic!("Object not found: {}", key);
        }
        
        let obj = self.objects.remove(key).unwrap();
        obj.delete();

        self.vault_digest = self.hash();
        self.save();
    }

    pub fn restore_objects(&mut self) {
        let obs_path = Vault::get_path_objects(self.agent_id, &self.name);

        println!("Restoring objects from: {}", obs_path);
        
        if !fs::exists(&obs_path).unwrap() {
            panic!("Objects directory not found: {}", obs_path);
        }

        for entry in fs::read_dir(&obs_path).unwrap() {
            let entry = entry.unwrap();

            if entry.path().is_file() {
                let encrypted_filename = entry.file_name().into_string().unwrap();
                let obj = VaultObject::open(&self.name, self.agent_id, encrypted_filename, self.derive_vault_key());
                
                self.objects.insert(obj.key.clone(), obj);
            }
        }
        
        println!("Objects restored: {}", self.objects.len());

        self.vault_digest = self.hash();
        self.save();
    }

    ////////////////////////
    // CRYPTO /////////////
    ////////////////////////

    pub fn derive_vault_key(&self) -> [u8; 16] {
        let salt = "varta_vault_aes_encryption";
        let hkdf = Hkdf::<Sha256>::new(Some(salt.as_bytes()), &self.master_key);
        let mut aes_key = [0u8; 16];
        let context: &[u8] = self.name.as_bytes();
        hkdf.expand(context, &mut aes_key)
            .expect("HKDF expansion failed");

        aes_key
    }

    // Derive AES key for main object encryption
    pub fn derive_meta_key(
        derivation_key: &[u8; 32],
        name: &str,
    ) -> [u8; 16] {
        let salt = format!("varta_meta_encryption");
        let hkdf = Hkdf::<Sha256>::new(Some(salt.as_bytes()), derivation_key);
        let mut aes_key = [0u8; 16];
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
        let mut sorted_keys: Vec<&String> = self.objects.keys().collect();
        sorted_keys.sort();
        
        for key in sorted_keys {
            let obj = self.objects.get(key).unwrap();
            hasher.update(&obj.hash());
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
