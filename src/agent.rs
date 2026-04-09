use std::io::Read;
use std::fs::File;
use std::fs;
use sha2::{Sha256, Digest};
use hex;
use hkdf::Hkdf;
use crate::crypto::symm_enc;
use crate::device::Device;
use crate::common::{ROOT_SECRETS_FOLDER, generate_random_key};
use borsh::{from_slice, to_vec};
use zeroize::Zeroize;

pub struct Agent {
    pub name: String,
    master_key: [u8; 32],
}



impl Agent {
    pub fn new(name: String, password: Option<String>, derivation_key: Option<[u8; 32]>) -> Self {
        let master_key = if let Some(key) = derivation_key {
            Agent::derive_master_key(key)
        } else {
            generate_random_key()
        };
        
        println!("Master key created.");

        let agent = Self {
            name,
            master_key,
        };
        
        let mut pwd = password.unwrap_or_else(|| String::new());
        let meta_key = Agent::derive_meta_key(pwd.clone());
        pwd.zeroize();
        agent.save(meta_key);

        agent
    }
    
    pub fn save(&self, meta_key: [u8; 32]) {
        let agent_path = Agent::get_path(Agent::get_id(&self.name));

        if !fs::exists(&agent_path).unwrap() {
            fs::create_dir_all(&agent_path).unwrap();
        }

        let (nonce, cypher) = symm_enc::encrypt(&meta_key, &self.master_key);

        let encrypted_data = (nonce, cypher);
        fs::write(format!("{}/master_key", agent_path), to_vec(&encrypted_data).unwrap()).unwrap();
        println!("Agent saved. {}", agent_path);
    }

    pub fn login(name: String, password: String) -> Agent {
        let meta_key = Agent::derive_meta_key(password);
        Agent::load(name, meta_key)
    }


    pub fn load(name: String, meta_key: [u8; 32]) -> Agent {
        if !Agent::exists(&name) {
            panic!("Agent not found: {}", name);
        }

        let agent_id = Agent::get_id(&name);
        let agent_path = Agent::get_path(agent_id);

        println!("Reading master key...");
        
        let mut file = File::open(format!("{}/master_key", agent_path)).unwrap();
        
        let mut encrypted_data = Vec::new();
        file.read_to_end(&mut encrypted_data).unwrap();

        let (nonce, cypher): (Vec<u8>, Vec<u8>) = from_slice(&encrypted_data).unwrap();
        let master_key_vec = symm_enc::decrypt(&meta_key, &nonce, &cypher);
        let master_key: [u8; 32] = master_key_vec.try_into().expect("Invalid key length");

        println!("Master key read: {}", name);

        Self {
            name,
            master_key,
        }
    }

    ////////////////////////////////////
    // GETTERS /////////////////////////
    ////////////////////////////////////

    pub fn get_name(&self) -> &str {
        &self.name
    }

    ////////////////////////////////////
    // CRYPTO //////////////////////////
    ////////////////////////////////////

    pub fn derive_meta_key(password: String) -> [u8; 32] {
        let device_id = {
            let device = Device::instance();
            device.get_id()
        };

        let salt = format!("varta_meta_aes_seed_{}", password);
        let hkdf = Hkdf::<Sha256>::new(Some(salt.as_bytes()), &device_id);
        let mut enc_key = [0u8; 32];
        hkdf.expand(b"varta_meta_aes", &mut enc_key).unwrap();
        enc_key
    }

    pub fn derive_master_key(derivation_key: [u8; 32]) -> [u8; 32] {
        let mut master_key = [0u8; 32];
        let hkdf = Hkdf::<Sha256>::new(Some(derivation_key.as_slice()), b"varta_agent_master_key");
        hkdf.expand(b"varta_agent_master_key", &mut master_key).unwrap();
        master_key
    }

    pub fn derive_vault_key(&self, vault_name: &str) -> [u8; 32] {
        let salt = format!("varta_vault_derivation_{}", vault_name);
        let hkdf = Hkdf::<Sha256>::new(Some(salt.as_bytes()), &self.master_key);
        let mut vault_key = [0u8; 32];
        hkdf.expand(b"varta_vault_key", &mut vault_key).unwrap();
        vault_key
    }


    ////////////////////////////////////
    // STATIC //////////////////////////
    ////////////////////////////////////

    pub fn get_id(name: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(name.as_bytes());
        hasher.finalize().into()
    }

    pub fn get_path(id: [u8; 32]) -> String {
        format!("{}/{}", ROOT_SECRETS_FOLDER, hex::encode(id))
    }

    pub fn exists(name: &str) -> bool {
        let agent_id = Agent::get_id(name);
        let agent_path = Agent::get_path(agent_id);
        fs::exists(&agent_path).unwrap() && fs::exists(format!("{}/master_key", &agent_path)).unwrap()
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        self.master_key.zeroize();
        println!("🔒 Agent master_key zeroized");
    }
}
