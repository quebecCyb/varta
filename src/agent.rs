use std::fs;
use std::path::{Path, PathBuf};
use sha2::{Sha256, Digest};
use hex;
use hkdf::Hkdf;
use crate::crypto::symm_enc;
use crate::device::Device;
use crate::config::{
    ROOT_SECRETS_FOLDER, generate_random_key,
    MASTER_KEY_FILE,
    AGENT_META_KEY_CONTEXT,
    AGENT_MASTER_KEY_SALT, AGENT_MASTER_KEY_CONTEXT,
    AGENT_VAULT_KEY_SALT_PREFIX, AGENT_VAULT_KEY_CONTEXT,
};
use zeroize::Zeroize;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

const NONCE_SIZE: usize = 12;

fn serialize_encrypted(nonce: &[u8], cypher: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(NONCE_SIZE + cypher.len());
    data.extend_from_slice(nonce);
    data.extend_from_slice(cypher);
    data
}

fn deserialize_encrypted(data: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    if data.len() < NONCE_SIZE {
        return Err("Invalid encrypted data: too short".into());
    }
    
    let nonce = data[..NONCE_SIZE].to_vec();
    let cypher = data[NONCE_SIZE..].to_vec();
    
    Ok((nonce, cypher))
}

pub struct Agent {
    name: String,
    master_key: [u8; 32],
}

impl Agent {
    pub fn new(name: String, password: Option<String>, derivation_key: Option<[u8; 32]>) -> Self {
        let master_key = if let Some(key) = derivation_key {
            Agent::derive_master_key(key)
        } else {
            generate_random_key()
        };

        let agent = Self {
            name,
            master_key,
        };
        
        let pwd = password.unwrap_or_else(|| String::new());
        let meta_key = Agent::derive_meta_key(pwd);
        agent.save(meta_key).expect("Failed to save agent");

        agent
    }
    
    pub fn save(&self, meta_key: [u8; 32]) -> Result<()> {
        let agent_path = Agent::get_path(self.id());

        if !agent_path.exists() {
            fs::create_dir_all(&agent_path)?;
        }

        let (nonce, cypher) = symm_enc::encrypt(&meta_key, &self.master_key);
        let serialized = serialize_encrypted(&nonce, &cypher);
        
        let master_key_path = agent_path.join(MASTER_KEY_FILE);
        fs::write(master_key_path, serialized)?;
        
        Ok(())
    }

    pub fn login(name: String, password: String) -> Result<Agent> {
        let meta_key = Agent::derive_meta_key(password);
        Agent::load(name, meta_key)
    }


    pub fn load(name: String, meta_key: [u8; 32]) -> Result<Agent> {
        if !Agent::exists(&name) {
            return Err(format!("Agent not found: {}", name).into());
        }

        let agent_id = Agent::get_id(&name);
        let agent_path = Agent::get_path(agent_id);
        let master_key_path = agent_path.join(MASTER_KEY_FILE);
        
        let encrypted_data = fs::read(master_key_path)?;
        let (nonce, cypher) = deserialize_encrypted(&encrypted_data)?;
        
        let master_key_vec = symm_enc::decrypt(&meta_key, &nonce, &cypher);
        let master_key: [u8; 32] = master_key_vec.try_into()
            .map_err(|_| "Invalid master key length")?;

        Ok(Self {
            name,
            master_key,
        })
    }

    /// ================================
    /// GETTERS
    /// ================================

    pub fn get_name(&self) -> &str {
        &self.name
    }

    pub fn id(&self) -> [u8; 32] {
        Agent::get_id(&self.name)
    }

    /// ================================
    /// CRYPTO
    /// ================================
    pub fn derive_meta_key(mut password: String) -> [u8; 32] {
        let device_id = {
            let device = Device::instance();
            device.get_id()
        };

        let password_bytes = password.as_bytes();
        let hkdf = Hkdf::<Sha256>::new(Some(&device_id), password_bytes);
        
        let mut enc_key = [0u8; 32];
        hkdf.expand(AGENT_META_KEY_CONTEXT, &mut enc_key)
            .expect("HKDF expansion failed");
        
        password.zeroize();

        enc_key
    }

    pub fn derive_master_key(derivation_key: [u8; 32]) -> [u8; 32] {
        let mut master_key = [0u8; 32];
        let hkdf = Hkdf::<Sha256>::new(Some(derivation_key.as_slice()), AGENT_MASTER_KEY_SALT);
        hkdf.expand(AGENT_MASTER_KEY_CONTEXT, &mut master_key).unwrap();
        master_key
    }

    pub fn derive_vault_key(&self, vault_name: &str) -> [u8; 32] {
        let salt = format!("{}{}", AGENT_VAULT_KEY_SALT_PREFIX, vault_name);
        let hkdf = Hkdf::<Sha256>::new(Some(salt.as_bytes()), &self.master_key);
        let mut vault_key = [0u8; 32];
        hkdf.expand(AGENT_VAULT_KEY_CONTEXT, &mut vault_key).unwrap();
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

    pub fn get_path(id: [u8; 32]) -> PathBuf {
        PathBuf::from(ROOT_SECRETS_FOLDER).join(hex::encode(id))
    }

    pub fn exists(name: &str) -> bool {
        let agent_id = Agent::get_id(name);
        let agent_path = Agent::get_path(agent_id);
        agent_path.join(MASTER_KEY_FILE).exists()
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        self.master_key.zeroize();
    }
}
