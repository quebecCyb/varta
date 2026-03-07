use std::io::Read;
use std::fs::File;
use std::fs;
use sha2::{Sha256, Digest};
use hex;
use hkdf::Hkdf;

use crate::common::{ROOT_SECRETS_FOLDER, generate_random_key};

pub struct Agent {
    pub name: String,
    master_key: [u8; 32],
}

impl Agent {
    pub fn new(name: String, master_key: Option<[u8; 32]>) -> Self {

        let master_key = master_key.unwrap_or(generate_random_key());
        println!("Master key created.");

        let agent = Self {
            name,
            master_key,
        };

        agent.save();
        agent
    }
    
    pub fn save(&self) {
        let agent_path = Agent::get_path(Agent::get_id(&self.name));

        if !fs::exists(&agent_path).unwrap() {
            fs::create_dir_all(&agent_path).unwrap();
        }

        fs::write(format!("{}/master_key", agent_path), self.master_key).unwrap();
        println!("Agent saved. {}", agent_path);
    }


    pub fn login(name: String) -> Agent {
        if !Agent::exists(&name) {
            panic!("Agent not found: {}", name);
        }

        let agent_id = Agent::get_id(&name);
        let agent_path = Agent::get_path(agent_id);

        let mut master_key = [0u8; 32];
        
        println!("Reading master key...");
        let mut file = File::open(format!("{}/master_key", agent_path)).unwrap();
        file.read_exact(&mut master_key).unwrap();
        println!("Master key read: {}", name);

        Agent::new(name, Some(master_key))
    }

    ////////////////////////////////////
    // CRYPTO //////////////////////////
    ////////////////////////////////////

    // pub fn get_ecc_seed(&self) -> [u8; 32] {
    //     let salt = format!("varta_ecc_seed_{}", self.name);
    //     let hkdf = Hkdf::<Sha256>::new(Some(salt.as_bytes()), &self.master_key);
    //     let mut ecc_seed = [0u8; 32];
    //     hkdf.expand(b"varta_ed25519", &mut ecc_seed).unwrap();
    //     ecc_seed
    // }

    pub fn get_vault_derivation_key(&self) -> [u8; 32] {
        self.master_key
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
