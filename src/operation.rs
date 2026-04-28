
use std::collections::BTreeMap;
use sha2::{Sha256, Digest};
use hkdf::Hkdf;
use borsh::{BorshSerialize, BorshDeserialize, from_slice, to_vec};
use crate::device::Device;
use crate::config::{
    OPERATION_FILE_EXT,
    OP_INITIAL, OP_CREATE,
};
use crate::vault::Vault;
use crate::vault_object::VaultObject;
use crate::crypto::symm_enc;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};



#[derive(BorshSerialize, BorshDeserialize)]
pub struct Operation {
    device_id: [u8; 32],
    agent_id: [u8; 32],
    vault_name: String,

    device_clock: u64,
    vector_clock: BTreeMap<[u8;32], u64>,

    timestamp: u64,
    operation_type: String,

    value_key: Vec<u8>,
    value_hash: [u8; 32],

    vault_digest: [u8; 32],
    prev_op_hash: [u8; 32],
    pub op_hash: [u8; 32],
    op_iter_hash: [u8; 32],
    signature: Vec<u8>,
}

impl Operation {
    pub fn initial(aes_key: &[u8; 32], agent_id: [u8; 32], vault_name: &str) -> Self {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let device_id = {
            let device = Device::instance();
            device.get_id()
        };

        let mut op = Self {
            device_id,
            agent_id,
            vault_name: vault_name.to_string(),
            device_clock: 0,
            vector_clock: BTreeMap::new(),
            timestamp,
            operation_type: OP_INITIAL.to_string(),
            value_key: Vec::new(),
            value_hash: [0u8; 32],
            vault_digest: [0u8; 32],
            prev_op_hash: [0u8; 32],
            op_hash: [0u8; 32],
            op_iter_hash: [0u8; 32],
            signature: Vec::new(),
        };

        op.hash();
        op.hash_iter();
        op.sign();
        op.save(aes_key);
        op
    }
    
    pub fn new(aes_key: &[u8; 32], vault: &Vault, obj: &VaultObject, operation_type: &str, prev_op: &Operation) -> Self {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let device_id = {
            let device = Device::instance();
            device.get_id()
        };

        let mut vector_clock = prev_op.vector_clock.clone();

        if !vector_clock.contains_key(&device_id) {
            vector_clock.insert(device_id, 0);
        }

        vector_clock.insert(device_id, vector_clock.get(&device_id).unwrap() + 1);

        let mut op = Self {
            device_id,
            agent_id: vault.get_agent_id(),
            vault_name: vault.get_name().to_string(),
            device_clock: *vector_clock.get(&device_id).unwrap(),
            vector_clock,
            timestamp,
            operation_type: operation_type.to_string(),
            value_key: obj.key().as_bytes().to_vec(),
            value_hash: obj.hash(),
            vault_digest: vault.state_hash(),
            prev_op_hash: prev_op.op_hash,
            op_hash: [0u8; 32],
            op_iter_hash: [0u8; 32],
            signature: Vec::new(),
        };

        op.hash();
        op.hash_iter();
        op.sign();
        op.save(aes_key);
        op
    }

    pub fn read(aes_key: &[u8; 32], agent_id: [u8; 32], vault_name: &str, filename: &str) -> Self {
        let path = Vault::get_path_operations(agent_id, vault_name);
        let path = format!("{}/{}", path, filename);
        let data = fs::read(&path).unwrap();
        let (nonce, ciphertext): (Vec<u8>, Vec<u8>) = from_slice(&data).unwrap();

        let aes_key = Operation::derive_operation_key(aes_key, &filename);
        let op: Operation = from_slice(&symm_enc::decrypt(&aes_key, &nonce, &ciphertext)).unwrap();
        op
    }

    pub fn save(&self, aes_key: &[u8; 32]) {
        let path = Vault::get_path_operations(self.agent_id, &self.vault_name);
        let filename = Operation::get_filename(self.device_clock, &self.op_hash);

        if !fs::exists(&path).unwrap() {
            fs::create_dir_all(&path).unwrap();
        }

        let path = format!("{}/{}", path, filename);

        let aes_key = Operation::derive_operation_key(aes_key, &filename);
        let (nonce, ciphertext) = symm_enc::encrypt(&aes_key, &to_vec(self).unwrap());
        let encrypted_data = (nonce, ciphertext);

        fs::write(&path, to_vec(&encrypted_data).unwrap());
        println!("Operation saved: {}_.....{}", Operation::format_clock(self.device_clock), OPERATION_FILE_EXT);
    }


    /// =====================
    /// CRYPTO 
    /// =====================

    pub fn sign(&mut self) {
        let signature = {
            let device = Device::instance();
            device.sign(&self.op_iter_hash)
        };
        self.signature = signature.to_vec();
    }

    pub fn hash(&mut self) {
        let mut hasher = Sha256::new();
        hasher.update(&self.device_id);
        hasher.update(&self.agent_id);
        hasher.update(&self.device_clock.to_le_bytes());
        hasher.update(&self.timestamp.to_le_bytes());
        hasher.update(&self.operation_type.as_bytes());
        hasher.update(&self.value_key);
        hasher.update(&self.value_hash);
        hasher.update(&self.vault_digest);
        hasher.update(&self.prev_op_hash);

        for key in self.vector_clock.keys() {
            let obj = self.vector_clock.get(key).unwrap();
            hasher.update(&obj.to_le_bytes());
        }

        self.op_hash = hasher.finalize().into();
    }

    pub fn hash_iter(&mut self) {
        let mut hasher = Sha256::new();
        hasher.update(&self.prev_op_hash);
        hasher.update(&self.op_hash);
        self.op_iter_hash = hasher.finalize().into();
    }


    pub fn derive_operation_key(vault_aes_key: &[u8; 32], key: &str) -> [u8; 32] {
        let salt = "varta_operation_aes_encryption";
        let hkdf = Hkdf::<Sha256>::new(Some(salt.as_bytes()), vault_aes_key);
        let mut aes_key = [0u8; 32];
        let context: &[u8] = key.as_bytes();
        hkdf.expand(context, &mut aes_key)
            .expect("HKDF expansion failed");

        aes_key
    }

    fn format_clock(device_clock: u64) -> String {
        format!("{:016x}", device_clock)
    }

    // Static
    pub fn get_filename(device_clock: u64, op_hash: &[u8; 32]) -> String {
        format!("{}_{}.{}", Operation::format_clock(device_clock), hex::encode(op_hash), OPERATION_FILE_EXT)
    }
}

