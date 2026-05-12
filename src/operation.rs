
use std::collections::BTreeMap;
use sha2::{Sha256, Digest};
use hkdf::Hkdf;
use borsh::{BorshSerialize, BorshDeserialize, from_slice, to_vec};
use crate::device::Device;
use crate::config::{
    OPERATION_FILE_EXT,
    OP_INITIAL,
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

    pub fn to_bytes(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(to_vec(self)?)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(from_slice(bytes)?)
    }

    pub fn initial(agent_id: [u8; 32], vault_name: &str) -> Self {
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
        op
    }
    
    pub fn new(vault: &Vault, obj: &VaultObject, operation_type: &str, prev_op: &Operation) -> Self {
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
        op
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

    fn format_clock(device_clock: u64) -> String {
        format!("{:016x}", device_clock)
    }
}

