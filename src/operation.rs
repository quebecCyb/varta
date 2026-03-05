

use std::collections::HashMap;

pub enum OperationType {
    Create,
    Update,
    Delete,
}

pub struct Operation {
    device_id: [u8; 32],
    agent_id: [u8; 32],

    device_clock: u64,
    vector_clock: HashMap<[u8;32], u64>,

    timestamp: u64,
    operation_type: OperationType,

    value_key: [u8; 32],
    value: Vec<u8>,
    nonce: [u8; 12],

    vault_digest: [u8; 32],
    op_hash: [u8; 32],
    op_iter_hash: [u8; 32],
    signature: [u8; 64],
}

impl Operation {
    // pub fn new() -> Self {

    // }

    // pub fn create() -> Self {
        
    // }

    // pub fn open() -> Self {

    // }

    // pub fn save(&self) -> Self {
        
    // }

    // pub fn sign(&mut self) {
        
    // }

}

