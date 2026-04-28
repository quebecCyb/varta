pub use rand::rngs::OsRng;
use rand::RngCore;

pub const VERSION: u8 = 1;

// ============================================
// Paths and Folders
// ============================================
pub const ROOT_SECRETS_FOLDER: &str = "secrets";
pub const OBJECTS_FOLDER: &str = "obs";
pub const OPERATIONS_FOLDER: &str = "operations";

// ============================================
// File Extensions
// ============================================
pub const OBJECT_FILE_EXT: &str = "ob";
pub const OPERATION_FILE_EXT: &str = "op";

// ============================================
// File Names
// ============================================
pub const MASTER_KEY_FILE: &str = "master_key";
pub const VAULT_INDEX_FILE: &str = "index";

// ============================================
// HKDF Salts and Contexts
// ============================================
pub const AGENT_META_KEY_SALT_PREFIX: &str = "varta_meta_aes_seed_";
pub const AGENT_META_KEY_CONTEXT: &[u8] = b"varta_meta_aes";
pub const AGENT_MASTER_KEY_SALT: &[u8] = b"varta_agent_master_key";
pub const AGENT_MASTER_KEY_CONTEXT: &[u8] = b"varta_agent_master_key";
pub const AGENT_VAULT_KEY_SALT_PREFIX: &str = "varta_vault_derivation_";
pub const AGENT_VAULT_KEY_CONTEXT: &[u8] = b"varta_vault_key";

pub const VAULT_AES_KEY_SALT: &str = "varta_vault_aes_encryption";
pub const VAULT_META_KEY_SALT: &str = "varta_meta_encryption";

// ============================================
// Operation Types
// ============================================
// Structural

pub const OP_INITIAL: &str = "initial";
pub const OP_CREATE: &str = "create_object";
pub const OP_UPDATE: &str = "update_object";
pub const OP_DELETE: &str = "delete_object";

// Sync
pub const OP_MERGE: &str = "Merge";
pub const OP_CONFLICT: &str = "Conflict";

// Audit - Network
pub const OP_SYNC: &str = "Sync";
pub const OP_SYNC_SUCCESS: &str = "SyncSuccess";
pub const OP_SYNC_FAIL: &str = "SyncFail";

// Audit - Offline
pub const OP_ACCESS: &str = "Access";
pub const OP_LIST: &str = "List";
pub const OP_READ: &str = "Read";

// ============================================
// Helper Functions
// ============================================

pub fn generate_random_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}
