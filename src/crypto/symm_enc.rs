use aes_gcm::{Aes128Gcm, KeyInit, aead::{Aead, Nonce}};
use aes_siv::{Aes128SivAead};
use hex;
use aes_siv::aead::Nonce as NonceSiv;

// ============================================
// Random IV encryption (для vault index, etc)
// ============================================

pub fn encrypt(
    aes_key: &[u8; 16],
    plaintext: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let cipher = Aes128Gcm::new(aes_key.into());

    let nonce_bytes = crate::common::generate_random_key();
    let nonce = Nonce::<Aes128Gcm>::from_slice(&nonce_bytes[0..12]);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .expect("Encryption failed");

    (nonce_bytes[0..12].to_vec(), ciphertext)
}

pub fn decrypt(
    aes_key: &[u8; 16],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Vec<u8> {
    let cipher = Aes128Gcm::new(aes_key.into());

    let nonce = Nonce::<Aes128Gcm>::from_slice(nonce);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .expect("Decryption failed");

    plaintext
}

// ============================================
// Deterministic encryption (для имен файлов)
// ============================================

/// AES-SIV
pub fn encrypt_filename(aes_key: &[u8; 16], filename: &str) -> String {
    let mut key_256 = [0u8; 32];
    key_256[0..16].copy_from_slice(aes_key);
    key_256[16..32].copy_from_slice(aes_key);
    
    let nonce = NonceSiv::<Aes128SivAead>::from_slice(b"vaultfilename_iv");
    let cipher = Aes128SivAead::new(&key_256.into());

    let ciphertext = cipher
        .encrypt(nonce, filename.as_bytes())
        .expect("Filename encryption failed");
    
    hex::encode(ciphertext)
}

pub fn decrypt_filename(aes_key: &[u8; 16], hex_ciphertext: &str) -> String {
    let mut key_256 = [0u8; 32];
    key_256[0..16].copy_from_slice(aes_key);
    key_256[16..32].copy_from_slice(aes_key);
    
    let cipher = Aes128SivAead::new(&key_256.into());
    
    let ciphertext = hex::decode(hex_ciphertext)
        .expect("Invalid hex in filename");
    
    let nonce = NonceSiv::<Aes128SivAead>::from_slice(b"vaultfilename_iv");

    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_slice())
        .expect("Filename decryption failed");
    
    String::from_utf8(plaintext)
        .expect("Invalid UTF-8 in decrypted filename")
}