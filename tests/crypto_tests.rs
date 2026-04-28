use varta::crypto::symm_enc;
use varta::crypto::sign::{sign_ed25519, sign_hybrid, verify_hybrid, keypair_postq, ED25519_SIG_LEN};
use varta::config::generate_random_key;

#[test]
fn test_symmetric_encryption_decryption() {
    let key = generate_random_key();
    let plaintext = b"Secret password: hunter2";
    
    let (nonce, ciphertext) = symm_enc::encrypt(&key, plaintext);
    let decrypted = symm_enc::decrypt(&key, &nonce, &ciphertext);
    
    assert_eq!(plaintext.to_vec(), decrypted);
}

#[test]
fn test_symmetric_encryption_different_nonces() {
    let key = generate_random_key();
    let plaintext = b"Same message";
    
    let (nonce1, ciphertext1) = symm_enc::encrypt(&key, plaintext);
    let (nonce2, ciphertext2) = symm_enc::encrypt(&key, plaintext);
    
    assert_ne!(nonce1, nonce2, "Nonces should be different");
    assert_ne!(ciphertext1, ciphertext2, "Ciphertexts should be different with different nonces");
}

#[test]
fn test_filename_encryption_deterministic() {
    let key = generate_random_key();
    let filename = "my_secret_file.txt";
    
    let encrypted1 = symm_enc::encrypt_filename(&key, filename);
    let encrypted2 = symm_enc::encrypt_filename(&key, filename);
    
    assert_eq!(encrypted1, encrypted2, "Filename encryption should be deterministic");
    
    let decrypted = symm_enc::decrypt_filename(&key, &encrypted1, None);
    assert_eq!(filename, decrypted);
}

#[test]
fn test_ed25519_signature() {
    let secret_key = generate_random_key();
    let message = b"Important message to sign";
    
    let signature = sign_ed25519(&secret_key, message);
    
    assert_eq!(signature.len(), ED25519_SIG_LEN);
}

#[test]
fn test_hybrid_signature_verification() {
    let ed25519_sk = generate_random_key();
    let (pq_pk, pq_sk) = keypair_postq();
    let message = b"Quantum-resistant signed message";
    
    let signature = sign_hybrid(&ed25519_sk, &pq_sk, message);
    
    let ed25519_pk = {
        use ed25519_dalek::SigningKey;
        let sk = SigningKey::from_bytes(&ed25519_sk);
        sk.verifying_key().to_bytes()
    };
    
    let is_valid = verify_hybrid(&ed25519_pk, &pq_pk, message, &signature);
    assert!(is_valid, "Hybrid signature should be valid");
}

#[test]
fn test_hybrid_signature_invalid_message() {
    let ed25519_sk = generate_random_key();
    let (pq_pk, pq_sk) = keypair_postq();
    let message = b"Original message";
    let tampered_message = b"Tampered message";
    
    let signature = sign_hybrid(&ed25519_sk, &pq_sk, message);
    
    let ed25519_pk = {
        use ed25519_dalek::SigningKey;
        let sk = SigningKey::from_bytes(&ed25519_sk);
        sk.verifying_key().to_bytes()
    };
    
    let is_valid = verify_hybrid(&ed25519_pk, &pq_pk, tampered_message, &signature);
    assert!(!is_valid, "Signature should be invalid for tampered message");
}

#[test]
fn test_random_key_generation() {
    let key1 = generate_random_key();
    let key2 = generate_random_key();
    
    assert_ne!(key1, key2, "Random keys should be different");
    assert_eq!(key1.len(), 32);
    assert_eq!(key2.len(), 32);
}
