use ed25519_dalek::{Signer, Verifier, SigningKey, VerifyingKey, Signature};
use pqcrypto_dilithium::dilithium2::{
    keypair, detached_sign as pq_sign, verify_detached_signature as pq_verify,
    SecretKey as PQSecretKey,
    PublicKey as PQPublicKey,
};
use pqcrypto_traits::sign::{DetachedSignature};
use pqcrypto_dilithium::dilithium2::DetachedSignature as PQDetachedSignature;

pub const ED25519_SIG_LEN: usize = 64;
pub const DILITHIUM2_SIG_LEN: usize = 2420;
pub const HYBRID_SIG_LEN: usize = ED25519_SIG_LEN + DILITHIUM2_SIG_LEN;

// ==========================
// Keypair
// ==========================

pub fn keypair_postq() -> (PQPublicKey, PQSecretKey) {
    keypair()
}

// ==========================
// Hybrid sign
// ==========================

pub fn sign_hybrid(
    ed25519_sk: &[u8; 32],
    pq_sk: &PQSecretKey,
    message: &[u8],
) -> [u8; HYBRID_SIG_LEN] {
    // ED25519
    let ed_sk = SigningKey::from_bytes(ed25519_sk);
    let ed_sig = ed_sk.sign(message);

    // Dilithium2
    let pq_sig = pq_sign(message, pq_sk);

    // concat
    let mut out = [0u8; HYBRID_SIG_LEN];
    out[..64].copy_from_slice(&ed_sig.to_bytes());
    out[64..].copy_from_slice(pq_sig.as_bytes());

    out
}

pub fn sign_ed25519(
    ed25519_sk: &[u8; 32],
    message: &[u8],
) -> [u8; ED25519_SIG_LEN] {
    // ED25519
    let ed_sk = SigningKey::from_bytes(ed25519_sk);
    let ed_sig = ed_sk.sign(message);

    ed_sig.to_bytes()
}

// ==========================
// Hybrid verify
// ==========================

pub fn verify_hybrid(
    ed25519_pk: &[u8; 32],
    pq_pk: &PQPublicKey,
    message: &[u8],
    signature: &[u8; HYBRID_SIG_LEN],
) -> bool {
    let (ed_part, pq_part) = signature.split_at(64);

    // ED25519
    let ed_pk = match VerifyingKey::from_bytes(ed25519_pk) {
        Ok(pk) => pk,
        Err(_) => return false,
    };

    let ed_sig = match Signature::from_slice(ed_part) {
        Ok(sig) => sig,
        Err(_) => return false,
    };

    if ed_pk.verify(message, &ed_sig).is_err() {
        return false;
    }

    // Dilithium2
    let pq_sig = match PQDetachedSignature::from_bytes(pq_part) {
        Ok(sig) => sig,
        Err(_) => return false,
    };

    pq_verify(&pq_sig, message, pq_pk).is_ok()
}