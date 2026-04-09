use varta::device::Device;
use varta::crypto::sign::ED25519_SIG_LEN;

#[test]
fn test_device_creation() {
    let device = Device::new();
    let device_id = device.get_id();
    
    assert_eq!(device_id.len(), 32);
}

#[test]
fn test_device_id_consistency() {
    let device1 = Device::new();
    let device2 = Device::new();
    
    let id1 = device1.get_id();
    let id2 = device2.get_id();
    
    assert_eq!(id1, id2, "Device ID should be consistent across instances");
}

#[test]
fn test_device_signing() {
    let device = Device::new();
    let message = b"Test message for device signing";
    
    let signature = device.sign(message);
    
    assert_eq!(signature.len(), ED25519_SIG_LEN);
}

#[test]
fn test_device_signature_deterministic() {
    let device = Device::new();
    let message = b"Same message";
    
    let sig1 = device.sign(message);
    let sig2 = device.sign(message);
    
    assert_eq!(sig1, sig2, "Signatures should be deterministic for the same message");
}

#[test]
fn test_device_signature_different_messages() {
    let device = Device::new();
    let message1 = b"First message";
    let message2 = b"Second message";
    
    let sig1 = device.sign(message1);
    let sig2 = device.sign(message2);
    
    assert_ne!(sig1, sig2, "Signatures should differ for different messages");
}
