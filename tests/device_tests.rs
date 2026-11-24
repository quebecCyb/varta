use varta::device::Device;
use varta::crypto::sign::ED25519_SIG_LEN;

#[test]
fn test_device_creation() {
    Device::initialize();
    let device = Device::instance();
    let device_id = device.get_id();
    
    assert_eq!(device_id.len(), 32);
}

#[test]
fn test_device_id_consistency() {
    Device::initialize();

    // Вариант А: Ограничиваем область видимости скобками
    let id1 = {
        let device1 = Device::instance();
        device1.get_id() // Блокировка снимается сразу при выходе из {}
    };

    // Вариант Б: Просто вызываем в одну строку (гарда умрет сразу после точки с запятой)
    let id2 = Device::instance().get_id();

    assert_eq!(id1, id2, "Device ID should be consistent across instances");
}

#[test]
fn test_device_signing() {
    Device::initialize();
    let device = Device::instance();
    let message = b"Test message for device signing";
    
    let signature = device.sign(message);
    
    assert_eq!(signature.len(), ED25519_SIG_LEN);
}

#[test]
fn test_device_signature_deterministic() {
    Device::initialize();
    let device = Device::instance();
    let message = b"Same message";
    
    let sig1 = device.sign(message);
    let sig2 = device.sign(message);
    
    assert_eq!(sig1, sig2, "Signatures should be deterministic for the same message");
}

#[test]
fn test_device_signature_different_messages() {
    Device::initialize();
    let device = Device::instance();
    let message1 = b"First message";
    let message2 = b"Second message";
    
    let sig1 = device.sign(message1);
    let sig2 = device.sign(message2);
    
    assert_ne!(sig1, sig2, "Signatures should differ for different messages");
}
