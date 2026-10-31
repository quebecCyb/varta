use std::fs;
use varta::config::{config, generate_random_key, Config, CONFIG};
use varta::storage::obs::ObjectStorage;

#[ctor::ctor]
fn init_test_config() {
    let _ = CONFIG.set(Config::load_test());
    cleanup_test_data();
}

#[ctor::dtor]
fn global_teardown() {
    cleanup_test_data();
}


fn bytes_to_hex(bytes: &[u8; 32]) -> String {
    let mut hex = String::with_capacity(64);
    for byte in bytes {
        // :02x выводит байт как hex из 2 символов в нижнем регистре (например, 0a, ff)
        hex.push_str(&format!("{:02x}", byte));
    }
    hex
}

fn cleanup_test_data() {
    let _ = fs::remove_dir_all(config().root_secrets_folder.clone());
}

#[test]
fn test_add_obj_storage() {
    let enc_key = generate_random_key();
    const KEY: &str = "key";

    let value = generate_random_key().to_vec();
    let mut storage = ObjectStorage::new(config().root_secrets_folder.clone().join("test_vault")).unwrap();


    let add_result = storage.add_object(KEY, &value, &enc_key);
    assert!(add_result.is_ok());

    let result = storage.get_object(KEY, &enc_key).unwrap();

    assert_eq!(&value, &result);
}


#[test]
fn test_empty_obj_storage() {
    let enc_key = generate_random_key();
    const KEY: &str = "KEY";

    let storage = ObjectStorage::new(config().root_secrets_folder.clone().join("test_vault")).unwrap();

    let result = storage.get_object(KEY, &enc_key);
    assert_eq!("Block not found in index", result.err().unwrap().to_string());
}


#[test]
fn test_deleted_obj_storage() {

    let enc_key = generate_random_key();
    const KEY: &str = "KEY";

    let value = generate_random_key().to_vec();
    let mut storage = ObjectStorage::new(config().root_secrets_folder.clone().join("test_vault")).unwrap();


    let add_result = storage.add_object(KEY, &value, &enc_key);
    assert!(add_result.is_ok());

    let result = storage.get_object(KEY, &enc_key).unwrap();

    assert_eq!(&value, &result);
    let del_result = storage.del_object(KEY, &enc_key);
    assert!(del_result.is_ok());

    let result = storage.get_object(KEY, &enc_key);
    assert_eq!("Block not found in index", result.err().unwrap().to_string());
}


#[test]
fn test_upd_obj_storage() {
    let filename = generate_random_key();
    let enc_key = generate_random_key();
    const KEY: &str = "KEY";

    let value = generate_random_key().to_vec();
    let final_value = generate_random_key().to_vec();

    let mut storage = ObjectStorage::new(config().root_secrets_folder.clone().join(format!("test_vault_{}", bytes_to_hex(&filename)) )).unwrap();


    let add_result = storage.add_object(KEY, &value, &enc_key);
    assert!(add_result.is_ok());
    let upd_result = storage.upd_object(KEY, &final_value, &enc_key);
    assert!(upd_result.is_ok());
    
    let result = storage.get_object(KEY, &enc_key).unwrap();

    assert_eq!(&final_value, &result);
}


