use varta::agent::Agent;
use varta::vault::Vault;
use std::fs;

fn cleanup_test_data() {
    let _ = fs::remove_dir_all("secrets");
}

#[test]
fn test_agent_creation_and_login() {
    cleanup_test_data();
    
    let agent_name = "test_agent".to_string();
    let password = "secure_password123".to_string();
    
    let agent = Agent::new(agent_name.clone(), password.clone(), None);
    assert_eq!(agent.name, agent_name);
    
    let loaded_agent = Agent::login(agent_name.clone(), password);
    assert_eq!(loaded_agent.name, agent_name);
    
    cleanup_test_data();
}

#[test]
fn test_vault_creation_and_opening() {
    cleanup_test_data();
    
    let agent_name = "vault_test_agent".to_string();
    let password = "password123".to_string();
    let vault_name = "my_vault".to_string();
    
    let agent = Agent::new(agent_name.clone(), password.clone(), None);
    let vault = Vault::new(vault_name.clone(), &agent);
    
    assert_eq!(vault.name, vault_name);
    
    let opened_vault = Vault::open(vault_name.clone(), &agent);
    assert_eq!(opened_vault.name, vault_name);
    
    cleanup_test_data();
}

#[test]
fn test_vault_object_lifecycle() {
    cleanup_test_data();
    
    let agent_name = "object_test_agent".to_string();
    let password = "password123".to_string();
    let vault_name = "test_vault".to_string();
    
    let agent = Agent::new(agent_name.clone(), password.clone(), None);
    let mut vault = Vault::new(vault_name.clone(), &agent);
    
    let key = "github_token".to_string();
    let value = b"ghp_1234567890abcdef".to_vec();
    
    vault.create_object(key.clone(), value.clone());
    
    let objects = vault.list_objects();
    assert!(objects.contains(&key));
    
    let obj = vault.read_object(&key);
    assert_eq!(obj.read(), value);
    
    let new_value = b"ghp_newtoken9876543210".to_vec();
    vault.update_object(&key, new_value.clone());
    
    let updated_obj = vault.read_object(&key);
    assert_eq!(updated_obj.read(), new_value);
    
    vault.delete_object(&key);
    let objects_after_delete = vault.list_objects();
    assert!(!objects_after_delete.contains(&key));
    
    cleanup_test_data();
}

#[test]
fn test_vault_persistence() {
    cleanup_test_data();
    
    let agent_name = "persistence_agent".to_string();
    let password = "password123".to_string();
    let vault_name = "persistent_vault".to_string();
    
    let agent = Agent::new(agent_name.clone(), password.clone(), None);
    let mut vault = Vault::new(vault_name.clone(), &agent);
    
    let key1 = "secret1".to_string();
    let value1 = b"value1".to_vec();
    let key2 = "secret2".to_string();
    let value2 = b"value2".to_vec();
    
    vault.create_object(key1.clone(), value1.clone());
    vault.create_object(key2.clone(), value2.clone());
    
    drop(vault);
    
    let loaded_agent = Agent::login(agent_name.clone(), password);
    let loaded_vault = Vault::open(vault_name, &loaded_agent);
    
    let objects = loaded_vault.list_objects();
    assert_eq!(objects.len(), 2);
    assert!(objects.contains(&key1));
    assert!(objects.contains(&key2));
    
    assert_eq!(loaded_vault.read_object(&key1).read(), value1);
    assert_eq!(loaded_vault.read_object(&key2).read(), value2);
    
    cleanup_test_data();
}

#[test]
fn test_multiple_vaults_per_agent() {
    cleanup_test_data();
    
    let agent_name = "multi_vault_agent".to_string();
    let password = "password123".to_string();
    
    let agent = Agent::new(agent_name.clone(), password.clone(), None);
    
    let vault1 = Vault::new("work_vault".to_string(), &agent);
    let vault2 = Vault::new("personal_vault".to_string(), &agent);
    
    assert_eq!(vault1.name, "work_vault");
    assert_eq!(vault2.name, "personal_vault");
    
    let loaded_agent = Agent::login(agent_name, password);
    let loaded_vault1 = Vault::open("work_vault".to_string(), &loaded_agent);
    let loaded_vault2 = Vault::open("personal_vault".to_string(), &loaded_agent);
    
    assert_eq!(loaded_vault1.name, "work_vault");
    assert_eq!(loaded_vault2.name, "personal_vault");
    
    cleanup_test_data();
}

#[test]
#[should_panic(expected = "Agent not found")]
fn test_login_nonexistent_agent() {
    cleanup_test_data();
    
    Agent::login("nonexistent_agent".to_string(), "password".to_string());
    
    cleanup_test_data();
}

#[test]
#[should_panic(expected = "Vault not found")]
fn test_open_nonexistent_vault() {
    cleanup_test_data();
    
    let agent_name = "test_agent".to_string();
    let password = "password123".to_string();
    
    let agent = Agent::new(agent_name.clone(), password.clone(), None);
    
    Vault::open("nonexistent_vault".to_string(), &agent);
    
    cleanup_test_data();
}
