use crate::device::Device;
use crate::agent::Agent;
use crate::vault::Vault;
use zeroize::Zeroize;

pub struct Session {
    agent: Option<Agent>,
    vault: Option<Vault>,
    kek: Vec<u8>,
}

impl Session {
    pub fn new() -> Self {
        Device::initialize();

        Self { agent: None, vault: None, kek: Vec::new() }
    }

    // Getters
    pub fn get_agent(&self) -> Option<&Agent> {
        self.agent.as_ref()
    }

    pub fn get_vault(&self) -> Option<&Vault> {
        self.vault.as_ref()
    }

    // agents
    pub fn create_agent(&mut self, name: String, password: Option<String>) {
        let agent = Agent::new(name, password, None);
        self.agent = Some(agent);
    }

    pub fn login_agent(&mut self, name: String, password: String) {
        let agent = Agent::login(name, password);
        self.agent = Some(agent);
    }

    pub fn switch(&mut self) {
        drop(self.agent.take());
        drop(self.vault.take());
    }

    // Vaults
    pub fn new_vault(&mut self, name: String) {
        let agent = self.agent.as_ref().expect("No agent logged in");
        let mut v_key = agent.derive_vault_key(&name); 
        let vault = Vault::new(name, Agent::get_id(agent.get_name()), &v_key);
        v_key.zeroize();
        self.vault = Some(vault);
    }

    pub fn open_vault(&mut self, name: String) {
        let agent = self.agent.as_ref().expect("No agent logged in");
        let mut v_key = agent.derive_vault_key(&name); 
        let vault = Vault::open(name, Agent::get_id(agent.get_name()), &v_key);
        v_key.zeroize();
        self.vault = Some(vault);
    }

    pub fn close_vault(&mut self) {
        drop(self.vault.take());
    }

    // Objects 
    pub fn add_object(&mut self, key: String, value: Vec<u8>) {
        self.vault.as_mut().unwrap().create_object(key, value);
    }

    pub fn update_object(&mut self, key: String, value: Vec<u8>) {
        self.vault.as_mut().unwrap().update_object(&key, value);
    }

    pub fn list_objects(&self) -> Vec<String> {
        self.vault.as_ref().unwrap().list_objects()
    }

    pub fn read_object(&self, key: &str) -> crate::vault_object::VaultObject {
        self.vault.as_ref().unwrap().read_object(key)
    }

    pub fn delete_object(&mut self, key: &str) {
        self.vault.as_mut().unwrap().delete_object(key)
    }
}


impl Drop for Session {
    fn drop(&mut self) {
        // Явно уничтожаем Agent и Vault, чтобы вызвать их Drop
        if let Some(agent) = self.agent.take() {
            drop(agent);
        }
        
        if let Some(vault) = self.vault.take() {
            drop(vault);
        }
        
        // Очищаем KEK
        self.kek.zeroize();
        
        // Device будет автоматически очищен через свой Drop
        
        println!("🔒 Session cleaned and dropped");
    }
}


