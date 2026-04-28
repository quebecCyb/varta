use crate::device::Device;
use crate::agent::Agent;
use crate::vault::Vault;
use zeroize::Zeroize;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub struct Session {
    agent: Option<Agent>,
    vault: Option<Vault>,
    // Session encrpytion for cache | future update 
    // kek: Vec<u8>,
}

impl Session {
    pub fn new() -> Self {
        Device::initialize();

        Self { agent: None, vault: None }
    }

    // Getters
    pub fn get_agent(&self) -> Option<&Agent> {
        self.agent.as_ref()
    }

    pub fn get_vault(&self) -> Option<&Vault> {
        self.vault.as_ref()
    }

    // agents
    pub fn create_agent(&mut self, name: String, password: Option<String>) -> Result<()> {
        let agent = Agent::new(name, password, None);
        self.agent = Some(agent);
        Ok(())
    }

    pub fn login_agent(&mut self, name: String, password: String) -> Result<()> {
        let agent = Agent::login(name, password)?;
        self.agent = Some(agent);
        Ok(())
    }

    pub fn switch(&mut self) {
        drop(self.agent.take());
        drop(self.vault.take());
    }

    // Vaults
    pub fn new_vault(&mut self, name: String) -> Result<()> {
        let agent = self.agent.as_ref()
            .ok_or("No agent logged in")?;
        let mut v_key = agent.derive_vault_key(&name); 
        let vault = Vault::new(name, agent.id(), &v_key)?;
        v_key.zeroize();
        self.vault = Some(vault);
        Ok(())
    }

    pub fn open_vault(&mut self, name: String) -> Result<()> {
        let agent = self.agent.as_ref()
            .ok_or("No agent logged in")?;
        let mut v_key = agent.derive_vault_key(&name); 
        let vault = Vault::open(name, agent.id(), &v_key)?;
        v_key.zeroize();
        self.vault = Some(vault);
        Ok(())
    }

    pub fn close_vault(&mut self) -> Result<()> {
        self.vault.take()
            .ok_or("No vault opened")?;
        Ok(())
    }

    // Objects 
    pub fn add_object(&mut self, key: String, value: Vec<u8>) -> Result<()> {
        let vault = self.vault.as_mut()
            .ok_or("No vault opened")?;
        vault.create_object(key, value)?;
        Ok(())
    }

    pub fn update_object(&mut self, key: String, value: Vec<u8>) -> Result<()> {
        let vault = self.vault.as_mut()
            .ok_or("No vault opened")?;
        vault.update_object(&key, value)?;
        Ok(())
    }

    pub fn list_objects(&self) -> Result<Vec<String>> {
        let vault = self.vault.as_ref()
            .ok_or("No vault opened")?;
        vault.list_objects()
    }

    pub fn read_object(&self, key: &str) -> Result<crate::vault_object::VaultObject> {
        let vault = self.vault.as_ref()
            .ok_or("No vault opened")?;
        vault.read_object(key)
    }

    pub fn delete_object(&mut self, key: &str) -> Result<()> {
        let vault = self.vault.as_mut()
            .ok_or("No vault opened")?;
        vault.delete_object(key)?;
        Ok(())
    }
}


impl Drop for Session {
    fn drop(&mut self) {
        self.agent.take();
        self.vault.take();
    }
}


