use crate::device::Device;
use crate::agent::Agent;
use crate::vault::Vault;
use crate::vault_object::VaultObject;
use crate::config::ROOT_SECRETS_FOLDER;
use zeroize::Zeroize;

use std::fs::{self, File};
use std::path::{Path, PathBuf};
use flate2::Compression;
use flate2::write::GzEncoder;
use flate2::read::GzDecoder;

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

        let mut results: Vec<String> = Vec::new();
        for res in vault.list_objects_iter() {
            let mut bytes = res?;
            let obj = VaultObject::from_bytes(&bytes)?;
            results.push(obj.key().to_string());
            bytes.zeroize();
        }

        Ok(results)
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

    // =====================
    // RAW BACKUP/RESTORE
    // =====================

    pub fn raw_backup(&self) -> Result<PathBuf> {
        let agent = self.agent.as_ref()
            .ok_or("No agent logged in")?;
        
        let agent_path = Agent::get_path(agent.id());
        if !agent_path.exists() {
            return Err("Agent folder not found".into());
        }

        let backup_dir = PathBuf::from(ROOT_SECRETS_FOLDER)
            .parent()
            .unwrap_or(Path::new("."))
            .join("backups");
        
        fs::create_dir_all(&backup_dir)?;

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let backup_filename = format!("agent_{}_{}.tar.gz", agent.get_name(), timestamp);
        let backup_path = backup_dir.join(&backup_filename);

        let tar_gz = File::create(&backup_path)?;
        let enc = GzEncoder::new(tar_gz, Compression::default());
        let mut tar = tar::Builder::new(enc);

        tar.append_dir_all(agent.get_name(), &agent_path)?;
        tar.finish()?;

        println!("✅ Raw backup created: {}", backup_path.display());
        Ok(backup_path)
    }

    pub fn raw_restore<P: AsRef<Path>>(backup_path: P) -> Result<String> {
        let backup_path = backup_path.as_ref();
        
        if !backup_path.exists() {
            return Err(format!("Backup file not found: {:?}", backup_path).into());
        }

        let tar_gz = File::open(backup_path)?;
        let dec = GzDecoder::new(tar_gz);
        let mut archive = tar::Archive::new(dec);

        let restore_dir = PathBuf::from(ROOT_SECRETS_FOLDER);
        fs::create_dir_all(&restore_dir)?;

        archive.unpack(&restore_dir)?;

        let agent_name = backup_path
            .file_stem()
            .and_then(|s| s.to_str())
            .and_then(|s| s.strip_prefix("agent_"))
            .and_then(|s| s.rsplit_once('_').map(|(name, _)| name))
            .unwrap_or("unknown")
            .to_string();

        println!("✅ Raw restore completed from: {}", backup_path.display());
        println!("   Agent name (estimated): {}", agent_name);
        
        Ok(agent_name)
    }
}


impl Drop for Session {
    fn drop(&mut self) {
        self.agent.take();
        self.vault.take();
    }
}


