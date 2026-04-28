use crate::storage::Storage;
use crate::storage::components::index::Index;
use crate::storage::components::block::Block;
use crate::storage::components::block_header::BlockType;
use crate::storage::components::header::{Header, FileType};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub struct ObjectStorage {
    storage: Storage, 
}

impl Drop for ObjectStorage {
    fn drop(&mut self) {
        // Storage has its own Drop implementation
        // which will be called automatically
    }
}

impl ObjectStorage {
    pub fn new(path: &str) -> Result<Self> {
        let header = Header::new(FileType::Storage);
        let storage = Storage::create(path, header)?;
        Ok(Self { storage })
    }
    
    pub fn open(path: &str) -> Result<Self> {
        let storage = Storage::open(path)?;
        Ok(Self { storage })
    }
    
    pub fn storage(&self) -> &Storage {
        &self.storage
    }
    
    pub fn storage_mut(&mut self) -> &mut Storage {
        &mut self.storage
    }
    
    pub fn set_vault_metadata(
        &mut self,
        nonce: [u8; 12],
        ciphertext: [u8; 97],
        tag: [u8; 16],
    ) -> Result<()> {
        self.storage.header_mut().set_vault_metadata(nonce, ciphertext, tag);
        self.storage.update_metadata()?;
        Ok(())
    }
    
    pub fn get_vault_metadata(&self) -> (&[u8; 12], &[u8; 97], &[u8; 16]) {
        self.storage.header().get_vault_metadata()
    }
    
    pub fn has_vault_metadata(&self) -> bool {
        self.storage.header().has_vault_metadata()
    }

    pub fn add_object(&mut self, key: &str, data: &[u8], aes_key: &[u8; 32]) -> Result<u64> {
        let index = Index::index_hash(key.as_bytes());
        let block = Block::encrypt_padded(BlockType::Password, aes_key, data)?;
        let offset = self.storage.add_block(block, index)?;
        Ok(offset)
    }

    pub fn upd_object(&mut self, key: &str, data: &[u8], aes_key: &[u8; 32]) -> Result<u64> {
        let index = Index::index_hash(key.as_bytes());
        let block = Block::encrypt_padded(BlockType::Password, aes_key, data)?;
        let offset = self.storage.upd_block(block, index)?;
        Ok(offset)
    }

    pub fn get_object(&self, key: &str, aes_key: &[u8; 32]) -> Result<Vec<u8>> {
        let index = Index::index_hash(key.as_bytes());
        let block = self.storage.get_block(&index)?;
        let plaintext = block.decrypt(aes_key)?;
        Ok(plaintext)
    }

    pub fn del_object(&mut self, key: &str, _aes_key: &[u8; 32]) -> Result<()> {
        let index = Index::index_hash(key.as_bytes());
        self.storage.del_block(&index)?;
        Ok(())
    }
    
    pub fn secure_del_object(&mut self, key: &str, _aes_key: &[u8; 32]) -> Result<()> {
        let index = Index::index_hash(key.as_bytes());
        self.storage.secure_del_block(&index)?;
        Ok(())
    }
    
    pub fn list_objects(&self) -> Vec<String> {
        // TODO: Реализовать хранение ключей в индексе
        // Пока возвращаем пустой список
        Vec::new()
    }
    
    /// Проверить существование объекта
    pub fn has_object(&self, key: &str) -> bool {
        let index = Index::index_hash(key.as_bytes());
        self.storage.has_block(&index)
    }
    
    pub fn secure_delete(mut self) -> Result<()> {
        // todo
        //self.storage.secure_delete()
        Ok(())
    }
}
