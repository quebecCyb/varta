use crate::storage::Storage;
use crate::storage::components::index::Index;
use crate::storage::components::block::Block;
use crate::storage::components::block_header::BlockType;
use crate::storage::components::header::{Header, FileType};
use crate::config::OBJECT_FILE_EXT;

use std::path::Path;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub struct ObjectStorage {
    storage: Storage, 
}

impl ObjectStorage {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let header = Header::new(FileType::Storage);
        let path_with_ext = path.as_ref().with_extension(OBJECT_FILE_EXT);
        let storage = Storage::create(path_with_ext, header, true)?;
        Ok(Self { storage })
    }
    
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path_with_ext = path.as_ref().with_extension(OBJECT_FILE_EXT);
        let storage = Storage::open(path_with_ext)?;
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
    
    pub fn list_objects<'a>(&'a self, aes_key: &'a [u8; 32]) -> ObjectPlainIter<'a> {
        ObjectPlainIter {
            storage: self.storage(),
            indices: self.storage.list_indices(),
            pos: 0,
            aes_key,
        }
    }
    
    pub fn has_object(&self, key: &str) -> bool {
        let index = Index::index_hash(key.as_bytes());
        self.storage.has_block(&index)
    }
    
    pub fn secure_delete(self) -> Result<()> {
        self.storage.secure_delete()
    }
}


pub struct ObjectPlainIter<'a> {
    storage: &'a Storage,
    indices: Vec<[u8; 32]>,
    pos: usize,
    aes_key: &'a [u8; 32],
}

impl<'a> Iterator for ObjectPlainIter<'a> {
    type Item = Result<Vec<u8>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.indices.len() {
            return None;
        }

        let index = self.indices[self.pos];
        self.pos += 1;

        let res = (|| {
            let block = self.storage.get_block(&index)?;
            block.decrypt(self.aes_key)
        })();

        Some(res)
    }
}
