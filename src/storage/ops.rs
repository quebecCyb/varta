use crate::storage::Storage;
use crate::storage::components::block::Block;
use crate::storage::components::block_header::BlockType;
use crate::storage::components::header::{Header, FileType};
use crate::config::OPERATION_FILE_EXT;

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub struct OperationStorage {
    storage: Storage, 
}

impl OperationStorage {
    pub fn new(path: &str) -> Result<Self> {
        let header = Header::new(FileType::Storage);
        let storage = Storage::create(format!("{}.{}", path, OPERATION_FILE_EXT), header, false)?;

        Ok(Self { storage })
    }


    pub fn open(path: &str) -> Result<Self> {
        let storage = Storage::open(format!("{}.{}", path, OPERATION_FILE_EXT))?;
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

    pub fn append_operation(&mut self, data: &[u8], aes_key: &[u8; 32]) -> Result<u64> {
        let block = Block::encrypt_padded(BlockType::Custom, aes_key, data)?;

        let offset = self.storage.size()?;
        self.storage.append(&block.to_bytes())?;
        Ok(offset)
    }

    pub fn read_last_operation(&self, aes_key: &[u8; 32]) -> Result<Option<Vec<u8>>> {
        let file_size = self.storage.size()?;

        let block_size = Block::block_size() as u64;
        let meta_size = self.storage.header().size() as u64;

        if file_size <= meta_size {
            return Ok(None);
        }

        let data_size = file_size - meta_size;
        if data_size < block_size {
            return Ok(None);
        }

        let last_offset = file_size - block_size;

        let mut file = File::open(self.storage.path())?;
        file.seek(SeekFrom::Start(last_offset))?;

        let mut buffer = vec![0u8; block_size as usize];
        file.read_exact(&mut buffer)?;

        let block = Block::from_bytes(&buffer)?;
        let plaintext = block.decrypt(aes_key)?;
        Ok(Some(plaintext))
    }
    
}
