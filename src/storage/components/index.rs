
use std::collections::HashMap;
use std::io::{self, Read, Write};
use borsh::{to_vec, from_slice};
use zeroize::Zeroize;
use sha2::{Sha256, Digest};


type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

const INDEX_BLOCK_SIZE: usize = 12288;

pub struct Index {
    index: HashMap<[u8; 32], (u64, u64)>, // encrypted key -> (offset, length) - will be zeroized
}

impl Drop for Index {
    fn drop(&mut self) {
        let keys: Vec<[u8; 32]> = self.index.keys().copied().collect();
        for mut key in keys {
            key.zeroize();
        }
        self.index.clear();
    }
}

impl Index {
    pub fn new() -> Self {
        Self {
            index: HashMap::new(),
        }
    }
    
    pub fn from_data(data: Option<&[u8]>) -> Result<Self> {
        let index = match data {
            Some(bytes) if !bytes.is_empty() => from_slice(bytes)?,
            _ => HashMap::new(),
        };
        
        Ok(Self { index })
    }
    
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(to_vec(&self.index)?)
    }
    
    pub fn get(&self, key: &[u8; 32]) -> Option<&(u64, u64)> {
        self.index.get(key)
    }
    
    pub fn insert(&mut self, key: [u8; 32], offset: u64, length: u64) {
        self.index.insert(key, (offset, length));
    }
    
    pub fn remove(&mut self, key: &[u8; 32]) -> Option<(u64, u64)> {
        self.index.remove(key)
    }
    
    pub fn contains_key(&self, key: &[u8; 32]) -> bool {
        self.index.contains_key(key)
    }
    
    pub fn keys(&self) -> Vec<&[u8; 32]> {
        self.index.keys().collect()
    }
    
    pub fn len(&self) -> usize {
        self.index.len()
    }

    pub fn size(&self) -> usize {
        INDEX_BLOCK_SIZE
    }
    
    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    pub fn index_hash(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
}

pub fn read_index<R: Read>(reader: &mut R, index_size: u32) -> io::Result<Index> {
    // Reading index block
    let mut block = vec![0u8; INDEX_BLOCK_SIZE];
    reader.read_exact(&mut block)?;
    
    if index_size == 0 {
        return Ok(Index::new());
    }
    
    // Deserializing only index_size bytes (the rest is padding)
    let index_data = &block[..index_size as usize];
    
    Index::from_data(Some(index_data))
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

pub fn write_index<W: Write>(writer: &mut W, index: &Index) -> io::Result<()> {
    let bytes = index.to_bytes()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    
    if bytes.len() > INDEX_BLOCK_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Index size {} exceeds block size {}", bytes.len(), INDEX_BLOCK_SIZE)
        ));
    }
    
    writer.write_all(&bytes)?;
    
    // padding to INDEX_BLOCK_SIZE
    let padding = INDEX_BLOCK_SIZE - bytes.len();
    if padding > 0 {
        let zeros = vec![0u8; padding];
        writer.write_all(&zeros)?;
    }
    
    Ok(())
}
