
use std::io::{self, Read, Write};
use zeroize::Zeroize;
use borsh::{to_vec, from_slice, BorshDeserialize, BorshSerialize};

const REGISTRY_BLOCK_SIZE: usize = 4096;


type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;


#[derive(BorshSerialize, BorshDeserialize)]
pub struct Registry {
    settings: [u8; 1], // Binary / Boolean line: key_save
    keys: Vec<String>, // encrypted key -> (offset, length) - will be zeroized
}

impl Drop for Registry {
    fn drop(&mut self) {
        self.settings.zeroize();

        for key in &mut self.keys {
            key.zeroize();
        }

        self.keys.clear();
    }
}
impl Registry {
    pub fn new() -> Self {
        Self {
            settings: [1],
            keys: Vec::new(),
        }
    }

    pub fn from_data(data: &[u8]) -> Result<Self> {
        let registry = from_slice(data)?;
        Ok(registry)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(to_vec(self)?)
    }

    pub fn settings(&self) -> &[u8; 1] {
        &self.settings
    }

    pub fn set_key_save(&mut self, enabled: bool) {
        self.settings[0] = u8::from(enabled);
    }

    pub fn key_save(&self) -> bool {
        self.settings[0] == 1
    }

    pub fn add_key(&mut self, key: String) {
        self.keys.push(key);
    }

    pub fn keys(&self) -> &[String] {
        &self.keys
    }

    pub fn remove_key(&mut self, key: &str) {
        if let Some(position) = self.keys.iter().position(|k| k == key) {
            let mut removed = self.keys.remove(position);
            removed.zeroize();
        }
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }
}
pub fn read_registry<R: Read>(
    reader: &mut R,
    registry_size: u32,
) -> io::Result<Registry> {
    // Always read the full block (like read_index)
    let mut block = vec![0u8; REGISTRY_BLOCK_SIZE];
    reader.read_exact(&mut block)?;

    if registry_size == 0 {
        return Ok(Registry::new());
    }

    // Deserialize only registry_size bytes (the rest is padding)
    let registry_data = &block[..registry_size as usize];

    Registry::from_data(registry_data)
        .map_err(|e| io::Error::new(
            io::ErrorKind::InvalidData,
            e.to_string(),
        ))
}

pub fn write_registry<W: Write>(
    writer: &mut W,
    registry: &Registry,
) -> io::Result<u64> {
    let bytes = registry.to_bytes()
        .map_err(|e| io::Error::new(
            io::ErrorKind::InvalidData,
            e.to_string(),
        ))?;

    if bytes.len() > REGISTRY_BLOCK_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Registry size {} exceeds block size {}", bytes.len(), REGISTRY_BLOCK_SIZE),
        ));
    }

    let size = bytes.len() as u64;

    writer.write_all(&bytes)?;

    // Padding to REGISTRY_BLOCK_SIZE
    let padding = REGISTRY_BLOCK_SIZE - bytes.len();
    if padding > 0 {
        writer.write_all(&vec![0u8; padding])?;
    }

    Ok(size)
}
