use std::fs::{File, OpenOptions};
use std::io::{Read, Write, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use rand::RngCore;

use sha2::{Sha256, Digest};

use super::components::header::{Header, read_header, write_header};
use super::components::index::{Index, read_index, write_index};
use super::components::block::Block;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub struct Storage {
    path: PathBuf,
    header: Header,
    index: Index,
}

impl Drop for Storage {
    fn drop(&mut self) {
        // Header and Index have their own Drop implementations
        // which will be called automatically
    }
}

impl Storage {

    pub fn create<P: AsRef<Path>>(path: P, header: Header) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        
        let mut header = header;
        let index = Index::new();

        let index_bytes = index.to_bytes()
            .map_err(|e| -> Box<dyn std::error::Error> { e })?;
        header.set_index_size(index_bytes.len() as u32);

        let mut file = File::create(&path)?;
        
        // Write metadata (header + index)
        Self::write_metadata_to_file(&mut file, &header, &index)?;
        
        Ok(Self { path, header, index })
    }

    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        
        if !path.exists() {
            return Err(format!("Storage file not found: {:?}", path).into());
        }
        
        let mut file = File::open(&path)?;
        
        // Read metadata (header + index)
        let (header, index) = Self::read_metadata_from_file(&mut file)?;
        
        Ok(Self { path, header, index })
    }

    // Read binary
    pub fn read_binary(&self) -> Result<Vec<u8>> {
        let mut file = File::open(&self.path)?;
        
        let header_size = self.header.size();
        file.seek(SeekFrom::Start(header_size as u64))?;
        
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        
        Ok(data)
    }

    
    pub fn integrity(&self) -> Result<[u8; 32]> {
        let mut file = File::open(&self.path)?;
        let mut hasher = Sha256::new();
        
        let mut buffer = vec![0u8; 1024 * 1024]; // 1 MB chunks
        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
        }
        
        Ok(hasher.finalize().into())
    }

    pub fn compute_mac(&self, key: &[u8; 32]) -> Result<[u8; 32]> {
        use hmac::{Hmac, Mac};
        
        let data = self.read_binary()?;
        
        let mut mac = Hmac::<Sha256>::new_from_slice(key)
            .expect("HMAC can take key of any size");
        mac.update(&data);
        
        let result = mac.finalize();
        let mac_bytes = result.into_bytes();
        
        let mut output = [0u8; 32];
        output.copy_from_slice(&mac_bytes);
        Ok(output)
    }
    
    pub fn verify_mac(&self, key: &[u8; 32], expected_mac: &[u8; 32]) -> Result<bool> {
        let computed_mac = self.compute_mac(key)?;
        Ok(computed_mac == *expected_mac)
    }

    pub fn write(&mut self, data: &[u8]) -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&self.path)?;
        
        // Write header
        write_header(&mut file, &self.header)?;

        // Compute MAC
        let mac = self.compute_mac(&[0u8; 32])?;
        self.header.set_mac(mac);
        
        // Write data
        file.write_all(data)?;
        file.sync_all()?;
        
        Ok(())
    }

    pub fn append(&mut self, data: &[u8]) -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .append(true)
            .open(&self.path)?;
        
        file.write_all(data)?;
        file.sync_all()?;
        
        Ok(())
    }

    pub fn add_block(&mut self, block: Block, index: [u8; 32]) -> Result<u64> {
        // Current filesize = current offset
        let file = OpenOptions::new()
            .read(true)
            .open(&self.path)?;
        
        let offset = file.metadata()?.len();
        let block_size = block.size() as u64;
        
        // put down
        drop(file);
        self.append(&block.to_bytes())?;
        
        // index update
        self.index.insert(index, offset, block_size);
        self.update_metadata()?;
        
        Ok(offset)
    }


    pub fn upd_block(&mut self, block: Block, index: [u8; 32]) -> Result<u64> {
        let new_size = block.size() as u64;
        
        if let Some(&(offset, old_size)) = self.index.get(&index) {
            // The same size
            if new_size == old_size {
                let mut file = OpenOptions::new()
                    .write(true)
                    .open(&self.path)?;
                
                file.seek(SeekFrom::Start(offset))?;
                file.write_all(&block.to_bytes())?;
                file.sync_all()?;
                
                Ok(offset)
            // Different size / update index
            } else {
                self.secure_del_block(&index)?;
                self.add_block(block, index)
            }
        } else {
            self.add_block(block, index)
        }
    }

    /// Проверить существование блока
    pub fn has_block(&self, index: &[u8; 32]) -> bool {
        self.index.contains_key(index)
    }

    pub fn get_block(&self, index: &[u8; 32]) -> Result<Block> {
        let &(offset, size) = self.index.get(index)
            .ok_or("Block not found in index")?;
        
        // Read the block binary
        let mut file = File::open(&self.path)?;
        file.seek(SeekFrom::Start(offset))?;
        
        let mut buffer = vec![0u8; size as usize];
        file.read_exact(&mut buffer)?;
        
        // Deserialize
        Block::from_bytes(&buffer)
            .map_err(|e| format!("Failed to deserialize block: {}", e).into())
    }

    pub fn del_block(&mut self, index: &[u8; 32]) -> Result<()> {
        if !self.index.contains_key(index) {
            return Err("Block not found in index".into());
        }
        
        // Offset / size
        let &(offset, size) = self.index.get(index).unwrap();
        
        // Deleting from file
        let mut file = OpenOptions::new()
            .write(true)
            .open(&self.path)?;
        
        file.seek(SeekFrom::Start(offset))?;
        
        // Writing zeros instead of data
        let zeros = vec![0u8; size as usize];
        file.write_all(&zeros)?;
        file.sync_all()?;
        
        // Removing from index
        self.index.remove(index);
        self.update_metadata()?;
        
        Ok(())
    }
    
    /// Secure deletion with multiple overwrites (DoD 5220.22-M standard)
    pub fn secure_del_block(&mut self, index: &[u8; 32]) -> Result<()> {
        if !self.index.contains_key(index) {
            return Err("Block not found in index".into());
        }

        let &(offset, size) = self.index.get(index).unwrap();
        
        let mut file = OpenOptions::new()
            .write(true)
            .open(&self.path)?;
        
        let size = size as usize;
        
        // DoD 5220.22-M: 3 passes
        // Pass 1: Write 0x00
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(&vec![0x00; size])?;
        file.sync_all()?;
        
        // Pass 2: Write 0xFF
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(&vec![0xFF; size])?;
        file.sync_all()?;
        
        // Pass 3: Write random data
        file.seek(SeekFrom::Start(offset))?;
        let mut random_data = vec![0u8; size];
        rand::thread_rng().fill_bytes(&mut random_data);
        file.write_all(&random_data)?;
        file.sync_all()?;
        
        // Removing from index
        self.index.remove(index);
        
        self.update_metadata()?;
        
        Ok(())
    }

    pub fn header(&self) -> &Header {
        &self.header
    }

    pub fn header_mut(&mut self) -> &mut Header {
        &mut self.header
    }

    pub fn update_header(&self) -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .open(&self.path)?;
        
        // Write header at the beginning of file
        write_header(&mut file, &self.header)?;
        file.sync_all()?;
        
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    pub fn size(&self) -> Result<u64> {
        let metadata = std::fs::metadata(&self.path)?;
        Ok(metadata.len())
    }

    pub fn delete(self) -> Result<()> {
        std::fs::remove_file(&self.path)?;
        Ok(())
    }
    
    /// Securely delete storage file (overwrite with random data before deletion)
    pub fn secure_delete(self) -> Result<()> {
        use rand::RngCore;
        
        let file_size = self.size()?;
        
        let mut file = OpenOptions::new()
            .write(true)
            .open(&self.path)?;
        
        // Overwrite entire file with random data
        const CHUNK_SIZE: usize = 4096;
        let mut random_chunk = vec![0u8; CHUNK_SIZE];
        let mut remaining = file_size as usize;
        
        while remaining > 0 {
            let write_size = remaining.min(CHUNK_SIZE);
            rand::thread_rng().fill_bytes(&mut random_chunk[..write_size]);
            file.write_all(&random_chunk[..write_size])?;
            remaining -= write_size;
        }
        
        file.sync_all()?;
        drop(file);
        
        // Delete file
        std::fs::remove_file(&self.path)?;
        
        // Drop will automatically zeroize header and index
        Ok(())
    }


    /// Read metadata (header + index) from file
    fn read_metadata_from_file<R: Read>(reader: &mut R) -> Result<(Header, Index)> {
        let header = read_header(reader)?;
        let index = read_index(reader, header.index_size())?;
        Ok((header, index))
    }
    
    /// Write metadata (header + index) to file
    fn write_metadata_to_file<W: Write>(writer: &mut W, header: &Header, index: &Index) -> Result<()> {
        write_header(writer, header)?;
        write_index(writer, index)?;
        Ok(())
    }
    
    /// Update metadata (header + index) in existing file
    /// Fast update - metadata size is fixed (Header + Index block)
    pub fn update_metadata(&mut self) -> Result<()> {
        // Update index size in header
        let index_bytes = self.index.to_bytes()
            .map_err(|e| -> Box<dyn std::error::Error> { e })?;
        self.header.set_index_size(index_bytes.len() as u32);
        
        // Open file for writing
        let mut file = OpenOptions::new()
            .write(true)
            .open(&self.path)?;
        
        // Seek to beginning and overwrite metadata
        file.seek(SeekFrom::Start(0))?;
        Self::write_metadata_to_file(&mut file, &self.header, &self.index)?;
        file.sync_all()?;
        
        Ok(())
    }
}
