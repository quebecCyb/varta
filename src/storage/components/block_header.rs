use std::io;
use std::time::{SystemTime, UNIX_EPOCH};


const BLOCK_MAGIC: &[u8; 4] = b"VBLK";
pub const HEADER_SIZE: usize = 64;
pub const VERSION: u8 = 1;


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockType {
    Password = 0x01,
    Note = 0x02,
    File = 0x03,
    Card = 0x04,
    Identity = 0x05,
    Custom = 0xFF,
}

impl BlockType {
    pub fn from_u8(value: u8) -> io::Result<Self> {
        match value {
            0x01 => Ok(BlockType::Password),
            0x02 => Ok(BlockType::Note),
            0x03 => Ok(BlockType::File),
            0x04 => Ok(BlockType::Card),
            0x05 => Ok(BlockType::Identity),
            0xFF => Ok(BlockType::Custom),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unknown block type: {}", value)
            )),
        }
    }
    
    pub fn to_u8(&self) -> u8 {
        *self as u8
    }
}

pub struct BlockHeader {
    magic: [u8; 4],
    version: u8,
    block_type: BlockType,
    flags: u16,
    timestamp: u64,
    modified_at: u64,
    plaintext_size: u32,
    reserved: [u8; 36],
}

impl BlockHeader {
    
    pub fn new(block_type: BlockType, plaintext_size: u32) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Self {
            magic: *BLOCK_MAGIC,
            version: VERSION,
            block_type,
            flags: 0,
            timestamp: now,
            modified_at: now,
            plaintext_size,
            reserved: [0u8; 36],
        }
    }
    
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(HEADER_SIZE);
        
        buffer.extend_from_slice(&self.magic);
        buffer.push(self.version);
        buffer.push(self.block_type.to_u8());
        buffer.extend_from_slice(&self.flags.to_le_bytes());
        buffer.extend_from_slice(&self.timestamp.to_le_bytes());
        buffer.extend_from_slice(&self.modified_at.to_le_bytes());
        buffer.extend_from_slice(&self.plaintext_size.to_le_bytes());
        buffer.extend_from_slice(&self.reserved);
        
        buffer
    }
    
    pub fn from_bytes(data: &[u8]) -> io::Result<Self> {
        if data.len() < HEADER_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Block header too short"
            ));
        }
        
        let mut offset = 0;
        
        let mut magic = [0u8; 4];
        magic.copy_from_slice(&data[offset..offset + 4]);
        if &magic != BLOCK_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid block magic: expected {:?}, got {:?}", BLOCK_MAGIC, magic)
            ));
        }
        offset += 4;
        
        let version = data[offset];
        offset += 1;
        
        let block_type = BlockType::from_u8(data[offset])?;
        offset += 1;
        
        let flags = u16::from_le_bytes([data[offset], data[offset + 1]]);
        offset += 2;
        
        let timestamp = u64::from_le_bytes(
            data[offset..offset + 8].try_into().unwrap()
        );
        offset += 8;
        
        let modified_at = u64::from_le_bytes(
            data[offset..offset + 8].try_into().unwrap()
        );
        offset += 8;
        
        let plaintext_size = u32::from_le_bytes(
            data[offset..offset + 4].try_into().unwrap()
        );
        offset += 4;
        
        let mut reserved = [0u8; 36];
        reserved.copy_from_slice(&data[offset..offset + 36]);
        
        Ok(Self {
            magic,
            version,
            block_type,
            flags,
            timestamp,
            modified_at,
            plaintext_size,
            reserved,
        })
    }
    
    pub fn size(&self) -> usize {
        HEADER_SIZE
    }
    
    pub fn block_type(&self) -> BlockType {
        self.block_type
    }
    
    pub fn version(&self) -> u8 {
        self.version
    }
    
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }
    
    pub fn modified_at(&self) -> u64 {
        self.modified_at
    }
    
    pub fn plaintext_size(&self) -> u32 {
        self.plaintext_size
    }
    
    pub fn is_compressed(&self) -> bool {
        self.flags & 0x01 != 0
    }
    
    pub fn set_compressed(&mut self, compressed: bool) {
        if compressed {
            self.flags |= 0x01;
        } else {
            self.flags &= !0x01;
        }
    }
    
    pub fn is_deleted(&self) -> bool {
        self.flags & 0x02 != 0
    }
    
    pub fn set_deleted(&mut self, deleted: bool) {
        if deleted {
            self.flags |= 0x02;
        } else {
            self.flags &= !0x02;
        }
        
        if deleted {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            self.modified_at = now;
        }
    }
    
    pub fn touch(&mut self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.modified_at = now;
    }
}
