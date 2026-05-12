use std::io::{self, Read, Write};
use zeroize::Zeroize;

// Magic bytes for different file types
pub const MAGIC_STORAGE: &[u8; 4] = b"SVRT";   // Storage vault
pub const MAGIC_OBJECT: &[u8; 4] = b"OVRT";    // Object audit log
pub const MAGIC_ACTIVITY: &[u8; 4] = b"AVRT";  // Activity audit log

const CURRENT_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    Storage,
    ObjectAudit,
    ActivityAudit,
}

impl FileType {
    pub fn magic(&self) -> &'static [u8; 4] {
        match self {
            FileType::Storage => MAGIC_STORAGE,
            FileType::ObjectAudit => MAGIC_OBJECT,
            FileType::ActivityAudit => MAGIC_ACTIVITY,
        }
    }
    
    pub fn from_magic(magic: &[u8; 4]) -> io::Result<Self> {
        match magic {
            b"SVRT" => Ok(FileType::Storage),
            b"OVRT" => Ok(FileType::ObjectAudit),
            b"AVRT" => Ok(FileType::ActivityAudit),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unknown magic bytes: {:?}", magic)
            )),
        }
    }
    
    pub fn extension(&self) -> &'static str {
        match self {
            FileType::Storage => "svrt",
            FileType::ObjectAudit => "ovrt",
            FileType::ActivityAudit => "avrt",
        }
    }
}

pub struct Header {
    file_type: FileType,
    version: u16,
    flags: u8,
    mac: [u8; 32],
    index_size: u32,               // if 0 - index off
    
    metadata_nonce: [u8; 12],      // 12 bytes
    metadata_ciphertext: [u8; 97], // 97 bytes (version + agent_id + master_key + vault_digest)
    metadata_tag: [u8; 16],        // 16 bytes
    
    reserved: [u8; 128],
}

impl Drop for Header {
    fn drop(&mut self) {
        self.mac.zeroize();
        self.metadata_nonce.zeroize();
        self.metadata_ciphertext.zeroize();
        self.metadata_tag.zeroize();
        self.reserved.zeroize();
    }
}

impl Header {
    pub fn new(file_type: FileType) -> Self {
        Self {
            file_type,
            version: CURRENT_VERSION,
            flags: 0,
            mac: [0u8; 32],
            index_size: 0,
            metadata_nonce: [0u8; 12],
            metadata_ciphertext: [0u8; 97],
            metadata_tag: [0u8; 16],
            reserved: [0u8; 128],
        }
    }

    pub fn size(&self) -> usize {
        4 +  // magic
        2 +  // version
        1 +  // flags
        32 + // mac
        4 +  // index_size
        12 + // metadata_nonce
        97 + // metadata_ciphertext
        16 + // metadata_tag
        128  // reserved
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(self.size());
        
        buffer.extend_from_slice(self.file_type.magic());
        buffer.extend_from_slice(&self.version.to_le_bytes());
        buffer.push(self.flags);
        buffer.extend_from_slice(&self.mac);
        buffer.extend_from_slice(&self.index_size.to_le_bytes());
        buffer.extend_from_slice(&self.metadata_nonce);
        buffer.extend_from_slice(&self.metadata_ciphertext);
        buffer.extend_from_slice(&self.metadata_tag);
        buffer.extend_from_slice(&self.reserved);
        
        buffer
    }

    pub fn from_bytes(data: &[u8]) -> io::Result<Self> {
        if data.len() < 4 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Data too short"));
        }

        let mut offset = 0;

        let magic: [u8; 4] = data[offset..offset + 4].try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid magic"))?;
        let file_type = FileType::from_magic(&magic)?;
        offset += 4;

        if data.len() < offset + 2 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Missing version"));
        }
        let version = u16::from_le_bytes([data[offset], data[offset + 1]]);
        offset += 2;

        if data.len() < offset + 1 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Missing flags"));
        }
        let flags = data[offset];
        offset += 1;
        
        if data.len() < offset + 32 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Missing MAC"));
        }
        let mut mac = [0u8; 32];
        mac.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        if data.len() < offset + 4 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Missing index_size"));
        }
        let index_size = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        offset += 4;
        
        if data.len() < offset + 12 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Missing metadata_nonce"));
        }
        let mut metadata_nonce = [0u8; 12];
        metadata_nonce.copy_from_slice(&data[offset..offset + 12]);
        offset += 12;
        
        if data.len() < offset + 97 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Missing metadata_ciphertext"));
        }
        let mut metadata_ciphertext = [0u8; 97];
        metadata_ciphertext.copy_from_slice(&data[offset..offset + 97]);
        offset += 97;
        
        if data.len() < offset + 16 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Missing metadata_tag"));
        }
        let mut metadata_tag = [0u8; 16];
        metadata_tag.copy_from_slice(&data[offset..offset + 16]);
        offset += 16;
        
        if data.len() < offset + 128 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Missing reserved bytes"));
        }
        let mut reserved = [0u8; 128];
        reserved.copy_from_slice(&data[offset..offset + 128]);

        Ok(Self {
            file_type,
            version,
            flags,
            mac,
            index_size,
            metadata_nonce,
            metadata_ciphertext,
            metadata_tag,
            reserved,
        })
    }

    pub fn version(&self) -> u16 {
        self.version
    }

    pub fn index_size(&self) -> u32 {
        self.index_size
    }

    pub fn set_index_size(&mut self, size: u32) {
        self.index_size = size;
    }
    
    pub fn mac(&self) -> &[u8; 32] {
        &self.mac
    }
    
    pub fn set_mac(&mut self, mac: [u8; 32]) {
        self.mac = mac;
    }
    
    pub fn file_type(&self) -> FileType {
        self.file_type
    }
    
    pub fn set_vault_metadata(
        &mut self,
        nonce: [u8; 12],
        ciphertext: [u8; 97],
        tag: [u8; 16],
    ) {
        self.metadata_nonce = nonce;
        self.metadata_ciphertext = ciphertext;
        self.metadata_tag = tag;
    }
    
    pub fn get_vault_metadata(&self) -> (&[u8; 12], &[u8; 97], &[u8; 16]) {
        (
            &self.metadata_nonce,
            &self.metadata_ciphertext,
            &self.metadata_tag,
        )
    }
    
    pub fn has_vault_metadata(&self) -> bool {
        self.metadata_nonce != [0u8; 12]
    }
}

pub fn read_header<R: Read>(reader: &mut R) -> io::Result<Header> {
    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic)?;
    
    let file_type = FileType::from_magic(&magic)?;

    let mut version_bytes = [0u8; 2];
    reader.read_exact(&mut version_bytes)?;
    let version = u16::from_le_bytes(version_bytes);

    let mut flags = [0u8; 1];
    reader.read_exact(&mut flags)?;
    
    let mut mac = [0u8; 32];
    reader.read_exact(&mut mac)?;

    let mut index_size_bytes = [0u8; 4];
    reader.read_exact(&mut index_size_bytes)?;
    let index_size = u32::from_le_bytes(index_size_bytes);
    
    let mut metadata_nonce = [0u8; 12];
    reader.read_exact(&mut metadata_nonce)?;
    
    let mut metadata_ciphertext = [0u8; 97];
    reader.read_exact(&mut metadata_ciphertext)?;
    
    let mut metadata_tag = [0u8; 16];
    reader.read_exact(&mut metadata_tag)?;
    
    let mut reserved = [0u8; 128];
    reader.read_exact(&mut reserved)?;

    Ok(Header {
        file_type,
        version,
        flags: flags[0],
        mac,
        index_size,
        metadata_nonce,
        metadata_ciphertext,
        metadata_tag,
        reserved,
    })
}

pub fn write_header<W: Write>(writer: &mut W, header: &Header) -> io::Result<()> {
    let bytes = header.to_bytes();
    writer.write_all(&bytes)?;
    Ok(())
}
