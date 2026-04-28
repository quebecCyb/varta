use varta::storage::{Storage, Header};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Binary Storage Example ===\n");

    // 1. Create header with KDF parameters
    let salt = [42u8; 32];
    let nonce = [1u8; 12];
    let header = Header::new(
        1,      // kdf_type: Argon2
        3,      // time_cost
        65536,  // memory_cost (64 MB)
        4,      // parallelism
        salt,
        nonce,
    );

    println!("Created header:");
    println!("  Version: {}", header.version());
    println!("  KDF Type: {}", header.kdf_type());
    println!("  Time Cost: {}", header.time_cost());
    println!("  Memory Cost: {} KB", header.memory_cost());
    println!("  Parallelism: {}", header.parallelism());
    println!("  Header size: {} bytes\n", header.size());

    // 2. Create storage file
    let path = "/tmp/varta_test.bin";
    let mut storage = Storage::create(path, header)?;
    println!("Created storage file: {}\n", path);

    // 3. Write encrypted data
    let data = b"This is encrypted vault data!";
    storage.write(data)?;
    println!("Written {} bytes of encrypted data\n", data.len());

    // 4. Read back
    let read_data = storage.read()?;
    println!("Read {} bytes back", read_data.len());
    println!("Data matches: {}\n", read_data == data);

    // 5. Append more data
    let more_data = b" More encrypted data!";
    storage.append(more_data)?;
    println!("Appended {} bytes\n", more_data.len());

    // 6. Read all data
    let all_data = storage.read()?;
    println!("Total size: {} bytes", all_data.len());
    println!("File size: {} bytes\n", storage.size()?);

    // 7. Reopen storage
    drop(storage);
    let storage = Storage::open(path)?;
    println!("Reopened storage file");
    println!("Header version: {}", storage.header().version());
    println!("Header KDF type: {}\n", storage.header().kdf_type());

    // 8. Clean up
    storage.delete()?;
    println!("Deleted storage file");

    Ok(())
}
