use std::io::{self, Write, Read};
use rand::rngs::OsRng;
use rand::RngCore;
use std::fs::File;
use std::fs;
// use sha2::{Sha256};

mod common;
mod agent;
mod crypto;
mod vault_object;
use crate::agent::Agent;
mod operation;
mod vault;
use crate::vault::Vault;

const DEVICE_KEY_FILE: &str = "device_key";

fn load_or_create_device_key() -> [u8; 32] {
    let mut device_key: [u8; 32] = [0u8; 32];

    if fs::exists(DEVICE_KEY_FILE).unwrap() {
        println!("Reading device key...");
        let mut file = File::open(DEVICE_KEY_FILE).unwrap();
        file.read_exact(&mut device_key).unwrap();
        println!("Device key read.");
    }

    if device_key == [0u8; 32] {
        println!("Creating device key...");
        OsRng.fill_bytes(&mut device_key);
        let mut file = File::create(DEVICE_KEY_FILE).unwrap();
        file.write_all(&device_key).unwrap();
        println!("Device key created.");
    }

    println!("Device key: {:?}", device_key);
    device_key
}

fn str_to_fixed_32(s: &str) -> Result<[u8; 32], &'static str> {
    let bytes = s.as_bytes();

    if bytes.len() > 32 {
        return Err("Key must be at most 32 bytes");
    }

    let mut key = [0u8; 32];
    key[..bytes.len()].copy_from_slice(bytes);

    Ok(key)
}

fn read_input() -> String {
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}

fn get_args(input: &str) -> Vec<&str> {
    input.split_whitespace().collect()
}

fn print_help() {
    println!("Available commands:");
    println!("  agent new <name>    - Create a new agent");
    println!("  agent login <name>  - Login as an agent");
    println!("  agent switch        - Switch to another agent");
    println!("  vault new <name>    - Create a new vault");
    println!("  vault open <name>   - Open a vault");
    println!("  vault close         - Close current vault");
    println!("  help                - Show this help");
    println!("  exit                - Exit the application");
}

fn main() {
    let _device_key = load_or_create_device_key();

    let mut current_agent: Option<Agent> = None;
    let mut current_vault: Option<Vault> = None;

    println!("Password Manager - Type 'help' for available commands");

    loop {
        // Show prompt based on current state
        let prompt = match (&current_agent, &current_vault) {
            (Some(agent), Some(vault)) => format!("{}:{} > ", agent.name, vault.name),
            (Some(agent), None) => format!("{} > ", agent.name),
            (None, _) => "guest > ".to_string(),
        };

        print!("{}", prompt);
        io::stdout().flush().unwrap();

        let input = read_input();
        if input.is_empty() {
            continue;
        }

        let args = get_args(&input);
        let command = args[0];

        match command {
            "exit" => {
                println!("Bye...");
                break;
            }
            
            "help" => print_help(),
            
            "agent" => {
                if args.len() < 2 {
                    println!("Usage: agent <new|login|switch> [name]");
                    continue;
                }

                match args[1] {
                    "new" => {
                        if args.len() < 3 {
                            println!("Usage: agent new <name>");
                            continue;
                        }

                        let agent = Agent::create(args[2].to_string());
                        println!("Agent '{}' created", agent.name);

                        current_agent = Some(agent);
                        current_vault = None;
                    }
                    "login" => {
                        if args.len() < 3 {
                            println!("Usage: agent login <name>");
                            continue;
                        }

                        let agent = Agent::login(args[2].to_string());
                        println!("Logged in as '{}'", agent.name);

                        current_agent = Some(agent);
                        current_vault = None;
                    }
                    "switch" => {
                        current_agent = None;
                        current_vault = None;
                        println!("Agent logged out");
                    }
                    _ => println!("Unknown agent command: {}", args[1]),
                }
            }
            
            "vault" => {
                if args.len() < 2 {
                    println!("Usage: vault <new|open|close> [name]");
                    continue;
                }

                let Some(ref agent) = current_agent else {
                    println!("Please login first (use 'agent login <name>' or 'agent new <name>')");
                    continue;
                };

                match args[1] {
                    "new" => {
                        if args.len() < 3 {
                            println!("Usage: vault new <name>");
                            continue;
                        }
                        println!("Creating vault '{}'...", args[2]);
                        // create_vault(args[2].to_string(), agent);
                        let derivation_key = agent.get_vault_derivation_key();
                        current_vault = Some(Vault::create(args[2].to_string(), agent, derivation_key));
                    }
                    "open" => {
                        if args.len() < 3 {
                            println!("Usage: vault open <name>");
                            continue;
                        }
                        println!("Opening vault '{}'...", args[2]);
                        // open_vault(args[2].to_string(), agent);
                        let derivation_key = agent.get_vault_derivation_key();
                        current_vault = Some(Vault::open(args[2].to_string(), agent, derivation_key));
                    }
                    "close" => {
                        if let Some(vault) = &current_vault {
                            println!("Closing vault '{}'", vault.name);
                            current_vault = None;
                        } else {
                            println!("No vault is currently open");
                        }
                    }
                    _ => println!("Unknown vault command: {}", args[1]),
                }
            }

            "object" => {
                if args.len() < 2 {
                    println!("Usage: object <add|update|delete> [key] [value]");
                    continue;
                }

                let Some(ref mut vault) = current_vault else {
                    println!("Please open a vault first (use 'vault open <name>')");
                    continue;
                };

                match args[1] {
                    "add" => {
                        if args.len() < 4 {
                            println!("Usage: object add <key> <value>");
                            continue;
                        }
                        println!("Adding object '{}'...", args[2]);

                        let key: &str = args[2];

                        let value = args[3].as_bytes().to_vec();
                        
                        vault.create_object(key.to_string(), value);
                        println!("Object created with key: {}", key);
                    }
                    "update" => {
                        if args.len() < 4 {
                            println!("Usage: object update <key> <value>");
                            continue;
                        }
                        println!("Updating object '{}'...", args[2]);
                        
                        let key: &str = args[2];

                        let value = args[3].as_bytes().to_vec();
                        
                        if vault.update_object(key, value) {
                            println!("Object updated: {}", key);
                        } else {
                            println!("Object not found: {}", key);
                        }
                    }
                    "list" => {
                        println!("Listing objects...");
                        for key in vault.list_objects() {
                            println!("{}", key);
                        }
                    }
                    "read" => {
                        if args.len() < 3 {
                            println!("Usage: object read <key>");
                            continue;
                        }
                        println!("Reading object '{}'...", args[2]);

                        let key: &str = args[2];
                        
                        if let Some(obj) = vault.read_object(key) {
                            println!("Object read: {}", key);
                            println!("Value: {}", String::from_utf8_lossy(&obj.value));
                        } else {
                            println!("Object not found: {}", key);
                        }
                    }
                    "delete" => {
                        if args.len() < 3 {
                            println!("Usage: object delete <key>");
                            continue;
                        }
                        println!("Deleting object '{}'...", args[2]);
                        
                        let key: &str = args[2];
                        
                        if vault.delete_object(key) {
                            println!("Object deleted: {}", key);
                        } else {
                            println!("Object not found: {}", key);
                        }
                    }
                    _ => println!("Unknown object command: {}", args[1]),
                }
            }
            
            _ => println!("Unknown command: '{}'. Type 'help' for available commands.", command),
        }
    }
}