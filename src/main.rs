use std::io::{self, Write};

mod common;
mod agent;
mod crypto;
mod vault_object;
mod device;
use crate::agent::Agent;
mod operation;
mod vault;
use crate::vault::Vault;
use crate::device::Device;


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
    let _device = Device::new();

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

                        let agent = Agent::new(args[2].to_string(), None);
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
                        
                        current_vault = Some(Vault::new(args[2].to_string(), agent));
                    }
                    "open" => {
                        if args.len() < 3 {
                            println!("Usage: vault open <name>");
                            continue;
                        }
                        println!("Opening vault '{}'...", args[2]);
                        current_vault = Some(Vault::open(args[2].to_string(), agent));
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
                        
                        vault.update_object(key, value);
                        println!("Object updated: {}", key);
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
                        
                        let obj = vault.read_object(key);
                        let value = String::from_utf8(obj.value.clone()).unwrap();
                        println!("Object read: {}", value);
                    }
                    "delete" => {
                        if args.len() < 3 {
                            println!("Usage: object delete <key>");
                            continue;
                        }
                        println!("Deleting object '{}'...", args[2]);
                        
                        let key: &str = args[2];
                        
                        vault.delete_object(key);
                        println!("Object deleted: {}", key);
                    }
                    _ => println!("Unknown object command: {}", args[1]),
                }
            }
            
            _ => println!("Unknown command: '{}'. Type 'help' for available commands.", command),
        }
    }
}