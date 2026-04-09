use std::io::{self, Write};
use zeroize::Zeroize;
mod common;
mod agent;
mod os;
mod crypto;
mod session;
mod vault_object;
mod device;
mod operation;
mod vault;
use crate::session::Session;


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

    println!("Agent commands:");
    println!("  agent new <name>    - Create a new agent");
    println!("  agent login <name>  - Login as an agent");
    println!("  agent switch        - Switch to another agent");

    println!("Vault commands:");
    println!("  vault new <name>    - Create a new vault");
    println!("  vault open <name>   - Open a vault");
    println!("  vault close         - Close current vault");

    println!("Object commands:");
    println!("  object add <key> <value>     - Create new object");
    println!("  object update <key> <value>  - Update existing object");
    println!("  object read <key>            - Read object value");
    println!("  object delete <key>          - Delete object");
    println!("  object list                  - List all object keys");

    println!("  help                - Show this help");
    println!("  exit                - Exit the application");
}

fn main() {
    println!("\n{}", "=".repeat(60));
    println!(r#"
    ██╗   ██╗ █████╗ ██████╗ ████████╗ █████╗ 
    ██║   ██║██╔══██╗██╔══██╗╚══██╔══╝██╔══██╗
    ██║   ██║███████║██████╔╝   ██║   ███████║
    ╚██╗ ██╔╝██╔══██║██╔══██╗   ██║   ██╔══██║
     ╚████╔╝ ██║  ██║██║  ██║   ██║   ██║  ██║
      ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝"#);
    println!("\n    🔐 Secure Password Manager v{}", env!("CARGO_PKG_VERSION"));
    println!("    🛡️  Hardware-backed encryption on Apple devices");
    println!("\n{}", "=".repeat(60));
    println!("\n💡 Type 'help' to see available commands\n");

    let mut session = Session::new();

    loop {
        // Show prompt based on current state
        let prompt = match (session.get_agent(), session.get_vault()) {
            (Some(agent), Some(vault)) => format!("{}:{} > ", agent.get_name(), vault.get_name()),
            (Some(agent), None) => format!("{} > ", agent.get_name()),
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
                    println!("Usage: agent <new|login|switch> [name] (password)");
                    continue;
                }

                match args[1] {
                    "new" => {
                        if args.len() < 3 {
                            println!("Usage: agent new [name] [password?]");
                            continue;
                        }

                        let password = if args.len() >= 4 {
                            Some(args[3].to_string())
                        } else {
                            None
                        };
                        session.create_agent(args[2].to_string(), password);
                        if let Some(agent) = session.get_agent() {
                            println!("Agent '{}' created", agent.get_name());
                        }
                    }
                    "login" => {
                        if args.len() < 3 {
                            println!("Usage: agent login [name] [password?]");
                            continue;
                        }

                        let password = if args.len() >= 4 {
                            args[3].to_string()
                        } else {
                            String::new()
                        };
                        session.login_agent(args[2].to_string(), password);
                        if let Some(agent) = session.get_agent() {
                            println!("Logged in as '{}'", agent.get_name());
                        }
                    }
                    "switch" => {
                        session.switch();
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


                match args[1] {
                    "new" => {
                        if args.len() < 3 {
                            println!("Usage: vault new <name>");
                            continue;
                        }
                        println!("Creating vault '{}'...", args[2]);
                        
                        session.new_vault(args[2].to_string());
                    }
                    "open" => {
                        if args.len() < 3 {
                            println!("Usage: vault open <name>");
                            continue;
                        }
                        println!("Opening vault '{}'...", args[2]);
                        session.open_vault(args[2].to_string());
                    }
                    "close" => {
                        if let Some(vault) = session.get_vault() {
                            println!("Closing vault '{}'", vault.get_name());
                        }
                        session.close_vault();
                    }
                    _ => println!("Unknown vault command: {}", args[1]),
                }
            }

            "object" => {
                if args.len() < 2 {
                    println!("Usage: object <add|update|delete> [key] [value]");
                    continue;
                }

                match args[1] {
                    "add" => {
                        if args.len() < 4 {
                            println!("Usage: object add <key> <value>");
                            continue;
                        }
                        println!("Adding object '{}'...", args[2]);

                        let key: &str = args[2];

                        let value = args[3].as_bytes().to_vec();
                        
                        session.add_object(key.to_string(), value);
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
                        
                        session.update_object(key.to_string(), value);
                        println!("Object updated: {}", key);
                    }
                    "list" => {
                        println!("Listing objects...");
                        for key in session.list_objects() {
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
                        
                        let obj = session.read_object(key);
                        let value = String::from_utf8(obj.get_value().to_vec()).unwrap();
                        println!("Object read: {}", value);
                    }
                    "delete" => {
                        if args.len() < 3 {
                            println!("Usage: object delete <key>");
                            continue;
                        }
                        println!("Deleting object '{}'...", args[2]);
                        
                        let key: &str = args[2];
                        
                        session.delete_object(key);
                        println!("Object deleted: {}", key);
                    }
                    _ => println!("Unknown object command: {}", args[1]),
                }
            }
            
            _ => println!("Unknown command: '{}'. Type 'help' for available commands.", command),
        }
    }
}