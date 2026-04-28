use colored::Colorize;
use crate::session::Session;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub struct CommandHandlers;

impl CommandHandlers {
    pub fn handle_agent(session: &mut Session, args: &[&str], read_password: impl Fn(&str) -> std::io::Result<String>) -> Result<()> {
        if args.len() < 2 {
            return Err("Usage: agent <new|login|switch> [name]".into());
        }
        
        match args[1] {
            "new" => {
                if args.len() < 3 {
                    return Err("Usage: agent new <name>".into());
                }
                
                let password = if args.len() > 3 {
                    args[3..].join(" ")
                } else {
                    read_password(&format!("🔐 Enter password for '{}': ", args[2]))?
                };
                
                let password_opt = if password.is_empty() { None } else { Some(password) };
                session.create_agent(args[2].to_string(), password_opt)?;
                
                if let Some(agent) = session.get_agent() {
                    println!("{} Agent '{}' created", "✓".green().bold(), agent.get_name().cyan());
                }
            }
            "login" => {
                if args.len() < 3 {
                    return Err("Usage: agent login <name>".into());
                }
                
                let password = if args.len() > 3 {
                    args[3..].join(" ")
                } else {
                    read_password(&format!("🔐 Enter password for '{}': ", args[2]))?
                };
                
                session.login_agent(args[2].to_string(), password)?;
                if let Some(agent) = session.get_agent() {
                    println!("{} Logged in as '{}'", "✓".green().bold(), agent.get_name().cyan());
                }
            }
            "switch" => {
                session.switch();
                println!("{} Agent logged out", "✓".green().bold());
            }
            _ => return Err(format!("Unknown agent command: {}", args[1]).into()),
        }
        Ok(())
    }

    pub fn handle_vault(session: &mut Session, args: &[&str]) -> Result<()> {
        if args.len() < 2 {
            return Err("Usage: vault <new|open|close> [name]".into());
        }
        
        match args[1] {
            "new" => {
                if session.get_agent().is_none() {
                    return Err("No agent logged in. Use 'agent login <name>' first.".into());
                }
                if args.len() < 3 {
                    return Err("Usage: vault new <name>".into());
                }
                
                let vault_name = args[2..].join(" ");
                println!("{} Creating vault '{}'...", "⚙".blue(), vault_name.cyan());
                session.new_vault(vault_name.clone())?;
                println!("{} Vault '{}' created", "✓".green().bold(), vault_name.cyan());
            }
            "open" => {
                if session.get_agent().is_none() {
                    return Err("No agent logged in. Use 'agent login <name>' first.".into());
                }
                if args.len() < 3 {
                    return Err("Usage: vault open <name>".into());
                }
                
                let vault_name = args[2..].join(" ");
                println!("{} Opening vault '{}'...", "⚙".blue(), vault_name.cyan());
                session.open_vault(vault_name.clone())?;
                println!("{} Vault '{}' opened", "✓".green().bold(), vault_name.cyan());
            }
            "close" => {
                if session.get_vault().is_none() {
                    return Err("No vault opened. Use 'vault open <name>' first.".into());
                }
                if let Some(vault) = session.get_vault() {
                    println!("{} Closing vault '{}'", "✓".green().bold(), vault.get_name().cyan());
                }
                session.close_vault()?;
            }
            _ => return Err(format!("Unknown vault command: {}", args[1]).into()),
        }
        Ok(())
    }

    pub fn handle_object(session: &mut Session, args: &[&str]) -> Result<()> {
        if args.len() < 2 {
            return Err("Usage: object <add|update|read|delete|list> [key] [value]".into());
        }
        
        if session.get_agent().is_none() {
            return Err("No agent logged in. Use 'agent login <name>' first.".into());
        }
        if session.get_vault().is_none() {
            return Err("No vault opened. Use 'vault open <name>' first.".into());
        }
        
        match args[1] {
            "add" => {
                if args.len() < 4 {
                    return Err("Usage: object add <key> <value>".into());
                }
                let key = args[2];
                let value = args[3..].join(" ").as_bytes().to_vec();
                session.add_object(key.to_string(), value)?;
                println!("{} Object created: {}", "✓".green().bold(), key.cyan());
            }
            "update" => {
                if args.len() < 4 {
                    return Err("Usage: object update <key> <value>".into());
                }
                let key = args[2];
                let value = args[3..].join(" ").as_bytes().to_vec();
                session.update_object(key.to_string(), value)?;
                println!("{} Object updated: {}", "✓".green().bold(), key.cyan());
            }
            "read" => {
                if args.len() < 3 {
                    return Err("Usage: object read <key>".into());
                }
                let key = args[2];
                let obj = session.read_object(key)?;
                let value = String::from_utf8(obj.value().to_vec())
                    .unwrap_or_else(|_| "<binary data>".to_string());
                println!("{} {}: {}", "📄".blue(), key.cyan().bold(), value.white());
            }
            "delete" => {
                if args.len() < 3 {
                    return Err("Usage: object delete <key>".into());
                }
                let key = args[2];
                session.delete_object(key)?;
                println!("{} Object deleted: {}", "✓".green().bold(), key.cyan());
            }
            "list" => {
                let keys = session.list_objects()?;
                if keys.is_empty() {
                    println!("{} No objects found", "📭".yellow());
                } else {
                    println!("{} Objects ({}):", "📋".blue(), keys.len().to_string().cyan().bold());
                    for key in keys {
                        println!("  {} {}", "•".green(), key.cyan());
                    }
                }
            }
            _ => return Err(format!("Unknown object command: {}", args[1]).into()),
        }
        Ok(())
    }
}
