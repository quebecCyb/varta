use std::io::{self, Write};
use colored::Colorize;
use rpassword::read_password;
use crate::session::Session;
use super::handlers::CommandHandlers;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub struct Cli {
    session: Session,
}

impl Cli {
    pub fn new() -> Self {
        Self {
            session: Session::new(),
        }
    }

    pub fn run(&mut self) {
        self.print_banner();
        
        loop {
            print!("{}", self.get_prompt());
            io::stdout().flush().unwrap();

            let input = match self.read_input() {
                Ok(input) => input,
                Err(e) => {
                    println!("{} Failed to read input: {}", "✗".red().bold(), e);
                    continue;
                }
            };
            
            if input.is_empty() {
                continue;
            }

            let args: Vec<&str> = self.get_args(&input);
            
            if args.is_empty() {
                continue;
            }

            let result = match args[0] {
                "exit" => {
                    println!("{} {}", "👋", "Goodbye!".cyan().bold());
                    break;
                }
                "help" => {
                    self.print_help();
                    Ok(())
                }
                "agent" => {
                    let read_pwd = |prompt: &str| -> io::Result<String> {
                        print!("{}", prompt);
                        io::stdout().flush()?;
                        read_password()
                    };
                    CommandHandlers::handle_agent(&mut self.session, &args, read_pwd)
                }
                "vault" => CommandHandlers::handle_vault(&mut self.session, &args),
                "object" => CommandHandlers::handle_object(&mut self.session, &args),
                _ => {
                    println!("{} Unknown command: '{}'. Type {} for available commands.", 
                    "✗".red().bold(), 
                    args[0].yellow(), 
                    "help".green().bold());
                    Ok(())
                }
            };

            if let Err(e) = result {
                println!("{} {}", "✗".red().bold(), e.to_string().yellow());
            }
        }
    }

    // IO Helpers

    fn read_input(&self) -> io::Result<String> {
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        Ok(input.trim().to_string())
    }

    fn read_password_secure(&self, prompt: &str) -> io::Result<String> {
        print!("{}", prompt);
        io::stdout().flush()?;
        read_password()
    }

    fn get_args<'a>(&self, input: &'a str) -> Vec<&'a str> {
        input.split_whitespace().collect()
    }

    fn require_args(&self, args: &[&str], min: usize, usage: &str) -> Result<()> {
        if args.len() < min {
            println!("Usage: {}", usage);
            return Err("Insufficient arguments".into());
        }
        Ok(())
    }

    fn get_prompt(&self) -> String {
        let prompt = match (self.session.get_agent(), self.session.get_vault()) {
            (Some(agent), Some(vault)) => format!("{}:{} > ", agent.get_name(), vault.get_name()),
            (Some(agent), None) => format!("{} > ", agent.get_name()),
            (None, _) => "guest > ".to_string(),
        };
        prompt
    }

    fn require_agent(&self) -> Result<()> {
        if self.session.get_agent().is_none() {
            return Err("No agent logged in. Use 'agent login <name>' first.".into());
        }
        Ok(())
    }

    fn require_vault(&self) -> Result<()> {
        self.require_agent()?;
        if self.session.get_vault().is_none() {
            return Err("No vault opened. Use 'vault open <name>' first.".into());
        }
        Ok(())
    }

    fn print_banner(&self) {
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
    }

    fn print_help(&self) {
        println!("Available commands:");
        println!("\nAgent commands:");
        println!("  agent new <name>     - Create a new agent (password will be prompted)");
        println!("  agent login <name>   - Login as an agent (password will be prompted)");
        println!("  agent switch         - Switch to another agent");
        println!("\nVault commands:");
        println!("  vault new <name>    - Create a new vault");
        println!("  vault open <name>   - Open a vault");
        println!("  vault close         - Close current vault");
        println!("\nObject commands:");
        println!("  object add <key> <value>     - Create new object");
        println!("  object update <key> <value>  - Update existing object");
        println!("  object read <key>            - Read object value");
        println!("  object delete <key>          - Delete object");
        println!("  object list                  - List all object keys");
        println!("\n  help                - Show this help");
        println!("  exit                - Exit the application");
    }

}
