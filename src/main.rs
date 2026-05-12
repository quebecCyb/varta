mod config;
mod agent;
mod os;
mod crypto;
mod session;
mod vault_object;
mod device;
mod operation;
mod vault;
mod cli;
mod storage;
mod backup;

use cli::Cli;

fn main() {
    let mut cli = Cli::new();
    cli.run();
}