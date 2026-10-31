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

use cli::Cli;
use config::{Config, CONFIG};

fn main() {
    CONFIG
        .set(Config::load())
        .expect("Already initialized");
    let mut cli = Cli::new();
    cli.run();
}