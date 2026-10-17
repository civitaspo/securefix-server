use anyhow::Result;
use clap::Parser;

mod bootstrap;

#[cfg(test)]
use securefix::{api, config, control, hex_encode};
#[cfg(test)]
mod fixtures;

#[derive(Parser)]
#[command(name = "securefix-bootstrap", version)]
struct Cli {
    #[command(subcommand)]
    command: bootstrap::Command,
}

fn main() -> Result<()> {
    bootstrap::run(Cli::parse().command)
}
