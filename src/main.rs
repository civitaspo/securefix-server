use anyhow::Result;
use clap::{Parser, Subcommand};
use securefix::{api, event, output, policy, workflow};

mod approval;
#[cfg(test)]
mod fixtures;
mod merge;
mod policy_check;
mod release;
mod request;
mod runtime;
mod securefix_gate;
mod settings;
#[cfg(test)]
mod workflow_tests;

#[derive(Parser)]
#[command(
    name = "securefix",
    version,
    about = "Scoped OSS automation for civitaspo repositories"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    #[command(about = "Validate repository capabilities")]
    Policy {
        #[command(subcommand)]
        command: policy::Command,
    },
    #[command(about = "Capture and dispatch approval or merge requests")]
    Request {
        #[command(subcommand)]
        command: request::Command,
    },
    #[command(about = "Review authorized pull requests")]
    Approve {
        #[command(subcommand)]
        command: approval::Command,
    },
    #[command(about = "Wait for checks and squash accepted heads")]
    Merge {
        #[command(subcommand)]
        command: merge::Command,
    },
    #[command(about = "Prepare and publish authorized releases")]
    Release {
        #[command(subcommand)]
        command: release::Command,
    },
    #[command(about = "Publish the SHA-keyed trusted runtime archive")]
    Runtime {
        #[command(subcommand)]
        command: runtime::Command,
    },
    #[command(about = "Reconcile repository settings and activate merge controls")]
    Settings {
        #[command(subcommand)]
        command: settings::Command,
    },
    #[command(about = "Apply signed CI fixes from a verified source run")]
    Securefix {
        #[command(subcommand)]
        command: securefix_gate::Command,
    },
    #[command(about = "Publish head-specific policy checks")]
    Check {
        #[command(subcommand)]
        command: policy_check::Command,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Policy { command } => policy::run(command),
        Command::Request { command } => request::run(command),
        Command::Approve { command } => approval::run(command),
        Command::Merge { command } => merge::run(command),
        Command::Release { command } => release::run(command),
        Command::Runtime { command } => runtime::run(command),
        Command::Settings { command } => settings::run(command),
        Command::Securefix { command } => securefix_gate::run(command),
        Command::Check { command } => policy_check::run(command),
    }
}
