//! CLI commands

pub mod completions;
pub mod config;
pub mod run;
pub mod service;
pub mod test;

use clap::Subcommand;

/// CLI commands
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Run the DPI bypass (main command)
    Run(run::RunArgs),

    /// Configuration management
    Config(config::ConfigArgs),

    /// Test connectivity
    Test(test::TestArgs),

    /// Windows service management
    Service(service::ServiceArgs),

    /// Generate shell completions
    Completions(completions::CompletionsArgs),
}
