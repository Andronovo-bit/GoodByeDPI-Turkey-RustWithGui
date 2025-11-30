//! CLI commands

pub mod completions;
pub mod config;
pub mod driver;
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
    
    /// WinDivert driver management
    Driver {
        #[command(subcommand)]
        command: driver::DriverCommands,
    },

    /// Generate shell completions
    Completions(completions::CompletionsArgs),
}
