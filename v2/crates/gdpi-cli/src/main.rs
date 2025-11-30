//! GoodbyeDPI-Turkey CLI
//!
//! Command-line interface for the DPI bypass tool.

mod args;
mod commands;
mod logging;

use anyhow::Result;
use clap::Parser;
use tracing::error;

use args::Args;

fn main() -> Result<()> {
    // Parse command line arguments
    let args = Args::parse();

    // Initialize logging
    logging::init(&args)?;

    // Print banner
    print_banner();

    // Run the main logic
    let result = run(args);

    if let Err(ref e) = result {
        error!("Fatal error: {:#}", e);
    }

    result
}

fn run(args: Args) -> Result<()> {
    match args.command {
        Some(commands::Command::Run(run_args)) => {
            commands::run::execute(run_args)
        }
        Some(commands::Command::Config(config_args)) => {
            commands::config::execute(config_args)
        }
        Some(commands::Command::Test(test_args)) => {
            commands::test::execute(test_args)
        }
        Some(commands::Command::Service(service_args)) => {
            commands::service::execute(service_args)
        }
        Some(commands::Command::Completions(comp_args)) => {
            commands::completions::execute(comp_args)
        }
        None => {
            // Default: run with legacy mode or config file
            let run_args = commands::run::RunArgs::from_legacy(&args);
            commands::run::execute(run_args)
        }
    }
}

fn print_banner() {
    use colored::Colorize;

    println!();
    println!("{}", "╔═══════════════════════════════════════════════════════╗".cyan());
    println!("{}", "║                                                       ║".cyan());
    println!("{}{}{}",
        "║  ".cyan(),
        "GoodbyeDPI Turkey v2.0".green().bold(),
        "                             ║".cyan()
    );
    println!("{}{}{}",
        "║  ".cyan(),
        "DPI bypass tool for Turkey".white(),
        "                      ║".cyan()
    );
    println!("{}", "║                                                       ║".cyan());
    println!("{}", "╚═══════════════════════════════════════════════════════╝".cyan());
    println!();
}
