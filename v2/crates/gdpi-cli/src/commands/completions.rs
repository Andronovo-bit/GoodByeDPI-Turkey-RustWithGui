//! Shell completions generator

use anyhow::Result;
use clap::{Args, CommandFactory, ValueEnum};
use clap_complete::{generate, Shell};
use std::io;

use crate::args::Args as CliArgs;

/// Completions command arguments
#[derive(Args, Debug)]
pub struct CompletionsArgs {
    /// Shell to generate completions for
    #[arg(value_enum)]
    pub shell: ShellType,
}

/// Supported shells
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ShellType {
    /// Bash shell
    Bash,
    /// Zsh shell
    Zsh,
    /// Fish shell
    Fish,
    /// PowerShell
    Powershell,
    /// Elvish shell
    Elvish,
}

impl From<ShellType> for Shell {
    fn from(shell: ShellType) -> Self {
        match shell {
            ShellType::Bash => Shell::Bash,
            ShellType::Zsh => Shell::Zsh,
            ShellType::Fish => Shell::Fish,
            ShellType::Powershell => Shell::PowerShell,
            ShellType::Elvish => Shell::Elvish,
        }
    }
}

/// Execute completions command
pub fn execute(args: CompletionsArgs) -> Result<()> {
    let mut cmd = CliArgs::command();
    let shell: Shell = args.shell.into();
    
    generate(shell, &mut cmd, "goodbyedpi", &mut io::stdout());
    
    Ok(())
}
