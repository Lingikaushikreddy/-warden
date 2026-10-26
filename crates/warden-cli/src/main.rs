use clap::Parser;
use std::process::ExitCode;

fn main() -> ExitCode {
    ExitCode::from(warden_cli::run(warden_cli::Cli::parse()))
}
