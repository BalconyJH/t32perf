mod app;
mod attestation;
mod capture_config;
mod cli;
mod controller;
mod controller_capture_config;
mod controller_driver;
mod controller_journal;
mod controller_qualification;
mod controller_recovery;
mod fixture;
mod mcp;
mod normalize;
mod operations;
mod perf_run;
mod pipeline;
mod receipt;
mod sampling;
mod stack;
mod summary;
mod target_adapter_provisioning;

use std::{io::Write as _, process::ExitCode};

use clap::{Parser as _, error::ErrorKind};
use cli::{Cli, Command};
use serde_json::json;
use tracing_subscriber::EnvFilter;

fn main() -> ExitCode {
    initialize_logging();
    let arguments = std::env::args_os().collect::<Vec<_>>();
    let json_requested = arguments.iter().any(|argument| argument == "--json");
    let cli = match Cli::try_parse_from(arguments) {
        Ok(cli) => cli,
        Err(error) => return render_clap_error(error, json_requested),
    };

    let json_mode = cli.json;
    let mcp_mode = matches!(&cli.command, Command::Mcp);
    let command_name = cli.command.name();
    tracing::info!(command = command_name, "command_started");
    match app::execute(cli) {
        Ok(outcome) => {
            tracing::info!(
                command = outcome.command,
                exit_code = outcome.exit_code,
                "command_completed"
            );
            if mcp_mode {
                return ExitCode::from(outcome.exit_code);
            }
            if let Err(error) = render_success(json_mode, &outcome) {
                eprintln!("failed to write command result: {error}");
                return ExitCode::from(1);
            }
            ExitCode::from(outcome.exit_code)
        }
        Err(error) => {
            tracing::warn!(
                command = command_name,
                error_code = error.code,
                exit_code = error.exit_code,
                "command_failed"
            );
            if mcp_mode {
                eprintln!(
                    "{}: MCP service failed; inspect trusted local configuration and durable evidence",
                    error.code
                );
            } else if let Err(render_error) = render_failure(json_mode, &error) {
                eprintln!("failed to write command error: {render_error}");
            }
            ExitCode::from(error.exit_code)
        }
    }
}

fn initialize_logging() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    let json =
        std::env::var("T32PERF_LOG_FORMAT").is_ok_and(|value| value.eq_ignore_ascii_case("json"));
    if json {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .with_target(false)
            .json()
            .flatten_event(true)
            .try_init();
    } else {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .with_target(false)
            .try_init();
    }
}

fn render_success(json_mode: bool, outcome: &app::CommandOutcome) -> std::io::Result<()> {
    let mut stdout = std::io::stdout().lock();
    let document = json!({
        "ok": true,
        "command": outcome.command,
        "result": outcome.result,
    });
    if json_mode {
        serde_json::to_writer(&mut stdout, &document)?;
    } else {
        serde_json::to_writer_pretty(&mut stdout, &document)?;
    }
    stdout.write_all(b"\n")
}

fn render_failure(json_mode: bool, error: &app::AppError) -> std::io::Result<()> {
    if json_mode {
        let mut stdout = std::io::stdout().lock();
        serde_json::to_writer(
            &mut stdout,
            &json!({
                "ok": false,
                "error": {
                    "code": error.code,
                    "message": error.message,
                    "details": error.details,
                }
            }),
        )?;
        stdout.write_all(b"\n")
    } else {
        eprintln!("{}: {}", error.code, error.message);
        Ok(())
    }
}

fn render_clap_error(error: clap::Error, json_requested: bool) -> ExitCode {
    match error.kind() {
        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion if json_requested => {
            let mut stdout = std::io::stdout().lock();
            let _ = serde_json::to_writer(
                &mut stdout,
                &json!({
                    "ok": true,
                    "command": "help",
                    "result": {"text": error.to_string()}
                }),
            );
            let _ = stdout.write_all(b"\n");
            ExitCode::SUCCESS
        }
        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => {
            let _ = error.print();
            ExitCode::SUCCESS
        }
        _ if json_requested => {
            let message = error.to_string();
            let mut stdout = std::io::stdout().lock();
            let _ = serde_json::to_writer(
                &mut stdout,
                &json!({
                    "ok": false,
                    "error": {
                        "code": "INVALID_ARGUMENT",
                        "message": message.trim(),
                        "details": {}
                    }
                }),
            );
            let _ = stdout.write_all(b"\n");
            ExitCode::from(1)
        }
        _ => {
            let _ = error.print();
            ExitCode::from(1)
        }
    }
}
