use pretty_assertions::assert_eq;
use std::env;
use tokio::process::Command;

const TRUSTIFY_CLI_HELP: &str = "huevos

Usage: trustify-cli <COMMAND>

Commands:
  importer  
  server    Run the API server
  help      Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
";

#[tokio::test]
async fn trustify_cli_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_trustify-cli"))
        .output()
        .await
        .expect("");

    let output_str = String::from_utf8_lossy(&output.stderr).to_string();
    assert_eq!(TRUSTIFY_CLI_HELP, output_str);
}
