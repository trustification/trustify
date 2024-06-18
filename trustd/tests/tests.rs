use regex::Regex;
use std::process::Stdio;
use std::{env, path::Path};
use std::{fs, thread, time};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

#[tokio::test]
async fn test_embedded_ui() {
    // This test creates a 'trustify/trustd/.trustify' directory, so we need to remove it.
    let trustify_dir = Path::new(".trustify");
    if trustify_dir.exists() {
        fs::remove_dir_all(trustify_dir).expect("Failed to remove '.trustify'");
    }

    // Starts trustd pm-mode to access the database later,
    // avoiding running postgres in a container.
    let mut pm_mode = Command::new(env!("CARGO_BIN_EXE_trustd"))
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to start trustd pm-mode.");

    // https://docs.rs/tokio/latest/tokio/process/index.html
    let stdout = pm_mode
        .stdout
        .take()
        .expect("pm_mode did not have a handle to stdout");

    let mut reader = BufReader::new(stdout).lines();

    let mut pg_port = String::new();

    let pg_line = "connect to postgres".to_string();
    let started = "Tokio runtime found".to_string();

    // Regex to find the pg port in this line:
    // INFO trustify_common::db: connect to postgres://postgres:trustify@localhost:1234/trustify
    let r = Regex::new(r"localhost:(\d+)").unwrap();

    while let Some(line) = reader.next_line().await.unwrap() {
        if line.contains(&pg_line) {
            let caps = r.captures(&line).unwrap();
            // The pg port
            if pg_port.is_empty() {
                pg_port.push_str(&caps[1]);
            }
        }

        if line.contains(&started) {
            // Start trustd devmode with different http port 8123.
            let mut trustd = Command::new(env!("CARGO_BIN_EXE_trustd"))
                .arg("api")
                .arg("--devmode")
                .arg("--auth-disabled")
                .arg("--http-server-bind-port")
                .arg("8123")
                .arg("--db-user")
                .arg("postgres")
                .arg("--db-password")
                .arg("trustify")
                .arg("--db-port")
                .arg(&pg_port)
                .stdout(Stdio::piped())
                .spawn()
                .expect("Failed to start trustd devmode.");

            // Wait for availability
            let seconds = time::Duration::from_secs(15);
            thread::sleep(seconds);

            let res = reqwest::get("http://localhost:8123/sboms").await.unwrap();
            assert_eq!(200, res.status().as_u16());
            let res = reqwest::get("http://localhost:8123/packages")
                .await
                .unwrap();
            assert_eq!(200, res.status().as_u16());
            let res = reqwest::get("http://localhost:8123/vulnerabilities")
                .await
                .unwrap();
            assert_eq!(200, res.status().as_u16());
            let res = reqwest::get("http://localhost:8123/importers")
                .await
                .unwrap();
            assert_eq!(200, res.status().as_u16());
            let res = reqwest::get("http://localhost:8123/advisories")
                .await
                .unwrap();
            assert_eq!(200, res.status().as_u16());

            let _ = trustd.kill().await;

            let out = trustd.wait_with_output().await.unwrap();
            let stdout = String::from_utf8_lossy(&out.stdout);

            assert!(stdout.contains("GET /sboms"));
            assert!(stdout.contains("GET /packages"));
            assert!(stdout.contains("GET /vulnerabilities"));
            assert!(stdout.contains("GET /importers"));
            assert!(stdout.contains("GET /advisories"));
            let _ = pm_mode.kill().await;
        }
    }
}
