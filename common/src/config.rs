use std::env;
use std::fmt::{Display, Formatter};
use std::path::PathBuf;

#[derive(clap::Args, Debug, Clone)]
#[command(next_help_heading = "Database")]
#[group(id = "database")]
pub struct Database {
    #[arg(id = "db-user", long, env = "DB_USER", default_value_t = Self::default().username)]
    pub username: String,
    #[arg(
        id = "db-password",
        long,
        env = "DB_PASSWORD",
        default_value_t = Self::default().password,
    )]
    pub password: String,
    #[arg(id = "db-host", long, env = "DB_HOST", default_value_t = Self::default().host)]
    pub host: String,
    #[arg(id = "db-port", long, env = "DB_PORT", default_value_t = Self::default().port)]
    pub port: u16,
    #[arg(id = "db-name", long, env = "DB_NAME", default_value_t = Self::default().name)]
    pub name: String,
}

// It would seem we could combine `default_value_t` with `flatten` on
// the relevant field in the parent parser.
//
// The clap authors disagree: https://github.com/clap-rs/clap/issues/3269
//
impl Default for Database {
    fn default() -> Self {
        const DEFAULT_PORT: u16 = 5432;
        Database {
            username: env::var("DB_USER").unwrap_or("postgres".into()),
            password: env::var("DB_PASSWORD").unwrap_or("trustify".into()),
            name: env::var("DB_NAME").unwrap_or("trustify".into()),
            host: env::var("DB_HOST").unwrap_or("localhost".into()),
            port: match env::var("DB_PORT") {
                Ok(s) => match s.parse::<u16>() {
                    Ok(p) => p,
                    Err(_) => {
                        log::warn!("DB_PORT should be an integer; using {DEFAULT_PORT}");
                        DEFAULT_PORT
                    }
                },
                _ => DEFAULT_PORT,
            },
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
pub enum StorageStrategy {
    Fs,
    S3,
}

impl Display for StorageStrategy {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageStrategy::Fs => write!(f, "fs"),
            StorageStrategy::S3 => write!(f, "s3"),
        }
    }
}

#[derive(clap::Args, Debug, Clone)]
#[command(next_help_heading = "Storage")]
#[group(id = "storage", multiple = false)]
pub struct StorageConfig {
    #[arg(
        id = "storage-strategy",
        long,
        env,
        default_value_t = StorageStrategy::Fs,
    )]
    pub storage_strategy: StorageStrategy,

    #[arg(
        id = "storage-fs-path",
        long,
        env = "DB_NAME",
        default_value = "./.trustify/storage",
        required = false,
        required_if_eq("storage-strategy", "fs")
    )]
    pub fs_path: Option<PathBuf>,
}
