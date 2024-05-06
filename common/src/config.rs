use std::env;
use std::fmt::{Display, Formatter};
use std::path::PathBuf;

const DB_NAME: &str = "trustify";
const DB_USER: &str = "postgres";
const DB_PASS: &str = "trustify";
const DB_HOST: &str = "localhost";
const DB_PORT: u16 = 5432;

const ENV_DB_NAME: &str = "DB_NAME";
const ENV_DB_USER: &str = "DB_USER";
const ENV_DB_PASS: &str = "DB_PASSWORD";
const ENV_DB_HOST: &str = "DB_HOST";
const ENV_DB_PORT: &str = "DB_PORT";

#[derive(clap::Args, Debug, Clone)]
#[command(next_help_heading = "Database")]
#[group(id = "database")]
pub struct Database {
    #[arg(id = "db-user", long, env = ENV_DB_USER, default_value_t = DB_USER.into())]
    pub username: String,
    #[arg(
        id = "db-password",
        long,
        env = ENV_DB_PASS,
        default_value_t = DB_PASS.into(),
    )]
    pub password: String,
    #[arg(id = "db-host", long, env = ENV_DB_HOST, default_value_t = DB_HOST.into())]
    pub host: String,
    #[arg(id = "db-port", long, env = ENV_DB_PORT, default_value_t = DB_PORT.into())]
    pub port: u16,
    #[arg(id = "db-name", long, env = ENV_DB_NAME, default_value_t = DB_NAME.into())]
    pub name: String,
}

impl Default for Database {
    fn default() -> Self {
        Database {
            username: env::var(ENV_DB_USER).unwrap_or(DB_USER.into()),
            password: env::var(ENV_DB_PASS).unwrap_or(DB_PASS.into()),
            name: env::var(ENV_DB_NAME).unwrap_or(DB_NAME.into()),
            host: env::var(ENV_DB_HOST).unwrap_or(DB_HOST.into()),
            port: match env::var(ENV_DB_PORT) {
                Ok(s) => match s.parse::<u16>() {
                    Ok(p) => p,
                    Err(_) => {
                        log::warn!("{ENV_DB_PORT} should be an integer; using {DB_PORT}");
                        DB_PORT
                    }
                },
                _ => DB_PORT,
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
