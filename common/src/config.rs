use std::env;
use std::fmt::{Display, Formatter};
use std::path::PathBuf;

const DB_NAME: &str = "trustify";
const DB_USER: &str = "postgres";
const DB_PASS: &str = "trustify";
const DB_HOST: &str = "localhost";
const DB_PORT: u16 = 5432;
const DB_MAX_CONN: u32 = 75;
const DB_MIN_CONN: u32 = 25;

const ENV_DB_NAME: &str = "DB_NAME";
const ENV_DB_USER: &str = "DB_USER";
const ENV_DB_PASS: &str = "DB_PASSWORD";
const ENV_DB_HOST: &str = "DB_HOST";
const ENV_DB_PORT: &str = "DB_PORT";
const ENV_DB_MAX_CONN: &str = "TRUSTD_MAX_CONN";
const ENV_DB_MIN_CONN: &str = "TRUSTD_MIN_CONN";

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
    #[arg(id = "db-max-conn", long, env = ENV_DB_MAX_CONN, default_value_t = DB_MAX_CONN.into())]
    pub max_conn: u32,
    #[arg(id = "db-min-conn", long, env = ENV_DB_MIN_CONN, default_value_t = DB_MIN_CONN.into())]
    pub min_conn: u32,
}

impl Database {
    pub fn from_env() -> Result<Database, anyhow::Error> {
        Ok(Database {
            username: env::var(ENV_DB_USER).unwrap_or(DB_USER.into()),
            password: env::var(ENV_DB_PASS).unwrap_or(DB_PASS.into()),
            name: env::var(ENV_DB_NAME).unwrap_or(DB_NAME.into()),
            host: env::var(ENV_DB_HOST).unwrap_or(DB_HOST.into()),
            port: match env::var(ENV_DB_PORT) {
                Ok(s) => s.parse::<u16>()?,
                _ => DB_PORT,
            },
            max_conn: match env::var(ENV_DB_MAX_CONN) {
                Ok(s) => s.parse::<u32>()?,
                _ => DB_MAX_CONN,
            },
            min_conn: match env::var(ENV_DB_MIN_CONN) {
                Ok(s) => s.parse::<u32>()?,
                _ => DB_MIN_CONN,
            },
        })
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
pub struct StorageConfig {
    #[arg(
        id = "storage-strategy",
        long, env = "STORAGE_STRATEGY",
	requires_ifs([("s3", "bucket"), ("s3", "region"), ("s3", "access_key"), ("s3", "secret_key")]),
	requires_if("fs", "storage-fs-path"),
        default_value_t = StorageStrategy::Fs,
    )]
    pub storage_strategy: StorageStrategy,

    #[arg(
        id = "storage-fs-path",
        long,
        env = "STORAGE_FS_PATH",
        default_value = "./.trustify/storage",
        conflicts_with = "s3"
    )]
    pub fs_path: Option<PathBuf>,

    #[command(flatten)]
    pub s3_config: S3Config,
}

#[derive(Clone, Debug, Default, clap::Args)]
#[command(next_help_heading = "S3")]
#[group(id = "s3", requires = "storage-strategy")]
pub struct S3Config {
    /// S3 bucket name
    #[arg(env = "TRUSTD_S3_BUCKET", long = "s3-bucket")]
    pub bucket: Option<String>,

    /// S3 region name
    #[arg(env = "TRUSTD_S3_REGION", long = "s3-region")]
    pub region: Option<String>,

    /// S3 access key
    #[arg(env = "TRUSTD_S3_ACCESS_KEY", long = "s3-access-key")]
    pub access_key: Option<String>,

    /// S3 secret key
    #[arg(env = "TRUSTD_S3_SECRET_KEY", long = "s3-secret-key")]
    pub secret_key: Option<String>,
}
