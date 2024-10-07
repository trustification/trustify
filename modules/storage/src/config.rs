use crate::service::Compression;
use std::fmt::{Display, Formatter};
use std::path::PathBuf;

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
        long,
        env = "TRUSTD_STORAGE_STRATEGY",
        requires_ifs([("s3", "bucket"), ("s3", "region"), ("s3", "access_key"), ("s3", "secret_key")]),
        requires_if("fs", "storage-fs-path"),
        default_value_t = StorageStrategy::Fs,
    )]
    pub storage_strategy: StorageStrategy,

    #[arg(
        id = "storage-fs-path",
        long,
        env = "TRUSTD_STORAGE_FS_PATH",
        default_value = "./.trustify/storage",
        conflicts_with = "s3"
    )]
    pub fs_path: Option<PathBuf>,

    #[arg(
        id = "storage-compression",
        long,
        env = "TRUSTD_STORAGE_COMPRESSION",
        default_value_t = Compression::None,
        conflicts_with = "s3"
    )]
    pub compression: Compression,

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
