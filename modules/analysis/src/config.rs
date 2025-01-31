use bytesize::ByteSize;
use trustify_common::model::BinaryByteSize;

#[derive(clap::Args, Debug, Clone)]
pub struct AnalysisConfig {
    #[arg(
        id = "max-cache-size",
        long,
        env = "TRUSTD_MAX_CACHE_SIZE",
        default_value = "200 MiB",
        help = "Maximum size of the graph cache."
    )]
    pub max_cache_size: BinaryByteSize,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            max_cache_size: BinaryByteSize(ByteSize::mib(200)),
        }
    }
}
