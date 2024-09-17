#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct Config {
    /// An upload limit in bytes. Zero meaning "unlimited".
    pub upload_limit: usize,
}
