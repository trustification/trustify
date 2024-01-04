#[derive(clap::Args, Debug, Clone)]
pub struct Database {
    #[arg(id = "db-user", long, env = "DB_USER")]
    pub username: String,
    #[arg(id = "db-password", long, env = "DB_PASSWORD")]
    pub password: String,
    #[arg(id = "db-host", long, env = "DB_HOST", default_value = "localhost")]
    pub host: String,
    #[arg(id = "db-port", long, env = "DB_PORT", default_value_t = 5432)]
    pub port: u16,
    #[arg(id = "db-name", long, env = "DB_NAME", default_value = "huevos")]
    pub name: String,
}
