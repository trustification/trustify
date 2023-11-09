#[derive(clap::Args, Debug)]
pub struct Database {
    #[arg(id = "db-user", long, env)]
    pub username: String,
    #[arg(id = "db-password", long, env)]
    pub password: String,
    #[arg(id = "db-host", long, env, default_value = "localhost")]
    pub host: String,
    #[arg(id = "db-port", long, env, default_value_t = 5432)]
    pub port: u16,
    #[arg(id = "db-name", long, env, default_value = "huevos")]
    pub name: String,
}
