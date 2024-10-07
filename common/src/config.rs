use std::env;

const DB_NAME: &str = "trustify";
const DB_USER: &str = "postgres";
const DB_PASS: &str = "trustify";
const DB_HOST: &str = "localhost";
const DB_PORT: u16 = 5432;
const DB_MAX_CONN: u32 = 75;
const DB_MIN_CONN: u32 = 25;

const ENV_DB_NAME: &str = "TRUSTD_DB_NAME";
const ENV_DB_USER: &str = "TRUSTD_DB_USER";
const ENV_DB_PASS: &str = "TRUSTD_DB_PASSWORD";
const ENV_DB_HOST: &str = "TRUSTD_DB_HOST";
const ENV_DB_PORT: &str = "TRUSTD_DB_PORT";
const ENV_DB_MAX_CONN: &str = "TRUSTD_DB_MAX_CONN";
const ENV_DB_MIN_CONN: &str = "TRUSTD_DB_MIN_CONN";

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
