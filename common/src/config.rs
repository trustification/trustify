use std::fmt::{Display, Formatter};

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
pub enum DbStrategy {
    External,
    Managed,
}

impl Display for DbStrategy {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            DbStrategy::External => {
                write!(f, "external")
            }
            DbStrategy::Managed => {
                write!(f, "managed")
            }
        }
    }
}

#[derive(clap::Args, Debug, Clone)]
#[command(next_help_heading = "Database")]
#[group(id = "database")]
pub struct Database {
    #[arg(
        id = "db-strategy",
        long,
        env,
        default_value_t = DbStrategy::Managed,
    )]
    pub db_strategy: DbStrategy,
    #[arg(
        id = "db-user",
        long,
        env = "DB_USER",
        default_value = "trustify",
        group = "external-db",
        required = false,
        required_if_eq("db-strategy", "external")
    )]
    pub username: String,
    #[arg(
        id = "db-password",
        long,
        env = "DB_PASSWORD",
        default_value = "trustify",
        group = "external-db",
        required = false,
        required_if_eq("db-strategy", "external")
    )]
    pub password: String,
    #[arg(
        id = "db-host",
        long,
        env = "DB_HOST",
        default_value = "localhost",
        group = "external-db"
    )]
    pub host: String,
    #[arg(
        id = "db-port",
        long,
        env = "DB_PORT",
        default_value_t = 5432,
        group = "external-db"
    )]
    pub port: u16,
    #[arg(
        id = "db-name",
        long,
        env = "DB_NAME",
        default_value = "trustify",
        group = "external-db"
    )]
    pub name: String,
}
