pub use sea_orm_migration::prelude::*;

mod m0000010_init;
mod m0000970_alter_importer_add_heartbeat;

#[cfg(feature = "ai")]
pub mod ai;
#[cfg(feature = "ai")]
mod ai_m0000010_create_conversation;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m0000010_init::Migration),
            Box::new(m0000970_alter_importer_add_heartbeat::Migration),
        ]
    }
}

pub struct Now;

impl Iden for Now {
    fn unquoted(&self, s: &mut dyn Write) {
        write!(s, "now").unwrap()
    }
}

pub struct UuidV4;

impl Iden for UuidV4 {
    fn unquoted(&self, s: &mut dyn Write) {
        write!(s, "gen_random_uuid").unwrap()
    }
}
