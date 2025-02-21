pub use sea_orm_migration::prelude::*;

#[cfg(feature = "ai")]
pub mod ai;
#[cfg(feature = "ai")]
mod ai_m0000010_create_conversation;
mod m0000010_init;
mod m0000020_add_sbom_group;
mod m0000030_perf_adv_vuln;
mod m0000040_create_license_export;
mod m0000970_alter_importer_add_heartbeat;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m0000010_init::Migration),
            Box::new(m0000970_alter_importer_add_heartbeat::Migration),
            Box::new(m0000020_add_sbom_group::Migration),
            Box::new(m0000030_perf_adv_vuln::Migration),
            Box::new(m0000040_create_license_export::Migration),
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
