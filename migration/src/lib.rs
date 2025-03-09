pub use sea_orm_migration::prelude::*;

mod m0000010_init;
mod m0000020_add_sbom_group;
mod m0000030_create_licensing_infos;
mod m0000040_sbom_package_license;
mod m0000970_alter_importer_add_heartbeat;

#[cfg(feature = "ai")]
pub mod ai;
#[cfg(feature = "ai")]
mod ai_m0000010_create_conversation;
mod m0000050_drop_purl_license_assertion;
mod m0000060_drop_cpe_license_assertion;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m0000010_init::Migration),
            Box::new(m0000030_create_licensing_infos::Migration),
            Box::new(m0000040_sbom_package_license::Migration),
            Box::new(m0000970_alter_importer_add_heartbeat::Migration),
            Box::new(m0000020_add_sbom_group::Migration),
            Box::new(m0000050_drop_purl_license_assertion::Migration),
            Box::new(m0000060_drop_cpe_license_assertion::Migration),
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
