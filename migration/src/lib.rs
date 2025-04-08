pub use sea_orm_migration::prelude::*;

#[cfg(feature = "ai")]
pub mod ai;
#[cfg(feature = "ai")]
mod ai_m0000010_create_conversation;
mod m0000010_init;
mod m0000020_add_sbom_group;
mod m0000030_perf_adv_vuln;
mod m0000040_create_license_export;
mod m0000050_perf_adv_vuln2;
mod m0000060_perf_adv_vuln3;
mod m0000070_perf_adv_vuln4;
mod m0000080_get_purl_refactor;
mod m0000090_release_perf;
mod m0000100_perf_adv_vuln5;
mod m0000970_alter_importer_add_heartbeat;
mod m0000980_get_purl_fix;
mod m0000990_sbom_add_suppliers;
mod m0001000_sbom_non_null_suppliers;
mod m0001010_alter_mavenver_cmp;
mod m0001020_alter_pythonver_cmp;
mod m0001030_perf_adv_gin_index;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m0000010_init::Migration),
            Box::new(m0000020_add_sbom_group::Migration),
            Box::new(m0000030_perf_adv_vuln::Migration),
            Box::new(m0000040_create_license_export::Migration),
            Box::new(m0000050_perf_adv_vuln2::Migration),
            Box::new(m0000060_perf_adv_vuln3::Migration),
            Box::new(m0000070_perf_adv_vuln4::Migration),
            Box::new(m0000080_get_purl_refactor::Migration),
            Box::new(m0000090_release_perf::Migration),
            Box::new(m0000100_perf_adv_vuln5::Migration),
            Box::new(m0000970_alter_importer_add_heartbeat::Migration),
            Box::new(m0000980_get_purl_fix::Migration),
            Box::new(m0000990_sbom_add_suppliers::Migration),
            Box::new(m0001000_sbom_non_null_suppliers::Migration),
            Box::new(m0001010_alter_mavenver_cmp::Migration),
            Box::new(m0001020_alter_pythonver_cmp::Migration),
            Box::new(m0001030_perf_adv_gin_index::Migration),
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
