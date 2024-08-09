use crate::sea_orm::prelude::Uuid;
use sea_orm_migration::prelude::*;

const NAMESPACE: Uuid = Uuid::from_bytes([
    0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x41, 0x18, 0xa1, 0x38, 0xb8, 0x9f, 0x19, 0x35, 0xe0, 0xa7,
]);

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(License::Table)
                    .col(ColumnDef::new(License::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(License::Text).string().not_null())
                    .col(ColumnDef::new(License::SpdxLicenses).array(ColumnType::Text))
                    .col(ColumnDef::new(License::SpdxLicenseExceptions).array(ColumnType::Text))
                    .to_owned(),
            )
            .await?;

        let db = manager.get_connection();
        let license_list = include_bytes!("m0000543_create_license/licenses.json");
        if let Ok(license_json) = serde_json::from_slice::<'_, serde_json::Value>(license_list) {
            if let Some(licenses) = license_json.get("licenses") {
                if let Some(licenses) = licenses.as_array() {
                    for license in licenses {
                        let license_id = license.get("licenseId");
                        let name = license.get("name");

                        if let (Some(license_id), Some(name)) = (license_id, name) {
                            let license_id = license_id.as_str();
                            let name = name.as_str();

                            if let (Some(license_id), Some(name)) = (license_id, name) {
                                insert(db, license_id, name).await?;
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(License::Table).to_owned())
            .await
    }
}

async fn insert(
    db: &SchemaManagerConnection<'_>,
    identifier: &str,
    name: &str,
) -> Result<(), DbErr> {
    // UUID based upon a hash of the lowercase de-ref'd license.
    let uuid = Uuid::new_v5(&NAMESPACE, name.to_lowercase().as_bytes());

    db.execute(
        db.get_database_backend().build(
            Query::insert()
                .into_table(License::Table)
                .columns([License::Id, License::Text, License::SpdxLicenses])
                .on_conflict(OnConflict::columns([License::Id]).do_nothing().to_owned())
                .values([
                    SimpleExpr::Value(Value::Uuid(Some(Box::new(uuid)))),
                    SimpleExpr::Value(Value::String(Some(Box::new(name.to_string())))),
                    SimpleExpr::Value(Value::Array(
                        ArrayType::String,
                        Some(Box::new(vec![Value::String(Some(Box::new(
                            identifier.to_string(),
                        )))])),
                    )),
                ])
                .map_err(|e| DbErr::Custom(e.to_string()))?,
        ),
    )
    .await?;
    Ok(())
}

#[derive(DeriveIden)]
enum License {
    Table,
    Id,
    Text,
    SpdxLicenses,
    SpdxLicenseExceptions,
}
