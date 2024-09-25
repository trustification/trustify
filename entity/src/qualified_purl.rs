use sea_orm::{entity::prelude::*, FromJsonQueryResult, FromQueryResult};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use trustify_common::purl::Purl;

// TODO: some day we might 'collapse' all the purl structs to this one, that day is not today.
//
// Instead of using composition or directly relating to any existing purl struct we will implement
// to & from impl and in places we may invalidate DRY principle by copying across required code blocks.

#[derive(Debug, Clone, PartialEq, Eq, Hash, FromJsonQueryResult)]
pub struct CanonicalPurl {
    pub ty: String,
    pub namespace: Option<String>,
    pub name: String,
    pub version: Option<String>,
    pub qualifiers: BTreeMap<String, String>,
}

// inspired by common/src/purl.rs#135 but avoids any temporary strings for speed
impl Display for CanonicalPurl {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "pkg://{}", self.ty)?;

        if let Some(ns) = &self.namespace {
            write!(f, "/{}", ns)?;
        }

        write!(f, "/{}", self.name)?;

        if let Some(version) = &self.version {
            write!(f, "@{}", version)?;
        }

        if !self.qualifiers.is_empty() {
            write!(f, "?")?;
            for (i, (k, v)) in self.qualifiers.iter().enumerate() {
                if i > 0 {
                    write!(f, "&")?;
                }
                write!(f, "{}={}", k, v)?;
            }
        }

        Ok(())
    }
}

impl Serialize for CanonicalPurl {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Start a new struct serialization
        let mut state = serializer.serialize_struct("CanonicalPurl", 5)?;

        // Serialize each field
        state.serialize_field("ty", &self.ty)?;
        state.serialize_field("namespace", &self.namespace)?;
        state.serialize_field("name", &self.name)?;
        state.serialize_field("version", &self.version)?;
        state.serialize_field("qualifiers", &self.qualifiers)?;

        // End the struct serialization
        state.end()
    }
}

impl<'de> Deserialize<'de> for CanonicalPurl {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            ty: String,
            namespace: Option<String>,
            name: String,
            version: Option<String>,
            qualifiers: BTreeMap<String, String>,
        }

        let helper = Helper::deserialize(deserializer)?;
        Ok(CanonicalPurl {
            ty: helper.ty,
            namespace: helper.namespace,
            name: helper.name,
            version: helper.version,
            qualifiers: helper.qualifiers,
        })
    }
}

impl From<Purl> for CanonicalPurl {
    fn from(purl: Purl) -> Self {
        CanonicalPurl {
            ty: purl.ty,
            namespace: purl.namespace,
            name: purl.name,
            version: purl.version,
            qualifiers: purl.qualifiers,
        }
    }
}
impl From<CanonicalPurl> for Purl {
    fn from(purl: CanonicalPurl) -> Self {
        Purl {
            ty: purl.ty,
            namespace: purl.namespace,
            name: purl.name,
            version: purl.version,
            qualifiers: purl.qualifiers,
        }
    }
}

impl From<CanonicalPurl> for Value {
    fn from(canonical_purl: CanonicalPurl) -> Self {
        json!({
            "ty": canonical_purl.ty,
            "namespace": canonical_purl.namespace,
            "name": canonical_purl.name,
            "version": canonical_purl.version,
            "qualifiers": canonical_purl.qualifiers,
        })
    }
}

impl TryFrom<Value> for CanonicalPurl {
    type Error = serde_json::Error;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        serde_json::from_value(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "qualified_purl")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    pub versioned_purl_id: Uuid,
    pub qualifiers: Qualifiers,
    #[sea_orm(column_type = "JsonBinary")]
    pub purl: CanonicalPurl,
}

#[derive(
    Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize, FromJsonQueryResult,
)]
pub struct Qualifiers(pub BTreeMap<String, String>);

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::versioned_purl::Entity",
        from = "super::qualified_purl::Column::VersionedPurlId"
        to = "super::versioned_purl::Column::Id"
    )]
    VersionedPurl,
    #[sea_orm(
        belongs_to = "super::sbom_package_purl_ref::Entity",
        from = "Column::Id",
        to = "super::sbom_package_purl_ref::Column::QualifiedPurlId"
    )]
    SbomPackage,
}

impl Related<super::versioned_purl::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::VersionedPurl.def()
    }
}

impl Related<super::sbom_package_purl_ref::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::SbomPackage.def()
    }
}

impl Related<super::base_purl::Entity> for Entity {
    fn to() -> RelationDef {
        super::versioned_purl::Relation::BasePurl.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

#[derive(FromQueryResult, Debug)]
pub struct PackageType {
    pub package_type: String,
}

#[derive(FromQueryResult, Debug)]
pub struct PackageNamespace {
    pub package_namespace: String,
}

#[cfg(test)]
mod test {
    use super::*;
    use test_log::test;
    use trustify_common::purl::Purl;

    #[test]
    fn test_canonical_purl() {
        let cp = CanonicalPurl {
            ty: "rpm".to_string(),
            namespace: Some("redhat".to_string()),
            name: "".to_string(),
            version: Some("3.8-6.el8".to_string()),
            qualifiers: Default::default(),
        };

        assert_eq!("rpm", cp.ty);
        assert_eq!(Some("redhat".to_string()), cp.namespace);
        assert_eq!(Some("3.8-6.el8".to_string()), cp.version);

        let model = crate::qualified_purl::ActiveModel {
            id: Default::default(),
            versioned_purl_id: Default::default(),
            qualifiers: Default::default(),
            purl: sea_orm::ActiveValue::Set(cp.clone()),
        };
        assert_eq!(model.clone().purl.unwrap(), cp,);

        let purl: Purl = serde_json::from_str(
            r#"
            "pkg://rpm/redhat/filesystem@3.8-6.el8?arch=aarch64"
            "#,
        )
        .unwrap();
        let cp = purl.clone().into();
        let model = crate::qualified_purl::ActiveModel {
            id: Default::default(),
            versioned_purl_id: Default::default(),
            qualifiers: Default::default(),
            purl: sea_orm::ActiveValue::Set(purl.into()),
        };
        assert_eq!(model.clone().purl.unwrap(), cp);
        assert_eq!(cp.qualifiers.get("arch"), Some(&"aarch64".to_string()));
        // check we can serialize CanonicalPurl to url string
        assert_eq!(
            model.clone().purl.unwrap().to_string(),
            "pkg://rpm/redhat/filesystem@3.8-6.el8?arch=aarch64",
        );

        // check we can serialize CanonicalPurl to json value
        let json_value: serde_json::Value = model.purl.unwrap().into();
        assert_eq!(
            json_value,
            json!({"ty": "rpm", "namespace": "redhat", "name": "filesystem", "version": "3.8-6.el8", "qualifiers": {"arch": "aarch64"}})
        );

        // check we can serialize CanonicalPurl to Purl
        let purl: Purl = serde_json::from_str(
            r#"
            "pkg://rpm/redhat/filesystem@3.8-6.el8?arch=aarch64"
            "#,
        )
        .unwrap();
        let cp1: CanonicalPurl = purl.clone().into();
        assert_eq!(purl, cp1.into());
    }
}
