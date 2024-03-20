use crate::{advisory, vulnerability};
use sea_orm::entity::prelude::*;
use trustify_cvss::cvss4;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "cvss4")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub advisory_id: i32,

    #[sea_orm(primary_key)]
    pub vulnerability_id: i32,

    #[sea_orm(primary_key)]
    pub minor_version: i32,

    pub av: AttackVector,
    pub ac: AttackComplexity,
    pub at: AttackRequirements,
    pub pr: PrivilegesRequired,
    pub ui: UserInteraction,
    pub vc: VulnerableConfidentiality,
    pub vi: VulnerableIntegrity,
    pub va: VulnerableAvailability,
    pub sc: SubsequentConfidentiality,
    pub si: SubsequentIntegrity,
    pub sa: SubsequentAvailability,
}

impl From<Model> for cvss4::Cvss4Base {
    fn from(value: Model) -> Self {
        Self {
            minor_version: value.minor_version as u8,
            av: value.av.into(),
            ac: value.ac.into(),
            at: value.at.into(),
            pr: value.pr.into(),
            ui: value.ui.into(),
            vc: value.vc.into(),
            vi: value.vi.into(),
            va: value.va.into(),
            sc: value.sc.into(),
            si: value.si.into(),
            sa: value.sa.into(),
        }
    }
}


#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
    belongs_to = "super::advisory::Entity",
    from = "super::cvss4::Column::AdvisoryId"
    to = "super::advisory::Column::Id")]
    Advisory,

    #[sea_orm(
    belongs_to = "super::advisory::Entity",
    from = "super::cvss4::Column::VulnerabilityId"
    to = "super::advisory::Column::Id")]
    Vulnerability,
}

impl Related<advisory::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Advisory.def()
    }
}

impl Related<vulnerability::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Vulnerability.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}


#[derive(Debug, Clone, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "cvss4_av")]
pub enum AttackVector {
    #[sea_orm(string_value = "n")]
    Network,
    #[sea_orm(string_value = "a")]
    Adjacent,
    #[sea_orm(string_value = "l")]
    Local,
    #[sea_orm(string_value = "p")]
    Physical,
}

impl From<AttackVector> for cvss4::AttackVector {
    fn from(value: AttackVector) -> Self {
        match value {
            AttackVector::Network => Self::Network,
            AttackVector::Adjacent => Self::Adjacent,
            AttackVector::Local => Self::Local,
            AttackVector::Physical => Self::Physical,
        }
    }
}

impl From<cvss4::AttackVector> for AttackVector {
    fn from(value: cvss4::AttackVector) -> Self {
        match value {
            cvss4::AttackVector::Network => Self::Network,
            cvss4::AttackVector::Adjacent => Self::Adjacent,
            cvss4::AttackVector::Local => Self::Local,
            cvss4::AttackVector::Physical => Self::Physical,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "cvss4_ac")]
pub enum AttackComplexity {
    #[sea_orm(string_value = "l")]
    Low,
    #[sea_orm(string_value = "h")]
    High,
}

impl From<AttackComplexity> for cvss4::AttackComplexity {
    fn from(value: AttackComplexity) -> Self {
        match value {
            AttackComplexity::Low => Self::Low,
            AttackComplexity::High => Self::High,
        }
    }
}

impl From<cvss4::AttackComplexity> for AttackComplexity {
    fn from(value: cvss4::AttackComplexity) -> Self {
        match value {
            cvss4::AttackComplexity::Low => Self::Low,
            cvss4::AttackComplexity::High => Self::High,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "cvss4_at")]
pub enum AttackRequirements {
    #[sea_orm(string_value = "n")]
    None,
    #[sea_orm(string_value = "p")]
    Present,
}

impl From<AttackRequirements> for cvss4::AttackRequirements {
    fn from(value: AttackRequirements) -> Self {
        match value {
            AttackRequirements::None => Self::None,
            AttackRequirements::Present => Self::Present
        }
    }
}

impl From<cvss4::AttackRequirements> for AttackRequirements {
    fn from(value: cvss4::AttackRequirements) -> Self {
        match value {
            cvss4::AttackRequirements::None => Self::None,
            cvss4::AttackRequirements::Present => Self::Present,
        }
    }
}


#[derive(Debug, Clone, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "cvss4_pr")]
pub enum PrivilegesRequired {
    #[sea_orm(string_value = "n")]
    None,
    #[sea_orm(string_value = "l")]
    Low,
    #[sea_orm(string_value = "h")]
    High,
}

impl From<PrivilegesRequired> for cvss4::PrivilegesRequired {
    fn from(value: PrivilegesRequired) -> Self {
        match value {
            PrivilegesRequired::None => Self::None,
            PrivilegesRequired::Low => Self::Low,
            PrivilegesRequired::High => Self::High
        }
    }
}

impl From<cvss4::PrivilegesRequired> for PrivilegesRequired {
    fn from(value: cvss4::PrivilegesRequired) -> Self {
        match value {
            cvss4::PrivilegesRequired::None => Self::None,
            cvss4::PrivilegesRequired::Low => Self::Low,
            cvss4::PrivilegesRequired::High => Self::High,
        }
    }
}


#[derive(Debug, Clone, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "cvss4_ui")]
pub enum UserInteraction {
    #[sea_orm(string_value = "n")]
    None,
    #[sea_orm(string_value = "p")]
    Passive,
    #[sea_orm(string_value = "a")]
    Active,
}

impl From<UserInteraction> for cvss4::UserInteraction {
    fn from(value: UserInteraction) -> Self {
        match value {
            UserInteraction::None => Self::None,
            UserInteraction::Passive => Self::Passive,
            UserInteraction::Active => Self::Active,
        }
    }
}

impl From<cvss4::UserInteraction> for UserInteraction {
    fn from(value: cvss4::UserInteraction) -> Self {
        match value {
            cvss4::UserInteraction::None => Self::None,
            cvss4::UserInteraction::Passive => Self::Passive,
            cvss4::UserInteraction::Active => Self::Active,
        }
    }
}

// ----

#[derive(Debug, Clone, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "cvss4_vc")]
pub enum VulnerableConfidentiality {
    #[sea_orm(string_value = "n")]
    None,
    #[sea_orm(string_value = "l")]
    Low,
    #[sea_orm(string_value = "h")]
    High,
}

impl From<VulnerableConfidentiality> for cvss4::VulnerableConfidentiality {
    fn from(value: VulnerableConfidentiality) -> Self {
        match value {
            VulnerableConfidentiality::None => Self::None,
            VulnerableConfidentiality::Low => Self::Low,
            VulnerableConfidentiality::High => Self::High,
        }
    }
}

impl From<cvss4::VulnerableConfidentiality> for VulnerableConfidentiality {
    fn from(value: cvss4::VulnerableConfidentiality) -> Self {
        match value {
            cvss4::VulnerableConfidentiality::High => Self::High,
            cvss4::VulnerableConfidentiality::Low => Self::Low,
            cvss4::VulnerableConfidentiality::None => Self::None
        }
    }
}

// ---


#[derive(Debug, Clone, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "cvss4_vi")]
pub enum VulnerableIntegrity {
    #[sea_orm(string_value = "n")]
    None,
    #[sea_orm(string_value = "l")]
    Low,
    #[sea_orm(string_value = "h")]
    High,
}

impl From<VulnerableIntegrity> for cvss4::VulnerableIntegrity {
    fn from(value: VulnerableIntegrity) -> Self {
        match value {
            VulnerableIntegrity::None => Self::None,
            VulnerableIntegrity::Low => Self::Low,
            VulnerableIntegrity::High => Self::High,
        }
    }
}

impl From<cvss4::VulnerableIntegrity> for VulnerableIntegrity {
    fn from(value: cvss4::VulnerableIntegrity) -> Self {
        match value {
            cvss4::VulnerableIntegrity::High => Self::High,
            cvss4::VulnerableIntegrity::Low => Self::Low,
            cvss4::VulnerableIntegrity::None => Self::None
        }
    }
}

// ---

#[derive(Debug, Clone, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "cvss4_va")]
pub enum VulnerableAvailability {
    #[sea_orm(string_value = "n")]
    None,
    #[sea_orm(string_value = "l")]
    Low,
    #[sea_orm(string_value = "h")]
    High,
}

impl From<VulnerableAvailability> for cvss4::VulnerableAvailability {
    fn from(value: VulnerableAvailability) -> Self {
        match value {
            VulnerableAvailability::None => Self::None,
            VulnerableAvailability::Low => Self::Low,
            VulnerableAvailability::High => Self::High,
        }
    }
}

impl From<cvss4::VulnerableAvailability> for VulnerableAvailability {
    fn from(value: cvss4::VulnerableAvailability) -> Self {
        match value {
            cvss4::VulnerableAvailability::High => Self::High,
            cvss4::VulnerableAvailability::Low => Self::Low,
            cvss4::VulnerableAvailability::None => Self::None
        }
    }
}

// ---
// ---
// ---
// ---





#[derive(Debug, Clone, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "cvss4_sc")]
pub enum SubsequentConfidentiality {
    #[sea_orm(string_value = "n")]
    Negligible,
    #[sea_orm(string_value = "l")]
    Low,
    #[sea_orm(string_value = "h")]
    High,
}

impl From<SubsequentConfidentiality> for cvss4::SubsequentConfidentiality {
    fn from(value: SubsequentConfidentiality) -> Self {
        match value {
            SubsequentConfidentiality::Negligible => Self::Negligible,
            SubsequentConfidentiality::Low => Self::Low,
            SubsequentConfidentiality::High => Self::High,
        }
    }
}

impl From<cvss4::SubsequentConfidentiality> for SubsequentConfidentiality {
    fn from(value: cvss4::SubsequentConfidentiality) -> Self {
        match value {
            cvss4::SubsequentConfidentiality::High => Self::High,
            cvss4::SubsequentConfidentiality::Low => Self::Low,
            cvss4::SubsequentConfidentiality::Negligible => Self::Negligible
        }
    }
}

// ---


#[derive(Debug, Clone, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "cvss4_si")]
pub enum SubsequentIntegrity {
    #[sea_orm(string_value = "n")]
    None,
    #[sea_orm(string_value = "l")]
    Low,
    #[sea_orm(string_value = "h")]
    High,
}

impl From<SubsequentIntegrity> for cvss4::SubsequentIntegrity {
    fn from(value: SubsequentIntegrity) -> Self {
        match value {
            SubsequentIntegrity::None => Self::None,
            SubsequentIntegrity::Low => Self::Low,
            SubsequentIntegrity::High => Self::High,
        }
    }
}

impl From<cvss4::SubsequentIntegrity> for SubsequentIntegrity {
    fn from(value: cvss4::SubsequentIntegrity) -> Self {
        match value {
            cvss4::SubsequentIntegrity::High => Self::High,
            cvss4::SubsequentIntegrity::Low => Self::Low,
            cvss4::SubsequentIntegrity::None => Self::None
        }
    }
}

// ---

#[derive(Debug, Clone, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "cvss4_sa")]
pub enum SubsequentAvailability {
    #[sea_orm(string_value = "n")]
    None,
    #[sea_orm(string_value = "l")]
    Low,
    #[sea_orm(string_value = "h")]
    High,
}

impl From<SubsequentAvailability> for cvss4::SubsequentAvailability {
    fn from(value: SubsequentAvailability) -> Self {
        match value {
            SubsequentAvailability::None => Self::None,
            SubsequentAvailability::Low => Self::Low,
            SubsequentAvailability::High => Self::High,
        }
    }
}

impl From<cvss4::SubsequentAvailability> for SubsequentAvailability {
    fn from(value: cvss4::SubsequentAvailability) -> Self {
        match value {
            cvss4::SubsequentAvailability::High => Self::High,
            cvss4::SubsequentAvailability::Low => Self::Low,
            cvss4::SubsequentAvailability::None => Self::None
        }
    }
}

