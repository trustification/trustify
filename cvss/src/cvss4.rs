use std::fmt::{Display, Formatter};
use std::str::FromStr;

#[derive(Debug, Copy, Clone)]
pub struct Cvss4Base {
    pub minor_version: u8,
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

#[derive(Debug, Copy, Clone)]
pub enum Cvss4Error {
    Invalid,
    MinorVersion,
    AttackVector,
    AttackComplexity,
    AttackRequirements,
    PrivilegesRequired,
    UserInteraction,
    VulnerableConfidentiality,
    VulnerableIntegrity,
    VulnerableAvailability,
    SubsequentConfidentiality,
    SubsequentIntegrity,
    SubsequentAvailability,
}

impl FromStr for Cvss4Base {
    type Err = Cvss4Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts = s.split('/').collect::<Vec<_>>();
        if parts.len() == 12 && parts[0].starts_with("CVSS:4.0") {
            let minor_version = 0;

            let av = parts[1];
            let ac = parts[2];
            let at = parts[3];
            let pr = parts[4];
            let ui = parts[5];
            let vc = parts[6];
            let vi = parts[7];
            let va = parts[8];
            let sc = parts[9];
            let si = parts[10];
            let sa = parts[11];

            Ok(
                Cvss4Base {
                    minor_version,
                    av: AttackVector::from_str(av)?,
                    ac: AttackComplexity::from_str(ac)?,
                    at: AttackRequirements::from_str(at)?,
                    pr: PrivilegesRequired::from_str(pr)?,
                    ui: UserInteraction::from_str(ui)?,
                    vc: VulnerableConfidentiality::from_str(vc)?,
                    vi: VulnerableIntegrity::from_str(vi)?,
                    va: VulnerableAvailability::from_str(va)?,
                    sc: SubsequentConfidentiality::from_str(sc)?,
                    si: SubsequentIntegrity::from_str(si)?,
                    sa: SubsequentAvailability::from_str(sa)?,
                }
            )
        } else {
            Err(Cvss4Error::Invalid)
        }
    }
}

impl Display for Cvss4Base {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CVSS:4.{}/AV:{}/AC:{}/AT:{}/PR:{}/UI:{}/VC:{}/VI:{}/VA:{}/SC:{}/SI:{}/SA:{}",
            self.minor_version,
            self.av,
            self.ac,
            self.at,
            self.pr,
            self.ui,
            self.vc,
            self.vi,
            self.va,
            self.sc,
            self.si,
            self.sa,
        )
    }
}

#[derive(Debug, Copy, Clone)]
pub enum AttackVector {
    Network,
    Adjacent,
    Local,
    Physical,
}

impl Display for AttackVector {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Network => 'N',
                Self::Adjacent => 'A',
                Self::Local => 'L',
                Self::Physical => 'P',
            }
        )
    }
}

impl FromStr for AttackVector {
    type Err = Cvss4Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if ! s.starts_with("AV:") {
            return Err(Self::Err::AttackVector)
        }

        match s.chars().nth(3) {
            Some('N') => Ok(Self::Network),
            Some('A') => Ok(Self::Adjacent),
            Some('L') => Ok(Self::Local),
            Some('P') => Ok(Self::Physical),
            _ => Err(Cvss4Error::AttackVector),
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum AttackComplexity {
    Low,
    High,
}

impl Display for AttackComplexity {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Low => 'L',
                Self::High => 'H',
            }
        )
    }
}

impl FromStr for AttackComplexity {
    type Err = Cvss4Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.starts_with("AC:") {
            return Err(Self::Err::AttackComplexity);
        }
        match s.chars().nth(3) {
            Some('L') => Ok(Self::Low),
            Some('H') => Ok(Self::High),
            _ => Err(Self::Err::AttackComplexity),
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum AttackRequirements {
    None,
    Present,
}

impl Display for AttackRequirements {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::None => 'N',
                Self::Present => 'P',
            }
        )
    }
}

impl FromStr for AttackRequirements {
    type Err = Cvss4Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.starts_with("AT:") {
            return Err(Self::Err::AttackRequirements);
        }

        match s.chars().nth(3) {
            Some('N') => Ok(Self::None),
            Some('P') => Ok(Self::Present),
            _ => Err(Self::Err::AttackRequirements)
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum PrivilegesRequired {
    None,
    Low,
    High,
}

impl Display for PrivilegesRequired {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::None => 'N',
                Self::Low => 'L',
                Self::High => 'H',
            }
        )
    }
}

impl FromStr for PrivilegesRequired {
    type Err = Cvss4Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.starts_with("PR:") {
            return Err(Self::Err::PrivilegesRequired);
        }

        match s.chars().nth(3) {
            Some('N') => Ok(Self::None),
            Some('L') => Ok(Self::Low),
            Some('H') => Ok(Self::High),
            _ => Err(Self::Err::PrivilegesRequired),
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum UserInteraction {
    None,
    Passive,
    Active,
}

impl Display for UserInteraction {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::None => 'N',
                Self::Passive => 'P',
                Self::Active => 'A',
            }
        )
    }
}

impl FromStr for UserInteraction {
    type Err = Cvss4Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.starts_with("UI:") {
            return Err(Self::Err::UserInteraction);
        }

        match s.chars().nth(3) {
            Some('N') => Ok(Self::None),
            Some('P') => Ok(Self::Passive),
            Some('A') => Ok(Self::Active),
            _ => Err(Self::Err::UserInteraction),
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum VulnerableConfidentiality {
    High,
    Low,
    None,
}

impl Display for VulnerableConfidentiality {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::High => 'H',
                Self::Low => 'L',
                Self::None => 'N',
            }
        )
    }
}

impl FromStr for VulnerableConfidentiality {
    type Err = Cvss4Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.starts_with("VC:") {
            return Err(Self::Err::VulnerableConfidentiality);
        }

        match s.chars().nth(3) {
            Some('N') => Ok(Self::None),
            Some('L') => Ok(Self::Low),
            Some('H') => Ok(Self::High),
            _ => Err(Self::Err::VulnerableConfidentiality),
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum SubsequentConfidentiality {
    High,
    Low,
    Negligible,
}



impl Display for SubsequentConfidentiality {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::High => 'H',
                Self::Low => 'L',
                Self::Negligible => 'N',
            }
        )
    }
}

impl FromStr for SubsequentConfidentiality {
    type Err = Cvss4Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.starts_with("SC:") {
            return Err(Self::Err::SubsequentConfidentiality);
        }

        match s.chars().nth(3) {
            Some('N') => Ok(Self::Negligible),
            Some('L') => Ok(Self::Low),
            Some('H') => Ok(Self::High),
            _ => Err(Self::Err::SubsequentConfidentiality),
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum VulnerableIntegrity {
    High,
    Low,
    None,
}

impl Display for VulnerableIntegrity {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::High => 'H',
                Self::Low => 'L',
                Self::None => 'N',
            }
        )
    }
}

impl FromStr for VulnerableIntegrity {
    type Err = Cvss4Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.starts_with("VI:") {
            return Err(Self::Err::VulnerableIntegrity);
        }

        match s.chars().nth(3) {
            Some('N') => Ok(Self::None),
            Some('L') => Ok(Self::Low),
            Some('H') => Ok(Self::High),
            _ => Err(Self::Err::VulnerableIntegrity),
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum SubsequentIntegrity {
    High,
    Low,
    None,
}

impl Display for SubsequentIntegrity {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::High => 'H',
                Self::Low => 'L',
                Self::None => 'N',
            }
        )
    }
}

impl FromStr for SubsequentIntegrity {
    type Err = Cvss4Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.starts_with("SI:") {
            return Err(Self::Err::SubsequentIntegrity);
        }

        match s.chars().nth(3) {
            Some('N') => Ok(Self::None),
            Some('L') => Ok(Self::Low),
            Some('H') => Ok(Self::High),
            _ => Err(Self::Err::SubsequentIntegrity),
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum VulnerableAvailability {
    High,
    Low,
    None,
}

impl Display for VulnerableAvailability {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::High => 'H',
                Self::Low => 'L',
                Self::None => 'N',
            }
        )
    }
}

impl FromStr for VulnerableAvailability {
    type Err = Cvss4Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.starts_with("VA:") {
            return Err(Self::Err::VulnerableAvailability);
        }

        match s.chars().nth(3) {
            Some('N') => Ok(Self::None),
            Some('L') => Ok(Self::Low),
            Some('H') => Ok(Self::High),
            _ => Err(Self::Err::VulnerableAvailability),
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum SubsequentAvailability {
    High,
    Low,
    None,
}

impl Display for SubsequentAvailability {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::High => 'H',
                Self::Low => 'L',
                Self::None => 'N',
            }
        )
    }
}

impl FromStr for SubsequentAvailability {
    type Err = Cvss4Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.starts_with("SA:") {
            return Err(Self::Err::SubsequentAvailability);
        }

        match s.chars().nth(3) {
            Some('N') => Ok(Self::None),
            Some('L') => Ok(Self::Low),
            Some('H') => Ok(Self::High),
            _ => Err(Self::Err::SubsequentAvailability),
        }
    }
}
