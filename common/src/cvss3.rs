use std::fmt::{Display, Formatter};
use std::str::FromStr;

#[derive(Debug, Copy, Clone)]
pub struct Cvss3Base {
    pub minor_version: u8,
    pub av: AttackVector,
    pub ac: AttackComplexity,
    pub pr: PrivilegesRequired,
    pub ui: UserInteraction,
    pub s: Scope,
    pub c: Confidentiality,
    pub i: Integrity,
    pub a: Availability,
}

impl Display for Cvss3Base {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CVSS:3.{}/AV:{}/AC:{}/PR:{}/UI:{}/S:{}/C:{}/I:{}/A:{}",
            self.minor_version, self.av, self.ac, self.pr, self.ui, self.s, self.c, self.i, self.a
        )
    }
}

#[derive(Copy, Clone, Debug)]
pub enum Cvss3Error {
    Invalid,
    MinorVersion,
    AttackVector,
    AttackComplexity,
    PrivilegesRequired,
    UserInteraction,
    Scope,
    Confidentiality,
    Integrity,
    Availability,
}

impl FromStr for Cvss3Base {
    type Err = Cvss3Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts = s.split('/').collect::<Vec<_>>();
        if parts.len() == 9 && parts[0] == "CVSS:3.1" {
            let minor_version = if parts[0] == "CVSS:3.1" {
                1
            } else if parts[0].starts_with("CVSS:3") {
                0
            } else {
                return Err(Cvss3Error::MinorVersion);
            };

            let av = parts[1];
            let ac = parts[2];
            let pr = parts[3];
            let ui = parts[4];
            let s = parts[5];
            let c = parts[6];
            let i = parts[7];
            let a = parts[8];

            Ok(Cvss3Base {
                minor_version,
                av: AttackVector::from_str(av)?,
                ac: AttackComplexity::from_str(ac)?,
                pr: PrivilegesRequired::from_str(pr)?,
                ui: UserInteraction::from_str(ui)?,
                s: Scope::from_str(s)?,
                c: Confidentiality::from_str(c)?,
                i: Integrity::from_str(i)?,
                a: Availability::from_str(a)?,
            })
        } else {
            Err(Cvss3Error::Invalid)
        }
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
                AttackVector::Network => 'N',
                AttackVector::Adjacent => 'A',
                AttackVector::Local => 'L',
                AttackVector::Physical => 'P',
            }
        )
    }
}

impl FromStr for AttackVector {
    type Err = Cvss3Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.chars().nth(3) {
            Some('N') => Ok(Self::Network),
            Some('A') => Ok(Self::Adjacent),
            Some('L') => Ok(Self::Local),
            Some('P') => Ok(Self::Physical),
            _ => Err(Cvss3Error::AttackVector),
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
                AttackComplexity::Low => 'L',
                AttackComplexity::High => 'H',
            }
        )
    }
}

impl FromStr for AttackComplexity {
    type Err = Cvss3Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.chars().nth(3) {
            Some('L') => Ok(Self::Low),
            Some('H') => Ok(Self::High),
            _ => Err(Cvss3Error::AttackComplexity),
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
                PrivilegesRequired::None => 'N',
                PrivilegesRequired::Low => 'L',
                PrivilegesRequired::High => 'H',
            }
        )
    }
}

impl FromStr for PrivilegesRequired {
    type Err = Cvss3Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.chars().nth(3) {
            Some('N') => Ok(Self::None),
            Some('L') => Ok(Self::Low),
            Some('H') => Ok(Self::High),
            _ => Err(Cvss3Error::PrivilegesRequired),
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum UserInteraction {
    None,
    Required,
}

impl Display for UserInteraction {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                UserInteraction::None => 'N',
                UserInteraction::Required => 'R',
            }
        )
    }
}

impl FromStr for UserInteraction {
    type Err = Cvss3Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.chars().nth(3) {
            Some('N') => Ok(Self::None),
            Some('R') => Ok(Self::Required),
            _ => Err(Cvss3Error::UserInteraction),
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum Scope {
    Unchanged,
    Changed,
}

impl Display for Scope {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Scope::Unchanged => 'U',
                Scope::Changed => 'C',
            }
        )
    }
}

impl FromStr for Scope {
    type Err = Cvss3Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.starts_with("S:") {
            return Err(Cvss3Error::Scope);
        }
        match s.chars().nth(2) {
            Some('U') => Ok(Self::Unchanged),
            Some('C') => Ok(Self::Changed),
            _ => Err(Cvss3Error::Scope),
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum Confidentiality {
    None,
    Low,
    High,
}

impl Display for Confidentiality {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Confidentiality::None => 'N',
                Confidentiality::Low => 'L',
                Confidentiality::High => 'H',
            }
        )
    }
}

impl FromStr for Confidentiality {
    type Err = Cvss3Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.starts_with("C:") {
            return Err(Cvss3Error::Confidentiality);
        }
        match s.chars().nth(2) {
            Some('N') => Ok(Self::None),
            Some('L') => Ok(Self::Low),
            Some('H') => Ok(Self::High),
            _ => Err(Cvss3Error::Confidentiality),
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum Integrity {
    None,
    Low,
    High,
}

impl Display for Integrity {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Integrity::None => 'N',
                Integrity::Low => 'L',
                Integrity::High => 'H',
            }
        )
    }
}

impl FromStr for Integrity {
    type Err = Cvss3Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.starts_with("I:") {
            return Err(Cvss3Error::Integrity);
        }
        match s.chars().nth(2) {
            Some('N') => Ok(Self::Low),
            Some('L') => Ok(Self::Low),
            Some('H') => Ok(Self::High),
            _ => Err(Cvss3Error::Integrity),
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum Availability {
    None,
    Low,
    High,
}

impl Display for Availability {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Availability::None => 'N',
                Availability::Low => 'L',
                Availability::High => 'H',
            }
        )
    }
}

impl FromStr for Availability {
    type Err = Cvss3Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.starts_with("A:") {
            return Err(Cvss3Error::Availability);
        }

        match s.chars().nth(2) {
            Some('N') => Ok(Self::Low),
            Some('L') => Ok(Self::Low),
            Some('H') => Ok(Self::High),
            _ => Err(Cvss3Error::Availability),
        }
    }
}
