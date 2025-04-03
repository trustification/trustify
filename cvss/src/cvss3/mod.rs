use crate::cvss3::score::Score;
use crate::cvss3::severity::Severity;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

pub mod score;
pub mod severity;

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

impl Cvss3Base {
    /// Calculate Base CVSS score: overall value for determining the severity
    /// of a vulnerability, generally referred to as the "CVSS score".
    ///
    /// Described in CVSS v3.1 Specification: Section 2:
    /// <https://www.first.org/cvss/specification-document#t6>
    ///
    /// > When the Base metrics are assigned values by an analyst, the Base
    /// > equation computes a score ranging from 0.0 to 10.0.
    /// >
    /// > Specifically, the Base equation is derived from two sub equations:
    /// > the Exploitability sub-score equation, and the Impact sub-score
    /// > equation. The Exploitability sub-score equation is derived from the
    /// > Base Exploitability metrics, while the Impact sub-score equation is
    /// > derived from the Base Impact metrics.
    pub fn score(&self) -> Score {
        let exploitability = self.exploitability().value();
        let iss = self.impact().value();

        let iss_scoped = if !self.is_scope_changed() {
            6.42 * iss
        } else {
            (7.52 * (iss - 0.029)) - (3.25 * (iss - 0.02).powf(15.0))
        };

        let score = if iss_scoped <= 0.0 {
            0.0
        } else if !self.is_scope_changed() {
            (iss_scoped + exploitability).min(10.0)
        } else {
            (1.08 * (iss_scoped + exploitability)).min(10.0)
        };

        Score::new(score).roundup()
    }

    /// Calculate Base Exploitability score: sub-score for measuring
    /// ease of exploitation.
    ///
    /// Described in CVSS v3.1 Specification: Section 2:
    /// <https://www.first.org/cvss/specification-document#t6>
    ///
    /// > The Exploitability metrics reflect the ease and technical means by which
    /// > the vulnerability can be exploited. That is, they represent characteristics
    /// > of *the thing that is vulnerable*, which we refer to formally as the
    /// > *vulnerable component*.
    pub fn exploitability(&self) -> Score {
        let av_score = self.av.score();
        let ac_score = self.ac.score();
        let ui_score = self.ui.score();
        let pr_score = self.pr.scoped_score(self.is_scope_changed());

        (8.22 * av_score * ac_score * pr_score * ui_score).into()
    }

    /// Calculate Base Impact Score (ISS): sub-score for measuring the
    /// consequences of successful exploitation.
    ///
    /// Described in CVSS v3.1 Specification: Section 2:
    /// <https://www.first.org/cvss/specification-document#t6>
    ///
    /// > The Impact metrics reflect the direct consequence
    /// > of a successful exploit, and represent the consequence to the
    /// > *thing that suffers the impact*, which we refer to formally as the
    /// > *impacted component*.
    pub fn impact(&self) -> Score {
        let c_score = self.c.score();
        let i_score = self.i.score();
        let a_score = self.a.score();
        (1.0 - ((1.0 - c_score) * (1.0 - i_score) * (1.0 - a_score)).abs()).into()
    }

    /// Calculate Base CVSS `Severity` according to the
    /// Qualitative Severity Rating Scale (i.e. Low / Medium / High / Critical)
    ///
    /// Described in CVSS v3.1 Specification: Section 5:
    /// <https://www.first.org/cvss/specification-document#t17>
    pub fn severity(&self) -> Severity {
        self.score().severity()
    }

    /// Has the scope changed?
    fn is_scope_changed(&self) -> bool {
        self.s.is_changed()
    }
}

// Serialize Cvss3 scores back as a string, reconstituted from
// the column deconstructed variant we're storing.
impl Display for Cvss3Base {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CVSS:3.{}/AV:{}/AC:{}/PR:{}/UI:{}/S:{}/C:{}/I:{}/A:{}",
            self.minor_version, self.av, self.ac, self.pr, self.ui, self.s, self.c, self.i, self.a
        )
    }
}

#[derive(Clone, Debug)]
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
    InvalidSeverity { name: String },
}

impl Display for Cvss3Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl FromStr for Cvss3Base {
    type Err = Cvss3Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts = s.split('/').collect::<Vec<_>>();
        if parts.len() == 9 && parts[0].starts_with("CVSS:") {
            let minor_version = if parts[0] == "CVSS:3.1" {
                1
            } else if parts[0].starts_with("CVSS:3") {
                0
            } else {
                return Err(Self::Err::MinorVersion);
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
            Err(Self::Err::Invalid)
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
                Self::Network => 'N',
                Self::Adjacent => 'A',
                Self::Local => 'L',
                Self::Physical => 'P',
            }
        )
    }
}

impl FromStr for AttackVector {
    type Err = Cvss3Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.starts_with("AV:") {
            return Err(Self::Err::AttackVector);
        }
        match s.chars().nth(3) {
            Some('N') => Ok(Self::Network),
            Some('A') => Ok(Self::Adjacent),
            Some('L') => Ok(Self::Local),
            Some('P') => Ok(Self::Physical),
            _ => Err(Self::Err::AttackVector),
        }
    }
}

impl AttackVector {
    fn score(self) -> f64 {
        match self {
            AttackVector::Physical => 0.20,
            AttackVector::Local => 0.55,
            AttackVector::Adjacent => 0.62,
            AttackVector::Network => 0.85,
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum AttackComplexity {
    Low,
    High,
}

impl AttackComplexity {
    fn score(self) -> f64 {
        match self {
            AttackComplexity::High => 0.44,
            AttackComplexity::Low => 0.77,
        }
    }
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
    type Err = Cvss3Error;

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
pub enum PrivilegesRequired {
    None,
    Low,
    High,
}

impl PrivilegesRequired {
    pub fn scoped_score(self, scope_change: bool) -> f64 {
        match self {
            PrivilegesRequired::High => {
                if scope_change {
                    0.50
                } else {
                    0.27
                }
            }
            PrivilegesRequired::Low => {
                if scope_change {
                    0.68
                } else {
                    0.62
                }
            }
            PrivilegesRequired::None => 0.85,
        }
    }
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
    type Err = Cvss3Error;

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
    Required,
}

impl UserInteraction {
    fn score(self) -> f64 {
        match self {
            UserInteraction::Required => 0.62,
            UserInteraction::None => 0.85,
        }
    }
}

impl Display for UserInteraction {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::None => 'N',
                Self::Required => 'R',
            }
        )
    }
}

impl FromStr for UserInteraction {
    type Err = Cvss3Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.starts_with("UI:") {
            return Err(Self::Err::UserInteraction);
        }
        match s.chars().nth(3) {
            Some('N') => Ok(Self::None),
            Some('R') => Ok(Self::Required),
            _ => Err(Self::Err::UserInteraction),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Scope {
    Unchanged,
    Changed,
}

impl Scope {
    pub fn is_changed(self) -> bool {
        self == Scope::Changed
    }
}

impl Display for Scope {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Unchanged => 'U',
                Self::Changed => 'C',
            }
        )
    }
}

impl FromStr for Scope {
    type Err = Cvss3Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.starts_with("S:") {
            return Err(Self::Err::Scope);
        }
        match s.chars().nth(2) {
            Some('U') => Ok(Self::Unchanged),
            Some('C') => Ok(Self::Changed),
            _ => Err(Self::Err::Scope),
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum Confidentiality {
    None,
    Low,
    High,
}

impl Confidentiality {
    fn score(self) -> f64 {
        match self {
            Confidentiality::None => 0.0,
            Confidentiality::Low => 0.22,
            Confidentiality::High => 0.56,
        }
    }
}

impl Display for Confidentiality {
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

impl FromStr for Confidentiality {
    type Err = Cvss3Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.starts_with("C:") {
            return Err(Self::Err::Confidentiality);
        }
        match s.chars().nth(2) {
            Some('N') => Ok(Self::None),
            Some('L') => Ok(Self::Low),
            Some('H') => Ok(Self::High),
            _ => Err(Self::Err::Confidentiality),
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum Integrity {
    None,
    Low,
    High,
}

impl Integrity {
    fn score(self) -> f64 {
        match self {
            Integrity::None => 0.0,
            Integrity::Low => 0.22,
            Integrity::High => 0.56,
        }
    }
}

impl Display for Integrity {
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

impl FromStr for Integrity {
    type Err = Cvss3Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.starts_with("I:") {
            return Err(Self::Err::Integrity);
        }
        match s.chars().nth(2) {
            Some('N') => Ok(Self::None),
            Some('L') => Ok(Self::Low),
            Some('H') => Ok(Self::High),
            _ => Err(Self::Err::Integrity),
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum Availability {
    None,
    Low,
    High,
}

impl Availability {
    fn score(self) -> f64 {
        match self {
            Availability::None => 0.0,
            Availability::Low => 0.22,
            Availability::High => 0.56,
        }
    }
}

impl Display for Availability {
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

impl FromStr for Availability {
    type Err = Cvss3Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.starts_with("A:") {
            return Err(Self::Err::Availability);
        }

        match s.chars().nth(2) {
            Some('N') => Ok(Self::None),
            Some('L') => Ok(Self::Low),
            Some('H') => Ok(Self::High),
            _ => Err(Self::Err::Availability),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn verify_scores() {
        for (cvss, expected) in [
            ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
            ("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N", 4.8),
            ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", 3.3),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),
            ("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", 5.4),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", 5.3),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3),
            ("CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H", 5.5),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),
            ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N", 6.1),
            ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N", 4.8),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
        ] {
            assert_eq!(expected, Cvss3Base::from_str(cvss).unwrap().score().value());
        }
    }
}
